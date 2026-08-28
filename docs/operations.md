# Operations

## S3 permissions and layout

This section applies when `COG_S3_BUCKET` is configured. Without it, cog
uses its persistent local SQLite database as the source of truth and does not
require object storage or a lease.

Give cog a dedicated bucket or prefix. Its identity needs `ListBucket` on the
bucket, restricted to the configured prefix, and `GetObject`, `PutObject`, and
`DeleteObject` beneath that prefix. The provider must honor conditional creates
and ETag/version-based conditional updates; cog probes both before acquiring
the lease and refuses to start if either is unavailable.

Enable bucket versioning. The mutable `lease.json` object benefits from version
history during incident analysis. LTX objects live beneath generation-qualified
paths and are immutable by protocol. Do not configure a lifecycle rule that can
delete LTX generations until retention/compaction has published and verified a
new restorable anchor. In particular, never expire every object for the newest
completed generation.

Use TLS for S3 in production. `COG_S3_ALLOW_HTTP=true` is intended only for
local MinIO tests. Restrict bucket credentials to the cog workload and treat
read access as sensitive because the database contains encrypted credentials
and authentication records.

## AWS credential renewal

Choose credentials according to the lifetime of the process:

- EC2 instance metadata and web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` plus
  `AWS_ROLE_ARN`) are renewable. ECS task credentials and EKS Pod Identity are
  renewable too. Clanker Operations Gateway keeps the provider attached to its S3 client and the
  provider refreshes its cache shortly before expiration. The refreshed
  credentials are therefore used by lease renewal, LTX upload, restore, and the
  final sync and lease relinquish during orderly shutdown.
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional
  `AWS_SESSION_TOKEN` form one static credential set. They take precedence over
  workload identity and are resolved when the S3 client is built. A temporary
  session passed this way will expire in a running process; changing its
  environment cannot refresh it. Restart with a new set or, preferably, use a
  renewable workload provider.

AWS CLI profiles, IAM Identity Center/SSO, and `login_session` are not part of
cog's provider chain. Do not assume that `AWS_PROFILE`,
`AWS_SHARED_CREDENTIALS_FILE`, or a mounted CLI cache supplies renewable
credentials. A startup log records only the selected provider class and never
credential material.

## Backup, restore, and disaster recovery

In S3 mode, the bucket is the durable source of truth; the local `/data` directory is a
replaceable working copy. For an ordinary restore, stop all cog instances,
preserve the bucket, remove or archive the local data volume, and start exactly
one instance with the same bucket prefix and master key. It acquires a new lease
generation, restores the newest complete LTX chain, and only then starts HTTP.

For disaster recovery, first copy the complete configured prefix—including
`lease.json` history and every `ltx/g...` directory—to a protected bucket. Use a
new empty local volume and, if restoring into a different bucket, retain object
keys exactly. Never hand-edit TXID filenames or combine files from different
generation directories.

Validate a recovery by checking `/readyz`, SQLite integrity through the admin
surface, and expected users/integrations before returning traffic. Keep the
source bucket until the recovered instance has produced and uploaded a new
generation.

### Completed-generation markers

Clanker Operations Gateway restores only generations containing an immutable `complete.json`
marker. A new owner writes that marker only after its complete initial LTX
chain has uploaded, independently reconstructed a SQLite database, and passed
`PRAGMA integrity_check`. LTX objects without a marker can be a valid but
historical prefix left by an interrupted startup and must never be selected
merely because their generation number is newer. Garbage collection is also
disabled until the current generation is marked complete.

An existing bucket upgraded from a release that predates completion markers
fails closed when it contains LTX data but no marked generation. Recover it by
restoring candidate generations offline, validating SQLite integrity and the
expected application records, and then marking exactly the selected generation
before starting the upgraded service. Never guess from generation number,
object count, or maximum TXID: a rolled-back database can create a newer and
numerically longer chain.

## Master key lifecycle

Generate `COG_MASTER_KEY` from at least 32 cryptographically random bytes, for
example `openssl rand -base64 48`, and store it in a workload secret manager.
The value is used as key-derivation input and must be identical on takeover.
Loss of the key makes stored upstream credentials unrecoverable; bucket backups
do not replace key escrow.

Online key rotation is not implicit: changing the environment value makes old
ciphertexts unreadable. Until a dedicated re-encryption command is available,
rotate during downtime by reconnecting every integration under a fresh cog
installation, or retain the previous key and restore the original bucket. Never
attempt a partial rotation by editing SQLite directly. Record which key version
belongs to each bucket backup and test recovery periodically.

## Safe upstream OAuth troubleshooting

Treat downstream agent authorization to cog separately from cog's authorization to an upstream MCP server. Inspect the upstream protected-resource and authorization-server metadata without following or pre-opening any returned consent URL. Confirm that `resource` is the provider's exact canonical URI, that the issuer agrees with callback `iss` when supplied, that PKCE S256 is advertised, and that configured scopes are actually supported.

If the callback fails, inspect only its `error`, escaped `error_description`, and `iss`; never record the full callback URL, authorization code, state, tokens, signed parameters, or provider response bodies. Use the integration status to distinguish connection-required from a base MCP failure. After correcting metadata or configuration, POST the integration reconnect endpoint to discard stale registration and token state, start OAuth again, and give the newly returned one-time URL directly to the human. Render it as a fenced value or angle-bracket autolink in chat surfaces, since Markdown punctuation can corrupt a query value.

Finally, use a separately obtained cog bearer token to perform MCP `initialize` and tool discovery. A successful browser page alone proves only that the upstream callback completed.

## Shutdown and takeover

Send SIGINT for an orderly stop. The server stops on terminal lease-renewal
failure. On SIGINT it uploads the final captured LTX position, stops renewal,
and conditionally expires only its own lease record. SIGKILL and host loss rely
on lease expiry; a replacement must not be started with clocks known to be
incorrect.

## Git transports and SSH incident response

See [Git transports](git.md) for SSH certificate setup.
SSH is a separate TCP listener and must be allowed through the host firewall and
load balancer directly; Nginx's HTTP listener cannot proxy it as an HTTP route.
Verify the effective systemd configuration, listener ownership, `/readyz`, and
both host/CA fingerprints after deployment and S3 takeover.

For emergency SSH disablement, stop COG orderly with SIGINT and block the
published SSH port; Git access remains unavailable until COG is restarted. For a user
CA compromise, prepare and activate a replacement CA, revoke affected OAuth
clients or repository grants immediately, and retain the retiring CA only for
the maximum certificate lifetime. For a host-key compromise, disable SSH,
prepare and activate a replacement while stopped, distribute the new pinned
`known_hosts` entry through `repository_access`, and then re-enable the listener.
Never tell clients to bypass host-key checking.

Repository removal, integration disconnect, client revocation, and stale-owner
fencing take effect at the next SSH command even for an unexpired certificate.
Rotation order is prepare, durably replicate, distribute overlap, activate,
observe, then retire after `retirement_time`. CA overlap is at least the maximum
certificate lifetime plus clock skew; host overlap is at least 24 hours unless
the operator documents a longer client rollout window and rollback plan.
