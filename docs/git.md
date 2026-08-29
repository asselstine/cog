# Git over short-lived SSH certificates

SSH is the downstream Git transport. By default COG listens on
`127.0.0.1:2222`, derives the advertised host from `COG_BASE_URL`, and
advertises the listener port. Set `COG_SSH_LISTEN=0.0.0.0:2222` when exposing
the listener directly, or override the public port when a TCP proxy maps it.

An authorized MCP client first calls `repository_access`. Its versioned
`remotes` object reports whether SSH is ready, the pinned `knownHosts` line,
host-key fingerprint, and certificate TTL. The opaque
repository UUID is the only accepted SSH path.

Reuse an existing Ed25519 identity from SSH configuration, the SSH agent, or a
standard identity path. Never send its private key to COG and never create or
replace an identity merely because a COG certificate expired. If no Ed25519
identity exists, stop and report that one must be provisioned outside this
workflow.

Before requesting a certificate, reuse a saved COG certificate while
`ssh_certificate_status` reports it as valid. For initial enrollment, call
`ssh_certificate` with `repositoryId`, `permission`, and the exact contents of
the existing public key. Write the returned `certificate` separately from the
private key, and write `knownHosts` to a private `known_hosts` file.

After the certificate expires, call `renew_ssh_certificate` with the same
public key and the previous certificate. The renewal tool verifies that the
previous certificate belongs to that key, client, and repository before
issuing a replacement. It never creates or rotates an SSH identity.

For example, with an existing identity at `$SSH_IDENTITY`:

```sh
KEY_DIR="$(mktemp -d)"
chmod 700 "$KEY_DIR"
ssh-keygen -y -f "$SSH_IDENTITY" > "$KEY_DIR/id_ed25519.pub"
```

Use argument arrays where an automation API supports them. The equivalent POSIX
invocation, after saving the returned certificate, is:

```sh
GIT_SSH_COMMAND="ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KEY_DIR/known_hosts -o CertificateFile=$KEY_DIR/id_ed25519-cert.pub -i $SSH_IDENTITY" \
  git clone -- "$SSH_REMOTE_URL"
```

PowerShell uses the same OpenSSH files and options:

```powershell
$env:GIT_SSH_COMMAND = "ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KeyDir/known_hosts -o CertificateFile=$KeyDir/id_ed25519-cert.pub -i $SshIdentity"
git clone -- $SshRemoteUrl
```

The certificate expires after at most 15 minutes and is never renewed
implicitly. Renew it against the same identity with `renew_ssh_certificate`.
If the private key was actually lost, provision a replacement identity
explicitly rather than treating certificate expiry as key loss. COG never
receives or recovers the client private key. Raw public keys, passwords, shells,
PTYs, forwarding, subsystems, arbitrary environment variables, and commands
other than exact upload-pack or receive-pack requests are rejected.

The embedded listener translates native SSH Git framing to the provider's smart
HTTP service in process. GitHub App JWTs and installation tokens remain inside
COG and never enter command arguments or subprocess environments. Request and
response streams are bounded and backpressured; certificate bindings and live
lease, integration, client, repository, and permission state are rechecked
immediately before provider I/O.

## Transport boundary

Agents use SSH exclusively. COG does not expose a downstream Git-over-HTTPS
route or issue Git passwords. HTTPS remains an internal upstream transport from
COG to GitHub; provider credentials never leave the COG process.

For incident response, revoke the agent's integration or OAuth client access,
disable or disconnect the integration, change the GitHub App repository
selection, or rotate the App key and update COG's encrypted `privateKey`.
Configuration changes, disconnect, and deletion invalidate cached installation
tokens. JWTs and installation tokens are memory-only.

COG rejects upstream userinfo, fragments, redirects, and DNS answers in private,
loopback, link-local, multicast, or unspecified ranges. Explicit loopback HTTP
is reserved for controlled local provider tests.
