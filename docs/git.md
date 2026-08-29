# Git over SSH with renewable key leases

SSH is the downstream Git transport. By default COG listens on
`127.0.0.1:2222`, derives the advertised host from `COG_BASE_URL`, and
advertises the listener port. Set `COG_SSH_LISTEN=0.0.0.0:2222` when exposing
the listener directly, or override the public port when a TCP proxy maps it.

An authorized MCP client first calls `repository_access`. Its versioned
`remotes` object reports the repository-specific SSH URL, pinned
`knownHosts` line, host-key fingerprint, and key-lease tools. The opaque
repository UUID is the only accepted SSH path.

Each agent reuses one existing Ed25519 identity from SSH configuration, the SSH
agent, or a standard identity path. The private key always remains local. The
agent sends only the exact canonical public key to `ssh_key_register`; COG
binds it to the authenticated OAuth agent and starts an internal authorization
lease. One agent cannot register a different key without an explicit future
rotation workflow, and a public key cannot belong to multiple agents.

Call `ssh_key_status` to inspect the registration and lease. Before expiry,
call `ssh_key_lease_renew` with the same public key. Renewal changes only
`lease_expires_at` in COG's database: it does not generate, sign, replace, or
return key material. An expired lease causes raw public-key SSH authentication
to fail until authenticated MCP renews it.

For example, with an existing identity at `$SSH_IDENTITY`, save the
`knownHosts` value returned by `repository_access` and use:

```sh
GIT_SSH_COMMAND="ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KEY_DIR/known_hosts -i $SSH_IDENTITY" \
  git clone -- "$SSH_REMOTE_URL"
```

PowerShell uses the same OpenSSH files and options:

```powershell
$env:GIT_SSH_COMMAND = "ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KeyDir/known_hosts -i $SshIdentity"
git clone -- $SshRemoteUrl
```

COG accepts only the `git` SSH username, registered Ed25519 public keys with
live leases, and exact upload-pack or receive-pack commands. Passwords, shells,
PTYs, forwarding, subsystems, arbitrary environment variables, and other
commands are rejected.

The embedded listener translates native SSH Git framing to the provider's smart
HTTP service in process. GitHub App JWTs and installation tokens remain inside
COG. The key lease, repository grant, integration state, OAuth-bound identity,
and COG ownership lease are rechecked immediately before provider I/O.

## Host authentication

COG's durable encrypted host key identifies the SSH server to agents. Clients
must pin the exact `knownHosts` entry returned by `repository_access`; never
disable host-key checking. The host key is independent of agent keys and is the
only private SSH key stored by COG.

## Incident response

Revoke an agent's repository grant or OAuth client access, disable or disconnect
the integration, expire its registered key lease, or rotate Cog's host key as
appropriate. A host-key rotation requires distributing the new pin. Agent key
rotation is intentionally not implicit: provision and authorize it explicitly
if the agent's private key is lost or compromised.
