# SSH Git transport

## Completed

- [x] Embedded SSH server with durable encrypted Ed25519 host and user-CA keys.
- [x] Short-lived, repository- and identity-bound OpenSSH certificates issued
  through the authenticated `ssh_certificate` MCP operation.
- [x] Strict Git command, certificate, permission, integration, grant, lease,
  timeout, concurrency, streaming, and size validation.
- [x] Native SSH Git-to-provider smart-HTTP adapter without subprocesses or
  credentials in arguments, environments, logs, metrics, or MCP results.
- [x] SSH-only `repository_access` discovery with structured host pinning and
  client setup guidance.
- [x] Key inspection and rotation controls in the Vite administration UI.
- [x] SSH metrics, redacted audits, operations documentation, container/systemd
  configuration, fixtures, and CI release gates.
- [x] Stock OpenSSH certificate interoperability, parser/property tests, key
  persistence/rotation tests, S3 takeover tests, and Rust/frontend validation.
- [x] Remove the legacy downstream Git-over-HTTPS route, `sealed_credentials`
  MCP operation, `git-credential-cog` binary, `COG_GIT_ORIGIN`, credential
  storage/API code, packaging, tests, documentation, and dependencies.
- [x] Add schema migration 6 to delete legacy `git_credentials` records.

## External release gates

- [ ] Run and record the macOS and Windows OpenSSH release jobs.
- [ ] Build and smoke-test the release container with its published SSH port.
- [ ] Complete the focused security review before enabling SSH in production.
- [ ] Configure the production SSH listener, firewall/load balancer, host-key
  pins, readiness monitoring, and graceful takeover test during an approved
  deployment window.
