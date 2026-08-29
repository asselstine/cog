# ADR 0001: Embedded SSH frontend for Git

- Status: accepted
- Date: 2026-08-28

## Decision

COG's target SSH transport is an embedded asynchronous SSH server in the COG
process. Clients generate Ed25519 private keys locally and send only canonical
public keys through authenticated MCP. COG binds one public key to each OAuth
agent and maintains a renewable internal authorization lease. Downstream Git
access is SSH-only; smart HTTP remains an internal provider transport.

The SSH frontend must authenticate registered public keys with live leases and turn an exact
`git-upload-pack '<repository UUID>'` or `git-receive-pack '<repository UUID>'`
exec request into calls to a transport-neutral Git service. It must not invoke a
shell. The key registration binds the authenticated user, identity, agent,
OAuth client, public-key fingerprint, and lease expiry. Live key leases,
database grants, integration state, and COG ownership are checked again
immediately before upstream I/O.

## Library assessment

`ssh-key` 0.6.7 is selected and pinned for Ed25519 private/public key support,
canonical parsing, fingerprints, a RustCrypto security
maintenance path, and dual Apache-2.0/MIT licensing. It is platform-independent
and its parsers are suitable for direct unit/property/fuzz coverage.

`russh` is the target server library: it supports embedded async servers,
Ed25519 host keys, raw public-key authentication, environment and exec
channel callbacks, channel-window backpressure, and cancellation without an
OpenSSH daemon or helper process. It is Apache-2.0 licensed and supports the
Windows Rust targets. It will be pinned when the listener lands, so this ADR
does not add a large unused dependency before the protocol adapter is complete.

Before release, both dependency trees are gates for `cargo audit`, RustSec,
license/source policy, Windows compilation, and fuzz testing.

## Protocol boundary

Native Git-over-SSH is not an HTTP request and cannot be piped into the Axum
smart-HTTP handler. For protocol v0/v1, the SSH service begins with the native
reference advertisement; smart HTTP adds a service preamble around discovery.
Protocol v2 carries `GIT_PROTOCOL=version=2` and exchanges multiple pkt-line
commands. Fetch and push require service-specific smart-HTTP discovery and POST
requests while preserving flush/delim packets, sideband progress, half-close,
EOF, cancellation, and upstream error semantics.

The adapter therefore owns framing conversion while sharing repository
resolution, authorization, GitHub installation-token minting, URL validation,
limits, timeouts, metrics, audit, and fencing with HTTP. Every stream remains
bounded and backpressured; the design must be reassessed if interoperability
requires buffering a complete pack.

## Key durability and rotation

The Ed25519 host key is stored in SQLite with private material encrypted by
COG's existing master-key envelope. Creation is transactional and converges on
one active host key. S3 replication acknowledgement is required before an
endpoint may advertise new key material. Rotation retains retiring host keys
for the operator's pin-overlap window. An unreadable key is a startup recovery
error and is never silently replaced.

Agent public keys are stored without private material. Their renewable leases
are authoritative server-side state and are durably replicated before an MCP
registration or renewal succeeds.

## Consequences

COG remains a single binary and can enforce authorization and lease fencing in
process. Client private keys and GitHub credentials never cross the MCP/SSH
boundary. The implementation is more involved than a byte proxy because it
must translate native Git service framing to GitHub smart HTTP. Environments
that block outbound SSH continue to use HTTPS with host and credential checks
unchanged.
