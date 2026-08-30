# RMCP flag-day baseline

Recorded on 2026-08-30 before the official Rust MCP SDK rewrite.

## Quality baseline

- `cargo fmt --all --check`: passed.
- `cargo clippy --all-targets -- -D warnings`: passed.
- `cargo test`: 145 tests passed; the 5 MinIO/S3 tests that require
  `tests/infrastructure/compose.yml` were ignored as designed.
- Toolchain: Rust and Cargo 1.98.0.

## SDK selection

`rmcp` 3.1.4 is the current crates.io release and declares Rust 1.88 as its
MSRV. Cog pins that exact release. Cog's direct `reqwest` dependency is aligned
to the SDK's 0.13 series. The dependency graph temporarily also contains
`reqwest` 0.12 through `object_store`; removing that version is outside the MCP
transport rewrite and depends on upstream storage compatibility.

## Legacy transport inventory

- Streamable HTTP is represented as `transport = "http"` in README examples,
  route tests, and integration records.
- Stdio is represented in `tests/fixtures/stdio-mcp.sh` and upstream transport
  tests, and remains deployment-policy gated.
- The obsolete two-endpoint HTTP+SSE transport is accepted by
  `server::administration::validate_transport`, instantiated by
  `mcp::service`, implemented by `mcp::client::HttpMcp::new_sse`, and exercised
  by `legacy_sse_discovers_endpoint_and_keeps_stream`. These are migration
  targets, not compatibility requirements.
- `git` is a product integration kind backed by Cog's SSH Git service; it is
  not an MCP upstream transport and is unaffected by removal of MCP SSE.

## Custom-wire tests to replace

- `tests/protocol/mcp.rs` directly constructs Cog `RpcRequest` envelopes and
  checks Cog's initialization negotiation and protocol errors.
- `tests/protocol/upstream.rs` checks hand-written request IDs, initialization,
  SSE parsing, cancellation notifications, and direct stdio JSON-line framing.
- `tests/server/routes.rs` checks the old downstream endpoint's protocol-header
  handling and response buffering, as well as legacy SSE configuration.
- Metadata assertions for top-level `securitySchemes` and `x-cog-*` fields
  have been migrated immediately to SDK annotations and reverse-DNS `_meta`
  keys; the removed top-level fields are now explicitly asserted absent.

These tests document the pre-rewrite boundaries. They should be replaced with
behavior tests through RMCP transports, not mechanically preserved.

## Dependency review result

- `cargo audit`: passed after adding RMCP.
- `cargo deny check`: license, source, and ban checks passed, but the advisory
  check remains red because `rustyriver 0.1.0` brings `object_store 0.11.2` and
  vulnerable `quick-xml 0.37.5` (RUSTSEC-2026-0194 and RUSTSEC-2026-0195).
  `paste 1.0.15`, brought by V8, is also flagged as unmaintained
  (RUSTSEC-2024-0436). Neither path was introduced by RMCP. These must be
  resolved or explicitly adjudicated before the final dependency gate can be
  marked green.
