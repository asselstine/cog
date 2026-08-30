# File structure cleanup record

The reorganization started from a clean baseline on 2026-08-30:

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

All three commands passed before files moved. The server inventory contained the
application state and lifecycle types in `src/server.rs`, with route groups for
health/assets, browser sessions, downstream OAuth, upstream OAuth, GitHub App,
administration, MCP, and SSH. Those groups are now represented by sibling
modules under `src/server/`, and route behavior remains exercised through the
public router construction seam in `tests/server/`.

The database inventory consisted of the `Database` handle, row/domain types,
migrations, and persistence methods for identity, OAuth, integrations, Git,
SSH, and audit data. Persistence implementations now live under `src/db/`, with
the facade retaining the shared connection and transaction primitives. The
existing database integration suite continues to cover migrations and each
feature group through the public `Database` API.

The final MCP ownership split keeps wire models, protocol dispatch, catalog
behavior, service composition, upstream clients, and native tools in distinct
`src/mcp/` modules. Native definition metadata and dispatch share one enum-based
registry, and the V8 runtime consumes only the MCP runtime-host interface.
