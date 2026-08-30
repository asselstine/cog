# File structure cleanup

Status: **planned**.

The goal is to make ownership and dependency direction visible from the file
tree without changing runtime behavior. Follow the useful part of celld's
layout: organize around real architectural boundaries, not an arbitrary maximum
file size. Keep Cog as one Rust crate during the initial reorganization; only
introduce a workspace if a genuinely independent, I/O-free core emerges.

## Preparation

- [ ] Record a clean baseline with `cargo fmt --all --check`,
  `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
- [ ] Inventory the public items, route groups, database methods, and test
  coverage associated with `src/server.rs` and `src/db.rs` before moving code.
- [ ] Keep structural moves separate from behavior changes so each change can
  be reviewed as a relocation with equivalent tests.

## Rust application structure

- [ ] Keep `src/server.rs` as a small facade containing the application state,
  child-module declarations, and server entry points; add implementation modules
  under `src/server/` without converting the facade to `src/server/mod.rs`.
- [ ] Extract startup orchestration, storage construction, HTTP listener setup,
  graceful shutdown ordering, and durability coordination into
  `src/server/startup.rs`. Keep lifecycle ownership there while delegating
  protocol-specific construction and serving to the owning feature module.
- [ ] Extract route assembly into `src/server/router.rs`; keep handlers in
  feature modules instead of adding more implementation to the router.
- [ ] Extract health, readiness, version, and metrics handlers into
  `src/server/health.rs`.
- [ ] Extract login, logout, cookies, browser sessions, CSRF checks, and browser
  authentication into `src/server/session.rs`.
- [ ] Extract only embedded Vite assets, the application shell/fallback, and
  static asset responses into `src/server/frontend.rs`. Keep UI bootstrap and
  mutation JSON endpoints with their owning administration/feature modules, and
  keep interactive screens and reusable UI components in `frontend/` as
  required by `AGENTS.md`.
- [ ] Separate downstream OAuth authorization-server routes from upstream
  integration OAuth flows, using `src/server/authorization_server.rs` and
  `src/server/upstream_oauth.rs`.
- [ ] Extract GitHub App setup, manifest callbacks, and installation callbacks
  into `src/server/github.rs`.
- [ ] Extract SSH binding, server configuration, connection, authentication,
  serving, and Git transport handling into `src/server/ssh.rs`; return a
  lifecycle handle to startup so `startup.rs` retains shutdown ordering and
  durability coordination. Leave transport-neutral Git logic under `src/git/`.
- [ ] Consolidate MCP ownership under a cohesive `src/mcp/` subsystem rather
  than concentrating it in one large file. Use this target layout:
  - `src/mcp.rs` remains the small public facade and child-module declaration
    point.
  - `src/mcp/protocol.rs` owns JSON-RPC request/response types and MCP
    initialize, list, and call dispatch.
  - `src/mcp/model.rs` owns the MCP tool wire model, annotations, and security
    schemes. Model `title` explicitly instead of relying on flattened extension
    data; reserve the flattened map for genuinely unknown or extension fields.
  - `src/mcp/catalog.rs` owns `ToolProvider`, `Catalog`, discovery, describe,
    invocation, namespacing, and advertisement transforms.
  - `src/mcp/service.rs` builds the authenticated catalog and owns the native,
    policy, measurement, and OAuth step-up provider composition.
  - `src/mcp/client/http.rs`, `src/mcp/client/stdio.rs`, and
    `src/mcp/client/auth.rs` own upstream MCP transports, session lifecycle,
    challenge parsing, and incremental-scope handling. Remove `src/upstream.rs`
    after its MCP-specific responsibilities have moved here.
  - `src/mcp/tools/mod.rs`, `execute.rs`, `admin.rs`, and `git.rs` own the full
    native tool surface, grouped by coherent feature rather than one file per
    small tool.
- [ ] Introduce one complete `NativeToolDefinition` and registry as the single
  source of truth for every native tool. Each definition must include a stable
  enum ID, namespace, wire name, title, description, input schema, annotations,
  required scope, and any runtime availability rule needed for advertisement.
  Resolve external names to the enum once and dispatch on that enum rather than
  repeatedly matching string names.
- [ ] Remove parallel native-tool registries and routing tables, including
  `admin::NAMES`, `git::NAMES`, name-to-scope matches, `native_target`,
  `admin_tool(name, description)`, and `git_control_tool(name, description)`.
  Registry methods should be the only implementation of public-name mapping,
  `cog_` prefixes, code-mode targets, required scopes, and conditional
  advertisement.
- [ ] Colocate every native tool's title, tool description, typed arguments,
  parameter descriptions, schema constraints, annotations, scope, availability,
  and dispatch adapter in its owning `src/mcp/tools/*.rs` module. Generate JSON
  Schema from typed argument structs if practical so the advertised schema and
  deserialized arguments cannot drift; otherwise keep a neighboring `schema()`
  function beside the argument type.
- [ ] Move `AdminProvider`, `GitControlProvider`, and execute invocation glue
  into their corresponding `src/mcp/tools/` modules. A handler should receive
  an already-resolved definition, authorize with that definition's scope,
  deserialize its typed arguments, invoke the domain operation, and return the
  result. Unknown tools and insufficient scope must remain distinguishable.
- [ ] Move shared administration, identity, integration, and Git behavior out
  of HTTP/server helpers into transport-neutral domain operations, for example
  focused `integrations`, `identity`, and `git` service modules. HTTP handlers
  and MCP tool adapters should both call those operations; domain services must
  not know about tool names, MCP schemas, JSON-RPC, or MCP authorization
  metadata.
- [ ] Reduce `src/server/mcp.rs` to the HTTP transport boundary: parse MCP query
  options, authenticate the bearer token, validate origin and protocol headers,
  apply HTTP-level limits, invoke the MCP service, and convert its response to
  Axum. It must not contain tool metadata, tool-name routing, scope maps, native
  provider implementations, catalog behavior, or upstream MCP client logic.
- [ ] Replace `runtime.rs`'s concrete `Catalog` dependency with a narrow MCP-owned
  host interface for `search`, `describe`, and `call`. The V8 runtime needs a
  privileged execution bridge but should not know how MCP catalogs, providers,
  or tool definitions are represented.
- [ ] Add registry-focused tests that iterate the real definitions and verify
  unique IDs and public names; non-empty titles and descriptions; documented
  parameters; object schemas that reject unknown fields; annotations and
  scopes; a dispatch handler for every definition; no unreachable handler;
  round-tripping of native prefixes and code-mode targets; conditional Git/SSH
  availability; and identical metadata across `tools/list`, code-mode search,
  and describe.
- [ ] Complete the MCP consolidation in reviewable stages: establish the model,
  IDs, typed arguments, and registry; move all metadata into definitions;
  switch advertisement, authorization, and routing to the registry; move native
  providers; extract shared domain operations; move the catalog and upstream
  clients; thin the HTTP endpoint; narrow the runtime bridge; then remove stale
  helpers, imports, and checklist entries.
- [ ] Treat the MCP consolidation as complete only when a production-code search
  for native names such as `repository_access` or `integration_disconnect`
  finds their definitions and handlers only under `src/mcp/tools/`. Outside
  `src/mcp/`, permit MCP tool concepts only at necessary boundaries such as the
  HTTP endpoint and runtime host bridge; tests and user-facing documentation are
  expected exceptions.
- [ ] Extract authenticated JSON administration endpoints into focused modules
  rather than one catch-all API file if integrations, identities, and tokens
  remain independently substantial.
- [ ] Review visibility after each extraction and make items private to their
  owning module unless they are part of Cog's intentional library/test API.

## Database structure

- [ ] Keep `src/db.rs` as a small facade retaining the `Database` handle, shared
  transaction primitives, and child-module declarations; add implementation
  modules under `src/db/` without converting the facade to `src/db/mod.rs`.
- [ ] Move schema versions and migration execution into
  `src/db/migrations.rs` without changing migration order or transaction
  boundaries.
- [ ] Colocate database row/domain types with their owning feature module;
  avoid a generic `models.rs` dumping ground.
- [ ] Move user, identity, and agent persistence into `src/db/identity.rs`.
- [ ] Move browser sessions, OAuth clients, authorization codes, tokens, and
  client grants into `src/db/oauth.rs`.
- [ ] Move integration, connection, secret, GitHub App setup, and upstream OAuth
  persistence into `src/db/integrations.rs`.
- [ ] Move Git repository, grant, and pending-request persistence into
  `src/db/git.rs`.
- [ ] Move host and agent SSH-key persistence into `src/db/ssh.rs`.
- [ ] Move audit-event persistence and queries into `src/db/audit.rs`.
- [ ] Preserve operations that must be atomic as single `Database` methods or
  explicit transactions; do not split transaction ownership merely to shorten
  files.

## Frontend structure

- [ ] Reduce `frontend/src/main.jsx` to application mounting and global style
  imports.
- [ ] Move top-level routing/state selection into `frontend/src/App.jsx`.
- [ ] Move `Login`, `Consent`, `Dashboard`, and
  `GitHubInstallationComplete` into `frontend/src/screens/`.
- [ ] Move `Shell`, `Permission`, `Pills`, and future reusable UI into
  `frontend/src/components/`.
- [ ] Centralize JSON requests and consistent error handling in
  `frontend/src/api.js` rather than duplicating fetch behavior across screens.
- [ ] Add frontend linting and tests if the split introduces enough independent
  UI logic to justify them; do not add tooling solely for directory symmetry.

## Separate operational and repository cleanup

These tasks are intentionally independent of the module reorganization so
structural commits remain reviewable and operational state is not changed as a
side effect of source moves.

- [ ] Verify whether the ignored literal `~/rexec-data/` directory is used by
  any process or configuration, then move or remove it from the checkout as a
  separate operational cleanup.
- [ ] Clean generated build trees (`target/`, `fuzz/target/`,
  `frontend/node_modules/`, and `frontend/dist/`) only when they are not needed;
  keep all of them ignored and do not make cleanup a refactoring prerequisite.

- [ ] Move `SCALING.md` to `docs/design/scaling.md` and
  `FUTURE_ENVELOPE_ENCRYPTION_PLAN.md` to a clearly named `docs/design/` or
  `docs/plans/` location, then update inbound links.
- [ ] Move completed historical reports out of the active TODO list after this
  cleanup is complete, retaining useful evidence in `docs/history/` if it is
  still valuable.
- [ ] Reconcile the differing `audit.toml` and `.cargo/audit.toml` files into
  one verified configuration used by local development and CI.
- [ ] Remove the empty `src/bin/` directory.
- [ ] Keep root-level installer files where stable download URLs require them;
  avoid moving deployment artifacts merely for visual symmetry.
- [ ] Add a concise repository-layout section to `README.md` after the new
  structure settles.

## Test alignment and verification

- [ ] Add focused tests for the native MCP definition registry: tool names are
  unique, every advertised native tool has a schema and annotations, and
  preauthorization uses the required scope stored in the same definition.
- [ ] Mirror the new server and database feature boundaries in the existing
  integration-test modules while retaining a small number of Cargo test
  targets to avoid unnecessary build/link overhead.
- [ ] Keep route behavior tested through `build_router` and HTTP requests; do
  not expose private handlers solely to make the reorganization testable.
- [ ] Run `cargo fmt --all --check`,
  `cargo clippy --all-targets -- -D warnings`, and `cargo test` after each
  independently reviewable extraction.
- [ ] Run the frontend production build and verify that Cargo still embeds the
  generated Vite output.
- [ ] Run the MinIO/S3, installer, SSH interoperability, coverage, and Gitleaks
  CI paths before declaring the reorganization complete.
- [ ] Reassess a Cargo workspace only after the split. Create a separate core
  crate only if policy/protocol decisions form a stable boundary with no I/O,
  clocks, randomness, locks, or runtime dependencies.

# Test-source separation

Status: **complete**.

The production Rust tree previously contained 18 `#[cfg(test)]` modules, 143 test
attributes, and approximately 9,824 lines from those module boundaries through
the ends of their files. The largest migrations are `src/server.rs` (about
5,456 lines), `src/db.rs` (822), `src/upstream.rs` (676), `src/mcp.rs` (450),
and `src/git/ssh.rs` (401). Test fixtures are also embedded in those modules,
including the GitHub App private key reported by Gitleaks, OAuth/HTTP mock
servers, in-memory providers, generated LTX payloads, and inline stdio scripts.

Moving the modules verbatim is not sufficient: integration tests in `tests/`
cannot access private items through `super::*`. Preserve encapsulation by
testing public behavior wherever possible and add or reshape production APIs
only when they are useful runtime seams, not test-only back doors.

## Migration TODOs

- [x] Create a small number of integration-test targets under `tests/` (for
  example `core.rs`, `protocol.rs`, `git.rs`, and `server.rs`) with subordinate
  modules and reusable helpers under `tests/common/`; keep static data and
  executable mock programs under `tests/fixtures/`.
- [x] Move the smaller public-API suites first: `authz.rs`, `config.rs`,
  `crypto.rs`, `db.rs`, `lease.rs`, `oauth.rs`, `runtime.rs`,
  `git/grants.rs`, `git/model.rs`, `git/service.rs`, and the public portions of
  `git/ssh.rs`.
- [x] Migrate the parser and storage-internal suites in `ltx.rs`, `mcp.rs`,
  `diagnostics.rs`, `upstream.rs`, and `git/pack.rs`. Rewrite assertions around
  public entry points where practical; otherwise extract narrowly scoped,
  production-meaningful parser or codec APIs rather than making internals
  public solely for tests.
- [x] Migrate `git/providers/github.rs` to a provider integration suite using
  its public constructor and `GitProvider` behavior, with the mock GitHub HTTP
  service implemented in `tests/common/`.
- [x] Break the `server.rs` migration into focused route suites (OAuth,
  administration, MCP, GitHub App, assets/health, and SSH). Introduce a public
  router/application construction seam with explicit dependencies, then drive
  private handlers through HTTP instead of exporting them or reconstructing
  application screens in Rust.
- [x] Consolidate duplicated helpers now embedded in `server.rs` and
  `upstream.rs`: temporary app/database setup, request/response helpers, Axum
  mock servers, fake `ToolProvider` implementations, callback listeners, and
  stdio process fixtures.
- [x] Move test drivers and infrastructure that are still outside `tests/`
  (`tests/infrastructure/test-s3.sh`,
  `tests/infrastructure/test-installers.sh`, and
  `tests/infrastructure/compose.yml`) into a clear `tests/` support/infrastructure layout, then
  update CI and documentation paths. Keep `fuzz/` separate because it is a
  Cargo fuzzing target rather than application test code.
- [x] Replace committed secret-shaped fixtures instead of merely relocating
  them: generate the GitHub App signing key at runtime, generate one master key
  per test and pass it to every process that must share it, and avoid literal
  credential-shaped diagnostic samples when an assembled/runtime value tests
  the same behavior.
- [x] Remove obsolete entries from `.gitleaksignore` after the fixture cleanup
  and run the same Gitleaks mode used by GitHub Actions. If the CI configuration
  intentionally scans historical commits, handle historical fixture findings
  explicitly rather than adding broad path or rule exclusions.
- [x] Update the `ssh-interop` job to run the new integration-test target and
  filter;
  update coverage and S3/install test commands for the relocated targets and
  scripts.
- [x] Delete every `#[cfg(test)] mod tests` block and all test-only helpers,
  fixtures, imports, and dependencies from `src/` after its replacement suite
  passes.
- [x] Add a CI guard that fails when `src/` contains `#[cfg(test)]`, `#[test]`,
  `#[tokio::test]`, or test fixture files, so test code cannot drift back into
  production sources.

## Migration verification

- [x] Confirm `rg` finds no Rust test modules or test attributes under `src/`.
- [x] Run `cargo fmt --all --check`.
- [x] Run `cargo clippy --all-targets -- -D warnings`.
- [x] Run `cargo test` on every supported platform, including the relocated
  stock OpenSSH interoperability suite.
- [x] Run the relocated MinIO/S3 and installer suites.
- [x] Run
  `cargo llvm-cov report --no-default-ignore-filename-regex --fail-under-lines 95`
  and retain at least the
  current 95.25% line coverage.
- [x] Run Gitleaks with the GitHub Actions configuration and confirm that the
  private-key and generic-api-key findings are gone without broad allowlists.

# Test coverage completion report

Status: **complete**.

The full CI coverage sequence now measures **95.26% line coverage**:
**18,135/19,037 lines covered**, with **902 uncovered lines**. This is a
measured improvement from the original **86.40%** baseline and leaves 49 lines
of headroom over the 95% CI gate.

## Completed work

- [x] Regenerated the baseline and final reports from clean LLVM coverage
  instrumentation.
- [x] Kept tests deterministic with temporary databases, in-memory object
  stores, in-process Axum fixtures, local MinIO, and local SSH/Git processes.
- [x] Added unit coverage for authorization, configuration/crypto failure
  paths, diagnostics redaction/classification, Git helpers, MCP validation,
  OAuth, runtime limits, upstream scope challenges, and database lifecycles.
- [x] Added database coverage for identities, agents, grants, tokens, OAuth
  state, refresh rotation, integration updates, migrations, storage modes,
  audit records, Git grants, and GitHub App setup transitions.
- [x] Added HTTP coverage for login/session behavior, OAuth registration and
  consent, token exchange/revocation, MCP protocol and scope boundaries,
  administration APIs, UI mutations, readiness, metrics, and frontend assets.
- [x] Added provider coverage for upstream OAuth discovery/callback/rotation,
  GitHub App manifest and installation callbacks, GitHub repository lookup,
  policy filtering, and bounded/redacted failures.
- [x] Added production SSH coverage with stock OpenSSH for certificate
  authentication, upload-pack, receive-pack, invalid users/commands, raw-key
  rejection, revoked grants, shell rejection, metrics, and audit outcomes.
- [x] Made instrumented onboarding processes shut down cleanly so subprocess
  coverage profiles are flushed reliably.
- [x] Ran the instrumented MinIO lease, replication, takeover, and SSH-key
  persistence suite.

## Verification

- [x] `cargo fmt --all --check`
- [x] `cargo clippy --all-targets -- -D warnings`
- [x] `cargo test` (145 migrated tests plus onboarding and non-instrumented targets)
- [x] `cargo llvm-cov clean --workspace`
- [x] `cargo llvm-cov --all-targets --no-report`
- [x] `COG_COVERAGE=1 tests/infrastructure/test-s3.sh`
- [x] `tests/infrastructure/test-installers.sh`
- [x] `cargo test --test onboarding`
- [x] `cargo llvm-cov report --no-default-ignore-filename-regex --fail-under-lines 95`
- [x] Confirmed the requested 95.25% headroom target with the exact final
  report.

## Optional future coverage

The original stretch items—deeper fault injection, additional takeover races,
abrupt SSH disconnect/backpressure cases, and pursuing 97%—remain optional and
are not required for the completed 95% coverage objective.
