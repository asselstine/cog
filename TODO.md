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
