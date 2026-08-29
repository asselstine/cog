# Test coverage completion report

Status: **complete**.

The full CI coverage sequence now measures **95.25% line coverage**:
**17,290/18,152 lines covered**, with **862 uncovered lines**. This is a
measured improvement from the original **86.40%** baseline and leaves 45 lines
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
- [x] `cargo test` (143 unit tests plus onboarding and non-instrumented targets)
- [x] `cargo llvm-cov clean --workspace`
- [x] `cargo llvm-cov --all-targets --no-report`
- [x] `COG_COVERAGE=1 scripts/test-s3.sh`
- [x] `scripts/test-installers.sh`
- [x] `cargo test --test onboarding`
- [x] `cargo llvm-cov report --fail-under-lines 95`
- [x] Confirmed the requested 95.25% headroom target with the exact final
  report.

## Optional future coverage

The original stretch items—deeper fault injection, additional takeover races,
abrupt SSH disconnect/backpressure cases, and pursuing 97%—remain optional and
are not required for the completed 95% coverage objective.
