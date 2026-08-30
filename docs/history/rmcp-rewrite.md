# Official Rust MCP SDK rewrite completion record

The flag-day rewrite was completed on 2026-08-30. Cog now uses the pinned
`rmcp` 3.1.4 SDK for downstream Streamable HTTP serving and upstream
Streamable HTTP and child-process transports. The former Cog-owned JSON-RPC
envelopes, lifecycle negotiation, request IDs, SSE parser, session state, and
stdio framing were deleted.

## Resulting architecture

- `src/mcp/server.rs` implements the dynamic `ServerHandler` surface.
- `src/server/mcp.rs` owns HTTP authentication, origin and rate checks,
  preflight authorization, body limits, and mounting the SDK service.
- `src/mcp/client/http.rs` and `src/mcp/client/stdio.rs` are thin SDK provider
  wrappers with bounded calls and safe-boundary discovery reconnects.
- MCP wire models come from `rmcp::model`; Cog extensions use reverse-DNS keys
  under `_meta`.
- `execute.integrations` declares the immutable integration IDs available to
  one V8 invocation. Cog preauthorizes the declared set and removes every
  undeclared integration from that invocation's runtime catalog.
- New integration configuration accepts only `http` and explicitly enabled
  `stdio`. Stored legacy `sse` rows remain visible as unsupported and include
  an actionable migration message.

## Behavioral verification

The replacement tests exercise SDK HTTP sessions, custom and bearer headers,
pagination, calls, cleanup, stdio initialization, persistent processes,
bounded and redacted diagnostics, safe discovery reconnect, call timeout
without side-effect retry, MCP 2026-07-28 discovery, negotiated legacy
initialization, hybrid/code-mode tool lists and instructions, namespaced
metadata, explicit integration declarations, authorization challenges, and
session cleanup through Cog's real Axum router.

The local completion gates pass:

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- frontend production build
- the full LLVM coverage sequence with the 95% line gate
- MinIO/S3 and installer interoperability suites
- `cargo audit --deny warnings`
- `cargo deny check licenses bans sources`

The baseline and dependency review are in `rmcp-baseline.md`. The remaining
`cargo deny check advisories` findings are the pre-existing
`rustyriver -> object_store 0.11 -> quick-xml 0.37` advisories and V8's
unmaintained `paste` build dependency. They have no clean upgrade in the MCP
rewrite's dependency scope and remain explicit release-policy decisions.

MCP Inspector and the official conformance suite require a running,
OAuth-provisioned deployment. Run and record them as release validation for
the deployed endpoint; they are not a reason to retain a shadow endpoint or a
second protocol implementation.
