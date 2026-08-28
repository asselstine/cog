# Clanker Operations Gateway (COG)

Cog is a self-hosted gateway that gives AI agents secure, governed access to tools.

Install on Linux or macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/actionllama/cog/main/install.sh | sh
```

Install on Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/actionllama/cog/main/install.ps1 | iex
```

Initialize cog, create the first user non-interactively, and start it:

```sh
cog
printf '%s\n' "$PASSWORD" | cog create-user owner@example.com --password-stdin
cog
```

The first command creates the native state directory and intentionally exits
until an owner exists. Open <http://localhost:4788> after the final command.
The default files are:

```text
~/.cog/master.key
~/.cog/data/cog.sqlite
```

The installers verify release checksums. Set `COG_VERSION` to pin a release
(for example `0.2.0` or `v0.2.0`) and `COG_INSTALL_DIR` to override the
destination.

## Deployment and configuration

Local SQLite is authoritative by default; S3 is used only when
`COG_S3_BUCKET` is configured. See [operations](docs/operations.md) for S3,
backup, restore, recovery, and master-key handling.

### Run with Docker

```sh
docker build -t cog .

docker run --rm \
  -p 4788:4788 \
  -v cog-data:/data \
  -e COG_S3_BUCKET=my-cog-bucket \
  -e COG_MASTER_KEY='at-least-32-random-secret-characters' \
  -e COG_BASE_URL='https://cog.example.com' \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  cog
```

Before starting cog, create a user with the same storage configuration the server will use:

```sh
cog create-user owner@example.com --password-stdin
```

The command reads one password line from standard input and uses the same storage mode as the server. With S3 configured it acquires the exclusive lease, restores the current database, and durably replicates the new user. It fails while another cog instance holds that lease, so stop the service before adding a user.

Then start cog and open the configured base URL to sign in. Agents connect to the streamable HTTP MCP endpoint at `/mcp` and complete the advertised OAuth flow.

The `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` environment
variables are a static credential set: cog reads them when it builds the S3
client and cannot renew them. For long-running AWS deployments, omit those
variables and use an EC2 instance role, or set both
`AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`. Those providers cache
temporary credentials only until shortly before expiration and renew them
in-process for lease maintenance, replication, restore, and orderly shutdown.
ECS task credentials and EKS Pod Identity are renewable as well.

AWS CLI profiles, IAM Identity Center/SSO, and `login_session` are not supported
credential providers. Setting `AWS_PROFILE` or mounting a shared AWS config file
does not enable refresh; use workload identity or inject a deliberately managed
static credential set instead.

Important configuration:

| Variable | Default | Description |
| --- | --- | --- |
| `COG_S3_BUCKET` | none | Optional S3 bucket name. When omitted, local SQLite is authoritative. |
| `COG_HOME` | `~/.cog` | Native state home (`%LOCALAPPDATA%\cog` on Windows). |
| `COG_MASTER_KEY` | generated | Optional explicit secret; otherwise stored in `<cog-home>/master.key`. |
| `COG_BASE_URL` | `http://localhost:4788` | Public origin used for OAuth metadata and callbacks. Use HTTPS in production. |
| `COG_LISTEN` | `127.0.0.1:4788` | HTTP listen address. Docker explicitly uses `0.0.0.0:4788`. |
| `COG_DATA_DIR` | `<cog-home>/data` | SQLite working-state directory. Docker explicitly uses `/data`. |
| `COG_S3_PREFIX` | `cog/` | Object prefix reserved for cog. |
| `COG_S3_ENDPOINT` | AWS endpoint | Custom S3-compatible endpoint. |
| `COG_S3_REGION` | `us-east-1` | S3 region. |
| `COG_S3_ALLOW_HTTP` | `false` | Permit plaintext S3 transport for local development only. |
| `COG_LEASE_TTL_SECS` | `30` | S3 ownership lease lifetime. |
| `COG_V8_HEAP_MB` | `128` | Heap limit for each fresh code-mode isolate. |
| `COG_EXECUTION_TIMEOUT_SECS` | `30` | Maximum code-mode execution time. |
| `COG_ALLOW_STDIO` | `false` | Explicit deployment policy allowing administrators to run configured local MCP commands. |
| `COG_SERVER_LOCAL_CALLBACKS` | `off` | Opt-in delivery of agent OAuth callbacks from the cog host: `off`, `auto`, or fail-closed `required`. |

### Add an integration

The admin API uses granular OAuth scopes. Connection reads require `integrations:read` and mutations require `integrations:write`; agent/token reads and mutations require `agents:read` and `agents:write`, and audit reads require `audit:read`. A new identity receives only the mandatory `mcp` capability by default:

```sh
curl -X POST "$COG_URL/api/integrations" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "github",
    "transport": "http",
    "config": { "url": "https://example.com/mcp" }
  }'
```

Supported configuration types are streamable HTTP/SSE and local stdio. Static HTTP headers can be supplied when creating an integration; they are encrypted before storage.

For upstream OAuth, add an `oauth` object. Clanker Operations Gateway discovers RFC 9728 protected-resource metadata, then supports both OAuth Authorization Server Metadata and OpenID Connect Discovery. Endpoints and a `client_id` may also be configured explicitly. When an authorization server advertises Client ID Metadata Document support, cog identifies itself with its stable `/.well-known/oauth-client` URL; otherwise it retains Dynamic Client Registration as a compatibility fallback. The protected metadata's exact `resource` URI is sent once in the authorization request and is bound to code exchange and refresh. Servers without protected-resource metadata can use an explicit `oauth.resource`; cog rejects a conflict rather than guessing which audience is correct. Resource URIs must be absolute, contain no userinfo or fragment, and use HTTPS except for loopback development.

`scope` remains optional. If neither integration configuration nor authorization-server metadata supplies scopes, cog omits it instead of assuming every MCP server accepts `mcp`. POST `/api/integrations/{id}/oauth/start` and open the structured `authorization_url` value without prefetching it. POST `/api/integrations/{id}/reconnect` for a full reauthorization: this clears stale registration metadata, pending state, and tokens before the next OAuth start. Changing integration configuration does the same.

GitHub Git integrations should be created with the native
`cog.github_app_setup_start` administration tool. It returns a one-time COG
browser URL that submits a GitHub App manifest, encrypts the generated private
key at callback, continues through installation and exact repository selection,
records the installation ID, and enables the integration. Progress is available
through `cog.github_app_setup_status`; neither tool returns App credentials.
See [Git smart HTTP](docs/git.md) for the complete flow and manual fallback.

Agent-to-cog authorization and cog-to-upstream authorization are separate trust relationships. A successful provider browser callback only connects one identity to that upstream. Every agent in the identity can use its enabled connections; durable capabilities and exact repository permissions are evaluated from current identity grants on every request.

## Development

The project requires stable Rust, Node.js with npm, Docker, and Docker Compose. V8 is downloaded as a prebuilt artifact by the `v8` crate during the first build. The Vite + React + Tailwind CSS application lives in `frontend`; Cargo installs its locked dependencies, builds it, and embeds the generated assets in the cog binary.

For frontend-only development, run `npm install` and `npm run dev` in `frontend`. The Vite development server proxies application requests to a local cog instance.

Run local checks:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run the S3 integration suite:

```sh
scripts/test-s3.sh
```

The script starts MinIO, creates an isolated bucket, runs the ignored S3 tests, and removes its containers and volumes. It does not use AWS credentials.

Measure coverage with:

```sh
cargo llvm-cov --all-targets --summary-only
```

CI requires 95% line coverage. The full CI sequence, including the instrumented MinIO process and takeover tests, currently measures 95.02% first-party line coverage.

## Deeper description

### Request path and code mode

The MCP endpoint defaults to code mode at `/mcp`. Connect to
`/mcp?codemode=false` to advertise every connected integration tool directly
under its immutable `<integration-id>.<tool-name>` name instead of advertising
the `execute` tool. COG administration tools remain available with their
`cog_` prefix in either mode. Directly advertised integration tools declare
their `integration:<id>` OAuth scope and use the same incremental-consent flow
as code mode.

An agent discovers cog's OAuth metadata and dynamically registers an untrusted OAuth client. During PKCE authorization the user selects or creates an identity; approval creates the durable agent binding. Tokens identify that agent, while current identity grants and connections determine access.

Dynamic client registration remains automatic and requires no registration credential. Clanker Operations Gateway limits registrations to 128-byte client names, 10 unique redirect URIs of at most 2,048 bytes each, and 16 KiB of metadata. It accepts at most 20 registration attempts per minute, reuses an identical recent unused registration, removes unused registrations after 24 hours, and retains at most 1,000 unused clients. Clients with retained tokens or a live authorization code are never removed by this cleanup.

Clanker Operations Gateway negotiates MCP `2025-11-25` and retains `2025-06-18` compatibility for clients and upstream servers. Each execution creates a fresh V8 isolate. The isolate has no filesystem, environment, process, socket, or unrestricted network APIs. Its only privileged host bridge is:

- `codemode.search(query)` performs case-insensitive literal substring matching (not semantic search) across names and descriptions without loading every schema. If a task phrase returns no matches, use `codemode.search("")` to enumerate the full catalog. Enabled integrations remain discoverable regardless of upstream connection or downstream grant state. Results report `upstreamConnected`, `upstreamStatus`, `clientAccessGranted`, and the exact OAuth `requiredScope`; describing or calling an ungranted integration produces only an `insufficient_scope` challenge so a capable host can request downstream incremental consent.
- `codemode.describe("integration-id.tool-name")` returns one tool's schema. Both `describe` and `call` require the immutable target returned by search, not an integration label or bare tool name.
- `codemode.call("integration-id.tool-name", arguments)` invokes the upstream MCP with credentials held outside V8.

Nested code-mode providers require two discovery layers. For Cloudflare-style integrations, first use cog's literal `codemode.search()` to find the integration's upstream `search` or execution tool and describe that immutable target. Then call the provider tool to locate and invoke the provider-specific operation; do not guess a provider operation as a cog target.

The isolate has a configurable heap limit. A watchdog uses V8's termination handle to interrupt CPU-bound or infinite code at the execution deadline.

### Users, OAuth, and credentials

Data is isolated first by user and then by identity. Downstream capabilities include `mcp`, `integrations:read`, `integrations:write`, `agents:read`, `agents:write`, `audit:read`, `git:read`, and `git:write`. Access-token scope is a protocol snapshot; authentication always joins token → agent → identity and reads live identity grants and enabled connections.

For progressive consent, protected-resource metadata advertises only the baseline `mcp` scope. Clanker Operations Gateway returns an HTTP 403 `insufficient_scope` challenge containing `mcp` and the exact newly required administration or `integration:<uuid>` scope. Retain the same MCP client registration, reauthorize with the accumulated scope set, and refresh that client's credential. A new process that creates a new dynamic registration is a different client, so grants do not transfer. Never use `integration_reconnect` to obtain downstream access; reconnect replaces cog's upstream provider credentials and cannot grant the calling client access.

Code-mode targets use immutable integration IDs, for example `<uuid>.tool_name`; discovery also returns `integrationLabel` for human-readable display. A token must contain both `mcp` and the matching `integration:<uuid>` grant. Adding or renaming an integration never expands an existing token. Deleted integrations disappear immediately, and a recreated integration has a new UUID and therefore requires fresh consent. Grant revocation updates existing access and refresh-token state immediately.

When granted the matching administration scope, code-mode discovery includes the built-in `cog` integration. The same operations are advertised natively with a `cog_` prefix and MCP safety annotations. Calling a native administration tool without its granular scope returns an OAuth `insufficient_scope` challenge so a capable host can request user consent and retry. The tools cover integration list/get/create/update/disconnect/authorize/enable-disable/delete, client and token listing/revocation, individual integration-grant revocation, and audit reads. Results redact headers, secrets, token material, and ciphertext. `cog.integration_disconnect` atomically removes upstream OAuth tokens, dynamic client secrets and metadata, pending PKCE state, and static authentication headers while preserving the immutable integration and every downstream grant. It is also available as `DELETE /api/integrations/{id}/credentials` and is idempotent. `cog.integration_authorize` attaches new credentials to that same integration; it returns `alreadyConnected` without a URL while valid credentials exist, and otherwise returns a one-time upstream authorization URL which must be opened by the user without prefetching. `integration_reconnect` is deprecated compatibility behavior for disconnect followed by authorization start and never reports success before new credentials are obtained. `integration_delete` is intentionally stronger: it permanently removes the integration ID and its downstream grants. None of these upstream operations grants an agent downstream access.

Clanker Operations Gateway is both an OAuth authorization server for agents and an OAuth client for upstream MCPs. Authorization codes and states are short-lived and single-use, and both directions use PKCE-S256. Upstream tokens and static credentials are encrypted with AES-256-GCM using a key derived from `COG_MASTER_KEY`. Plaintext credentials are never injected into generated code.

Device authorization is the preferred standards-based flow for multi-tenant deployments and untrusted clients. For a trusted agent running in the same network namespace as cog, `COG_SERVER_LOCAL_CALLBACKS=auto` can deliver the approved code directly to an exact registered `http://127.0.0.1` or `http://[::1]` callback. `auto` falls back to the standard browser redirect only if the connection fails before any callback bytes are sent; `required` never falls back. After any bytes containing the code are sent, cog reports uncertain delivery instead of attempting a second channel. The callback client bypasses proxies, follows no redirects, sends no cookies or authorization headers, and uses short timeouts and bounded response-header reads. Keep this extension `off` when clients are in separate containers/network namespaces or are not fully trusted.

### SQLite, LTX, and S3 ownership

Clanker Operations Gateway keeps its active database in embedded SQLite using WAL mode. Without `COG_S3_BUCKET`, the local database is authoritative and SQLite manages normal WAL checkpointing. With S3 configured, cog probes the bucket to confirm conditional creates and updates are enforced, then claims a compare-and-swap lease. A live lease is required for mutations and MCP execution.

Each new database records whether it is local-only or S3-backed. Clanker Operations Gateway refuses to start a local-only database with S3 configured, and refuses to start an S3 working copy without its bucket configuration. Databases created before this marker existed are treated as legacy S3 databases. Converting a local database to S3 therefore requires an explicit migration rather than an accidental configuration change.

Lease generations fence replication paths. Database state is encoded as immutable LTX v3 objects under the active generation, and a new owner restores the newest completed generation before opening SQLite. A stale process can write only beneath its older generation and cannot supersede a newer owner's state.

The replication engine keeps a dedicated SQLite capture connection open, disables automatic checkpoints, and converts committed WAL transactions into ordered Litestream-compatible LTX v3 level-zero segments. Mutation handlers wait for the covering segments to reach S3 before acknowledging success. Compaction, cross-process output-gate fault testing, and stronger durability testing remain before production use.

### Deployment model

There is no external SQL database, cache, queue, coordination service, or JavaScript worker service. Production consists of one cog process and a persistent local working directory, plus an optional S3-compatible bucket. Local stdio MCP integrations run as configured child processes; they are integrations rather than cog infrastructure.
