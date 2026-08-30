# Scaling Clanker Operations Gateway

## Current architecture

COG is currently a single-writer service. In S3 mode, one process acquires an
exclusive lease for the configured bucket and prefix, restores the durable LTX
chain into a local SQLite working copy, and serves requests while it continues
to hold that lease. Mutations are captured from SQLite's WAL and uploaded as
LTX objects. A second ordinary COG process using the same bucket and prefix
cannot start while the lease is live.

This provides clear ownership and failover semantics, but it is not a
read-replica topology. S3 is the durable source of truth and takeover medium,
not currently a live replication feed consumed by multiple serving instances.

## Do normal operations require writes?

Most MCP work does not inherently require a durable COG mutation. Tool
discovery reads configuration, and a tool call normally performs its side
effect at the upstream MCP provider rather than in COG's database.

However, the current authentication path turns every authenticated request
into a local SQLite write. `auth_context()` calls `token_context()`, which
updates `oauth_tokens.last_used_at` for the bearer token. This includes normal
MCP discovery and upstream tool calls.

That access-time update is not synchronously uploaded to S3 after every MCP
request. It can remain in the local WAL until a later durability sync or an
orderly shutdown. Explicit administrative and OAuth mutations generally call
`persist()` and require an LTX durability proof before success is acknowledged.

Other operations that write COG state include:

- Upstream OAuth access-token refresh and refresh-token rotation.
- Downstream OAuth registration, authorization, token issuance, refresh, and
  revocation.
- Browser login, logout, and session management.
- Integration, client, token, and grant administration.
- Audit records associated with authentication and administrative operations.

## Proposed topology

A useful horizontal scaling model is one authoritative writer plus multiple
read-serving replicas:

```text
                         +-- read replica
clients -- load balancer +-- read replica
             |           +-- read replica
             |
             +-------------- writer
                                |
                          SQLite WAL -> LTX -> S3
```

The writer would retain the exclusive S3 lease and remain the only process
allowed to mutate durable COG state. Each replica would:

- Use its own local SQLite working copy.
- Avoid acquiring or renewing the writer lease.
- Follow new immutable LTX objects from the writer's current generation.
- Apply LTX changes in order and expose its applied TXID and replication lag.
- Open the serving database read-only, preferably with SQLite `query_only`
  enabled as an additional safeguard.
- Reject or proxy writer-only operations.
- Stop serving security-sensitive requests when lag exceeds a configured
  threshold.

COG does not currently implement this replica mode or continuous LTX following.

## Request routing

| Request class | Replica-safe | Notes |
| --- | --- | --- |
| Health, public metadata, and static UI | Yes | No application-state mutation. |
| Tool discovery | Yes, after access-time writes are removed | Reads integrations, grants, and schemas. |
| Read-only administration | Yes, subject to lag policy | Results may be stale. |
| Upstream tool calls | Usually | COG state is normally read-only, although the upstream tool itself may mutate upstream state. |
| Upstream OAuth refresh | No | Refresh may replace encrypted access and refresh tokens. |
| Downstream OAuth flows | No | Creates or changes clients, codes, tokens, and grants. |
| Integration and client administration | No | Mutates durable COG configuration. |
| Browser login and logout | No, currently | Creates or removes sessions and records audit events. |

The load balancer can route public and replica-safe requests to any sufficiently
caught-up replica. It should route state-changing requests to the writer.
Replicas may either proxy a request that unexpectedly needs a write or return a
response that causes the client to retry against the writer.

## Required changes

### Make the common MCP path read-only

`last_used_at` should not require a transaction for every authenticated
request. It is operational metadata rather than authorization state. Possible
alternatives are:

- Remove it.
- Coalesce updates in memory and periodically flush them through the writer.
- Send best-effort usage events to the writer.
- Record at most one update per token during a coarse interval, such as an
  hour.

Best-effort, coalesced usage reporting preserves the useful timestamp without
making it part of the critical request path.

### Add an explicit replica mode

Replica mode needs different startup and fencing behavior from an ordinary S3
instance. A replica must not contend for `lease.json`, publish LTX, create a new
generation, run migrations, or perform local mutations. It must identify the
valid completed generation, follow its subsequently published LTX objects, and
apply them strictly in TXID order.

The implementation must also handle database readers while applying WAL
changes. Options include applying changes through a dedicated SQLite/WAL
mechanism or building a new local database and atomically switching serving
generations. The design should never expose a partially applied transaction.

### Centralize upstream OAuth refresh

A replica can use an unexpired upstream access token, but it must not rotate
credentials when that token expires. Exactly one authority should refresh and
persist the replacement. A replica should request a usable credential from the
writer or route the affected tool call to the writer, then wait until the new
credential reaches its local view.

This also avoids several replicas independently using the same refresh token,
which can fail with providers that rotate or single-use refresh tokens.

### Define revocation consistency

Replication lag is security-sensitive. A stale replica might temporarily
accept a revoked downstream token, a revoked integration grant, or an
integration that has been disconnected or deleted. Viable safeguards include:

- Enforcing a small maximum TXID or wall-clock lag and failing closed beyond
  it.
- Pushing revocation events to replicas immediately.
- Checking token and grant validity against the writer or a strongly
  consistent shared authorization cache.
- Routing especially sensitive operations through the writer.

The lag contract must be explicit. Ordinary stale reads may be acceptable;
stale authorization decisions often are not.

## Alternative: stateless execution workers

A simpler first scaling step is to keep one COG state authority and move
expensive code execution and upstream I/O to stateless workers. The authority
would authenticate requests, resolve integrations and credentials, and perform
all durable mutations. Workers would run V8 and communicate with upstream MCP
servers using narrowly scoped, short-lived work descriptions.

This avoids live SQLite replication and stale authorization decisions while
scaling the parts of the request path most likely to consume CPU, memory, and
connections. It does add an internal protocol and requires care not to expose
long-lived provider credentials unnecessarily.

## Recommended sequence

1. Decouple `last_used_at` from bearer-token validation so normal MCP traffic
   is locally read-only.
2. Measure whether the limiting resource is V8 execution, upstream network
   concurrency, provider-session management, or SQLite.
3. Add stateless execution workers if execution and upstream I/O are the main
   bottlenecks.
4. Add an explicit LTX-following replica mode if independent read-serving COG
   instances are still needed.
5. Before replicas serve authenticated traffic, implement centralized OAuth
   refresh and a fail-closed revocation-lag policy.

COG likely does not need horizontal write scaling: durable configuration and
OAuth mutations should remain relatively infrequent. The useful scaling target
is the read and execution plane while preserving one clear authority for
credentials, authorization, and durable state.
