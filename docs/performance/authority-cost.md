# Authority cost per request

Part of #439. This page counts, from the source, which cluster-mode request
paths talk to PostgreSQL, how many pool checkouts, statements and network round
trips each one spends, and how to read the series that separates waiting for a
connection from the work done on it. It publishes no latency numbers. Measured
capacity scenarios are the next step of #439, and results from a target
environment remain a qualification item under #389; nothing here is a
production SLO.

Standalone mode has no shared authority and spends no PostgreSQL round trips on
any request. Everything below is cluster mode (`STATE_BACKEND=postgres`), and
every read below goes to the writable primary. Moving any of them to a lagging
read replica is outside the scope of this work: the primary is the security
authority.

## What a round trip is here

- **A checkout** is one `deadpool_postgres::Pool::get` through the shared
  boundary in [`storage/postgres.rs`](../../gateway/src/storage/postgres.rs)
  (`checkout`). It waits for a free slot when every connection is in use, then
  either recycles an idle connection, which costs one `ROLLBACK` round trip
  (`build_pool` sets `RecyclingMethod::Custom("ROLLBACK")`, sent over the
  simple query protocol), or opens a new one, which costs a TCP connect, TLS
  and session startup. The wait is bounded by `DATABASE_ACQUIRE_TIMEOUT_MS`;
  creating and recycling are bounded by `DATABASE_CONNECT_TIMEOUT_MS`. A
  checkout that fails is classified exactly as before and refuses the caller,
  which answers `503`.
- **A statement** is one SQL statement a store sends on the held connection.
  What it costs depends on how it is sent:
  - Every parameterized or row-returning statement on these paths is passed
    to tokio-postgres as SQL text, through `query`, `query_one`, `query_opt` or
    `execute`. Nothing in `gateway/src/storage` prepares a statement ahead of
    time or uses `prepare_cached`. For SQL text, tokio-postgres 0.7 first
    prepares the statement (`Parse`, `Describe`, `Sync`) and waits for its
    parameter and row descriptions, then binds and executes it (`Bind`,
    `Execute`, `Sync`) and waits for the rows. That is **two** round trips,
    one after the other. The prepared statement is closed when it is dropped:
    that `Close` is written to the connection without waiting for an answer,
    so it is pipelined ahead of the connection's next message rather than
    adding a wait. (The driver's documentation counts the same path as "three
    round trips (for prepare, execute, and close)"; the close is the one
    nothing waits on.) Every type these statements bind or return is a
    built-in PostgreSQL type, so none of them adds a catalog lookup.
  - `BEGIN`, `COMMIT` and `ROLLBACK` go through `batch_execute`, the simple
    query protocol: **one** round trip each.
- **The rule the tables use**, on a warm pool: one round trip per checkout
  (the recycle), two per SQL-text statement, one per `BEGIN` or `COMMIT`. A
  checkout that has to open a connection replaces its recycle with the connect,
  TLS and startup exchanges, which is several round trips.
- Every authority call takes its own checkout and returns the connection when
  it finishes. Within one request the calls run one after another, in
  middleware order, so the counts below add up, and every round trip waits for
  the one before it.

## Summary

Steady state: the replica's compiled security revision is current, the shared
rate-limit bucket already exists, and no policy rate-limit rule matches. Each
row lists the checkouts made before the response is produced, in order, by
operation class.

| Path | Checkouts | Statements | Round trips | Classes, in order |
| --- | ---: | ---: | ---: | --- |
| Protected HTTP route, JWT carrying `jti` | 3 | 3 | 9 | `rate_limit`, `credential_check`, `revision_check` |
| Protected HTTP route, JWT without `jti` | 2 | 2 | 6 | `rate_limit`, `revision_check` |
| Protected HTTP route, service token, cached verification | 3 | 3 | 9 | `rate_limit`, `revision_check`, `revision_check` |
| Protected HTTP route, service token, verification miss | 4 | 4 | 12 | `rate_limit`, `revision_check`, `credential_check`, `revision_check` |
| MCP `tools/call`, JWT carrying `jti`, tool without its own concurrency limit | 4 | 4 | 12 | `rate_limit`, `credential_check`, `revision_check`, `execution_lease` |
| Admin policy write (`PUT /v1{ADMIN_PREFIX}/policy`), admin session over a token carrying `jti` | 5 | 12 | 27 | `rate_limit`, `credential_check`, `revision_check`, `security_state_read`, `control_plane_write` |

Every statement in the first five rows is SQL text, so each of those checkouts
costs three round trips: the recycle, the prepare and the execute. The admin
policy write is four such checkouts and one commit checkout of fifteen (see
[Admin mutations](#admin-mutations)).

Add one checkout, one statement and three round trips wherever a policy
rate-limit rule matches the request, and the costs in
[When the replica is behind](#when-the-replica-is-behind) when it is not
current. A service-token verification for a revoked, expired or unknown token
is two statements rather than one, so five round trips for that checkout rather
than three.

## The shared front

These run in this order (`routing.rs::apply_middleware`; later layers run
earlier).

| Layer | When it consults the authority | Checkouts | Statements | Round trips | Class | Operation |
| --- | --- | ---: | ---: | ---: | --- | --- |
| Global rate limit, [`middleware/rate_limit.rs`](../../gateway/src/middleware/rate_limit.rs) `rate_limit_request` | Every request the local limiter allowed, except `/health`, `/livez`, `/readyz`, `/startupz` and `/metrics` | 1 | 1 | 3 | `rate_limit` | `rate_limit_decide` |
| Authentication, [`middleware/auth.rs`](../../gateway/src/middleware/auth.rs) | Depends on the credential; see below | 0-2 | 0-3 | 0-8 | see below | see below |
| Policy rate limit, `policy_rate_limit_request` | Only when a policy rate-limit rule matches the principal, method and path | 1 | 1 | 3 | `rate_limit` | `rate_limit_decide` |
| RBAC gate, [`middleware/rbac.rs`](../../gateway/src/middleware/rbac.rs) through `ClusterSecurityRuntime::admit` | Protected data-plane and MCP routes; admin routes use the admin gate instead | 1 | 1 | 3 | `revision_check` | `policy_revision_read` |

A local-limiter denial spends no round trip. A decision that creates a new
bucket and pushes the live count past `RATE_LIMIT_MAX_BUCKETS` adds one bounded
eviction: one more checkout and statement (`rate_limit_evict`, three more round
trips), taken while the decision's own connection is still held, so that
request briefly holds two connections.

### Credentials

- **JWT bearer.** Signature and claims are verified in process. A token that
  carries a `jti` (required with `JWT_REQUIRE_JTI`) is looked up in the shared
  denylist: one checkout, one statement, three round trips
  ([`postgres_jwt_revocations.rs`](../../gateway/src/storage/postgres_jwt_revocations.rs)
  `is_revoked`, class `credential_check`, operation `jwt_revocation_lookup`).
  A token without one costs nothing here.
- **Service token** (`ggw_` prefix). The validator reads the security revision
  on every request (class `revision_check`, operation `policy_revision_read`,
  three round trips), then serves a cached verification only if it was made at
  that same revision and is inside `SERVICE_TOKEN_CACHE_TTL_MS`. Otherwise it
  verifies: one checkout, then one `UPDATE ... RETURNING` for a live token
  (three round trips in all), or that plus one `SELECT` to say why a token is
  not live (five)
  ([`postgres_service_tokens.rs`](../../gateway/src/storage/postgres_service_tokens.rs)
  `verify`, class `credential_check`, operation `service_token_verify`).
  Because the cache is keyed by the shared revision, any control-plane commit
  anywhere in the deployment makes the next request for every cached token a
  verification. A service-token request therefore reads the revision twice:
  once in the validator and once in the gate.
- **Admin session cookie.** The session table is held in process
  ([`auth/admin_session.rs`](../../gateway/src/auth/admin_session.rs)), but
  each request re-validates the token the session was issued for through the
  admin login provider's JWT validator, revocation store included. A session
  therefore costs what its token costs: one revocation lookup (three round
  trips) when that token carries a `jti`, nothing otherwise. The OIDC login
  that issues a session uses the pending-login store, which is not on this
  page.

### When the replica is behind

The gate reads the counter, and if the replica's compiled revision is behind,
reconciles inline within `RECONCILE_DEADLINE` (250 ms) before admitting
([`security_cluster.rs`](../../gateway/src/security_cluster.rs)
`admit_bounded`). One pass reads each registered resource's activation
revision, fetches the ones that moved, and reads the counter again:

| Resource | Activation read | Fetch when it moved | In the acquisition series |
| --- | --- | --- | --- |
| Policy | `active()`: the whole active document, parsed and re-hashed | `active()` again | yes, `security_state_read` |
| Service tokens | `state_revision()` | `state_revision()` again, then the verification cache is cleared | yes, `security_state_read` |
| Tools document | `active_tools()`: the whole active document | `active_tools()` again | no |
| Connections | `state_revision()` | the state revision, every record, the managed MCP and OpenAPI catalogs, and any queued dependency rows | no |

The policy and service-token reads are one checkout and one SQL-text statement
each, so three round trips apiece, and the counter re-read is three more. The
tools and connections reads follow the same rule per statement.

A commit that lands mid-pass sends the pass round again, still inside the same
deadline; running out of it is `503`. A request that finds a pass in progress
waits on its lock and, if that pass caught the replica up, is admitted without
running one of its own. The background poller
normally gets there first: it reads the counter every `RECONCILE_POLL_INTERVAL`
(250 ms) and runs the same pass, so a request pays this only when it arrives
between a commit and the next poll.

## MCP tool calls

An MCP request passes through the same front, including the RBAC gate. The MCP
handler itself ([`mcp.rs`](../../gateway/src/mcp.rs)) does not touch
PostgreSQL; `initialize` and `tools/list` cost the front and nothing more.

`tools/call` admits through the tool runtime
([`tools/runtime.rs`](../../gateway/src/tools/runtime.rs)), which in cluster
mode leases its concurrency slots from the authority
([`postgres_execution_leases.rs`](../../gateway/src/storage/postgres_execution_leases.rs),
class `execution_lease`):

| Step | When | Checkouts | Statements | Round trips | Operation |
| --- | --- | ---: | ---: | ---: | --- |
| Per-tool lease | Only for a tool with its own concurrency limit; taken first | 1 per attempt | 1 per attempt | 3 per attempt | `execution_lease_acquire` |
| Global lease | Every invocation | 1 per attempt | 1 per attempt | 3 per attempt | `execution_lease_acquire` |
| Renewal | Every `TOOL_LEASE_TTL_MS / 3` per held lease, while the tool runs | 1 | 1 | 3 | `execution_lease_renew` |
| Release | Once per held lease, from a spawned task after the invocation | 1 | 1 | 3 | `execution_lease_release` |

A full scope is retried with jittered backoff from 10 ms doubling to 200 ms
until the queue timeout (`TOOL_RUNTIME_QUEUE_TIMEOUT_MS`, 1 s by default), and
every retry is another checkout, statement and three round trips. Renewals and
releases run beside or after the request rather than in front of it, but they
hold connections from the same pool while they do.

## Admin mutations

Admin routes go through the global rate limit and authentication like any
request. The RBAC middleware exempts them; instead
`routing.rs::admin_revision_gate_middleware` reads the counter once (class
`revision_check`, three round trips, reconciling inline when behind, as above)
before any admin endpoint runs.

**Policy write** (`PUT /v1{ADMIN_PREFIX}/policy`, `admin_policy.rs`):

1. The handler reads the authoritative document to judge `If-Match`: one
   checkout, one statement, three round trips (`active()`, class
   `security_state_read`, operation `policy_active_read`).
2. The commit takes one checkout (class `control_plane_write`) and runs eight
   statements on it: `BEGIN`, the policy/overlay advisory transaction lock, the
   active pointer `FOR UPDATE`, the new version insert, the revision counter
   update, the pointer update, the outbox insert and `COMMIT`
   ([`postgres_policy.rs`](../../gateway/src/storage/postgres_policy.rs),
   [`postgres_documents.rs`](../../gateway/src/storage/postgres_documents.rs)).
   The six in the middle are SQL text and `BEGIN` and `COMMIT` are not, so the
   commit is fifteen round trips with its recycle: 1 + 6 × 2 + 2. The commit
   is not in the operation series; the nightly gate times it end to end as
   `control_plane_mutation`.

**Service-token revoke** (`DELETE` on a token, `admin_tokens.rs`): one checkout
(class `control_plane_write`) and eight statements for a live token: `BEGIN`,
the token state row `FOR UPDATE`, the token row `FOR UPDATE`, the revision
counter update, the token update, the state revision update, the outbox insert
and `COMMIT`. That is fifteen round trips, counted as for the policy commit. A
repeat revoke spends no revision: `BEGIN`, the two locking reads and `COMMIT`,
four statements and seven round trips.

Every committed mutation advances the shared counter, so after it every
replica, the committing one included, runs one reconcile pass: in its
background poller, or inline on the first request that sees the new revision.

## Work that shares the pool but is not a request

Per replica, independent of request rate unless noted:

- The background reconcile poller: one counter read every 250 ms, about four a
  second at idle, in the `revision_check` class, three round trips each.
- The membership heartbeat and the readiness probe's bounded read (at most one
  per `READINESS_PROBE_CACHE_MS` window that a probe actually asks for).
- The PostgreSQL audit sink: one batched store call per 200 events or 250 ms
  ([`audit/postgres_sink.rs`](../../gateway/src/audit/postgres_sink.rs)).
  Every audited request adds to these batches, so audit volume is pool load
  even though no request waits for it.
- The cluster conformance snapshot refresher in
  [`middleware/observation.rs`](../../gateway/src/middleware/observation.rs).
- The singleton leases: every replica keeps trying the maintenance and
  discovery-projector leases, and whichever holds one renews it (class
  `execution_lease`).
- On the leader only: the maintenance pass on a dedicated advisory-lock session
  (its checkout is class `maintenance`) and its sweeps, and the discovery
  projector reading the audit stream and committing projection batches.

## Reading the series

`greengateway_database_pool_acquire_seconds{operation_class, error_class}`
times the checkouts of the six authority stores: policy and the revision
counter, service tokens, JWT revocations, rate limits, execution leases and the
dedicated session. A checkout is recorded when the pool hands it a connection,
when the pool refuses it, and when its caller stops waiting first. A checkout
that was dropped before it started waiting has no wait to record.
`operation_class` is one of seven fixed names:

| `operation_class` | What is waiting for a connection |
| --- | --- |
| `revision_check` | The security-revision counter read: the gates, the service-token validator and the background poller |
| `credential_check` | Service-token verification and the JWT revocation lookup |
| `rate_limit` | Shared rate-limit decisions and their bounded evictions |
| `execution_lease` | Tool and singleton lease acquire, renew and release |
| `security_state_read` | Activation revisions and active documents for reconciliation, and admin reads of policy, history and tokens |
| `control_plane_write` | Policy commits, service-token create, revoke and rotate, JWT revocations |
| `maintenance` | The dedicated maintenance session, cleanup sweeps and operator commands |

A class says what kind of work waited, not which caller waited. Two classes mix
callers with different deadlines:

- `revision_check` holds the gates' reads, which give up at
  `RECONCILE_DEADLINE` (250 ms); the service-token validator's read, which has
  no deadline of its own beyond the pool's; and the background poller's, about
  four a second per replica, inside a 30 s pass deadline.
- `security_state_read` holds admin reads beside inline and background
  reconcile reads.

So the class alone cannot isolate the request path's share of the pool wait.

`error_class` says how the checkout ended:

| `error_class` | What happened |
| --- | --- |
| `none` | The pool handed over a connection. |
| `timeout`, `unavailable`, ... | The pool refused, classified exactly as everywhere else. `timeout` here is the same event `greengateway_database_pool_timeouts_total` counts, but that counter also sees checkouts outside these stores, so it can be the larger of the two. |
| `cancelled` | The caller stopped waiting before the pool answered: its own deadline passed, or its request was dropped. The sample is how long it had waited by then. This is not a pool timeout and is not counted in `_pool_timeouts_total`; the caller's own refusal is unchanged. |

`cancelled` matters most under saturation, because the request-path callers
give up long before the pool does. With the defaults, the pool waits
`DATABASE_ACQUIRE_TIMEOUT_MS` (5 s) for a connection. The gates give up on the
revision read at `RECONCILE_DEADLINE` (250 ms) and answer `503`; the RBAC gate
audits that refusal as `authz.revision_check_failed` with reason
`security_revision_reconcile_deadline`. The tool runtime gives up on a lease at
its queue timeout (1 s) and rejects the call, audited as `tool.invoke_rejected`
with reason `queue_timeout`. So a gated `revision_check` sample under `none` is
at most about 250 ms, and an `execution_lease` sample under `none` from a tool
call is at most about the queue timeout: a longer wait ended as `cancelled`
instead. Quantiles of `none` alone are therefore censored at those deadlines;
read the `cancelled` rate beside them, and remember that a `cancelled` sample is
itself only a lower bound on how long that caller would have waited.

No label carries a principal, token, route, key, statement or request ID. The
registry audit in `app_tests.rs` holds every rendered value to its declared
list and the family to exactly one series per class and outcome: seven classes
by eight outcomes today (six classified kinds, `none` and `cancelled`), with
the class list capped at eight.

The stores time their statements in `greengateway_database_operation_seconds`
starting once the connection is held, so a checkout that never produced one
records nothing there. A SQL-text statement's time there covers both of its
round trips, so an operation's floor is about two network round-trip times per
statement; the acquisition series' floor on a warm pool is one, the recycle.
An operation is recorded when it
finishes, so one its caller's deadline cut off mid-statement records nothing in
the operation series. The membership store, the connectivity check and the
readiness probe predate this split and still include their checkout in their
operation time.

No buckets are configured, so the exporter renders both histograms as
summaries: per-replica quantiles over a short rolling window, plus `_sum` and
`_count`. Quantiles cannot be averaged across replicas; compare them per
replica, and use the counters for anything deployment-wide.

```promql
# Checkouts per second the authority is asked for, by class.
sum by (operation_class) (rate(greengateway_database_pool_acquire_seconds_count[5m]))

# Mean wait for a connection, by class, across the deployment, among
# checkouts that got one.
sum by (operation_class) (rate(greengateway_database_pool_acquire_seconds_sum{error_class="none"}[5m]))
  / sum by (operation_class) (rate(greengateway_database_pool_acquire_seconds_count{error_class="none"}[5m]))

# The worst replica's p99 wait among checkouts that got a connection, for
# the per-request classes. Censored: a gated revision_check wait or a tool's
# execution_lease wait longer than its caller's deadline is not in here; it
# is in the cancelled rate below.
max by (operation_class) (
  greengateway_database_pool_acquire_seconds{quantile="0.99", error_class="none",
    operation_class=~"revision_check|credential_check|rate_limit|execution_lease"})

# Checkouts whose caller stopped waiting, by class.
sum by (operation_class) (
  rate(greengateway_database_pool_acquire_seconds_count{error_class="cancelled"}[5m]))

# Checkouts that did not get a connection, by class and how they ended.
sum by (operation_class, error_class) (
  rate(greengateway_database_pool_acquire_seconds_count{error_class!="none"}[5m]))
```

Read the two series together, with the pool gauges:

| Acquisition wait | Statement time | `_pool_waiting` | What it means |
| --- | --- | --- | --- |
| Rising | Flat | Above `0`, `_available` at `0` | Requests are queueing for connections: the concurrency is more than the pool, or something is holding connections. Check the other classes and the pool users this series does not cover before raising `DATABASE_POOL_MAX`. |
| `none` flat near a caller's deadline, `cancelled` rising | Flat | Above `0`, `_available` at `0` | The same queue, past the point the `none` quantiles can show: callers are giving up. Expect `503` responses and the `authz.revision_check_failed` and `queue_timeout` audit events above to rise with it. |
| Flat | Rising | `0` | The database is slow for these statements: locks, CPU or I/O. Start with `pg_stat_activity` (see [pool sizing](../deployment/pool-sizing.md#what-to-look-at-when-it-is-3am)). |
| Rising | Rising | Above `0` | Slow statements are holding connections longer and the queue is following. Fix the statement first; a larger pool only buys time. |

A wait is never zero even on an idle pool: it includes the `ROLLBACK` that
recycles the connection, and a checkout that has to open a connection includes
the connect. Short spikes after a scale-up or a database restart are
connections being created, not queueing.

### Mapping to the published budgets

[The HA state model's budgets](../architecture/ha-state-model.md#6-blocking-budgets)
and the nightly benchmark that measures them
([`tests/ha/performance.rs`](../../gateway/tests/ha/performance.rs)) name the
same work this page counts:

| Budget | Authority call | Acquisition class | Statement series `operation` |
| --- | --- | --- | --- |
| `security_revision_check` | `SecurityRevisionSource::current` | `revision_check` | `policy_revision_read` |
| `service_token_authoritative_check` | `PostgresServiceTokenStore::verify` | `credential_check` | `service_token_verify` |
| `revocation_lookup` | `PostgresJwtRevocationStore::is_revoked` | `credential_check` | `jwt_revocation_lookup` |
| `distributed_rate_limit_decision` | `PostgresRateLimitStore::decide` | `rate_limit` | `rate_limit_decide` |
| `lease_acquire` | `PostgresExecutionLeaseStore::try_acquire` | `execution_lease` | `execution_lease_acquire` |
| `connection_acquire_warm` | `storage::postgres::checkout` | every class | -- |

The benchmark still measures copies of these statements on one warm
connection, and it prepares each copy once and then executes it, so one of its
samples is one execute round trip. The product sends the same SQL text
unprepared, so every call is a prepare and an execute: two round trips, plus
the recycle in front of it. The state model's budget table describes the
revision check as one prepared statement; the product does not prepare it
today. The product series measure the calls as they run, under whatever load a
replica carries. They answer different questions and are not interchangeable
evidence for a budget.

## What this page does not establish

- How long any of this takes. The counts are from the source at the time of
  writing; the latency of each step depends on the database, the network, the
  pool size and the load.
- Where tail latency or timeouts start to degrade as replicas, pool ceilings
  and request mix change. That is the capacity matrix #439 adds next.
- That a deployment's connection ceiling is safe. That is the arithmetic in
  [pool sizing](../deployment/pool-sizing.md), which this page does not change.
