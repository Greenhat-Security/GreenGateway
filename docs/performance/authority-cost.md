# Authority cost per request

Part of #439. This page counts, from the source, which cluster-mode request
paths talk to PostgreSQL, how many pool checkouts, statements and network round
trips each one spends, and how to read the series that separates waiting for a
connection from the work done on it. The counts publish no latency numbers;
[the capacity matrix](#the-capacity-matrix) records what these paths cost
under load on a hosted CI runner, every night. Results from a target
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
eviction: one more statement (`rate_limit_evict`, two more round trips) on the
decision's own connection, with no checkout of its own. No request holds two
connections, so new keys arriving at the bound together cannot each hold one
connection while waiting for another. The decision commits with its own
statement; an eviction that fails after it is logged and does not refuse the
request, and the next key past the bound evicts the excess.

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
  even though, with `AUDIT_DURABILITY=best_effort`, no request waits for it.
  Under the default `required`, a request's authentication and authorization
  records also wake the flusher, so it commits whenever such records are
  waiting -- still one store call and one connection at a time per replica --
  and the request does wait for that commit. The nightly matrix runs
  `best_effort` (`performance_options` in `gateway/tests/ha/performance.rs`),
  so its numbers do not include that wait.
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
| `rate_limit` | Shared rate-limit decisions (a decision's bounded eviction runs on its connection) |
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

## The capacity matrix

The `nightly-performance` workflow runs the paths above under load and
publishes what the series on this page said about them, as the `ha-capacity`
artifact (90 days). The producer is
[`tests/ha/capacity.rs`](../../gateway/tests/ha/capacity.rs);
`scripts/check-test-evidence.py capacity` validates its report and rebuilds the
uploaded file from an allowlist of bounded fields (see
[test evidence](../deployment/test-evidence.md)). If a cell is incomplete, or
the validator rejects the report, the run publishes `ha-capacity-diagnostics`
instead: the producer's report as written, with each cell's reason codes. That
file is sanitized by the producer alone; only `ha-capacity` is rebuilt from the
allowlist.

### The cells

| Axis | Values |
| --- | --- |
| Replicas | 2, 3 |
| `DATABASE_POOL_MAX` per replica | 2, 10 (the product default) |
| Request mix | `jwt_proxy`, `mixed_credentials` |

The eight crossed cells are named `r<replicas>-p<pool>-<mix>`, for example
`r3-p2-jwt_proxy`. A ninth, `r2-p10-mixed_credentials-contention`, runs the
mixed load with concurrent control-plane and audit work:

- `jwt_proxy`: every request is a proxied `GET` with a JWT carrying a `jti`.
  That is the first row of the [summary](#summary): `rate_limit`,
  `credential_check`, `revision_check`.
- `mixed_credentials`: out of every ten requests, six are that `GET`, three are
  the same `GET` with a service token, and one is an admin policy read
  (`GET /v1{ADMIN_PREFIX}/policy`). The policy read adds a
  `security_state_read` checkout for the authoritative document.
- The contention cell adds a writer and an audit feeder. The writer commits a
  policy document on alternating replicas, waits until every replica has
  compiled it (at most 10 s), then pauses 250 ms before the next commit, so
  it commits at most four times a second. Each commit forces every replica to
  reconcile and makes the next request for every cached service token a
  verification. The feeder appends a batch of 200
  `http.request_observed` events to the audit stream every second, through the
  production statements and lock, for the discovery projector. This is on top
  of the audit rows every request writes.

Every cell starts its own cluster on a fresh database. The load generator runs
24 closed-loop workers, spread evenly over the replicas, and sends straight to
each replica rather than through the harness balancer. It discards a 2 s
warm-up, then measures for 20 s. Each worker presents its own
documentation-range client address through a proxy header trusted from
loopback only. The global limiter's shared bucket is keyed by client address,
so a generator on one address would queue the whole deployment on one bucket
row. The replicas, PostgreSQL 16 and the generator share one hosted runner.
The report records its cores, the server version and `max_connections`. The
numbers describe that machine, not yours.

### What a cell records

| Field | What it is |
| --- | --- |
| `requests` | Completed requests, throughput, status counts (`200` and `503` only in a complete cell), client timeouts, `rate_503`, `rate_client_timeout`, and nearest-rank p50/p95/p99/max latency over all requests (`latency_ms`) and over served ones (`served_latency_ms`), overall and per request kind. |
| `pool.replicas[].acquire` | Per replica, one row per `operation_class` and `error_class` whose count moved during the window. Each row has the exact count and sum delta, and the exporter's p50/p95/p99/max in milliseconds (see [Reading it](#reading-it) for how those are computed). |
| `pool.acquire_counts` | Deployment-wide counts for all 56 class and outcome pairs, zeros included. A `cancelled` of zero is stated, not left out. |
| `pool.replicas[]` | The `greengateway_database_pool_timeouts_total` and `audit_events_dropped_total` deltas. Also the largest `size`, smallest `available` and largest `waiting` sampled every 500 ms. |
| `pool.connection_ceiling` | `replicas x DATABASE_POOL_MAX`, as configured. |
| `database` | `pg_stat_activity` sampled every 500 ms, as max and mean per sample. It covers the runtime role's sessions (`runtime_backends`, `active`, `idle`, `idle_in_transaction`), every session in the database waiting on `Lock`, `LWLock` and `IO`, and ungranted `pg_locks` entries. It also has `longest_lock_wait_ms`: the longest time any session seen waiting on `Lock` had spent in its current statement (`clock_timestamp() - query_start`), which is an upper bound on that lock wait rather than the wait itself. Last come the `pg_stat_database` deltas (`xact_commit`, `xact_rollback`, `deadlocks`, `blks_hit`, `blks_read`, `temp_files`). |
| `control_plane` | Contention cell only. Commit status counts and latency, and convergence: the time from a commit returning to every replica's `greengateway_security_revision_compiled` reaching the committed revision. Commits that never converge within 10 s are counted, not dropped. |
| `projector` | Contention cell only. Events the feeder appended, the projector's checkpoint and applied-observation deltas, and the stream lag after the window. |

Database CPU is not collected. SQL has no portable view of it without an
extension or host access. Read it from the database host or your provider's
metrics.

### Reading it

- Change one axis at a time. Compare `r2-p2-<mix>` with `r2-p10-<mix>` for the
  pool ceiling, `r2-p<n>-<mix>` with `r3-p<n>-<mix>` for scale-out, and a mixed
  cell with the contention cell for concurrent control-plane and audit work.
- Start with outcomes. When `rate_503` or `rate_client_timeout` rises with
  `cancelled` and `timeout` counts in `pool.acquire_counts`, the cell has
  passed the point where requests give up waiting for a connection. Check
  `waiting_max` and `available_min` on the replicas beside it.
- Then read the acquisition rows. The rules in
  [Reading the series](#reading-the-series) apply. `none` quantiles are
  censored at the callers' deadlines, so a `revision_check` `cancelled` row
  sits near 250 ms. A `rate_limit` checkout has no deadline of its own, so its
  `none` tail can run up to the pool's 5 s. The quantiles cover the
  exporter's rolling window of about a minute, which on a 20 s cell includes
  cluster start and warm-up. Read a row's `count` before its quantiles: a
  class with few samples, like `security_state_read` or
  `control_plane_write`, is dominated by those.
- The acquisition quantiles are not nearest-rank. The exporter keeps each
  series in a DDSketch (metrics-util's default summary, accurate to within
  0.01 % of the true value). It renders p50, p95 and p99 as the representative
  value of the sketch bucket each rank falls in, and `max_ms` as the exact
  largest sample. So a row's p99 can sit just above its `max_ms` when both
  fall in one bucket, and a row with a single sample in the window shows
  p50 = p95 = p99 slightly above `max_ms`. That is the sketch's rounding, not
  a disordered row; the gate orders p50, p95 and p99 against each other only.
  The request, commit and convergence latencies are nearest-rank over the
  generator's own samples, so they are exact and fully ordered.
- Use `database` to tell queueing from a slow database. Lock waits show as
  `lock_waiting`, `ungranted_locks` and `longest_lock_wait_ms`. Contention on
  shared buffers and internal structures shows as `lwlock_waiting`.
  `runtime_backends.max` is how many connections the deployment actually
  opened. Pools open lazily, so this can stay below `connection_ceiling`.
- `stat_delta` is approximate. Each backend flushes its own counters at most
  about once a second. `xact_commit` divided by `requests.completed` still
  gives a rough count of database transactions per request.

### What the gate checks

The nightly fails on the matrix only when evidence is incomplete. It checks
each of the following. Every declared cell is present. Each cell ran for at
least its measured window, completed at least one request per worker, served
at least one of them, and has no status other than `200` or `503`. No client
transport errors occurred. Every request kind in the mix completed. Every
replica's scrape carries `revision_check` acquisitions, whatever their outcome,
and a nonzero pool `size` gauge. Every class the mix exercises appears in the
deployment-wide counts. The database was sampled at least three times. In the
contention cell, at least one commit converged and the projector advanced. It
checks the matrix too: at least two replica counts by two pool ceilings by
both mixes, plus one contention cell that runs the mixed load on a
configuration a plain cell also ran.

The gate never compares a latency, a refusal rate or a wait with a threshold.
A complete cell in which half the requests were refused passes, because that
refusal is the result being recorded. A replica whose every revision read was
cancelled passes for the same reason. A cell that served nothing fails: every
request refused or timed out for a whole measured window means the harness was
broken, for example a hung upstream, not that the pool was measured. No
capacity budget exists, and this matrix does not set one.

### Collecting the same numbers in a deployment

The gateway itself needs no new privilege for any of this. The database side
needs at most one grant, to a separate monitoring role:

- The acquisition series and the pool gauges come from each replica's
  `/metrics`, which needs no credential. Scrape each replica separately.
  Quantiles are per replica and cannot be averaged across replicas.
- Any role can read `pg_locks` and `pg_stat_database`. Any role can also read
  `pg_stat_activity`, and sees the `state`, `wait_event_type` and `query`
  columns of its own role's sessions, so the runtime role can already see how
  its own connections are spending their time. The same columns for another
  role's sessions, which lock waits usually involve, are visible only to
  superusers and members of `pg_read_all_stats`, which is part of
  `pg_monitor`. To see the whole database, grant `pg_monitor` to a separate
  monitoring role. The gateway's runtime role should not get that grant. The
  harness reads these views as the CI superuser and keeps only aggregate
  counts:

  ```sql
  SELECT state, wait_event_type, count(*)
  FROM pg_stat_activity
  WHERE datname = 'greengateway' AND usename = '<runtime role>'
  GROUP BY state, wait_event_type;

  SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
  WHERE NOT l.granted AND a.datname = 'greengateway';
  ```

### How it feeds pool sizing

[Pool sizing](../deployment/pool-sizing.md) keeps the arithmetic, and this
matrix does not change it. For each pool ceiling and replica count, the report
gives the observed side of that arithmetic: peak connections opened against
the configured ceiling, at the server's recorded `max_connections` and
`superuser_reserved_connections`. It also gives the ceiling at which
cancelled waits and `503` refusals appeared under this load. Issue #439's next
step, a sizing report and guard, takes those as tested inputs. It does not take
them as limits: a benchmark result never changes a deployment's limits by
itself, and a deployment still sizes against its own measured load.

## What this page does not establish

- How long any of this takes in your environment. The counts are from the
  source at the time of writing. The latency of each step depends on the
  database, the network, the pool size and the load, and the capacity matrix
  measures only a hosted CI runner.
- That a deployment's connection ceiling is safe. That is the arithmetic in
  [pool sizing](../deployment/pool-sizing.md), which this page does not change.
