# Runbook: pool sizing and timeouts

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule: the deployment must not be able to ask the database for more connections than it has.** Every replica opens its own pool against the one primary, so the ceiling is a property of the deployment, not of any replica, and a replica added without redoing this arithmetic is the one that exhausts `max_connections` for everybody.

## The arithmetic

```
replicas x DATABASE_POOL_MAX  +  headroom  <=  max_connections - superuser_reserved_connections
```

`headroom` is not a fudge factor. It is a list, and you should be able to name every entry:

| Consumer | Connections | When |
| --- | --- | --- |
| The migration job | up to 2 | during `gateway migrate up` (one migrator, one advisory-lock holder) |
| `gateway import-standalone` | up to 2 | during a cutover only |
| `gateway cluster-members` / `maintenance-run` | 1 each | when an operator or cron runs one |
| The maintenance leader's dedicated pass session | 1 | continuously, on one replica, from within that replica's pool |
| Your monitoring and backup tooling | whatever it opens | continuously |
| An operator's `psql` | 1-2 | at 3am, which is the moment the ceiling matters |

The maintenance leader's pass session comes out of that replica's own `DATABASE_POOL_MAX`, so it does not add to the total — but it does mean the leader has one fewer connection for requests than its peers while a pass runs. With a pool of 10 that is 10%; with a pool of 2 it is half, which is a reason not to set the pool that low.

Worked example, the default `DATABASE_POOL_MAX=10` against a stock `max_connections=100` with `superuser_reserved_connections=3`:

```
3 replicas x 10 = 30
+ 2 (migration job, during a deploy)
+ 2 (operator psql, monitoring)
= 34   <=   97      # comfortable
```

Scaling to eight replicas at the same pool size:

```
8 x 10 = 80 + 4 = 84  <=  97     # fits, with 13 spare
```

Ten replicas does not fit, and the failure is not graceful: the eleventh replica's pool cannot open connections, it fails startup or its requests time out acquiring, and the deployment loses capacity at the moment you were adding it. Either raise `max_connections` on the server (each connection costs the server memory; check the server's own limits first) or lower `DATABASE_POOL_MAX`.

Check the server's actual numbers rather than assuming the defaults:

```sql
SHOW max_connections;
SHOW superuser_reserved_connections;
```

The pool opens connections lazily. `DATABASE_POOL_MAX` is a ceiling, not a startup cost, so a deployment that never reaches its ceiling never pays for it — which is also why an over-sized pool looks fine right up until the load that reaches the ceiling arrives.

## Sizing the pool itself

A replica's pool needs to cover its concurrent database work, which is one connection per in-flight request that is touching the authority, plus the background tasks: the membership heartbeat, and on the leader the maintenance pass and the discovery projector.

Start at the default `DATABASE_POOL_MAX=10` and change it on evidence:

- **Requests failing with `503` and a `Timeout` classification on `database_pool`** means acquisition is timing out — the pool is too small for the concurrency, or a query is holding connections too long. Look at query duration before raising the pool; a pool raise buys time against a slow query, it does not fix one.
- **`max_connections` pressure across the deployment** means the pool is too large for the replica count. Lower it, or raise the server's limit, or put a connection pooler in front — with the caveat below.

A pooler (PgBouncer and friends) is allowed only in **session** pooling mode. Transaction pooling breaks this gateway: it holds session state the gateway relies on. The pooled sessions carry `search_path` pinned to `greengateway, pg_catalog` and the three server-side timeouts as connection-time startup parameters, and advisory locks — which `migrate up`, the maintenance pass, and the discovery projector all use — are session-scoped and would be released or misattributed under transaction pooling. Point the gateway at the writable primary directly unless you have a specific reason not to, and never at a read endpoint (see [the failover runbook](failover.md)).

## The timeouts

Two of these are enforced by the server, on every pooled session, as startup parameters set at connection time. That matters: no statement can outlive them regardless of what code runs later, and a DSN that tried to override them is rejected.

| Setting | Default | Enforced by | Effect |
| --- | --- | --- | --- |
| `DATABASE_STATEMENT_TIMEOUT_MS` | 15000 | server (`statement_timeout`) | caps any one statement |
| `DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS` | 30000 | server (`idle_in_transaction_session_timeout`) | kills a session sitting in an open transaction |
| `DATABASE_LOCK_TIMEOUT_MS` | 5000 | server (`lock_timeout`) | caps waiting on a lock |
| `DATABASE_CONNECT_TIMEOUT_MS` | 5000 | client | caps establishing one connection |
| `DATABASE_ACQUIRE_TIMEOUT_MS` | 5000 | client | caps checking one connection out of the pool |
| `DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS` | 60000 | server, migration job only | caps a migration statement and its lock waits |

The relationship that matters: `DATABASE_ACQUIRE_TIMEOUT_MS` plus `DATABASE_STATEMENT_TIMEOUT_MS` is roughly the worst case a request spends waiting on the authority before the gateway gives up. That should be comfortably inside whatever your load balancer and callers consider a timeout, or they will hang up first and you will debug the wrong layer.

**Why a failure here is `503` and not `401`/`403`.** A request that cannot reach the authority has not been denied; it has not been decided. Cluster mode returns `503` for every dependency failure so that "cannot check" is never confused with "checked and denied" — in the response, in the audit trail, and in your dashboards. If you see authorization failures during a database incident, something is wrong with more than the database.

Raising `DATABASE_STATEMENT_TIMEOUT_MS` above the default is almost always the wrong response to a slow query, because the statement timeout is what stops one slow query from holding a pool connection and turning a slow endpoint into a deployment-wide outage. The exception is the migration job, which has its own, larger setting for exactly this reason.

## What to look at when it is 3am

There are no pool-depth metrics on `/metrics` today. Observe the pool from the database side and from the logs. (Gap: a `greengateway_database_pool_*` gauge would make this a dashboard instead of a query.)

**How many connections each replica is holding, right now:**

```sql
SELECT application_name, state, count(*)
FROM pg_stat_activity
WHERE datname = 'greengateway'
GROUP BY application_name, state
ORDER BY application_name, state;
```

Give each replica a distinct `application_name` in its DSN or this tells you nothing. Expected output: one group per replica, mostly `idle`, with `active` counts that track request load. A replica at exactly `DATABASE_POOL_MAX` with a queue behind it is the one timing out.

**Anything stuck:**

```sql
SELECT pid, application_name, state, wait_event_type, wait_event,
       now() - query_start AS running_for, left(query, 80) AS query
FROM pg_stat_activity
WHERE datname = 'greengateway' AND state <> 'idle'
ORDER BY query_start;
```

Expected output at rest: nothing, or sub-second entries. A statement running longer than `DATABASE_STATEMENT_TIMEOUT_MS` should not exist — if one does, the timeout is not being applied, which means something is connecting outside the gateway's configuration.

**Whether the server is refusing connections:**

```sql
SELECT count(*) FROM pg_stat_activity;
SHOW max_connections;
```

Close to the ceiling means the arithmetic at the top of this page is wrong for the current replica count. The immediate mitigation is to scale replicas **down** by one, which is counter-intuitive under load and is nonetheless the action that restores service; then fix the sizing before scaling back up.

## When a step fails

**Replicas start timing out after a scale-up.** Total pool ceiling exceeded `max_connections`. Scale back down to the last known-good replica count, confirm with the `count(*)` query above, then either lower `DATABASE_POOL_MAX` across all replicas (a fingerprint-neutral change, but still a rolling restart) or raise the server's `max_connections` (a database restart).

**`503` from every replica at once, with `Unavailable` on `database_pool`.** The pool is closed, which means the connection to the primary is gone, not that it is busy. This is a database availability incident — go to [the failover runbook](failover.md).

**A single replica times out while its peers are fine.** That replica's pool is exhausted by its own work. Check whether it is the maintenance leader (`greengateway_cluster_maintenance_leader` is `1` on exactly one replica) and whether a pass is running long.

**Migration statements time out.** Raise `DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS` for the job only. Do not raise the serving replicas' `DATABASE_STATEMENT_TIMEOUT_MS` to match; they have no business running a statement that long.
