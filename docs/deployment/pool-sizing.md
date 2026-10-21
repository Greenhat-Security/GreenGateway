# Runbook: pool sizing and timeouts

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule: the deployment must not be able to ask the database for more connections than it has.** Every replica opens its own pool against the one primary, so the ceiling is a property of the deployment, not of any replica, and a replica added without redoing this arithmetic is the one that exhausts `max_connections` for everybody.

## The arithmetic

```
pods x DATABASE_POOL_MAX  +  headroom  <=  max_connections - superuser_reserved_connections - reserved_connections
```

`pods` is the most gateway replicas that can run at once, not the number running today: the autoscaler's maximum when there is one, plus the pods a rolling update starts before old ones leave (see [Replica ceilings](#replica-ceilings)). The two reserved settings hold slots back for superusers and, from PostgreSQL 16, for roles granted `pg_use_reserved_connections`; the gateway's runtime role is neither, so those slots are not its to use. Before PostgreSQL 16 `reserved_connections` does not exist; count it as 0.

`headroom` is not a fudge factor. It is a list, and you should be able to name every entry:

| Consumer | Connections | When |
| --- | --- | --- |
| The migration job | up to 2 | during `gateway migrate up` (one migrator, one advisory-lock holder) |
| `gateway import-standalone` | up to 2 | during a cutover only |
| `gateway maintenance-run` | up to 3 | when an operator or cron runs one: its dedicated pass session, plus the ledger writes and lease renewals it makes beside that session |
| `gateway cluster-members`, `revoke-jwt`, `jwt-revocations-cleanup`, `rate-limit-buckets-cleanup` | 1 each | when an operator or cron runs one |
| The maintenance leader's dedicated pass session | 1 | continuously, on one replica, from within that replica's pool |
| Your backup tooling | 1 per `pg_dump`; `pg_dump --jobs=N` opens N+1 | while a dump runs |
| Your monitoring | whatever it opens | continuously |
| An operator's `psql` | 1-2 | at 3am, which is the moment the ceiling matters |
| Anything else that connects to this server | whatever it opens | if the server is shared |

Replication connections (a standby, `pg_basebackup`, a logical subscriber) take `max_wal_senders` slots on PostgreSQL 12 and later, not `max_connections` slots, so they are not on this list.

The maintenance leader's pass session comes out of that replica's own `DATABASE_POOL_MAX`, so it does not add to the total — but it does mean the leader has one fewer connection for requests than its peers while a pass runs. With a pool of 10 that is 10%; with a pool of 2 it is half, which is a reason not to set the pool that low.

Worked example, the default `DATABASE_POOL_MAX=10` against a stock `max_connections=100` with `superuser_reserved_connections=3` and `reserved_connections=0`, budgeting one `pg_dump`, one monitoring connection and two operator sessions:

```
3 replicas x 10                         = 30
+ 2  migrator (during a deploy)
+ 2  import (during a cutover)
+ 4  maintenance (one maintenance-run and one other command at once)
+ 1  backup
+ 1  monitoring
+ 2  operator psql
= 42   <=   97      # comfortable
```

Scaling to eight replicas at the same pool size:

```
8 x 10 = 80 + 12 = 92  <=  97     # fits, with 5 spare
```

Nine replicas do not fit (90 + 12 = 102), and neither do eight on Kubernetes with the default rolling update, which runs 25% more pods while it rolls: ten pods, 100 + 12 = 112. The failure is not graceful: the replica past the ceiling cannot open connections, it fails startup or its requests time out acquiring, and the deployment loses capacity at the moment you were adding it. Either raise `max_connections` on the server (each connection costs the server memory; check the server's own limits first) or lower `DATABASE_POOL_MAX`. [Checking a deployment before rollout](#checking-a-deployment-before-rollout) runs this arithmetic for you and refuses a deployment that does not fit.

Check the server's actual numbers rather than assuming the defaults:

```sql
SHOW max_connections;
SHOW superuser_reserved_connections;
SHOW reserved_connections;   -- PostgreSQL 16 and later
```

The pool opens connections lazily. `DATABASE_POOL_MAX` is a ceiling, not a startup cost, so a deployment that never reaches its ceiling never pays for it — which is also why an over-sized pool looks fine right up until the load that reaches the ceiling arrives.

## Sizing the pool itself

A replica's pool needs to cover its concurrent database work, which is one connection per in-flight request that is touching the authority, plus the background tasks: the membership heartbeat, and on the leader the maintenance pass and the discovery projector. [Authority cost](../performance/authority-cost.md) counts the checkouts, statements and round trips each request path makes, and which background work shares the pool.

Start at the default `DATABASE_POOL_MAX=10` and change it on evidence:

- **Requests failing with `503` and a `Timeout` classification on `database_pool`** means acquisition is timing out — the pool is too small for the concurrency, or a query is holding connections too long. Look at query duration before raising the pool; a pool raise buys time against a slow query, it does not fix one.
- **`max_connections` pressure across the deployment** means the pool is too large for the replica count. Lower it, or raise the server's limit, or put a connection pooler in front — with the caveat below.

A pooler (PgBouncer and friends) is allowed only in **session** pooling mode. Transaction pooling breaks this gateway: it holds session state the gateway relies on. The pooled sessions carry `search_path` pinned to `greengateway, pg_catalog` and the three server-side timeouts as connection-time startup parameters, and advisory locks — which `migrate up`, the maintenance pass, and the discovery projector all use — are session-scoped and would be released or misattributed under transaction pooling. Point the gateway at the writable primary directly unless you have a specific reason not to, and never at a read endpoint (see [the failover runbook](failover.md)). A session pooler does not reduce what the server must hold: every gateway connection keeps a server session for its whole life, so the pooler needs at least as many server connections as the gateway pools can ask for, and it is those server connections that count against `max_connections`.

## Replica ceilings

The number to multiply by is the most gateway pods that can hold a pool at the same moment:

- **The autoscaler's maximum.** A HorizontalPodAutoscaler takes the Deployment to `maxReplicas` whenever its metric says so, without anyone redoing this page. Budget `maxReplicas`, or `spec.replicas` if that is larger.
- **Rollout surge.** A Kubernetes `RollingUpdate` starts up to `maxSurge` new pods (25% by default, rounded up) before old ones leave, and each opens its own pool while the old ones still hold theirs. `Recreate` adds none, and neither does a StatefulSet, which replaces pods one at a time. `docker compose up` replaces a service's containers in place and adds none; a Swarm stack whose `deploy.update_config.order` is `start-first` starts each new task before stopping the old one.
- **Pods still draining.** A terminating pod keeps its connections until it exits, up to its shutdown drain and timeout, and Kubernetes does not count it against `maxSurge`. Keep some spare for a rollout that replaces pods faster than they drain.
- **Hand scaling.** `kubectl scale` and `docker compose up --scale` change the count without touching the files a review sees. Redo the arithmetic first.

## Checking a deployment before rollout

`scripts/pool_sizing.py` runs [the arithmetic](#the-arithmetic) for a deployment and refuses one that over-commits the server. It needs only the Python standard library, reads the files it is given, and changes nothing: a rejected deployment gets the shortfall, the required headroom and the largest settings that would fit, and the change is yours to make.

```sh
# By hand: the replica ceiling, the server's limits and every headroom entry.
python scripts/pool_sizing.py check --replicas 3 --autoscaler-max 6 --surge 2 --pool-max 10 \
  --max-connections 200 --superuser-reserved-connections 3 --reserved-connections 0 \
  --pooler none --backup 1 --monitoring 1 --operator 2 --other 0

# A Compose deployment. A file that runs its own PostgreSQL supplies the
# server's limits from that service's command line.
python scripts/pool_sizing.py check --compose docs/deployment/docker-compose.ha.yml \
  --pooler none --backup 1 --monitoring 1 --operator 2 --other 0

# Kubernetes: check what will be applied, rendered, rather than overlay sources.
kubectl kustomize path/to/overlay > rendered.yaml
python scripts/pool_sizing.py check --kubernetes rendered.yaml \
  --max-connections 200 --superuser-reserved-connections 3 --reserved-connections 0 \
  --pooler none --backup 1 --monitoring 1 --operator 2 --other 0
```

Exit status 0 means the deployment fits, 1 that it was rejected, and 2 that the input could not be read with certainty, so nothing was decided. `--json` prints the decision for a pipeline.

What it counts:

- **Gateway pools.** Every container or Compose service whose environment selects `STATE_BACKEND=postgres` is a gateway process. With no command it serves, and counts `DATABASE_POOL_MAX` (10 when unset) times its replica ceiling: the larger of `spec.replicas` and its HorizontalPodAutoscaler's `maxReplicas`, plus the Deployment's `maxSurge`; or the Compose `scale` or `deploy.replicas`. One that runs `migrate`, `import-standalone` or another one-shot command is a job, and its connections from the table above must fit inside the matching headroom entry.
- **Headroom, by name.** `--migrator` (default 2), `--import` (default 2) and `--maintenance` (default 4: one `maintenance-run` and one other one-shot command at once) are the gateway's own consumers. Lower one only when that consumer cannot run, such as `--import 0` once the cutover is done. `--backup`, `--monitoring`, `--operator` and `--other` have no default, because only you know them: name each, even as 0.
- **The server.** `max_connections - superuser_reserved_connections - reserved_connections`, from the flags or from the Compose file's own PostgreSQL service. Take them from `SHOW` on the real server.
- **The pooler.** `--pooler none` when the gateway connects to the primary directly. `--pooler session` takes `--pooler-server-connections`, the most server connections the pooler can open, which is budgeted on the server in place of the gateway pools and must be at least what the pools can ask for. `transaction` and `statement` are rejected whatever the arithmetic says, for the reasons above.

What it refuses rather than guesses, with exit status 2: YAML outside the plain block style deployment files use (tags, multi-line plain scalars, complex keys); a Compose file that uses `include`, `env_file` or `extends`, or interpolates a sizing variable (render it with `docker compose config --format json` and check that instead); a Kustomization (render it); an `envFrom` source that is not in the files (`--external-env secret/NAME` declares one supplied elsewhere that sets neither `STATE_BACKEND` nor `DATABASE_POOL_MAX`); an autoscaler other than a HorizontalPodAutoscaler; a cluster-mode gateway in a DaemonSet, a bare Pod or a kind it does not model, such as an Argo Rollout; a CronJob whose runs can overlap; a replaced entrypoint; and any value the gateway would itself refuse at startup.

What it cannot see: hand scaling after the fact, server settings changed after the files were written, a role's or database's own `CONNECTION LIMIT`, and clients that are not in the files. The report lists the services it did not count; budget them under `--other`.

### The shipped examples

The required `ha-compose-example` CI job runs `python scripts/pool_sizing.py examples`. It checks the Compose examples in `docs/deployment` and every manifest under `deploy/` against the headroom that `EXAMPLE_BUDGETS` in the script names for each cluster-mode example, so an example change that over-commits fails the build. The job also renders the HA example with `docker compose config` and requires the guard's reading of the file to match Compose's. A cluster-mode example without a budget, a budget for an example that no longer runs in cluster mode, an unreviewed new service beside the gateways, and a Kustomize overlay or patch that could move a replica count or pool size all fail too. Run the command before changing an example.

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

`/metrics` samples `greengateway_database_pool_size`, `greengateway_database_pool_available` and `greengateway_database_pool_waiting` from this replica's pool. Zero available connections with waiting callers is pressure; `greengateway_database_pool_timeouts_total` records checkout timeouts that a later snapshot could miss. `greengateway_database_pool_acquire_seconds` times each authority-store checkout by operation class, apart from the statements that follow it in `greengateway_database_operation_seconds`, so a slow request can be read as queueing for a connection or as a slow database. A wait the request gave up on before the pool answered is recorded as `error_class="cancelled"`, and under saturation that is where the longest request-path waits go; [authority cost](../performance/authority-cost.md#reading-the-series) shows how to read the outcomes and the two series together. See [operational alerts](operational-alerts.md#database-capacity) for checked rules and first-response guidance. Correlate them with the database and logs:

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
