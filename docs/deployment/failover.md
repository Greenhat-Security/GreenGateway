# Runbook: failover

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is experimental and is not a supported HA configuration until the #241 release gate passes.

**The rule: exactly one writable PostgreSQL primary is the authority, and no security decision is ever read from a lagging replica.** Cluster mode makes the *gateway* replicas replaceable. It does not make the database replaceable, and it does not spread authority across more than one node. Every revision check, revocation lookup, token verification, distributed limit, execution lease, and control-plane mutation reads and writes the primary.

There are therefore two entirely different failovers, and confusing them is how a security incident happens:

| | Gateway replica failure | Database primary failure |
| --- | --- | --- |
| Blast radius | one replica's share of traffic | the whole deployment |
| Automatic? | yes, if your load balancer honours `/readyz` | only if your PostgreSQL platform does it |
| Correct behaviour while it lasts | the other replicas serve normally | every replica answers `503` |
| Your job | confirm the survivors are healthy | restore a single writable primary |

## Why you must not point the gateway at a read replica

An asynchronous read replica is behind the primary by an unbounded amount. Every one of the following goes wrong if a security decision is answered from one:

- A **revoked JWT** is still absent from the replica's copy of the denylist, so a withdrawn token is accepted.
- A **policy version** the administrator just committed has not arrived, so a rule that was tightened is enforced in its old form.
- A **rate-limit bucket** or an **execution lease** read from a replica is a different number than the one the primary holds, so the limit is not a limit.
- A **service token** that was just rotated verifies against its old hash.

Every one of those is a stale allow. Cluster mode's design says fail closed, never stale-allow, and the way that promise is kept is that the DSN names the primary. So:

- Point `DATABASE_URL_FILE` at the writable primary. Not at a read endpoint, not at a "reader" hostname, not at a pooler configured to route reads elsewhere.
- If your provider gives you separate writer and reader endpoints, the writer endpoint is the only correct one — including for `gateway cluster-members`, which is read-only and still must see the authority's current view.
- A pooler is allowed only in **session** pooling mode. Transaction pooling breaks session-scoped advisory locks and the connection-time session settings the gateway relies on. See [the pool sizing runbook](pool-sizing.md).

## Gateway replica failure

This is the case cluster mode is *for*, and it should be boring.

**What happens on its own.** The failed replica stops answering `/readyz` with `200`; the load balancer stops sending it traffic; the surviving replicas serve the load. The failed replica's row in `greengateway.cluster_members` goes stale on the database clock once its heartbeat is older than `CLUSTER_MEMBER_STALE_MS`, and the maintenance singleton sweeps it — never request handling, and never the member itself, so a replica partitioned away from you but still running cannot un-stale itself.

If the failed replica held the maintenance lease, or the discovery projector lease, a successor takes it after the lease's TTL lapses on the database clock. Replicas without a lease retry with a jittered backoff, so takeover is staggered rather than a thundering herd. Nothing is lost: leases are fenced, a stale leader's late writes are refused, and the projector resumes from its committed checkpoint.

**What to check.**

```sh
gateway cluster-members
```

Expected output: a header line, then one line per member. The states are `ready`, `starting`, `draining` and `stale`.

```
deployment=deploy-prod-eu members=3 live=2 stale_window_ms=30000
ready     instance=... version=0.5.0 schema=1..11 fingerprint=... heartbeat=... age_secs=1.2 ...
ready     instance=... version=0.5.0 schema=1..11 fingerprint=... heartbeat=... age_secs=2.8 ...
stale     instance=... version=0.5.0 schema=1..11 fingerprint=... heartbeat=... age_secs=94.0 ...
```

This command is read-only and writes no row for itself, so running it during an incident does not add a member.

Per replica:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://<replica>:8080/readyz
curl -sS http://<replica>:8080/readyz
```

Expected output: `200` and `{"status":"ready"}` on a healthy replica. A `503` carries a reason, and the reason is the diagnosis:

| `reason` | Meaning | Action |
| --- | --- | --- |
| `starting` | the replica has not finished coming up | wait; if it persists, read its startup logs — cluster mode fails closed at startup for schema, binding, and policy problems |
| `draining` | the replica is shutting down on purpose | none; expected during a rollout |
| `config_fingerprint_mismatch` | this replica's security-relevant static configuration disagrees with a live member's | see below |
| `required_upstream_unavailable` | a proxy upstream marked required for readiness is down | a data-plane problem, not a cluster problem |

**`config_fingerprint_mismatch` during a rollout is the common one.** Agreement is sticky and one-way: an already-serving replica is never taken out of rotation by a mismatched newcomer, which holds a bad rollout at the door instead of letting it spread. The consequence is that a deliberate fingerprint change (a route, an exempt path, a key generation, anything security-relevant and static) completes on its own only where the old replicas leave without waiting for the new one to become ready — a `Recreate` strategy, a rolling update whose `maxUnavailable` covers every old replica, or an operator draining the old replicas by hand. Under a readiness-gated rolling update (Kubernetes `RollingUpdate` with `maxUnavailable: 0`, the default) the rollout stalls at the door.

That stall is a decision handed to you, not a bug: the gateway cannot tell an intended configuration change from a misconfigured replica at the moment the newcomer boots. Your two options are to roll back, or to force the old replicas out. There is no third option where both generations serve.

To decide which, compare fingerprints: `gateway cluster-members` prints each member's. If the newcomer's is the one you intended, drain the old replicas. If it is not, roll back and find the configuration difference.

## Database primary failure

**Expected behaviour while the primary is unavailable: every replica answers `503` on protected traffic, and `/readyz` reflects it.** This is correct. A replica that cannot prove it is acting on current authoritative security state stops being ready and rejects protected traffic. `503` means "cannot check", never "checked and denied" — you should see no increase in `401`/`403` during a database incident, and if you do, investigate that separately.

**Your job is to restore exactly one writable primary.** Not to fail the gateway over to something else; there is nothing else.

If your platform does automatic failover (a managed service with a standby, or Patroni and friends), the sequence is:

1. The platform promotes the standby.
2. The DSN's hostname resolves to the new primary — **if** it is a virtual hostname or an endpoint the platform re-points. If your DSN names a physical host, no amount of promotion helps; the DSN is the thing that has to change. Check this before you need it.
3. The gateway's pool reconnects. There is no manual step and no restart, provided the hostname resolves. `DATABASE_STARTUP_RETRY_LIMIT` governs the retry at startup only; a running replica's pool retries on its own schedule.
4. Replicas return to `200` on `/readyz` as authority reads start succeeding.

If the DSN must change (a managed provider's restore-to-timestamp produces a new instance with a new hostname, for example):

1. Write the new DSN file, still mode `0400`. See [the roles and grants runbook](roles-and-grants.md).
2. Restart the replicas one at a time, waiting for each to reach `ready` in `gateway cluster-members` before the next.

A running replica has no way to re-read its DSN file; the restart is the mechanism.

**Before any replica connects to a promoted or restored primary, verify it.** Run the five checks in [the backup and recovery runbook](backup-and-recovery.md) — schema current, binding correct, an active policy exists, the audit stream is contiguous and the projector checkpoint is not ahead of it, and the counts match. A promoted standby that was behind is a database with a shorter history, and the projector checkpoint is the field most likely to be inconsistent with it.

**Never promote a standby while the old primary is still writable.** Two writable primaries with the same `DEPLOYMENT_ID` is split brain, and the deployment binding does not protect you from it — the binding stops two *deployments* sharing a database, not one deployment writing to two databases. Fence the old primary first, at the platform level.

## Deliberate replica maintenance

Draining is a supported operation and is not a failure. A replica that receives `SIGTERM` stops accepting new work, stamps `draining_at` on its member row (so peers stop counting its fingerprint against a newcomer's), finishes in-flight requests within `SHUTDOWN_DRAIN_DELAY_MS` and `SHUTDOWN_TIMEOUT_MS`, releases any lease it holds at once, and exits.

To take one out:

1. Remove it from the load balancer's backend set, or let `/readyz` do it — a draining replica answers `503` with `draining`.
2. `SIGTERM` the process (`docker compose stop gateway-2`, or the orchestrator's normal termination).
3. Confirm `gateway cluster-members` shows it `draining`, then gone.

To scale down to one replica deliberately (which is what [the cutover runbook](cutover.md) does), drain the others the same way. One replica is a correct, if unavailable-during-restart, cluster-mode deployment.

## When a step fails

**`gateway cluster-members` itself fails.** It needs the authority too. If it cannot connect, the database is the problem, not the roster.

**A replica shows `ready` in the roster but the load balancer is not sending it traffic.** The roster is the database's view; the load balancer's is its own. Check that the load balancer probes `/readyz` and not `/livez` — `/livez` says the process is alive and will happily point traffic at a replica that is deliberately refusing it.

**Every replica is `stale` but they are all running.** They cannot write their heartbeat, which means they cannot reach the authority. Same diagnosis as `503` everywhere: this is a database incident.

**A replica keeps restarting with a startup error naming the schema.** It found a schema outside its manifest range. A replica never migrates by itself; run `gateway migrate up` from the migration job, or roll back to the binary that matches the schema. Do not set `DATABASE_AUTO_MIGRATE=true` to get past it in production — it changes who applies DDL, not whether the ledger is sound, and a tampered ledger still refuses.

**Two replicas both report `greengateway_cluster_maintenance_leader = 1`.** Metrics are scraped at different instants and a takeover was in flight; re-scrape. If it persists across scrapes, the lease fencing is not doing its job and that is a bug worth reporting, not an operational condition to work around.
