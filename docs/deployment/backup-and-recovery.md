# Runbook: backup, point-in-time recovery, and restore verification

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule: in cluster mode the gateway replicas hold nothing durable.** Every policy version, tools document, Connection record, credential binding reference, audit event, discovery aggregate, signal, suggestion and service-token hash lives in the one PostgreSQL deployment namespace. A replica is a cache with a process attached. **The database is the deployment.** Back it up as if losing it means losing the product, because it does.

Two things are deliberately *not* in the database and are not covered by a database backup:

- **Secrets.** Credential bindings are stored as references; the secret material lives in your external secret provider. Back that up on its own schedule, and restore-test it separately — a database restored beside an empty secret store gives you Connections that describe credentials nobody has.
- **The static configuration.** The environment each replica boots with is part of the trust model (it is fingerprinted, and disagreement blocks readiness). Keep it in version control. A perfect database restore next to a reconstructed-from-memory environment is a deployment whose replicas will not agree to become ready.

## What to back up

One logical database. Two mechanisms, and you want both:

1. **Physical base backup plus WAL archive**, which is what makes point-in-time recovery possible. This is the primary mechanism.
2. **A periodic logical dump** (`pg_dump --format=custom`), which is what survives a PostgreSQL major-version problem and what you can inspect without restoring.

A managed provider usually gives you (1) as a checkbox with a retention window. Read the window carefully: "7 days of PITR" and "7 daily snapshots" are very different recovery stories, and only the first can take you back to a moment before a bad migration or a bad import.

Whichever mechanism, the recovery objective that matters is set by the audit log: cluster mode's audit events are the compliance record, and a restore that loses the last hour of them has lost an hour of evidence, not just an hour of throughput. Decide the acceptable loss explicitly and configure WAL archiving to meet it (`archive_timeout` bounds how long an idle server holds an unarchived segment).

## Take a backup before every migration and every import

This is not general advice; it is the specific precondition of two documented procedures.

**Before `gateway migrate up`.** There is no schema downgrade. Recovering from an unwanted migration means restoring to a point before it ran.

**Before `gateway import-standalone --apply`.** The snapshot taken here is the pre-cutover restore point, and it is one half of the rollback story in [the rollback boundary runbook](rollback-boundary.md). The other half is the standalone deployment's own backup.

```sh
pg_dump --format=custom --no-owner --file=/backups/greengateway-pre-migrate-$(date -u +%Y%m%dT%H%M%SZ).dump \
  "$MIGRATION_DSN"
```

Expected output: no output, exit `0`, and a file whose size is plausible for your data (an audit history of a few million events is not a 40 KB dump). Check it:

```sh
pg_restore --list /backups/greengateway-pre-migrate-*.dump | head -20
```

Expected output: a table of contents naming `greengateway` schema objects. `pg_restore --list` failing is your backup failing, discovered now rather than during the incident.

Write down the exact UTC timestamp you took it at. PITR takes a target time, and "sometime around eleven" is not one.

## Point-in-time recovery

The procedure is your PostgreSQL provider's, not this project's, and you should have run it before you need it. What this runbook adds is what "recovered" means for *this* application.

The shape, for a self-managed server:

1. Stop every gateway replica. **Do this first.** Replicas writing to a database you are about to rewind will produce state the recovery target does not contain, and rows written after the target are exactly what you are trying to discard.
2. Restore the base backup into a fresh data directory.
3. Set the recovery target in `postgresql.conf`: `recovery_target_time = '2026-09-01 22:14:00+00'`, plus `recovery_target_action = 'promote'`.
4. Create `recovery.signal` in the data directory and start the server.
5. Watch the log for `recovery stopping before commit of transaction ...` and then `database system is ready to accept connections`.

For a managed provider, this is one restore-to-timestamp operation that produces a **new instance**. That new instance has a new hostname, which means new DSN files and a rolling restart, and it is worth rehearsing that the hostname change is the thing that takes longest.

**Choose the recovery target on evidence, not on memory.** The two useful anchors:

```sql
SELECT version, name, applied_at, applied_by
FROM greengateway.schema_migrations ORDER BY version DESC LIMIT 5;
```

tells you when each migration landed, and

```sql
SELECT max(occurred_at) FROM greengateway.audit_events;
SELECT last_position FROM greengateway.audit_stream_state;
```

tells you how far the audit record goes. Recovering to a point before a migration means a target time before that migration's `applied_at`, by a margin, not on the second.

## Verify the restore before you point anything at it

A restore is not finished when the database starts. It is finished when these five checks pass. Run them against the restored database with the **migration** role, before any replica is allowed to connect.

**1. The schema is exactly this binary's manifest.**

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
  gateway migrate check
```

Expected output: a status line and exit `0`. `not initialized` means you restored the wrong thing. `N migration(s) unapplied after M applied` means you recovered to a point before a migration the current binary requires — either recover to a later target, or run `gateway migrate up` deliberately and accept that you have re-applied it.

**2. The deployment binding is this deployment.**

```sql
SELECT * FROM greengateway.deployment_binding;
```

Expected output: exactly one row, naming your `DEPLOYMENT_ID`. A different ID means this database belongs to another deployment and every gateway command will refuse it — which is the binding doing its job.

**3. There is an active policy document.**

```sql
SELECT active_version, document_etag, security_revision, activated_at
FROM greengateway.policy_active;
```

Expected output: one row. **If this is empty, no replica will start**: cluster mode has no "no policy" state and a replica that found none exits with `STATE_BACKEND=postgres requires an initialized deployment`. An empty `policy_active` after a restore means you recovered to a point before the deployment was initialized.

**4. The audit stream is contiguous and the projector checkpoint is sane.**

```sql
SELECT count(*) AS rows,
       min(position) AS first,
       max(position) AS head,
       max(position) - min(position) + 1 AS span
FROM greengateway.audit_stream;

SELECT checkpoint_position FROM greengateway.discovery_projector_state;
```

Expected output: `rows = span` (no gaps), and a `checkpoint_position` that is at most `head`. A checkpoint **ahead** of the stream head means the projector state and the stream were restored from different points — the projector would then skip real events forever. Set it back to the head before starting a replica, and record that you did.

**5. Counts against the last known-good.** Keep the last import report or a periodic count snapshot for exactly this comparison:

```sql
SELECT 'policy_documents' t, count(*) FROM greengateway.policy_documents
UNION ALL SELECT 'connection_records', count(*) FROM greengateway.connection_records
UNION ALL SELECT 'audit_events', count(*) FROM greengateway.audit_events
UNION ALL SELECT 'service_tokens', count(*) FROM greengateway.service_tokens
UNION ALL SELECT 'discovery_signals', count(*) FROM greengateway.discovery_signals
ORDER BY 1;
```

Expected output: numbers that match your last snapshot, minus whatever the recovery target legitimately discarded. A number that is *higher* than the snapshot is a sign you restored a different database.

Only after all five: start **one** replica, confirm `/readyz` answers `200`, confirm `gateway cluster-members` shows it `ready`, and then scale out. The one-replica step exists so that a replica which refuses to start refuses alone.

## Restore drills

A backup you have not restored is a hypothesis. Run a drill on a schedule — quarterly is defensible, monthly is better — and treat it as a real procedure:

1. Restore the most recent backup into an **isolated scratch database**, preserving the backup's `DEPLOYMENT_ID`. The immutable deployment binding is part of the backup; using a different ID must fail verification. Give the scratch environment separate credentials and network rules that cannot reach the production database or business upstreams. Verify the scratch DSN target through the database platform before starting a gateway; the preserved binding cannot distinguish two restored copies. Do not edit binding rows or deployment-scoped data to make a drill pass.
2. Run all five verification checks above.
3. Start one gateway replica against it and confirm `/readyz` answers `200`.
4. Write down how long steps 1 to 3 took. That number, not the retention window, is your real recovery time objective.
5. Destroy the scratch instance.

Never point a scratch replica at the production database to "check the backup". Two logical deployments must never share a database, and the binding will refuse it — but the refusal is a safety net, not a plan.

## When a step fails

**`pg_restore --list` fails on the dump.** The backup is corrupt or truncated. Fall back to the previous one and find out why the newer one is bad before you need it again.

**PITR overshoots — you recovered past the event you were trying to discard.** You cannot go forward from a promoted timeline, but the base backup and WAL are still there: restore again from the same base backup to an earlier target. This is why you keep the base backup until well after the recovery is verified.

**PITR undershoots — too much data is missing.** Same answer, later target. If the WAL archive does not extend far enough, it does not extend far enough; that is the recovery-point objective you actually have, and it is worth writing down honestly rather than discovering twice.

**`gateway migrate check` reports a checksum mismatch after a restore.** The ledger does not match the binary's manifest. Either the restored database is from a different lineage, or the binary is not the one that ran against it. Do not run `migrate up` to "fix" it — that refusal is tamper detection. Identify which of the two is wrong first.

**Replicas will not become ready after a restore, with `config_fingerprint_mismatch`.** This is not a database problem. The static configuration the replicas booted with disagrees; see [the failover runbook](failover.md).

**Everything restored and the Connections are all failing.** The secret store, not the database. Restore or re-point that; the bindings in the database are references, and references to nothing fail exactly like this.
