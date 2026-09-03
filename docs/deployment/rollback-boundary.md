# Runbook: the rollback boundary

Companion to [the cutover runbook](cutover.md) and [the PostgreSQL deployment guide](postgres.md). Cluster mode is experimental and is not a supported HA configuration until the #241 release gate passes.

**The rule: rollback means restoring the pre-cutover standalone backup and starting the standalone gateway against it. It is safe only until the cluster's first control-plane write, first admitted login, or first service-token mutation.** After that, rolling back is not a rollback — it is a restore that discards whatever the cluster decided in the meantime.

There is deliberately no reverse migration, and there never will be one. A "cluster to standalone migration" that reconstructed local authority from shared state would have to decide which replica's view wins, and every such decision is an opportunity for a stale allow. The asymmetry is a security decision, not a gap someone forgot to fill.

## The three zones

| Zone | Where you are | Rollback costs |
| --- | --- | --- |
| **1. Free** | The import has run. No replica has served anything. | Nothing. Restore the standalone backup, start standalone, done. |
| **2. Lossy** | A replica is up and serving, but no control-plane write, admitted login, or token mutation has happened. | The audit events the cluster recorded while serving, and any Connection status observations. Not retrojected into the standalone store. |
| **3. Past the boundary** | Any one of the three events below has happened. | An administrative decision the cluster made and the standalone store never saw. Restoring silently reverts it. |

Zone 2 is not free, and it is worth being precise about what it costs. Every request a cluster replica serves produces audit events, and every audit event is part of your compliance record. Rolling back from zone 2 restores a standalone store whose audit log stops at the cutover. Nothing is corrupted; a window of evidence is simply gone. That may be acceptable for a fifteen-minute smoke test and unacceptable for a day.

Zone 3 is where "roll back" stops meaning what people think it means. The three crossings:

### Crossing 1: the first cluster-mode control-plane write

A policy commit, a tools-registration change, a Connection create/update/credential rebind, or a discovery-lifecycle decision (accepting a rule suggestion is also a policy write). Each of these advances the shared security revision and creates an immutable version row. The standalone backup does not contain it, and restoring the backup reverts it — silently, because nothing in standalone mode knows the cluster ever existed.

### Crossing 2: the first admitted admin login

An OIDC login admitted in cluster mode creates administrator session state in the cluster and consumes a pending-login row. Its existence means an administrator has been operating against the cluster, which means crossing 1 is likely to follow within minutes — and it means that after a rollback that administrator's session refers to an authority that no longer exists.

### Crossing 3: the first service-token mutation

A token issued, rotated or revoked in cluster mode. The plaintext of a service token exists exactly once, at issue; it is never stored anywhere, in either mode. So a token issued against the cluster **cannot be moved into the standalone store by any means**, and rolling back invalidates it permanently.

The import carries the standalone deployment's existing token hashes across (see [the cutover runbook](cutover.md)), which is what makes this crossing detectable rather than immediate: every token the import wrote sits at `revision = 1` and carries the import's own security revision, so a token that has been *changed* in cluster mode is distinguishable from one that was merely carried over. It also removes the reason operators used to cross this line within minutes of a cutover — you no longer have to re-issue tokens to get traffic flowing, so do not.

A revocation is on the wrong side of this line too, and that surprises people: revoking a compromised token in cluster mode is the right thing to do operationally and it still ends your free rollback, because the standalone backup you would restore does not know the token was revoked and would bring it back to life.

## The evidence: the import report

The apply's report is the baseline. Keep it — this is what it is for.

Its per-section `counts` and `checksum` fields record exactly what the import put in the namespace, and its `checksum` values are SHA-256 over a canonical export computed identically on both sides: keys sorted, and for the audit log each event framed by its own byte length with the sequence closed by its element count, so a prefix of a longer history never digests to the same value as the history itself. That last property is why the checksum is evidence rather than a checksum: a namespace that has grown since the import cannot produce the report's number.

Note the `security_revision` value in the report's `policy` and `tools` sections, and the `policy_active_version` and `tool_document_version`. Those four numbers are your boundary markers.

The cheapest way to re-derive the baseline if you have lost the report: run `--apply --resume` against the imported namespace. Every section reports `already-imported`, nothing is written, and the checksums come back identical.

## Deciding which zone you are in, at 3am

Run all four. Each takes milliseconds. Substitute the numbers from your apply report where indicated.

**1. Has the control plane been written since the import?** Compare against the version numbers your apply report recorded. Substitute the three numbers below; anything *above* them was written after the import finished.

```sql
-- Substitute: :policy_active_version, :tool_document_version from the apply
-- report's `policy` and `tools` sections.
SELECT 'policy' AS resource, version, actor_user_id, created_at
FROM greengateway.policy_documents WHERE version > :policy_active_version
UNION ALL
SELECT 'tools', version, actor_user_id, created_at
FROM greengateway.tool_documents WHERE version > :tool_document_version
UNION ALL
SELECT 'connections', c.version, c.actor_user_id, c.created_at
FROM greengateway.connection_documents c
WHERE c.actor_user_id <> 'import-standalone'
ORDER BY created_at;
```

Expected output in zones 1 and 2: **zero rows**. Any row is crossing 1, and the row tells you who and when.

**Use the version numbers, not the actor, for policy.** The import writes the activation it performs as `import-standalone`, but it deliberately preserves the *standalone deployment's own* actors on every history row it carries across — that history is the operator's record and rewriting its authorship would be a lie. So `policy_documents` legitimately contains rows authored by real administrator IDs, all of them at or below the report's `policy_active_version`, and a query that filtered on the actor alone would report a crossing that never happened. Connection documents carry no imported history, so the actor works there.

**2. Has the security revision advanced past the import's?**

```sql
SELECT max(revision) AS current_revision FROM greengateway.security_outbox;
SELECT active_version, security_revision FROM greengateway.policy_active;
SELECT active_version, security_revision FROM greengateway.tool_active;
SELECT last_revision FROM greengateway.connection_state_revision;
```

Expected output in zones 1 and 2: the values the apply report recorded, unchanged. Higher is crossing 1, even if query 1 came back empty — which would mean something wrote without an actor, and is worth understanding before you do anything else.

**3. Has a service token been issued, rotated or revoked?**

```sql
SELECT last_revision FROM greengateway.service_token_state_revision;
SELECT count(*) AS tokens, count(*) FILTER (WHERE revision > 1) AS mutated,
       max(security_revision) AS newest_revision
FROM greengateway.service_tokens;
```

The import writes every token it carries at `revision = 1`, under one shared security revision, and sets the state high-water mark to it. So expected output in zones 1 and 2 is: `tokens` equal to your apply report's `service_tokens` count, `mutated = 0`, and both `last_revision` and `newest_revision` equal to the `security_revision` the report's `principals_and_service_tokens` section recorded.

Anything else is crossing 3, and it is permanent — a token issued against the cluster cannot follow you back, and a revocation performed against the cluster will be undone by the restore. Specifically: more `tokens` than the report means one was issued; `mutated > 0` means one was rotated or revoked; a higher `last_revision` with the counts unchanged means a token changed and you should find out which before deciding anything.

**4. Has an administrator logged in, and has anything been served?**

```sql
SELECT count(*) FROM greengateway.admin_pending_logins;

SELECT event_type, count(*), min(ingested_at) AS first, max(ingested_at) AS last
FROM greengateway.audit_events
WHERE ingested_at > TIMESTAMPTZ '2026-09-01 22:00:00+00'   -- your apply's finish time
GROUP BY event_type ORDER BY 3;
```

Expected output in zone 1: no rows at all. In zone 2: `gateway.ready` and traffic events (`http.request_observed`, `authz.allowed`) — these are the cost of rolling back from zone 2, and the counts tell you how much it is. A `policy.changed`, `connection.changed`, `service_token.changed`, `signal.lifecycle_changed`, `suggestion.lifecycle_changed` or `traffic.endpoint_review_changed` event is crossing 1 or 3, confirming query 1 or 3.

A non-zero `admin_pending_logins` count means a login is **in flight**, not that one was admitted — the row is deleted when the callback consumes it. Treat it as a warning that crossing 2 is about to happen and go and stop the administrator.

## Rolling back from zone 1 or zone 2

1. **Stop every gateway replica.** All of them, before anything else. A replica still serving is still crossing the boundary while you work.

   ```sh
   docker compose -f docs/deployment/docker-compose.ha.yml stop gateway-1 gateway-2 lb
   gateway cluster-members
   ```

   Expected output: every member `stale` or gone.

2. **Re-run the four queries above.** Confirm the zone did not change while you were reading this page. If it did, you are in zone 3; stop and read the next section.

3. **Restore the standalone state directory from the pre-cutover backup**, to the same paths the standalone environment file names.

   ```sh
   tar --extract --gzip --file /backups/standalone-precutover-<stamp>.tgz -C /var/lib/greengateway
   ```

   Restore, do not merge. If the standalone gateway ran at all after the backup was taken, its files have diverged from it and only the backup is a coherent state.

4. **Start the standalone gateway** with its original environment (`STATE_BACKEND=sqlite`, or simply unset — sqlite is the default).

   ```sh
   curl -sS http://<standalone>:8080/readyz
   ```

   Expected output: `{"status":"ready"}` and HTTP `200`.

5. **Verify against the import report.** The report's `source` block names the policy history version count, tools count, Connection count, discovery endpoint count and service-token count it read. Those are what standalone should now show. If they do not match, you restored the wrong backup.

6. **Put it back in the load balancer**, and confirm one real protected request is decided as it was before.

7. **Leave the cluster database alone.** Do not drop it, and do not empty it. It is the only record of what the cluster did in zone 2, and you may want those audit events later. If you intend to retry the cutover, you need an empty namespace — take a dump of the current one first, then drop and recreate the database, then start again at the top of [the cutover runbook](cutover.md). `--resume` will not help: it resumes an interrupted import, and this namespace's sections are complete.

## If you are in zone 3

There is no procedure that gives you both. Choose deliberately, and write down which you chose:

**Option A — go forward.** Fix whatever made you want to roll back, in the cluster. This is usually right, and it is almost always right if the reason was operational (a misconfigured replica, a load-balancer probe, a pool size) rather than a defect in the imported state.

**Option B — restore the standalone backup and accept the loss.** Do this only with an explicit, recorded decision, and only after you have enumerated what is being discarded:

- Run query 1 and record every control-plane write: which resource, which version, which actor, when. Each one is an administrative decision that is about to be reverted, and each one needs to be re-made by hand in standalone afterwards, or consciously abandoned.
- Run query 3 and record the token count. Those tokens are gone; their holders must be re-issued credentials.
- Export the cluster's audit events from the cutover onward before you stop using the database. They are the record of what happened in the window you are about to erase, and they will not exist anywhere else.

  ```sql
  \copy (SELECT * FROM greengateway.audit_events WHERE ingested_at > TIMESTAMPTZ '<apply finish time>' ORDER BY id) TO '/backups/cluster-window-audit.csv' WITH CSV HEADER
  ```

- Then follow the zone 1/2 procedure above.

**Do not attempt to hand-copy cluster rows into the standalone SQLite stores.** The two sides have different revision spaces, different ETag lineages and different identity columns, and there is no tool that reconciles them. That is what "no automatic reverse migration" means in practice.

## Shrinking the boundary

The window between "the cluster is serving" and "the cluster has been written to" is the one you control. Practical ways to keep it wide:

- **Do not let administrators into the cluster's admin UI during the verification window.** Verify with read-only checks and one real protected request. Every step in [the cutover runbook](cutover.md)'s step 6 is deliberately a read.
- **Do the token re-issue last**, after you have decided to keep the cutover — not first, because it is crossing 3 and it is irreversible.
- **Keep the verification window short and scripted.** The four queries on this page are the script; have them in a file before the window opens.
- **Keep the standalone backup for longer than you think you need it.** Its cost is disk; its absence is the whole of option B.
