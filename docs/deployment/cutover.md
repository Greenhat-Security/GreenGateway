# Runbook: standalone to cluster cutover

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is experimental and is not a supported HA configuration until the #241 release gate passes.

**The rule: the cutover is offline, one-way, and verified.** There is no live switch, no dual-write window, and no automatic reverse migration. The standalone deployment stops being the authority at a moment you choose, and the cluster becomes the authority at a moment you choose, and those two moments must not overlap.

Read [the rollback boundary runbook](rollback-boundary.md) **before** you start. It defines the exact point after which going back means accepting data loss, and you want to have read it while you are calm.

## What this build actually imports

Check this table against your deployment before scheduling anything. Every section below is implemented; the point of the table is that you should know what crosses and what does not **before** the night of the cutover, not from the report afterwards.

| Section | What crosses |
| --- | --- |
| `preflight` | writes nothing; proves both configurations valid, every source file openable read-only and parseable by this binary, the schema current, and the namespace empty |
| `policy` | the policy document and its full version history — source version numbers, actors and timestamps preserved — one shared security revision, recomputed ETags |
| `tools` | the tools document and its per-lane name reservations |
| `connections` | records, credential bindings (**references only**), statuses and history, dependencies (`source_revision` 0), MCP and OpenAPI catalogs revalidated on the way in |
| `audit` | SQLite audit events in event order, deduplicated by `event_id`, appended to the durable stream with contiguous positions |
| `observations_and_discovery` | endpoint aggregates and their child rows, reviews (including cleared ones), signals with their revisions, rule suggestions, detector windows, and `discovery_projector_state.checkpoint_position` set to the imported stream head |
| `principals_and_service_tokens` | service-token **hashes** with their prefixes and timestamps. The plaintext never existed on disk and is not reconstructable |
| `validation` | per-table row counts and logical SHA-256 checksums for both sides, a read-only constraint pass, active ETags, the projector checkpoint, and proof that the excluded runtime tables are empty |

Three consequences you must plan around:

- **Service tokens keep working, and that is a security fact as well as a convenience.** The hashes cross, so every token the standalone deployment issued still authenticates against the cluster. If the cutover is also the moment you wanted to rotate credentials, rotate them deliberately afterwards — the import will not do it for you, and a token you meant to retire is now live on the new authority.
- **Discovery history crosses, so signals do not re-fire.** The detector windows come across with the aggregates precisely so the first projector run does not re-raise your whole endpoint inventory as new. Learner template groups are the exception: standalone never persisted them, so they cross as nothing and the cluster relearns them exactly as a standalone restart would. The report counts that as `0` rather than hiding it.
- **Timestamps are truncated to microseconds.** The source keeps RFC 3339 text; the target's columns are `timestamptz`, which holds microseconds. Policy-history, audit and service-token instants are therefore truncated at the write rather than silently rounded by a cast. This is stated so that a sub-microsecond difference is never mistaken for a lost row.

The **principal directory is never imported**: cluster mode has no principal directory, so there is no destination for it — no migration creates the table, and `PRINCIPAL_SQLITE_PATH` is refused in cluster mode. It is a projection of authenticated traffic, and that traffic *is* imported, with the audit log. The report names the source file it left behind (`source.principal_file`, `source.principal_present`, `principal_directory_rows_imported: 0`) so you see it rather than discover it missing afterwards.

The report's `not_imported` field lists everything else deliberately left out — `cluster_members`, `maintenance_jobs`, `execution_leases`, the two rate-limit tables, pending logins, JWT revocations — and the validation pass **proves** those tables empty rather than asserting it in prose. `security_outbox` is named there too, with a caveat worth reading once: the import writes no outbox row of its own, but the policy and tools sections run the ordinary reviewed control-plane commits, and a commit appends one. So that table holds two rows after an import. They describe this deployment's initialization, and they are the reason `security_outbox` is on the `not_imported` list but not on the list of tables proven empty.

The command also never moves secret material. Credential bindings are imported as references; the secrets stay in your secret store, and local-secret keyring material is not touched. A cluster deployment binds credentials through an external secret provider — `CONNECTION_LOCAL_SECRET_KEYRING` is rejected in cluster mode.

If your standalone deployment used the encrypted local-secret keyring, that has a consequence you should see as a **number** before the night rather than as a failed request after it: those secrets live in rows inside `CONNECTIONS_SQLITE_PATH`, nothing carries them across, and every binding that resolved through one resolves through nothing until you re-provision it. The report says how many there are (`source.connection_local_secrets`) and names the omission in `not_imported` (`connection_local_secrets`). A non-zero count is a re-provisioning task on the checklist below, not a defect.

## The command

```
gateway import-standalone --from <standalone-env-file> [--dry-run | --apply [--resume]]
```

Two configurations are involved, and they cannot be one process environment: a configuration that names both a local authority (`POLICY_FILE`, the `*_SQLITE_PATH` settings) and `STATE_BACKEND=postgres` is refused at startup. So:

- **The process environment is the TARGET cluster** — `STATE_BACKEND=postgres`, `DEPLOYMENT_ID`, `DATABASE_URL_FILE` — exactly as every other one-shot command reads it.
- **The source is the file `--from` names**: the standalone deployment's own environment file, parsed and validated through the same `Config` validator the standalone gateway uses. "Both configurations valid" is a real check, not a claim.

Run it with the **migration** role's DSN, beside `gateway migrate up`, not with a serving replica's runtime role. Importing a policy history preserves its version numbers, which means naming an identity column's values and realigning the sequence afterwards — a privilege the least-privilege runtime role deliberately does not hold. See [the roles and grants runbook](roles-and-grants.md).

Modes:

- **`--dry-run` is the default.** It reads the source and the target's emptiness and writes **nothing** — not even the deployment binding, because binding is a write and a dry run that bound a database you then decided against would have changed the thing it promised only to read. Rehearsals are free; run as many as you like.
- **`--apply`** performs the import.
- **`--apply --resume`** re-runs an import interrupted after some sections committed.

`--apply --dry-run` together is a usage error, not a preference: one of the two is a mistake and guessing which would be the dangerous half of the guess. `--resume` without `--apply` is a usage error too — there is no such thing as an interrupted dry run.

Every source read goes through the parser or store standalone mode itself uses. No ad-hoc SQL is ever run against the source databases, and **the source is never written to, in any mode**.

That last part takes one mechanism to be true rather than only intended. Those stores normalize a schema when they open a file — `CREATE TABLE`, `ALTER TABLE ADD COLUMN`, a journal-mode pragma — and the discovery suggestions engine goes further and dismisses open legacy `baseline_allow` suggestions. Pointed at your live standalone deployment, a rehearsal would therefore have thrown away lifecycle work an administrator was still doing. So the command copies each of those databases into a private temporary directory first (`VACUUM INTO`, from a read-only connection, which is the copy that is consistent with a write-ahead log a running gateway is still appending to), lets the stores normalize the copies, and deletes them when the read finishes. The audit log — the one file with no size bound — is not copied: its reader runs no schema statement, so it is opened read-only in place. Budget temporary space for the *other* databases, which are small.

## The cutover

Timings below are for a small deployment. The audit section is the one that scales with your data; the dry run tells you how long it takes, which is the main reason to do one.

### 0. Before the window

- [ ] Read [the rollback boundary runbook](rollback-boundary.md).
- [ ] Provision the database, the two roles, and TLS: [roles and grants](roles-and-grants.md), [TLS](tls.md).
- [ ] Size the pools for the replica count you intend to end at: [pool sizing](pool-sizing.md).
- [ ] Confirm your secret provider holds every credential the standalone deployment's Connections reference, and that a cluster replica can reach it.
- [ ] Plan how service tokens will exist after the cutover (see the table above).
- [ ] Do a full rehearsal — steps 1 to 4 — against a scratch database with a **different** `DEPLOYMENT_ID`. Keep the dry-run report.

### 1. Dry run, against the real target

Nothing is written — to the target *or* to the standalone deployment's own files (see [the command](#the-command)) — so this is safe to run while the standalone deployment is still serving.

```sh
STATE_BACKEND=postgres \
DEPLOYMENT_ID=deploy-prod-eu \
DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
DATABASE_TLS_MODE=verify \
  gateway import-standalone --from /etc/greengateway/standalone.env --dry-run \
  | tee /var/log/greengateway/import-dryrun-$(date -u +%Y%m%dT%H%M%SZ).json
```

Expected output: pretty-printed JSON on stdout and exit `0`. The shape:

```json
{
  "command": "import-standalone",
  "mode": "dry-run",
  "deployment_id": "deploy-prod-eu",
  "schema": { "status": "current", "applied": 11, "version_min": 1, "version_max": 11 },
  "source": {
    "policy_file": "/var/lib/greengateway/policy.json",
    "policy_history_file": "/var/lib/greengateway/policy-history.sqlite",
    "policy_history_present": true,
    "tools_file": "/var/lib/greengateway/tools.json",
    "connections_file": "/var/lib/greengateway/connections.sqlite",
    "audit_file": "/var/lib/greengateway/audit.sqlite",
    "audit_present": true,
    "discovery_file": "/var/lib/greengateway/discovery.sqlite",
    "discovery_present": true,
    "service_token_file": "/var/lib/greengateway/service-tokens.sqlite",
    "principal_file": "/var/lib/greengateway/principals.sqlite",
    "principal_present": true,
    "policy_history_versions": 17,
    "tools": 24,
    "connections": 6,
    "connection_local_secrets": 0,
    "discovery_endpoints": 312,
    "service_tokens": 4
  },
  "sections": [
    { "section": "policy",      "status": "planned", "counts": { "policy_active_version": 18, "policy_documents": 18, "policy_history_versions": 17 }, "checksum": "sha256:...", "duration_ms": 0 },
    { "section": "tools",       "status": "planned", "counts": { "tool_document_version": 1, "tool_name_reservations": 24, "tools": 24 }, "checksum": "sha256:...", "duration_ms": 0 },
    { "section": "connections", "status": "planned", "counts": { "catalog_entries": 88, "connection_documents": 6, "connection_records": 6, "credential_bindings": 7, "current_statuses": 6, "dependencies": 2, "mcp_catalogs": 2, "openapi_catalogs": 1, "status_history": 41, "tool_name_reservations": 12 }, "checksum": "sha256:...", "duration_ms": 0 },
    { "section": "audit",       "status": "planned", "counts": { "audit_events_source": 2000, "audit_events_deduplicated": 1994, "duplicate_event_ids": 6 }, "checksum": "sha256:...", "duration_ms": 8412 },
    { "section": "observations_and_discovery", "status": "planned", "counts": { "detector_states": 312, "discovery_endpoint_reviews": 9, "discovery_endpoints": 312, "discovery_rule_suggestions": 14, "discovery_signals": 27, "template_groups": 0 }, "checksum": "sha256:...", "duration_ms": 0 },
    { "section": "principals_and_service_tokens", "status": "planned", "counts": { "principal_directory_present": 1, "principal_directory_rows_imported": 0, "service_tokens": 4, "service_tokens_inserted": 0 }, "checksum": "sha256:...", "duration_ms": 0 }
  ],
  "validation": {
    "status": "planned",
    "tables": [ { "table": "audit_events", "source": 1994, "target": 0 }, "..." ],
    "checksums": [ { "section": "policy", "source": "sha256:...", "target": "" }, "..." ],
    "checks": []
  },
  "not_imported": [
    "cluster_members", "maintenance_jobs", "execution_leases",
    "rate_limit_buckets", "rate_limit_cardinality",
    "admin_pending_logins", "jwt_revocations",
    "security_outbox (the import announces nothing; a commit appends its own row)",
    "principal_directory (cluster mode has none; the audit log it projects from is imported)",
    "connection_local_secrets (the local-secret keyring stays with the standalone deployment; credential bindings cross as references and must be re-provisioned in the cluster's secret store)"
  ],
  "duration_ms": 8590
}
```

In a dry run `validation.status` is `planned`: the source side of every row count and checksum is real, the target side is empty, and no named check has run, because there is nothing yet to check. After an apply it is `verified`, both sides are populated, and `checks` holds the eight named ones.

**Read four things and write them down.** They are the evidence you will compare against after the apply:

1. Every section's `checksum`. These are SHA-256 over a canonical export, computed the same way on both sides — canonicalized key order, and for the audit log each event framed by its own byte length and the sequence closed by its element count, so a prefix of a longer history never digests to the same value.
2. The audit section's `audit_events_source`, `audit_events_deduplicated` and `duplicate_event_ids`. Duplicates in the source are expected and are deduplicated by `event_id`; a large number is worth understanding before you commit to it.
3. `source.principal_file` — the one source file that stays behind — `source.connection_local_secrets`, which is how many credential bindings you will have to re-provision, and `validation.tables`, whose source column is the row count each section expects to produce.
4. `not_imported` — confirm it says what the table above says. Nothing should be a surprise here on the night.

The report is redacted by construction: it carries counts, checksums, revisions and durations, and never a plaintext token, secret, login material or DSN. Standalone configuration problems are reported by **setting name only**, because the validator's own messages quote the offending value and some of those values are key material.

### 2. Stop control-plane writes on the standalone deployment

This is the beginning of the outage window and the beginning of the one-way part.

- [ ] Announce it. Administrators must stop making policy, tools, Connection and discovery-lifecycle changes.
- [ ] Take the standalone deployment out of the load balancer, or stop it. If you leave it serving read traffic, understand that every audit event it records from this moment forward is an event the cluster will not have.
- [ ] Confirm nothing is still writing: the standalone `POLICY_FILE`'s mtime and the SQLite files' mtimes should stop moving.

### 3. Back up both sides

- [ ] Back up the standalone deployment's whole state directory — `POLICY_FILE`, `TOOLS_FILE`, every `*_SQLITE_PATH`, and the local secret keyring if you use one. **This is the artefact a rollback restores.** Copy it somewhere the cutover cannot touch.
- [ ] Back up the target database, even though it is empty. See [backup and recovery](backup-and-recovery.md).

```sh
tar --create --gzip --file /backups/standalone-precutover-$(date -u +%Y%m%dT%H%M%SZ).tgz \
  -C /var/lib/greengateway .
```

Expected output: no output, exit `0`. Verify it lists what you expect:

```sh
tar --list --file /backups/standalone-precutover-*.tgz | head -20
```

### 4. Migrate

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
  gateway migrate up
```

Expected output: one line naming the migrations applied, exit `0`. Then apply the runtime role's table grants if you have not set default privileges ([roles and grants](roles-and-grants.md)).

### 5. Import

```sh
STATE_BACKEND=postgres \
DEPLOYMENT_ID=deploy-prod-eu \
DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
DATABASE_TLS_MODE=verify \
  gateway import-standalone --from /etc/greengateway/standalone.env --apply \
  | tee /var/log/greengateway/import-apply-$(date -u +%Y%m%dT%H%M%SZ).json
```

Expected output: the same JSON shape with `"mode": "apply"`, every section's `status` as `"imported"`, `"validation": { "status": "verified", ... }` with every entry in `checks` showing `"passed": true`, and exit `0`.

**`validation.status` is the single thing to read first.** The import does not ask you to take its word for the result: it re-reads the target through the cluster's own readers and compares. If that says `verified`, the counts and checksums below are a confirmation rather than a discovery. If the command exited non-zero with `validation_failed`, stop here — see the refusals table.

The apply establishes the database foundation exactly as a replica's boot does, which is how it claims the database for this `DEPLOYMENT_ID` — by the same code path as everything else that writes to it. Each section is its own transaction with its own counts and checksum, so a failure aborts the run and leaves the sections before it committed, which is what makes `--resume` possible.

**Compare the apply's checksums against the dry run's, section by section.** They must be identical. The connections section's checksum is deliberately computed from the *persisted* status fields rather than an aged projection, so a rehearsal and an apply an hour later produce the same number; a difference means the source changed between the two runs, which means step 2 did not hold.

### 6. Start one replica and verify

One. Not all of them. A replica that refuses to start should refuse alone.

```sh
docker compose -f docs/deployment/docker-compose.ha.yml up -d gateway-1
```

Then, in order:

```sh
curl -sS http://gateway-1:8080/readyz
```

Expected output: `{"status":"ready"}` with HTTP `200`. A `503` carries a reason; see [the failover runbook](failover.md) for what each one means.

```sh
gateway cluster-members
```

Expected output: `members=1 live=1` and one `ready` line. (PR 14's cluster status API and UI have not landed on this branch; `gateway cluster-members` is the status surface available today. When PR 14 lands, this step becomes a call to the status endpoint and this runbook should be updated to name it.)

Then check the imported state through the product, not through SQL:

- [ ] The admin policy view shows the policy you expect, with its history and the version count the report named.
- [ ] The tools list matches.
- [ ] Every Connection is present, and its status resolves — a Connection whose credential reference cannot be found in the secret store will say so, and that is a secret-store problem, not an import problem.
- [ ] The audit view shows history from before the cutover.
- [ ] Send one real protected request through and confirm it is allowed or denied exactly as it was in standalone.

Cross-check the counts against the report:

```sql
SELECT 'policy_documents' t, count(*) FROM greengateway.policy_documents
UNION ALL SELECT 'tool_name_reservations', count(*) FROM greengateway.tool_name_reservations
UNION ALL SELECT 'connection_records', count(*) FROM greengateway.connection_records
UNION ALL SELECT 'audit_events', count(*) FROM greengateway.audit_events
ORDER BY 1;

SELECT count(*) AS rows, min(position) AS first, max(position) AS head,
       max(position) - min(position) + 1 AS span
FROM greengateway.audit_stream;
```

Expected output: counts matching the report's sections, and `rows = span` on the stream (contiguous positions, no gaps).

One more, because it is the check that decides whether your discovery views are about to fill up with false alarms:

```sql
SELECT p.checkpoint_position, p.fence, (SELECT max(position) FROM greengateway.audit_stream) AS head
FROM greengateway.discovery_projector_state p;
```

Expected output: `checkpoint_position = head`, and `fence = 0` until the first replica claims the projector. The import sets the checkpoint to the imported stream head precisely so the projector does not re-project history it already carried across as aggregates. A checkpoint behind the head means the first leader will replay imported events and re-raise signals you have already reviewed — the validation pass checks this (`projector_checkpoint_at_stream_head`), so seeing it here should only ever be a confirmation.

**This step is the last point at which rollback is free.** Do not proceed until you are satisfied. See [the rollback boundary runbook](rollback-boundary.md).

### 7. Scale out

Bring up the second replica, confirm both are `ready` in `gateway cluster-members` with the **same fingerprint**, then add them to the load balancer.

```sh
docker compose -f docs/deployment/docker-compose.ha.yml up -d gateway-2 lb
gateway cluster-members
```

Expected output: `members=2 live=2`, two `ready` lines, identical `fingerprint=` values. Different fingerprints mean the two replicas' static configuration differs and the newcomer will sit at `503 config_fingerprint_mismatch` — fix the configuration, do not work around the gate.

### 8. Close out

- [ ] Archive both import reports (dry run and apply) with the backups. Their checksums are the evidence of what was carried across.
- [ ] Keep the standalone backup for at least as long as your rollback window.
- [ ] Do **not** delete the standalone state directory yet, and do not restart the standalone gateway against it. A standalone process that comes back up and writes to those files makes the backup and the files diverge.

## Refusals, and what each one means

Every refusal prints `Error: <code>: <message>` on stderr and exits non-zero. The **code** is stable across releases — script against it, not against the prose.

| Code | Meaning | What to do |
| --- | --- | --- |
| `usage` | argument list is not a legal shape | check `--apply`/`--dry-run` are not both present, and that `--resume` accompanies `--apply` |
| `standalone_env_file_unreadable` | `--from` could not be read | check the path and permissions from inside the container, if containerized |
| `standalone_env_file_malformed` | a line is not `KEY=VALUE`; only the **line number** is reported, because the text may be credential material | fix that line |
| `standalone_config_invalid` | the standalone configuration does not validate; **setting names only**, values withheld | run the standalone gateway against that file to see the full messages |
| `standalone_config_is_not_standalone` | the `--from` file sets `STATE_BACKEND=postgres` | you pointed `--from` at the cluster's environment; it wants the standalone one |
| `standalone_policy_file_missing` | no `POLICY_FILE` in the source | cluster mode refuses to start without an initialized policy document, so there would be nothing a replica could serve |
| `source_sqlite_unreadable` | a configured SQLite file exists but cannot be opened read-only | named with its setting; check the file and its permissions. Preflight proves every configured file openable up front, so you are not told this after three sections have committed |
| `source_snapshot_failed` | a configured SQLite file could not be copied into the command's private snapshot | the readers normalize a schema on open, so they are pointed at a copy and never at your live database. Check the temporary directory's free space and permissions. The command will not fall back to opening the original read-write |
| `source_document_unparseable` | a policy, tools or Connection document on disk is not one this binary can read | a document the importer cannot read is a document the cluster could not serve. Fix it in standalone first, or upgrade the binary |
| `target_not_postgres` | the process environment is not cluster mode | set `STATE_BACKEND=postgres` |
| `target_deployment_id_missing` | no `DEPLOYMENT_ID` | set it |
| `target_unavailable` | the database is not usable | a connectivity, TLS or credentials problem; see [TLS](tls.md) |
| `target_schema_not_current` | the schema is not this binary's manifest | run `gateway migrate up` first |
| `target_deployment_mismatch` | the database is bound to a different deployment | you are pointed at another deployment's database. Stop. A dry run and an apply both refuse with this code — the apply's binding step raises it, and it is never reported as `target_unavailable`, which you would otherwise be entitled to retry |
| `target_namespace_not_empty` | the namespace already holds authoritative state; the message names the occupied tables and counters, never their contents | import into an empty namespace, or `--resume` if this is a continuation |
| `section_conflict` | a section's resource is already initialized with something **other** than what this import would write | `--resume` cannot repair this. The namespace is another import's, or a cluster's |
| `section_failed` | a section's transaction failed, classified, never SQL text | fix the cause and `--apply --resume` |
| `validation_failed` | every section committed, but step 8 could not prove the result correct. The message names the failing check — a row-count difference, a checksum difference between the two sides, a missing or unvalidated constraint, an ETag that does not match the source, a projector checkpoint that is not at the stream head, or a runtime table that is not empty | **Do not start replicas.** This is the one refusal that means the database may hold a wrong state rather than no state. Treat it as a failed cutover: restore the target to empty and start again from step 1, keeping the report — the named check is the whole diagnosis |
| `store_failure` | an underlying store error | as for `section_failed` |

**"Empty namespace" is defined precisely**, and it is worth knowing which side of the line things fall on. Empty means every authoritative content table holds no rows and every authoritative counter still sits where migration seeded it: the audit tables, the policy, tools and Connection control planes, service tokens, the discovery tables, and the counters `security_revision_state`, `audit_stream_state`, `connection_state_revision`, `service_token_state_revision`, `discovery_projector_state`.

Runtime state a replica rebuilds or elects — membership rows, the maintenance ledger, execution leases, rate-limit buckets, pending logins, JWT revocations — is deliberately **not** on that list. A database a replica has merely connected to is still an empty namespace. That is what makes a cutover rehearsal repeatable.

## Resuming an interrupted apply

A section failure leaves the sections before it committed and nothing partial: each section is one transaction.

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
  gateway import-standalone --from /etc/greengateway/standalone.env --apply --resume
```

Expected output: `"mode": "apply-resume"`, with already-committed sections reporting `"status": "already-imported"` and the rest `"imported"`. Exit `0`.

`--resume` skips the namespace-empty check and **only** that check. Every section still recognizes its own completed work by the resource's natural key before writing anything: the policy section by the active document's ETag, the tools section by the tools document's ETag, the connections section by the set of record IDs already present, the audit section by `event_id`. A resource that is initialized with something this import did not write is `section_conflict`, and no re-run repairs it.

Running `--apply --resume` on a complete import is safe and changes nothing: every section reports `already-imported` and the checksums are unchanged. That is also the cheapest way to re-derive the evidence if you lost the report.

## When a step fails

**The dry run's audit section takes far longer than the window allows.** The audit log is the one part of a standalone deployment with no bound at all. It is paged, not loaded into memory, so it costs time rather than memory. Options: schedule a longer window, or trim the standalone audit log's retention *before* the cutover so there is less to carry.

**The apply's checksums differ from the dry run's.** Something wrote to the source between the two runs. Stop, work out what (step 2 is the usual gap: an administrator who did not get the message, or a standalone process still running), restore the target to empty, and start again from step 1.

**A replica will not start after a successful import, saying the deployment is uninitialized.** The policy section did not commit. Check the apply report: the `policy` section should say `imported` with a `policy_active_version`. If it says `planned`, you ran a dry run.

**A Connection's status is failing after the cutover.** Its credential binding is a reference and the secret is not in the cluster's secret provider. That is a secret-store task; the import correctly refused to move key material.

**A caller that worked in standalone now gets `401`.** Service-token hashes *are* imported, so a token that authenticated before should authenticate now; check the report's `service_tokens_imported` count and whether that token was already revoked in the source (revocations cross too). If the count is right and the token is not revoked, the caller is not presenting a service token — look at JWT or IdP configuration, which is static configuration and does not come from the database at all.

**You need to go back.** [The rollback boundary runbook](rollback-boundary.md), now, before doing anything else.
