# Deploying GreenGateway with PostgreSQL (experimental cluster mode)

This guide covers the PostgreSQL foundation of issue #241's cluster mode: backend selection, the secret-file connection string, TLS, pool sizing, and the database roles an operator provisions. **Cluster mode is experimental and is not a supported HA configuration until the #241 release gate passes** — the foundation here is the substrate later PRs build the shared state on, not a finished multi-replica product.

Read [the HA state model](../architecture/ha-state-model.md) and [ADR-0007](../adr/0007-shared-state-and-ha-modes.md) first: they define the single-primary trust boundary, the strict per-request revision discipline, and the failure matrix this deployment shape exists to serve. One cluster is one tenant and one trust domain (ADR-0002 still applies).

## Runbooks

This guide explains the mode. The runbooks beside it are the procedures — exact commands, expected output, and what to do when a step fails. Read them before you need them.

| Runbook | Covers |
| --- | --- |
| [Database roles and grants](roles-and-grants.md) | the migration/runtime split, provisioning, the grants, verifying that the runtime role holds no DDL, and rotation |
| [TLS and the certificate authority](tls.md) | verified TLS to the authority, private and provider CAs, generating material for the example, expiry and CA rotation |
| [Pool sizing and timeouts](pool-sizing.md) | the connection arithmetic against `max_connections`, what each timeout bounds, and how to see pool pressure from the database side |
| [Backup, PITR, and restore verification](backup-and-recovery.md) | what to back up, when, and the five checks that decide whether a restore is finished |
| [Failover](failover.md) | replica failure versus primary failure, why no security read may come from a lagging replica, and `/readyz` reasons |
| [Standalone to cluster cutover](cutover.md) | `gateway import-standalone` end to end: dry run, quiesce, back up, migrate, import, one replica, verify, scale out |
| [The rollback boundary](rollback-boundary.md) | exactly when going back is still free, and the queries that tell you which side of the line you are on |
| [Disaster recovery](disaster-recovery.md) | rebuilding a deployment from the database, the secret store and the static configuration |

An example two-replica deployment is in [`docker-compose.ha.yml`](docker-compose.ha.yml) beside them. Its PostgreSQL service is a single container and is labelled as an example only — use a managed or HA PostgreSQL in production.

## The deployment shape

```
 callers ──> load balancer ──> GreenGateway replica 1 ─┐
                         ──> GreenGateway replica 2 ─┼──> one PostgreSQL primary (the authority)
                         ──> GreenGateway replica N ─┘
```

- Two or more stateless gateway replicas behind one load balancer.
- One writable PostgreSQL primary as the single authority for shared mutable state. A lagging read replica is never consulted for security decisions; do not point the gateway at a pooler or a read endpoint.
- Every replica carries the same `DEPLOYMENT_ID` and a matching static-configuration fingerprint; a replica that disagrees about authentication, proxies, cookies, exemptions, routing, egress, or key generation cannot become ready.
- Every replica's DSN points at the same primary with the same database role.

Standalone mode (`STATE_BACKEND=sqlite`, the default) remains the recommended single-instance shape and is unchanged by any of this.

## Enabling cluster mode

Three settings select the mode; everything else has a safe default:

```sh
STATE_BACKEND=postgres
DEPLOYMENT_ID=deploy-prod-eu          # stable, non-secret, 1-64 bytes, [A-Za-z0-9._-] with letter/digit ends
DATABASE_URL_FILE=/run/secrets/greengateway/database-url
```

Startup fails closed, naming the setting, when:

- `DEPLOYMENT_ID` or `DATABASE_URL_FILE` is missing in postgres mode;
- any writable local authority (`POLICY_FILE`, `TOOLS_FILE`, `CONNECTION_LOCAL_SECRET_KEYRING`, or any `*_SQLITE_PATH`) is set alongside postgres — in cluster mode the database is the single authority, and a local store next to it is a fallback path, not a leftover. The keyring is on that list because the secrets it encrypts live in the connections SQLite database, which cluster mode does not have: a cluster deployment binds credentials through one of the external secret providers instead;
- the database does not answer the connectivity check within `DATABASE_STARTUP_RETRY_LIMIT` retries (backoff starts at 250 ms, doubles, and caps at 8 s; `0` fails on the first attempt) — an unreachable authority is a startup failure, never a silent fallback to local state;
- `STATE_BACKEND=sqlite` is set with `DEPLOYMENT_ID`, `DATABASE_URL_FILE`, `DATABASE_TLS_CA_FILE`, a cluster-only keyring, or a `DISCOVERY_PROJECTOR_*` setting configured — material a mode will never read is rejected rather than ignored.

Moving a deployment from sqlite to postgres is a one-way, verified, offline import — `gateway import-standalone`, in [the cutover runbook](cutover.md); there is deliberately no live switch and no automatic reverse migration.

## The connection string

`DATABASE_URL_FILE` names a file containing one `postgresql://` URL. The connection string is credential material: it is read once at startup through the same bounded, permission-checked reader the TLS material uses, and its contents never appear in configuration, `Debug` output, logs, metrics, status, or errors.

The file must:

- be a regular file of at most 8 KiB;
- grant no group or other permission at all (`chmod 0400`; a Kubernetes Secret volume needs `defaultMode: 0400` — the default `0644` is refused);
- contain a `postgresql://` URL naming its **host, user, and database explicitly**. Ambient defaults (the OS account name, a localhost socket) are not trusted: a DSN that would quietly mean a different database on a different host is a misconfiguration, and it is treated as one;
- carry only these query parameters: `user`, `password`, `host`, `port`, `dbname`, `application_name`. Anything else — `sslmode`, `options`, and anything unrecognized — is rejected. TLS policy comes from `DATABASE_TLS_MODE`, and the session timeouts (`statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout`) are set by this gateway from the `DATABASE_*_TIMEOUT_MS` settings as startup parameters on every pooled connection; a DSN that could override either would make the operator's configuration a guess.

Example DSN file:

```
postgresql://greengateway@db.internal.example.com:5432/greengateway?application_name=greengateway-eu-1
```

## TLS

Production connections require TLS with certificate and hostname verification — the default `DATABASE_TLS_MODE=verify`, verified against the platform trust store plus the optional `DATABASE_TLS_CA_FILE` bundle layered on top (extra anchors, never a replacement). A server that will not speak TLS fails the connection; there is no plaintext fallback.

The one exception is named for what it is: `DATABASE_TLS_MODE=loopback-dev` skips TLS entirely and is refused at startup for any target that is not loopback, the name `localhost`, or a Unix socket. It exists for development against a local database and for CI, and it cannot quietly become a production plaintext connection because the refusal names the setting.

Full TLS in practice:

- Give the PostgreSQL server a certificate for the hostname in the DSN, from a CA the gateway's platform trust store already knows, or
- put that CA in a PEM bundle at `DATABASE_TLS_CA_FILE` (public material: world-readable is fine, group/world-writable is refused).

The commands to verify a chain, to generate material for a lab, and the CA-rotation order that avoids an outage are in [the TLS runbook](tls.md).

## Database roles: least privilege

Provision two roles. The runtime role holds only what the gateway's operations need; the migration role holds DDL and exists for the migration job. Separating them means the credentials a replica runs with every day cannot change the schema. The full procedure — the grants in the order they can actually run, the two commands that prove the boundary holds, and password rotation — is [the roles and grants runbook](roles-and-grants.md).

```sql
-- One-time, as a superuser or the database owner.

-- The runtime role: DML and sequences only, no DDL, no superuser.
CREATE ROLE greengateway LOGIN PASSWORD '<set-by-your-secret-manager>';
GRANT CONNECT ON DATABASE greengateway TO greengateway;

-- `gateway migrate up` (below) creates the greengateway schema and its
-- ledger. After the first migration, grant the runtime role exactly what
-- validate-only pods need:
--   GRANT USAGE ON SCHEMA greengateway TO greengateway;
--   GRANT SELECT ON greengateway.schema_migrations TO greengateway;
-- plus the table privileges as the shared-state PRs land their tables
-- (SELECT/INSERT/UPDATE/DELETE ON ALL TABLES IN SCHEMA greengateway, and
-- USAGE/SELECT on its sequences).

-- The migration role: DDL, used only by the migration job/CLI.
CREATE ROLE greengateway_migrator LOGIN PASSWORD '<set-by-your-secret-manager>';
GRANT greengateway TO greengateway_migrator;
```

Notes:

- The runtime role needs no advisory-lock privileges beyond connection — PostgreSQL advisory locks need none — and no role in `pg_write_all_data` or anything administrative.
- Runtime-role connections are what serving replicas open; point their `DATABASE_URL_FILE` at the runtime role's DSN. The migration job's DSN points at the migration role.
- The grants above are commented because they can only run after the schema exists; the migration job runs them (or an operator does) once, after the first `migrate up`.
- CI proves the boundary from the other side: a role with nothing but `LOGIN` can run the validate-only check against a migrated schema and cannot bootstrap or migrate a clean one.
- Rotate both passwords through the operator's secret manager; updating the DSN file and restarting picks up the new value.

## Schema migrations

The schema lives in one `greengateway` schema, built by checked-in, ordered, checksummed migrations and recorded in a ledger table (`greengateway.schema_migrations`: one row per applied migration, with its checksum). Pooled sessions pin `search_path` to that schema and `pg_catalog`, so nothing resolves objects through ambient defaults.

Two one-shot commands, run from a migration job or an operator shell (they connect, print one line, and exit — they never serve):

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=... DATABASE_URL_FILE=... \
  gateway migrate check   # validate only; exits nonzero when not current
STATE_BACKEND=postgres DEPLOYMENT_ID=... DATABASE_URL_FILE=... \
  gateway migrate up      # apply pending migrations under the advisory lock
```

`migrate check` is a gate for scripts and CI: it exits `0` only when the schema is current, printing its status line (`not initialized`, or `N migration(s) unapplied after M applied`) and exiting `1` otherwise — refusals (tamper, newer gateway) print their reason and exit `1` as errors. `migrate up` exits `0` on every clean outcome, including a no-op run.

The rules, enforced by `check`, by `up`, and by every serving replica's startup:

- **Every migration is one transaction with its ledger row.** A failed migration rolls back completely; there is no dirty half-applied state and no automatic downgrade.
- **The ledger must be a checksum-matching, gap-free prefix of the binary's manifest.** An unknown version (written by a newer gateway), a checksum mismatch (edited migration files), or a deleted/reordered row is refused — by `check` with the reason, and by startup, fail closed.
- **Serving pods validate only.** A replica that finds the schema behind the binary fails startup naming `gateway migrate up`; it never migrates by itself. `DATABASE_AUTO_MIGRATE=true` opts a development deployment into auto-migration at startup and changes nothing else: a tampered ledger still refuses.
- **Concurrent migrators are safe.** `migrate up` serializes on a stable advisory lock (released by closing the migrator's connection, on every code path); simultaneous jobs produce exactly one applier and one no-op observer. Migration statements and lock waits run under `DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS`, bounded per transaction.
- **Rolling upgrades coexist.** Migrations are additive (expand first; destructive cleanup is a later, explicit step), so version N and N+1 binaries can serve against one schema during a rollout. A binary never activates a document version it cannot parse — those rules land with the control-plane PRs, on this ledger. A security resource a release introduces (the JWT revocation denylist, for instance) is enforced by replicas at that release: during the rollout an older replica keeps its pre-upgrade behaviour, so a withdrawal is deployment-wide once the rollout completes (`revoke-jwt` says so). The membership PR adds the minimum-version fence that makes the write path refuse while older replicas are still registered.
- **One deployment per database.** Every authoritative pointer and revision counter in the schema is a singleton, so a database holds exactly one deployment's state. Establishing the foundation binds the database to its `DEPLOYMENT_ID` (`greengateway.deployment_binding`, from migration 0007) once the schema is current, and refuses a database bound to another deployment — at startup (before or after development auto-migration), in every one-shot command, in `gateway migrate up` once it has applied, and in `gateway migrate check` when the schema is current (an older schema reports the upgrade it needs first).

Rollback boundary: there is no schema downgrade. Rolling back an application release means redeploying the previous binary against the still-compatible schema (additive migrations keep it readable); recovering a damaged ledger or an unwanted migration state means restoring the database from backup — PITR to a point before the migration, verified with `gateway migrate check` before replicas restart. Take a backup or snapshot before every `migrate up` ([the backup and recovery runbook](backup-and-recovery.md)); that snapshot is also the pre-cutover restore point for the standalone-to-cluster import below.

## Pool sizing and timeouts

The pool math against the server's `max_connections`:

```
replicas x DATABASE_POOL_MAX + migrator/leader headroom  <=  max_connections - superuser_reserved_connections
```

With the default `DATABASE_POOL_MAX=10`, three replicas need `3 x 10 + headroom`: 35 of the server's connections, leaving the rest for the migration job, operators, and other clients. The pool opens connections lazily; the ceiling is a ceiling, not a startup cost.

Every pooled session carries server-side bounds set at connection time, so no statement can outlive them regardless of what code runs later:

| Setting | Default | Server-side effect |
| --- | --- | --- |
| `DATABASE_STATEMENT_TIMEOUT_MS` | 15000 | `statement_timeout` — any one statement |
| `DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS` | 30000 | `idle_in_transaction_session_timeout` — a session sitting in an open transaction |
| `DATABASE_LOCK_TIMEOUT_MS` | 5000 | `lock_timeout` — waiting on a lock |

Client-side bounds: `DATABASE_CONNECT_TIMEOUT_MS` (default 5000) caps establishing one connection, and `DATABASE_ACQUIRE_TIMEOUT_MS` (default 5000) caps checking one out of the pool.

The headroom term itemized, worked examples at three and eight replicas, the session-pooling-only rule for connection poolers, and the `pg_stat_activity` queries to run when the pool is the suspect are in [the pool sizing runbook](pool-sizing.md).

## The policy control plane

The policy document is the first shared resource on the ledger (issue #241, PR 7). In cluster mode there is no writable `POLICY_FILE`: the authority is the database, and every mutation through the admin API is one transaction — a new immutable `greengateway.policy_documents` version (which is also the history entry), the next security revision from `greengateway.security_revision_state`, the `greengateway.policy_active` pointer advance, and one `greengateway.security_outbox` change record, all committing together or not at all.

What that buys, and what it costs:

- **Compare-and-swap on `If-Match`.** Two writers presenting the same current ETag (on one replica or on two) produce exactly one winner and one `412`; the loser's transaction writes nothing. The ETag is the SHA-256 of the canonicalized document, so it is stable across replicas.
- **A deployment is initialized exactly once.** The first policy is an explicit act (the standalone-to-cluster import workflow of PR 15, or a seeding tool); a replica that starts against a database with no active policy fails startup saying so. It never serves protected traffic with no policy and never falls back to local state.
- **Strict per-request revision checks.** Every protected request reads the current security revision from the primary after the request starts. If the replica's compiled snapshot is keyed by that revision, the request serves under it (and the authorization audit event records `security_revision`); if the replica is behind, it reconciles within a bounded 250 ms budget (fetch, validate, atomic swap) and otherwise returns `503` with zero upstream attempts — never a stale allow, and never a `401`/`403` for a dependency failure. The revision check is one round statement per request; the state model's budget for it is 5 ms p99 warm.
- **An invalid document is refused, everywhere.** A document that fails validation (or whose recorded ETag does not match its body) fails startup, fails reconciliation, and fails commits — fail closed, with the last valid compiled snapshot still serving only until the revision it was keyed by is superseded.
- **History and rollback.** `GET /v1/admin/policy/history` pages the immutable versions newest-first, and rollback commits the target version as a new version. There is no in-place edit and no delete.

`LISTEN/NOTIFY` is deliberately absent here: correctness comes from the durable revision counter plus reconciliation (per-request checks now; the background poller keeps replicas warm between requests), and notifications can only ever be a latency optimization on top.

## The tools control plane

The tools document (the TOOLS_FILE's local lane: `schema_version` plus the manually-registered tools) is the second shared resource on the same ledger (issue #241, PR 8), with exactly the policy document's model: immutable `tool_documents` versions doubling as history, one `tool_active` pointer, the same shared security-revision counter, and one outbox row per commit. The managed tool lanes (per-connection MCP and OpenAPI catalogs) remain derived state owned by their connections and publish through the connection surfaces.

Differences from the policy plane, and why:

- **An empty tools document is valid** (standalone without TOOLS_FILE serves exactly that), so a first boot seeds one empty document idempotently — racing first boots produce exactly one seeded document. There is no uninitialized-deployment failure mode here.
- **One security revision covers every resource.** The strict per-request gate compares a single compiled-revision watermark against the one counter: a policy commit, a tools commit, or (later) a token change all advance it, and a replica is current only when it has confirmed *every* resource at or below the counter. The authorization audit's `security_revision` records that watermark.
- **Registration commits through the authority.** `POST /v1/admin/tools/openapi/register` reads the authoritative document and ETag, merges, validates against the replica's current lanes, commits the new immutable version under the request's `If-Match` (a racing writer loses with `412`), and installs the lane. A commit that cannot compile locally for a reason the authority does not judge is durable at the authority and fails closed on that replica until reconciliation resolves or surfaces the conflict.
- **A request dispatches under the Connection state it was admitted with.** When the gate admits a request it pins the current Connection snapshot for that request's whole dispatch; the proxy and the tool executor resolve every Connection target from it, never from a snapshot a reconcile installed while the request was in flight. A request admitted at revision N therefore dispatches to N's endpoints under N's authorization — never to an endpoint from N+2 under an allow that N+1 withdrew.
- **Reconciliation converges in any order.** A replica installing content the authority has committed treats a name another lane still holds as what it provably is — stale, since the authority reserved the name for the installing owner and legacy projections carry no catalogs — and evicts that holder rather than refusing; the holder's own authoritative content, which no longer carries the name, follows in the same pass. A name that moved between lanes, or two names swapped, therefore installs on a lagging replica whichever lane it reconciles first. Request-path installs, which run before the authority has accepted anything, still refuse — and so does an authoritative install whose name collides with a tool this replica's static configuration holds (a legacy projection's MCP proxy is not reserved at the authority), since that is a real collision and not staleness. Cluster-mode boot merges use the same eviction: the boot seeds are read one resource at a time, so a name that moved between two seeds' revisions installs rather than aborting startup, and the gate's first pass reconciles every resource to the current revision before a request is served. A pass also re-reads the shared counter before publishing its watermark and goes again if a commit landed mid-pass, so the watermark it publishes never trails the content it installed.
- **Tool names are reserved at the authority.** `greengateway.tool_name_reservations` holds one row per published tool name across the local lane and every managed OpenAPI and MCP catalog. Each lane's commit replaces its own rows inside its transaction, and the primary key refuses a name another lane holds: the writer gets `409` naming the holder, and nothing is written. Two lanes racing to publish one name therefore produce exactly one winner, and the authority never holds a set of documents no replica's registry can install — which matters because a lane conflict at reconcile time fails the security gate closed on every replica. Replacing the holder's catalog (or document) without the name frees it.
## The Connection control plane

Connections (issue #240's first-class Connection records, their credential bindings, their managed MCP and OpenAPI catalogs, and their safe status history) are the third shared resource on the same ledger, and the last one PR 8 adds. `CONNECTIONS_SQLITE_PATH` is rejected in cluster mode: the authority is `greengateway.connection_records` and the tables beside it.

What is authoritative, and what is derived:

- **Records and their catalogs are authoritative.** Every create, replace, delete, and catalog replacement is one transaction that writes the row, appends the immutable specification version, advances the shared security-revision counter, records the connections high-water mark, and appends an outbox row identifying the Connection. Two `resource_type` labels separate the two counters the outbox carries: `connection` rows are a specification-version chain (`to_version` 0 marks a deletion), `connection_catalog` rows carry a catalog revision.
- **Status history, dependency rows, and activity timestamps are derived.** They are written on the same transaction but authorize nothing: status is observational, and the dependency rows exist to refuse an admin delete that would orphan a live reference — which PostgreSQL also refuses referentially (`ON DELETE RESTRICT`).
- **Reconciliation covers records first, then catalogs.** The catalog republish filters on whether each Connection is still enabled and still of the right kind, so it must run against the records the authority just returned; the other order would keep serving a catalog whose Connection was disabled on another replica.
- **Persisted catalogs are re-validated when loaded**, exactly as the standalone loader does: contiguous ordinals, the catalog validators, and for OpenAPI entries the canonical encoding this binary would write. A row edited out of band, or a constraint dropped, surfaces as corruption at startup and on every read rather than as tools to serve.
- **A record this replica cannot enforce fails the gate closed.** If an enabled Connection's credential binding cannot be resolved here, reconciliation refuses rather than publishing it — a replica that cannot honour the current revision stops serving instead of serving the previous one.

Two things are deliberately absent in cluster mode:

- **`connection_local_secrets` is not ported.** The local secret keyring encrypts material inside the connections SQLite database, so `CONNECTION_LOCAL_SECRET_KEYRING` is rejected alongside `CONNECTIONS_SQLITE_PATH`. A cluster deployment binds credentials through one of the external secret providers (Vault, GCP, Azure, AWS, Kubernetes).
- **Dependency rows are published asynchronously.** The two callers that derive them — the proxy-route builder and the tool registry's definition validator — are synchronous by construction and have no async context to write from, so the set is queued and flushed by a background task and by every reconcile pass. An admin delete flushes the queued sets first and is refused if that flush fails, so the guard is complete before the delete is judged; flushes and mutations share one lock, so a batch the background flusher has already taken is written before a delete is judged rather than requeued for an owner that no longer exists. The store's referential constraint (`ON DELETE RESTRICT`) remains the backstop. Those rows authorize no request.
- **A deleted Connection takes its specification versions with it**, exactly as the standalone store does: the versions are the record's history, not a ledger that outlives it. The deletion is recorded in the outbox (`to_version` 0) and attributed by the admin audit event the handler records with its actor.

## Service tokens

Service tokens are the first authentication resource on the shared ledger (issue #241, PR 9). `SERVICE_TOKEN_SQLITE_PATH` is rejected in cluster mode; the authority is `greengateway.service_tokens`, and every replica verifies against it.

What changes, and why it is safe:

- **Every token mutation is a committed control-plane mutation.** Create, revoke, and rotate each run one transaction that advances the shared security revision, sets the resource's high-water mark to that revision, and appends an outbox row naming the token. Verification is observational and moves nothing.
- **A revoke on any replica is refused by the next request on every replica.** The validator still keeps its bounded, TTL-limited cache, but in cluster mode a cached verification is served only while the shared security revision still reads what it read when the entry was made — one indexed singleton read per request. A revoke moves that revision inside its own transaction, so the very next request on any replica, however fresh its cache, goes back to the store and is refused. The standalone caveat in `docs/configuration.md` (revocations from another process take effect no later than the cache TTL) does not apply in cluster mode.
- **A revoke cannot be undone by a racing verify.** The `last_used_at` write carries the revoked/expired guard in the same statement, so it either touches a live row or touches nothing; expiry is judged by the database clock.
- **The cache cannot outlive the authority's clock.** `verify` returns the remaining lifetime measured at the database, and the validator caps its cache entry with it, so a replica whose clock lags cannot keep serving an expired token until the cache TTL elapses. The cap is anchored before the verification round-trip, so the round-trip's own duration is never credited to the token. Validity is the authority's verdict on the authority's clock alone: a replica whose wall clock runs ahead never rejects a token the authority just accepted. Expiry moves no revision, which is why the revision check alone would not cover it.
- **Concurrent rotations are serialized by the token's row lock** and both succeed; the later commit's plaintext is the live one and every earlier plaintext is dead. A rotate that loses to a revoke is refused as a conflict; a revoke that lands after a rotate closes the rotated token. Either way no plaintext is live after a revoke.
- **A dependency failure is `503`.** A store or revision read that fails answers `503`, on the request path and on the token admin endpoints alike — never `401`/`403`, and never a fallback to the cache.

The plaintext token continues to appear exactly once, in the response to create and rotate; the store holds only its SHA-256. A creating principal whose ID exceeds the record's 512-byte bound, and a list cursor whose timestamp does not parse, are refused as the caller's errors (`400`) before the insert or the cast that would otherwise surface them as store failures.

### JWT revocations

Cluster mode wires a real `RevocationStore` behind every JWT provider's validator: `greengateway.jwt_revocations`, a shared denylist keyed by the provider's principal issuer (the configured issuer, normalized, or `provider:<name>` when none is configured) and a SHA-256 digest of the `jti` under the deployment ID and that issuer. The raw `jti` never reaches the database, and an equal `jti` from two issuers is two different JWTs. A `jti` is not consume-once: a row means the JWT was withdrawn, its absence means nothing, and bearer reuse stays valid.

Every JWT that carries a `jti` is checked against the denylist on every request, on every replica; a denylist that cannot be consulted answers `503`, never `401`. Expiry is judged by the database clock. A row stays effective for the validator's `exp` leeway (60 seconds) plus a two-second rounding and clock-skew margin past its `expires_at` (the token's own `exp` when known) — the validator accepts the token until the leeway ends, sampling a whole-second clock of its own — and only after that is it a no-op on read and reclaimable by cleanup. A revoke whose `expires_at` is already past the retention window is refused as the caller's error rather than recorded as an ineffective row, and the cutoff is judged again under the revision lock on the statement clock, so a revoke that waited behind another commit cannot record a row that lapsed during the wait.

There is deliberately no admin HTTP endpoint for revoking JWTs yet — a permission model for withdrawing other people's sessions is a product decision — so the write path is an operator command, run with the same environment as a replica:

```bash
gateway revoke-jwt https://issuer.example/ <jti> 2026-12-31T00:00:00Z
```

```bash
gateway jwt-revocations-cleanup 1000
```

The first records the withdrawal as a committed control-plane mutation (it advances the shared security revision and appends an outbox row naming the digest); a repeat inside the row's effective window with no longer expiry spends nothing, while a repeat whose earlier finite row has lapsed, or that carries a later or unbounded expiry, replaces the row — a lapsed revocation never turns a break-glass revoke into a silent no-op. The second reclaims rows past their expiry and leeway, bounded per run and on the expiry index; the maintenance singleton (below) runs the same step on every pass, so scheduling it is no longer needed.

### Admin login state

When `ADMIN_LOGIN_PROVIDER` is set, the OIDC login flow's pending state (the `state` a browser is sent out with, and the PKCE verifier and nonce it must present back) lives in `greengateway.admin_pending_logins`, so the callback completes on whichever replica receives it — no sticky routing. A login's TTL starts when it is admitted (after the admission lock, on the statement clock), and the flow's ID-token validator refreshes its JWKS on the same background schedule as the bearer validators. The `state` (a 128-bit random value) is stored only as a digest under the deployment ID, and the per-client quota key is an HMAC under the primary login key rather than a plain digest of an enumerable address; the verifier and nonce are sealed with XChaCha20-Poly1305 under `ADMIN_LOGIN_KEYRING` (the connections keyring's key-file discipline, files beneath `CONNECTION_SECRETS_ROOT`), with the deployment ID, the row, and the field bound as associated data. Consumption is one transaction — a `DELETE … RETURNING` guarded by the database clock, then opening both envelopes — that commits only when the envelopes open, so exactly one concurrent callback, on any replica, completes a login, and a replica whose keyring cannot open the row rolls the delete back for one that can. Admissions serialize on a transaction-scoped advisory lock so the global and per-client quotas hold across replicas (the three limits are part of the static-configuration fingerprint, so replicas apply one set), and each admission prunes a bounded number of expired rows. A store that cannot be consulted answers `503` on both `/auth/login` and `/auth/callback`; it is never reported as an unknown state and no code is exchanged at the identity provider.

## Shared rate limits and execution leases

Cluster mode enforces the configured rate and concurrency limits across the cluster (issue #241, PR 10), not per replica.

**Rate limits.** The process-local buckets stay in front as each replica's emergency bound, and every request they allow -- bar the five operational endpoints below -- is then decided by one atomic statement on `greengateway.rate_limit_buckets` using database time: GCRA (the local token bucket written as one comparison and one assignment), so one configured burst of N permits N requests across all replicas together, refilling at the configured rate on the database clock. Rows are keyed by an HMAC under `RATE_LIMIT_KEYRING` (required in this mode) over the deployment ID, the lane, and the caller key, so no address or principal reaches the database. Cardinality is bounded exactly: `greengateway.rate_limit_cardinality` counts live buckets and moves in the same statement that inserts or deletes them, and a new key that pushes the count past `RATE_LIMIT_MAX_BUCKETS` evicts the oldest buckets in one bounded statement. A limiter that cannot be consulted answers `503` with zero upstream attempts -- never a silent allow and never `429`. The exception is `/health`, `/livez`, `/readyz`, `/startupz`, and `/metrics`, which are decided by the local bucket alone and never consult the authority: a fail-closed gate in front of them would answer `rate limiter unavailable` in exactly the outage `/readyz` exists to report, leaving an orchestrator unable to tell `storage_unavailable` from `schema_incompatible` from a limiter that is merely busy, and refusing `/metrics` at the moment an operator most wants the scrape. They are not unlimited -- each replica's local bucket still bounds them, and it spends no round trip -- but their bound is per replica rather than per deployment, which is the price of an endpoint that answers when the database does not. `gateway rate-limit-buckets-cleanup [limit]` reclaims buckets idle for `RATE_LIMIT_BUCKET_TTL_MS` by the database clock (bounded per run, idempotent, keeps the count exact); the maintenance singleton (below) runs the same step on every pass, so scheduling it is no longer needed. The `rate_limit_shared_decisions_total{lane,outcome}` counter reports `allowed`, `denied`, and `unavailable` decisions.

**Execution leases.** The tool runtime's global limit and each tool's `max_concurrent` are slots in `greengateway.execution_leases` (`global`, and `tool:<name>`), so they bound the cluster; the local semaphores remain the per-replica bound underneath, and the local queue depth is still per replica. Acquiring a slot is one statement that takes the lowest free-or-expired slot with a fence drawn from one sequence for the whole deployment, so every acquisition carries a strictly larger fence than every earlier one; a lost race returns no row and the runtime retries with jittered backoff inside `TOOL_RUNTIME_QUEUE_TIMEOUT_MS`. A running invocation renews at a third of `TOOL_LEASE_TTL_MS` and is cancelled locally (`lease_lost`) on the first failed renewal, so its work stops before the slot can be reclaimed; a crashed holder's slot returns only after the TTL elapses on the database clock; release on normal completion frees the slot at once. A lapsed holder can neither renew nor release a successor's slot, and `is_current` is the fence check a fenced write of shared follow-up state makes (the durable observations of PR 11 are the first). An authority that cannot be consulted refuses admission (`503`, `authority_unavailable`) before any work starts.

## Global discovery

Cluster mode has no per-process discovery aggregator (issue #241, PR 11). `DISCOVERY_SQLITE_PATH` is rejected like every other local store; discovery is always on, and its authority is the set of `greengateway.discovery_*` tables (migration 0009) that mirror the standalone SQLite schema column for column, plus three that only cluster mode needs: the persisted detector windows, the learned path-template groups, and `discovery_projector_state`.

**Observations are audit events, and the durable audit stream is the ingestion path.** Every replica emits one `http.request_observed` event per request into the PostgreSQL audit store, which stores it idempotently by event ID and numbers it on the commit-ordered stream (PRs 5-6). Nothing new is ingested for discovery, so a replayed or duplicated observation cannot inflate a count: the second copy of an event ID is not stored, and an event that is stored is projected exactly once.

**One fenced projector.** One replica at a time — whichever holds the single slot of the `discovery-projector` scope in `greengateway.execution_leases`, under `DISCOVERY_PROJECTOR_LEASE_TTL_MS` — runs the same in-memory aggregation the standalone sink runs, fed from `stream_after(checkpoint)` in batches of `DISCOVERY_PROJECTOR_BATCH` rows, polling every `DISCOVERY_PROJECTOR_POLL_MS` when idle. Every flush is one transaction that locks `discovery_projector_state`, verifies the row's fence is the leader's lease fence, writes the endpoint rows, detector state, learner groups, and newly opened signals, and advances the checkpoint to the last stream position read — so a crash between read and commit applies nothing and the successor resumes from the committed checkpoint, and a leader whose lease was reclaimed has its next flush refused (`Conflict`) with nothing applied. Claiming leadership writes a strictly larger fence into the same row, so a stale leader can neither claim nor commit. Detector windows and learned templates are part of what the flush persists, so a successor continues the same error and volume windows rather than restarting them: a signal that needs history across a failover fires exactly once. Signals are unique cluster-wide by `(signal_type, target_kind, target_key)` (`INSERT ... ON CONFLICT DO NOTHING`), and the leader emits `signal.opened` only for the signals its own batch opened. A flush whose COMMIT the server applied but the client never heard about is retried as the identical batch and changes nothing: the writes are absolute, the `projected_events` counter is guarded by the checkpoint the row already carries, and the batch's opened signals are found again by their ids so they are announced exactly once.

**Eviction is global.** `DISCOVERY_ENDPOINT_LIMIT` bounds the projector's working set, and only the leader evicts — the least-recently-seen endpoints on the global `last_seen` order (event timestamps, ties by key — the one order a successor can rebuild from the rows, so a failover evicts exactly what the uninterrupted leader would have), under its fence, deleting their rows and derived signals in the flush — so no replica can evict an endpoint another replica's traffic still evidences.

**Every replica reads the same tables.** The admin traffic, schema, signals, and principals surfaces are served by a PostgreSQL read store with the same ordering, cursors, filters, and inferred-schema threshold as the standalone store, so a page fetched from one replica continues correctly on another. The request-path schema-conformance check reads a per-replica snapshot that a background task refreshes from the read store every five seconds (observed endpoints, plus inferred schemas for the endpoints that replica's traffic has asked about, bounded); the request path never queries PostgreSQL. Discovery views therefore lag live traffic by the projector cadence plus the refresh interval, which is the "observational state may lag" row of the HA state model, never a stale allow.

## Discovery lifecycle workflows

Signals, rule suggestions, and endpoint reviews are decided by administrators, and in cluster mode two administrators can be talking to two replicas. Issue #241, PR 12 makes every one of those decisions a compare-and-swap and makes accepting a suggestion one transaction.

**Every lifecycle row carries a revision.** Migration 0011 adds `revision bigint NOT NULL DEFAULT 1` to `discovery_signals`, `discovery_rule_suggestions`, and `discovery_endpoint_reviews`; standalone SQLite gets the same column in place when the store is opened, so both modes expose it. Every read of a signal, suggestion, or review returns its `revision`, and the traffic surfaces report the endpoint's `review_revision` (`0` only while the endpoint has never been reviewed). The number changes only when the row does, and for an endpoint it only ever increases: clearing a review nulls `reviewed_at` and bumps the revision rather than deleting the row, so a later review of the same endpoint never reuses a revision an admin may still be holding. Without that, an `If-Match` from a long-cleared review would match an unrelated newer one and overwrite it.

**Transitions are conditional.** Acknowledging or dismissing a signal, dismissing a suggestion, and marking or clearing a review are each one statement: `UPDATE ... SET state = <to>, revision = revision + 1 WHERE id = <id> AND state = <from> AND (<expected> IS NULL OR revision = <expected>)`. Zero rows updated means somebody else moved the row first, and the handler answers `409` with the row as it now stands and a stable `reason` (`signal_not_open`, `signal_revision_mismatch`, `suggestion_not_open`, `suggestion_revision_mismatch`, `review_revision_mismatch`) rather than overwriting a decision it never saw. The expected revision is optional and travels as `If-Match` — bare or quoted, the value a read returned; on the accept route, where `If-Match` is already the policy ETag, it travels as `X-GreenGateway-Suggestion-Revision` instead. Omitting it keeps the from-state predicate, which is what makes re-acknowledging an already-acknowledged signal a `409` in both modes rather than a silent second success. The from-state is the set of states the transition leaves, not always a single one: acknowledging leaves `open`, while dismissing leaves `open` or `acknowledged`, so an operator who acknowledged a signal can still clear it. Dismissing twice is still a `409` with `signal_not_open`, because `dismissed` is terminal.

**Accepting a suggestion is one transaction.** In cluster mode the accept route locks the suggestion row `FOR UPDATE`, re-checks that it is still open at the expected revision and still identity-bound, and then runs the policy control plane's own commit steps on the same connection: the `If-Match` compare-and-swap against the active document, the immutable new version that is also the history row, the security-revision advance, the active pointer, and the `security_outbox` row — followed by the transition to `accepted`. One `COMMIT` covers all of it, so the HA state model's rule 7 holds: an installed rule without a moved suggestion, or a moved suggestion without its rule, cannot exist. A stale policy ETag, a suggestion another replica accepted or dismissed first, or a crash anywhere in between rolls the whole thing back and the caller sees `412` or `409` with nothing written. The two audit events (`policy.changed`, `suggestion.lifecycle_changed`) and the replica's local revision-snapshot install happen after the commit — audit is at-least-once, so an event describing a rolled-back acceptance must be impossible, while losing the events of a committed acceptance to a crash is tolerable. One consequence worth knowing before reading version numbers: a rolled-back acceptance still consumes a `policy_documents` identity value, so an aborted attempt leaves a gap in version numbers. The security revision, a counter row rather than a sequence, has no gaps.

Standalone mode keeps its sequence — validate, write the policy file, then the conditional transition. That sequence is not one transaction, so the gateway holds a process-wide suggestion-lifecycle lock across all three steps; every other suggestion transition route takes the same lock. A dismissal racing an acceptance therefore lands entirely before it (the acceptance is then refused on the state predicate, having written nothing) or entirely after it, and the rule can never end up installed for a suggestion that reads `dismissed`. The lock is per process, which is enough because standalone mode is one process with one policy file; if the transition were somehow refused anyway, the rule stays and the response is `409` with `reason: suggestion_transitioned_concurrently` and the new policy ETag.

**Generation runs against PostgreSQL.** Suggestion generation is still explicit and admin-triggered (no scheduler; the maintenance singleton does not run it). In cluster mode it reads observed endpoints and open signals from the projected discovery tables, derives the role/endpoint matrix by scanning the durable audit stream's `http.request_observed` events with the same accumulator the SQLite store uses, plans with the same planner, and inserts with `ON CONFLICT (suggestion_type, method, path_pattern, principal_key) DO NOTHING` — so re-running it, on this replica or another, inserts nothing new, and two replicas generating at once cannot double-insert a target. Baseline evidence records its source as `audit_postgres` in cluster mode and `audit_sqlite` in standalone mode; the suggestion set is otherwise identical for the same fixture, which is pinned by a parity test. The scan is bounded by the matrix scan budget and streamed row by row, so a large audit history costs time, not memory. The policy it filters against -- generation suppresses candidates an existing rule already covers -- is read from the control plane's active document, not from the replica's installed snapshot: a suggestion is stored by identity and never re-evaluated against a later policy, so one minted from a snapshot that had not yet caught up with another replica's commit would stay open forever and would append a duplicate rule if accepted.

Audit retention does not trim a stream position the projector has not committed past (`PostgresDiscoveryStore::minimum_retained_position`); the maintenance singleton below enforces that floor.

## Membership and maintenance

Every cluster-mode replica keeps one row in `greengateway.cluster_members` (issue #241, PR 13): its instance and boot identity, binary version, migration-manifest range (`schema_version_min/max`) and document-schema range (`document_version_min/max`), static-configuration fingerprint, `started_at`, `last_heartbeat_at`, `ready_at`, `draining_at`, the security revisions it has compiled and last observed (their gap is that replica's reconciliation lag), and the last classified failure of its own background work. The row is written at boot, refreshed every `CLUSTER_HEARTBEAT_MS` by a task registered with the lifecycle, stamped ready once the replica is serving and agreed, and stamped draining when it begins draining. Liveness is judged on the database clock: a row whose heartbeat is older than `CLUSTER_MEMBER_STALE_MS` is stale and is swept only by the maintenance singleton -- never by request handling and never by the member itself, so a partitioned replica's row is reaped by database time alone.

**Fingerprint agreement.** After writing its boot row, and on every heartbeat until it succeeds, a replica compares the fingerprints of the live, non-draining members with its own. If any differs, the replica logs the member's instance ID and fingerprint and answers `/readyz` with `503` and reason `config_fingerprint_mismatch` (HA state model invariant 14). It does not exit; readiness is granted on the first heartbeat after the last disagreeing member drains or goes stale. Agreement is sticky: an already-serving replica is never taken out of rotation by a mismatched newcomer, which holds a bad rollout at the door instead of letting it spread. The same gate means a fingerprint change (a route, an exempt path, a key generation, anything in the static configuration) completes on its own only where the old replicas leave without waiting for the new one to become ready: a `Recreate` strategy, a rolling update whose `maxUnavailable` covers every old replica, or an operator draining the old replicas by hand. Under a readiness-gated rolling update -- Kubernetes `RollingUpdate` with `maxUnavailable: 0`, the Deployment default -- the new replica is never ready while an old one serves and the old one is never terminated while the new one is unready, so the rollout stalls at the door until the operator either rolls it back or forces the old replicas out. The gateway cannot tell an intended change from a misconfigured replica at the moment the newcomer boots; a stalled rollout is that decision handed to the operator, not made for them. Readiness also requires the schema ledger to be within the binary's manifest range, which startup validation already enforces; the row's `schema_version_*` columns surface it.

**Maintenance singleton.** One lease slot (`greengateway.execution_leases`, scope `maintenance`, capacity 1, TTL `CLUSTER_MAINTENANCE_LEASE_TTL_MS`) elects the replica that runs the deployment's housekeeping. Every replica tries the slot; the holder runs one bounded pass at once and then every `CLUSTER_MAINTENANCE_INTERVAL_MS`, renewing the lease at a third of its TTL and stopping -- cancelling the pass in flight -- on the first renewal that finds the lease gone or once half the TTL passes without one the authority could answer, always before the slot can be reclaimed. Replicas without the lease retry with a jittered backoff (`interval/4 +/- up to interval/8`, the offset fixed by the instance ID), so a crashed leader is followed by one staggered takeover after its TTL lapses on the database clock; a draining leader releases at once. Each pass opens a dedicated session holding `pg_try_advisory_lock` on the maintenance key for the pass's lifetime (a held key means another pass is running and this one is skipped; a lost connection cancels the pass), then runs the jobs in a fixed order on that session's connection -- so the lock covers every statement for as long as it runs, even one whose pass was cancelled mid-way, and a lost connection fails the step in flight rather than at the next job -- each one bounded step of at most 1000 rows and 30 seconds: JWT revocation cleanup, rate-limit idle sweep, pending-login prune, stale member sweep, PostgreSQL audit retention (only with `AUDIT_POSTGRES_RETENTION_DAYS`; never past the position a durable stream consumer has yet to apply, which is the discovery projector's committed checkpoint; the candidates are drawn from an index-ordered window of ten times the step's limit, so a step's work is bounded by the step and not by the backlog, and a large history is drained one step per pass rather than timing out every pass), and execution-lease reaping (rows expired for more than one `TOOL_LEASE_TTL_MS`; a live lease is never touched). A failing job is logged and recorded with its classified code, and never blocks the next.

**Maintenance ledger.** `greengateway.maintenance_jobs` records each job's `last_started_at`, `last_success_at`, `last_failure_code`, and `last_duration_ms` under the lease fence the current leader adopted the rows at; every write carries `WHERE fence = <the writer's fence>` and, in the same statement, requires the maintenance lease at that fence to be live on the database clock, so a leader that lost its lease finds its late writes refused from the instant the lease lapses -- before any successor has acquired the slot, and before one that has acquired adopts the rows -- and stops. The one-shot cleanup commands above remain available for operators; with the singleton running they are no longer needed on a schedule. Two operator commands, run with the same environment as a replica, cover the roster and the pass:

```bash
gateway cluster-members
```

```bash
gateway maintenance-run
```

The first prints one line per member row (`ready`, `starting`, `draining`, or `stale` on the database clock against `CLUSTER_MEMBER_STALE_MS`, with the identity, versions, fingerprint, heartbeat age, and security revisions); it is read-only and writes no row for itself. The second runs exactly one bounded pass for a cron until the in-process singleton is trusted: it takes the `maintenance` lease like any leader (TTL `CLUSTER_MAINTENANCE_LEASE_TTL_MS`, renewed while the pass runs, released at the end), so a live leader's slot makes it exit non-zero having run nothing rather than run alongside, its ledger writes carry its own fence, and it prints the ledger row of every job afterwards; a pass with any failing job, or one refused by a higher fence, also exits non-zero. Metrics: `greengateway_cluster_maintenance_leader` (1 on the replica holding the lease), `greengateway_cluster_maintenance_job_runs_total{job,outcome}`, and `greengateway_cluster_members_live` (the roster's live count, published by the leader's stale sweep).

## What has landed and what has not

## Readiness and status

Three surfaces answer three different questions from the same process state, so they cannot disagree with each other: `/readyz` says whether **this replica** may be sent traffic, `GET /v1{ADMIN_PREFIX}/cluster` says what the **deployment** looks like from this replica, and `/metrics` (below) is the same facts as time series. When they are read together, `/readyz` is the one an orchestrator acts on and the cluster API is the one that says why.

### The `/readyz` reason chain

`/readyz` is unauthenticated and deliberately topology-safe. It answers `200` with `{"status":"ready","reason":null}` or `503` with `{"status":"not_ready","reason":"<one word>"}`, and nothing else: one stable string from a fixed vocabulary, never an error message, a SQLSTATE, a host, a count, or an identifier. Anything that would help an operator diagnose faster would equally help an unauthenticated caller map the deployment, so it lives on the admin API below instead.

The chain is evaluated in the order of the [HA state model](../architecture/ha-state-model.md)'s failure matrix and stops at the first condition that holds, so the reason you are shown is the one to fix first — a replica that is both cut off from the database and behind on its security revision reports `storage_unavailable`, because nothing below that rung can be judged on an authority that cannot be read. Standalone mode evaluates only the lifecycle rung and the upstream rung; the four authority-backed reasons exist only in cluster mode, where the probe that owns them is constructed at all, so standalone `/readyz` answers exactly what it answered before this feature existed.

| Order | `reason` | What it means | What to do at 3am |
| --- | --- | --- | --- |
| 1 | `starting` | The lifecycle is not accepting work yet: this process has not finished booting. | Expected for the first seconds of a pod's life. If it persists past your startup budget, read the process logs — the replica is stuck in a startup step (schema validation, the first heartbeat, key or TLS material), and restarting it will simply stick again. |
| 1 | `draining` | Shutdown has begun; the replica is refusing new traffic while in-flight work finishes. | Expected during a rollout or a deliberate drain. The cluster API reports `state: "draining"` rather than `not_ready` so you can tell an intentional drain from a fault at a glance. |
| 2 | `config_fingerprint_mismatch` | Cluster mode only. A live, non-draining member's static-configuration fingerprint differs from this replica's, so the newcomer is held at the door (HA state model invariant 14). | Decide which configuration is correct, then make the fleet agree. See [Enabling cluster mode](#enabling-cluster-mode) and the fingerprint-agreement rules under [Membership and maintenance](#membership-and-maintenance) — under a `maxUnavailable: 0` rolling update this condition stalls the rollout by design rather than spreading it. |
| 3 | `storage_unavailable` | Cluster mode only. The probe's one bounded read either could not be issued (the pool could not be checked out, the statement failed) or answered on a session that cannot write — `pg_is_in_recovery()` is true, or `transaction_read_only` is `on`. | Check the pool first (`greengateway_database_pool_available`, `_waiting`, `_timeouts_total`) and then what the DSN actually reached: this reason is what a replica pointed at a pooler, a read endpoint, or a failed-over standby reports. A replica that cannot write cannot renew a lease, record an audit event, or prove a security decision, so refusing traffic is correct. See [Pool sizing and timeouts](#pool-sizing-and-timeouts) and [The connection string](#the-connection-string). |
| 4 | `schema_incompatible` | Cluster mode only. The migration ledger's extent is outside the manifest range this binary serves on — in either direction. A ledger table or schema that is missing entirely is reported the same way (the probe treats it as a ledger covering nothing). | Another gateway version migrated the database out from under this replica, or this replica booted against a database that was never migrated for it. Compare `schema.current_version` against `schema.binary_min`/`binary_max` on the cluster endpoint, then finish or roll back the expand/contract sequence. See [Schema migrations](#schema-migrations). |
| 5 | `instance_lease_invalid` | Cluster mode only. This replica's last **successful** membership heartbeat is older than `CLUSTER_MEMBER_STALE_MS`, so the roster has stopped counting it live and the maintenance singleton may sweep its row at any moment. | One failed heartbeat is not this condition; a heartbeat that has been failing for longer than the stale window is. Look for a partition or a write path that has started failing — the same cause usually shows as `greengateway_cluster_heartbeat_age_seconds` climbing without bound. See [Membership and maintenance](#membership-and-maintenance). |
| 6 | `security_revision_not_compiled` | Cluster mode only. This replica's security gate has been refusing every admission for longer than the reconcile deadline, so it is already failing protected traffic closed here. The condition is the gate's own outcome, recorded as each request or background pass decides it — not a comparison of the two watermarks, which say a replica is healthy when the counter read itself is what times out, and say it is behind whenever a busy deployment commits between two probes. | Inside the deadline a replica whose reconcile is merely slow keeps serving and stays ready; past it, routing more traffic here only produces more `503`s. Read `local.compiled_security_revision`, `local.observed_security_revision`, `local.revision_lag`, and `reconcile.failures_total` on the cluster endpoint to see whether the reconciler is failing or just slow. See [The policy control plane](#the-policy-control-plane). |
| 7 | `required_upstream_unavailable` | A proxy pool this gateway requires has no healthy upstream. | Unrelated to cluster state — this rung predates cluster mode and behaves identically in both modes. See [The deployment shape](#the-deployment-shape). |

Only the authority-backed rungs cost a database round trip, and they cost at most one per `READINESS_PROBE_CACHE_MS` (default 1000, ceiling 60000): the probe issues a single `SELECT 1`-class statement that asks two things at once — is this session writable, and how many migrations does the ledger carry — under the session `statement_timeout`, caches the answer for that window, and collapses concurrent probes onto the one in-flight check. So a probe storm from an orchestrator, or a scrape interval set too aggressively, cannot turn readiness into a load source. The lifecycle, fingerprint, heartbeat-age and revision rungs read process-local state and are re-evaluated on every single probe regardless of the cache. The trade the cache makes is that a change in the authority is not visible for up to one window; `READINESS_PROBE_CACHE_MS=0` consults the authority on every probe if you need that during an incident.

The probe itself is never gated on the shared rate limiter. `/readyz`, `/livez`, `/startupz` and `/metrics` are decided by this replica's local bucket alone (see [Shared rate limits and execution leases](#shared-rate-limits-and-execution-leases)), so during a storage incident the probe answers its own reason -- `storage_unavailable` -- instead of the limiter's `rate limiter unavailable`, and the scrape that would tell you the same thing as time series is still served.

The probe's own statement is timed as `greengateway_database_operation_seconds{operation="readiness_probe"}`. A `/readyz` that has become slow is a readiness check that will start timing out inside an orchestrator, and that series is where it shows first.

### The cluster status API

Two read-only admin routes, both gated on the permission `admin:cluster:read` and nothing else:

```
GET /v1{ADMIN_PREFIX}/cluster
GET /v1{ADMIN_PREFIX}/cluster/replicas
```

There are no mutation routes on this surface and no route on which one replica acts on another. Both answer `401 Unauthorized` with no authenticated principal, `404 Not Found` with `{"error":"cluster status API requires POLICY_FILE to be configured"}` when RBAC is not configured, and `403 Forbidden` when the principal does not hold `admin:cluster:read`. The permission is deliberately not `admin:status:read`: `/status` describes this process's configuration, while these two describe the deployment's topology — how many replicas exist, which are live, what versions they run, which one holds the maintenance lease — so they are granted separately. Full field lists are in [configuration.md](../configuration.md).

`GET /v1{ADMIN_PREFIX}/cluster` reports `mode` (`cluster` or `standalone`), `ready` (whether `/readyz` would answer `200` right now), `state`, and `reason`, then the sections behind them: `schema`, `replicas`, `binary_versions`, `local`, `reconcile`, `projector`, `leader_tasks`, `audit`, and `pools`. `state` and `reason` are computed from the same chain `/readyz` runs, so this view can never disagree with the probe your load balancer is acting on:

- `not_ready` — the chain refused and the replica is not draining. `reason` is the readiness reason above, verbatim.
- `draining` — the chain refused because the replica is draining. `reason` is `draining`.
- `degraded` — the replica **is** serving, and one of four specific things is nonetheless wrong. Worst first: `replicas_unavailable` (the roster could not be read, so nothing below it can be judged against the rest of the deployment), `security_revision_lagging` (`local.revision_lag` is above zero but still inside the reconcile deadline), `maintenance_job_failing` (a singleton job's ledger row carries a failure code from its last run), `member_error_reported` (a live replica in the roster is carrying a classified failure on its own membership row).
- `ready` — the chain refused nothing and none of the four degraded conditions holds. `reason` is `null`.

A `degraded` replica is still in rotation and still serving. It is the state to page on before it becomes `not_ready`, not the state to pull traffic on.

`GET /v1{ADMIN_PREFIX}/cluster/replicas` returns `{"replicas": [...]}` — the membership roster, live members first and, within each group, in the order the store returned them (oldest boot first). Each entry is one `cluster_members` row: `instance_id`, `boot_id`, `binary_version`, `schema_version_min`/`_max`, `document_version_min`/`_max`, `fingerprint`, `started_at`, `last_heartbeat_at`, `heartbeat_age_secs`, `ready_at`, `draining_at`, `compiled_security_revision`, `observed_security_revision`, `last_error_code`, and `live`. It is the same roster `gateway cluster-members` prints, over HTTP and with the same redaction as the status route.

In standalone mode both routes serve the same shapes rather than a different API: `mode` is `standalone`, the roster is this process alone, and the sections that only a cluster has — `projector`, `leader_tasks`, `pools.database`, `schema.current_version` — are `null`. In cluster mode a section whose read did not answer is `null` for the same reason, so `null` always means "not reported", never "zero". The one place that matters for judgement: `schema.compatible` is `true` when `current_version` is `null`, because a ledger this replica could not read is not evidence of disagreement — `storage_unavailable` is what reports that, on both surfaces.

### What these endpoints deliberately never disclose

Every string on this surface is written by *some other replica* into a shared table, so an admin API that echoed those strings would be a way to move data — a DSN, an address, a host — out of a database row and into an operator's browser. The response therefore does not filter strings, it *recognizes* them: each string field has a known shape (a three-component semantic version, 64 lowercase hex characters, a UTC timestamp, one of the repository classifier's fixed error kinds `unavailable` / `timeout` / `conflict` / `invalid data` / `incompatible schema` / `internal`, one of the singleton's fixed job names `audit_retention` / `execution_lease_reaper` / `jwt_revocation_cleanup` / `pending_login_prune` / `rate_limit_idle_sweep` / `stale_member_sweep`), and a value that is not of that shape is replaced **whole** by `unknown` — or, for a timestamp, by `null`. Never trimmed, never partially escaped: filtering `postgres://user:pass@10.0.0.5:5432/db` still leaves the address behind, and a four-component "version" is a dotted quad.

So no DSN, database host, user or name, IP address, policy, tool or secret content, query text, or raw error string can travel through either response. Instance and boot identifiers are UUIDs, which cannot carry text at all; everything else is a number or a fixed enum.

Hostnames are the single, opt-in exception. `local.hostname` is `null` unless the deployment sets `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`, and even then it carries only *this* process's own hostname (read once at startup from `HOSTNAME`, or `COMPUTERNAME` on Windows), bounded to 253 characters of `[A-Za-z0-9._-]` and dropped whole if it is anything else. No roster column holds another replica's hostname, so there is nothing to expose there. Turn it on when you need to map a roster UUID onto a pod; leave it off — the default — and you lose nothing else on this surface.

### Where the console's remediation links point

The admin console's Cluster page never renders the raw `reason` string. It maps each one to a fixed label and a link into this guide, so the reasons and the sections that fix them stay in step:

| `reason` | Section |
| --- | --- |
| `starting`, `draining`, and any reason the console does not recognize | [Readiness and status](#readiness-and-status) (this section) |
| `config_fingerprint_mismatch` | [Enabling cluster mode](#enabling-cluster-mode) |
| `storage_unavailable` | [Pool sizing and timeouts](#pool-sizing-and-timeouts) |
| `schema_incompatible` | [Schema migrations](#schema-migrations) |
| `instance_lease_invalid`, `replicas_unavailable`, `maintenance_job_failing`, `member_error_reported` | [Membership and maintenance](#membership-and-maintenance) |
| `security_revision_not_compiled`, `security_revision_lagging` | [The policy control plane](#the-policy-control-plane) |
| `required_upstream_unavailable` | [The deployment shape](#the-deployment-shape) |

Renaming or removing any heading in that table breaks a link an operator follows mid-incident, so treat those anchors as part of this file's contract.

## Metrics

`/metrics` serves the Prometheus text format. The HA series below carry the `greengateway_` prefix and answer one question between them: is this replica, and the deployment it belongs to, healthy enough to be sent traffic -- and if not, which condition has to be fixed first. They are the machine-readable form of `/readyz`'s reason and of the cluster status API's `state`; the three surfaces read the same process state, so they cannot disagree.

**Every label value is drawn from a fixed enum.** Nothing caller-influenced -- an instance id, a principal, a proxied route, a host, a URL, a token id, a query, an error string -- is ever a label. A metric label is unbounded state the process keeps for the life of the registry and hands to every scrape, so a caller who could steer one could both mint time series without limit and read back what they minted from an endpoint that is routinely less protected than the admin API. Where the interesting value *is* high-cardinality (which replica, which error text, which tool), it goes to the roster row, the audit event, or the log, all of which are bounded and access-controlled. A test walks the whole rendered registry after a synthetic run and fails the build if a label value has the shape of an address, a UUID, a URL, or an email, or falls outside its metric's declared vocabulary.

Which replica a series belongs to is the scrape target's job, not a label's: every gauge below describes the process that served the scrape.

| Series | Type | Labels | What it says |
| --- | --- | --- | --- |
| `greengateway_gateway_ready` / `_draining` | gauge | -- | The lifecycle phase, as a pair: `0,0` starting, `1,0` ready, `0,1` draining. Published from boot, so "never became ready" is visible as `0` rather than as an absent series. |
| `greengateway_inflight_requests` | gauge | -- | Requests inside the observation layer right now. Maintained by a guard, so a cancelled or rejected request still takes its increment back down. Climbing while throughput does not is a stalled upstream or an exhausted pool; not falling during a drain is a shutdown that will hit its deadline. |
| `greengateway_schema_compatible` | gauge | -- | `1` when the migration ledger is a checksum-matching prefix covering this binary's manifest. `0` on a serving replica is `/readyz`'s `schema_incompatible`: another gateway migrated the database out from under this one. |
| `greengateway_migration_lock_wait_seconds` | histogram | -- | How long the migrator waited for the schema advisory lock. A second migrator waiting behind a slow first one is healthy and shows as one long observation; long on every boot means migrations contend with something that is not another migrator. |
| `greengateway_database_pool_size` / `_available` / `_waiting` | gauge | -- | deadpool's `Pool::status()`, sampled at scrape. `available` pinned at `0` with `waiting` climbing is the saturation that becomes `storage_unavailable` once checkouts start timing out. |
| `greengateway_database_pool_timeouts_total` | counter | -- | Pool checkouts that timed out, counted where they are classified -- the one choke point every checkout failure passes through. The gauges above keep no history; this is the series that remembers a burst that has already cleared. |
| `greengateway_database_operation_seconds` | histogram | `operation`, `error_class` | Store latency by *what was asked of the store* (an `OPERATION_*` constant, never the statement, its parameters, or its rows) and how it ended (`none` on success, otherwise a classified repository error kind). Wired today for the membership roster and job ledger -- the HA control plane's own store -- the connectivity check, and the readiness probe's statement; the other stores adopt the same helper as they are touched. |
| `greengateway_security_revision_compiled` / `_current` / `_lag` | gauge | -- | This replica's compiled watermark, the authority's counter as last read, and the difference (never negative). A lag that stays non-zero is a replica that is reconciling; what takes it out of rotation is the gate refusing admissions past the reconcile deadline (`/readyz`'s `security_revision_not_compiled`), which these gauges do not by themselves show. |
| `greengateway_reconcile_failures_total` | counter | `reason` | Background reconcile passes that failed, by classification: the authority could not be read, the bounded deadline passed with the replica still behind, or the authoritative document could not be compiled by this binary. |
| `greengateway_cluster_heartbeat_age_seconds` | gauge | -- | How long ago this replica's roster row last landed. Past `CLUSTER_MEMBER_STALE_MS` the deployment has stopped counting it live and `/readyz` refuses with `instance_lease_invalid`. Published after every heartbeat tick, including the failed ones -- which is when it matters. |
| `greengateway_cluster_config_mismatch` | gauge | -- | `1` while this replica is still held at the fingerprint door. Summed across a deployment: how many replicas a security-relevant configuration change is blocking. |
| `greengateway_cluster_lease_age_seconds` | gauge | `scope` | How long this replica has held a singleton lease (`maintenance`, `discovery_projector`), back to `0` when the term ends. Zero everywhere for longer than the acquisition backoff means nobody is leading; an age that keeps resetting is leadership changing hands. Per-tool lease scopes are deliberately absent: a scope is `tool:<name>`, and a tool name is control-plane data. |
| `greengateway_leader_task_last_success_age_seconds` | gauge | `task` | How long ago each singleton job last succeeded, read back from the fenced ledger by the leader, so a job failing across several leader terms still shows its true age. A job that has never succeeded has no series -- there is no age for a success that never happened. |
| `greengateway_cluster_members_live`, `greengateway_cluster_maintenance_leader`, `greengateway_cluster_maintenance_job_runs_total{job,outcome}` | -- | -- | PR 13's, described under [Membership and maintenance](#membership-and-maintenance). |
| `greengateway_discovery_projector_checkpoint` / `_lag_events` | gauge | -- | The projector's committed position and how far behind the audit stream's head it is, published by the leading replica. A checkpoint that stops advancing while the lag grows is wedged; one that advances while the lag grows cannot keep up with observation volume. The two need different answers, which is why the lag alone is not enough. |
| `greengateway_discovery_projector_errors_total` | counter | `kind` | Projector failures by *which step of a leader's term* failed: lease acquisition, the leadership claim, the state load, being fenced out, a batch, or an observation dropped for exceeding the persisted column bounds. Never by store error, and never by the observation -- observations carry caller-controlled paths and principals. |
| `greengateway_audit_queue_depth` / `_capacity` / `_oldest_age_seconds` | gauge | -- | The audit writer's channel, sampled at scrape. Depth approaching capacity is the precondition for `audit_events_dropped_total` beginning to count. The oldest age is the one depth hides: a sink stuck on a single event has an empty queue behind it and an age that climbs without bound. |
| `greengateway_audit_flush_total` | counter | `outcome` | Durable flushes of the audit buffer. `outcome="failure"` counts batches the gateway had already told a caller it recorded and then lost. |
| `greengateway_audit_stream_connections_total` | counter | `outcome` | Durable audit-stream (SSE) connection attempts: a live tail, a gapless replay from a `Last-Event-ID`, a header that was not a position, a cursor older than the retained window, or an authority that could not be consulted. The cursor value is caller-controlled and is never a label. |
| `greengateway_audit_stream_replay_backlog_events` | histogram | -- | How many positions a resuming client was behind at reconnect. Size the audit retention window against this: a backlog approaching the retained span is a consumer about to start getting `410 Gone` instead of a gapless resume. |
| `greengateway_audit_stream_duplicate_positions_total` | counter | -- | Stream positions delivered at or below the cursor already served. An invariant violation, not a workload measure: it must stay at `0`. Counted rather than asserted because delivering a duplicate frame under an `id:` the client has already seen silently corrupts a reconnecting consumer's idea of what it has processed, while ending the stream would turn a store-side bug into an outage. |
| `greengateway_execution_lease_failures_total` | counter | `kind` | Execution-lease failures: the lease was reported gone, a renewal could not be answered in time, or a completed holder could not free its slot (which costs the next caller up to one TTL of concurrency). The scope is not a label, for the reason given above. |

Everything except the four sampled families -- the pool gauges, the audit queue gauges, and the lifecycle pair -- is published by the task that owns the value, at the moment it changes, so a value that stops changing keeps its last true reading rather than quietly tracking whether anybody is scraping. The sampled families are read when `/metrics` is served, which is what a Prometheus gauge means anyway: the audit writer is a blocking consumer, so publishing from it would record only the instants it is awake (exactly the instants a backlog is draining), and `Pool::status()` is a snapshot with no history and no event to hang a publication on.

## The standalone-to-cluster import

A deployment that has been running standalone holds durable, operator-owned state in files and SQLite databases. `gateway import-standalone` carries it into one cluster deployment namespace: once, offline, in one direction, with the evidence needed to decide whether the cutover succeeded.

```
gateway import-standalone --from <standalone-env-file> [--dry-run | --apply [--resume]]
```

Two configurations are involved and they cannot be one process environment, because `Config` refuses a configuration that names both a local authority and `STATE_BACKEND=postgres`. The process environment is the **target** cluster, as in every other one-shot command here; the **source** is the standalone deployment's own environment file, named by `--from` and validated through the same `Config` validator, so "both configurations valid" is a real check rather than a claim. Run it with the migration role's DSN, beside `gateway migrate up`: preserving a policy history's version numbers means naming an identity column's values and realigning the sequence afterwards, which the runtime role deliberately cannot do.

`--dry-run` is the default and writes nothing at all — not even the deployment binding, since binding is a write and a rehearsal must leave the database exactly as it found it. `--apply` performs the import; `--apply --resume` continues one that was interrupted. Each section is its own transaction with its own counts and checksum, so an interrupted run leaves whole sections committed and nothing partial, and a resumed section recognizes its own completed work by the resource's natural key (the active document's ETag for policy and tools, the record IDs for Connections, `event_id` for audit) before writing anything. Every source read goes through the parser or store standalone mode itself uses; no ad-hoc SQL touches the source.

The target must be an empty deployment namespace: the schema current, the database unbound or bound to this `DEPLOYMENT_ID`, every authoritative content table empty and every authoritative counter still where migration seeded it. Runtime state a replica rebuilds or elects — membership rows, the maintenance ledger, execution leases, rate-limit buckets, pending logins, JWT revocations — is deliberately not on that list, so a database a replica has merely connected to is still empty and a cutover rehearsal stays repeatable. Refusals print a stable machine-readable code (`target_namespace_not_empty`, `source_document_unparseable`, `standalone_config_invalid`, and the rest) that operators can script against; the prose after it may change between releases, the code does not.

The report is pretty-printed JSON on stdout: counts, checksums, revisions and durations, and never a plaintext token, secret, login material or DSN. Standalone configuration problems are reported by setting name only, because the validator's own messages quote the offending value and some of those values are key material. Checksums are SHA-256 over canonical exports computed identically on both sides, which is what makes them evidence rather than decoration — and they are what [the rollback boundary runbook](rollback-boundary.md) compares against.

All nine sections of issue #241 §9 are performed. The last of them is a verification pass, and it is the reason the command is worth running rather than a hand-written script: it re-reads the target through the cluster's own readers, compares per-table row counts and per-section SHA-256 checksums against the source, reads every foreign key and unique index in a read-only constraint pass, checks the active ETags and the projector checkpoint, boots the Connections graph through the same `validate_persisted_state` a replica runs at startup, and proves the excluded runtime tables empty. A failed check refuses the run with the code `validation_failed`, naming the check that failed. What the command deliberately leaves behind is listed in the report's `not_imported` field.

The principal directory is never imported: cluster mode has no principal directory, so there is no destination for it — no migration creates the table, and `PRINCIPAL_SQLITE_PATH` is refused in cluster mode. It is a projection of authenticated traffic, and that traffic is imported with the audit log. The report names the file left behind rather than letting it go missing quietly.

The full procedure — dry run, quiesce control-plane writes, back up both sides, migrate, import, start one replica, verify, scale out — is [the cutover runbook](cutover.md), and the point after which going back stops being free is [the rollback boundary runbook](rollback-boundary.md).



Provided so far: mode selection with fail-closed validation, the redacted secret-file DSN, the verified-TLS bounded pool, deployment/instance identity, the static-configuration fingerprint, least-privilege role guidance, the versioned migration system with its CLI and startup validation, CI against a real PostgreSQL 16 including the no-DDL privilege boundary, the durable audit event store and cross-replica SSE stream (PRs 5-6), the versioned policy control plane (PR 7, semantics above), the discovery lifecycle workflows (PR 12, above), cluster membership with the maintenance singleton (PR 13, above), the readiness reasons, cluster status API, metrics and Cluster page (PR 14, above), and the standalone-to-cluster import with its operator runbooks (PR 15, above).

Deliberately not yet present: nothing from the #241 sequence except the release gate (PR 16) that proves the whole of it. The versioned policy control plane (PR 7), the versioned tools and Connection control planes (PR 8), the shared authentication state (PR 9), the shared rate limits and execution leases (PR 10), global discovery (PR 11), the conditional discovery lifecycle transitions, atomic suggestion acceptance, and cluster-mode suggestion generation (PR 12, above), membership, fingerprint-gated readiness, and the leased maintenance singleton (PR 13, above), the readiness reasons, the cluster status API, the HA metrics and the Cluster page (PR 14, above), and the standalone-to-cluster import (PR 15, above) have landed: the admin policy, tools-registration, Connection, and discovery APIs serve from PostgreSQL in cluster mode under the semantics above, and the deployment's housekeeping is fenced singleton work. Until the release gate (PR 16) passes, do not deploy this mode expecting HA, and expect that a postgres-mode replica serves with its local-only features unconfigured (any `*_SQLITE_PATH` is rejected), with the shared features arriving as the PRs land.
