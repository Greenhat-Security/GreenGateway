# Deploying GreenGateway with PostgreSQL (experimental cluster mode)

This guide covers the PostgreSQL foundation of issue #241's cluster mode: backend selection, the secret-file connection string, TLS, pool sizing, and the database roles an operator provisions. **Cluster mode is experimental and is not a supported HA configuration until the #241 release gate passes** — the foundation here is the substrate later PRs build the shared state on, not a finished multi-replica product.

Read [the HA state model](../architecture/ha-state-model.md) and [ADR-0007](../adr/0007-shared-state-and-ha-modes.md) first: they define the single-primary trust boundary, the strict per-request revision discipline, and the failure matrix this deployment shape exists to serve. One cluster is one tenant and one trust domain (ADR-0002 still applies).

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
- `STATE_BACKEND=sqlite` is set with `DEPLOYMENT_ID`, `DATABASE_URL_FILE`, or `DATABASE_TLS_CA_FILE` configured — material a mode will never read is rejected rather than ignored.

Moving a deployment from sqlite to postgres is a one-way, verified, offline import (a later #241 PR); there is deliberately no live switch and no automatic reverse migration.

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

## Database roles: least privilege

Provision two roles. The runtime role holds only what the gateway's operations need; the migration role holds DDL and exists for the migration job. Separating them means the credentials a replica runs with every day cannot change the schema.

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

Rollback boundary: there is no schema downgrade. Rolling back an application release means redeploying the previous binary against the still-compatible schema (additive migrations keep it readable); recovering a damaged ledger or an unwanted migration state means restoring the database from backup — PITR to a point before the migration, verified with `gateway migrate check` before replicas restart. Take a backup or snapshot before every `migrate up`; that snapshot is also the pre-cutover restore point for the standalone-to-cluster import workflow of a later #241 PR.

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

The plaintext token continues to appear exactly once, in the response to create and rotate; the store holds only its SHA-256.

### JWT revocations

Cluster mode wires a real `RevocationStore` behind every JWT provider's validator: `greengateway.jwt_revocations`, a shared denylist keyed by the provider's principal issuer (the configured issuer, normalized, or `provider:<name>` when none is configured) and a SHA-256 digest of the `jti` under the deployment ID and that issuer. The raw `jti` never reaches the database, and an equal `jti` from two issuers is two different JWTs. A `jti` is not consume-once: a row means the JWT was withdrawn, its absence means nothing, and bearer reuse stays valid.

Every JWT that carries a `jti` is checked against the denylist on every request, on every replica; a denylist that cannot be consulted answers `503`, never `401`. Expiry is judged by the database clock. A row stays effective for the validator's `exp` leeway (60 seconds) past its `expires_at` (the token's own `exp` when known) — the validator accepts the token until then — and only after that is it a no-op on read and reclaimable by cleanup.

There is deliberately no admin HTTP endpoint for revoking JWTs yet — a permission model for withdrawing other people's sessions is a product decision — so the write path is an operator command, run with the same environment as a replica:

```bash
gateway revoke-jwt https://issuer.example/ <jti> 2026-12-31T00:00:00Z
```

```bash
gateway jwt-revocations-cleanup 1000
```

The first records the withdrawal as a committed control-plane mutation (it advances the shared security revision and appends an outbox row naming the digest); a repeat inside the row's effective window with no longer expiry spends nothing, while a repeat whose earlier finite row has lapsed, or that carries a later or unbounded expiry, replaces the row — a lapsed revocation never turns a break-glass revoke into a silent no-op. The second reclaims rows past their expiry and leeway, bounded per run and on the expiry index, until the membership PR makes it fenced singleton work.

### Admin login state

When `ADMIN_LOGIN_PROVIDER` is set, the OIDC login flow's pending state (the `state` a browser is sent out with, and the PKCE verifier and nonce it must present back) lives in `greengateway.admin_pending_logins`, so the callback completes on whichever replica receives it — no sticky routing. The `state` (a 128-bit random value) is stored only as a digest under the deployment ID, and the per-client quota key is an HMAC under the primary login key rather than a plain digest of an enumerable address; the verifier and nonce are sealed with XChaCha20-Poly1305 under `ADMIN_LOGIN_KEYRING` (the connections keyring's key-file discipline, files beneath `CONNECTION_SECRETS_ROOT`), with the deployment ID, the row, and the field bound as associated data. Consumption is one transaction — a `DELETE … RETURNING` guarded by the database clock, then opening both envelopes — that commits only when the envelopes open, so exactly one concurrent callback, on any replica, completes a login, and a replica whose keyring cannot open the row rolls the delete back for one that can. Admissions serialize on a transaction-scoped advisory lock so the global and per-client quotas hold across replicas (the three limits are part of the static-configuration fingerprint, so replicas apply one set), and each admission prunes a bounded number of expired rows. A store that cannot be consulted answers `503` on both `/auth/login` and `/auth/callback`; it is never reported as an unknown state and no code is exchanged at the identity provider.

## What has landed and what has not

Provided so far: mode selection with fail-closed validation, the redacted secret-file DSN, the verified-TLS bounded pool, deployment/instance identity, the static-configuration fingerprint, least-privilege role guidance, the versioned migration system with its CLI and startup validation, CI against a real PostgreSQL 16 including the no-DDL privilege boundary, the durable audit event store and cross-replica SSE stream (PRs 5-6), and the versioned policy control plane (PR 7, semantics above).

Deliberately not yet present — arriving with the later PRs of #241: JWT revocation and pending-login state (the rest of PR 9), distributed rate limiting and leases (PR 10), global discovery (PR 11-12), membership and readiness (PR 13-14), and the import workflow (PR 15). The versioned policy control plane (PR 7) and the versioned tools and Connection control planes (PR 8) have landed: the admin policy, tools-registration, and Connection APIs serve from PostgreSQL in cluster mode under the semantics above. Until the release gate (PR 16) passes, do not deploy this mode expecting HA, and expect that a postgres-mode replica serves with its local-only features unconfigured (any `*_SQLITE_PATH` is rejected), with the shared features arriving as the PRs land.
