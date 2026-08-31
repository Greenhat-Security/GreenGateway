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
- any writable local authority (`POLICY_FILE`, `TOOLS_FILE`, or any `*_SQLITE_PATH`) is set alongside postgres — in cluster mode the database is the single authority, and a local store next to it is a fallback path, not a leftover;
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
- **Rolling upgrades coexist.** Migrations are additive (expand first; destructive cleanup is a later, explicit step), so version N and N+1 binaries can serve against one schema during a rollout. A binary never activates a document version it cannot parse — those rules land with the control-plane PRs, on this ledger.

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

## What has landed and what has not

Provided so far: mode selection with fail-closed validation, the redacted secret-file DSN, the verified-TLS bounded pool, deployment/instance identity, the static-configuration fingerprint, least-privilege role guidance, the versioned migration system with its CLI and startup validation, CI against a real PostgreSQL 16 including the no-DDL privilege boundary, the durable audit event store and cross-replica SSE stream (PRs 5-6), and the versioned policy control plane (PR 7, semantics above).

Deliberately not yet present — arriving with the later PRs of #241: shared authentication state (PR 9), distributed rate limiting and leases (PR 10), global discovery (PR 11-12), membership and readiness (PR 13-14), the import workflow (PR 15), and the versioned tool/Connection control plane (PR 8). The versioned policy control plane (PR 7) has landed: the admin policy API serves from PostgreSQL in cluster mode under the semantics above. Until the release gate (PR 16) passes, do not deploy this mode expecting HA, and expect that a postgres-mode replica serves with its local-only features unconfigured (any `*_SQLITE_PATH` is rejected), with the shared features arriving as the PRs land.
