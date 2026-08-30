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

Provision two roles. The runtime role holds only what the gateway's operations need; the migration role holds DDL and exists for the migration workflow of a later #241 PR. Separating them means the credentials a replica runs with every day cannot change the schema.

```sql
-- One-time, as a superuser or the database owner.

-- The runtime role: DML and sequences only, no DDL, no superuser.
CREATE ROLE greengateway LOGIN PASSWORD '<set-by-your-secret-manager>';
GRANT CONNECT ON DATABASE greengateway TO greengateway;

-- The schema lands with the migration CLI (#241 PR 4). When it exists:
--   GRANT USAGE ON SCHEMA greengateway TO greengateway;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA greengateway TO greengateway;
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA greengateway TO greengateway;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA greengateway
--     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO greengateway;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA greengateway
--     GRANT USAGE, SELECT ON SEQUENCES TO greengateway;

-- The migration role: DDL, used only by the migration job/CLI.
CREATE ROLE greengateway_migrator LOGIN PASSWORD '<set-by-your-secret-manager>';
--   GRANT USAGE, CREATE ON SCHEMA greengateway TO greengateway_migrator;
--   GRANT greengateway TO greengateway_migrator;  -- so migrated tables stay usable by the runtime role
```

Notes:

- The runtime role needs no advisory-lock privileges beyond connection — PostgreSQL advisory locks need none — and no role in `pg_write_all_data` or anything administrative.
- Runtime-role connections are what the gateway opens; point `DATABASE_URL_FILE` at the runtime role's DSN.
- The lines about schema grants are commented because the schema arrives with PR 4's migrations; the roles can be created ahead of it. CI's PostgreSQL foundation job runs today against a database with no gateway schema at all: PR 3 proves connectivity, not tables.
- Rotate both passwords through the operator's secret manager; updating the DSN file and restarting a replica picks up the new value.

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

## What PR 3 does and does not provide

Provided here: mode selection with fail-closed validation, the redacted secret-file DSN, the verified-TLS bounded pool, deployment/instance identity, the static-configuration fingerprint, least-privilege role guidance, and CI against a real PostgreSQL 16.

Deliberately not yet present — arriving with the later PRs of #241: repositories and migrations (PR 4 onward), shared audit (PR 5), versioned control plane (PR 7-8), shared authentication state (PR 9), distributed rate limiting and leases (PR 10), global discovery (PR 11-12), membership and readiness (PR 13-14), and the import workflow (PR 15). Until the release gate (PR 16) passes, do not deploy this mode expecting HA, and expect that a postgres-mode replica serves with its local-only features unconfigured (any `*_SQLITE_PATH` is rejected), with the shared features arriving as the PRs land.
