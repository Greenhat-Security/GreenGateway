# Runbook: database roles and grants

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule this runbook exists to enforce: the credentials a serving replica runs with every day cannot change the schema.** Two roles, two DSN files, two different jobs. If you find yourself granting DDL to the runtime role to make something work, the thing that is broken is not the grant.

## The two roles

| | Runtime role (`greengateway`) | Migration role (`greengateway_migrator`) |
| --- | --- | --- |
| Used by | every serving replica | `gateway migrate up`, `gateway import-standalone` |
| Holds DDL | no | yes |
| Runs continuously | yes | no — it connects, does one job, prints one line, exits |
| DSN file | the one in each replica's `DATABASE_URL_FILE` | the one in the migration job's `DATABASE_URL_FILE` |
| Privileges | `CONNECT`, `USAGE` on the schema, `SELECT/INSERT/UPDATE/DELETE` on its tables, `USAGE/SELECT` on its sequences | the above plus schema ownership and DDL |

`gateway import-standalone` runs under the **migration** role, not the runtime role. That is not laziness about least privilege: importing a standalone deployment's policy history preserves its version numbers, which means naming an identity column's values and realigning the sequence afterwards, and the runtime role deliberately does not hold that. Run the import beside `gateway migrate up` in the cutover order, from the same job or the same operator shell.

## Provisioning, once

Run as a superuser or the database owner. Replace the passwords with values your secret manager generated; nothing here should be typed twice.

```sql
CREATE ROLE greengateway LOGIN PASSWORD '<runtime-password>';
CREATE ROLE greengateway_migrator LOGIN PASSWORD '<migration-password>';
GRANT CONNECT ON DATABASE greengateway TO greengateway;
GRANT CONNECT ON DATABASE greengateway TO greengateway_migrator;
GRANT greengateway TO greengateway_migrator;
```

Expected output: `CREATE ROLE` twice, then `GRANT` three times. Nothing else exists yet — the `greengateway` schema is created by the first migration, so the table grants below cannot run until after it.

`GRANT greengateway TO greengateway_migrator` makes the migration role a member of the runtime role. It is there so a table the migrator creates is readable by the runtime role through the default privileges set below, and so the migration job can verify its own work by reading as the runtime role would.

## Build the schema, then grant

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
  gateway migrate up
```

Expected output: one line naming the migrations applied. A no-op run (schema already current) also exits `0`.

Now the grants, as the superuser or database owner again:

```sql
GRANT USAGE ON SCHEMA greengateway TO greengateway;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA greengateway TO greengateway;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA greengateway TO greengateway;

-- So a table a LATER migration creates is covered without repeating this step.
-- FOR ROLE greengateway_migrator, because that is the role that will create it.
ALTER DEFAULT PRIVILEGES FOR ROLE greengateway_migrator IN SCHEMA greengateway
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO greengateway;
ALTER DEFAULT PRIVILEGES FOR ROLE greengateway_migrator IN SCHEMA greengateway
  GRANT USAGE, SELECT ON SEQUENCES TO greengateway;

REVOKE CREATE ON SCHEMA greengateway FROM greengateway;
```

The final `REVOKE` is the boundary itself. It should be a no-op — the runtime role was never granted `CREATE` — and it is written down so that a future operator who grants it has to delete a line rather than merely forget to add one.

If you skip the `ALTER DEFAULT PRIVILEGES` statements, you must re-run the two `ON ALL TABLES`/`ON ALL SEQUENCES` grants after every migration that adds a table. A replica that starts against a table it cannot read fails closed with a permission error, which is the right failure, at the worst possible time.

## Verify the boundary

Both of these are worth running once after provisioning and once after any grant change. They take seconds.

**The runtime role can read and write, and cannot create:**

```sh
psql "$RUNTIME_DSN" -c "CREATE TABLE greengateway.privilege_probe (id int);"
```

Expected output: `ERROR:  permission denied for schema greengateway`. If it prints `CREATE TABLE` instead, the boundary is not in place — drop the table and re-run the `REVOKE`.

**The runtime role can validate the schema but not migrate it:**

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-runtime \
  gateway migrate check
```

Expected output: a status line and exit `0` when the schema is current. `migrate check` is validate-only and is safe to run with the runtime role; `migrate up` under the runtime role is expected to fail on the first DDL statement, and a deployment that finds it succeeds has a grant it should not have.

**What each replica actually connects as:**

```sql
SELECT usename, count(*), min(backend_start)
FROM pg_stat_activity
WHERE datname = 'greengateway'
GROUP BY usename ORDER BY usename;
```

Expected output: rows for `greengateway` only, in steady state. A `greengateway_migrator` row that is not a migration job in flight is a replica pointed at the wrong DSN file — fix the file, restart that replica, and check why the two DSNs were interchangeable.

## The DSN files

Each role's connection string lives in a file named by `DATABASE_URL_FILE`. The gateway reads it once at startup through a bounded, permission-checked reader and never lets its contents reach configuration, `Debug` output, logs, metrics, status, or an error message. The file must:

- be a regular file of at most 8 KiB;
- grant **no** group or other permission (`chmod 0400`; a Kubernetes Secret volume needs `defaultMode: 0400`, because the default `0644` is refused);
- name host, user and database explicitly — ambient defaults are not trusted;
- carry only the `user`, `password`, `host`, `port`, `dbname` and `application_name` query parameters. `sslmode`, `options`, and anything unrecognized are rejected: TLS policy comes from `DATABASE_TLS_MODE` (see [the TLS runbook](tls.md)) and the session timeouts are set by the gateway from the `DATABASE_*_TIMEOUT_MS` settings, and a DSN that could override either would make your configuration a guess.

Two example files. Give each replica a distinct `application_name` so `pg_stat_activity` tells you which one is holding a connection:

```
postgresql://greengateway@db.internal.example.com:5432/greengateway?application_name=greengateway-eu-1
```

```
postgresql://greengateway_migrator@db.internal.example.com:5432/greengateway?application_name=greengateway-migrate
```

The password goes in the file too, as the DSN's userinfo or a `password` parameter, and the file's mode is what protects it.

## Rotation

1. Generate the new password in your secret manager.
2. `ALTER ROLE greengateway PASSWORD '<new>';` — takes effect for new connections only; existing pooled connections keep working.
3. Write the new DSN file, still `0400`.
4. Restart the replicas one at a time, waiting for each to report `ready` (see [the failover runbook](failover.md)) before moving to the next.

There is no way to make a running replica re-read the DSN file; a restart is the mechanism. Rotating the migration role's password needs no restart at all, because nothing holds it open.

## When a step fails

**`gateway migrate up` fails with `permission denied for schema greengateway`.** The migration job is using the runtime DSN. Check `DATABASE_URL_FILE` on the job, not the grants.

**A replica fails startup with `permission denied for table greengateway.<something>`.** A migration added a table and the grants were not re-applied, and the default privileges are not set. Re-run the two `ON ALL` grants and the two `ALTER DEFAULT PRIVILEGES` statements, then restart the replica. The replica failed closed; no traffic was served under a partial view.

**A replica fails startup with a DSN file permission complaint.** The file has group or other bits set. `chmod 0400`; on Kubernetes set `defaultMode: 0400` on the Secret volume. The message names the setting, not the file's contents.

**`CREATE ROLE` says the role already exists.** Someone provisioned it before. Confirm what it can do (`\du greengateway` and the `CREATE TABLE` probe above) rather than assuming; an existing role with `SUPERUSER` or `pg_write_all_data` is a finding, not a shortcut.
