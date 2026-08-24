# Connections Operator Guide

GreenGateway Connections give proxy routes, HTTP tools, OpenAPI-managed tools,
and streamable-HTTP MCP servers one destination, credential, TLS, test, and
catalog authority. A Connection is not a network or policy grant: normal
authentication, RBAC/tool policy, and egress policy must all allow an operation
before GreenGateway resolves its protected material or contacts an upstream.

This guide covers production custody and day-two operations. See the
[migration guide](migration.md) for moving legacy settings and the
[admin guide](admin-guide.md) for the browser workflow. The complete field and
limit reference remains in [configuration.md](../configuration.md).

## Production Readiness Checklist

Before enabling the first managed Connection:

1. Put `CONNECTIONS_SQLITE_PATH` on durable storage and include its SQLite
   database, WAL, and SHM boundary in backups.
2. Create a dedicated `CONNECTION_SECRETS_ROOT`; do not reuse a source checkout,
   home directory, container image layer, or general configuration directory.
3. If encrypted local secrets are needed, create and separately back up a
   32-byte primary master key, then configure
   `CONNECTION_LOCAL_SECRET_KEYRING`.
4. Configure operator-owned environment/file aliases through
   `CONNECTION_SECRET_ALIASES`; never put their locators in a Connection
   request.
5. Explicitly allow every managed endpoint and OAuth token host in egress
   policy. Managed destinations do not auto-authorize themselves.
6. Grant the narrow Connection and tool permissions each operator needs.
7. Save new Connections disabled, test their stored profiles, refresh managed
   catalogs where applicable, inspect audit events, and enable them only after
   the results are understood.
8. Exercise backup restore and legacy rollback before removing any old
   deployment setting.

Leaving `CONNECTIONS_SQLITE_PATH` unset is a supported read-only state. It
creates no database and preserves the legacy runtime. Configured legacy
upstreams appear in the Connections inventory as immutable projections.

Two opt-in deployment examples make the storage boundary explicit:

- [`docker-compose.connections.yml`](../../docker-compose.connections.yml)
  bind-mounts a durable database directory and a separate read-only secrets
  root. The host directories must be prepared for UID/GID `10001` before
  startup.
- [`greengateway-connections.example.yaml`](../../deploy/kubernetes/greengateway-connections.example.yaml)
  uses one replica and a `ReadWriteOnce` volume for SQLite. Its init container
  copies a projected Kubernetes Secret into memory-backed real files because
  projected Secret leaves are symlinks, which GreenGateway rejects.

These are custody examples, not high-availability designs. Do not share one
SQLite database between gateway processes or scale either example beyond one
writer.

## Secret Authority

Connection documents contain opaque secret bindings, never plaintext values,
environment-variable names, mounted-file paths, ciphertext, or master-key IDs.
Three providers are available:

| Provider | Provisioned by | Rotation |
|---|---|---|
| Operator environment | Startup configuration and process environment | Change the deployment environment; usually restart the process |
| Operator file | Startup configuration and a protected mounted file | Atomically replace the file inside the same protected root |
| Encrypted local | A write-only admin operation | Rotate in the admin UI or API; the old value is not returned |

Environment and file aliases are resolved for each authorized use. The
provider does not cache their values. An in-flight request keeps its already
resolved, redacted value, while the next request observes a successfully
replaced mounted file.

### Configure operator aliases

`CONNECTION_SECRET_ALIASES` is trusted startup JSON. The admin API sees only
the alias ID, safe label, provider kind, and configured state.

```sh
CONNECTION_SECRET_ALIASES='[
  {
    "id": "billing-bearer",
    "label": "Billing bearer token",
    "source": {"type": "environment", "key": "GGW_BILLING_BEARER"}
  },
  {
    "id": "partner-ca",
    "label": "Partner CA bundle",
    "source": {"type": "file", "key": "partner-ca.pem"}
  }
]'
```

An environment key is a bounded ASCII name. A file key is one filename
segment, not a path. Absolute paths, separators, `.`/`..`, drive or alternate
stream syntax, trailing dots/spaces, Windows device names, symbolic links,
reparse points, and non-regular files are rejected.

Do not use aliases to turn admin input into an environment or filesystem
lookup. Adding or changing a locator is a deployment change and requires a
gateway restart.

### Protect the canonical secrets root

`CONNECTION_SECRETS_ROOT` must exist and canonicalize to a directory at
startup. GreenGateway keeps a capability-backed handle to that directory.
Replacing the configured path or one of its ancestors later does not redirect
the retained handle.

On Unix, use a dedicated directory owned by the gateway service account:

```sh
install -d -m 0700 /run/greengateway-secrets
chmod 0600 /run/greengateway-secrets/*
```

The enforced Unix boundary is that the root cannot be group/other writable and
each secret or key file grants no group/other permissions. Mode `0700` for the
directory and `0600` for leaves is the recommended stricter baseline. On
Windows, grant read access only to the gateway service identity and the
required administrators; the platform-specific regular-file and reparse-point
checks do not replace an operator-managed ACL.

File aliases and master-key files are opened relative to the retained root
without following links. The opened handle is checked again and reads are
bounded by purpose. Mounts must expose real regular files; symlink-based secret
layouts are intentionally unsupported. Rotate a file by atomically replacing
the leaf within the same protected root, then confirm the next authorized test
or call succeeds.

## Encrypted Local Secret Store

The encrypted local provider stores authenticated ciphertext in the
Connections SQLite database and keeps master keys outside it. It uses one
primary key for new writes and may retain decrypt-only predecessors while
rotation is in progress.

### Create the first master key

Each key file contains exactly 32 raw random bytes: no base64, hex, newline, or
text wrapper. Generate it directly into the protected mount so it is not
printed or stored in shell history:

```sh
umask 077
openssl rand -out /run/greengateway-secrets/local-secret-2026-07.key 32
test "$(wc -c < /run/greengateway-secrets/local-secret-2026-07.key)" -eq 32
```

Do not display the file to verify it. Back it up through the deployment's
secret-custody system, separately from the SQLite backup.

Configure the durable database, root, and one primary key:

```sh
CONNECTIONS_SQLITE_PATH=/var/lib/greengateway/connections.sqlite
CONNECTION_SECRETS_ROOT=/run/greengateway-secrets
CONNECTION_LOCAL_SECRET_KEYRING='[
  {
    "id": "local-2026-07",
    "file": "local-secret-2026-07.key",
    "role": "primary"
  }
]'
```

The keyring has at most eight entries and exactly one `primary`. GreenGateway
fails startup if encrypted rows exist but a required key is absent, wrong, or
cannot authenticate those rows. It never treats unreadable encrypted material
as an empty binding.

### Rotate a master key

Master-key rotation is separate from rotating a stored API key, bearer token,
OAuth client secret, certificate, or private key.

1. Create and back up a new 32-byte file in the same protected root.
2. Change the old key's role to `decrypt_only`, add the new key as `primary`,
   and restart GreenGateway with both files present.
3. With the same production configuration environment available, run one
   bounded, resumable transaction at a time:

   ```sh
   gateway connection-secrets reencrypt --batch-size 64
   ```

   `N` must be from 1 through 64. This is a one-shot maintenance command; it
   prints `reencrypted=N remaining=N` and exits without starting gateway
   listeners. Each invocation processes only one bounded batch. Serialize
   invocations and repeat until `remaining=0`. If a row cannot be
   authenticated, the whole current batch rolls back and must be investigated;
   already completed earlier batches do not need to be repeated.
4. Prove that no row still names the predecessor:

   ```sh
   gateway connection-secrets ensure-key-unused --key-id local-2026-07
   ```

5. Only after that command succeeds, remove the predecessor from
   `CONNECTION_LOCAL_SECRET_KEYRING`, restart, and then retire its mounted file
   according to the key-custody policy.

Never remove a decrypt-only entry or key file based only on the number of
successful batches. The explicit unused-key check is the retirement gate.

### Backup and restore

Treat the following as one recovery set with separate custody:

- the Connections SQLite database and its consistent WAL boundary;
- every master-key file still present in
  `CONNECTION_LOCAL_SECRET_KEYRING`;
- the exact key roles and IDs used by that backup;
- operator file secrets and the deployment configuration that defines their
  opaque aliases.

Use a SQLite-aware online backup, or stop the gateway cleanly before taking a
filesystem-level copy. Do not copy only the main database while an uncheckpointed
WAL may contain committed changes. Keep key backups away from database backups
so compromise of one store alone is insufficient.

For a restore rehearsal:

1. Restore the database/WAL boundary to an isolated path.
2. Restore the corresponding key files into a protected isolated root.
3. Configure the exact backed-up key IDs and roles.
4. Start an isolated gateway with outbound egress blocked.
5. Confirm startup succeeds and only safe secret metadata is visible.
6. Permit only controlled recovery-validation destinations, Test representative
   disabled Connections, and keep ordinary production egress blocked until the
   rehearsal is complete.

A database without every key referenced by its encrypted rows is intentionally
unrecoverable. A key backup without its database has no secret records.
GreenGateway has no reveal or plaintext export operation. If all copies of a
required master key are lost, the affected local secret values cannot be
decrypted; restore a complete older recovery set or create replacement secrets
from their original systems of record and rebind the affected Connections.
Failing open, extracting ciphertext, or editing key IDs in SQLite is not a
recovery method.

## Authentication Profiles

Connections support `none`, a header API key, a static bearer token, and OAuth
2.0 client credentials. Enabled authenticated Connections require a compatible
configured alias. Authentication and TLS material require HTTPS.

For header API keys, choose a dedicated upstream header. GreenGateway rejects
headers that it or HTTP owns, including `Authorization`, `Cookie`, `Host`,
framing, forwarding, hop-by-hop, proxy-authentication, `Sec-*`, and request-ID
headers. The caller's value for the selected header is removed and the
protected value is injected last.

### OAuth 2.0 client credentials

The supported OAuth profile is deliberately narrow:

- grant: `client_credentials`;
- client authentication: `client_secret_basic`;
- explicit HTTPS token URL;
- optional bounded scopes, `audience`, and `resource`;
- JSON bearer-token response with a positive bounded `expires_in`.

The token endpoint receives its own egress, DNS-pinning, TLS, response-size,
and timeout checks. Redirects and token-endpoint metadata discovery are not
followed. Access tokens are held only in a bounded in-memory, revision-keyed
cache and are never persisted. Concurrent refreshes share one bounded
single-flight operation. An upstream `401` invalidates only the token
generation used by that request and does not replay the rejected operation.

Authorization-code, PKCE, device-code, resource-owner-password, refresh-token,
implicit, token-exchange, and JWT assertion flows are not Connection
authentication modes. `client_secret_post`, `private_key_jwt`, and automatic
issuer/token-endpoint discovery are also unsupported. Do not emulate them with
custom request headers or a tool argument; retain the legacy integration or
place a purpose-built token broker behind an independently secured Connection.

## TLS, Custom CAs, and Mutual TLS

TLS trust is independent from HTTP authentication:

- A custom CA bundle is a protected alias whose complete PEM bundle must parse.
- Mutual TLS uses separate protected certificate and private-key aliases. Both
  are required before an enabled Connection can use mTLS, and the pair must
  match.
- Certificate hostname/SNI verification remains enabled with custom roots and
  mTLS.
- There is no `skip_verify`, insecure mode, caller-provided CA, or per-request
  TLS override.

Use a private development CA instead of disabling verification. Encrypted-local
rotation preflights the complete proposed CA or identity and leaves the prior
value and active runtime unchanged on parse or certificate/key-match failure.
Operator environment/file aliases do not retain a last-known-good value:
validate their replacement externally before changing the environment or
atomically replacing the mounted leaf.

## Tests and Catalog Refreshes

The Test action is a constrained probe of saved state, not a general HTTP
client. It accepts no URL, method, path, header, body, credential, TLS, timeout,
or egress override. HTTP tests use only the saved `GET` or `HEAD` profile and
expected status set. MCP tests perform a bounded protocol check and do not call
a tool, read a resource, or publish a catalog.

Run Test after:

- changing endpoint, authentication, TLS, timeout, or test-profile settings;
- rotating a referenced operator or encrypted-local secret;
- changing relevant egress or upstream policy;
- restoring a backup;
- enabling a disabled draft.

Managed OpenAPI and MCP discovery use Refresh. A refresh builds and validates a
complete candidate before publishing it. On a failed refresh, no partial
catalog is published. If a previous successful catalog exists, it remains the
last-known-good catalog and the Connection reports `degraded/catalog_stale`.
Without a prior catalog, the Connection becomes unavailable. Investigate the
safe failure reason and catalog age rather than repeatedly refreshing.

For OpenAPI, preview and confirm the selected generated tools before the first
registration. Subsequent refreshes preserve a surviving public tool name only
when it still represents the same operation and safe mapping; a document
cannot silently move an existing name to a different request.

## Observability and Alerts

The audit stream records bounded, payload-free events for Connection and
playground operations:

- `connection.changed`
- `connection.credential_changed`
- `connection.secret_changed`
- `connection.tested`
- `connection.refreshed`
- `connection.oauth_token_refresh`
- `connection.secret_resolution_failed`
- `tool.invoke_start`, `tool.invoke_success`, `tool.invoke_failure`, and
  `tool.invoke_rejected`
- `tool.playground_output_rejected`

Events contain stable IDs, safe reason/outcome categories, revision or count
data, and bounded latency where applicable. They must not contain resolved
values, secret locators, token responses, certificate contents, arguments,
results, upstream bodies, DNS answers, or raw transport errors.

Prometheus metrics remain available at `/metrics`. At minimum, monitor normal
request outcomes for the Connection admin/test/refresh routes and
`connection_oauth_token_refresh_total` by its bounded `result` and `reason`
labels. Alert on:

- repeated `connection.secret_resolution_failed` events;
- any sustained OAuth refresh failure rate;
- a healthy Connection becoming `unavailable`;
- `degraded/catalog_stale` with catalog age beyond the service's approved
  staleness objective;
- repeated test/refresh admission rejection or failure;
- unexpected credential, TLS, origin, or binding changes;
- key re-encryption that stops making progress or a predecessor that cannot be
  proven unused;
- playground execution by a principal outside the approved operator group.

Avoid connection names, URLs, secret IDs, provider locators, or other
high-cardinality/sensitive values in alert labels. Link an alert to the
redacted audit event and stable Connection ID instead.

## Safe Disable and Rollback

Disabling a managed Connection prevents production use without deleting its
metadata, status, catalog, dependencies, or protected bindings. It is the
preferred first containment action when the managed path is suspect.

For an operator-visible regression:

1. Stop new managed traffic by restoring the previous route/tool/MCP policy or
   disabling the affected Connection.
2. Keep the managed database and secret/key material intact for investigation;
   do not clear bindings or delete secrets as part of traffic rollback.
3. Restore the last-known-good legacy deployment settings described in the
   [migration guide](migration.md).
4. Restart with the prior reviewed configuration and verify readiness, policy,
   representative traffic, and redacted audit events.
5. Repair the managed candidate while it remains disabled, then Test and
   Refresh before another cutover.

Deleting a Connection is not a rollback mechanism. Retained proxy/tool/catalog
dependencies block deletion, and there is no force-delete path. Likewise,
clearing a binding is a sensitive mutation, not a harmless way to pause
traffic.

## External Secret Providers

Issue #240 intentionally ships operator environment/file aliases and the
encrypted local provider first. Follow-up provider integrations are tracked
separately so each can receive its own workload-identity, egress, TLS,
rotation, bounds, and redaction review:

- [HashiCorp Vault #271](https://github.com/Greenhat-Security/GreenGateway/issues/271)
- [AWS Secrets Manager #272](https://github.com/Greenhat-Security/GreenGateway/issues/272)
- [Azure Key Vault #273](https://github.com/Greenhat-Security/GreenGateway/issues/273)
- [Google Cloud Secret Manager #274](https://github.com/Greenhat-Security/GreenGateway/issues/274)
- [Kubernetes Secrets API #275](https://github.com/Greenhat-Security/GreenGateway/issues/275)

Until one of those integrations lands, do not place cloud-provider locators in
Connection fields or grant a gateway administrator indirect access to an
arbitrary provider path.
