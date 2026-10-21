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
5. Explicitly allow every managed endpoint and OAuth token host in egress policy. Managed destinations do not auto-authorize themselves, and allowlisting a host is not sufficient when it resolves to a private address — see [Admitting a private API server](#admitting-a-private-api-server).
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
Eight providers are available:

| Provider | Provisioned by | Rotation |
|---|---|---|
| Operator environment | Startup configuration and process environment | Change the deployment environment; usually restart the process |
| Operator file | Startup configuration and a protected mounted file | Atomically replace the file inside the same protected root |
| Encrypted local | A write-only admin operation | Rotate in the admin UI or API; the old value is not returned |
| HashiCorp Vault KV v2 | `CONNECTION_VAULT_PROVIDER` | Rotate in Vault; unpinned aliases pick it up after the bounded cache expires |
| AWS Secrets Manager | `CONNECTION_AWS_PROVIDER` | Rotate in AWS; `AWSCURRENT` becomes visible after the bounded cache expires |
| Azure Key Vault | `CONNECTION_AZURE_PROVIDER` | Rotate in Key Vault; unversioned aliases pick it up after the bounded cache expires |
| Google Cloud Secret Manager | `CONNECTION_GCP_PROVIDER` | Add a version in GCP; `latest` aliases pick it up after the bounded cache expires |
| Kubernetes Secrets API | `CONNECTION_KUBERNETES_PROVIDER` | Update the Secret; aliases pick it up after the bounded cache expires |

The five network providers are read-only: the gateway never creates, rotates, or deletes material in them, and a pinned version stays pinned until an operator changes the configuration.

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

Connections support `none`, a header API key, a static bearer token, OAuth
2.0 client credentials, and a delegated issuer token, which calls the upstream
as each caller with that caller's own token (see
[Delegated issuer tokens](#delegated-issuer-tokens)). Every enabled
secret-backed primary or additional binding requires a compatible configured
alias. Authentication and TLS material require HTTPS.

For header API keys, choose a dedicated upstream header. GreenGateway rejects
headers that it or HTTP owns, including `Authorization`, `Cookie`, `Host`,
framing, forwarding, hop-by-hop, proxy-authentication, `Sec-*`, and request-ID
headers. The caller's value for the selected header is removed and the
protected value is injected last.

### Additional secret headers and identity-aware proxies

A Connection can carry up to four `additional_headers` alongside its primary
`authentication` profile. Each entry contains a `header_name` and an opaque
`secret_id`; the referenced secret must be compatible with the
`header_api_key` purpose, so the same 8 KiB limit and HTTP-header value safety
checks apply. A disabled draft may temporarily omit an entry's `secret_id`, but
every entry must be bound before the Connection can be enabled. Any Connection
that sends a primary or additional credential must use HTTPS.

Additional header names are normalized to lowercase and must be unique without
regard to case. They cannot match the primary `header_api_key` name and cannot
use any of the reserved names listed above, including `Authorization`. Use the
primary authentication profile for the upstream application's credential and
the additional list for credentials required by an intermediary.

For example, a Cloudflare Access service token needs two distinct secrets in
addition to this upstream API key. This is the relevant Connection fragment;
each of the three IDs must refer to its own configured secret:

```json
{
  "authentication": {
    "type": "header_api_key",
    "header_name": "x-api-key",
    "secret_id": "twenty-api-key"
  },
  "additional_headers": [
    {
      "header_name": "cf-access-client-id",
      "secret_id": "twenty-access-client-id"
    },
    {
      "header_name": "cf-access-client-secret",
      "secret_id": "twenty-access-client-secret"
    }
  ]
}
```

If the identity-aware proxy accepts client certificates, mTLS is an alternative
to its HTTP token headers: configure the Connection's independent client
certificate and private-key bindings, and keep the primary HTTP authentication
profile for the upstream. Do not assume this alternative works until the proxy
has been configured to accept and authorize that certificate.

Every data-plane lane treats all Connection-owned header names as one protected
set. Tool and proxy request builders remove caller-supplied values for the
primary and every additional name; managed MCP refuses any custom transport
header with a colliding name. After permitted transforms and complete
resolution, the operator values are injected last. If any binding cannot be
resolved or injected, no anonymous or partially authenticated request is sent.
This applies to Connection-bound manual and OpenAPI tools, Connection proxy
routes, HTTP stored tests, and managed MCP POST, SSE GET, and session DELETE
traffic. Managed OpenAPI discovery and all managed MCP protocol traffic,
including its stored test, send the set only when
`use_connection_authentication` is `true`; turning that flag off suppresses
both the primary authentication and the additional headers for those gated
operations. OpenAPI-generated tool execution remains an ordinary
Connection-bound HTTP request and uses the Connection's credential set.
Additional headers do not satisfy an OpenAPI security scheme—the security
matcher considers only the primary `authentication` profile.

Configuring an additional header on create—or adding, removing, reordering,
renaming, binding, or clearing one later—is credential-authority work and
requires `admin:connections:secrets:write` in addition to the ordinary
Connection write permission. Creation initializes the credential and Connection
revisions; a later change advances both revisions, changes the resource ETag,
invalidates stale status, and is emitted as a redacted credential change. Safe
read responses return only each normalized header name and `secret_configured`;
they never return the secret ID or value. On `PUT`, round-trip the matching
`secret_configured: true` marker to retain a hidden binding, or submit an
explicit `secret_id` only as a secrets writer.

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
implicit, and JWT assertion flows are not Connection authentication modes, and
token exchange is offered only as a per-caller
[delegated issuer token](#delegated-issuer-tokens). `client_secret_post`, `private_key_jwt`, and automatic
issuer/token-endpoint discovery are also unsupported. Do not emulate them with
custom request headers or a tool argument; retain the legacy integration or
place a purpose-built token broker behind an independently secured Connection.

### Signed caller assertions

A Connection with a `caller_assertion` block tells its upstream who is
calling. On every call of a manual HTTP tool it signs a short-lived JWT that
names the validated calling principal and sends it in `header_name`, alongside
the Connection's own credential. The credential says which system is calling; the assertion says on
whose behalf. An upstream the operator controls verifies the assertion against
the gateway's published key set (see [The published JWKS](#the-published-jwks))
and can then apply its own per-user ownership and entitlement checks, which a
single shared credential makes impossible. It is the same shape as Google IAP's
`X-Goog-IAP-JWT-Assertion` and Cloudflare Access's `Cf-Access-Jwt-Assertion`.

#### Which calls are attested

Manual HTTP tools bound to the Connection are attested, whether they are called
through the MCP endpoint or the admin tool playground. Every other lane on such
a Connection is refused with `caller_assertion_not_enforced`, before any DNS
lookup, secret read, OAuth mint or upstream request, rather than sent without
the assertion: managed OpenAPI tools and composite tools, proxied requests,
managed MCP sessions and MCP tool calls, OpenAPI and MCP discovery, enum and
label source fetches, and stored Connection tests. Those lanes either have no
calling principal to attest, or do not hold the exact request before it is
sent.

On those lanes the refusal reason appears as follows:

- Managed OpenAPI or MCP tool call: the `failure_reason` of
  `tool.invoke_failure` and the `reason` of `tool.upstream_request`. A
  composite tool reports at the tool level: its `failure_reason` is
  `composite_failed`, and the failing step's `caller_assertion_not_enforced` is
  only in the error details returned to the caller, not in any audit event.
- Stored Connection test: the `authenticated` stage reason.
- OpenAPI preview, registration and refresh, and MCP catalog refresh: the
  `reason` of a `409 Conflict` response. A refused registration is also
  audited as `tool_registry.changed` with action
  `managed_openapi_catalog_registration_rejected`, and a refused refresh as
  `connection.refreshed`, both with outcome `failure` and this reason.
- Enum source refresh: the `reason` of `connection.enum_source_refresh_failed`.
  Label sources compile during OpenAPI preview and registration, which are
  refused first.
- Proxied request: the caller receives `502` with `{"error":"bad_gateway"}`.
  The refusal is recorded by tracing only: the reason appears as
  `error_category` on the gateway's warning log line, and no structured audit
  event names it. Every other Connection failure on a proxy route behaves the
  same way.

A manual tool may be bound to an attested Connection. Other bindings fail the way bindings to a disabled Connection do: a
proxy route bound to it fails startup or the whole reload that contains it. A
managed OpenAPI catalog on it is withdrawn from the tool list and kept in
storage; refresh it after removing the block to publish it again. Managed MCP
tools stay listed, and every call to one is refused.

#### What the assertion says

The JOSE header carries `alg` (`ES256` or `RS256`, from `algorithm`), `kid`
(from `kid`) and `typ` (from `token_type`). The claims are:

| Claim | Value |
| --- | --- |
| `iss` | `issuer` |
| `aud` | `audience` |
| `sub` | The caller's identity provider issuer, `#`, then the provider's subject, for example `https://idp.example#alice`. The provider issuer scopes the subject because two providers can issue the same subject for different people. |
| `caller_iss`, `caller_sub` | The two halves of `sub`, unscoped. An upstream that matches its own user records reads these and never parses `sub`. |
| `iat`, `exp` | Signing time and `iat` plus `lifetime_seconds`. |
| `jti` | The gateway request ID of the call (`X-Request-Id`), the same ID its audit events carry. |
| `email` | With `email` in `claims`, the principal's email, when it has one. Copied from the principal as its identity provider gave it; see the note below the table. |
| `roles` | With `roles` in `claims`, the principal's roles, as an array. |
| `method`, `path`, `request_sha256` | With `bind_request: true`: the request method, the request target exactly as it appears on the request line (path, then `?` and the query when there is one), and the lowercase hexadecimal SHA-256 of the exact body bytes sent, which is the hash of empty input for a request without a body. |

Every identity claim comes from the authenticated principal, never from a tool
argument; the bound request claims describe the request the gateway built
from the arguments, as sent. The assertion is signed once per call,
after every other header and the body are final, and written as the last
header. The lane removes the header name from anything a caller supplied, and
validation keeps it apart from the Connection's primary and additional header
names and from the headers a tool sets. If a value were still present at
injection the call would be refused with `caller_assertion_header_conflict`
rather than send two values or replace one. The signing key is read and
loaded on every call, through the same secret resolution and loader that admit
it on a save and publish it in the JWKS, so a key that stops loading stops
signing on the next call. It is loaded before the Connection's credential is
resolved, so a key that cannot sign refuses the call before any OAuth token is
requested.

Identify a user by `caller_iss` and `caller_sub`, or by `sub`, never by
`email`. The gateway copies `email` from the principal without checking that
the identity provider verified it (`email_verified` is not consulted), so it
is advisory: use it for display or notifications, not to look up who the
caller is.

`request_sha256` is over the bytes on the wire, not a canonical form of the
JSON: the upstream hashes exactly what it received. A body that parses to the
same JSON with its keys in another order has a different digest.

#### Which callers can be attested

A principal that an identity provider vouched for can be attested: a bearer
JWT, a session cookie, a client certificate, or the admin session that runs a
tool in the playground. A call is refused with `caller_assertion_no_principal`
before any DNS lookup, secret read or upstream request when there is nobody to
name: an anonymous call, a service token (a credential the gateway issued to a
system, not a person), or a principal without an issuer to scope its subject
by. The refusal is audited like any other: `tool.invoke_failure` names the
reason and the caller's actor, and `tool.upstream_request` records the
refused request.

#### HTTPS only

An assertion is a bearer credential for its lifetime: anyone who reads it can
present it as the caller until it expires. A new or replacement write of a
Connection that carries the block must use an `https://` `base_url`, or it is
refused with `422`, `endpoint.base_url` and `https_required`, as a credentialed
Connection is. A document stored over plain HTTP by an earlier release still
loads, and every call on it is refused with `caller_assertion_not_enforced`.

#### Failure reasons

Each refusal is a fixed string in the `failure_reason` of `tool.invoke_failure`
(its `reason` is `work_error`) and the `reason` of `tool.upstream_request`:

| Reason | Meaning |
| --- | --- |
| `caller_assertion_no_principal` | The call has nobody to attest: anonymous, a service token, or a principal without an issuer. |
| `caller_assertion_key_not_published` | This replica leaves the Connection's keys out of the published JWKS, so no upstream that fetched it could verify what the Connection signed: one of its keys, the signing key or a published key, did not resolve or load at the last check, or another enabled Connection publishes a different key under one of its `kid`s. See [Stored Connections whose keys cannot be used](#stored-connections-whose-keys-cannot-be-used). |
| `caller_assertion_key_unusable` | At call time, the signing key's alias is unknown or refused, or holds material that is not a usable key for `algorithm`. |
| `caller_assertion_key_unavailable` | At call time, the signing key's source could not be read. |
| `caller_assertion_claim_invalid` | A value would not survive as a claim: a subject longer than 256 bytes, an issuer longer than 512 bytes or containing `#`, a role longer than 128 bytes, an email longer than 320 bytes, a request ID longer than 128 bytes, with `bind_request` a request target longer than 2048 bytes or a method longer than 16 bytes, or any of them containing a control character. |
| `caller_assertion_header_conflict` | Another header source had already set the assertion header. |
| `caller_assertion_signature_failed`, `caller_assertion_token_too_long` | Signing failed, including on a host whose clock reads before 1970, or the assertion would exceed 8 KiB. |
| `caller_assertion_not_enforced` | The lane does not attest its caller, or the stored block is one only an earlier release accepted: `bind_approval: true`, an assertion header that matches an additional header, or a plain HTTP endpoint. |

A signing key that cannot be read or loaded at call time also raises
`connection.secret_resolution_failed` with the same reason. None of these
responses, logs or events carries the assertion, the key or anything derived
from either.

An assertion counts as a credential when the upstream answers. A `401` or
`403` from the upstream of an attested Connection fails the call with
`upstream_authentication_rejected`, as on any Connection with a credential, and
the upstream's body is not returned to the caller: an error body that echoed
the assertion would hand the caller a bearer token it could present to the
upstream directly until it expires. A per-user denial therefore reaches the
caller as that reason rather than as the upstream's message; the upstream's own
log, found by `jti`, has the detail. On an OAuth Connection every upstream
`401` also drops the cached access token, so the next call mints a new one: an
upstream should answer a user it denies with `403`, and keep `401` for a
credential or assertion it cannot verify.

#### Audit

`tool.upstream_request` for a request that carried an assertion records which
key signed it and its `jti`, whatever the outcome:

```json
"caller_assertion": { "kid": "gw-2026-09", "jti": "6f1c2a4e-..." }
```

The attested caller is the event's `actor`. To find the gateway's record of a
request an upstream logged, search the audit for its `jti`.

#### Verifying an assertion

An upstream verifies the signature against the published JWKS, pins `iss`,
`aud`, `typ` and the algorithm, checks `exp`, and, with `bind_request`, compares
the bound request with the one it received. For example, in Python with PyJWT
2.8 or later:

```python
import hashlib

import jwt

JWKS = jwt.PyJWKClient("https://gateway.example/.well-known/caller-assertion-jwks.json")


def verified_caller(method, request_target, body, headers):
    token = headers["X-Caller-Assertion"]
    if jwt.get_unverified_header(token).get("typ") != "at+jwt":
        raise PermissionError("not a caller assertion")
    claims = jwt.decode(
        token,
        JWKS.get_signing_key_from_jwt(token).key,
        algorithms=["ES256"],  # the Connection's algorithm, never the token's
        issuer="https://gateway.example",
        audience="https://internal.example/api",
        options={"require": ["iss", "aud", "sub", "iat", "exp", "jti"]},
    )
    # With bind_request: the method, the request target as it appeared on the
    # request line, and the exact body bytes received.
    if claims["method"] != method or claims["path"] != request_target:
        raise PermissionError("assertion is for another request")
    if claims["request_sha256"] != hashlib.sha256(body).hexdigest():
        raise PermissionError("body changed after signing")
    # Reject a second use of the same assertion until it expires.
    if not remember_once((claims["sub"], claims["jti"]), until=claims["exp"]):
        raise PermissionError("assertion replayed")
    return claims["caller_iss"], claims["caller_sub"]
```

`remember_once` stands for the upstream's own replay cache. Key it on `sub` and
`jti` together: `jti` is the gateway request ID, which a client may supply
itself in `X-Request-Id`, so it is not guaranteed unique per call, and two
callers can send the same one. Keyed on both, a repeat can only be the same
caller's, and a client that reuses an ID sees its own second call rejected.
Compare `path` with the request target before any proxy in front of the
upstream rewrote it. `exp` is `iat` plus `lifetime_seconds` on the gateway's
clock; if the two clocks can drift apart, allow a few seconds of leeway
(`leeway=` in PyJWT) rather than lengthening the lifetime.

#### The block in the admin UI

The admin UI shows the block read only, on the Connection detail page and in
the editor: every field except the key aliases, which appear only as
configured or not, with a note on which calls are attested. The UI has no
controls for the block and never sends it. A replacement (`PUT`) that omits
`caller_assertion` keeps the current block, so a save in the UI leaves it
exactly as stored and cannot put the Connection back into service unattested.
The gateway revalidates the kept block on every save, so the editor refuses a
primary or additional header name that matches the assertion header before it
writes, and a block stored with `bind_approval: true` has to be removed before
the Connection can be saved again. To stop attesting, remove the block
deliberately: send `"caller_assertion": null` in a `PUT` through the admin API.

New and replacement writes reject `bind_approval: true`, because no approval
subsystem exists for a mutation to be bound to, an assertion `header_name` that
matches any additional header name regardless of case, and a plain HTTP
endpoint.

A caller assertion binds private keys, so it is credential authority: creating
a Connection that carries one, deleting it, and any change to the block,
including removing it with `null`, needs `admin:connections:secrets:write` as
well as `admin:connections:write`. So does changing the endpoint or test
target of a Connection that carries one, as for any Connection with credential
bindings. A routine save that keeps the block exactly as stored, such as a
rename, does not.

#### Signing keys

The `signing_key_id` and the `signing_key_id` of each entry in `published_keys`
name a secret alias that must hold exactly one PKCS#8 PEM private key block
(`-----BEGIN PRIVATE KEY-----`, at most 16 KiB): a P-256 key for `es256`, or an
RSA key of at least 2048 bits for `rs256`. A PKCS#1 (`BEGIN RSA PRIVATE KEY`)
or SEC1 (`BEGIN EC PRIVATE KEY`) key, an encrypted key, a public key, a
certificate, and any second PEM block beside the key are refused. Commentary
outside the block is allowed. `openssl genpkey` writes the accepted form:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out assertion-es256.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out assertion-rs256.pem
```

Keep a key behind an operator alias or an external secret provider. The
encrypted local store cannot hold one: its schema predates the
`assertion_signing_key` purpose, and a local create for that purpose is
refused before anything is written.

Saving an enabled Connection checks every key it configures. Operator aliases
are read and loaded on the save itself; an alias behind a network provider is
read and loaded by the admin API before the save, the same pass that resolves
every other deferred binding. A key that cannot be used refuses the save with
`422` and a problem naming the field and one of these codes:

| Code | Meaning |
| --- | --- |
| `unresolvable_binding` | The alias is not configured, is unknown to its source, is refused by it, or holds material that is not valid for a signing key. |
| `invalid_signing_key` | The material is not exactly one PKCS#8 `PRIVATE KEY` block. |
| `algorithm_mismatch` | The material is a usable key for the other algorithm, so `algorithm` is wrong. |
| `unusable_signing_key` | The key cannot sign with the configured algorithm: an EC key on another curve, an RSA key under 2048 bits, or malformed key material. |
| `duplicate_kid` | Another enabled Connection on this replica publishes a different key under the same `kid`. Two Connections may share one key: the same alias, `kid` and algorithm. |

A source that cannot be read at that moment answers `503` instead, and the save
can be retried. None of these responses, logs or admin views carries the alias,
the material or anything derived from it.

#### The published JWKS

The public half of every key an enabled Connection signs with or publishes is
served as one JWK Set at `GET /.well-known/caller-assertion-jwks.json`. The
path is deliberately not `/.well-known/jwks.json`, which an upstream behind the
gateway may publish for itself.

- It is public. A verifier holds no gateway credential, so the path is always
  exempt from authentication and RBAC, whatever `AUTH_EXEMPT_PATHS` and
  `RBAC_EXEMPT_PATHS` say, and it is gateway-owned: a proxy route never answers
  it, even one at `/`. It is served on the data listener, which is the only
  listener when the admin surface shares it, and not on a separate admin
  listener. It is served whether or not any Connection attests its caller
  (`{"keys":[]}` when none does), and there is no setting that turns it off.
  It exposes each published `kid`, its algorithm and how many keys there are.
- It carries public members only: `kty`, `crv`, `x` and `y` for an ES256 key,
  `kty`, `n` and `e` for an RS256 key, plus `kid`, `alg` and `use: "sig"`. The
  public half is derived from the private key rather than configured beside it,
  and is re-encoded from that fixed member list, so no private parameter can
  reach the document.
- It is one set for the whole gateway. A key two Connections share is
  published once. Any principal who can bind a caller assertion can therefore
  add a key every verifier of this set will trust, so a verifier must pin the
  `iss` and `aud` it expects, and each upstream should be given its own
  `audience`.
- A response carries `Cache-Control: public, max-age=300` and a strong `ETag`;
  a request with a matching `If-None-Match` is answered `304 Not Modified`.
- The gateway reads the keys again when the set of configured keys changes (a
  save or reconcile that adds, removes or disables one) and otherwise every
  300 seconds, so a change of material behind an alias reaches a verifier that
  honours `max-age` within about 600 seconds. A set that left a Connection out
  is read again every 30 seconds, by the next fetch or the next tool call on
  that Connection, whichever comes first, and a save of a Connection rebuilds
  that replica's set at the next fetch, so a repaired key comes back promptly.
  However often the set is fetched, the gateway reads each alias at most once
  per build, and a fetch that arrives while the set is being rebuilt for the
  same keys is answered from the previous build rather than held on the secret
  provider.
- After a refresh fails to read a key, the gateway does not keep publishing
  what that key held before: the material behind an alias that is not pinned to
  a version may have changed, and the gateway never uses what such an alias
  held as a fallback once it can no longer read it. That Connection is left out
  of the set until a refresh reads the key again. Verifiers should keep their
  last good copy when a fetch fails.
- A fetch that has no set built from the current configuration waits up to 10
  seconds for a build in progress, then gets `503` with
  `Cache-Control: no-store`, so a verifier keeps the set it already holds.

A Connection publishes all of its keys or none of them. Its keys are left out
when one of its aliases is not configured, cannot be read, or does not hold a
usable key for its algorithm, and when it publishes a `kid` that another
enabled Connection publishes for a different key; the save check above
prevents that, but two replicas can each admit one side of it concurrently,
and a document stored before the check was never held to it, so both
Connections are left out. Every other Connection's keys are still published.

When a Connection's keys are left out, the gateway logs a warning,
`an enabled Connection's caller-assertion keys cannot all be used; its keys are
left out of the published JWKS and its tool calls are refused until they load`,
with `connection_id`, `field` and `code`, when it first finds the problem and
whenever the problem changes. The Connection's admin detail reports the same
pair as `configuration.caller_assertion.key_problem`, and the admin UI shows it
as "Keys not published". The codes are those in the table above, plus
`binding_unavailable` when the key's source could not be read. Startup and a
cluster reconcile read the keys behind operator aliases; a key behind a network
provider is only checked there for being configured, and is first read when
the set is built.

#### Stored Connections whose keys cannot be used

A stored Connection whose keys cannot be used never stops the gateway starting
and never fails a cluster reconcile. Its keys are left out of the JWKS and the
problem is logged and shown as above.

While a replica leaves a Connection's keys out of the set it publishes, it
refuses every tool call on that Connection with
`caller_assertion_key_not_published`, before any DNS lookup, credential read or
upstream request, even when the signing key itself still loads: an upstream
that fetched that set could not verify what the Connection signs. The verdict
is per replica, from its own last check of exactly the keys the Connection
configures now, so a replica that reads the keys can serve while another that
cannot refuses.

The refusal does not wait for a verifier to fetch the set. A call that finds
the keys left out first reads them again, the way a fetch would and at most
once per 30-second retry interval however many calls arrive, so once every
key loads the set publishes them and the same call is served. Within the
interval a call reads nothing and is refused. A save of the Connection clears
the problem at once, because the save loads every key.

A key that cannot be read or loaded when a call signs, after the keys were
last published, refuses that call with `caller_assertion_key_unusable` or
`caller_assertion_key_unavailable`. Every other lane refuses the Connection
with `caller_assertion_not_enforced`, as it refuses every attested Connection.
Startup and reconcile still refuse a stored Connection whose other bindings
this replica cannot resolve, as they always have.

A save is held to the stricter rule. A save that keeps such a Connection
enabled checks its keys again and is refused until they are usable, including
an admin UI save of another field, because the UI keeps the stored block. To
clear the problem, do one of these:

- Put a usable key behind the alias and save the Connection again. The set
  includes its keys from the next fetch.
- Disable the Connection. A disabled Connection publishes nothing, and saving
  it needs no key.
- Remove the block with `"caller_assertion": null`, which needs
  `admin:connections:secrets:write`.

#### Upgrade note: caller assertions stored by earlier releases

Earlier releases stored a `caller_assertion` block without reading its signing
key, so an enabled Connection may carry an alias that is not configured, a
placeholder, or a key in a format this release refuses. After upgrading:

- The gateway starts, and a cluster reconcile succeeds, as before. Each such
  Connection publishes no keys, reports `key_problem`, logs the warning above,
  and its tool calls are refused with `caller_assertion_key_not_published`
  until its keys load.
- Its next save is stricter. A save that keeps it enabled, including an admin
  UI save of another field, loads its keys and is refused with `422` and the
  field and code until they are usable.
- Creating, deleting, or changing a Connection's `caller_assertion`, including
  removing it, now needs `admin:connections:secrets:write`.

Before or after upgrading, put a real PKCS#8 key behind each enabled attested
Connection's aliases, disable the Connection, or remove its block.
`GET /v1{ADMIN_PREFIX}/connections/{id}` reports
`configuration.caller_assertion.key_problem` for every Connection that still
needs attention, and the admin UI shows it on the Connection's page.

#### Rotating a signing key

The JWKS lets a key rotate without a flag day, provided every verifier holds a
key before anything is signed with it, and still holds it until everything it
signed has expired:

1. Put the next key behind a new alias. Add it to `published_keys` with a new
   `kid` and its algorithm, and save.
2. Wait at least 300 seconds, the JWKS `max-age`, so every verifier that
   honours it has fetched the next key before it signs anything. Wait longer if
   a verifier caches the set for longer.
3. In one `PUT`, make the next key the signing key (`signing_key_id`, `kid` and
   `algorithm`) and move the previous signing key into `published_keys`.
4. Keep the previous key published for at least `lifetime_seconds` plus the
   verifiers' cache time, 300 seconds for one that honours `max-age`, so every
   assertion it signed has expired before a verifier drops it. Then remove it
   from `published_keys` and save.
5. Never change the material behind an alias or `kid` that is published. A
   verifier caches keys by `kid` and would reject what the new material signs
   until its cache expires. To retire a compromised key, remove it from the
   block, which withdraws it at the next fetch, and publish a new key under a
   new `kid`.

The gateway does not enforce these waits. A tool call signs with whichever key
is `signing_key_id` when it runs, so skipping step 2 leaves every verifier that
has not fetched the next key rejecting calls until its cache expires, and
skipping step 4 rejects assertions the previous key signed that have not
expired yet.

#### Upgrade note: attested Connections start serving tool calls

Earlier releases refused every lane on a Connection carrying `caller_assertion`
with `caller_assertion_not_enforced`. From this release, manual HTTP tools on
such a Connection are served, and every one of their requests carries the
signed assertion, once its stored block passes every rule a new write is held
to:

- `bind_approval` is `false`;
- the assertion `header_name` matches no primary or additional header name;
- the endpoint is `https://`;
- every key it configures loads, so the replica publishes them, and no other
  enabled Connection publishes a different key under one of its `kid`s;
- the signing key loads for its `algorithm` when the call is made.

A block that fails one of the first three rules stays refused with
`caller_assertion_not_enforced`; a key problem refuses each call with its own
reason (see [Failure reasons](#failure-reasons)). A save of an
attested Connection whose endpoint is still plain HTTP, including an admin UI
save of another field, is now refused with `https_required` until the endpoint
uses HTTPS or the block is removed. A `TOOLS_FILE`
manual tool bound to such a Connection used to fail startup or the reload that
contained it; it now loads.

Before upgrading, check every enabled Connection that carries the block:

- Its upstream verifies the assertion, or at least tolerates the extra header,
  because it starts arriving on the first call.
- Its callers are principals an identity provider vouched for: anonymous calls
  and service tokens are refused with `caller_assertion_no_principal`.
- To keep a Connection refused until its upstream is ready, disable it or
  remove the block with `"caller_assertion": null` before upgrading.

Managed OpenAPI tools, composite tools, proxied requests, managed MCP, discovery,
enum and label sources and stored tests on such a Connection stay refused, as
before.

### Delegated issuer tokens

A Connection with `delegated_issuer_token` authentication calls its upstream
as the calling user, with that user's own token, instead of as one service
identity shared by every caller. It is for per-user systems -- a mailbox, a
calendar, a document store, a chat workspace -- where a shared credential
would let every caller read one account.

The gateway never holds anybody's provider grant. A trusted issuer does: an
identity provider or token broker that stores each user's grant for the
upstream (Auth0, Keycloak, Entra or a small purpose-built service) and
answers OAuth 2.0 token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)).
For each caller the gateway asks it for that caller's access token, caches the
answer for that caller only, and sends it upstream as
`Authorization: Bearer`.

```json
"authentication": {
  "type": "delegated_issuer_token",
  "token_exchange_url": "https://issuer.example/oauth2/token-exchange",
  "client_id": "greengateway",
  "client_secret_id": "issuer-exchange-secret",
  "requested_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "audience": "https://gmail.googleapis.com",
  "subject_token_source": "caller_assertion"
},
"caller_assertion": {
  "signing_key_id": "gateway-assertion-key",
  "kid": "gw-2026-10",
  "algorithm": "es256",
  "issuer": "https://gateway.example",
  "audience": "https://issuer.example",
  "token_type": "caller-assertion+jwt",
  "header_name": "x-caller-assertion",
  "lifetime_seconds": 60
}
```

#### What the issuer receives

On a cache miss the gateway POSTs a form to `token_exchange_url`,
authenticated with `client_secret_basic` (`client_id` and the secret behind
`client_secret_id`):

| Field | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | A caller assertion naming the caller (below). |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `scope` | `requested_scopes`, space-separated, when configured. |
| `audience`, `resource` | As configured, when configured. |

`subject_token_source` has one value, `caller_assertion`: the subject token is
a JWT the gateway signs with the Connection's `caller_assertion` key, built
exactly as a [signed caller assertion](#signed-caller-assertions) is -- `iss`,
`aud` and `typ` from the block, `sub` as the provider issuer, `#` and the
provider subject, `caller_iss` and `caller_sub` beside it, and the configured
`email` and `roles` claims -- with a fresh `jti` and no request binding,
because the token it buys serves many requests. The issuer verifies it against
`/.well-known/caller-assertion-jwks.json`, pins `iss`, `aud` and `typ`, and
looks up the stored grant for `caller_iss` and `caller_sub`. Set the block's
`audience` to the value the issuer expects, never to an upstream's.

The caller's own inbound bearer token is never forwarded to the issuer.
Exchanging it would mean the gateway retaining a credential the caller gave to
the gateway alone; that is a separate decision with its own security review.

On a delegated Connection the assertion goes to the issuer only. It is not sent
upstream, and its `header_name` is only cleared from anything a caller sends.
The block is otherwise required and checked as usual: a write without one is
refused with `caller_assertion` and `required`, and one with
`bind_request: true` with `caller_assertion.bind_request` and
`unsupported_binding`. The Connection must be `http_api`.

The issuer must answer `200` with JSON carrying `access_token`,
`issued_token_type` `urn:ietf:params:oauth:token-type:access_token`,
`token_type` `Bearer` and a positive `expires_in` of at most seven days.
RFC 8693 only recommends `expires_in`; the gateway requires it, because a
token with no stated lifetime could only be cached on a guess. Other fields,
a `refresh_token` included, are skipped unread and never kept.

#### Endpoint, secrets and egress

- `token_exchange_url` must be `https://`, without userinfo, query or
  fragment; anything else is refused on write with
  `authentication.token_exchange_url` and `invalid_token_url` (or
  `invalid_authority`).
- Its host must be in the egress allowlist. Every exchange checks it before
  the signing key or the client secret is read, and a refused host fails the
  call with `delegated_token_egress_denied`. Redirects are not followed.
- `client_secret_id` is resolved with the `token_exchange_client_secret`
  purpose. As with a signing key, the encrypted local store cannot hold one:
  provision it through an operator alias or an external secret provider. A
  disabled draft may leave it unset.
- The purpose sets the secret's size and encoding rules only. Operator and
  external-provider aliases are not tied to a purpose: one alias resolves
  under any. So the gateway keeps this secret apart itself. A save is refused
  with `422`, the candidate's field and `secret_purpose_conflict` when it would
  bind a token-exchange client secret's alias under any other field -- an
  OAuth client secret, a static bearer or API key, an additional header, TLS
  material or a caller-assertion key -- on the same Connection or any other,
  enabled or not; and when it would bind such a field to an alias any
  Connection exchanges with. Two delegated Connections may share one client
  secret. The check runs inside the store's write transaction, under the lock
  every mutation takes, so in cluster mode two replicas cannot each pass it.
  Still give the token-exchange client secret an alias of its own: a provider
  object behind two aliases is two aliases to the gateway.

#### Which calls are served

Only manual HTTP tool calls, whether from `/mcp` or the admin playground: they
are the one lane that has a validated principal to exchange a token for. Every
other lane -- managed OpenAPI and composite tools, proxied requests, managed MCP,
discovery, enum and label sources and stored Connection tests -- is refused with
`caller_assertion_not_enforced`, as on any Connection carrying a
`caller_assertion` block. There is no service-principal fallback: a call
with no principal, or a service token's, is refused with
`delegated_token_no_principal` before anything is read or sent.

#### The cache

- Tokens are cached in memory per Connection revision, per caller (a digest of
  the caller's issuer, subject, email and roles) and per egress policy. Two
  callers never share a token, and a caller whose attested claims changed is
  exchanged for again.
- A token is refreshed shortly before the issuer's `expires_in` -- a fifth of
  its lifetime, at most thirty seconds early, plus up to five seconds of jitter
  -- and is never reused for longer than 900 seconds whatever `expires_in`
  says, which bounds how long a grant the issuer revokes keeps working here.
- Concurrent calls of one caller share one exchange, and an exchange a
  cancelled call started still completes for the others.
- At most 1,024 callers' tokens are held across every delegated Connection. A
  full cache evicts an idle entry, which costs that caller one more exchange,
  and refuses a call with `delegated_token_unavailable` only while every entry
  is held by a call in flight.
- A save of the Connection or an egress policy change moves the cache key: the
  first call afterwards exchanges again and drops every idle token held for
  the Connection's earlier configuration.
- Rotating the client secret does not. The gateway cannot see a rotation
  behind an operator alias or an external provider, so tokens already cached
  keep being served until they are refreshed, for at most 900 seconds; the
  next exchange simply uses the new secret. Rotating the secret does not
  revoke the tokens the issuer already handed out, either. After an incident,
  revoke at the issuer and save the Connection to drop its cached tokens.
- An upstream `401` drops the token that request used, so the caller's next
  call exchanges again. The rejected call is not replayed.
- Nothing is persisted. A restart starts with an empty cache.

#### Failure reasons

Each refusal is a fixed string in the `failure_reason` of
`tool.invoke_failure` and the `reason` of `tool.upstream_request`, and no
upstream request is made:

| Reason | Meaning |
| --- | --- |
| `delegated_token_no_principal` | The call names nobody: anonymous, or a service token. |
| `delegated_token_egress_denied` | The egress policy refuses `token_exchange_url`. |
| `delegated_token_denied` | The issuer refused this caller: `invalid_grant` or `access_denied` on a `4xx`, or any `403`. Usually the user has not connected the upstream at the issuer, or the grant was revoked; reconnecting there fixes it. |
| `delegated_token_exchange_failed` | No usable token came back for a reason no caller can fix: the issuer was unreachable or failed, rejected the gateway's client authentication (`invalid_client`) or request, or answered with something other than a bounded bearer access token. |
| `delegated_token_unavailable` | Every cache entry is held by a call in flight. |
| `credential_invalid`, `credential_unavailable` | The client secret or the signing key could not be resolved or loaded. Also raises `connection.secret_resolution_failed`. |

A failed exchange is not cached: the caller's next call asks the issuer again.

#### Audit and metrics

Every exchange emits `connection.delegated_token_exchange` with the caller as
its `actor`:

```json
{
  "connection_id": "mail",
  "auth_type": "delegated_issuer_token",
  "outcome": "failure",
  "reason": "delegated_token_denied",
  "subject_token": { "kid": "gw-2026-10", "jti": "3a1f0c9e-..." },
  "issuer_status": 400,
  "issuer_error": "invalid_grant",
  "latency_ms": 41
}
```

`issuer_error` is recorded only when it is one of the error codes RFC 6749 and
RFC 8693 register, and as `unregistered` otherwise, so an issuer's own text
never reaches the audit trail. Search the issuer's log for the
`subject_token.jti` to find its side of an exchange. A tool call served from
the cache emits no exchange event; its `tool.upstream_request` carries the
caller as `actor` as usual. `connection_delegated_token_exchange_total`, labelled
by `result` and `reason`, counts exchanges.

No token -- the subject token, the issued access token, a refresh token, the
client secret or anything the issuer said in an error body -- reaches a caller
error, a log line, a metric or an audit event.

#### Trust boundary

Phase 8 moves per-user systems behind the gateway; this credential is where
the trust sits:

- **The issuer's grant store is the most sensitive component in the
  deployment.** Whoever holds this Connection's client secret can ask the
  issuer for any user's upstream token, so one leaked secret unlocks every
  stored grant. Keep the secret in an external provider, restrict the issuer
  to this client's subject tokens and audience, have it store grants
  encrypted, grant read-only scopes wherever the upstream allows it, and
  have it log every hand-out.
- **The issuer must verify the subject token.** It is the only proof of who
  the caller is. Pin the gateway's `iss`, the `aud` and `typ` the block
  configures, and the JWKS URL; never accept an unsigned subject or one the
  gateway did not sign. Every Connection's assertions verify against the same
  JWKS, so give the delegated Connection's block an `aud` (or `typ`) that
  no other attested Connection uses: otherwise an assertion sent to that
  Connection's upstream is also a subject token the issuer accepts, and only
  the client secret stands between that upstream and the caller's grant.
- **The gateway keeps tokens only in the bounded cache above**, never on disk,
  and for at most 900 seconds.
- **Revocation on user disable is not automatic yet.** A disabled user cannot
  call the gateway once their sign-in no longer validates, and a token the
  issuer revokes stops being used here within the cache lifetime. Purging a
  user's cached tokens the moment they are disabled, and audited revocation
  at the issuer, are follow-ups. Until then, revoke the grant at the issuer and,
  for an immediate stop, save the Connection, which drops every cached token
  for it. In cluster mode each replica holds its own cache and stops using the
  old tokens only once it has applied the save, at its next reconcile; until
  then it keeps serving them.
- Policy is unchanged: tool policy and `rules[]` apply per principal before any
  exchange, so read-only deny rules and per-tool roles limit what a caller can
  do with their own token.

#### In the admin UI

The Connection detail page shows this credential read only -- every field but
the client secret's alias, which appears only as configured or not -- and the
caller assertion as its subject token. The editor does not open such a
Connection, because saving through a form that cannot represent the credential
would replace it; create and change it through the admin API.

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

## OpenAPI Overlays

An OpenAPI overlay is one versioned document stored beside a managed
Connection's generated catalog. It can narrow and clarify generated tools, but
cannot add an upstream method, path, credential, or non-catalog write. The
compiled definitions are stored in the catalog, so restart and replica replay
use the same reviewed result. Editing an overlay does not change the Connection
ETag; the overlay has its own quoted strong ETag
`"overlay:{connection_id}:c{connection_revision}:r{catalog_revision}:o{overlay_revision}"`.
Overlay revision `0` means no overlay is stored. The catalog component is
monotonic across overlay mutations, while the Connection component also moves
when a kind replacement removes and later recreates the OpenAPI catalog. Thus a
pre-delete or pre-replacement ETag cannot become valid again. A full Connection
DELETE followed by a new POST creates a replacement Connection resource and is
governed by the Connection resource's own precondition contract.

This release accepts tool rename, tool titles, tool and parameter descriptions, explicit MCP tool annotations, parameter titles, visibility, document- and source-label disambiguation, body serialization, and declarative request/response transforms, plus bounded composite tools with compensation, dynamic enum bindings, and compile-time label sources.

Use `title` for the MCP tool's top-level display title and `annotations` for explicit MCP client hints: `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`. GreenGateway passes annotations published by an upstream MCP server through unchanged and exposes overlay-declared annotations on generated and composite tools. It never infers `readOnlyHint` from an HTTP method: a generated GET without an explicit overlay annotation remains unannotated. A composite cannot declare `readOnlyHint: true` when any step or compensation is non-GET. These values are advisory client metadata only; RBAC, direct rules, enabled state, and Connection policy remain authoritative.

Overlay keys always use the generated name shown by OpenAPI preview, even when
the tool is renamed for agents. Operation IDs are case-sensitive. In
particular, Twenty generates `UpdateOneCompany`, not `updateOneCompany`; using
the latter returns an unknown-generated-tool problem with the correct name.
Only generated tools named under `tools.*` are overlaid. Every other tool keeps
its original definition and `whole_args_json` body byte-for-byte.

Use this workflow:

1. Preview the OpenAPI document with the candidate `overlay` field. Review the
   compiled tool names, descriptions, schemas, body modes, warnings, label
   reports, and resolved enum values. Preview resolves sources but does not
   persist the overlay or install a refresh schedule.
2. `GET /v1/admin/connections/{id}/overlay` and retain its overlay ETag. A
   Connection with no overlay reports revision `0` and an `o0` ETag.
3. `PUT /v1/admin/connections/{id}/overlay` with that exact ETag in `If-Match`.
   Missing and stale preconditions return `428` and `412`. Validation or
   compilation failure returns `422` with every bounded `problems` entry and
   writes neither the overlay nor a partial catalog.
4. Review the returned overlay and catalog revisions, per-tool label reports,
   warnings, and source status. Registration and later Refresh operations use
   the stored overlay and rederive renamed tools from their generated names.
5. To remove the overlay, send `DELETE` with its exact ETag. The gateway
   republishes the bare generated catalog and deletes the overlay atomically.

The gateway persists a bounded canonical snapshot of initial and label-source
reports with the overlay. Overlay GET preserves those compile-time label facts
and projects each enum entry from the exact in-memory state this replica serves,
so `sources` agrees with tools/list, tools/call, and inventory after a timer
refresh. The read performs no source fetch and no durable write. Dynamic value
rows are bound to the Connection and credential revisions, the overlay revision,
and a digest of the complete source declaration. Reusing a source ID, changing
tenants, or changing a credential therefore cannot resurrect values from the
source's previous meaning.

Reading requires `admin:connections:read`; PUT and DELETE require
`admin:connections:write`. A source declaration that supplies a raw
`request.path` always also requires `admin:connections:secrets:write`, because
the Connection may gain HTTP, additional-header, or mTLS authority before a
later resolve and the GET is not constrained by the OpenAPI document. A source that names
`request.tool` is constrained to a generated GET operation instead. Refresh
continues to require `admin:connections:refresh`; its stored source plan was
already authorized when the overlay was written.

### Dynamic enum and label sources

`enum_sources` select string or boolean values from a bounded GET response.
`tools.<generated>.parameters.<name>.enum_source` binds that set to a generated
property, while `composites.<name>.parameters.<name>.enum_source` binds it to a
composite input property. The resolved set replaces any static OpenAPI `enum`;
it is never combined with or backfilled from the document. Values are compared
by exact JSON equality, with no trimming, case folding, numeric conversion, or
other coercion. Duplicate values are removed in upstream order. Numeric dynamic
values are rejected.

Source resolution is synchronous for preview, overlay PUT, registration, and
Connection Refresh. By default, a source that has never resolved makes the
write fail with `422`. `allow_unresolved_enum_sources=true` permits only enum
sources to begin missing; label sources are compile input and must resolve.
While an enum is missing, `tools/list` advertises the property without an enum
and marks its description unavailable, and every call using the tool fails
closed with `enum_source_unavailable` before egress.

After publication, a timer refreshes expired enum sources. `tools/list`,
`tools/call`, inventory reads, and overlay GET perform no upstream fetch and do
not enqueue refresh work. Fresh and permitted last-known-good stale values are
injected into an owned validation/list clone; the stored `ToolDefinition` and
its digest never change. Each fetch is GET-only, remains below the Connection's
base path, is path-normalized, refuses redirects, checks a contextless HTTP
deny and a referenced tool's enabled flag before credentials are read, and uses
the Connection's ordinary egress, TLS, credential, and response bounds.

The refresh tick is 15 seconds, so replicas adopt a newer durable value revision
within one tick. `ttl_secs` has a 60-second floor, `max_stale_secs` bounds how
long a failed refresh may keep serving the last good set, and an expired set
becomes missing rather than accepting unchecked input. Enum validation errors
name the JSON pointer and return the exact `allowed` values in MCP and
playground error details.

`label_sources` are resolved only during compile flows. Their bounded printable
labels are compiled into property descriptions through fixed templates and are
therefore covered by the stored definition digest. Treat label text as
untrusted upstream data, not as instructions.

`body_args_json` is the default body mode for a tool named in the overlay. It
omits path placeholders and query arguments from the JSON body after using them
to render the request. Set `whole_args_json` explicitly only when the upstream
expects the legacy flattened object. Tools not named in the overlay always keep
the legacy mode.

Request shapes replace one object-valued JSON body property with one or more
agent-facing properties. They cannot reshape path or query arguments, and this
schema revision does not flatten or reshape array request bodies. Put reusable
shapes under `shapes.*` and reference them with `$use`; a reference prefixes
its agent properties with the configured `prefix`, or with the wire property
name by default. Inline shapes keep their declared agent property names. A
shape's explicit `required` list makes exactly those agent properties required,
even for an optional wire property. When it is omitted, all agent properties
inherit a required wire property's requirement and none are required for an
optional wire property.

For example, this reusable shape exposes a plain decimal and currency code
while retaining the upstream's integer-micros object. The same shape can be
used on write parameters and as a decode-only field on reads:

```json
{
  "schema_version": "0.1.0",
  "shapes": {
    "money": {
      "agent": {
        "amount": { "type": "number" },
        "currency": { "type": "string" }
      },
      "required": ["amount", "currency"],
      "wire": {
        "/amountMicros": {
          "from": "amount",
          "codec": {
            "kind": "decimal_scale",
            "scale": 6,
            "wire_encoding": "integer_string"
          }
        },
        "/currencyCode": { "from": "currency" }
      }
    }
  },
  "tools": {
    "UpdateOneCompany": {
      "parameters": {
        "annualRecurringRevenue": {
          "shape": { "$use": "money", "prefix": "annual_revenue" }
        }
      },
      "response": { "root": "/data/updateCompany" }
    },
    "findManyCompanies": {
      "response": {
        "root": "/data/companies/*",
        "fields": {
          "annualRecurringRevenue": {
            "$use": "money",
            "prefix": "annual_revenue"
          }
        }
      }
    }
  }
}
```

The compiler validates every named tool, including generated tools that are
not currently selected. It rejects colliding agent property names, invalid
agent JSON Schema fragments, `format` annotations, missing or overlapping wire
pointers, ambiguous inverse mappings, and codec chains whose output type does
not match the OpenAPI wire schema. The transformed agent schema is what
`tools/list` advertises and what `tools/call` validates. Request wire pointers
may traverse declared object properties only. A pointer that would construct a
nested array is rejected in schema revision 0.1.0 because RFC 6901 text alone
cannot distinguish an array index from an object key such as `"0"`.

Responses are decoded inside the executor before either MCP or the admin
playground projects the result. `response.root` overrides
`defaults.response_root`; `response.fields` supplies decode-only shapes for
read operations. When a JSON 2xx response schema is declared, overlay PUT
rejects a root or field the schema proves impossible. A free-form or absent
response schema is accepted with an explicit unverified warning. A field-level
decode failure keeps that field's wire representation and returns a bounded
warning instead of hiding a successful upstream write. At most 32 warnings are
returned. When the warning set is truncated, the final entry is
`{"path":"/","reason":"warnings_truncated"}`.

Document-label disambiguation compares properties within one tool. It uses the
first non-empty document `title` or first line of `description`, and qualifies
only duplicate labels through the fixed template. A parameter description set
explicitly by the overlay always wins. Static enum options may be shown in the
qualified description, capped at 16 values. Unique and unlabelled properties
are unchanged. Twenty normally exposes neither usable titles nor descriptions,
so a document-only overlay can legitimately report **0 labels matched the
configured document label sources**; this wording also covers documents whose
available labels are excluded by `label_from`. Add explicit parameter
descriptions until configured label sources are available.

### Composite tools

A composite is one agent-facing tool whose sequential steps name generated
tools from the same managed OpenAPI catalog. It cannot introduce a method or
path. Each real forward or compensation request still uses the Connection's
credential and additional headers, passes the Connection egress policy, and is
checked against HTTP deny rules on its rendered path.

Composite input properties can use
`composites.<name>.parameters.<property>.enum_source` to share the same dynamic
enum sources and exact-value validation as generated-tool properties.

Use `visibility: composite_only` for sharp step or rollback tools that agents
must not discover or call directly. They remain visible in the admin inventory
and usable by the admin playground. The composite itself needs its own tool
policy entry. Under default-deny it is invisible until that entry exists; under
default-allow it uses the runtime default timeout. Overlay PUT and preview
report `policy_entry_present` and `steps_max` for every composite. Size the
policy timeout with this lower bound:

`timeout_ms >= steps_max * connection request timeout + compensation_timeout_ms`

The executor reserves `compensation_timeout_ms` inside that one admitted policy
timeout. Fan-out is sequential and bounded by `maxItems` plus
`limits.max_iterations`. Successful steps are compensated in reverse completion
order after a definite failure. Ambiguous writes, including the default
500/502/503/504 outcomes, are never compensated automatically and are reported
as possible orphans. Failed or budget-exhausted compensation is returned as an
error with confirmed or possible orphans rather than being hidden. Cancellation,
lease loss, or timeout sends no new request after the invocation future is
dropped; the audit tree records any pending compensation.

### JSON pointer bases

The meaning of `/` is determined by the field containing the pointer.

| Field | `/` is the root of |
| --- | --- |
| `shape.wire."<pointer>"` | The wire value of the one parameter being shaped (`/amountMicros` inside `annualRecurringRevenue`). |
| `shape.response.<agent>.from` | The wire value of that parameter inside each selected response-root object. |
| `response.root`, `defaults.response_root` | The parsed JSON body of the upstream response. |
| `enum_sources.*.select.items`, `label_sources.*.select.items` | The parsed JSON body of the source GET. |
| `select.value`, `select.label`, `select.key` | One selected item. |
| `$input.pointer` | The value of the named composite input. |
| `$step.pointer` | The whole parsed JSON body of the named earlier step. Twenty pointers therefore begin with `/data/`, such as `/data/createNote/id`. |
| `$item.pointer` | The current `for_each` element. |
| `$self` | The whole parsed JSON body of the step being compensated. |

### Codec behavior

Codec chains encode left to right and decode right to left; they reject inexact
values rather than rounding, trimming, or normalizing them.

| Codec | Encode (agent to wire) | Decode (wire to agent) | Type | Invertible |
| --- | --- | --- | --- | --- |
| `decimal_scale` | Shift the JSON number's exact decimal text by `scale`; reject excess fraction digits, a non-integer result, or an oversized result. | Accept only a canonical integer or integer string matching `^-?(0\|[1-9][0-9]*)$`; reject forms such as `"007"`, `"+5"`, `"-0"`, and `"5.0"`. | `number`/`integer` to integer or string | Yes |
| `json_string` | Serialize the JSON value to one compact JSON string. | Parse the wire string as JSON; on failure retain the wire value and report a warning. | Any to `string` | Yes |
| `markdown_blocks` | Convert the supported Markdown subset to a BlockNote block array. | No inverse conversion; a response binding is required. | `string` to `array` | No |

Twenty's `bodyV2.blocknote` property is a JSON **string**, not an array. A
rich-text shape must therefore chain `markdown_blocks` and then `json_string`.
For exact currency values, `decimal_scale` operates on the JSON number token
and never through floating-point multiplication.

## HTTP Tool Error Bodies

An HTTP-rendered tool's non-2xx response becomes an MCP error result with
`{status, body}`. For JSON objects, the body retains only these top-level keys:
`type`, `title`, `code`, `error`, `error_code`, `message`, `messages`,
`statusCode`, `detail`, `details`, and `errors`. `messages` must be an array;
only string entries among its first eight items survive. `statusCode` must be
a JSON number and is upstream-provided metadata; the outer `status` records
the actual HTTP response status. Other top-level keys are removed.

For example, a NestJS-style 400 response can preserve
`{"statusCode":400,"error":"BadRequestException","messages":["filter must use a supported comparison operator"]}`.
Free-form diagnostics naming Authorization, Bearer, or Basic authentication
are withheld as `[redacted]`, including opaque credentials without a recognizable
prefix. This conservative context check runs before truncation. Other strings
are capped at 512 characters before token redaction, with
`...[truncated]` appended when shortened. Existing URL, internal-hostname, and
credential-token redaction applies to every retained string, including
`messages` entries. Other retained values keep the existing limits of eight
array items, 16 fields per nested object, and four nesting levels; sensitive
nested keys have their values redacted. The configured
[`EGRESS_MAX_RESPONSE_BYTES`](../configuration.md#egress_max_response_bytes)
limit still bounds the upstream response body before sanitization.

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
- `tool.transform_warning` (one bounded summary event for a transformed
  response that produced warnings)
- `tool.composite_completed`
- `tool.playground_output_rejected`

Events contain stable IDs, safe reason/outcome categories, revision or count
data, and bounded latency where applicable. They must not contain resolved
values, secret locators, token responses, certificate contents, arguments,
results, upstream bodies, DNS answers, or raw transport errors.

Executor work failures retain `reason: "work_error"` for existing consumers and
add `failure_reason`, for example `invalid_params`, `host_not_allowed`,
`catalog_stale`, or `internal_configuration_error`. A warning log records the
tool name and this category, without the display error or arguments.

Input-schema failures also include at most 16 `problems` entries with `path`,
`keyword`, and `message`. Paths and keywords are capped at 64 characters;
messages are capped at 128. Paths preserve schema-defined property names and
array indices. Caller-selected map keys and ambiguous schema traversal become
`*`, and messages use fixed descriptions. Enum choices and unexpected property
names remain in the caller's existing error response, but are omitted from
audit evidence because they can contain caller or upstream data.

Query a specific failure through the authenticated admin audit API:

```text
GET /v1/admin/audit?event_type=tool.invoke_failure&reason=invalid_params
```

The `reason` filter matches either top-level `reason` or `failure_reason` exactly
and composes with the existing filters and `before_id` cursor. Thus
`reason=work_error` still selects the umbrella category, including older rows;
older rows without a detailed failure reason cannot be reconstructed. The
filter accepts 1–64 lowercase ASCII letters, digits, or underscores. Use the
configured admin prefix when it differs from `/v1/admin`.

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

A disabled Connection withdraws its managed OpenAPI or MCP catalog tools from
the advertised tool list and reports `disabled/disabled` rather than a catalog
freshness state, so it never raises the `degraded/catalog_stale` alert above.
The retained catalog is republished at the next refresh or gateway restart once
the Connection is re-enabled.

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

Issue #240 shipped operator environment/file aliases and the encrypted local
provider first. All five external providers have since landed, each with its own
workload-identity, egress, TLS, rotation, bounds, and redaction review:

- [HashiCorp Vault KV v2](../configuration.md#connection_vault_provider) — `CONNECTION_VAULT_PROVIDER` ([#271](https://github.com/Greenhat-Security/GreenGateway/issues/271), [operator guide](../secrets/vault-kv-v2.md))
- [AWS Secrets Manager](../configuration.md#connection_aws_provider) — `CONNECTION_AWS_PROVIDER` ([#272](https://github.com/Greenhat-Security/GreenGateway/issues/272))
- [Azure Key Vault](../configuration.md#connection_azure_provider) — `CONNECTION_AZURE_PROVIDER` ([#273](https://github.com/Greenhat-Security/GreenGateway/issues/273))
- [Google Cloud Secret Manager](../configuration.md#connection_gcp_provider) — `CONNECTION_GCP_PROVIDER` ([#274](https://github.com/Greenhat-Security/GreenGateway/issues/274))
- [Kubernetes Secrets API](../configuration.md#connection_kubernetes_provider) — `CONNECTION_KUBERNETES_PROVIDER` ([#275](https://github.com/Greenhat-Security/GreenGateway/issues/275))

Every provider is read-only and operator-configured: aliases bind one fixed
resource each, and neither callers nor ordinary Connection mutations can choose a
provider locator. Do not place cloud-provider locators in Connection fields
directly — reference an alias ID instead, which is all the admin API accepts or
returns.

### Admitting a private API server

Each provider is reached through the ordinary egress client, so its endpoint must be admitted as a host -- in `EGRESS_ALLOWED_HOSTS` or in policy `egress.hosts`, which are additive -- *and* survive the private-address guard. That second half is easy to miss, and it bites the Kubernetes Secrets API hardest: in-cluster the API server is a private or otherwise non-global address in nearly every deployment (`kubernetes.default.svc`, a ClusterIP, a node-local endpoint), so the default `EGRESS_DENY_PRIVATE_IPS=true` still refuses the connection after the host is allowlisted, and the refusal looks like a provider fault rather than a policy one.

Admit that one range through an explicit policy-file egress CIDR rather than setting `EGRESS_DENY_PRIVATE_IPS=false`. The environment variable is a process-wide switch on the egress client every subsystem shares, so turning it off to reach one API server also opens proxy routes, managed tools, and OAuth token exchanges onto private address space — the reason that guard exists. A policy CIDR grants exactly the range the API server occupies and leaves the guard standing everywhere else. Where the egress policy also restricts ports, admit the API server's port — commonly `6443`, not `443`. Both are startup-time settings: policy hosts, CIDRs, and ports cannot be hot-reloaded, so plan the change with a restart. [`CONNECTION_KUBERNETES_PROVIDER`](../configuration.md#connection_kubernetes_provider) carries the full admission rule and the per-profile TLS trust options that go with it.
