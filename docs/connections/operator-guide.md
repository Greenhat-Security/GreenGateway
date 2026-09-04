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

Connections support `none`, a header API key, a static bearer token, and OAuth
2.0 client credentials. Every enabled secret-backed primary or additional
binding requires a compatible configured alias. Authentication and TLS material
require HTTPS.

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

This release accepts tool rename, tool and parameter descriptions, parameter
titles, visibility, document- and source-label disambiguation, body
serialization, and declarative request/response transforms, plus bounded
composite tools with compensation, dynamic enum bindings, and
compile-time label sources.

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
