# ADR-0006: First-Class Connections And Credential Authority

## Status

Accepted

## Context

Issue #240 introduces a shared upstream `Connection` for proxy routes, manual
HTTP tools, OpenAPI-managed tools, and streamable-HTTP MCP servers. Today those
surfaces use separate legacy configuration, HTTP tools share one global
upstream, and MCP provenance is encoded through an internal sentinel mapping.
Literal route headers are the only compatibility mechanism for some upstream
credentials.

A connection combines a destination with references to credentials and TLS
material. That makes destination mutation, discovery, testing, catalog refresh,
and tool invocation security-sensitive: if authorization, egress, or authority
binding is performed in the wrong order, a normal editor can redirect a stored
credential or turn the gateway into an SSRF scanner.

This decision is based on main commit
`17a50bf658247c813f63cfb14b06fc97cdd21d38`, after issue #239 landed its
production data-plane transport, DNS-generation, bounded resilience, lifecycle,
streaming, and mTLS isolation primitives. Connections must consume those
primitives; they do not create another client or pool stack.

Checklist item 1 adds the vocabulary, schemas, validation boundaries, typed
tool metadata, and redacted secret wrappers. It does not add a database,
secret provider, credential injection, OAuth, admin route, discovery request,
test request, inventory, UI, or runtime connection selection. Existing legacy
execution remains authoritative until the later checklist item that migrates
each lane with parity tests.

## Decision

### Terminology and ownership

A `Connection` is a stable logical destination and credential profile. It is
never an authorization grant. It contains:

- an immutable stable ID, bounded display metadata, enabled state, kind, and
  management source;
- one normalized HTTP(S) origin and explicit origin-relative base path;
- an authentication binding and an independent TLS profile;
- bounded timeout and stored test profiles;
- optional typed OpenAPI or MCP discovery configuration; and
- monotonic connection, credential, TLS, discovery, and status revisions.

It never contains resolved secret material. The initial kinds are `http_api`
and `mcp_streamable_http`.

The implementation is divided into focused responsibilities:

| Responsibility | Interface |
|---|---|
| Transactional metadata, dependency, catalog, binding, and revision state | `ConnectionStore` |
| Complete-candidate validation and atomic immutable runtime publication | `ConnectionManager` |
| Opaque ID to bounded redacted material resolution | `SecretResolver` |
| Static header, bearer, and OAuth behavior | `CredentialProvider` |
| CA trust and optional client identity independent of HTTP authentication | `TlsProfile` |
| Bounded all-or-nothing OpenAPI/MCP refresh | `ConnectionCatalogService` |
| Safe reason/state/time/count history | `ConnectionStatusStore` |
| Manual, legacy, OpenAPI, and MCP capability merge | `CapabilityInventory` |

The control plane will use one versioned SQLite store when explicitly
configured. An unset store preserves legacy runtime behavior and makes managed
mutation read-only/unavailable; it never creates an implicit database. Runtime
publication will use an immutable snapshot and atomic swap. A failed parse,
validation, resolution, TLS build, transaction, or catalog compile leaves both
the stored and active prior revision unchanged.

### Authorization and side-effect order

Authentication, global rate limiting, RBAC/direct route policy, tool policy,
and admin permission checks remain authoritative. A Connection does not make
its endpoint reachable and never edits the egress allowlist.

The required invocation order is:

```text
authenticate
  -> global rate limit
  -> classify the stable logical route/tool
  -> RBAC/direct/tool authorization
  -> connection snapshot lookup
  -> credential/TLS resolution
  -> final authority and egress validation
  -> #239 client acquisition and DNS pinning
  -> credential injection
  -> upstream bytes
```

A denial produces zero connection-specific store/provider reads, OAuth calls,
DNS lookups, client acquisition, or upstream bytes. Tool arguments, bodies,
headers, OpenAPI `servers`, discovered MCP metadata, and client input can never
choose or replace the configured connection ID.

Tests, OpenAPI retrieval, MCP initialize/list/call/SSE/session deletion, OAuth
token requests, and refreshes follow the same egress and transport boundary.
Redirects remain disabled. Every DNS answer is validated and the accepted
address generation is pinned as specified by ADR-0005.

### IDs, URLs, and path authority

Connection and secret IDs are 1–128 ASCII bytes, begin with an ASCII letter or
digit, and contain only letters, digits, `.`, `_`, or `-`. Managed connection
IDs are immutable generated UUIDs. Bounded slugs may be used for presentation
and namespacing. Projected legacy IDs reserve `legacy-default-http`,
`legacy-route-*`, and `legacy-mcp-*`; managed IDs cannot collide with them.

An endpoint `base_url` is at most 2,048 bytes and is an `http` or `https`
origin only. Parsing rejects missing hosts, userinfo, paths, queries, and
fragments. Host casing and default ports normalize through the URL parser. A
credentialed or mTLS connection requires HTTPS.

Base, test, and discovery paths are 1–1,024 byte origin-relative paths. They
start with one `/` and reject scheme-relative forms, repeated leading
authorities, backslashes, queries, fragments, literal or percent-encoded dot
segments, encoded separators, NULs, and invalid UTF-8 percent encoding.
Absolute URLs and authority-changing mappings are forbidden.

OAuth token URLs are explicit HTTPS URLs of at most 2,048 bytes, with no
userinfo, query, or fragment. There is no metadata discovery or redirect
following. Token endpoint egress, DNS, TLS, pinning, bounds, and client identity
are evaluated independently.

### Wire model and typed tool metadata

The version 0.1 connection write shape is
[`connection.v0.schema.json`](../schemas/connection.v0.schema.json). Every
object rejects unknown fields. The schema accepts opaque secret IDs only; it
cannot express environment names, file paths, inline credential values,
ciphertext, nonces, provider locators, access tokens, or private keys.

`ToolTarget` and `ToolSource` make destination and provenance explicit:

```rust
enum ToolTarget {
    Http {
        connection_id: String,
        mapping: HttpToolMapping,
    },
    Mcp {
        connection_id: String,
        remote_tool_name: String,
    },
}

enum ToolSource {
    Manual,
    OpenApi {
        connection_id: String,
        operation_id: Option<String>,
    },
    Mcp {
        connection_id: String,
        remote_tool_name: String,
    },
    Legacy,
}
```

The version 0 tools schema permits optional `target` and `source` fields. During
migration the legacy `upstream` field remains required and executable.
If typed metadata is present, its HTTP mapping or MCP names must equal that
legacy mapping, preventing two conflicting authorities. Existing files
deserialize with `source=legacy`, serialize without the new optional fields,
and execute exactly as before. Credentials and unrestricted URLs are forbidden
from tool arguments and path templates.

### Credential and TLS model

HTTP authentication is one of:

- `none`;
- `header_api_key` with one opaque secret ID and a validated header name;
- `static_bearer` with one opaque token secret ID; or
- `oauth2_client_credentials` with explicit client ID, opaque client-secret ID,
  explicit HTTPS token URL, optional bounded scopes and audience/resource, and
  `client_secret_basic`.

TLS is separate so custom trust and mTLS can accompany any HTTP authentication
mode. Client certificate and private-key IDs are configured together. No
`skip_verify` option exists.

Disabled drafts may omit an opaque HTTP secret binding or retain only one side
of a pending mTLS identity selection. Every supplied field is still validated.
Before `enabled` can become true, the selected authentication mode must have
its required secret ID and a client certificate/private-key selection must be
complete and resolvable. This conditional completeness is part of the v0.1
write schema, not an API-specific exception.

Header API-key names reject `Authorization`, `Cookie`, `Host`,
`Content-Length`, proxy authentication, forwarding headers, hop-by-hop and
connection-nominated headers, framing headers, the gateway request ID,
security/protocol-managed `Sec-*` headers, and invalid HTTP names. Later
injection strips inbound `Authorization`, `Cookie`, and the selected API-key
header; applies safe legacy header transforms; validates the final authority
and egress destination; and injects the connection credential last. Failure to
resolve or construct a credential fails closed with no anonymous retry.

### Secret trust and confidentiality

The trust chain is:

```text
Connection -> CredentialBinding -> SecretId -> SecretResolver -> ResolvedSecret
```

Ordinary connection APIs accept opaque IDs only. Environment variables and
mounted-file locators are trusted startup configuration behind operator
aliases, never admin-controlled input. An optional local provider may accept a
secret value exactly once at its dedicated write/rotate endpoint and has no
reveal operation.

Operator aliases are bounded startup JSON. Environment locators use validated
ASCII variable names. File locators are one validated filename segment below a
canonical configured root; traversal, absolute/drive/alternate-stream forms,
symbolic links, Windows reparse points, non-regular files, and unsafe
platform-supported permissions fail closed. A capability-backed handle anchors
the validated root across later path or ancestor replacement. The leaf is
opened relative to that handle without following links and in nonblocking mode,
validated from the opened handle, and read through a purpose-specific byte cap.
Values are resolved on every authorized use rather than cached, so atomic
mounted-file replacement affects the next resolution without changing an
already in-flight redacted value.

Internal resolved secret wrappers do not implement `Serialize` or `Clone`.
Their manual `Debug` output is exactly `<redacted>`, their bytes are bounded by
purpose, borrowed rather than copied for use, and zeroized on replacement and
drop. Values are not trimmed or transformed. Public/admin DTOs are distinct
from internal material and omit resolved values, ciphertext, nonces, hashes,
fingerprints, locators, master-key IDs, access tokens, private keys, and
low-entropy suffixes.

The encrypted local provider will use XChaCha20-Poly1305 with a fresh random
24-byte nonce for every encrypted field and a 32-byte primary master key loaded
from a mounted file outside the database. Canonical authenticated additional
data includes schema version, secret UUID, secret version,
connection/credential purpose, and field purpose. A keyring has one primary
encrypt key and explicit decrypt-only predecessors. Unknown algorithms,
missing/wrong keys, AAD mismatch, ciphertext/tag modification, or interrupted
rotation fail closed. Database, WAL, and backups contain ciphertext only.

### Fixed conservative limits

These limits are schema/versioned defaults. A later configurable value may only
be equal or more restrictive unless a new schema and resource review changes
the ceiling.

| Resource | Limit/default |
|---|---:|
| Managed and projected connections | 256 |
| Credential records | 512 |
| Operator secret aliases | 512 entries / 256 KiB startup JSON |
| Concurrent operator alias reads | 16 |
| Environment locator / file key | 128 / 255 bytes |
| Retained connection dependency rows | 4,096 |
| Managed OpenAPI document | 2 MiB |
| Published catalog entries | 4,096 |
| Current plus retained safe status/history rows | 4,096 |
| Concurrent refreshes | 4 |
| Connection/secret ID | 128 bytes |
| Display name | 128 characters |
| Description | 1,024 characters |
| URL | 2,048 bytes |
| Base/test/discovery path | 1,024 bytes |
| Header name | 64 bytes |
| OAuth client ID | 256 bytes |
| OAuth scopes | 16 entries, 128 characters each |
| OAuth audience/resource | 512 bytes each |
| Stored expected statuses | 16 |
| Connect/request/response-idle timeout | 1–120,000 ms |
| Timeout defaults | 10,000 / 30,000 / 30,000 ms |
| API key, bearer, or OAuth client secret | 8 KiB |
| TLS private key | 256 KiB |
| Certificate or CA bundle | 1 MiB |

Collection and byte limits are checked before expensive parsing, compilation,
resolution, or network work. OAuth response/cache, test concurrency, provider
reads, request/response bodies, status, metrics cardinality, and retained
catalog generations receive separate lower bounds in the PR that implements
them.

Stored test profiles use exact uppercase `GET`, `HEAD`, or `OPTIONS` methods
and 1–16 unique status codes from 100 through 599. Case and duplicates are
rejected rather than silently normalized.

### Permissions and mutation authority

The permission vocabulary is:

| Permission | Authority |
|---|---|
| `admin:connections:read` | Safe connection/status metadata |
| `admin:connections:write` | Non-sensitive presentation and operational metadata |
| `admin:connections:secrets:write` | Bind, rotate, clear, clone, or redirect credential/TLS use |
| `admin:connections:test` | Run the persisted bounded test profile |
| `admin:connections:refresh` | Refresh persisted OpenAPI/MCP discovery |
| `admin:tools:read` | Inventory and safe capability detail |
| `admin:tools:write` | Manual/managed tool mutation |
| `admin:tools:execute` | Enter the constrained tool playground |

Changing where an existing credential may be sent is a secret-use mutation.
`admin:connections:secrets:write` is required to change a credentialed origin,
OAuth token URL, scopes/audience/resource, auth mode/header, mTLS identity, or
credentialed discovery target, and to attach, replace, rotate, clear, delete,
or clone a binding. A plain connection writer cannot perform those operations.
Every sensitive change atomically increments the credential revision and emits
a separate credential-change audit event.

All admin routes remain below dynamic `/v1{ADMIN_PREFIX}`. Writes require CSRF
under existing cookie-auth rules and an exact `If-Match`; missing preconditions
return 428 and stale revisions return 412. Validation is 400/422, authorized
missing resources are 404, dependencies/concurrent refreshes are 409, bounded
busy work is 429, and unavailable configured storage/providers are sanitized
503 responses. Authorization precedes ID lookup. There is no force-delete,
secret reveal, URL/header override, arbitrary request, or client-decoded
permission path.

### Status, audit, and errors

Safe status contains bounded state/reason codes, times, latency, catalog age and
count, kind, source, and revisions. Public probes reveal no connection
topology. Read DTOs summarize authentication/provider configuration and never
include revealing secret IDs or internal locators.

Structured events are `connection.changed`,
`connection.credential_changed`, `connection.refreshed`,
`connection.oauth_token_refresh`, and
`connection.secret_resolution_failed`. Allowed fields are bounded stable
connection ID/kind, source, action and changed-field names, auth type,
old/new revisions, safe outcome/reason, latency, and bounded counts. URLs with
userinfo/query/fragment, resolved IPs, DNS answers, raw errors, credentials,
headers, forms, tokens, ciphertext, fingerprints, provider locators, private
keys, certificate contents, tool arguments/results, MCP contents, and upstream
bodies/challenges are forbidden.

### Threat model

| Threat | Prevention and detection | Residual risk |
|---|---|---|
| Stored credential redirected by an ordinary editor | Separate secret-use permission, immutable ID, conditional revision, sensitive-field diff, audit | A fully authorized secrets writer can intentionally rebind; alerts and least privilege are required |
| Denied call causes secret or network side effects | Authorization-before-lookup invariant and zero-call counter tests | Bugs in future adapters require regression tests for every lane |
| Tool/OpenAPI/MCP input replaces authority | Typed configured target, origin-relative mappings, server metadata ignored for authority | Malicious schemas/content remain untrusted and bounded |
| SSRF, rebinding, or redirect credential leak | Existing #239 egress, all-answer validation, exact pinning, cache isolation, redirects off, injection last | Operators can explicitly allow risky destinations |
| Cross-connection credential/client reuse | Cache key includes connection/revisions, authority, destination/egress generation, timeouts/protocol, TLS roots, and mTLS identity | In-flight calls may finish on their immutable old revision |
| Caller header overrides configured credential | Strip inbound sensitive/configured header, reject conflicts, inject last | Approved legacy literal headers remain a migration risk |
| Secret exposure through serialization/debug/storage | Separate DTOs, non-serializable redacted wrapper, encryption, canary scans | Process memory and privileged host inspection remain in the operator trust boundary |
| Local file/environment exfiltration | Opaque admin IDs, trusted alias config, canonical root, traversal/symlink/device/permission checks | Platform permission guarantees vary and must be documented |
| OAuth token misuse or stampede | Narrow flow, separate egress/TLS, bounded single-flight memory cache, revision key, no persistence/replay | Compromised upstream or IdP can still observe its intended credential |
| Test/refresh becomes arbitrary client or scanner | Persisted ID/profile only, no overrides, permissions, quotas, egress, safe result stages | Authorized operators can exercise already configured destinations |
| Partial refresh publishes broken catalog | Build and validate candidate, transactional revision, atomic publish, last-known-good retention | Catalog may be stale and must be visibly marked |
| Resource exhaustion/cardinality attack | Fixed collection/byte/time/concurrency/history bounds and low-cardinality labels | Limits may need tuning through reviewed schema revisions |

## Compatibility and rollout

Legacy `UPSTREAM_URL`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`, tools files,
OpenAPI wrappers, route selection, authorization, and exposed MCP names remain
unchanged until their named migration PR. Projections use
`legacy-default-http`, collision-checked route IDs, and
`legacy-mcp-{normalized-name}`. Manual tools later appear as `local_file`
provenance. Existing `add_request_headers` remains compatible but is deprecated
for secrets; migration copies references only and never emits literal values.

The rollout sequence is the issue #240 checklist: vocabulary and schema; store
and projections; operator aliases; encrypted local provider; admin CRUD;
static authentication; OAuth; MCP; OpenAPI; inventory; test and mTLS; UI;
playground; migration/deployment/docs. Each lane preserves the old runtime
until its candidate passes parity and failure-path tests.

## Consequences

Connections have one authority model before persistence or credential behavior
lands. Later changes have explicit schema, permission, revision, egress,
redaction, and resource contracts to test. Secret handling gains a narrow type
that is difficult to serialize or debug accidentally.

The cost is additional typed metadata, conservative bounds, separate
permissions, revision-aware clients, and staged migration. The first PR
deliberately carries unused model vocabulary while runtime remains legacy; this
is preferable to introducing security-sensitive behavior before the store and
authorization boundaries exist.
