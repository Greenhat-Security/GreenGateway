# ADR-0006: First-Class Connections And Credential Authority

## Status

Accepted and implemented for the issue #240 runtime, control-plane, discovery,
inventory, UI, test, and constrained-playground slices on the current `main`
branch.

## Context

GreenGateway originally configured HTTP proxy routes, manual HTTP tools,
OpenAPI-generated tools, and streamable-HTTP MCP servers through separate
legacy settings. HTTP tools shared a global upstream, MCP provenance used an
internal mapping, and literal route headers were the only compatibility
mechanism for some upstream credentials.

A reusable upstream configuration is useful only if it does not become an
implicit authorization grant or a new SSRF/credential exfiltration path.
Destination mutation, secret binding, TLS identity, OAuth, stored tests,
discovery, inventory, and tool execution all cross security boundaries. The
implementation therefore consumes the production data-plane primitives from
[ADR-0005](0005-production-proxy-data-plane.md); it does not create an alternate
resolver, HTTP client, or redirect path.

## Decision

### Connection model and ownership

A `Connection` is a stable logical destination and credential profile. It is
never an authorization grant and never modifies the egress allowlist. The
initial kinds are `http_api` and `mcp_streamable_http`.

A managed Connection contains:

- an immutable generated ID, bounded presentation fields, enabled state, kind,
  and `managed` source;
- one normalized HTTP(S) origin and a separately validated origin-relative base
  path;
- one HTTP authentication binding and an independent TLS profile;
- bounded timeout and stored test profiles;
- optional typed OpenAPI or MCP discovery configuration; and
- monotonic connection, credential, TLS, discovery, and status revisions.

It contains opaque secret references, never resolved secret material.

| Responsibility | Current implementation |
| --- | --- |
| Transactional metadata, dependency, catalog, binding, and revision state | `ConnectionStore` / `SqliteConnectionStore` |
| Complete-candidate validation and immutable runtime publication | `ConnectionControlPlane` and `ConnectionRuntimeSnapshot` |
| Opaque alias to bounded redacted material | `SecretResolver` |
| Header API key, bearer, and OAuth behavior | `ConnectionHttpRuntime` |
| Custom CA and optional client identity, separate from HTTP auth | `TlsProfile` and the checked egress client |
| All-or-nothing OpenAPI/MCP refresh | `OpenApiConnectionCatalogService` and `McpConnectionCatalogService` |
| Safe status/history | Connection status store |
| Manual, legacy, OpenAPI, and MCP capability merge | `CapabilityInventory` |
| Persisted bounded test execution | `ConnectionTestService` |

When `CONNECTIONS_SQLITE_PATH` is unset, GreenGateway creates no implicit
database. Legacy HTTP routes, the default HTTP upstream, and MCP upstreams are
projected as read-only Connections. Managed create/update/delete, local
encrypted-secret management, tests, and refresh that require the store return a
sanitized unavailable response.

When the store is configured, a mutation validates the complete candidate,
commits it and its dependencies transactionally, then atomically publishes one
immutable runtime snapshot. A failed parse, validation, provider/TLS preflight,
transaction, or catalog compile leaves the stored and active prior revision
unchanged.

### Authorization and side-effect order

Authentication, global/principal rate limiting, RBAC, direct method/path rules,
tool policy, and admin permissions remain authoritative. The common managed
outbound order is:

```text
authenticate and rate-limit
  -> authorize stable route/tool/admin operation
  -> capture immutable Connection/definition/catalog authority
  -> validate scheme/host/port
  -> resolve DNS, validate every answer, exact-pin one accepted address
  -> prepare TLS/provider/client against that checked destination
  -> resolve static credential or obtain OAuth token
  -> remove caller/conflicting credentials and inject configured credential last
  -> send bounded upstream bytes
```

An initial security denial produces zero Connection-specific provider reads,
OAuth calls, DNS lookups, client acquisition, or upstream bytes. In-memory
lookup of a registered opaque capability ID does not inspect provider, DNS, or
upstream state.

The zero-side-effect statement is not a promise to recall already-authorized
work. Ordinary proxy and MCP/tool runtime authorization is snapshot-based: an
invocation already admitted under that snapshot can finish even if policy is
reloaded later. Bytes already sent cannot be revoked. New invocations use the
new state.

The admin playground has a stricter queued-execution boundary. After its bounded
runtime queue, it rechecks the live `admin:tools:execute` permission, execution
ETag, rendered HTTP direct rule, and captured Connection/catalog revision
before egress. Revocation or mutation while queued therefore stops that
playground call before provider, DNS, or upstream side effects.

Stored tests and refreshes require the exact current Connection ETag. Their
target builders compare the expected ETag again before protocol/egress work;
catalog publication also remains conditional on the captured revision.

### IDs, URLs, and authority

Connection and secret IDs contain 1-128 URL-safe ASCII bytes, start with an
ASCII letter or digit, and use only letters, digits, `.`, `_`, or `-`. Managed
Connection IDs are generated UUIDs. Projected legacy IDs reserve
`legacy-default-http`, `legacy-route-*`, and `legacy-mcp-*`; managed IDs cannot
collide with them.

An endpoint `base_url` is at most 2,048 bytes and contains an `http` or `https`
origin only. Missing hosts, userinfo, paths, queries, and fragments are
rejected. A credentialed or mTLS Connection requires HTTPS.

Base, test, and discovery paths are 1-1,024 byte origin-relative paths. They
reject scheme-relative forms, repeated leading authorities, backslashes,
queries, fragments, literal or percent-encoded dot segments, encoded
separators, NULs, and invalid percent-encoded UTF-8. Tool arguments, request
headers/bodies, OpenAPI `servers`, and discovered MCP metadata cannot replace
the configured Connection ID, origin, token URL, credential header, or TLS
profile.

The version 0.1 write schema is
[`connection.v0.schema.json`](../schemas/connection.v0.schema.json). Objects
reject unknown fields. The schema accepts opaque secret IDs only; it cannot
express environment names, file paths, inline secrets, ciphertext, nonces,
access tokens, or private keys.

### Typed tool authority

`ToolTarget` identifies the configured execution destination and `ToolSource`
records provenance:

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
        catalog_revision: Option<u64>,
    },
    Mcp {
        connection_id: String,
        remote_tool_name: String,
    },
    Legacy,
}
```

Legacy tool files remain readable. When typed metadata is present, its HTTP
mapping or MCP names must agree with the compatible legacy mapping, so two
authorities cannot coexist in one definition. Managed OpenAPI/MCP definitions
bind both source and target to the same Connection and catalog revision.

### Credential and TLS model

HTTP authentication is one of:

- `none`;
- `header_api_key` with a validated header name and opaque secret ID;
- `static_bearer` with an opaque token secret ID; or
- `oauth2_client_credentials` with explicit client ID, opaque client-secret ID,
  explicit HTTPS token URL, bounded scopes/audience/resource, and
  `client_secret_basic`.

TLS is independent of HTTP authentication. A custom CA alias and an optional
paired client-certificate/private-key identity can accompany any authentication
mode. There is no skip-verification setting.

Disabled drafts can omit a required HTTP secret binding or hold only one side
of a pending mTLS identity, but every supplied field is still validated. An
enabled Connection must be complete and all referenced material must pass
purpose-specific preflight.

Header API-key names reject `Authorization`, `Cookie`, `Host`,
`Content-Length`, proxy authentication, forwarding, hop-by-hop,
connection-nominated, framing, request-ID, and `Sec-*` headers. Runtime
forwarding strips gateway/caller credentials and the configured API-key header,
applies permitted route transforms, and injects the Connection credential only
after egress/TLS preparation. Resolution or injection failure is fail-closed;
there is no anonymous retry. A credentialed `TRACE` tool call is rejected.

TLS material is resolved only after the ordinary egress preflight. The exact
checked socket is rebound to the prepared TLS client without another DNS lookup.
Local-secret versions are read before and after TLS resolution; a concurrent
rotation fails preparation. Transport partitioning includes Connection ID and
revisions, profile, egress generation, timeouts, TLS material versions, roots,
and client identity.

### OAuth token endpoint and cache

An OAuth token URL is an explicit HTTPS URL of at most 2,048 bytes with no
userinfo, query, or fragment. There is no discovery or redirect following.

The token endpoint has its own `EgressClient` profile. It independently applies
scheme/host/port policy, complete DNS-answer validation, exact pinning, TLS
hostname/certificate verification, redirect denial, timeout limits, and 16 KiB
request/response limits before resolving or sending the client secret. Passing
egress for the upstream API never authorizes the token endpoint.

The upstream Connection's custom CA and mTLS identity are not inherited by the
OAuth token client. This prevents a credential or client identity intended for
the API origin from crossing into the identity-provider transport.

The in-memory access-token cache is bounded to the maximum Connection count and
single-flights one mint per cache slot. A key includes Connection ID,
Connection ETag, encrypted-local client-secret version when present, and token
client egress generation. Tokens refresh before expiry, are not persisted, and
are zeroized on replacement/drop. A `401` from the intended managed upstream
invalidates only the matching token generation; it does not erase a newer
generation. Connection tests mint within their own deadline and do not reuse
the detached data-plane token cache.

### Secret trust and confidentiality

The trust chain is:

```text
Connection -> credential/TLS binding -> opaque SecretId
  -> SecretResolver -> purpose-bounded ResolvedSecret
```

Ordinary Connection APIs accept opaque IDs only. Operator environment and file
locators are trusted startup configuration behind aliases, never admin input.
File aliases are one validated filename below a canonical configured root.
Traversal, absolute/drive/alternate-stream forms, symbolic links, Windows
reparse points, non-regular files, unsafe permissions, and replacement races
fail closed. Environment/file values are resolved on every authorized use under
a bounded provider permit.

`ResolvedSecret` does not implement `Serialize` or `Clone`, prints only a
redacted marker, enforces a purpose-specific byte cap, and zeroizes material on
replacement and drop. Values are not trimmed or transformed.

The optional encrypted local provider uses XChaCha20-Poly1305 with a fresh
24-byte nonce per encrypted field and 32-byte master keys loaded from protected
mounted files outside SQLite. Authenticated additional data binds schema,
secret ID/version, credential purpose, and field purpose. Exactly one keyring
entry is primary; predecessors are decrypt-only.

Create, rotate, delete, bounded re-encryption, and old-key disuse verification
have no reveal operation. Rotation preflights replacement material against
every enabled dependent Connection before atomically changing ciphertext and
the published local-secret version. Referenced deletion fails with bounded
Connection dependency IDs. Database/WAL/backups contain ciphertext, but the
database and key files are separate recovery artifacts that must be restored
together.

Connection DTOs expose only configured booleans for bound credentials/TLS.
The separately permissioned secret catalog exposes opaque resource IDs, label,
provider kind, compatible purpose, version, dependency count, and allowed
actions; it never exposes a locator or value.

### Discovery, tests, inventory, and playground

Managed MCP refresh initializes one checked streamable-HTTP session and builds
a bounded tool/resource/template catalog. Managed OpenAPI refresh downloads a
bounded document from the stored path, validates and compiles the entire
candidate, and binds definitions to the Connection/catalog revision.
Successful publication is transactional and atomic. Failed discovery, parse,
validation, or publication retains the last-known-good catalog and records a
bounded degraded/stale status.

Stored tests accept no body or target override. HTTP tests use only persisted
`GET`/`HEAD`, path, and expected statuses. MCP tests initialize, inspect at most
one advertised metadata page, and close; they do not call tools or read
resources. Tests have global/principal/Connection rate and concurrency limits,
a ten-second total deadline, exact ETag binding, and safe per-stage results.

The capability inventory requires `admin:tools:read`. It merges manual, legacy,
last-known-good OpenAPI, and last-known-good MCP metadata with typed provenance,
safe status, and policy visibility. Listing/detail performs no provider read,
OAuth exchange, DNS lookup, or upstream request. A stale catalog remains
visible as stale rather than disappearing.

The admin playground requires `admin:tools:execute`, a registered available
tool, and the strong execution ETag returned by inventory detail. It accepts
only a bounded JSON `arguments` object and preserves JSON numeric tokens through
backend mapping. It has no arbitrary URL/header/TLS/credential/method override.
HTTP arguments are validated before the rendered method/path rule. MCP and HTTP
requests run through the normal executor, Connection, egress, TLS, credential,
and audit paths. Projected output is capped at 64 KiB; HTTP headers and
non-success bodies are withheld and unsafe output fails closed with a safe
reason.

### Conservative bounds

| Resource | Implemented limit/default |
| --- | ---: |
| Managed plus projected Connections | 256 |
| Operator secret aliases | 512 entries / 256 KiB startup JSON |
| Local keyring | 8 entries / 16 KiB startup JSON |
| Concurrent operator provider reads | 16 |
| Retained dependency rows | 4,096 |
| Managed OpenAPI document | 2 MiB |
| Published catalog entries | 4,096 |
| Concurrent refreshes | 4 globally; one catalog mutation per Connection |
| Stored test concurrency | 4 global / 2 per principal / 1 per Connection |
| Stored test deadline | 10 seconds |
| OAuth request/response | 16 KiB each |
| OAuth token cache | 256 revision/version-partitioned slots |
| Playground request/result | 64 KiB each |
| Connection/secret ID | 128 bytes |
| Display name / description | 128 / 1,024 characters |
| URL / origin-relative path | 2,048 / 1,024 bytes |
| Header name | 64 bytes |
| OAuth client ID | 256 bytes |
| OAuth scopes | 16 entries, 128 characters each |
| API key, bearer, or OAuth client secret | 8 KiB |
| TLS private key | 256 KiB |
| Certificate or CA bundle | 1 MiB |

Collection and byte limits are checked before expensive parsing, provider,
compilation, or network work.

### Permissions and mutation authority

| Permission | Authority |
| --- | --- |
| `admin:connections:read` | Safe Connection and status metadata |
| `admin:connections:write` | Non-sensitive presentation and operational metadata |
| `admin:connections:secrets:write` | Bind, rotate, clear, clone, redirect, or delete credential/TLS authority |
| `admin:connections:test` | Run the persisted bounded test profile |
| `admin:connections:refresh` | Refresh persisted OpenAPI/MCP discovery |
| `admin:tools:read` | Read policy-filtered inventory and capability detail |
| `admin:tools:write` | Mutate manual/managed tool definitions |
| `admin:tools:execute` | Run the constrained admin playground |

Changing where an existing credential may be sent is a secret-use mutation.
Secrets-write is required for a credentialed origin, OAuth token URL,
scopes/audience/resource, authentication mode/header, mTLS identity, or
credentialed discovery/test target, and for explicit hidden binding fields even
when the submitted marker appears unchanged. A plain Connection writer cannot
perform these operations.

Authorization precedes resource-ID lookup. Control-plane writes use exact strong
ETags/`If-Match`; missing preconditions are `428`, stale revisions are `412`,
and concurrent catalog/dependency conflicts are `409`. Cookie-authenticated
writes remain subject to CSRF. There is no force-delete, secret reveal, URL or
header override, arbitrary probe body, or client-decoded permission path.

### Status, audit, and errors

Safe status contains bounded state/reason codes, times, latency, catalog age and
count, kind/source, and revisions. Public probes reveal no Connection topology.
Connection read DTOs summarize authentication/provider configuration without
bound secret IDs or locators.

Implemented event types include `connection.changed`,
`connection.credential_changed`, `connection.secret_changed`,
`connection.refreshed`, `connection.tested`,
`connection.oauth_token_refresh`,
`connection.secret_resolution_failed`, tool invocation/upstream outcomes, and
`tool.playground_output_rejected`.

Protected secret-management audit may include the stable opaque local-secret
resource ID. Other safe fields are stable Connection/tool IDs, kind/source,
action and changed-field names, authentication kind, revisions, outcome/reason,
latency, invocation source, and bounded counts. Audit, logs, metrics, public
errors, and admin DTOs exclude secret values, environment/file/key locators,
key material, ciphertext/nonces, access/refresh tokens, credential headers,
certificate/private-key contents, tool arguments/results, raw URLs with
query/userinfo, resolved addresses/DNS answers, raw errors, upstream bodies,
credential challenges, and MCP session/content payloads.

### Threat model

| Threat | Implemented prevention/detection | Residual risk |
| --- | --- | --- |
| Ordinary editor redirects a stored credential | Separate secrets-write permission, sensitive-field intent/diff, immutable ID, exact ETag, credential-change audit | A fully authorized secrets writer can intentionally rebind; least privilege and alerts remain required |
| Initial denial triggers provider or network side effects | Authorization-before-snapshot/provider/egress invariant and zero-counter regressions | Does not recall work already authorized or bytes already sent |
| Policy/ETag/Connection changes while playground call is queued | Final live permission, execution ETag, rendered rule, and revision checks before egress | An in-flight call that has already passed the final check may finish |
| Connection mutates between target lookup and dispatch | Immutable target, revision/ETag partitioning, and current-revision check on preconditioned lanes | Ordinary already-authorized invocations intentionally retain snapshot semantics |
| Tool/OpenAPI/MCP input replaces authority | Typed configured target, origin-relative mappings, source/target equality, server metadata ignored for authority | Malicious schemas/content are still untrusted input and must remain bounded |
| SSRF, rebinding, or redirect leaks a credential | Host/port policy, validate all DNS answers, exact pin, TLS verification, redirects/ambient proxy off, credential injection last | Operators can explicitly allow risky destinations |
| OAuth token endpoint bypasses upstream egress | Independent token client, egress/DNS/pin/TLS/bounds, no discovery/redirects, no inherited upstream mTLS | A compromised intended IdP observes the client credential |
| Cross-Connection credential/client reuse | Cache partitions include Connection/revisions, destination/egress generation, profile/timeouts, TLS identity/roots, and local-secret versions | Bounded old entries can remain unreachable until eviction; in-flight calls hold old material |
| Caller overrides configured credential | Strip inbound sensitive/configured headers, reject conflicts, inject last | Approved legacy literal route headers remain a migration risk |
| Secret exposure through DTO/debug/storage/audit | Separate DTOs, redacted non-serializable wrapper, encryption, no reveal, canary scans, safe event vocabulary | Process memory and privileged host inspection remain trusted |
| Local file/environment exfiltration | Opaque admin aliases, trusted startup locators, canonical root, no-follow/permission/device checks, bounded reads | Platform filesystem guarantees vary |
| OAuth stampede or stale token reuse | Bounded single-flight cache, expiry skew, revision/version/egress key, exact-generation `401` invalidation | Provider outage fails closed and can reduce availability |
| Test/refresh becomes arbitrary client or scanner | Persisted ID/profile only, permission, exact ETag, no override/body, quotas/deadline, egress, safe stages | Authorized operators can exercise an already-configured destination |
| Partial refresh replaces a good catalog | Candidate build/validation, transactional revision, atomic publish, last-known-good retention | Catalog can become stale and must be monitored |
| Secret rotation mixes old/new TLS material | Mutation serialization, dependent preflight, version-before/after check, versioned transport/token keys | Already in-flight immutable use may finish |
| Audit itself leaks secrets | Bounded allowlisted fields/reasons, sanitized transport categories, forbidden-field/canary regressions | A future event requires the same review discipline |
| Resource/cardinality exhaustion | Fixed collection, byte, time, concurrency, cache, and history bounds with low-cardinality labels | Limits may require reviewed versioned tuning |

## Compatibility and migration

Legacy `UPSTREAM_URL`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`, and tool files
remain supported. Their read-only projections provide a common inventory model
without writing managed state. Existing `add_request_headers` remains a
compatibility feature but is deprecated for credentials because literal values
can enter configuration and operational tooling.

Migration is explicit and reversible per route/tool. Operators create trusted
aliases or encrypted local secrets, create a managed Connection, bind one
consumer, verify test/catalog/inventory behavior, then remove the legacy
literal. GreenGateway never reveals or copies a legacy literal into a public
API response.

Operational procedures are documented in the
[operator guide](../connections/operator-guide.md),
[migration and rollback guide](../connections/migration.md),
[admin guide](../connections/admin-guide.md), and
[issue #240 acceptance map](../testing/issue-240-acceptance.md).

## Consequences

Proxy, HTTP tool, OpenAPI, MCP, test, refresh, inventory, and playground lanes
share one destination and credential authority model. New providers can
implement the narrow opaque-ID resolver boundary without changing admin input
into an arbitrary locator. Egress, TLS, cache, audit, and revision behavior are
explicit and testable.

The cost is additional typed metadata, exact preconditions, conservative
bounds, distinct permissions, immutable snapshots, and operator-managed key and
database recovery. Authorization remains invocation-scoped rather than a
retroactive recall system, so emergency revocation procedures must include
gateway drain or upstream/network revocation when already-dispatched work must
be stopped.
