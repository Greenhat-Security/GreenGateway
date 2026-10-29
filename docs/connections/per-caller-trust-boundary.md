# Per-Caller Credential Trust Boundary

Phase 8 of the roadmap (issue #446) lets a Connection act for the calling user
instead of as one service identity shared by every caller. This page collects
in one place where trust sits when it does: what each component holds, what
the gateway enforces, what the operator and the issuer must provide because
the gateway cannot, and what is deliberately not built.

It describes what the current `main` branch implements. Field references,
failure reasons and step-by-step procedures stay in the
[operator guide](operator-guide.md); the design record is
[ADR-0006](../adr/0006-first-class-connections-and-credentials.md#delegated-issuer-tokens-issue-441-phase-8).

## The three mechanisms

| | Signed caller assertion (#463) | Delegated issuer token (#441) | Google domain-wide delegation (#442) |
| --- | --- | --- | --- |
| The upstream receives | The Connection's own credential, if it has one, plus a short-lived JWT the gateway signs that names the caller | The caller's own access token, as `Authorization: Bearer` | The caller's own Google access token, as `Authorization: Bearer` |
| Who decides access upstream | The upstream, from the assertion's `caller_iss` and `caller_sub` | The issuer, by the grant it holds for the caller, then the upstream | Google, by the scopes the Workspace administrator authorised for the service account, then the upstream API, as the user the caller's email names |
| The gateway holds | A signing key, by alias | A signing key and a token-exchange client secret, by alias, and the issued tokens in a bounded memory cache | No secret: the `id` of a workload identity profile from startup configuration, and the minted tokens in a bounded memory cache |
| Reference | [Signed caller assertions](operator-guide.md#signed-caller-assertions) | [Delegated issuer tokens](operator-guide.md#delegated-issuer-tokens) | [Google domain-wide delegation](operator-guide.md#google-domain-wide-delegation) |

A delegated issuer token Connection always carries a `caller_assertion`
block: the assertion is the subject token of the exchange and goes to the
issuer only, never upstream. A domain-wide delegation Connection carries
none, because Google verifies no assertion of the gateway's. Both per-caller
credentials require kind `http_api`. The domain-wide delegation's trust
boundary differs enough to have
[its own section](#google-domain-wide-delegation-442); the rest of this page
covers all three unless it says otherwise.

Swagger 2.0 and Google Discovery import (#443) add no credential of their
own. They bring catalogs whose operations require user-consent OAuth 2.0
flows or OpenID Connect, which bind only to a delegated issuer token
Connection; see
[Imported catalogs and per-caller scheme binding](#imported-catalogs-and-per-caller-scheme-binding-443).

## Which lanes serve each mechanism

| Lane | Attested Connection | `delegated_issuer_token` | `google_domain_wide_delegation` |
| --- | --- | --- | --- |
| Manual HTTP tool call, from `/mcp` or the admin playground | One assertion per call | The caller's token | The caller's token |
| Managed OpenAPI tool call | One assertion per call | The caller's token, for the operations its catalog binds ([below](#imported-catalogs-and-per-caller-scheme-binding-443)) | Refused: no catalog is registered on, or kept live on, such a Connection |
| Composite tool leaf: each forward step, `for_each` iteration and compensation | One assertion per leaf, each with its own `jti` | Refused | Refused |
| Managed MCP tool call | One assertion per request of the session the call opens | Not applicable: kind `http_api` only | Not applicable: kind `http_api` only |
| Connection-bound proxy route | One assertion per forwarded request | Refused | Refused |
| Stored Connection test | Refused | Run as the administrator who asks, with a token exchanged inline and cached nowhere | Run as the administrator who asks, with a token minted inline and cached nowhere |
| OpenAPI specification fetch, MCP catalog refresh, enum and label sources | Refused | Refused | Refused |

A refusal is `caller_assertion_not_enforced` for a Connection that carries a
`caller_assertion` block, a delegated one included, and
`authentication_not_supported` for a domain-wide delegation. Each of these
refusals happens before any DNS lookup, secret read, token request or upstream
byte of the refused request;
nothing is ever sent without the assertion or with a shared identity in place
of the caller's. A stored block that only an earlier release accepted --
`bind_approval: true`, an assertion header that matches an additional header,
or a plain HTTP endpoint -- is refused on every lane. The lane rule is
[`caller_assertion_servable_on`](#where-it-is-enforced) for the block and
`credential_servable_on` for the credential; the managed OpenAPI catalog
lifecycle asks the same two functions, so what cannot be served cannot be
registered or stay live. See
[Which calls are attested](operator-guide.md#which-calls-are-attested) and
[Which calls are served](operator-guide.md#which-calls-are-served).

## What each component can do in the wrong hands

From most to least sensitive. The domain-wide delegation's own list is
[in its section](#what-it-can-do-in-the-wrong-hands).

- **The issuer's grant store.** It holds every user's grant for the upstream,
  so whoever reads it can obtain any user's upstream token. It lives at the
  issuer, outside the gateway, and only the issuer's own encryption, access
  control and audit protect it. It is the most sensitive component of a
  delegated issuer token deployment.
- **The token-exchange client secret and the caller-assertion signing key
  together.** The key signs a subject token naming anyone and the secret
  authenticates the exchange, so the pair obtains any user's token through
  the issuer's normal path. To the issuer such an exchange looks like any
  other; only the gateway's audit, which has no event for it, tells it apart.
- **The token-exchange client secret alone.** It exchanges any subject token
  the issuer accepts. An assertion the gateway signed for another attested
  Connection is one, if that Connection shares the delegated block's `aud`
  and `typ`, so the secret alone is enough when audiences are shared. The
  gateway does not stop two Connections from using the same `aud`.
- **The caller-assertion signing key alone.** It signs assertions naming any
  user that every verifier pinned to that Connection's `iss`, `aud` and `typ`
  accepts, until the key is withdrawn from the published JWKS and the
  verifiers' caches of it expire.
- **`admin:connections:secrets:write`.** It decides which keys the JWKS
  publishes, which aliases a Connection binds, and where a credential may be
  sent: the endpoint, the stored test's method and path, the token-exchange
  and revocation URLs, scopes, audience and resource, and for a domain-wide
  delegation the service account, profile, scopes and trusted issuers. Every
  verifier of the one gateway-wide JWKS trusts a key such a principal binds.
- **`admin:tools:write`.** It decides which upstream operations a caller's own
  token is used for: by binding manual tools to a per-caller Connection, and
  by registering the selected operations of a delegated Connection's managed
  OpenAPI catalog, of those the Connection's requested scopes bind. HTTP
  direct rules and tool policy still apply to every call.
- **`admin:principals:write`.** It purges a principal's cached tokens and
  revokes them at the issuer. That costs the user a fresh exchange on their
  next call; it cannot obtain a token.
- **`admin:connections:test`.** On a per-caller Connection it obtains the
  tester's own token, never another user's: the test names the tester, sends
  the saved `GET` or `HEAD` test request with the token and drops it. The test
  result carries stage outcomes only, never the token or the upstream's body.
  The issuer, or Google, still handed the token out, and it stays valid there
  until it expires.
- **A gateway replica's memory.** It holds up to 1,024 cached delegated issuer
  tokens and, in a cache of its own, up to 1,024 cached Google tokens, each
  for at most 900 seconds, a running test's token for its one request, and
  resolved secrets while they are in use. As ADR-0006's threat model records,
  process memory and privileged host inspection are trusted.

## What the gateway enforces

### Identity comes from authentication, never from the request

- Every identity claim in an assertion, a subject token or a Google assertion
  comes from the principal the gateway authenticated, never from a tool
  argument, a header, a body or the audit actor.
- `sub` is the caller's identity-provider issuer, `#`, and the provider's
  subject, so two providers that issue the same subject never name the same
  person; `caller_iss` and `caller_sub` carry the two halves. `email` is
  copied without checking `email_verified` and must not be used to identify
  the user. A domain-wide delegation is the exception: Google knows a user by
  email only, so it names the caller by `email`, and only when the caller's
  issuer is one of the Connection's `subject_issuers`.
- Only a principal an identity provider vouched for is attested or has a
  token obtained for it: a bearer JWT, a session cookie, a client
  certificate, or the admin session that runs a tool in the playground or a
  stored test of a per-caller Connection. An anonymous call, a gateway
  service token, and a principal without an issuer are refused
  (`caller_assertion_no_principal`, `delegated_token_no_principal`) before
  any DNS lookup, secret read or upstream request; a composite tool is
  refused at its first leaf, so it sends nothing. There is no fallback to a
  shared service identity.
- A per-caller token is cached for one caller only. The delegated cache key
  digests the caller's issuer, subject, email and roles, and the Google one the
  issuer, subject and email, so two callers never share a token and a caller
  whose claims changed is exchanged or minted for again. A stored test neither
  reads nor fills either cache, so a test never serves a later call and a
  cached token never makes a test pass.
- Any value a caller sends under the assertion header or a Connection-owned
  credential header is removed before the gateway writes its own, and the
  assertion is written last. No mechanism sends the caller's inbound
  credentials to the issuer, to Google or to the upstream; see
  [Out of scope](#out-of-scope).

### Where secrets may live

- The signing key (purpose `assertion_signing_key`) and the token-exchange
  client secret (purpose `token_exchange_client_secret`) are bound by opaque
  alias only. They resolve from an operator environment or file alias, or
  from one of the five read-only external providers listed under
  [Secret Authority](operator-guide.md#secret-authority). The
  [encrypted local store](operator-guide.md#encrypted-local-secret-store)
  refuses to create either, because its schema predates both purposes. Keep
  the client secret in an external provider.
- The gateway keeps the client secret apart itself, because operator and
  external-provider aliases carry no purpose: a save is refused with
  `secret_purpose_conflict` when it would bind a token-exchange client
  secret's alias under any other field of any Connection, or bind another
  field to an alias a Connection exchanges with. The store checks this inside
  its write transaction, so cluster replicas cannot race past it.
- Both are read and loaded on every use: the key for every signed request and
  every exchange, the secret for every exchange and every revocation. The
  gateway caches neither. An external provider caches a resolved value for at
  most 60 seconds; environment and file aliases are read each time.
- A domain-wide delegation binds no secret alias. The Connection names a
  `CONNECTION_GCP_PROVIDER` workload identity profile by `id`; its audience
  and projected token file stay in startup configuration, and no service
  account key is held anywhere.
- No admin response, admin UI view, log line or audit event carries the
  material, and the Connection read model shows the client secret and each
  signing key only as configured or not, without its alias. The admin UI
  editor keeps a stored key by sending `"signing_key_configured": true`, and
  the gateway keeps the alias of the stored key with the same `kid` and
  algorithm. Naming any key alias in a `PUT`, the stored one included, needs
  `admin:connections:secrets:write` (`403` without it), so a principal without
  that permission cannot confirm a guessed alias by watching which save goes
  through unchanged.
- Binding, changing or removing a `caller_assertion` block or a per-caller
  credential, creating or deleting a Connection that carries one, and
  changing the endpoint or stored test target of such a Connection need
  `admin:connections:secrets:write` in addition to `admin:connections:write`.

### Tokens stay in memory, in bounded caches

| What | Bound | Dropped or replaced when |
| --- | --- | --- |
| Delegated access tokens | 1,024 callers per replica across every delegated Connection. Each is reused for at most 900 seconds, whatever `expires_in` says; the issuer must state an `expires_in` of 1 second to 7 days. | Refreshed a fifth of its lifetime early (at most 30 seconds) plus up to 5 seconds of jitter. No longer served after a save that changes the Connection or an egress policy change, whose first call drops the idle tokens of the earlier configuration. Dropped on an upstream `401` for that token, a [purge](operator-guide.md#purging-a-principals-tokens), idle eviction when the cache is full, and a restart. |
| Google access tokens | A cache of their own: 1,024 callers per replica across every domain-wide delegation Connection, each reused for at most 900 seconds. | Refreshed and dropped as delegated tokens are, a principal purge included. Google offers no revocation, so a dropped token stays valid there until it expires. |
| A stored test's token | Not cached: one exchange or mint per test of a per-caller Connection, inline and within the test's deadline. | Dropped when the test's one request ends. A purge cannot revoke it, since the gateway no longer holds it: it stays valid at the issuer, or at Google, until it expires. |
| Subject tokens | Not cached: one per exchange, with a fresh `jti` and no request binding. | Each exchange signs a new one. |
| Google assertions | Not cached: one per mint, signed by Google, valid for 300 seconds. | Each mint asks Google to sign a new one. |
| Caller assertions | Not cached: one per request, one per request of a managed MCP session, and one per leaf request of a composite tool. `lifetime_seconds` is 1 to 300; at most 8 KiB. | Each request signs a new one. |
| Signing key and client secret material | Not cached by the gateway; at most 60 seconds by an external provider. | Read again on the next use. |
| Published JWKS | Public halves only. Rebuilt when the configured keys change, otherwise every 300 seconds; served with `max-age=300`. | A key that fails to read is left out of the set, not kept from an earlier read. |

Nothing is persisted. No token, refresh token or other field of an issuer's
or Google's answer is written to SQLite, PostgreSQL, a file or the audit
trail; a `refresh_token` in the response is skipped unread. Cached tokens are
zeroized when they are dropped or replaced.

### No token material in errors, logs, metrics or audit

- The assertion, the subject token, the issued access token, any refresh
  token, the client secret, the signing key, the profile's federated token,
  the Google assertion and anything derived from them never reach a
  caller-facing error, a log line, a metric or an audit event.
- Audit identifies what was signed only by its `kid` and `jti`, and records
  the issuer's or Google's HTTP status and its error code only when RFC 6749,
  RFC 8693 or RFC 7009 registers it (`unregistered` otherwise), so an
  issuer's own text never reaches the audit trail.
- An upstream `401` or `403` on a credentialed or attested Connection fails
  a tool call with `upstream_authentication_rejected`, and a proxied request
  with `502`, without the upstream's body, which could echo the credential. A
  credentialed `TRACE` tool call is refused.

### Policy runs before any credential is used

Authentication, rate limits, RBAC, the tool's `enabled` and `allowed_roles`
policy, `tool_name` rules, argument validation and HTTP direct rules on the
tool's rendered method and path all run before the gateway signs anything,
asks the issuer for a token or asks Google to sign, and the upstream
destination passes egress policy before any secret is read. A call the
gateway's policy denies never reaches the issuer or Google. The
token-exchange and revocation endpoints must be in the egress allowlist and
are checked before the client secret or the signing key is read; Google's
signing and token endpoints are checked before the federated identity is
read; redirects are not followed.

Each leaf request of a composite tool is checked on its own: its member
tool's HTTP direct rules on the leaf's rendered method and path, then its
admission, key load and signature just before it is sent, so a leaf the
policy denies is neither signed nor sent.

A stored test of a per-caller Connection is not a tool call, so tool policy
does not apply to it. It needs `admin:connections:test`, accepts no body or
target override, sends only the saved `GET` or `HEAD` test request, and checks
that request's destination against egress policy before it obtains the
tester's token.

To keep callers to reads, request read-only scopes at the issuer or in the
Workspace delegation list and, as a second layer at the gateway, register
only read tools on a per-caller Connection and deny other methods with an
HTTP direct rule (see [`POLICY_FILE`](../configuration.md#policy_file)).
Rendered tool egress evaluates only rules without a `dispatch` binding, and a
tool's rendered path is its `path_template` with arguments substituted,
without the Connection's `base_path`. An overlay's or tool's `readOnlyHint` is
advisory client metadata and enforces nothing.

### Every hand-out and every use is audited

| Event | Emitted | Carries |
| --- | --- | --- |
| `connection.delegated_token_exchange` | On every exchange: each token the issuer hands out, a stored test's included | The caller, or the tester, as `actor`, `connection_id`, outcome and reason, `subject_token.kid` and `subject_token.jti`, issuer status and registered error code. Its `request_id` is the fixed `connection-delegated-token`, because one token serves many calls. |
| `connection.google_delegation_token` | On every mint: each token Google hands out, a stored test's included | The caller, or the tester, as `actor`, `connection_id`, the service account, the scopes, the last step attempted, Google's status and registered error code. |
| `tool.upstream_request` | On every tool request, each leaf request of a composite tool included, cached token or not | The caller as `actor`, `connection_id`, tool, method and outcome; when the request carried an assertion upstream, its `kid` and `jti` (`jti_base` and `count` for a managed MCP session). |
| `connection.tested` | On every stored test | The tester as `actor`, `connection_id`, outcome and the stage outcomes. A per-caller Connection's test also emits its exchange or mint event. |
| `connection.caller_assertion` | On every proxied request on an attested route | The caller as `actor`, the route, outcome, and the `kid` and `jti` or the refusal reason. |
| `connection.delegated_token_purge` and `connection.delegated_token_revocation` | On every operator purge, on every purge a revoked JWT started that dropped something, and on each token a purge revokes | `purge_id`, trigger, principal, entry count (Google tokens counted as `google_delegation_entries`); per delegated token, the revocation outcome and reason. |
| `connection.secret_resolution_failed` | When a signing key or client secret cannot be read or loaded | The fixed reason, never the alias or the material. |

A call served from the cache emits no exchange or mint event. Join an
exchange to the issuer's own log by `subject_token.jti`, to an upstream's log
by the assertion's `jti`, and to the calls it served by `actor` and
`connection_id`; an exchange or mint a test made pairs with that test's
`connection.tested` by the same two fields. Each leaf of a composite tool has
its own `jti`: the request ID, a dot and the leaf's number among the leaves
that signed one, counting from 1 in the order they are sent.
`connection_delegated_token_exchange_total`,
`connection_google_delegation_token_total`,
`connection_delegated_token_purge_total` and
`connection_delegated_token_revocation_total` count the same decisions. See
[Audit and metrics](operator-guide.md#audit-and-metrics) for the delegated
payloads and [Google domain-wide delegation](operator-guide.md#google-domain-wide-delegation)
for the mint's.

### Disabling a user

The gateway keeps no user records and receives no signal from an identity
provider, so it does not learn by itself that a user was disabled. What it
guarantees is narrower: a cached token is served only to a call
authenticated as the same principal, so once no credential the user holds
still authenticates at the gateway, no cached token of theirs is served
again. Until then, a bearer JWT issued before the disable keeps validating
until it expires unless its `jti` is revoked, and tokens already handed out
stay valid at the issuer, at Google and at the upstream until their own
expiry unless they are revoked there.

When a user is disabled:

1. Disable the user at their identity provider, and suspend them in
   Workspace if a domain-wide delegation names them.
2. Stop the gateway serving their cached tokens and revoke those tokens at the
   issuer:
   - **Standalone:** `POST /v1{ADMIN_PREFIX}/principal/delegated-tokens/revoke`
     with their issuer and subject (`admin:principals:write`). It drops their
     delegated and Google tokens alike. See
     [Purging a principal's tokens](operator-guide.md#purging-a-principals-tokens).
   - **Cluster mode:** that endpoint is refused with `409`; see
     [Cluster mode](#cluster-mode) for what to do instead.
3. Revoke the user's grant at the issuer. A purge does not stop a user whose
   credentials still validate and whose grant the issuer still holds: their
   next call simply exchanges again.

A purge revokes each dropped delegated token at the Connection's
`revocation_url` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) once, in
the background and without retry. Without a `revocation_url` a purged token is
only dropped. Give every delegated Connection one when the issuer supports
it. Google tokens are only dropped, since Google offers no revocation for
them. A token a stored test obtained is in no cache, so no purge drops or
revokes it: it stays valid until it expires.

After an incident that may have exposed the client secret or the signing key:
disable the Connection, revoke the grants at the issuer, rotate the client
secret, retire the signing key by publishing a new key under a new `kid`
([Rotating a signing key](operator-guide.md#rotating-a-signing-key)), and only
then re-enable the Connection. A disabled Connection publishes no keys, so
disabling it also withdraws its keys from the JWKS at the next fetch, unless
another enabled Connection publishes the same key; a verifier that honours
`max-age` drops them within 300 seconds after that. Rotating the client secret
alone neither drops the gateway's cached tokens nor revokes what the issuer
already handed out.

## Imported catalogs and per-caller scheme binding (#443)

Managed OpenAPI Connections import
[Swagger 2.0](operator-guide.md#importing-swagger-20-documents) and
[Google Discovery](operator-guide.md#importing-google-discovery-documents)
documents beside OpenAPI 3.x. An imported document is untrusted input and
grants no authority:

- **Conversion adds nothing the document did not describe.** Each document is
  converted to the OpenAPI 3.0 document it describes, and tools are generated
  from that exactly as from an uploaded OpenAPI 3.x document. A construct with
  no faithful OpenAPI 3.0 form leaves its operation out, with a warning, so no
  tool sends a request the document did not describe. A reference to another
  document refuses the whole document and is never resolved, and the document
  is bounded in size (2 MiB), operations (4,096), nesting (256 levels) and,
  for Swagger 2.0, copied nodes.
- **A user-consent scheme binds only to a token issued for that user.** The
  user-consent OAuth 2.0 flows (`authorizationCode`, `implicit`, `password`;
  Swagger 2.0's `accessCode`, `implicit` and `password`; the flow a Discovery
  document's scopes convert to) and `openIdConnect` bind to a
  `delegated_issuer_token` Connection only, and only when every scope the
  alternative requires is in its `requested_scopes`, compared exactly. A
  credential shared by every caller never binds them
  (`oauth2_without_client_credentials`, `open_id_connect`), and a scheme with
  only a `clientCredentials` flow never binds to a delegated Connection
  (`requires_oauth2_client_credentials`). See
  [Security binding and read-only selection](operator-guide.md#security-binding-and-read-only-selection).
- **The requested scopes are the only evidence.** The gateway does not read
  the token the issuer returns, so it cannot check that the token carries
  only the requested scopes; the issuer must issue no more. The document's
  `authorizationUrl`, `tokenUrl`, `refreshUrl` and `openIdConnectUrl`, and the
  Google endpoints a Discovery conversion writes into its scheme, are never
  contacted and never compared with the Connection: the token comes from the
  Connection's `token_exchange_url`.
- **A document's scopes are its author's claim.** An operation that needs a
  scope the Connection does not request is listed with `missing_scopes` and
  cannot be registered, but a document can label a write with a read scope.
  Registration publishes only the `selected_tool_names` the operator
  confirms, so select only `GET` and `HEAD` operations for read access, and
  keep tool policy and `rules[]` for what scopes cannot express.
- **No caller supplies a credential through a tool.** A Discovery document's
  document-level system parameters (`key`, `access_token`, `oauth_token`,
  `alt`, `fields` and the others) are never tool arguments; each is named in a
  `global_parameter_not_mapped` warning.
- **A delegated Connection's catalog is registered from an uploaded
  specification.** Fetching one from the upstream has no caller to exchange
  for and is refused with `caller_assertion_not_enforced`, as are a refresh
  that fetches from a discovery `path`, composite tools when they run, and an
  overlay's enum and label sources.
- **No catalog runs on a domain-wide delegation.** The managed OpenAPI tool
  lane never sends that credential, so a preview, a registration that selects
  a tool, a refresh and an overlay edit on such a Connection answer `409` with
  `authentication_not_supported` before anything is fetched or minted. A save
  that switches a Connection with a live catalog to that credential takes the
  catalog off the tool list, keeps it stored and records `tool_registry.changed`
  with action `managed_openapi_catalog_withdrawn`. Bind the operations such a
  Connection should serve as manual HTTP tools.

## Cluster mode

Everything above holds on every replica. What changes with several replicas:

- **Caches are per replica.** Each replica holds its own delegated and Google
  caches, of up to 1,024 callers each, and nothing shares tokens between
  replicas, so the issuer or Google can see one exchange or mint per caller
  per replica.
- **No purge crosses replicas.** The operator purge endpoint answers `409`.
  Revoke the user's outstanding JWTs with `gateway revoke-jwt` instead (see
  [JWT revocations](../deployment/postgres.md#jwt-revocations)): each replica
  the revoked token is presented to refuses it and purges its own caches for
  that principal, delegated and Google tokens alike, and revokes the delegated
  ones at the issuer. This needs tokens with a `jti`: set `require_jti: true`
  on every JWT provider whose tokens you may need to withdraw. A replica the
  revoked token never reaches keeps that principal's cached tokens, served
  only while another credential of theirs still authenticates there, until
  they age out after at most 900 seconds.
- **To stop every cached token of one Connection on every replica**, for all
  of its users, disable the Connection or make any other real change to it.
  That moves its cache key, so each replica stops serving the tokens it cached
  before once it has applied the change at its next reconcile; until then it
  keeps serving them. None is revoked at the issuer. Saving it unchanged is a
  no-op and keeps them.
- **Stored tests run on the replica that serves the admin request**, with a
  token cached on none.
- **Key publication is judged per replica.** A replica that cannot read a
  Connection's keys leaves them out of the JWKS it serves and refuses that
  Connection's calls with `caller_assertion_key_not_published`, while another
  replica that can read them serves. Give every replica the same secret
  sources, so every replica publishes the same set.
- **The workload identity profile is each replica's own startup
  configuration** (`CONNECTION_GCP_PROVIDER`). Configure the same profile on
  every replica that may serve a domain-wide delegation Connection.
- **Secret exclusivity is decided in the store.** `secret_purpose_conflict` is
  checked inside the write transaction, under the lock every mutation takes,
  so two replicas cannot each bind one client secret alias under two
  purposes.
- **Converted catalogs wait for every replica.** Storing a catalog converted
  from Swagger 2.0 or Discovery is the gated operation
  `connections.openapi_swagger2_catalog` or
  `connections.openapi_discovery_catalog`, admitted only while every live
  replica advertises `openapi_swagger2_catalogs` or
  `openapi_discovery_catalogs`; see
  [operation gating](../deployment/postgres.md#membership-and-maintenance).
  Binding user-consent schemes adds no cluster capability: earlier releases
  refuse to register a catalog on a delegated Connection and withdraw a stored
  one from their tool list, so during a rolling upgrade only upgraded replicas
  serve such a catalog's tools.

## What the operator and the issuer must provide

The gateway cannot check these; they are for the operator and the issuer to
provide:

- **The issuer stores grants encrypted** at rest, restricts who and what can
  read them, and keys each grant on `caller_iss` and `caller_sub`, never on
  `email`.
- **The issuer verifies every subject token**: the signature against
  `/.well-known/caller-assertion-jwks.json` fetched over HTTPS, the
  algorithm, `iss`, `aud` and `typ` it expects, and `exp`. It never accepts an
  unsigned subject token or one the gateway did not sign, and it should
  refuse a `jti` it has already seen.
- **The issuer restricts the gateway's client** to its own subject tokens and
  audience, and hands out only the scopes the Connection requests. The
  gateway sends `requested_scopes`, `audience` and `resource` but treats the
  issued token as opaque: it does not check that the token names the caller,
  carries only the requested scopes, or is meant for the upstream. The
  `scope` in the issuer's answer is only bounded in size. A managed catalog's
  operations bind on those requested scopes alone.
- **Grants are read-only wherever the upstream allows it.** A read-only grant
  limits a caller to reads even if a gateway rule is missing.
- **The issuer logs every hand-out** with the subject token's `jti`, so its log
  can be matched one-to-one with `connection.delegated_token_exchange`. An
  exchange in the issuer's log with no matching gateway event was not made by
  the gateway.
- **The delegated block's `aud` or `typ` is used by no other attested
  Connection.** Otherwise an assertion sent to that other Connection's upstream
  is also a subject token the issuer accepts.
- **Upstreams never echo credentials back.** A successful response body is
  returned to the caller as the tool result without being inspected for
  token material, so an upstream that echoes the request's `Authorization`
  header or the assertion hands the caller a token they could present to the
  upstream directly, outside the gateway's policy. An upstream should also
  answer a user it denies with `403`, and keep `401` for a credential or
  assertion it cannot verify.
- **Assertion verifiers** fetch the JWKS over HTTPS, pin `iss`, `aud`, `typ`
  and the algorithm, keep a replay cache keyed on `sub` and `jti`, and with
  `bind_request` compare the method, request target and body digest; see
  [Verifying an assertion](operator-guide.md#verifying-an-assertion). A
  composite tool's leaves and a managed MCP session's requests each carry a
  distinct `jti`, so such a cache accepts every request of one call.
- **Least privilege for the four permissions above**, and alerting on
  `connection.credential_changed` for per-caller and attested Connections.
- **The egress allowlist names only** the upstream, the token-exchange
  endpoint and the revocation endpoint each delegated Connection needs, and
  the Google endpoints a domain-wide delegation needs.

## Google domain-wide delegation (#442)

A `google_domain_wide_delegation` Connection holds no secret and no grant. A
Workspace super-admin authorises one service account for a fixed list of
scopes; whoever can sign a JWT as that account can then obtain a token for
any user of the domain, for those scopes, by naming the user's email as
`sub`. The gateway never holds the account's key: it has Google sign each
assertion through the IAM Credentials `signJwt` method, authenticated as the
federated identity of a `CONNECTION_GCP_PROVIDER` workload identity profile,
and exchanges it at Google's token endpoint with the JWT bearer grant
(RFC 7523).

### What it can do in the wrong hands

- **The workload identity profile's federated identity** (or the
  `service_account` the profile impersonates), with
  `roles/iam.serviceAccountTokenCreator` on the delegated account, signs as
  that account, and so obtains any domain user's token for the authorised
  scopes. It is the most sensitive part of this mechanism. It is read from a
  projected token file named only in startup configuration; nothing an admin
  API caller writes can name another file or audience.
- **The Workspace scope list for the account.** It, not the Connection's
  `scopes`, is what Google enforces: a Connection can only ask for less.
- **`admin:connections:secrets:write`.** Writing such a Connection, through
  the admin API or the admin UI editor, is credential authority: it decides
  which service account, profile, scopes and trusted issuers are used, and
  which tools then act as every user of the domain.
- **Any identity provider listed in `subject_issuers`.** It names the
  Workspace user by the `email` it puts in its tokens. The gateway copies
  `email` without checking `email_verified`, so a provider that lets a user
  choose or change an unverified address could make the gateway act as
  someone else.

### What the gateway enforces

- **Only listed issuers name a user.** A caller attested by any other issuer
  is refused with `google_delegation_issuer_not_trusted`, a caller with no
  single plain email address with `google_delegation_no_email`, and a call
  with no principal, a service token included, with
  `delegated_token_no_principal`, all before anything is read or sent.
- **No key at rest, fixed endpoints.** The account must be a dedicated
  `{name}@{project}.iam.gserviceaccount.com` account, and the only
  caller-independent value that reaches a URL. `iamcredentials.googleapis.com`
  and `oauth2.googleapis.com` are fixed and both checked against the egress
  policy before the federated identity is read; `sts.googleapis.com`, where the
  profile obtains that identity, must be allowlisted too.
- **The assertion says only what was asked.** `iss` is the account, `sub` the
  caller's email, `scope` the Connection's sorted scopes, `aud` the token
  endpoint, and `exp` 300 seconds after `iat`. A signed assertion whose claims
  differ from those sent is refused and never exchanged. A `401` or `403` from
  `signJwt` earns exactly one retry, with a fresh federated token.
- **Manual HTTP tool calls and stored tests only**, on `http_api` Connections
  without a `caller_assertion`. A stored test runs as the principal who asks
  for it, with a token minted for that one request and cached nowhere, as for
  a delegated issuer token. Every other lane answers
  `authentication_not_supported`, and the managed OpenAPI catalog lifecycle
  applies the same rule: a preview, registration, refresh or overlay edit on
  such a Connection is refused with that reason before anything is fetched or
  minted, and a live catalog is withdrawn from the tool list when a save
  switches its Connection to this credential.
- **A bounded, per-caller cache of its own**, keyed on the caller's issuer,
  subject and email: at most 1,024 callers per replica and 900 seconds per
  token, dropped on an upstream `401`, a save of the Connection, or a
  principal purge (counted as `google_delegation_entries` in
  `connection.delegated_token_purge`).
- **Every mint is audited** as `connection.google_delegation_token`, with the
  caller as `actor`, the service account, the scopes, the last step attempted,
  Google's status and only a registered error code; no federated token,
  assertion or access token reaches an error, a log line, a metric or an
  audit event. `connection_google_delegation_token_total` counts the same
  decisions.

### What the operator must provide

- **A dedicated service account** used for nothing else, authorised in the
  Workspace admin console for read-only scopes only, and for as few as the
  bound tools need.
- **Token Creator for the profile's identity alone** on that account, and on
  no other account.
- **`subject_issuers` names only the provider authoritative for the domain**,
  one that asserts only verified addresses the domain owns.
- **App verification for restricted scopes.** Google requires verification
  for restricted scopes (Gmail, Drive) used by external apps; an internal
  Workspace app is normally exempt. Check this before relying on such a scope.
- **No key, ever.** Create no key for the delegated account, and forbid key
  creation by organisation policy where possible: a key would be a second way
  to act as every user that the gateway's audit never sees.
- **Review the mint audit beside Google's.** The gateway records every token
  it obtains; changes to the Workspace delegation list and to Token Creator
  grants on the account are recorded only by Google.

The [operator guide](operator-guide.md#google-domain-wide-delegation) walks
through the setup step by step.

### Not covered

- **Revocation at Google.** A purge or a save drops cached tokens, but Google
  is not asked to revoke them, so a dropped token stays valid there until it
  expires (about an hour). Suspending the user in Workspace stops new tokens.
- **Checking Google's side.** The gateway cannot see which scopes the
  Workspace administrator authorised, who holds Token Creator on the account,
  or whether a key exists for it. It learns of a missing scope or grant only
  when a mint fails, and of a key never.

## Out of scope

- **Raw bearer forwarding.** The caller's inbound bearer token is never
  forwarded: not to the issuer as a subject token, not to Google and not to an
  upstream. Proxy routes remove the inbound `Authorization` and `Cookie`
  headers, and tool requests are built without the caller's headers.
  Exchanging the inbound token (for example an on-behalf-of flow) would make
  the gateway retain and forward a credential presented to it alone; it needs
  its own security review. `subject_token_source` is a closed enum whose only
  value is `caller_assertion`, so adding another source is an explicit change.
  The `forward_cookie_session` route option, which passes on a validated
  browser session for one trusted upstream, is rejected on Connection routes
  and is not a per-caller credential mechanism.
- **Approval binding (`bind_approval`).** The block reserves the field for an
  assertion that would also carry the approval that authorised a mutation.
  No approval subsystem exists, so new and replacement writes refuse
  `bind_approval: true` (`caller_assertion.bind_approval`,
  `unsupported_binding`), the published write schemas accept only `false`,
  and a block an earlier release stored with `true` is refused on every lane
  with `caller_assertion_not_enforced` rather than signed without the approval
  it promises. Editing such a block in the admin UI turns it off.
- **Consent flows and refresh tokens.** No Connection runs an
  authorization-code, PKCE or device-code flow, and the gateway stores no
  upstream refresh token. Users connect their accounts at the issuer. An
  imported document's authorization and token URLs are never used.
- **Per-caller tokens on other lanes.** Composite tools, proxied requests,
  managed MCP, discovery, enum and label sources refuse a delegated issuer
  token Connection with `caller_assertion_not_enforced`, and every lane but
  manual HTTP tool calls and stored tests refuses a domain-wide delegation
  with `authentication_not_supported`. No managed OpenAPI catalog binds to a
  domain-wide delegation.
- **Attesting the lanes with no caller.** OpenAPI and MCP discovery, enum and
  label sources, and a stored test of an attested Connection that is not
  delegated refuse the Connection rather than send a request without the
  assertion.
- **Learning that a user was disabled**, for example through SCIM or an
  identity-provider webhook, and **carrying a purge between cluster replicas**.
- **Verifying issued tokens**: no introspection, scope, audience or subject
  check of the token the issuer returns.
- **Retrying a failed revocation**, and any revocation at Google.

## Where it is enforced

| Concern | Source |
| --- | --- |
| Which lane serves which block and credential | `gateway/src/connections/http.rs` (`caller_assertion_servable_on`, `credential_servable_on`) |
| Exchange, cache key, purge and revocation | `gateway/src/connections/token_exchange.rs` |
| Domain-wide delegation: issuer and email checks, signing, exchange and audit | `gateway/src/connections/google_delegation.rs` |
| The workload identity profile's federated token | `gateway/src/connections/gcp_secret.rs` |
| Bounded token cache, refresh skew and zeroized slots | `gateway/src/connections/oauth.rs` |
| Assertion claims, signing, key loading and the JWKS | `gateway/src/connections/caller_assertion.rs` |
| Secret purposes and the local-store refusal | `gateway/src/connections/secret.rs` |
| Write validation, `bind_approval` and the secrets-write rule | `gateway/src/connections/model.rs` |
| Configured-key markers and alias naming as secret authority | `gateway/src/admin_connections.rs` |
| Policy before credentials on tool calls | `gateway/src/tools/executor.rs` |
| One assertion per composite leaf | `gateway/src/tools/executor.rs` (`prepare_composite_leaf`), `gateway/src/connections/http.rs` (`composite_leaf_target`) |
| A stored test run as the tester, with an uncached token | `gateway/src/connections/test.rs`, `gateway/src/connections/http.rs` (`test_target`) |
| User-consent scheme binding on requested scopes | `gateway/src/tools/openapi.rs` (`per_caller_requested_scopes`) |
| Swagger 2.0 and Discovery conversion | `gateway/src/tools/swagger2.rs`, `gateway/src/tools/google_discovery.rs` |
| Catalogs a Connection may keep live | `gateway/src/connections/openapi.rs` (`managed_openapi_catalog_withdrawal_reason`) |
| Inbound `Authorization` and `Cookie` removed on proxy routes | `gateway/src/proxy/forward.rs` (`strip_gateway_credentials`) |
| Operator purge, refused in cluster mode | `gateway/src/admin_observability.rs` (`principal_delegated_tokens_revoke_endpoint`) |
| Purge on a revoked JWT | `gateway/src/auth/jwt.rs`, `gateway/src/connections/http.rs` (`RevokedCredentialObserver`) |

The regression `no_token_material_reaches_an_error_a_log_line_or_an_audit_event`
in `gateway/src/tools/executor_delegated_token_tests.rs` checks the
no-token-material rule end to end for delegated tokens, and
`a_connection_test_runs_as_the_tester_with_a_token_it_never_caches` the
stored test. `every_composite_leaf_signs_its_own_assertion_with_a_distinct_jti`
in `gateway/src/tools/executor_caller_assertion_tests.rs` covers composite
leaves, and `gateway/src/connections/google_delegation_tests.rs` checks that
no Google token material reaches the audit trail.
