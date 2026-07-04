# Configuration

GreenGateway reads configuration from environment variables. Each variable is documented below with its own level-3 heading of the exact form `### VAR_NAME`. This document is kept in sync with the code by the automated drift test in `gateway/tests/env_example.rs`, so drift here is a CI failure, not just a documentation staleness risk.

### LISTEN_ADDR

The socket address the gateway binds to when it starts.

Default: `0.0.0.0:8080`

Format and validation: must parse as a Rust `SocketAddr`, such as `127.0.0.1:8080`, `0.0.0.0:8080`, or `[::1]:8080`. Non-Unicode values and invalid socket addresses are rejected during configuration loading.

### ADMIN_LISTEN_ADDR

Optional socket address for serving the gateway admin UI and control-plane API on a separate listener.

Default: empty, which serves the admin surface on `LISTEN_ADDR` with the data-path routes, matching the single-listener default.

Format and validation: unset, empty, or whitespace-only values disable split-listener mode. Non-empty values must parse as a Rust `SocketAddr`, using the same validation as `LISTEN_ADDR`. When set, `ADMIN_LISTEN_ADDR` must differ from `LISTEN_ADDR`.

When set, GreenGateway starts two listeners in the same process. `LISTEN_ADDR` serves `/health`, `/version`, `/metrics`, and the reverse proxy fallback when `UPSTREAM_URL` is configured. `ADMIN_LISTEN_ADDR` serves the admin UI at `ADMIN_PREFIX` and admin APIs under `/v1{ADMIN_PREFIX}`. The same security middleware stack applies to both listeners; only the route sets differ.

### ADMIN_PREFIX

Path prefix for the gateway's admin UI and control-plane API surface.

Default: `/admin`

Format and validation: must be a non-root URI path prefix that starts with `/`, has no trailing slash, and contains only non-empty path segments made of ASCII letters, digits, `.`, `-`, `_`, or `~`. Invalid prefixes are rejected during configuration loading.

With the default, the admin UI remains at `/admin` and the existing admin APIs remain under `/v1/admin`, including `/v1/admin/audit`, `/v1/admin/events/stream`, `/v1/admin/status`, `/v1/admin/policy`, `/v1/admin/policy/validate`, the policy rule-management routes under `/v1/admin/policy/rules`, and the traffic inventory routes `/v1/admin/traffic/endpoints` and `/v1/admin/traffic/endpoint`. When `ADMIN_PREFIX` is changed, the admin UI moves to the new prefix and the admin APIs move to the corresponding `/v1{ADMIN_PREFIX}` prefix: for example, `ADMIN_PREFIX=/ops` serves the UI at `/ops` and admin APIs at `/v1/ops/audit`, `/v1/ops/events/stream`, `/v1/ops/status`, `/v1/ops/policy`, `/v1/ops/policy/validate`, `/v1/ops/policy/rules`, `/v1/ops/traffic/endpoints`, and `/v1/ops/traffic/endpoint`. The default `/admin` path and default `/v1/admin/*` API paths are no longer intercepted in that mode, so they can fall through to the reverse proxy when `UPSTREAM_URL` is configured.

The default `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` include the effective `ADMIN_PREFIX` so the static admin UI shell can load before an operator pastes a token. Admin APIs remain protected by authentication and endpoint-specific authorization checks.

### AUDIT_LOG_FILE

Optional JSON Lines audit log file path.

Default: empty, which disables the file sink. Audit events are always written to stdout.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The file sink opens lazily on first write, appends one JSON event per line, and logs write/open failures without stopping request handling.

### AUDIT_SQLITE_PATH

Optional SQLite audit event store path for queryable local audit history.

Default: empty, which disables the SQLite sink.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates the audit event schema and indexes if needed, and fans audit events out to SQLite in addition to stdout and any JSONL file sink. Startup also migrates older audit databases in place by adding any missing promoted payload columns used for indexed queries, including `payload_matched_rule_id` for rule hit counts.

### AUDIT_SQLITE_RETENTION_DAYS

Optional SQLite audit event retention window, in days.

Default: empty, which disables SQLite pruning.

Format and validation: must parse as a `u32` day count when set. This value is only applied when `AUDIT_SQLITE_PATH` is also set; if the path is unset, the parsed retention value is accepted but has no effect.

### DISCOVERY_SQLITE_PATH

Optional SQLite endpoint discovery inventory store path.

Default: empty, which disables endpoint aggregation.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates discovery aggregate tables and indexes if needed, and consumes `http.request_observed` audit events into per-method, per-endpoint-template aggregates on the audit writer thread. This keeps aggregation out of the request hot path.

This uses a separate config surface from `AUDIT_SQLITE_PATH` because audit history and derived endpoint inventory often have different retention and lifecycle requirements. Operators that prefer a single SQLite file may explicitly set `DISCOVERY_SQLITE_PATH` to the same path as `AUDIT_SQLITE_PATH`; the discovery tables use their own `discovery_` prefixes.

Capacity caveat: distinct principal tracking is exact and currently has no cap, eviction, or retention setting. The `discovery_endpoint_principals` table stores one row per distinct authenticated `actor.user_id` per `(method, endpoint_template)` for the lifetime of the database, and the aggregator mirrors that set in memory while running. In long-running or high-cardinality deployments, size grows proportionally to distinct authenticated users multiplied by distinct endpoint templates; plan database and memory capacity accordingly before enabling this setting. Unauthenticated calls contribute to aggregate call counts but not to distinct principal rows.

Traffic inventory admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/traffic/endpoints` lists discovered endpoint aggregates. It requires a principal with the dedicated `admin:traffic:read` permission, returns `401 Unauthorized` with no authenticated principal, and returns `403 Forbidden` when the principal lacks that permission. If `DISCOVERY_SQLITE_PATH` is unset, the traffic inventory routes return `404 Not Found` with `{"error":"traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/traffic/endpoints` supports `method`, `endpoint_template` substring, `endpoint_template_prefix`, `first_seen_after`, `first_seen_before`, `last_seen_after`, `last_seen_before`, `min_call_count`, `sort`, `limit`, and `cursor` query parameters. Timestamp filters must be RFC 3339. `sort` accepts `last_seen`, `call_count`, or `first_seen`; all sorts are descending with a deterministic method/template tie-breaker, and the default is `last_seen`. Pagination follows the admin API limit-plus-cursor pattern: the response has `{"endpoints":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters and sort. Each endpoint entry includes `method`, `endpoint_template`, `first_seen`, `last_seen`, `call_count`, `distinct_principal_count`, `latency` count and p50/p95/p99 milliseconds, and exact per-status counts.

Endpoint detail uses query parameters rather than a wildcard path route so endpoint templates containing `/` do not require path-segment encoding: `GET /v1{ADMIN_PREFIX}/traffic/endpoint?method=GET&endpoint_template=/users/{id}`. The response contains `endpoint` for the aggregate row, `principals` for a bounded per-principal page, and `audit` for optional raw-event enrichment. Principal pagination uses `principal_limit` and `principal_cursor`, with a default limit of 50 and the same maximum as the audit query API. `from`, `to`, `bucket=hour|day`, `events_limit`, and `events_before_id` control audit-derived time-series and recent-event enrichment.

The detail route can enrich from `AUDIT_SQLITE_PATH` when it is also configured. If `AUDIT_SQLITE_PATH` is unset, the detail response still returns aggregate and principal data and marks `audit.available=false`; it omits `time_series` and `recent_events`. Audit enrichment reverse-maps raw concrete audit paths to endpoint templates by re-running the stateless path templater and requiring an exact template match. This correctly handles literal paths and immediate well-known identifier templates such as `/users/{id}`. It does not reconstruct statefully learned slug/cardinality templates such as `/catalog/{param}`, because the discovery aggregator's live learner state is not stored in the audit database.

### POLICY_FILE

Optional RBAC policy JSON file path.

Default: empty, which means no policy file is loaded.

A copyable starter policy for real deployments is available at `docs/examples/policy.starter.json` — read [docs/examples/policy.starter.README.md](examples/policy.starter.README.md) first, since `default_action: "allow"` means unmatched routes pass through unauthenticated/unauthorized until you add `routes` rules.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The policy loader reads the file as JSON, validates that `schema_version` starts with `0.`, warns on unknown top-level keys, and rejects invalid policy documents.

Route rules in a policy's `routes` array are evaluated in document order. The first rule whose `path_prefix` matches the request path and whose `methods` match the request method determines the required permission.

Rate-limit overrides in a policy's `rate_limits` array are also evaluated in document order, and the first matching entry wins. Each entry may constrain `principal` with the same `roles`, `auth_methods`, and `principal_ids` matcher used by direct firewall rules; omit it or use `{}` to match authenticated and unauthenticated callers. Each entry may also constrain `methods` and an absolute `path` pattern using the same whole-path anchored glob syntax as `rules[].path`: literal segments, `*`, `**`, and `{name}` captures. Matching entries must set positive `requests_per_second` and positive `burst` values.

Rate limiting runs in two independent stages, not a fallback chain: a coarse, IP/session-keyed global lane (`RATE_LIMIT_READ_*`/`RATE_LIMIT_WRITE_*` below) runs early, before authentication, and always applies to every request regardless of the policy. A second, principal-keyed check runs after authentication and applies ONLY when the request has a validated `Principal` AND a `rate_limits` entry matches it — in that case the request must pass BOTH the global lane and the matching policy lane's bucket. A `rate_limits` override can therefore only add an additional constraint on top of the global lane for authenticated, matched requests; it can never loosen or replace the global lane, and it has no effect at all on unauthenticated requests or authenticated requests with no matching entry (those are governed by the global lane alone).

Policy administration APIs are available only when `POLICY_FILE` is configured. When it is unset, `GET /v1{ADMIN_PREFIX}/policy`, `PUT /v1{ADMIN_PREFIX}/policy`, `POST /v1{ADMIN_PREFIX}/policy/validate`, the rule-management endpoints under `/v1{ADMIN_PREFIX}/policy/rules`, `POST /v1{ADMIN_PREFIX}/policy/rules/preview`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` return `404 Not Found` with `{"error":"policy API requires POLICY_FILE to be configured"}` after the caller is authenticated. `GET /v1{ADMIN_PREFIX}/policy` returns the current in-memory live policy, not a fresh file read, and includes a strong ETag header. The ETag is `"sha256:<hex>"`, where `<hex>` is the SHA-256 digest of the policy serialized as canonical JSON with object keys sorted recursively.

Policy administration uses dedicated RBAC permissions. `GET /v1{ADMIN_PREFIX}/policy`, `POST /v1{ADMIN_PREFIX}/policy/validate`, `POST /v1{ADMIN_PREFIX}/policy/rules/preview`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` require `admin:policy:read`; `PUT /v1{ADMIN_PREFIX}/policy`, `POST /v1{ADMIN_PREFIX}/policy/rules`, `PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}`, `DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}`, and `PUT /v1{ADMIN_PREFIX}/policy/rules/order` require `admin:policy:write`. Missing authentication returns `401 Unauthorized`, and a principal without the required permission returns `403 Forbidden`.

`PUT /v1{ADMIN_PREFIX}/policy` replaces the whole policy document. It requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid policy JSON or policy validation errors return `400 Bad Request` with `{"valid":false,"errors":[...]}`. On success, the policy is persisted to `POLICY_FILE`, synchronously reloaded into the live RBAC state before the response returns, and the response includes the new ETag. A successful replace emits a `policy.changed` audit event with actor attribution and a lightweight before/after summary.

`POST /v1{ADMIN_PREFIX}/policy/validate` validates a candidate whole-policy JSON document without persisting it, changing the live policy, or emitting `policy.changed`. It returns `{"valid":true}` on success or `400 Bad Request` with `{"valid":false,"errors":[...]}` on failure.

Granular rule-management endpoints mutate only the `rules` array but validate the full resulting policy before persisting. Each mutation requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid JSON, invalid rule shape, invalid reordered policy, or invalid order sets return `400 Bad Request` without partial mutation.

Rules defined directly in the policy file without an explicit `id` still use the legacy array-index fallback (see the `rules[]` schema above), not the API's generated `rule-<uuid-v4>` scheme. Their effective id shifts whenever an earlier rule in the list is deleted or the list is reordered, through this API or a direct file edit — a script that captures such a rule's effective id and reuses it across separate requests can end up addressing the wrong rule. Give a rule an explicit `id` in the policy file if you need to address it reliably by id over time; rules created through `POST /v1{ADMIN_PREFIX}/policy/rules` are unaffected, since they always receive a stable id.

`POST /v1{ADMIN_PREFIX}/policy/rules` appends one direct firewall rule. The request body is a single rule object using the documented `rules[]` shape (`methods`, `path`, `principal`, `action`, and optional `id`). If `id` is omitted, the server assigns a stable generated id using the `rule-<uuid-v4>` scheme before persisting, so API-created rules never depend on array-index fallback. If a client supplies an explicit `id` that collides with any current effective rule id, including legacy index fallback ids, the request returns `400 Bad Request`. On success it returns `201 Created` with the created rule, including its assigned or confirmed `id`, and the new ETag.

`PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}` partially updates one existing rule by effective id. The JSON body may include any of `methods`, `path`, `principal`, and `action`; `id` is the path identity and is not patchable. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with the updated rule and the new ETag.

`DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}` removes one existing rule by effective id. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with `{"deleted_rule_id":"..."}` and the new ETag.

`PUT /v1{ADMIN_PREFIX}/policy/rules/order` reorders the current rules. The request body is a raw JSON array of rule ids in the desired order, for example `["allow-public","deny-admin"]`. The array must be an exact permutation of the current effective rule ids: same length, no duplicates, no missing ids, and no unknown ids. Invalid sets return `400 Bad Request` with errors describing the mismatch. On success it returns `200 OK` with `{"order":[...]}` and the new ETag.

Every successful rule mutation emits `policy.changed` with actor attribution, the same lightweight `before`/`after` policy summaries and `changed_sections` used by whole-policy replace, plus a granular `diff_summary`: `{"action":"rule_created","rule_id":"...","position":N}`, `{"action":"rule_updated","rule_id":"...","changed_fields":[...]}`, `{"action":"rule_deleted","rule_id":"...","position":N}`, or `{"action":"rules_reordered","new_order":[...]}`.

`POST /v1{ADMIN_PREFIX}/policy/rules/preview` evaluates a candidate direct firewall rule against historical `http.request_observed` rows in the SQLite audit store without persisting it, changing the live policy, or emitting `policy.changed`. The request body is `{"rule":{...},"from":"<RFC3339>","to":"<RFC3339>","sample_limit":20}`; `rule` uses the same `rules[]` shape as the policy document, `from`/`to` are optional RFC 3339 bounds, and `sample_limit` is optional and capped at 100. The response is `{"match_count":N,"scanned_event_count":M,"sample_strategy":"newest_matches","samples":[...]}`. Samples include `event_id`, `timestamp`, `request_id`, `source_ip`, `method`, `path`, `actor`, `status`, optional `policy_decision`, and optional historical `matched_rule_id`. Preview requires `AUDIT_SQLITE_PATH`; when it is unset the endpoint returns `503 Service Unavailable` with `{"error":"policy rule preview requires AUDIT_SQLITE_PATH to be configured"}`.

`GET /v1{ADMIN_PREFIX}/policy/rules/hits` returns per-rule historical request hit counts for the current live policy as `{"rules":[{"rule_id":"...","hits":0}]}`. Counts are grouped from indexed `http.request_observed.payload_matched_rule_id` values, so each observed request contributes at most one hit and paired `authz.*` audit events are not double-counted. Rules without an explicit `id` use the same zero-based array index fallback as live RBAC audit attribution. When `AUDIT_SQLITE_PATH` is unset, the endpoint still succeeds and returns all live rules with `hits: 0`.

Concurrent policy mutations through this API are safely serialized against each other, including whole-policy `PUT` and granular rule create/update/delete/reorder. A losing request with an ETag from the same starting policy receives `412 Precondition Failed`, never a silently-overwritten update. The `If-Match` guard does not order against a direct edit of the `POLICY_FILE` on disk racing an in-flight API mutation. The file's own atomic write (temp file + rename) means a concurrent reader, including the background file watcher, never observes a torn/partial file, but if something outside this API writes to `POLICY_FILE` at the same moment an API mutation completes, the file watcher's next debounced reload may pick up either write, and the ETag a caller received may no longer describe the live policy a moment later. Treat the returned `ETag` as best-effort freshness, not a guarantee against external file edits, if anything outside this API also writes to `POLICY_FILE`.

### RBAC_EXEMPT_PATHS

Comma-separated paths that bypass RBAC authorization.

Default: `/health,/version,/metrics,/admin`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. When unset, the default is `/health,/version,/metrics` plus the effective `ADMIN_PREFIX`. Exempt paths are matched as segment-boundary-aware prefixes, so `/admin` covers `/admin/assets/app.js` but not `/administrator` or `/admin-panel`. Exempt paths are allowed through without RBAC permission checks and do not emit authz audit events.

### CORS_ALLOW_ORIGINS

Comma-separated list of exact origins allowed by CORS.

Default: empty list. With the default, cross-origin browser requests receive no CORS allow-origin response header.

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a valid HTTP header value. Configure full origins such as `http://localhost:3000` or `https://app.example.test`.

### MAX_BODY_SIZE

Maximum request body size accepted from the `Content-Length` header, in bytes.

Default: `1048576` (1 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. Requests with a `Content-Length` larger than this value are rejected with `413 Payload Too Large`.

### RATE_LIMIT_READ_RPS

Global pre-authentication read-lane token refill rate for `GET` and `HEAD` requests, in requests per second. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `50.0`

Format and validation: must parse as a finite non-negative `f64`. The read lane uses a separate token bucket from mutating methods.

### RATE_LIMIT_READ_BURST

Global pre-authentication read-lane token bucket burst size for `GET` and `HEAD` requests. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `100`

Format and validation: must parse as a `u32`. A fresh read-lane bucket starts full.

### RATE_LIMIT_WRITE_RPS

Global pre-authentication write-lane token refill rate for every method other than `GET` and `HEAD`, in requests per second. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `10.0`

Format and validation: must parse as a finite non-negative `f64`. The write lane uses a separate token bucket from `GET` and `HEAD`.

### RATE_LIMIT_WRITE_BURST

Global pre-authentication write-lane token bucket burst size for every method other than `GET` and `HEAD`. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `20`

Format and validation: must parse as a `u32`. A fresh write-lane bucket starts full.

### TRUST_PROXY_HEADERS

Whether to trust `X-Forwarded-For` and `X-Real-IP` as canonical client IP inputs.

Default: `false`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, forwarded proxy headers are ignored and the connection peer IP is used. Enable this only when GreenGateway is deployed behind a trusted proxy boundary that sanitizes these headers.

### SESSION_COOKIE_NAME

Optional cookie name used for session-based keying by the global, pre-authentication rate-limit lane (see above) when the request has no matching cookie.

Default: empty string

Format and validation: any valid Unicode string is accepted. The global lane runs before authentication and always keys on this cookie (when set and present on the request, via a non-cryptographic hash) or otherwise the canonical client IP — it never sees a validated `Principal`, since authentication has not run yet at that point in the middleware stack. The SEPARATE, post-authentication policy `rate_limits` lane (see above) always keys on the validated principal's stable `user_id` when one is present, regardless of this setting.

Security note: leave this unset (the default) unless a trusted upstream layer validates the session cookie before the global rate-limit lane sees the request. A client-controlled, unvalidated cookie can be rotated to evade the global lane's keying; canonical client IP keying remains the safe default when no cookie is configured. This does not affect the policy `rate_limits` lane, which only ever keys on a cryptographically-validated `Principal`.

### VALIDATION_ALLOWED_CONTENT_TYPES

Comma-separated list of `Content-Type` prefixes accepted for mutating requests.

Default: `application/json`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a valid HTTP header value. `POST`, `PUT`, and `PATCH` requests are accepted when their `Content-Type` starts with any configured entry, allowing values such as `application/json; charset=utf-8`.

### AUTH_ENABLED

Enables global authentication middleware.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, non-exempt requests run through authentication. When disabled, authentication is a no-op passthrough and no `Principal` is injected for downstream handlers.

### AUTH_MODE

Authentication enforcement mode.

Default: `required`

Format and validation: must be `required` or `observe`. In `required` mode, non-exempt requests must present a supported, valid credential or they are rejected with `401 Unauthorized`. In `observe` mode, authentication still attempts to validate credentials and still emits `auth.failure` audit events, but authentication failures are forwarded without a `Principal` and tagged on observation events as unauthenticated. `AUTH_ENABLED=false` skips authentication entirely; `AUTH_MODE=observe` keeps authentication running without letting the auth layer itself block.

### AUTH_COOKIE_NAME

Cookie name read as a session credential by authentication middleware.

Default: `session`

Format and validation: must be a non-empty RFC 6265 cookie name. The cookie value is treated as credential material and is never echoed in logs, audit payloads, or client responses.

### AUTH_EXEMPT_PATHS

Comma-separated paths that bypass authentication.

Default: `/health,/version,/metrics,/admin`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. When unset, the default is `/health,/version,/metrics` plus the effective `ADMIN_PREFIX`. Exempt paths are matched as segment-boundary-aware prefixes, so `/admin` covers `/admin/assets/app.js` but not `/administrator` or `/admin-panel`. Exempt paths are allowed through without credential extraction and do not emit auth audit events.

### JWT_JWKS_URL

Optional JWKS endpoint used to validate RS256 bearer JWTs.

Default: empty, which means no JWT validator is built.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode. The validator fetches public keys from this endpoint and caches them by `kid`.

Egress trust: when this value is a URL with a host, that host is automatically trusted for gateway-originated egress. Operators do not need to duplicate the JWKS host in `EGRESS_ALLOWED_HOSTS`.

### JWT_ISSUER

Optional expected JWT issuer.

Default: empty, which disables issuer checking.

Format and validation: unset, empty, or whitespace-only values become `None`. When set, bearer JWTs must include a matching `iss` claim.

Egress trust: if this value is a URL with a host, that host is automatically trusted for gateway-originated egress because some deployments use the issuer URL as an identity-provider discovery base. Non-URL issuer identifiers are ignored for egress trust.

### JWT_AUDIENCE

Optional expected JWT audience.

Default: empty, which disables audience checking.

Format and validation: unset, empty, or whitespace-only values become `None`. When set, bearer JWTs must include a matching `aud` claim.

### JWT_JWKS_TIMEOUT_MS

Timeout for JWKS HTTP fetches, in milliseconds.

Default: `2000`

Format and validation: must parse as a `u64` millisecond duration.

### JWT_REQUIRE_JTI

Whether bearer JWTs must include a non-empty `jti` claim.

Default: `false`

Format and validation: must parse as a Rust boolean, `true` or `false`. When enabled, tokens without a non-empty `jti` are rejected.

### ROLES_CLAIM

Flat JWT claim name used to read roles.

Default: `roles`

Format and validation: must be a non-empty Unicode string. The validator reads this claim as a flat JSON array of strings; missing claims and non-array values produce an empty role list.

### CSRF_ENABLED

Enables double-submit-cookie CSRF checks for the gateway's own state-changing control-plane requests.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, cookie-authenticated state-changing control-plane requests must include a valid CSRF cookie/header token pair. Bearer-authenticated requests bypass this check because CSRF is a browser cookie-auth concern. The current gateway routes are `GET` probes and are exempt, so this setting is dormant for current production traffic.

### CSRF_COOKIE_NAME

Cookie name used to store the CSRF token.

Default: `csrf_token`

Format and validation: must be a non-empty RFC 6265 cookie name. The CSRF cookie is intentionally not `HttpOnly`, because browser JavaScript must read it and echo the token into the configured CSRF request header.

The CSRF cookie is issued with the `Secure` attribute, so browsers will not store it over plain `http://` except on `localhost`; deployments terminating TLS upstream are fine, but testing over non-localhost plain HTTP will not receive the cookie.

### CSRF_HEADER_NAME

Request header that must echo the CSRF cookie token on protected state-changing requests.

Default: `x-csrf-token`

Format and validation: must be a valid HTTP header name. This header is also included in the gateway CORS allow-header list.

### CSRF_COOKIE_DOMAIN

Optional `Domain` attribute for the CSRF cookie.

Default: empty, which omits the `Domain` attribute and leaves the cookie host-scoped.

Format and validation: unset or empty values become `None`. Non-empty values must be valid cookie domain attribute text, such as `.example.test` or `admin.example.test`.

### CSRF_EXEMPT_PATHS

Comma-separated paths that bypass CSRF checks.

Default: `/health,/version,/metrics`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. Exempt paths return before CSRF cookie issuance, so the default probe routes do not receive a CSRF cookie today.

### UPSTREAM_URL

Optional `http` or `https` upstream origin for the catch-all reverse proxy fallback.

Default: empty, which disables proxying and leaves unmatched paths on axum's default `404`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be a valid `http` or `https` URL with a host. The proxy uses only the configured scheme, host, and port; each incoming request's path and query are forwarded unchanged. The upstream host is automatically trusted for gateway-originated egress, so operators do not need to duplicate it in `EGRESS_ALLOWED_HOSTS`. Private resolved IP ranges are still blocked by default unless `EGRESS_DENY_PRIVATE_IPS=false` is explicitly configured.

`UPSTREAM_URL` and `UPSTREAM_ROUTES` are mutually exclusive when `UPSTREAM_ROUTES` contains at least one entry. This keeps proxy startup deterministic and avoids an implicit precedence rule between the legacy catch-all upstream and the routing table.

### UPSTREAM_ROUTES

Optional ordered routing table for the reverse proxy fallback, encoded as a JSON array.

Default: empty, which disables route-table proxying. `UPSTREAM_URL` continues to provide the legacy catch-all proxy when this value is unset or an empty array.

Format and validation: unset, empty, or whitespace-only values become an empty route table. Non-empty values must be a JSON array of objects. Each object has optional `path_prefix`, optional `host`, and required `upstream_url` fields. Unknown fields are rejected. `upstream_url` uses the same validation as `UPSTREAM_URL`: it must be a valid `http` or `https` URL with a host. `path_prefix`, when present, must be a URI path starting with `/`. `host`, when present, must be a hostname without a port and is normalized to lowercase. Each entry must set at least one of `path_prefix` or `host`; an entry with only `path_prefix: "/"` is rejected because it would be an unconditional catch-all. Use `UPSTREAM_URL` for the legacy catch-all behavior or add a host to make the root prefix host-specific.

Route entries may also set these optional per-upstream fields:

- `timeout_ms`: total timeout for this route's upstream requests, in milliseconds. When unset, the route inherits `UPSTREAM_TIMEOUT_MS` if configured, otherwise `EGRESS_TIMEOUT_MS`.
- `response_idle_timeout_ms`: maximum idle time between streamed response chunks for this route, in milliseconds. When unset, the route inherits `UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS` if configured, otherwise `EGRESS_RESPONSE_IDLE_TIMEOUT_MS`.
- `connect_timeout_ms`: TCP/TLS connection timeout for this route, in milliseconds. When unset, the route inherits `UPSTREAM_CONNECT_TIMEOUT_MS` if configured, otherwise `EGRESS_CONNECT_TIMEOUT_MS`.
- `add_request_headers`: object mapping header names to values added to requests sent to this route's upstream after the gateway strips hop-by-hop headers and propagates `x-request-id`.
- `strip_request_headers`: array of request header names removed before sending to this route's upstream after the gateway strips hop-by-hop headers and propagates `x-request-id`.
- `tls_ca_bundle_path`: filesystem path to a PEM CA bundle whose certificates are added to this route's TLS trust store.

Per-route header validation rejects invalid header names or values, rejects adding hop-by-hop or gateway-managed headers such as `connection`, `host`, and `content-length`, and rejects adding or stripping `x-request-id`. The gateway owns request-id propagation so audit and tracing correlation cannot be disabled by route configuration. A route also cannot add and strip the same header.

`tls_ca_bundle_path` is the supported mechanism for upstreams served by private or internal certificate authorities. Certificate verification remains strict by default, and no route inherits a custom CA unless it explicitly configures one. GreenGateway does not expose a per-route skip-verify option; use a local test CA bundle for development instead of disabling verification.

Matching semantics: a route with both `host` and `path_prefix` requires both to match. Host matching is exact against the request `Host` header after lowercasing and ignoring any port. Path matching uses the gateway's segment-boundary-aware prefix matcher, so `/api` matches `/api` and `/api/users` but not `/apiary`. Among matching routes, the longest `path_prefix` wins. For equal prefix lengths, a host-qualified route wins over a path-only route. Remaining exact ties use declaration order, with the first route winning; exact duplicate `host` plus `path_prefix` matcher keys are rejected at startup.

Every distinct routing-table upstream origin is health-checked and auto-seeded into the egress allowlist. Duplicate route entries pointing at the same upstream origin share one health-check loop.

Example:

```json
[
  {
    "path_prefix": "/api",
    "upstream_url": "https://api.internal.example",
    "timeout_ms": 1500,
    "add_request_headers": {
      "x-gateway-upstream": "api"
    },
    "strip_request_headers": [
      "x-client-secret"
    ],
    "tls_ca_bundle_path": "/etc/greengateway/internal-ca.pem"
  },
  {
    "host": "app.example.test",
    "path_prefix": "/",
    "upstream_url": "https://app.internal.example"
  }
]
```

### UPSTREAM_TIMEOUT_MS

Optional total timeout override for configured upstream proxy requests, in milliseconds.

Default: empty, which inherits `EGRESS_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. This applies only to requests sent to configured upstream proxy targets, including `UPSTREAM_URL`, `UPSTREAM_ROUTES`, and the background upstream reachability checks; other gateway-originated egress, such as JWKS fetches, continues to use `EGRESS_TIMEOUT_MS`.

### UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS

Optional idle timeout override between streamed upstream response body chunks, in milliseconds.

Default: empty, which inherits `EGRESS_RESPONSE_IDLE_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. This applies only to streaming proxy responses from configured upstream proxy targets.

### UPSTREAM_CONNECT_TIMEOUT_MS

Optional TCP/TLS connection timeout override for configured upstream proxy requests, in milliseconds.

Default: empty, which inherits `EGRESS_CONNECT_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. This applies only to requests sent to configured upstream proxy targets, including the background upstream reachability checks.

## Gateway-Owned Paths And Proxy Collisions

GreenGateway separates its control plane from proxied data-plane traffic. In the default single-listener mode, gateway-owned paths are matched before the reverse proxy fallback, and unmatched paths under gateway-owned control-plane prefixes are not forwarded to the upstream. If an upstream also serves content at one of these paths, that upstream content is unreachable through GreenGateway at the colliding path; move the gateway admin surface with `ADMIN_PREFIX` if the upstream genuinely needs that namespace.

When `ADMIN_LISTEN_ADDR` is set, this separation is stronger: the data-path listener does not register the admin UI or admin API routes, and the admin listener does not register probes, metrics, or the reverse proxy fallback.

The current gateway-owned paths are:

- `/health`
- `/version`
- `/metrics`
- The effective `ADMIN_PREFIX` UI path and its subpaths, defaulting to `/admin`
- The effective admin API prefix. With the default admin prefix this is `/v1/admin`; with `ADMIN_PREFIX=/ops` this is `/v1/ops`

The `/mcp` surface is reserved by the roadmap for Phase 6, but this codebase does not serve an `/mcp` route yet. When it lands, it should be added to the same gateway-owned path list rather than handled by scattered proxy checks.

### EGRESS_ALLOWED_HOSTS

Comma-separated hostnames the egress HTTP client may call for gateway-originated outbound requests.

Default: empty list, which denies all egress requests.

Format and validation: split on commas, trim whitespace, ignore empty entries, lowercase entries, and require each entry to be an ASCII hostname without a port. Configure only hostnames, not URLs. The egress client still blocks private resolved IP ranges by default even when a hostname is allowlisted.

Infrastructure endpoint hosts configured elsewhere, including `UPSTREAM_URL`, every `UPSTREAM_ROUTES[].upstream_url`, `JWT_JWKS_URL`, and URL-shaped `JWT_ISSUER` values, are auto-seeded into the effective egress allowlist. This allows deployments to proxy to configured upstreams or validate tokens without duplicating those hosts here.

### EGRESS_TIMEOUT_MS

Total timeout for each egress HTTP request, in milliseconds.

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration. The timeout applies to the whole request, including connection, sending, and response body streaming.

### EGRESS_RESPONSE_IDLE_TIMEOUT_MS

Idle timeout between streamed egress response body chunks, in milliseconds.

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration. For streaming proxy responses, this timeout starts before the first body chunk and resets after every successfully received chunk. If the upstream response body is idle for longer than this window, the stream is aborted and treated as a gateway timeout.

### EGRESS_CONNECT_TIMEOUT_MS

TCP/TLS connection timeout for each egress HTTP request, in milliseconds.

Default: `10000`

Format and validation: must parse as a `u64` millisecond duration.

### EGRESS_MAX_RESPONSE_BYTES

Maximum egress response body size, in bytes.

Default: `5242880` (5 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. The egress client streams response bodies and aborts once this cap is exceeded rather than buffering unbounded data.

### EGRESS_MAX_REQUEST_BODY_BYTES

Maximum egress request body size, in bytes.

Default: `1048576` (1 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. The egress client checks this cap before sending a request.

### EGRESS_DENY_PRIVATE_IPS

Whether the egress client blocks private and special-use resolved IP ranges.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, the egress client blocks RFC1918 IPv4 ranges, CGNAT, loopback, link-local, IPv4 `0/8`, IPv6 loopback, IPv6 ULA, and IPv6 link-local addresses even when the hostname is allowlisted. If any resolved address for a hostname is private, the request is denied.
