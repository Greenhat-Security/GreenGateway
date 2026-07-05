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

With the default, the admin UI remains at `/admin` and the existing admin APIs remain under `/v1/admin`, including `/v1/admin/audit`, `/v1/admin/events/stream`, `/v1/admin/status`, `/v1/admin/policy`, `/v1/admin/policy/history`, `/v1/admin/policy/rollback/{version}`, `/v1/admin/policy/validate`, the policy rule-management routes under `/v1/admin/policy/rules`, the token-management routes under `/v1/admin/tokens`, the schema routes `/v1/admin/schema/coverage` and `/v1/admin/schema/inferred`, `/v1/admin/signals`, the signal transition routes under `/v1/admin/signals/{id}`, and the traffic inventory routes `/v1/admin/traffic/endpoints`, `/v1/admin/traffic/endpoint`, and `/v1/admin/traffic/endpoints/review`. When `ADMIN_PREFIX` is changed, the admin UI moves to the new prefix and the admin APIs move to the corresponding `/v1{ADMIN_PREFIX}` prefix: for example, `ADMIN_PREFIX=/ops` serves the UI at `/ops` and admin APIs at `/v1/ops/audit`, `/v1/ops/events/stream`, `/v1/ops/status`, `/v1/ops/policy`, `/v1/ops/policy/history`, `/v1/ops/policy/rollback/{version}`, `/v1/ops/policy/validate`, `/v1/ops/policy/rules`, `/v1/ops/tokens`, `/v1/ops/schema/coverage`, `/v1/ops/schema/inferred`, `/v1/ops/signals`, `/v1/ops/signals/{id}/acknowledge`, `/v1/ops/signals/{id}/dismiss`, `/v1/ops/traffic/endpoints`, `/v1/ops/traffic/endpoint`, and `/v1/ops/traffic/endpoints/review`. The default `/admin` path and default `/v1/admin/*` API paths are no longer intercepted in that mode, so they can fall through to the reverse proxy when `UPSTREAM_URL` is configured.

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

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates discovery aggregate tables and indexes if needed, creates the persisted endpoint-review, signal, and rule-suggestion tables if needed, and consumes `http.request_observed` audit events into per-method, per-endpoint-template aggregates on the audit writer thread. This keeps aggregation and signal persistence out of the request hot path.

This uses a separate config surface from `AUDIT_SQLITE_PATH` because audit history and derived endpoint inventory often have different retention and lifecycle requirements. Operators that prefer a single SQLite file may explicitly set `DISCOVERY_SQLITE_PATH` to the same path as `AUDIT_SQLITE_PATH`; the discovery tables use their own `discovery_` prefixes.

Capacity caveat: distinct principal tracking is exact and currently has no cap, eviction, or retention setting. The `discovery_endpoint_principals` table stores one row per distinct authenticated `actor.user_id` per `(method, endpoint_template)` for the lifetime of the database, and the aggregator mirrors that set in memory while running. In long-running or high-cardinality deployments, size grows proportionally to distinct authenticated users multiplied by distinct endpoint templates; plan database and memory capacity accordingly before enabling this setting. Unauthenticated calls contribute to aggregate call counts but not to distinct principal rows.

Signal engine: discovery signals are stored in the same SQLite file because they are derived from discovered traffic inventory rather than raw audit history. The first shipped signal type is `new_endpoint_seen`, emitted only when the live endpoint aggregator creates a new `(method, endpoint_template)` aggregate in memory. Existing aggregate rows loaded from `DISCOVERY_SQLITE_PATH` at startup are treated as already known, so upgrading with a populated discovery database does not backfill or flood `new_endpoint_seen` signals on the next request to those endpoints.

Additional signal detectors also run only inside the discovery aggregator on the audit writer thread. Request middleware emits the same `http.request_observed` audit event as before; detector window maintenance, signal construction, and SQLite `INSERT OR IGNORE` persistence are not performed inline in request handling. All signal detectors write through the generic `discovery_signals` table, whose `(signal_type, target_kind, target_key)` uniqueness prevents duplicate lifecycle rows for the same logical target.

Rule suggestions are also stored in this SQLite file, in `discovery_rule_suggestions`. Suggestion generation is an explicit off-hot-path computation; the request handler and discovery aggregator do not compute suggestions while serving traffic. A generated suggestion reflects traffic and signals as of the last explicit generation run. Re-running generation is idempotent for the same logical target because the table has a uniqueness constraint on `(suggestion_type, method, path_pattern, principal_key)` and inserts use `INSERT OR IGNORE`.

### SCHEMA_MISMATCH_SIGNAL_THRESHOLD

Cumulative schema mismatch count that opens a `schema_mismatch` discovery signal for an endpoint.

Default: `5`.

Format and validation: must parse as an integer greater than `0`.

Trigger condition: when an endpoint's persisted rolling/cumulative `schema_mismatch_count` crosses this threshold from below. The signal target is the endpoint `(method, endpoint_template)`. Clean schema checks with `schema_mismatch:false` and requests where no conformance check was possible do not increment the counter and therefore cannot trigger the signal. Existing endpoints loaded from `DISCOVERY_SQLITE_PATH` with counts already at or above the threshold are treated as already past the crossing point, so startup does not backfill signals for old mismatches.

Minimum sample behavior: none beyond the threshold itself; this detector is count-based. Duplicate prevention is endpoint-scoped through `UNIQUE(signal_type, target_kind, target_key)`.

### ERROR_RATE_SPIKE_SIGNAL_THRESHOLD

Recent error-rate increase, as a ratio delta, that opens an `error_rate_spike` discovery signal for an endpoint.

Default: `0.40`, meaning a 40 percentage-point increase over baseline.

Format and validation: must parse as a finite number greater than `0.0` and less than or equal to `1.0`.

Trigger condition: status codes `400` through `599` count as errors. The aggregator keeps a fixed recent window of the last 20 observations for each endpoint and compares that recent error rate to the endpoint's cumulative baseline excluding that recent window. A signal opens when `recent_error_rate - baseline_error_rate >= ERROR_RATE_SPIKE_SIGNAL_THRESHOLD`. This is deterministic and O(1) per observation: the endpoint aggregate tracks cumulative error count plus a fixed in-memory recent error window.

Minimum sample behavior: evaluation waits until both the recent window and the baseline have at least 20 calls. An endpoint with one failed request, or with only a recent window and no baseline, cannot trigger this detector.

### PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD

Prior distinct principal count required before a new authenticated principal/endpoint pair opens a `principal_new_to_endpoint` discovery signal.

Default: `1`.

Format and validation: must parse as an integer greater than `0`.

Trigger condition: an authenticated `actor.user_id` makes its first observed call to an endpoint that is not brand new and already had at least this many other distinct authenticated principals in `discovery_endpoint_principals`. The signal target kind is `principal_endpoint`, with identity including the method, endpoint template, and principal. Unauthenticated requests do not participate in this detector. A brand-new endpoint's first principal does not trigger this detector; that event is covered by `new_endpoint_seen` instead.

Minimum sample behavior: the configured prior-principal threshold is the floor. With the default of `1`, the second distinct authenticated principal on an existing endpoint triggers; with `2`, the third distinct principal triggers.

### VOLUME_OUTLIER_SIGNAL_THRESHOLD

Per-endpoint call-volume multiple that opens a `volume_outlier` discovery signal.

Default: `3.0`.

Format and validation: must parse as a finite number greater than `1.0`.

Trigger condition: the aggregator groups each endpoint's traffic into non-overlapping 20-call windows using the audit event timestamps. After a baseline of three completed windows is established, each completed 20-call window is compared to the endpoint's average baseline calls-per-second rate. A signal opens when the new window is at least `VOLUME_OUTLIER_SIGNAL_THRESHOLD` times faster than baseline (`direction:"increase"`) or at most `1 / VOLUME_OUTLIER_SIGNAL_THRESHOLD` of baseline (`direction:"decrease"`). Window duration is clamped to at least one second so same-second bursts are deterministic and finite.

Minimum sample behavior: evaluation starts only after three completed baseline windows, so a brand-new endpoint needs at least 80 calls in the current process before this detector can fire. The volume baseline is in-memory and re-establishes after restart; persisted aggregate counts are not scanned to recreate historical timing windows.

### RULE_SUGGESTION_BASELINE_WINDOW_HOURS

Lookback window, in hours, used by explicit rule suggestion generation for baseline allow candidates.

Default: `24`

Format and validation: must parse as an integer between `1` and `876000`.

Baseline behavior: generation reads discovered endpoint templates from `DISCOVERY_SQLITE_PATH` and role claims from `AUDIT_SQLITE_PATH` over this lookback window. For each observed `(method, endpoint_template, role)` combination that is not already covered by an active direct `allow` or `shadow` rule, it persists an open `baseline_allow` suggestion whose proposed rule has `action:"allow"`, the discovered endpoint template as `path`, the observed method as its single method, and `principal.roles` containing that one role.

Audit dependency: baseline role suggestions require `AUDIT_SQLITE_PATH`. Discovery tracks distinct `actor.user_id` values per endpoint but does not store role claims, so GreenGateway does not fall back to per-principal-id allow suggestions when audit history is unavailable. In that case explicit generation still evaluates anomaly-derived suggestions, but the baseline section is reported unavailable with `omitted_reason:"baseline role suggestions require AUDIT_SQLITE_PATH because role claims are only stored in audit history"`.

Unauthenticated and role-less traffic: baseline generation skips unauthenticated observations and authenticated observations whose audit actor has no role claims. It also skips observations whose audit payload says `policy_decision:"denied"` so denied probes do not become allow-rule candidates.

Matching limitation: audit history stores concrete request paths. Baseline generation uses the same `stateless_path_template` matching strategy as traffic endpoint audit enrichment, so it matches literal paths and immediate well-known identifier templates such as `/users/{id}`. Stateful learned slug templates such as `/catalog/{param}` are not reverse-mapped from raw audit paths.

Anomaly-derived behavior: generation reads open discovery signals only. Acknowledged and dismissed signals are ignored. Each open signal with a usable endpoint target creates a `signal_shadow_<signal_type>` suggestion unless the active direct policy already has a first-matching `deny` or `shadow` rule for that target. These suggestions use `action:"shadow"` rather than `deny` because discovery signals are deterministic advisory signals with false-positive risk; operators can review the referenced signal id, signal type, explanation, and evidence in the suggestion before deciding whether to enforce a blocking rule.

### PAYLOAD_CAPTURE_ENABLED

Explicit opt-in for sampled request-shape capture into the discovery SQLite database.

Default: `false`, which disables payload-shape capture. With the default, the request path does not create payload capture handles, observation events do not include `payload_shape`, and fresh discovery databases do not create the payload capture tables.

Format and validation: must parse as a boolean. When set to `true`, `DISCOVERY_SQLITE_PATH` must also be set; otherwise startup fails closed with a clear configuration error because this feature has no output destination without the discovery database.

When enabled and sampled, GreenGateway captures request shape only:

- Query string parameters: parameter names and a coarse `value_type` of `number` or `string`. Query parameter values are read only for this in-memory type guess and are never stored.
- JSON request bodies for proxied requests: top-level object keys only, after the proxy has already buffered the request body for upstream forwarding. Nested object keys, array contents, and scalar values are not captured.

The capture output is attached to the existing `http.request_observed` audit event as `payload_shape` and is consumed by the existing SQLite discovery aggregator on the audit writer thread. SQLite writes and reservoir maintenance are not performed in the request handler.

Runtime schema conformance may reuse the same in-memory shape extraction for a request, but it does not cause `payload_shape` to be emitted or stored unless payload capture itself sampled that request.

The on-disk tables are created only when payload capture is enabled:

- `discovery_payload_shape_stats(method, endpoint_template, shape_observation_count, updated_at)`
- `discovery_payload_shape_samples(method, endpoint_template, sample_slot, observed_at, shape_hash, shape_json)`

Rows are keyed by the same `(method, endpoint_template)` concept used by `discovery_endpoint_aggregates`. Each endpoint keeps at most 128 `discovery_payload_shape_samples` rows in a deterministic reservoir. `shape_observation_count` is the number of sampled shapes offered to that endpoint reservoir, which can exceed the stored row count.

`shape_json` has this shape:

```json
{
  "query_params": [
    {
      "name": "page",
      "redacted": false,
      "value_type": "number"
    },
    {
      "name_hash": "sha256:...",
      "redacted": true,
      "value_type": "string"
    }
  ],
  "json_body": {
    "top_level_keys": [
      {
        "name": "name",
        "redacted": false
      },
      {
        "name_hash": "sha256:...",
        "redacted": true
      }
    ]
  }
}
```

Sensitive-looking query parameter names and JSON top-level key names are not stored verbatim. A name is treated as sensitive when its normalized ASCII-alphanumeric form contains one of these markers: `password`, `passwd`, `pwd`, `ssn`, `socialsecurity`, `token`, `secret`, `apikey`, `credential`, `creditcard`, `cardnumber`, `authorization`, `jwt`, or `bearer`. For those names, GreenGateway stores `redacted: true` and `name_hash`, a `sha256:` hash of the normalized name. It omits `name`.

Under every configuration, payload capture never stores query parameter values, JSON values, full request bodies, response bodies, non-JSON body bytes, nested JSON structure, array contents, headers, cookies, credentials, or authorization decisions beyond the existing observation event fields.

### PAYLOAD_CAPTURE_SAMPLE_RATE

Deterministic per-request sample rate for payload-shape capture.

Default: `0.10`.

Format and validation: must parse as a finite `f64` greater than or equal to `0.0` and less than `1.0`. Values of `1.0`, negative numbers, `NaN`, and infinity are rejected. The upper bound is intentionally exclusive so enabling payload capture cannot become exhaustive.

Sampling uses a canonical JSON SHA-256 hash of the request id, method, and path, then compares that hash to the configured rate. Query parameter values and body bytes are not part of the sampling seed. A rate of `0.0` creates no payload shape samples even when `PAYLOAD_CAPTURE_ENABLED=true`.

### OPENAPI_SPEC_PATH

Optional local OpenAPI 3.x JSON or YAML document path for schema coverage in the legacy single `UPSTREAM_URL` mode.

Default: empty, which disables schema coverage unless one or more `UPSTREAM_ROUTES` entries set `openapi_spec_path`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway verifies that the file exists and parses as an OpenAPI 3.x document during startup. Invalid paths, unsupported OpenAPI versions, malformed JSON, or malformed YAML fail startup with an aggregated `OpenAPI schema configuration is invalid` error.

The schema coverage API is `GET /v1{ADMIN_PREFIX}/schema/coverage`. It requires a loaded RBAC policy and the `admin:schema:read` permission. Missing authentication returns `401 Unauthorized`, and a principal without `admin:schema:read` returns `403 Forbidden`.

When a spec and `DISCOVERY_SQLITE_PATH` are both configured, the response is:

```json
{
  "spec_configured": true,
  "discovery_configured": true,
  "undocumented_endpoints": [
    {
      "method": "GET",
      "endpoint_template": "/internal/health"
    }
  ],
  "unused_operations": [
    {
      "method": "PATCH",
      "path_template": "/users/{userId}",
      "operation_id": "updateUser",
      "summary": "Update a user",
      "source": "/etc/greengateway/openapi.yaml"
    }
  ]
}
```

`undocumented_endpoints` are observed `(method, endpoint_template)` pairs from `discovery_endpoint_aggregates` with no matching spec operation. `unused_operations` are OpenAPI operations with no matching observed endpoint. Matching compares normalized path shapes: any whole path segment shaped like `{anything}` on either side is treated as the same wildcard marker, so `/users/{userId}` matches the discovery template `/users/{id}`. Segment counts must still match; `/reports/{id}/summary` does not match `/reports/{id}/summary/details`.

For request-time conformance, the OpenAPI parser also reads inline operation/path query parameters and inline `application/json` object request-body schemas. It checks required query parameter names and required top-level JSON body keys. It does not resolve `$ref`, validate nested schemas, validate scalar value types, or enforce optional fields.

When no spec is configured, the endpoint returns `404 Not Found` with `{"error":"schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured","spec_configured":false}`. When no discovery database path is configured, it returns `503 Service Unavailable` with `{"error":"schema coverage requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}`.

The inferred request schema API is `GET /v1{ADMIN_PREFIX}/schema/inferred?method=POST&endpoint_template=/users/{id}`. It uses query parameters, not path captures, so endpoint templates containing `/` can be passed directly with normal query-string encoding. It requires a loaded RBAC policy and the same `admin:schema:read` permission as schema coverage. Missing authentication returns `401 Unauthorized`, and a principal without `admin:schema:read` returns `403 Forbidden`.

The endpoint reads the payload-shape reservoir in `discovery_payload_shape_samples` and returns a per-`(method, endpoint_template)` inferred request shape.

When `PAYLOAD_CAPTURE_ENABLED=true` and captured samples exist for the requested endpoint, the response is:

```json
{
  "method": "POST",
  "endpoint_template": "/users/{id}",
  "sample_count": 2,
  "required_threshold": 0.95,
  "query_params": [
    {
      "name": "page",
      "redacted": false,
      "present_count": 2,
      "frequency": 1.0,
      "required": true,
      "value_types": [
        { "value_type": "number", "count": 2 }
      ]
    },
    {
      "name": "search",
      "redacted": false,
      "present_count": 1,
      "frequency": 0.5,
      "required": false,
      "value_types": [
        { "value_type": "string", "count": 1 }
      ]
    }
  ],
  "json_body_keys": [
    {
      "name": "display_name",
      "redacted": false,
      "present_count": 2,
      "frequency": 1.0,
      "required": true
    },
    {
      "name_hash": "sha256:...",
      "redacted": true,
      "present_count": 1,
      "frequency": 0.5,
      "required": false
    }
  ]
}
```

`sample_count` is the number of stored reservoir samples used for the inference, not a claim that the endpoint has only received that many requests. `present_count` is the number of those samples containing the query parameter or JSON top-level key, and `frequency` is `present_count / sample_count`. Query parameter `value_types` reuse the coarse `number` or `string` values captured by payload shape sampling. JSON body key entries do not include value types because payload capture records top-level key presence only, not JSON values or nested structure.

A field is inferred as `required: true` when its frequency is at least `0.95`; otherwise it is reported as optional with `required: false`. This high threshold is intentionally conservative because payload capture is sampled and bounded, so a field should be present in nearly every retained sample before the gateway labels it likely required.

Redacted field names remain redacted. If payload capture stored only `name_hash` for a sensitive-looking query parameter or JSON top-level key, the inferred schema response also uses only `name_hash` with `redacted: true` and never reconstructs or guesses the original name.

If `PAYLOAD_CAPTURE_ENABLED` is not enabled, the endpoint returns `404 Not Found` with `{"error":"inferred schema requires PAYLOAD_CAPTURE_ENABLED=true","payload_capture_configured":false}`. If payload capture is enabled but `DISCOVERY_SQLITE_PATH` is unavailable, it returns `503 Service Unavailable` with `{"error":"inferred schema requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}`. If payload capture is enabled and the discovery database exists but there are no captured samples for the requested endpoint, it returns `404 Not Found` with `{"error":"inferred schema has no captured payload samples for method and endpoint_template","schema_inferred":false}`.

Runtime conformance emits `schema_mismatch` on `http.request_observed` only when a check was possible. With a configured OpenAPI spec, matching operations use the spec shape and non-matching data-plane requests are flagged as undocumented with `schema_mismatch: true`. Without a configured spec, GreenGateway falls back to the inferred schema only when payload capture is enabled, a matching discovered endpoint has an inferred schema, and `sample_count >= 5`. Lower-sample inferred schemas are treated as insufficient evidence and leave `schema_mismatch` absent rather than `false`.

Conformance checks are intentionally conservative: a mismatch means a required query parameter or required top-level JSON body key is missing, or a request is undocumented while a spec is configured. Unexpected extra query parameters or JSON keys are not flagged, because many backends tolerate additive inputs and flagging them would create noisy false positives. Gateway-owned routes such as `/health`, `/version`, `/metrics`, `ADMIN_PREFIX`, and `/v1{ADMIN_PREFIX}` are skipped so admin polling does not pollute upstream schema inventory.

The request-time path avoids unnecessary body work. If no OpenAPI spec match, undocumented-spec check, or sufficiently sampled inferred schema is available, no conformance body-shape handle is attached. If the selected expected shape only has required query parameters, no JSON body parsing is requested. JSON body top-level key extraction runs only when a selected schema has required body keys, and it reuses the same shape-capture handle as payload capture when payload capture sampled the same request.

Remote OpenAPI URLs are intentionally not supported by this setting. Runtime URL fetching must go through the SSRF-hardened egress client and is future work.

Traffic inventory admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/traffic/endpoints` lists discovered endpoint aggregates, and `GET /v1{ADMIN_PREFIX}/traffic/endpoint` returns one endpoint detail. These read routes require a principal with the dedicated `admin:traffic:read` permission. `POST /v1{ADMIN_PREFIX}/traffic/endpoints/review` marks or clears an endpoint review flag and requires `admin:traffic:write`. All traffic admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"traffic endpoint inventory requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the traffic inventory routes return `404 Not Found` with `{"error":"traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/traffic/endpoints` supports `method`, `endpoint_template` substring, `endpoint_template_prefix`, `first_seen_after`, `first_seen_before`, `last_seen_after`, `last_seen_before`, `min_call_count`, `new_since_hours`, `is_new=true|false`, `reviewed=true|false`, `covered_by_rule=true|false`, `sort`, `limit`, and `cursor` query parameters. Timestamp filters must be RFC 3339. `new_since_hours` defaults to `24`, making "new since yesterday" the default `is_new` window. `sort` accepts `last_seen`, `call_count`, or `first_seen`; all sorts are descending with a deterministic method/template tie-breaker, and the default is `last_seen`. Pagination follows the admin API limit-plus-cursor pattern: the response has `{"endpoints":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters and sort. Each endpoint entry includes `method`, `endpoint_template`, `first_seen`, `last_seen`, `call_count`, `schema_mismatch_count`, `distinct_principal_count`, `is_new`, `reviewed`, `reviewed_at`, `reviewed_by`, `covered_by_rule`, `latency` count and p50/p95/p99 milliseconds, and exact per-status counts.

`schema_mismatch_count` is persisted in `discovery_endpoint_aggregates` and increments only for observed requests whose `http.request_observed` payload has `schema_mismatch: true`. Clean checks with `schema_mismatch: false` and requests where no check was possible do not increment it. The same field is returned on the endpoint detail object from `GET /v1{ADMIN_PREFIX}/traffic/endpoint`.

Lifecycle fields are independent booleans rather than a single enum. An endpoint can be new, reviewed, and covered by a direct rule at the same time, so the API does not collapse those states into a mutually-exclusive value. `is_new` is computed from `first_seen` and the `new_since_hours` window; it is not persisted. `reviewed`, `reviewed_at`, and `reviewed_by` are persisted in `discovery_endpoint_reviews`, keyed by `(method, endpoint_template)`. The table stores `method TEXT`, `endpoint_template TEXT`, `reviewed_at TEXT`, and nullable `reviewed_by TEXT`, with `(method, endpoint_template)` as the primary key. `covered_by_rule` is computed live from the current active RBAC policy. The gateway builds a representative concrete path from the endpoint template, evaluates it with the same `RuleMatcher` used by request-time direct firewall rules, and counts any matching direct rule action (`allow`, `deny`, or `shadow`) as coverage. Principal-constrained rules are checked with a representative principal satisfying the rule constraints, so role-scoped direct rules still count as explicit coverage for the endpoint. If RBAC is not loaded, the internal coverage helper returns `false`; the admin API itself still requires RBAC so traffic reads can be permission-gated.

Endpoint detail uses query parameters rather than a wildcard path route so endpoint templates containing `/` do not require path-segment encoding: `GET /v1{ADMIN_PREFIX}/traffic/endpoint?method=GET&endpoint_template=/users/{id}`. The response contains `endpoint` for the aggregate row, `principals` for a bounded per-principal page, and `audit` for optional raw-event enrichment. For principals that have both `admin:traffic:read` and `admin:signals:read`, the endpoint object on both the list and detail responses includes `open_signals`, shaped as `{"count":N,"signal_types":[...]}`, for open endpoint-scoped discovery signals on that `(method, endpoint_template)`. For principals with only `admin:traffic:read`, `open_signals` is omitted entirely rather than returned as `null` or an empty summary. Principal pagination uses `principal_limit` and `principal_cursor`, with a default limit of 50 and the same maximum as the audit query API. `from`, `to`, `bucket=hour|day`, `events_limit`, and `events_before_id` control audit-derived time-series and recent-event enrichment.

`POST /v1{ADMIN_PREFIX}/traffic/endpoints/review` accepts `{"method":"GET","endpoint_template":"/users/{id}","reviewed":true}` to mark an endpoint reviewed and the same body with `"reviewed":false` to clear the mark. The endpoint must already exist in the discovery aggregate table or the request returns `404 Not Found`. On success, the response is `{"reviewed":true,"reviewed_at":"<RFC3339>","reviewed_by":"<principal user_id>"}` when marked or `{"reviewed":false,"reviewed_at":null,"reviewed_by":null}` when cleared. Successful review changes emit a `traffic.endpoint_review_changed` audit event with the acting principal and the method/template payload.

Signals admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/signals` lists discovery signals. It requires `admin:signals:read`. `POST /v1{ADMIN_PREFIX}/signals/{id}/acknowledge` moves a signal to `acknowledged`, and `POST /v1{ADMIN_PREFIX}/signals/{id}/dismiss` moves a signal to `dismissed`; both require `admin:signals:write`. All signal admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"signals API requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the signal routes return `404 Not Found` with `{"error":"signals API requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/signals` supports `state=open|acknowledged|dismissed`, `signal_type`, `target_kind`, `target_key`, `limit`, and `cursor`. Results are ordered by `created_at` descending with `id` as a deterministic tie-breaker. Pagination follows the same limit-plus-cursor pattern as traffic inventory: the response has `{"signals":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters. Endpoint-scoped target filters use `target_kind=endpoint` and `target_key="<METHOD> <endpoint_template>"`, for example `target_key=GET /users/{id}`.

Each signal response includes `id`, `signal_type`, `target`, `explanation`, `evidence`, `state`, `created_at`, `updated_at`, `transitioned_at`, and `transitioned_by`. `target` is generic and currently uses `{"kind":"endpoint","identity":{"method":"GET","endpoint_template":"/users/{id}"}}` for endpoint-scoped signals. `evidence` is structured JSON. For `new_endpoint_seen`, evidence includes `first_seen`, `initial_call_count`, `initial_status`, `initial_latency_ms`, and nullable `initial_principal`. `explanation` is a human-readable sentence that names the endpoint and explains why the signal fired.

Signal rows are persisted in `discovery_signals`. The table stores `id TEXT`, `signal_type TEXT`, `target_kind TEXT`, `target_key TEXT`, `target_identity_json TEXT`, `explanation TEXT`, `evidence_json TEXT`, `state TEXT`, `created_at TEXT`, `updated_at TEXT`, nullable `transitioned_at TEXT`, and nullable `transitioned_by TEXT`. `(signal_type, target_kind, target_key)` is unique, so a detector cannot create duplicate lifecycle records for the same logical target. New persisted signals are pushed to `/v1{ADMIN_PREFIX}/events/stream` as `signal.opened` SSE events. The SSE data is an audit-event envelope whose payload contains `id`, `signal_type`, `target`, `explanation`, `evidence`, `state`, `created_at`, `updated_at`, `transitioned_at`, and `transitioned_by`. Successful lifecycle transitions emit a `signal.lifecycle_changed` audit event with the acting principal and signal target payload; the same event is available on the SSE stream.

Suggestions admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/suggestions` lists persisted rule suggestions. It requires `admin:suggestions:read`. `POST /v1{ADMIN_PREFIX}/suggestions/generate` runs the explicit off-hot-path suggestion generator and persists newly discovered suggestions; it requires `admin:suggestions:write`. `POST /v1{ADMIN_PREFIX}/suggestions/{id}/accept` creates a real direct firewall rule from the suggestion and then moves the suggestion to `accepted`; it requires both `admin:suggestions:write` and `admin:policy:write`. `POST /v1{ADMIN_PREFIX}/suggestions/{id}/dismiss` moves a suggestion to `dismissed`; it requires `admin:suggestions:write` only. All suggestion admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"suggestions API requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the suggestion routes return `404 Not Found` with `{"error":"suggestions API requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/suggestions` supports `state=open|dismissed|accepted`, `suggestion_type`, `limit`, and `cursor`. Results are ordered by `created_at` descending with `id` as a deterministic tie-breaker. Pagination follows the same limit-plus-cursor pattern as signals: the response has `{"suggestions":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters.

Each suggestion response includes `id`, `suggestion_type`, `method`, `path_pattern`, `principal_key`, `rationale`, `evidence`, `proposed_rule`, `state`, `created_at`, `updated_at`, `transitioned_at`, `transitioned_by`, and optional `source_signal_id`. `proposed_rule` is the structured rule that would be accepted, not an opaque serialized blob: it contains `methods`, `path`, `principal` constraints (`roles`, `auth_methods`, and `principal_ids`), `action`, and an `id` only if the persisted proposal already supplied one. Generated baseline suggestions normally propose `action:"allow"` with one observed role, while signal-derived suggestions normally propose `action:"shadow"`.

Suggestion freshness is explicit. Listing does not recompute suggestions. A list response reflects traffic, audit history, discovery signals, and the active policy as of the most recent successful `POST /v1{ADMIN_PREFIX}/suggestions/generate` call. Generation is idempotent for the same logical target because persisted suggestions are unique on `(suggestion_type, method, path_pattern, principal_key)`. Re-running generation may add new suggestions for newly observed traffic or newly opened signals, but it does not update already persisted suggestion rows or reopen dismissed/accepted suggestions.

`POST /v1{ADMIN_PREFIX}/suggestions/generate` returns the generator run summary: `inserted_count`, `baseline`, and `anomaly`. `baseline` reports whether audit-backed role suggestions were available, how many role/endpoint observations were found, how many were skipped because policy already covered them, skipped unauthenticated/no-role/denied observations, scanned audit rows, and whether the 100,000-row scan cap truncated the run. `anomaly` reports open signal count and skip counts. Baseline suggestions require `AUDIT_SQLITE_PATH`; without it, generation still evaluates anomaly-derived suggestions and returns `baseline.available=false` with the documented `omitted_reason`.

Accepting a suggestion is intentionally a policy-write action, not just a suggestion lifecycle action. The caller must hold `admin:suggestions:write` to operate on the suggestion record and `admin:policy:write` because accepting persists a real direct firewall rule into `POLICY_FILE`. Both accept and dismiss require the suggestion to currently be in the `open` state; a suggestion that was already accepted or dismissed returns `409 Conflict` with `{"error":"suggestion is not open"}` and its stored state/transition metadata is left unchanged. Accept uses the same internal rule-create path as `POST /v1{ADMIN_PREFIX}/policy/rules`: the request must include an exact `If-Match` header for the current policy ETag, missing `If-Match` returns `428 Precondition Required`, a stale or non-matching ETag returns `412 Precondition Failed`, duplicate supplied rule ids return `400 Bad Request`, and full policy validation runs before persistence. On success, the response is `201 Created` with the new policy `ETag` and `{"suggestion":{...accepted suggestion...},"rule":{...created rule...}}`. If the policy changed after the suggestion was reviewed, the stale ETag failure is surfaced exactly as the policy rule API would surface it and the suggestion remains `open`; callers should refetch policy and suggestions before retrying. A successful accept emits the normal `policy.changed` audit event with `diff_summary.action="rule_created"` and also emits `suggestion.lifecycle_changed` for the `accepted` transition.

Dismiss does not mutate policy, so it does not require `admin:policy:write` and does not require `If-Match`. On success, `POST /v1{ADMIN_PREFIX}/suggestions/{id}/dismiss` returns the transitioned suggestion with `state:"dismissed"`, `transitioned_at`, and `transitioned_by`, and emits `suggestion.lifecycle_changed`. Unknown suggestion ids return `404 Not Found`.

The detail route can enrich from `AUDIT_SQLITE_PATH` when it is also configured. If `AUDIT_SQLITE_PATH` is unset, the detail response still returns aggregate and principal data and marks `audit.available=false`; it omits `time_series` and `recent_events`. When audit enrichment is available, `audit.time_series_truncated` and `audit.recent_events_scan_truncated` are each `true` if their respective scan (time-series counting and recent-event listing run as two independent bounded scans) hit the 100,000-row safety cap after SQL-level method/path narrowing. Audit enrichment reverse-maps raw concrete audit paths to endpoint templates by re-running the stateless path templater and requiring an exact template match. This correctly handles literal paths and immediate well-known identifier templates such as `/users/{id}`. It does not reconstruct statefully learned slug/cardinality templates such as `/catalog/{param}`, because the discovery aggregator's live learner state is not stored in the audit database.

### POLICY_FILE

Optional RBAC policy JSON file path.

Default: empty, which means no policy file is loaded.

A copyable starter policy for real deployments is available at `docs/examples/policy.starter.json` — read [docs/examples/policy.starter.README.md](examples/policy.starter.README.md) first, since `default_action: "allow"` means unmatched routes pass through unauthenticated/unauthorized until you add `routes` rules.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The policy loader reads the file as JSON, validates that `schema_version` starts with `0.`, warns on unknown top-level keys, and rejects invalid policy documents.

Route rules in a policy's `routes` array are evaluated in document order. The first rule whose `path_prefix` matches the request path and whose `methods` match the request method determines the required permission.

Direct firewall rules in `rules` are also evaluated in document order with first-match-wins semantics. Each rule may set `enabled` to `true` or `false`; omitted `enabled` values default to `true` so existing policy files remain active without edits. A rule with `enabled:false` is skipped entirely during live request evaluation, as if it were not present in the rulebase, so the request falls through to the next rule and then to the policy default action if no enabled rule matches.

Rate-limit overrides in a policy's `rate_limits` array are also evaluated in document order, and the first matching entry wins. Each entry may constrain `principal` with the same `roles`, `auth_methods`, and `principal_ids` matcher used by direct firewall rules; omit it or use `{}` to match authenticated and unauthenticated callers. Each entry may also constrain `methods` and an absolute `path` pattern using the same whole-path anchored glob syntax as `rules[].path`: literal segments, `*`, `**`, and `{name}` captures. Matching entries must set positive `requests_per_second` and positive `burst` values.

Rate limiting runs in two independent stages, not a fallback chain: a coarse, IP/session-keyed global lane (`RATE_LIMIT_READ_*`/`RATE_LIMIT_WRITE_*` below) runs early, before authentication, and always applies to every request regardless of the policy. A second, principal-keyed check runs after authentication and applies ONLY when the request has a validated `Principal` AND a `rate_limits` entry matches it — in that case the request must pass BOTH the global lane and the matching policy lane's bucket. A `rate_limits` override can therefore only add an additional constraint on top of the global lane for authenticated, matched requests; it can never loosen or replace the global lane, and it has no effect at all on unauthenticated requests or authenticated requests with no matching entry (those are governed by the global lane alone).

Policy administration APIs are available only when `POLICY_FILE` is configured. When it is unset, `GET /v1{ADMIN_PREFIX}/policy`, `PUT /v1{ADMIN_PREFIX}/policy`, `GET /v1{ADMIN_PREFIX}/policy/history`, `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}`, `POST /v1{ADMIN_PREFIX}/policy/validate`, the rule-management endpoints under `/v1{ADMIN_PREFIX}/policy/rules`, `POST /v1{ADMIN_PREFIX}/policy/rules/preview`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` return `404 Not Found` with `{"error":"policy API requires POLICY_FILE to be configured"}` after the caller is authenticated. `GET /v1{ADMIN_PREFIX}/policy` returns the current in-memory live policy, not a fresh file read, and includes a strong ETag header. The ETag is `"sha256:<hex>"`, where `<hex>` is the SHA-256 digest of the policy serialized as canonical JSON with object keys sorted recursively.

Policy administration uses dedicated RBAC permissions. `GET /v1{ADMIN_PREFIX}/policy`, `GET /v1{ADMIN_PREFIX}/policy/history`, `POST /v1{ADMIN_PREFIX}/policy/validate`, `POST /v1{ADMIN_PREFIX}/policy/rules/preview`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` require `admin:policy:read`; `PUT /v1{ADMIN_PREFIX}/policy`, `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}`, `POST /v1{ADMIN_PREFIX}/policy/rules`, `PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}`, `DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}`, and `PUT /v1{ADMIN_PREFIX}/policy/rules/order` require `admin:policy:write`. Missing authentication returns `401 Unauthorized`, and a principal without the required permission returns `403 Forbidden`.

`PUT /v1{ADMIN_PREFIX}/policy` replaces the whole policy document. It requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid policy JSON or policy validation errors return `400 Bad Request` with `{"valid":false,"errors":[...]}`. On success, the policy is persisted to `POLICY_FILE`, synchronously reloaded into the live RBAC state before the response returns, and the response includes the new ETag. A successful replace emits a `policy.changed` audit event with actor attribution, a lightweight before/after summary, and `diff_summary.action="policy_replaced"`.

`POST /v1{ADMIN_PREFIX}/policy/validate` validates a candidate whole-policy JSON document without persisting it, changing the live policy, or emitting `policy.changed`. It returns `{"valid":true}` on success or `400 Bad Request` with `{"valid":false,"errors":[...]}` on failure.

Granular rule-management endpoints mutate only the `rules` array but validate the full resulting policy before persisting. Each mutation requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid JSON, invalid rule shape, invalid reordered policy, or invalid order sets return `400 Bad Request` without partial mutation.

Rules defined directly in the policy file without an explicit `id` still use the legacy array-index fallback (see the `rules[]` schema above), not the API's generated `rule-<uuid-v4>` scheme. Their effective id shifts whenever an earlier rule in the list is deleted or the list is reordered, through this API or a direct file edit — a script that captures such a rule's effective id and reuses it across separate requests can end up addressing the wrong rule. Give a rule an explicit `id` in the policy file if you need to address it reliably by id over time; rules created through `POST /v1{ADMIN_PREFIX}/policy/rules` are unaffected, since they always receive a stable id.

`POST /v1{ADMIN_PREFIX}/policy/rules` appends one direct firewall rule. The request body is a single rule object using the documented `rules[]` shape (`methods`, `path`, `principal`, `action`, and optional `id`). If `id` is omitted, the server assigns a stable generated id using the `rule-<uuid-v4>` scheme before persisting, so API-created rules never depend on array-index fallback. If a client supplies an explicit `id` that collides with any current effective rule id, including legacy index fallback ids, the request returns `400 Bad Request`. On success it returns `201 Created` with the created rule, including its assigned or confirmed `id`, and the new ETag.

`PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}` partially updates one existing rule by effective id. The JSON body may include any of `enabled`, `methods`, `path`, `principal`, and `action`; `id` is the path identity and is not patchable. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with the updated rule and the new ETag.

`DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}` removes one existing rule by effective id. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with `{"deleted_rule_id":"..."}` and the new ETag.

`PUT /v1{ADMIN_PREFIX}/policy/rules/order` reorders the current rules. The request body is a raw JSON array of rule ids in the desired order, for example `["allow-public","deny-admin"]`. The array must be an exact permutation of the current effective rule ids: same length, no duplicates, no missing ids, and no unknown ids. Invalid sets return `400 Bad Request` with errors describing the mismatch. On success it returns `200 OK` with `{"order":[...]}` and the new ETag.

Every successful policy mutation through the admin API appends one row to policy version history. This includes whole-policy replace, rule create/update/delete/reorder, and rollback. History is append-only: rollback never deletes, rewrites, or truncates earlier versions; it restores a stored snapshot and then appends a new version whose `diff_summary` is `{"action":"policy_rolled_back","target_version":N}`. Version rows store a monotonic integer `version`, the acting principal's `user_id`, an RFC 3339 `created_at` timestamp, the structured `diff_summary`, and the full validated policy snapshot after the mutation.

Policy file persistence and live-policy reload are the commit point for policy mutations. If the policy commit succeeds but the secondary history append fails, the mutation response still uses the normal success status, body, and ETag for that endpoint, and the gateway logs a `tracing::error!` for operators. Those rare responses include `X-GreenGateway-Policy-History-Warning: policy_history_append_failed` so API clients and admin UI code can surface that this mutation may have created a hole in version history. The header is omitted in the normal case where the history row is appended successfully.

Every successful rule mutation emits `policy.changed` with actor attribution, the same lightweight `before`/`after` policy summaries and `changed_sections` used by whole-policy replace, plus a granular `diff_summary`: `{"action":"rule_created","rule_id":"...","position":N}`, `{"action":"rule_updated","rule_id":"...","changed_fields":[...]}`, `{"action":"rule_deleted","rule_id":"...","position":N}`, or `{"action":"rules_reordered","new_order":[...]}`. Whole-policy replace uses `{"action":"policy_replaced"}`. Rollback uses `{"action":"policy_rolled_back","target_version":N}`.

`GET /v1{ADMIN_PREFIX}/policy/history` lists versions newest first. It accepts `limit` and `cursor` query parameters using the same paginated shape as other admin list APIs; `limit` defaults to 50 and is capped at 500. The response is:

```json
{
  "versions": [
    {
      "version": 12,
      "actor": "user-123",
      "created_at": "2026-07-04T12:00:00Z",
      "diff_summary": {
        "action": "rule_created",
        "rule_id": "rule-...",
        "position": 3
      }
    }
  ],
  "next_cursor": "11"
}
```

By default, list entries omit full policy snapshots. Add `include_policy=true` to include each version's `policy` snapshot for detail views or verification. Invalid `limit`, `cursor`, or `include_policy` values return `400 Bad Request`.

`POST /v1{ADMIN_PREFIX}/policy/rollback/{version}` restores the exact policy snapshot stored at the given version. It is a policy write and requires `admin:policy:write` plus an exact `If-Match` header for the current live policy ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; an unknown version returns `404 Not Found` with `{"error":"policy version was not found"}`. On success, rollback persists to `POLICY_FILE`, reloads live RBAC state, appends a new history version, emits `policy.changed`, returns the restored policy JSON, and includes the new ETag.

`POST /v1{ADMIN_PREFIX}/policy/rules/preview` evaluates a candidate direct firewall rule against historical `http.request_observed` rows in the SQLite audit store without persisting it, changing the live policy, or emitting `policy.changed`. The request body is `{"rule":{...},"from":"<RFC3339>","to":"<RFC3339>","sample_limit":20}`; `rule` uses the same `rules[]` shape as the policy document, `from`/`to` are optional RFC 3339 bounds, and `sample_limit` is optional and capped at 100. The response is `{"match_count":N,"scanned_event_count":M,"sample_strategy":"newest_matches","samples":[...]}`. Samples include `event_id`, `timestamp`, `request_id`, `source_ip`, `method`, `path`, `actor`, `status`, optional `policy_decision`, and optional historical `matched_rule_id`. Preview requires `AUDIT_SQLITE_PATH`; when it is unset the endpoint returns `503 Service Unavailable` with `{"error":"policy rule preview requires AUDIT_SQLITE_PATH to be configured"}`.

`GET /v1{ADMIN_PREFIX}/policy/rules/hits` returns per-rule historical request hit counts for the current live policy as `{"rules":[{"rule_id":"...","hits":0}]}`. Counts are grouped from indexed `http.request_observed.payload_matched_rule_id` values, so each observed request contributes at most one hit and paired `authz.*` audit events are not double-counted. Rules without an explicit `id` use the same zero-based array index fallback as live RBAC audit attribution. When `AUDIT_SQLITE_PATH` is unset, the endpoint still succeeds and returns all live rules with `hits: 0`.

Concurrent policy mutations through this API are safely serialized against each other, including whole-policy `PUT` and granular rule create/update/delete/reorder. A losing request with an ETag from the same starting policy receives `412 Precondition Failed`, never a silently-overwritten update. The `If-Match` guard does not order against a direct edit of the `POLICY_FILE` on disk racing an in-flight API mutation. The file's own atomic write (temp file + rename) means a concurrent reader, including the background file watcher, never observes a torn/partial file, but if something outside this API writes to `POLICY_FILE` at the same moment an API mutation completes, the file watcher's next debounced reload may pick up either write, and the ETag a caller received may no longer describe the live policy a moment later. Treat the returned `ETag` as best-effort freshness, not a guarantee against external file edits, if anything outside this API also writes to `POLICY_FILE`.

### POLICY_HISTORY_SQLITE_PATH

Optional SQLite policy version history store path.

Default: empty. When `POLICY_FILE` is configured and `POLICY_HISTORY_SQLITE_PATH` is unset, GreenGateway opens a sibling SQLite database at `<POLICY_FILE>.history.sqlite`. When `POLICY_FILE` is unset, no policy history store is opened.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When the effective history path is available, the gateway opens or creates the database at startup and creates the `policy_versions` table and indexes if needed. Startup fails if the database cannot be opened or initialized.

This is deliberately separate from `DISCOVERY_SQLITE_PATH` and `AUDIT_SQLITE_PATH`. Policy version history is a core policy administration safety feature and is not gated by traffic discovery or audit-query storage. Operators that prefer a single SQLite file may explicitly set `POLICY_HISTORY_SQLITE_PATH` to the same path as either of those settings; policy history uses its own `policy_versions` table and remains append-only.

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

### AUTH_PROVIDERS

Ordered JSON array of authentication provider objects.

Default: empty, which means the legacy single-provider `JWT_*` settings below are used as an implicit one-entry provider named `legacy` when `JWT_JWKS_URL` is set.

Format and validation: unset, empty, or whitespace-only values use the legacy fallback. Non-empty values must be a JSON array. Each entry must include a non-empty unique `name`, `type` set to `jwt`, and at least one of `jwks_url` or `issuer`. Optional fields are `audience`, `jwks_timeout_ms`, `require_jti`, and `roles_claim`. `jwks_url`, `issuer`, and `audience` are trimmed, and blank values are treated as unset. `jwks_timeout_ms` defaults to `2000`, `require_jti` defaults to `false`, and `roles_claim` defaults to `roles`.

Example with OIDC discovery: `[{"name":"primary","type":"jwt","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"roles","require_jti":false}]`

Example with an explicit JWKS endpoint: `[{"name":"primary","type":"jwt","jwks_url":"https://idp.example.com/.well-known/jwks.json","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"roles","require_jti":false}]`

When `AUTH_PROVIDERS` is set, it defines the ordered auth provider chain and takes precedence over the legacy single-provider JWT settings for validator assembly. The legacy settings remain supported for backward compatibility.

OIDC discovery: when a provider has `issuer` but no `jwks_url`, startup fetches `{issuer}/.well-known/openid-configuration` through the egress client and uses the returned `jwks_uri` for later JWKS refreshes. Discovery failure or a discovery document without `jwks_uri` prevents the provider from being constructed.

JWT algorithms: JWKS keys with `kty` `RSA` validate RS256 tokens, `kty` `EC` with `crv` `P-256` validates ES256 tokens, and `kty` `OKP` with `crv` `Ed25519` validates EdDSA tokens. Unsupported or incomplete keys are skipped during JWKS refresh.

Egress trust: each provider `jwks_url`, and each provider `issuer` when it is a URL with a host, is automatically trusted for gateway-originated egress.

### JWT_JWKS_URL

Optional JWKS endpoint used to validate bearer JWTs.

Default: empty, which means no JWT validator is built.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode. The validator fetches public keys from this endpoint and caches them by `kid`. Supported JWKS signing keys are RSA for RS256, EC P-256 for ES256, and OKP Ed25519 for EdDSA.

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

### SERVICE_TOKEN_SQLITE_PATH

Optional SQLite store path for service tokens managed by `POST /v1{ADMIN_PREFIX}/tokens` and accepted as `ggw_` bearer credentials.

Default: empty, which disables the service-token admin API storage backend and does not add the service-token validator to the auth chain.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, GreenGateway creates or opens the SQLite database at startup and initializes the `service_tokens` table if needed.

### SERVICE_TOKEN_CACHE_TTL_MS

Service-token verification cache TTL, in milliseconds.

Default: `5000`

Format and validation: must parse as a positive `u64` millisecond duration. The validator caches successful and failed `ggw_` bearer-token verification results in-process so normal requests do not require a fresh SQLite lookup every time. Revocations or rotations performed by this process's admin API invalidate that process's cached entry immediately; revocations made outside this process or in another process take effect no later than this TTL. Keep the value short for security-sensitive deployments.

Service token admin API: when `SERVICE_TOKEN_SQLITE_PATH` and `POLICY_FILE` are configured, `POST /v1{ADMIN_PREFIX}/tokens` creates a service token and requires `admin:tokens:write`; `GET /v1{ADMIN_PREFIX}/tokens` and `GET /v1{ADMIN_PREFIX}/tokens/{id}` require `admin:tokens:read`; `DELETE /v1{ADMIN_PREFIX}/tokens/{id}` revokes a token and requires `admin:tokens:write`; `POST /v1{ADMIN_PREFIX}/tokens/{id}/rotate` rotates a token and requires `admin:tokens:write`. Create and rotate responses include the plaintext `ggw_` token exactly once with a notice that it will not be shown again. List and get responses return only token metadata. Create, revoke, and rotate emit `service_token.changed` audit events with actor attribution, token id, display prefix, scopes, and lifecycle timestamps, never plaintext tokens or token hashes.

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
- `openapi_spec_path`: filesystem path to a local OpenAPI 3.x JSON or YAML document for this upstream route's schema coverage.

Per-route header validation rejects invalid header names or values, rejects adding hop-by-hop or gateway-managed headers such as `connection`, `host`, and `content-length`, and rejects adding or stripping `x-request-id`. The gateway owns request-id propagation so audit and tracing correlation cannot be disabled by route configuration. A route also cannot add and strip the same header.

`tls_ca_bundle_path` is the supported mechanism for upstreams served by private or internal certificate authorities. Certificate verification remains strict by default, and no route inherits a custom CA unless it explicitly configures one. GreenGateway does not expose a per-route skip-verify option; use a local test CA bundle for development instead of disabling verification.

`openapi_spec_path` uses the same parser and startup validation as `OPENAPI_SPEC_PATH`. For route-table specs, coverage is scoped by `path_prefix` when a route has one. The current discovery aggregate table stores only `(method, endpoint_template)` and not the matched upstream route or request host, so host-only routes cannot yet be separated from the global observed inventory. If a route has a `path_prefix`, schema paths may be written either as gateway paths such as `/api/users/{userId}` or as upstream-local paths such as `/users/{userId}`; the coverage matcher considers both the raw spec path and the path prefixed with the route's `path_prefix`.

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
    "tls_ca_bundle_path": "/etc/greengateway/internal-ca.pem",
    "openapi_spec_path": "/etc/greengateway/api.openapi.yaml"
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

Infrastructure endpoint hosts configured elsewhere, including `UPSTREAM_URL`, every `UPSTREAM_ROUTES[].upstream_url`, configured `AUTH_PROVIDERS[].jwks_url` values, URL-shaped `AUTH_PROVIDERS[].issuer` values, `JWT_JWKS_URL`, and URL-shaped `JWT_ISSUER` values, are auto-seeded into the effective egress allowlist. This allows deployments to proxy to configured upstreams, fetch OIDC discovery documents, or validate tokens without duplicating those hosts here.

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
