# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Each phase is versioned as it completes (`0.1` for Phase 1, `0.2` for Phase 2,
`0.3` for Phase 3, `0.4` for Phase 4, … `1.0` once all 7 phases land) — see the
[pinned roadmap issue](https://github.com/Greenhat-Security/GreenGateway/issues/44)
for full phase-by-phase status.

### Changed — breaking

- `GET /v1{ADMIN_PREFIX}/audit`, `GET /v1{ADMIN_PREFIX}/events/stream`, and
  `GET /v1{ADMIN_PREFIX}/status` now require a configured `POLICY_FILE` and
  the granular permissions `admin:audit:read`, `admin:audit:stream`, and
  `admin:status:read` respectively, matching every other admin endpoint's
  authorization pattern. Previously these three routes used a separate,
  hardcoded check for a role literally named `admin` on the principal, with
  no dependency on `POLICY_FILE` at all. **If you run these three endpoints
  today with a JWT/OIDC role mapped to `admin` but no `POLICY_FILE`
  configured, they will start returning `404 Not Found` after upgrading** —
  add a policy file granting the appropriate role the new permission
  strings (or `*`) to restore access.

## [0.5.0] - 2026-07-04

### Added — Phase 5 (visual rule builder)

- Rule suggestions from observed traffic: a suggestion engine (evaluated
  off the request hot path) generating baseline `allow` suggestions from the
  observed role/endpoint matrix and anomaly-derived `deny`/`shadow`
  suggestions from open discovery signals, deduplicated against existing
  policy coverage. An admin API (`GET /v1{ADMIN_PREFIX}/suggestions`,
  `POST .../accept`, `POST .../dismiss`) requires `admin:suggestions:read`/
  `admin:suggestions:write`; accepting a suggestion additionally requires
  `admin:policy:write` since it creates a real policy rule.
- Visual rule builder UI: an ordered rule table (drag-reorder, enable/disable
  toggles, per-rule hit counts, action color coding, default-action banner)
  and a rule editor (visual matcher builder for method/path/principal/action
  with inventory-backed path hints, a debounced live preview against
  historical traffic before saving) — full rule lifecycle (create, edit,
  reorder, disable, delete) without touching JSON. One-click "create rule"
  actions from a traffic inventory endpoint, a live-tail event, or an
  anomaly signal pre-fill the editor's matcher fields; signal-originated
  rules default to `shadow` so their impact can be previewed before
  enforcing.
- Policy versioning, diff, and rollback: every policy mutation (rule
  create/patch/delete/reorder, full-document replace, and rollback itself)
  appends an append-only version record (actor, timestamp, structured diff)
  to a dedicated SQLite store; `GET /v1{ADMIN_PREFIX}/policy/history` and
  `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}` expose it, with a
  version-history timeline UI (human-readable per-action diff sentences,
  one-click rollback validated against the current live policy ETag). A
  history-store write failure never turns an already-successful policy
  mutation into an error response — it's surfaced as a non-fatal
  `X-GreenGateway-Policy-History-Warning` response header instead.
- Shadow-mode review workflow: a review queue over the direct-firewall-rule
  engine's live `action: shadow` enforcement (rules are evaluated before the
  route-permission model; a matching shadow rule forwards the request and
  emits a real `authz.would_deny` audit event carrying the matched rule's
  id). `GET /v1{ADMIN_PREFIX}/policy/rules/shadow-review` aggregates, per
  currently-enabled shadow rule, a would-deny count, distinct affected
  principals, and sample requests in a single bounded scan; the UI adds
  one-click Promote (shadow → deny, gated behind an explicit confirmation
  step since it starts enforcing real blocks) and Disable actions.

### Fixed

- Firewall rules and rate-limit overrides with a path segment that looks like
  a capture but isn't valid (e.g. `/api/{bad-name}`, an unterminated
  `/api/{id`, or an empty `/api/{}`) are now rejected at policy-validation
  time instead of being silently persisted as a rule that can never match any
  request. Previously such a rule would save successfully and appear normal
  in the admin UI while providing no actual coverage.

## [0.4.0] - 2026-07-04

### Added — Phase 4 (traffic discovery)

- Endpoint path templating: normalizes concrete request paths into stable
  endpoint shapes (`/users/123` → `/users/{id}`), with well-known-ID
  recognition (numeric/UUID/hex-hash/ULID) plus a stateful, cardinality-bounded
  learner for slug-style segments.
- A background endpoint-discovery aggregator (`DISCOVERY_SQLITE_PATH`),
  running entirely on the existing off-hot-path audit-log-writer thread: per
  `(method, endpoint_template)` call counts, first/last-seen, latency
  percentiles (p50/p95/p99) via a bounded reservoir, status-code
  distribution, and distinct-principal counts.
- Traffic inventory admin API: `GET /v1{ADMIN_PREFIX}/traffic/endpoints`
  (filter/sort/paginate) and `GET /v1{ADMIN_PREFIX}/traffic/endpoint` (detail,
  with audit-enriched time-series and recent events when `AUDIT_SQLITE_PATH`
  is also configured), plus `POST /v1{ADMIN_PREFIX}/traffic/endpoints/review`
  to mark/clear a persisted per-endpoint review flag. Endpoint lifecycle
  fields — `is_new` (configurable window), `reviewed`, and `covered_by_rule`
  (evaluated live against the active RBAC policy) — are independent booleans,
  not a single enum.
- Discovery UI: an embedded traffic inventory table (filters, cursor
  pagination, new/uncovered/reviewed badges, mark/clear review action) and a
  per-endpoint drill-down page (status/latency charts, principal breakdown,
  audit time-series and recent events with honest truncation/omission
  disclosure when audit enrichment isn't available).
- Schema awareness: optional OpenAPI 3.x ingestion per upstream, matched
  against observed endpoints to surface undocumented endpoints and unused
  spec operations; opt-in (`PAYLOAD_CAPTURE_ENABLED`), off-by-default,
  redaction-aware sampled request-shape capture with no request/response
  bodies stored unless explicitly enabled; request-shape inference (query
  params, JSON body top-level structure) from captured samples when no spec
  is configured; and request-time conformance checking — spec-based when a
  spec is configured, inference-based otherwise once enough samples exist —
  flagging missing required query params/JSON body keys or undocumented
  calls as `schema_mismatch` on the observation event, rolled up into a
  persisted `schema_mismatch_count` per endpoint. Conformance checking uses a
  short-TTL in-memory cache for the inferred-schema lookup path so it never
  re-scans the discovery database or re-parses historical samples on every
  request.
- Anomaly signals v1: a deterministic (not ML) signal engine — evaluated
  entirely on the background aggregator thread, never inline in request
  handling — with a generic `Signal` model (type, target, explanation,
  structured evidence, lifecycle: open/acknowledged/dismissed) and
  duplicate-prevention via a unique `(signal_type, target_kind, target_key)`
  constraint. Five detectors ship: `new_endpoint_seen`, `schema_mismatch`,
  `error_rate_spike` (recent-vs-baseline delta), `principal_new_to_endpoint`
  (a principal's first call to an endpoint with existing history from other
  principals), and `volume_outlier` (windowed baseline deviation) — each with
  its own configurable, validated threshold. An admin API
  (`GET /v1{ADMIN_PREFIX}/signals`, `POST .../acknowledge`,
  `POST .../dismiss`) requires the dedicated `admin:signals:read`/
  `admin:signals:write` permissions; a summarized `open_signals` field on the
  traffic inventory endpoints requires the same `admin:signals:read`
  permission in addition to `admin:traffic:read`, computed via a single
  set-based query per page rather than one query per endpoint. `signal.opened`
  and `signal.lifecycle_changed` events are pushed on the existing SSE feed,
  and a new admin UI Signals view (filter, evidence display,
  acknowledge/dismiss, live updates) plus signal badges on the traffic
  inventory surface all of the above.

## [0.3.0] - 2026-07-03

### Added — Phase 3 (core gateway)

- A reverse proxy to a configured upstream — all HTTP verbs, streamed
  responses and binary bodies, hop-by-hop header stripping, request-id
  propagation, a 502/504 error taxonomy, and upstream latency recorded on
  every observation event.
- Reserved-prefix protection: gateway-owned routes always take precedence
  over the reverse proxy, with a remappable admin surface path via
  `ADMIN_PREFIX`, and an optional second listener (`ADMIN_LISTEN_ADDR`) to
  keep the control plane off the data path entirely.
- Multi-upstream routing: a routing table with longest-prefix and
  host-based upstream selection, per-upstream timeouts, per-upstream
  request header add/strip rules, custom TLS trust bundles, and per-upstream
  health reporting.
- Egress-allowlist auto-seeding: a configured upstream's host is
  automatically trusted for egress without needing to be duplicated in
  `EGRESS_ALLOWED_HOSTS`; private-IP blocking remains a separate,
  unaffected check.
- Policy modes: `default_action: allow|deny`, an `enforcement_mode: shadow`
  per-rule override that observes would-be denials without blocking, and an
  `AUTH_MODE: observe` option to authenticate without blocking while rolling
  out credentials.
- Firewall rules as data: a fuzz-tested rule matcher (anchored glob and
  `{param}` path segments, first-match-wins), a hardened rule schema, and an
  `action: shadow` per-rule override, wired into the live request path
  alongside the existing route-permission RBAC engine.
- Hot-reloadable RBAC policy: file-watch and `SIGHUP` triggers, atomic
  validate-before-swap (an invalid edit is rejected and the last-known-good
  policy keeps serving, with zero dropped requests), and an atomic
  temp-file-plus-rename persistence primitive underpinning the policy-editing
  APIs below.
- A complete policy administration API under `/v1/admin/policy*`: whole-policy
  read/replace/validate guarded by ETag/`If-Match` against concurrent edits;
  granular per-rule create/update/delete/reorder operations that emit a
  `policy.changed` audit trail; rule preview (evaluate a candidate rule
  against historical audit traffic before committing it, reusing the same
  fuzz-tested matcher); and per-rule historical hit counts.
- Policy-driven egress controls: wildcard host globs and CIDR-scoped
  private-IP exceptions on top of the existing SSRF-hardened client, with a
  fresh per-request DNS resolve to close rebinding windows.
- Policy-driven rate-limit overrides: per-principal and per-endpoint limiter
  rules with principal-first keying, falling back to the existing global
  read/write lanes when no override matches.

## [0.2.0] - 2026-07-03

### Added — Phase 2 (dev visibility)

- Observation events: a `http.request_observed` event emitted for every request
  (method, path, status, latency, auth outcome, matched policy decision),
  positioned to wrap rate-limiting, validation, CSRF, auth, and RBAC so it
  fires even for rejected requests.
- A SQLite audit sink (batched writes, retention pruning, durable across
  restarts) and an admin-role-gated query API (`GET /v1/admin/audit`) with
  time-range/event-type/actor/path/status filters and keyset pagination.
- A live SSE event feed (`GET /v1/admin/events/stream`) backed by an in-process
  broadcast sink, with backpressure handling so a stalled consumer never
  blocks request processing.
- An embedded admin UI (Vite + React + TypeScript, built into the binary and
  served at `/admin`): a log explorer over the query API, a live tail over the
  SSE feed, and a status page reporting real running-config values (version,
  uptime, RBAC/audit-sink/rate-limit state) — never hardcoded.
- A local dev harness: a checked-in JWKS fixture and seeded RBAC policy, a
  `docker-compose.dev.yml` profile bringing up a fully authenticated gateway
  in one command, and a traffic generator doubling as a CI smoke test that
  asserts real observation/auth/authz events appear for a varied request mix.

## [0.1.0] - 2026-07-03

### Added — Phase 1 (source-available foundation)

- Project scaffolding: README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue/PR
  templates, `.gitignore`, `.editorconfig`, AGENTS.md, architecture docs, and
  founding ADRs (HTTP-upstreams-only scope; single-tenant-per-deployment).
- Cargo workspace with a `gateway` binary exposing `/health`, `/version`, and
  `/metrics` (Prometheus); CI (fmt, clippy, test, `cargo-audit`), a multi-stage
  container image with GHCR publishing, gitleaks secret scanning, and a documented
  release process.
- Unified environment-variable configuration with aggregated startup validation,
  a self-verifying `.env.example`, and a drift-checked configuration reference.
- Security middleware stack: request-ID + tracing, config-driven CORS, header
  hardening (spoofable-identity stripping), body-size/content-type validation,
  token-bucket rate limiting with a spoofing-resistant canonical client IP, and
  double-submit CSRF — with an asserted middleware order.
- Authentication: a `Principal` model and pluggable `SessionValidator`s, a JWKS
  JWT validator (RS256, configurable roles claim, issuer/audience enforcement),
  and a fail-closed global auth middleware emitting auth audit events.
- Authorization: a deny-by-default RBAC policy engine with config-driven
  route→permission rules (segment-aware matching, unsafe-path fail-close) and
  authz audit events.
- Audit pipeline: a versioned event envelope with SHA-256 redaction, and
  asynchronous stdout/file JSONL sinks off the request hot path.
- Egress firewall: an SSRF-hardened outbound HTTP client (host allowlist,
  private-IP blocking including IPv4-mapped-IPv6/NAT64, pinned-IP resolution),
  with all gateway-originated HTTP routed through it and enforced by CI.
