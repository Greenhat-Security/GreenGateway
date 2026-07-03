# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 1 (open-source-ready foundation)

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

Later phases (the universal reverse proxy, traffic discovery, the visual rule
builder, MCP support, and identity integrations) are tracked in the roadmap.
