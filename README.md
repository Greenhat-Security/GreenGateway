<div align="center">

![GreenGateway (GG)](docs/images/gg-cover.png)

# GreenGateway (GG)

### A universal MCP + API gateway you self-host

[![License: Source-available](https://img.shields.io/badge/License-Source--available-blue.svg?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange?style=flat-square)](#project-status)
[![Rust](https://img.shields.io/badge/built%20with-Rust-DEA584?style=flat-square&logo=rust&logoColor=black)](gateway)
[![Roadmap](https://img.shields.io/badge/roadmap-7%20phases-blueviolet?style=flat-square)](https://github.com/Greenhat-Security/GreenGateway/issues/44)
[![CI](https://img.shields.io/github/actions/workflow/status/Greenhat-Security/GreenGateway/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Greenhat-Security/GreenGateway/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**Auth, authorization, audit, and traffic visibility in front of any API or MCP server — without hand-rolling a control plane yourself.**

[What's Real Today](#whats-real-today) · [Planned Scope](#planned-scope) · [Quick Start](#quick-start) · [Architecture](#architecture-sketch) · [Contributing](#contributing)

</div>

---

> **Community project by [Greenhat-Security](https://github.com/Greenhat-Security).** GreenGateway (GG) is pre-alpha, self-hosted, and source-available under the Apache License 2.0 with the Commons Clause. It is not production ready. See [Project Status](#project-status) before evaluating it for anything real.

## Table of Contents

- [What GreenGateway Is](#what-greengateway-is)
- [Project Status](#project-status)
- [What's Real Today](#whats-real-today)
- [Planned Scope](#planned-scope)
- [Architecture Sketch](#architecture-sketch)
- [Quick Start](#quick-start)
  - [Option 1: Cargo](#option-1-cargo-for-development)
  - [Option 2: Docker Compose](#option-2-docker-compose)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

---

## What GreenGateway Is

GreenGateway — GG for short — is a source-available, self-hosted universal MCP and API gateway for teams that want authentication, authorization, traffic visibility, and a visual firewall in front of any API or MCP server, without hand-rolling that control plane themselves.

It is designed to sit between clients and existing HTTP backends or MCP servers, learn what is being used, and turn that traffic into enforceable, reviewable rules.

## Project Status

**GreenGateway is pre-alpha and under active initial development.** It is not production ready yet.

Development follows a 7-phase roadmap. **Phases 1 through 4 are complete** — a real security middleware stack, authentication, a hot-reloadable RBAC engine (including shadow-enforcement, observe-only auth modes, and data-driven direct firewall rules), an egress firewall with policy-driven overrides, a full audit/observability pipeline, a streaming reverse proxy with multi-upstream routing and per-upstream settings, a complete policy administration API (read/replace/validate, granular rule operations, and rule preview against historical traffic), and full traffic discovery — endpoint inventory, a discovery UI, OpenAPI-based and inferred schema conformance checking, and a deterministic anomaly-signal engine with detectors, admin API, SSE surfacing, and UI — all exist and run today (see [What's Real Today](#whats-real-today)). **Phases 5 through 7 are still roadmap and vision**, not shipped functionality — the visual firewall rule builder, native MCP protocol support, and the broader identity directory do not exist yet.

Progress is tracked in the pinned roadmap issue: [Roadmap / project plan (#44)](https://github.com/Greenhat-Security/GreenGateway/issues/44).

## What's Real Today

This is what's actually built, working, and covered by CI as of Phases 1 through 4:

| Area | What's implemented |
| --- | --- |
| **Gateway server** | Rust/axum binary exposing `GET /health`, `GET /version`, `GET /metrics` (Prometheus), with an optional second listener (`ADMIN_LISTEN_ADDR`) to keep the control plane off the data path |
| **Security middleware** | Request-ID + tracing, config-driven CORS, security-header hardening, token-bucket rate limiting (global lanes plus policy-driven per-principal/per-endpoint overrides), body-size/content-type validation, double-submit CSRF — in an asserted, fixed order |
| **Authentication** | A `Principal` model with pluggable session validators, plus a JWKS-backed JWT validator (RS256, configurable roles claim, issuer/audience enforcement); fails closed by default, with an `AUTH_MODE=observe` option to authenticate without blocking while rolling out credentials |
| **Authorization** | A deny-by-default RBAC policy engine with config-driven route-to-permission rules, data-driven direct firewall rules (fuzz-tested, anchored glob/`{param}` path matching, first-match-wins) with an `action: shadow` per-rule override that logs would-be denials without blocking, and hot reload (file-watch + `SIGHUP`) with validate-before-swap so an invalid edit never takes down the last-known-good policy |
| **Reverse proxy** | A multi-upstream routing table (longest-prefix and host-based selection, per-upstream timeouts, request header add/strip rules, and custom TLS trust bundles), or a single catch-all `UPSTREAM_URL` for simple deployments — all HTTP verbs, streamed responses and binary bodies, hop-by-hop header stripping, request-id propagation, a 502/504 error taxonomy, per-upstream health reporting, and upstream latency recorded on every observation event. Gateway-owned routes (health/version/metrics, the admin UI and its API) always take precedence over the proxy, and the admin surface's own path is remappable via `ADMIN_PREFIX` |
| **Egress firewall** | An SSRF-hardened outbound HTTP client: host allowlisting (including policy-driven wildcard host globs and CIDR-scoped private-IP exceptions), private/special-use IP blocking (including IPv4-mapped-IPv6/NAT64), pinned-IP resolution with a fresh, per-request DNS resolve to close rebinding windows |
| **Audit pipeline** | A versioned audit-event envelope with SHA-256 redaction, delivered asynchronously off the request hot path |
| **Queryable audit store** | A SQLite audit sink (batched writes, retention pruning) with an admin API — `GET /v1/admin/audit` — supporting time-range, event-type, actor, path, and status filters with keyset pagination |
| **Live event feed** | Server-Sent Events at `GET /v1/admin/events/stream`, backed by an in-process broadcast sink with backpressure handling |
| **Policy administration** | A complete policy CRUD API: whole-policy read/replace/validate (ETag-guarded against concurrent edits), granular per-rule create/update/delete/reorder operations with an audit trail, and rule preview — evaluate a candidate rule against historical traffic before committing it, plus per-rule historical hit counts — all through protected, permission-gated `/v1/admin/policy*` APIs |
| **Endpoint discovery** | Path templating that normalizes concrete request paths into stable endpoint shapes (`/users/123` → `/users/{id}`) with cardinality-explosion guards, and a background aggregator that rolls per-endpoint call counts, status distribution, latency percentiles, and distinct-principal counts into a queryable SQLite store — entirely off the request hot path |
| **Traffic endpoint inventory** | Optional SQLite discovery aggregation (`DISCOVERY_SQLITE_PATH`) with admin APIs for listing endpoint templates, viewing per-endpoint principals, time-series counts, recent raw events, review state, "new since" lifecycle flags, and active-policy direct-rule coverage |
| **Schema awareness** | Optional OpenAPI 3.x ingestion per upstream matched against observed endpoints (undocumented endpoints, unused operations); opt-in, off-by-default, redaction-aware payload-shape sampling (`PAYLOAD_CAPTURE_ENABLED`); request-shape inference from captured samples when no spec is configured; and request-time conformance checking that flags missing required query params/JSON body keys or undocumented calls, rolling up a `schema_mismatch_count` per endpoint |
| **Anomaly signals** | A deterministic (not ML) signal engine with lifecycle (open/acknowledged/dismissed) and structured evidence, evaluated entirely off the request hot path: `new_endpoint_seen`, `schema_mismatch`, `error_rate_spike`, `principal_new_to_endpoint`, and `volume_outlier`, each with configurable thresholds; an admin API to list/filter/acknowledge/dismiss; and live `signal.opened`/`signal.lifecycle_changed` events on the SSE feed |
| **Admin UI** | An embedded Vite + React + TypeScript app, built into the binary and served at `/admin` (or `ADMIN_PREFIX`): a log explorer, live tail, a traffic inventory table and per-endpoint drill-down (with schema-mismatch and signal badges), a signals view (filter, evidence, acknowledge/dismiss, live updates), and a status page reporting real running-config values |
| **Local dev harness** | Checked-in JWKS/RBAC fixtures, a `docker-compose.dev.yml` profile that brings up a fully authenticated gateway with a sample echo upstream in one command, and a traffic-generator/CI smoke test |

None of this requires a real backend to try — the dev harness in [Quick Start](#quick-start) is self-contained.

## Planned Scope

Everything below is roadmap and vision beyond what's listed in [What's Real Today](#whats-real-today) — mostly **not yet implemented**, except where a phase is explicitly marked in progress. It is what GreenGateway is being built toward, tracked phase-by-phase in the [pinned roadmap issue](https://github.com/Greenhat-Security/GreenGateway/issues/44):

| Phase | Capability | Status |
| --- | --- | --- |
| 5 | **Visual firewall-style rule builder** — inspect discovered traffic, create rules in one click, review policy in shadow mode, roll back through versioned policy history | Not started |
| 6 | **Native MCP support** — speak the real MCP protocol instead of a bespoke REST facade, with a dynamic tool registry, JSON Schema validation, and OpenAPI-to-tools generation | Not started |
| 7 | **Identity directory & broader IdP integration** — pluggable OIDC/cookie-session identity providers beyond the current JWT/JWKS validator, plus a Layer-7-firewall-style directory of every user and bot that has traversed the gateway | Not started |

Do not evaluate GG today assuming any capability not explicitly listed in [What's Real Today](#whats-real-today) already works.

## Architecture Sketch

```text
client
  |
  v
GreenGateway
  |-- auth: authenticate the caller
  |-- authz/policy: evaluate RBAC and rules-as-data
  |-- proxy/MCP: forward HTTP traffic or handle MCP protocol flows
  |-- audit: record identity, request, decision, and outcome
  |
  v
your backend API or MCP server
```

The HTTP half of the proxy layer above is real today — multi-upstream routing (or a single catch-all `UPSTREAM_URL`) forwards traffic, and rules-as-data (policy-driven RBAC and direct firewall rules, evaluated and hot-reloadable through a full CRUD API) governs what's allowed. The MCP-protocol half is still ahead, targeted for Phase 6 — see [What's Real Today](#whats-real-today) for exactly what's implemented now.

## Quick Start

GreenGateway currently includes a gateway server with `GET /health`, `GET /version`, `GET /metrics`, an embedded admin UI at `/admin` (traffic inventory, signals, log explorer, live tail, status), a working reverse proxy — either a single catch-all `UPSTREAM_URL` or a full multi-upstream routing table — and optional traffic discovery (endpoint inventory, schema awareness, anomaly signals) when `DISCOVERY_SQLITE_PATH` is set (see [What's Real Today](#whats-real-today)). The visual rule-builder and remaining capabilities described in [Planned Scope](#planned-scope) are still pre-alpha roadmap work.

For the full list of environment variables, see [docs/configuration.md](docs/configuration.md). As more variables land, that document and [.env.example](.env.example) are kept in sync with the code by an automated test.

### Option 1: Cargo (for development)

Local builds require Rust plus Node.js and npm on `PATH`, because `cargo build --workspace` builds and embeds the admin UI. This scaffold was tested with Node.js `v24.15.0` and npm `11.12.1`.

`.env.example` documents the available environment variables and defaults; to override one today, set it in the real shell/process environment rather than sourcing a `.env` file.

```sh
cargo build --workspace
cargo run

# Or, with a non-default listen address:
LISTEN_ADDR=127.0.0.1:9090 cargo run
```

In another terminal:

```sh
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

The embedded admin UI shell is available at:

```sh
curl http://localhost:8080/admin
```

For frontend development with hot reload, run the backend and Vite dev server side by side:

```sh
cargo run
```

```sh
cd admin-ui
npm ci
npm run dev
```

Then open `http://127.0.0.1:5173/admin/`. The Vite dev server proxies `/v1/admin` requests to `http://127.0.0.1:8080` by default; set `GREENGATEWAY_BACKEND_URL` before `npm run dev` to target a different backend.

### Option 2: Docker Compose

```sh
docker compose up --build
```

In another terminal:

```sh
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

For a seeded local development stack with JWT auth, RBAC, a JWKS sidecar, the embedded admin UI, and queryable SQLite audit storage, run:

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This dev stack serves the checked-in local JWKS fixture from `dev/jwks/`, starts an internal-only echo upstream behind the gateway, loads `dev/policy.json`, and writes queryable audit events to an ephemeral SQLite database inside the gateway container. The admin UI shell remains available without a token at `http://localhost:8080/admin`; protected admin APIs and the seeded `/__dev-echo` proxy path require a dev JWT signed with `dev/jwks/dev-signing-key.pem`.

To exercise the authenticated dev stack, including an end-to-end proxy request to the echo upstream, run:

```sh
node scripts/generate-traffic.mjs --smoke-test
```

## Configuration

GreenGateway reads all configuration from environment variables — no config files are required to run it. Every variable is documented with defaults, format, and validation behavior in [docs/configuration.md](docs/configuration.md), including:

- Server binding (`LISTEN_ADDR`)
- Auth (`JWT_JWKS_URL`, `JWT_ISSUER`, `JWT_AUDIENCE`, `ROLES_CLAIM`, `AUTH_MODE`, ...)
- RBAC (`POLICY_FILE`, `RBAC_EXEMPT_PATHS`)
- Reverse proxy (`UPSTREAM_URL`, `ADMIN_PREFIX`)
- Rate limiting, CORS, CSRF, and body validation
- Egress firewall (`EGRESS_ALLOWED_HOSTS`, `EGRESS_DENY_PRIVATE_IPS`, ...)
- Audit sinks (`AUDIT_LOG_FILE`, `AUDIT_SQLITE_PATH`, `AUDIT_SQLITE_RETENTION_DAYS`)

For real deployments that want to enable RBAC without immediately blocking unmatched traffic, start from [docs/examples/policy.starter.json](docs/examples/policy.starter.json) — see [docs/examples/policy.starter.README.md](docs/examples/policy.starter.README.md) for what `default_action: "allow"` does and doesn't protect against.

`docs/configuration.md` and `.env.example` are kept in sync with the actual code by an automated CI drift test, so they should never silently fall out of date.

## Contributing

GreenGateway is a pre-alpha project — contributions may involve documentation, governance, and architecture work as much as implementation. Full guidelines live in [CONTRIBUTING.md](CONTRIBUTING.md).

Work is tracked as checklist items on GitHub issues, one issue per feature area, sized so each checklist item maps to one focused pull request. Start with the pinned roadmap to find open work: [Roadmap / project plan (#44)](https://github.com/Greenhat-Security/GreenGateway/issues/44).

Security-relevant changes — auth, RBAC, egress controls, audit behavior, secrets handling, policy evaluation — receive extra review scrutiny. Please report suspected vulnerabilities per [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

This project is source-available under the [Apache License 2.0 with the Commons Clause](LICENSE). You may use, fork, and modify the software for personal or internal business use. You may not sell, resell, host, offer, or provide this software, or a substantially similar derivative, as a paid product, hosted SaaS, support offering, or commercial service without a separate commercial license from the copyright holder.

Commercial SaaS, resale, paid hosting, managed service, or paid support usage requires a separate written commercial license. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

---

<div align="center">

Maintained by [Greenhat-Security](https://github.com/Greenhat-Security) · [Issues](https://github.com/Greenhat-Security/GreenGateway/issues) · [Roadmap](https://github.com/Greenhat-Security/GreenGateway/issues/44)

</div>
