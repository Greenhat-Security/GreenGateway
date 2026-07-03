<div align="center">

# GreenGateway (GG)

### A universal MCP + API gateway you self-host

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange?style=flat-square)](#project-status)
[![Rust](https://img.shields.io/badge/built%20with-Rust-DEA584?style=flat-square&logo=rust&logoColor=black)](gateway)
[![Roadmap](https://img.shields.io/badge/roadmap-7%20phases-blueviolet?style=flat-square)](https://github.com/Greenhat-Security/GreenGateway/issues/44)
[![CI](https://img.shields.io/github/actions/workflow/status/Greenhat-Security/GreenGateway/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Greenhat-Security/GreenGateway/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**Auth, authorization, audit, and traffic visibility in front of any API or MCP server — without hand-rolling a control plane yourself.**

[What's Real Today](#whats-real-today) · [Planned Scope](#planned-scope) · [Quick Start](#quick-start) · [Architecture](#architecture-sketch) · [Contributing](#contributing)

</div>

---

> **Community project by [Greenhat-Security](https://github.com/Greenhat-Security).** GreenGateway (GG) is pre-alpha, self-hosted, and licensed under GPL-3.0. It is not production ready. See [Project Status](#project-status) before evaluating it for anything real.

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

GreenGateway — GG for short — is an open-source, self-hosted universal MCP and API gateway for teams that want authentication, authorization, traffic visibility, and a visual firewall in front of any API or MCP server, without hand-rolling that control plane themselves.

It is designed to sit between clients and existing HTTP backends or MCP servers, learn what is being used, and turn that traffic into enforceable, reviewable rules.

## Project Status

**GreenGateway is pre-alpha and under active initial development.** It is not production ready yet.

Development follows a 7-phase roadmap. **Phases 1 and 2 are complete** — a real security middleware stack, authentication, RBAC, an egress firewall, and a full audit/observability pipeline all exist and run today (see [What's Real Today](#whats-real-today)). **Phases 3 through 7 are still roadmap and vision**, not shipped functionality — most notably the actual reverse-proxy-to-any-backend capability, native MCP protocol support, and the visual firewall rule builder do not exist yet.

Progress is tracked in the pinned roadmap issue: [Roadmap / project plan (#44)](https://github.com/Greenhat-Security/GreenGateway/issues/44).

## What's Real Today

This is what's actually built, working, and covered by CI as of Phases 1-2:

| Area | What's implemented |
| --- | --- |
| **Gateway server** | Rust/axum binary exposing `GET /health`, `GET /version`, `GET /metrics` (Prometheus) |
| **Security middleware** | Request-ID + tracing, config-driven CORS, security-header hardening, token-bucket rate limiting, body-size/content-type validation, double-submit CSRF — in an asserted, fixed order |
| **Authentication** | A `Principal` model with pluggable session validators, plus a JWKS-backed JWT validator (RS256, configurable roles claim, issuer/audience enforcement); fails closed by default |
| **Authorization** | A deny-by-default RBAC policy engine with config-driven route-to-permission rules and segment-aware path matching |
| **Egress firewall** | An SSRF-hardened outbound HTTP client: host allowlisting, private/special-use IP blocking (including IPv4-mapped-IPv6/NAT64), pinned-IP resolution |
| **Audit pipeline** | A versioned audit-event envelope with SHA-256 redaction, delivered asynchronously off the request hot path |
| **Queryable audit store** | A SQLite audit sink (batched writes, retention pruning) with an admin API — `GET /v1/admin/audit` — supporting time-range, event-type, actor, path, and status filters with keyset pagination |
| **Live event feed** | Server-Sent Events at `GET /v1/admin/events/stream`, backed by an in-process broadcast sink with backpressure handling |
| **Admin UI** | An embedded Vite + React + TypeScript app, built into the binary and served at `/admin`: a log explorer, a live tail, and a status page reporting real running-config values |
| **Local dev harness** | Checked-in JWKS/RBAC fixtures, a `docker-compose.dev.yml` profile that brings up a fully authenticated gateway in one command, and a traffic-generator/CI smoke test |

None of this requires a real backend to try — the dev harness in [Quick Start](#quick-start) is self-contained.

## Planned Scope

Everything below is roadmap and vision — **not yet implemented**. It is what GreenGateway is being built toward, tracked phase-by-phase in the [pinned roadmap issue](https://github.com/Greenhat-Security/GreenGateway/issues/44):

| Phase | Capability | Status |
| --- | --- | --- |
| 3 | **Universal HTTP reverse proxy** — place GG in front of any HTTP backend, starting default-allow for discovery, then tightening through policy over time | Not started |
| 4 | **Traffic discovery** — automatic endpoint inventory, schema conformance checks against observed traffic, anomaly signals | Not started |
| 5 | **Visual firewall-style rule builder** — inspect discovered traffic, create rules in one click, review policy in shadow mode, roll back through versioned policy history | Not started |
| 6 | **Native MCP support** — speak the real MCP protocol instead of a bespoke REST facade, with a dynamic tool registry, JSON Schema validation, and OpenAPI-to-tools generation | Not started |
| 7 | **Identity directory & broader IdP integration** — pluggable OIDC/cookie-session identity providers beyond the current JWT/JWKS validator, plus a Layer-7-firewall-style directory of every user and bot that has traversed the gateway | Not started |

Do not evaluate GG today assuming any of the above already works — it doesn't yet.

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

The proxy/MCP layer above is the Phase 3/6 target shape. Today, that position in the request path is a placeholder — see [What's Real Today](#whats-real-today) for what actually runs in front of it.

## Quick Start

GreenGateway currently includes a minimal gateway server with `GET /health`, `GET /version`, `GET /metrics`, and an embedded admin UI shell at `/admin`. The broader gateway, auth, policy, and discovery capabilities described in [Planned Scope](#planned-scope) are still pre-alpha roadmap work.

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

This dev stack serves the checked-in local JWKS fixture from `dev/jwks/`, loads `dev/policy.json`, and writes queryable audit events to an ephemeral SQLite database inside the gateway container. The admin UI shell remains available without a token at `http://localhost:8080/admin`; protected admin APIs require a dev JWT signed with `dev/jwks/dev-signing-key.pem`.

## Configuration

GreenGateway reads all configuration from environment variables — no config files are required to run it. Every variable is documented with defaults, format, and validation behavior in [docs/configuration.md](docs/configuration.md), including:

- Server binding (`LISTEN_ADDR`)
- Auth (`JWT_JWKS_URL`, `JWT_ISSUER`, `JWT_AUDIENCE`, `ROLES_CLAIM`, ...)
- RBAC (`POLICY_FILE`, `RBAC_EXEMPT_PATHS`)
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

GreenGateway is licensed under [GPL-3.0](LICENSE).

---

<div align="center">

Maintained by [Greenhat-Security](https://github.com/Greenhat-Security) · [Issues](https://github.com/Greenhat-Security/GreenGateway/issues) · [Roadmap](https://github.com/Greenhat-Security/GreenGateway/issues/44)

</div>
