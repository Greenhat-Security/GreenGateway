# ADR-0003: Admin UI Stack And Embedding

## Status

Accepted

## Context

Phase 2 adds developer visibility features through an embedded admin UI. This is the first frontend code in GreenGateway, so the stack, production embedding model, and local development workflow need to be explicit before the log explorer, live tail, and status views land.

The UI shell must be reachable before the operator has pasted a bearer token. Until admin SSO lands in Phase 7, the UI stores that pasted token in browser session storage and attaches it to admin API calls. The static shell contains no secrets; the security boundary remains the admin-role checks on the admin API endpoints, which default to `/v1/admin/audit` and `/v1/admin/events/stream`.

## Decision

GreenGateway's admin UI is a separate top-level `admin-ui/` npm project using **Vite + React + TypeScript**. It is not a Cargo workspace member.

Production UI assets are built into `admin-ui/dist/` and embedded in the `gateway` binary with `rust-embed`. The gateway serves the static shell at the configured admin prefix and its subpaths, defaulting to `/admin` and `/admin/*`, with SPA fallback to `index.html` for client-side routes. The admin shell path is exempt from auth and RBAC middleware because it contains no secrets and must show the token entry flow. Admin data APIs remain protected by their existing admin-role checks.

The `gateway` Cargo build script runs `npm ci` and `npm run build` in `admin-ui/`, so `cargo build --workspace` from a fresh checkout produces a binary with embedded UI assets when Node.js and npm are available on `PATH`.

Local frontend development uses Vite's own dev server and `server.proxy` configuration. Contributors run `cargo run` for the backend and `npm run dev` in `admin-ui/` for hot reload, then visit the Vite dev server directly. GreenGateway does not include a Rust-side proxy to Vite.

## Consequences

Building the gateway now requires Node.js and npm in addition to the Rust toolchain. This keeps production builds reproducible and avoids a manual UI build step.

The Vite dev-server proxy keeps frontend iteration separate from the gateway's egress-only HTTP client guard. No additional Rust outbound HTTP dependency or reverse-proxy path is introduced for development.

Later admin UI PRs can add routes and shared frontend API clients without revisiting the stack or embedding model. Backend authorization stays centralized in the existing admin API handlers rather than in the static shell.
