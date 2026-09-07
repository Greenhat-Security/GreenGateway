# ADR-0003: Admin UI Stack And Embedding

## Status

Accepted

## Context

Phase 2 adds developer visibility features through an embedded admin UI. This is the first frontend code in GreenGateway, so the stack, production embedding model, and local development workflow need to be explicit before the log explorer, live tail, and status views land.

The UI shell must be reachable before the operator has pasted a bearer token. Until admin SSO lands in Phase 7, the UI stores that pasted token in browser session storage and attaches it to admin API calls. The static shell contains no secrets; the security boundary remains the admin-role checks on the admin API endpoints, which default to `/v1/admin/audit` and `/v1/admin/events/stream`.

## Decision

GreenGateway's admin UI is a separate top-level `admin-ui/` npm project using **Vite + React + TypeScript**. It is not a Cargo workspace member.

Production UI assets are built into `admin-ui/dist/` and embedded in the `gateway` binary with `rust-embed`. The gateway serves the static shell at the configured admin prefix and its subpaths, defaulting to `/admin` and `/admin/*`, with SPA fallback to `index.html` for client-side routes. The admin shell path is exempt from auth and RBAC middleware because it contains no secrets and must show the token entry flow. Admin data APIs remain protected by their existing admin-role checks.

The `gateway` Cargo build script runs the reviewed npm installer (`scripts/npm-script-policy.mjs`) and `npm run build` in `admin-ui/`, so `cargo build --workspace` from a fresh checkout produces a binary with embedded UI assets when Node.js and npm are available on `PATH`.

Local frontend development uses Vite's own dev server and `server.proxy` configuration. Contributors run `cargo run` for the backend and `npm run dev` in `admin-ui/` for hot reload, then visit the Vite dev server directly. GreenGateway does not include a Rust-side proxy to Vite.

## Consequences

Building the gateway now requires Node.js and npm in addition to the Rust toolchain. This keeps production builds reproducible and avoids a manual UI build step.

The Vite dev-server proxy keeps frontend iteration separate from the gateway's egress-only HTTP client guard. No additional Rust outbound HTTP dependency or reverse-proxy path is introduced for development.

Later admin UI PRs can add routes and shared frontend API clients without revisiting the stack or embedding model. Backend authorization stays centralized in the existing admin API handlers rather than in the static shell.

## Server-provided admin permissions

The admin UI uses the existing authenticated `GET /v1{ADMIN_PREFIX}/capabilities`
endpoint for global permission affordances. It does not decode JWT roles or fetch
policy to infer permissions. JWT, opaque service-token, and cookie sessions use
the same permission checks and the existing bearer/cookie/CSRF transport.

| Consumer | Server permission used |
| --- | --- |
| Identities | `admin:principals:read` |
| Cluster | `admin:cluster:read` |
| Service tokens | `admin:tokens:write` |
| OpenAPI tool registration | `admin:tools:write` |

`useAdminCapabilities` shares one active request across mounted consumers. Its
states are loading, ready, unauthenticated (401), forbidden (403), and unavailable
(network failure, timeout, 503, or malformed response). Only a ready response
containing the exact permission enables a global mutation affordance. Loading and
error states have accessible explanations; errors offer a retry button. Requests
use `cache: no-store` and time out after ten seconds. URLs use the runtime admin
API prefix on the management UI's origin, including split-listener deployments.

The state is discarded when the last consumer unmounts. A new mount requests
fresh capabilities. While mounted, focus, navigation, manual retries, successful
local policy mutations, and resource authorization failures invalidate grants;
refreshes coalesce to at most one request per five seconds. Visible pages also
refresh every sixty seconds. Hidden pages discard their grants and suspend
refreshes until visible. An in-flight refresh already satisfies focus/navigation.
This bounds how long an external policy change can leave old affordances visible;
the backend independently authorizes every action during that interval.

Successful bearer save/clear and auth callback/logout integration notify an
identity generation shared by the transport and UI shell. A new identity clears
grants immediately, starts a fresh request without the old identity's delay, and
remounts protected routes to clear data, drafts, and one-time token displays. The
transport rejects late responses from previous generations. A 401 invalidates
identity state once per authentication failure episode; canceled requests cannot
invalidate the active session. A successful capabilities response allows a later
401 to invalidate a recovered cookie session again. An expired session replaces
the protected route with a focused sign-in notice; Check session explicitly
rechecks an externally renewed cookie session. A 503 never means logout.
No browser-readable identity identifier or policy contents are added to the API.
HttpOnly cookie changes outside this UI are discovered on the next bounded
capability refresh; they are not directly observable through browser storage.

A resource 403 triggers a capability refresh, but never retries the rejected
resource request or mutation. Token/tool mutation denials remain disabled until
the view is reopened or the identity changes. Directory/cluster reads start after
the first confirmed read grant; permission polling does not restart a failed read.
Reopen the view to retry its resource request. Data is hidden while its global
read permission is unknown or denied.

Per-resource action metadata remains authoritative where it is more precise:
policy response write metadata and connection/tool action metadata continue to
control those editors. A global grant cannot override a resource denial. The
credential storage policy remains owned by issue #424; this change only adds
session lifecycle notifications.
