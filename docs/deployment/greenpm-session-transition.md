# GreenPM browser-session transition

Refs Greenhat-Security/GreenPM#1.

`forward_cookie_session` supports a browser session that the destination API also validates. It is disabled by default and is not a general credential-forwarding option. The intended transition is Cloudflare GreenPM frontend/BFF → GreenGateway → existing PM API or the application-owned GreenPM API. Static pages and Auth login are outside the product-operation data path. The BFF must never fall back to an origin or carry database credentials.

## Identity and transport contract

The authentication middleware records an internal, redacted session only after successful cookie-provider validation. It cannot be created from an inbound identity header. Gateway-issued admin sessions, bearer/service tokens, any Authorization+cookie mixture, duplicate cookies and conflicting secure-name aliases do not qualify. The proxy removes ordinary inbound credentials, then reconstructs exactly that one validated cookie and at most one configured CSRF cookie. Encoded values are preserved; unrelated cookies are discarded. The destination validates the cookie again and retains module, organization and project permission checks.

Both Gateway and the destination must enforce mutation CSRF. The proxy independently requires a unique matching CSRF header/cookie for POST/PUT/PATCH/DELETE. GET/HEAD/OPTIONS can bootstrap without a CSRF cookie. TRACE and unknown methods are refused. Header transforms cannot overwrite the session, CSRF or claimed identity; claimed user/role/tenant headers are stripped. The original Origin header remains available to the destination. `upstream.cookie_session_delegation` records route, actor, acceptance/rejection and a bounded reason; it never records the session or CSRF token. “accepted” means delegation validation succeeded, not that an upstream call completed.

Startup requires enabled, required-mode authentication; enabled CSRF; no overlapping exemptions; different auth and CSRF cookie names; and an explicit route ID and non-root path prefix. A relay uses one HTTPS origin URL. Connections, pools, streaming, WebSockets, gRPC, retries and health probes are excluded from this initial contract. Existing egress/DNS/IP/TLS checks still run, redirects are not followed, and upstream redirect responses are rejected so a browser cannot be redirected around the Gateway. All ordinary routes retain the existing credential-stripping behavior.

This does not turn a Gateway agent token into a human browser session. Future agents need a separately reviewed delegated token/assertion contract with their own scopes and upstream identity verification. Sending a shared Authorization bearer to the legacy API would override the user cookie and is prohibited here.

## Configuration to merge with the current deployment

Read the current Fly app configuration and secrets through the authorized organization account. Do not replace an entire route table or policy with the sample. The previously observed deployment name was `greenhat-gateway-cmmugg`; that observation is not a deployment credential or proof that a checked-in sample is live.

The existing shared Auth integration can use the cookie-session provider `greenhat-session` with `introspection_url` `https://auth.greenhatsec.com/api/session/introspect`. Preserve the full configured provider contract, including its claims. Verify these non-secret settings before rollout:

- `AUTH_ENABLED=true`, `AUTH_MODE=required`, and `AUTH_COOKIE_NAME` matching the canonical shared Auth cookie.
- `CSRF_ENABLED=true`, `CSRF_COOKIE_NAME` and `CSRF_HEADER_NAME` matching the legacy and application-owned APIs. Do not infer their deployed names from repository defaults.
- Required policy enforcement with exact operation allow rules and explicit upstream route dispatch binding. Keep existing routes/rules and administrator access intact.
- `EGRESS_DENY_PRIVATE_IPS=true`. Legacy `upstream_url` hosts are auto-seeded into the exact host allowlist; additional managed Connection destinations require explicit egress permission. No broad private-IP exception is necessary for public HTTPS Fly origins.

Example route entries (replace the application-owned hostname with its reviewed production origin):

```json
[
  {"id":"greenpm-legacy","path_prefix":"/api/exponential","upstream_url":"https://api.greenhatsec.com","forward_cookie_session":true},
  {"id":"greenpm-module-access","path_prefix":"/api/me/module-access","upstream_url":"https://api.greenhatsec.com","forward_cookie_session":true},
  {"id":"greenpm-owned","path_prefix":"/api/greenpm-owned","upstream_url":"https://greenpm-api.example.test","forward_cookie_session":true}
]
```

Gateway route selection uses host/path prefix, not HTTP method. The BFF therefore rewrites only the app-owned operations to `/api/greenpm-owned`: PATCH/DELETE teams/{id}, projects/{id}, projects/{id}/members, GET search, PATCH tasks/{id}/assignee, PATCH tasks/{id}/move, and GET my-tasks. The API accepts that namespace and independently validates each operation. Browser `/api/search` becomes Gateway `/api/greenpm-owned/search`; do not send it to an unverified legacy `/api/search` route. Other PM operations stay under `/api/exponential`. The shared `/api/me/module-access` route is GET-only in policy.

For a public Fly origin, require a distinct origin-admission secret in addition to user/session/CSRF validation. A bounded transitional configuration can overwrite `x-pm-origin-key` via `add_request_headers` on the app-owned route. Store the whole route JSON in the deployment secret store and the matching key in the API's secret store; never commit the key or print the route JSON. This header authenticates Gateway as a system; it must not substitute a user or bypass resource permissions. Independently test that a direct origin request without that key fails. The already-public legacy API needs its own compatibility-aware admission change before claiming that every historical entry point is inaccessible directly.

## Exact operation policy

The [operation-rule sample](../examples/greenpm-session-rules.json) is a rules fragment, not a replacement policy. It permits only the existing native REST method/path pairs and ten app-owned pairs. Every allow is bound to a stable route ID and to the cookie-session provider boundary; each route then has a scoped catch-all deny. Apply the fragment ahead of broader permits, using the deployed canonical issuer/provider label. It does not grant module or project membership: each destination must enforce those checks. Namespaced route selection cannot replace endpoint authorization.

For the assignment/personal-feed rollout (#528), insert only `greenpm-task-assignment` and `greenpm-personal-tasks` before the existing `greenpm-owned-deny-other-operations` rule. Keep every existing rule and all other policy sections unchanged. Deploying the frontend/API does not update Gateway's live policy: a missing operation remains denied even when isolated application previews pass. Verify the live rule order and reload, then verify a permitted user's assignment round trip and personal feed. Anonymous rejection alone does not prove authenticated routing works. The owned backend continues to enforce CSRF, verified sessions, module grants, organization and task/project permissions.

The legacy matrix was inspected at Tools API commit `99e0b7441a3e71e2eef37ed9c6fceeae8e77c80f`, `gateway/src/lib.rs:9210-9314`. A transport allowlist does not prove those implementations meet every application authorization requirement. Validate their actual permission behavior and remove the temporary destination as ownership moves to GreenPM.

## Release checks

Before enabling the route, test two different valid users; revoked/missing sessions; introspection outage; no module grant; cross-project/tenant denial; missing/mismatched/duplicate CSRF; mixed bearer/cookie requests; cookie aliases; spoofed actor headers; exact unsupported methods/paths; origin-secret rejection; and a redirecting upstream. Check audit attribution without credential values. Test rollback with the existing route table/policy preserved. Configure previews as isolated fixtures with separate origins and machine credentials, never production cookies or databases. Preview bearer traffic must not use `forward_cookie_session`.

Task ordering uses the exact `greenpm-task-move` PATCH rule for `/api/greenpm-owned/tasks/{task_id}/move` (issue #530). Add it before the owned deny rule only after review. The API independently verifies the session and project edit permission, checks the destination belongs to that project/status, and persists integer ordering atomically. No direct database or legacy fallback is introduced.

## Upstream CSRF cookie-name compatibility (issue #532)

A session-delegating route may set `upstream_csrf_cookie_name` when its trusted origin uses a different CSRF cookie name. Gateway continues to validate the incoming `CSRF_COOKIE_NAME` and `CSRF_HEADER_NAME` pair, rejects ambiguous/mismatched inputs, and forwards the same token value with only the destination cookie name changed. An incoming cookie with the destination name is never an authority source. The option requires `forward_cookie_session: true`, a safe cookie name, and a name that cannot collide with the configured session cookie or its secure/host aliases. Omitting the option preserves the existing behavior.

For GreenPM, set `upstream_csrf_cookie_name: "gh_api_csrf"` only on `greenpm-legacy`: live legacy API reads issue that name, while Gateway and the owned GreenPM API use `csrf_token`. Keep `greenpm-owned` unchanged. Activate the setting only with a binary that supports it; preserve all routes, their credentials, the live policy, authentication and CSRF enforcement. Status and comment writes must be tested alongside rejection cases. A successful isolated GreenPM preview alone does not prove this upstream contract.
