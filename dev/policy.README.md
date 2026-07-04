# Dev RBAC Policy

`policy.json` is the seeded local-development policy used by `docker-compose.dev.yml`.

It is intentionally small. Most routes cover GreenGateway's own control-plane surface so local traffic can exercise auth, RBAC, and audit:

- `/v1/admin/audit`
- `/v1/admin/events/stream`
- `/v1/admin/status`
- `/v1/admin/policy`
- `/v1/admin/policy/validate`

The dev compose stack also starts an internal-only echo upstream and points `UPSTREAM_URL` at it. The `/__dev-echo` route is a narrow allowance for authenticated proxy smoke-test traffic to reach that upstream while the policy remains `default_action: "deny"`.

The `admin` role grants `"*"` for local demos. The `reader` role intentionally has no seeded permissions so follow-up traffic tests can demonstrate denied requests without implying working control-plane access.

The RBAC policy rules for these routes are still evaluated before the handlers and can emit `authz.allowed` or `authz.denied` audit events. The audit and status handlers also enforce a separate hardcoded gate: the authenticated `Principal.roles` must contain the literal `"admin"` role. The policy handlers use dedicated live-policy permissions instead: `admin:policy:read` for `GET /v1/admin/policy` and `POST /v1/admin/policy/validate`, and `admin:policy:write` for `PUT /v1/admin/policy`. The seeded `admin` role grants `"*"` so it can exercise all of them locally. A `reader`-role token receives `403 Forbidden` for the admin routes.

Health, version, metrics, and `/admin` remain exempt through the compose environment, matching the gateway defaults.
