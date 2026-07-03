# Dev RBAC Policy

`policy.json` is the seeded local-development policy used by `docker-compose.dev.yml`.

It is intentionally small because Phase 2 has no reverse proxy target yet. The routes cover GreenGateway's own control-plane surface so local traffic can exercise auth, RBAC, and audit:

- `/v1/admin/audit`
- `/v1/admin/events/stream`
- `/v1/admin/status`

The `admin` role grants `"*"` for local demos. The `reader` role is intentionally limited so follow-up traffic tests can demonstrate denied requests. Health, version, metrics, and `/admin` remain exempt through the compose environment, matching the gateway defaults.
