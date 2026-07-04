# Starter RBAC Policy

`policy.starter.json` is a suggested starting point for real GreenGateway deployments.
It is not used by the local dev harness; the dev stack has its own stricter policy in `dev/policy.json`.

This starter policy sets `default_action` to `"allow"` and `enforcement_mode` to `"enforce"`. With no matching route rule, requests pass through to the upstream backend, so operators can place GreenGateway in front of an existing service without immediately locking themselves out.

As deployment hardening progresses, add `routes` rules for sensitive paths, grant the matching permissions through `roles`, and eventually change `default_action` to `"deny"` once expected traffic is covered by explicit policy. To preview authorization denials before blocking traffic, set `enforcement_mode` to `"shadow"` globally or on an individual route rule; shadow denials forward the request and emit `authz.would_deny` audit events.

The policy schema also supports an ordered direct `rules` section for newer firewall-style policy documents. This starter keeps it omitted so the initial traffic-flow story stays minimal; `routes` remains supported for backward compatibility.

Observe-only auth is configured gateway-wide with `AUTH_MODE=observe`; it is not part of the RBAC policy document and is not enabled by this starter policy.
