# Starter RBAC Policy

`policy.starter.json` is a suggested starting point for real GreenGateway deployments.
It is not used by the local dev harness; the dev stack has its own stricter policy in `dev/policy.json`.

This starter policy sets `default_action` to `"allow"` and `enforcement_mode` to `"enforce"`. With no matching route rule, requests pass through to the upstream backend, so operators can place GreenGateway in front of an existing service without immediately locking themselves out.

As deployment hardening progresses, add `routes` rules for sensitive paths, grant the matching permissions through `roles`, and eventually change `default_action` to `"deny"` once expected traffic is covered by explicit policy. To preview authorization denials before blocking traffic, set `enforcement_mode` to `"shadow"` globally or on an individual route rule; shadow denials forward the request and emit `authz.would_deny` audit events.

The [pinned roadmap issue (#44)](https://github.com/Greenhat-Security/GreenGateway/issues/44) tracks later tightening steps, including observe-only auth mode. Observe-only auth is planned follow-up work and is not enabled by this starter policy today.
