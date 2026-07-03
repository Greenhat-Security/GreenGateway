# Starter RBAC Policy

`policy.starter.json` is a suggested starting point for real GreenGateway deployments.
It is not used by the local dev harness; the dev stack has its own stricter policy in `dev/policy.json`.

This starter policy sets `default_action` to `"allow"`. With no matching route rule, requests pass through to the upstream backend, so operators can place GreenGateway in front of an existing service without immediately locking themselves out.

As deployment hardening progresses, add `routes` rules for sensitive paths, grant the matching permissions through `roles`, and eventually change `default_action` to `"deny"` once expected traffic is covered by explicit policy.

The [pinned roadmap issue (#44)](https://github.com/Greenhat-Security/GreenGateway/issues/44) tracks later tightening steps, including shadow enforcement and observe-only auth modes. Those modes are planned follow-up work and are not enabled by this starter policy today.
