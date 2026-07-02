# GreenGateway Architecture

GreenGateway is pre-alpha. This document describes the target architecture for
the first implementation wave so future contributors can place their work in
the same request path. It is not a description of code that has already shipped.

The middleware ordering below is the design target for issues #4 through #9 to
implement consistently. If any of those issues change the order or ownership of
a concern, this document should be updated in the same change set.

## Request lifecycle

Every inbound request is expected to pass through the gateway in this order:

| Order | Layer | Owner | Responsibility |
| --- | --- | --- | --- |
| 1 | Request ID | #4 | Assign or propagate a request ID so logs, traces, and audit events can be correlated end-to-end. |
| 2 | Tracing | #4 | Start structured request tracing around the full request lifecycle. |
| 3 | CORS | #4 | Enforce config-driven allowed origins with a neutral default. |
| 4 | Security headers | #4 | Strip spoofable identity headers on ingress and add hardening headers on responses. |
| 5 | Rate limiting | #4 | Apply token-bucket limits with separate read and write lanes, keyed by principal, then session, then client IP, using the trusted-proxy setting to determine the canonical client IP. |
| 6 | Request validation | #4 | Enforce body size caps and content-type requirements before handlers consume request bodies. |
| 7 | CSRF | #4 | Enforce a double-submit cookie on the gateway's own control-plane endpoints, with bearer-token requests bypassing CSRF checks. |
| 8 | Authentication | #5 | Run pluggable validators, starting with JWT/JWKS, with cookie sessions and additional identity providers deferred to Phase 7; fail closed with `401` on any non-exempt route. |
| 9 | Authorization / RBAC | #6 | Evaluate deny-by-default role permissions, starting at route level, with tool-level checks and full rules-as-data deferred to later phases. |
| 10 | Route handling / proxy | Later phase | Execute the actual handler or proxy behavior; in Phase 1 this remains a placeholder because proxying lands in Phase 3. |
| 11 | Audit | #8 | Emit structured, versioned audit events for every security-relevant decision made by the layers above. |

Audit is listed last to show that every decision has a durable security record,
but it is cross-cutting rather than a single final handler. Each layer that
accepts, rejects, transforms, or annotates a security-relevant request state
should emit an event into the shared audit pipeline.

```text
request
  -> request ID
  -> tracing
  -> CORS
  -> security headers
  -> rate limiting
  -> request validation
  -> CSRF
  -> authentication
  -> authorization / RBAC
  -> route handling / proxy placeholder
  -> response

audit events are emitted throughout the path and correlated by request ID
```

## Crate layout

The intended workspace shape is a gateway binary crate that wires together a
small set of focused library crates or modules. At a high level, those focused
areas are:

- Security middleware and response hardening.
- Authentication.
- RBAC and policy evaluation.
- Egress firewalling.
- Audit event production and delivery.

This is deliberately vague until issue #3 defines the authoritative Rust
workspace shape. Do not treat the concern list above as final crate names,
module paths, or API boundaries. Once #3 lands, this section should be updated
to reflect the actual workspace layout without contradicting the decisions made
there.

## Concern Ownership

| Concern | Request path position | Implementation issue |
| --- | ---: | --- |
| Request ID | 1 | #4 |
| Tracing | 2 | #4 |
| CORS | 3 | #4 |
| Security headers | 4 | #4 |
| Rate limiting | 5 | #4 |
| Request validation | 6 | #4 |
| CSRF | 7 | #4 |
| Authentication | 8 | #5 |
| Authorization / RBAC | 9 | #6 |
| Route handling / proxy | 10 | Later phase |
| Audit | Cross-cutting across all positions | #8 |
| Egress firewall | Applies when outbound proxy behavior exists | #7 |
| Configuration | Supplies settings consumed by the layers above | #9 |

## Cross-cutting notes

Every layer up through authentication and authorization should fail closed when
state is ambiguous: deny or reject the request rather than silently allowing it.
This follows the root [AGENTS.md code conventions](../AGENTS.md#code-conventions)
for security-sensitive code.

Audit events from every layer share one versioned envelope format, defined by
issue #8. The request ID from the first layer must be included so downstream
audit consumers can reconstruct the security decisions made for a request from
ingress through final handling.
