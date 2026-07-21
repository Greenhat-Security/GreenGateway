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
| 5 | Observation | #10 | Emit one `http.request_observed` audit event per request with method, path, status, latency, and the auth/authz outcome from any inner layer that reached a decision for end-to-end request observability. |
| 6 | Logical route classification | #239 | Classify only stable logical policy/observation context. This pre-auth step has no endpoint, resolver, egress-client, health, or forwarding capability. |
| 7 | IP/global rate limiting | #4 | Apply the pre-auth/IP/global token-bucket stage. Forwarded client IPs are accepted only from direct peers in explicitly configured trusted proxy CIDRs. |
| 8 | Request validation | #4 | Enforce body size caps and content-type requirements before handlers consume request bodies. |
| 9 | CSRF | #4 | Enforce a double-submit cookie on the gateway's own control-plane endpoints, with bearer-token requests bypassing CSRF checks. |
| 10 | Authentication | #5 | Run pluggable validators, starting with JWT/JWKS, with cookie sessions and additional identity providers deferred to Phase 7; fail closed with `401` on any non-exempt route. |
| 11 | Principal/policy rate limiting | #4 | Apply the authenticated-principal and policy override stage without changing the classified route. |
| 12 | Authorization / RBAC | #6 | Evaluate deny-by-default role permissions, starting at route level, with tool-level checks and full rules-as-data deferred to later phases. |
| 13 | Route handling / proxy | #239 | Forward an already-authorized request through the egress boundary. Current single-upstream compatibility remains authoritative while the bounded production data plane lands incrementally. |
| 14 | Audit | #8 | Emit structured, versioned audit events for every security-relevant decision made by the layers above. |

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
  -> observation
  -> logical route classification (data only)
  -> IP/global rate limiting
  -> request validation
  -> CSRF
  -> authentication
  -> principal/policy rate limiting
  -> authorization / RBAC
  -> route handling / proxy placeholder
  -> response

audit events are emitted throughout the path and correlated by request ID
```

## Production data-plane boundary

The current proxy classifies a configured logical upstream before authentication and authorization so policy can evaluate the intended route. Physical network work still occurs only in the fallback handler after the security middleware has allowed the request. Proxy and health traffic use `EgressClient`, which validates the hostname and port, resolves and validates every DNS answer, pins the selected address, preserves hostname/SNI verification, and disables redirects.

Issue #239 evolves that path without changing the security order:

```text
stable logical route
  -> IP/global rate limit
  -> request validation / CSRF
  -> authentication
  -> principal/policy rate limit
  -> authorization / direct rules
  -> bounded pool admission
  -> eligible physical endpoint
  -> egress policy + complete DNS validation + exact pin
  -> bounded attempt(s)
  -> response and terminal observation
```

Pre-authorization routing may remain a pure logical classification only. It must not select an endpoint, resolve DNS, acquire a client or permit, or open a socket. Failover and retries stay inside the already-authorized route. See [ADR-0005](adr/0005-production-proxy-data-plane.md) for the target pooling, health, readiness, shutdown, SSE, mTLS, threat, compatibility, and rollout contracts. Later target behavior in that ADR is not implied to be shipped by the initial extraction PR.

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
| Observation | 5 | #10 |
| Logical route classification | 6 | #239 |
| IP/global rate limiting | 7 | #4 |
| Request validation | 8 | #4 |
| CSRF | 9 | #4 |
| Authentication | 10 | #5 |
| Principal/policy rate limiting | 11 | #4 |
| Authorization / RBAC | 12 | #6 |
| Route handling / proxy | 13 | #239 |
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
ingress through final handling. Observation adds one `http.request_observed`
summary event per request and relies on the same request ID to correlate with
the more specific auth, authz, and other security decision events.
