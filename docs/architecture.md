# GreenGateway Architecture

GreenGateway is alpha software. This document describes the request and
production proxy data-plane boundaries implemented in the current `main`
branch. The security order is a compatibility contract: new availability
features must remain after authorization and behind egress validation.

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
| 13 | Route handling / proxy | #239 | Admit an already-authorized request to its logical pool, select an eligible configured endpoint, and forward bounded attempt(s) through the egress boundary. |
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
  -> bounded route handling / proxy
  -> response

audit events are emitted throughout the path and correlated by request ID
```

## Production data-plane boundary

The proxy classifies a configured logical route before authentication and
authorization so policy can evaluate stable dispatch identity. Physical network
work still occurs only in the fallback handler after the security middleware
has allowed the request. Proxy attempts and active health checks use
`EgressClient`, which validates the hostname and port, resolves and validates
every DNS answer, pins the selected address, preserves hostname/SNI
verification, and disables redirects.

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

Pre-authorization routing is a pure logical classification. It does not select
an endpoint, resolve DNS, acquire a client or permit, or open a socket. Failover
and retries stay inside the already-authorized route. See
[ADR-0005](adr/0005-production-proxy-data-plane.md) for the threat,
compatibility, and rollout contracts.

### Destination and transport flow

```text
configured endpoint URL
  -> scheme/host/port allowlist
  -> resolve through injectable resolver
  -> validate every IPv4/IPv6/mapped/NAT64 answer
  -> exact validated socket address
  -> bounded cache key
       (origin + exact address + egress generation + timeouts
        + TLS roots + client identity + protocol/proxy policy)
  -> reused reqwest client with redirects and ambient proxies disabled
  -> hostname URL sent with SNI and certificate verification intact
```

The client cache is sharded, has a hard process-wide entry ceiling, and expires
idle entries. In-flight callers hold their own client reference, so eviction
does not invalidate active work. DNS is resolved and validated before each new
request attempt; a stale cached client is not a substitute for failed or unsafe
current DNS.

### Pool, health, retry, and circuit state

```text
logical pool (stable policy identity)
  +-- bounded admission queue / in-flight permits
  +-- endpoint A -> health state -> circuit state -> egress config/identity A
  +-- endpoint B -> health state -> circuit state -> egress config/identity B
  `-- retry budget (safe replayable methods only)
```

Weighted selection uses only configured endpoint state. Health workers are one
per configured endpoint with health enabled, use the same egress/TLS boundary,
and stop during drain. Passive failures, active health, and circuits use safe
bounded categories. Retry prefers an eligible endpoint not already attempted,
shares one request deadline, and never replays streamed bodies or unsafe
methods.

Client certificates and custom roots are parsed at startup and remain
endpoint-local. Their fingerprints partition transport reuse but are excluded
from diagnostics and telemetry.

### Response and SSE completion

Ordinary response mode preserves the compatibility first-chunk commitment
boundary. Explicit SSE mode commits status and headers promptly, then streams
with one-chunk backpressure plus independent idle, byte, duration, and shutdown
limits. A correlated `upstream.stream_terminated` audit event records a bounded
terminal outcome after a streamed response finishes; payload bytes are never
captured by this telemetry.

### Readiness and shutdown

```text
running
  -> first termination signal
  -> readiness false; retry/health work cancelled
  -> drain delay (load balancers observe /readyz=503)
  -> listeners stop accepting; registered HTTP/SSE/background work drains
  -> hard request/background deadline
  -> terminal shutdown audit event
  -> audit admission closes; queued events and sinks flush
  -> process exit
```

`/livez` is process liveness, `/startupz` is required initialization, and
`/readyz` combines accepting-work state with required pool capacity. These
handlers read cached state and do no synchronous network or durable-store work.
Unified and split listeners share one lifecycle coordinator; unexpected exit of
one listener cancels and drains the other.

## Crate layout

The Cargo workspace currently contains the `gateway` binary crate. Its focused
modules include:

- `middleware/` for ingress validation, auth decision propagation, rate limits,
  and end-to-end observations;
- `auth/` and `rbac/` for identities, tokens, policy, and authorization;
- `egress.rs` plus `egress/client_cache.rs` for SSRF validation, exact pinning,
  TLS identities, and bounded reusable clients;
- `proxy/` for classification, admission, health, retry, circuits, request and
  response streaming, and terminal telemetry;
- `lifecycle.rs` for probes, signal coordination, task/request tracking, and
  bounded shutdown;
- `audit/` and `discovery/` for event delivery, durable queries, inventory, and
  signals; and
- `tools/` and `mcp.rs` for local tools, upstream MCP, and MCP protocol handling.

`main.rs` composes these modules and owns the HTTP route surfaces. Outbound HTTP
must not be added outside `egress.rs`; CI enforces that boundary with
`scripts/check-egress-only.sh`.

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
