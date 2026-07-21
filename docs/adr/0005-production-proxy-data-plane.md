# ADR-0005: Production Proxy Data Plane Security Boundaries

## Status

Accepted

## Context

Issue #239 evolves GreenGateway's correct but alpha-scale HTTP proxy into a bounded, resilient production data plane. The current implementation already has fail-closed authentication, rate limiting, RBAC/direct-rule enforcement, egress allowlists, all-answer DNS validation, exact address pinning, redirect denial, request/response bounds, header sanitization, audit, and observation. It does not yet reuse pinned transports, stream request bodies, select from endpoint pools, bound admission, retry, break circuits, expose deployment readiness, drain listeners and audit sinks, support quiet SSE correctly, or isolate per-endpoint mTLS identities.

Availability work is unusually capable of bypassing security by moving DNS, endpoint selection, connection acquisition, or retry decisions ahead of authorization. Reusing a client under an incomplete key can also cross DNS generations, egress policies, custom roots, or client identities. The target architecture therefore has to be fixed before those behaviors are implemented.

This decision was prepared against main commit `450ca108a963750f8f110143861f69bff62d5163`. Issue #239 checklist item 1 extracts current proxy and lifecycle responsibilities and introduces deterministic resolver/clock seams, but does not ship the later production features described here.

## Scope

This ADR defines:

- logical route/pool identity versus physical endpoint identity;
- the order of authorization, admission, selection, DNS validation, and attempts;
- SSRF-safe reusable transport and DNS-generation boundaries;
- additive endpoint-pool configuration vocabulary and legacy compatibility;
- request-body, admission, health, retry, circuit, lifecycle, SSE, and mTLS target constraints;
- module ownership, failure/redaction rules, and resource bounds; and
- a threat model and rollout sequence.

## Non-goals

This decision does not add runtime pooling, endpoint selection, retries, circuits, request streaming, readiness probes, signal handling, graceful drain, SSE changes, mTLS, configuration fields, public endpoints, metrics, or dependencies in checklist item 1. It does not add dynamic service discovery, distributed resilience state, arbitrary tunneling, WebSockets, transparent gRPC, HTTP/3, an upstream-credential UX, or an admin pool editor.

## Decision

Unless a subsection explicitly identifies a current compatibility anchor, this entire Decision section describes target architecture to be delivered by later issue #239 checklist PRs. Accepting the ADR does not claim those features are implemented.

### Request and identity boundary

The target request path is:

```text
request ID
  -> stable logical route classification
  -> remaining security middleware
  -> authentication / rate limit / RBAC / direct rules
  -> bounded admission for that logical route
  -> eligible physical endpoint selection
  -> destination resolution, validation, and exact pinning
  -> bounded attempt(s)
  -> response and terminal observation
```

Pre-authorization classification may derive only the stable logical route/pool needed by policy. It must not choose a physical endpoint, resolve DNS, acquire a transport or permit, open a socket, or emit upstream bytes. A denial at any earlier gate produces none of those side effects.

Authorization and discovery bind to the logical route. Health, weights, configuration order, failover, and retries cannot change which policy is evaluated. Every attempt stays inside that authorized logical route and cannot fall through to another route or the legacy catch-all. The gateway-controlled request ID spans the logical request; bounded attempt number and endpoint ID are separate post-authorization metadata.

Current compatibility uses `upstream_origin` as routed authorization/observation identity. Existing `UPSTREAM_URL` and `UPSTREAM_ROUTES[].upstream_url` keep their dispatch/origin semantics until a separate schema and differential-parity migration introduces stable route IDs. Checklist item 1 does not perform that migration.

### Egress, DNS, and immutable destination generations

All proxy attempts, health probes, retries, SSE requests, and later upgraded transports go through `gateway/src/egress.rs`. No availability component may create an alternate outbound path.

For each destination generation, egress performs this order:

1. parse only `http` or `https` URLs;
2. reject userinfo and validate the normalized hostname and port against policy;
3. resolve through the injected resolver;
4. reject resolver errors and empty answers;
5. validate every returned IPv4/IPv6 address, including mapped IPv4 and configured NAT64 forms;
6. reject the entire generation if any answer is prohibited;
7. form an immutable validated-address generation and select/pin only from it;
8. retain the configured hostname in the URL for HTTP `Host`, TLS SNI, and certificate hostname verification; and
9. keep redirects disabled.

Resolvers return complete ordered DNS facts only. They do not filter, select, authorize, cache, or fall back. A mixed safe/prohibited answer, safe-to-private change, empty answer, or resolver error makes the endpoint ineligible for new work. GreenGateway never silently uses an ambient resolver or stale-last-known-good generation after that failure.

The checklist item 1 production resolver delegates to the existing Tokio system lookup. An injected resolver changes only the source of DNS facts; `EgressClient` retains hostname/port policy, all-answer validation, address selection, pinning, TLS, redirect, timeout, and response-bound authority. Route-derived clients must inherit the same resolver rather than silently returning to ambient DNS.

### Reusable transport partition

The later bounded client cache key includes:

- scheme, normalized hostname, and port;
- the exact validated socket address or immutable validated-address generation;
- effective egress-policy/configuration generation;
- connect/request/response-idle and protocol profile;
- TLS root-set fingerprint;
- client-identity fingerprint; and
- explicit outbound-proxy policy, if such support is introduced.

Hostname-only, origin-only, route-only, or endpoint-ID-only keys are forbidden. Cache entries have hard cardinality and idle bounds. Eviction remains safe while in-flight requests hold references. Concurrent acquisition cannot serialize unrelated pools behind one global lock.

Each cached reqwest client also has a finite conservative pool idle timeout, a finite maximum number of idle connections per host, and a finite TCP keepalive interval. Admission bounds active work; these transport settings separately bound retained idle sockets and detect dead peers. Exact values are versioned, documented, and load-tested before the cache PR merges; no omitted value may inherit an unbounded library default.

The first cache implementation obeys all of these rules:

- Resolve and validate before every cache acquisition.
- Select a reusable client only with the current immutable validated generation.
- Enforce hard client cardinality and finite idle lifetime.
- Evict safely while in-flight requests retain references.
- Coordinate misses per key so unrelated pools do not share a global acquisition lock.

A later DNS-generation cache requires its own reviewed design with resolver TTL input, a finite monotonic validation lease, refresh before admitting new work, and fail-closed refresh errors. It cannot serve a stale generation to preserve availability.

Every reqwest client built by `EgressClient`, plus the separately built egress-validated/pinned MCP transport client, explicitly calls `no_proxy()` so `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and related process environment settings cannot redirect a supposedly pinned request. Future outbound-proxy support requires an explicit reviewed configuration that preserves destination validation and is part of the transport key. Certificate and hostname verification remain mandatory; there is no insecure skip-verification option.

Caller-provided body vectors on the direct `EgressClient` request paths are
rejected before DNS resolution. Gateway MCP `call_tool` payloads are
conservatively serialized with maximum-width runtime identifiers and rejected
before destination resolution, connection, or session initialization; MCP
initialization/discovery messages and tool calls retain the exact transport
serialization-time check as a fail-closed boundary.

### Header, body, and response boundary

Every attempt independently:

- removes hop-by-hop, non-standard `Proxy-Connection`, and `Connection`-nominated headers;
- ignores client `Host` and stale/conflicting framing;
- strips gateway `Authorization` and `Cookie` credentials;
- replaces untrusted forwarding metadata with the canonical client IP;
- restores the gateway-controlled request ID; and
- applies the configured route add/strip header policy without permitting request-ID replacement.

The current compatibility body mode is `buffered`: GreenGateway consumes and validates the complete bounded body before any outbound request, so a rejected body produces zero upstream bytes. Later `stream` mode is explicit and non-replayable; it rejects known oversize bodies before dialing and aborts at the first byte above the effective global/per-route ceiling. Discovery capture is a separately bounded tee and never converts truncated data into conformance evidence.

Current response streaming, byte/idle bounds, first-chunk-before-downstream-commit behavior, sanitized 502/504 mapping, and one-attempt default remain unchanged in checklist item 1. SSE header-commit behavior changes only in its dedicated PR.

### Additive configuration contract

Later pool configuration is additive and uses these exact field names:

```json
{
  "id": "payments",
  "upstreams": [
    {
      "id": "payments-a",
      "url": "https://payments-a.example",
      "weight": 1,
      "tls_ca_bundle_path": "/run/secrets/payments-ca.pem",
      "client_identity_pem_path": "/run/secrets/payments-client.pem"
    }
  ],
  "load_balancing": { "strategy": "weighted_round_robin" },
  "request_body": { "mode": "buffered" },
  "limits": {
    "max_in_flight": 128,
    "queue_depth": 256,
    "queue_timeout_ms": 100
  },
  "health_check": {
    "method": "GET",
    "path": "/ready",
    "interval_ms": 10000,
    "timeout_ms": 1000,
    "healthy_threshold": 2,
    "unhealthy_threshold": 3,
    "expected_statuses": [200, 204],
    "required_for_readiness": true,
    "minimum_healthy": 1
  },
  "retry": {
    "max_attempts": 2,
    "methods": ["GET", "HEAD", "OPTIONS"],
    "statuses": [502, 503, 504]
  },
  "circuit_breaker": {
    "failure_threshold": 5,
    "open_ms": 30000,
    "half_open_max_requests": 1,
    "recovery_threshold": 2
  }
}
```

`UPSTREAM_URL` stays a legacy catch-all. A route's existing `upstream_url` maps to one endpoint of weight 1 and is mutually exclusive with `upstreams`. Legacy behavior remains one attempt, no circuit breaker, current buffered request behavior, and current health behavior until explicitly migrated.

Checklist item 1 and later schema evolution continue accepting a legacy-only configuration without requiring any new field or applying new pool validation to it.

For existing syntax, `id` remains optional. The global catch-all uses internal compatibility IDs `legacy-catch-all` and `legacy-catch-all-1`; legacy route entries use bounded declaration-order IDs `legacy-route-N` and `legacy-endpoint-N`. They contain no host, URL, path, or address material and are stable for an unchanged ordered configuration generation. They are transport bookkeeping only: current `upstream_origin` remains the authorization/observation identity until explicit IDs are adopted. Operators requiring identity stability across route insertion/reordering migrate that route to the new syntax with an explicit `id`; every route using `upstreams` requires an explicit route ID and explicit endpoint IDs.

`path_prefix`, `host`, `timeout_ms`, `response_idle_timeout_ms`, `connect_timeout_ms`, `add_request_headers`, `strip_request_headers`, and `openapi_spec_path` remain route-scoped and apply to every physical attempt. The legacy route-level `tls_ca_bundle_path` is accepted only with `upstream_url`; it is rejected with `upstreams`, where TLS CA and client identity are endpoint-scoped. Pool-only `load_balancing`, `request_body`, `limits`, `health_check`, `retry`, and `circuit_breaker` objects are rejected beside legacy `upstream_url`. Header policy and OpenAPI association never vary by selected endpoint.

Route and endpoint IDs are 1 to 64 ASCII characters matching `[a-z][a-z0-9._-]{0,63}` and are unique within their configuration scope. New `upstreams[].url` values use only `http`/`https`, contain no userinfo, query, or fragment, and have an empty or root path; the inbound path/query is appended to the endpoint origin. Legacy `upstream_url` retains the current behavior in which any configured base path is discarded through `Url::origin`. Unknown fields, empty/duplicate IDs, duplicate matchers, empty pools, zero/out-of-range weights, excessive collections, zero durations, invalid statuses, unsafe retry combinations, impossible readiness capacity, unbounded queues, and conflicting TLS inputs fail startup with aggregated sanitized errors before any listener binds.

Exact numeric defaults and maxima not fixed above are owned by the versioned configuration schema in the PR that implements each field. They must be finite, conservative, documented, and tested; absence may never mean unbounded behavior.

### Selection, admission, health, retry, and circuit targets

Weighted selection is deterministic over endpoints that belong to the authorized pool, are eligible under cached health, are not blocked by an open circuit, and can admit work within bounded concurrency/queue limits. No inbound header, query, path capture, or body value may choose an endpoint. Queue full/timeout and all-unavailable states return sanitized 503 without a busy loop. Cancellation releases every permit and queue slot.

Active health uses the same egress, immutable destination, TLS, redirect, timeout, and cancellation boundaries as traffic. Workers are bounded by configured endpoints, use jitter and thresholds, emit audit only on state transitions, and stop/join during shutdown. They forward no client credentials or headers and expose only safe reason categories. Ordinary client 4xx, authentication/RBAC/egress denial, body-limit failure, and cancellation are not endpoint failures.

The current health compatibility anchor is an immediate `HEAD` to each distinct origin, followed by fixed 30-second sleeps; any HTTP status is reachable and failure does not block startup. Checklist item 1 preserves that behavior while making its clock deterministic.

Retries default to one total attempt. Later retries require explicit configuration, an eligible safe/replayable method and body, a retryable pre-commit failure, destination revalidation per attempt, bounded exponential backoff with jitter, one total request deadline, alternate-endpoint preference, maximum attempts, and a per-pool amplification budget. Policy/egress denial, TLS verification errors, body-limit errors, cancellation, client 4xx, and any post-commit error never trigger retries.

Circuit state is per configured endpoint. It uses a monotonic clock, bounded failure window, `closed -> open -> half_open` transitions, bounded half-open concurrency, and explicit recovery/failure thresholds. All-open pools fail quickly with sanitized 503. Wall-clock timestamps are evidence only and do not control cooldowns or deadlines.

### Lifecycle, probes, and audit drain target

The target lifecycle is:

```text
Starting -> Ready -> Draining -> Stopped
    |          |          |
    +----------+----------+-> Failed
```

Gateway-owned `GET|HEAD /livez`, `/startupz`, and `/readyz` are reserved on the data listener, are default authentication/RBAC/CSRF exemptions, and can never reach proxy fallback. `/livez` reports process/event-loop liveness only. `/startupz` reports completion of required initialization. `/readyz` reads cached state and is successful only while accepting work and every pool marked `required_for_readiness` meets `minimum_healthy`. New probe handlers never synchronously access DNS, upstreams, or durable stores and expose aggregate state without origins, IPs, paths, issuer/certificate details, or raw errors. Detailed endpoint health remains on the admin status surface and requires `admin:status:read`. `/readyz` returns 503 immediately on draining. `/health` retains its compatible HTTP 200 top-level contract and currently exposed route-origin field as a named temporary compatibility exception; the dedicated probe/status PR deprecates and migrates that detail rather than silently changing it during extraction.

Successful initialization records `gateway.ready`. On the first termination signal, GreenGateway atomically enters `Draining`, makes readiness false, records `gateway.shutdown_started`, optionally waits a bounded propagation delay, stops accepting on unified or both split listeners, stops new admission, prevents new retries/probes, cancels background work, and drains in-flight HTTP/SSE to a hard deadline. A clean drain records `gateway.shutdown_completed`; deadline cancellation or a second forced signal records `gateway.shutdown_forced`. Only then does it close audit admission, drain queued events in order, and flush sinks with bounded acknowledgement before exiting according to server/durable-flush success. Unexpected loss of one split listener cancels and drains its peer; the process cannot remain half-serving.

Audit writer creation failure fails startup. Events attempted after audit admission closes increment the dedicated bounded dropped reason `closed`. Upstream health transitions, circuit transitions, and retry exhaustion use stable structured event types and safe identifiers/reason codes; individual successful probes and raw transport details are not audited.

Policy Studio analysis jobs are control-plane work. They neither gate data-plane readiness nor extend the data-plane shutdown deadline.

Checklist item 1 only extracts the current bind/serve composition. It preserves bind-before-startup-event ordering, actual bound-address reporting, `ConnectInfo<SocketAddr>`, `tokio::try_join!` split behavior, current health-worker start timing, and the lack of graceful shutdown until the dedicated lifecycle PR.

### SSE and per-endpoint mTLS targets

Explicit SSE mode commits upstream status/headers without waiting indefinitely for the first data event, streams with backpressure, separates overall/idle/byte/duration controls, treats keepalives as idle activity, propagates client disconnect and shutdown cancellation, and records a correlated payload-free terminal outcome. Unlimited total bytes or duration are permitted only with finite idle and concurrency limits.

Per-endpoint mTLS accepts mounted PEM identity references validated at startup. Private key material is never accepted inline and no raw certificate/key material appears in `Debug`, logs, status, metrics, audit, or errors. Reusable transports are partitioned by client-identity and root-set fingerprints so one endpoint can never use another endpoint's credentials. Configured hostname/SNI and certificate verification remain mandatory.

### Module ownership for checklist item 1

- `main.rs` remains the composition root and keeps request middleware, `AppState`, pre-auth route classification, gateway-owned/unsafe path authority, and a small proxy fallback gate.
- `proxy` exposes a data-only pre-authorization classifier with no resolver, egress client, health selector, admission state, or forwarding capability, plus a separate post-gate transport state. It owns current route matching details, route-specific egress construction, header mechanics, health state/workers, target construction, one-attempt forwarding, response forwarding, and sanitized transport error mapping.
- `lifecycle` owns `GatewayApp`, unified/split bind and serve orchestration, actual-address startup emission, and `ConnectInfo` serving.
- `egress` owns the crate-private resolver, hostname/port policy, all-answer validation, exact pinning, TLS, redirects, timeouts, and response bounds.

The pre-auth classifier may call only pure logical matching. It cannot call a physical-upstream accessor or any egress method. Route-derived egress clients inherit the default client's injected resolver and all security policy.

### Failure and public-error semantics

| Condition | Public behavior | Availability-state effect |
| --- | --- | --- |
| Authentication/RBAC/direct-rule denial | Existing 401/403 | None; zero endpoint/DNS work |
| Unsafe or gateway-owned path | Existing 404 | None; zero endpoint/DNS work |
| Known oversized buffered request | 413 before dial | None |
| Invalid/blocked destination | Sanitized existing 502 mapping | Endpoint ineligible; safe internal reason only |
| No eligible endpoint/all circuits open | Sanitized 503 | No extra attempts |
| Admission full/timeout | Sanitized 503 | Not an endpoint-health failure |
| Pre-commit transport failure | Sanitized 502 | Retryable only when explicitly eligible |
| Pre-commit timeout | Sanitized 504 | Retryable only when explicitly eligible |
| Client disconnect | Cancel upstream and release resources | Not an endpoint failure |
| Draining | No new admission; bounded existing drain | No new retry/probe work |

New public errors, probes, audit, metrics, and logs never expose credentials, queries, raw URLs, resolved addresses, resolver error details, certificate/key material, or raw transport errors. Checklist item 1 replaces current raw proxy, committed response-stream, health-check, identity-egress, MCP transport, and egress enforcement details in logs with bounded safe categories while retaining client status/body behavior. The existing `/health` JSON field `upstreams[].origin` is the explicit compatibility exception described above and is not expanded. Existing `upstream_origin`-keyed metrics remain unchanged as a named compatibility exception until the route-ID migration; no new metric adds an origin label. New metrics use bounded stable route/pool/endpoint identifiers and never principal, path, request ID, origin, address, or raw-error labels.

## Threat model

| Threat | Control |
| --- | --- |
| Pre-auth DNS, capacity, or socket work | Pure logical classification before the unchanged security gates; deterministic zero-resolver/zero-upstream denial tests. |
| Failover changes authorization identity | Authorization binds to one logical route; every physical attempt remains inside it. |
| Mixed or rebound DNS | Validate all answers, create immutable exact-pinned generations, and deny mixed/error/empty/safe-to-private results without stale fallback. |
| Pooled transport crosses trust profiles | Complete cache key includes destination generation, egress generation, TLS roots, identity, protocol/timeouts, and proxy policy. |
| Ambient proxy or resolver bypass | System lookup is injectable but policy remains in egress; redirects and implicit outbound proxies are disabled. |
| Retry amplification or unsafe replay | One-attempt default, replay/method/error eligibility, total deadline, bounded attempts/backoff, and per-pool budget. |
| Admission or state exhaustion | Hard route/endpoint/cache/queue/task/retry/circuit/metric bounds; no all-down busy loop. |
| Streamed prefix reaches upstream before rejection | Streaming is explicit; counted limits abort promptly and evidence acknowledges any upstream-visible prefix. |
| mTLS identity crossover | Identity/root fingerprints partition clients; mounted secrets never enter public/config JSON values. |
| Probe topology disclosure | Cached aggregate probes only; protected detail uses stable IDs and safe reason codes. |
| SSE or cancellation resource leak | Completion guards release permits/transports on every success, error, disconnect, and shutdown branch. |
| Split listeners half-serve | Coordinated listener ownership; unexpected peer loss drains/fails the process. |
| Audit loss or shutdown hang | Bounded close/admission stop, ordered drain, flush acknowledgement, and hard deadline with forced evidence. |
| Behavior drift during extraction | Thin adapters, existing full-stack regression suite, focused seams, and no feature/config additions in checklist item 1. |

## Consequences

Production data-plane behavior lands incrementally behind narrow, testable seams rather than in `main.rs`. Availability cannot silently override authorization, egress, TLS, or resource bounds. The approach costs more configuration validation, state ownership, deterministic testing, and migration work, but prevents pooled transports and failover from becoming alternate trust paths.

Existing configurations need no migration for checklist item 1. Later pool adoption is per route and reversible to `upstream_url`. WebSocket and transparent gRPC remain separate protocol-specific issues.

## Verification for checklist item 1

Checklist item 1 must demonstrate:

- unchanged auth/RBAC/rate/unsafe/gateway-owned ordering and zero egress on denial;
- complete-answer resolver injection, mixed-answer denial, empty/error failure, and first-address pinning only after validation;
- inherited resolver behavior for route-derived transport profiles;
- unchanged buffered request, header, URL, health, response-stream, and sanitized error behavior;
- unchanged unified/split listener behavior and `ConnectInfo` peer-address delivery;
- deterministic current health timestamps/sleeps through the clock seam;
- no new direct outbound primitive outside the egress boundary; and
- clean formatting, clippy, workspace tests, egress-only guard, and diff checks.

The issue #239 epic is not production-ready until its remaining checklist PRs, protocol follow-up designs, deployment/E2E checks, and load/soak release evidence are complete.
