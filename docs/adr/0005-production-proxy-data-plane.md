# ADR-0005: Production Proxy Data Plane Security Boundaries

## Status

Accepted and implemented by issue #239

## Context

Issue #239 evolved GreenGateway's alpha-scale HTTP proxy into the current
bounded, resilient data plane. The implementation includes fail-closed
authentication, rate limiting, RBAC/direct-rule enforcement, egress allowlists,
all-answer DNS validation, exact address pinning, redirect denial, bounded
reusable transports, endpoint pools, admission, safe retries and circuits,
buffered/streamed requests, readiness, coordinated drain, bounded SSE, mTLS
isolation, audit, and terminal observation.

Availability work is unusually capable of bypassing security by moving DNS,
endpoint selection, connection acquisition, or retry decisions ahead of
authorization. Reusing a client under an incomplete key can also cross DNS
generations, egress policies, custom roots, or client identities. This ADR fixes
the implemented ordering and partition boundaries.

This decision was prepared against main commit
`450ca108a963750f8f110143861f69bff62d5163` and implemented incrementally by
issue #239. [The architecture overview](../architecture.md) describes the
current composition.

## Scope

This ADR defines:

- logical route/pool identity versus physical endpoint identity;
- the order of authorization, admission, selection, DNS validation, and attempts;
- SSRF-safe reusable transport and DNS-generation boundaries;
- additive endpoint-pool configuration vocabulary and legacy compatibility;
- request-body, admission, health, retry, circuit, lifecycle, SSE, and mTLS boundaries;
- module ownership, failure/redaction rules, and resource bounds; and
- a threat model and rollout sequence.

## Non-goals

Dynamic service discovery, distributed resilience state, arbitrary tunneling,
WebSockets, transparent gRPC, HTTP/3, and an admin pool editor remain outside
this decision. First-class upstream credentials and managed destinations are
specified separately by [ADR-0006](0006-first-class-connections-and-credentials.md).

## Decision

This section describes the implemented issue #239 contract. Explicit legacy
compatibility notes remain part of that contract.

### Request and identity boundary

The request path is:

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

Explicit pool routes use stable route and endpoint IDs. Existing `UPSTREAM_URL`
and legacy `UPSTREAM_ROUTES[].upstream_url` retain their compatible
dispatch/origin identity; bounded declaration-order compatibility IDs are
transport bookkeeping and do not silently change legacy policy identity.

### Egress, DNS, and immutable destination generations

All proxy attempts, health probes, retries, SSE requests, and managed
Connection transports go through `gateway/src/egress.rs`. No availability or
credential component may create an alternate outbound path.

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

The production resolver delegates to Tokio system lookup. An injected resolver
changes only the source of DNS facts; `EgressClient` retains hostname/port
policy, all-answer validation, address selection, pinning, TLS, redirect,
timeout, and response-bound authority. Route-derived clients inherit the same
resolver rather than silently returning to ambient DNS.

### Reusable transport partition

The bounded client cache key includes:

- scheme, normalized hostname, and port;
- the exact validated socket address or immutable validated-address generation;
- effective egress-policy/configuration generation;
- connect/request/response-idle and protocol profile;
- TLS root-set fingerprint;
- client-identity fingerprint; and
- explicit outbound-proxy policy, if such support is introduced.

Hostname-only, origin-only, route-only, or endpoint-ID-only keys are forbidden. Cache entries have hard cardinality and idle bounds. Eviction remains safe while in-flight requests hold references. Concurrent acquisition cannot serialize unrelated pools behind one global lock.

Each cached reqwest client also has a finite conservative pool idle timeout, a
finite maximum number of idle connections per host, and a finite TCP keepalive
interval. Admission bounds active work; these transport settings separately
bound retained idle sockets and detect dead peers. The implementation retains
at most 128 exact-pinned clients process-wide, makes an entry ineligible after
five minutes without a cache hit and removes it lazily on the next access to its
shard, expires idle HTTP pool connections after 90 seconds, retains at most
eight idle connections per host in each exact-pinned client, and configures a
30-second TCP keepalive interval. Lazy entry removal cannot retain a live idle
socket past the separate 90-second reqwest pool limit, and the hard 128-entry
ceiling still bounds memory. These internal ceilings are deliberately not
environment-tunable.

The first cache implementation obeys all of these rules:

- Resolve and validate before every cache acquisition.
- Select a reusable client only with the current immutable validated generation.
- Enforce hard client cardinality and finite idle lifetime.
- Evict safely while in-flight requests retain references.
- Coordinate misses per key so unrelated pools do not share a global acquisition lock.

Any future DNS-generation cache requires a separately reviewed design with
resolver TTL input, a finite monotonic validation lease, refresh before
admitting new work, and fail-closed refresh errors. The current implementation
validates DNS before each attempt and never serves a stale generation to
preserve availability.

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

The compatibility body mode remains `buffered`: GreenGateway consumes and validates the complete bounded body before any outbound request, so a rejected body produces zero upstream bytes. The request-body abstraction also supports explicit, non-replayable `stream` mode. It rejects known oversize bodies before DNS or dialing, counts the actual stream independently of `Content-Length`, forwards at most the effective ceiling, and then aborts on overflow. Dropping an in-flight request drops the source stream, so downstream cancellation does not leave a detached upload running. Discovery capture is a separate 64 KiB bounded tee; cancellation, source errors, and truncation are reported as incomplete and never converted into payload-shape or body-conformance evidence.

Ordinary response streaming retains byte/idle bounds, sanitized 502/504
mapping, a first-chunk-before-downstream-commit boundary, and a one-attempt
default. Explicit SSE mode has the prompt-header-commit and terminal-telemetry
contract below.

### Additive configuration contract

Pool configuration is additive and uses these exact field names:

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

`UPSTREAM_URL` stays a legacy catch-all. A route's existing `upstream_url` maps to endpoint `primary` with weight 1 and is mutually exclusive with `upstreams`. New pools require a stable route ID and stable endpoint IDs. Selection uses a deterministic weighted sequence over configuration-owned endpoints only; request headers, path captures, queries, and bodies cannot influence it. Every pool has hard in-flight and queue bounds. Admission occurs after authorization and before physical endpoint selection, DNS, or dialing; queue saturation and queue timeout return a sanitized `503`, and cancellation drops queue/in-flight permits. Legacy behavior remains one attempt, no circuit breaker, buffered request behavior, and current health behavior until explicitly migrated.

The current schema accepts legacy-only configuration without requiring a new
pool field or applying pool-only validation to it.

For existing syntax, `id` remains optional. The global catch-all uses internal compatibility IDs `legacy-catch-all` and `legacy-catch-all-1`; legacy route entries use bounded declaration-order IDs `legacy-route-N` and `legacy-endpoint-N`. They contain no host, URL, path, or address material and are stable for an unchanged ordered configuration generation. They are transport bookkeeping only: current `upstream_origin` remains the authorization/observation identity until explicit IDs are adopted. Operators requiring identity stability across route insertion/reordering migrate that route to the new syntax with an explicit `id`; every route using `upstreams` requires an explicit route ID and explicit endpoint IDs.

`path_prefix`, `host`, `timeout_ms`, `response_idle_timeout_ms`, `connect_timeout_ms`, `add_request_headers`, `strip_request_headers`, and `openapi_spec_path` remain route-scoped and apply to every physical attempt. The legacy route-level `tls_ca_bundle_path` is accepted only with `upstream_url`; it is rejected with `upstreams`, where TLS CA and client identity are endpoint-scoped. Pool-only `load_balancing`, `request_body`, `limits`, `health_check`, `retry`, and `circuit_breaker` objects are rejected beside legacy `upstream_url`. Header policy and OpenAPI association never vary by selected endpoint.

Route and endpoint IDs are 1 to 64 ASCII characters matching `[a-z][a-z0-9._-]{0,63}` and are unique within their configuration scope. New `upstreams[].url` values use only `http`/`https`, contain no userinfo, query, or fragment, and have an empty or root path; the inbound path/query is appended to the endpoint origin. Legacy `upstream_url` retains the current behavior in which any configured base path is discarded through `Url::origin`. Unknown fields, empty/duplicate IDs, duplicate matchers, empty pools, zero/out-of-range weights, excessive collections, zero durations, invalid statuses, unsafe retry combinations, impossible readiness capacity, unbounded queues, and conflicting TLS inputs fail startup with aggregated sanitized errors before any listener binds.

Exact numeric defaults and maxima not fixed above are owned by the current
versioned configuration parser. They are finite, conservative, documented, and
tested; absence never means unbounded behavior.

### Selection, admission, health, retry, and circuits

Weighted selection is deterministic over endpoints that belong to the authorized pool, are eligible under cached health, are not blocked by an open circuit, and can admit work within bounded concurrency/queue limits. No inbound header, query, path capture, or body value may choose an endpoint. Queue full/timeout and all-unavailable states return sanitized 503 without a busy loop. Cancellation releases every permit and queue slot.

Active health uses the same egress, immutable destination, TLS, redirect, timeout, and cancellation boundaries as traffic. Workers are bounded by configured endpoints, use jitter and thresholds, emit audit only on state transitions, and stop/join during shutdown. They forward no client credentials or headers and expose only safe reason categories. Ordinary client 4xx, authentication/RBAC/egress denial, body-limit failure, and cancellation are not endpoint failures.

Legacy health retains compatible non-blocking startup behavior. Explicit pool
health uses configured method/path/interval/timeout/statuses and thresholds,
feeds readiness only when requested, and is deterministic under the injected
clock in tests.

Retries default to one total attempt. Configured retries require an eligible
safe/replayable method and body, a retryable pre-commit failure, destination
revalidation per attempt, bounded exponential backoff with jitter, one total
request deadline, alternate-endpoint preference, maximum attempts, and a
per-pool amplification budget. Policy/egress denial, TLS verification errors,
body-limit errors, cancellation, client 4xx, and any post-commit error never
trigger retries.

Circuit state is per configured endpoint. It uses a monotonic clock, bounded failure window, `closed -> open -> half_open` transitions, bounded half-open concurrency, and explicit recovery/failure thresholds. All-open pools fail quickly with sanitized 503. Wall-clock timestamps are evidence only and do not control cooldowns or deadlines.

### Lifecycle, probes, and audit drain

The lifecycle is:

```text
Starting -> Ready -> Draining -> Stopped
    |          |          |
    +----------+----------+-> Failed
```

Gateway-owned `GET|HEAD /livez`, `/startupz`, and `/readyz` are reserved on the
data listener, are default authentication/RBAC/CSRF exemptions, and can never
reach proxy fallback. `/livez` reports process/event-loop liveness only.
`/startupz` reports completion of required initialization. `/readyz` reads
cached state and is successful only while accepting work and every pool marked
`required_for_readiness` meets `minimum_healthy`. Probe handlers never
synchronously access DNS, upstreams, or durable stores and expose aggregate
state without origins, IPs, paths, issuer/certificate details, or raw errors.
Detailed endpoint health remains on the admin status surface and requires
`admin:status:read`. `/readyz` returns 503 immediately on draining. `/health`
retains its compatible HTTP 200 top-level contract and existing route-origin
field as a named compatibility exception.

Successful initialization records `gateway.ready`. On the first termination signal, GreenGateway atomically enters `Draining`, makes readiness false, records `gateway.shutdown_started`, optionally waits a bounded propagation delay, stops accepting on unified or both split listeners, stops new admission, prevents new retries/probes, cancels background work, and drains in-flight HTTP/SSE to a hard deadline. A clean drain records `gateway.shutdown_completed`; deadline cancellation or a second forced signal records `gateway.shutdown_forced`. Only then does it close audit admission, drain queued events in order, and flush sinks with bounded acknowledgement before exiting according to server/durable-flush success. Unexpected loss of one split listener cancels and drains its peer; the process cannot remain half-serving.

Audit writer creation failure fails startup. Events attempted after audit admission closes increment the dedicated bounded dropped reason `closed`. Upstream health transitions, circuit transitions, and retry exhaustion use stable structured event types and safe identifiers/reason codes; individual successful probes and raw transport details are not audited.

Policy Studio analysis jobs are control-plane work. They neither gate data-plane readiness nor extend the data-plane shutdown deadline.

The lifecycle implementation preserves bind-before-startup-event ordering,
actual bound-address reporting, `ConnectInfo<SocketAddr>`, coordinated
unified/split listeners, health-worker ownership, graceful drain, and bounded
audit flush.

### SSE and per-endpoint mTLS

Explicit SSE mode commits upstream status/headers without waiting indefinitely for the first data event, streams with backpressure, separates overall/idle/byte/duration controls, treats keepalives as idle activity, propagates client disconnect and shutdown cancellation, and records a correlated payload-free terminal outcome. Unlimited total bytes or duration are permitted only with finite idle and concurrency limits.

Per-endpoint mTLS accepts mounted PEM identity references validated at startup. Private key material is never accepted inline and no raw certificate/key material appears in `Debug`, logs, status, metrics, audit, or errors. Reusable transports are partitioned by client-identity and root-set fingerprints so one endpoint can never use another endpoint's credentials. Configured hostname/SNI and certificate verification remain mandatory.

### Module ownership

- `main.rs` remains the composition root and keeps request middleware, `AppState`, pre-auth route classification, gateway-owned/unsafe path authority, and a small proxy fallback gate.
- `proxy` exposes a data-only pre-authorization classifier with no resolver,
  egress client, health selector, admission state, or forwarding capability,
  plus a separate post-gate transport state. It owns route matching,
  route-specific egress construction, headers, admission, endpoint selection,
  health/circuits/retries, request/response forwarding, and sanitized transport
  error mapping.
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

Public errors, probes, audit, metrics, and logs never expose credentials,
queries, raw URLs, resolved addresses, resolver details, certificate/key
material, or raw transport errors. Proxy, response-stream, health,
identity-egress, MCP transport, and egress failures use bounded safe categories
while retaining the documented client status/body behavior. MCP challenge
headers, response bodies/content types, peer metadata, session identifiers, and
raw egress errors are discarded or categorized before they can reach
displayable errors; dependency-internal `rmcp` tracing is disabled while
gateway-owned bounded outcomes and audits remain enabled. The existing
`/health` JSON `upstreams[].origin` field and legacy `upstream_origin` metrics
are named compatibility exceptions and are not expanded. New metrics use
bounded route/pool/endpoint identifiers and never principal, path, request ID,
origin, address, or raw-error labels.

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
| Behavior drift across module boundaries | Thin adapters, full-stack regression coverage, focused seams, and an egress-only outbound primitive check. |

## Consequences

Production data-plane behavior is implemented behind narrow, testable seams
rather than concentrated in `main.rs`. Availability cannot silently override
authorization, egress, TLS, or resource bounds. The approach costs more
configuration validation, state ownership, deterministic testing, and migration
work, but prevents pooled transports and failover from becoming alternate trust
paths.

Existing configurations need no migration. Pool adoption is per route and
reversible to `upstream_url`. WebSocket and transparent gRPC remain separate
protocol-specific issues.

## Verification contract

The regression suite demonstrates:

- unchanged auth/RBAC/rate/unsafe/gateway-owned ordering and zero egress on denial;
- complete-answer resolver injection, mixed-answer denial, empty/error failure, and first-address pinning only after validation;
- inherited resolver behavior for route-derived transport profiles;
- unchanged buffered request, header, URL, health, response-stream, and sanitized error behavior;
- unchanged unified/split listener behavior and `ConnectInfo` peer-address delivery;
- deterministic current health timestamps/sleeps through the clock seam;
- no new direct outbound primitive outside the egress boundary; and
- clean formatting, clippy, workspace tests, egress-only guard, and diff checks.

Issue #239 is implemented. GreenGateway remains alpha software, and
deployment-specific load/soak thresholds and release evidence remain operator
gates rather than claims made by this ADR.
