# Production Proxy Data Plane: PR 1 Design

**Issue:** #239

**Scope:** checklist item 1 only

**Base:** stacked after the Policy Studio ADR branch, reserving this decision as ADR-0005

## Purpose

This change establishes the security boundary and code seams needed for later production-data-plane work without shipping pooling, retries, streaming request bodies, readiness behavior, or shutdown behavior prematurely.

PR 1 has four deliverables:

1. Record the target SSRF-safe pooling, logical-route, endpoint, lifecycle, and threat-model decisions in ADR-0005.
2. Extract proxy transport responsibilities from `main.rs` while preserving the current request path and all public behavior.
3. Extract server lifecycle composition from `main.rs` while preserving unified and split-listener behavior.
4. Introduce injectable DNS resolver and clock seams so later behavior can be tested without public DNS or wall-clock sleeps.

The extraction is successful only if existing configurations, security gates, egress behavior, headers, limits, health behavior, errors, and audit/observation behavior remain unchanged.

## Current compatibility anchors

The current implementation remains authoritative during PR 1:

- `UPSTREAM_URL` is the legacy fallback upstream.
- Each `UPSTREAM_ROUTES` entry has exactly one `upstream_url`.
- Route classification currently associates a request with an upstream origin before auth/RBAC; no physical network work occurs there.
- Authentication, RBAC, rate limiting, unsafe-path rejection, and gateway-owned path rejection run before proxy forwarding.
- `EgressClient` owns URL, hostname, port, DNS-answer, IP, redirect, timeout, TLS, response-size, and response-idle enforcement.
- Proxy request bodies are buffered and bounded before an outbound request is sent.
- Proxy responses retain the existing first-chunk-before-commit behavior.
- Health checks issue an immediate `HEAD`, repeat every 30 seconds, count any HTTP status as reachable, and do not gate startup.
- `/health` keeps its existing HTTP 200 compatibility contract.
- Unified and split listeners keep their current startup and failure behavior.

PR 1 must not opportunistically change any of these anchors.

## Non-goals

PR 1 does not add or enable:

- Reusable-client caching or connection pooling changes.
- Endpoint pools, weights, failover, admission queues, retries, or circuit breakers.
- Request streaming, body spooling, or replayability changes.
- Active-health configurability or readiness-based routing.
- `/livez`, `/startupz`, or `/readyz`.
- Graceful shutdown, signal handling, background-task cancellation, or audit draining.
- SSE semantic changes or terminal-stream observations.
- Per-endpoint mTLS.
- New environment variables, JSON configuration fields, endpoints, metrics, or dependencies.
- Runtime route IDs or migration of authorization, observation, discovery, or audit identity from the current upstream-origin representation.

## Security invariants

### Logical identity before authorization

Pre-authorization routing may classify only the stable logical identity required by current policy evaluation. It must not select a physical endpoint, resolve DNS, create or acquire a client, acquire capacity, or open a socket.

The order remains:

```text
request ID
  -> stable logical request classification
  -> remaining security middleware
  -> authentication
  -> authorization / direct rules
  -> unsafe and gateway-owned path protection
  -> physical destination work through EgressClient
  -> upstream bytes
```

A rejection at any gate before forwarding produces zero resolver calls and zero upstream bytes. Future failover and retries may operate only inside the already-authorized logical route; they may never fall through to another route or the legacy fallback.

Existing policy and observation code still keys routed behavior with `upstream_origin`. PR 1 documents, but does not implement, the later migration to stable route IDs and separate physical endpoint IDs.

### Egress and DNS ownership

All outbound proxy attempts and health checks continue through `gateway/src/egress.rs`. The resolver seam returns DNS facts only. It cannot authorize an address, select a fallback, cache an answer, or construct a client.

For every destination, `EgressClient` continues to:

1. Accept only `http` and `https`.
2. validate the hostname and destination port against configured egress policy;
3. resolve through the injected resolver;
4. reject empty results and resolver errors;
5. validate every answer, including mapped and NAT64 forms;
6. reject the entire result if any answer is prohibited;
7. pin the current client to the first answer only after all answers pass;
8. retain the configured hostname for HTTP `Host`, TLS SNI, and certificate verification; and
9. keep redirects disabled.

There is no stale-last-known-good fallback, unchecked system-resolver fallback, or discard-private-and-continue behavior.

The production resolver delegates to Tokio's system lookup with exactly the current behavior. Tests use a deterministic fake resolver. The default `EgressClient` constructor remains the path for production callers; resolver injection is crate-private testable infrastructure.

### Future reusable-client key

PR 1 records but does not build the cache. A later reusable transport key must contain at least:

- scheme, normalized hostname, and port;
- exact validated socket address or immutable validated-address generation;
- effective egress-policy/configuration generation;
- timeout and protocol profile;
- TLS root-set fingerprint;
- client-identity fingerprint; and
- explicit outbound-proxy policy, if proxy support is introduced.

Keying only by hostname, origin, or route is forbidden. A safe-to-private DNS transition, mixed answer, empty answer, or resolution error makes the destination ineligible for new work; a cached formerly-safe destination cannot bypass revalidation rules.

The first client-cache implementation resolves and validates before every cache acquisition. The cache is consulted only after producing the current immutable validated-address generation. A later DNS-generation cache is permitted only through a separate reviewed design with resolver TTL input, a finite monotonic validation lease, refresh-before-new-work behavior, and fail-closed refresh errors; a stale generation is never used to preserve availability. Client entries have a hard cardinality, a finite idle lifetime, in-flight-safe eviction, and per-key acquisition so unrelated pools do not serialize behind one global lock.

Every cached client also has a finite conservative pool idle timeout, a finite maximum idle-connection count per host, and finite TCP keepalive. Admission bounds active requests; these settings separately bound retained sockets. No absent configuration inherits an unbounded library default.

Every reqwest client constructed by `EgressClient`, plus the separately built egress-validated/pinned MCP transport client, explicitly disables ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and related environment proxy discovery. Future outbound-proxy support must be configured, validated, and keyed explicitly; it cannot inherit process environment behavior or bypass exact destination pinning. Isolated subprocess tests set hostile proxy environment variables and prove the pinned local destination is still used while the proxy receives no request.

Known buffered outbound bodies are rejected before DNS resolution. MCP
tool-call payloads are conservatively serialized with maximum-width runtime
identifiers and rejected before destination resolution, connection, or session
initialization; exact transport serialization keeps the existing second size
check.

### Header, credential, and framing boundary

Extraction must preserve the current per-attempt header boundary:

- Remove hop-by-hop, non-standard `Proxy-Connection`, and `Connection`-nominated headers.
- Ignore inbound `Host`.
- remove gateway `Authorization` and `Cookie` credentials;
- replace untrusted forwarding metadata with the canonical client IP;
- preserve the gateway-controlled request ID;
- apply configured add/strip request-header policy; and
- remove stale/conflicting length and transfer framing.

Later retries and alternate endpoints must apply this boundary independently on every attempt. PR 1 performs only one current attempt.

### Body and retry safety

Buffered request behavior is unchanged: the configured maximum is enforced before dialing and an oversize request returns 413 with no outbound work. Request streaming is a later opt-in mode.

The compatibility default remains exactly one attempt. No error in PR 1 is retried. Future retries require explicit configuration, replayable bodies, method/error eligibility, a single overall deadline, bounded attempts, and a retry budget. Policy denial, egress denial, TLS validation failure, request-size failure, client cancellation, and response commitment can never be availability retry signals.

## Reserved target configuration vocabulary

Later PRs may add strict additive configuration using these names. ADR-0005 owns their meaning so independent implementations do not drift:

- Logical route: `id`, `upstreams`, `load_balancing`, `request_body`, `limits`, `health_check`, `retry`, `circuit_breaker`.
- Physical endpoint: `id`, `url`, `weight`, `tls_ca_bundle_path`, and `client_identity_pem_path`.
- Existing `upstream_url` remains the single-endpoint compatibility form.

Nested field names are fixed by issue #239: `load_balancing.strategy`; `request_body.mode`; `limits.max_in_flight`, `queue_depth`, and `queue_timeout_ms`; `health_check.method`, `path`, `interval_ms`, `timeout_ms`, `healthy_threshold`, `unhealthy_threshold`, `expected_statuses`, `required_for_readiness`, and `minimum_healthy`; `retry.max_attempts`, `methods`, and `statuses`; and `circuit_breaker.failure_threshold`, `open_ms`, `half_open_max_requests`, and `recovery_threshold`.

Route and endpoint IDs are 1 to 64 ASCII characters matching `[a-z][a-z0-9._-]{0,63}`. New endpoint URLs accept only `http`/`https`, reject userinfo, query, and fragment components, and require an empty or root path; the inbound path/query is appended to the endpoint origin. Legacy `upstream_url` keeps its current `Url::origin` behavior that discards a configured base path. The later configuration PR defines finite numeric defaults/maxima, duplicate detection, and mutual exclusion between `upstream_url` and `upstreams`. Unknown fields and invalid combinations fail startup. PR 1 adds none of these fields.

Existing route matchers, timeouts, add/strip headers, and `openapi_spec_path` remain route-scoped for every attempt. Legacy route-level `tls_ca_bundle_path` is valid only with `upstream_url`; new pools use only endpoint-level CA/identity paths. Pool-only resilience objects are rejected beside `upstream_url`. Legacy syntax may omit IDs and receives bounded ordinal internal compatibility IDs that contain no topology; explicit IDs are required for new pool syntax and for stability across route reordering.

## Target lifecycle model

The eventual lifecycle state machine is:

```text
Starting -> Ready -> Draining -> Stopped
    |          |          |
    +----------+----------+-> Failed
```

- `Starting` means configuration and required resources are still initializing.
- `Ready` means listeners accept new work and configured readiness requirements are satisfied.
- `Draining` begins atomically on termination; readiness is immediately false, new admission and new background work stop, and existing work receives a bounded drain window.
- `Stopped` follows a clean bounded drain and audit flush.
- `Failed` follows listener loss, required initialization failure, or a required durable flush failure.

Unexpected termination of either split listener must eventually cancel and drain its peer; the process must not remain half-serving. Policy Studio analysis jobs never gate data-plane readiness and cannot extend the data-plane shutdown budget.

PR 1 only separates lifecycle composition and introduces a minimal clock abstraction used by already-existing timestamp/sleep behavior. It does not change lifecycle states or server semantics.

The later lifecycle PR emits `gateway.ready` after successful initialization and owns this exact first-signal sequence: atomically enter `Draining`; make readiness false; emit `gateway.shutdown_started`; wait only the configured bounded readiness-propagation delay; stop unified or both split listeners from accepting; stop new admission, retries, and health probes; cancel background workers; drain in-flight HTTP/SSE until the hard deadline; cancel remaining work and emit `gateway.shutdown_forced` at the deadline, otherwise emit `gateway.shutdown_completed`; then close audit admission, drain in order, and await a bounded sink flush acknowledgement. A second signal may force immediate cancellation. A clean drain exits zero; listener failure or required durable-flush failure exits nonzero. Loss of one split listener coordinates the same failure/drain for its peer. Audit writer creation failure blocks startup; events attempted after close increment dropped reason `closed`. Health/circuit transitions and retry exhaustion emit stable structured events, not raw transport detail.

## Target health, streaming, and TLS boundaries

These decisions constrain later work but do not ship in PR 1:

- Active health uses the same egress and TLS enforcement as traffic, has bounded workers and deterministic scheduling, and exposes safe reason categories rather than origins or IPs.
- `/livez` is process-only, `/startupz` is initialization-only, and `/readyz` reads cached required-pool capacity only. Probe handlers never synchronously dial.
- Draining makes `/readyz` fail immediately while `/livez` remains process-liveness-only.
- SSE commits headers without waiting indefinitely for a data event, retains bounded idle/concurrency controls, propagates cancellation, and records a terminal outcome without payload content.
- Per-endpoint mTLS keys pooled clients by identity and trust fingerprints. Private keys are mounted references, never inline JSON, logs, audit fields, status output, or errors. Hostname/SNI verification remains mandatory.

## Module boundaries

### `gateway/src/proxy/mod.rs`

Owns two deliberately separate interfaces:

- A pre-authorization classifier containing route-matching data only. It returns stable logical policy/observation context and has no resolver, egress client, health selector, admission state, or forwarding method.
- A post-authorization forwarder containing physical transport/health state and callable only from the root fallback after current security and path gates.

The module owns:

- proxy route matching and compatibility upstream mapping;
- route-specific egress client selection;
- request-header policy;
- current health target/state mechanics;
- target URL composition;
- one-attempt request forwarding;
- response forwarding; and
- sanitized proxy error mapping.

`main.rs` gives `ProxyDispatchState` only the classifier, never the forwarder. It keeps a small fallback adapter whose ordering remains visible and auditable: record current metrics, reject unsafe/gateway-owned paths, reject missing proxy/route state, derive canonical client IP, then call the extracted proxy forwarder.

The extracted proxy module must not become a second authentication or authorization entry point. Tests prove that classification cannot select an endpoint/client or invoke a resolver, independently of request-level DNS call counts.

### `gateway/src/lifecycle.rs`

Owns application routers/listeners and the existing serve composition:

- unified versus split listener binding;
- startup messages/audit emissions using actual bound addresses;
- spawning or joining the existing server futures; and
- the common `serve_router` helper.

`main.rs` remains the composition root for configuration, shared state, middleware, and router construction.

### `gateway/src/egress.rs`

Owns a crate-private asynchronous resolver trait and the production system resolver. Every existing resolution call uses the injected resolver; policy validation and address selection stay inside `EgressClient`.

The seam must be reusable by proxy, health, OIDC/auth, MCP, and tool egress without changing the default production constructor.

### Clock seam

The minimal clock supplies current wall-clock time and asynchronous sleep for existing health timestamps and scheduling. It adds no circuit-breaker semantics in PR 1. Later monotonic deadlines/cooldowns may extend or complement it; wall-clock time must not be used for safety-sensitive elapsed-time state machines.

## Threat model

| Threat | Required control |
| --- | --- |
| Pre-auth endpoint/client selection, dialing, or DNS | `ProxyDispatchState` holds only a pure classifier; physical state is available only to the post-gate fallback. Denial tests assert zero selection, resolver, and upstream activity. |
| Cross-route failover | Physical attempts are scoped to one authorized logical route; no fallback to another route or legacy upstream. |
| Mixed safe/private DNS answers | Validate all answers before pinning any; one prohibited answer denies the destination. |
| Resolver failure with stale fallback | Empty/error results fail closed; no last-known-good or ambient resolver fallback. |
| Trust-profile cache collision | Future client keys include address generation, egress generation, TLS roots, identity, protocol/timeout, and proxy policy. |
| Retry amplification | Defaults remain one attempt; later retries are explicit, replay-safe, deadline-bound, and budgeted. |
| Admission queue exhaustion | Later queues and concurrency are hard-bounded and return sanitized 503 on timeout/full capacity. |
| Streamed-prefix leakage | Streaming is later explicit behavior with counted limits and audit semantics acknowledging upstream-visible prefixes. |
| mTLS identity crossover | Client identity and trust fingerprints partition reusable transports. |
| Readiness/topology leakage | Probe handlers use cached aggregate state and never expose origins, addresses, paths, certificates, or raw errors. |
| SSE task/permit leak | Client disconnect and shutdown cancel upstream work and release all owned capacity. |
| Half-serving split listeners | Loss of one listener becomes a coordinated process failure/drain, never an indefinitely partial service. |
| Audit loss during shutdown | Later lifecycle owns bounded close, ordered drain, sink flush acknowledgement, and forced-outcome evidence. |
| Extraction bypass | Current middleware and fallback ordering remain unchanged and are covered by parity and zero-egress tests. |

## Test strategy

### Resolver seam

Deterministic tests must show:

- Mixed safe/private answers are rejected.
- Empty and error results fail without fallback.
- Every answer is validated before the first is pinned.
- The normal constructor retains system-resolver behavior and injected construction changes no egress policy defaults.
- Resolver injection cannot bypass hostname, port, IP, NAT64, TLS, redirect, or response bounds.

### Proxy extraction

Existing tests remain regression anchors. Focused seam tests additionally cover:

- Authentication denial, principal-keyed and IP-keyed rate-limit denial, request validation, CSRF, RBAC/direct-rule denial, unsafe paths, and gateway-owned paths each produce zero request-scoped endpoint selection, resolver calls, and upstream bytes; background health is disabled or separately accounted for in these assertions.
- Route ordering, host binding, legacy fallback, URL composition, and origin identity remain exact.
- Hop-by-hop, nominated, credential, forwarding, request-ID, configured add/strip, and framing headers remain exact.
- Buffered oversize requests return 413 before dialing.
- Non-timeout failures remain sanitized 502 and timeouts remain sanitized 504.
- Response size, response idle, and current first-chunk behavior remain unchanged.

### Health and lifecycle extraction

Fake-clock and local-listener tests cover the current contract:

- Health performs an immediate first `HEAD`, then fixed 30-second checks.
- Any HTTP status is reachable; transport failure is unreachable.
- Failed health does not block startup.
- Unified and split listener composition keeps the same routers and failure propagation.

Tests use only local listeners, fake resolver results, and placeholder values. They do not rely on the public internet or public DNS.

## Verification

The PR is complete only when all of these pass:

```text
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
bash scripts/check-egress-only.sh
git diff --check
```

Review additionally checks:

- no new dependencies, public configuration, endpoints, or metrics;
- no direct outbound network primitive outside the egress allowlist;
- no new public surface exposes credentials, origins, IP addresses, resolver details, or raw transport errors;
- the existing `/health` JSON field `upstreams[].origin` is treated as a temporary compatibility exception, is not expanded in PR 1, and is migrated only in the dedicated readiness/status PR;
- proxy (including committed response tails), health-check, identity-egress, MCP transport, and egress enforcement logs plus new audit/status paths use bounded safe error categories rather than raw URLs, queries, addresses, resolver details, or transport errors; and
- the extracted diff is behavior-preserving rather than a hidden feature implementation; and
- later target architecture is labeled as target, not current production behavior.

## Acceptance criteria

- ADR-0005 and the ADR index capture the target decisions and compatibility boundary.
- `docs/architecture.md` names the current secure request path and links the target data-plane ADR.
- Proxy and lifecycle responsibilities are extracted from `main.rs` with the same external behavior.
- DNS and clock behavior can be injected deterministically without weakening production defaults.
- Focused tests demonstrate fail-closed seams and the full existing workspace suite passes.
- An external senior review and parallel independent Codex production-readiness reviews report no unresolved critical or important findings.
- The PR description says `Part of #239` and states clearly that it completes checklist item 1, not the full production-data-plane epic.
