# Production data-plane deployment

GreenGateway is alpha software. This guide describes the bounded proxy data
plane and gives operators a reviewable deployment starting point; it is not a
claim that every environment can use the project without its own threat review,
capacity test, and rollback exercise.

## Security boundary

Availability features do not create a second outbound path. Authentication,
rate limiting, RBAC/direct rules, and gateway-owned path rejection run before
pool admission or endpoint selection. Every proxy attempt and health probe then
uses the egress boundary for hostname/port policy, complete DNS-answer
validation, special-use address blocking, exact-address pinning, TLS hostname
and SNI verification, and redirect denial.

Keep these defaults:

- Do not add a TLS verification bypass.
- Keep `EGRESS_DENY_PRIVATE_IPS=true` unless the gateway is intentionally
  reaching reviewed private services from a controlled network.
- Mount CA bundles and client identities as read-only files. Do not place
  private keys inline in `UPSTREAM_ROUTES`.
- Use stable route and endpoint IDs; do not derive them from request data.
- Keep retries limited to replayable safe methods.

## DNS, TLS, and mTLS operations

GreenGateway resolves and validates every address again for each new request
attempt. A mixed public/private result, empty answer, resolver failure, or
safe-to-private change makes the endpoint ineligible for that work; it does not
fall back to a previously cached destination. The reusable transport is keyed
by the exact validated address generation, egress-policy generation, timeouts,
custom roots, and client identity.

For private certificate authorities, mount a reviewed PEM CA bundle and set the
endpoint's `tls_ca_bundle_path`. For mutual TLS, mount one regular PEM file of
at most 1 MiB containing the client certificate chain and exactly one matching
private key, then set `client_identity_pem_path` on that physical HTTPS
endpoint. Keep both files read-only and outside the environment JSON.

Identity and trust changes are startup state. Rotate them by replacing the
mounted secret and restarting GreenGateway, then verify `/startupz`, `/readyz`,
and a real TLS request before restoring traffic. A client identity is never
inherited by another endpoint, and no skip-verification setting exists.
Operational failures expose only bounded categories; certificate contents,
identity fingerprints, resolved addresses, and raw TLS errors remain private.

## Migrate one route at a time

An existing route needs no migration:

```json
{
  "path_prefix": "/payments",
  "upstream_url": "https://payments.example.test"
}
```

To opt that route into pooling, assign stable IDs and replace
`upstream_url` with `upstreams`:

```json
{
  "id": "payments",
  "path_prefix": "/payments",
  "upstreams": [
    {
      "id": "payments-a",
      "url": "https://payments-a.example.test",
      "weight": 3
    },
    {
      "id": "payments-b",
      "url": "https://payments-b.example.test",
      "weight": 1,
      "tls_ca_bundle_path": "/run/secrets/payments-ca.pem",
      "client_identity_pem_path": "/run/secrets/payments-client.pem"
    }
  ],
  "load_balancing": {
    "strategy": "weighted_round_robin"
  },
  "request_body": {
    "mode": "buffered"
  },
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
  }
}
```

The complete placeholder-only example is
[`docs/examples/upstream-pool.json`](../examples/upstream-pool.json). Validate
the JSON and start a canary before changing production traffic. A pool route is
a new logical authorization identity: review any policy `dispatch` binding and
confirm it names the stable route ID.

Compatibility defaults remain conservative:

- `UPSTREAM_URL` and legacy `upstream_url` map to one endpoint.
- Buffered request bodies, one total attempt, and no circuit breaker remain the
  defaults.
- Streaming uploads, retries, circuit breakers, SSE mode, and mTLS are opt-in.
- `/health` retains its compatibility response; deploy new infrastructure
  against the lifecycle probes below.

## Lifecycle probes

| Path | Purpose | Use |
| --- | --- | --- |
| `/livez` | Process/event-loop liveness only | Restart a stuck process |
| `/startupz` | Required initialization completed | Protect slow startup |
| `/readyz` | Accepting work and required pool capacity available | Remove from traffic |
| `/health` | Legacy compatibility status | Existing clients only |

Probe handlers read cached state and perform no synchronous DNS or upstream I/O.
During shutdown, `/readyz` changes to `503` immediately while `/livez` stays
`200` until the process exits.

The image-level Docker `HEALTHCHECK` uses `/livez`. The checked-in Compose
service overrides it with `/readyz`, because Compose health is used as an
admission dependency for the development stack.

## Shutdown signals

The coordinated shutdown — readiness false, `gateway.shutdown_started`, the drain delay, listeners and background work stopped within the shutdown timeout, the member row stamped `draining_at` in cluster mode, the audit flush, `gateway.shutdown_completed` — starts on the first of these and is forced by a second:

| Platform | Signals |
| --- | --- |
| Unix | `SIGINT`, `SIGTERM` |
| Windows | Ctrl-C (`CTRL_C_EVENT`), Ctrl-Break (`CTRL_BREAK_EVENT`) |

Both Windows events take exactly the path `SIGTERM` does. Ctrl-Break is listened for because it is the one console event a supervising process can deliver to a *single* child: `GenerateConsoleCtrlEvent` accepts `CTRL_C_EVENT` only for the whole console, but accepts `CTRL_BREAK_EVENT` for any process group, so a supervisor that spawns the gateway with `CREATE_NEW_PROCESS_GROUP` can drain that one gateway and nothing else. A service wrapper or a test harness on Windows should send Ctrl-Break; `TerminateProcess` is the equivalent of `SIGKILL` and leaves no draining stamp and no terminal audit record.

## Graceful termination budget

The maximum planned shutdown wall time is:

```text
SHUTDOWN_DRAIN_DELAY_MS
+ SHUTDOWN_TIMEOUT_MS
+ AUDIT_DRAIN_TIMEOUT_MS
+ supervisor/network overhead
```

The checked-in Compose values are 5 seconds + 30 seconds + 5 seconds, with a
45-second `stop_grace_period`. Keep at least several seconds of supervisor
headroom. A second signal forces the request/background drain but still attempts
the bounded audit flush.

Kubernetes should set `terminationGracePeriodSeconds` above the same sum:

```yaml
terminationGracePeriodSeconds: 45
containers:
  - name: gateway
    startupProbe:
      httpGet: { path: /startupz, port: http }
      periodSeconds: 2
      failureThreshold: 30
    livenessProbe:
      httpGet: { path: /livez, port: http }
      periodSeconds: 10
      failureThreshold: 3
    readinessProbe:
      httpGet: { path: /readyz, port: http }
      periodSeconds: 2
      failureThreshold: 2
```

Use the full checked-in
[`deploy/kubernetes/greengateway.example.yaml`](../../deploy/kubernetes/greengateway.example.yaml)
as a starting point. Replace its `latest` image tag with an immutable release
digest. The image and manifest use UID/GID 10001 so `runAsNonRoot` does not
depend on a runtime resolving a named image user.

## Local multi-upstream smoke test

The development overlay starts three weighted echo endpoints. Endpoint
`dev-echo-a` returns an intentional `503` only on the retry probe path. The CI
smoke sequence verifies:

1. a slow upload reaches its endpoint before the client finishes, and a delayed
   multi-chunk response reaches the client incrementally;
2. all three healthy endpoints receive weighted traffic;
3. bearer/cookie, untrusted forwarding metadata, and the caller's
   `x-request-id` are stripped, while the canonical forwarding address is
   preserved;
4. a retryable GET reaches a second endpoint in exactly two attempts;
5. the equivalent POST is attempted once;
6. stopping `dev-echo-b` makes it unhealthy while `/readyz` stays `200`;
7. ordinary traffic excludes that endpoint;
8. restarting it returns it to traffic only after the recovery threshold; and
9. stopping every endpoint makes `/readyz` and proxy traffic return sanitized
   `503` responses while `/livez` remains `200`.

Run the same sequence manually:

```sh
node scripts/init-dev-jwks.mjs
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
node scripts/generate-traffic.mjs --smoke-test
node scripts/verify-dev-pool.mjs healthy

docker compose -f docker-compose.yml -f docker-compose.dev.yml stop dev-echo-b
node scripts/verify-dev-pool.mjs degraded --endpoint dev-echo-b

docker compose -f docker-compose.yml -f docker-compose.dev.yml start dev-echo-b
node scripts/verify-dev-pool.mjs recovered --endpoint dev-echo-b

docker compose -f docker-compose.yml -f docker-compose.dev.yml stop dev-echo-a dev-echo-b dev-echo-c
node scripts/verify-dev-pool.mjs unavailable
```

The correctness suite also uses local TLS listeners for trusted custom CA,
wrong-hostname, untrusted-CA, required-client-certificate, and client-identity
isolation cases. It never depends on public DNS.

## Load and soak reproduction

Start the development stack with the load overlay, which raises the ingress
rate-limit ceiling so the proxy transport—not the intentional default limiter—
is measured:

```sh
node scripts/init-dev-jwks.mjs
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.load.yml up -d --build
npm run load:quick
npm run load:soak
npm run load:resilience
```

The quick suite is a short harness check. The full suite covers 1 KiB GETs at
concurrency 1, 50, and 200; 1 MiB uploads and downloads; deterministic mixed
2xx/5xx/timeout traffic; and a 30-minute mixed soak. JSON results are written
under ignored `artifacts/proxy-load/<timestamp>/` directories.

The resilience suite runs sustained traffic while stopping and recovering one
endpoint, then measures the all-down pool with only sanitized `503` responses
accepted. It restores all three development upstreams in a `finally` path. Use
`npm run load:resilience:quick` for its shorter harness check.

Each result includes throughput, p50/p95/p99/max latency, status/error counts,
response bytes, upstream-attempt delta, retry delta, cache-request delta, and
retry amplification. The harness exits nonzero on client errors, `429`, or any
other status outside the scenario's expected set. Suite runners also require a
parseable GreenGateway `/metrics` response, require the deterministic mixed
status counts, require flapping attempt amplification within `1.0`–`1.1`, and
require exactly zero upstream attempts and retries after every endpoint is
unhealthy. Capture host/container resource evidence at the start, peak, and end
of each run:

```sh
docker stats --no-stream
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.load.yml exec gateway \
  sh -c 'printf "fds="; find /proc/1/fd -maxdepth 1 -type l | wc -l; printf "threads="; grep Threads /proc/1/status; printf "rss="; grep VmRSS /proc/1/status'
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.load.yml logs dev-echo-a dev-echo-b dev-echo-c \
  | grep -c '"GET '
```

The last command is a coarse request/accept diagnostic, not a protocol parser.
For authoritative upstream TCP accept counts, run the same suite against an
instrumented target appropriate to the deployment environment.

The committed baseline and interpretation rules live in
[`docs/performance/proxy-baseline.md`](../performance/proxy-baseline.md). Do not
set regression thresholds from a different machine class, debug build, cold
image build, or noisy shared runner.

## Metrics and alerts

Scrape `/metrics` from a protected operational network. Useful starting alerts:

- `/readyz` is non-200 for longer than the active health threshold window.
- `proxy_admission_rejections_total` increases for queue-full or queue-timeout
  reasons.
- retry amplification (`proxy_upstream_attempts_total / completed requests`)
  exceeds the reviewed load-suite baseline.
- `proxy_retry_budget_exhausted_total` increases.
- `upstream_circuit_transitions_total{state="open"}` or
  `upstream_health_transitions_total{state="unhealthy"}` increases repeatedly.
- `egress_client_cache_evictions_total{reason="capacity"}` grows continuously.
- `proxy_stream_terminations_total` grows for `idle_timeout`, `size_limit`,
  `upstream_error`, or `shutdown` outside an expected deployment window.

Route/pool/endpoint metric labels are bounded configuration IDs. Do not add
origins, paths, principals, request IDs, resolved addresses, or raw error text
as labels.

## Rollback

Keep the old route value with the deployment change. To roll back one pool:

1. stop sending new traffic to the canary;
2. restore the previous `upstream_url` route or `UPSTREAM_URL`;
3. remove pool-only `upstreams`, `load_balancing`, `limits`, `health_check`,
   `retry`, `circuit_breaker`, `request_body`, and `sse` fields;
4. restart GreenGateway so transport clients and mounted identity state are
   rebuilt from the restored configuration;
5. wait for `/startupz` and `/readyz`;
6. verify auth/RBAC, request-ID, forwarding-header, audit, and egress behavior
   before returning traffic.

There is no database migration for the proxy pool configuration. Do not
silently weaken egress, TLS, authentication, or authorization to make rollback
pass. If the legacy destination is no longer safe or reachable, keep the
gateway unavailable and correct the infrastructure instead.

## Admin browser isolation

Deploy the control plane on a separate private origin using `ADMIN_LISTEN_ADDR` and edge host routing. Keep data-plane upstreams off that origin. Path prefixes alone are not browser isolation.

All proxied response documents now receive an additional enforced CSP `sandbox; frame-ancestors 'none'`. Upstream headers cannot relax it. HTTP API clients are unaffected; active upstream web applications cannot execute scripts or forms on the gateway origin. Host such applications directly on their own origin. This is an intentional compatibility change for deployments previously browsing application HTML through the API gateway.

Forced response cleanup has a final 100 ms cooperative grace within supervisor headroom. Remaining gRPC connection tasks are owned by their listener and aborted when its drain is cancelled; they are not detached from process shutdown.
