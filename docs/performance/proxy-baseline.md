# Proxy performance baseline

This baseline is an engineering comparison aid, not a service-level objective.
Results are meaningful only when the same revision, release build, machine
class, container limits, network topology, and load command are recorded.

## Reproduce

Start the seeded three-upstream stack:

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.load.yml up -d --build
```

Run the short harness check:

```sh
npm run load:quick
```

Run the release-candidate suite, including the 30-minute soak:

```sh
npm run load:soak
npm run load:resilience
```

The scripts write machine-readable JSON under
`artifacts/proxy-load/<timestamp>/`. Preserve those artifacts with the release
evidence. Record `docker stats`, gateway `/proc/1/status`, descriptor count, and
upstream accept evidence as described in the
[deployment guide](../deployment/production-data-plane.md#load-and-soak-reproduction).

## Comparison rules

- Use a release image, not `cargo run` or a debug binary.
- Warm the stack before recording both candidate and comparison runs.
- Keep CPU/memory limits and the load-generator host fixed.
- Compare p50/p95/p99, throughput, RSS, descriptors, task/thread count,
  upstream accepts, retry amplification, and status mix.
- A 1 MiB streamed transfer must not create request-sized growth per
  concurrent request beyond the explicitly buffered compatibility mode.
- The 30-minute soak must finish without monotonic RSS, descriptor, task, cache,
  or queue growth.
- An all-down pool must remain bounded: no busy loop, retry storm, or attempts
  above the configured maximum.
- Do not set a numeric CI regression threshold until at least two repeat runs on
  the intended runner class establish normal variance.

## Issue #239 development baseline

The following controlled comparison was recorded on 2026-07-26 using Docker
Desktop on a Windows development host. Both release images used the same
isolated Docker bridge, dedicated Python HTTP/1.1 upstream, legacy single-route
configuration, disabled authentication, warmed containers, and this command:

```sh
node scripts/proxy-load.mjs --base-url <gateway> --requests 100 \
  --concurrency 1 --response-bytes 1024 --output <result>.json
```

The comparison revision is `450ca10`, the last revision before the pooling
series. The candidate binary is from `6910708`, the issue #239 main branch after
PR #10. Upstream accept counters were reset immediately before each run.

| Measurement | Pre-pooling `450ca10` | Candidate `6910708` |
| --- | ---: | ---: |
| Successful responses | 100/100 | 100/100 |
| Throughput | 179.467 req/s | 20.487 req/s |
| p50 latency | 4.761 ms | 51.450 ms |
| p95 latency | 9.485 ms | 92.137 ms |
| p99 latency | 19.254 ms | 95.674 ms |
| Maximum latency | 29.317 ms | 96.589 ms |
| Upstream TCP accepts | 102 | 2 |
| Gateway memory after run | 6.879 MiB | 7.898 MiB |
| Gateway processes/threads | 18 | 18 |

The candidate reduced upstream TCP accepts by approximately 98%, demonstrating
that the pooled transport reused its connection. It was nevertheless 88.6%
slower in this concurrency-one microbenchmark and had materially higher
latency. The result is consistent with a keep-alive interaction between the
pooled client and this small Python HTTP/1.1 server, but it does not establish a
root cause. Treat the result as a regression signal, not as a performance
improvement.

The candidate harness also completed these functional development checks
without client errors or unexpected statuses:

| Scenario | Result |
| --- | --- |
| 1 MiB streamed upload, concurrency 10 | 20/20 HTTP 200; 33.134 req/s; p95 416.350 ms |
| 30-second mixed harness check, concurrency 50 | 6,786 responses; 215.617 req/s; p95 1,504.771 ms |
| Mixed retry amplification | 7,464 attempts / 6,786 responses = 1.099912 |

The mixed scenario intentionally returns 70% HTTP 200 and 10% each HTTP 500,
503, and 504. The measured status mix was exactly 4,752/678/678/678.

### Thirty-minute soak and cold-start regression

The issue #239 release candidate then completed a continuous 30-minute mixed
soak at concurrency 50:

| Measurement | Result |
| --- | ---: |
| Completed responses | 395,610 |
| Throughput | 219.601 req/s |
| p50 / p95 / p99 latency | 92.942 / 1,504.894 / 1,518.899 ms |
| Intended 200 / 500 / 503 / 504 responses | 276,893 / 39,556 / 39,556 / 39,556 |
| Upstream attempts / retries | 435,117 / 39,556 |
| Retry amplification | 1.099864 |
| Gateway RSS, start / observed peak / end | 68,660 / 110,652 / 104,160 KiB |
| Threads, start / end | 56 / 56 |
| File descriptors, start / end | 124 / 35 |
| Fixed endpoint-cache entries | 10 |

RSS warmed, reached its observed peak, and then fell before the run ended.
Thread and descriptor counts remained bounded, the endpoint cache stayed at its
fixed cardinality, and retry amplification matched the configured one-retry
mixed workload. Docker's final memory reading was 231.1 MiB; that figure
includes filesystem-backed SQLite pages and is recorded separately from RSS.

The first version of this soak also returned 49 unexpected HTTP 401 responses
during the initial concurrent JWT verification wave. That exposed a cold-cache
JWKS refresh race: waiters whose refresh was coalesced did not re-check the key
cache after the leading request populated it. The release candidate now
re-checks only the verified cache after the coordinated refresh, preserving
fail-closed behavior. A deterministic 50-way first-use regression test verifies
one JWKS fetch and no rejected valid token.

After rebuilding a fresh container with that fix, a 5,000-request,
concurrency-50 mixed run completed with zero client errors, zero unexpected
statuses, and the exact expected 3,500/500/500/500 status mix. It sustained
210.678 req/s with 1.100 retry amplification. This short cold-start rerun is the
direct regression proof for the isolated first-wave fault; the completed
30-minute soak remains the proxy resource-stability evidence.

## Release-gate status

This development record makes the observed behavior reproducible and preserves
an honest before/after result, but it does **not** define a production
throughput or latency threshold. Before the first release that treats
performance as an automated gate:

1. repeat both revisions on the intended Linux runner with fixed CPU and memory
   limits;
2. investigate or explicitly accept the low-concurrency latency regression;
3. repeat the candidate run at least twice to establish variance; and
4. set numeric thresholds from those Linux results.

Until that evidence exists, performance remains a manual release review gate.
No throughput or latency improvement is claimed by issue #239.
