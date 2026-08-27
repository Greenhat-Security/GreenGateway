# Deploying the gRPC transport

GreenGateway can proxy gRPC transparently over HTTP/2, preserving framing, trailers, deadlines, cancellation, and all four call shapes, while every authentication, authorization, egress, resource, audit, and shutdown boundary stays fail-closed. It is off by default and has to be turned on twice: once for the process, once per route.

## The deployment shape

The gRPC listener speaks **h2c prior knowledge over plaintext**. It does not terminate TLS, does not negotiate ALPN, and does not support the `Upgrade: h2c` mechanism (which hyper 1.x removed and which no gRPC client uses).

The listener reads the HTTP/2 connection preface itself, within a ten-second budget, before it builds anything else. A client sending something other than the preface is dropped there, and a socket that connects and then says nothing cannot hold a connection slot indefinitely. Once the preface has arrived there is no timer on the connection at all: call duration, idle time, and deadlines are bounded per call by the route's policy, which is where a multiplexed transport carrying hour-long streams has to bound them.

That is the conventional shape for a gRPC backend, and it means the gateway must be fronted by something that terminates the client's TLS and re-originates h2c to it. nginx `grpc_pass` and Envoy both do this. Anything that speaks HTTP/1.1 to the container does not, and cannot be made to.

```
gRPC client  --TLS/h2-->  nginx grpc_pass / Envoy  --h2c-->  GreenGateway  --h2 or h2c-->  upstream
```

Outbound is not restricted the same way: the gateway's own gRPC client speaks HTTP/2 over TLS when the endpoint URL is `https`, with ALPN pinned to `h2` and the same trust decision, address pinning, hostname verification, custom-CA isolation, and per-endpoint mTLS identity every other outbound request gets.

### Where gRPC cannot work

**Cloudflare Containers.** Cloudflare terminates the client connection at its edge, and the Durable Object opens its own connection to the container over plain HTTP/1.1. No HTTP/2 connection preface ever reaches the gateway, so the listener would sit on a port nothing speaks HTTP/2 to. This is structural, not a configuration gap: `GRPC_LISTEN_ADDR` is deliberately not forwarded by the Cloudflare wrapper, and setting it in the dashboard has no effect. See [cloudflare.md](cloudflare.md).

**Any front end that re-originates HTTP/1.1.** The same reasoning applies to any load balancer, service mesh sidecar, or platform ingress configured to speak HTTP/1.1 to the backend. Check what your front end originates, not what it accepts.

## Turning it on

### 1. The listener

```sh
GRPC_LISTEN_ADDR=0.0.0.0:8090
```

Unset — the default — means **no HTTP/2 server is constructed at all**. The address must differ from `LISTEN_ADDR` and `ADMIN_LISTEN_ADDR`; a collision is refused at startup.

Two HTTP/2 settings are operator-tunable:

| Setting | Default | What it bounds |
|---|---|---|
| `GRPC_MAX_CONCURRENT_STREAMS` | 100 | Concurrent streams per connection. Multiplies with the connection cap to give the real inbound ceiling. |
| `GRPC_MAX_METADATA_BYTES` | 16384 | Decoded size of one request's metadata. |

The rest of the HTTP/2 settings — frame size, flow-control windows, the pending-accept-reset bound that closes the HTTP/2 Rapid Reset shape, keep-alive, and the accepted-connection cap — are fixed constants stated explicitly in `gateway/src/proxy/grpc/listen.rs`, each with the reason it is not a knob.

### 2. The route

A route carries gRPC only if it declares a `grpc` policy block. A route without one is refused with `UNIMPLEMENTED`; there is no default policy, because a proxy with no limits is exactly what this transport must not be.

```json
[
  {
    "id": "greeter",
    "path_prefix": "/helloworld.Greeter",
    "upstreams": [{ "id": "primary", "url": "https://greeter.internal:443" }],
    "grpc": {
      "max_concurrent_calls": 256,
      "max_concurrent_calls_per_endpoint": 128,
      "queue_depth": 64,
      "queue_timeout_ms": 100,
      "connect_timeout_ms": 10000,
      "idle_timeout_ms": 300000,
      "max_duration_ms": 3600000,
      "max_message_bytes": 4194304,
      "max_request_bytes": 268435456,
      "max_response_bytes": 268435456,
      "max_metadata_entries": 64
    }
  }
]
```

Every field has a default; the block may be `{}`. Notable ones:

- **`max_concurrent_calls` counts CALLS, not connections.** gRPC multiplexes many streams over one connection, so a connection count would bound nothing. This is a separate admission pool from the route's HTTP `limits.max_in_flight`, because a streaming call can hold its slot for an hour and sharing the pool would let a few streams starve the route's HTTP traffic.
- **`max_duration_ms` is also the cap on a client's `grpc-timeout`.** A client asking for two hours on a route whose ceiling is five minutes gets five minutes, and the value forwarded upstream is the gateway's, never the client's bytes. `0` disables the ceiling, in which case an uncapped client deadline is honoured.
- **`idle_timeout_ms`** is measured on the upstream-to-client direction, which is where a stalled server shows up. `0` disables it.
- **`max_message_bytes`** applies to the *encoded* message — the length declared in the five-byte gRPC envelope — in both directions, and is enforced on the declaration rather than after the bytes have been forwarded.
- **`max_metadata_entries`** bounds the *count* of metadata entries, in headers and trailers independently. `GRPC_MAX_METADATA_BYTES` bounds their size; a byte budget does not constrain a count.

`grpc` cannot be combined with `upstream_url` (it needs an `upstreams` pool) or with `connection_id` (injecting a managed credential once for a stream that then lives for an hour is a different security question, deferred rather than assumed safe).

### 3. Authentication

The gRPC listener runs the identical middleware stack as the data listener — the same `apply_middleware` call, with the same value: authentication, rate limiting, CSRF, request validation, route classification, RBAC, and direct policy, in the same order.

Two consequences worth planning for:

- **CSRF applies.** A gRPC call must carry a bearer credential in `authorization` metadata, be on a `CSRF_EXEMPT_PATHS` entry, or run with `CSRF_ENABLED=false`. This is the same rule non-browser HTTP clients already follow.
- **Authorization is by method path.** The canonical identity is `/package.Service/Method`, which is the HTTP path, so existing RBAC path rules apply to it directly:

```json
{ "path": "/helloworld.Greeter/*", "methods": ["POST"], "action": "allow", "roles": ["greeter-client"] }
```

The method path is held to the protobuf identifier grammar — a dot-separated sequence of identifiers, a slash, one identifier, nothing else — so it has exactly one spelling. The string RBAC evaluates, the string audit records, and the string sent upstream as `:path` are the same bytes.

## What crosses the boundary

The gateway terminates both sides and re-originates the call. Nothing is tunnelled.

**Removed from the request:** every hop-by-hop header, every header nominated by `Connection`, `Host`, `Content-Length`, the client's `Authorization` and `Cookie`, the gateway request ID, every spoofable client-IP forwarding header, and any `grpc-status` / `grpc-message` a client tried to send.

**Stated by the gateway:** `:authority` (derived from the validated endpoint, never from a header), `content-type` (the canonical constant matched against the allow-list, not the caller's bytes), `te: trailers`, `grpc-timeout` (the capped deadline), and `x-forwarded-for` / `x-real-ip` (the gateway's own view of the caller).

**Forwarded transparently:** application metadata, `grpc-encoding` and `grpc-accept-encoding` (compression is end-to-end; the gateway neither compresses nor decompresses), message bytes, the upstream's **server initial metadata** (its response headers), and the upstream's own response trailers including its `grpc-status` and `grpc-message`.

Response metadata is relayed under the same three rules as the request direction: the forbidden names are removed, the entry count is bounded by `max_metadata_entries`, and `content-type` and `Trailer` are the gateway's own rather than the upstream's bytes. A `grpc-status` in the headers of a response that then carries messages is removed rather than relayed -- an upstream cannot know the outcome before it has sent the messages, and a client that read a status early would apply it to messages it had not seen.

A genuine **Trailers-Only** answer -- the status in the HEADERS frame with `END_STREAM`, which is how a gRPC server says `NOT_FOUND` -- is relayed as one, with the upstream's own status and message preserved. What distinguishes it from a premature status is the end of the stream, not the presence of the header.

To inject an upstream credential, use the route's `add_request_headers`.

## Error mapping

A call refused before it reached the endpoint produces a protocol-correct **trailers-only** response: HTTP 200 whose HEADERS frame carries the status and ends the stream. It is never an HTTP error status, and never a successful message envelope.

| Refusal | gRPC status |
|---|---|
| Authentication denied | `UNAUTHENTICATED` (16) |
| RBAC or direct-policy denial | `PERMISSION_DENIED` (7) |
| Rate limited, admission queue full or timed out, a bound exceeded | `RESOURCE_EXHAUSTED` (8) |
| Malformed method path, content type, `TE`, `grpc-timeout`, or framing | `INVALID_ARGUMENT` (3) or `INTERNAL` (13) |
| No route, or a route with no `grpc` policy block | `UNIMPLEMENTED` (12) |
| Draining, no healthy endpoint, endpoint unreachable, upstream misbehaving | `UNAVAILABLE` (14) |
| The call's own deadline elapsed | `DEADLINE_EXCEEDED` (4) |
| A path that is not a gRPC method path at all -- every gateway-owned probe path included, since this listener serves none of them | `INVALID_ARGUMENT` (3) |
| The client went away mid-stream | `CANCELLED` (1) |

An upstream `grpc-status` is preserved verbatim **only** after an authenticated, authorized call reached the selected endpoint and the upstream answered HTTP 200 with a gRPC content type. That holds for both shapes an upstream can use: a status in the trailers after messages, and a Trailers-Only answer with the status in the HEADERS frame. Anything else is the gateway's own status.

One deliberate deviation from the gRPC-over-HTTP2 specification's suggested table: HTTP 429 maps to `RESOURCE_EXHAUSTED` rather than `UNAVAILABLE`. The specification's table is written for an intermediary that cannot know why a 429 was produced; here it is always this gateway's own rate limiter, and `RESOURCE_EXHAUSTED` tells a client the call was refused rather than that the server was down — which changes whether retrying is sensible.

## Retries

**Retries are disabled for gRPC**, and a streaming call is never replayable in any case. A route's `retry` block does not apply to its gRPC calls.

One pooled-connection case is not a retry and is worth naming: if a pooled HTTP/2 connection was closed by the peer while it sat idle, the gateway opens a new one. No bytes of the call had reached the upstream, so nothing is replayed.

## Observability

Metrics (all labels are configured identifiers or fixed literals — the method path is never a metric label, because its cardinality is chosen by the caller):

- `proxy_grpc_calls_total{pool_id,result,reason,status}`
- `proxy_grpc_active_calls{pool_id,endpoint_id}`
- `proxy_grpc_messages_total{pool_id,endpoint_id,direction}`
- `proxy_grpc_bytes_total{pool_id,endpoint_id,direction}`
- `proxy_grpc_call_duration_seconds{pool_id,endpoint_id,status}`
- `grpc_listener_connections_total{outcome}` -- `closed`, `drained`, `error`, or `preface_rejected` for a client that was not speaking HTTP/2 -- and `grpc_listener_connections_active`
- `grpc_upstream_connections_total{result}`, `grpc_upstream_connection_slots`

Audit: one `upstream.grpc_call` event per call, carrying pool, endpoint, method identity, result, bounded reason, gRPC status name, deadline, per-direction message and byte counts, and duration.

Protobuf message bytes are counted and forwarded, never read — the only thing parsed out of a body is the five-byte envelope header — and the upstream's raw `grpc-message` is forwarded to the client but never recorded. The method identity appears as an audit field only after it has passed the grammar; a path that failed validation is caller-controlled bytes and is not recorded at all.

## Non-goals

gRPC-Web transcoding, protobuf schema discovery, protobuf inspection or rewriting, reflection-based authorization, RFC 8441 extended `CONNECT`, and automatic retry of streaming or non-idempotent calls.
