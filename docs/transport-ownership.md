# Transport ownership

Issue #432 inventory, reviewed against main `128ab1a` (2026-09-07).
This records construction authority, not a claim that Rust restricts ambient
network access. Function names below are stable review anchors; line numbers drift.

| Traffic or operation | Production owner | Authority and constraints |
| --- | --- | --- |
| HTTP proxy, ordinary API tools, OpenAPI fetches, SSE and health probes to upstreams | `egress.rs`: `base_client_builder_for_profile`, `pinned_client_with_profile`, checked request methods; `egress/client_cache.rs` stores clients | `EgressClient` validates URL, host, port, current DNS answers and address policy, then pins the checked socket. Cache identity includes destination, TLS and protocol profile; reuse does not bypass current preflight. Proxies and automatic redirects are disabled. |
| DNS | `egress.rs`: `SystemDnsResolver::resolve` | System resolver supplies candidates to the checked-destination policy; it does not itself authorize a connection. |
| MCP streamable HTTP | `tools/mcp_upstream.rs`: `mcp_http_client`, called by checked-target preparation and managed transport code | Existing exception: a concrete reqwest client for rmcp. Checked host/address, no proxy or redirects, explicit HTTP/1, request/read/connect timeouts. The planned migration moves this exact factory into `egress` and retains the wrapper's URL/session/body/deadline checks. |
| gRPC upstream | `egress/grpc.rs`: `EgressClient::connect_grpc`, `handshake_grpc` | Revalidates the checked destination and configuration generation, connects TCP to the pinned address, verifies TLS against the original server name, then builds the dedicated hyper HTTP/2 client. Pool and deadlines remain bounded. |
| WebSocket upstream | `egress.rs` HTTP upgrade path; `proxy/websocket.rs`: `attempt_upgrade` | Checked, pinned HTTP/1 handshake supplies `EgressUpgradedStream`. `WebSocketStream::from_raw_socket` wraps that already-established stream; it does not select or dial another destination. Frame, message, idle and lifetime bounds remain in the bridge. |
| OIDC discovery, token exchange, JWKS, external cookie-session validation, connection authentication/token exchange | `auth/oidc.rs`, `auth/oidc_login.rs`, `auth/jwt.rs`, `auth/cookie_session_validator.rs` and connection auth code consume `EgressClient` | Authentication/provider code is a consumer of checked HTTP, not an independent client factory. Configured identity/provider endpoints still traverse destination policy. |
| PostgreSQL storage, audit, sessions, rate limits and HA coordination | `storage/postgres.rs`: `verified_tls_connector`, `build_pool`, `PostgresFoundation` | Separate infrastructure authority: validated operator DSN, bounded pool/connect/recycle/wait and server-side timeouts, verified TLS except the existing explicit bounded plaintext policy. Repositories borrow the shared pool. This is not arbitrary request-controlled HTTP egress. |
| Data and management listeners | `lifecycle.rs` startup binding; `inbound_tls.rs` listener wrapping and accept loop | Operator listen addresses, separate data/admin authorities and TLS configuration; bounded admission/handshake behavior. These accept inbound connections. |
| gRPC listener | `proxy/grpc/listen.rs`: `GrpcListener::bind`, `build_h2_server` | Separate opt-in configured listener and router, bounded HTTP/2 settings. The client belongs only to `egress/grpc.rs`; normal data/admin listeners do not gain h2c. |
| Local container/process health command | `egress.rs`: `check_local_health` | Dedicated bounded local health request, not an upstream selected by a gateway caller. |
| Build tools | `gateway/build.rs` | Executes pinned UI build tools during compilation; not linked as runtime network authority. Build scripts and proc-macro dependencies must be reviewed separately because syntax scanning does not expand their output. |
| Tests | Cargo test targets and modules reached only under `cfg(test)` | Disposable local servers/clients, PostgreSQL test services and the HA process harness. File names alone are not proof of exclusion from production. |

## Boundary decision

Keep the existing egress module. A new crate would still have access to std/tokio
sockets and would add dependency/build churn without creating an OS capability
boundary. Move the MCP client factory into the existing checked transport owner;
keep protocol adaptation in the MCP and WebSocket consumers. Inbound listeners
and the shared PostgreSQL foundation retain their separate construction owners.

The existing `scripts/check-egress-only.sh` remains enforced while the syntax gate
is added. Preserve its reqwest/alias confinement, pinned MCP factory, separate h2
client/server ownership and forbidden `http2` features on reqwest, axum and
hyper-util. The presence of hyper's own HTTP/2 feature is intentional.

## Structural guard contract

Parse production Rust syntax, including feature and target alternatives. Resolve
import aliases conservatively and require review of new raw networking references,
constructors and dependency exposure. A review record must identify exact source
scope, owner and purpose; a directory wildcard is not an exception. Failed file
enumeration, parsing or locked metadata resolution cannot yield a pass.

Macro expansion, generated source, FFI and external crate implementations are not
fully examined by a syntax parser. Their inputs and dependencies need explicit
review records; unexamined changes must fail review. The gate must describe its
bounded alias handling and must not claim full Rust type or name resolution.
Behavioral tests still establish checked-address pinning, hostname/SNI verification,
redirect rejection, protocol restrictions and fail-closed errors.
