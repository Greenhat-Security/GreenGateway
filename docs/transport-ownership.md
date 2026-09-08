# Transport ownership

Issue #432 inventory, reviewed against main `128ab1a` (2026-09-07).
This records construction authority, not a claim that Rust restricts ambient
network access. Function names below are stable review anchors; line numbers drift.

| Traffic or operation | Production owner | Authority and constraints |
| --- | --- | --- |
| HTTP proxy, ordinary API tools, OpenAPI fetches, SSE and health probes to upstreams | `egress.rs`: `base_client_builder_for_profile`, `pinned_client_with_profile`, checked request methods; `egress/client_cache.rs` stores clients | `EgressClient` validates URL, host, port, current DNS answers and address policy, then pins the checked socket. Cache identity includes destination, TLS and protocol profile; reuse does not bypass current preflight. Proxies and automatic redirects are disabled. |
| DNS | `egress.rs`: `SystemDnsResolver::resolve` | System resolver supplies candidates to the checked-destination policy; it does not itself authorize a connection. |
| MCP streamable HTTP | `egress.rs`: `mcp_http_client` for the legacy adapter; `EgressClient::mcp_reqwest_client_at_checked_destination` for managed connections | Concrete reqwest clients for rmcp are constructed inside egress. Checked host/address, no proxy or redirects, explicit HTTP/1, request/read/connect timeouts. The adapter retains its URL/session/body/deadline checks; managed connections retain configuration-aware TLS/profile revalidation. |
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
boundary. The MCP client factory now belongs to the existing checked transport owner;
keep protocol adaptation in the MCP and WebSocket consumers. Inbound listeners
and the shared PostgreSQL foundation retain their separate construction owners.

The existing `scripts/check-egress-only.sh` remains enforced while the syntax gate
is added. Preserve its reqwest/alias confinement, pinned MCP factory inside egress, separate h2
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

## Running the structural gate

Run `python scripts/transport_guard.py check` with the pinned Rust/Node tools.
CI runs it in the required `egress-only` job after the existing protocol guard,
and retains `target/transport-guard/decision.json`, enumeration, syntax facts and
candidate records. A failure never becomes a successful empty scan.

`transport-ownership.json` records exact file, item/function, syntax SHA256, owner
and purpose. Comparisons use equality, never glob matching. New, changed and stale
records fail. A constructor change inside an already-reviewed function also fails.
Imports, chained renames and reexports use a conservative global alias union;
colliding names can require extra review. This is not lexical/type resolution.

The dependency record covers the complete locked workspace graph, all features,
unfiltered target alternatives, package checksums, dependency edges, workspace
renames and Cargo target declarations. Every new package or feature/edge needs
review, including a networking library whose name the source guard does not know.
These comparisons run before compiling the syntax tool. Build-script input hashes
are separately reviewed. The tool is a dev-only Cargo example using the existing
syn/quote/proc-macro2 packages; it is not linked into the shipped gateway.

The parser follows declared modules from all Cargo targets, parses every enumerated
Rust file, and excludes from production only non-shipped Cargo targets or cfg
expressions provably false with `test=false`. Other feature/target conditions stay
in scope, including inactive platform alternatives. Unowned files, ambiguous paths,
conditional module paths, escaping paths and parse errors fail. Generated Rust
cannot quietly become an unowned source file; supporting a generator requires a
reviewed extension to enumeration and its input contract.

Raw client/socket/process/FFI references, calls to the two concrete MCP client factories
(including inferred local types), conservative unresolved connection methods,
capability imports and glob/renamed imports receive exact review records. PostgreSQL
pool consumers and stream adapters can appear in the records without being socket
constructors. Their purpose labels distinguish them from request egress.

Macro rules, custom macro calls, unrecognized attributes and unsafe/foreign code
require exact scope review. A small explicit set of standard formatting/container,
Tokio expression-container, tracing/metrics, JSON and SQL-parameter macros has a
reviewed implementation through the locked dependency graph; their recursive input
tokens are still scanned for capability names/aliases and connection methods.
Standard derives and serde/async-trait attributes are reviewed transformations over
syntax the parser visits. Macro definitions and renamed imports cannot change
silently. Custom expansion is not executed or claimed to be type-checked by this
gate; existing behavioral tests and dependency review remain necessary.

To change ownership, run `python scripts/transport_guard.py inventory` in a reviewed
checkout. This produces a candidate artifact, never updates policy or reports a
passing check. Review the graph and changed source scopes, explain each owner and
purpose, and edit the exact policy records in the same PR. Do not copy the candidate
over policy without reviewing it; the candidate deliberately lacks scope approvals.
Never add a file-wide bypass or regenerate policy automatically in CI.

## Regression evidence

`cargo test --locked --example transport_guard` parses harmless source fixtures for
direct sockets, chained imports/reexports, type aliases, function pointers, glob
imports, unresolved receivers, macro inputs, custom expansion, cfg variants and
foreign/unsafe code. It never executes the represented networking expressions.

`python -m unittest discover -s scripts -p test_transport_guard.py -v` rejects broad
or missing approvals, changed/new/stale scopes and failed enumeration. Inert Cargo
metadata fixtures prove new packages/features and changed build scripts fail before
tool compilation, and an unknown registry fails before metadata fetching. Both
suites are required by the egress job. Existing local MCP, egress and gRPC suites
continue checking runtime behavior; syntax fixtures do not substitute for them.
