# Production Proxy Data Plane PR 1 Implementation Plan

**Goal:** Complete checklist item 1 of issue #239 with an accepted security ADR, behavior-preserving proxy/lifecycle extraction, injectable resolver/clock seams, and focused regression evidence.

**Architecture:** Keep `main.rs` as the composition root and current pre-forward security gate. Move already-shipped forwarding and health mechanics into `proxy`, listener serving into `lifecycle`, and DNS lookup behind a crate-private resolver owned by `EgressClient`. No new data-plane feature or configuration ships in this slice.

**Tech stack:** Rust, Axum, Tokio, reqwest, async-trait, Markdown, existing local test infrastructure

## File map

- Create `docs/adr/0005-production-proxy-data-plane.md`.
- Modify `docs/adr/README.md`.
- Modify `docs/architecture.md`.
- Create `gateway/src/proxy/mod.rs` (and focused module tests where useful).
- Create `gateway/src/lifecycle.rs`.
- Modify `gateway/src/egress.rs` for resolver injection.
- Modify `gateway/src/main.rs` for module wiring and behavior-preserving delegation.
- Add a focused integration test only if module-level tests cannot prove a required gate.

Do not add dependencies, configuration keys/fields, public routes, metrics, production pooling, retries, streaming, readiness, shutdown, SSE, or mTLS behavior. Three intentional security corrections are in scope: every reqwest client built by `EgressClient` disables ambient process proxy discovery so environment variables cannot bypass exact destination pinning; proxy, health, identity-egress, and MCP transport logs replace raw errors with bounded safe categories; and the non-standard hop-by-hop `Proxy-Connection` header is stripped in both directions.

## Task 1: Freeze the security design

- [ ] Create ADR-0005 from the reviewed design specification.
- [ ] Label future pooling/lifecycle behavior explicitly as target architecture.
- [ ] Record current compatibility anchors and non-goals.
- [ ] Define logical-route versus physical-endpoint identity and zero-egress-before-authorization.
- [ ] Define all-answer DNS validation, exact pinning, no stale fallback, and the future transport cache key.
- [ ] Define target config vocabulary without implementing it.
- [ ] Define lifecycle/health/SSE/mTLS target boundaries and the threat model.
- [ ] Index ADR-0005 and add a concise target-data-plane section/link to `docs/architecture.md`.
- [ ] Run Markdown structure/link/diff checks and commit the documentation unit.
- [ ] Send that commit to one external senior reviewer and parallel independent Codex security/production reviewers; resolve all critical and important findings.

## Task 2: Introduce the resolver seam

- [ ] Add a crate-private async `Resolver` trait returning a complete `Vec<SocketAddr>` or `io::Error`.
- [ ] Add `SystemResolver` that delegates to `tokio::net::lookup_host`.
- [ ] Store `Arc<dyn Resolver>` in `EgressClient`.
- [ ] Keep `EgressClient::new` as the production constructor and delegate to an internal injectable constructor.
- [ ] Add `reconfigured`/equivalent derived-client construction that preserves the resolver `Arc`; route timeout/custom-CA overrides must use it rather than `EgressClient::new`.
- [ ] Call reqwest's `no_proxy()` on the shared base builder and every derived pinned client path; do not honor ambient `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`.
- [ ] Call `no_proxy()` on the separately built MCP reqwest transport after egress validation/pinning and cover it with the same hostile-environment isolation model.
- [ ] Route every existing lookup through the stored resolver.
- [ ] Keep hostname/port validation, all-answer IP/NAT64 validation, first-address selection, exact pinning, SNI, certificate validation, redirects, and error mapping unchanged.
- [ ] Add a deterministic fake resolver with call accounting.
- [ ] Test mixed answers, empty answers, resolver errors, and validate-all-before-pin behavior.
- [ ] Add an isolated subprocess/environment test proving hostile proxy environment variables receive zero connections while the injected exact pin receives the request.
- [ ] Test a route-derived timeout/custom-CA client still uses the injected fake resolver and never ambient DNS.
- [ ] Test at least one non-proxy default-constructor path or shared constructor invariant because OIDC/MCP/tools also use `EgressClient`.
- [ ] Run focused egress tests, formatting, clippy, and diff checks; commit the resolver unit.

## Task 3: Extract proxy responsibilities

- [ ] Move proxy route/state, current health state, route-egress-client selection, target/header helpers, one-attempt forwarding, response forwarding, and sanitized proxy errors to `gateway/src/proxy/mod.rs`.
- [ ] Keep a small `main.rs` fallback adapter with the current metrics and safety-gate ordering.
- [ ] Avoid duplicate implementations or compatibility shims that can drift; use narrow `pub(crate)` exports only where composition requires them.
- [ ] Preserve Axum state/middleware order and the current observation context.
- [ ] Preserve legacy fallback, route order, host matching, URL/base-path behavior, custom CA behavior, timeouts, request/response limits, health behavior, and generic errors, except for the explicit fail-closed ambient-proxy correction.
- [ ] Preserve every credential, forwarding, hop-by-hop, nominated, request-ID, configured add/strip, and framing header rule, with the explicit addition of unconditional `Proxy-Connection` stripping.
- [ ] Replace raw proxy request, response-first-chunk, request-body-read, health-check, and egress enforcement details in logs with bounded safe categories; preserve client status/body behavior.
- [ ] Test captured proxy/health/egress failure logs do not contain URLs, queries, addresses, DNS messages, certificate paths, or raw reqwest errors.
- [ ] Add or relocate focused tests without mechanically moving unrelated `main.rs` tests.
- [ ] Assert authentication denial, both rate-limit stages, validation, CSRF, RBAC/direct-rule denial, unsafe paths, and gateway-owned paths cannot cause request-scoped endpoint selection, resolver calls, or upstream bytes; disable or separately account for background health.
- [ ] Run focused proxy tests, egress-only guard, formatting, clippy, and diff checks; commit the extraction unit.

## Task 4: Extract lifecycle composition and clock

- [ ] Move `GatewayApp`, listener bind/serve orchestration, and `serve_router` to `gateway/src/lifecycle.rs`.
- [ ] Preserve unified and split listener addresses, routers, startup emissions, task joining, and failure propagation exactly.
- [ ] Add a minimal injectable clock for current timestamp/sleep behavior only where extraction needs it.
- [ ] Keep health policy/state in the proxy boundary; do not implement signals, readiness, cancellation, drain, or audit flush.
- [ ] Add deterministic tests for the clock seam and current immediate-then-30-second health schedule where practical.
- [ ] Test unified and split ephemeral binding, actual bound addresses in `gateway.startup`, second-bind failure with no startup event or half-serving data listener, and `ConnectInfo` peer-address delivery.
- [ ] Preserve `tokio::try_join!` peer cancellation/failure propagation and cover it with a focused injected-server-future test if Axum cannot be made to fail deterministically.
- [ ] Run lifecycle/main focused tests, formatting, clippy, and diff checks; commit the lifecycle unit.

## Task 5: Production-readiness verification

- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo clippy --workspace -- -D warnings`.
- [ ] Run `cargo test --workspace`.
- [ ] Run `bash scripts/check-egress-only.sh` (or the repository-supported equivalent shell when Bash is unavailable).
- [ ] Run `git diff --check` and review `origin/main..HEAD` for unrelated changes.
- [ ] Scan for direct outbound primitives outside allowed egress locations.
- [ ] Scan the diff for secret material, insecure TLS flags, fail-open behavior, raw upstream/resolver error leakage, ignored tests, and placeholders.
- [ ] Have the committed final diff reviewed in parallel by the external senior reviewer and at least two independent Codex reviewers: security/SSRF and behavior/production readiness.
- [ ] Resolve findings, rerun the complete gate, and record exact test evidence.

## Task 6: Publish the focused PR

- [ ] Push `codex/issue-239-proxy-design-extraction`.
- [ ] Open a ready PR stacked on #244 only while #244 is unmerged because it owns ADR-0004; retargeting to `main` after #244 lands is the normal final state.
- [ ] Include `Part of #239`, checklist item 1 scope, explicit non-goals, threat controls, test evidence, and review evidence.
- [ ] State that this PR does not make the full issue #239 epic production-ready.
- [ ] Inspect remote diff/check status and fix any branch/CI discrepancy before handoff.

## Required final evidence

- Every new resolver/clock test is deterministic and internet-independent.
- A denial path proves zero DNS and zero upstream work.
- No security default, public behavior, or error-redaction contract weakens.
- Existing workspace tests pass, with any pre-existing/flaky result isolated and rerun rather than hidden.
- No unresolved critical or important reviewer finding remains.
- The PR is reviewable as one issue #239 checklist item and does not claim completion of the 11-PR epic.
