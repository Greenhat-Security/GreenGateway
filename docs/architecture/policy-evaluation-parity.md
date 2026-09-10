# Policy evaluation parity matrix

Contract evidence for [#421](https://github.com/Greenhat-Security/GreenGateway/issues/421). It names, per lane, the legacy decision entry point, the kernel entry point that reproduces it, how inputs are normalized, what happens with no match, and what authority the result is bound to.

**The legacy entry points are still authoritative.** Nothing in `gateway/src/policy_eval/` decides a live request. [#422](https://github.com/Greenhat-Security/GreenGateway/issues/422) owns the cutover, lane by lane, and each lane's legacy implementation is removed only after its differential tests prove parity. Until then the kernel's correctness claim is exactly what its tests assert and no more.

## Lanes

| Lane | Legacy entry point | Kernel entry point | Input normalization | No match | Bound to |
| --- | --- | --- | --- | --- | --- |
| Contextless HTTP direct rules | `matching_direct_rule` → `RuleMatcher::evaluate_with_dispatch` (`middleware/rbac.rs`) | `CompiledPolicy::match_direct`, `canonical_path: None` | Exact already-separated request path; method folded by `MethodMatcher`; `RuleDispatchContext::contextless()` | Falls through to routes | `ResourceSnapshot` + context digest |
| Ordinary permission routes | `matching_route_for_request` → `matching_route_with_host` | `CompiledPolicy::match_route`, `canonical_path: None` | `path_prefix_matches` preserves segment boundaries; wildcard methods; ASCII case folding | Falls through to default | same |
| Default action | `policy.default_action` + `enforcement_mode` arms | tail of `CompiledPolicy::evaluate` | — | `DefaultAllow` / `DefaultDeny` | same |
| Host-qualified routes | `route_host_matches` | `route_host_matches` in `policy_eval` | Host with port and brackets already stripped; bare IPv6 literals recognized by parsing | Unbound route serves any host **unless** an upstream was selected | same |
| Dispatch-scoped direct rules | `RuleDispatchContext::classified_with_route_id` | `HttpTarget::ProxyDispatch` + `DispatchFacts` | Caller-supplied routing facts only; the kernel resolves nothing | Rule does not match | same |
| Selected virtual upstream | `required_upstream_host` branch, `host_policy_required` | `Reason::HostPolicyRequired` | Derived from `route_host`, never carried twice | **Refused outright** — the policy default does not apply and shadow does not soften it | same |
| MCP alias identities | `evaluate_equivalent_paths_with_dispatch` + exact-then-prefix route search | `match_direct` / `match_route` with `canonical_path: Some(..)` | Request path plus the canonical policy identity, carried in `HttpTarget::McpAlias` | Action-major precedence across both identities; route matched exactly on the request path, then by prefix on the canonical one | same |
| Rate lane selection | `policy_rate_limit_request` guard + `RateLimitState::matching_limiter` | `CompiledPolicy::select_rate_lane` | Method, path pattern, principal; **anonymous reaches no override**, reproducing the live early return | `RateLaneOutcome::NoOverride` | `InputBinding` on the selection itself |
| Tool admission | `evaluate_tool_authorization`, `tool_policy_eligibility` (`tools/runtime.rs`, `tools/inventory.rs`) | **not implemented** | — | — | — |
| Static egress | `egress.rs` | **not implemented** | — | — | — |

## Trace reasons and limitation codes

Both sets are stable wire contracts, not internal names. `Reason` serializes as `matched_rule`, `missing_permission`, `missing_principal`, `default_allow`, `default_deny`, `host_policy_required`, `incomplete`. `Limitation` serializes as `missing_method`, `missing_path`, `missing_principal_fact`, `missing_dispatch_fact`, `missing_host_fact`.

Every `Limitation` variant now shares the `Missing` prefix, because every one is a fact that was not supplied — the kernel has no "unsupported" limitation since every target is evaluated. `clippy::enum_variant_names` is allowed there with that reason: dropping the prefix would edit a published contract to satisfy a naming lint.

## What is not evaluated

`Evaluation::not_evaluated` enumerates the stages a policy verdict says nothing about: authentication, CSRF, request admission, management permissions, MCP, tools, rate selection, mutable capacity, egress, DNS, transport, upstream execution, live revision freshness and gateway build identity. An `Allow` or `Observe` is never a statement that a request will succeed or forward.

## Facts the lanes require, and what happens without them

A supported fact that is unavailable produces `indeterminate` with a stable limitation, never a default. Three distinctions are load-bearing:

- **`HostFact` is three-state.** `Absent` is a request that carried no `Host` header; `Missing` is a host that was never captured. Only the second is unanswerable. `upstream_route::request_host_without_port` returning `None` means *absent* — mapping it to `Missing` would turn every Host-less request against a host-qualified policy into a denial the legacy path never produced.
- **`HttpTarget::Missing` means routing was never classified**, which is not the same as a request with no dispatch. A dispatch-scoped rule silently not applying is different from it not matching, and `routing_context_known` is the single bit that decides which happened. Production cannot reach this: `proxy_dispatch_context_middleware` is layered after the RBAC layer in `routing.rs` so that it runs before it, and marks classification unconditionally. `route_classification_is_marked_completed_for_every_path` holds that half of the invariant.
- **A missing principal is not an anonymous principal.** A rule may constrain the principal, so guessing would select a different lane or match a different rule.

## Invariants the kernel's correctness rests on

Neither is enforced by a type, so both are asserted by a test:

- **An MCP alias is never also a classified proxy dispatch.** `HttpTarget::McpAlias` and `ProxyDispatch` are mutually exclusive variants and the kernel evaluates an alias under `contextless()`, while the legacy path threads the real dispatch context into its alias branch. If a request were ever both, the two would diverge in both directions. It cannot happen because `proxy_dispatch_context_middleware` computes an observation context only for paths that are not gateway-owned, and `GatewayRoutes::from_config` puts every `mcp_route_paths` entry into `prefix_owned_paths` — two call sites of the same function, agreeing by shared derivation and nothing else. Asserted by `every_mcp_route_path_is_gateway_owned_so_an_alias_is_never_a_classified_dispatch`.
- **Route indices cross two vectors.** `match_route` enumerates `engine.policy().routes`; an adapter resolving `RuleReference::Route(index)` for audit attribution reads `RbacPolicyState.routes`, a separate clone. They agree today only because both are clones of the same vector in order. The differential fixtures therefore assert the resolved `permission` and `path_prefix`, not only the outcome and reason — an index-base mismatch is otherwise invisible: right verdict, wrong audit record.

## Evidence

The differential tests drive the **real `rbac_middleware`** and compare against it, never a second hand-written evaluator. That is not stylistic. It caught a semantic the kernel had wrong — a selected virtual upstream with no host-bound route is refused outright — where a hand-written oracle would have encoded the same wrong assumption twice and passed. In the same change a hand-written assertion elsewhere in the suite *was* wrong about the same behaviour.

Two corollaries, both learned the hard way:

- **The oracle includes the guard, not just the extracted function.** Comparing the rate lane against `matching_limiter` directly hid that `policy_rate_limit_request` returns before reaching it for a request with no principal, so the kernel was reporting an override governing traffic production never rate-limits.
- **Compare the installed instance, not a copy.** The middleware oracles read the `CompiledPolicy` the `RbacState` installed. A separately compiled copy of the same policy can agree with the middleware while the installed one diverges, and the comparison would not notice.

Purity is asserted rather than assumed: `pure_evaluation_is_thread_safe_deterministic_bounded_and_redacted_without_a_runtime` evaluates with no async runtime present and checks the trace is bounded and carries no identity values, and `evaluating_a_policy_emits_no_audit_events` drives allow, deny, observe and indeterminate decisions plus a rate selection through a capturing audit sink and requires it to stay empty. A shadow observation is *reported* as `Evaluation::observation` for a caller to emit, never emitted by the kernel.

## Digests

`PolicyDigest::Source` covers the exact accepted source bytes and is available only to the offline compiler, the only caller that holds them. `PolicyDigest::ValidatedPolicy` covers an install path that never did: the live gateway hands over an already-parsed `Policy`, and loading canonicalizes it, so the bytes cannot be reconstructed. It carries frame kind `gg.validated-policy.v1`, deliberately outside ADR-0004's reserved `source`/`semantic` namespace — see `policy-evaluation-kernel.md` for why it is not, and cannot become, JCS.

A result bound to one digest is not reusable under the other, and a context pinned to one is rejected by the other rather than answered.
