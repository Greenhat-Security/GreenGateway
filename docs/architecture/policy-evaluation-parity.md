# Policy evaluation parity matrix

Contract evidence for [#421](https://github.com/Greenhat-Security/GreenGateway/issues/421). It names, per lane, the legacy decision entry point, the kernel entry point that reproduces it, how inputs are normalized, what happens with no match, and what authority the result is bound to.

**HTTP/RBAC now uses the shared evaluator (#422, PR 1).** The table names the pre-cutover entry points and the kernel replacements. The old HTTP middleware and matching helpers remain only in `rbac_legacy_tests.rs` as a frozen test oracle; they are absent from serving builds. Tool admission, rate selection, static egress and analysis consumers have not been migrated.

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
| Tool invocation | `ToolRuntime::execute_with_context` → `authorize_tool_call`, `prepare_invocation` | `evaluate_tool`, `Invocation` | Runtime Actor-projected identity; exact tool name | Enabled matching entry allows without a tool rule; absent entry denies | Policy `ResourceSnapshot` + tool context digest |
| Tool visibility | `ToolRuntime::tool_visible_to_context` | `evaluate_tool`, `Visibility` | Same runtime identity; registry listing remains outside | Enabled matching entry visible; absent entry hidden | same, operation-bound |
| Inventory eligibility | `RbacState::tool_policy_eligibility` via inventory | `evaluate_tool`, `PolicyEligibility` | Authenticated Principal directly | Exact existing eligible/reason pair | same, operation-bound |
| Composite leaf enablement | `ToolRuntime::composite_leaf_enabled` | `evaluate_tool`, `CompositeLeaf` | Exact policy name; ignores identity/tool rules under an existing grant | Absent entry denies | same, operation-bound |
| Rendered tool HTTP rules | `ToolRuntime::authorize_http_operation` | `evaluate_tool`, `RenderedHttp` | Exact separated rendered path/method; runtime identity; **unknown dispatch** | Allow; no route/default fallback | same, operation-bound |
| Static egress | `egress.rs` | **not implemented** | — | — | — |

## Trace reasons and limitation codes

Both sets are stable wire contracts, not internal names. `Reason` serializes as `matched_rule`, `missing_permission`, `missing_principal`, `default_allow`, `default_deny`, `host_policy_required`, `incomplete`. `Limitation` serializes as `missing_method`, `missing_path`, `missing_principal_fact`, `missing_dispatch_fact`, `missing_host_fact`.

Every `Limitation` variant now shares the `Missing` prefix, because every one is a fact that was not supplied — the kernel has no "unsupported" limitation since every target is evaluated. `clippy::enum_variant_names` is allowed there with that reason: dropping the prefix would edit a published contract to satisfy a naming lint.

## What is not evaluated

`Evaluation::not_evaluated` enumerates the stages a policy verdict says nothing about: authentication, CSRF, request admission, management permissions, MCP, tools, rate selection, mutable capacity, egress, DNS, transport, upstream execution, live revision freshness and gateway build identity. An `Allow` or `Observe` is never a statement that a request will succeed or forward.

## Facts the lanes require, and what happens without them

A supported fact that is unavailable produces `indeterminate` with a stable limitation, never a default. Three distinctions are load-bearing:

- **`HostFact` is three-state.** `Absent` is a request that carried no `Host` header; `Missing` is a host that was never captured. Only the second is unanswerable. `upstream_route::request_host_without_port` returning `None` means *absent* — mapping it to `Missing` would turn every Host-less request against a host-qualified policy into a denial the legacy path never produced. A malformed or oversized `Host` also yields `None`, but request admission has already answered such a request `400` or `431` before any policy runs (see below), so by evaluation time `None` is a request with no host.
- **`HttpTarget::Missing` means routing was never classified**, which is not the same as a request with no dispatch. A dispatch-scoped rule silently not applying is different from it not matching, and `routing_context_known` is the single bit that decides which happened. Production cannot reach this: `proxy_dispatch_context_middleware` is layered after the RBAC layer in `routing.rs` so that it runs before it, and marks classification unconditionally. `route_classification_is_marked_completed_for_every_path` holds that half of the invariant.
- **A missing principal is not an anonymous principal.** A rule may constrain the principal, so guessing would select a different lane or match a different rule.

## Invariants the kernel's correctness rests on

Neither is enforced by a type, so both are asserted by a test:

- **An MCP alias is never also a classified proxy dispatch.** `HttpTarget::McpAlias` and `ProxyDispatch` are mutually exclusive variants and the kernel evaluates an alias under `contextless()`, while the legacy path threads the real dispatch context into its alias branch. If a request were ever both, the two would diverge in both directions. It cannot happen because `proxy_dispatch_context_middleware` computes an observation context only for paths that are not gateway-owned, and `GatewayRoutes::from_config` puts every `mcp_route_paths` entry into `prefix_owned_paths` — two call sites of the same function, agreeing by shared derivation and nothing else. Asserted by `every_mcp_route_path_is_gateway_owned_so_an_alias_is_never_a_classified_dispatch`.
- **Route indices cross two vectors.** `match_route` enumerates `engine.policy().routes`; an adapter resolving `RuleReference::Route(index)` for audit attribution reads `RbacPolicyState.routes`, a separate clone. They agree today only because both are clones of the same vector in order. The differential fixtures therefore assert the resolved `permission` and `path_prefix`, not only the outcome and reason — an index-base mismatch is otherwise invisible: right verdict, wrong audit record.

## Rejections the kernel keeps, and why a served request cannot reach them

`EvaluationError` has ten variants. Seven are adapter-controlled or unreachable by construction, as [#422](https://github.com/Greenhat-Security/GreenGateway/issues/422) enumerates. The other three — `ContextTooLarge`, `InvalidPrincipal` and `InvalidHost` — were reachable from production until [#488](https://github.com/Greenhat-Security/GreenGateway/issues/488) moved each limit to where a limit belongs, with a status code of its own:

| Kernel rejection | Trigger | Refused first by | Answer |
| --- | --- | --- | --- |
| `ContextTooLarge` | path over `MAX_REQUEST_PATH_BYTES` (8 KiB, also the setting's ceiling) | `middleware::validate`, before authentication | `414` |
| `ContextTooLarge` | method over 64 bytes | same | `501` |
| `ContextTooLarge` | host over 4 KiB (`Host` field or the target's `:authority`) | same | `431` |
| `ContextTooLarge` | more than 256 roles, a role over 256 bytes, a subject or issuer over 4 KiB | every `SessionValidator`, through `auth::principal::check_principal_shape` (`Principal::check_shape`): JWT, cookie-session introspection and service tokens judge the facts they shape from a credential; the client-certificate validator holds the bound by construction (`MAX_IDENTITY_BYTES <= MAX_PRINCIPAL_SUBJECT_BYTES` is a compile-time assertion, roles are empty, the issuer is a constant) and judges the built principal all the same | `401` |
| `InvalidPrincipal` | an empty subject or an empty role | same | `401` |
| `InvalidHost` | a host that is not a bare host, from either source | `upstream_route::host_header`, read by admission | `400` |
| `ContextTooLarge` | a dispatch fact (route id, route host, route path prefix, upstream origin) over 4 KiB, or an MCP alias identity over 8 KiB | configuration validation at startup: route ids and hosts are bounded below it by their own grammars, and route path prefixes, upstream URLs and `GATEWAY_PUBLIC_URL` (from which the origin and the MCP resource path derive) are refused above `request_bounds::MAX_DISPATCH_FACT_BYTES` | refused configuration |

The kernel keeps its checks: it is pure and states its own work limit rather than trusting that a caller applied one. What changed is that both sides now read the same constants (`request_bounds`, `auth::principal`) and, for the host, the same predicate (`upstream_route::is_bare_host`), and `request_host_without_port` no longer produces anything that predicate refuses. `the_kernel_bounds_are_exactly_the_bounds_admission_and_authentication_enforce` pins each boundary on both sides of the same byte, and `a_request_and_principal_that_pass_admission_and_authentication_cannot_be_refused_by_the_kernel_for_shape` is a property over lengths and host forms: whatever `request_shape_problem` and `check_principal_shape` accept, `evaluate` never answers with one of the three.

The issuer bound is worth a sentence. A principal's issuer is configuration — the provider's normalized `issuer`, or `provider:<name>` — not a claim, so an issuer over 4 KiB is an operator's mistake rather than an attacker's input. Configuration validation refuses it at startup, and the JWT and cookie-session validators judge it by the same predicate at every authentication all the same, so it cannot reach the kernel by either route. Note that the validator's rejection text (`principal claims out of bounds: ...` for a JWT, `cookie-session claims out of bounds: ...` for an introspected session) is the individual validator's verdict; the validator chain every deployment runs (`auth::ChainValidator`) reports the generic `no configured auth provider accepted the credential` to `auth.failure`.

## Evidence

The differential matrices drive both the **frozen original middleware** and the **live `rbac_middleware` adapter** against the kernel. The oracle is the original implementation, never a newly hand-written evaluator or the new adapter alone. That is not stylistic. It caught a semantic the kernel had wrong — a selected virtual upstream with no host-bound route is refused outright — where a hand-written oracle would have encoded the same wrong assumption twice and passed. In the same change a hand-written assertion elsewhere in the suite *was* wrong about the same behaviour.

Two corollaries, both learned the hard way:

- **The oracle includes the guard, not just the extracted function.** Comparing the rate lane against `matching_limiter` directly hid that `policy_rate_limit_request` returns before reaching it for a request with no principal, so the kernel was reporting an override governing traffic production never rate-limits.
- **Compare the installed instance, not a copy.** The middleware oracles read the `CompiledPolicy` the `RbacState` installed. A separately compiled copy of the same policy can agree with the middleware while the installed one diverges, and the comparison would not notice.

Purity is asserted rather than assumed: `pure_evaluation_is_thread_safe_deterministic_bounded_and_redacted_without_a_runtime` evaluates with no async runtime present and checks the trace is bounded and carries no identity values, and `evaluating_a_policy_emits_no_audit_events` drives allow, deny, observe and indeterminate decisions plus a rate selection through a capturing audit sink and requires it to stay empty. A shadow observation is *reported* as `Evaluation::observation` for a caller to emit, never emitted by the kernel.

## Digests

`PolicyDigest::Source` covers the exact accepted source bytes and is available only to the offline compiler, the only caller that holds them. `PolicyDigest::ValidatedPolicy` covers an install path that never did: the live gateway hands over an already-parsed `Policy`, and loading canonicalizes it, so the bytes cannot be reconstructed. It carries frame kind `gg.validated-policy.v1`, deliberately outside ADR-0004's reserved `source`/`semantic` namespace — see `policy-evaluation-kernel.md` for why it is not, and cannot become, JCS.

A result bound to one digest is not reusable under the other, and a context pinned to one is rejected by the other rather than answered.

## Tool lane evidence and cutover limits

`policy_eval::tools::tests` compares all five operations against the installed
policy and unchanged live consumers. The admission matrix varies global mode,
default, first-rule action, identity constraints, anonymous/authenticated callers,
and absent/disabled entries. It checks invocation errors, work execution,
visibility, inventory reason codes and composite enablement. Audit comparisons
check event type and original rule attribution, including source ordinals after
disabled and unrelated rules. Rendered HTTP fixtures distinguish unknown from
contextless dispatch and prove that no-match allows even with a deny default,
a permission route and no tool entry. Shadow stays visible/eligible but produces
Observe for invocation/rendered HTTP.

Tool context version 1 and semantics `gg-tool-policy-v1` are independent of the
HTTP context version. Every result binds the operation and all supplied policy
facts. Missing facts fail closed; malformed facts return errors. Inventory has
no anonymous live contract, so an anonymous inventory context is inconsistent.
Composite enablement can complete with a missing identity because it does not
use identity. The new API is bounded, but a live adapter still needs parity at
its rejection boundaries: policy tool names have no equivalent 4 KiB bound, and
rendered HTTP method/path facts do not pass through inbound request admission.

The runtime Actor projection accepts three auth modes and currently drops a
client-certificate identity, whereas inventory retains it. The differential
fixture pins both outcomes. Adapters must preserve or explicitly change that
behavior with both authorities tested. `evaluate_tool_http_rule` currently loads
the current policy instead of `effective_policy()`; this pure extraction accepts
an explicit snapshot and does not change that live pinning behavior.

Registry existence and listing metadata, composite grant validity, enum-source
refresh, non-RBAC permissive fallback, transport and mutable execution state are
outside this contract. The named operation and `not_evaluated` trace fields make
those limits explicit. Static egress remains outstanding under #421.
