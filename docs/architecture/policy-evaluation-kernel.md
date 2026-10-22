# Pure policy evaluation foundation

Issue #421 introduces `gateway/src/policy_eval/`. **The HTTP/RBAC adapter now
uses it for live decisions**, including routes, host qualification, dispatch
constraints and raw/canonical MCP HTTP identities (#422, PR 1), and so do tool
admission (#422, PR 2), policy rate-lane selection (#422, PR 3a), the static
egress checks (#422, PR 3b) and the admin analysis consumers: the historical
rule preview, endpoint coverage and suggestion coverage (#422, PR 4). This does
not complete #422 or add Policy Studio simulation/replay endpoints.

It now covers contextless HTTP direct rules and permission routes, host-qualified
routes and dispatch-scoped direct rules, MCP alias identities, and rate-lane
selection, plus five policy-backed tool operations and the static egress lane.
[policy-evaluation-parity.md](policy-evaluation-parity.md) is the per-lane
inventory: legacy entry point, normalization, default, trace reason, authority.

## Supported contract

The compiler consumes at most 1 MiB of JSON with unique object members, known
fields and the exact policy schema `0.1.0`. It reuses the existing policy
normalizer/validator, direct `RuleMatcher`, role `PolicyEngine`, method matcher
and segment-boundary prefix matcher. The legacy startup/parser's broader `0.x`
acceptance behavior is unchanged. No future schema or field is inferred.

The context is at version 3; each lane that added a required fact bumped it, so a
context built for an earlier shape is refused rather than reinterpreted. It
supplies a pinned `ResourceSnapshot`, method, exact URI path, principal facts, an
HTTP classification, a three-state request host, and routing facts when a dispatch
was classified. Missing identity
facts differ from a known anonymous caller. The principal projection copies
only user ID, issuer, roles and auth method; it drops session ID, email and
organization and cannot carry headers, tokens or credentials. Authentication
has already occurred outside this domain. The adapter must supply the canonical
identity facts actually used by the live authority.

The immutable compiled object owns its policy and matcher. Evaluation accepts no
runtime, resolver, store, provider, audit sink or arbitrary callback. It has no
async operation. Input and output formatting never includes policy or context
values. Input size/count limits, the JSON parser's nesting limit and bounded
result traces bound the new API's inputs and output. There is no independent
rule-count or evaluation-work budget yet; apply one before exposing this API
through a service. Evaluation does not validate credential
freshness or perform a live cluster-revision check.

| Lane | Existing source | This slice |
| --- | --- | --- |
| Ordinary direct HTTP rules | `RuleMatcher::evaluate_with_dispatch`, RBAC middleware direct branch | First enabled HTTP match in source order; original rule ordinal; Allow, Deny and Shadow remain independent of global mode |
| Ordinary permission routes | RBAC `matching_route_with_host`, `PolicyEngine::principal_has_permission` | First prefix/method match; exact/wildcard permission; role issuer/auth-method activation; route override inherits global mode |
| Default and observe behavior | RBAC default branches | Default allow or deny; shadow converts a logical deny to observation within this lane |
| Host/dispatch-qualified rules | RBAC matching/direct/host helpers | Host-bound routes and dispatch-scoped rules evaluated; a selected upstream narrows direct rules to denies and is refused outright when no host-bound route authorizes it |
| MCP raw/canonical aliases | `evaluate_equivalent_paths_with_dispatch`, exact-then-prefix route search | Both identities decide, under action-major precedence; the request path is matched exactly and only the canonical identity by prefix |
| Rate lane selection | `policy_rate_limit_request` guard, `RateLimitPolicyState::matching_limiter` | First matching override; anonymous reaches none, reproducing the live early return; live since #422 PR 3a, with buckets, capacity and enforcement left to the limiter |
| Policy-backed tools | `ToolRuntime` invocation, visibility, composite enablement, rendered HTTP rules; `RbacState::tool_policy_eligibility` | Separate pure operations preserve each consumer's precedence and shadow behavior; live since #422 PR 2 |
| Static egress | `EgressClient::checked_destination`, `rebind_checked_destination`, `revalidated_destination` | URL shape, scheme, host and port allowlists before any name is resolved, then the address checks over supplied answers; live since #422 PR 3b, with DNS, redirects, TLS and transport left to `crate::egress` |
| Analysis consumers | Rule preview, endpoint coverage and suggestion coverage, each with its own `RuleMatcher` call and route check | `evaluate` over representative requests, and `match_direct_rules` for a candidate rule's own predicates; since #422 PR 4, with unanswerable facts reported rather than counted |

Every target is evaluated, so there is no `unsupported_target` limitation and no
`unsupported_routing_policy`; both are gone. What remains is facts: each missing
supported fact has its own stable limitation code, and the request host is
demanded only when the compiled policy actually has a host-qualified route, so a
caller is never asked for a fact that cannot change the answer. Indeterminate always carries Block and cannot be reused.
Malformed paths, unsupported context versions and mismatched snapshots reject
evaluation; internal invariant/encoding errors remain distinct errors. These
errors are not normal denials and cannot be converted to an empty successful
analysis. The caller must map every error to failed analysis/effective block.

The result distinguishes logical Allow/Deny/Indeterminate from the lane effect
Allow/Block/Observe. `complete` means complete for the **named HTTP policy
domain**, never for a whole request. A host-bound request whose first matching
direct rule is a shadow also reports that observation separately from the rule
that decided, because the live path records it and an adapter dropping it would
lose telemetry. Every trace enumerates authentication, CSRF, request
admission, management permissions, other policy lanes, mutable capacity, DNS,
transport, upstream execution, live revision freshness and exact gateway build
identity as not evaluated. Allow/Observe is no promise that a request forwards.

## Tool operation contract

`CompiledPolicy::evaluate_tool` accepts `ToolEvaluationContext` version 1,
independent of HTTP context version 3. Its domain is `tool_policy_v1` and its
semantics version is `gg-tool-policy-v1`. Each result names exactly one operation:

| Operation | Policy decision | Shadow rule |
| --- | --- | --- |
| `Invocation` | Entry exists, enabled, caller identity matches, then first matching tool rule | Logical Deny / Observe; invocation may continue |
| `Visibility` | Same admission conditions, returned as policy visibility only | Eligible; no observation |
| `PolicyEligibility` | Authenticated inventory preview with existing inventory reason codes | Eligible; no observation |
| `CompositeLeaf` | Entry exists and is enabled; caller must already have a composite grant | Tool rules and identity constraints do not participate |
| `RenderedHttp` | First direct HTTP rule against the rendered method/path with **unknown dispatch** | Logical Deny / Observe; HTTP operation may continue |

Tool entry role constraints compare exact claims; they do not activate role
permission definitions. Policy defaults and global enforcement mode do not
change these decisions. Rendered HTTP intentionally does not evaluate entry
existence/enablement, HTTP routes/defaults, or contextless-only dispatch rules.
It must not be replaced with `CompiledPolicy::evaluate`.

Missing tool name, identity, rendered method or path yields an incomplete Block;
composite enablement does not require identity. Inventory accepts authenticated
identity only, matching its live API. Supplied malformed facts remain errors.
No tool-name grammar is invented: names match exactly as the policy does, with
an offline 4 KiB work bound. **Tool-name admission is not currently bounded by
that constant.** Rendered requests also bypass inbound HTTP admission; this
slice does not claim its path/method bounds are already enforced there. Before
#422 can switch these callers, it must reconcile all such rejection boundaries.

Adapters must capture the consumer's actual identity projection. Runtime
currently reconstructs a principal from `Actor` only for bearer, cookie and
service-token modes; a client-certificate actor becomes anonymous there.
Inventory uses its full authenticated principal. Differential tests pin this
existing difference; this extraction does not repair or expand it.

Traces bind operation, tool name, projected identity, rendered method/path,
policy digest, authority, context and semantics versions. They contain none of
the corresponding raw values. Completeness is scoped to the named operation,
not full tool admission. Registry existence/listing metadata, request schemas,
composite grants, leases, capacity, credentials, egress and execution remain
outside the decision. Non-RBAC legacy `DefaultToolPolicy::Allow` fallback and
`SourceAuthorizer` enum-source refresh (which uses contextless deny-only rules)
are separate contracts and are not covered by this lane.

## Bindings, digests and traces

A snapshot binds one of two digests, and which one is part of the binding.

`PolicyDigest::Source` implements ADR-0004's `GGDIGEST` length-delimited SHA-256
frame with kind `source`, media type `application/json`, schema `0.1.0` and the
exact accepted input bytes. Whitespace changes therefore change the binding. It is
available only to the offline compiler, which is the only caller holding bytes.

`PolicyDigest::ValidatedPolicy` covers an install path that never held them. The
live gateway hands over an already-parsed `Policy`, and loading canonicalizes
(issuer trailing slashes, among others), so the source bytes cannot be
reconstructed from it; reporting a reconstruction as a source digest would break
the guarantee that identical pinned inputs produce identical trace bytes, and
would break it invisibly until someone diffed an offline trace against a
production one. This digest is over a deterministic encoding of the validated
policy, with object keys sorted explicitly rather than relying on
`serde_json::Map` ordering — `Policy::roles` is a `HashMap`, and `preserve_order`
is a feature-unification accident away from being enabled.

**Still no semantic digest is exposed.** `ValidatedPolicy` carries its own frame
kind, `gg.validated-policy.v1`, deliberately outside ADR-0004's reserved
`source`/`semantic` namespace. It is not RFC 8785/JCS and cannot become JCS by
adding a validation step: its key order is byte-wise UTF-8 where JCS mandates
UTF-16 code units, and numbers defer to `serde_json` rather than ECMAScript
shortest-representation. Both differences are reachable with operator-authored
keys. Framing it as `semantic` would place a different value under the frame the
real JCS digest will use, with nothing in the frame to tell them apart. Existing
normalization and the ad hoc policy ETag are likewise not relabeled. A semantic
digest requires the ADR's normalization and JCS contract across the other
resource lanes.

A standalone snapshot binds that source without inventing a persistent revision.
A PostgreSQL snapshot additionally binds a nonnegative security watermark (zero
is the initialized ledger value). The caller supplies that watermark; the pure
compiler does not prove it current or prove it originated from a database.
There is no invented Connection, routing, configuration or tool revision.

Each result binds source, authority/watermark, context version, exact evaluator
semantics version and a digest of the supplied policy-relevant context facts.
`reusable_for` requires complete evaluation, validated matching snapshot/version
and identical context binding. It does not implement caching or authenticate a
caller-provided result. Output is process-owned and has no deserialization API.

Traces contain bounded enums, rule/route ordinals, numeric revisions and digests;
they never copy authored IDs, paths, permissions, principal values or errors.
Ordinals refer to the pinned source order (including disabled/non-HTTP entries)
so later authorized adapters can recover legacy attribution without exposing
authored strings in analysis. The fixed-schema JSON encoding is deterministic
and capped at 2 KiB. It is not a general canonical policy serializer or signed
evidence envelope. Privacy projections and historical evidence remain #243.

## Verification and handoff

Run `cargo test -p gateway --bin gateway policy_eval::` for the kernel's own
tests, plus the RBAC suite. CI gates on two distinct Clippy invocations --
`cargo clippy --workspace --locked` and
`cargo clippy -p gateway --no-default-features --all-targets` -- which differ in
whether `cfg(test)` and the `postgres` feature are on, so run both rather than a
superset of them. The structural transport and dependency gates must pass too.

**The differential matrices run against both the frozen pre-cutover middleware
and the live `rbac_middleware`.** The original implementation is retained only
in `rbac_legacy_tests.rs`, compiled under `cfg(test)`, so comparing the adapter
to the kernel cannot make the kernel its own oracle. That is the method, not a detail: it
caught a semantic the kernel had wrong -- a selected virtual upstream with no
host-bound route is refused outright, and neither the policy default nor shadow
enforcement softens it -- where a second evaluator would have encoded the same
wrong assumption twice and agreed with itself. Two corollaries, both found the
hard way and both recorded in
[policy-evaluation-parity.md](policy-evaluation-parity.md): the oracle must
include any guard that runs before the extracted function, and it must compare the
compiled instance the state actually installed rather than a separately compiled
copy of the same policy.

The matrices cover contextless HTTP over enforcement modes, defaults, direct
actions, order, path boundaries, methods and principal activation; host-bound and
dispatch-scoped requests including the direct-shadow observation that precedes a
route decision; MCP aliases over rulebases where the two precedence orders
disagree; and rate-lane selection against the frozen selector with its guard.
Further tests cover missing versus anonymous facts, malformed and oversized
inputs, exact digest/revision/context/semantics binding, duplicate and future
source rejection, redaction, and deterministic concurrent evaluation with no async
runtime present. Purity is asserted rather than assumed: evaluation through a
capturing audit sink must leave it empty.

Tool differential tests drive the unchanged live runtime and inventory authority,
comparing policy decisions, rejection reasons, and emitted rule attribution.
They compare the compiled instance installed by `RbacState`, use only local
execution closures, and exercise shadow/default combinations and identity
constraints. Additional tests assert input binding, missing/invalid facts,
redacted bounded traces, thread determinism and no audit emission.

The HTTP/route adapter was the first #422 cutover and static egress the last
lane of #421 PR 2. Its trusted-fact boundary is described below; its acceptance
criterion, that a denied request makes zero DNS calls, is held by tests whose
resolver panics when called.

## Live HTTP adapter (#422, PR 1)

Admission, exemptions and the cluster revision gate remain outside the evaluator.
The adapter uses the compiled instance on the admitted policy bundle (or the
standalone snapshot), captures existing classifier and principal facts, and
translates the result into existing response extensions and audit events.
Rule and route ordinals resolve against that same snapshot. A selected-host
shadow observation is emitted before the final route verdict, as before.

An absent Host is a known `Absent` fact. Missing classification is incomplete;
inconsistent observation/authorization contexts and evaluator failures block,
even in shadow mode, with `policy_evaluation_incomplete` or
`policy_evaluation_error` as the audit/decision reason. Warning diagnostics carry
only bounded limitation/error enums. No credentials, DNS, transport or downstream
handler are invoked on these failures. Production admission already rejects the
shape violations documented in the parity matrix before this stage.

Rollback is a code rollback; policy schemas, persistence and revisions are
unchanged. The legacy implementation is not a runtime fallback.

## Live rate adapter (#422, PR 3a)

The policy rate stage asks `select_rate_lane` which override governs an
authenticated request and charges that override's bucket. The question carries
the method, the exact request path and the principal projection; routing and
host facts are not captured there and are supplied as missing, which selection
does not read. A request with no principal still returns before selection, as
it always has, and the kernel answers the same case `NoOverride`.

The stage selects with the compiled instance of the snapshot the RBAC lane
installed, handed over by every install path, and builds its buckets from the
rule vector that instance indexes (`CompiledPolicy::rate_limit_rules`). The
two are swapped as one value. The question is bound to the request's pinned
snapshot when there is one; the stage runs before the RBAC middleware pins
anything, so today that is the installed snapshot, and a different pin is
refused as a snapshot mismatch rather than charged against another policy's
buckets.

A selection the evaluator refuses or cannot complete refuses the request with
the authorization stage's answer for an unevaluated request: `403`, an
`authz.denied` record with `policy_evaluation_error` or
`policy_evaluation_incomplete`, and a denied policy decision. A path
`is_unsafe_request_path` refuses is refused before the evaluator is asked, with
`unsafe_path`, as the authorization stage refuses it. Both reachable cases,
unsafe paths and asterisk-form targets, were already refused by the
authorization stage with the same answer. Mutable capacity, the shared store and
the global lanes are unchanged and stay outside the evaluator.

## Static egress lane (#422, PR 3b)

`CompiledEgressPolicy::evaluate` (`policy_eval::egress`) accepts
`EgressEvaluationContext` version 1, independent of the HTTP and tool context
versions. Its domain is `static_egress_v1` and its semantics version is
`gg-static-egress-v1`. Its resource is not the HTTP policy: the controls it
decides by are partly configuration (the exact bootstrap and auto-seeded hosts,
the non-global switch, NAT64 prefixes) and partly the policy `egress` section
(host patterns, ports, private-address CIDRs), so its `EgressSnapshot` binds a
digest over exactly those controls, with every collection sorted, under its own
frame kind `gg.egress-controls.v1`.

The context carries the destination as `EgressDestination` -- scheme, lowercased
host, explicit or default port, and whether userinfo or a fragment is present,
normalized once from the URL -- and a `ResolutionFact`: `Missing`, or `Resolved`
with the complete answer set in resolver order. The static checks run first and
in the pre-cutover order (host present, no userinfo, no fragment, `http` or
`https`, host allowlist, port allowlist), and a refusal there is complete and
final whatever the facts are. A destination they admit is `Indeterminate` with
`missing_resolution_fact` until answers are supplied. Over answers, the lane
refuses an empty set or any answer on another port, then refuses the set if any
answer is non-global and outside every policy CIDR (when non-global blocking is
on), reporting that answer's ordinal; otherwise it allows and pins answer 0.

The answers are trusted only in the sense that the lane decides over what it is
given. It never resolves a name, and it cannot say whether a set is what a
resolver returned or how fresh it is; those, the lookup itself, redirect
refusal, TLS, the pinned transport and request and response bounds are in
`not_evaluated`. The predicates are the egress module's own -- host patterns,
the non-global registry with its NAT64 handling, CIDR membership -- so their
semantics cannot drift between the lane and the module applying it. The lane
imposes no bound of its own on a URL or an answer set: the pre-cutover checks had
none, and a bound found at decision time would refuse destinations the gateway
reaches today.

The live adapter is `crate::egress`. Each `EgressClient` compiles one lane from
its configuration when it is built and asks it twice per decision: with no
facts, so that only a destination it admits reaches the resolver, then with the
resolver's answers. Rebinding and revalidation ask with the pinned address as
the only answer and resolve nothing. A resolver failure is refused by the
adapter before the lane is asked again. An evaluator error, or an answer the
question cannot have, refuses the destination as `invalid_policy`; every other
refusal is the error, warning and safe category the pre-cutover checks
produced. Traces bind the destination facts and the answers but contain none of
their values: the blocked answer is an ordinal, and the host, scheme, port and
addresses stay out. `canonical_trace_bytes` and `reusable_for` remain offline.
The frozen pre-cutover checks and the differential fixtures are described in
[policy-evaluation-parity.md](policy-evaluation-parity.md).

## Analysis consumers (#422, PR 4)

Three admin consumers used to judge policy beside the evaluator: the
historical rule preview (`POST .../policy/rules/preview`), the endpoint
coverage the traffic inventory reports, and the check rule suggestions use to
skip a candidate the policy already covers. Each now builds an ordinary
`PolicyEvaluationContext` and asks the kernel (`policy_eval::analysis`), so its
facts are validated and refused exactly as a live request's are. Rule hit
counts are recorded attribution, not an evaluation; the endpoint now keys them
by the live snapshot's own rule ids, the ones the adapter writes as
`matched_rule_id`.

Coverage asks `evaluate` what the policy would decide for a representative
request and reads which rule decided. The preview asks something narrower --
whether one candidate rule's own predicates match a retained observation, with
no earlier rule, route, default or host narrowing -- which is the existing
contract of a historical match counter. `CompiledPolicy::match_direct_rules`
answers it over the same matcher and context: the first enabled direct HTTP
rule whose method, path, principal and dispatch binding accept the facts. It
refuses an MCP alias, whose two identities have no first match, and carries no
input binding because nothing retains its answer.

Like every lane, it demands a fact only when an answer can turn on it: a
missing principal, or a missing dispatch, is `indeterminate` only when an
enabled HTTP rule reads it. The preview turns that into a reported
`unevaluated_reasons` count and `complete: false`, never a non-match; a fact
the evaluator refuses is reported the same way as `malformed_observation`. An
evaluator error that is not a refusal of the supplied facts fails the preview.
`CompiledPolicy::for_analysis` compiles a policy a consumer holds with a
digest and no revision, since none of them holds the watermark, and
`for_candidate_rule` compiles a candidate rule alone. `recorded_dispatch` maps
the routing facts observations and discovery record onto the kernel's target,
refusing route facts that have no origin.

Representative requests are synthetic, and the parity inventory lists the facts
they lack: a route id outside a pooled route, the request host, and an MCP
alias identity. The frozen pre-cutover consumers, the differential fixtures and
every documented difference are in
[policy-evaluation-parity.md](policy-evaluation-parity.md).
