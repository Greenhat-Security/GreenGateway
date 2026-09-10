# Pure policy evaluation foundation

Issue #421 introduces `gateway/src/policy_eval/`. **It has no production caller.**
Live HTTP/RBAC middleware, MCP/tool admission, rate selection and egress remain
authoritative. Issue #422 owns adapter cutover after differential parity.

It now covers contextless HTTP direct rules and permission routes, host-qualified
routes and dispatch-scoped direct rules, MCP alias identities, and rate-lane
selection. Tool admission and static egress are not implemented.
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
| Rate lane selection | `policy_rate_limit_request` guard, `RateLimitState::matching_limiter` | First matching override; anonymous reaches none, reproducing the live early return; enforcement and buckets untouched |
| Tools, static egress | Existing respective authorities | Not evaluated; #421 PR 2 owns extraction |

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

**The differential tests drive the real `rbac_middleware` and compare against it,
never a second hand-written evaluator.** That is the method, not a detail: it
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
disagree; and rate-lane selection against the live selector with its guard.
Further tests cover missing versus anonymous facts, malformed and oversized
inputs, exact digest/revision/context/semantics binding, duplicate and future
source rejection, redaction, and deterministic concurrent evaluation with no async
runtime present. Purity is asserted rather than assumed: evaluation through a
capturing audit sink must leave it empty.

Nothing here marks any #422 cutover complete. The remaining #421 PR 2 lanes are
tool admission and static egress; static egress needs its trusted-fact boundary
established before any of it is pure, since its acceptance criterion is that a
denied request makes zero DNS calls.
