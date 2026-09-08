# Pure policy evaluation foundation

Issue #421 PR 1 introduces `gateway/src/policy_eval/`. It has no production caller.
Live HTTP/RBAC middleware, MCP/tool admission, rate selection and egress remain
authoritative. Issue #422 owns adapter cutover after differential parity.

## Supported contract

The compiler consumes at most 1 MiB of JSON with unique object members, known
fields and the exact policy schema `0.1.0`. It reuses the existing policy
normalizer/validator, direct `RuleMatcher`, role `PolicyEngine`, method matcher
and segment-boundary prefix matcher. The legacy startup/parser's broader `0.x`
acceptance behavior is unchanged. No future schema or field is inferred.

The version-1 context supplies a pinned `ResourceSnapshot`, method, exact URI
path, principal facts, and a contextless HTTP classification. Missing identity
facts differ from a known anonymous caller. The principal projection copies
only user ID, issuer, roles and auth method; it drops session ID, email and
organization and cannot carry headers, tokens or credentials. Authentication
has already occurred outside this domain. The adapter must supply the canonical
identity facts actually used by the live authority.

The immutable compiled object owns its policy and matcher. Evaluation accepts no
runtime, resolver, store, provider, audit sink or arbitrary callback. It has no
async operation. Input and output formatting never includes policy or context
values. Input size/count limits, the JSON parser's nesting limit and bounded
result traces bound the new API. Evaluation does not validate credential
freshness or perform a live cluster-revision check.

| Lane | Existing source | This slice |
| --- | --- | --- |
| Ordinary direct HTTP rules | `RuleMatcher::evaluate_with_dispatch`, RBAC middleware direct branch | First enabled HTTP match in source order; original rule ordinal; Allow, Deny and Shadow remain independent of global mode |
| Ordinary permission routes | RBAC `matching_route_with_host`, `PolicyEngine::principal_has_permission` | First prefix/method match; exact/wildcard permission; role issuer/auth-method activation; route override inherits global mode |
| Default and observe behavior | RBAC default branches | Default allow or deny; shadow converts a logical deny to observation within this lane |
| Host/dispatch-qualified rules | RBAC matching/direct/host helpers | Explicitly unsupported, including contextless dispatch matchers, until PR 2 |
| MCP raw/canonical aliases, tools, rate selection, static egress | Existing respective authorities | Not evaluated; PR 2 owns extraction |

Policies containing host-qualified routes or dispatch-bound direct rules return
`indeterminate/unsupported_routing_policy` conservatively, including when an
earlier rule appears sufficient. A proxy or MCP target returns
`indeterminate/unsupported_target`. Missing supported facts have distinct stable
limitation codes. Indeterminate always carries Block and cannot be reused.
Malformed paths, unsupported context versions and mismatched snapshots reject
evaluation; internal invariant/encoding errors remain distinct errors. These
errors are not normal denials and cannot be converted to an empty successful
analysis. The caller must map every error to failed analysis/effective block.

The result distinguishes logical Allow/Deny/Indeterminate from the lane effect
Allow/Block/Observe. `complete` means complete for **contextless HTTP policy**,
never for a whole request. Every trace enumerates authentication, CSRF, request
admission, management permissions, other policy lanes, mutable capacity, DNS,
transport, upstream execution, live revision freshness and exact gateway build
identity as not evaluated. Allow/Observe is no promise that a request forwards.

## Bindings, digests and traces

The source digest implements ADR-0004's `GGDIGEST` length-delimited SHA-256 frame
with kind `source`, media type `application/json`, schema `0.1.0` and the exact
accepted input bytes. Whitespace changes therefore change the binding.
**No semantic digest is exposed.** Existing normalization and the ad hoc policy
ETag are not relabeled RFC 8785/JCS. A future semantic digest requires the ADR's
normalization and JCS contract, including the other resource lanes.

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

Run `cargo test -p gateway --bin gateway policy_eval::` for this slice. The
in-process middleware differential matrix compares 2,304 synthetic requests over
global/route enforcement, defaults, direct actions, order, path boundaries,
methods, anonymous/active/inactive principals and wildcard roles. It compares
final decision, reason, matched rule/route attribution, HTTP status and emitted
allow/deny/would-deny event types. No listener or upstream is used.

Additional tests cover missing versus anonymous facts, unsupported lanes,
malformed/bounded inputs, exact source/revision/context/semantics binding,
duplicate/future source rejection, redaction, principal constraints and
deterministic concurrent evaluation without an async runtime. Run the existing
RBAC tests, formatter, workspace Clippy and structural transport/security gates
as well. This PR does not mark #421 PR 2/3 or any #422 cutover complete.

PR 2 must extend the context/resource contracts before supporting dispatch and
MCP precedence. In particular host-qualified requests can emit a direct-shadow
observation and then reach a different final route/direct decision; a single
final outcome cannot represent their complete trace. PR 3 supplies the full
lane/normalization/authority inventory and broader side-effect evidence.
