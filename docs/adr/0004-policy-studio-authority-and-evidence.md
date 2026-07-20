# ADR-0004: Policy Studio Authority and Evidence

## Status

Accepted

## Context

Issue #243 extends the #218/#219 Rulebase, Builder, Shadow review, and History shell; it does not rebuild that UI.

Current production decisions are fragmented across HTTP/RBAC middleware, MCP aliases, tool admission and rendered tool HTTP operations, rate selection and stateful buckets, and egress validation plus DNS. The existing rule preview is a historical matcher counter, not a whole-policy simulator.

A security control plane cannot tolerate a second approximate evaluator, fail-open missing context, browser authority, unbounded historical analysis, or evidence that overclaims safety or completeness.

This decision was prepared against main commit `450ca108a963750f8f110143861f69bff62d5163`; later work must re-check the code anchors against its base.

## Scope

This ADR covers Policy Studio authorization semantics, drafts, simulation, tests, replay, analysis, evidence, signing boundaries, APIs, and rollout.

## Non-goals

This ADR does not introduce:

- Multi-tenancy.
- A general policy language.
- Real authentication, credential, or provider validation during simulation.
- Live DNS or upstream calls.
- Reconstruction of uncaptured dynamic state.
- Automatic policy mutation.
- Configuration-bundle ownership.
- Compliance certification.

## Decision

### Truth model

| Concept | Meaning | Must not be presented as |
| --- | --- | --- |
| Synthetic simulation | Deterministic evaluation of a supplied typed hypothetical context. | A live request or historical observation. |
| Historical replay | Bounded recomputation over retained facts under a pinned cutoff. | A reconstruction of facts that were never captured. |
| Recorded result | What the gateway recorded at the time under its then-current evaluator and resources. | The candidate policy result. |
| Shadow evidence | Observed live would-deny behavior while the effective request was forwarded. | An enforced denial or proof of policy safety. |
| Analyzer finding | A proven, bounded-observation, heuristic, or inconclusive statement with an explicit proof basis. | A stronger proof class than it actually has. |
| Synthetic test | An operator-authored deterministic expectation. | Historical evidence. |
| Evidence package | A reproducible aggregate report over pinned inputs, limits, and limitations. | Proof that its mutable source data was complete or untampered. |
| Signed attestation | Proof that a trusted key holder signed unchanged package bytes. | Compliance certification, policy safety, or source completeness. |

No newly allowed decisions were observed among N replayable events.

Missing, stale, unsupported, malformed, pruned, empty, or truncated input cannot become allow, pass, zero, or safe.

### Authoritative evaluator and adapters

A typed, deterministic, side-effect-free `CompiledPolicy` kernel is authoritative for logical policy decisions. Its inputs are a versioned `PolicyEvaluationContext` and a redacted, immutable `ResourceSnapshot`.

The kernel covers ordered HTTP rules; restrictive precedence across raw and canonical MCP inputs; host-qualified route behavior; route order, permissions, defaults, and shadow layers; tool existence, enablement, identity, direct rules, and rendered HTTP operations; rate lane and first matching override selection; and static egress decisions only when trusted, pinned resolution facts are supplied.

Thin live adapters and offline callers use the same kernel. No caller copies or approximates its evaluator logic. For the same inputs, the logical result is identical in runtime, synthetic simulation, historical replay, and synthetic test modes.

When a supported policy-relevant fact is unavailable, the kernel returns `indeterminate` with stable limitation codes. The production adapter preserves that logical outcome and maps it to an effective block. Malformed or internally inconsistent contexts are rejected before evaluation. Internal evaluator errors fail analysis runs and block production requests; they are not normal `indeterminate` results.

### Side-effect boundary

Analysis is prohibited from performing DNS or HTTP operations; making MCP, provider, or secret-store calls; validating tokens or credentials; invoking tools; acquiring semaphores; reading or writing production rate buckets; mutating policies or suggestions; selecting a physical upstream; or emitting normal data-plane authorization events.

Authentication validity, CSRF, request validation, dynamic rate capacity, future semaphore capacity, unpinned DNS outcomes, transport health, and upstream execution are outside the pure verdict.
