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

When a historical comparison finds no newly allowed decisions, it must report its bounded result as:

> No newly allowed decisions were observed among N replayable events.

Missing, stale, unsupported, malformed, pruned, empty, or truncated input cannot become allow, pass, zero, or safe.

### Authoritative evaluator and adapters

This section defines the target architecture. Accepting this ADR does not mean that the kernel or adapters are implemented; existing production paths remain authoritative until each path is migrated and parity is verified.

A typed, deterministic, side-effect-free `CompiledPolicy` kernel is authoritative for logical policy decisions. Its inputs are a versioned `PolicyEvaluationContext` and a redacted, immutable `ResourceSnapshot`.

The kernel covers ordered HTTP rules; restrictive precedence across raw and canonical MCP inputs; host-qualified route behavior; route order, permissions, defaults, and shadow layers; tool existence, enablement, identity, direct rules, and rendered HTTP operations; rate lane and first matching override selection; and static egress decisions only when trusted, pinned resolution facts are supplied.

Thin live adapters and offline callers use the same kernel. No caller copies or approximates its evaluator logic. For the same inputs, the logical result is identical in runtime, synthetic simulation, historical replay, and synthetic test modes.

When a supported policy-relevant fact is unavailable, the kernel returns `indeterminate` with stable limitation codes. The production adapter preserves that logical outcome and maps it to an effective block. Malformed or internally inconsistent contexts are rejected before evaluation. Internal evaluator errors fail analysis runs and block production requests; they are not normal `indeterminate` results.

### Side-effect boundary

Analysis is prohibited from performing DNS or HTTP operations; making MCP, provider, or secret-store calls; validating tokens or credentials; invoking tools; acquiring semaphores; reading or writing production rate buckets; mutating policies or suggestions; selecting a physical upstream; or emitting normal data-plane authorization events.

Authentication validity, CSRF, request validation, dynamic rate capacity, future semaphore capacity, unpinned DNS outcomes, transport health, and upstream execution are outside the pure verdict.

### Exact versions, stable identity, and resource snapshots

Policy and analysis resources use exact schema dispatch. A parser accepts only versions it implements; it does not accept arbitrary `0.x` or `1.x` families and must not silently ignore unknown fields. Every direct rule, route, rate override, identity mapping, suppression, test case, and future condition node has a unique, non-empty stable identifier. Role and tool names are canonically unique.

Validation produces structured diagnostics with a stable code, severity, JSON Pointer, stable element identifier when applicable, safe message and remediation, and explicit flags for whether the diagnostic blocks simulation, tests, publication, or complete evidence.

An immutable `ResourceSnapshot` binds the exact versions and digests relevant to a decision: policy, routing, tools, Connections, configuration, authentication mappings, egress, policy tests, cluster revision, evaluator semantics, and gateway build. When normalization can erase source representation, GreenGateway retains both the original source-document digest and the normalized semantic digest. A result that lacks a required version or digest is incomplete or unsupported; it is not reusable under a guessed current value.

### Canonical digest contract

The target digest contract accepts JSON only as UTF-8 without a byte-order mark. Parsing rejects duplicate object member names and non-finite numbers, and inputs satisfy RFC 8785 JSON Canonicalization Scheme and I-JSON constraints. JCS performs no Unicode normalization, so original code points remain significant.

Every digest hashes this unambiguous byte frame:

```text
ASCII "GGDIGEST" || 0x00 ||
u64be(len(kind)) || UTF8(kind) ||
u64be(len(media_type)) || UTF8(media_type) ||
u64be(len(schema_version)) || UTF8(schema_version) ||
u64be(len(payload)) || payload
```

Each `len` is the unsigned 64-bit big-endian byte length of the field that follows. `kind` is `source` or `semantic`. A source payload is the exact accepted source-document bytes. A semantic payload is the RFC 8785 canonical byte sequence of the schema-version-defined normalized policy or artifact. A version without normative normalization has no semantic digest. Media type and exact schema version are mandatory. The external representation is `sha256:` followed by 64 lowercase hexadecimal characters.

This framing is used for freshness bindings, evidence subjects, manifest entries, signature subjects, and inputs to strong ETags. The current ad hoc key-sorted ETag implementation does not satisfy this target contract and remains a compatibility mechanism until a later #243 slice migrates it explicitly.

### Server authority and state transitions

The browser is a client, not a policy or capability authority. A server-owned draft has an unpredictable owner-scoped identifier and binds its owner, active base revision and ETag, candidate semantic digest, resource-snapshot digest, creation and update times, expiry, and enforced size/count quotas. Draft mutation uses a strong ETag.

Publication is a separate authorized current-authority operation. It revalidates the candidate schema, current resources, required tests, risk acknowledgements, and every conditional binding. A stale draft remains reviewable and returns an explicit conflict; GreenGateway never silently rebases it.

Publication and evidence are independent branches:

```text
active policy + immutable resource snapshot
                  |
                  v
             server draft
                  |
        +---------+-----------------------------+
        |                                       |
        v                                       v
simulation / tests / replay / analyzer   current-authority revalidation
        |                                + required test/risk gates
        v                                       |
immutable completed run results                 v
        |                               conditional publication
        v                                       |
aggregate evidence                              v
        |                               new active revision
        v
optional protected signing
```

Digest-bound completed test results may satisfy publication gates, but evidence and signatures confer no publication authority. Optimizer output, discovery suggestions, shadow promotion, and remediation actions only create or modify reviewable drafts. They never mutate active policy implicitly.

### API and authorization contract

Policy Studio reserves the semantics of capabilities, drafts, simulations, replays, analyses, tests, evidence, and suggestions under the configured admin prefix. Issue #242 owns the final OpenAPI route suffixes and generated client contract; changing a suffix must not change these resource semantics.

The minimum permission matrix is:

| Operation | Required permissions |
| --- | --- |
| Read active policy and basic diagnostics | `admin:policy:read` |
| Create or read synthetic simulation | `admin:policy:read` + `admin:policy:simulate` |
| Run or read structural analysis | `admin:policy:read` + `admin:policy:analyze` |
| Run or read historical replay | `admin:policy:read` + `admin:policy:simulate` + `admin:audit:read` |
| Read or run synthetic tests | `admin:policy:read` + `admin:policy:simulate` |
| Mutate tests or drafts, or publish/apply | `admin:policy:write` |
| Read aggregate evidence | `admin:policy:evidence:read` |
| Read audit-derived detail | Operation read permission + `admin:audit:read` |
| Export signed evidence | `admin:policy:evidence:export` |
| Apply optimizer, suggestion, or shadow promotion | `admin:policy:write` plus current conditional preconditions |

Every endpoint requires normal authentication and server-side RBAC. Cookie-authenticated mutations use the shared CSRF mechanism. Request bytes are bounded before expensive parsing, unknown request fields are rejected, list and detail results are paginated, and aggregate and audit-derived detail projections remain separate.

The common result envelope carries schema and evaluator versions; active and base revisions and ETags; source and semantic policy digests; relevant resource digests; evaluation mode; logical outcome; enforcement; effective action; completeness and limitation codes; stable terminal reason; matched stable identifiers; required and granted permission where relevant; optional bounded trace; and the limits applied to the run.

### Failure and bounds semantics

| Condition | Required behavior |
| --- | --- |
| Unauthenticated or unauthorized | Return `401` or `403` before evaluator, audit, or job work. |
| Malformed input | Return `400` with a sanitized stable error. |
| Byte, count, or depth violation | Return `413` or bounded `422`; create no job or mutation. |
| Invalid candidate, context, or tests | Return `422` structured diagnostics; create no artifact or mutation. |
| Missing mutation precondition | Return `428`. |
| Stale active or draft ETag | Return `412`; never silently rebase. |
| Stale semantic, resource, or risk binding | Return `409`; require rerun and review. |
| Work quota exhausted | Return bounded `429`, or dependency-specific `503`; never evict another job. |
| Required authority unavailable | Return `503` for the dependent operation; independent synthetic simulation may remain available. |
| Empty, incomplete, interrupted, or truncated work | Record an explicit incomplete or failed state; never satisfy publication or evidence-complete gates. |
| Unknown policy-relevant fact | Return `indeterminate` with a stable reason; production blocks. |
| Incompatible evaluator or resource version | Reject the run, reuse, or publication. |
| Expired artifact | Return `410` or a distinct expired state. |
| Ambiguous mutation response | Read authoritative revision state; never retry blindly. |

Every byte, count, string, nesting, trace, scan, result, time, memory, TTL, per-actor concurrency, and deployment concurrency dimension has a positive server-enforced bound. Zero never means unlimited. The capabilities resource advertises effective limits and run metadata records the limits applied. Compile-time hard ceilings cannot be raised through configuration; operators may lower them.

The current one-mebibyte request-body default and 100,000-row audit scan ceilings are compatibility anchors, not defaults for every future Policy Studio resource. Each endpoint slice selects and tests its exact numeric defaults against load and data-plane latency budgets before that endpoint ships.

### Privacy projections

Policy Studio exposes separate aggregate and detail projections. Aggregate results contain counts, stable categories, digests, proof bases, and limitation codes. Audit-derived event or principal detail additionally requires `admin:audit:read`, has independent pagination and output limits, and never enters canonical v1 evidence.

Secret-marked or categorically forbidden fields are rejected as synthetic input rather than silently removed before evaluation. Forbidden fields include credentials, authorization and cookie headers, proxy and hop-by-hop headers, configured credential headers, and secret-store values. This rejection avoids a privacy filter turning a complete evaluation into an undocumented approximation.

Approved, bounded, non-secret matcher inputs may exist transiently in the authenticated request and evaluator memory so the canonical evaluator receives exact typed facts. These inputs include explicitly allowlisted headers, query values, typed identity attributes, and validated tool arguments. Their raw values are discarded after evaluation and excluded from persisted run results, traces, errors, URLs, browser storage, logs, metrics, audit events, temporary files, evidence, and signatures.

Raw HTTP bodies, tool results, serialized production principals, and raw source events are not accepted merely to improve analysis. Existing retained source IP, request ID, user agent, path, and actor fields pass through a centralized purpose-specific projection before crossing the audit boundary.

A signature proves package integrity and signer possession only. It does not prove source completeness, policy safety, source-database integrity, or compliance with any framework.

## Threat model

### Assets

- Integrity of active and draft policy and their conditional publication state.
- Exact policy, evaluator, and resource versions and digests.
- Authorization correctness, fail-closed behavior, and data-plane availability.
- Confidentiality of audit-derived and hypothetical policy input data.
- Integrity of synthetic tests, risk acknowledgements, suppressions, and analyzer proof classifications.
- Integrity of evidence packages and custody of protected signer keys.
- CPU, memory, storage, worker, and queue capacity shared with the data plane.

### Trust boundaries and actors

The design crosses these trust boundaries:

- An unauthenticated caller entering the authenticated admin API.
- An authenticated low-permission operator requesting privileged policy operations.
- A browser crossing into server-side policy and capability authority.
- Policy Studio services reading privacy-sensitive audit storage.
- The pure evaluator exchanging typed data with mutable runtime adapters.
- Standalone storage integrating with the #241 cluster authority.
- The evidence assembler invoking a #240 protected signer reference.
- An exported package reaching an offline verifier with an out-of-band trust root.

Relevant actors include unauthenticated attackers, compromised low-permission operators, malicious or mistaken policy authors, stale or buggy browsers, malicious or malformed retained events, exhausted or crashed workers, compromised signing infrastructure, malicious artifact producers or consumers, and operators who over-trust incomplete evidence.

### Abuse cases and controls

| Threat | Required controls | Detection and residual risk |
| --- | --- | --- |
| Authorization logic drifts between live and offline paths | One shared kernel, thin adapters, evaluator version binding, and differential and property tests. | Internal failures block. Implementation defects remain possible and require release-gate tests and review. |
| Missing context becomes allow | Typed availability, stable indeterminate reasons, and a fail-closed production adapter. | Historical facts may remain unavailable; affected results remain explicitly incomplete. |
| Analysis causes live side effects | Pure kernel, injected immutable snapshots, network-deny harnesses, and production-state isolation tests. | An adapter violation is a release-blocking security defect. |
| A stale or replayed mutation publishes | Strong ETags plus revision, resource, candidate, test, risk, and idempotency bindings. | An ambiguous response requires an authoritative read before any retry. |
| Audit or principal detail leaks | Separate detail permission, centralized purpose-specific projections, bounded output, and privacy-safe control-plane audit. | Authorized detail readers still handle sensitive operational data. |
| Analysis exhausts shared resources | Positive hard limits, quotas, deadlines, cancellation, bounded result retention, and data-plane latency gates. | Analysis may become unavailable under pressure but must not weaken authorization or readiness. |
| Traces or errors exfiltrate matcher values | Stable reason codes, bounded sanitized messages, and a prohibition on raw matcher values outside evaluator memory. | Every newly captured field requires privacy review. |
| Replay cutoff or pruning races omit events | Immutable high-water marks and cutoffs, snapshot semantics, or explicit incomplete/failure results. | The mutable source may already have been incomplete before the snapshot. |
| Analyzer reports a false proof | Lane-aware analysis, canonical evaluator checks, complexity budgets, brute-force/property validation, and inconclusive fallback. | Heuristics remain advisory and are labeled separately from proofs. |
| A change causes lockout or an overbroad grant | Cross-resource validation, required tests, explicit risk gates, and conditional publication. | A fully authorized operator can still acknowledge and publish deliberate risk. |
| Concurrent suggestion or policy changes partially apply | One compare-and-set winner, idempotent operations, and #241 transactions/outbox integration in cluster mode. | Standalone crash recovery must expose authoritative revision state. |
| Canonicalization ambiguity breaks bindings | Exact UTF-8/JCS validation, framed digest input, versioned normalization, and cross-platform vectors. | A future schema requires its own reviewed normalization contract. |
| A signing API becomes a signing oracle | #240 protected key references, evidence-specific package assembly, and no arbitrary bytes or digest signing endpoint. | Trust-root distribution, rotation, revocation, and key compromise remain operator responsibilities. |
| An evidence archive tampers with or exhausts a verifier | Manifest digests, DSSE/in-toto envelopes, media-type and path allowlists, size and decompression limits, and zero-network verification. | A valid signature still does not establish source completeness. |
| Evidence is presented as safety or compliance proof | Mandatory limitations in APIs, UI, documentation, and artifacts, including bounded no-new-allow wording. | GreenGateway cannot prevent downstream humans from misrepresenting a report. |

## Dependency boundaries

| Issue | Authority owned by that issue | Policy Studio integration rule |
| --- | --- | --- |
| #218/#219 | Existing React Rulebase, Builder, Shadow review, and History workspace foundation. | Extend the existing workspace. Server-derived capabilities and explanations remain authoritative; do not rebuild a browser policy engine. |
| #239 | Transport, readiness, draining, shutdown, and their lifecycle semantics. | Analysis jobs expose bounded cancellation and shutdown hooks, but analysis availability never gates data-plane readiness. Static simulation never performs transport or DNS work. |
| #240 | Connections, credential and secret resolution, secret providers, and signer-key custody. | Consume redacted Connection/resource digests and protected signer references only. Never resolve, persist, export, or generically sign secret values. |
| #241 | PostgreSQL repositories, authoritative security revisions, transactions, outbox behavior, durable leases, fencing, and HA job coordination. | Cluster drafts, jobs, suggestions, evidence, and publication use that authority. Until it exists, return explicit unsupported or unavailable results instead of a weaker local fallback. |
| #242 | `ggctl`, configuration bundles, staging, activation, rollback, GitOps, generated OpenAPI, and CLI version contracts. | Contribute policy-domain resources and commands through those authorities. Evidence is not a deployable configuration archive, backup, or second CLI. |

Existing policy CRUD and history remain authoritative during migration. Policy Studio must not create a second activation, revision, transaction, CLI, secret, transport, or configuration authority.

## Rollout and migration

Implementation proceeds in this order:

1. Preserve policy v0 behavior and compatibility endpoints.
2. Add stable identifiers, structured diagnostics, canonicalization, and explicit reviewable v0-to-v1 conversion without automatically rewriting source files.
3. Extract evaluator lanes behind differential tests while existing production paths remain authoritative until each migration proves parity.
4. Add immutable resource snapshots and server-owned drafts before simulation, tests, replay, analyzer, or evidence resources consume them.
5. Add standalone resources only where their semantics are equivalent. Return explicit unsupported or unavailable capabilities for cluster behavior until #241 lands.
6. Route publication, activation, rollback, CLI, and GitOps workflows through #242 rather than creating a parallel authority.
7. Add signing only after #240 provides protected signer references and offline trust-root behavior.
8. Deprecate the legacy per-rule preview and browser-generated pseudo-expression only after compatible server-backed replacements ship and a documented migration window passes.

Rollback retains the last compatible v0 source document. GreenGateway never silently downgrades, drops, or rewrites v1-only semantics. An incompatible policy, evaluator, resource, or test version blocks run reuse and publication. A failed migration leaves the previously active revision authoritative.

## Consequences

The principal benefit is one explainable authorization authority for live decisions, simulation, tests, replay, and analyzer semantic checks. Exact versions and deterministic digests make stale work detectable. Explicit completeness and privacy projections prevent missing evidence from appearing safe. Separate permissions and publication bindings reduce the blast radius of compromised operators or browsers.

The cost is additional schema, snapshot, reason-code, capability, quota, and lifecycle metadata. Each runtime authorization lane must be migrated behind differential tests. Operators must handle explicit indeterminate, incomplete, stale, and unsupported states. Cluster publication, durable jobs, Connections, signer custody, and CLI workflows cannot be declared complete before their owning issues provide the required authorities.

## Rejected alternatives

- A simulator that copies middleware logic: it inevitably drifts from production behavior.
- Browser-owned drafts, capability inference, or policy expressions: the browser is not a security authority.
- Treating unknown or unavailable facts as no-match or allow: this violates fail-closed behavior.
- Unbounded replay, traces, analyzer work, or evidence: this creates denial-of-service and privacy risks.
- Treating retained observations as proof that a policy is safe or unused: retained history is bounded and may be incomplete.
- Automatically applying optimizer output, discovery suggestions, or shadow promotions: advisory output must re-enter reviewable draft and publication gates.
- Ad hoc key sorting or implementation-dependent map iteration for digests: neither is a normative cross-platform contract.
- A generic arbitrary-payload signing endpoint: it exposes protected keys as a signing oracle.
- Waiting for every dependency epic before recording these boundaries: without an accepted contract, parallel implementation is more likely to create competing authorities.

## Checklist item 1 traceability

| Requirement | ADR section |
| --- | --- |
| Truth model | [Truth model](#truth-model) |
| Evaluator boundary | [Authoritative evaluator and adapters](#authoritative-evaluator-and-adapters) and [Side-effect boundary](#side-effect-boundary) |
| Versioning and canonicalization | [Exact versions, stable identity, and resource snapshots](#exact-versions-stable-identity-and-resource-snapshots) and [Canonical digest contract](#canonical-digest-contract) |
| Privacy projections | [Privacy projections](#privacy-projections) |
| API resource and result schemas | [API and authorization contract](#api-and-authorization-contract) |
| Limits | [Failure and bounds semantics](#failure-and-bounds-semantics) |
| Permission matrix | [API and authorization contract](#api-and-authorization-contract) |
| Evidence trust statement | [Truth model](#truth-model) and [Privacy projections](#privacy-projections) |
| Dependency boundaries | [Dependency boundaries](#dependency-boundaries) |
| Rollout and migration | [Rollout and migration](#rollout-and-migration) |
