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
