# Policy Studio ADR and Threat Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete checklist item 1 of issue #243 by adding an accepted, indexed ADR that fixes the Policy Studio authority, evaluator, evidence, privacy, threat, dependency, and migration contracts.

**Architecture:** Add one comprehensive ADR with an embedded threat model so later Policy Studio slices share one normative source. The ADR is documentation-only: it defines the common evaluator and control-plane contracts without adding endpoints, schemas, configuration, UI, or runtime behavior.

**Tech Stack:** Markdown, Git, ripgrep, existing GreenGateway ADR conventions

---

## File Map

- Create `docs/adr/0004-policy-studio-authority-and-evidence.md`: the accepted architecture decision and embedded threat model.
- Modify `docs/adr/README.md`: add the sequential ADR-0004 index entry.
- Reference `docs/superpowers/specs/2026-07-20-policy-studio-adr-threat-model-design.md`: the reviewed design contract; do not modify it during implementation unless the implementation exposes a contradiction.

Do not modify Rust, TypeScript, JSON schemas, configuration, CI, screenshots, or runtime documentation in this slice.

### Task 1: Establish the Authority and Evaluator Contract

**Files:**
- Create: `docs/adr/0004-policy-studio-authority-and-evidence.md`

- [ ] **Step 1: Verify the ADR number and target file are unused**

Run:

```powershell
git ls-tree -r --name-only HEAD docs/adr
Test-Path docs/adr/0004-policy-studio-authority-and-evidence.md
```

Expected: the list ends at `0003-admin-ui-stack.md`; `Test-Path` prints `False`.

- [ ] **Step 2: Create the ADR header, status, context, scope, and non-goals**

Start the document with:

```markdown
# ADR-0004: Policy Studio Authority and Evidence

## Status

Accepted

## Context
```

The Context section must state all of the following in direct prose:

- Issue #243 extends the #218/#219 Rulebase, Builder, Shadow review, and History shell; it does not rebuild that UI.
- Current production decisions are fragmented across HTTP/RBAC middleware, MCP aliases, tool admission and rendered tool HTTP operations, rate selection and stateful buckets, and egress validation plus DNS.
- The existing rule preview is a historical matcher counter, not a whole-policy simulator.
- A security control plane cannot tolerate a second approximate evaluator, fail-open missing context, browser authority, unbounded historical analysis, or evidence that overclaims safety or completeness.
- The decision is prepared against main commit `450ca108a963750f8f110143861f69bff62d5163` and later work must re-check code anchors.

Add `## Scope` and `## Non-goals`. Scope covers Policy Studio authorization semantics, drafts, simulation, tests, replay, analysis, evidence, signing boundaries, APIs, and rollout. Non-goals must explicitly exclude multi-tenancy, a general policy language, real authentication/credential/provider validation during simulation, live DNS or upstream calls, reconstruction of uncaptured dynamic state, automatic policy mutation, configuration-bundle ownership, and compliance certification.

- [ ] **Step 3: Document the eight-way truth model**

Add `## Decision` and state that the entire section is target architecture, not shipped behavior; current production paths remain authoritative until migrated behind differential parity tests. Then add `### Truth model`. Include this exact table:

```markdown
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
```

Immediately below the table include the required historical wording: `No newly allowed decisions were observed among N replayable events.` State that missing, stale, unsupported, malformed, pruned, empty, or truncated input cannot become allow, pass, zero, or safe.

- [ ] **Step 4: Define one mode-independent evaluator**

Add `### Authoritative evaluator and adapters`. Define:

- A typed, deterministic, side-effect-free `CompiledPolicy` kernel.
- Inputs: a versioned `PolicyEvaluationContext` and redacted immutable `ResourceSnapshot`.
- Coverage: ordered HTTP rules; raw/canonical MCP restrictive precedence; host-qualified route behavior; route order, permissions, defaults, and shadow layers; tool existence/enablement/identity/direct rules/rendered HTTP operations; rate lane and first matching override; static egress only with trusted pinned resolution facts.
- Thin live adapters and offline callers use the same kernel; no copied evaluator exists.
- The logical result is identical in runtime, synthetic, replay, and test modes.
- Supported but unavailable facts return `indeterminate` with stable limitation codes. Production preserves the logical outcome and maps it to an effective block.
- Malformed/internally inconsistent contexts are rejected before evaluation. Internal evaluator errors fail analysis runs and block production; they are not normal indeterminate results.

Add `### Side-effect boundary` and explicitly prohibit analysis from DNS, HTTP, MCP/provider/secret-store calls, token or credential validation, tool invocation, semaphore acquisition, production bucket reads or writes, policy/suggestion mutation, physical upstream selection, and normal data-plane authz event emission.

State that authentication validity, CSRF, request validation, dynamic rate capacity, future semaphore capacity, DNS outcomes without pinned facts, transport health, and upstream execution are outside the pure verdict.

- [ ] **Step 5: Verify the first section structurally and commit it**

Run:

```powershell
rg -n '^## (Status|Context|Scope|Non-goals|Decision)$|^### (Truth model|Authoritative evaluator and adapters|Side-effect boundary)$' docs/adr/0004-policy-studio-authority-and-evidence.md
rg -n 'No newly allowed decisions were observed among N replayable events\.' docs/adr/0004-policy-studio-authority-and-evidence.md
git diff --check
```

Expected: every required heading and the exact safe wording are found; `git diff --check` prints nothing.

Commit:

```powershell
git add -- docs/adr/0004-policy-studio-authority-and-evidence.md
git commit -m "Define Policy Studio evaluator authority"
```

### Task 2: Define Version, Digest, Resource, API, and Publication Contracts

**Files:**
- Modify: `docs/adr/0004-policy-studio-authority-and-evidence.md`

- [ ] **Step 1: Add exact versions, stable identity, and snapshots**

Add `### Exact versions, stable identity, and resource snapshots`. Require:

- Exact policy schema dispatch; arbitrary `0.x` or `1.x` families are rejected.
- Unique, non-empty stable IDs for every policy element that later analysis or evidence can reference.
- Canonically unique role and tool names.
- Structured diagnostics with stable code, severity, JSON Pointer, stable element ID, safe message/remediation, and blocking scopes.
- Snapshot versions and digests for policy, routing, tools, Connections, configuration, authentication mappings, egress, tests, cluster revision, evaluator semantics, and gateway build.
- Original source digest and semantic digest are both retained when normalization loses representational details.

- [ ] **Step 2: Add the normative digest framing**

Add `### Canonical digest contract`. State that accepted JSON is UTF-8 without BOM, duplicate members and non-finite numbers are rejected, RFC 8785/I-JSON constraints apply, and JCS does not normalize Unicode.

Include this exact preimage definition:

```text
ASCII "GGDIGEST" || 0x00 ||
u64be(len(kind)) || UTF8(kind) ||
u64be(len(media_type)) || UTF8(media_type) ||
u64be(len(schema_version)) || UTF8(schema_version) ||
u64be(len(payload)) || payload
```

Define each `len` as the unsigned 64-bit big-endian byte length of the following field. `kind` is `source` or `semantic`. Source payload is the exact accepted source bytes. Semantic payload is the RFC 8785 bytes of the schema-version-defined normalized artifact. If a version lacks normative normalization, no semantic digest is produced. Output is `sha256:` plus 64 lowercase hexadecimal characters.

Require this framing for freshness bindings, evidence/manifest/signature subjects, and inputs to strong ETags. Do not claim that the current ad hoc ETag implementation already satisfies it.

- [ ] **Step 3: Define server drafts and independent publication/evidence flows**

Add `### Server authority and state transitions`. Require owner-scoped unpredictable draft IDs, base revision and ETag, candidate digest, resource-snapshot digest, timestamps, TTL, quotas, and strong ETags. Publishing is a separate current-authority operation that revalidates schema, resources, required tests, risks, and conditional bindings. Stale drafts remain reviewable and are never silently rebased.

Define owner authorization independently of operation permission; unpredictable IDs are not authorization and cross-owner recovery needs a separately named permission/audit event. Define the atomic publication tuple: candidate digest, base revision/ETag, resource snapshot, evaluator, exact test suite and complete-result digests, exact risk codes/diagnostic digests, actor, short expiry, intended operation, and payload digest. Bind suggestion application to its identifier/version, source cutoff/evidence digest, candidate/resources, actor, operation, and expiry. Bind idempotency to owner, operation, payload, and the complete tuple; mismatched reuse conflicts.

Include this flow, preserving the independent branches:

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

State that digest-bound completed tests may gate publication, but evidence and signatures confer no publication authority. Suggestions, optimizer output, shadow promotion, and remediation only create or modify reviewable drafts.

- [ ] **Step 4: Add API resource, result, and permission contracts**

Add `### API and authorization contract`. Reserve the semantics of capabilities, drafts, simulations, replays, analyses, tests, evidence, and suggestions under the configured admin prefix without freezing #242's final route suffixes.

State that the proposed permission names are reserved target contracts and are not implemented until their endpoint slice adds and tests them.

Include this exact minimum permission matrix:

```markdown
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
```

Require normal authentication/server RBAC, shared CSRF for cookie mutations, request byte limits before expensive parsing, rejection of unknown request fields, pagination, and separate aggregate/detail projections.

Define the common result envelope fields: schema and evaluator versions; active/base revisions and ETags; source/semantic policy digests; relevant resource digests; mode and declared completeness domain; logical outcome; enforcement; effective action; completeness and limitation codes; stable terminal reason; matched stable IDs; required/granted permission; bounded stage trace; and applied limits. Require `matched`, `skipped`, `not_applicable`, `unknown`, and `not_evaluated` stage statuses; all out-of-kernel live stages must be explicit and `would_forward` must remain policy-only.

- [ ] **Step 5: Add failure and bounds semantics**

Add a failure table containing all mappings below:

```markdown
| Condition | Required behavior |
| --- | --- |
| Unauthenticated or unauthorized | `401` or `403` before evaluator, audit, or job work. |
| Malformed input | `400` with sanitized stable error. |
| Byte/count/depth violation | `413` or bounded `422`; create no job or mutation. |
| Invalid candidate/context/tests | `422` structured diagnostics; create no artifact or mutation. |
| Missing mutation precondition | `428`. |
| Stale active or draft ETag | `412`; never silently rebase. |
| Stale semantic/resource/risk binding | `409`; rerun and review. |
| Work quota exhausted | Bounded `429`, or dependency-specific `503`; never evict another job. |
| Required authority unavailable | `503` for the dependent operation; independent synthetic simulation may remain available. |
| Empty, incomplete, interrupted, or truncated work | Explicit incomplete/failed state; never satisfy publication or evidence-complete gates. |
| Unknown policy-relevant fact | `indeterminate` with stable reason; production blocks. |
| Incompatible evaluator/resource version | Reject run, reuse, or publication. |
| Expired artifact | `410` or distinct expired state. |
| Ambiguous mutation response | Read authoritative revision state; never retry blindly. |
```

Define the bounds policy: every bytes/count/string/nesting/trace/scan/result/time/memory/TTL/per-actor/deployment dimension is positive and server-enforced; zero never means unlimited; capabilities advertise effective limits; run metadata records applied limits; compile-time hard ceilings cannot be raised by configuration; and operators may lower them. Record the current one-mebibyte request-body default and 100,000-row audit scan ceiling only as compatibility anchors. Require each later endpoint slice to select/test exact numeric defaults before shipping.

- [ ] **Step 6: Verify contracts and commit them**

Run:

```powershell
rg -n '^### (Exact versions, stable identity, and resource snapshots|Canonical digest contract|Server authority and state transitions|API and authorization contract)$' docs/adr/0004-policy-studio-authority-and-evidence.md
rg -n 'GGDIGEST|admin:policy:simulate|admin:policy:evidence:export|zero never means unlimited|evidence and signatures confer no publication authority' docs/adr/0004-policy-studio-authority-and-evidence.md
git diff --check
```

Expected: all headings and invariant phrases are found; `git diff --check` prints nothing.

Commit:

```powershell
git add -- docs/adr/0004-policy-studio-authority-and-evidence.md
git commit -m "Specify Policy Studio control-plane contracts"
```

### Task 3: Add Privacy, Threat, Dependency, and Migration Decisions

**Files:**
- Modify: `docs/adr/0004-policy-studio-authority-and-evidence.md`

- [ ] **Step 1: Define privacy projections and transient matcher inputs**

Add `### Privacy projections`. State:

- Aggregate results contain counts, stable categories, digests, proof bases, and limitations.
- Audit-derived event or principal detail requires `admin:audit:read`, is separately bounded, and never enters canonical v1 evidence.
- Secret-marked or forbidden values (credentials, authorization/cookie/proxy/hop-by-hop/configured credential headers, secret-store values) are rejected as synthetic input rather than stripped into an approximate evaluation.
- Approved bounded non-secret matcher inputs for ad hoc simulations (allowlisted headers, query values, typed identity attributes, validated tool arguments) may exist only in the authenticated request and evaluator memory, then are discarded.
- Strict-versioned saved synthetic test fixtures are the sole persistence exception: bounded, secret-free typed values stored beside policy under owner authorization, strong ETags, stable IDs, canonical digests, lifecycle/retention bounds, and protected policy-resource storage. Only authorized test CRUD returns fixtures; all results and secondary outputs expose identifiers/digests/expectations/sanitized outcomes.
- Raw ad hoc matcher values and saved fixture values outside authorized test CRUD are excluded from persisted results, traces, errors, URLs, browser storage, logs, metrics, audits, temporary files, evidence, and signatures.
- Every draft, test revision, job, result, detail projection, and evidence artifact has a positive retention/TTL limit, bounded cleanup, and observable expiry. Exact tested defaults land with later slices; configuration may only lower hard ceilings. Existing audit retention remains the compatibility anchor, and expiry/pruning is never an empty success.
- Raw HTTP bodies, tool results, serialized production principals, and raw source events are not accepted merely to improve analysis.
- Existing source IP, request ID, user agent, path, and actor data pass a centralized purpose-specific projection before crossing the audit boundary.

Repeat the evidence limitation: a valid signature proves only that a holder of a verifier-trusted key produced unchanged package bytes when the trust root is supplied out of band, not source completeness, policy safety, signer identity beyond that key mapping, or compliance.

Also add `### Control-plane observability`. Require structured privacy-safe events for run lifecycle, draft/test changes, cancellation, suggestion application, publication, and evidence export; low-cardinality metrics; explicit safe/forbidden field sets; and fail-closed transaction/outbox behavior when a required event cannot be recorded.

- [ ] **Step 2: Add the embedded threat model**

Add `## Threat model`, then subsections for assets, trust boundaries/actors, and abuse cases. Include assets for policy integrity, version integrity, authorization correctness/availability, audit-derived data, tests/risk acknowledgements, evidence/signer custody, and data-plane resources.

Include trust boundaries for unauthenticated-to-admin API, low-permission-to-privileged operations, browser-to-server authority, Policy Studio-to-audit storage, pure evaluator-to-mutable adapters, standalone-to-#241 cluster authority, evidence-to-#240 signer, and package-to-offline trust root.

Include this minimum abuse-case table:

```markdown
| Threat | Required controls | Detection and residual risk |
| --- | --- | --- |
| Authorization drift | One shared kernel, differential/property tests, evaluator version binding. | Internal failures block; implementation bugs remain possible and require tests/review. |
| Missing context becomes allow | Typed availability, indeterminate reasons, fail-closed production adapter. | Historical facts may remain unavailable and results stay incomplete. |
| Analysis causes live side effects | Pure kernel, injected immutable snapshot, network-deny and state-isolation tests. | Adapter mistakes remain a release-blocking defect. |
| Stale or replayed mutation | Strong ETags plus revision/resource/candidate/test/risk digests and idempotency. | Ambiguous responses require authoritative reads. |
| Audit-detail disclosure | Separate detail permission, centralized projection, bounded output, privacy-safe audit. | Authorized detail readers still handle sensitive operational data. |
| Resource exhaustion | Positive hard limits, quotas, deadlines, cancellation, bounded result retention. | Exhaustion may make analysis unavailable but must not weaken data-plane authorization. |
| Trace/error exfiltration | Stable codes, bounded sanitized messages, no raw matcher values. | New fields require privacy review. |
| Replay cutoff or pruning race | Immutable high-water/cutoff, snapshot or explicit incomplete/failure. | Mutable source history may have been incomplete before capture. |
| False analyzer proof | Canonical evaluator, lane-aware proofs, complexity budgets, inconclusive fallback. | Heuristics remain advisory. |
| Policy lockout or overbroad grant | Cross-resource validation, required tests, risk gates, conditional publish. | Authorized operators can still approve risky policy deliberately. |
| Canonicalization ambiguity | Exact UTF-8/JCS validation and framed digest contract with cross-platform vectors. | Future schema normalization requires a versioned contract. |
| Signing-oracle or key misuse | #240 protected key references, evidence-specific payload construction, no arbitrary signing endpoint. | Trust-root distribution and key compromise remain operator concerns. |
| Malicious, unknown, rotated, or revoked verifier key | #242 out-of-band trust root, versioned key IDs/algorithms, explicit rotation/revocation, fail-closed unknown-key handling. | Operators own authentic trust-root distribution and incident response. |
| Artifact tampering or archive abuse | Manifest digests, DSSE/in-toto envelope, size/type/path/decompression bounds, offline verification. | Valid signatures do not validate source completeness. |
| Evidence or compliance overclaim | Mandatory limitation wording in API/UI/docs/artifacts. | Humans may still misuse reports outside GreenGateway. |
```

- [ ] **Step 3: Define dependency ownership**

Add `## Dependency boundaries` and a table for:

- #218/#219: existing React workspace foundation; extend it; server capabilities remain authoritative.
- #239: transport, readiness, drain, shutdown; analysis lifecycle cannot gate data-plane readiness.
- #240: Connections, secret/credential resolution, signer-key custody; #243 consumes redacted digests and protected key references only.
- #241: PostgreSQL authority, revisions, transactions, outbox, leases/fencing, HA jobs; unavailable cluster semantics return unsupported/unavailable rather than local fallback.
- #242: ggctl, configuration bundles, stage/activate/rollback, GitOps, generated OpenAPI; #243 adds policy-domain resources through those authorities and creates no second CLI or configuration archive.

State that existing CRUD/history remains authoritative during migration and no second authority may be introduced.

- [ ] **Step 4: Add rollout, rollback, consequences, and rejected alternatives**

Add `## Rollout and migration` with this order:

1. Preserve policy v0 behavior and compatibility endpoints.
2. Add stable IDs, diagnostics, canonicalization, and explicit reviewable v0-to-v1 conversion without automatic source rewrite.
3. Extract evaluator lanes behind differential tests while the live path remains authoritative.
4. Add snapshots and server drafts before simulation/tests/replay/analyzer/evidence.
5. Add standalone resources only where semantics are equivalent; report unsupported cluster features until #241 exists.
6. Route publication/CLI through #242.
7. Add signed artifact generation only after #240 protected references and #242 artifact, `ggctl` offline-verification, and trust-root contracts exist.
8. Deprecate legacy per-rule preview and browser pseudo-expressions only after compatible server replacements ship.

Rollback retains the last compatible v0 document and never silently downgrades or discards v1-only semantics.

Add `## Consequences`, first stating that this ADR is documentation-only and ships no runtime behavior. Cover the benefits and costs: one semantic authority, explicit incompleteness, deterministic bindings, more version/limit metadata, new permissions, and staged dependency-aware delivery.

Add `## Rejected alternatives` rejecting: duplicate simulator logic; browser-owned drafts/capabilities; fail-open unknown input; unbounded replay; observation-as-proof; automatic optimizer/suggestion application; ad hoc key-sorted JSON; generic signing endpoints; and waiting for all dependency epics before defining the contract.

- [ ] **Step 5: Add checklist traceability and commit**

Add `## Checklist item 1 traceability` with rows for truth model, evaluator boundary, versioning/canonicalization, privacy projections, API schemas, limits, permission matrix, evidence trust statement, dependency boundaries, and rollout/migration. Point every row to the exact ADR heading that satisfies it.

Run:

```powershell
rg -n '^### Privacy projections$|^## (Threat model|Dependency boundaries|Rollout and migration|Consequences|Rejected alternatives|Checklist item 1 traceability)$' docs/adr/0004-policy-studio-authority-and-evidence.md
rg -n 'signature proves package integrity|no second authority|never silently downgrades|inconclusive' docs/adr/0004-policy-studio-authority-and-evidence.md
git diff --check
```

Expected: all headings and safety phrases are found; `git diff --check` prints nothing.

Commit:

```powershell
git add -- docs/adr/0004-policy-studio-authority-and-evidence.md
git commit -m "Document Policy Studio threats and rollout"
```

### Task 4: Index and Verify ADR-0004

**Files:**
- Modify: `docs/adr/README.md`
- Verify: `docs/adr/0004-policy-studio-authority-and-evidence.md`

- [ ] **Step 1: Add ADR-0004 to the index**

Append this list item after ADR-0003:

```markdown
- [ADR-0004: Policy Studio Authority and Evidence](0004-policy-studio-authority-and-evidence.md): Policy Studio and live authorization share one fail-closed evaluator, versioned resource snapshots, bounded privacy-safe analysis, and evidence that never overstates source completeness or publication authority.
```

- [ ] **Step 2: Verify local links and exact referenced files**

Run:

```powershell
$adrLinks = Select-String -Path docs/adr/README.md -Pattern '\]\(([^)]+\.md)\)' -AllMatches
$missing = foreach ($match in $adrLinks.Matches) {
  $target = Join-Path docs/adr $match.Groups[1].Value
  if (-not (Test-Path -LiteralPath $target)) { $target }
}
$missing
```

Expected: no output.

Verify the code anchors named by the ADR still exist:

```powershell
@(
  'gateway/src/rbac/policy.rs',
  'gateway/src/middleware/rbac.rs',
  'gateway/src/tools/runtime.rs',
  'gateway/src/middleware/rate_limit.rs',
  'gateway/src/egress.rs',
  'gateway/src/audit/query.rs',
  'gateway/src/middleware/observation.rs',
  'gateway/src/rbac/policy_history.rs',
  'gateway/src/discovery/suggestions.rs',
  'admin-ui/src/lib/policy.ts'
) | ForEach-Object { if (-not (Test-Path -LiteralPath $_)) { $_ } }
```

Expected: no output.

- [ ] **Step 3: Run content and safety scans**

Run:

```powershell
rg -n -i '\b(TODO|TBD|FIXME|XXX)\b' docs/adr/0004-policy-studio-authority-and-evidence.md
rg -n -i 'this policy is safe|signature proves (source|audit).{0,20}complete|missing (evidence|context) (is|means|defaults to) (zero|allow|pass)|certif(ied|ies) compliance' docs/adr/0004-policy-studio-authority-and-evidence.md
git diff --check origin/main..HEAD
git status --short --branch
```

Expected: the placeholder scan has no matches. The unsafe-claim scan has no affirmative claim; a hit is acceptable only when the surrounding sentence explicitly prohibits that wording. Diff check has no output; status shows only the intended ADR/index work or a clean tree after commit.

- [ ] **Step 4: Review the complete diff for scope and traceability**

Run:

```powershell
git diff --stat origin/main..HEAD
git diff origin/main..HEAD -- docs/adr/0004-policy-studio-authority-and-evidence.md docs/adr/README.md
```

Expected: executable files are absent. Confirm every checklist-item-1 phrase has a traceability row and every threat row includes both controls and residual risk.

- [ ] **Step 5: Commit the index and any review corrections**

Run:

```powershell
git add -- docs/adr/README.md docs/adr/0004-policy-studio-authority-and-evidence.md
git commit -m "Index the Policy Studio architecture decision"
```

Expected: commit succeeds. If the ADR was unchanged after Task 3, the commit contains only the index. Do not use `--allow-empty`.

### Task 5: Independent Review and Handoff

**Files:**
- Review: `docs/adr/0004-policy-studio-authority-and-evidence.md`
- Review: `docs/adr/README.md`

- [ ] **Step 1: Record the review range**

Run:

```powershell
git rev-parse origin/main
git rev-parse HEAD
git status --short --branch
```

Expected: base is `450ca108a963750f8f110143861f69bff62d5163`; the tree is clean and the branch is ahead of `origin/main`.

- [ ] **Step 2: Dispatch the Fable 5 independent reviewer**

Dispatch a reviewer named `fable_5_reviewer`. Provide it with only the issue requirement, reviewed design spec, base SHA, head SHA, ADR/index paths, and repository guardrails. Require findings grouped as Critical, Important, and Minor with line references and a clear ready/not-ready verdict. The review must check semantic authority, fail-closed behavior, digest interoperability, privacy, threat coverage, dependency ownership, rollout, and checklist traceability.

- [ ] **Step 3: Resolve every Critical and Important finding**

For each valid finding, edit with `apply_patch`, rerun the exact verification commands from Task 4, and commit the corrections with an imperative message. Push back only with concrete repository or issue evidence.

- [ ] **Step 4: Obtain a clean focused re-review**

Give the same reviewer the fix range and require an explicit `Ready to proceed: Yes` with no remaining Critical or Important findings.

- [ ] **Step 5: Prepare the handoff summary**

Report:

- Issue #243 checklist item 1 and `Part of #243` scope.
- Files and commits created.
- Verification commands and outcomes.
- Review findings fixed and final verdict.
- Explicit note that no runtime behavior changed and checklist items 2 through 22 remain open.
- The next authorized action; do not push or open a PR unless the user requests publishing.
