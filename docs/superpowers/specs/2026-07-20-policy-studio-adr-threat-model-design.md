# Policy Studio ADR and Threat Model Design

Date: 2026-07-20

Issue: [#243](https://github.com/Greenhat-Security/GreenGateway/issues/243), checklist item 1

Branch: `codex/issue-243-policy-studio-adr`

## Purpose

Create the architectural contract that every later Policy Studio slice must follow. This first slice is documentation-only. It must prevent later contributors from introducing a second authorization implementation, treating incomplete historical evidence as proof of safety, leaking sensitive audit data, or competing with the authorities owned by issues #239 through #242.

The implementation will add one comprehensive ADR with an embedded threat model. Keeping the decisions together matches the repository's existing ADR convention and gives later pull requests one normative source for evaluator semantics, control-plane authority, privacy, evidence, dependencies, and migration.

## Deliverables

The implementation changes only:

- `docs/adr/0004-policy-studio-authority-and-evidence.md`, added as an accepted ADR.
- `docs/adr/README.md`, updated with the ADR-0004 index entry.

It does not change Rust, TypeScript, schemas, configuration, CI, or runtime behavior. The pull request will use `Part of #243` and will not claim that any later checklist item is complete.

## ADR Structure

ADR-0004 will use the repository's Context, Decision, and Consequences pattern, expanded with tables where #243 requires a precise contract. Its sections will be:

1. Status and context.
2. Scope and non-goals.
3. Required truth model.
4. Authoritative evaluator and side-effect boundary.
5. Versions, stable identities, immutable snapshots, and canonical digests.
6. Draft, simulation, test, replay, analysis, evidence, and publication data flow.
7. API resource families, result envelope, permissions, failure semantics, and bounds.
8. Privacy projections and data-retention rules.
9. Embedded threat model.
10. Dependency ownership for #218 and #239 through #242.
11. Compatibility, rollout, and migration.
12. Consequences and rejected alternatives.
13. Checklist-item-1 traceability matrix.

## Normative Architectural Decisions

### Truth model

The ADR will keep eight concepts distinct:

1. Synthetic simulation.
2. Historical replay.
3. Recorded historical result.
4. Shadow evidence.
5. Analyzer finding.
6. Synthetic test.
7. Evidence package.
8. Signed attestation.

Every result will identify its kind, pinned inputs, completeness, and limitations. Missing, stale, unsupported, malformed, pruned, or truncated input cannot become an allow, a pass, a zero count, or a safety claim. Historical comparison uses the required wording: "No newly allowed decisions were observed among N replayable events."

### One evaluator

One typed, deterministic, side-effect-free `CompiledPolicy` kernel will own logical policy decisions. Live HTTP, route/default/shadow, MCP, tool, rate-selection, and trusted-context static egress paths will call it through thin adapters. Simulation, tests, replay, and analyzer semantic checks will call the same kernel rather than reproduce its logic.

The kernel accepts a versioned `PolicyEvaluationContext` and a redacted immutable `ResourceSnapshot`. It returns a bounded typed result containing logical outcome, enforcement, effective action, completeness, stable reason codes, matched stable identifiers, permissions, and optional bounded trace steps. Unknown or internally inconsistent input is indeterminate for analysis and fail-closed for production.

Authentication validity, CSRF, request-schema validation, mutable rate-bucket capacity, semaphore availability, DNS resolution, transport health, physical upstream selection, and upstream execution stay outside the pure verdict. Analysis performs no DNS, network, provider, secret-store, credential-validation, tool-invocation, production-bucket, semaphore, policy-mutation, or ordinary data-plane audit side effect.

### Identity, versioning, and digests

Policy schemas use exact version dispatch. Policy-relevant elements receive unique non-empty stable identifiers. Resource snapshots carry exact component versions and digests for policy, routing, tools, Connections, configuration, authentication mappings, egress, tests, cluster revision, evaluator semantics, and gateway build.

RFC 8785 JSON Canonicalization Scheme bytes followed by SHA-256 are the normative cross-platform digest contract for canonical JSON artifacts. The design retains both the original source-document digest and normalized semantic digest whenever normalization can erase representational differences. Digests use explicit media-type and schema-version domains so bytes from different artifact classes cannot be confused.

### Server authority and state transitions

The browser is a client, never a policy or capability authority. Server-owned drafts bind owner, base revision and ETag, candidate digest, resource-snapshot digest, timestamps, and expiry. Mutation uses strong ETags. Publication is a separate authorized operation that revalidates current schema, resources, tests, risks, and conditional bindings. Stale resources produce an explicit conflict and are not silently rebased.

The documented flow is:

```text
active policy + immutable resource snapshot
                  |
                  v
             server draft
                  |
        +---------+----------+
        |         |          |
        v         v          v
   simulation   tests   replay/analyzer
        |         |          |
        +---------+----------+
                  |
          immutable run result
                  |
          aggregate evidence
                  |
       optional protected signing
                  |
        conditional publication
```

Optimizer output, discovery suggestions, and remediation actions only create or modify reviewable drafts. They never mutate active policy implicitly.

### API and authorization contract

The ADR will reserve the issue's suggested resource families under the configured admin prefix: capabilities, drafts, simulations, replays, analyses, tests, evidence, and suggestions. Exact route suffixes may evolve with the OpenAPI work owned by #242, but their resource semantics may not.

The minimum permission matrix from #243 remains normative. In particular, policy read does not imply audit-detail access, evidence export, analysis, simulation, or mutation. Cookie-authenticated mutations use the shared CSRF mechanism. Authentication and authorization happen before expensive parsing, evaluator work, audit reads, or job creation.

Every result envelope exposes schema/evaluator versions, pinned revisions and digests, mode, outcome, enforcement, effective action, completeness, limitation codes, terminal reason, stable matched identifiers, and applied bounds. List and detail data are separately paginated and permissioned.

The ADR will preserve the issue's status semantics: 401/403 for access failures; 400 for malformed input; 413 or bounded 422 for size/count/depth violations; 422 for diagnostics; 428 for missing mutation preconditions; 412 for stale ETags; 409 for stale semantic bindings; 429 for exhausted quotas; 503 for required dependency unavailability; and 410 for expired artifacts. Partial, empty, interrupted, or truncated work has a completed-incomplete or failed state and cannot satisfy publication or evidence-complete gates.

### Bounds policy

The ADR will define the ownership and behavior of limits without inventing unvalidated performance numbers for endpoints that do not yet exist:

- Every byte, count, string, nesting, trace, scan, result, time, memory, TTL, per-actor concurrency, and deployment concurrency dimension has a positive server-enforced bound. Zero never means unlimited.
- The server publishes effective limits through its capabilities resource and includes applied limits in run metadata.
- Compile-time hard ceilings cannot be raised by configuration; operators may choose lower deployment limits.
- Request bytes are rejected before expensive parsing. Structural limits are checked before work is queued. Runtime limits end with explicit incomplete or failed results.
- The existing one-mebibyte request-body default and 100,000-row audit scan ceilings are recorded as compatibility anchors, not silently generalized to every future resource.
- Each later API slice must select and test its exact numeric defaults against load and data-plane latency budgets before the endpoint ships. Changing an advertised limit is a versioned operational change, not an undocumented implementation detail.

This gives later slices a binding boundedness contract while avoiding arbitrary limits that have no implementation or load evidence yet.

## Privacy Design

The ADR will define separate aggregate and detail projections. Aggregate results contain counts, stable categories, digests, proof bases, and limitation codes. Audit-derived event or principal detail additionally requires `admin:audit:read`, is independently bounded, and is never included in canonical v1 evidence.

Raw credentials, authorization or cookie headers, bodies, sensitive query/header values, tool arguments or results, full principals, source events, and secret material are excluded from simulations, traces, errors, URLs, browser persistence, logs, metrics, temporary files, evidence, and signatures. Existing retained fields such as source IP, request ID, user agent, path, and actor data must pass a centralized purpose-specific projection before leaving the audit boundary.

Evidence is aggregate-first, deterministic, and privacy-minimized. A valid signature proves only that a trusted key holder signed unchanged package bytes. It does not prove that the source audit store was complete or untampered, that a policy is safe, or that a compliance framework is satisfied.

## Embedded Threat Model

The threat model will use a compact asset/trust-boundary/abuse-case structure rather than introduce a separate repository convention.

### Assets

- Active and draft policy integrity.
- Exact policy and resource versions.
- Authorization correctness and availability.
- Audit-derived sensitive data.
- Synthetic test expectations and risk acknowledgements.
- Evidence package integrity and signer-key custody.
- Data-plane latency and resource availability.

### Trust boundaries and actors

- Unauthenticated caller to authenticated admin API.
- Authenticated low-permission operator to privileged policy operations.
- Browser to server authority.
- Policy Studio services to audit storage.
- Pure evaluator to mutable runtime adapters.
- Standalone storage to #241 cluster authority.
- Evidence assembler to #240 protected signer.
- Exported package to an offline verifier and out-of-band trust root.

Actors include unauthenticated attackers, compromised low-permission operators, malicious policy authors, stale or buggy browsers, compromised audit inputs, exhausted or crashed workers, malicious artifact consumers, and operators who accidentally over-trust incomplete evidence.

### Abuse cases and controls

The ADR will map each threat to prevention, detection, and residual risk. Required cases include authorization-logic drift, fail-open missing context, side effects during analysis, stale draft or suggestion publication, audit-detail disclosure, resource-exhaustion attacks, trace or error exfiltration, replay cutoff races, false analyzer proofs, policy lockout, non-atomic mutation, canonicalization ambiguity, signing-oracle abuse, artifact tampering/archive bombs, untrusted keys, and overclaiming source completeness or compliance.

Residual risks are stated honestly: retained audit history may be incomplete or tampered before analysis; signatures do not repair source trust; static analysis may be inconclusive; dynamic rate, semaphore, health, and DNS state cannot be reconstructed unless trusted facts were captured; and open dependency epics limit cluster or signing behavior.

## Dependency Boundaries

- #218/#219 owns the existing React Policy workspace foundation. #243 extends it and keeps server-derived capabilities authoritative.
- #239 owns transport, readiness, draining, and shutdown. Analysis jobs expose bounded lifecycle hooks but never gate data-plane readiness.
- #240 owns Connections, credential and secret resolution, and signer-key custody. #243 consumes only redacted resource digests and protected signer references and cannot expose a generic signing oracle.
- #241 owns PostgreSQL repositories, authoritative revisions, transactions, outbox behavior, durable leases, fencing, and HA coordination. Cluster-only operations report unsupported or unavailable until that authority exists.
- #242 owns ggctl, configuration bundles, stage/activate/rollback, GitOps, and generated OpenAPI. #243 contributes policy-domain resources through those authorities and does not create a second CLI or deployable configuration archive.

Existing policy CRUD and history remain authoritative during migration. Missing prerequisites produce explicit capability and dependency results rather than a weaker local or browser-only substitute.

## Rollout and Compatibility

The ADR will prescribe an incremental migration:

1. Preserve policy v0 behavior and compatibility endpoints.
2. Land stable identity, diagnostics, canonicalization, and explicit v0-to-v1 conversion without automatic source rewrite.
3. Extract evaluator lanes behind differential tests, keeping the live path authoritative throughout.
4. Add snapshots and server drafts before simulation, tests, replay, analysis, and evidence.
5. Integrate standalone resources first only where semantics are equivalent; report unsupported cluster features until #241 lands.
6. Integrate publication and CLI workflows through #242 rather than creating parallel authorities.
7. Add signing only after #240 provides protected signer references and offline trust-root behavior.
8. Deprecate the legacy per-rule preview and browser pseudo-expression only after compatible server-backed replacements ship.

Rollback must retain the last compatible v0 document and must never automatically downgrade or discard v1-only semantics. An incompatible evaluator or resource version blocks reuse or publication.

## Verification

Because this slice changes documentation only, verification is proportional and evidence-based:

- Confirm the branch is based on the exact current `origin/main` commit named by #243.
- Check ADR numbering and update the ADR index.
- Validate every repository-relative link and referenced path.
- Run `git diff --check`.
- Scan for placeholders, ambiguous "safe" claims, missing-context-as-zero wording, compliance claims, or any fail-open language.
- Use a traceability table to map every checklist-item-1 phrase to at least one ADR section: truth model, evaluator boundary, versioning/canonicalization, privacy projections, API schemas, limits, permission matrix, evidence trust statement, dependency boundaries, and rollout/migration.
- Review the completed commit independently before implementation planning.

Cargo, frontend, and runtime tests are not required for a documentation-only change that does not alter executable files. Later implementation slices must add the differential, property, side-effect, privacy, concurrency, and cross-platform tests required by #243.

## Acceptance Criteria

The design slice is complete when:

- ADR-0004 is indexed and contains every section above without placeholders.
- A later contributor can determine what is authoritative, what is pinned, what is bounded, what can be incomplete, and which dependency owns each operation.
- The threat model connects each material abuse case to controls and residual risk.
- The ADR never treats observation as proof, signatures as source attestation, missing evidence as zero, or browser state as authority.
- The diff contains documentation only and receives an independent review.
