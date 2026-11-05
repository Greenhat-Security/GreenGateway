# Policy analysis

A policy analysis reads one policy and reports what is provably wrong with its
structure, or risky about its defaults: rules, routes and rate-limit overrides
that can never decide a request because an earlier element always does,
elements whose written intent never applies, allows and shadows that match
every caller on every path, and permissive defaults.
`POST /v1{ADMIN_PREFIX}/policy/analyses` analyzes the active policy or a
candidate -- position-aware edits over it, a complete document you send, one of
your server-side drafts, or a version of the policy history -- and answers
stable findings, each with an optional advisory patch (issue #243, slice 15).

An analysis is structural. It reads the policy and the gateway's configured
MCP alias paths, never retained traffic, so it never says anything about what
was or was not observed, and it never calls an element unreachable because it
was not seen. A report with no findings is not a statement that a policy is
safe: the analyzer reports only what it can prove (see
[False-positive bias](#false-positive-bias)), and a policy can be wrong in
ways no structural check sees.

An analysis changes nothing. It does not write, activate or rewrite a policy
-- a candidate is validated, analyzed and discarded, and a patch is returned,
never applied -- emits no data-plane authorization event, records no metric
of its own, and touches no rate bucket, tool permit, resolver or upstream.
Beyond the access record every admin request gets, the only record it leaves
is one `policy.analysis_run` audit event. It reads the deployment's
[suppressions](#suppressions), which only change how a finding is labeled.

## The request

A request is a `policy-analysis.v1` document. The version is dispatched
exactly, every object refuses unknown members, and a member named like a
credential is refused with `forbidden_field`. The published schema is
[`docs/schemas/policy-analysis.v1.schema.json`](schemas/policy-analysis.v1.schema.json);
the gateway's parser is authoritative.

```json
{
  "schema_version": "policy-analysis.v1",
  "base_etag": "\"sha256:...\"",
  "candidate": { "source": "active" },
  "format": "json"
}
```

| Member | Meaning |
| --- | --- |
| `schema_version` | Exactly `policy-analysis.v1`. |
| `description` | Optional, at most 1024 bytes. Never repeated in results or audit. |
| `base_etag` | Required: the ETag of the active policy the request was written against, as `GET /v1{ADMIN_PREFIX}/policy` returns it. A different active ETag is `412` and nothing runs. |
| `candidate` | Required: `{"source": "active"}`, `{"source": "edits", "edits": [...]}`, `{"source": "inline", "policy": {...}}`, `{"source": "draft", "draft_id": "pd_...", "draft_etag": "\"sha256:...\""}` or `{"source": "revision", "version": 7}`, exactly as for a [simulation](policy-simulation.md#candidates), parsed, read and validated by the same code. A draft or history version is read, owner-scoped and validated again, and never written, as [a simulation reads one](policy-simulation.md#drafts-and-history-versions). |
| `format` | `json` (the default) or `sarif`. |

## Running an analysis

```http
POST /v1/admin/policy/analyses
Content-Type: application/json

{ "schema_version": "policy-analysis.v1", ... }
```

- The caller needs both `admin:policy:read` and the new
  `admin:policy:analyze`; either alone is `403`, and neither
  `admin:policy:simulate` nor `admin:policy:write` stands in for it. Both are
  checked before the body is read. `GET /v1{ADMIN_PREFIX}/capabilities` lists
  `admin:policy:analyze` for a principal that holds it.
- The base is the policy file's current snapshot in standalone mode, or the
  authoritative active document, at the revision it was read, in cluster mode.
- The policy's own routes are evaluated before the handler, as for every admin
  route. A policy whose routes gate the admin API needs a route for
  `POST /v1{ADMIN_PREFIX}/policy/analyses` ahead of a catch-all for unsafe
  policy methods; `dev/policy.json` carries one that grants
  `admin:policy:analyze`.

| Status | `reason` | Meaning |
| --- | --- | --- |
| `200` | -- | The analysis ran. `Cache-Control: no-store`; `application/json`, or `application/sarif+json` for `format: "sarif"`. Check `complete`: an incomplete analysis is still `200`. |
| `400` | `policy_analysis_request_invalid` | The body is not JSON or repeats a member name anywhere. |
| `401`, `403` | -- | Not authenticated, or missing either permission. |
| `404` | -- | No policy is configured, or a `revision` candidate names a deployment with no policy history. |
| `404` | `policy_draft_not_found`, `policy_revision_not_found` | A `draft` candidate names no draft of yours, or a `revision` candidate a version the history does not hold. |
| `409` | `policy_draft_base_stale` | A `draft` candidate is pinned to another base than `base_etag`. |
| `410` | `policy_draft_expired` | A `draft` candidate has expired. |
| `412` | `policy_analysis_base_stale` | `base_etag` is not the active policy's ETag, which `current_etag` carries. Nothing ran; no rebase is attempted. |
| `412` | `policy_draft_stale` | A `draft` candidate's `draft_etag` is no longer the draft's ETag. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_analysis_invalid` | The request, or an edit applied to the base, is invalid: value-free `diagnostics` with JSON pointers, as for a simulation. |
| `422` | `policy_candidate_invalid` | The candidate policy does not validate; `errors` are the policy validator's messages. |
| `422` | `policy_revision_incompatible` | A `revision` candidate is not a policy this build and deployment accept now. |
| `422` | `policy_analysis_result_too_large` | The rendered result would exceed 8 MiB. Nothing is cut short. |
| `429` | `policy_analysis_busy` | Two analyses are already running on this replica, or this caller already has one running. Nothing was queued. |
| `500` | -- | The evaluator refused a question the analyzer built, or an invariant failed. No partial result. |
| `503` | -- | Cluster mode could not read the active policy. |
| `503` | `policy_drafts_unavailable`, `policy_history_unavailable` | The drafts store or the policy history a stored candidate names could not be read. |

## The result

```json
{
  "schema_version": "policy-analysis-results.v1",
  "mode": "structural",
  "request_digest": "sha256:...",
  "analyzer": {
    "version": "gg-policy-analyzer-v1",
    "http_semantics_version": "gg-http-alias-v1",
    "http_context_version": 3,
    "tool_semantics_version": "gg-tool-policy-v1",
    "tool_context_version": 1,
    "gateway_version": "..."
  },
  "base": { "source": "active", "etag": "\"sha256:...\"" },
  "analyzed": { "source": "edits", "etag": "\"sha256:...\"", "edits": 2 },
  "resources": { "mcp_alias_paths": 1 },
  "resource_snapshot": { "schema_version": "1.0.0", "digest": "sha256:...", "complete": true, "components": { "...": "..." } },
  "complete": true,
  "limitations": [],
  "budget": { "comparisons": 12, "max_comparisons": 2000000, "max_findings": 1000 },
  "suppressions": { "available": true, "records": 3 },
  "summary": {
    "findings": 1, "patches": 1,
    "by_severity": { "high": 1, "low": 0, "medium": 0 },
    "by_proof_basis": { "heuristic": 0, "inconclusive": 0, "proven": 1 },
    "by_code": { "rule_shadowed": 1 },
    "by_suppression_state": { "suppressed": 0, "suppression_expired": 0, "suppression_mismatched": 1 }
  },
  "findings": [
    {
      "code": "rule_shadowed",
      "fingerprint": "sha256:...",
      "severity": "high",
      "proof_basis": "proven",
      "element": { "section": "rules", "pointer": "/rules/3", "position": 3, "id": "deny-admin" },
      "related": { "section": "rules", "pointer": "/rules/1", "position": 1, "id": "api-allow" },
      "never_decides_in": ["http", "rendered_tool_http"],
      "may_decide_in": ["mcp_alias", "selected_upstream", "source_request"],
      "rationale": "an earlier, less restrictive enabled rule matches every request this rule matches, ...",
      "remediation": "move the rule before the less restrictive rule that covers it, ...",
      "details": { "action": "deny", "covering_action": "allow" },
      "patch": {
        "format": "policy-simulation.v1/edits",
        "applies_to_etag": "\"sha256:...\"",
        "access_effect": "narrowing",
        "edits": [{ "op": "move", "section": "rules", "from": 3, "to": 1, "expect_id": "deny-admin" }]
      },
      "limitations": [],
      "suppression": {
        "state": "suppression_mismatched",
        "suppression_id": "pas_...",
        "mismatched": ["policy"]
      }
    }
  ]
}
```

| Member | Meaning |
| --- | --- |
| `base`, `analyzed` | The pinned active policy, and the document analyzed: the base itself, or the candidate, with its own ETag and, for policy v1, its `semantic_digest`. A `draft` adds the `draft_id` and `draft_revision` it was read at, and a `revision` the `version`. Every position, pointer and patch names the analyzed document. SARIF carries the same identity in its run properties, as `analyzed_draft_id` and `analyzed_draft_revision`, or `analyzed_version`, beside `analyzed_semantic_digest` and `resource_snapshot_digest`. The analysis a [policy evidence package](policy-evidence.md#the-analysis) carries has no `base`: no active policy was pinned, and the package names what its candidate replaces. |
| `resources.mcp_alias_paths` | How many MCP alias paths the analysis read from this gateway's static configuration (their values are not repeated). |
| `resource_snapshot` | The [resource snapshot](configuration.md#policy_file) the analysis was judged against, as `POST .../policy/validate` reports one: its `digest`, whether it is `complete`, and the versions and digests of the resources it read. A suppression binds its `digest`. |
| `suppressions` | Whether the deployment's [suppression](#suppressions) records were read (`available`) and how many (`records`, ended and unmatched ones included). |
| `complete` | Every check ran over every element. `false` means the analysis stopped at a bound named in `limitations`, and says nothing about the elements it did not reach. |
| `limitations` | `comparison_budget_exhausted`, `deadline_exceeded` or `findings_truncated`. |
| `summary` | Counts only, the same counts the audit event carries, `by_suppression_state` among them. |
| `findings` | Sorted by severity, then section, position and code. |

A finding never repeats a path, permission, caller or any other value from
the policy: it names elements by section, pointer, position and stable id, and
a role by its name, as validation diagnostics do. `rationale` and
`remediation` are fixed texts per code.

| Finding member | Meaning |
| --- | --- |
| `code` | The stable finding code; see the table below. The rationale and remediation texts may be reworded; the code is the contract. |
| `fingerprint` | `sha256:` over the code and the identities of `element` and `related` -- each element's stable id, a role's name, or its position when it has neither. It does not change when unrelated elements change, or when an element with an id moves, so a [suppression](#suppressions) or a CI baseline can name it. |
| `severity` | `high`, `medium` or `low`: how likely the finding is to be an exposure rather than clutter. |
| `proof_basis` | How the finding was established; see below. |
| `element`, `related` | The element the finding is about, and the element that establishes it (the earlier rule that covers it, the route or rule that decides first, the catch-all that masks a default). |
| `never_decides_in` | For a reachability finding, the evaluation lanes in which the element provably never decides a request. |
| `may_decide_in` | The lanes in which the analyzer did not prove that: the element may still decide there. |
| `details` | Value-free facts specific to the code, listed below. |
| `patch` | An advisory candidate patch, when the analyzer has one; see [Advisory patches](#advisory-patches). |
| `limitations` | `witness_unconfirmed` for an inconclusive finding. |
| `suppression` | `null`, or the [suppression state](#how-a-finding-reads) and the id of the suppression that decided it. Never its reason. |

### Evaluation lanes

The same policy elements decide differently depending on how a request
reaches them, so a reachability claim says in which lanes it holds.

| Lane | What decides |
| --- | --- |
| `http` | An ordinary request: one path identity, no selected virtual upstream. Direct rules by first match, then routes by first match, then the default. |
| `mcp_alias` | An MCP endpoint reached by an alias path: both identities, the most restrictive direct action anywhere winning, then a route whose prefix equals the request path, then routes by prefix on the canonical identity. |
| `selected_upstream` | A host-qualified virtual upstream: direct denies only, then host-bound routes; the default never applies. |
| `rendered_tool_http` | A rendered local tool HTTP operation: direct rules by first match with no dispatch context. |
| `source_request` | An enum-source refresh request: direct denies only. |
| `tool` | MCP tool-name rules, by first match among the rules naming the tool. |
| `rate` | Rate-limit override selection, by first match. |

### Proof bases

- `proven`: derived from the policy and the evaluator's documented semantics,
  lane by lane. Every reachability claim is also confirmed by the canonical
  evaluator before it is reported: the analyzer builds a witness request the
  claimed element itself matches (asking the evaluator about the element
  alone), asks the evaluator which element decides that witness in the
  element's ordinary lane over the analyzed policy (for a route, the route
  lane; for a route a rule pre-empts, the whole HTTP decision), and reports the
  claim only when an earlier element does. The other lanes a claim names are
  covered by the brute-force tests, not by a witness at run time.
- `heuristic`: a statement whose risk depends on the deployment rather than on
  the policy alone.
- `inconclusive`: a relation the evaluator did not confirm on its witness --
  for example a pattern whose only matching path the evaluator refuses as
  unsafe. It is reported, never dropped, and carries no patch.

`bounded_replay`, the basis of a finding informed by retained traffic, is
reserved: this analyzer reads no traffic.

### Finding codes

| Code | Severity | Basis | Patch (access effect) | Meaning |
| --- | --- | --- | --- | --- |
| `default_allow` | high; low when masked | proven | set `default_action` to `deny` (narrowing; equivalent when masked) | `default_action` is `allow`. `details.masked` is `true` when a route for `/` with every method and no host, or an enabled rule matching every caller, method and path, decides every ordinary request first (`related` names it). |
| `global_shadow_enforcement` | high; low when inert | proven | set `enforcement_mode` to `enforce` (narrowing; equivalent when inert) | `enforcement_mode` is `shadow`. `details.inheriting_routes` counts routes without their own mode and `details.default_softened` says whether a reachable default denial is softened; with neither it is inert. |
| `broad_unconstrained_allow` | high | proven | delete the rule (narrowing) | An enabled allow rule with no principal constraint and no dispatch binding matches every path. `details.all_methods`. |
| `broad_unconstrained_shadow` | high | proven | delete the rule (narrowing) | The same for a shadow rule, which forwards what it decides. |
| `wildcard_grant_without_issuer` | medium | heuristic | none | A role grants `*` and names no issuer. Whether that matters depends on how many issuers the deployment trusts. |
| `rule_unreachable` | low; medium when the covering action differs | proven | delete the rule (equivalent) | An earlier enabled rule at least as restrictive (deny over shadow over allow) matches every request this rule matches, so it never decides in any lane: `never_decides_in` lists every HTTP lane, or `tool` for a tool-name rule. `details.relation` is `duplicate` or `covered`; `details.action`, `details.covering_action`. |
| `rule_shadowed` | high for a deny; low for a shadow | proven | move the rule before the covering rule (narrowing) | An earlier, less restrictive rule covers it: it never decides an ordinary request, and `may_decide_in` lists where it still may (`mcp_alias` for a shadow; also `selected_upstream` and `source_request` for a deny; none for a tool-name rule). |
| `route_unreachable` | low | proven | delete the route (equivalent) | An earlier route with the same permission and effective enforcement mode covers it (`details.decided_by: "route"`), or a direct deny for every caller does (`"rule"`). |
| `route_shadowed` | medium | proven | move the route before the covering route (narrowing, expanding, equivalent or unknown) | An earlier route covers it with a different permission or mode (`details.permission_differs`, `details.mode_differs`). The effect is judged from the roles: narrowing when every role granting this route's permission also grants the earlier one's (and the modes do not loosen), expanding for the reverse, otherwise unknown. |
| `route_bypassed` | high | proven | delete the rule (narrowing) | A direct allow or shadow for every caller, with no dispatch binding, decides every ordinary request the route matches, so its permission is never checked; a host-bound route still decides a selected upstream (`may_decide_in`). `details.rule_action`. |
| `rate_override_unreachable` | low | proven | delete the override (equivalent) | An earlier override with the same limits selects every request this one matches. |
| `rate_override_shadowed` | medium when stricter; low otherwise | proven | move the override before the covering one (narrowing when stricter, expanding when looser, otherwise unknown) | An earlier override with different limits covers it. `details.limits` is `stricter`, `looser` or `mixed`. |

A route that some direct rule pre-empts is reported for that and is not also
compared with earlier routes.

### Access effects

A patch's `access_effect` is judged on the effective action -- forwarded or
blocked -- and, for a rate override, on the configured limits:

- `equivalent`: no request's decision changes.
- `narrowing`: nothing forwarded after the patch was blocked before it, and
  nothing is admitted under a looser limit; some requests may now be blocked
  or limited.
- `expanding`: some request may be forwarded, or admitted under a looser
  limit, that was not before.
- `unknown`: the analyzer could not tell.

## How claims are established

Every reachability claim rests on an inclusion proof: every request the
covered element's predicates accept also satisfies the covering element's.
Methods, principals, hosts, dispatch bindings and route prefixes are compared
exactly by the matchers' own reading of them; path patterns are compared
through the matcher's own segment parser by looking for one alignment of the
two patterns that works for every path (a `**` may absorb any run of the
other pattern's segments). Then the lane semantics decide where the covered
element can still win: a covering rule at least as restrictive wins in every
lane, a less restrictive one only where rules decide by first match, and a
broader earlier route does not stop a route at an MCP alias path from
deciding the alias first.

Before a claim is reported as `proven`, the evaluator confirms it on a witness
request, as described under [Proof bases](#proof-bases). The tests also check
every proven claim and every patch's access effect by brute force: random
small policies are analyzed, and every request of a small universe -- every
path of up to three segments, three methods, nine callers, in every lane -- is
decided by the evaluator before and after each patch (`policy_analysis::tests`).

## False-positive bias

The analyzer is biased toward missing findings rather than inventing them.
When it cannot prove that one element covers another it says nothing. It
does not report:

- an element covered only by the union of several earlier elements, or any
  partial overlap between two elements;
- a pattern inclusion that needs different alignments for different paths;
- two spellings of one legacy upstream origin as one dispatch binding, or a
  dispatch-bound rule as covering an unbound one;
- a route at a configured MCP alias path covered by a broader earlier route,
  because the alias selects it by exact prefix first;
- a rule scoped to a dispatch, or constrained to any principal field, as
  broad, and an allow narrower than every path as broad at all;
- a role's coverage through the permissions other roles grant: principal
  constraints are compared field by field;
- a rule with typed `conditions` as covering another element, as broad, as
  masking the default or as bypassing a route: its conditions bound what it
  matches in ways no predicate comparison does (a conditioned rule can still
  be the covered one). This build validates conditions but accepts no
  document that uses them yet, so this takes effect once they are enforced;
  identity mappings are enforced, so the mapped-role rule below applies now;
- anything about traffic: nothing is unused, unobserved or unreachable
  because retained traffic lacks it.

In mapped-role mode (a policy v1 document with `identity_mappings`), a
caller's claimed roles are not its roles, and the analyzer does not
synthesize a caller the mappings grant a role. A claim whose witness needs a
role-holding caller is therefore not confirmed and is reported
`inconclusive`, without a patch.

So a report with no findings means the analyzer proved none of these
problems, not that the policy has none.

## Advisory patches

A patch is a list of [`policy-simulation.v1` edits](policy-simulation.md#position-aware-edits)
over the analyzed document, which `applies_to_etag` names, with the access
effect the analyzer proved for it. Nothing in the gateway applies one: there is
no apply operation, an analysis writes nothing, and a patch is only ever
returned. To adopt one:

1. Simulate it: for an analysis of the active policy, send the patch's `edits`
   as an edits candidate to [`POST .../policy/simulations`](policy-simulation.md)
   with the same `base_etag`; for an edits candidate, append them after the
   candidate's own edits; for an inline, draft or revision candidate, apply them
   to that document.
2. Run the [policy tests](policy-tests.md) that guard the change, and analyze
   the result again.
3. Save the edited document as a [draft](configuration.md#policy_file) and publish it
   through the ordinary conditional publication, with `admin:policy:write`
   and every precondition and cross-resource check a publication runs.

Each patch stands alone and is computed against the analyzed document; two
patches are not guaranteed to compose, and positions shift once one is applied.

## Bounds and completeness

An analysis runs on a blocking thread behind its own limiter: at most two per
replica and one per caller, a body within 2 MiB, a two-second deadline, at
most 2,000,000 element comparisons and 1,000 findings, and an 8 MiB result.
The linear checks (defaults, wildcard grants, broad rules) run first; the
pairwise checks stop when the budget or deadline is spent, and analysis stops
at the findings cap. Any of these makes `complete` `false` and names the
bound in `limitations`; the findings already reported stand, each proven on
its own, and nothing is said about the elements not reached.

## Suppressions

A suppression records that a reviewer read one finding and decided it needs
no change until a stated time. It changes no policy and no enforcement, and it
never removes a finding from a report: it only marks the finding, and only
while it still describes exactly what was reviewed. There is no way to
suppress a code, a section or every finding at once.

A suppression names:

- the finding, by its `fingerprint` and `code` as a report gave them;
- the **binding**: the ETag of the policy the finding was reviewed in, that
  policy's [semantic digest](schemas/policy.v1.schema.json) when it is policy
  v1 (a 0.x document has none, and its ETag alone binds it), and the
  `resource_snapshot.digest` the analysis reported;
- a `reason`, 1 to 512 bytes of text without control characters;
- the principal that created it (canonical issuer and subject), when, and an
  `expires_at` at most 90 days later. The bound is compiled in; configuration
  cannot raise it.

### How a finding reads

Every finding in a report carries `suppression`: `null`, or the state of the
suppression that decided it and that suppression's id.

| `suppression.state` | When |
| --- | --- |
| `suppressed` | A suppression names this finding's fingerprint and code, its binding equals this analysis's analyzed ETag, semantic digest and resource snapshot digest, and it has not ended. |
| `suppression_mismatched` | A suppression names the finding and has not ended, but binds another policy or other resources: `mismatched` lists `policy`, `resource_snapshot` or both. Any edit to the policy, an analysis of a different candidate, a tool or Connection change, a configuration change or, in cluster mode, any change to the security revision makes a suppression mismatched. So does a resource snapshot that is not `complete`: nothing binds resources the analysis could not read. |
| `suppression_expired` | Every suppression naming the finding has ended: its `expires_at` passed, or it was withdrawn. |

Only `suppressed` hides anything, and even then the finding is still listed,
counted in `summary.findings` and its severity, and carries its patch. An
expired or mismatched suppression hides nothing; the state says why the
finding is back. When several suppressions name one finding, one that applies
wins; otherwise an unended mismatched one is reported before an ended one, and
within a state the most recently created is named. Whether a suppression has
ended is the store's judgement when the analysis read it, so two analyses of
the same policy can differ once a suppression expires between them.

`summary.by_suppression_state` counts the findings in each state, every state
listed. `suppressions.available` says whether the records were read at all:
when no store is configured or it cannot be read, no finding is suppressed,
`available` is `false` and the counts are zero, which is never the same as a
deployment with no suppressions. A suppression's `reason` never appears in a
report, SARIF or an audit event; read it from the listing below.

In SARIF, a suppressed finding's result carries one suppression,
`{"kind": "external", "status": "accepted", "properties": {"suppression_id": ...}}`;
every other result carries an empty `suppressions` array, which SARIF reads as
checked and not suppressed, so an expired or mismatched suppression is never a
SARIF suppression. Its state is in the result's `properties.suppression`. When
the records could not be read, no result carries `suppressions`, SARIF's "not
checked".

### The suppression API

| Operation | Route | Permissions |
| --- | --- | --- |
| List | `GET /v1{ADMIN_PREFIX}/policy/analyses/suppressions` | `admin:policy:read` and `admin:policy:analyze` |
| Create | `POST /v1{ADMIN_PREFIX}/policy/analyses/suppressions` | `admin:policy:write` |
| Expire now | `DELETE /v1{ADMIN_PREFIX}/policy/analyses/suppressions/{id}` | `admin:policy:write` |

Permissions are decided before any body, store or policy read. A policy whose
routes gate the admin API needs routes for these ahead of its catch-alls;
`dev/policy.json` routes `POST` and `DELETE` under
`/v1/admin/policy/analyses/suppressions` to `admin:policy:write`, and a `GET`
falls to its `admin:policy:read` route (the handler then also requires
`admin:policy:analyze`).

**Create.** The body is the
[`policy-analysis-suppression.v1`](schemas/policy-analysis-suppression.v1.schema.json)
request; unknown and repeated members are refused, and the gateway's checks
are authoritative.

```http
POST /v1/admin/policy/analyses/suppressions
If-Match: "sha256:..."
Content-Type: application/json

{
  "fingerprint": "sha256:...",
  "code": "rule_shadowed",
  "reason": "kept on purpose: the deny decides at the MCP alias first",
  "expires_at": "2026-12-01T00:00:00Z",
  "resource_snapshot_digest": "sha256:..."
}
```

`If-Match` names the live policy ETag the finding was reviewed in, as exactly
one strong entity tag, and `resource_snapshot_digest` the snapshot digest the
analysis reported. The gateway checks both against the current state and
records the live ETag, its semantic digest and the snapshot digest as the
binding: a suppression is always created against the live policy, never
re-bound to a policy or resources nobody reviewed. To suppress a finding of a
candidate, publish the candidate and analyze the live policy. `expires_at` is
RFC 3339, kept to the second, and must be after now and at most 90 days after
it on the store's clock. The answer is `201` with the suppression and its
strong `ETag`.

**List.** Every retained suppression, ended ones included, oldest first, with
the store's `limits` (`max_suppressions`, `max_ttl_seconds`,
`max_reason_bytes`). Each carries `suppression_id`, `etag`, `revision`,
`state` (`active`, `expired` or `withdrawn`), `fingerprint`, `code`,
`reason`, `created_by`, `created_at`, `expires_at`, `withdrawn_at` once
withdrawn, and its `binding`.

**Expire now.** `DELETE` with the suppression's `etag` in `If-Match` ends it
at once: its `state` becomes `withdrawn`, `revision` moves from 1 to 2, and
every analysis from then on reports its finding `suppression_expired`. It is
a compare-and-set on the revision, so of two holding one ETag exactly one
wins. A suppression is never edited; to change a reason or an expiry, expire
it and create another.

| Status | `reason` | Meaning |
| --- | --- | --- |
| `200`, `201` | -- | Listed, expired now, or created. `Cache-Control: no-store`. |
| `400` | `policy_analysis_suppression_request_invalid` | The body is not JSON of the request's shape: an unknown, missing or repeated member. |
| `400` | `policy_analysis_suppression_etag_invalid` | `If-Match` is not exactly one strong entity tag. |
| `401`, `403` | -- | Not authenticated, or missing a permission. |
| `404` | -- | No policy is configured. |
| `404` | `policy_analysis_suppression_not_found` | No suppression has this id. |
| `409` | `resource_snapshot_stale` | The resources changed since the analysis; `resource_snapshot` is the current snapshot. Analyze again. |
| `409` | `policy_analysis_suppression_exists` | This finding already has a suppression under this binding that has not ended; `suppression_id` names it. |
| `410` | `policy_analysis_suppression_ended` | The suppression already expired or was withdrawn. |
| `412` | `policy_etag_mismatch` | `If-Match` is not the live policy ETag, which `current_etag` carries. Analyze again. |
| `412` | `policy_analysis_suppression_etag_mismatch` | The suppression changed since its ETag was read. |
| `422` | `policy_analysis_suppression_invalid` | A member is out of its bounds; value-free `diagnostics` with JSON pointers (`fingerprint_invalid`, `code_unknown`, `reason_invalid`, `expires_at_invalid`, `resource_snapshot_digest_invalid`). |
| `422` | `policy_analysis_suppression_expiry_out_of_range` | `expires_at` is not after now, or is more than `max_ttl_seconds` ahead. |
| `428` | -- | `If-Match` is missing. |
| `429` | `policy_analysis_suppression_quota_exceeded` | The deployment already holds `max_suppressions` (256) suppressions that have not ended. |
| `503` | `policy_analysis_suppressions_unavailable` | No suppression store is configured, or it could not be read or written. |

### Storage and bounds

Standalone mode keeps suppressions in a `policy_analysis_suppressions` table
of the policy history database (`POLICY_HISTORY_SQLITE_PATH`, or the
`<POLICY_FILE>.history.sqlite` default), judged on the process clock. Cluster
mode keeps them in `greengateway.policy_analysis_suppressions` (PostgreSQL
migration 31), shared by every replica and judged on database time; a create
takes a transaction-scoped advisory lock so the bound holds across replicas.
At most 256 suppressions that have not ended may exist. An ended suppression
stays listed, and keeps its findings reading `suppression_expired`, until a
create needs its room: the table never holds more than 256 rows, and the
earliest-ended row goes first. `gateway import-standalone` leaves standalone
suppressions behind; their binding names a standalone policy and resources.

Each create emits `policy.analysis_suppression_created` and each expiry
`policy.analysis_suppression_withdrawn`, with the `suppression_id` and the
finding `code` only. A create or expiry refused against current state (a
stale policy or snapshot, a duplicate, the bound, the expiry window, an ended
or changed suppression) emits `policy.analysis_suppression_refused` with the
`operation` (`create` or `withdraw`), the stable `reason`, the `code` and the
`suppression_id` when there is one. None carries the fingerprint, the binding
or the reason, and no suppression records a metric of its own. A request
refused before it was understood (authorization, a malformed body, an
out-of-bounds member) is not recorded as a suppression decision.

## Audit

Each completed analysis emits one `policy.analysis_run` audit event with the
acting principal and the request envelope, `request_digest`, `base_etag`,
`security_revision` (cluster mode), `candidate_source`, `candidate_etag`, the
number of `edits`, for a stored candidate its `candidate_draft_id` and
`candidate_draft_revision` or its `candidate_version`, the `format`,
`complete`, the `limitations`, the `summary` counts (by severity, proof basis,
code and suppression state), `suppressions_available`,
`resource_snapshot_digest` and `resource_snapshot_complete`, and the analyzer
and evaluator versions. It never carries a finding's element, pointer, id or
fingerprint, a suppression id or reason, a patch, or policy content. A refused
request (`4xx`) is not recorded as an
analysis.

## Not part of this slice

- Findings informed by retained traffic (`bounded_replay`), and unused roles
  and permissions.
- Partial overlaps and first-match conflicts short of full coverage, MCP
  alias and host-qualified exception effects beyond reachability, tool policy
  versus tool-name rule conflicts, egress lints, unknown cross-resource
  references and administrator lockout (the
  [cross-resource checks](configuration.md#policy_file) run at publication for the last
  two).
- `ggctl` integration.
