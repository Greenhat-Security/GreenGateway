# Policy evidence packages

A policy evidence package is a reproducible, aggregate report about one
policy candidate: a **publication** (one version of the policy history) or a
**draft** (a server-side policy draft you own).
`POST /v1{ADMIN_PREFIX}/policy/evidence` assembles it on the server from what
the candidate's authority holds and what this gateway build recomputes from
it, and returns it as canonical JSON (issue #243;
[ADR-0004](adr/0004-policy-studio-authority-and-evidence.md)).

A package can cover:

- **Document digests**: the candidate's policy ETag and, for a policy v1
  document, its ADR-0004 semantic digest; the same for what it replaces (the
  history version before a publication, the live policy a draft is pinned
  to).
- **The approval as recorded** (publications only): when the history recorded
  the publication, by which operation, and what that operation was bound to.
- **Validation**: the candidate revalidated by this build with the checks
  `POST /policy/validate` applies, including the cross-resource checks and the
  resource snapshot they read.
- **Tests**: a [policy test suite](policy-tests.md) you send, or the stored
  suite pinned by its ETag, run against the candidate.
- **Simulation**: [synthetic cases](policy-simulation.md) you send, decided
  under the candidate and what it replaces.
- **Historical impact**: the result of a finished [replay job](policy-replay.md#replay-jobs)
  of yours whose candidate is the packaged document, with its comparison
  against the policy the job was pinned to and against what was recorded.
- **Analysis**: the conservative [structural analyzer](policy-analysis.md)'s
  findings over the candidate, with their proof basis, the suppressions that
  apply to them and whether the analysis was complete, as a separate
  manifest artifact.
- **A Markdown rendering** of the report, derived from it through a fixed
  template and bound by digest.

## What a package is, and what it is not

A package is evidence in the bounded sense ADR-0004 defines: a report over
pinned inputs, the limits applied and the limitations that remain. It is not
proof that the policy is safe, that its history or audit sources were
complete or untampered, or of compliance with any framework. Every package
says so in its own report. A publication's report carries:

> This package is unsigned. It reports what this gateway's policy history
> recorded about one publication and what this gateway build recomputed from
> it, under the stated versions and bounds. It does not prove that the policy
> is safe, that the history or audit sources it was read from were complete or
> untampered, or compliance with any framework.

A draft's report carries instead:

> This package is unsigned. It reports one server-side policy draft, as this
> gateway's draft workspace held it at the stated draft ETag, and what this
> gateway build recomputed from it, under the stated versions and bounds. It is
> not evidence of a publication: the draft may still change, expire or never be
> published. It does not prove that the policy is safe, that the sources it was
> read from were complete or untampered, or compliance with any framework.

The Markdown rendering repeats the statement of its report verbatim.

Every result in a package is computed by the server. A request names the
candidate and supplies inputs (a suite, cases, a replay job id, whether to
analyze); it cannot supply a digest, a result or a document. Generating a
package writes nothing: it is not stored, does not activate or change any
policy, does not touch or extend a draft, and leaves one
`policy.evidence_exported` audit event.

Packages are **unsigned**. Signing them with protected keys and verifying a
signature against an out-of-band trust root is a later slice (#243 slice 21),
which needs protected signer references (#240). Until then a package is
integrity-checkable (its manifest binds every artifact by digest) but says
nothing about who produced it. `ggctl evidence verify` checks that integrity
offline ([below](#verifying-a-package)) and reports a package that passes as
`integrity_valid` and `unsigned`, never as trusted.

## Requesting a package

In **Policy Studio → Evidence**, choose a version number from Policy history
or open a saved draft in the Edit tab. Save or rebase outstanding draft
changes before generating its package. Choose which evidence to include.
The Test and Simulate options use the cases on those tabs. Historical impact
uses the ID of a completed replay you own. Each option requires the
permissions listed below.

Choose **Generate evidence package** to read its trust statement, limitations,
report digest and Markdown report. **Download canonical JSON** saves the
original gateway response for offline verification. Changing the inputs or
leaving the Evidence tab discards the in-page download.

To request the same format from the API:

```sh
curl --fail-with-body -sS -X POST "$GATEWAY/v1/admin/policy/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @evidence-request.json \
  -D headers.txt -o policy-evidence.json
grep -qi '^x-greengateway-policy-evidence-completeness: complete' headers.txt
grep -qi '^x-greengateway-policy-evidence-candidate-kind: publication' headers.txt
```

### The request

The body is a `policy-evidence-request.v1` document, published as
[`docs/schemas/policy-evidence-request.v1.schema.json`](schemas/policy-evidence-request.v1.schema.json):

```json
{
  "schema_version": "policy-evidence-request.v1",
  "publication": { "version": 12, "etag": "\"sha256:...\"" },
  "suite": { "schema_version": "policy-tests.v1", "cases": [] },
  "simulation": {
    "trace": "terminal",
    "projections": ["as_authored"],
    "cases": []
  },
  "replay_job_id": "rpl_...",
  "analysis": true
}
```

- `schema_version` must be exactly `policy-evidence-request.v1`.
- Exactly one candidate (`422 policy_evidence_invalid` with `missing_field` or
  `conflicting_field` otherwise):
  - `publication.version` is the policy history version, as
    `GET /v1{ADMIN_PREFIX}/policy/history` lists it: an integer from 1 to
    2^53 - 1. `publication.etag` (optional) pins the document you reviewed: a
    stored document with a different policy ETag is `409`.
  - `draft` names one of your [server-side drafts](configuration.md) by
    `draft_id` and the strong `draft_etag` you reviewed it at, both required,
    exactly as a simulation's `draft` candidate names one:
    `{"draft_id": "pd_...", "draft_etag": "\"sha256:...\""}`.
- `suite` (optional) is a complete `policy-tests.v1` suite, parsed exactly as
  `POST /policy/tests/runs` parses one, or a reference to the
  [stored suite](policy-tests.md#storing-a-suite-beside-the-policy):
  `{"source": "stored", "etag": "\"sha256:...\""}`. The ETag is required, so a
  package binds the stored version its reader reviewed and never whichever is
  stored when it is assembled; the request digest covers it. A stored suite
  that no longer carries that ETag is `409` (`policy_evidence_suite_mismatch`)
  and no package is produced; no stored suite is `404`
  (`policy_tests_not_found`), and a store that cannot be read `503`
  (`policy_tests_unavailable`). Diagnostics are located under `/suite`.
- `simulation` (optional) holds `cases` (1 to 256 `policy-simulation.v1`
  cases), `projections` (`as_authored` and `enforce_all_shadow`; default
  `["as_authored"]`) and `trace` (`terminal`, the default, or `matched`). A
  `full` trace is not part of an evidence package.
- `replay_job_id` (optional) names a replay job you started that has finished
  with a result (`completed` or `completed_incomplete`).
- `analysis` (optional, boolean) set to `true` runs the structural analyzer
  over the candidate and adds its results to the package. Omitted or `false`
  leaves them out.

Unknown members, repeated member names (`400`), credential-shaped members
(`token`, `authorization`, `headers` and similar, refused as `forbidden_field`)
and `null` sections are refused with structured, value-free diagnostics
(`422 policy_evidence_invalid`). The request digest in the report is the
ADR-0004 semantic digest of the request (media type
`application/vnd.greengateway.policy-evidence-request+json`), so two requests
that differ only in whitespace or member order name the same inputs.

### Permissions

Every package needs both `admin:policy:read` and the new
`admin:policy:evidence:read`, checked before the body is read. A section adds
the permissions of its own endpoint, checked before any history, draft or
policy read and any evaluation, so nothing can be learned through a package
that could not be read directly:

| Section | Additional permissions |
| --- | --- |
| `suite` (inline or the stored suite) or `simulation` | `admin:policy:simulate` |
| `replay_job_id` | `admin:policy:simulate` and `admin:audit:read` |
| `analysis` | `admin:policy:analyze` |

A draft needs no permission beyond the two, because reading your own draft
needs only `admin:policy:read`, but it is served only to its owner: another
principal's draft is the same `404 policy_draft_not_found` as one that does
not exist. A replay job is likewise served only to the principal that started
it, as on the replay routes. The admin capabilities endpoint lists
`admin:policy:evidence:read` when it is held. The route-level RBAC rule for
`POST /v1/admin/policy/evidence` should grant `admin:policy:evidence:read`
ahead of the catch-all `admin:policy:write` rule for unsafe policy methods,
because generating a package writes nothing; see `dev/policy.json`.

## The package

The response body is the package's [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
(JCS) bytes, served as `application/vnd.greengateway.policy-evidence+json`
with `Cache-Control: no-store` and a fixed download name:
`Content-Disposition: attachment; filename="policy-evidence.json"` for a
publication, `filename="policy-draft-evidence.json"` for a draft. Three
headers repeat what a pipeline usually gates on:
`X-GreenGateway-Policy-Evidence-Completeness` (`complete` or `incomplete`),
`X-GreenGateway-Policy-Evidence-Digest` (the report digest) and
`X-GreenGateway-Policy-Evidence-Candidate-Kind` (`publication` or `draft`). A
gate that admits a publication should check the candidate kind as well as the
completeness: a draft's package can be complete. The package schema is
published as
[`docs/schemas/policy-evidence.v1.schema.json`](schemas/policy-evidence.v1.schema.json).

### Envelope and manifest

```json
{
  "schema_version": "policy-evidence.v1",
  "generated_at": "2026-10-28T12:00:00Z",
  "manifest": [
    {
      "name": "report",
      "media_type": "application/vnd.greengateway.policy-evidence-report+json",
      "schema_version": "policy-evidence-report.v1",
      "digest": "sha256:...",
      "size": 18234
    },
    {
      "name": "analysis",
      "media_type": "application/vnd.greengateway.policy-analysis-results+json",
      "schema_version": "policy-analysis-results.v1",
      "digest": "sha256:...",
      "size": 6120
    },
    {
      "name": "report_markdown",
      "media_type": "text/markdown; charset=utf-8; variant=GFM",
      "schema_version": "policy-evidence-report-markdown.v1",
      "digest": "sha256:...",
      "size": 4410
    }
  ],
  "report": { },
  "analysis": { },
  "report_markdown": "# Policy evidence report\n..."
}
```

Each manifest entry names the envelope member of the same name, in this
order; `analysis` and its entry are present exactly when the request asked
for the analysis. For the JSON artifacts (`report`, `analysis`) `digest` is
the ADR-0004 semantic digest of the member: SHA-256 over the frame
`"GGDIGEST" 0x00`, then `semantic`, the media type, the schema version and
the member's JCS bytes, each preceded by its length as an unsigned 64-bit
big-endian integer; `size` is the length of those JCS bytes. For
`report_markdown`, a string, `digest` is the ADR-0004 source digest of its
UTF-8 bytes (the same frame with `source` in place of `semantic`) and `size`
their length. The report repeats the analysis entry in `analysis.artifact`, so
the report digest binds the analysis too. Everything a reader relies on is in
the report and the artifacts it names; the envelope adds only `generated_at`,
which no digest covers.

The package is deterministic: the same candidate, suite, cases, replay job
and, with the analysis, suppression records, judged by the same gateway build
under the same deployment checks, produce a byte-identical report, analysis
and Markdown, and so identical digests, on any platform and however many
packages are assembled at once. Two exports of the same inputs differ only in
`generated_at`. (Whether a suppression has ended is the store's judgement when
the package is assembled, so the same records can read differently once one
expires.)

### The report

| Member | What it holds |
| --- | --- |
| `schema_version`, `redaction_profile` | `policy-evidence-report.v1` and `policy-evidence-aggregate.v1` |
| `candidate_kind` | `publication` or `draft` |
| `gateway_version`, `evaluator` | The build and the evaluator semantics and context versions that judged the inputs |
| `request_digest` | The request's semantic digest |
| `publication` | Publications only: `version`; `policy` (`schema_version`, `etag`, `semantic_digest` or `null`); `predecessor` (the history version immediately before it, with the same identity, or `null`); and `predecessor_check` |
| `approval` | Publications only: the approval as recorded (below) |
| `draft` | Drafts only: `draft_id`, `revision`, the `draft_etag` you pinned, `policy` (the draft's document identity) and `base` (`source` `active` and the `policy` identity of the live policy the draft is pinned to) |
| `validation` | `basis` (`revalidated_by_this_build`), `valid`, up to 100 `diagnostics` in the form `POST /policy/validate` reports them, `diagnostics_truncated`, and the `resource_snapshot` the cross-resource checks read |
| `tests` | `{"included": false}`, or `included` and `results`: the `policy-test-results.v1` report, whose `policy.source` is `publication` or `draft`, and whose `suite.stored` names the stored version (`version` and `etag`) when the request named the stored suite |
| `simulation` | `{"included": false}`, or `included`, `mode` (`synthetic`), `trace`, `projections`, `base` (a publication's predecessor `version` and `etag`, a draft's base `etag`, or `null`), `candidate` (a publication's `version` and `etag`, a draft's `draft_revision` and `etag`), `not_evaluated`, `summary` and per-case `cases` as a simulation reports them |
| `replay` | `{"included": false}`, or `included`, `mode` (`historical_replay`), `state`, the job's `request_digest`, `evaluator`, `base` and `candidate` ETags, `projections`, `window`, `cutoff`, `limits`, `not_replayed`, `predecessor_check`, `result_digest` and the `policy-replay-results.v1` `result` |
| `analysis` | `{"included": false}`, or `included`, `artifact` (the manifest entry of the analysis), `analyzer` (its versions), `analyzed` (the source, ETag and stored identity it analyzed), `complete`, `limitations` (the analyzer's own), `suppressions` (`available`, `records`), `summary` (counts by severity, proof basis, code and suppression state) and `findings` (below) |
| `completeness`, `limitations` | `complete` exactly when `limitations` is empty |
| `trust` | `signed` (`false`) and the fixed `statement` quoted above for the candidate kind |

**Document digests.** The history and the drafts store keep the normalized
document, not the bytes it was submitted as, so a package carries no source
digest. A policy v1 document's semantic digest is the one
`POST /policy/validate` reports for the same document. A 0.x document has no
normative normalization, so it has no semantic digest; it is bound by its
policy ETag alone, which is a compatibility mechanism, and the report says so
with `policy_semantic_digest_unavailable`.

**The predecessor.** `predecessor` is the history version immediately before
the publication: what it replaced, as far as the history knows. When the
publication recorded the base it was made against (a draft's pinned base, or
the policy a bound shadow review was read under), `predecessor_check` compares
the two: `matches_recorded_base` or `differs_from_recorded_base`. Otherwise it
is `no_recorded_base`, or `no_predecessor` when no earlier version is in the
history. In standalone mode a history append can fail after its policy
change committed (the change then answers with
`X-GreenGateway-Policy-History-Warning`), so only a recorded base can reveal a
gap; in cluster mode the history is written in the commit's own transaction.
The policy file's own document is never a history version, so the first
version recorded after the history was configured has no predecessor. Nor
is an edit of `POLICY_FILE` or a restart: in standalone mode an operator can
change the live policy between two publications without writing a version,
so the history version before a publication is not necessarily the document
it replaced, and only a recorded base that matches shows that it was.
A draft's predecessor is always known: it is its `base`, the live policy, and
the simulation, the replay check and the cross-resource checks compare the
draft with it.

**The approval as recorded.** GreenGateway has no approval workflow beyond the
authorized commit itself, so `approval.basis` is `authorized_commit`. The
section reports `recorded_at`, `operation` (`policy_replaced`,
`policy_rolled_back`, `policy_draft_published`, `rule_created`,
`rule_updated`, `rule_deleted`, `rules_reordered`, `imported_from_standalone`,
or `unrecognized` and `not_recorded`), and what the operation was bound to:
`draft` (the draft revision published and the base ETag it was pinned to),
`shadow_review` (the transition, the reviewed policy ETag and the evidence
digest of the review a promotion or disable was bound to),
`rollback_target_version`, and `rule_id`. Only the members the gateway writes
are read, each only in the shape it writes it in; anything else is left out,
never repeated. `actor` is always `withheld`: an actor's subject is often an
email address. An authorized reader finds it under the same version in the
policy history. A draft has no approval: nothing has been committed.

**Validation.** Revalidation is a judgement by this build and this deployment's
checks at generation time; the history does not record what validation said at
publication time, and the drafts store judged a draft when it was saved. It
runs the document's own checks, the deployment checks (proxy dispatch, the
document format this deployment commits) and the cross-resource checks a
publication runs, reading the resources current now: references another
resource contradicts, and risks. Those checks judge a publication on its own,
as the replacement of itself: the checks that compare a publication with what
it replaced -- `egress_change_requires_restart` and `policy_write_unreachable`
-- are not repeated, because the history cannot show what it replaced (see
the predecessor above) and its commit ran them against the policy that was
live then. A draft is judged as the replacement of its base, the live policy
publishing it would replace, so those checks do run for it, including whether
it leaves `admin:policy:write` reachable. Neither runs the publisher-specific
lockout check, because the caller asking for evidence is not necessarily the
one who publishes and a package must not depend on who asks for it.
`resource_snapshot` is the snapshot those checks read, with the digest
`POST /policy/validate` reports for the same resources; a snapshot that could
not read every resource adds a `resource_unavailable` warning, which blocks
complete evidence. A suite, cases or an analysis cannot be evaluated against a
candidate that now fails a check they depend on: the request is refused with
`422 policy_evidence_publication_not_evaluable` (or
`policy_evidence_draft_not_evaluable`) and its diagnostics. Without any of
them, the package is still produced and reports `valid: false`.

**Simulation.** The cases are decided under the candidate and, as the base,
under what it replaces. A predecessor that no longer compiles under this build
leaves the candidate judged alone (`base: null`,
`simulation_base_not_evaluable`). A package supplies no egress controls and no
global rate lanes, in tests and cases alike, because this process's
configuration does not describe the gateway that served a publication or will
serve a draft: an egress case, or a rate sequence on a global lane, is
`incomplete` (`missing_egress_controls`, `missing_rate_lane_configuration`),
and a sequence on an override runs on the candidate's own limits.

**Historical impact.** A replay job's result describes the candidate it
replayed, so a job is bound only when its candidate's policy ETag is the
packaged document's (`409 policy_evidence_replay_binding_stale` otherwise). Its
impact comparison is against the active policy the job was pinned to, so
`predecessor_check` says whether that base is what the candidate replaces
(`matches_predecessor`): a job started before publication, with the draft's
document as an inline or draft candidate, compares the publication with what
it replaced. A job started afterwards compares the published policy with
itself and with the record (`differs_from_predecessor`); it is still
reported, and the package names `replay_base_not_predecessor`. The section
repeats the job's own bindings, projections, window, cutoff and limits and its
counts-only result, including the [impact comparison](policy-replay.md#impact-comparison)
and the bounded statement it makes, exactly as the job produced them. It
leaves out the job id, and `result_digest` ties the section to the job's
`policy.replay_completed` audit record. The package adds no statement of its
own about newly allowed decisions.

### Draft packages

A draft package is about a server-side draft you own, read exactly as a
simulation reads a draft candidate and never written:

- It must be yours (`404 policy_draft_not_found` otherwise, exactly as for a
  draft that does not exist), unexpired (`410 policy_draft_expired`), still at
  the `draft_etag` you named (`412 policy_draft_stale`), and pinned to the
  live policy (`409 policy_draft_base_stale` once the live policy has moved:
  the draft is never rebased into a package). Without a drafts store the
  request is `503 policy_drafts_unavailable`.
- The report is labelled `candidate_kind: draft`, carries `draft` instead of
  `publication` and `approval`, names the draft's base as what it replaces,
  and carries the draft trust statement. The published schema refuses a draft
  report that carries a publication's members, and a publication report that
  carries a draft's.
- It is never presented as a publication: its download name, its candidate
  kind header, its Markdown heading and its trust statement all say draft. A
  complete draft package is complete evidence about the draft at that ETag,
  not about any publication; publishing the draft is a separate, ordinary
  publish under its own preconditions.

### The analysis

With `analysis: true` the package carries the conservative structural
analyzer's results over the candidate as the `analysis` artifact, and the
report summarizes them.

**The artifact** is the `policy-analysis-results.v1` document
`POST /v1{ADMIN_PREFIX}/policy/analyses` returns for the same candidate given
as a `revision` (a publication) or `draft` candidate, with three differences:
it has no `base` (no active policy was pinned, and the report names what the
candidate replaces), its `request_digest` is the evidence request's, and
`analyzed.source` is `revision` (with `version`) or `draft` (with `draft_id`
and `draft_revision`). Its findings, fingerprints, proof bases, lanes,
rationales, remediations and advisory patches are the analyzer's own; see
[policy analysis](policy-analysis.md), including what it cannot see. A
candidate patch is never applied.

**Suppressions** are read once per package and applied exactly as an analysis
applies them: a finding is `suppressed` only when a record names its
fingerprint and code, the candidate's ETag and semantic digest and the
complete resource snapshot validation read, and has not ended; otherwise a
record naming it is reported as `suppression_mismatched` or
`suppression_expired` and hides nothing. A suppressed finding is still listed
and counted. A suppression's reason never enters a package. When the records
cannot be read, nothing is suppressed, `suppressions.available` is `false`,
and the package is incomplete (`analysis_suppressions_unavailable`).

**The report's `analysis.findings`** lists, for every finding of the
artifact, its `code`, `fingerprint`, `severity`, `proof_basis` (`proven`,
`heuristic` or `inconclusive`), `element` (section, JSON Pointer, position,
stable id, role name) and `suppression` (`null`, or `state`,
`suppression_id` and, for a mismatched record, what it binds differently).
Rationales, remediations, lanes, details and patches stay in the artifact.

**Completeness.** An analysis that ran out of its comparison budget, its
two-second deadline or its findings cap is `complete: false` with the
analyzer's own limitation codes, says nothing about what it did not reach, and
makes the package incomplete (`analysis_incomplete`). A finding-free complete
analysis is not a statement that the policy is free of the problems the
analyzer looks for.

### The Markdown rendering

`report_markdown` is a GitHub-flavored Markdown rendering of the report for
human review. It is derived, and the JSON report is authoritative:

- It is rendered from the report's RFC 8785 bytes alone, through one fixed
  template (`policy-evidence-report-markdown.v1`): fixed headings, labels and
  sentences, with values from members the template names. Rendering the same
  report bytes always gives the same Markdown bytes, so a reader can render
  the report again and compare.
- It contains no more data than the report: every value it shows is a scalar
  of the report, written as an inline code span (or `none` for `null`), and a
  member the template does not name is never shown. It leaves much out:
  per-case results, the replay result and everything only the analysis
  artifact holds.
- Every value is sanitized: inside a code span, every character that is not
  printable ASCII, the backtick, the pipe, the backslash and a space at either
  end are written as `\u{XXXX}`, so no value can close its span, split a table
  cell, become a link or HTML, or carry a control, bidirectional or invisible
  character.
- It repeats the report's trust statement verbatim, and a report whose
  statement is not the fixed one for its candidate kind is not rendered at
  all.
- Its manifest entry binds it by the ADR-0004 source digest of its UTF-8
  bytes.

### Completeness and limitation codes

A report is `complete` only when every section is present and complete and
nothing below applies. An incomplete report never satisfies an
evidence-complete gate. `limitations` lists, sorted:

| Code | Meaning |
| --- | --- |
| `policy_semantic_digest_unavailable` | The candidate is a 0.x document, which has no normative normalization; it is bound by its ETag alone |
| `predecessor_not_in_history` | No earlier version is in the history, so what the publication replaced is unknown and a simulation has no base |
| `predecessor_differs_from_recorded_base` | The history version before the publication is not the base the publication recorded it was made against |
| `validation_blocks_evidence` | Revalidation reported a diagnostic whose `blocks.evidence` is `true`, such as a 0.x document's missing element ids |
| `validation_diagnostics_truncated` | Revalidation reported more than 100 diagnostics |
| `tests_not_included` | The request carried no suite |
| `tests_incomplete` | The suite's status is `incomplete` or `error`: a case was undecided or refused. A `failed` suite is complete evidence of the failure |
| `simulation_not_included` | The request carried no cases |
| `simulation_base_not_evaluable` | What the candidate replaces no longer compiles under this build, so the cases were decided under the candidate alone |
| `replay_not_included` | The request named no replay job |
| `replay_incomplete` | The job is `completed_incomplete`: its window was truncated, passed its deadline, changed under it, or held no replayable record |
| `replay_base_not_predecessor` | The job compared the candidate with a policy other than what it replaces, so its impact is not the candidate's own |
| `analysis_not_included` | The request did not ask for the analysis |
| `analysis_incomplete` | The analyzer ran out of its comparison budget, its deadline or its findings cap |
| `analysis_suppressions_unavailable` | The suppression records could not be read, so no finding's suppression state is known |

### Verifying a package

`ggctl evidence verify policy-evidence.json` checks a package offline, with the
gateway's own digest code: the file must be exactly its RFC 8785 bytes, its
envelope must hold only what its manifest lists, and each artifact must have
its defined media type and schema version and the stated size and digest. See
[docs/ggctl.md](ggctl.md#evidence-verify) for its exit codes and report.

A reader without `ggctl` can check the manifest without trusting the transport
that delivered the package:

```python
import hashlib, json, struct

def framed(kind, entry, payload):
    frame = b"GGDIGEST\x00"
    for part in (kind, entry["media_type"].encode(),
                 entry["schema_version"].encode(), payload):
        frame += struct.pack(">Q", len(part)) + part
    return "sha256:" + hashlib.sha256(frame).hexdigest()

package = json.load(open("policy-evidence.json", encoding="utf-8"))
for entry in package["manifest"]:
    member = package[entry["name"]]
    if isinstance(member, str):  # report_markdown: its UTF-8 bytes
        payload, kind = member.encode("utf-8"), b"source"
    else:
        # A sketch: Python's encoder agrees with RFC 8785 for ASCII member
        # names, integers and short decimal fractions, which is what a report
        # and an analysis hold. Use a full RFC 8785 implementation where it
        # matters.
        payload = json.dumps(member, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        kind = b"semantic"
    assert len(payload) == entry["size"]
    assert framed(kind, entry, payload) == entry["digest"]
analysis = [e for e in package["manifest"] if e["name"] == "analysis"]
if analysis:
    assert package["report"]["analysis"]["artifact"] == analysis[0]
```

Python sorts keys by code point, which equals RFC 8785's UTF-16 order for
ASCII member names, and spells some numbers (such as `1e-07`) differently from
RFC 8785, so treat a mismatch from this sketch as a reason to check with a
conforming encoder. A matching digest shows that an artifact is the one the
manifest names. Without a signature it does not show who produced it.

## Status codes

| Status | Reason | When |
| --- | --- | --- |
| `200` | | The package |
| `400` | `policy_evidence_request_invalid` | The body is not JSON, or repeats a member name |
| `401` / `403` | | Not authenticated, or a permission above is missing |
| `404` | `policy_evidence_publication_not_found` | The history has no such version |
| `404` | `policy_draft_not_found` | You own no draft with that id |
| `404` | `policy_evidence_replay_job_not_found` | No replay job of yours has that id |
| `404` | | No policy history is configured (publications) |
| `408` | `policy_evidence_request_timeout` | The body did not arrive within five seconds |
| `409` | `policy_evidence_publication_mismatch` | `publication.etag` is not the stored document's ETag |
| `409` | `policy_draft_base_stale` | The live policy is no longer the one the draft is pinned to |
| `409` | `policy_evidence_replay_job_unfinished` | The job holds no result: pending, failed, cancelled, interrupted or expired (`state` names which) |
| `409` | `policy_evidence_replay_binding_stale` | The job's candidate is not the packaged document |
| `410` | `policy_draft_expired` | The draft's TTL has passed |
| `412` | `policy_draft_stale` | The draft changed since the `draft_etag` you named |
| `413` | | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower |
| `422` | `policy_evidence_invalid` | The request is invalid; `diagnostics` say why |
| `422` | `policy_evidence_publication_not_evaluable` | The publication fails a check the requested suite, cases or analysis depend on, or no longer compiles |
| `422` | `policy_evidence_draft_not_evaluable` | The same, for a draft |
| `422` | `policy_evidence_case_refused` | The evaluator refused a simulated case |
| `422` | `policy_evidence_too_large` | The package, every artifact included, would exceed 4 MiB; it is refused whole, never cut short |
| `429` | `policy_evidence_busy` | Four packages are being assembled on this replica, or one of yours is |
| `503` | `policy_evidence_history_unavailable` | The history could not be read |
| `503` | `policy_drafts_unavailable` | No drafts store is configured, or it could not be read |
| `503` | `policy_evidence_deadline_exceeded` | The suite and cases were not decided within five seconds |
| `503` | `policy_evidence_audit_unavailable` | The export could not be recorded; no package was released |
| `503` | `policy_replay_store_unavailable` | Cluster mode: the replay job store could not be read |

## Privacy

A report follows the `policy-evidence-aggregate.v1` redaction profile: digests,
ETags, versions, stable codes, counts, timestamps of history records and of the
replay window, and case, rule, route, draft, finding and suppression
identifiers. It carries no policy content, no fixture value (paths, subjects,
roles of hypothetical callers), no audit record or replay sample, no actor
identity, no request id, source address or user agent, no suppression reason,
and no free-text error detail. Validation diagnostics are the stable code,
JSON Pointer, element id and fixed message and remediation
`POST /policy/validate` returns, never its free-text detail. The test,
simulation and analysis sections are the same value-free results their own
endpoints return: an analysis names elements by section, JSON Pointer,
position, stable id and, for a role, its name, as `POST /policy/analyses`
does, and its texts are the analyzer's fixed rationales and remediations. The
Markdown rendering carries no more than the report.

A package is not self-contained: it does not embed the suite, the cases, the
policy documents or the replayed records, so it cannot be replayed without the
authorities it was read from, and it carries nothing those authorities would
not show an authorized reader.

## Audit

A package is released only once its `policy.evidence_exported` audit event is
accepted by the audit authority; under `AUDIT_DURABILITY=required` an event
that cannot be recorded withholds the package (`503
policy_evidence_audit_unavailable`). The event carries the acting principal and
the request envelope, `candidate_kind`, `publication_version` (a publication)
or `draft_id` and `draft_revision` (a draft), `policy_etag`,
`policy_semantic_digest`, `request_digest`, `report_digest`,
`analysis_digest`, `markdown_digest`, `completeness`, `limitations`, whether
tests, cases and the analysis were included, the suite status, the replay
`result_digest` and the package size. It never carries a case, a fixture
value, a finding, a suppression reason, policy content or the package itself.
Refused requests are not recorded as exports.

## Limits and what comes later

Generation is synchronous: a body within `MAX_BODY_SIZE` or 2 MiB, whichever
is lower, that arrives within five seconds; at most 512 test cases and 256
simulation cases; a five-second deadline on deciding both, compilation
included, and then the analyzer's own two-second deadline, the one
`POST /policy/analyses` applies; a 4 MiB package, every artifact included; and
at most four packages being assembled at once per replica and one per caller,
each on a blocking thread. Work is admitted only once the body is in hand, and
its slot is held until the blocking work ends, even when the client
disconnects first. A package reads a publication from whichever authority
holds the history: the SQLite history beside the policy file in standalone
mode, the immutable PostgreSQL policy documents in cluster mode; a draft from
the drafts store of the same mode, and the suppressions from the same place
an analysis reads them. The tests drive the standalone path; cluster mode
shares the code but has no end-to-end evidence test yet. A replay job can be
bound only in standalone mode, where replay jobs exist.

Not part of this work, and not to be inferred from it:

- Signing (DSSE envelopes, in-toto statements, protected signer references,
  key rotation) and verifying a signature against a trust root (slice 21,
  #240, #242). `ggctl evidence verify` checks integrity only.
- Packages about an inline candidate and server-side storage for later download.
