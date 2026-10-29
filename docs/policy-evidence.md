# Policy evidence packages

A policy evidence package is a reproducible, aggregate report about one
policy publication: one version of the policy history.
`POST /v1{ADMIN_PREFIX}/policy/evidence` assembles it on the server from what
the history recorded about that version and what this gateway build
recomputes from it, and returns it as canonical JSON (issue #243, slice 20;
[ADR-0004](adr/0004-policy-studio-authority-and-evidence.md)).

A package can cover:

- **Document digests**: the published document's policy ETag and, for a policy
  v1 document, its ADR-0004 semantic digest; the same for the history version
  before it.
- **The approval as recorded**: when the history recorded the publication, by
  which operation, and what that operation was bound to.
- **Validation**: the publication revalidated by this build with the checks
  `POST /policy/validate` applies, including the cross-resource checks and the
  resource snapshot they read.
- **Tests**: a [policy test suite](policy-tests.md) you send, run against the
  published document.
- **Simulation**: [synthetic cases](policy-simulation.md) you send, decided
  under the published document and the version it replaced.
- **Historical impact**: the result of a finished [replay job](policy-replay.md#replay-jobs)
  of yours whose candidate is the published document, with its comparison
  against the policy the job was pinned to and against what was recorded.

## What a package is, and what it is not

A package is evidence in the bounded sense ADR-0004 defines: a report over
pinned inputs, the limits applied and the limitations that remain. It is not
proof that the policy is safe, that its history or audit sources were
complete or untampered, or of compliance with any framework. Every package
says so in its own report:

> This package is unsigned. It reports what this gateway's policy history
> recorded about one publication and what this gateway build recomputed from
> it, under the stated versions and bounds. It does not prove that the policy
> is safe, that the history or audit sources it was read from were complete or
> untampered, or compliance with any framework.

Every result in a package is computed by the server. A request names the
publication and supplies inputs (a suite, cases, a replay job id); it cannot
supply a digest, a result or a document. Generating a package writes nothing:
it is not stored, does not activate or change any policy, and leaves one
`policy.evidence_exported` audit event.

Packages are **unsigned**. Signing them with protected keys and verifying them
offline is a later slice (#243 slice 21), which needs protected signer
references (#240) and offline verification in `ggctl` (#242). Until then a
package is integrity-checkable (its manifest binds its report by digest) but
says nothing about who produced it.

## Requesting a package

```sh
curl --fail-with-body -sS -X POST "$GATEWAY/v1/admin/policy/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @evidence-request.json \
  -D headers.txt -o policy-evidence.json
grep -qi '^x-greengateway-policy-evidence-completeness: complete' headers.txt
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
  "replay_job_id": "rpl_..."
}
```

- `schema_version` must be exactly `policy-evidence-request.v1`.
- `publication.version` (required) is the policy history version, as
  `GET /v1{ADMIN_PREFIX}/policy/history` lists it: an integer from 1 to
  2^53 - 1. `publication.etag` (optional) pins the document you reviewed: a
  stored document with a different policy ETag is `409`.
- `suite` (optional) is a complete `policy-tests.v1` suite, parsed exactly as
  `POST /policy/tests/runs` parses one. Its diagnostics are located under
  `/suite`.
- `simulation` (optional) holds `cases` (1 to 256 `policy-simulation.v1`
  cases), `projections` (`as_authored` and `enforce_all_shadow`; default
  `["as_authored"]`) and `trace` (`terminal`, the default, or `matched`). A
  `full` trace is not part of an evidence package.
- `replay_job_id` (optional) names a replay job you started that has finished
  with a result (`completed` or `completed_incomplete`).

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
the permissions of its own endpoint, checked before any history read or
evaluation, so nothing can be learned through a package that could not be read
directly:

| Section | Additional permissions |
| --- | --- |
| `suite` or `simulation` | `admin:policy:simulate` |
| `replay_job_id` | `admin:policy:simulate` and `admin:audit:read` |

A replay job is served only to the principal that started it, as on the replay
routes. The admin capabilities endpoint lists `admin:policy:evidence:read`
when it is held. The route-level RBAC rule for
`POST /v1/admin/policy/evidence` should grant `admin:policy:evidence:read`
ahead of the catch-all `admin:policy:write` rule for unsafe policy methods,
because generating a package writes nothing; see `dev/policy.json`.

## The package

The response body is the package's [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
(JCS) bytes, served as `application/vnd.greengateway.policy-evidence+json`
with `Cache-Control: no-store` and
`Content-Disposition: attachment; filename="policy-evidence.json"`. Two headers
repeat what a pipeline usually gates on:
`X-GreenGateway-Policy-Evidence-Completeness` (`complete` or `incomplete`) and
`X-GreenGateway-Policy-Evidence-Digest` (the report digest). The package
schema is published as
[`docs/schemas/policy-evidence.v1.schema.json`](schemas/policy-evidence.v1.schema.json).

### Envelope and manifest

```json
{
  "schema_version": "policy-evidence.v1",
  "generated_at": "2026-10-28T12:00:00Z",
  "manifest": [{
    "name": "report",
    "media_type": "application/vnd.greengateway.policy-evidence-report+json",
    "schema_version": "policy-evidence-report.v1",
    "digest": "sha256:...",
    "size": 18234
  }],
  "report": { }
}
```

`digest` is the ADR-0004 semantic digest of `report`: SHA-256 over the frame
`"GGDIGEST" 0x00`, then `semantic`, the media type, the schema version and the
report's JCS bytes, each preceded by its length as an unsigned 64-bit
big-endian integer. `size` is the length of the report's JCS bytes. Everything
a reader relies on is in the report; the envelope adds only `generated_at`,
which is outside the digest.

The report is deterministic: the same publication, suite, cases and replay
job, judged by the same gateway build under the same deployment checks,
produce a byte-identical report and digest, on any platform. Two exports of
the same inputs differ only in `generated_at`.

### The report

| Member | What it holds |
| --- | --- |
| `schema_version`, `redaction_profile` | `policy-evidence-report.v1` and `policy-evidence-aggregate.v1` |
| `gateway_version`, `evaluator` | The build and the evaluator semantics and context versions that judged the inputs |
| `request_digest` | The request's semantic digest |
| `publication` | `version`; `policy` (`schema_version`, `etag`, `semantic_digest` or `null`); `predecessor` (the history version immediately before it, with the same identity, or `null`); and `predecessor_check` |
| `approval` | The approval as recorded (below) |
| `validation` | `basis` (`revalidated_by_this_build`), `valid`, up to 100 `diagnostics` in the form `POST /policy/validate` reports them, `diagnostics_truncated`, and the `resource_snapshot` the cross-resource checks read |
| `tests` | `{"included": false}`, or `included` and `results`: the `policy-test-results.v1` report, whose `policy.source` is `publication` |
| `simulation` | `{"included": false}`, or `included`, `mode` (`synthetic`), `trace`, `projections`, `base` (the predecessor's version and ETag, or `null`), `candidate` (the publication's), `not_evaluated`, `summary` and per-case `cases` as a simulation reports them |
| `replay` | `{"included": false}`, or `included`, `mode` (`historical_replay`), `state`, the job's `request_digest`, `evaluator`, `base` and `candidate` ETags, `projections`, `window`, `cutoff`, `limits`, `not_replayed`, `predecessor_check`, `result_digest` and the `policy-replay-results.v1` `result` |
| `completeness`, `limitations` | `complete` exactly when `limitations` is empty |
| `trust` | `signed` (`false`) and the fixed `statement` quoted above |

**Document digests.** The history keeps the normalized document, not the bytes
it was submitted as, so a package carries no source digest. A policy v1
document's semantic digest is the one `POST /policy/validate` reports for the
same document. A 0.x document has no normative normalization, so it has no
semantic digest; it is bound by its policy ETag alone, which is a
compatibility mechanism, and the report says so with
`policy_semantic_digest_unavailable`.

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
version recorded after the history was configured has no predecessor.

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
policy history.

**Validation.** Revalidation is a judgement by this build and this deployment's
checks at generation time; the history does not record what validation said at
publication time. It runs the document's own checks, the deployment checks
(proxy dispatch, the document format this deployment commits) and the
cross-resource checks a publication runs, reading the resources current now:
references another resource contradicts, risks, and whether the publication
leaves `admin:policy:write` reachable. Those checks judge the publication as
the replacement of its predecessor (of itself when the history holds nothing
before it), and without the publisher-specific lockout check, because the
caller asking for evidence is not the one who published and a package must
not depend on who asks for it. `resource_snapshot` is the snapshot those
checks read, with the digest `POST /policy/validate` reports for the same
resources; a snapshot that could not read every resource adds a
`resource_unavailable` warning, which blocks complete evidence. A suite or cases cannot be evaluated against a publication
that now fails a check they depend on: the request is refused with `422
policy_evidence_publication_not_evaluable` and its diagnostics. Without either,
the package is still produced and reports `valid: false`.

**Simulation.** The cases are decided under the publication and, as the base,
under its predecessor. A predecessor that no longer compiles under this build
leaves the publication judged alone (`base: null`,
`simulation_base_not_evaluable`).

**Historical impact.** A replay job's result describes the candidate it
replayed, so a job is bound only when its candidate's policy ETag is the
publication's (`409 policy_evidence_replay_binding_stale` otherwise). Its
impact comparison is against the active policy the job was pinned to, so
`predecessor_check` says whether that base is the publication's predecessor
(`matches_predecessor`): a job started before publication, with the draft's
document as an inline candidate, compares the publication with what it
replaced. A job started afterwards compares the published policy with itself
and with the record (`differs_from_predecessor`); it is still reported, and
the package names `replay_base_not_predecessor`. The section repeats the job's
own bindings, projections, window, cutoff and limits and its counts-only
result, including the [impact comparison](policy-replay.md#impact-comparison)
and the bounded statement it makes, exactly as the job produced them. It
leaves out the job id, and `result_digest` ties the section to the job's
`policy.replay_completed` audit record. The package adds no statement of its
own about newly allowed decisions.

### Completeness and limitation codes

A report is `complete` only when every section is present and complete and
nothing below applies. An incomplete report never satisfies an
evidence-complete gate. `limitations` lists, sorted:

| Code | Meaning |
| --- | --- |
| `policy_semantic_digest_unavailable` | The published document is 0.x, which has no normative normalization; it is bound by its ETag alone |
| `predecessor_not_in_history` | No earlier version is in the history, so what the publication replaced is unknown and a simulation has no base |
| `predecessor_differs_from_recorded_base` | The history version before the publication is not the base the publication recorded it was made against |
| `validation_blocks_evidence` | Revalidation reported a diagnostic whose `blocks.evidence` is `true`, such as a 0.x document's missing element ids |
| `validation_diagnostics_truncated` | Revalidation reported more than 100 diagnostics |
| `tests_not_included` | The request carried no suite |
| `tests_incomplete` | The suite's status is `incomplete` or `error`: a case was undecided or refused. A `failed` suite is complete evidence of the failure |
| `simulation_not_included` | The request carried no cases |
| `simulation_base_not_evaluable` | The predecessor no longer compiles under this build, so the cases were decided under the publication alone |
| `replay_not_included` | The request named no replay job |
| `replay_incomplete` | The job is `completed_incomplete`: its window was truncated, passed its deadline, changed under it, or held no replayable record |
| `replay_base_not_predecessor` | The job compared the publication with a policy other than its predecessor, so its impact is not the publication's own |

### Verifying a package

A reader can check the manifest without trusting the transport that delivered
the package:

```python
import hashlib, json, struct

package = json.load(open("policy-evidence.json", encoding="utf-8"))
entry = package["manifest"][0]
report = package["report"]
# A sketch: Python's encoder agrees with RFC 8785 for ASCII member names,
# integers and short decimal fractions, which is what a report holds. Use a
# full RFC 8785 implementation where it matters.
payload = json.dumps(report, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
frame = b"GGDIGEST\x00"
for part in (b"semantic", entry["media_type"].encode(),
             entry["schema_version"].encode(), payload):
    frame += struct.pack(">Q", len(part)) + part
assert len(payload) == entry["size"]
assert "sha256:" + hashlib.sha256(frame).hexdigest() == entry["digest"]
```

Python sorts keys by code point, which equals RFC 8785's UTF-16 order for
ASCII member names, and spells some numbers (such as `1e-07`) differently from
RFC 8785, so treat a mismatch from this sketch as a reason to check with a
conforming encoder. A matching digest shows that the report is the one the
manifest names. Without a signature it does not show who produced it.

## Status codes

| Status | Reason | When |
| --- | --- | --- |
| `200` | | The package |
| `400` | `policy_evidence_request_invalid` | The body is not JSON, or repeats a member name |
| `401` / `403` | | Not authenticated, or a permission above is missing |
| `404` | `policy_evidence_publication_not_found` | The history has no such version |
| `404` | `policy_evidence_replay_job_not_found` | No replay job of yours has that id |
| `404` | | No policy history is configured |
| `408` | `policy_evidence_request_timeout` | The body did not arrive within five seconds |
| `409` | `policy_evidence_publication_mismatch` | `publication.etag` is not the stored document's ETag |
| `409` | `policy_evidence_replay_job_unfinished` | The job holds no result: pending, failed, cancelled or expired (`state` names which) |
| `409` | `policy_evidence_replay_binding_stale` | The job's candidate is not the published document |
| `413` | | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower |
| `422` | `policy_evidence_invalid` | The request is invalid; `diagnostics` say why |
| `422` | `policy_evidence_publication_not_evaluable` | The publication fails a check the requested suite or cases depend on, or no longer compiles |
| `422` | `policy_evidence_case_refused` | The evaluator refused a simulated case |
| `422` | `policy_evidence_too_large` | The package would exceed 4 MiB; it is refused whole, never cut short |
| `429` | `policy_evidence_busy` | Four packages are being assembled on this replica, or one of yours is |
| `503` | `policy_evidence_history_unavailable` | The history could not be read |
| `503` | `policy_evidence_deadline_exceeded` | The suite and cases were not decided within five seconds |
| `503` | `policy_evidence_audit_unavailable` | The export could not be recorded; no package was released |
| `503` | `policy_evidence_replay_unsupported_in_cluster` | A replay job was named in cluster mode, which has none |

## Privacy

A report follows the `policy-evidence-aggregate.v1` redaction profile: digests,
ETags, versions, stable codes, counts, timestamps of history records and of the
replay window, and case, rule and route identifiers. It carries no policy
content, no fixture value (paths, subjects, roles of hypothetical callers), no
audit record or replay sample, no actor identity, no request id, source
address or user agent, and no free-text error detail. Validation diagnostics
are the stable code, JSON Pointer, element id and fixed message and
remediation `POST /policy/validate` returns, never its free-text detail. The
test and simulation sections are the same value-free results their own
endpoints return.

A package is not self-contained: it does not embed the suite, the cases, the
policy documents or the replayed records, so it cannot be replayed without the
authorities it was read from, and it carries nothing those authorities would
not show an authorized reader.

## Audit

A package is released only once its `policy.evidence_exported` audit event is
accepted by the audit authority; under `AUDIT_DURABILITY=required` an event
that cannot be recorded withholds the package (`503
policy_evidence_audit_unavailable`). The event carries the acting principal and
the request envelope, `publication_version`, `policy_etag`,
`policy_semantic_digest`, `request_digest`, `report_digest`, `completeness`,
`limitations`, whether tests and cases were included, the suite status, the
replay `result_digest` and the package size. It never carries a case, a
fixture value, policy content or the package itself. Refused requests are not
recorded as exports.

## Limits and what comes later

Generation is synchronous: a body within `MAX_BODY_SIZE` or 2 MiB, whichever
is lower, that arrives within five seconds; at most 512 test cases and 256
simulation cases; a five-second deadline on deciding both, compilation
included; a 4 MiB package; and at most four packages being assembled at once
per replica and one per caller, each on a blocking thread. Work is admitted
only once the body is in hand, and its slot is held until the blocking work
ends, even when the client disconnects first. A package reads the history
from whichever authority holds it: the SQLite history beside the policy file
in standalone mode, the immutable PostgreSQL policy documents in cluster mode.
The tests drive the standalone path; cluster mode shares the code but has no
end-to-end evidence test yet. A replay job can be bound only in standalone
mode, where replay jobs exist.

Not part of this slice, and not to be inferred from it:

- Signing (DSSE envelopes, in-toto statements, protected signer references,
  key rotation) and offline verification with `ggctl` (slice 21, #240, #242).
- A derived Markdown rendering of the report.
- Analyzer findings (slice 15).
- Packages about a draft or an arbitrary candidate rather than a publication,
  stored or downloadable-later artifacts, and an Evidence tab in the admin UI.
