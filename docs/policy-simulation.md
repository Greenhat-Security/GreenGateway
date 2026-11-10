# Policy simulation

A policy simulation asks what the policy would decide for a batch of
hypothetical requests, tool questions, rate sequences and outbound
destinations, before anything changes.
`POST /v1{ADMIN_PREFIX}/policy/simulations` evaluates the cases against the
active policy and a candidate -- the active policy itself, position-aware edits
over it, a complete document you send, one of your server-side drafts, or a
version of the policy history -- and explains each decision at the trace level
you ask for, as written and with every shadow projected as enforced (issue
#243, slice 10; tool and rate stage traces, isolated rate sequences and egress
cases in slice 12).

A simulation is the exploratory sibling of a [policy test suite](policy-tests.md):
its cases are `policy-tests.v1` cases without an `expect`, parsed by the same
code, and it reports what the policy decides instead of whether that matches an
expectation. A simulated case and a test case with the same facts are the same
question.

Every case is decided by the compiled policy evaluator the gateway uses for
live traffic (`gateway/src/policy_eval`), through the same context builders the
test runner uses. The HTTP, tool and rate stage traces are reported by that
evaluator as it runs
(see [the evaluation kernel](architecture/policy-evaluation-kernel.md#stage-trace-and-synthetic-simulation-243-slice-10)),
so a trace can only describe the decision production makes.

## What a simulation means, and what it does not

A result is the policy's answer for the facts a case states. It is not a
prediction that a real request with those facts would succeed: authentication,
CSRF, request admission and schema validation, tool registry state, request
rendering, live rate capacity, tool leases, credentials, an upstream's egress,
DNS, transport and the upstream are not part of a policy decision and are not
evaluated. Every result lists them in `not_evaluated`. An egress case
evaluates the static egress lane for the destination it states, and nothing
else; an isolated rate sequence describes a fresh synthetic bucket, never a
live caller's allowance.

Three answers are always reported separately, so a shadowed deny is never read
as an allow:

| Member | Values | Meaning |
| --- | --- | --- |
| `logical` | `allow`, `deny`, `indeterminate` | What the policy decided. A shadow rule's would-deny is `deny`. |
| `enforcement` | `enforced`, `shadowed`, `not_applicable` | Whether a denial blocks or is only observed. `not_applicable` for an allow and for an undecided case. |
| `effective_action` | `would_forward`, `would_block`, `unknown` | What the request would meet at this stage. A shadowed deny is `would_forward`; an undecided case is `unknown`, never a forward. |

A simulation changes nothing. It does not write, activate or rewrite a policy
(a candidate is validated, compiled for the run and discarded), emits no
data-plane authorization event or metric, reads or
charges no rate bucket, acquires no tool permit, resolves no name and contacts
no upstream. The simulation request itself is admitted like any admin `POST`:
it is counted, passes the generic write limiter and gets the access record
every HTTP request gets. A completed run emits one
`policy.simulation_run` audit event. A test drives cases that, live, would
charge a one-request rate bucket, record a would-deny, admit a tool, resolve
the upstream's name and dispatch to a reachable upstream -- isolated sequences
that exhaust their synthetic copy of that bucket and egress cases for the
upstream's own address among them -- proves none of that happened, and checks
the audit, resolver, bucket and upstream against the live path afterwards
(`admin_policy_simulations_tests`).

### Control-plane metrics

After both permission checks, the gateway counts each simulation response in
`greengateway_policy_simulations_total`. Its only label, `outcome`, is
`completed` for a returned report, `busy` for a concurrency refusal,
`conflict` for HTTP 409 or 412, `refused` for other client errors, and
`failed` for server errors. A completed report can contain indeterminate
decisions. Requests dropped before the handler produces a response do not
contribute a sample.

`greengateway_policy_simulation_duration_seconds` measures time from
authorization until the response is ready, including reading the request,
loading the candidate and rendering the result. Its histogram has finite
buckets from 10 ms to 5 s. `greengateway_policy_simulation_traces_truncated_total`
counts returned reports that reached the stage-trace bound. Both metrics
use no application labels. Individual synthetic cases produce no series.

## The request

A request is a `policy-simulation.v1` document. The version is dispatched
exactly, every object refuses unknown members, and a member named like a
credential (`token`, `authorization`, `cookie` and similar) is refused with
`forbidden_field`. A case may state the request facts a rule condition
reads in an optional `facts` member, exactly as a
[policy test case](policy-tests.md#request-facts) does, a tool invocation's
`arguments` included; a fact a condition reads that the case omits is
`indeterminate`, the simulator never reads the clock, and no stated value,
an argument least of all, appears in a result or trace. The published schema is
[`docs/schemas/policy-simulation.v1.schema.json`](schemas/policy-simulation.v1.schema.json);
the gateway's parser is authoritative and additionally checks path, host and
origin syntax, identity bounds, unique case ids and byte lengths.

```json
{
  "schema_version": "policy-simulation.v1",
  "description": "Lock the orders API down",
  "base_etag": "\"sha256:...\"",
  "candidate": {
    "source": "edits",
    "edits": [
      {
        "op": "insert", "section": "rules", "position": 0,
        "value": { "id": "orders-lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" }
      },
      { "op": "move", "section": "rules", "from": 3, "to": 1, "expect_id": "watch-exports" }
    ]
  },
  "trace": "matched",
  "projections": ["as_authored", "enforce_all_shadow"],
  "cases": [
    {
      "id": "reader-reads-orders",
      "kind": "http",
      "request": { "method": "GET", "path": "/orders/42" },
      "principal": { "subject": "synthetic-reader", "roles": ["orders-reader"], "auth_method": "bearer_token" }
    },
    {
      "id": "readers-orders-rate",
      "kind": "rate",
      "request": { "method": "GET", "path": "/orders/42" },
      "principal": { "subject": "synthetic-reader", "roles": ["orders-reader"], "auth_method": "bearer_token" }
    }
  ]
}
```

| Member | Meaning |
| --- | --- |
| `schema_version` | Exactly `policy-simulation.v1`. |
| `description` | Optional, at most 1024 bytes. Never repeated in results or audit. |
| `base_etag` | Required: the ETag of the active policy the request was written against, as `GET /v1{ADMIN_PREFIX}/policy` returns it. A different active ETag is `412` and nothing runs. Every position in an edit, and every comparison with the base, therefore means what the author read. |
| `candidate` | Required: what to simulate; see below. |
| `trace` | `terminal` (the default), `matched` or `full`. |
| `projections` | One or both of `as_authored` (the default) and `enforce_all_shadow`, each at most once. |
| `cases` | 1 to 256 cases, with the members of a [`policy-tests.v1` case](policy-tests.md#case-kinds) except `expect`, which is refused. Ids are unique. |

### Candidates

- `{"source": "active"}` simulates the pinned base itself. Nothing is compared
  with a base.
- `{"source": "edits", "edits": [...]}` applies 1 to 64 explicit edits to the
  pinned base, in order, each to the result of the ones before it.
- `{"source": "inline", "policy": {...}}` simulates a complete policy document
  submitted with the request.
- `{"source": "draft", "draft_id": "pd_...", "draft_etag": "\"sha256:...\""}`
  simulates one of your server-side drafts as it is at that draft ETag, and
  `{"source": "revision", "version": 7}` a version of the policy history; see
  [Drafts and history versions](#drafts-and-history-versions).

An edited or inline candidate is validated exactly as a policy write
validates one -- the 0.x or v1 rules its `schema_version` selects, and the
proxy-dispatch checks -- and is never stored. An inline candidate is read
from the exact bytes of `candidate.policy`, by the same parser
`PUT /v1{ADMIN_PREFIX}/policy` reads its body with, so a v1 document is held
to the rules only its bytes can show: the 1 MiB bound, and no number spelled
through serde_json's private number tag (`{"$serde_json::private::Number":
"..."}`), which a JSON value would silently read as a number. (A repeated
member anywhere in the request is already `400
policy_simulation_request_invalid`.) An edited candidate has no bytes of its
own and is validated as the document its edits produce. A candidate whose
document format this deployment's replicas do not serve is refused as
`POST /v1{ADMIN_PREFIX}/policy/validate` and a policy test run refuse it;
cluster mode serves 0.x and policy v1 alike, so a v1 candidate is simulated
there too, and whether every live replica reads it is asked only when a
document is committed. A candidate that does not validate is `422
policy_candidate_invalid`.

### Drafts and history versions

A stored candidate is read when the request is served, never written, and
reported by its identity. Policy test runs, policy analyses and replay jobs
read one exactly as described here.

- **A draft** (`draft_id`, at most 64 bytes, and `draft_etag`, at most 256) is
  read through the drafts store under the drafts API's own owner scope. It
  must be yours: another principal's draft, including the same subject's from
  another issuer, is `404 policy_draft_not_found`, exactly as one that does not
  exist. It must be unexpired (`410 policy_draft_expired`) and still at
  `draft_etag`, the strong ETag `GET /v1{ADMIN_PREFIX}/policy/drafts/{id}`
  returned (`412 policy_draft_stale` once it has changed). And it must be
  pinned to `base_etag`: a draft edited from another policy is `409
  policy_draft_base_stale`, with the draft's `base_etag` and the request's as
  `policy_etag`. Nothing is rebased; to compare the draft with a newer base,
  re-pin it with `PATCH` first. A published draft is frozen, so its ETag keeps
  naming one document, and it can still be read this way. Reading a draft
  never writes it: its revision, ETag and expiry stay as they were, and no
  `policy.draft_changed` is emitted. Its candidate is validated again under
  this build and deployment, as an inline candidate is (`422
  policy_candidate_invalid`). A deployment whose drafts store is unavailable
  answers `503 policy_drafts_unavailable`.
- **A history version** (`version`, a positive integer) is read from the
  history authority -- the SQLite policy history in standalone mode, the
  immutable `policy_documents` rows in cluster mode -- as
  `GET /v1{ADMIN_PREFIX}/policy/history` lists it, and validated again under
  this build and deployment, as a write of it would be today. A version they
  would not accept, a document this build cannot read included, is `422
  policy_revision_incompatible` with the `version` and the validator's
  `errors`; it is never evaluated as something other than what it was. A
  version the history does not hold is `404 policy_revision_not_found`, a
  history that cannot be read `503 policy_history_unavailable`, and a
  deployment with no history `404`. Nothing is reactivated.

Naming a stored candidate needs no permission beyond the request's own. Every
endpoint that takes one already requires `admin:policy:read`, which is what
reading a draft or a history version directly needs, and checks it before
anything is read, so a caller without it learns nothing about whether a draft
exists. Using your draft needs no `admin:policy:write`.

### Position-aware edits

An edit always says where it lands; there is no append in an unstated
position.

| `op` | Members | Effect |
| --- | --- | --- |
| `insert` | `section`, `position`, `value` | The complete element `value` takes `position`; the elements from it on move down one. `position` may be the section's length, which appends, and must be stated. |
| `replace` | `section`, `position`, `value`, optional `expect_id` | The element at `position` becomes `value`. |
| `move` | `section`, `from`, `to`, optional `expect_id` | The element at `from` is taken out and ends at `to`, an existing position. |
| `delete` | `section`, `position`, optional `expect_id` | The element at `position` is removed. |
| `set` | `field`, `value` | `default_action` (`allow` or `deny`) or `enforcement_mode` (`enforce` or `shadow`). |

`section` is `rules`, `routes` or `rate_limits`; a section the base omits is
empty. `expect_id` names the stable `id` the element at the position must
carry, or the edit is refused with `edit_target_mismatch`: policy v1 gives
every rule, route and rate override an id, while a 0.x document gives one only
to the rules that set it and never to a route or override, so naming one of
those can only mismatch. An edit that cannot apply refuses the whole candidate
with `422 policy_simulation_invalid` and the edit's JSON Pointer; nothing is
half-applied. Whether the edited elements are valid is the policy validator's
answer, as for any write.

### Projections

`as_authored` evaluates the policy as written. `enforce_all_shadow` evaluates
an in-memory copy in which every shadow is enforcing: each direct `shadow` rule
is a `deny`, the global `enforcement_mode` is `enforce`, and every route's own
`shadow` override is `enforce` (a route keeps its override, now enforcing, so a
trace still says whether its mode was its own). Order, ids and every other
member are untouched, so a position names the same element in both. The copy
is compiled for the run and discarded; nothing is rewritten.

The projection answers "what would block if I promoted every shadow". It never
previews an intended allow: a shadow rule's `allow` counterpart is not
something it can infer.

### Trace levels

| Level | Adds |
| --- | --- |
| `terminal` | The outcome only: `logical`, `enforcement`, `effective_action`, stable `reason`, `complete` and any stable `limitation`. A rate case gives the selected override's position, and a sequence's lane and step outcomes. |
| `matched` | The element that decided (`matched`): a rule by position, action and `id`; a route by position, `id` (v1), required `permission` and `permission_granted`. For HTTP, the shadow rule that was only `observation` beside a host-bound route's decision. A rate case adds the override's `id` (v1), `requests_per_second` and `burst`, and a sequence the limits its bucket was built from. An egress case adds the position in its hypothetical address list of the address that would be pinned (`pinned_address`) or that was refused (`refused_address`) -- never the address. |
| `full` | One step per evaluator stage of the case's lane, in order, each `matched`, `no_match`, `not_applicable`, `skipped` (after the decision) or `unknown` (after an undecided answer). HTTP: `facts`, `request_host`, `direct_rules`, `upstream_host_binding`, `routes`, `default`, with the element, permission check and enforcement mode where they apply. A tool operation: `facts`, `tool_entry` (with `enabled`), `tool_identity`, `tool_rules` (with the matched rule and its action). A rendered tool request: `facts`, `rendered_http_rules`. A rate case: `facts`, `anonymous_bypass` (`matched` when the live bypass for a request without a principal applied), `rate_overrides` (with the matched override by position and `id`). Egress cases have no stages. |

A full trace is bounded: a simulation returns at most 4096 stage steps in
total, across every lane. Past that, an evaluation reports
`stages_truncated: true` in place of its steps and the result's
`trace.stages_truncated` is `true`; its decision is still reported in full.
An evaluation's steps are listed whole or not at all. An authored id or permission longer than 128 bytes is
reported by position only, with `id_omitted` or `permission_omitted`.

## Running a simulation

```http
POST /v1/admin/policy/simulations
Content-Type: application/json

{ "schema_version": "policy-simulation.v1", ... }
```

- The caller needs both `admin:policy:read` and `admin:policy:simulate`, the
  same pair a policy test run needs; either alone is `403`. Both are checked
  before the body is read.
- The base is the policy file's current snapshot in standalone mode, or the
  authoritative active document, at the revision it was read, in cluster mode.
- The policy's own routes are evaluated before the handler, as for every admin
  route. A policy whose routes gate the admin API needs a route for
  `POST /v1{ADMIN_PREFIX}/policy/simulations` ahead of a catch-all for unsafe
  policy methods; `dev/policy.json` carries one that grants
  `admin:policy:simulate`.

| Status | `reason` | Meaning |
| --- | --- | --- |
| `200` | -- | The simulation completed. `Cache-Control: no-store`. |
| `400` | `policy_simulation_request_invalid` | The body is not JSON or repeats a member name anywhere. |
| `401`, `403` | -- | Not authenticated, or missing either permission. |
| `404` | -- | No policy is configured, or a `revision` candidate names a deployment with no policy history. |
| `404` | `policy_draft_not_found` | A `draft` candidate names no draft of yours. |
| `404` | `policy_revision_not_found` | A `revision` candidate names a version the history does not hold. |
| `409` | `policy_draft_base_stale` | A `draft` candidate is pinned to another base than `base_etag`. |
| `410` | `policy_draft_expired` | A `draft` candidate has expired. |
| `412` | `policy_simulation_base_stale` | `base_etag` is not the active policy's ETag, which `current_etag` carries. Nothing ran; no rebase is attempted. Checked before a stored candidate is read. |
| `412` | `policy_draft_stale` | A `draft` candidate's `draft_etag` is no longer the draft's ETag. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_simulation_invalid` | The request, or an edit applied to the base, is invalid. At most 64 `diagnostics` (`code`, JSON `pointer`, fixed `message`) and `diagnostics_truncated`. Diagnostics never repeat an input value. |
| `422` | `policy_candidate_invalid` | The candidate policy does not validate; `errors` are the policy validator's messages. |
| `422` | `policy_revision_incompatible` | A `revision` candidate is not a policy this build and deployment accept now; `version` and `errors` say which and why. |
| `422` | `policy_simulation_case_refused` | The evaluator refused a case's facts; `pointer` and `code` name it. |
| `422` | `policy_simulation_result_too_large` | The result would exceed 8 MiB. Nothing is cut short; simulate fewer cases or a lower trace level. |
| `429` | `policy_simulation_busy` | Four simulations are already evaluating on this replica, or this caller already has one running. Nothing was queued. |
| `500` | -- | An evaluator invariant failed or a policy did not compile. No partial result. |
| `503` | -- | Cluster mode could not read the active policy, or (`policy_simulation_deadline_exceeded`) the evaluation did not finish within two seconds. No partial result. |
| `503` | `policy_drafts_unavailable`, `policy_history_unavailable` | The drafts store or the policy history a stored candidate names could not be read. |

Simulation does not need the audit query store: it reads no retained traffic.

Diagnostic codes are those of [policy test suites](policy-tests.md#running-a-suite),
plus `empty_simulation`, `empty_edits`, `too_many_edits`,
`duplicate_projection`, `position_out_of_range` and `edit_target_mismatch`.

## The result

```json
{
  "schema_version": "policy-simulation-results.v1",
  "mode": "synthetic",
  "request_digest": "sha256:...",
  "evaluator": {
    "http_semantics_version": "gg-http-alias-v1",
    "http_context_version": 3,
    "tool_semantics_version": "gg-tool-policy-v1",
    "tool_context_version": 1,
    "egress_semantics_version": "gg-static-egress-v1",
    "egress_context_version": 1,
    "gateway_version": "1.0.1"
  },
  "synthetic_resources": {
    "egress_controls_digest": "sha256:...",
    "global_rate_lanes": "configured"
  },
  "base": { "source": "active", "etag": "\"sha256:...\"" },
  "candidate": { "source": "edits", "etag": "\"sha256:...\"", "edits": 2 },
  "trace": { "level": "matched", "max_stages": 4096, "stages_truncated": false },
  "projections": ["as_authored", "enforce_all_shadow"],
  "not_evaluated": ["authentication", "csrf", "..."],
  "summary": {
    "cases": 2,
    "projections": {
      "as_authored": {
        "would_forward": 0, "would_block": 1, "unknown": 0, "shadowed": 0,
        "rate_override": 1, "no_rate_override": 0, "rate_unknown": 0,
        "egress_allow": 0, "egress_deny": 0, "egress_unknown": 0,
        "changed_from_base": 1
      },
      "enforce_all_shadow": { "...": 0 }
    },
    "projection_changed": 0
  },
  "cases": [
    {
      "id": "reader-reads-orders",
      "pointer": "/cases/0",
      "kind": "http",
      "results": [
        {
          "projection": "as_authored",
          "base": {
            "lane": "http", "logical": "allow", "enforcement": "not_applicable",
            "effective_action": "would_forward", "reason": "matched_rule", "complete": true,
            "matched": { "kind": "route", "position": 0, "permission": "orders:read", "permission_granted": true },
            "observation": null
          },
          "changed": true,
          "candidate": {
            "lane": "http", "logical": "deny", "enforcement": "enforced",
            "effective_action": "would_block", "reason": "matched_rule", "complete": true,
            "matched": { "kind": "rule", "position": 0, "id": "orders-lockdown", "action": "deny" },
            "observation": null
          }
        }
      ],
      "projection_changed": false
    }
  ]
}
```

- `request_digest` is the ADR-0004 source digest of the exact request bytes,
  framed with the media type `application/vnd.greengateway.policy-simulation+json`
  and version `policy-simulation.v1`. The audit event carries the same value.
- `base.etag` is the pinned active ETag (cluster mode adds
  `security_revision`); `candidate.etag` is the ETag the candidate would have
  once written -- the digest that identifies it -- and equals the base's for
  the `active` source. A `draft` candidate adds the `draft_id` and the
  `draft_revision` it was read at, and a `revision` candidate the `version`:
  `{"source": "draft", "etag": "\"sha256:...\"", "draft_id": "pd_...",
  "draft_revision": 3}`.
- Each case has one entry per projection. When the candidate is not the base,
  each entry also has the `base` answer under the same projection and
  `changed`, which compares outcomes -- logical decision, enforcement,
  effective action and reason, or for a rate case the selected limits -- not
  positions, which an insert shifts without changing anything.
- With both projections, `projection_changed` says whether promoting every
  shadow changes the candidate's answer for the case.
- `summary` counts, per projection, the candidate's effective actions for
  HTTP and tool cases, the shadowed denials, the rate selections, the egress
  verdicts and the cases that changed from the base.
- `synthetic_resources` names what egress cases and rate sequences were
  decided by: the digest of the egress controls (never a host, port or range)
  and whether the global rate lanes' configured limits were available.

A result never contains a fixture value -- no path, host, subject, issuer,
role, origin or tool name a case supplied -- only case ids and pointers, stable
codes, element positions and, for a caller who already holds
`admin:policy:read`, the matched element's id and a route's permission. It has
no timestamp or duration.

A rate case reports which `rate_limits` override the live rate stage would
select (`selected`: `override`, `no_override` or `indeterminate`) and its
configured limits. It does not model live bucket capacity, and it never reads a
production bucket.

### Isolated rate sequences

A rate case may add `"sequence": { "at_ms": [0, 0, 250, 1000] }`: one to 64
virtual instants, in milliseconds since the sequence's origin (at most one
day), never decreasing. Each instant is one request, checked in order against
a fresh bucket built for the sequence alone from the selected lane's
configured rate and burst -- the selected override's own limits, or, when no
override governs, the global `read` lane's (for `GET` and `HEAD`) or `write`
lane's from `RATE_LIMIT_READ_*` / `RATE_LIMIT_WRITE_*`, as the live limiter
splits them. The bucket starts empty: no bucket exists until the first step,
which meets a full burst, exactly as a key the live limiter has never seen
does. Each step takes the live limiter's own token arithmetic.

```json
"sequence": {
  "lane": "policy_override", "key_class": "principal",
  "bucket": "isolated_empty", "clock": "virtual",
  "requests_per_second": 2.5, "burst": 5,
  "steps": ["allowed", "allowed", "allowed", "allowed", "allowed", "limited", "allowed"],
  "allowed": 6, "limited": 1, "complete": true
}
```

`lane` is `policy_override`, `global_read` or `global_write`; `key_class` is
the class of key the live lane buckets by (`principal` or `client_ip`). The
limits appear from the `matched` level. A sequence never reads, creates,
charges or evicts a production bucket, the shared PostgreSQL rate state, a
bucket gauge or any metric, so it says what a key with no history would meet,
never what any live caller has left. It models one bucket only: the global
lane a request also passes before an override, the cluster's shared rate
authority, bucket eviction and other callers sharing a key are not modelled.
A sequence whose lane the selection could not decide does not run
(`"complete": false`); one that needs the global lanes when their
configuration is unavailable is `missing_rate_lane_configuration`, and the
rate result is incomplete either way.

### Egress cases

An egress case asks whether the effective egress controls admit an outbound
destination. It states the destination's facts and, optionally, the only
resolution input a case can carry -- an explicitly hypothetical address list:

```json
{
  "id": "billing-api",
  "kind": "egress",
  "destination": { "scheme": "https", "host": "billing.example.test", "port": 443 },
  "resolution": { "hypothetical_addresses": ["192.0.2.10:443"] }
}
```

`destination` has `scheme`, `host` (omit it for a URL without one), `port`
(the URL's explicit port or its scheme's default; omit it only when there is
neither) and the booleans `userinfo` and `fragment` (whether the URL carried
them -- there is no member for their values, a path or a query). An egress case
has no `principal`. `hypothetical_addresses` lists up to 16 IP socket
addresses in the order a resolver would answer; an empty list is a name that
resolves to nothing.

The case is decided by the static egress lane the gateway's egress client
decides every destination by (`gateway/src/policy_eval/egress.rs`), with the
same checks in the same order: shape, scheme, host allowlist and patterns,
port allowlist, then every answer's port and, with `EGRESS_DENY_PRIVATE_IPS`,
whether it is non-global outside the policy CIDRs. A destination the static
checks refuse is refused with its reason (`host_not_allowed`,
`port_not_allowed` and so on) whether or not addresses are supplied. One they
admit, with no `resolution`, is `indeterminate` with the limitation
`missing_resolution_evidence`: no DNS lookup ever runs, and there is no
fallback. With hypothetical addresses the verdict is `allowed`, or
`unexpected_resolved_port`, `empty_resolution` or `non_global_address`.

The controls are this process's effective egress controls -- `EGRESS_ALLOWED_HOSTS`,
auto-seeded infrastructure hosts, the live policy's `egress` section and the
non-global switch -- never a candidate's `egress` section: egress changes are
not applied by a policy write and need a restart
(`egress_change_requires_restart`), so these are the controls any published
candidate would meet. An egress case's base and candidate answers are
therefore always the same. The result binds the controls by
`synthetic_resources.egress_controls_digest`, and never repeats a host, scheme
or address. An egress allow says the destination would be admitted and its
first answer pinned; it is no promise that a connection is made, that TLS
succeeds or that the upstream answers.

## Audit

Each completed simulation emits one `policy.simulation_run` audit event with
the acting principal and the request envelope, `request_digest`, `base_etag`,
`security_revision` (cluster mode), `candidate_source`, `candidate_etag`, the
number of `edits`, for a stored candidate its `candidate_draft_id` and
`candidate_draft_revision` or its `candidate_version`, the `trace` level, the
`projections`, the number of `cases`,
the `summary` counts and the evaluator semantics versions. It never carries a
case id, a fixture value, an edit, a matched element or policy content. A
refused request (`4xx`) is not recorded as a simulation.

## Limits and what comes later

A simulation is synchronous and CPU-only: at most 256 cases, 64 edits and two
projections, a body within 2 MiB, a two-second deadline, an 8 MiB result, at
most four simulations evaluating at once per replica and one per caller, each
on a blocking thread rather than an async worker. A simulation is admitted
only once its body is in hand, and its slot is held until the blocking
evaluation ends, even when the client disconnects first. Each case is
evaluated once per projection, and once more when the candidate differs from
the base.

Not part of this slice, and not to be inferred from it:

- Routing derived server-side from the pinned configuration snapshot.
- Egress for a candidate `egress` section, and egress evaluated as part of an
  HTTP or tool case's upstream.
- Trusted, pinned resolution evidence: the only resolution input today is a
  case's hypothetical list.
- Historical replay over retained traffic, which is
  [its own job API](policy-replay.md#replay-jobs).

The admin UI's Policy Studio has a Simulate view over this API (#243 slice
18): it simulates the open draft's text, unsaved edits included, or the live
policy, and shows each answer's logical decision, enforcement and effective
action as separate steps. See **Policy Studio workbench** in
[the configuration reference](configuration.md#policy_file).
