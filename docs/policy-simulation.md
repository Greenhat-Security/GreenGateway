# Policy simulation

A policy simulation asks what the policy would decide for a batch of
hypothetical requests and tool questions, before anything changes.
`POST /v1{ADMIN_PREFIX}/policy/simulations` evaluates the cases against the
active policy and a candidate -- the active policy itself, position-aware edits
over it, or a complete document you send -- and explains each decision at the
trace level you ask for, as written and with every shadow projected as
enforced (issue #243, slice 10).

A simulation is the exploratory sibling of a [policy test suite](policy-tests.md):
its cases are `policy-tests.v1` cases without an `expect`, parsed by the same
code, and it reports what the policy decides instead of whether that matches an
expectation. A simulated case and a test case with the same facts are the same
question.

Every case is decided by the compiled policy evaluator the gateway uses for
live traffic (`gateway/src/policy_eval`), through the same context builders the
test runner uses. The HTTP stage trace is reported by that evaluator as it runs
(see [the evaluation kernel](architecture/policy-evaluation-kernel.md#stage-trace-and-synthetic-simulation-243-slice-10)),
so a trace can only describe the decision production makes.

## What a simulation means, and what it does not

A result is the policy's answer for the facts a case states. It is not a
prediction that a real request with those facts would succeed: authentication,
CSRF, request admission and schema validation, tool registry state, request
rendering, rate capacity, tool leases, credentials, egress and DNS, transport
and the upstream are not part of a policy decision and are not evaluated. Every
result lists them in `not_evaluated`.

Three answers are always reported separately, so a shadowed deny is never read
as an allow:

| Member | Values | Meaning |
| --- | --- | --- |
| `logical` | `allow`, `deny`, `indeterminate` | What the policy decided. A shadow rule's would-deny is `deny`. |
| `enforcement` | `enforced`, `shadowed`, `not_applicable` | Whether a denial blocks or is only observed. `not_applicable` for an allow and for an undecided case. |
| `effective_action` | `would_forward`, `would_block`, `unknown` | What the request would meet at this stage. A shadowed deny is `would_forward`; an undecided case is `unknown`, never a forward. |

A simulation changes nothing. It does not write, activate or rewrite a policy
(a candidate is validated, compiled for the run and discarded), emits no
data-plane authorization event, records no metric of its own, reads or
charges no rate bucket, acquires no tool permit, resolves no name and contacts
no upstream. The simulation request itself is admitted like any admin `POST`:
it is counted, passes the generic write limiter and gets the access record
every HTTP request gets. Beyond that, the only record it leaves is one
`policy.simulation_run` audit event. A test drives cases that, live, would
charge a one-request rate bucket, record a would-deny, admit a tool and
dispatch to a reachable upstream, proves none of that happened, and checks the
audit, bucket and upstream against the live path afterwards
(`admin_policy_simulations_tests`).

## The request

A request is a `policy-simulation.v1` document. The version is dispatched
exactly, every object refuses unknown members, and a member named like a
credential (`token`, `authorization`, `cookie`, `headers` and similar) is
refused with `forbidden_field`. The published schema is
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

An edited or inline candidate is validated exactly as a policy write
validates one -- the 0.x or v1 rules its `schema_version` selects, and the
proxy-dispatch checks -- and is never stored. A candidate that does not
validate is `422 policy_candidate_invalid`. Server-side drafts and historical
revisions are not candidate sources yet.

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
| `terminal` | The outcome only: `logical`, `enforcement`, `effective_action`, stable `reason`, `complete` and any stable `limitation`. A rate case gives the selected override's position. |
| `matched` | The element that decided (`matched`): a rule by position, action and `id`; a route by position, `id` (v1), required `permission` and `permission_granted`. For HTTP, the shadow rule that was only `observation` beside a host-bound route's decision. A rate case adds the override's `id` (v1), `requests_per_second` and `burst`. |
| `full` | For HTTP cases, one step per evaluator stage in order -- `facts`, `request_host`, `direct_rules`, `upstream_host_binding`, `routes`, `default` -- each `matched`, `no_match`, `not_applicable`, `skipped` (after the decision) or `unknown` (after an undecided answer), with the element, permission check and enforcement mode where they apply. Tool and rate cases add nothing beyond `matched`. |

A full trace is bounded: a simulation returns at most 4096 stage steps in
total. Past that, an evaluation reports `stages_truncated: true` in place of
its steps and the result's `trace.stages_truncated` is `true`; its decision is
still reported in full. An authored id or permission longer than 128 bytes is
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
| `404` | -- | No policy is configured. |
| `412` | `policy_simulation_base_stale` | `base_etag` is not the active policy's ETag, which `current_etag` carries. Nothing ran; no rebase is attempted. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_simulation_invalid` | The request, or an edit applied to the base, is invalid. At most 64 `diagnostics` (`code`, JSON `pointer`, fixed `message`) and `diagnostics_truncated`. Diagnostics never repeat an input value. |
| `422` | `policy_candidate_invalid` | The candidate policy does not validate; `errors` are the policy validator's messages. |
| `422` | `policy_simulation_case_refused` | The evaluator refused a case's facts; `pointer` and `code` name it. |
| `422` | `policy_simulation_result_too_large` | The result would exceed 8 MiB. Nothing is cut short; simulate fewer cases or a lower trace level. |
| `429` | `policy_simulation_busy` | Four simulations are already evaluating on this replica, or this caller already has one running. Nothing was queued. |
| `500` | -- | An evaluator invariant failed or a policy did not compile. No partial result. |
| `503` | -- | Cluster mode could not read the active policy, or (`policy_simulation_deadline_exceeded`) the evaluation did not finish within two seconds. No partial result. |

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
    "gateway_version": "1.0.1"
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
  once written, and equals the base's for the `active` source.
- Each case has one entry per projection. When the candidate is not the base,
  each entry also has the `base` answer under the same projection and
  `changed`, which compares outcomes -- logical decision, enforcement,
  effective action and reason, or for a rate case the selected limits -- not
  positions, which an insert shifts without changing anything.
- With both projections, `projection_changed` says whether promoting every
  shadow changes the candidate's answer for the case.
- `summary` counts, per projection, the candidate's effective actions, the
  shadowed denials, the rate selections and the cases that changed from the
  base.

A result never contains a fixture value -- no path, host, subject, issuer,
role, origin or tool name a case supplied -- only case ids and pointers, stable
codes, element positions and, for a caller who already holds
`admin:policy:read`, the matched element's id and a route's permission. It has
no timestamp or duration.

A rate case reports which `rate_limits` override the live rate stage would
select (`selected`: `override`, `no_override` or `indeterminate`) and its
configured limits. It does not model bucket capacity, and it never reads a
production bucket.

## Audit

Each completed simulation emits one `policy.simulation_run` audit event with
the acting principal and the request envelope, `request_digest`, `base_etag`,
`security_revision` (cluster mode), `candidate_source`, `candidate_etag`, the
number of `edits`, the `trace` level, the `projections`, the number of `cases`,
the `summary` counts and the evaluator semantics versions. It never carries a
case id, a fixture value, an edit, a matched element or policy content. A
refused request (`4xx`) is not recorded as a simulation.

## Limits and what comes later

A simulation is synchronous and CPU-only: at most 256 cases, 64 edits and two
projections, a body within 2 MiB, a two-second deadline, an 8 MiB result, at
most four simulations evaluating at once per replica and one per caller, each
on a blocking thread rather than an async worker. Each case is evaluated once
per projection, and once more when the candidate differs from the base.

Not part of this slice, and not to be inferred from it:

- Server-side drafts and historical revisions as candidate sources, and
  routing derived server-side from the pinned configuration snapshot.
- Stage traces for the tool and rate lanes, and egress cases.
- Isolated rate-bucket sequences on a virtual clock.
- Historical replay over retained traffic (`/policy/replays`), and the
  Simulator UI.
