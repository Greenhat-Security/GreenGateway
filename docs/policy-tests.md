# Policy test suites

A policy test suite is a list of synthetic cases: a hypothetical request or
tool question, the identity facts of a hypothetical caller, and the decision you
expect the policy to make. `POST /v1{ADMIN_PREFIX}/policy/tests/runs` runs a
suite against the active policy, or against a candidate you send with it, and
answers JSON, SARIF 2.1.0 or JUnit XML (issue #243, slice 11).

Every case is decided by the same compiled policy evaluator the gateway uses
for live traffic (`gateway/src/policy_eval`): the runner builds the same typed
context a live adapter builds and asks the same question, so a test reports
what production would decide for those facts, not what a copy of the rules
would. See [the evaluation kernel](architecture/policy-evaluation-kernel.md).

## What a passing run means, and what it does not

A passing case means that the policy gives the expected answer for the facts
the case states. It does not mean that a real request with those facts would
succeed. Authentication, CSRF, request admission and schema validation, tool
registry state, request rendering, rate capacity, tool leases, credentials,
egress and DNS, transport and the upstream are not part of a policy decision
and are not evaluated; every report lists them in `not_evaluated`.

A run never passes by default:

- An empty suite is refused (`422`, `empty_suite`).
- A case the evaluator refuses is `error`, and one it cannot decide is
  `incomplete`. Neither counts as a pass, whatever the case expected, and a run
  with either is not `passed`.
- `indeterminate` is not an expectation you can write. Every case states every
  fact it depends on, so an undecided answer is reported as incomplete, never
  matched.

A run changes nothing. It does not write or activate the policy (a candidate is
validated and judged, never stored), emits no data-plane authorization events,
touches no rate bucket or tool permit, makes no network request, and keeps
nothing after it answers.

## The suite document

A suite is a `policy-tests.v1` document. The version is dispatched exactly: any
other `schema_version` is refused, and every object refuses unknown members.
The published schema is
[`docs/schemas/policy-tests.v1.schema.json`](schemas/policy-tests.v1.schema.json);
the gateway's parser is authoritative and additionally checks path, host and
origin syntax, the identity bounds authentication applies, unique case ids,
and byte rather than character lengths.

```json
{
  "schema_version": "policy-tests.v1",
  "description": "Orders API access",
  "cases": [
    {
      "id": "reader-reads-orders",
      "description": "the orders route grants orders:read",
      "kind": "http",
      "request": { "method": "GET", "path": "/orders/42" },
      "principal": {
        "subject": "synthetic-reader",
        "issuer": "https://idp.example.test",
        "roles": ["orders-reader"],
        "auth_method": "bearer_token"
      },
      "expect": { "logical": "allow", "matched": { "route": 0 } }
    },
    {
      "id": "anonymous-orders-blocked",
      "kind": "http",
      "request": { "method": "GET", "path": "/orders/42" },
      "principal": "anonymous",
      "expect": { "logical": "deny", "effect": "block", "reason": "missing_principal" }
    },
    {
      "id": "export-tool-denied-for-auditors",
      "kind": "tool",
      "tool": { "name": "reports.export", "operation": "invocation" },
      "principal": { "subject": "synthetic-auditor", "roles": ["auditor"], "auth_method": "session_cookie" },
      "expect": { "logical": "deny", "reason": "matched_rule", "matched": { "rule": "deny-export" } }
    },
    {
      "id": "readers-get-the-orders-rate-override",
      "kind": "rate",
      "request": { "method": "GET", "path": "/orders/42" },
      "principal": { "subject": "synthetic-reader", "roles": ["orders-reader"], "auth_method": "bearer_token" },
      "expect": { "rate_override": 0 }
    }
  ]
}
```

| Member | Meaning |
| --- | --- |
| `schema_version` | Exactly `policy-tests.v1`. |
| `description` | Optional, at most 1024 bytes. Never repeated in results. |
| `cases` | 1 to 512 cases. |
| `cases[].id` | Unique within the suite, at most 128 bytes, an ASCII letter or digit followed by letters, digits, `.`, `_`, `:` or `-`. Results, SARIF and JUnit identify a case by this id and its JSON Pointer. |
| `cases[].kind` | `http`, `tool`, `tool_http` or `rate`. Each kind accepts only its own members. |
| `cases[].principal` | `"anonymous"`, or `subject` (required), `issuer`, `roles` and `auth_method` (required: `bearer_token`, `session_cookie`, `service_token` or `client_certificate`). The issuer is canonicalized as authentication canonicalizes it (a trailing `/` is dropped). |
| `cases[].expect` | What the case asserts; see below. |

### Case kinds

- **`http`** asks the HTTP lane (direct rules, MCP alias identities, routes,
  host binding, defaults and shadow enforcement). `request` has `method`,
  `path` (an already-separated request path: no query, fragment, dot segments
  or `%`), an optional `host` without a port (absent means a request with no
  `Host` header), and an optional `target`:
  - `{"kind": "contextless"}` (the default): a request the gateway serves
    itself, with no proxy dispatch.
  - `{"kind": "mcp_alias", "canonical_path": "/mcp"}`: an MCP endpoint reached
    by `path` whose canonical policy identity is `canonical_path`. Both
    identities decide, under the alias precedence order.
  - `{"kind": "proxy_dispatch", "upstream_origin": "https://api.internal.example.test", "route_id": "orders", "route_host": "api.example.test", "route_path_prefix": "/orders"}`:
    a proxied request with these hypothetical routing facts. `upstream_origin`
    is an `http` or `https` origin (no credentials, path, query or fragment) or
    `pool:<route id>`; it is only compared with rule dispatch matchers and is
    never contacted. A `route_host` selects a virtual upstream, so only a
    host-bound route can authorize it.
- **`tool`** asks the tool lane about `tool.name`: `operation` is
  `invocation` (the default), `visibility` (tool listing) or `eligibility`
  (the inventory answer, which needs an authenticated principal).
- **`tool_http`** asks whether a rendered tool HTTP request, `request.method`
  and `request.path` (which may carry percent-escapes), is allowed by the
  direct HTTP rules, as the tool executor asks before sending it. `tool.name`
  names the tool.
- **`rate`** asks which `rate_limits` override governs `request.method` and
  `request.path` for the principal: first match in order, and never one for an
  anonymous caller, exactly as the live rate stage selects. It does not model
  bucket capacity.

There is no member for a token, cookie, header, query value, body or any other
credential or request content. A member named like one (`token`,
`authorization`, `cookie`, `headers`, `password`, `secret` and similar) is
refused with `forbidden_field` rather than as an ordinary unknown member.

### Expectations

For `http`, `tool` and `tool_http` cases:

| Member | Meaning |
| --- | --- |
| `logical` | Required: `allow` or `deny`. A shadow rule's would-deny is `deny`. |
| `effect` | Optional: `allow`, `block` or `observe` (denied in logic, forwarded because of shadow enforcement). |
| `reason` | Optional stable reason code. HTTP: `matched_rule`, `missing_permission`, `missing_principal`, `default_allow`, `default_deny`, `host_policy_required`. Tool lane: `unknown_tool`, `disabled`, `role_not_allowed`, `matched_rule`, `allowed`, `not_in_policy`, `policy_disabled`, `principal_not_eligible`, `policy_denied`, `eligible`, `no_http_rule`. |
| `matched` | Optional: `"none"`, `{"rule": "<rule id>"}` (a direct rule's `id`, or its position for a rule without one, as the other policy APIs name it), or, for `http` only, `{"route": <position>}`. |

Only the members you write are asserted. For `rate` cases, `expect` is
`{"rate_override": <position>}` or `{"rate_override": null}` for no override.

Routes and rate overrides are named by position because the current policy
schema gives them no identifiers; a reordered policy changes them.

## Running a suite

```http
POST /v1/admin/policy/tests/runs
Content-Type: application/json
If-Match: "sha256:..."            (optional)

{ "suite": { ... }, "format": "json" }
```

- The caller needs both `admin:policy:read` and `admin:policy:simulate`;
  either one alone is `403`. Both are checked before the body is read. The
  admin capabilities endpoint lists `admin:policy:simulate` when it is held.
- `format` is `json` (the default), `sarif` or `junit`.
- `policy` (optional) is a candidate policy document. It is validated as
  `POST /v1{ADMIN_PREFIX}/policy/validate` validates one and judged without
  being stored. Without it the run judges the active policy: the policy file's
  current snapshot in standalone mode, or the authoritative active document in
  cluster mode.
- `If-Match` (optional, active policy only) pins the run to the policy ETag you
  reviewed; a different active ETag is `412` and nothing runs. Combining it
  with a candidate is `400`.

The policy's own routes are evaluated before the handler, as for every admin
route. A policy whose routes gate the admin API -- `dev/policy.json`, for
instance, sends every unsafe method under `/v1/admin/policy` to
`admin:policy:write` -- needs a route for `POST
/v1{ADMIN_PREFIX}/policy/tests/runs` ahead of that catch-all, or a tester
without write access is refused before the run is considered. The dev policy
carries one that grants `admin:policy:simulate`.

A completed run is `200` whatever its outcome, with `Cache-Control: no-store`
and `X-GreenGateway-Policy-Tests-Status: passed|failed|incomplete|error`, so a
pipeline can gate on the header or on `status` without parsing the rendering.

| Status | `reason` | Meaning |
| --- | --- | --- |
| `400` | `policy_tests_request_invalid` | The body is not a JSON object, repeats a member name anywhere, has a member other than `suite`, `policy` and `format`, lacks `suite`, names an unknown format, or combines `If-Match` with a candidate. |
| `401`, `403` | -- | Not authenticated, or missing either permission. |
| `404` | -- | No policy is configured. |
| `408` | `policy_tests_request_timeout` | The body did not arrive within five seconds. Nothing ran. |
| `412` | -- | `If-Match` does not name the active policy. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_tests_invalid` | The suite is invalid. The body lists at most 64 `diagnostics` (`code`, JSON `pointer`, fixed `message`) and `diagnostics_truncated`. Diagnostics never repeat an input value. |
| `422` | `policy_candidate_invalid` | The candidate policy is invalid; `errors` are the policy validator's messages. |
| `429` | `policy_tests_busy` | Four runs are already evaluating on this replica, or this caller already has one running. Nothing was queued. |
| `500` | -- | The policy under test did not compile. No partial result. |
| `503` | -- | Cluster mode could not read the active policy, or (`policy_tests_deadline_exceeded`) the run did not finish within five seconds. No partial result. |

Diagnostic codes: `invalid_type`, `missing_field`, `unknown_field`,
`forbidden_field`, `invalid_value`, `too_long`, `unsupported_schema_version`,
`empty_suite`, `too_many_cases`, `duplicate_case_id`, `invalid_case_id`,
`invalid_method`, `invalid_path`, `invalid_host`, `invalid_origin`,
`invalid_principal`, `inconsistent_case`, `unsupported_number`.

### JSON report

```json
{
  "schema_version": "policy-test-results.v1",
  "status": "failed",
  "mode": "test",
  "suite": { "schema_version": "policy-tests.v1", "digest": "sha256:..." },
  "policy": { "source": "active", "etag": "\"sha256:...\"" },
  "evaluator": {
    "http_semantics_version": "gg-http-alias-v1",
    "http_context_version": 3,
    "tool_semantics_version": "gg-tool-policy-v1",
    "tool_context_version": 1
  },
  "gateway_version": "1.0.1",
  "not_evaluated": ["authentication", "csrf", "..."],
  "summary": { "total": 4, "passed": 3, "failed": 1, "incomplete": 0, "errors": 0 },
  "cases": [
    {
      "id": "anonymous-orders-blocked",
      "pointer": "/cases/1",
      "kind": "http",
      "status": "failed",
      "expected": { "logical": "deny", "effect": "block", "reason": "missing_principal" },
      "actual": {
        "logical": "deny", "effect": "observe", "reason": "missing_principal",
        "matched": { "route": 0 }, "complete": true, "limitation": null
      },
      "mismatches": ["effect"]
    }
  ]
}
```

- `status` is the worst case outcome: `error`, then `incomplete`, then
  `failed`; `passed` only when every case passed.
- `suite.digest` is the ADR-0004 semantic digest of the submitted suite: the
  RFC 8785 (JCS) bytes of the document, framed with the media type
  `application/vnd.greengateway.policy-tests+json` and version
  `policy-tests.v1`. The version defines no normalization beyond JCS, so member
  order and whitespace do not change it and any other change does.
- `policy.etag` is the active policy's ETag, or for a candidate the ETag it
  would have once written. `policy.source` is `active` or `inline_candidate`;
  cluster mode adds `security_revision`.
- Each case reports its `status` (`passed`, `failed`, `incomplete`, `error`),
  what was `expected`, what the evaluator answered in stable codes (`actual`,
  absent for `error`), which expectations did not hold (`mismatches`, in the
  order `logical`, `effect`, `reason`, `matched`, `rate_override`), and for an
  evaluator refusal its stable `error` code.

The report is deterministic: it has no timestamp or duration, so the same
policy and suite give the same bytes. It never contains a fixture value -- no
path, host, subject, issuer, role or tool name a case supplied -- only case
ids, expectations, stable codes and the matched rule id or route position.

### SARIF

`"format": "sarif"` answers `application/sarif+json`, SARIF 2.1.0 with tool
`greengateway-policy-tests`. There is one result per case that did not pass,
under the rule `policy-test/failed`, `policy-test/incomplete` or
`policy-test/error`, located by a logical location whose `name` is the case id
and whose `fullyQualifiedName` is its JSON Pointer. An empty `results` array
means every case passed; the run's `properties` carry `status`, the suite
digest, the policy source and ETag, the summary and `not_evaluated`, so an
all-passing file is distinguishable from an empty one.

### JUnit

`"format": "junit"` answers `application/xml`: one `testsuite` named
`policy-tests.v1` with a `testcase` per case (`classname` `policy.<kind>`,
`name` the case id). A failed or incomplete case carries a `failure`, a refused
one an `error`; nothing is ever `skipped`. The suite `properties` carry the run
status, suite digest, policy source and ETag, and the evaluator versions.

### In a pipeline

```sh
jq -n --slurpfile suite policy-tests.v1.json --slurpfile policy policy.json \
  '{suite: $suite[0], policy: $policy[0], format: "junit"}' |
curl --fail-with-body -sS -X POST "$GATEWAY/v1/admin/policy/tests/runs" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @- \
  -D headers.txt -o policy-tests.junit.xml
grep -qi '^x-greengateway-policy-tests-status: passed' headers.txt
```

Use a service token that holds only `admin:policy:read` and
`admin:policy:simulate`. One caller runs one suite at a time: a second run
under the same identity while the first is still evaluating is `429`
(`policy_tests_busy`), so run a pipeline's suites one after another.

## Audit

Each completed run emits one `policy.tests_run` audit event with the acting
principal and the request envelope, `policy_source`, `policy_etag`,
`security_revision` (cluster mode), `suite_digest`, `status`, the five summary
counts and the evaluator semantics versions. It never carries a case id, a
fixture value, a matched rule or policy content. Refused requests (`4xx`) are
not recorded as runs.

## Limits and what comes later

A run is synchronous and CPU-only: at most 512 cases, a body within
`MAX_BODY_SIZE` or 2 MiB, whichever is lower, that arrives within five seconds,
a five-second deadline on the evaluation, and at most four runs evaluating at
once per replica and one per caller, each on a blocking thread rather than an
async worker. A run is admitted only once its body is in hand, so an upload in
progress holds no slot, and its slot is held until the blocking evaluation
ends, even when the client disconnects first.

Not part of this slice, and not to be inferred from it:

- Storing a suite beside the policy as a versioned resource with a strong
  ETag (`GET`/`PUT /policy/tests`), and requiring a passing suite before a
  policy change is activated. Today a suite is submitted with each run and
  nothing is gated on it.
- Isolated rate-bucket sequences on a virtual clock, egress cases, typed claim,
  header, query, tool-argument and time-window matchers, and stable route and
  rate-override identifiers (policy v1).
- `ggctl policy test` (#242). The runner holds no application state, so that
  command can link it rather than reimplement it.
