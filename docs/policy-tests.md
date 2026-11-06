# Policy test suites

A policy test suite is a list of synthetic cases: a hypothetical request, tool
question, rate sequence or outbound destination, the identity facts of a
hypothetical caller where the lane has one, and the decision you expect.
`POST /v1{ADMIN_PREFIX}/policy/tests/runs` runs a suite against the active
policy, against a candidate you send with it, or against one of your
server-side drafts or a version of the policy history, and answers JSON, SARIF
2.1.0 or JUnit XML (issue #243, slice 11; isolated rate sequences and egress
cases in slice 12). A deployment can also keep one suite beside its policy, as
a versioned resource with a strong ETag (`GET`/`PUT
/v1{ADMIN_PREFIX}/policy/tests`), and a run or an
[evidence package](policy-evidence.md) can name that stored suite instead of
carrying one. With `POLICY_TESTS_REQUIRED=true` no policy change is activated
unless the stored suite passes against it
([below](#requiring-the-stored-suite-before-activation)).

Every case is decided by the same compiled policy evaluator the gateway uses
for live traffic (`gateway/src/policy_eval`): the runner builds the same typed
context a live adapter builds and asks the same question, so a test reports
what production would decide for those facts, not what a copy of the rules
would. See [the evaluation kernel](architecture/policy-evaluation-kernel.md).

## What a passing run means, and what it does not

A passing case means that the policy gives the expected answer for the facts
the case states. It does not mean that a real request with those facts would
succeed. Authentication, CSRF, request admission and schema validation, tool
registry state, request rendering, live rate capacity, tool leases,
credentials, an upstream's egress, DNS, transport and the upstream are not part
of a policy decision and are not evaluated; every report lists them in
`not_evaluated`. A rate sequence's steps describe a fresh, isolated bucket,
never a live caller's allowance, and an egress case is judged over the
addresses it supposes, never ones anything resolved.

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
touches no production rate bucket or tool permit, resolves no name, makes no
network request, and keeps nothing after it answers.

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
| `cases[].kind` | `http`, `tool`, `tool_http`, `rate` or `egress`. Each kind accepts only its own members. |
| `cases[].principal` | Every kind but `egress`: `"anonymous"`, or `subject` (required), `issuer`, `roles`, `auth_method` (required: `bearer_token`, `session_cookie`, `service_token` or `client_certificate`), `organization`, `scopes` and `claims`. The issuer is canonicalized as authentication canonicalizes it (a trailing `/` is dropped). `organization` (1 to 8192 bytes) is the organization the principal's identity provider verified, which a policy's identity mappings may test; omitted, the principal has none. `scopes` (at most 256 RFC 6749 scope tokens of at most 256 bytes) are the OAuth scopes the principal's JWT validation verified, which `scope` conditions and mappings' `scopes` test; omitted, the principal has no scope fact (as a session or service token has none), so a matcher that reads scopes is `indeterminate`, and `[]` is a token that granted none. `claims` (at most 16) maps each claim name its provider allowlists in `verified_claims` to what the token carried: a string of at most 256 bytes without control characters, a boolean, a number, or a list of at most 32 such strings, `[]` being a claim the token did not carry; a name omitted was not captured, so a `claim` condition that reads it is `indeterminate`, and a name no allowlist may list (`sub`, `jti`, `email`, `scope`, a credential name and the rest `verified_claims` refuses) is `forbidden_field`. As on the live lanes each is read only when an identity mapping or a condition reads it, and no result repeats one. |
| `cases[].facts` | `http`, `tool` and `tool_http` only: optional request facts a rule condition reads, `source_ip`, `headers`, `query`, `now` and, for a tool invocation, `arguments`; see [Request facts](#request-facts). |
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
  live bucket capacity. An optional `sequence`, `{"at_ms": [0, 0, 250]}`, runs
  one to 64 requests at virtual instants (milliseconds since the sequence's
  origin, at most one day, never decreasing) against a fresh bucket built from
  the selected lane's configured rate and burst: the override's own, or, when
  no override governs, the global `read` (`GET`, `HEAD`) or `write` lane's.
  The bucket starts empty, so the first step meets a full burst as a key the
  live limiter has never seen does, and each step takes the live limiter's own
  token arithmetic. No production bucket, shared rate state or metric is read
  or changed. See [isolated rate sequences](policy-simulation.md#isolated-rate-sequences).
- **`egress`** asks whether the effective egress controls admit
  `destination` (`scheme`, optional `host` and `port`, and the booleans
  `userinfo` and `fragment`), decided by the static egress lane the egress
  client decides by. The only resolution input is an optional
  `resolution.hypothetical_addresses` list of up to 16 IP socket addresses.
  Without it, a destination the static checks admit is undecided
  (`incomplete`, `missing_resolution_evidence`); no DNS lookup ever runs and
  there is no fallback. An egress case has no `principal`. See
  [egress cases](policy-simulation.md#egress-cases).

There is no member for a token, cookie, body or any other credential or
request content. A member named like one (`token`, `authorization`,
`cookie`, `headers`, `password`, `secret` and similar) outside `facts` is
refused with `forbidden_field` rather than as an ordinary unknown member.

### Request facts

A policy v1 rule may carry conditions over the source network, request
headers, query parameters, a time window and a tool call's arguments. A case
states those facts in an optional `facts` member, typed and bounded:

| Member | Meaning |
| --- | --- |
| `source_ip` | The canonical client address the gateway would derive after trusted-proxy processing: an IPv4 or IPv6 address without a port. An IPv4-mapped IPv6 address is its IPv4 address. |
| `headers` | An object from a lowercase header name to the values of its occurrences, in order: `{"x-environment": ["prod", "canary"]}` is two field lines. Each value is a whole field line, compared exactly. |
| `query` | An object from a decoded parameter name to its decoded values, in order; `""` is a parameter without a value. |
| `now` | The evaluation instant, `YYYY-MM-DDTHH:MM:SSZ`. |
| `arguments` | A tool invocation's arguments as they stand once the tool's input schema has accepted them: one JSON object, nested at most 8 levels deep, of at most 128 values with member names of at most 256 bytes and strings of at most 8192 bytes. Only the scalars at the pointers the tool's `tool_argument` conditions read are evaluated, as the live lane reduces a validated call's; the runner has no tool registry, so it neither re-validates them nor judges pointer eligibility, which publication checks. |

`http` cases may state the first four; `tool` cases `source_ip`, `now` and,
for the `invocation` operation only, `arguments` (a visibility or eligibility
preview never has a call's arguments, on the live lane or here); `tool_http`
cases only `source_ip` and `now`, because a tool call carries no headers or
query of its own and a rendered request no arguments
(`fact_not_applicable`); `rate` and `egress` cases none, because rate
overrides carry no conditions and an outbound destination involves no caller. A fact a condition reads that the case does not state is
unknown: the case is `indeterminate` with `missing_matcher_fact` and is
reported `incomplete`, never passed, whatever it expected. An empty
`headers` or `query` object states a request that carried none, which is a
certain no-match. The organization, scopes and claims a condition reads are
the principal's `organization`, `scopes` and `claims`, as for identity
mappings. A header or query name that can
carry a credential, an identity or hop-by-hop routing -- the names a
condition may not read, such as `authorization`, `cookie`, `x-forwarded-for`,
`connection`, `x-api-key` or `access_token` -- is refused with
`forbidden_field`, in any letter case; more than 128 occurrences, or more
than 128 argument values, is `too_many_facts`; a value is at most 8192 bytes
without control characters; arguments that are not an object are
`invalid_type` and arguments past their other bounds `invalid_value`. No
stated value appears in a report or diagnostic.

### Expectations

For `http`, `tool` and `tool_http` cases:

| Member | Meaning |
| --- | --- |
| `logical` | Required: `allow` or `deny`. A shadow rule's would-deny is `deny`. |
| `effect` | Optional: `allow`, `block` or `observe` (denied in logic, forwarded because of shadow enforcement). |
| `reason` | Optional stable reason code. HTTP: `matched_rule`, `missing_permission`, `missing_principal`, `default_allow`, `default_deny`, `host_policy_required`. Tool lane: `unknown_tool`, `disabled`, `role_not_allowed`, `matched_rule`, `allowed`, `not_in_policy`, `policy_disabled`, `principal_not_eligible`, `policy_denied`, `eligible`, `no_http_rule`. |
| `matched` | Optional: `"none"`, `{"rule": "<rule id>"}` (a direct rule's `id`, or its position for a rule without one, as the other policy APIs name it), or, for `http` only, `{"route": <position>}`. |

Only the members you write are asserted. For `rate` cases, `expect` is
`{"rate_override": <position>}` or `{"rate_override": null}` for no override,
and, for a case with a sequence, optionally `"steps"`: one `allowed` or
`limited` per step, in order. For `egress` cases, `expect` is `logical`
(`allow` or `deny`) and an optional `reason`: `allowed`, `missing_host`,
`userinfo`, `fragment`, `scheme_not_allowed`, `host_not_allowed`,
`missing_port`, `port_not_allowed`, `empty_resolution`,
`unexpected_resolved_port` or `non_global_address`. Assertions are subsets of
the answer -- the lane, the step outcomes, the egress verdict -- never a trace.

An egress case or a sequence that needs configuration a run does not have is
`incomplete` with `missing_egress_controls` or
`missing_rate_lane_configuration`. The admin API always supplies both; a
[policy evidence package](policy-evidence.md) supplies neither, because this
process's configuration does not describe the gateway that served a historical
publication (a sequence on an override still runs on the publication's own
limits).

Routes and rate overrides are named by position because the current policy
schema gives them no identifiers; a reordered policy changes them.

## Storing a suite beside the policy

`/v1{ADMIN_PREFIX}/policy/tests` holds at most one suite: the stored suite, an
exact-version `policy-tests.v1` document kept with the policy authority. Every
write is a new immutable version; nothing is edited in place and nothing is
deleted. Storing a suite changes no enforcement and activates nothing; with
`POLICY_TESTS_REQUIRED=true` it is the suite every later policy change must
pass.

```http
PUT /v1/admin/policy/tests
Content-Type: application/json
If-None-Match: *                  (the first suite)
If-Match: "sha256:..."            (replacing the stored one)

{ "schema_version": "policy-tests.v1", "cases": [ ... ] }
```

- **Permissions.** `GET` needs both `admin:policy:read` and
  `admin:policy:simulate`, what a run of the suite needs; `PUT` needs
  `admin:policy:write`. Both are decided before any header, body or store is
  read. The dev policy's routes already cover the path: `GET` under the
  `admin:policy:read` route for `/v1/admin/policy`, `PUT` under the
  `admin:policy:write` catch-all.
- **The ETag is the suite digest.** The strong `ETag` is the suite's
  [semantic digest](#json-report) in quotes, so `report.suite.digest` names the
  stored version a run decided, and two versions carry one ETag exactly when
  they are the same suite (member order and whitespace do not count).
  `X-GreenGateway-Policy-Tests-Version` gives the stored version number.
- **The representation.** `GET` and a successful `PUT` answer the stored suite
  as its RFC 8785 (JCS) bytes, `application/json`, with `Cache-Control:
  private, no-store`. It is the document you stored, re-serialized; send it
  back unchanged and you store the same ETag again.
- **Exactly one precondition.** `PUT` requires `If-None-Match: *` to store the
  first suite or `If-Match` with exactly one strong entity tag naming the
  stored one. Neither is `428`; both, a list, a weak tag, `If-Match: *` or any
  other `If-None-Match` is `400`. A precondition that no longer holds is `412`,
  decided in the store's own transaction, so of two writers holding one ETag
  exactly one wins. A replaced suite answers `200`, the first one `201`.
- **Strict and bounded, like a run.** The body is read within `MAX_BODY_SIZE` or
  2 MiB, whichever is lower, and within five seconds; repeated member names
  are refused before parsing; and the suite is parsed by exactly the parser a
  run uses (at most 512 cases), with the same value-free diagnostics. A suite
  that holds the character U+0000 in any string is refused as well, because
  the cluster store cannot hold one, so a stored suite means the same thing in
  both modes. Nothing refused is stored.
- **Where it lives.** Standalone, in a `policy_test_suite_versions` table of the
  policy history database (`POLICY_HISTORY_SQLITE_PATH`, or the
  `<POLICY_FILE>.history.sqlite` default): the newest row is the stored suite,
  and a write is one SQLite transaction that re-checks the precondition and
  appends, so a crash leaves the old version or the new one. In cluster mode,
  in PostgreSQL migration 29's `greengateway.policy_test_suite_versions` and
  `greengateway.policy_test_suite_active`, committed through the same
  versioned-document transaction as the policy, as a resource of its own (see
  [the policy control plane](deployment/postgres.md#the-policy-control-plane)).
  Never in browser storage. Every read re-parses the stored suite and requires
  it to reproduce its ETag; a row edited out of band answers `503` and is never
  run. `import-standalone` does not carry a standalone suite into a cluster.

| Status | `reason` | Meaning |
| --- | --- | --- |
| `200`, `201` | -- | Read, replaced or first stored. |
| `400` | `policy_tests_precondition_invalid` | The precondition is not exactly one strong tag in `If-Match` or `If-None-Match: *`. |
| `400` | `policy_tests_request_invalid` | The body is not JSON, or repeats a member name anywhere. |
| `401`, `403` | -- | Not authenticated, or missing a permission. |
| `404` | -- | No policy is configured. |
| `404` | `policy_tests_not_found` | No suite is stored (`GET`). |
| `408` | `policy_tests_request_timeout` | The body did not arrive within five seconds. |
| `409` | `authority_evidence_unsupported` | `AUTHORITY_EVIDENCE_DURABILITY=required` in standalone mode, which records no evidence of the write beyond the version row ([authority evidence](authority-evidence.md)). Nothing was written. |
| `412` | `policy_tests_etag_mismatch` | `If-Match` does not name the stored suite (or none is stored). |
| `412` | `policy_tests_exist` | `If-None-Match: *`, and a suite is already stored. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_tests_invalid` | The suite is invalid; `diagnostics` as for a run. |
| `428` | `policy_tests_precondition_required` | Neither `If-Match` nor `If-None-Match` was sent. |
| `503` | `policy_tests_unavailable` | No suite store is configured or it could not be read or written. |

With `POLICY_TESTS_REQUIRED=true` a successful `PUT` also reports what the
[activation gate](#requiring-the-stored-suite-before-activation) would answer
for the active policy under the suite just stored, in
`X-GreenGateway-Policy-Tests-Active-Status`: `passed`, or the refusal's
`status`. The suite is stored either way, so storing the suite the next
policy must pass never needs the current policy to pass it first.

## Requiring the stored suite before activation

`POLICY_TESTS_REQUIRED=true` ([configuration](configuration.md#policy_tests_required))
makes the stored suite a precondition of every policy change the admin API
activates: `PUT /v1{ADMIN_PREFIX}/policy`, rollback, rule create, update (a
promotion or disable bound to a shadow review included), delete and reorder, a
draft publication (one bound to a suggestion included, which commits as that
suggestion's acceptance), and a discovery suggestion's acceptance, standalone
or in cluster mode (where the candidate and the suggestion's transition commit
in one transaction). Each runs the stored suite against its candidate inside
the commit precondition: under the policy write lock, after the cross-resource
checks, before any authority is asked to write. The run is the one
`POST .../policy/tests/runs` makes for a candidate -- the same runner, the
same egress controls and rate lanes, the same five-second deadline on a
blocking thread -- and the write lock serializes it with every other
publication on the replica.

The change is committed only when every case of the suite passed. Anything
else refuses it and writes nothing:

| `required_tests.status` | Meaning |
| --- | --- |
| `suite_missing` | No suite is stored. |
| `suite_invalid` | The stored suite no longer verifies against its ETag (a row edited out of band) or this build no longer accepts it. |
| `suite_unavailable` | No suite store is configured, or it could not be read (`503`). |
| `failed` | At least one case's expectation did not hold. |
| `incomplete` | At least one case could not be decided, or the run decided fewer cases than the suite holds. |
| `error` | The evaluator refused at least one case. |
| `deadline_exceeded` | The run did not finish within five seconds. |
| `evaluation_failed` | The candidate did not compile or the evaluation did not complete. |

An evaluator error is never a pass, and neither is an undecided or
incomplete case, whatever the case expected.

```json
{
  "error": "the stored policy test suite this deployment requires did not pass against this policy; nothing was written",
  "reason": "policy_tests_required_failed",
  "required_tests": {
    "status": "failed",
    "suite_version": 3,
    "suite_etag": "\"sha256:...\"",
    "summary": { "total": 4, "passed": 3, "failed": 1, "incomplete": 0, "errors": 0 }
  }
}
```

The answer is `422 policy_tests_required_failed`, or `503
policy_tests_unavailable` for `suite_unavailable`. `suite_version` and
`suite_etag` are `null` when no suite was read, and `summary` is `null` unless
the run completed. The answer carries counts only: run the stored suite
(`{"suite": {"source": "stored"}}`) against the same candidate to see which
cases did not pass. A draft publication that is refused this way is also
audited as `policy.draft_publish_refused` with the same reason.

Each refusal is audited as `policy.publication_refused` with the code
(`policy_tests_required_failed` or `policy_tests_unavailable`), the policy ETag
the change would have replaced, the resource snapshot digest and
`required_tests` as in the answer. A change the suite admitted records
`required_tests` (`suite_version`, `suite_etag`, `total` and `passed`) in its
`policy.changed` event. Neither ever carries a case id, a fixture value or a
matched element.

What the gate does not cover:

- It reads the suite once per publication. In cluster mode another replica
  can store a new suite between that read and the policy commit; the
  `policy.changed` record names the suite version that admitted the change.
- A watched or `SIGHUP` reload of `POLICY_FILE`, a restart, and
  `gateway import-standalone` are not publications through the API and are
  not gated: whoever can write the policy file or run the import is trusted
  with the policy.
- Bundle activation (#242) has no runtime path in this build: nothing opens a
  revision ledger or selects a bundle at startup, so there is no activation
  there to gate yet.

## Running a suite

```http
POST /v1/admin/policy/tests/runs
Content-Type: application/json
If-Match: "sha256:..."            (optional)

{ "suite": { ... }, "format": "json" }
```

- `suite` is a complete suite, or `{"source": "stored"}` to run the stored
  suite, optionally pinned as `{"source": "stored", "etag": "\"sha256:...\""}`
  to the strong ETag you reviewed. A reference accepts only those two members,
  and `etag` must be one strong entity tag. A pinned ETag that is no longer
  stored is `412` (`policy_tests_etag_mismatch`) and nothing runs; no stored
  suite is `404` (`policy_tests_not_found`).
- The caller needs both `admin:policy:read` and `admin:policy:simulate`;
  either one alone is `403`. Both are checked before the body is read. The
  admin capabilities endpoint lists `admin:policy:simulate` when it is held.
- `format` is `json` (the default), `sarif` or `junit`.
- `policy` (optional) is a candidate policy document. It is validated as
  `POST /v1{ADMIN_PREFIX}/policy/validate` validates one, from the exact bytes
  of the member, so a v1 document is held to the same exact-source rules
  (size, and no number spelled through serde_json's private number tag), and
  judged without being stored. `"policy": null` is a candidate, and invalid.
  Without it the run judges the active policy: the policy file's
  current snapshot in standalone mode, or the authoritative active document in
  cluster mode.
- `candidate` (optional, instead of `policy`) names a stored candidate with
  the members a [simulation's](policy-simulation.md#drafts-and-history-versions)
  has: `{"source": "draft", "draft_id": "pd_...", "draft_etag":
  "\"sha256:...\""}` for one of your drafts at that draft ETag, or
  `{"source": "revision", "version": 7}` for a policy history version. It is
  read, owner-scoped and validated again exactly as a simulation reads it,
  and never written. A run has no `base_etag`, so a draft is judged only while
  it is pinned to the live policy, the one it would be published over;
  otherwise it is `409 policy_draft_base_stale`. Any other `source` is `400`:
  an inline document is the `policy` member, and edits need a base.
- `If-Match` (optional, active policy only) pins the run to the policy ETag you
  reviewed; a different active ETag is `412` and nothing runs. Combining it
  with a candidate, inline or stored, is `400`.

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
| `400` | `policy_tests_request_invalid` | The body is not a JSON object, repeats a member name anywhere, has a member other than `suite`, `policy`, `candidate` and `format`, lacks `suite`, names an unknown format, names both `policy` and `candidate`, has a `candidate` that is not a well-formed `draft` or `revision` (with `diagnostics` when its members are wrong), combines `If-Match` with a candidate, or names the stored suite with a malformed reference. |
| `401`, `403` | -- | Not authenticated, or missing either permission. |
| `404` | -- | No policy is configured, or a `revision` candidate names a deployment with no policy history. |
| `404` | `policy_draft_not_found`, `policy_revision_not_found` | The `candidate` names no draft of yours, or a version the history does not hold. |
| `404` | `policy_tests_not_found` | The run names the stored suite, and none is stored. |
| `408` | `policy_tests_request_timeout` | The body did not arrive within five seconds. Nothing ran. |
| `409` | `policy_draft_base_stale` | The draft is pinned to another base than the live policy. |
| `410` | `policy_draft_expired` | The draft has expired. |
| `412` | -- | `If-Match` does not name the active policy. |
| `412` | `policy_draft_stale` | `draft_etag` is no longer the draft's ETag. |
| `412` | `policy_tests_etag_mismatch` | The stored suite is not the one the reference pinned. |
| `413` | -- | The body exceeds `MAX_BODY_SIZE` or 2 MiB, whichever is lower. |
| `422` | `policy_tests_invalid` | The suite is invalid. The body lists at most 64 `diagnostics` (`code`, JSON `pointer`, fixed `message`) and `diagnostics_truncated`. Diagnostics never repeat an input value. |
| `422` | `policy_candidate_invalid` | The candidate policy is invalid; `errors` are the policy validator's messages. |
| `422` | `policy_revision_incompatible` | The history version is not a policy this build and deployment accept now. |
| `429` | `policy_tests_busy` | Four runs are already evaluating on this replica, or this caller already has one running. Nothing was queued. |
| `500` | -- | The policy under test did not compile. No partial result. |
| `503` | -- | Cluster mode could not read the active policy, or (`policy_tests_deadline_exceeded`) the run did not finish within five seconds. No partial result. |
| `503` | `policy_drafts_unavailable`, `policy_history_unavailable` | The drafts store or the policy history the candidate names could not be read. |
| `503` | `policy_tests_unavailable` | The run names the stored suite, and no suite store is configured or it could not be read. |

Diagnostic codes: `invalid_type`, `missing_field`, `unknown_field`,
`forbidden_field`, `invalid_value`, `too_long`, `unsupported_schema_version`,
`empty_suite`, `too_many_cases`, `duplicate_case_id`, `invalid_case_id`,
`invalid_method`, `invalid_path`, `invalid_host`, `invalid_origin`,
`invalid_principal`, `inconsistent_case`, `unsupported_number`,
`fact_not_applicable`, `too_many_facts`.

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
    "tool_context_version": 1,
    "egress_semantics_version": "gg-static-egress-v1",
    "egress_context_version": 1
  },
  "synthetic_resources": {
    "egress_controls_digest": "sha256:...",
    "global_rate_lanes": "configured"
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
- `suite.stored` is present only when the run decided the stored suite:
  `{"version": <stored version>, "etag": "\"sha256:...\""}`. A suite sent
  with the run has no `stored` member, so its report is unchanged.
- `suite.digest` is the ADR-0004 semantic digest of the submitted suite: the
  RFC 8785 (JCS) bytes of the document, framed with the media type
  `application/vnd.greengateway.policy-tests+json` and version
  `policy-tests.v1`. The version defines no normalization beyond JCS, so member
  order and whitespace do not change it and any other change does.
- `policy.etag` is the active policy's ETag, or for a candidate the ETag it
  would have once written. `policy.source` is `active`, `inline_candidate`,
  `draft` or `revision` (or `publication` inside a
  [policy evidence package](policy-evidence.md)); cluster mode adds
  `security_revision` for the active policy. A `draft` adds the `draft_id` and
  the `draft_revision` it was read at, and a `revision` the `version`.
- Each case reports its `status` (`passed`, `failed`, `incomplete`, `error`),
  what was `expected`, what the evaluator answered in stable codes (`actual`,
  absent for `error`), which expectations did not hold (`mismatches`, in the
  order `logical`, `effect`, `reason`, `matched`, `rate_override`, `steps`),
  and for an evaluator refusal its stable `error` code. A sequence's step
  outcomes are `expected.steps` and `actual.steps`.
- `synthetic_resources` binds the egress controls egress cases were decided by
  by digest, and says whether the global rate lanes were available.

The report is deterministic: it has no timestamp or duration, so the same
policy and suite give the same bytes. It never contains a fixture value -- no
path, host, address, subject, issuer, role or tool name a case supplied -- only case
ids, expectations, stable codes and the matched rule id or route position.

### SARIF

`"format": "sarif"` answers `application/sarif+json`, SARIF 2.1.0 with tool
`greengateway-policy-tests`. There is one result per case that did not pass,
under the rule `policy-test/failed`, `policy-test/incomplete` or
`policy-test/error`, located by a logical location whose `name` is the case id
and whose `fullyQualifiedName` is its JSON Pointer. An empty `results` array
means every case passed; the run's `properties` carry `status`, the suite
digest, the policy source and ETag (with `policy_draft_id` and
`policy_draft_revision`, or `policy_version`, for a stored candidate), the
summary and `not_evaluated`, so an all-passing file is distinguishable from an
empty one.

### JUnit

`"format": "junit"` answers `application/xml`: one `testsuite` named
`policy-tests.v1` with a `testcase` per case (`classname` `policy.<kind>`,
`name` the case id). A failed or incomplete case carries a `failure`, a refused
one an `error`; nothing is ever `skipped`. The suite `properties` carry the run
status, suite digest, policy source and ETag, the evaluator versions and, for a
stored candidate, `policy_draft_id` and `policy_draft_revision` or
`policy_version`.

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
`security_revision` (cluster mode), for a stored candidate its
`policy_draft_id` and `policy_draft_revision` or its `policy_version`,
`suite_source` (`inline` or `stored`), `suite_version` (stored suites only),
`suite_digest`, `status`, the five summary counts and the evaluator semantics
versions. It never carries a case id, a fixture value, a matched rule or
policy content. Refused requests (`4xx`) are not recorded as runs.

Each stored or replaced suite emits one `policy.tests_changed` event with the
acting principal and the request envelope, `action` (`created` or
`replaced`), the new `version`, `suite_digest`, `previous_suite_digest` (`null`
for the first suite), `case_count`, `case_kinds` (the number of `http`, `tool`,
`tool_http`, `rate` and `egress` cases) and, in cluster mode, the `security_revision` the
write committed at. With `POLICY_TESTS_REQUIRED=true` it also carries
`active_policy`: the activation gate's answer for the active policy under the
new suite (`status`, `suite_version`, `suite_etag` and `summary`, as in a
[refusal](#requiring-the-stored-suite-before-activation)). It never carries a
case, a case id or a fixture value, and a refused write emits none. Cluster mode additionally records the write in
`greengateway.document_change_evidence` (action `policy_tests.publish`), in the
same transaction.

## Limits and what comes later

A run is synchronous and CPU-only: at most 512 cases, a body within
`MAX_BODY_SIZE` or 2 MiB, whichever is lower, that arrives within five seconds,
a five-second deadline on the evaluation, and at most four runs evaluating at
once per replica and one per caller, each on a blocking thread rather than an
async worker. A run is admitted only once its body is in hand, so an upload in
progress holds no slot, and its slot is held until the blocking evaluation
ends, even when the client disconnects first.

Not part of this slice, and not to be inferred from it:

- Gating bundle activation or a policy file reload on the stored suite (see
  [what the gate does not cover](#requiring-the-stored-suite-before-activation)).
- Typed claim, header, query, tool-argument and time-window matchers, and
  stable route and rate-override identifiers (policy v1).
- Running a suite offline. `ggctl policy test` (docs/ggctl.md) sends a suite
  to this endpoint and reports the gateway's run, as JSON or the gateway's
  own JUnit report; it does not run cases itself.

The admin UI's Policy Studio has a Test view over this API (#243 slice 18).
It keeps the suite in page memory only, runs it against the live policy under
`If-Match` or against the open draft's text as a candidate, and never shows an
incomplete or refused case as a pass. It does not read or write the stored
suite yet. See **Policy Studio workbench** in
[the configuration reference](configuration.md#policy_file).
