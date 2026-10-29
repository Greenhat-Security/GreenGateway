# Policy replay contexts

Historical replay asks what a policy -- the active one, or a candidate --
would have decided for traffic the gateway already served. Before any
replay can run, each retained record has to be turned into the facts the
policy evaluator reads, with every fact the record does not carry stated as
missing rather than guessed. A **replay context** is that record, and this
page describes its format, `replay-context.v1`, and how the gateway reads one
out of the audit events it writes today (issue #243, slice 12), and the
bounded [replay jobs](#replay-jobs) that decide a window of them again under
a candidate policy (slice 13).

The recorded-versus-candidate comparison (slice 14) is a later slice. Nothing
on the request path writes a replay context: every context comes from the
legacy adapters described below, is built in memory, and is never stored.

## What a replay context is, and what it is not

A replay context carries, for one HTTP request or one tool invocation:

- the **facts the policy evaluator reads** -- method and exact path, the
  principal, the request host, the routing classification and dispatch facts,
  the MCP identity, the tool name, and the egress destination -- each stated
  as recorded, absent or `not_recorded`;
- the **recorded result**: what the gateway's policy stage recorded at the
  time, under the evaluator and resources it ran then. It is a comparison
  aid, never an input to a replayed decision.

It does not carry anything the evaluator does not read. Source address, user
agent, request id, email, organization, session, headers, query values,
bodies and their shapes, response status, latency, upstream status, pool,
endpoint and attempts, tool arguments and results, rendered tool paths,
connection and assertion identifiers, and free-text errors have no member to
land in. A context is redacted by its shape, not by a filter that could miss
a field.

What it does keep -- subject, issuer, roles, the exact path, the host and the
routing facts -- it keeps because the evaluator decides on them, exactly as
recorded. Hashing or truncating them would change the answer. Keeping them
out of replay results, traces, audit and evidence is the job of the output
projection that later slices add; a replay context is input, not output, and
is handled with the same care as the audit records it comes from.

A replayed decision is the decision the evaluator makes for the recorded
facts. It is not a claim about what would happen to a new request: the
stages outside the policy verdict (authentication, request admission, rate
capacity, tool leases, egress resolution, transport, the upstream) are not
replayed, and a replay never reconstructs facts that were not recorded.

## The record

The published schema is
[`docs/schemas/replay-context.v1.schema.json`](schemas/replay-context.v1.schema.json).
The gateway's parser is authoritative: it dispatches the version exactly,
refuses unknown and repeated members everywhere, refuses a credential-shaped
member (`token`, `authorization`, `cookie`, `headers`, `email` and similar) by
name, and checks what JSON Schema cannot state -- byte lengths, the exact-path
and bare-host predicates, principal shape bounds, reason-code syntax and the
dispatch origin form. A serialized context is at most 128 KiB.

```json
{
  "schema_version": "replay-context.v1",
  "source": "http_observation",
  "facts": {
    "lane": "http",
    "method": "POST",
    "path": "/api/items/42",
    "principal": {
      "state": "authenticated",
      "subject": "user-1",
      "issuer": "https://issuer.example",
      "roles": ["writer"],
      "auth_method": "bearer_token"
    },
    "request_host": { "state": "present", "host": "api.example.test" },
    "routing": {
      "state": "proxy_dispatch",
      "route_id": "payments",
      "route_path_prefix": "/api",
      "upstream_origin": "https://payments.example.test"
    },
    "egress": { "state": "not_recorded" }
  },
  "recorded": {
    "policy": "allowed",
    "reason": "matched_rule",
    "permission": "items:write",
    "path_prefix": "/api"
  }
}
```

### Sources and lanes

| `source` | Lane | Read from |
| --- | --- | --- |
| `http_observation` | `http` | `http.request_observed` for an HTTP request |
| `tool_admission` | `tool` | `tool.invoke_start`, or the `tool.invoke_rejected` written at admission |
| `tool_rule_decision` | `tool` | `authz.denied` written when a tool-name rule refused an invocation |

An `http` context's facts serve the HTTP lane and rate-lane selection, which
reads the method, path and principal. A `tool` context replays the invocation
operation (`"operation": "invocation"`); no record states a visibility,
inventory or composite question.

### Fact states

| Fact | States | Meaning of `not_recorded` |
| --- | --- | --- |
| `principal` | `anonymous`; `authenticated` with `subject`, optional `issuer`, `roles` and `auth_method`; `not_recorded` | The record names a caller but not fully: an issuer it may have had, or an authentication mode no principal carries |
| `request_host` | `present` with `host`; `absent`; `not_recorded` | The record predates host capture. `absent` is a request with no usable `Host` |
| `routing` | `local` with an `mcp_identity`; `proxy_dispatch` with `upstream_origin` and optional `route_id`, `route_host`, `route_path_prefix`; `not_recorded` | Classification was not recorded, or not fully |
| `mcp_identity` | `canonical`; `alias` with `canonical_path`; `not_recorded` | The path could have been an MCP route alias and the record does not say |
| `egress` | `destination` with `scheme`, optional `host` and `port`, the `userinfo` and `fragment` flags, and `resolution`; `not_recorded` | No destination was recorded |

`method` and `path` (HTTP) and `tool_name` (tool) are always present: every
record a context is read from carries them. `upstream_origin` is either a
pooled route's logical `pool:` origin or a serialized URL origin, never a URL
with a path, query or userinfo. An egress destination says only whether its
URL had userinfo or a fragment, never what they were, and v1 carries no
resolution evidence: `resolution` is always `not_recorded`.

### The recorded result

| Member | Meaning |
| --- | --- |
| `policy` | `allowed`, `denied` or `would_deny` for an HTTP request; `admitted` or `denied` for a tool invocation. `admitted` means policy let the invocation through; whether a shadow rule also observed it is a separate record |
| `reason` | The policy stage's stable reason code, when recorded |
| `matched_rule_id`, `permission`, `path_prefix` | The element that decided, as recorded |
| `attribution_omitted` | Present, and `true`, when the record named a rule id or permission over 256 bytes: it is dropped and flagged, never cut |

A recorded `denied` with a reason such as `policy_evaluation_incomplete` or a
revision-check code is what the gateway recorded for a request its policy
stage refused to answer, not a policy denial; the reason says which.

v1 does not say which policy revision or evaluator version produced the
recorded result, because no audit record the adapters read carries either.
A replay can therefore compare a recorded result with a replayed one, but it
cannot attribute a difference to a policy change rather than an evaluator
change. Binding a record to a revision needs a record the gateway does not
write yet.

## Reading the audit records the gateway writes today

None of today's audit events was designed for replay. The legacy adapter reads
one stored event and answers with exactly one stable code, so a replay over a
window can always say how many records it could not use and why:

| Code | Meaning |
| --- | --- |
| `replayable` | The one replayable record of its request or invocation; a replay context |
| `duplicate_tool_observation`, `duplicate_http_decision`, `duplicate_tool_rule_decision`, `duplicate_tool_rejection`, `duplicate_tool_outcome` | Another record of the same request or invocation is the replayable one |
| `not_policy_evaluated` | The request never reached the policy stage (`policy_decision: not_evaluated`): refused by authentication, exempt from policy, or a probe |
| `unsupported_envelope_version` | An audit envelope version the adapter was not written for |
| `unsupported_rendered_tool_request` | A rendered tool request's decision record: its path carries tool arguments and is not adapted |
| `unsupported_tool_rejection` | A `tool.invoke_rejected` reason the adapter does not know, so it cannot say which record is the invocation's replayable one |
| `malformed_payload`, `malformed_method`, `malformed_path`, `malformed_principal`, `malformed_request_host`, `malformed_routing`, `malformed_tool_name`, `malformed_policy_decision`, `malformed_recorded_result` | A request record this gateway would not have written |
| `not_request_record` | Not a request or invocation record |

### One record per request and per invocation

A request or an invocation leaves several events, and replaying each would
count it several times. The adapter names exactly one of them replayable:

| Request or invocation | Replayable record | Duplicates |
| --- | --- | --- |
| HTTP request | `http.request_observed` | its `authz.*` decision |
| Tool invocation policy admitted | `tool.invoke_start`, or the `tool.invoke_rejected` (`queue_full`, `queue_timeout`, `cancelled`, `authority_unavailable`) written instead | a tool-rule `authz.allowed` or `authz.would_deny`, the outcome events, the tool's own `http.request_observed` |
| Tool invocation refused by its entry or the evaluator | `tool.invoke_rejected` (`unknown_tool`, `disabled`, `role_not_allowed`, `tool_name_out_of_bounds`, `policy_evaluation_incomplete`, `policy_evaluation_error`) | the tool's own `http.request_observed` |
| Tool invocation refused by a tool-name rule | the tool-rule `authz.denied` | the `tool.invoke_rejected` (`matched_rule`) beside it, the tool's own `http.request_observed` |

A `matched_rule` rejection is never the replayable record, because the
runtime writes the same rejection when a rendered HTTP rule refuses an
invocation it had already admitted, and the reason alone cannot tell the two
apart; the tool-rule decision or the invocation's start always exists beside
it. A test drives real invocations through the tool runtime and checks that
exactly one record of each is replayable.

An operational probe whose observation was suppressed
(`AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY`) leaves no replayable record.

### What the records establish

- **Envelope.** Events at audit schema `0.1.0` predate the actor's issuer, so
  an actor in one is `not_recorded`. `0.2.0` records the issuer whenever the
  principal had one. Any other version is unsupported until the adapter is
  reviewed for it.
- **Principal.** No actor is an anonymous request. An actor whose
  authentication mode is not one of `bearer_token`, `session_cookie`,
  `service_token` or `client_certificate` is `not_recorded`, not guessed.
- **Host and routing.** Observations record the routing classification
  (`routing_context_known`), the request host and the dispatch facts since the
  same change. An observation without `routing_context_known` records
  neither, so its host is `not_recorded`, not absent. A dispatch recorded
  without a route id predates route ids, which every dispatch now carries, so
  its routing is `not_recorded`.
- **MCP identity.** Never recorded. An MCP route alias is always the public
  URL's path with `/mcp` appended, so a locally classified path that does not
  end in `/mcp` is its own identity under every configuration. One that does
  (other than `/mcp` itself) is `not_recorded`.
- **Egress.** Never recorded. No record names the destination a request
  connected to or what it resolved to.
- **Tool callers.** A tool-rule decision record names the actor the tool
  runtime projected, which for a client certificate is none: the record names
  no actor, and replay judges that caller anonymous, as the lane did.

## Replaying a context

Each fact becomes the evaluator input it names, and nothing else: a recorded
fact reaches the evaluator unchanged and an unrecorded one reaches it as
missing, which the evaluator answers as `indeterminate` with a stable
limitation whenever a decision could turn on it -- never a no-match and never
an allow.

| Recorded | Evaluator input |
| --- | --- |
| principal `not_recorded`, `anonymous`, `authenticated` | missing, anonymous, the principal's subject, issuer, roles and method |
| request host `not_recorded`, `absent`, `present` | missing, absent, the host |
| routing `not_recorded` | an unclassified request: `missing_dispatch_fact` |
| routing `local`, identity `canonical` or `alias` | a contextless request, or an MCP alias decided under both identities |
| routing `local`, identity `not_recorded` | both readings; see below |
| routing `proxy_dispatch` | the classified dispatch with the recorded facts |
| egress `destination` | the destination with no resolution facts |

**MCP identity.** A record that does not say whether its path was an MCP
alias is decided under both readings, contextless and alias, and answers
only when they agree on everything a decision states: outcome, effect,
reason, the deciding element and any shadow observation. When they disagree
the answer is `indeterminate` with `missing_mcp_identity`. Choosing the
contextless reading would decide an alias request under the wrong
precedence order.

**Rate lane.** Rate-lane selection reads the recorded method, path and
principal, exactly as the live rate stage does, and an anonymous caller
reaches no override, as live. Which lane governed the request at the time,
and whether its bucket had capacity, was never recorded and is not
reconstructed.

**Tool lane.** A tool invocation's principal is projected the way the live
tool runtime projects an invocation's actor, through the runtime's own
function: `bearer_token`, `session_cookie` and `service_token` callers carry
their identity, and a `client_certificate` caller is judged anonymous there,
so it is here.

**Egress.** A recorded destination is decided with no resolution facts. A
destination the static checks refuse is refused; one they admit is
`indeterminate`, because the addresses it resolved to could still have
refused it. No replay performs a lookup.

## Replay jobs

`POST /v1{ADMIN_PREFIX}/policy/replays` starts a bounded job that decides one
window of the standalone audit log again under a candidate policy, through the
same evaluator the live adapters call, and reports what it decided as counts.
`GET /v1{ADMIN_PREFIX}/policy/replays/{id}` reads the job, its progress and,
once it has finished, its result; `DELETE` on the same path cancels a job that
has not finished and discards one that has.

Every route needs `admin:policy:read`, `admin:policy:simulate` and
`admin:audit:read`, checked before a body is read or a job is looked up. A job
is served only to the principal that started it (the same canonical issuer
and subject): anyone else gets the same `404 policy_replay_job_not_found` as
for a job that does not exist.

### The request

The request is a `policy-replay.v1` document, published as
[`docs/schemas/policy-replay.v1.schema.json`](schemas/policy-replay.v1.schema.json).
The gateway's parser is authoritative: it dispatches the version exactly and
refuses unknown, repeated and credential-shaped members.

```json
{
  "schema_version": "policy-replay.v1",
  "base_etag": "\"sha256:...\"",
  "candidate": { "source": "edits", "edits": [
    { "op": "insert", "section": "rules", "position": 0,
      "value": { "id": "lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" } }
  ] },
  "window": { "from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z" },
  "max_records": 50000,
  "idempotency_key": "nightly"
}
```

| Member | Meaning |
| --- | --- |
| `base_etag` | Required. The active policy's ETag the request was written against. A different active policy is `412 policy_replay_base_stale`, never a rebase |
| `candidate` | Required. `active` (the base itself), `edits` (1 to 64 position-aware edits over the base) or `inline` (a complete policy document), with exactly the members a [simulation](policy-simulation.md) candidate has. An edited or inline candidate is validated like a policy write and never stored |
| `window` | Required. `from` and optional `to`, RFC 3339 date-times with an offset; the window is `[from, to)` over audit timestamps. `to` defaults to the moment the job is created and may not be later; the window must begin before it ends and may cover at most 31 days |
| `max_records` | Optional. The most records the job reads, 1 to 100,000; 100,000 when omitted |
| `idempotency_key` | Optional. 1 to 128 ASCII letters, digits, `.`, `_`, `:` and `-`. A retry by the same principal with the same key and the same request bytes answers `200` with the job it already started, and starts nothing; the same key with a different request is `409 policy_replay_idempotency_conflict`. A key is remembered as long as its job is |

A request that passes is `202 Accepted`, with the job's representation and a
`Location` header naming it. An invalid one is `422 policy_replay_invalid`
with structured diagnostics (or `policy_candidate_invalid` for a candidate a
policy write would refuse), and creates no job.

### The snapshot a job reads

When a job is created, before it is queued, the gateway fixes its **cutoff**:
the newest audit row id stored at that moment (`high_water`) and how many rows
of the window are at or below it (`selected_records`). Audit row ids only grow,
so a record written after the cutoff -- including one the audit writer had not
flushed yet, whatever its timestamp -- never enters the job. A row whose
timestamp did not parse when it was stored belongs to no window.

The job reads the window oldest first, in pages, each its own read
transaction on a read-only connection of its own, so it holds no snapshot
between pages and cannot write to the log it reads. When it has read the
window it counts the window's rows again: if retention pruned rows the cutoff
selected while the job ran, the result says `source_changed` and is
incomplete, never silently short. A window reaching back past audit retention
simply holds fewer rows; the cutoff's count says how many.

### Bounds

| Bound | Value | When reached |
| --- | --- | --- |
| Records read | `max_records`, at most 100,000 | The scan stops; `scan_truncated` |
| Run time | 60 seconds | The scan stops; `deadline_exceeded` |
| One page | 500 rows, and 4 MiB of their JSON past the first row | The next page continues |
| One row | 256 KiB of actor and payload JSON | Counted as `oversized_record`; its JSON is never read |
| Running jobs | 1 per replica, on a blocking thread | Further jobs are `queued` |
| Queued or running jobs | 4 per replica, 1 per principal | `429 policy_replay_busy` |
| Request body arrival | 5 seconds | `408 policy_replay_request_timeout` |
| Unexpired jobs held | 32 per replica, 8 per principal | `429 policy_replay_quota_exhausted` |
| Finished job kept | 15 minutes after it finishes | The job reads `expired`, with no result |
| Expired job remembered | 1 hour after that | `404` |
| Request body | 2 MiB, or `MAX_BODY_SIZE` if lower | `413` |

No job is ever evicted to make room for another. A stopped scan is still a
result, an incomplete one whose counts cover what was read; it is never a
complete answer.

A job is admitted the way a [policy test run](policy-tests.md) or a
[simulation](policy-simulation.md) is, through the same per-replica and
per-principal bound, which the replay route keeps for itself: only once its
body is in hand, so an upload still arriving holds no slot, and then for as
long as its evaluation lasts. The job holds its slot while it is queued and
hands it to the blocking thread that runs it, so the slot comes back only
when that work has ended -- neither a dropped request nor a cancellation
frees it early -- and before the job reads as finished. A retry naming a job
already admitted is answered before a slot is asked for.

### Lifecycle

`queued`, then `running`, then one of:

| State | Meaning |
| --- | --- |
| `completed` | Every record the cutoff selected was read and classified, the window was unchanged at the end, and at least one record was replayed |
| `completed_incomplete` | A result whose `limitations` say what it does not cover: `scan_truncated`, `deadline_exceeded`, `source_changed`, or `no_data` when nothing in the window was replayable. It satisfies no gate |
| `failed` | No result, with a stable `failure.reason`: `source_unavailable`, `compile_failed`, `evaluator_failed` (the evaluator broke its own contract; nothing it counted is an answer), `result_too_large`, `audit_unavailable` or `internal` |
| `cancelled` | No result. A queued job stops at once; a running one before its next record |
| `expired` | 15 minutes have passed since the job finished: its result, if it had one, is gone, and it no longer counts against any quota |

`completed` does not mean every record was decided: records the candidate
answered `indeterminate`, records the adapters could not use and records the
evaluator refused are all counted, by code.

Every job leaves exactly its own lifecycle records: `policy.replay_started`
when it is admitted, and one of `policy.replay_completed`,
`policy.replay_cancelled` or `policy.replay_failed` when it ends. They carry
the job id, the base and candidate ETags, the request digest, the window and
cutoff, counts, limitation codes and the result digest -- never a record, a
principal, a path or policy content -- and the envelope of the request that
started the job. A job is queued only once the audit log accepts its start
(otherwise `503 policy_replay_audit_unavailable`, and no job), and its result
is published only once the audit log accepts its completion: a result whose
completion is not accepted is `failed` with `audit_unavailable`. "Accepted"
is what `AUDIT_DURABILITY` makes it: committed to the audit store under
`required`, queued for the writer under `best_effort`.

### Status codes

| Status | When |
| --- | --- |
| `202` | `POST`: the job is queued. `DELETE`: cancellation of a queued or running job was requested |
| `200` | `GET`: the job. `POST`: an idempotent retry, naming the job it already started |
| `204` | `DELETE`: a finished job was discarded |
| `400` | A body that is not JSON, or repeats a member (`policy_replay_request_invalid`) |
| `401`, `403` | Not authenticated, or missing one of the three permissions; nothing is read or started |
| `404` | No such job for this principal (`policy_replay_job_not_found`) |
| `409` | An idempotency key reused for a different request |
| `408` | The body did not arrive within five seconds (`policy_replay_request_timeout`). Nothing was started |
| `412` | `base_etag` is not the active policy's ETag |
| `413` | The body is over its bound |
| `422` | An invalid request, window, edit or candidate |
| `429` | `policy_replay_busy` or `policy_replay_quota_exhausted` |
| `503` | `audit_evidence_unavailable` (no standalone audit log, or it could not be read), `policy_replay_audit_unavailable` (the start was not recorded), or `policy_replay_unsupported_in_cluster` |

A job's representation is always sent with `Cache-Control: no-store`.

### The result

A job's representation (`policy-replay-job.v1`) states its state, the
evaluator and gateway versions, the base ETag and whether it is still the
active one (`base.current`: a result stays the answer for the policies it was
pinned to, and is stale for the live one once that changes), the candidate's
source and ETag, the window, the cutoff, the limits applied and its progress.
A finished job adds `result_digest` and `result`, a
`policy-replay-results.v1` document:

```json
{
  "schema_version": "policy-replay-results.v1",
  "mode": "historical_replay",
  "complete": true,
  "limitations": [],
  "source": {
    "kind": "standalone_audit_log",
    "window": { "from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z" },
    "high_water": 18734,
    "max_records": 50000
  },
  "records": {
    "selected": 9, "scanned": 9, "replayable": 8, "duplicate": 1,
    "not_policy_evaluated": 0, "unsupported": 0, "malformed": 0,
    "not_request_record": 0, "unreadable": 0, "oversized": 0,
    "by_code": { "duplicate_http_decision": 1, "replayable": 8 }
  },
  "replayed": {
    "total": 8,
    "http": {
      "replayable": 7, "decided": 7, "indeterminate": 0, "refused": 0,
      "outcomes": [
        { "logical": "allow", "enforcement": "not_applicable",
          "effective_action": "would_forward", "reason": "matched_rule", "count": 4 },
        { "logical": "deny", "enforcement": "enforced",
          "effective_action": "would_block", "reason": "matched_rule", "count": 3 }
      ],
      "limitations": {}, "refusals": {}, "egress_not_replayed": 0
    },
    "rate": { "no_override": 3, "override": 4, "indeterminate": 0, "refused": 0,
              "limitations": {}, "refusals": {} },
    "tool": { "replayable": 1, "decided": 1, "indeterminate": 0, "refused": 0,
              "outcomes": [], "limitations": {}, "refusals": {},
              "egress_not_replayed": 0 }
  },
  "not_replayed": ["authentication", "request_admission", "rate_capacity",
                   "tool_leases", "egress", "transport", "upstream"]
}
```

(The tool lane's `outcomes` are abbreviated above; they have the HTTP lane's
shape.)

- **`records`** classifies every row read: the adapter code of each, as in
  [Reading the audit records the gateway writes today](#reading-the-audit-records-the-gateway-writes-today),
  plus `unreadable_record` (actor or payload JSON that does not parse) and
  `oversized_record`.
- **`replayed`** is the candidate's answer for every replayable record, per
  lane: decided outcomes counted by logical decision, enforcement, effective
  action and reason, in the [simulation](policy-simulation.md)'s vocabulary,
  so a shadowed deny is never counted as an allow; `indeterminate` answers by
  limitation code (`missing_principal_fact`, `missing_dispatch_fact`,
  `missing_mcp_identity` and the rest); and `refused` records, whose facts
  the evaluator refused because no served request could have left them.
  `rate` is rate-lane selection for the HTTP records: which override the
  candidate would select, never whether a bucket had capacity.
- **`not_replayed`** names the stages a replay does not include. v1 records
  carry no egress destination, so egress is never replayed.

A result holds counts and stable codes only. It repeats no subject, issuer,
path, host, request id, source address, user agent, rule id or other value
from a record. Every count is keyed by a code from a closed set and rendered
sorted, and `result_digest` is the ADR-0004 semantic digest
(`application/vnd.greengateway.policy-replay-results+json`,
`policy-replay-results.v1`) of the result: two complete jobs over the same
cutoff, candidate and evaluator produce byte-identical results, however the
log was paged. A job stopped by its deadline is the one exception, and says
so.

A result reports what the candidate decides for the records. It does not yet
compare that with what was recorded or with the active policy: that is the
impact comparison (slice 14), and only it can support the statement "No newly
allowed decisions were observed among N replayable events". No replay result
says a policy is safe.

### Standalone only, and process-local

Jobs live in the memory of the replica that admitted them, and run there.
Shutting the gateway down cancels every job, and a running one stops before
its next record. A restart forgets every job: its id is `404` afterwards,
never resumed and never a partial result. Cluster mode answers every replay
route `503 policy_replay_unsupported_in_cluster`, after the permission checks
and before a body is read, a cutoff fixed or a job admitted: a replicated job
needs the durable leases of #241, and the cluster audit authority is
PostgreSQL, which no replay reader covers yet. Without a
standalone audit log (`AUDIT_SQLITE_PATH` unset) the start route is
`503 audit_evidence_unavailable`, never an empty result.

### In the admin UI

The Policy Studio's Impact view (#243 slice 18) starts jobs over the live
policy or the open draft's text, polls them, cancels or discards them, and
shows a result's records by classification and its decisions per lane. It
lists only the jobs started in the page. A start whose answer was lost is
checked by sending the same request under the same idempotency key, never
retried as a new job. An incomplete result is labelled as satisfying no gate,
`no_data` is shown as no decisions rather than as zero, and the view states
that a replay does not compare its decisions with recorded ones yet. See
**Policy Studio workbench** in
[the configuration reference](configuration.md#policy_file).

### Side effects

A job reads the audit log, and that is all it does outside its own memory. It
writes nothing, emits no audit event but its lifecycle records and no metric
but its requests' own admission metrics, reads or charges no rate bucket,
acquires no tool permit, resolves no name and contacts no upstream. A test
replays retained records that, live, would charge a one-request rate bucket,
record a would-deny, admit a tool and reach an upstream, and checks that the
job left only its two lifecycle records, moved no metric beyond its requests'
own, charged no bucket, reached no upstream and wrote no row to the log --
then sends the same request live to show each of those checks can fail.

## How this is verified

- Real requests through the live RBAC and observation middleware, across
  enforce and shadow policies, contextless, unclassified, proxy-dispatched,
  host-bound and MCP-alias requests and every authentication method, are
  observed, adapted and replayed: every fact the adapter read is the
  request's, the recorded result is the live decision, and every replayed
  decision is the live one or `indeterminate` for a stated reason -- never a
  different answer.
- Real invocations through the tool runtime are adapted the same way: exactly
  one record of each is replayable, and its replayed admission is the live
  one.
- Canary values in every member the evaluator does not read never appear in
  a serialized context or its formatting.
- Every context round-trips through the parser, matches the published
  schema, and the parser and the schema refuse the same malformed contexts.
- A replay job's engine is run over in-memory and SQLite audit logs: a window
  touching every classification and lane is counted by stable code; rows
  written after the cutoff are never read; the record bound, the deadline,
  pruning during a run and an empty window each give an incomplete result
  with their own limitation; cancellation and a failing source give no result;
  oversized and unreadable rows are counted without their JSON being read; the
  same cutoff and candidate give byte-identical results however the log is
  paged; no result repeats a record value; and the run records no metric.
- Through the application: every route refuses a caller missing any of its
  three permissions, and serves a job only to its owner; a stale base, an
  invalid window, edit or candidate creates no job; an idempotent retry starts
  nothing; queued jobs are cancelled, quotas refuse rather than evict, and
  results expire; a stalled upload holds no admission slot and is refused at
  its deadline, and a job holds its slot until its evaluation ends; in cluster mode every route answers `503` without reading a
  body, admitting a job, recording a lifecycle event or consulting the
  cluster authority; and the side-effect test above holds.
- The `policy-replay.v1` parser and its published schema accept and refuse
  the same requests.
