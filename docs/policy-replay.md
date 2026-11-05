# Policy replay contexts

Historical replay asks what a policy -- the active one, or a candidate --
would have decided for traffic the gateway already served. Before any
replay can run, each retained record has to be turned into the facts the
policy evaluator reads, with every fact the record does not carry stated as
missing rather than guessed. A **replay context** is that record, and this
page describes its format, `replay-context.v2`, and how the gateway reads one
out of the audit events it writes (issue #243, slice 12), the
[decision facts](#decision-facts) the request path records beside each
verdict so a replay can tell what decided it, the bounded
[replay jobs](#replay-jobs) that decide a window of them again under
a candidate policy (slice 13), and the [impact comparison](#impact-comparison)
that compares those answers with the active policy the candidate was written
against and with what was recorded (slice 14).

Nothing on the request path writes a replay context: every context comes from
the legacy adapters described below, is built in memory, and is never stored.
What the request path does write, beside each verdict, is its decision facts:
codes, versions and digests that say which policy and evaluator decided, and
nothing a request carried.

## What a replay context is, and what it is not

A replay context carries, for one HTTP request or one tool invocation:

- the **facts the policy evaluator reads** -- method and exact path, the
  principal, the request host, the routing classification and dispatch facts,
  the MCP identity, the tool name, and the egress destination -- each stated
  as recorded, absent or `not_recorded`;
- the **recorded result**: what the gateway's policy stage recorded at the
  time, under the evaluator and resources it ran then, and -- for a record
  written since the gateway records them -- the
  [decision facts](#decision-facts) it was decided with. It is a comparison
  aid, never an input to a replayed decision; the
  [impact comparison](#recorded-against-base) is what compares it. (One
  decision fact, the routing classification, also settles the MCP identity an
  observation leaves unstated; see [What the records establish](#what-the-records-establish).)

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
[`docs/schemas/replay-context.v2.schema.json`](schemas/replay-context.v2.schema.json).
The gateway's parser is authoritative: it dispatches the version exactly,
refuses unknown and repeated members everywhere, refuses a credential-shaped
member (`token`, `authorization`, `cookie`, `headers`, `email` and similar) by
name, and checks what JSON Schema cannot state -- byte lengths, the exact-path
and bare-host predicates, principal shape bounds, reason-code syntax, the
dispatch origin form, the `facts_available` bits each lane may set, and that
`recorded.decision` describes its own record. A serialized context is at most
128 KiB.

`replay-context.v2` is `replay-context.v1`
([schema](schemas/replay-context.v1.schema.json)) with one optional member,
`recorded.decision`. The parser still reads v1 exactly as it was published --
a v1 context with `recorded.decision` is refused, since v1 has no member for
it -- and writes v2.

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
    "path_prefix": "/api",
    "decision": {
      "schema_version": "policy-decision.v1",
      "lane": "http",
      "policy_etag": "\"sha256:...\"",
      "policy_semantic_digest": "sha256:...",
      "semantics_version": "gg-http-alias-v1",
      "context_version": 3,
      "facts_available": 31,
      "routing": "proxy_dispatch",
      "reason": "matched_rule",
      "element": { "kind": "route", "position": 0, "id": "payments" }
    }
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
| `decision` | The record's [decision facts](#decision-facts), exactly as written, when it carries them; absent for a record from before them and for a request the policy stage refused to answer |

A recorded `denied` with a reason such as `policy_evaluation_incomplete` or a
revision-check code is what the gateway recorded for a request its policy
stage refused to answer, not a policy denial; the reason says which.

A record without `decision` does not say which policy or evaluator produced
its result, so a replay can compare it with a replayed answer but cannot
attribute a difference to a policy change rather than an evaluator change.
One with `decision` names both, and the
[impact comparison](#recorded-against-base) labels such a difference
accordingly.

## Decision facts

Beside each policy verdict, the gateway records the facts it was decided with:
a `policy_decision_facts` member, in the `policy-decision.v1` format, on

- `http.request_observed`, for a request the HTTP policy stage answered;
- `tool.invoke_start`, and the `tool.invoke_rejected` written at admission --
  an entry's refusal, a tool-name rule's denial, or a capacity or lease
  refusal after policy admitted the call;
- a tool-name rule's `authz.allowed`, `authz.would_deny` and `authz.denied`.

```json
"policy_decision_facts": {
  "schema_version": "policy-decision.v1",
  "lane": "tool",
  "policy_etag": "\"sha256:...\"",
  "semantics_version": "gg-tool-policy-v1",
  "context_version": 1,
  "facts_available": 36,
  "reason": "matched_rule",
  "element": { "kind": "rule", "position": 4, "id": "deny-exports" }
}
```

| Member | Meaning |
| --- | --- |
| `schema_version` | Exactly `policy-decision.v1`. A reader dispatches on it; any change to what the member states is a new version |
| `lane` | `http` or `tool` |
| `policy_etag` | The ETag the admin API reports for the installed policy that decided: the one `GET .../policy` sends and a replay's `base_etag` names |
| `policy_semantic_digest` | That policy's ADR-0004 semantic digest, the one `POST .../policy/validate` reports. Absent for a 0.x policy, which has no normative normalization and so no semantic digest |
| `semantics_version`, `context_version` | The evaluator's semantics version (`gg-http-alias-v1` for the HTTP lane, `gg-tool-policy-v1` for the tool lane) and the version of the evaluation context it was given |
| `facts_available` | Which of the evaluator's inputs it had, as the bits below |
| `routing` | HTTP only: `unclassified`, `contextless`, `mcp_alias` (an MCP route alias, decided under the canonical `/mcp` identity as well) or `proxy_dispatch` |
| `reason` | The verdict's stable reason code: the observation's `policy_reason`, or the invocation's |
| `element` | The deciding element: `rule` or `route` with its `position` in that policy and its authored `id` (`id_omitted: true` instead, for one over 256 bytes), or `default`, `host_binding`, `tool_entry` (the invoked tool's entry, which the record names) or `no_tool_entry` |

`facts_available` sets one bit per input the evaluator was given, whatever its
value -- an anonymous principal and an absent `Host` are available -- and
leaves clear one it decided without. The positions are part of the version
and never reused:

| Bit | Value | Input |
| --- | --- | --- |
| 0 | 1 | method |
| 1 | 2 | path |
| 2 | 4 | principal |
| 3 | 8 | routing classification |
| 4 | 16 | request host |
| 5 | 32 | tool name |
| 6 | 64 | organization |
| 7 | 128 | client address |
| 8 | 256 | headers |
| 9 | 512 | query |
| 10 | 1024 | tool arguments |
| 11 | 2048 | clock |

Today an HTTP verdict sets method, path, principal, request host and, for a
classified request, routing (`31`); a tool invocation sets tool name and
principal (`36`). Either adds the organization (`64`) under a policy whose
roles come from identity mappings, which read the organization the
principal's issuer verified. No serving lane captures the client address,
headers, query, tool arguments or clock yet, so those bits stay clear.

A request the policy stage refused to answer -- an unsafe path, an
incomplete or failed evaluation, a failed revision check, an audit outage --
carries no decision facts, nor does a request that never reached the stage.
Neither does a decision made outside it, such as an admin endpoint's own
permission refusal. If an installed policy's identity cannot be computed,
which a validated policy always allows, its verdicts are recorded without
facts and an error is logged: never under a guessed identity.

**Cost on the request path.** A snapshot's identity -- ETag, semantic digest
and element ids -- is computed once, when the snapshot is installed, from the
policy its compiled instance holds, and shared by every verdict. A verdict
adds one reference count and a fixed-size value of codes, versions and
positions, and allocates nothing for them; the member is serialized where the
observation or tool record is written. The kernel calls the `http_policy`
and `tool_policy` microbenchmarks measure are unchanged.

**Storage.** The member is part of the stored payload JSON -- SQLite's
`payload_json` column and PostgreSQL's `payload_json` `jsonb` column -- so no
table, column, index or migration changed, and the audit envelope stays at
`0.2.0`. The member carries its own version instead. Readers that do not know
it ignore it, as they ignore every payload member they do not read.

### Privacy

Decision facts add no personal data to a record. They hold the policy's own
identity (ETag, semantic digest, element positions and authored ids), the
evaluator's versions, a bit set and closed codes. They hold no source
address, request id, user agent, email, subject, issuer, role, organization,
header, query value, body, tool argument, path, host, route, upstream or
error: the bit set says whether an input was present, never what it was.
Whatever personal data a record already carries stays in the members it
always had, under the same retention and access. A replay context keeps the
facts as recorded; a [replay result](#privacy-projection) never repeats them,
and counts records by what their facts establish instead.

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
| `unsupported_decision_facts_version` | Decision facts of a version the adapter was not written for |
| `unsupported_rendered_tool_request` | A rendered tool request's decision record: its path carries tool arguments and is not adapted |
| `unsupported_tool_rejection` | A `tool.invoke_rejected` reason the adapter does not know, so it cannot say which record is the invocation's replayable one |
| `malformed_payload`, `malformed_method`, `malformed_path`, `malformed_principal`, `malformed_request_host`, `malformed_routing`, `malformed_tool_name`, `malformed_policy_decision`, `malformed_recorded_result`, `malformed_decision_facts` | A request record this gateway would not have written |
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
- **MCP identity.** Not recorded by an observation's own members. An MCP
  route alias is always the public URL's path with `/mcp` appended, so a
  locally classified path that does not end in `/mcp` is its own identity
  under every configuration. One that does (other than `/mcp` itself) is
  `not_recorded` -- unless the record's decision facts state the routing
  classification: `contextless` is its own identity, and `mcp_alias` an alias
  of `/mcp`, the canonical identity every alias is decided under.
- **Decision facts.** Read into the recorded result exactly, when present.
  They must describe the record they sit on: its lane; its recorded reason
  (an invocation policy admitted records none, and its facts name `allowed`
  or `matched_rule`); and, for an observation, its routing -- `unclassified`
  for an unclassified request, `contextless` or `mcp_alias` for a local one,
  `proxy_dispatch` for a dispatch with a route id. Anything else is
  `malformed_decision_facts`, and another version
  `unsupported_decision_facts_version`. A record without them is read as
  before.
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
| routing `local`, identity `not_recorded` | both readings; see below. Only a record without decision facts has this state |
| routing `proxy_dispatch` | the classified dispatch with the recorded facts |
| egress `destination` | the destination with no resolution facts |
| organization (never recorded) | not recorded: an identity mapping that tests `organizations` is `missing_matcher_fact` |

**MCP identity.** A record that does not say whether its path was an MCP
alias is decided under both readings, contextless and alias, and answers
only when they agree on everything a decision states: outcome, effect,
reason, the deciding element and any shadow observation. When they disagree
the answer is `indeterminate` with `missing_mcp_identity`. Choosing the
contextless reading would decide an alias request under the wrong
precedence order.

**Identity mappings.** A record carries no organization, so replay leaves
the organization not recorded rather than read it as none: a principal whose
internal roles turn on a mapping that tests `organizations` is
`indeterminate` with `missing_matcher_fact` in every lane, where live it was
decided by the organization its provider verified. Mappings that test only
the issuer, authentication method, subject and claimed roles replay as they
are served.

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
window of the standalone audit log again under a candidate policy and under
the active policy it was written against, through the same evaluator the live
adapters call, and reports what each decided and how they differ as counts.
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
  "projections": ["as_authored", "enforce_all_shadow"],
  "max_records": 50000,
  "idempotency_key": "nightly"
}
```

| Member | Meaning |
| --- | --- |
| `base_etag` | Required. The active policy's ETag the request was written against. A different active policy is `412 policy_replay_base_stale`, never a rebase |
| `candidate` | Required. `active` (the base itself), `edits` (1 to 64 position-aware edits over the base), `inline` (a complete policy document), `draft` (one of your server-side drafts, by `draft_id` and `draft_etag`) or `revision` (a policy history `version`), with exactly the members a [simulation](policy-simulation.md) candidate has. An edited or inline candidate is validated like a policy write and never stored; a draft or history version is read, owner-scoped and validated again, and never written, as [a simulation reads one](policy-simulation.md#drafts-and-history-versions), when the job is created |
| `window` | Required. `from` and optional `to`, RFC 3339 date-times with an offset; the window is `[from, to)` over audit timestamps. `to` defaults to the moment the job is created and may not be later; the window must begin before it ends and may cover at most 31 days |
| `projections` | Optional. The [simulation](policy-simulation.md)'s projections the [impact comparison](#impact-comparison) is reported under, each named once: `as_authored`, `enforce_all_shadow` or both. `["as_authored"]` when omitted |
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

### The cluster reader

In cluster mode the audit authority is PostgreSQL's `audit_events` and its
commit-ordered `audit_stream`, and the reader over them
(`storage::postgres_audit_replay`) answers the job engine exactly as the
standalone reader does. Cluster mode still answers every replay route `503`
(see [below](#standalone-only-and-process-local)); the reader is what a cluster
job will read.

- **Cutoff.** `high_water` is the highest stream position assigned when the
  job is created, read in the same statement as the window's rows at or below
  it. A writer cannot take a stream position until the writer before it has
  committed, so every position at or below the cutoff was committed when it
  was read, and an event committed later -- whatever its timestamp, including
  one a replica had not flushed yet -- has a higher position and never enters
  the job.
- **Pages.** The job walks the stream by position above the last row it read
  and at or below the cutoff, keeping the events inside `[from, to)`, with the
  standalone page and row bounds. An oversized row's JSON never leaves the
  database. An actor that is not the shape the audit sink writes is
  `unreadable_record`. Every other row goes to the same adapters, so malformed
  and legacy records get the same codes.
- **Pruning and gaps.** Stream positions are gapless from 1 and never
  renumbered, so a missing position at or below the cutoff is a deleted event.
  When the job has read its window it counts the window's rows again (rows gone
  since the cutoff are `source_changed`, as standalone) and checks every
  position from the newest retained event older than the window to the oldest
  retained event at or after its end, across every position the cutoff
  selected. When no event older than the window is retained, the check starts
  at position 1. Any missing position makes the result `completed_incomplete`
  with `source_pruned`, whether retention reached past the window's start
  before or during the job, or a row was removed from inside it. A window that
  retention emptied is `source_pruned` as well as `no_data`. The check relies
  on commit order: an event deleted below the newest retained event older than
  the window is taken to be older than the window.
- **Sharing the database.** Every read checks a connection out under its own
  pool class, `policy_replay` (timed in
  `greengateway_database_pool_acquire_seconds`). It runs in a short read-only
  transaction with `SET LOCAL` bounds: 10 seconds per statement and 1 second
  per lock wait, or the session's `DATABASE_STATEMENT_TIMEOUT_MS` and
  `DATABASE_LOCK_TIMEOUT_MS` when those are shorter. A job holds one
  connection per replica, for one statement or two at a time. It keeps no
  snapshot between pages, takes only the shared lock every read takes and
  never the stream's write lock, and gives its connection back rather than
  wait behind a migration. Request decisions, the audit writer and retention
  never queue behind it. The cutoff and the closing check count the window's
  rows, so a window too large to count within the statement bound fails
  (`503` when the job is created, `source_unavailable` at its end) rather than
  being cut short.
- **Errors** are classified where they happen and logged there. No SQL, window
  bound, position or record value reaches the job, its result or its
  lifecycle records.

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
| Impact rows | 64 transition-matrix rows and 32 changed-element rows per lane and projection; 64 rows per lane of the recorded comparison | Further rows are counted in `matrix_omitted` or `changed_elements_omitted`; every transition count stays complete |
| Result | 512 KiB rendered | `failed` with `result_too_large`, never a cut result |

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
| `completed_incomplete` | A result whose `limitations` say what it does not cover: `scan_truncated`, `deadline_exceeded`, `source_changed`, `source_pruned` (cluster audit stream only: rows the window may have held are gone), or `no_data` when nothing in the window was replayable. It satisfies no gate |
| `failed` | No result, with a stable `failure.reason`: `source_unavailable`, `compile_failed`, `evaluator_failed` (the evaluator broke its own contract; nothing it counted is an answer), `result_too_large`, `audit_unavailable` or `internal` |
| `cancelled` | No result. A queued job stops at once; a running one before its next record |
| `expired` | 15 minutes have passed since the job finished: its result, if it had one, is gone, and it no longer counts against any quota |

`completed` does not mean every record was decided: records the candidate
answered `indeterminate`, records the adapters could not use and records the
evaluator refused are all counted, by code.

Every job leaves exactly its own lifecycle records: `policy.replay_started`
when it is admitted, and one of `policy.replay_completed`,
`policy.replay_cancelled` or `policy.replay_failed` when it ends. They carry
the job id, the base and candidate ETags, the request digest, the projections,
the window and cutoff (the start also names a stored candidate by its
`candidate_draft_id` and `candidate_draft_revision`, or its
`candidate_version`), counts (the completion's `impact` member counts newly
allowed, newly denied, enforcement-only, newly forwarded, newly blocked,
indeterminate and unsupported records per projection), limitation codes and
the result digest -- never a record, a principal, a path, an element id or
other policy content -- and the envelope of the request that started the
job. A job is queued only once the audit log accepts its start
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
| `404` | No such job for this principal (`policy_replay_job_not_found`), or a stored candidate that is not there (`policy_draft_not_found`, `policy_revision_not_found`, or no policy history) |
| `409` | An idempotency key reused for a different request, or a draft candidate pinned to another base than `base_etag` (`policy_draft_base_stale`) |
| `408` | The body did not arrive within five seconds (`policy_replay_request_timeout`). Nothing was started |
| `410` | The draft candidate has expired (`policy_draft_expired`) |
| `412` | `base_etag` is not the active policy's ETag, or the draft candidate's `draft_etag` is no longer the draft's (`policy_draft_stale`) |
| `413` | The body is over its bound |
| `422` | An invalid request, window, edit or candidate, or a history version this build does not accept now (`policy_revision_incompatible`) |
| `429` | `policy_replay_busy` or `policy_replay_quota_exhausted` |
| `503` | `audit_evidence_unavailable` (no standalone audit log, or it could not be read), `policy_replay_audit_unavailable` (the start was not recorded), `policy_replay_unsupported_in_cluster`, or a drafts store or policy history that could not be read (`policy_drafts_unavailable`, `policy_history_unavailable`) |

A job's representation is always sent with `Cache-Control: no-store`.

### The result

A job's representation (`policy-replay-job.v1`) states its state, the
evaluator and gateway versions, the base ETag and whether it is still the
active one (`base.current`), its `freshness`, the candidate's source and
ETag (with the `draft_id` and `draft_revision`, or the `version`, of a stored
candidate), the projections, the window, the cutoff, the limits applied and its
progress. A finished job adds `result_digest` and `result`, a
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
  "impact": {
    "candidate_is_base": false,
    "projections": { "as_authored": { "statement": {}, "http": {}, "tool": {} } },
    "rate": {},
    "recorded": { "http": {}, "tool": {} }
  },
  "not_replayed": ["authentication", "request_admission", "rate_capacity",
                   "tool_leases", "egress", "transport", "upstream"]
}
```

(The tool lane's `outcomes` are abbreviated above; they have the HTTP lane's
shape. `impact` is described in [Impact comparison](#impact-comparison).)

`freshness` says whether the result describes the live policy:

| `freshness.state` | Meaning |
| --- | --- |
| `current` | The active policy is still the job's base |
| `stale` | `reason: base_changed`: the active policy changed after the job was pinned. The result stays the answer for the policies it was pinned to, but it is not evidence about the live policy, and must not be reused to justify a change to it: start a new job |
| `unknown` | This response did not check (a cancellation's `202`, or a retry that raced its job's admission) |

- **`source`** names what was read -- `standalone_audit_log`, or
  `cluster_audit_stream` for the [cluster reader](#the-cluster-reader), whose
  `high_water` is a stream position rather than a row id -- with the window,
  the cutoff and the record bound.
- **`records`** classifies every row read: the adapter code of each, as in
  [Reading the audit records the gateway writes today](#reading-the-audit-records-the-gateway-writes-today),
  plus `unreadable_record` (actor or payload JSON that does not parse) and
  `oversized_record`.
- **`replayed`** is the candidate's answer, as authored, for every
  replayable record, per lane: decided outcomes counted by logical decision,
  enforcement, effective action and reason, in the
  [simulation](policy-simulation.md)'s vocabulary, so a shadowed deny is never
  counted as an allow; `indeterminate` answers by
  limitation code (`missing_principal_fact`, `missing_dispatch_fact`,
  `missing_mcp_identity` and the rest); and `refused` records, whose facts
  the evaluator refused because no served request could have left them.
  `rate` is rate-lane selection for the HTTP records: which override the
  candidate would select, never whether a bucket had capacity.
- **`not_replayed`** names the stages a replay does not include. v1 records
  carry no egress destination, so egress is never replayed.

A result holds counts and stable codes, and names policy elements only as
the [impact comparison](#privacy-projection) does: by position in the base or
the candidate, with the element's own id. It repeats no subject, issuer,
path, host, request id, source address, user agent, recorded rule id or other
value from a record. Every count is keyed by a code from a closed set or by a
policy element and rendered sorted, and `result_digest` is the ADR-0004
semantic digest (`application/vnd.greengateway.policy-replay-results+json`,
`policy-replay-results.v1`) of the result: two complete jobs over the same
cutoff, base, candidate, projections and evaluator produce byte-identical
results, however the log was paged. A job stopped by its deadline is the one
exception, and says so. No replay result says a policy is safe.

### Standalone only, and process-local

Jobs live in the memory of the replica that admitted them, and run there.
Shutting the gateway down cancels every job, and a running one stops before
its next record. A restart forgets every job: its id is `404` afterwards,
never resumed and never a partial result. Cluster mode answers every replay
route `503 policy_replay_unsupported_in_cluster`, after the permission checks
and before a body is read, a cutoff fixed or a job admitted: a replicated job
needs the durable leases of #241. The [cluster reader](#the-cluster-reader)
over PostgreSQL's audit stream exists, but no route uses it yet. Without a
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

## Impact comparison

A replay job decides every replayable record three ways, and the result's
`impact` member compares them (issue #243, slice 14):

- **Recorded**: what the gateway's policy stage recorded when the request was
  served, under the evaluator and resources it ran then.
- **Base**: the active policy the job was pinned to (`base_etag`), decided
  again now.
- **Candidate**: the candidate, decided again by the same evaluator.

Base against candidate is the impact of the change, reported per projection.
Recorded against base says how far the base, decided today, is from what was
recorded. The two are never folded into one answer: a difference between
recorded and base says nothing about the candidate, and is never counted as a
candidate change. A record with [decision facts](#decision-facts) says which
policy and evaluator decided it, and such a difference is labelled for what
they name; one without them cannot say whether the policy, the configuration
or the evaluator changed since.

When the candidate is `active`, the base is the candidate: one compiled
policy answers both, every transition is unchanged, and
`candidate_is_base` is `true`. The recorded comparison is still made.

### Transitions

Under each requested projection, every HTTP record and every tool invocation
is given one transition:

| Transition | Base, then candidate |
| --- | --- |
| `newly_allowed` | deny, then allow |
| `enforcement_only_change` | the same logical decision with a different effect: a deny enforced under one and shadowed under the other |
| `newly_denied` | allow, then deny, enforced or shadowed |
| `attribution_only_change` | the same decision and effect, decided by a different element or for a different reason, or with a different shadow observation |
| `unchanged_deny`, `unchanged_allow` | the same decision, effect, reason, deciding element and observation |
| `indeterminate` | either policy could not answer for want of a fact; each side's limitation is counted under `limitations.base` and `limitations.candidate` |
| `unsupported_context` | the evaluator refused the record's facts, counted by code under `refusals` |

Each decided pair also has a `forwarding` change, counted separately:
`newly_forwarded` when the base would block the request and the candidate
would forward it -- a newly allowed request, or a deny that is now only
shadowed -- and `newly_blocked` for the reverse. A shadowed deny is a deny
that forwards: a deny that became shadowed is an `enforcement_only_change`
that is `newly_forwarded`, never "unchanged".

Elements are compared by identity, not position. Two rules, routes or rate
overrides are the same element when they carry the same stable id, or, for
entries without one (a 0.x document's routes and overrides, and its rules
that set none), when their content is identical. An edit that inserts a rule
ahead of others moves them without changing them. Tool entries are the same
when they are the same tool name.

A lane's comparison:

```json
{
  "records": 10, "compared": 10,
  "transitions": { "newly_allowed": 1, "enforcement_only_change": 1,
                   "newly_denied": 3, "attribution_only_change": 1,
                   "unchanged_deny": 0, "unchanged_allow": 4,
                   "indeterminate": 0, "unsupported_context": 0 },
  "forwarding": { "newly_forwarded": 1, "newly_blocked": 4 },
  "matrix": [
    { "transition": "newly_allowed", "forwarding": "newly_forwarded",
      "base": { "logical": "deny", "enforcement": "enforced",
                "effective_action": "would_block", "reason": "default_deny" },
      "candidate": { "logical": "allow", "enforcement": "not_applicable",
                     "effective_action": "would_forward", "reason": "default_allow" },
      "count": 1 }
  ],
  "matrix_omitted": 0,
  "changed_elements": [
    { "transition": "newly_denied", "forwarding": "newly_blocked",
      "base": { "kind": "route", "position": 0 },
      "candidate": { "kind": "rule", "position": 0, "id": "lockdown" },
      "count": 3 }
  ],
  "changed_elements_omitted": 0,
  "limitations": { "base": {}, "candidate": {} },
  "refusals": {}
}
```

(The matrix and the changed elements are abbreviated.) `transitions` lists
every code, zeros included. `matrix` counts every decided pair by the two
decisions in the simulation's vocabulary; `changed_elements` counts the
changed records -- the first four transitions -- by the element that decided
under each policy: `rule` and `route` by position in that policy (with
`id`, or `id_omitted` for one over 128 bytes), `default`, `host_binding` (a
selected upstream no host-bound route authorized), `tool_entry` with the
policy's own tool name, or `no_tool_entry` for a tool the policy does not
list. Both lists are ordered for review: newly allowed first, then
enforcement-only changes, newly denied, attribution-only changes and the
unchanged; within a transition, newly forwarded first; and among changed
elements, the most records first.

`projections.as_authored` also carries a `statement`, the one thing the
comparison establishes, as a stable code:

| `statement.code` | When |
| --- | --- |
| `newly_allowed_observed` | At least one compared record was newly allowed or newly forwarded; the counts are `newly_allowed`, `newly_forwarded` and `replayable_events` (the compared records) |
| `no_newly_allowed_observed` | The result is complete, at least one record was compared, and none was newly allowed or newly forwarded. Only then is `text` given: "No newly allowed decisions were observed among N replayable events." N counts the compared records only; `indeterminate` and `unsupported_context` records are not among them |
| `not_established` | `reason: incomplete` for an incomplete result, `nothing_compared` when no record was decided under both policies |

The statement never says a policy is safe, and a replay cannot support one:
the stages outside the policy verdict were not replayed, and the window
holds only the traffic that was retained. `enforce_all_shadow` carries no
statement, because it describes a hypothetical, not the policy as it would
be served.

### Projections

`as_authored` compares the base and the candidate as written.
`enforce_all_shadow` compares them with every shadow made enforcing in both --
each direct `shadow` rule a `deny`, the global enforcement mode `enforce` and
every per-route `shadow` override `enforce` -- exactly as a
[simulation](policy-simulation.md)'s projection does. It answers "what would
this change block if every shadow were promoted", and never previews an
intended allow. Projections are in-memory copies compiled for the job;
nothing is rewritten, stored or activated.

### Rate selection

`impact.rate` compares which rate-limit override the base and the candidate
select for each HTTP record, for the policies as authored (a projection
changes no override): `unchanged`, `override_added`, `override_removed`,
`override_changed`, `indeterminate` or `unsupported_context`. An
`override_changed` record is also counted by how the candidate's configured
limits compare with the base's -- `looser`, `tighter`, `mixed` or `same`
(another override with the same limits) -- and changed records are named by
override (`rate_override` by position, with its id) or `no_override`. It is
selection only: whether a bucket had capacity was never recorded and is not
reconstructed.

### Recorded against base

`impact.recorded.http` and `impact.recorded.tool` compare each recorded
result with the base's answer as authored, the policy the gateway serves:

| Comparison | Meaning |
| --- | --- |
| `outcome_differs` | The base decides differently from what was recorded -- `allowed`, `denied` or `would_deny` for a request, `admitted` or `denied` for an invocation -- and nothing the record states explains it |
| `attribution_differs` | The same outcome, for a different reason or by a different element than the record names, and nothing the record states explains it |
| `evaluator_changed` | A difference, of outcome or attribution, in a record whose decision facts name the base policy decided by another evaluator: a `semantics_version` or `context_version` that is not this build's |
| `recorded_under_other_policy` | A difference in a record whose decision facts name another policy than the base (by ETag). What changed is the policy the record was decided under, not anything the candidate does |
| `agrees` | The same outcome and, when the record states a reason, the same reason and element |
| `recorded_not_policy_verdict` | The recorded reason is not a policy verdict -- `policy_evaluation_incomplete`, a revision-check code -- because the policy stage did not answer the request |
| `base_indeterminate`, `base_refused` | The base could not answer, or the evaluator refused the record's facts |

The element a record names is compared the way the live adapters record it:
a direct rule by its id, or its position when it has none; a route by its
permission and path prefix; a default or tool-entry decision by none. A
record that dropped an over-long attribution (`attribution_omitted`) is
compared without it, and a record that states no reason -- a tool invocation
policy admitted -- by outcome only. `matrix` counts the compared records by
recorded policy and reason against the base's.

A difference is labelled `recorded_under_other_policy` before
`evaluator_changed`: a record decided under another policy names that
policy's elements, so the evaluator is not what the comparison could isolate.
Only `outcome_differs` and `attribution_differs` remain unexplained -- a
record without decision facts, or one the base itself decided under this
evaluator and that still differs, which points at a configuration the policy
does not hold (MCP route paths, an identity provider's organizations) or at
the record.

Each lane's `provenance` counts every record by what its decision facts
establish, every code listed, zeros included:

| `provenance` | The record's decision facts name |
| --- | --- |
| `base_policy` | the base policy, decided by this build's evaluator |
| `other_policy` | another policy than the base |
| `other_evaluator` | the base policy, decided by another evaluator semantics or context version |
| `not_recorded` | nothing: the record carries no decision facts |

A difference here is a reason to look before reading the base-to-candidate
transitions as a forecast: the base, decided today, is not what served those
requests.

### Privacy projection

The comparison holds counts keyed by codes from closed sets and by policy
elements, and names a policy element only as the policy that decided names
it: its position, its own stable id when it is at most 128 bytes, and a tool
entry by the name in that policy's own tool map. It never repeats a value
only a record carries. A recorded rule id, permission or path prefix is
compared and never copied; a recorded reason is rendered only as the code it
matched in the closed set of verdict reasons; and a tool a record names that
the policy does not list is `no_tool_entry`, never its name. Paths, hosts,
principals, roles, route permissions and dispatch facts never appear. A
record's decision facts are compared and never copied either: the result
counts records by provenance code, and repeats no recorded ETag, digest,
evaluator version or element id.

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
  a serialized context or its formatting, with or without decision facts.
- Real requests through the live RBAC and observation middleware, and real
  invocations through the tool runtime, record decision facts on every
  verdict and none on a refusal; the observation's member is the verdict's
  own; the adapters read it back exactly, naming the installed policy's ETag
  and this build's evaluator; and the same records with the member removed
  are read and replayed as before. A record whose facts state an MCP alias is
  decided where the same record without them is `indeterminate`.
- The facts name the snapshot that decided: a v1 policy's semantic digest and
  a 0.x policy's none, a rule or route by position and id, an id-less rule by
  position, an over-long id as `id_omitted`; two verdicts share one identity,
  a reinstall makes a new one, and the per-verdict part is a fixed-size
  `Copy` value.
- Decision facts out of bounds, of another version, or describing another
  record -- its lane, its reason, its routing -- are refused by the parser and,
  where JSON Schema can state it, by the published schema; the adapter counts
  them as `malformed_decision_facts` or `unsupported_decision_facts_version`.
  A v1 context is read exactly as published.
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
- The cluster reader is run against a real PostgreSQL. A job reads exactly
  the window's rows at or below its cutoff, and rows committed after it with
  timestamps inside the window never enter. A batch that had already inserted
  its events but was still waiting for the stream lock when the cutoff was
  read is not counted. Under racing writers, every cutoff's count is exactly
  what its pages later read. Retention that stays before the window leaves a
  job complete. Retention past the window's start, before or during the job,
  a row deleted from inside the window and a window retention emptied are
  each `source_pruned`. Oversized, unreadable, legacy, malformed and
  non-request rows are counted by their codes, and an oversized row's JSON is
  never read. A locked stream fails a read within the replay's lock bound,
  not the session's. Every failure is classified, and no error carries SQL,
  schema names, the driver's message, a window bound or a record value. Each
  read is timed under the `policy_replay` checkout class.
- Through the application: every route refuses a caller missing any of its
  three permissions, and serves a job only to its owner; a stale base, an
  invalid window, edit or candidate creates no job; an idempotent retry starts
  nothing; queued jobs are cancelled, quotas refuse rather than evict, and
  results expire; a stalled upload holds no admission slot and is refused at
  its deadline, and a job holds its slot until its evaluation ends; in cluster mode every route answers `503` without reading a
  body, admitting a job, recording a lifecycle event or consulting the
  cluster authority; and the side-effect test above holds.
- The `policy-replay.v1` parser and its published schema accept and refuse
  the same requests, projections included.
- The impact comparison is run over a window that touches every transition,
  lane and recorded comparison: a candidate that inserts a rule, changes the
  default, enables a tool and loosens an override is counted transition by
  transition, with its forwarding changes, matrix and changed elements;
  elements that only moved, including an id-less one, are unchanged; the
  shadow projection is its own comparison and leaves the as-authored one as
  it was; a candidate that is its base changes nothing and gives the
  statement's sentence only when the result is complete; a record neither
  policy can answer is indeterminate on both sides; rows past their cap are
  counted; the comparison is byte-identical however the log is paged; and no
  record value -- subject, request id, address, user agent, path, recorded
  rule id, unlisted tool name, issuer, permission or non-verdict reason --
  appears in a result or completion record.
- A window whose records were decided under the base, under another policy,
  under another evaluator semantics or context version, or before decision
  facts, labels each difference `outcome_differs`,
  `recorded_under_other_policy` or `evaluator_changed` accordingly, counts
  every record's provenance, and -- with the candidate its own base -- leaves
  every transition unchanged and the statement's count whole: no recorded
  difference is a candidate change. No recorded ETag, evaluator version or
  element id appears in the result.
- Real requests through the live RBAC middleware, and real invocations
  through the tool runtime, are compared with the policy that decided them:
  every recorded verdict `agrees` -- including a rule without an id, which the
  gateway records by position -- a request the policy stage could not
  classify is `recorded_not_policy_verdict`, and an MCP alias whose identity
  was not recorded is `base_indeterminate`.
- Through the application, a job reports the impact of its candidate and the
  statement, records the impact counts in its completion event without an
  element id, reports the shadow projection on request, refuses an unknown
  projection before any job exists, and reads `stale` once the active policy
  changes.
