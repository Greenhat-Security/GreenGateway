# Policy replay contexts

Historical replay asks what a policy -- the active one, or a candidate --
would have decided for traffic the gateway already served. Before any
replay can run, each retained record has to be turned into the facts the
policy evaluator reads, with every fact the record does not carry stated as
missing rather than guessed. A **replay context** is that record, and this
page describes its format, `replay-context.v1`, and how the gateway reads one
out of the audit events it writes today (issue #243, slice 12).

There is no replay endpoint yet. The bounded replay job engine (slice 13) and
the recorded-versus-candidate comparison (slice 14) are the first consumers;
until they ship, replay contexts exist only inside the gateway and its tests.
Nothing on the request path writes one: every context comes from the legacy
adapters described below.

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
