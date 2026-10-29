# Semantic configuration diff and risk codes

**Status: alpha.** This page describes the semantic diff of issue #242 (PR 9)
and [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md) ("Change
classes" and "Plan, risk acknowledgment, and conditional apply"): what it
compares, how it classifies each change, the stable risk codes, and what it
never shows. [`ggctl diff`](ggctl.md#diff) reports it for two bundles. The
gateway compares two compiled environment configurations and two bundles it
read with its production validators, but nothing serves or logs those
comparisons yet: server plans and risk acknowledgments are #242 PR 11, and
`ggctl diff --env`, `--against-env` and `--server` need the environment
compiler and plans, which are still in the gateway crate. Nothing here
changes how a gateway is configured, started or reloaded.

## What it compares

The diff compares two **compiled** configurations, never their text, so
formatting, member order, the order of an unordered list and the spelling of
a default never register:

| Input | Compared as | Field identifiers |
| --- | --- | --- |
| Two environment configurations | the configuration compiler's validated plan (`gateway/src/config/plan.rs`), setting by setting | the environment variable name, for example `EGRESS_ALLOWED_HOSTS` |
| Two [configuration bundles](configuration-bundles.md) | what the shared bundle reader accepted: the manifest, the deployment document, and the policy and tools documents, as written and checked against their published schemas (`ggctl diff`) or in the form the gateway's production validators produce (the gateway) | a dotted document path, for example `policy.egress.hosts` or `resources.policy.sha256` |

Every compiler input is compared exactly once: the environment adapter
destructures every domain plan field by field, so a setting added to a plan
does not compile until it is named there, and fails CI's warnings-as-errors
builds as an unused binding until it is compared; a test holds the compared
names equal to the compiler's input inventory (`CONFIG_INPUTS`). A policy or tools member the
diff does not model is still compared, as `policy.unmodelled_members` or
`tools.unmodelled_members`, and any change to it is `unknown`. Ordered lists
whose order is meaning (policy routes, direct rules, rate-limit overrides,
upstream routes) stay ordered; sets (hosts, CIDRs, ports, origins, exempt
paths, permissions) are compared as sets, and host names case-insensitively.

`diff(a, a)` is empty for every configuration, and so is the diff of a policy
against its reordering or its spelled-out defaults: a seeded property test
holds both for generated policies, and fixed tests for environment
configurations and read bundles.

## What a change carries

Each field that differs is one change with:

- `field` and `section` (`bundle`, `listeners`, `tls`, `authentication`,
  `admin`, `browser_security`, `proxy_trust`, `routing`, `egress`, `limits`,
  `audit`, `observability`, `storage`, `cluster`, `connections`, `lifecycle`,
  `policy`, `tools`);
- `kind`: `added`, `removed` or `modified`;
- `class`, how it can take effect (ADR-0008, Change classes). Every
  environment setting is read at startup, so its changes are `restart`,
  except `STATE_BACKEND` and `DEPLOYMENT_ID`, which are `cluster_operation`
  (#241's `gateway import-standalone` and its procedure). Bundle policy and
  tools content is `live`, except the policy's `egress` member, which the
  gateway applies only at startup (`restart`); the manifest and deployment
  document are `restart`; the Connections source is `connection_or_secret`.
  In cluster mode a restart change to a setting in ADR-0007's
  static-configuration fingerprint also needs ADR-0007's coordinated
  procedure; the diff does not single those out yet, and `coordinated_cutover`
  is reserved for it;
- `effect`: `loosened` when any facet of the change weakens a control,
  otherwise `unknown` when no detector can tell, otherwise `tightened` or
  `neutral`;
- `riskCodes` and `severity`: a `loosened` change carries the codes of what it
  weakens, an `unknown` one carries `risk.unknown_impact`, and a `tightened`
  or `neutral` one carries none. **A change is never left without a code
  because a detector is missing**;
- `value`: what may be shown of it (below), and for a collection, `entries`:
  how many members or entries were added, removed and changed.

The diff's `changed`, `severity` (the highest of any code, `none` without
one), `riskCodes` (sorted, unique), `sections` and `changes` (ordered by
section, then field) are published as `diffResult` in
[`ggctl-report.v1alpha1.schema.json`](schemas/ggctl-report.v1alpha1.schema.json).

## What it never shows

The diff is value-free by construction. Only closed-vocabulary values are
ever shown, as `{"display": "shown", "before": ..., "after": ...}`: booleans,
words fixed in the gateway's source (`required`, `observe`, `1.2`, a profile
name, ...) and numbers (bounds, timeouts, rates, retention, counts). Every
other value (a path, URL, host, address, CIDR, name, claim, issuer, route or
document member) is reported only as `{"display": "withheld"}`, with entry
counts for a collection; entry names such as role, tool or provider names
never appear. A secret, secret reference or secret locator (TLS private keys,
`DATABASE_URL_FILE`, Connections roots, aliases, keyrings and secret
providers, authority pseudonym key aliases, and the auth provider list, which
holds client secrets) is reported only as `{"display": "reference"}`: never
an old or new value, and nothing derived from one, such as a fingerprint.
Values are compared for equality in memory and dropped; tests plant canary
values in every redacted kind and assert none reaches a report or a `Debug`
rendering.

## How changes are judged

A detector says which direction of change loosens a setting:

| Rule | Loosens | Tightens |
| --- | --- | --- |
| a flag | the looser value (`AUTH_ENABLED=false`, `TRUST_PROXY_HEADERS=true`) | the other |
| ranked words | a word further down the order (`required` < `observe`; `required` < `best_effort`; `1.3` < `1.2`; `production` < `migration` < `development`; `deny` < `allow`) | a word further up; a word not in the order is `unknown` |
| a bound | raising it or removing it (unbounded is the highest); for retention, journal capacity, the audit drain timeout and the rate limiter's bucket capacity and idle lifetime, lowering it | the other direction |
| an allow set | adding any member | only removing members |
| a restricting set, where empty means unrestricted (policy egress ports, a role's issuers and auth methods, a tool's allowed roles) | emptying it, or adding a member to a non-empty one | restricting an empty one, or only removing members |
| an optional sink (an audit file or store, a CRL) | removing it | adding it; replacing it is neutral |
| an optional source (a tools file, an OpenAPI spec) | adding or replacing it | removing it |
| a trust or binding value (an issuer, JWKS URL, CA file, public URL, credential) | any change | none |
| no detector | every change is `unknown` | none |

Some changes are judged from what they hold. A listener that reaches further
(loopback, one address, every address) or a new non-loopback gRPC listener
exposes it; moving the admin surface onto or off its own listener is
`unknown`. Removing `POLICY_FILE` enforces no policy at all, and pointing it
at another file is `unknown`, because the diff cannot see that policy.
Turning admin sessions on adds a cookie-authenticated admin path, and moving
them to another store is `unknown`. Removing a listener's TLS material serves
plaintext; an `http://` upstream URL, upstream route endpoint or MCP upstream server where
there was none is plaintext transport too; a route that newly forwards the
session cookie upstream increases data exposure, and a changed set of route
Connections is a credential binding change. A rate-limit override whose rate
or burst rose loosens limits, but an override that is added, removed or
moved, which can raise a limit as easily as lower one, is `unknown`. Policy
route and direct-rule edits are `unknown`; a route switched to
`enforcement_mode: shadow` is also `risk.shadow_enabled`. An unset upstream
timeout is compared as the egress timeout it inherits.

The authoritative tables are `SETTINGS` in `gateway/src/config/semantic_diff.rs`
for the environment and `gateway-config/src/semantic_diff/resources.rs` for
bundles and documents.

## Risk codes

A published code never changes meaning; renaming or
removing one requires a new report version. Authentication, egress and policy
weakening, letting requests or authority changes proceed without a durable
record of them, and anything no detector can classify, are `high`.

| Code | Severity | Meaning | Raised by |
| --- | --- | --- | --- |
| `risk.admin_access_path_removed` | high | an admin authentication path was removed, which can lock administrators out | reserved: no detector raises it yet (ADR-0008 makes it non-acknowledgeable online) |
| `risk.audit_durability_reduced` | medium | fewer events are recorded, less durably, or for less time | audit sinks and stores, retention, `AUDIT_DRAIN_TIMEOUT_MS`, `AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY`, `AUTHORITY_EVENT_SINK`, journal capacity and retention |
| `risk.auth_disabled` | high | authentication is turned off | `AUTH_ENABLED` |
| `risk.auth_observe_only` | high | failed authentication is observed instead of refused | `AUTH_MODE` |
| `risk.auth_trust_changed` | high | an identity provider, issuer, key source, audience, claim or client-certificate rule was added or changed, or a check on it was relaxed | `AUTH_PROVIDERS`, `JWT_*`, `ROLES_CLAIM`, service tokens, `ADMIN_LOGIN_PROVIDER`, client certificates |
| `risk.cookie_or_csrf_weakened` | high | CSRF protection or cookie scope was relaxed, or admin sessions last longer | `CSRF_ENABLED`, `CSRF_COOKIE_DOMAIN`, `ADMIN_SESSION_MODE`, `ADMIN_SESSION_TTL_SECS`, `ADMIN_SESSION_IDLE_TIMEOUT_SECS` |
| `risk.cors_broadened` | medium | more origins may make cross-origin requests | `CORS_ALLOW_ORIGINS` |
| `risk.credential_binding_changed` | high | a secret reference, key, secret provider or credential binding was added or changed | TLS keys, `DATABASE_URL_FILE`, Connections settings and keyrings, pseudonym key aliases, route Connections |
| `risk.data_exposure_increased` | medium | more request data is captured, or more deployment topology is disclosed | payload capture, `CLUSTER_STATUS_EXPOSE_HOSTNAMES`, session-cookie forwarding |
| `risk.egress_broadened` | high | more outbound destinations or ports are allowed | `EGRESS_ALLOWED_HOSTS`, `policy.egress.hosts`, `policy.egress.ports` |
| `risk.evidence_not_required` | high | requests or authority changes may proceed without a durable record of them | `AUDIT_DURABILITY` and `AUTHORITY_EVIDENCE_DURABILITY` moving from `required` to `best_effort` (unset `AUTHORITY_EVIDENCE_DURABILITY` is `best_effort`); returning to `required` tightens and carries no code |
| `risk.exemptions_broadened` | high | more paths are exempt from authentication, authorization or CSRF checks | `AUTH_EXEMPT_PATHS`, `RBAC_EXEMPT_PATHS`, `CSRF_EXEMPT_PATHS` |
| `risk.limits_loosened` | low | a size, rate, time, concurrency or validation bound was raised, removed or relaxed | request, egress, TLS, tool runtime, rate-limit and database bounds; policy rate overrides and tool timeouts |
| `risk.listener_exposed` | high | a listener is reachable beyond loopback, or another listener was opened | `LISTEN_ADDR`, `ADMIN_LISTEN_ADDR`, `GRPC_LISTEN_ADDR` |
| `risk.plaintext_transport` | high | a connection that used TLS no longer does | listener TLS, `DATABASE_TLS_MODE`, `http://` upstreams |
| `risk.policy_broadened` | high | a policy role or tool entry grants more or restricts less | `policy.roles`, `policy.tools` |
| `risk.policy_default_allow` | high | requests no policy rule matches are allowed, or no policy is enforced at all | `policy.default_action`, removing `POLICY_FILE` |
| `risk.private_egress_allowed` | high | outbound requests may reach private or other non-global addresses | `EGRESS_DENY_PRIVATE_IPS`, `policy.egress.cidrs` |
| `risk.profile_changed` | high | the deployment profile moved to one with fewer guarantees | `deployment.profile` |
| `risk.public_origin_changed` | medium | the public URL the gateway advertises changed | `GATEWAY_PUBLIC_URL` |
| `risk.routing_changed` | medium | requests are routed to a new or different upstream | `UPSTREAM_URL`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS` |
| `risk.shadow_enabled` | high | policy denials are observed instead of enforced | `policy.enforcement_mode`, route shadow overrides |
| `risk.storage_changed` | medium | a state store, its backend or its migration behavior changed | store paths, `STATE_BACKEND`, `DEPLOYMENT_ID`, `DATABASE_AUTO_MIGRATE`, `DATABASE_TLS_CA_FILE` |
| `risk.tls_weakened` | medium | the minimum TLS version was lowered | `TLS_MIN_VERSION` |
| `risk.tool_surface_broadened` | medium | more tools or tool sources are exposed | `TOOLS_FILE`, `OPENAPI_SPEC_PATH`, `tools.definitions` |
| `risk.trusted_proxies_changed` | medium | more peers are trusted to report the client address, or proxy headers are trusted | `TRUST_PROXY_HEADERS`, `TRUSTED_PROXY_CIDRS` |
| `risk.unknown_impact` | high | no detector can classify this change, so it is treated as a weakening | every change no detector can order |

Tests hold every code to its text, sort order and severity, check that each
known weakening of a policy and of an environment configuration carries its
code, and that applying more weakenings, in any seeded order, never removes a
code or lowers the severity.

## Output in `ggctl diff`

[`ggctl diff BUNDLE --against BUNDLE`](ggctl.md#diff) reads both bundles with
the shared reader, as `ggctl validate` does (so the production policy and
tools validators do not run and the report says so), and compares the
documents as they were written. It writes:

- human output: one line per change (severity, field, kind, the value or
  `(value withheld)` / `(reference changed)` with entry counts, class, effect
  and codes), then the number of changes, the highest severity and the codes;
- `--format json`: one `GgctlReport` whose `result.diff` is the `diffResult`
  above;
- `--format sarif`: SARIF 2.1.0 with the readers' diagnostics, then one rule
  per risk code (its fixed description, a `high`/`medium`/`low` code at level
  `error`/`warning`/`note`) and one result per code of each change, located
  at the change's field as a logical location and carrying its section, kind,
  class and effect. A change without a code is not a finding and has no
  result. This extends ADR-0008, which gives SARIF to `validate` only, so CI
  can annotate a review with the same codes a plan will require
  acknowledging.

`--check` exits `4` (`diff.drift_found`) when anything differs and `0`
otherwise; an invalid bundle is not compared and exits `3`.
