# Connections Migration and Rollback

This guide moves legacy upstreams and tools to managed Connections without a
flag day. GreenGateway supports mixed mode: legacy configuration remains
authoritative for every lane that has not been cut over, while managed
Connections serve only the routes and capabilities explicitly bound to them.

GreenGateway does not automatically rewrite legacy configuration, extract a
literal credential, create a managed Connection, or modify policy. Legacy
projections are an inventory view, not migration records. Every destination,
secret binding, route, tool, policy, and public-name change is an explicit
operator action.

See the [operator guide](operator-guide.md) before introducing encrypted local
secrets and the [admin guide](admin-guide.md) for the browser workflow.

## Compatibility and Deprecation Schedule

`UPSTREAM_URL`, legacy `UPSTREAM_ROUTES` destinations,
`MCP_UPSTREAM_SERVERS`, `OPENAPI_SPEC_PATH`, and legacy-compatible tool
definitions remain supported during the current major release. Literal
credential values in `UPSTREAM_ROUTES[].add_request_headers` are deprecated as
a secret-delivery mechanism, but they are not silently removed or transformed.

No removal version is assigned by issue #240. Any removal requires a future
major release, advance release-note notice, a supported migration path, and
published rollback guidance. A deprecation warning is therefore a planning
signal, not permission to delete a working legacy setting during this
upgrade.

## Before the First Cutover

1. Back up deployment configuration, `TOOLS_FILE`, policy, the Connections
   database/WAL boundary if present, and the corresponding secret/key custody
   artifacts.
2. Record representative success, deny, authentication failure, streaming, and
   timeout behavior for each lane.
3. Inventory legacy projections in **Connections** and capabilities in
   **Inventory**. Record any `omitted_legacy_projection_count`; with managed
   storage enabled, managed plus projected Connections must remain within the
   bounded inventory.
4. Record policy identifiers and public tool names used by clients. A
   display-name match is not sufficient.
5. Add managed endpoint and OAuth token hosts to egress policy. Unlike legacy
   configured infrastructure, managed Connection hosts are not auto-seeded.
6. Create operator aliases or encrypted-local secrets without removing their
   legacy sources.
7. Create the managed Connection as a disabled draft, then Test it. For a
   managed catalog, preview/register or Refresh it before enabling production
   traffic.
8. Define measurable acceptance and rollback triggers for that one lane.

Migrate one route or capability family at a time. Do not combine destination,
credential, policy, public-name, and unrelated resilience changes in one
cutover.

## Mixed-Mode Rules

- Setting `CONNECTIONS_SQLITE_PATH` enables managed mutations but does not
  disable `UPSTREAM_URL`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`, or
  `TOOLS_FILE`.
- Legacy projections remain read-only. Editing their display data in the UI is
  intentionally impossible.
- A managed Connection has an immutable generated ID. Use that ID in
  `UPSTREAM_ROUTES[].connection_id`, tool targets, dependencies, policy
  reviews, and operational records; display names may change.
- A route or tool has one destination authority. Do not keep a legacy
  credential transform on the same route after its managed authentication
  binding becomes authoritative.
- Managed and legacy capabilities may coexist only when their public names do
  not collide. The registry rejects collision rather than overwriting one.
- Keep the old configuration available for rollback until the managed lane has
  passed the agreed observation window.

## Migrate `UPSTREAM_URL`

`UPSTREAM_URL` is the legacy unconditional proxy fallback. A managed
Connection is selected through a named `UPSTREAM_ROUTES` entry, so the
cutover must also introduce an explicit host and/or non-root path matcher.

1. Create a managed `http_api` Connection with the normalized legacy origin
   and base path.
2. Move supported timeouts, authentication, custom CA, mTLS, and a safe
   `GET`/`HEAD` test profile into the Connection.
3. Test the disabled Connection.
4. Create a unique stable route ID and bind it with `connection_id`.
5. Preserve and revalidate the route's RBAC/direct-rule behavior. A
   host-qualified route requires a matching host-bound policy route.
6. Remove `UPSTREAM_URL` only in the reviewed cutover configuration, restart,
   and verify representative requests plus denials.

Example target shape:

```json
[
  {
    "id": "billing-route",
    "host": "billing.example.com",
    "path_prefix": "/",
    "connection_id": "00000000-0000-0000-0000-000000000000"
  }
]
```

Replace the placeholder with the generated immutable ID. A path-only
`path_prefix: "/"` route remains invalid because it would recreate an
unconditional catch-all. If clients cannot supply a stable host and no
non-root path boundary exists, retain `UPSTREAM_URL`; do not weaken route
validation to force the migration.

Rollback by restoring the previous `UPSTREAM_URL` deployment configuration and
policy, removing the managed route binding from `UPSTREAM_ROUTES`, and
restarting. Leave the disabled managed Connection and its bindings intact for
diagnosis.

## Migrate `UPSTREAM_ROUTES`

Migrate one logical route entry at a time:

1. Preserve its `id`, `host`, and `path_prefix` routing identity. If a legacy
   entry had no explicit ID, select and record a stable ID before changing its
   destination form.
2. Create a managed Connection for the route's origin and base path.
3. Move authentication, custom CA/mTLS, and Connection-supported timeout/test
   settings to that Connection.
4. Replace exactly one destination form (`upstream_url` or `upstreams`) with
   `connection_id`. Keep safe non-credential `add_request_headers` and
   `strip_request_headers` only when still required.
5. Revalidate route and direct-rule policy, Test the Connection, enable it, and
   observe traffic before migrating the next entry.

A Connection-bound route cannot also configure route-level TLS, timeout,
health-check, retry, or circuit-breaker fields that are unsupported for that
destination form. Retain the legacy route until required behavior has an
equivalent reviewed Connection path; do not silently drop resilience controls
for migration symmetry.

### Remove literal credential headers safely

Legacy `add_request_headers` can contain a literal upstream credential. There
is no automatic extraction because GreenGateway cannot reliably determine
whether a header is a secret, its purpose, or its correct custody system.

For each known credential header:

1. Provision the value independently as an operator alias or encrypted-local
   secret.
2. Bind that opaque alias to a header-API-key or bearer authentication profile
   on a disabled Connection.
3. Test the Connection and confirm deny paths perform no upstream call.
4. In one reviewed cutover, remove the literal credential header and switch
   the route to `connection_id`.
5. Rotate the original credential at its system of record if it spent time in
   deployment configuration or source control.

The route must not add or strip the Connection's selected API-key header.
GreenGateway rejects that conflict and always strips a caller-provided value
before injecting the protected credential last.

Rollback by restoring the exact prior route entry. Do not copy a protected
value back out of GreenGateway; use the separately retained legacy deployment
secret.

## Migrate `MCP_UPSTREAM_SERVERS`

For each legacy MCP server:

1. Create a disabled `mcp_streamable_http` Connection with `managed_mcp`
   discovery and the required authentication/TLS bindings.
2. Test the saved endpoint. Test performs only a bounded protocol check and
   does not publish a catalog.
3. Enable the Connection and Refresh it. Verify the complete catalog and tool
   policy eligibility before exposing it to clients.
4. Update tool-name policy and clients to the managed public names.
5. Remove only that legacy `MCP_UPSTREAM_SERVERS` entry, restart, and verify
   initialize/list/call deny and success cases.

Legacy public names are
`{legacy_server_name}:{remote_tool_name}`. Managed public names are
`{connection_id}:{remote_tool_name}`. The immutable Connection ID keeps the
managed name stable across display-name edits and refreshes, but migration
does not promise the legacy and managed prefixes will be identical. Treat the
name change as a policy and client compatibility change.

Do not register both forms under a colliding public name or silently broaden a
tool-name rule to cover the new prefix. Review each rule. On failed managed
Refresh, the last successful managed catalog remains active and status becomes
`degraded/catalog_stale`; that safety behavior does not automatically switch
traffic back to the legacy server.

Rollback by restoring the legacy server entry and its exact name, reverting
the associated client/policy changes, and disabling the managed Connection.

## Migrate Legacy OpenAPI Tools

Legacy OpenAPI coverage (`OPENAPI_SPEC_PATH` or
`UPSTREAM_ROUTES[].openapi_spec_path`) and legacy generated/manual tools do not
become a managed catalog merely because a similar Connection exists.

1. Create a managed `http_api` Connection with `managed_openapi` discovery.
2. Preview the stored document through the Connection path. Review operation
   IDs, rendered methods/paths, schemas, security declarations, and proposed
   public names.
3. Select and explicitly register the intended tools. Resolve any name
   collision with `TOOLS_FILE` or another catalog before publishing; managed
   registration never overwrites the existing tool.
4. Update policy only for the exact managed names and mappings.
5. Remove the corresponding legacy tool definitions or spec coverage only
   after managed invocation and deny-path acceptance passes.

A later managed refresh preserves a surviving public name only when it remains
bound to the same operation and safe mapping. Incompatible movement, collision,
invalid schema, or partial fetch publishes nothing; the last-known-good
managed catalog remains available.

Keep `OPENAPI_SPEC_PATH` if it is still needed for legacy traffic discovery
coverage. Managed tool registration and traffic schema coverage are related
but distinct functions, so removing one setting must not be assumed to replace
the other.

Rollback by restoring the prior `TOOLS_FILE`/spec configuration and policy,
removing the conflicting managed publication through the supported catalog
lifecycle, and disabling the managed Connection. Never edit catalog rows in
SQLite.

## Name and Policy Stability

Record these different identities during migration:

| Identity | Stability |
|---|---|
| Managed Connection ID | Immutable; use for route/tool bindings and operations |
| Display name | Editable presentation only |
| Legacy projection ID | Deterministic inventory identity; not a managed record |
| Managed MCP public name | Connection ID plus remote name; stable across display-name edits |
| Managed OpenAPI public name | Retained only while the same operation and mapping survives refresh |
| Route ID | Logical dispatch identity; keep stable when replacing the destination |

Policy is never inferred from a shared display name or origin. Re-run the
policy preview/acceptance checks when a route ID, tool name, connection target,
host boundary, authentication mode, or credentialed target changes.

## Cutover Acceptance

For each migrated lane, verify:

- unauthenticated and unauthorized calls fail before secret resolution, DNS,
  OAuth, or upstream traffic;
- the intended principal succeeds with the same public HTTP/MCP contract;
- caller-supplied authorization, cookie, and configured credential headers
  cannot override Connection authentication;
- custom CA and mTLS success and failure are strict;
- timeouts, body/response bounds, streaming, and cancellation remain within the
  accepted behavior;
- Test and Refresh emit only safe reasons and status;
- expected `connection.*` and `tool.*` audit events appear without arguments,
  results, secret IDs/locators, raw errors, or upstream bodies;
- rollback artifacts are still available and their restore instructions are
  current.

## Rollback Decision

Rollback if the managed lane changes authorization, destination selection,
public names without an approved client rollout, TLS validation, error
sanitization, resource bounds, or required availability beyond its acceptance
threshold.

Traffic rollback and data rollback are separate:

- **Traffic rollback:** restore the previous legacy route/tool/MCP
  configuration and policy, restart, verify, and disable the managed
  Connection. This is the normal response.
- **Data rollback:** restore a Connections database and its exact key recovery
  set only for control-plane corruption or disaster recovery. Do not restore
  an older database merely to redirect traffic.

Never delete a Connection, clear a binding, remove a decrypt-only master key,
or erase the managed catalog as the first rollback step. Those actions make
diagnosis or later recovery harder and may be blocked by retained
dependencies.
