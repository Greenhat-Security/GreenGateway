import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { NOT_AUTHORITY_CHANGES, OPERATIONS, QUALIFIED_PATHS, ROOT, readJson, schema, summary, validateEvent, validateInventory, validateSchema } from "./check-authority-evidence.mjs";

const inventory = () => readJson("docs/authority-evidence-inventory.json");
const source = (path) => readFileSync(resolve(ROOT, path), "utf8");
// Hoisted, so the tests above its siblings' helpers can use it.
function groupOf(value, id) {
  return value.groups.find((group) => group.id === id);
}
const fixture = () => ({
  schema_version: "authority_event.v1",
  authority_id: "10000000-0000-4000-8000-000000000001",
  event_id: "20000000-0000-4000-8000-000000000001",
  operation_id: "30000000-0000-4000-8000-000000000001",
  operation: "policy.publish",
  result: "committed",
  committed_at: "2026-09-08T12:00:00.123456Z",
  actor: { kind: "principal", subject_ref: "a".repeat(64), issuer_ref: "b".repeat(64), auth_mode: "bearer_token" },
  resource: { kind: "policy", ref: "c".repeat(64) },
  revision: { axis: "policy", before: "9007199254740992", after: "9007199254740993", security: "9007199254740994" },
});

test("inventory covers each required operation in both modes with live source anchors", () => {
  assert.equal(validateInventory(inventory()).operationModePairs, OPERATIONS.length * 2);
});

// Qualification is a reviewed table, QUALIFIED_PATHS, keyed by operation and
// mode (issue #425): a path in the inventory must equal its entry, and a row
// claims required durability exactly when every pair it holds has its
// reviewed path, it admits only the keyed form, it says nothing else is
// missing and it is delivered by its mode's dispatcher. These replace the
// hard-coded revoke and prepare guards and keep every case they held.
const pathOf = (value, id) => groupOf(value, id).qualified_delivery_paths[0];
const routing = "gateway/src/routing.rs";
const KEYED_ROUTES_OPEN = "pub(super) const KEYED_ROUTES: &[KeyedRoute] = &[";
// The router's table with one more honoured route, for a table entry the
// test adds.
const honouring = (method, route) => (path) => path === routing
  ? source(path).replace(KEYED_ROUTES_OPEN, `${KEYED_ROUTES_OPEN}\n    KeyedRoute {\n        method: "${method}",\n        route: "${route}",\n    },`)
  : source(path);

test("a row is supported only when every pair has its reviewed path", () => {
  // Today five rows qualify: PostgreSQL keyed preparation, and keyed
  // Connection create and replace and keyed catalog publication and overlay
  // changes in both modes.
  const current = validateInventory(inventory());
  assert.deepEqual(current.qualifiedPairs, [
    "catalog.mcp.publish/postgres", "catalog.mcp.publish/standalone", "catalog.openapi.publish/postgres", "catalog.openapi.publish/standalone",
    "catalog.overlay.delete/postgres", "catalog.overlay.delete/standalone", "catalog.overlay.replace/postgres", "catalog.overlay.replace/standalone",
    "connection.create/postgres", "connection.create/standalone", "connection.replace/postgres", "connection.replace/standalone", "credential.binding_change/postgres", "credential.binding_change/standalone",
    "mutation_approval.prepare/postgres",
  ]);
  assert.deepEqual(current.keyedWithdrawalPairs,
    ["connection.delete/postgres", "connection.delete/standalone", "service_token.revoke/postgres"]);
  const prepare = (value) => groupOf(value, "mutation_approval_prepare_postgres");
  // Every part of the bar is required: the path for each pair, keyed-only
  // admission, no remaining gap, and its mode's dispatcher.
  for (const [field, value] of Object.entries({
    operations: ["mutation_approval.prepare", "mutation_approval.review"], modes: ["postgres", "standalone"],
    required_mode: "admitted", delivery: "post_commit_telemetry", disposition: ["missing_metadata"],
    qualified_delivery_paths: [],
  })) {
    const changed = inventory();
    prepare(changed)[field] = value;
    assert.throws(() => validateInventory(changed), /unproven durability claim|duplicate coverage|unreviewed|qualified path|stands alone/, field);
  }
  const unclaimed = inventory();
  prepare(unclaimed).required_durability_supported = false;
  assert.throws(() => validateInventory(unclaimed), /mutation_approval_prepare_postgres: a row that meets the qualification bar must claim required durability/);
  const pathless = inventory();
  delete prepare(pathless).qualified_delivery_paths;
  assert.throws(() => validateInventory(pathless), /mutation_approval_prepare_postgres: unproven durability claim/);
  const standaloneDelivery = inventory();
  prepare(standaloneDelivery).delivery = "standalone_cursor_dispatch";
  assert.throws(() => validateInventory(standaloneDelivery), /mutation_approval_prepare_postgres: unproven durability claim/);
  // A row cannot claim durability, keyed-only admission or sufficiency
  // without the bar, whatever else it says.
  const claimed = inventory();
  groupOf(claimed, "mutation_approvals").required_durability_supported = true;
  assert.throws(() => validateInventory(claimed), /mutation_approvals: unproven durability claim/);
  // A qualified Connection row loses its claim with any one of its paths:
  // the credential binding change a keyed replacement makes has its own.
  for (const id of ["connection_postgres", "connection_standalone"]) {
    const partial = inventory();
    groupOf(partial, id).qualified_delivery_paths = groupOf(partial, id).qualified_delivery_paths
      .filter((path) => path.criteria.operation !== "credential.binding_change");
    assert.throws(() => validateInventory(partial), new RegExp(`${id}: unproven durability claim`), id);
  }
  // So does a qualified catalog row: an overlay removal is a publication
  // with its own path, not a withdrawal.
  for (const id of ["catalog_postgres", "catalog_standalone"]) {
    const partial = inventory();
    groupOf(partial, id).qualified_delivery_paths = groupOf(partial, id).qualified_delivery_paths
      .filter((path) => path.criteria.operation !== "catalog.overlay.delete");
    assert.throws(() => validateInventory(partial), new RegExp(`${id}: unproven durability claim`), id);
  }
  const keyedOnly = inventory();
  groupOf(keyedOnly, "mutation_approval_prepare_standalone").required_mode = "caller_key_required";
  assert.throws(() => validateInventory(keyedOnly), /unreviewed caller-key admission/);
  const sufficient = inventory();
  groupOf(sufficient, "tools_postgres").disposition = ["already_sufficient"];
  assert.throws(() => validateInventory(sufficient), /unreviewed sufficient disposition/);

  // A reviewed table entry is what earns a row, standalone included: with an
  // entry for standalone token issue (and its route honoured by the router),
  // the row qualifies once it meets the whole bar, and not before.
  const issue = {
    ...pathOf(inventory(), "mutation_approval_prepare_postgres").criteria,
    operation: "service_token.issue", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens",
  };
  const table = { ...QUALIFIED_PATHS, "service_token.issue/standalone": issue };
  const readSource = honouring("POST", "/v1{ADMIN_PREFIX}/tokens");
  const flipped = inventory();
  Object.assign(groupOf(flipped, "token_issue_standalone"), {
    required_mode: "caller_key_required", disposition: ["already_sufficient"], required_durability_supported: true,
    qualified_delivery_paths: [{ ...structuredClone(pathOf(flipped, "mutation_approval_prepare_postgres")), criteria: issue }],
  });
  assert.deepEqual(validateInventory(flipped, readSource, table).qualifiedPairs, [
    "catalog.mcp.publish/postgres", "catalog.mcp.publish/standalone", "catalog.openapi.publish/postgres", "catalog.openapi.publish/standalone",
    "catalog.overlay.delete/postgres", "catalog.overlay.delete/standalone", "catalog.overlay.replace/postgres", "catalog.overlay.replace/standalone",
    "connection.create/postgres", "connection.create/standalone", "connection.replace/postgres", "connection.replace/standalone", "credential.binding_change/postgres", "credential.binding_change/standalone",
    "mutation_approval.prepare/postgres", "service_token.issue/standalone",
  ]);
  assert.throws(() => validateInventory(flipped, readSource), /token_issue_standalone: qualified path service_token\.issue\/standalone is outside the reviewed table/);
  const journaled = structuredClone(flipped);
  groupOf(journaled, "token_issue_standalone").delivery = "journaled_dispatch";
  assert.throws(() => validateInventory(journaled, readSource, table), /token_issue_standalone: unproven durability claim/);
});

test("a path outside the reviewed table is refused", () => {
  // Every criterion of both reviewed paths is pinned: changing any one is
  // either a different reviewed pair, which does not exist, or a change of
  // reviewed criteria.
  for (const id of ["token_revoke_postgres", "mutation_approval_prepare_postgres"]) {
    for (const [field, value] of Object.entries({
      storage_mode: "standalone", method: "DELETE", operation: "service_token.rotate",
      route: "/v1{ADMIN_PREFIX}/tokens/{id}", operation_id_version: 4, actor_kind: "service_token",
      issuer: "optional", format: "delivery_v1", durable_sink: "log", filesystem: "unknown",
      wire_schema: "authority_event_delivery.v1",
    })) {
      const changed = inventory();
      pathOf(changed, id).criteria[field] = value;
      assert.throws(() => validateInventory(changed), new RegExp(`${id}: qualified path .* (is outside the reviewed table|criteria changed without review)`), `${id} ${field}`);
    }
    const extra = inventory();
    pathOf(extra, id).criteria.extra = "field";
    assert.throws(() => validateInventory(extra), /criteria changed without review/, id);
  }
  // A reviewed path does not travel to a row it was not reviewed for.
  const moved = inventory();
  groupOf(moved, "connection_postgres").qualified_delivery_paths = structuredClone(groupOf(moved, "token_revoke_postgres").qualified_delivery_paths);
  assert.throws(() => validateInventory(moved), /connection_postgres: qualified path outside its inventory group/);
  const keyed = inventory();
  groupOf(keyed, "jwt_postgres").qualified_delivery_paths = structuredClone(groupOf(keyed, "token_revoke_postgres").qualified_delivery_paths);
  assert.throws(() => validateInventory(keyed), /jwt_postgres: (qualified path outside its inventory group|a no_caller_key row has no keyed path)/);
  // The router honours a key on exactly the reviewed routes: a reviewed path
  // the router would refuse, and a key the router honours with no reviewed
  // path, both fail.
  const unrouted = (path) => path === routing
    ? source(path).replace(/\s*\/\/ Keyed approval preparation[^\n]*\n\s*KeyedRoute \{[\s\S]*?\n\s*\},/, "")
    : source(path);
  assert.notEqual(unrouted(routing), source(routing), "the test removes the preparation route");
  assert.throws(() => validateInventory(inventory(), unrouted), /qualified path mutation_approval\.prepare\/postgres \(PUT \/v1\{ADMIN_PREFIX\}\/tools\/\{id\}\/mutation-approvals\) is not honoured by KEYED_ROUTES/);
  assert.throws(() => validateInventory(inventory(), honouring("POST", "/v1{ADMIN_PREFIX}/tokens")),
    /KEYED_ROUTES in gateway\/src\/routing\.rs honours POST \/v1\{ADMIN_PREFIX\}\/tokens, which no reviewed qualified path names/);
  assert.throws(() => validateInventory(inventory(), (path) => path === routing ? source(path).replace(KEYED_ROUTES_OPEN, "const ROUTES: &[KeyedRoute] = &[") : source(path)),
    /declares no KEYED_ROUTES/);
  // Every entry the router could honour is read: the fields in either
  // order, and a block comment hides only what it comments out. An entry the
  // checker cannot read as two string literals -- a constant route, another
  // field, an entry that is not a literal -- fails rather than going unseen.
  const withEntry = (entry) => (path) => path === routing
    ? source(path).replace(KEYED_ROUTES_OPEN, `${KEYED_ROUTES_OPEN}\n    ${entry}`)
    : source(path);
  assert.throws(() => validateInventory(inventory(), withEntry('KeyedRoute { route: "/v1{ADMIN_PREFIX}/tokens", method: "POST" },')),
    /KEYED_ROUTES in gateway\/src\/routing\.rs honours POST \/v1\{ADMIN_PREFIX\}\/tokens, which no reviewed qualified path names/);
  validateInventory(inventory(), withEntry('/* KeyedRoute { method: "POST", route: "/v1{ADMIN_PREFIX}/tokens" }, */'));
  assert.throws(() => validateInventory(inventory(), withEntry('KeyedRoute { method: "POST", route: TOKENS_ROUTE },')),
    /must name method and route once each as string literals/);
  assert.throws(() => validateInventory(inventory(), withEntry('KeyedRoute { method: "POST", route: "/v1{ADMIN_PREFIX}/tokens", method: "PUT" },')),
    /must name method and route once each as string literals/);
  assert.throws(() => validateInventory(inventory(), withEntry('KeyedRoute { method: "POST" },')),
    /must name an upper-case method and a route/);
  assert.throws(() => validateInventory(inventory(), withEntry('TOKEN_ISSUE_ROUTE,')),
    /holds an entry that is not a KeyedRoute literal: TOKEN_ISSUE_ROUTE/);
  assert.throws(() => validateInventory(inventory(), withEntry('KeyedRoute { method: "POST", route: concat!("/v1", "{ADMIN_PREFIX}/tokens") },')),
    /KeyedRoute literal the checker cannot read|not a KeyedRoute literal|string literals/);
});

test("evidence anchors only in the gateway or the compiler it links", () => {
  const anchored = (path) => {
    const value = inventory();
    value.groups[0].sources[0] = { path, anchor: "fn reject_local_authority_in_postgres_mode(" };
    return value;
  };
  assert.doesNotThrow(() => validateInventory(anchored("gateway-config/src/compiler/storage.rs")));
  for (const path of ["docs/configuration.md", "gateway-config/tests/storage.rs", "ggctl/src/main.rs"]) {
    assert.throws(() => validateInventory(anchored(path), () => "fn reject_local_authority_in_postgres_mode("), /runtime or regression source/, path);
  }
});

test("deleting a mode or duplicating its coverage cannot silently pass", () => {
  const missing = inventory();
  missing.groups[0].modes = ["standalone"];
  assert.throws(() => validateInventory(missing), /duplicate coverage/);
  const missingGroup = inventory();
  missingGroup.groups.shift();
  assert.throws(() => validateInventory(missingGroup), /missing coverage/);
});

test("new mutation endpoint in a reviewed admin surface requires inventory review", () => {
  for (const endpoint of ["policy_bulk_put_endpoint", "policy_bulk_accept_endpoint"]) {
    assert.throws(() => validateInventory(inventory(), (path) =>
      source(path) + (path.endsWith("/admin_policy.rs") ? `\npub(super) async fn ${endpoint}(` : "")
    ), /unreviewed mutation entrypoint/);
  }
  assert.throws(() => validateInventory(inventory(), (path) =>
    source(path) + (path.endsWith("/admin_mutation_approvals.rs") ? "\npub(super) async fn bulk_review_endpoint(" : "")
  ), /unreviewed mutation entrypoint/);
});

test("a mutation endpoint in the policy draft, policy test and observability handlers must be reviewed", () => {
  const appending = (file, line) => (path) => source(path) + (path.endsWith(`/${file}`) ? `\n${line}` : "");
  for (const [file, endpoint] of [
    ["admin_policy_drafts.rs", "policy_draft_bulk_publish_endpoint"],
    ["admin_policy_tests.rs", "policy_tests_bulk_put_endpoint"],
    ["admin_observability.rs", "rule_suggestion_bulk_accept_endpoint"],
    ["admin_observability.rs", "principal_bulk_revoke_endpoint"],
    ["admin_policy.rs", "policy_bulk_publish_endpoint"],
  ]) {
    assert.throws(() => validateInventory(inventory(), appending(file, `pub(super) async fn ${endpoint}(`)),
      new RegExp(`unreviewed mutation entrypoint gateway/src/${file}::${endpoint}`), endpoint);
  }
  // The wider scan found suggestion acceptance, which both policy rows now
  // name.
  for (const id of ["policy_postgres", "policy_standalone"]) {
    assert.ok(groupOf(inventory(), id).entrypoints.some((ref) => ref.anchor === "async fn rule_suggestion_accept_endpoint("), id);
  }
  const unnamed = inventory();
  for (const id of ["policy_postgres", "policy_standalone"]) {
    groupOf(unnamed, id).entrypoints = groupOf(unnamed, id).entrypoints.filter((ref) => !ref.anchor.includes("rule_suggestion_accept_endpoint"));
  }
  assert.throws(() => validateInventory(unnamed), /unreviewed mutation entrypoint gateway\/src\/admin_observability\.rs::rule_suggestion_accept_endpoint/);
  // What it found that is not an authority change is excluded by a reviewed
  // table, each entry with a reason; an exclusion must still exist, and an
  // endpoint cannot be both excluded and an inventory entry point.
  assert.deepEqual(Object.keys(NOT_AUTHORITY_CHANGES).sort(), [
    "gateway/src/admin_observability.rs::principal_delegated_tokens_revoke_endpoint",
    "gateway/src/admin_policy_drafts.rs::policy_draft_create_endpoint",
    "gateway/src/admin_policy_drafts.rs::policy_draft_delete_endpoint",
    "gateway/src/admin_policy_drafts.rs::policy_draft_patch_endpoint",
  ]);
  for (const reason of Object.values(NOT_AUTHORITY_CHANGES)) assert.ok(reason.length >= 20, reason);
  const removed = (path) => path.endsWith("/admin_policy_drafts.rs")
    ? source(path).replace("pub(super) async fn policy_draft_patch_endpoint(", "pub(super) async fn policy_draft_amend_endpoint(")
    : source(path);
  assert.throws(() => validateInventory(inventory(), removed), /stale exclusion gateway\/src\/admin_policy_drafts\.rs::policy_draft_patch_endpoint/);
  const both = inventory();
  groupOf(both, "policy_postgres").entrypoints.push({ path: "gateway/src/admin_policy_drafts.rs", anchor: "pub(super) async fn policy_draft_create_endpoint(" });
  assert.throws(() => validateInventory(both), /gateway\/src\/admin_policy_drafts\.rs::policy_draft_create_endpoint is both excluded and an inventory entry point/);
});

test("the summary line is computed from the inventory", () => {
  const line = summary(validateInventory(inventory()));
  assert.match(line, new RegExp(`^Authority evidence inventory valid: ${inventory().groups.length} groups, ${OPERATIONS.length * 2} operation/mode pairs, \\d+ source references\\.`));
  assert.match(line, / Qualified in required mode: catalog\.mcp\.publish\/postgres, .*, connection\.create\/postgres, .*, mutation_approval\.prepare\/postgres\./);
  assert.match(line, / Admitted withdrawals with a reviewed keyed path: connection\.delete\/postgres, connection\.delete\/standalone, service_token\.revoke\/postgres\./);
  assert.equal(summary({ groups: 1, operationModePairs: 2, sourceReferences: 3, qualifiedPairs: [], keyedWithdrawalPairs: [] }),
    "Authority evidence inventory valid: 1 groups, 2 operation/mode pairs, 3 source references. Qualified in required mode: none. Admitted withdrawals with a reviewed keyed path: none.");
});

test("resource creation and replacement retain distinct revision histories", () => {
  for (const [operation, kind, axis, creates] of [
    ["mutation_approval.review", "mutation_approval", "mutation_approval", false],
    ["mutation_approval.revoke", "mutation_approval", "mutation_approval", false],
    ["connection.create", "connection", "connection", true],
    ["secret.create", "local_secret", "secret", true],
    ["service_token.issue", "service_token", "token", true],
    ["connection.replace", "connection", "connection", false],
    ["credential.binding_change", "credential_binding", "credential", false],
    ["secret.rotate", "local_secret", "secret", false],
    ["service_token.rotate", "service_token", "token", false],
    ["service_token.revoke", "service_token", "token", false],
    ["policy.rule.create", "policy", "policy", false],
  ]) {
    const value = fixture();
    value.operation = operation; value.resource.kind = kind;
    value.revision = { axis, before: creates ? null : "1", after: "2", security: "3" };
    assert.doesNotThrow(() => validateEvent(value), operation);
    value.revision.before = creates ? "1" : null;
    assert.throws(() => validateEvent(value), /creation must not claim|requires an existing revision/, operation);
  }
  // Publication can initialize an authority or advance an existing snapshot.
  const firstPublish = fixture(); firstPublish.revision.before = null;
  assert.doesNotThrow(() => validateEvent(firstPublish));
});

test("qualified preparation represents an authenticated caller creating exactly one pending occurrence", () => {
  const value = fixture();
  value.operation = "mutation_approval.prepare";
  value.operation_id = "30000000-0000-7000-8000-000000000001";
  value.resource.kind = "mutation_approval";
  value.revision = { axis: "mutation_approval", before: null, after: "1", security: null };
  assert.doesNotThrow(() => validateEvent(value));
  assert.throws(() => validateEvent({ ...value, operation_id: fixture().operation_id }), /UUIDv7/);
  assert.throws(() => validateEvent({ ...value, actor: { ...value.actor, issuer_ref: null } }), /issuer_ref/);
  const serviceActor = { ...value.actor, kind: "service_token", auth_mode: "service_token" };
  assert.throws(() => validateEvent({ ...value, actor: serviceActor }), /issuer-bound/);
  for (const changes of [{ after: "2" }, { security: "3" }]) {
    assert.throws(() => validateEvent({ ...value, revision: { ...value.revision, ...changes } }), /occurrence revision/);
  }
});

test("stale code and regression anchors fail with an actionable location", () => {
  const stale = inventory();
  stale.groups[0].tests[0].anchor = "async fn absent_authority_regression(";
  assert.throws(() => validateInventory(stale), /stale source anchor.*absent_authority_regression/);
});

test("a document cannot enable required durability or relabel a gap sufficient", () => {
  const qualified = inventory();
  qualified.groups[0].required_durability_supported = true;
  assert.throws(() => validateInventory(qualified), /unproven durability claim/);
  const enabled = inventory();
  enabled.required_durability_mode = "implemented";
  assert.throws(() => validateInventory(enabled), /cannot enable runtime durability/);
  const contradictory = inventory();
  contradictory.groups[0].disposition.push("already_sufficient");
  assert.throws(() => validateInventory(contradictory), /sufficient contradicts/);
});

test("closed event contract accepts large exact revisions independently of JSON key order", () => {
  assert.doesNotThrow(() => validateEvent(fixture()));
  const reordered = fixture();
  reordered.revision = { before: "1", after: "2", security: "3", axis: "policy" };
  assert.doesNotThrow(() => validateEvent(reordered));
  assert.equal(validateEvent(fixture()).revision.after, "9007199254740993");
});

test("all current authentication modes including certificates have a valid actor projection", () => {
  const modes = [...source("gateway/src/auth/principal.rs").matchAll(/Self::[A-Za-z]+ => "([a-z_]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...schema.properties.actor.properties.auth_mode.enum].sort(), [...modes, "system"].sort());
  for (const mode of modes) {
    const value = fixture(); value.actor.auth_mode = mode;
    if (mode === "service_token") value.actor.kind = "service_token";
    assert.doesNotThrow(() => validateEvent(value));
  }
});

test("actor kinds are the evidence tables' vocabulary and agree with the auth mode", () => {
  const kinds = [...source("gateway/src/auth/change_actor.rs").matchAll(/Self::[A-Za-z]+ => "([a-z_]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...schema.properties.actor.properties.kind.enum].sort(), [...kinds].sort());
  const migration = source("gateway/src/storage/migrations/0024_authority_evidence_actor_metadata.sql");
  for (const kind of kinds) assert.ok(migration.includes(`actor_kind = '${kind}'`), kind);
  for (const [kind, mode] of [["principal", "service_token"], ["service_token", "bearer_token"], ["service_token", "system"], ["system", "session_cookie"]]) {
    const value = fixture(); value.actor.kind = kind; value.actor.auth_mode = mode;
    assert.throws(() => validateEvent(value), /actor\/auth mode mismatch/, `${kind}/${mode}`);
  }
});

test("admin session grant and withdrawal project as creation and deletion of a session", () => {
  const granted = fixture();
  granted.operation = "admin_session.grant";
  granted.resource.kind = "admin_session";
  granted.actor.auth_mode = "session_cookie";
  granted.revision = { axis: "session", before: null, after: "1", security: null };
  assert.doesNotThrow(() => validateEvent(granted));
  granted.revision.before = "1";
  assert.throws(() => validateEvent(granted), /creation must not claim/);
  const withdrawn = fixture();
  withdrawn.operation = "admin_session.withdraw";
  withdrawn.resource.kind = "admin_session";
  withdrawn.revision = { axis: "session", before: "1", after: null, security: null };
  assert.doesNotThrow(() => validateEvent(withdrawn));
  withdrawn.revision.after = "2";
  assert.throws(() => validateEvent(withdrawn), /tombstone/);
  withdrawn.revision = { axis: "token", before: "1", after: null, security: null };
  assert.throws(() => validateEvent(withdrawn), /axis mismatch/);
});

test("the in-memory session authority stays unsupported and the shared one records and delivers transactional evidence", () => {
  const sessions = inventory().groups.filter((group) => group.operations.some((operation) => operation.startsWith("admin_session.")));
  for (const group of sessions) assert.equal(group.required_durability_supported, false, group.id);
  const standalone = sessions.filter((group) => group.modes.includes("standalone"));
  assert.deepEqual(standalone.map((group) => group.id), ["admin_session_standalone"]);
  assert.deepEqual(standalone[0].operations, ["admin_session.grant", "admin_session.withdraw"]);
  assert.deepEqual(standalone[0].disposition, ["unsupported_future_operation"]);
  assert.equal(standalone[0].delivery, "post_commit_telemetry");
  // The shared authority grants and withdraws in separate rows: neither has
  // a caller key, and the grant is not a withdrawal (owner ruling 5 of #425).
  const postgres = sessions.filter((group) => group.modes.includes("postgres"));
  assert.deepEqual(postgres.map((group) => [group.id, group.operations, group.modes]), [
    ["admin_session_grant_postgres", ["admin_session.grant"], ["postgres"]],
    ["admin_session_withdraw_postgres", ["admin_session.withdraw"], ["postgres"]],
  ]);
  for (const group of postgres) {
    assert.deepEqual(group.disposition, ["no_caller_key"], group.id);
    assert.equal(group.required_mode, "admitted", group.id);
    assert.equal(group.delivery, "journaled_dispatch", group.id);
    assert.ok(group.sources.some((ref) => ref.anchor.includes("admin_session_evidence")), group.id);
    assert.ok(group.sources.some((ref) => ref.anchor.includes("reserved_withdrawals")), group.id);
  }
});

// The rows required mode admits without qualification (issue #425, plan
// section 3.5, owner rulings 3 to 5). Each disposition is a closed list of
// operation/mode pairs, so neither can be used to relabel a gap.
const NO_CALLER_KEY = ["admin_session.grant/postgres", "admin_session.withdraw/postgres", "jwt.revoke/postgres", "secret.reencrypt/standalone"];
const WITHDRAWALS = ["connection.delete/postgres", "connection.delete/standalone", "secret.delete/standalone", "service_token.revoke/postgres", "service_token.revoke/standalone"];
const pairsOf = (group) => group.operations.flatMap((operation) => group.modes.map((mode) => `${operation}/${mode}`));
const rowsWith = (value, disposition) => value.groups.filter((group) => group.disposition.includes(disposition));
const row = (value, id) => value.groups.find((group) => group.id === id);

test("no_caller_key is limited to its reviewed pairs", () => {
  assert.deepEqual(rowsWith(inventory(), "no_caller_key").flatMap(pairsOf).sort(), NO_CALLER_KEY);
  for (const group of rowsWith(inventory(), "no_caller_key")) {
    assert.deepEqual(group.disposition, ["no_caller_key"], group.id);
    assert.equal(group.qualified_delivery_paths, undefined, group.id);
  }
  // A caller-started change that is not a withdrawal cannot be relabelled.
  for (const id of ["mutation_approvals", "token_rotate_postgres", "local_secrets", "token_issue_standalone", "policy_postgres", "local_secret_delete"]) {
    const relabelled = inventory();
    row(relabelled, id).disposition = ["no_caller_key"];
    assert.throws(() => validateInventory(relabelled), new RegExp(`${id}: no_caller_key is limited to its reviewed pairs`), id);
  }
  // Moving a reviewed pair into a wider row does not widen the label.
  const widened = inventory();
  row(widened, "admin_session_grant_postgres").operations = ["admin_session.grant", "connection.create"];
  row(widened, "connection_postgres").operations = ["connection.replace", "credential.binding_change"];
  row(widened, "connection_postgres").qualified_delivery_paths = row(widened, "connection_postgres").qualified_delivery_paths
    .filter((path) => path.criteria.operation !== "connection.create");
  assert.throws(() => validateInventory(widened), /admin_session_grant_postgres: no_caller_key is limited to its reviewed pairs/);
  // It stands alone, and a row that has it carries no keyed path.
  const combined = inventory();
  row(combined, "jwt_postgres").disposition = ["no_caller_key", "missing_metadata"];
  assert.throws(() => validateInventory(combined), /jwt_postgres: no_caller_key stands alone/);
  const keyed = inventory();
  row(keyed, "jwt_postgres").qualified_delivery_paths = structuredClone(row(keyed, "token_revoke_postgres").qualified_delivery_paths);
  assert.throws(() => validateInventory(keyed), /unreviewed qualified path|jwt_postgres: a no_caller_key row has no keyed path/);
});

test("withdrawal_admitted is limited to its reviewed pairs and needs a reviewed keyed path", () => {
  const revoke = (value) => row(value, "token_revoke_postgres");
  const current = inventory();
  assert.deepEqual(rowsWith(current, "withdrawal_admitted").map((group) => group.id),
    ["connection_delete_postgres", "connection_delete_standalone", "token_revoke_postgres"]);
  for (const id of ["connection_delete_postgres", "connection_delete_standalone"]) {
    assert.deepEqual(row(current, id).qualified_delivery_paths.map((path) => path.criteria.method), ["DELETE"], id);
  }
  assert.deepEqual(revoke(current).disposition, ["withdrawal_admitted"]);
  assert.deepEqual(pairsOf(revoke(current)), ["service_token.revoke/postgres"]);
  assert.equal(revoke(current).qualified_delivery_paths.length, 1);
  for (const pair of rowsWith(current, "withdrawal_admitted").flatMap(pairsOf)) assert.ok(WITHDRAWALS.includes(pair), pair);
  // A change that grants or replaces authority is never a withdrawal.
  for (const id of ["token_rotate_postgres", "policy_postgres", "local_secrets", "mutation_approvals", "jwt_postgres"]) {
    const relabelled = inventory();
    row(relabelled, id).disposition = ["withdrawal_admitted"];
    assert.throws(() => validateInventory(relabelled), new RegExp(`${id}: withdrawal_admitted is limited to its reviewed pairs`), id);
  }
  // Rotation folded back into the revoke row is not a withdrawal either.
  const folded = inventory();
  revoke(folded).operations = ["service_token.rotate", "service_token.revoke"];
  folded.groups = folded.groups.filter((group) => group.id !== "token_rotate_postgres");
  assert.throws(() => validateInventory(folded), /token_revoke_postgres: withdrawal_admitted is limited to its reviewed pairs/);
  // A withdrawal with no reviewed keyed path yet keeps its gap label: the
  // label is earned by the path, one per pair.
  for (const id of ["local_secret_delete", "token_revoke_standalone"]) {
    const unearned = inventory();
    row(unearned, id).disposition = ["withdrawal_admitted"];
    assert.throws(() => validateInventory(unearned), new RegExp(`${id}: withdrawal_admitted needs one reviewed keyed path per pair`), id);
  }
  const pathless = inventory();
  delete revoke(pathless).qualified_delivery_paths;
  assert.throws(() => validateInventory(pathless), /missing qualified revoke path|withdrawal_admitted needs one reviewed keyed path per pair/);
  const doubled = inventory();
  revoke(doubled).qualified_delivery_paths.push(structuredClone(revoke(doubled).qualified_delivery_paths[0]));
  assert.throws(() => validateInventory(doubled), /missing qualified revoke path|withdrawal_admitted needs one reviewed keyed path per pair/);
  // It stands alone, and the reviewed path belongs to a withdrawal_admitted row.
  const combined = inventory();
  revoke(combined).disposition = ["withdrawal_admitted", "missing_metadata"];
  assert.throws(() => validateInventory(combined), /token_revoke_postgres: withdrawal_admitted stands alone/);
  const gap = inventory();
  revoke(gap).disposition = ["missing_metadata"];
  assert.throws(() => validateInventory(gap), /token_revoke_postgres: a keyed path on an unqualified row needs withdrawal_admitted/);
});

test("neither disposition can claim required durability", () => {
  for (const disposition of ["no_caller_key", "withdrawal_admitted"]) {
    for (const group of rowsWith(inventory(), disposition)) {
      assert.equal(group.required_mode, "admitted", group.id);
      assert.equal(group.required_durability_supported, false, group.id);
      const supported = inventory();
      row(supported, group.id).required_durability_supported = true;
      assert.throws(() => validateInventory(supported), /unproven durability claim|is admitted and unqualified/, group.id);
      for (const mode of ["caller_key_required", "refused", "unavailable", "outside_gateway"]) {
        const moved = inventory();
        row(moved, group.id).required_mode = mode;
        assert.throws(() => validateInventory(moved), /unreviewed caller-key admission|is admitted and unqualified/, `${group.id} ${mode}`);
      }
    }
  }
  // The refused offline import is not one of them.
  const imported = inventory();
  row(imported, "configuration_import").disposition = ["no_caller_key"];
  assert.throws(() => validateInventory(imported), /configuration_import: no_caller_key is limited to its reviewed pairs/);
});

test("standalone evidence rows are delivered from their own stores and only they are", () => {
  const groups = inventory().groups;
  const delivered = groups.filter((group) => group.delivery === "standalone_cursor_dispatch").map((group) => group.id).sort();
  assert.deepEqual(delivered, [
    "catalog_standalone",
    "connection_delete_standalone",
    "connection_standalone",
    "local_secret_delete",
    "local_secret_reencrypt",
    "local_secrets",
    "token_issue_standalone",
    "token_revoke_standalone",
    "token_rotate_standalone",
  ]);
  for (const group of groups.filter((group) => delivered.includes(group.id))) {
    assert.deepEqual(group.modes, ["standalone"], group.id);
    assert.ok(["admitted", "caller_key_required"].includes(group.required_mode), group.id);
    assert.ok(!group.disposition.includes("missing_delivery"), group.id);
  }
  const profile = inventory().delivery_profiles.standalone_cursor_dispatch;
  assert.ok(profile.sources.some((ref) => ref.anchor.includes("MIGRATION_14_SQL")));
  assert.ok(profile.sources.some((ref) => ref.anchor.includes("run_standalone_dispatcher")));
});

test("required mode never admits an unsupported row or waves through a reachable one", () => {
  const groups = inventory().groups;
  for (const group of groups) {
    if (group.disposition.includes("unsupported_future_operation")) assert.notEqual(group.required_mode, "admitted", group.id);
  }
  const byId = Object.fromEntries(groups.map((group) => [group.id, group.required_mode]));
  assert.equal(byId.admin_session_standalone, "refused_at_startup");
  assert.equal(byId.policy_standalone, "refused");
  assert.equal(byId.token_rotate_standalone, "admitted");
  assert.equal(byId.token_revoke_standalone, "admitted");
  // The standalone Connections database records these in the change's own transaction.
  assert.equal(byId.connection_standalone, "caller_key_required");
  assert.equal(byId.connection_delete_standalone, "admitted");
  assert.equal(byId.local_secrets, "admitted");
  assert.equal(byId.local_secret_delete, "admitted");
  assert.equal(byId.local_secret_reencrypt, "admitted");
  // The offline import records evidence for two of its sections only.
  assert.equal(byId.configuration_import, "refused");
  assert.equal(byId.catalog_standalone, "caller_key_required");
  assert.equal(byId.configuration_activation, "refused_at_startup");

  const unknown = inventory();
  unknown.groups[0].required_mode = "ignored";
  assert.throws(() => validateInventory(unknown), /unknown required mode/);
  const admitted = inventory();
  admitted.groups.find((group) => group.id === "policy_standalone").required_mode = "admitted";
  assert.throws(() => validateInventory(admitted), /admits an unsupported operation/);
  const waved = inventory();
  waved.groups.find((group) => group.id === "mutation_approvals").required_mode = "outside_gateway";
  assert.throws(() => validateInventory(waved), /reachable entry point/);
});

test("not_refused is not a required mode", () => {
  // Required mode once ran configuration activation unrefused; owner
  // decision 2 (2026-11-19) made it refuse to start instead, so no row can
  // be waved through by that value any more, with or without entry points.
  for (const id of ["external_rotation", "configuration_activation", "mutation_approvals"]) {
    const changed = inventory();
    changed.groups.find((group) => group.id === id).required_mode = "not_refused";
    assert.throws(() => validateInventory(changed), /unknown required mode|activation stays refused at startup/, id);
  }
  const external = inventory();
  external.groups.find((group) => group.id === "external_rotation").required_mode = "not_refused";
  assert.throws(() => validateInventory(external), /external_rotation: unknown required mode/);
});

test("configuration activation stays refused at startup while the activation proof is uninhabited", () => {
  const PROOF = { path: "gateway/src/authority_events/required.rs", anchor: "pub(crate) enum ActivationProof {}" };
  const activation = (value) => value.groups.find((group) => group.id === "configuration_activation");
  assert.ok(source(PROOF.path).includes(PROOF.anchor), "the proof type is uninhabited on this branch");
  assert.ok(activation(inventory()).sources.some((ref) => ref.path === PROOF.path && ref.anchor === PROOF.anchor));
  for (const mode of ["admitted", "refused", "unavailable", "outside_gateway", "caller_key_required"]) {
    const changed = inventory();
    activation(changed).required_mode = mode;
    assert.throws(() => validateInventory(changed), /activation stays refused at startup|unreviewed caller-key admission/, mode);
  }
  const supported = inventory();
  activation(supported).required_durability_supported = true;
  assert.throws(() => validateInventory(supported), /activation stays refused at startup|unproven durability claim/);
  // The row must name the proof it waits for ...
  const unanchored = inventory();
  activation(unanchored).sources = activation(unanchored).sources.filter((ref) => ref.anchor !== PROOF.anchor);
  assert.throws(() => validateInventory(unanchored), /must anchor on the uninhabited activation proof/);
  // ... and moving the activation into another row does not escape the rule.
  const moved = inventory();
  const split = { ...structuredClone(activation(moved)), id: "configuration_activation_standalone", modes: ["standalone"], required_mode: "admitted" };
  activation(moved).modes = ["postgres"];
  moved.groups.push(split);
  assert.throws(() => validateInventory(moved), /configuration_activation_standalone: configuration activation stays refused at startup/);
  // Giving the proof a value (issue #242) breaks the row's anchor, so the
  // type, the startup check and this row change in one reviewed change.
  const inhabited = (path) => source(path).replace(PROOF.anchor, "pub(crate) struct ActivationProof { _ledger: () }");
  assert.throws(() => validateInventory(inventory(), inhabited), /stale source anchor: gateway\/src\/authority_events\/required\.rs :: pub\(crate\) enum ActivationProof \{\}/);
});

test("the activation rule follows the proof type's shape and the place serving startup asks", () => {
  const PROOF = { path: "gateway/src/authority_events/required.rs", anchor: "pub(crate) enum ActivationProof {}" };
  const CHECK = { path: "gateway/src/bootstrap/stages.rs", anchor: "crate::authority_events::required::startup_refusal(&config)" };
  const activation = (value) => value.groups.find((group) => group.id === "configuration_activation");
  const rewriting = (path, from, to) => (read) => read === path ? source(read).replace(from, to) : source(read);
  assert.ok(activation(inventory()).sources.some((ref) => ref.path === CHECK.path && ref.anchor === CHECK.anchor));
  assert.ok(source(CHECK.path).includes(CHECK.anchor), "serving startup asks on this branch");

  // A visibility change keeps the type uninhabited, so the rule stays on even
  // when the row is re-anchored on the new spelling and admitted.
  for (const spelling of ["pub enum ActivationProof {}", "pub(crate) enum ActivationProof{ }", "enum ActivationProof {\n}"]) {
    const widened = inventory();
    activation(widened).sources = activation(widened).sources.map((ref) => ref.anchor === PROOF.anchor ? { ...ref, anchor: spelling } : ref);
    activation(widened).required_mode = "admitted";
    activation(widened).disposition = ["missing_metadata"];
    assert.throws(() => validateInventory(widened, rewriting(PROOF.path, PROOF.anchor, spelling)),
      /configuration_activation: configuration activation stays refused at startup/, spelling);
    // Re-anchored but still refused at startup, the new spelling is accepted.
    const kept = inventory();
    activation(kept).sources = activation(kept).sources.map((ref) => ref.anchor === PROOF.anchor ? { ...ref, anchor: spelling } : ref);
    validateInventory(kept, rewriting(PROOF.path, PROOF.anchor, spelling));
  }

  // Renaming or removing the type cannot switch the rule off, and a
  // declaration left in a comment does not count.
  for (const replacement of ["pub(crate) enum ActivationEvidence {}", "", `// ${PROOF.anchor}\npub(crate) enum ActivationEvidence {}`]) {
    const renamed = inventory();
    activation(renamed).sources = activation(renamed).sources.filter((ref) => ref.anchor !== PROOF.anchor);
    activation(renamed).required_mode = "admitted";
    activation(renamed).disposition = ["missing_metadata"];
    assert.throws(() => validateInventory(renamed, rewriting(PROOF.path, PROOF.anchor, replacement)),
      /declares no ActivationProof/, JSON.stringify(replacement));
  }

  // The row must name the place serving startup asks: dropping that anchor
  // fails, and so does removing the call while the row keeps it.
  const dropped = inventory();
  activation(dropped).sources = activation(dropped).sources.filter((ref) => ref.anchor !== CHECK.anchor);
  assert.throws(() => validateInventory(dropped), /configuration_activation: configuration activation must anchor on the startup check in gateway\/src\/bootstrap\/stages\.rs/);
  const uncalled = rewriting(CHECK.path, CHECK.anchor, "None::<()>");
  assert.throws(() => validateInventory(dropped, uncalled), /must anchor on the startup check/);
  assert.throws(() => validateInventory(inventory(), uncalled), /stale source anchor: gateway\/src\/bootstrap\/stages\.rs :: crate::authority_events::required::startup_refusal\(&config\)/);
});

test("export evidence binds an existing configuration revision without inventing a mutation", () => {
  const value = fixture();
  value.operation = "configuration.export";
  value.resource.kind = "configuration";
  value.revision = { axis: "configuration", before: "7", after: "7", security: null };
  assert.doesNotThrow(() => validateEvent(value));
  value.revision.after = "8";
  assert.throws(() => validateEvent(value), /unchanged authority revision/);
});

test("JWT event projection uses the committed shared revision rather than the outbox sentinel", () => {
  const value = fixture();
  value.operation = "jwt.revoke";
  value.resource.kind = "jwt_revocation";
  value.revision = { axis: "jwt_revocation", before: null, after: "7", security: "7" };
  assert.doesNotThrow(() => validateEvent(value));
  value.revision.after = "1";
  assert.throws(() => validateEvent(value), /shared security revision/);
});

test("tombstone and maintenance events do not invent revision transitions", () => {
  const deleted = fixture();
  deleted.operation = "connection.delete";
  deleted.resource.kind = "connection";
  deleted.revision = { axis: "connection", before: "7", after: null, security: "12" };
  assert.doesNotThrow(() => validateEvent(deleted));
  deleted.revision.after = "0";
  assert.throws(() => validateEvent(deleted), /tombstone/);
  const reencrypt = fixture();
  reencrypt.operation = "secret.reencrypt";
  reencrypt.resource.kind = "local_secret";
  reencrypt.revision = { axis: "maintenance", before: null, after: null, security: null };
  reencrypt.actor = { ...reencrypt.actor, kind: "system", auth_mode: "system" };
  assert.doesNotThrow(() => validateEvent(reencrypt));
  reencrypt.revision.after = "1";
  assert.throws(() => validateEvent(reencrypt), /must not invent/);
});

test("failed, stale and unchanged operations cannot masquerade as committed changes", () => {
  for (const result of ["failed", "denied", "precondition_failed", "no_op"]) {
    const value = fixture(); value.result = result;
    assert.throws(() => validateEvent(value), /unexpected constant/);
  }
  for (const after of ["9007199254740992", "1", "0", null]) {
    const value = fixture(); value.revision.after = after;
    assert.throws(() => validateEvent(value), /revision must advance|needs an authority revision/);
  }
});

test("secret-bearing fields are rejected at every object boundary", () => {
  const fields = ["token", "secret_id", "ciphertext", "nonce", "provider_locator", "key_id", "authorization", "cookie", "payload", "raw_error", "url", "certificate", "private_key"];
  for (const location of [null, "actor", "resource", "revision"]) for (const field of fields) {
    const value = fixture();
    (location ? value[location] : value)[field] = "synthetic-forbidden-value";
    assert.throws(() => validateEvent(value), /unknown field/, String(location) + "." + field);
  }
  for (const reference of ["https://example.invalid/provider?secret=fixture", "Bearer synthetic-token", "../fixture-key", "fixture@example.invalid"]) {
    const value = fixture(); value.resource.ref = reference;
    assert.throws(() => validateEvent(value), /invalid shape/);
  }
});

test("malformed identity, timestamp, numeric representation and category fail closed", () => {
  const changes = [
    (value) => { delete value.operation_id; },
    (value) => { value.event_id = "fixture-token"; },
    (value) => { value.actor.subject_ref = "a".repeat(65); },
    (value) => { value.actor.auth_mode = "system"; },
    (value) => { value.committed_at = "2026-02-30T12:00:00Z"; },
    (value) => { value.committed_at = "2026-09-08T24:00:00Z"; },
    (value) => { value.revision.after = 9007199254740993; },
    (value) => { value.revision.after = "9223372036854775808"; },
    (value) => { value.revision.before = "-1"; },
    (value) => { value.revision.security = "0"; },
    (value) => { value.operation = "unknown.publish"; },
    (value) => { value.resource.kind = "connection"; },
    (value) => { value.revision.axis = "connection"; },
  ];
  for (const change of changes) {
    const value = fixture(); change(value);
    assert.throws(() => validateEvent(value));
  }
});

test("every required event field is actually enforced", () => {
  for (const field of schema.required) {
    const value = fixture(); delete value[field];
    assert.throws(() => validateEvent(value), /missing/);
  }
  for (const name of ["actor", "resource", "revision"]) for (const field of schema.properties[name].required) {
    const value = fixture(); delete value[name][field];
    assert.throws(() => validateEvent(value), /missing/);
  }
});

test("schema extensions cannot silently add constraints this checker ignores", () => {
  assert.throws(() => validateSchema("fixture", { type: "string", minLength: 50 }), /unsupported schema keyword/);
  assert.throws(() => validateSchema(null, { anyOf: [{ type: "null" }, { type: "string", minLength: 50 }] }), /unsupported schema keyword/);
  assert.throws(() => validateSchema({}, { type: "object", properties: { absent: { type: "string", minLength: 50 } } }), /unsupported schema keyword/);
});
