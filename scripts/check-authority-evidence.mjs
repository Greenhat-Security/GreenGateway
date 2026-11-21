#!/usr/bin/env node
// #425 PR1: source inventory and proposed wire contract, not runtime certification.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
export const OPERATIONS = [
  "admin_session.grant",
  "admin_session.withdraw",
  "catalog.mcp.publish",
  "catalog.openapi.publish",
  "catalog.overlay.delete",
  "catalog.overlay.replace",
  "configuration.activate",
  "configuration.export",
  "configuration.import",
  "connection.create",
  "connection.delete",
  "connection.replace",
  "credential.binding_change",
  "jwt.revoke",
  "mutation_approval.consume",
  "mutation_approval.prepare",
  "mutation_approval.review",
  "mutation_approval.revoke",
  "policy.file_reload",
  "policy.publish",
  "policy.rollback",
  "policy.rule.create",
  "policy.rule.delete",
  "policy.rule.reorder",
  "policy.rule.update",
  "policy.suggestion.accept",
  "policy_tests.publish",
  "secret.create",
  "secret.delete",
  "secret.external_rotate",
  "secret.reencrypt",
  "secret.rotate",
  "service_token.issue",
  "service_token.revoke",
  "service_token.rotate",
  "tools.publish"
];
const MODES = ["postgres", "standalone"];
const REVISION_OPERATIONS = {
  create: ["mutation_approval.prepare", "admin_session.grant", "connection.create", "secret.create", "service_token.issue"],
  advance: ["mutation_approval.consume", "mutation_approval.review", "mutation_approval.revoke", "connection.replace", "credential.binding_change", "catalog.overlay.delete", "catalog.overlay.replace",
    "policy.rollback", "policy.rule.create", "policy.rule.delete", "policy.rule.reorder", "policy.rule.update", "policy.suggestion.accept",
    "secret.rotate", "secret.external_rotate", "service_token.rotate", "service_token.revoke"],
  publish: ["catalog.mcp.publish", "catalog.openapi.publish", "configuration.activate", "configuration.import",
    "jwt.revoke", "policy.file_reload", "policy.publish", "policy_tests.publish", "tools.publish"],
  delete: ["admin_session.withdraw", "connection.delete", "secret.delete"],
  export: ["configuration.export"],
  maintenance: ["secret.reencrypt"],
};
assert.deepEqual(Object.values(REVISION_OPERATIONS).flat().sort(), [...OPERATIONS].sort(), "every operation needs exactly one revision contract");
const DISPOSITIONS = new Set(["already_sufficient", "missing_metadata", "missing_delivery", "unsupported_future_operation", "no_caller_key", "withdrawal_admitted"]);
// Rows required mode admits without qualification (issue #425, owner rulings
// of 2026-11-20). Each disposition stands alone, holds only its reviewed
// operation/mode pairs, and is admitted and unqualified, so neither can
// relabel a gap. `no_caller_key`: no authenticated remote caller starts the
// change, so no key can be bound to it; it is reconciled by its natural key
// (the issuer-scoped JTI digest, the session ID, the maintenance batch). The
// grant is not a withdrawal and is listed by its own ruling.
// `withdrawal_admitted`: a remote caller starts a change that only removes
// authority, so refusing its unkeyed or service-token form would fail open;
// the row is earned by a reviewed keyed path for every pair it holds.
const NO_CALLER_KEY_PAIRS = new Set(["jwt.revoke/postgres", "admin_session.withdraw/postgres", "secret.reencrypt/standalone", "admin_session.grant/postgres"]);
const WITHDRAWAL_PAIRS = new Set(["service_token.revoke/postgres", "service_token.revoke/standalone", "connection.delete/postgres", "connection.delete/standalone", "secret.delete/standalone"]);
const ADMITTED_UNQUALIFIED = { no_caller_key: NO_CALLER_KEY_PAIRS, withdrawal_admitted: WITHDRAWAL_PAIRS };
// The admin handler files whose mutation endpoints must each be an inventory
// entry point or a reviewed exclusion.
const ADMIN_FILES = ["admin_policy.rs", "admin_policy_drafts.rs", "admin_policy_tests.rs", "admin_observability.rs", "admin_tools.rs", "admin_mutation_approvals.rs", "admin_connections.rs", "admin_tokens.rs"];
const MUTATION_ENDPOINT = /(?:create|put|post|patch|delete|rollback|register|rotate|revoke|refresh|accept|publish)_endpoint$/;
// Endpoints the scan finds that are not authority changes, each with the
// reason it is outside the inventory. An exclusion must name an endpoint
// that exists and that no row claims.
export const NOT_AUTHORITY_CHANGES = {
  "gateway/src/admin_policy_drafts.rs::policy_draft_create_endpoint": "a policy draft is not active policy; only publishing one changes authority, and that is policy.publish",
  "gateway/src/admin_policy_drafts.rs::policy_draft_patch_endpoint": "a policy draft is not active policy; only publishing one changes authority, and that is policy.publish",
  "gateway/src/admin_policy_drafts.rs::policy_draft_delete_endpoint": "a policy draft is not active policy; only publishing one changes authority, and that is policy.publish",
  "gateway/src/admin_observability.rs::principal_delegated_tokens_revoke_endpoint": "the delegated-token purge withdraws cached delegated credentials; it is audited and recorded as a shared security revision through the operation gate, and is outside the authority-change inventory by owner ruling 8 on issue #425 (2026-11-20)",
};
const SCHEMA_KEYWORDS = new Set(["$schema", "title", "description", "type", "const", "enum", "anyOf", "pattern", "maxLength", "additionalProperties", "required", "properties"]);
export const readJson = (path) => JSON.parse(readFileSync(resolve(ROOT, path), "utf8"));
export const schema = readJson("docs/schemas/authority_event.v1.schema.json");

function check(condition, message) {
  if (!condition) throw new Error(message);
}

// Inspect the whole definition independently of the value, including unselected
// anyOf branches and absent properties, so new constraints cannot go unchecked.
export function validateSchemaDefinition(definition) {
  check(definition !== null && typeof definition === "object" && !Array.isArray(definition), "expected schema definition object");
  for (const key of Object.keys(definition)) check(SCHEMA_KEYWORDS.has(key), `unsupported schema keyword ${key}`);
  check([undefined, "object", "string", "null"].includes(definition.type), "unsupported schema type");
  if ("anyOf" in definition) {
    check(Array.isArray(definition.anyOf) && definition.anyOf.length > 0, "expected nonempty anyOf");
    for (const branch of definition.anyOf) validateSchemaDefinition(branch);
  }
  if ("properties" in definition) {
    check(definition.properties !== null && typeof definition.properties === "object" && !Array.isArray(definition.properties), "expected schema properties object");
    for (const property of Object.values(definition.properties)) validateSchemaDefinition(property);
  }
}

export function validateSchema(value, definition) {
  validateSchemaDefinition(definition);
  return validateSchemaValue(value, definition);
}

validateSchemaDefinition(schema);

function validateSchemaValue(value, definition, location = "$") {
  if ("anyOf" in definition) {
    check(definition.anyOf.some((branch) => {
      try { validateSchemaValue(value, branch, location); return true; } catch { return false; }
    }), `${location}: no allowed shape`);
  }
  if ("const" in definition) check(value === definition.const, `${location}: unexpected constant`);
  if ("enum" in definition) check(definition.enum.includes(value), `${location}: unknown category`);
  if (definition.type === "object") {
    check(value !== null && typeof value === "object" && !Array.isArray(value), `${location}: expected object`);
    for (const key of definition.required ?? []) check(Object.hasOwn(value, key), `${location}: missing ${key}`);
    for (const key of Object.keys(value)) {
      check(Object.hasOwn(definition.properties, key) || definition.additionalProperties !== false, `${location}: unknown field`);
      if (Object.hasOwn(definition.properties, key)) validateSchemaValue(value[key], definition.properties[key], `${location}.${key}`);
    }
  } else if (definition.type === "string") {
    check(typeof value === "string", `${location}: expected string`);
    if (definition.pattern) check(new RegExp(definition.pattern, "u").test(value), `${location}: invalid shape`);
    if (definition.maxLength) check([...value].length <= definition.maxLength, `${location}: too long`);
  } else if (definition.type === "null") {
    check(value === null, `${location}: expected null`);
  } else check(definition.type === undefined, `${location}: unsupported type`);
}

const resourceFor = (operation) => ({
  admin_session: "admin_session", mutation_approval: "mutation_approval",
  policy: "policy", policy_tests: "policy", tools: "tools", connection: "connection", credential: "credential_binding",
  catalog: "catalog", service_token: "service_token", jwt: "jwt_revocation", configuration: "configuration",
  secret: operation === "secret.external_rotate" ? "external_secret" : "local_secret",
})[operation.split(".")[0]];

export function validateEvent(event) {
  validateSchemaValue(event, schema);
  check(event.resource.kind === resourceFor(event.operation), "operation/resource mismatch");
  // Kind and auth mode agree as the evidence records them (migration 24): a
  // system actor is exactly the system mode, a service token exactly the
  // service_token mode, and every other mode is a principal's.
  check((event.actor.kind === "system") === (event.actor.auth_mode === "system"), "actor/auth mode mismatch");
  check((event.actor.kind === "service_token") === (event.actor.auth_mode === "service_token"), "actor/auth mode mismatch");
  const timestamp = event.committed_at.replace(/\.\d+Z$/, "Z");
  const instant = new Date(timestamp);
  check(Number.isFinite(instant.valueOf()) && instant.toISOString().replace(".000Z", "Z") === timestamp, "invalid calendar instant");
  for (const value of [event.revision.before, event.revision.after, event.revision.security]) {
    if (value !== null) check(BigInt(value) <= 9223372036854775807n, "revision exceeds signed 64-bit authority range");
  }
  const { before, after, security, axis } = event.revision;
  if (security !== null) check(BigInt(security) > 0n, "shared security revision must be positive");
  const transition = Object.entries(REVISION_OPERATIONS).find(([, operations]) => operations.includes(event.operation))[0];
  if (transition === "delete") check(before !== null && BigInt(before) > 0n && after === null, "deletion requires previous revision and tombstone");
  else if (transition === "export") {
    check(before !== null && BigInt(before) > 0n && after === before, "export must bind an unchanged authority revision");
  }
  else if (transition === "maintenance") {
    check(axis === "maintenance" && before === null && after === null, "re-encryption must not invent an authority revision");
  } else {
    check(after !== null && BigInt(after) > 0n, "committed mutation needs an authority revision");
    if (transition === "create") check(before === null, "creation must not claim a previous revision");
    if (transition === "advance") check(before !== null, "operation requires an existing revision");
    // JWT outbox values are a fixed sentinel, not a version chain. A new
    // authority event uses its security revision as the revocation axis.
    if (before !== null) check(BigInt(after) > BigInt(before), "revision must advance");
  }
  if (event.operation === "jwt.revoke") check(security !== null && after === security, "JWT event axis must use the shared security revision");
  const expectedAxis = event.operation.startsWith("admin_session.") ? "session"
    : event.operation.startsWith("mutation_approval.") ? "mutation_approval"
    : event.operation.startsWith("policy.") ? "policy"
    : event.operation.startsWith("policy_tests.") ? "policy_tests"
    : event.operation.startsWith("tools.") ? "tools"
    : event.operation.startsWith("connection.") ? "connection"
    : event.operation.startsWith("credential.") ? "credential"
    : event.operation.startsWith("catalog.") ? "catalog"
    : event.operation === "secret.reencrypt" ? "maintenance"
    : event.operation.startsWith("secret.") ? "secret"
    : event.operation.startsWith("service_token.") ? "token"
    : event.operation === "jwt.revoke" ? "jwt_revocation" : "configuration";
  check(axis === expectedAxis, "operation/revision axis mismatch");
  if (event.operation === "mutation_approval.prepare") {
    check(event.operation_id[14] === "7", "prepare requires a caller-supplied UUIDv7");
    check(event.actor.kind === "principal", "prepare requires an issuer-bound principal");
    check(after === "1" && security === null, "prepare creates occurrence revision 1 without a security revision");
  }
  return event;
}

// What AUTHORITY_EVIDENCE_DURABILITY=required does with a row (issue #425,
// PR 4). `admitted` runs it with the atomic record the row describes;
// `caller_key_required` admits only the keyed form on its reviewed paths.
// `refused` and `refused_at_startup` refuse it when asked or when the
// configuration enables it; `unavailable` rows cannot run in the mode at
// all; `outside_gateway` is a provider's write the gateway cannot refuse.
// No row is run unrefused: the activation that starts the gateway is refused
// at startup (owner decision 2 of #425, 2026-11-19).
const REQUIRED_MODES = new Set(["admitted", "caller_key_required", "refused", "refused_at_startup", "unavailable", "outside_gateway"]);

// Serving startup refuses required mode until a configuration activation can
// be proven durably recorded. The proof type has no value until #242 gives it
// one; while it has none, every row holding configuration.activate stays
// refused at startup and anchors on the type and on the place serving startup
// asks, so making it inhabited, or moving the check, breaks an anchor and the
// row changes in the same reviewed change. The type is recognised by its
// shape, not one spelling: a visibility change keeps the rule on, and a
// rename or removal fails outright instead of switching it off.
const ACTIVATION_PROOF_PATH = "gateway/src/authority_events/required.rs";
const ACTIVATION_PROOF_DECLARED = /\b(?:enum|struct|union|type)\s+ActivationProof\b/;
const ACTIVATION_PROOF_UNINHABITED = /\benum\s+ActivationProof\s*\{\s*\}/;
const ACTIVATION_CHECK = { path: "gateway/src/bootstrap/stages.rs", anchor: "crate::authority_events::required::startup_refusal(&config)" };
const withoutLineComments = (text) => text.replace(/\/\/.*$/gm, "");

// The gateway's source, and the configuration compiler it links from the
// shared gateway-config library (issue #242), which refuses the settings the
// evidence rows anchor on.
const SOURCE_ROOTS = ["gateway/src/", "gateway-config/src/"];

// The reviewed qualified delivery paths, one per operation/mode pair (issue
// #425). A path in the inventory must equal its entry here, criterion for
// criterion, and a row claims required durability exactly when every pair it
// holds has its path (see the qualification bar below). Adding an entry is
// the reviewed change that qualifies a pair: copy the method and route from
// KEYED_ROUTES in gateway/src/routing.rs, which must honour the key there.
// The criteria shared by every entry are the ones the evidence gate enforces
// (gateway/src/authority_events/required.rs, KeyedAdmission).
const KEYED_DELIVERY = {
  operation_id_version: 7, actor_kind: "principal", issuer: "canonical_provider", format: "qualified_v1",
  durable_sink: "file", filesystem: "unix_file_and_directory_sync", wire_schema: "authority_event.v1",
};
export const QUALIFIED_PATHS = Object.freeze({
  // Admitted withdrawal: the containing row also admits the unkeyed DELETE
  // and service-token callers, unqualified.
  "service_token.revoke/postgres": {
    operation: "service_token.revoke", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens/{id}/revoke", ...KEYED_DELIVERY,
  },
  // Keyed service-token issue and rotation in both modes (issue #425). The
  // standalone token database records the token's revision since then.
  "service_token.issue/postgres": {
    operation: "service_token.issue", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens", ...KEYED_DELIVERY,
  },
  "service_token.issue/standalone": {
    operation: "service_token.issue", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens", ...KEYED_DELIVERY,
  },
  "service_token.rotate/postgres": {
    operation: "service_token.rotate", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens/{id}/rotate", ...KEYED_DELIVERY,
  },
  "service_token.rotate/standalone": {
    operation: "service_token.rotate", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens/{id}/rotate", ...KEYED_DELIVERY,
  },
  // Admitted withdrawal, as in PostgreSQL: the containing row also admits
  // the unkeyed DELETE and service-token callers, unqualified.
  "service_token.revoke/standalone": {
    operation: "service_token.revoke", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/tokens/{id}/revoke", ...KEYED_DELIVERY,
  },
  "mutation_approval.prepare/postgres": {
    operation: "mutation_approval.prepare", storage_mode: "postgres", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/tools/{id}/mutation-approvals", ...KEYED_DELIVERY,
  },
  // Keyed Connection create and replace in both modes (issue #425). A
  // credential binding change is made by the keyed replacement, under its
  // key, so its path is the replacement's route.
  "connection.create/postgres": {
    operation: "connection.create", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections", ...KEYED_DELIVERY,
  },
  "connection.replace/postgres": {
    operation: "connection.replace", storage_mode: "postgres", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  "credential.binding_change/postgres": {
    operation: "credential.binding_change", storage_mode: "postgres", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  "connection.create/standalone": {
    operation: "connection.create", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections", ...KEYED_DELIVERY,
  },
  "connection.replace/standalone": {
    operation: "connection.replace", storage_mode: "standalone", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  "credential.binding_change/standalone": {
    operation: "credential.binding_change", storage_mode: "standalone", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  // Admitted withdrawal: the containing rows also admit the unkeyed DELETE
  // and service-token callers, unqualified.
  "connection.delete/postgres": {
    operation: "connection.delete", storage_mode: "postgres", method: "DELETE",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  "connection.delete/standalone": {
    operation: "connection.delete", storage_mode: "standalone", method: "DELETE",
    route: "/v1{ADMIN_PREFIX}/connections/{id}", ...KEYED_DELIVERY,
  },
  // Keyed catalog publication and overlay changes in both modes (issue
  // #425). An OpenAPI publication is made by a registration or by a refresh
  // of an OpenAPI Connection, under the same action and gate; its path is the
  // registration's route, and the refresh route is the MCP publication's.
  "catalog.mcp.publish/postgres": {
    operation: "catalog.mcp.publish", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/refresh", ...KEYED_DELIVERY,
  },
  "catalog.openapi.publish/postgres": {
    operation: "catalog.openapi.publish", storage_mode: "postgres", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/openapi/register", ...KEYED_DELIVERY,
  },
  "catalog.overlay.replace/postgres": {
    operation: "catalog.overlay.replace", storage_mode: "postgres", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/overlay", ...KEYED_DELIVERY,
  },
  "catalog.overlay.delete/postgres": {
    operation: "catalog.overlay.delete", storage_mode: "postgres", method: "DELETE",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/overlay", ...KEYED_DELIVERY,
  },
  "catalog.mcp.publish/standalone": {
    operation: "catalog.mcp.publish", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/refresh", ...KEYED_DELIVERY,
  },
  "catalog.openapi.publish/standalone": {
    operation: "catalog.openapi.publish", storage_mode: "standalone", method: "POST",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/openapi/register", ...KEYED_DELIVERY,
  },
  "catalog.overlay.replace/standalone": {
    operation: "catalog.overlay.replace", storage_mode: "standalone", method: "PUT",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/overlay", ...KEYED_DELIVERY,
  },
  "catalog.overlay.delete/standalone": {
    operation: "catalog.overlay.delete", storage_mode: "standalone", method: "DELETE",
    route: "/v1{ADMIN_PREFIX}/connections/{id}/overlay", ...KEYED_DELIVERY,
  },
});
// The dispatcher that delivers a qualified pair in each mode.
const QUALIFIED_DELIVERY = { postgres: "journaled_dispatch", standalone: "standalone_cursor_dispatch" };

// The router's table of routes that honour an Idempotency-Key; every other
// admin mutation route refuses one. Its entries and QUALIFIED_PATHS name the
// same method and route pairs.
const ROUTING_PATH = "gateway/src/routing.rs";
const KEYED_ROUTES_DECLARED = /pub\(super\) const KEYED_ROUTES: &\[KeyedRoute\] = &\[([\s\S]*?)\n\];/;
// One `KeyedRoute { ... }` literal; its body may hold string literals, whose
// route patterns carry braces.
const KEYED_ROUTE_LITERAL = /KeyedRoute\s*\{((?:[^{}"]|"[^"\\]*")*)\}/g;
const KEYED_ROUTE_FIELD = /^\s*(method|route)\s*:\s*"([^"\\]*)"\s*$/;
const withoutBlockComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "");

// The (method, route) pairs KEYED_ROUTES honours, read from the table body.
// Every entry must be a `KeyedRoute` literal naming `method` and `route` once
// each, in either order, as string literals; anything the checker cannot
// read this way (a constant, a spread, another field) fails, so no entry the
// router honours is invisible to the cross-check.
function keyedRoutes(declared) {
  const table = withoutBlockComments(declared);
  const opened = (table.match(/KeyedRoute\s*\{/g) ?? []).length;
  const literals = [...table.matchAll(KEYED_ROUTE_LITERAL)];
  check(literals.length === opened, `KEYED_ROUTES in ${ROUTING_PATH} has a KeyedRoute literal the checker cannot read`);
  const rest = table.replace(KEYED_ROUTE_LITERAL, "").replace(/[\s,]/g, "");
  check(rest === "", `KEYED_ROUTES in ${ROUTING_PATH} holds an entry that is not a KeyedRoute literal: ${rest.slice(0, 80)}`);
  return new Set(literals.map(([literal, body]) => {
    const fields = new Map();
    for (const part of body.split(",").filter((field) => field.trim() !== "")) {
      const field = part.match(KEYED_ROUTE_FIELD);
      check(field !== null && !fields.has(field[1]),
        `KEYED_ROUTES in ${ROUTING_PATH}: ${literal.replace(/\s+/g, " ")} must name method and route once each as string literals`);
      fields.set(field[1], field[2]);
    }
    check(/^[A-Z]+$/.test(fields.get("method") ?? "") && (fields.get("route") ?? "").startsWith("/"),
      `KEYED_ROUTES in ${ROUTING_PATH}: ${literal.replace(/\s+/g, " ")} must name an upper-case method and a route`);
    return `${fields.get("method")} ${fields.get("route")}`;
  }));
}

const pathKey = (criteria) => `${criteria?.operation}/${criteria?.storage_mode}`;
const sameList = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);

// The checker's summary of a valid inventory, computed from what it checked.
export function summary(result) {
  const list = (pairs) => pairs.length > 0 ? pairs.join(", ") : "none";
  return `Authority evidence inventory valid: ${result.groups} groups, ${result.operationModePairs} operation/mode pairs, ${result.sourceReferences} source references.`
    + ` Qualified in required mode: ${list(result.qualifiedPairs)}.`
    + ` Admitted withdrawals with a reviewed keyed path: ${list(result.keyedWithdrawalPairs)}.`;
}

export function validateInventory(inventory, readSource = (path) => readFileSync(resolve(ROOT, path), "utf8"), qualifiedPaths = QUALIFIED_PATHS) {
  check(inventory.version === 1 && inventory.issue === 425, "unknown inventory contract");
  check(/^[0-9a-f]{40}$/.test(inventory.reviewed_revision), "missing reviewed revision");
  assert.deepEqual(inventory.storage_modes, MODES, "storage modes changed without contract review");
  // A deployment selects evidence durability and the consumer format independently.
  check(inventory.required_durability_mode === "refuses_unsupported", "inventory cannot enable runtime durability");
  const seen = new Set();
  const ids = new Set();
  const coveredEntries = new Set();
  let references = 0;
  const sourceCache = new Map();
  const source = (path) => {
    const destination = resolve(ROOT, path);
    const relativePath = relative(ROOT, destination);
    check(!isAbsolute(relativePath) && relativePath !== ".." && !relativePath.startsWith(".." + "/") && !relativePath.startsWith(".." + "\\"), "reference escapes repository");
    if (!sourceCache.has(path)) sourceCache.set(path, readSource(path));
    return sourceCache.get(path);
  };
  const reference = (ref) => {
    check(ref && typeof ref.path === "string" && typeof ref.anchor === "string" && ref.anchor.length >= 8, "incomplete source anchor");
    check(SOURCE_ROOTS.some((root) => ref.path.startsWith(root)), "evidence must reference runtime or regression source");
    check(source(ref.path).includes(ref.anchor), `stale source anchor: ${ref.path} :: ${ref.anchor}`);
    references += 1;
  };
  check(Array.isArray(inventory.groups) && inventory.groups.length > 0, "empty inventory");
  const qualifiedPairs = [];
  const keyedWithdrawalPairs = [];
  let activationProofState;
  const activationUnproven = () => {
    if (activationProofState === undefined) {
      const proofSource = withoutLineComments(source(ACTIVATION_PROOF_PATH));
      check(ACTIVATION_PROOF_DECLARED.test(proofSource),
        `${ACTIVATION_PROOF_PATH} declares no ActivationProof: the configuration activation rule cannot be switched off by a rename`);
      activationProofState = ACTIVATION_PROOF_UNINHABITED.test(proofSource);
    }
    return activationProofState;
  };
  for (const group of inventory.groups) {
    check(!ids.has(group.id), `duplicate group ${group.id}`); ids.add(group.id);
    for (const field of ["boundary", "record", "actor", "identity", "follow_up", "test_claim"]) {
      check(typeof group[field] === "string" && group[field].trim().length >= 4, `${group.id}: missing ${field}`);
    }
    if (group.operations.includes("configuration.activate") && activationUnproven()) {
      check(group.required_mode === "refused_at_startup" && group.required_durability_supported === false,
        `${group.id}: configuration activation stays refused at startup while the activation proof is uninhabited`);
      check((group.sources ?? []).some((ref) => ref.path === ACTIVATION_PROOF_PATH && ACTIVATION_PROOF_UNINHABITED.test(ref.anchor)),
        `${group.id}: configuration activation must anchor on the uninhabited activation proof`);
      check((group.sources ?? []).some((ref) => ref.path === ACTIVATION_CHECK.path && ref.anchor === ACTIVATION_CHECK.anchor),
        `${group.id}: configuration activation must anchor on the startup check in ${ACTIVATION_CHECK.path}`);
    }
    const pairs = group.operations.flatMap((operation) => group.modes.map((mode) => `${operation}/${mode}`));
    // Every qualified path is a reviewed table entry, exactly, on a pair its
    // own row holds.
    const paths = group.qualified_delivery_paths;
    if (group.disposition.includes("no_caller_key")) {
      check(paths === undefined, `${group.id}: a no_caller_key row has no keyed path`);
    }
    check(paths === undefined || (Array.isArray(paths) && paths.length > 0), `${group.id}: an empty qualified path list`);
    for (const path of paths ?? []) {
      const key = pathKey(path?.criteria);
      check(Object.hasOwn(qualifiedPaths, key), `${group.id}: qualified path ${key} is outside the reviewed table`);
      assert.deepEqual(path.criteria, qualifiedPaths[key], `${group.id}: qualified path ${key} criteria changed without review`);
      check(pairs.includes(key), `${group.id}: qualified path outside its inventory group`);
      check(typeof path.guarantee === "string" && path.guarantee.length > 0, `${group.id}: missing qualified path guarantee`);
      check(Array.isArray(path.sources) && Array.isArray(path.tests) && path.sources.length > 0 && path.tests.length > 0, `${group.id}: missing qualified path evidence`);
      for (const ref of [...path.sources, ...path.tests]) reference(ref);
      for (const ref of path.tests) check(/(?:async )?fn [a-z0-9_]+\(/.test(ref.anchor), "qualified test anchor must name a function");
    }
    const covered = (paths ?? []).map((path) => pathKey(path.criteria));
    const onePathPerPair = covered.length === pairs.length && pairs.every((pair) => covered.filter((key) => key === pair).length === 1);
    // The qualification bar: a row claims required durability exactly when
    // every pair it holds has its reviewed path, it admits only the keyed
    // form, it records no remaining gap, and its mode's dispatcher delivers
    // it. Keyed-only admission and sufficiency are never claimed without it.
    const meetsBar = onePathPerPair
      && group.required_mode === "caller_key_required"
      && sameList(group.disposition, ["already_sufficient"])
      && group.modes.every((mode) => group.delivery === QUALIFIED_DELIVERY[mode]);
    check(!group.required_durability_supported || meetsBar, `${group.id}: unproven durability claim`);
    check(group.required_durability_supported === meetsBar, `${group.id}: a row that meets the qualification bar must claim required durability`);
    check(group.required_mode !== "caller_key_required" || meetsBar, `${group.id}: unreviewed caller-key admission`);
    if (meetsBar) qualifiedPairs.push(...pairs);
    for (const [disposition, reviewed] of Object.entries(ADMITTED_UNQUALIFIED)) {
      if (!group.disposition.includes(disposition)) continue;
      check(group.disposition.length === 1, `${group.id}: ${disposition} stands alone`);
      for (const pair of pairs) check(reviewed.has(pair), `${group.id}: ${disposition} is limited to its reviewed pairs (${pair} is not one)`);
      check(group.required_mode === "admitted" && group.required_durability_supported === false, `${group.id}: ${disposition} is admitted and unqualified`);
    }
    if (group.disposition.includes("withdrawal_admitted")) {
      // The paths themselves are held to the reviewed criteria above; here
      // every pair must have exactly one.
      const paths = Array.isArray(group.qualified_delivery_paths) ? group.qualified_delivery_paths : [];
      const covered = paths.map((path) => `${path.criteria?.operation}/${path.criteria?.storage_mode}`);
      check(paths.length === pairs.length && pairs.every((pair) => covered.filter((key) => key === pair).length === 1),
        `${group.id}: withdrawal_admitted needs one reviewed keyed path per pair`);
      keyedWithdrawalPairs.push(...pairs);
    } else {
      // A reviewed path on a row that is not itself qualified exists only
      // because the row also admits an unqualified withdrawal.
      check(group.qualified_delivery_paths === undefined || group.required_durability_supported === true,
        `${group.id}: a keyed path on an unqualified row needs withdrawal_admitted`);
    }
    check(REQUIRED_MODES.has(group.required_mode), `${group.id}: unknown required mode`);
    // An unsupported operation is never run as if it had evidence, and a
    // row with an entry point a request reaches cannot be waved through.
    check(!(group.required_mode === "admitted" && group.disposition.includes("unsupported_future_operation")), `${group.id}: required mode admits an unsupported operation`);
    check(group.required_mode !== "outside_gateway" || group.entrypoints.length === 0, `${group.id}: a reachable entry point must be admitted or refused`);
    check(group.disposition.length > 0 && new Set(group.disposition).size === group.disposition.length, `${group.id}: missing/duplicate disposition`);
    for (const disposition of group.disposition) check(DISPOSITIONS.has(disposition), `${group.id}: unknown disposition`);
    check(!group.disposition.includes("already_sufficient") || group.disposition.length === 1, "sufficient contradicts a gap");
    check(!group.disposition.includes("already_sufficient") || meetsBar, `${group.id}: unreviewed sufficient disposition`);
    check(Object.hasOwn(inventory.delivery_profiles, group.delivery), `${group.id}: missing delivery profile`);
    check(group.operations.length > 0 && group.modes.length > 0, "empty coverage row");
    for (const operation of group.operations) {
      check(OPERATIONS.includes(operation), `unknown operation ${operation}`);
      for (const mode of group.modes) {
        check(MODES.includes(mode), `unknown storage mode ${mode}`);
        const key = `${operation}/${mode}`;
        check(!seen.has(key), `duplicate coverage ${key}`); seen.add(key);
      }
    }
    check(group.sources.length > 0 && group.tests.length > 0, `${group.id}: missing source/test evidence`);
    for (const ref of [...group.sources, ...group.tests, ...group.entrypoints]) reference(ref);
    for (const ref of group.tests) check(/(?:async )?fn [a-z0-9_]+\(/.test(ref.anchor), "test anchor must name a function");
    for (const ref of group.entrypoints) coveredEntries.add(`${ref.path}::${ref.anchor.match(/async fn ([a-z0-9_]+)\(/)?.[1]}`);
  }
  for (const operation of OPERATIONS) for (const mode of MODES) check(seen.has(`${operation}/${mode}`), `missing coverage ${operation}/${mode}`);
  for (const profile of Object.values(inventory.delivery_profiles)) for (const ref of profile.sources) reference(ref);
  // Endpoint discovery catches a newly shipped mutation in the reviewed admin
  // surfaces even if nobody adds it to OPERATIONS or the JSON matrix. What it
  // finds is an inventory entry point or a reviewed exclusion, never both.
  const found = new Set();
  for (const file of ADMIN_FILES) {
    const path = `gateway/src/${file}`;
    for (const match of source(path).matchAll(/pub\(super\) async fn ([a-z0-9_]+_endpoint)\(/g)) {
      const endpoint = `${path}::${match[1]}`;
      found.add(endpoint);
      if (MUTATION_ENDPOINT.test(match[1])
          || /_mutation_approval_execute_endpoint$/.test(match[1])
          || file === "admin_mutation_approvals.rs" && /_review_endpoint$/.test(match[1])) {
        check(coveredEntries.has(endpoint) || Object.hasOwn(NOT_AUTHORITY_CHANGES, endpoint), `unreviewed mutation entrypoint ${endpoint}`);
      }
    }
  }
  for (const [endpoint, reason] of Object.entries(NOT_AUTHORITY_CHANGES)) {
    check(found.has(endpoint), `stale exclusion ${endpoint}: the endpoint no longer exists`);
    check(!coveredEntries.has(endpoint), `${endpoint} is both excluded and an inventory entry point`);
    check(typeof reason === "string" && reason.length >= 20, `${endpoint}: an exclusion needs its reason`);
  }
  // The router honours a key on exactly the reviewed routes: every reviewed
  // path's route is in KEYED_ROUTES, and every KEYED_ROUTES entry is named by
  // a reviewed path. Elsewhere the router refuses the key.
  const declared = withoutLineComments(source(ROUTING_PATH)).match(KEYED_ROUTES_DECLARED);
  check(declared !== null, `${ROUTING_PATH} declares no KEYED_ROUTES table`);
  const honoured = keyedRoutes(declared[1]);
  const reviewed = new Set(Object.values(qualifiedPaths).map((criteria) => `${criteria.method} ${criteria.route}`));
  for (const [key, criteria] of Object.entries(qualifiedPaths)) {
    check(honoured.has(`${criteria.method} ${criteria.route}`),
      `qualified path ${key} (${criteria.method} ${criteria.route}) is not honoured by KEYED_ROUTES in ${ROUTING_PATH}`);
  }
  for (const route of honoured) {
    check(reviewed.has(route), `KEYED_ROUTES in ${ROUTING_PATH} honours ${route}, which no reviewed qualified path names`);
  }
  assert.deepEqual([...schema.properties.operation.enum].sort(), [...OPERATIONS].sort(), "event schema and coverage operations diverged");
  // Asked even when no row holds the activation, so a rename never passes.
  activationUnproven();
  return {
    groups: inventory.groups.length, operationModePairs: seen.size, sourceReferences: references,
    qualifiedPairs: qualifiedPairs.sort(), keyedWithdrawalPairs: keyedWithdrawalPairs.sort(),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = validateInventory(readJson("docs/authority-evidence-inventory.json"));
    console.log(summary(result));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
