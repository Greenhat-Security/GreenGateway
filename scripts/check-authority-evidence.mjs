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
const DISPOSITIONS = new Set(["already_sufficient", "missing_metadata", "missing_delivery", "unsupported_future_operation"]);
const ADMIN_FILES = ["admin_policy.rs", "admin_tools.rs", "admin_mutation_approvals.rs", "admin_connections.rs", "admin_tokens.rs"];
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
// `caller_key_required` admits the PostgreSQL qualified prepare only.
// `refused` and `refused_at_startup` refuse it when asked or when the
// configuration enables it; `unavailable` rows cannot run in the mode at
// all; `outside_gateway` is a provider's write the gateway cannot refuse;
// `not_refused` is the activation that starts the gateway.
const REQUIRED_MODES = new Set(["admitted", "caller_key_required", "refused", "refused_at_startup", "unavailable", "outside_gateway", "not_refused"]);

// The gateway's source, and the configuration compiler it links from the
// shared gateway-config library (issue #242), which refuses the settings the
// evidence rows anchor on.
const SOURCE_ROOTS = ["gateway/src/", "gateway-config/src/"];

// One reviewed route and delivery configuration qualify. The inventory also
// covers unkeyed DELETE, other actors and rotation in the containing row.
const qualifiedRevoke = {
  operation: "service_token.revoke", storage_mode: "postgres", method: "POST",
  route: "/v1{ADMIN_PREFIX}/tokens/{id}/revoke", operation_id_version: 7,
  actor_kind: "principal", issuer: "canonical_provider", format: "qualified_v1",
  durable_sink: "file", filesystem: "unix_file_and_directory_sync", wire_schema: "authority_event.v1",
};

const qualifiedPrepare = {
  ...qualifiedRevoke, operation: "mutation_approval.prepare", method: "PUT",
  route: "/v1{ADMIN_PREFIX}/tools/{id}/mutation-approvals",
};

export function validateInventory(inventory, readSource = (path) => readFileSync(resolve(ROOT, path), "utf8")) {
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
  for (const group of inventory.groups) {
    check(!ids.has(group.id), `duplicate group ${group.id}`); ids.add(group.id);
    for (const field of ["boundary", "record", "actor", "identity", "follow_up", "test_claim"]) {
      check(typeof group[field] === "string" && group[field].trim().length >= 4, `${group.id}: missing ${field}`);
    }
    const pgPrepare = group.modes.includes("postgres") && group.operations.includes("mutation_approval.prepare");
    const pgRevoke = group.modes.includes("postgres") && group.operations.includes("service_token.revoke");
    if (pgPrepare) {
      assert.deepEqual(group.operations, ["mutation_approval.prepare"], "qualified prepare must be its own operation");
      assert.deepEqual(group.modes, ["postgres"], "qualified prepare must be its own mode");
      assert.deepEqual(group.disposition, ["already_sufficient"], "qualified prepare disposition");
      check(group.required_mode === "caller_key_required" && group.delivery === "journaled_dispatch",
        "qualified prepare requires keyed admission and journal delivery");
    } else {
      check(group.required_mode !== "caller_key_required", "unreviewed caller-key admission");
    }
    check(group.required_durability_supported === pgPrepare, `${group.id}: unproven durability claim`);
    if (pgPrepare || pgRevoke) {
      const expected = pgPrepare ? qualifiedPrepare : qualifiedRevoke;
      const name = pgPrepare ? "prepare" : "revoke";
      const paths = group.qualified_delivery_paths;
      check(Array.isArray(paths) && paths.length === 1, `missing qualified ${name} path`);
      const [path] = paths;
      assert.deepEqual(path.criteria, expected, `qualified ${name} criteria changed without review`);
      check(group.operations.includes(path.criteria.operation) && group.modes.includes(path.criteria.storage_mode), "qualified path outside its inventory group");
      check(typeof path.guarantee === "string" && path.guarantee.length > 0, "missing qualified path guarantee");
      check(path.sources.length > 0 && path.tests.length > 0, "missing qualified path evidence");
      for (const ref of [...path.sources, ...path.tests]) reference(ref);
      for (const ref of path.tests) check(/(?:async )?fn [a-z0-9_]+\(/.test(ref.anchor), "qualified test anchor must name a function");
    } else {
      check(group.qualified_delivery_paths === undefined, "unreviewed qualified path");
    }
    check(REQUIRED_MODES.has(group.required_mode), `${group.id}: unknown required mode`);
    // An unsupported operation is never run as if it had evidence, and a
    // row with an entry point a request reaches cannot be waved through.
    check(!(group.required_mode === "admitted" && group.disposition.includes("unsupported_future_operation")), `${group.id}: required mode admits an unsupported operation`);
    check(!["outside_gateway", "not_refused"].includes(group.required_mode) || group.entrypoints.length === 0, `${group.id}: a reachable entry point must be admitted or refused`);
    check(group.disposition.length > 0 && new Set(group.disposition).size === group.disposition.length, `${group.id}: missing/duplicate disposition`);
    for (const disposition of group.disposition) check(DISPOSITIONS.has(disposition), `${group.id}: unknown disposition`);
    check(!group.disposition.includes("already_sufficient") || group.disposition.length === 1, "sufficient contradicts a gap");
    check(!group.disposition.includes("already_sufficient") || pgPrepare, "unreviewed sufficient disposition");
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
  // surfaces even if nobody adds it to OPERATIONS or the JSON matrix.
  for (const file of ADMIN_FILES) {
    const path = `gateway/src/${file}`;
    for (const match of source(path).matchAll(/pub\(super\) async fn ([a-z0-9_]+_endpoint)\(/g)) {
      if (/(?:create|put|post|patch|delete|rollback|register|rotate|revoke|refresh|accept)_endpoint$/.test(match[1])
          || /_mutation_approval_execute_endpoint$/.test(match[1])
          || file === "admin_mutation_approvals.rs" && /_review_endpoint$/.test(match[1])) {
        check(coveredEntries.has(`${path}::${match[1]}`), `unreviewed mutation entrypoint ${path}::${match[1]}`);
      }
    }
  }
  assert.deepEqual([...schema.properties.operation.enum].sort(), [...OPERATIONS].sort(), "event schema and coverage operations diverged");
  return { groups: inventory.groups.length, operationModePairs: seen.size, sourceReferences: references };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = validateInventory(readJson("docs/authority-evidence-inventory.json"));
    console.log(`Authority evidence inventory valid: ${result.groups} groups, ${result.operationModePairs} operation/mode pairs, ${result.sourceReferences} source references. PostgreSQL keyed preparation qualifies in required mode. PostgreSQL keyed revocation has a qualified delivery path.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
