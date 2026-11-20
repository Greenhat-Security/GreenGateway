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
    const pairs = group.operations.flatMap((operation) => group.modes.map((mode) => `${operation}/${mode}`));
    for (const [disposition, reviewed] of Object.entries(ADMITTED_UNQUALIFIED)) {
      if (!group.disposition.includes(disposition)) continue;
      check(group.disposition.length === 1, `${group.id}: ${disposition} stands alone`);
      for (const pair of pairs) check(reviewed.has(pair), `${group.id}: ${disposition} is limited to its reviewed pairs (${pair} is not one)`);
      check(group.required_mode === "admitted" && group.required_durability_supported === false, `${group.id}: ${disposition} is admitted and unqualified`);
    }
    if (group.disposition.includes("no_caller_key")) {
      check(group.qualified_delivery_paths === undefined, `${group.id}: a no_caller_key row has no keyed path`);
    }
    if (group.disposition.includes("withdrawal_admitted")) {
      // The paths themselves are held to the reviewed criteria above; here
      // every pair must have exactly one.
      const paths = Array.isArray(group.qualified_delivery_paths) ? group.qualified_delivery_paths : [];
      const covered = paths.map((path) => `${path.criteria?.operation}/${path.criteria?.storage_mode}`);
      check(paths.length === pairs.length && pairs.every((pair) => covered.filter((key) => key === pair).length === 1),
        `${group.id}: withdrawal_admitted needs one reviewed keyed path per pair`);
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
  // Asked even when no row holds the activation, so a rename never passes.
  activationUnproven();
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
