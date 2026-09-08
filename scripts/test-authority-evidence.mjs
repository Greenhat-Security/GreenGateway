import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { OPERATIONS, ROOT, readJson, schema, validateEvent, validateInventory, validateSchema } from "./check-authority-evidence.mjs";

const inventory = () => readJson("docs/authority-evidence-inventory.json");
const source = (path) => readFileSync(resolve(ROOT, path), "utf8");
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

test("deleting a mode or duplicating its coverage cannot silently pass", () => {
  const missing = inventory();
  missing.groups[0].modes = ["standalone"];
  assert.throws(() => validateInventory(missing), /duplicate coverage/);
  const missingGroup = inventory();
  missingGroup.groups.shift();
  assert.throws(() => validateInventory(missingGroup), /missing coverage/);
});

test("new mutation endpoint in a reviewed admin surface requires inventory review", () => {
  assert.throws(() => validateInventory(inventory(), (path) =>
    source(path) + (path.endsWith("/admin_policy.rs") ? "\npub(super) async fn policy_bulk_put_endpoint(" : "")
  ), /unreviewed mutation entrypoint.*policy_bulk_put_endpoint/);
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
    assert.doesNotThrow(() => validateEvent(value));
  }
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
