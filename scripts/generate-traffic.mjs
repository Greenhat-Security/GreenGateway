#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const DEFAULT_RATE_LIMIT_READ_RPS = 50;
const DEFAULT_RATE_LIMIT_READ_BURST = 100;
const DEV_JWT_KID = "greengateway-dev-jwks-2026-07-03";
const DEV_JWT_ISSUER = "https://greengateway.dev.local";
const DEV_JWT_AUDIENCE = "greengateway-dev";
const ADMIN_ROUTES = [
  "/v1/admin/audit",
  "/v1/admin/status",
  "/v1/admin/events/stream",
];

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const devSigningKeyPath = path.join(
  repoRoot,
  "dev",
  "jwks",
  "dev-signing-key.pem",
);

function usage() {
  return `Usage: node scripts/generate-traffic.mjs [options]

Options:
  --base-url URL      Target gateway URL. Defaults to GREENGATEWAY_BASE_URL or ${DEFAULT_BASE_URL}
  --smoke-test        Assert request statuses and audit events, exiting non-zero on failure
  --repeat N          Run the traffic mix N times. Defaults to 1
  --loop              Run the traffic mix until interrupted
  --help              Show this help text`;
}

function parseArgs(argv) {
  const args = {
    baseUrl: process.env.GREENGATEWAY_BASE_URL || DEFAULT_BASE_URL,
    smokeTest: false,
    repeat: 1,
    loop: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (arg === "--smoke-test") {
      args.smokeTest = true;
      continue;
    }
    if (arg === "--loop") {
      args.loop = true;
      continue;
    }
    if (arg === "--base-url") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("--base-url requires a URL");
      }
      args.baseUrl = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--base-url=")) {
      args.baseUrl = arg.slice("--base-url=".length);
      continue;
    }
    if (arg === "--repeat") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("--repeat requires a positive integer");
      }
      args.repeat = parseRepeat(value);
      index += 1;
      continue;
    }
    if (arg.startsWith("--repeat=")) {
      args.repeat = parseRepeat(arg.slice("--repeat=".length));
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  if (args.smokeTest && args.loop) {
    throw new Error("--smoke-test cannot be combined with --loop");
  }

  return {
    ...args,
    baseUrl: args.baseUrl.replace(/\/+$/, ""),
  };
}

function parseRepeat(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("--repeat requires a positive integer");
  }
  return parsed;
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signJwt(privateKeyPem, claims) {
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: DEV_JWT_KID,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(signingInput), privateKeyPem)
    .toString("base64url");

  return `${signingInput}.${signature}`;
}

function mintToken(privateKeyPem, { role, expired, runId }) {
  const now = Math.floor(Date.now() / 1000);
  const subject = `${role}-dev-user`;

  return signJwt(privateKeyPem, {
    iss: DEV_JWT_ISSUER,
    aud: DEV_JWT_AUDIENCE,
    sub: subject,
    email: `${subject}@greengateway.dev.local`,
    iat: now,
    exp: expired ? now - 3600 : now + 600,
    jti: `${runId}-${role}-${crypto.randomUUID()}`,
    roles: [role],
  });
}

function bearer(token) {
  return { authorization: `Bearer ${token}` };
}

function requestId(runId, round, label, index = 0) {
  return `${runId}-r${round}-${label}-${index}`;
}

async function sendRequest({
  baseUrl,
  method = "GET",
  path: requestPath,
  headers = {},
  body,
  requestId: id,
  label,
  expected,
  smokeTest,
  timeoutMs = 5000,
}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const url = `${baseUrl}${requestPath}`;
  const requestHeaders = {
    "x-request-id": id,
    "user-agent": "greengateway-dev-traffic-generator/0.1",
    ...headers,
  };

  let status = null;
  let parsedBody = null;
  let error = null;

  try {
    const response = await fetch(url, {
      method,
      headers: requestHeaders,
      body,
      signal: controller.signal,
    });
    status = response.status;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      parsedBody = await response.json();
    } else if (requestPath === "/metrics") {
      await response.text();
    }
  } catch (err) {
    error = err;
  } finally {
    clearTimeout(timeout);
  }

  printRequestResult({ method, path: requestPath, label, status, expected, error });

  const ok =
    !error &&
    (!smokeTest ||
      expected === undefined ||
      expectedStatusList(expected).includes(status));

  return {
    label,
    requestId: id,
    method,
    path: requestPath,
    status,
    expected,
    ok,
    error,
    body: parsedBody,
  };
}

async function sendSseRequest({
  baseUrl,
  path: requestPath,
  headers,
  requestId: id,
  label,
  expected,
  smokeTest,
}) {
  const controller = new AbortController();
  let status = null;
  let error = null;

  try {
    const response = await fetch(`${baseUrl}${requestPath}`, {
      headers: {
        "x-request-id": id,
        "user-agent": "greengateway-dev-traffic-generator/0.1",
        ...headers,
      },
      signal: controller.signal,
    });
    status = response.status;
    const reader = response.body?.getReader();
    if (reader) {
      await Promise.race([reader.read(), sleep(400)]);
      await reader.cancel();
    }
  } catch (err) {
    if (status === null) {
      error = err;
    }
  } finally {
    controller.abort();
  }

  printRequestResult({
    method: "GET",
    path: requestPath,
    label,
    status,
    expected,
    error,
    note: "stream closed",
  });

  const ok =
    !error &&
    (!smokeTest ||
      expected === undefined ||
      expectedStatusList(expected).includes(status));

  return {
    label,
    requestId: id,
    method: "GET",
    path: requestPath,
    status,
    expected,
    ok,
    error,
  };
}

function expectedStatusList(expected) {
  return Array.isArray(expected) ? expected : [expected];
}

function printRequestResult({ method, path: requestPath, label, status, expected, error, note }) {
  const expectedText =
    expected === undefined ? "" : ` expected ${expectedStatusList(expected).join("/")}`;
  const statusText = error ? `ERR ${error.name || "error"}` : status;
  const noteText = note ? ` (${note})` : "";
  console.log(`${method} ${requestPath} [${label}] -> ${statusText}${expectedText}${noteText}`);
}

async function sendRateLimitBurst({ baseUrl, runId, round, readBurst }) {
  const requestCount = Math.max(readBurst + 75, 150);
  console.log(`GET /health [rate-limit-burst] x${requestCount}`);
  const results = await Promise.all(
    Array.from({ length: requestCount }, (_, index) =>
      sendQuietHealth(baseUrl, requestId(runId, round, "rate-limit-burst", index)),
    ),
  );
  const counts = countStatuses(results);
  const summary = Object.entries(counts)
    .sort(([left], [right]) => Number(left) - Number(right))
    .map(([status, count]) => `${status}:${count}`)
    .join(" ");
  console.log(`GET /health [rate-limit-burst] summary -> ${summary}`);

  return results.map((result, index) => ({
    label: "rate-limit-burst",
    requestId: requestId(runId, round, "rate-limit-burst", index),
    method: "GET",
    path: "/health",
    status: result.status,
    expected: [200, 429],
    ok: result.error === null,
    error: result.error,
  }));
}

async function sendQuietHealth(baseUrl, id) {
  try {
    const response = await fetch(`${baseUrl}/health`, {
      headers: {
        "x-request-id": id,
        "user-agent": "greengateway-dev-traffic-generator/0.1",
      },
    });
    await response.arrayBuffer();
    return { status: response.status, error: null };
  } catch (error) {
    return { status: "ERR", error };
  }
}

function countStatuses(results) {
  return results.reduce((counts, result) => {
    const key = result.error ? "ERR" : String(result.status);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

async function generateTrafficRound({
  baseUrl,
  tokens,
  runId,
  round,
  smokeTest,
  rateLimit,
}) {
  const results = [];
  const record = (result) => {
    results.push(result);
    return result;
  };

  console.log(`\nRound ${round}`);
  console.log("Baseline probes");
  for (const probePath of ["/health", "/version", "/metrics"]) {
    await sendRequest({
      baseUrl,
      path: probePath,
      requestId: requestId(runId, round, `baseline-${probePath.slice(1)}`),
      label: "baseline",
      expected: 200,
      smokeTest,
    }).then(record);
  }

  console.log("Admin token allowed calls");
  await sendRequest({
    baseUrl,
    path: "/v1/admin/audit",
    headers: bearer(tokens.admin),
    requestId: requestId(runId, round, "admin-audit"),
    label: "admin-token",
    expected: 200,
    smokeTest,
  }).then(record);
  const statusResult = await sendRequest({
    baseUrl,
    path: "/v1/admin/status",
    headers: bearer(tokens.admin),
    requestId: requestId(runId, round, "admin-status"),
    label: "admin-token",
    expected: 200,
    smokeTest,
  }).then(record);
  updateRateLimitFromStatus(rateLimit, statusResult.body);
  await sendSseRequest({
    baseUrl,
    path: "/v1/admin/events/stream",
    headers: bearer(tokens.admin),
    requestId: requestId(runId, round, "admin-events-stream"),
    label: "admin-token",
    expected: 200,
    smokeTest,
  }).then(record);

  console.log("Missing token admin denials");
  for (const adminPath of ADMIN_ROUTES) {
    const routeLabel = adminPath.split("/").filter(Boolean).pop();
    await sendRequest({
      baseUrl,
      path: adminPath,
      requestId: requestId(runId, round, `missing-token-${routeLabel}`),
      label: "missing-token",
      expected: 401,
      smokeTest,
    }).then(record);
  }

  console.log("Expired token admin denials");
  for (const adminPath of ADMIN_ROUTES) {
    const routeLabel = adminPath.split("/").filter(Boolean).pop();
    await sendRequest({
      baseUrl,
      path: adminPath,
      headers: bearer(tokens.expired),
      requestId: requestId(runId, round, `expired-token-${routeLabel}`),
      label: "expired-token",
      expected: 401,
      smokeTest,
    }).then(record);
  }

  console.log("Malformed bearer token denials");
  for (const adminPath of ADMIN_ROUTES) {
    const routeLabel = adminPath.split("/").filter(Boolean).pop();
    await sendRequest({
      baseUrl,
      path: adminPath,
      headers: bearer("this-is-not-a-jwt"),
      requestId: requestId(runId, round, `garbage-token-${routeLabel}`),
      label: "garbage-token",
      expected: 401,
      smokeTest,
    }).then(record);
  }

  console.log("Reader token admin denials");
  for (const adminPath of ADMIN_ROUTES) {
    const routeLabel = adminPath.split("/").filter(Boolean).pop();
    await sendRequest({
      baseUrl,
      path: adminPath,
      headers: bearer(tokens.reader),
      requestId: requestId(runId, round, `reader-token-${routeLabel}`),
      label: "reader-token",
      expected: 403,
      smokeTest,
    }).then(record);
  }

  console.log("Malformed body validation rejection");
  await sendRequest({
    baseUrl,
    method: "POST",
    path: "/does-not-exist",
    headers: { "content-type": "text/plain" },
    body: "not json",
    requestId: requestId(runId, round, "malformed-body"),
    label: "malformed-body",
    expected: 415,
    smokeTest,
  }).then(record);

  console.log("Rate-limit burst");
  results.push(
    ...(await sendRateLimitBurst({
      baseUrl,
      runId,
      round,
      readBurst: rateLimit.readBurst,
    })),
  );

  const cooldownMs = rateLimitCooldownMs(rateLimit);
  console.log(`Cooldown ${cooldownMs}ms for read-lane token refill`);
  await sleep(cooldownMs);

  return results;
}

function updateRateLimitFromStatus(rateLimit, body) {
  const read = body?.rate_limits?.read;
  if (!read) {
    return;
  }
  if (Number.isFinite(read.requests_per_second) && read.requests_per_second >= 0) {
    rateLimit.readRps = read.requests_per_second;
  }
  if (Number.isSafeInteger(read.burst) && read.burst > 0) {
    rateLimit.readBurst = read.burst;
  }
}

function rateLimitCooldownMs(rateLimit) {
  if (rateLimit.readRps <= 0) {
    return 3000;
  }

  return Math.min(
    10000,
    Math.ceil((rateLimit.readBurst / rateLimit.readRps) * 1000) + 750,
  );
}

async function fetchAuditEvents({ baseUrl, token, runId, fromTimestamp }) {
  let beforeId = null;
  const events = [];

  for (let page = 0; page < 4; page += 1) {
    const params = new URLSearchParams({
      limit: "500",
      from: fromTimestamp,
    });
    if (beforeId !== null) {
      params.set("before_id", String(beforeId));
    }

    const response = await fetch(`${baseUrl}/v1/admin/audit?${params.toString()}`, {
      headers: {
        ...bearer(token),
        "x-request-id": `${runId}-audit-query-${page}`,
        "user-agent": "greengateway-dev-traffic-generator/0.1",
      },
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`audit query returned ${response.status}: ${body}`);
    }
    const pageBody = await response.json();
    events.push(
      ...(pageBody.events || []).filter((event) =>
        String(event.request_id || "").startsWith(runId),
      ),
    );
    if (pageBody.next_cursor === null || pageBody.next_cursor === undefined) {
      break;
    }
    beforeId = pageBody.next_cursor;
  }

  return events;
}

async function pollAuditEvents(options, isComplete) {
  let lastEvents = [];
  let lastError = null;

  for (let attempt = 1; attempt <= 16; attempt += 1) {
    try {
      lastEvents = await fetchAuditEvents(options);
      if (isComplete(lastEvents)) {
        return lastEvents;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }

  if (lastEvents.length === 0 && lastError) {
    throw lastError;
  }
  return lastEvents;
}

async function runSmokeAssertions({
  baseUrl,
  adminToken,
  runId,
  fromTimestamp,
  results,
}) {
  const failures = [];
  const statusFailures = results.filter(
    (result) =>
      !result.ok ||
      (result.expected !== undefined &&
        !expectedStatusList(result.expected).includes(result.status)),
  );

  for (const failure of statusFailures) {
    const expected = expectedStatusList(failure.expected).join("/");
    const actual = failure.error ? `ERR ${failure.error.name}` : failure.status;
    failures.push(
      `${failure.method} ${failure.path} [${failure.label}] returned ${actual}, expected ${expected}`,
    );
  }

  if (!results.some((result) => result.label === "rate-limit-burst" && result.status === 429)) {
    failures.push("rate-limit burst did not produce a 429 response");
  }

  let events = [];
  try {
    events = await pollAuditEvents(
      {
        baseUrl,
        token: adminToken,
        runId,
        fromTimestamp,
      },
      (candidateEvents) => auditSummary(candidateEvents).failures.length === 0,
    );
  } catch (error) {
    failures.push(error.message);
  }

  const audit = auditSummary(events);
  failures.push(...audit.failures);

  console.log("\nSmoke assertions");
  printAssertion(
    "request statuses matched expected values",
    statusFailures.length === 0,
    `${statusFailures.length} mismatch(es)`,
  );
  for (const status of [200, 401, 403, 415, 429]) {
    printAssertion(
      `http.request_observed status ${status}`,
      audit.observedStatusCounts.has(status),
      `count ${audit.observedStatusCounts.get(status) || 0}`,
    );
  }
  printAssertion("auth.success", audit.authSuccessCount > 0, `count ${audit.authSuccessCount}`);
  printAssertion("auth.failure", audit.authFailureCount > 0, `count ${audit.authFailureCount}`);
  printAssertion("authz.denied", audit.authzDeniedCount > 0, `count ${audit.authzDeniedCount}`);

  if (failures.length > 0) {
    throw new Error(`smoke test failed:\n- ${failures.join("\n- ")}`);
  }

  console.log("All smoke checks passed");
}

function auditSummary(events) {
  const failures = [];
  const observed = events.filter(
    (event) => event.event_type === "http.request_observed",
  );
  const observedStatusCounts = new Map();
  for (const event of observed) {
    const status = event.payload?.status;
    observedStatusCounts.set(status, (observedStatusCounts.get(status) || 0) + 1);
  }

  for (const status of [200, 401, 403, 415, 429]) {
    if (!observedStatusCounts.has(status)) {
      failures.push(`missing http.request_observed audit event for status ${status}`);
    }
  }

  const authSuccessCount = countEvents(events, "auth.success");
  const authFailureCount = countEvents(events, "auth.failure");
  const authzDeniedCount = countEvents(events, "authz.denied");

  if (authSuccessCount === 0) {
    failures.push("missing auth.success audit event");
  }
  if (authFailureCount === 0) {
    failures.push("missing auth.failure audit event");
  }
  if (authzDeniedCount === 0) {
    failures.push("missing authz.denied audit event");
  }

  return {
    failures,
    observedStatusCounts,
    authSuccessCount,
    authFailureCount,
    authzDeniedCount,
  };
}

function countEvents(events, eventType) {
  return events.filter((event) => event.event_type === eventType).length;
}

function printAssertion(label, passed, detail) {
  const status = passed ? "PASS" : "FAIL";
  console.log(`${status} ${label} (${detail})`);
}

function printSummary(results) {
  const counts = countStatuses(results);
  const summary = Object.entries(counts)
    .sort(([left], [right]) => Number(left) - Number(right))
    .map(([status, count]) => `${status}:${count}`)
    .join(" ");

  console.log(`\nStatus summary: ${summary}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const privateKeyPem = await readFile(devSigningKeyPath, "utf8");
  const runId = `traffic-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const fromTimestamp = new Date(Date.now() - 5000).toISOString();
  const tokens = {
    admin: mintToken(privateKeyPem, { role: "admin", runId }),
    reader: mintToken(privateKeyPem, { role: "reader", runId }),
    expired: mintToken(privateKeyPem, { role: "admin", expired: true, runId }),
  };
  const rateLimit = {
    readRps: DEFAULT_RATE_LIMIT_READ_RPS,
    readBurst: DEFAULT_RATE_LIMIT_READ_BURST,
  };
  const allResults = [];

  console.log("GreenGateway traffic generator");
  console.log(`Target: ${args.baseUrl}`);
  console.log(`Mode: ${args.smokeTest ? "smoke-test" : "demo"}`);
  console.log(`Run: ${runId}`);

  let round = 1;
  do {
    allResults.push(
      ...(await generateTrafficRound({
        baseUrl: args.baseUrl,
        tokens,
        runId,
        round,
        smokeTest: args.smokeTest,
        rateLimit,
      })),
    );
    round += 1;
  } while (args.loop || round <= args.repeat);

  printSummary(allResults);

  if (args.smokeTest) {
    await runSmokeAssertions({
      baseUrl: args.baseUrl,
      adminToken: tokens.admin,
      runId,
      fromTimestamp,
      results: allResults,
    });
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
