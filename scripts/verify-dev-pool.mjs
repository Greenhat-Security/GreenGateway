#!/usr/bin/env node

import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const DEV_JWT_KID = "greengateway-dev-jwks-2026-07-03";
const DEV_JWT_ISSUER = "https://greengateway.dev.local";
const DEV_JWT_AUDIENCE = "greengateway-dev";
const EXPECTED_ENDPOINTS = ["dev-echo-a", "dev-echo-b", "dev-echo-c"];
const RETRY_FAILURE_ENDPOINT = "dev-echo-a";
const REQUESTS_PER_CHECK = 18;
const WAIT_TIMEOUT_MS = 30_000;

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const signingKeyPath = path.join(
  scriptDirectory,
  "..",
  "dev",
  "jwks",
  "dev-signing-key.pem",
);

function usage() {
  return `Usage: node scripts/verify-dev-pool.mjs <scenario> [options]

Scenarios:
  healthy       Verify weighted distribution plus GET retry and POST no-retry behavior
  degraded      Wait for --endpoint to become unhealthy and verify the remaining pool
  recovered     Wait for --endpoint to recover and verify all endpoints receive traffic
  unavailable   Verify /readyz=503, /livez=200, and a sanitized proxy 503

Options:
  --base-url URL       Gateway URL (default: ${DEFAULT_BASE_URL})
  --endpoint ID        Endpoint used by degraded/recovered (default: dev-echo-b)
  --help               Show this help text`;
}

function parseArgs(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    process.exit(0);
  }

  const scenario = argv.shift();
  if (!["healthy", "degraded", "recovered", "unavailable"].includes(scenario)) {
    throw new Error(`expected a valid scenario\n\n${usage()}`);
  }

  let baseUrl = process.env.GREENGATEWAY_BASE_URL || DEFAULT_BASE_URL;
  let endpoint = "dev-echo-b";
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--base-url") {
      baseUrl = requiredValue(argv, ++index, "--base-url");
    } else if (arg.startsWith("--base-url=")) {
      baseUrl = arg.slice("--base-url=".length);
    } else if (arg === "--endpoint") {
      endpoint = requiredValue(argv, ++index, "--endpoint");
    } else if (arg.startsWith("--endpoint=")) {
      endpoint = arg.slice("--endpoint=".length);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!EXPECTED_ENDPOINTS.includes(endpoint)) {
    throw new Error(`--endpoint must be one of ${EXPECTED_ENDPOINTS.join(", ")}`);
  }

  return { scenario, baseUrl: baseUrl.replace(/\/+$/, ""), endpoint };
}

function requiredValue(argv, index, option) {
  const value = argv[index];
  if (!value) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function mintAdminToken(privateKeyPem, runId) {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: DEV_JWT_KID,
  };
  const claims = {
    iss: DEV_JWT_ISSUER,
    aud: DEV_JWT_AUDIENCE,
    sub: "admin-dev-pool-smoke",
    iat: now,
    exp: now + 600,
    jti: `${runId}-${crypto.randomUUID()}`,
    roles: ["admin"],
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(signingInput), privateKeyPem)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function request(baseUrl, token, requestPath, options = {}) {
  const response = await fetch(`${baseUrl}${requestPath}`, {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      "user-agent": "greengateway-dev-pool-smoke/0.1",
      ...options.headers,
    },
  });
  const text = await response.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Binary and empty bodies are intentionally retained as text.
  }
  return {
    status: response.status,
    upstreamId: response.headers.get("x-dev-upstream-id"),
    body,
  };
}

async function probeStatus(baseUrl, pathName) {
  const response = await fetch(`${baseUrl}${pathName}`);
  return response.status;
}

async function waitFor(label, predicate) {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  let lastDetail = "not checked";
  while (Date.now() < deadline) {
    try {
      const result = await predicate();
      lastDetail = result.detail;
      if (result.ready) {
        return result.value;
      }
    } catch (error) {
      lastDetail = error.message;
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${label}: ${lastDetail}`);
}

async function waitForProbe(baseUrl, pathName, expectedStatus) {
  await waitFor(`${pathName}=${expectedStatus}`, async () => {
    const status = await probeStatus(baseUrl, pathName);
    return {
      ready: status === expectedStatus,
      detail: `last status ${status}`,
    };
  });
}

async function adminStatus(baseUrl, token) {
  const result = await request(baseUrl, token, "/v1/admin/status");
  if (result.status !== 200 || typeof result.body !== "object") {
    throw new Error(`admin status returned ${result.status}`);
  }
  return result.body;
}

function endpointFromStatus(status, endpointId) {
  const pools = status?.upstream?.pools;
  if (!Array.isArray(pools)) {
    return null;
  }
  for (const pool of pools) {
    const endpoint = pool.endpoints?.find(
      (candidate) => candidate.endpoint_id === endpointId,
    );
    if (endpoint) {
      return endpoint;
    }
  }
  return null;
}

async function waitForEndpointState(baseUrl, token, endpointId, expectedState) {
  return waitFor(`${endpointId}=${expectedState}`, async () => {
    const status = await adminStatus(baseUrl, token);
    const endpoint = endpointFromStatus(status, endpointId);
    return {
      ready: endpoint?.state === expectedState,
      detail: endpoint
        ? `state=${endpoint.state}, successes=${endpoint.consecutive_successes}, failures=${endpoint.consecutive_failures}`
        : "endpoint missing from status",
      value: endpoint,
    };
  });
}

async function sendPoolRequests({
  baseUrl,
  token,
  runId,
  method,
  requestPath,
  count = REQUESTS_PER_CHECK,
}) {
  const results = [];
  for (let index = 0; index < count; index += 1) {
    const requestId = `${runId}-${method.toLowerCase()}-${index}`;
    results.push({
      requestId,
      ...(await request(baseUrl, token, requestPath, {
        method,
        headers: {
          "content-type": "application/json",
          "x-request-id": requestId,
          "x-forwarded-for": "198.51.100.10",
          "x-real-ip": "198.51.100.11",
          ...(method === "GET" ? { cookie: "session=must-not-forward" } : {}),
        },
        body: method === "POST" ? JSON.stringify({ requestId }) : undefined,
      })),
    });
  }
  return results;
}

function endpointSet(results) {
  return new Set(results.map((result) => result.upstreamId).filter(Boolean));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertAllStatuses(results, expected) {
  const unexpected = results.filter((result) => result.status !== expected);
  assert(
    unexpected.length === 0,
    `${unexpected.length} request(s) returned a status other than ${expected}`,
  );
}

function assertAttemptHeaderBoundary(results) {
  for (const result of results) {
    const headers = result.body?.headers;
    assert(headers && typeof headers === "object", "echo response omitted upstream headers");
    assert(!("authorization" in headers), "gateway bearer authorization reached an upstream");
    assert(!("cookie" in headers), "client cookie reached an upstream");
    assert(
      headers["x-request-id"] === result.requestId,
      "gateway request ID was not preserved across the upstream attempt",
    );
    const forwarding = JSON.stringify({
      forwardedFor: headers["x-forwarded-for"],
      realIp: headers["x-real-ip"],
    });
    assert(
      !forwarding.includes("198.51.100.10") &&
        !forwarding.includes("198.51.100.11"),
      "untrusted client forwarding metadata reached an upstream",
    );
    assert(
      typeof headers["x-forwarded-for"] === "string" &&
        headers["x-forwarded-for"].length > 0 &&
        headers["x-real-ip"] === headers["x-forwarded-for"],
      "gateway did not set canonical client forwarding metadata",
    );
  }
}

async function verifyStreaming(baseUrl, token, runId) {
  const uploadChunkCount = 4;
  const uploadChunk = Buffer.alloc(128 * 1024, "x");
  let nextUploadChunk = 0;
  let uploadFinishedAt = null;
  const uploadBody = new ReadableStream({
    async pull(controller) {
      if (nextUploadChunk === uploadChunkCount) {
        uploadFinishedAt = Date.now();
        controller.close();
        return;
      }
      const chunk = Buffer.from(uploadChunk);
      if (nextUploadChunk === 0) {
        chunk[0] = '"'.charCodeAt(0);
      }
      if (nextUploadChunk + 1 === uploadChunkCount) {
        chunk[chunk.length - 1] = '"'.charCodeAt(0);
      }
      controller.enqueue(chunk);
      nextUploadChunk += 1;
      if (nextUploadChunk < uploadChunkCount) {
        await sleep(300);
      }
    },
  });
  const uploadResponse = await fetch(
    `${baseUrl}/__dev-stream/inspect`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "user-agent": "greengateway-dev-pool-smoke/0.1",
        "x-request-id": `${runId}-incremental-upload`,
      },
      body: uploadBody,
      duplex: "half",
    },
  );
  const uploadResult = await uploadResponse.json();
  assert(uploadResponse.status === 200, `streamed upload returned ${uploadResponse.status}`);
  assert(
    uploadResult.body_bytes === uploadChunk.length * uploadChunkCount,
    `streamed upload delivered ${uploadResult.body_bytes} bytes`,
  );
  assert(
    Number.isFinite(uploadResult.first_body_byte_epoch_ms) &&
      Number.isFinite(uploadFinishedAt) &&
      uploadResult.first_body_byte_epoch_ms + 100 < uploadFinishedAt,
    "upstream did not observe upload bytes before the client finished sending",
  );

  const responseStartedAt = Date.now();
  const downloadResponse = await fetch(
    `${baseUrl}/__dev-stream?response_bytes=${3 * 128 * 1024}&response_chunks=3&chunk_delay_ms=300`,
    {
      headers: {
        authorization: `Bearer ${token}`,
        "user-agent": "greengateway-dev-pool-smoke/0.1",
        "x-request-id": `${runId}-incremental-download`,
      },
    },
  );
  assert(downloadResponse.status === 200, `streamed response returned ${downloadResponse.status}`);
  const reader = downloadResponse.body?.getReader();
  assert(reader, "streamed response did not expose a readable body");
  const firstRead = await reader.read();
  const firstChunkAt = Date.now();
  assert(!firstRead.done && firstRead.value.byteLength > 0, "streamed response had no first chunk");
  let responseBytes = firstRead.value.byteLength;
  while (true) {
    const nextRead = await reader.read();
    if (nextRead.done) {
      break;
    }
    responseBytes += nextRead.value.byteLength;
  }
  const responseCompletedAt = Date.now();
  assert(responseBytes === 3 * 128 * 1024, `streamed response delivered ${responseBytes} bytes`);
  assert(
    firstChunkAt - responseStartedAt < responseCompletedAt - responseStartedAt - 200,
    "client did not receive response bytes incrementally",
  );
}

async function auditEvents(baseUrl, token, fromTimestamp, runId) {
  const params = new URLSearchParams({
    from: fromTimestamp,
    limit: "500",
  });
  const result = await request(
    baseUrl,
    token,
    `/v1/admin/audit?${params.toString()}`,
  );
  if (result.status !== 200 || !Array.isArray(result.body?.events)) {
    throw new Error(`audit query returned ${result.status}`);
  }
  return result.body.events.filter((event) =>
    String(event.request_id || "").startsWith(runId),
  );
}

async function waitForObservations(
  baseUrl,
  token,
  fromTimestamp,
  runId,
  expectedCount,
) {
  return waitFor(`${expectedCount} correlated observations`, async () => {
    const events = await auditEvents(baseUrl, token, fromTimestamp, runId);
    const observations = events.filter(
      (event) => event.event_type === "http.request_observed",
    );
    return {
      ready: observations.length >= expectedCount,
      detail: `${observations.length} observations`,
      value: observations,
    };
  });
}

async function verifyHealthy(baseUrl, token, runId) {
  await waitForProbe(baseUrl, "/readyz", 200);
  await verifyStreaming(baseUrl, token, runId);

  const distribution = await sendPoolRequests({
    baseUrl,
    token,
    runId: `${runId}-distribution`,
    method: "POST",
    requestPath: "/__dev-echo/distribution",
  });
  assertAllStatuses(distribution, 200);
  assertAttemptHeaderBoundary(distribution);
  const seen = endpointSet(distribution);
  assert(
    EXPECTED_ENDPOINTS.every((endpoint) => seen.has(endpoint)),
    `weighted distribution missed endpoints: saw ${[...seen].join(", ")}`,
  );

  const fromTimestamp = new Date(Date.now() - 2_000).toISOString();
  const getRunId = `${runId}-retry-get`;
  const getResults = await sendPoolRequests({
    baseUrl,
    token,
    runId: getRunId,
    method: "GET",
    requestPath: "/__dev-echo/retry-probe",
  });
  assertAllStatuses(getResults, 200);
  assertAttemptHeaderBoundary(getResults);

  const postRunId = `${runId}-retry-post`;
  const postResults = await sendPoolRequests({
    baseUrl,
    token,
    runId: postRunId,
    method: "POST",
    requestPath: "/__dev-echo/retry-probe",
  });
  assert(
    postResults.some((result) => result.status === 503),
    "POST retry probe never reached the intentional 503 endpoint",
  );
  assert(
    postResults.every((result) => [200, 503].includes(result.status)),
    "POST retry probe returned an unexpected status",
  );

  const observations = await waitForObservations(
    baseUrl,
    token,
    fromTimestamp,
    runId,
    getResults.length + postResults.length,
  );
  const getObservations = observations.filter((event) =>
    event.request_id.startsWith(getRunId),
  );
  const postObservations = observations.filter((event) =>
    event.request_id.startsWith(postRunId),
  );
  assert(
    getObservations.some(
      (event) =>
        event.payload?.upstream_attempts?.length === 2 &&
        event.payload.upstream_attempts[0].endpoint_id === RETRY_FAILURE_ENDPOINT &&
        event.payload.upstream_attempts[0].result === "retryable_status" &&
        event.payload.upstream_attempts[1].result === "response",
    ),
    "no GET observation proved a 503 followed by exactly one alternate-endpoint retry",
  );
  assert(
    getObservations.every(
      (event) =>
        event.payload?.status === 200 &&
        event.payload?.upstream_attempts?.length <= 2,
    ),
    "GET retry observations exceeded the configured attempt bound or failed",
  );
  assert(
    postObservations.every(
      (event) => event.payload?.upstream_attempts?.length === 1,
    ),
    "a POST request was retried",
  );
  assert(
    postObservations.some(
      (event) =>
        event.payload?.status === 503 &&
        event.payload?.upstream_endpoint_id === RETRY_FAILURE_ENDPOINT,
    ),
    "no POST observation proved the intentional 503 was attempted exactly once",
  );

  console.log(
    `PASS healthy pool: incremental upload/download; weighted endpoints=${[...seen].sort().join(",")}; GET retry and POST no-retry verified`,
  );
}

async function verifyDegraded(baseUrl, token, runId, endpoint) {
  await waitForEndpointState(baseUrl, token, endpoint, "unhealthy");
  await waitForProbe(baseUrl, "/readyz", 200);
  const results = await sendPoolRequests({
    baseUrl,
    token,
    runId,
    method: "POST",
    requestPath: "/__dev-echo/degraded",
  });
  assertAllStatuses(results, 200);
  const seen = endpointSet(results);
  assert(!seen.has(endpoint), `${endpoint} still received ordinary traffic`);
  assert(seen.size >= 2, `expected both remaining endpoints, saw ${[...seen].join(", ")}`);
  console.log(
    `PASS degraded pool: ${endpoint} excluded; readyz stayed healthy; remaining=${[...seen].sort().join(",")}`,
  );
}

async function verifyRecovered(baseUrl, token, runId, endpoint) {
  await waitForEndpointState(baseUrl, token, endpoint, "healthy");
  await waitForProbe(baseUrl, "/readyz", 200);
  const results = await sendPoolRequests({
    baseUrl,
    token,
    runId,
    method: "POST",
    requestPath: "/__dev-echo/recovered",
  });
  assertAllStatuses(results, 200);
  const seen = endpointSet(results);
  assert(seen.has(endpoint), `${endpoint} did not re-enter weighted traffic`);
  assert(
    EXPECTED_ENDPOINTS.every((candidate) => seen.has(candidate)),
    `recovered distribution missed endpoints: saw ${[...seen].join(", ")}`,
  );
  console.log(`PASS recovered pool: ${endpoint} re-entered weighted traffic`);
}

async function verifyUnavailable(baseUrl, token, runId) {
  await waitForProbe(baseUrl, "/readyz", 503);
  await Promise.all(
    EXPECTED_ENDPOINTS.map((endpoint) =>
      waitForEndpointState(baseUrl, token, endpoint, "unhealthy"),
    ),
  );
  assert(
    (await probeStatus(baseUrl, "/livez")) === 200,
    "/livez must remain healthy while required upstreams are unavailable",
  );
  const [result] = await sendPoolRequests({
    baseUrl,
    token,
    runId,
    method: "POST",
    requestPath: "/__dev-echo/unavailable",
    count: 1,
  });
  assert(result.status === 503, `all-down proxy returned ${result.status}, expected 503`);
  assert(
    result.body?.error === "service_unavailable" &&
      Object.keys(result.body).length === 1,
    `all-down proxy response was not the exact sanitized contract: ${JSON.stringify(result.body)}`,
  );
  const rendered = JSON.stringify(result.body);
  assert(
    !EXPECTED_ENDPOINTS.some((endpoint) => rendered.includes(endpoint)),
    `all-down response leaked endpoint identity: ${rendered}`,
  );
  console.log("PASS unavailable pool: readyz=503, livez=200, proxy response sanitized");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const privateKeyPem = await readFile(signingKeyPath, "utf8");
  const runId = `pool-smoke-${args.scenario}-${Date.now()}`;
  const token = mintAdminToken(privateKeyPem, runId);

  if (args.scenario === "healthy") {
    await verifyHealthy(args.baseUrl, token, runId);
  } else if (args.scenario === "degraded") {
    await verifyDegraded(args.baseUrl, token, runId, args.endpoint);
  } else if (args.scenario === "recovered") {
    await verifyRecovered(args.baseUrl, token, runId, args.endpoint);
  } else {
    await verifyUnavailable(args.baseUrl, token, runId);
  }
}

main().catch((error) => {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
});
