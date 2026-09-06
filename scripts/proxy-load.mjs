#!/usr/bin/env node

import crypto from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const DEV_JWT_KID = "greengateway-dev-jwks-2026-07-03";
const DEV_JWT_ISSUER = "https://greengateway.dev.local";
const DEV_JWT_AUDIENCE = "greengateway-dev";
const DEFAULT_REQUESTS = 1000;
const DEFAULT_CONCURRENCY = 50;
const DEFAULT_TIMEOUT_MS = 5000;

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const signingKeyPath = path.join(
  scriptDirectory,
  "..",
  "dev",
  "jwks",
  "generated",
  "dev-signing-key.pem",
);

function usage() {
  return `Usage: node scripts/proxy-load.mjs [options]

Options:
  --base-url URL          Gateway URL (default: ${DEFAULT_BASE_URL})
  --scenario NAME         steady or mixed (default: steady)
  --path PATH             Proxy load path (default: /__dev-load)
  --method METHOD         GET or POST (default: GET)
  --concurrency N         Concurrent clients (default: ${DEFAULT_CONCURRENCY})
  --requests N            Total requests (default: ${DEFAULT_REQUESTS})
  --duration-seconds N    Run until this duration instead of a fixed request count
  --response-bytes N      Successful response bytes (default: 1024)
  --body-bytes N          Exact JSON request-body bytes for POST (default: 0)
  --timeout-ms N          Client-side timeout per request (default: ${DEFAULT_TIMEOUT_MS})
  --token TOKEN           Use an explicit bearer token instead of the seeded dev key
  --expected-statuses CSV Override accepted HTTP statuses (for resilience runs)
  --require-metrics       Fail if the gateway metrics endpoint is unavailable
  --expected-upstream-attempts N  Require an exact upstream-attempt delta
  --expected-retries N    Require an exact retry delta
  --min-retry-amplification N  Require attempts / completed responses at or above N
  --max-retry-amplification N  Bound attempts / completed responses
  --output PATH           Write the JSON result to PATH
  --help                  Show this help text

The mixed scenario deterministically rotates 70% 2xx, 10% 500, 10% retryable
503, and 10% upstream-timeout requests against the seeded development stack.`;
}

function parseArgs(argv) {
  const parsed = {
    baseUrl: process.env.GREENGATEWAY_BASE_URL || DEFAULT_BASE_URL,
    scenario: "steady",
    path: "/__dev-load",
    method: "GET",
    concurrency: DEFAULT_CONCURRENCY,
    requests: DEFAULT_REQUESTS,
    durationSeconds: null,
    responseBytes: 1024,
    bodyBytes: 0,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    token: process.env.GREENGATEWAY_BEARER_TOKEN || null,
    expectedStatuses: null,
    requireMetrics: false,
    expectedUpstreamAttempts: null,
    expectedRetries: null,
    minRetryAmplification: null,
    maxRetryAmplification: null,
    output: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (arg === "--require-metrics") {
      parsed.requireMetrics = true;
      continue;
    }
    const [name, inlineValue] = arg.split("=", 2);
    const value = inlineValue ?? argv[index + 1];
    const consumesNext = inlineValue === undefined;
    switch (name) {
      case "--base-url":
        parsed.baseUrl = requireValue(name, value);
        break;
      case "--scenario":
        parsed.scenario = requireValue(name, value);
        break;
      case "--path":
        parsed.path = requireValue(name, value);
        break;
      case "--method":
        parsed.method = requireValue(name, value).toUpperCase();
        break;
      case "--concurrency":
        parsed.concurrency = positiveInteger(name, value);
        break;
      case "--requests":
        parsed.requests = positiveInteger(name, value);
        break;
      case "--duration-seconds":
        parsed.durationSeconds = positiveNumber(name, value);
        break;
      case "--response-bytes":
        parsed.responseBytes = nonnegativeInteger(name, value);
        break;
      case "--body-bytes":
        parsed.bodyBytes = nonnegativeInteger(name, value);
        break;
      case "--timeout-ms":
        parsed.timeoutMs = positiveInteger(name, value);
        break;
      case "--token":
        parsed.token = requireValue(name, value);
        break;
      case "--expected-statuses":
        parsed.expectedStatuses = statusSet(name, value);
        break;
      case "--expected-upstream-attempts":
        parsed.expectedUpstreamAttempts = nonnegativeInteger(name, value);
        break;
      case "--expected-retries":
        parsed.expectedRetries = nonnegativeInteger(name, value);
        break;
      case "--min-retry-amplification":
        parsed.minRetryAmplification = positiveNumber(name, value);
        break;
      case "--max-retry-amplification":
        parsed.maxRetryAmplification = positiveNumber(name, value);
        break;
      case "--output":
        parsed.output = requireValue(name, value);
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
    if (consumesNext) {
      index += 1;
    }
  }

  if (!["steady", "mixed"].includes(parsed.scenario)) {
    throw new Error("--scenario must be steady or mixed");
  }
  if (!["GET", "POST"].includes(parsed.method)) {
    throw new Error("--method must be GET or POST");
  }
  if (!parsed.path.startsWith("/") || parsed.path.includes("?")) {
    throw new Error("--path must be an absolute path without a query string");
  }
  if (parsed.method === "GET" && parsed.bodyBytes !== 0) {
    throw new Error("--body-bytes requires --method POST");
  }
  if (parsed.method === "POST" && parsed.bodyBytes === 1) {
    throw new Error("--body-bytes for JSON must be 0 or at least 2");
  }

  parsed.baseUrl = parsed.baseUrl.replace(/\/+$/, "");
  return parsed;
}

function requireValue(name, value) {
  if (!value) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function positiveInteger(name, value) {
  const parsed = Number.parseInt(requireValue(name, value), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} requires a positive integer`);
  }
  return parsed;
}

function nonnegativeInteger(name, value) {
  const parsed = Number.parseInt(requireValue(name, value), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} requires a non-negative integer`);
  }
  return parsed;
}

function positiveNumber(name, value) {
  const parsed = Number.parseFloat(requireValue(name, value));
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} requires a positive number`);
  }
  return parsed;
}

function statusSet(name, value) {
  const statuses = requireValue(name, value)
    .split(",")
    .map((status) => status.trim())
    .filter(Boolean);
  if (
    statuses.length === 0 ||
    statuses.some(
      (status) =>
        !/^[1-5][0-9]{2}$/.test(status) ||
        Number.parseInt(status, 10) < 100 ||
        Number.parseInt(status, 10) > 599,
    )
  ) {
    throw new Error(`${name} requires comma-separated HTTP status codes`);
  }
  return new Set(statuses);
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function loadToken(explicitToken, runId) {
  if (explicitToken) {
    return explicitToken;
  }
  const privateKeyPem = await readFile(signingKeyPath, "utf8");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: DEV_JWT_KID };
  const claims = {
    iss: DEV_JWT_ISSUER,
    aud: DEV_JWT_AUDIENCE,
    sub: "admin-proxy-load",
    iat: now,
    exp: now + 3600,
    jti: `${runId}-${crypto.randomUUID()}`,
    roles: ["admin"],
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(signingInput), privateKeyPem)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

function jsonBodyOfExactSize(size) {
  if (size === 0) {
    return undefined;
  }
  return `"${"x".repeat(size - 2)}"`;
}

function requestPath(options, sequence) {
  const query = new URLSearchParams({
    response_bytes: String(options.responseBytes),
  });
  if (options.scenario === "mixed") {
    const slot = sequence % 10;
    if (slot === 7) {
      query.set("status", "500");
    } else if (slot === 8) {
      query.set("status", "503");
    } else if (slot === 9) {
      query.set("delay_ms", "2000");
    }
  }
  return `${options.path}?${query.toString()}`;
}

async function fetchMetrics(baseUrl, required) {
  try {
    const response = await fetch(`${baseUrl}/metrics`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const metrics = aggregatePrometheus(await response.text());
    if (required && !("gateway_http_requests_total" in metrics)) {
      throw new Error("response did not contain GreenGateway metrics");
    }
    return metrics;
  } catch (error) {
    if (required) {
      throw new Error(`required gateway metrics unavailable: ${error.message}`);
    }
    return {};
  }
}

function aggregatePrometheus(text) {
  const totals = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) {
      continue;
    }
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+(-?[0-9.eE+]+)$/);
    if (!match) {
      continue;
    }
    const value = Number.parseFloat(match[2]);
    if (Number.isFinite(value)) {
      totals[match[1]] = (totals[match[1]] || 0) + value;
    }
  }
  return totals;
}

function metricDelta(before, after, name, absentIsZero = false) {
  if (!(name in before) && !(name in after)) {
    return absentIsZero ? 0 : null;
  }
  return (after[name] || 0) - (before[name] || 0);
}

function expectedMixedStatusCounts(completed) {
  const fullCycles = Math.floor(completed / 10);
  const remainder = completed % 10;
  return {
    200: fullCycles * 7 + Math.min(remainder, 7),
    500: fullCycles + (remainder > 7 ? 1 : 0),
    503: fullCycles + (remainder > 8 ? 1 : 0),
    504: fullCycles + (remainder > 9 ? 1 : 0),
  };
}

function percentile(sortedValues, quantile) {
  if (sortedValues.length === 0) {
    return null;
  }
  const index = Math.min(
    sortedValues.length - 1,
    Math.ceil(sortedValues.length * quantile) - 1,
  );
  return Number(sortedValues[index].toFixed(3));
}

async function run(options, token, runId) {
  const body = jsonBodyOfExactSize(options.bodyBytes);
  const latencies = [];
  const statuses = {};
  const errors = {};
  let responseBytes = 0;
  let issued = 0;
  let completed = 0;
  const startedAt = performance.now();
  const stopAt =
    options.durationSeconds === null
      ? null
      : startedAt + options.durationSeconds * 1000;

  async function worker() {
    while (true) {
      if (stopAt !== null && performance.now() >= stopAt) {
        return;
      }
      const sequence = issued;
      if (stopAt === null && sequence >= options.requests) {
        return;
      }
      issued += 1;
      const requestStarted = performance.now();
      try {
        const response = await fetch(
          `${options.baseUrl}${requestPath(options, sequence)}`,
          {
            method: options.method,
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
              "user-agent": "greengateway-proxy-load/0.1",
              "x-request-id": `${runId}-${sequence}`,
            },
            body,
            signal: AbortSignal.timeout(options.timeoutMs),
          },
        );
        const responseBody = await response.arrayBuffer();
        responseBytes += responseBody.byteLength;
        statuses[response.status] = (statuses[response.status] || 0) + 1;
      } catch (error) {
        const category =
          error?.name === "TimeoutError" || error?.name === "AbortError"
            ? "client_timeout"
            : "client_error";
        errors[category] = (errors[category] || 0) + 1;
      } finally {
        latencies.push(performance.now() - requestStarted);
        completed += 1;
      }
    }
  }

  await Promise.all(
    Array.from({ length: options.concurrency }, () => worker()),
  );
  const durationMs = performance.now() - startedAt;
  latencies.sort((left, right) => left - right);

  return {
    completed,
    duration_ms: Number(durationMs.toFixed(3)),
    requests_per_second: Number((completed / (durationMs / 1000)).toFixed(3)),
    latency_ms: {
      p50: percentile(latencies, 0.5),
      p95: percentile(latencies, 0.95),
      p99: percentile(latencies, 0.99),
      max: latencies.length
        ? Number(latencies[latencies.length - 1].toFixed(3))
        : null,
    },
    status_counts: statuses,
    error_counts: errors,
    response_bytes: responseBytes,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const runId = `proxy-load-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const token = await loadToken(options.token, runId);
  const metricsBefore = await fetchMetrics(
    options.baseUrl,
    options.requireMetrics,
  );
  const result = await run(options, token, runId);
  const metricsAfter = await fetchMetrics(
    options.baseUrl,
    options.requireMetrics,
  );
  if (options.requireMetrics) {
    const requiredAfterMetrics = new Set([
      "gateway_http_requests_total",
      "proxy_upstream_attempts_total",
      "egress_client_cache_requests_total",
    ]);
    if (options.expectedRetries !== null || options.scenario === "mixed") {
      requiredAfterMetrics.add("proxy_upstream_retries_total");
    }
    for (const metric of requiredAfterMetrics) {
      if (!(metric in metricsAfter)) {
        throw new Error(
          `required gateway metric missing from after snapshot: ${metric}`,
        );
      }
    }
  }
  const attempts = metricDelta(
    metricsBefore,
    metricsAfter,
    "proxy_upstream_attempts_total",
    options.requireMetrics,
  );
  const retries = metricDelta(
    metricsBefore,
    metricsAfter,
    "proxy_upstream_retries_total",
    options.requireMetrics,
  );
  const cacheRequests = metricDelta(
    metricsBefore,
    metricsAfter,
    "egress_client_cache_requests_total",
    options.requireMetrics,
  );
  const retryAmplification =
    attempts === null || result.completed === 0
      ? null
      : Number((attempts / result.completed).toFixed(6));
  const report = {
    schema_version: "1",
    recorded_at: new Date().toISOString(),
    run_id: runId,
    configuration: {
      base_url: options.baseUrl,
      scenario: options.scenario,
      path: options.path,
      method: options.method,
      concurrency: options.concurrency,
      requests: options.durationSeconds === null ? options.requests : null,
      duration_seconds: options.durationSeconds,
      response_bytes: options.responseBytes,
      body_bytes: options.bodyBytes,
      timeout_ms: options.timeoutMs,
      expected_statuses: [
        ...(options.expectedStatuses ||
          (options.scenario === "steady"
            ? new Set(["200"])
            : new Set(["200", "500", "503", "504"]))),
      ],
    },
    result,
    gateway_metric_delta: {
      upstream_attempts: attempts,
      retries,
      cache_requests: cacheRequests,
      retry_amplification: retryAmplification,
    },
  };
  const expectedStatuses =
    options.expectedStatuses ||
    (options.scenario === "steady"
      ? new Set(["200"])
      : new Set(["200", "500", "503", "504"]));
  const unexpectedStatuses = Object.keys(result.status_counts).filter(
    (status) => !expectedStatuses.has(status),
  );
  report.result.unexpected_statuses = unexpectedStatuses;
  const assertionFailures = [];

  if (options.scenario === "mixed") {
    const expectedCounts = expectedMixedStatusCounts(result.completed);
    for (const [status, expected] of Object.entries(expectedCounts)) {
      const actual = result.status_counts[status] || 0;
      if (actual !== expected) {
        assertionFailures.push(
          `mixed status ${status}: expected ${expected}, received ${actual}`,
        );
      }
    }
  }
  if (
    options.expectedUpstreamAttempts !== null &&
    attempts !== options.expectedUpstreamAttempts
  ) {
    assertionFailures.push(
      `upstream attempts: expected ${options.expectedUpstreamAttempts}, received ${attempts}`,
    );
  }
  if (options.expectedRetries !== null && retries !== options.expectedRetries) {
    assertionFailures.push(
      `retries: expected ${options.expectedRetries}, received ${retries}`,
    );
  }
  if (
    options.minRetryAmplification !== null &&
    (retryAmplification === null ||
      retryAmplification < options.minRetryAmplification)
  ) {
    assertionFailures.push(
      `retry amplification: minimum ${options.minRetryAmplification}, received ${retryAmplification}`,
    );
  }
  if (
    options.maxRetryAmplification !== null &&
    (retryAmplification === null ||
      retryAmplification > options.maxRetryAmplification)
  ) {
    assertionFailures.push(
      `retry amplification: maximum ${options.maxRetryAmplification}, received ${retryAmplification}`,
    );
  }
  report.result.assertion_failures = assertionFailures;

  const rendered = `${JSON.stringify(report, null, 2)}\n`;
  process.stdout.write(rendered);
  if (options.output) {
    await mkdir(path.dirname(path.resolve(options.output)), { recursive: true });
    await writeFile(options.output, rendered, "utf8");
  }

  if (
    Object.keys(result.error_counts).length > 0 ||
    unexpectedStatuses.length > 0 ||
    assertionFailures.length > 0
  ) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
