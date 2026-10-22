#!/usr/bin/env node

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

// Without --profile this is the development suite against the seeded stack.
// With --profile it runs a representative SLO profile against a real
// deployment (docs/deployment/qualification.md): the target comes from
// GREENGATEWAY_BASE_URL and the caller's credential from
// GREENGATEWAY_BEARER_TOKEN, never from the profile or the command line.

const PROFILE_KEYS = new Set([
  "schema_version",
  "label",
  "path",
  "method",
  "body_bytes",
  "timeout_ms",
  "expected_statuses",
  "gateway_metrics",
  "warmup",
  "scenarios",
]);
const SCENARIO_KEYS = new Set([
  "name",
  "concurrency",
  "requests",
  "duration_seconds",
  "slo",
  "observe_only",
]);
const SLO_KEYS = new Set([
  "p50_ms",
  "p95_ms",
  "p99_ms",
  "max_error_rate",
  "min_requests_per_second",
]);
const NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

// Exit status in profile mode: 0 every SLO met, 1 a target missed, 2 invalid
// input or a harness failure (nothing was decided).
let profileMode = false;
try {
  const options = parseSuiteArguments(process.argv.slice(2));
  profileMode = Boolean(options.profile);
  if (options.profile) {
    process.exitCode = await runProfile(options);
  } else {
    await runDevelopmentSuite(options.quick);
  }
} catch (error) {
  console.error(`run-load-suite: ${error.message}`);
  process.exitCode = profileMode ? 2 : 1;
}

function parseSuiteArguments(argv) {
  const parsed = {
    quick: false,
    profile: null,
    validateOnly: false,
    outputDirectory: null,
    allowPlainHttp: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--quick") {
      parsed.quick = true;
    } else if (argument === "--validate-only") {
      parsed.validateOnly = true;
    } else if (argument === "--allow-plain-http") {
      parsed.allowPlainHttp = true;
    } else if (argument === "--profile" || argument === "--output-dir") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error(`${argument} requires a value`);
      }
      parsed[argument === "--profile" ? "profile" : "outputDirectory"] = value;
      index += 1;
    } else {
      throw new Error(`unknown argument(s): ${argument}`);
    }
  }
  const profileOnly = parsed.validateOnly || parsed.outputDirectory || parsed.allowPlainHttp;
  if (!parsed.profile && profileOnly) {
    throw new Error("--validate-only, --output-dir and --allow-plain-http require --profile");
  }
  if (parsed.profile && parsed.quick) {
    throw new Error("--quick applies to the development suite; shorten the profile instead");
  }
  return parsed;
}

async function runDevelopmentSuite(quick) {
  const outputDirectory = path.resolve(
    "artifacts",
    "proxy-load",
    new Date().toISOString().replaceAll(":", "-"),
  );
  await mkdir(outputDirectory, { recursive: true });

  const scale = quick
    ? {
        c1: 50,
        c50: 250,
        c200: 500,
        transfer: 20,
        mixed: 250,
        soakSeconds: 30,
      }
    : {
        c1: 1000,
        c50: 10000,
        c200: 20000,
        transfer: 500,
        mixed: 10000,
        soakSeconds: 1800,
      };

  const scenarios = [
    ["get-1k-c1", "--concurrency", "1", "--requests", String(scale.c1)],
    ["get-1k-c50", "--concurrency", "50", "--requests", String(scale.c50)],
    ["get-1k-c200", "--concurrency", "200", "--requests", String(scale.c200)],
    [
      "download-1m",
      "--concurrency",
      "10",
      "--requests",
      String(scale.transfer),
      "--response-bytes",
      String(1024 * 1024),
    ],
    [
      "upload-1m",
      "--method",
      "POST",
      "--concurrency",
      "10",
      "--requests",
      String(scale.transfer),
      "--body-bytes",
      String(1024 * 1024),
      "--path",
      "/__dev-stream",
      "--response-bytes",
      "128",
    ],
    [
      "mixed",
      "--scenario",
      "mixed",
      "--concurrency",
      "50",
      "--requests",
      String(scale.mixed),
    ],
    [
      "soak",
      "--scenario",
      "mixed",
      "--concurrency",
      "50",
      "--duration-seconds",
      String(scale.soakSeconds),
    ],
  ];

  for (const [name, ...argumentsForScenario] of scenarios) {
    const output = path.join(outputDirectory, `${name}.json`);
    console.log(`\n=== ${name} ===`);
    const code = await runNode([
      "scripts/proxy-load.mjs",
      "--require-metrics",
      ...argumentsForScenario,
      "--output",
      output,
    ]);
    if (code !== 0) {
      throw new Error(`proxy-load scenario ${name} failed with exit ${code}`);
    }
  }

  console.log(`\nLoad suite complete: ${outputDirectory}`);
}

function requireKeys(object, allowed, where) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) {
    throw new Error(`${where} must be an object`);
  }
  const unknown = Object.keys(object).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new Error(`${where} has unknown key(s): ${unknown.join(", ")}`);
  }
}

function integerIn(value, where, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${where} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function positiveFinite(value, where) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${where} must be a positive number`);
  }
  return value;
}

function scenarioFrom(raw, where, { warmup }) {
  requireKeys(raw, SCENARIO_KEYS, where);
  const scenario = {
    name: warmup ? "warmup" : raw.name,
    concurrency: integerIn(raw.concurrency, `${where}.concurrency`, 1, 10000),
    requests: null,
    durationSeconds: null,
    slo: null,
  };
  if (!warmup && (typeof raw.name !== "string" || !NAME.test(raw.name) || raw.name === "warmup")) {
    throw new Error(`${where}.name must be a lowercase name other than warmup`);
  }
  if (warmup && ("name" in raw || "slo" in raw || "observe_only" in raw)) {
    throw new Error(`${where} takes only concurrency and requests or duration_seconds`);
  }
  if (("requests" in raw) === ("duration_seconds" in raw)) {
    throw new Error(`${where} needs exactly one of requests or duration_seconds`);
  }
  if ("requests" in raw) {
    scenario.requests = integerIn(raw.requests, `${where}.requests`, 1, 100000000);
  } else {
    scenario.durationSeconds = positiveFinite(raw.duration_seconds, `${where}.duration_seconds`);
  }
  if (warmup) {
    return scenario;
  }
  if (raw.observe_only === true) {
    if ("slo" in raw) {
      throw new Error(`${where} is observe_only, so it takes no slo`);
    }
    return scenario;
  }
  if ("observe_only" in raw) {
    throw new Error(`${where}.observe_only must be true when present`);
  }
  requireKeys(raw.slo, SLO_KEYS, `${where}.slo`);
  const slo = {};
  for (const key of ["p50_ms", "p95_ms", "p99_ms", "min_requests_per_second"]) {
    if (key in raw.slo) {
      slo[key] = positiveFinite(raw.slo[key], `${where}.slo.${key}`);
    }
  }
  if (!("p95_ms" in slo) && !("p99_ms" in slo)) {
    throw new Error(`${where}.slo needs a tail-latency target: p95_ms or p99_ms`);
  }
  const errorRate = raw.slo.max_error_rate;
  if (typeof errorRate !== "number" || !Number.isFinite(errorRate) || errorRate < 0 || errorRate >= 1) {
    throw new Error(`${where}.slo.max_error_rate must be a number from 0 up to, not including, 1`);
  }
  slo.max_error_rate = errorRate;
  scenario.slo = slo;
  return scenario;
}

function validateProfile(raw) {
  requireKeys(raw, PROFILE_KEYS, "the profile");
  if (raw.schema_version !== 1) {
    throw new Error("the profile must declare schema_version 1");
  }
  if (typeof raw.label !== "string" || !NAME.test(raw.label)) {
    throw new Error("label must be a lowercase name of at most 64 characters");
  }
  if (
    typeof raw.path !== "string" ||
    !raw.path.startsWith("/") ||
    raw.path.length > 2048 ||
    /[#\s]/.test(raw.path)
  ) {
    throw new Error("path must be an absolute request path without a fragment or whitespace");
  }
  const method = raw.method ?? "GET";
  if (!["GET", "POST"].includes(method)) {
    throw new Error("method must be GET or POST");
  }
  const bodyBytes = raw.body_bytes ?? 0;
  integerIn(bodyBytes, "body_bytes", 0, 64 * 1024 * 1024);
  if (method === "GET" && bodyBytes !== 0) {
    throw new Error("body_bytes requires method POST");
  }
  if (bodyBytes === 1) {
    throw new Error("body_bytes for JSON must be 0 or at least 2");
  }
  const expected = raw.expected_statuses ?? ["200"];
  if (
    !Array.isArray(expected) ||
    expected.length === 0 ||
    !expected.every((status) => typeof status === "string" && /^[1-5][0-9]{2}$/.test(status))
  ) {
    throw new Error("expected_statuses must list HTTP status codes as strings");
  }
  if (typeof (raw.gateway_metrics ?? false) !== "boolean") {
    throw new Error("gateway_metrics must be true or false");
  }
  if (!Array.isArray(raw.scenarios) || raw.scenarios.length === 0) {
    throw new Error("scenarios must be a non-empty list");
  }
  const scenarios = raw.scenarios.map((scenario, index) =>
    scenarioFrom(scenario, `scenarios[${index}]`, { warmup: false }),
  );
  const names = new Set(scenarios.map((scenario) => scenario.name));
  if (names.size !== scenarios.length) {
    throw new Error("scenario names must be unique");
  }
  if (!scenarios.some((scenario) => scenario.slo)) {
    throw new Error("at least one scenario needs an slo; a profile without targets establishes nothing");
  }
  return {
    label: raw.label,
    path: raw.path,
    method,
    bodyBytes,
    timeoutMs: integerIn(raw.timeout_ms ?? 5000, "timeout_ms", 1, 600000),
    expectedStatuses: [...new Set(expected)].sort(),
    gatewayMetrics: raw.gateway_metrics ?? false,
    warmup: raw.warmup === undefined ? null : scenarioFrom(raw.warmup, "warmup", { warmup: true }),
    scenarios,
  };
}

function checkedTarget(allowPlainHttp) {
  const baseUrl = process.env.GREENGATEWAY_BASE_URL;
  if (!baseUrl) {
    throw new Error("set GREENGATEWAY_BASE_URL to the deployment under test");
  }
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error("GREENGATEWAY_BASE_URL is not a URL");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("GREENGATEWAY_BASE_URL must be http or https");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("GREENGATEWAY_BASE_URL must carry no credentials, query or fragment");
  }
  if (!process.env.GREENGATEWAY_BEARER_TOKEN) {
    // The development key is never used against a real deployment.
    throw new Error("set GREENGATEWAY_BEARER_TOKEN to a caller credential issued for this run");
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const loopback = host === "localhost" || host === "::1" || /^127\./.test(host);
  if (parsed.protocol === "http:" && !loopback && !allowPlainHttp) {
    throw new Error(
      "refusing to send the bearer token over plain HTTP to a non-loopback host; use https, a port-forward, or --allow-plain-http inside a reviewed private network",
    );
  }
  return { transport: parsed.protocol.slice(0, -1) };
}

function scenarioArguments(profile, scenario, output) {
  const argumentsForScenario = [
    "scripts/proxy-load.mjs",
    "--exact-path",
    "--path",
    profile.path,
    "--method",
    profile.method,
    "--concurrency",
    String(scenario.concurrency),
    "--timeout-ms",
    String(profile.timeoutMs),
    "--expected-statuses",
    profile.expectedStatuses.join(","),
    "--output",
    output,
  ];
  if (scenario.requests !== null) {
    argumentsForScenario.push("--requests", String(scenario.requests));
  } else {
    argumentsForScenario.push("--duration-seconds", String(scenario.durationSeconds));
  }
  if (profile.bodyBytes > 0) {
    argumentsForScenario.push("--body-bytes", String(profile.bodyBytes));
  }
  if (profile.gatewayMetrics) {
    argumentsForScenario.push("--require-metrics");
  }
  return argumentsForScenario;
}

function evaluateScenario(scenario, report) {
  const result = report.result;
  const failures = [];
  const completed = result.completed;
  const unexpected = new Set(result.unexpected_statuses || []);
  const unexpectedResponses = Object.entries(result.status_counts || {})
    .filter(([status]) => unexpected.has(status))
    .reduce((total, [, count]) => total + count, 0);
  const clientErrors = Object.values(result.error_counts || {}).reduce(
    (total, count) => total + count,
    0,
  );
  const errorRate = completed > 0 ? (unexpectedResponses + clientErrors) / completed : null;
  if (!(completed > 0)) {
    failures.push("no request completed");
  }
  if (scenario.slo) {
    for (const [key, quantile] of [
      ["p50_ms", "p50"],
      ["p95_ms", "p95"],
      ["p99_ms", "p99"],
    ]) {
      const measured = result.latency_ms?.[quantile];
      if (key in scenario.slo && !(measured !== null && measured <= scenario.slo[key])) {
        failures.push(`${quantile} ${measured} ms exceeds ${scenario.slo[key]} ms`);
      }
    }
    if (errorRate === null || errorRate > scenario.slo.max_error_rate) {
      failures.push(`error rate ${errorRate} exceeds ${scenario.slo.max_error_rate}`);
    }
    if (
      "min_requests_per_second" in scenario.slo &&
      !(result.requests_per_second >= scenario.slo.min_requests_per_second)
    ) {
      failures.push(
        `throughput ${result.requests_per_second} req/s is below ${scenario.slo.min_requests_per_second}`,
      );
    }
  }
  if ((report.result.assertion_failures || []).length > 0) {
    failures.push("proxy-load reported assertion failures");
  }
  return {
    name: scenario.name,
    configuration: {
      concurrency: scenario.concurrency,
      requests: scenario.requests,
      duration_seconds: scenario.durationSeconds,
    },
    measured: {
      completed,
      duration_ms: result.duration_ms,
      requests_per_second: result.requests_per_second,
      latency_ms: result.latency_ms,
      error_rate: errorRate === null ? null : Number(errorRate.toFixed(6)),
      status_counts: result.status_counts,
      error_counts: result.error_counts,
    },
    gateway_metric_delta: report.gateway_metric_delta,
    slo: scenario.slo,
    verdict: verdictOf(scenario, failures),
    failures,
  };
}

function verdictOf(scenario, failures) {
  if (failures.length > 0) {
    return "failed";
  }
  // An observe-only step (a saturation ramp) records where the knee is; it
  // is never reported as meeting a target it did not have.
  return scenario.slo === null ? "observed" : "passed";
}

async function runProfile(suiteOptions) {
  const bytes = await readFile(suiteOptions.profile);
  let raw;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("the profile is not valid JSON");
  }
  const profile = validateProfile(raw);
  const profileSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  if (suiteOptions.validateOnly) {
    console.log(JSON.stringify({ profile_sha256: profileSha256, ...profile }, null, 2));
    console.log("profile valid; no traffic sent");
    return 0;
  }
  const target = checkedTarget(suiteOptions.allowPlainHttp);
  const startedAt = new Date();
  const outputDirectory = path.resolve(
    suiteOptions.outputDirectory ||
      path.join(
        "artifacts",
        "qualification",
        `load-${profile.label}-${startedAt.toISOString().replaceAll(":", "-")}`,
      ),
  );
  await mkdir(outputDirectory, { recursive: true });
  const planned = profile.warmup ? [profile.warmup, ...profile.scenarios] : profile.scenarios;
  const results = [];
  for (const scenario of planned) {
    const output = path.join(outputDirectory, `${scenario.name}.json`);
    console.log(`\n=== ${scenario.name} ===`);
    const code = await runNode(scenarioArguments(profile, scenario, output));
    // proxy-load exits 2 after writing its report when a request failed or a
    // status was unexpected; that is a measurement for the SLO to judge.
    // Any other failure means no trustworthy report exists.
    if (code !== 0 && code !== 2) {
      throw new Error(`proxy-load scenario ${scenario.name} failed with exit ${code}`);
    }
    const report = JSON.parse(await readFile(output, "utf8"));
    if (scenario.name !== "warmup") {
      results.push(evaluateScenario(scenario, report));
    }
  }
  const judged = results.filter((result) => result.slo !== null);
  const verdict = results.some((result) => result.verdict === "failed") ? "failed" : "passed";
  const summary = {
    schema_version: 1,
    kind: "greengateway-qualification-load",
    recorded_at: new Date().toISOString(),
    started_at: startedAt.toISOString(),
    profile_label: profile.label,
    profile_sha256: profileSha256,
    target,
    request: {
      path: profile.path.split("?")[0],
      has_query: profile.path.includes("?"),
      method: profile.method,
      body_bytes: profile.bodyBytes,
      expected_statuses: profile.expectedStatuses,
      timeout_ms: profile.timeoutMs,
    },
    warmup: profile.warmup !== null,
    scenarios: results,
    slo_scenarios_passed: judged.filter((result) => result.verdict === "passed").length,
    slo_scenarios_total: judged.length,
    verdict,
  };
  const summaryPath = path.join(outputDirectory, "slo-summary.json");
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  console.log(`\nSLO profile ${verdict}: ${summary.slo_scenarios_passed}/${judged.length} scenarios met their targets`);
  console.log(`Summary: ${summaryPath}`);
  console.log("The per-scenario reports beside it name the target URL; share slo-summary.json.");
  return verdict === "passed" ? 0 : 1;
}

function runNode(argumentsForNode) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argumentsForNode, {
      stdio: "inherit",
      env: process.env,
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      resolve(signal ? `signal ${signal}` : code);
    });
  });
}
