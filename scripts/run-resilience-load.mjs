#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const args = process.argv.slice(2);
const quick = args.includes("--quick");
const unknown = args.filter((argument) => argument !== "--quick");
if (unknown.length > 0) {
  throw new Error(`unknown argument(s): ${unknown.join(", ")}`);
}

const composeFiles = [
  "-f",
  "docker-compose.yml",
  "-f",
  "docker-compose.dev.yml",
  "-f",
  "docker-compose.load.yml",
];
const upstreams = ["dev-echo-a", "dev-echo-b", "dev-echo-c"];
const outputDirectory = path.resolve(
  "artifacts",
  "proxy-load",
  `resilience-${new Date().toISOString().replaceAll(":", "-")}`,
);
await mkdir(outputDirectory, { recursive: true });

const flappingSeconds = quick ? 45 : 180;
const phaseSeconds = quick ? 5 : 30;
const allDownRequests = quick ? 20 : 500;

try {
  await compose("start", ...upstreams);
  await runNode("scripts/verify-dev-pool.mjs", "recovered", "--endpoint", "dev-echo-b");

  let flappingFailure = null;
  const flappingLoad = runNode(
    "scripts/proxy-load.mjs",
    "--path",
    "/__dev-echo/flapping-load",
    "--duration-seconds",
    String(flappingSeconds),
    "--concurrency",
    "50",
    "--require-metrics",
    "--max-retry-amplification",
    "1.1",
    "--expected-statuses",
    "200",
    "--output",
    path.join(outputDirectory, "flapping-endpoint.json"),
  ).catch((error) => {
    flappingFailure = error;
  });
  await sleep(phaseSeconds * 1000);
  await compose("stop", "dev-echo-b");
  await runNode(
    "scripts/verify-dev-pool.mjs",
    "degraded",
    "--endpoint",
    "dev-echo-b",
  );
  await sleep(phaseSeconds * 1000);
  await compose("start", "dev-echo-b");
  await runNode(
    "scripts/verify-dev-pool.mjs",
    "recovered",
    "--endpoint",
    "dev-echo-b",
  );
  await flappingLoad;
  if (flappingFailure) {
    throw flappingFailure;
  }

  await compose("stop", ...upstreams);
  await runNode("scripts/verify-dev-pool.mjs", "unavailable");
  await runNode(
    "scripts/proxy-load.mjs",
    "--path",
    "/__dev-echo/all-down-load",
    "--requests",
    String(allDownRequests),
    "--concurrency",
    "20",
    "--require-metrics",
    "--expected-upstream-attempts",
    "0",
    "--expected-retries",
    "0",
    "--expected-statuses",
    "503",
    "--output",
    path.join(outputDirectory, "all-down.json"),
  );
} finally {
  await compose("start", ...upstreams);
}

await runNode("scripts/verify-dev-pool.mjs", "recovered", "--endpoint", "dev-echo-b");
console.log(`\nResilience load suite complete: ${outputDirectory}`);

function compose(...composeArgs) {
  return run("docker", ["compose", ...composeFiles, ...composeArgs]);
}

function runNode(...nodeArgs) {
  return run(process.execPath, nodeArgs);
}

function run(command, commandArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: "inherit",
      env: process.env,
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
      } else {
        reject(
          new Error(
            `${command} ${commandArgs.join(" ")} failed with ${
              signal ? `signal ${signal}` : `exit ${code}`
            }`,
          ),
        );
      }
    });
  });
}
