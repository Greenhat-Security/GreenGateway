#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const argumentsForSuite = process.argv.slice(2);
const quick = argumentsForSuite.includes("--quick");
const unknown = argumentsForSuite.filter((argument) => argument !== "--quick");
if (unknown.length > 0) {
  throw new Error(`unknown argument(s): ${unknown.join(", ")}`);
}

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
  await runNode([
    "scripts/proxy-load.mjs",
    ...argumentsForScenario,
    "--output",
    output,
  ]);
}

console.log(`\nLoad suite complete: ${outputDirectory}`);

function runNode(argumentsForNode) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argumentsForNode, {
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
            `node ${argumentsForNode.join(" ")} failed with ${
              signal ? `signal ${signal}` : `exit ${code}`
            }`,
          ),
        );
      }
    });
  });
}
