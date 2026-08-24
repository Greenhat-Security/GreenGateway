#!/usr/bin/env node

import { readFileSync, existsSync } from "node:fs";
import { basename, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const ledgerPath = resolve(
  repositoryRoot,
  "docs/testing/issue-240-acceptance.md",
);

const failures = [];
const javaScriptExtensions = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
]);

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasRustTestFunction(source, exactName) {
  const declaration = new RegExp(
    `((?:^[\\t ]*#\\[[^\\]]*\\][\\t ]*\\r?\\n)+)` +
      `^[\\t ]*(?:pub(?:\\([^\\r\\n)]*\\))?[\\t ]+)?` +
      `(?:async[\\t ]+)?fn[\\t ]+${escapeRegExp(exactName)}` +
      `[\\t ]*(?:<[^\\r\\n>{}]*>)?[\\t ]*\\(`,
    "m",
  ).exec(source);
  return Boolean(
    declaration &&
      /#\[\s*(?:test|tokio::test(?:\s*\([\s\S]*?\))?)\s*\]/.test(
        declaration[1],
      ),
  );
}

function javaScriptTestTitles(source, includeSuites = false) {
  const patterns = [
    /\b(?:test|it)(?:\.(?:only|fail|concurrent|serial))*\s*\(\s*(['"`])((?:\\[\s\S]|(?!\1)[\s\S])*?)\1\s*,/g,
  ];
  if (includeSuites) {
    patterns.push(
      /\b(?:(?:test|it)\.)?describe(?:\.(?:only|skip|serial|parallel))*\s*\(\s*(['"`])((?:\\[\s\S]|(?!\1)[\s\S])*?)\1\s*,/g,
    );
  }
  const titles = [];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      titles.push(match[2].replace(/\\(["'`\\])/g, "$1"));
    }
  }
  return titles;
}

function hasYamlJobKey(source, exactName) {
  const lines = source.split(/\r?\n/);
  const jobsIndex = lines.findIndex((line) =>
    /^[ ]*jobs:[ \t]*(?:#.*)?$/.test(line),
  );
  if (jobsIndex < 0) return false;
  const jobsIndent = lines[jobsIndex].match(/^[ ]*/)[0].length;
  let jobIndent;
  for (const line of lines.slice(jobsIndex + 1)) {
    if (/^[ \t]*(?:#.*)?$/.test(line)) continue;
    const indent = line.match(/^[ ]*/)[0].length;
    if (indent <= jobsIndent) break;
    jobIndent ??= indent;
    if (indent !== jobIndent) continue;
    const key = line.trim().match(/^([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$/);
    if (key?.[1] === exactName) return true;
  }
  return false;
}

function shellWords(value) {
  return [...value.matchAll(/"([^"]*)"|'([^']*)'|([^\s]+)/g)].map(
    (match) => match[1] ?? match[2] ?? match[3],
  );
}

function explicitCargoTestFilters(commandText) {
  const valueOptions = new Set([
    "-p", "--package", "--exclude", "--features", "--target",
    "--manifest-path", "-j", "--jobs", "--profile", "--target-dir",
    "--color", "--config", "-Z", "--bin", "--test", "--bench",
    "--example",
  ]);
  const filters = [];
  for (const segment of commandText.split(/\s*(?:&&|\|\||;)\s*/)) {
    const words = shellWords(segment);
    const cargo = words.findIndex((word) => /^(?:cargo|cargo\.exe)$/.test(word));
    if (cargo < 0 || words[cargo + 1] !== "test") continue;
    for (let index = cargo + 2; index < words.length; index += 1) {
      const word = words[index];
      if (word === "--") break;
      if (valueOptions.has(word)) {
        index += 1;
        continue;
      }
      if (word.startsWith("-")) continue;
      filters.push(word);
      break;
    }
  }
  return filters;
}

function rustFilterMatches(filter, evidence) {
  if (evidence.anchor.includes(filter) || filter.includes(evidence.anchor)) return true;
  if (evidence.stem === filter || evidence.stem.includes(filter)) return true;
  const moduleOffset = filter.indexOf(evidence.stem);
  if (moduleOffset < 0) return false;
  const suffix = filter.slice(moduleOffset + evidence.stem.length)
    .replace(/^::/, "").replace(/::$/, "");
  return suffix.length === 0 || evidence.anchor.includes(suffix) || suffix.includes(evidence.anchor);
}

function playwrightGrepValues(commandText) {
  return [...commandText.matchAll(
    /(?:^|\s)(?:--grep|-g)(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s;&]+))/g,
  )].map((match) => match[1] ?? match[2] ?? match[3]);
}

function validateStaticSelectors(id, commandText, evidenceRecords) {
  const rustEvidence = evidenceRecords.filter((item) => item.kind === "rust");
  const cargoFilters = explicitCargoTestFilters(commandText);
  if (rustEvidence.length > 0 && cargoFilters.length > 0 &&
      !cargoFilters.some((filter) => rustEvidence.some((item) => rustFilterMatches(filter, item)))) {
    failures.push(`${id} cargo test filter does not select any cited Rust test`);
  }
  const jsEvidence = evidenceRecords.filter((item) => item.kind === "javascript");
  const grepValues = playwrightGrepValues(commandText);
  if (jsEvidence.length === 0 || grepValues.length === 0) return;
  const tests = new Set();
  const candidates = new Set();
  for (const item of jsEvidence) {
    for (const title of javaScriptTestTitles(item.source)) tests.add(title);
    for (const title of javaScriptTestTitles(item.source, true)) candidates.add(title);
  }
  for (const outer of [...candidates]) {
    for (const test of tests) candidates.add(`${outer} ${test}`);
  }
  for (const value of grepValues) {
    try {
      const literal = value.match(/^\/([\s\S]*)\/([a-z]*)$/i);
      const expression = literal ? new RegExp(literal[1], literal[2].replace(/[gy]/g, "")) : new RegExp(value);
      if (![...candidates].some((title) => expression.test(title))) {
        failures.push(`${id} Playwright grep '${value}' selects no cited test or suite title`);
      }
    } catch {
      failures.push(`${id} has invalid Playwright grep '${value}'`);
    }
  }
}

function expectedRange(prefix, first, last) {
  return Array.from(
    { length: last - first + 1 },
    (_, offset) => `${prefix}-${String(first + offset).padStart(2, "0")}`,
  );
}

const expectedIds = [
  ...expectedRange("INV-AUTH", 1, 9),
  ...expectedRange("INV-MUT", 1, 6),
  ...expectedRange("INV-EGRESS", 0, 10),
  ...expectedRange("INV-HEADER", 1, 8),
  ...expectedRange("INV-SECRET", 1, 7),
  ...expectedRange("VM", 1, 21),
  ...expectedRange("E2E", 1, 12),
];
const expectedIdSet = new Set(expectedIds);

if (!existsSync(ledgerPath)) {
  throw new Error(`acceptance ledger is missing: ${ledgerPath}`);
}

const ledger = readFileSync(ledgerPath, "utf8");
const rows = new Map();
const acceptedStatuses = new Set([
  "automated",
  "partial",
  "manual-external",
]);
const nonValue = /^(?:n\/a|none|tbd|todo|\u2014|-)?$/i;

for (const [zeroBasedLine, rawLine] of ledger.split(/\r?\n/).entries()) {
  const idMatch = rawLine.match(
    /^\|\s*((?:INV-(?:AUTH|MUT|EGRESS|HEADER|SECRET)|VM|E2E)-\d{2})\s*\|/,
  );
  if (!idMatch) {
    continue;
  }

  const lineNumber = zeroBasedLine + 1;
  const cells = rawLine
    .slice(1, rawLine.endsWith("|") ? -1 : undefined)
    .split("|")
    .map((cell) => cell.trim());

  if (cells.length !== 9) {
    failures.push(
      `${idMatch[1]} at line ${lineNumber} has ${cells.length} columns; expected 9`,
    );
    continue;
  }

  const [
    id,
    requirement,
    status,
    evidence,
    command,
    owner,
    rationale,
    steps,
    reviewDate,
  ] = cells;

  if (rows.has(id)) {
    failures.push(`${id} is duplicated at line ${lineNumber}`);
    continue;
  }
  rows.set(id, { lineNumber, status });

  if (!expectedIdSet.has(id)) {
    failures.push(`${id} at line ${lineNumber} is not a required ledger ID`);
  }
  if (!requirement || nonValue.test(requirement)) {
    failures.push(`${id} has no requirement text`);
  }
  if (!acceptedStatuses.has(status)) {
    failures.push(`${id} has unsupported status '${status}'`);
  }
  if (!evidence || nonValue.test(evidence)) {
    failures.push(`${id} has no exact evidence or planned test`);
  }
  const commandMatch = command.match(/^`([^`\r\n]+)`$/);
  const commandText = commandMatch?.[1].trim();
  if (!commandText || commandMatch[1] !== commandText || nonValue.test(commandText)) {
    failures.push(`${id} must provide an exact backtick-delimited command`);
  }  if (!/^\d{4}-\d{2}-\d{2}$/.test(reviewDate)) {
    failures.push(`${id} has a non-ISO review date '${reviewDate}'`);
  }

  if (status !== "automated") {
    for (const [label, value] of [
      ["owner", owner],
      ["rationale", rationale],
      ["deterministic closure/manual steps", steps],
    ]) {
      if (!value || nonValue.test(value)) {
        failures.push(`${id} is ${status} but has no ${label}`);
      }
    }
    if (!steps.includes("Run `")) {
      failures.push(
        `${id} closure/manual steps must contain an exact Run-command step`,
      );
    }
  }

  const evidenceRecords = [];
  for (const rawEvidenceItem of evidence.split(";")) {
    const evidenceItem = rawEvidenceItem.trim();
    if (!evidenceItem) continue;
    if (evidenceItem.startsWith("planned:")) {
      failures.push(`${id} must not use planned evidence; put future work in closure steps`);
      continue;
    }
    if (evidenceItem.startsWith("command:")) {
      const relativePath = evidenceItem.slice("command:".length);
      if (!existsSync(resolve(repositoryRoot, relativePath))) failures.push(`${id} references missing command file '${relativePath}'`);
      continue;
    }
    const separator = evidenceItem.indexOf("#");
    if (separator <= 0 || separator === evidenceItem.length - 1) {
      failures.push(`${id} evidence '${evidenceItem}' must use path#exact_anchor`);
      continue;
    }
    const relativePath = evidenceItem.slice(0, separator);
    const exactAnchor = evidenceItem.slice(separator + 1);
    const absolutePath = resolve(repositoryRoot, relativePath);
    if (!existsSync(absolutePath)) {
      failures.push(`${id} references missing evidence file '${relativePath}'`);
      continue;
    }
    const source = readFileSync(absolutePath, "utf8");
    const extension = extname(relativePath).toLowerCase();
    let kind;
    let anchorExists = false;
    if (extension === ".rs") {
      kind = "rust";
      anchorExists = hasRustTestFunction(source, exactAnchor);
    } else if (javaScriptExtensions.has(extension)) {
      kind = "javascript";
      anchorExists = javaScriptTestTitles(source).includes(exactAnchor);
    } else if (extension === ".yml" || extension === ".yaml") {
      kind = "yaml";
      anchorExists = hasYamlJobKey(source, exactAnchor);
    } else {
      failures.push(`${id} evidence file '${relativePath}' has unsupported anchor type '${extension}'`);
      continue;
    }
    if (!anchorExists) {
      failures.push(`${id} evidence file '${relativePath}' does not define '${exactAnchor}' as an executable test/job anchor`);
      continue;
    }
    evidenceRecords.push({ anchor: exactAnchor, kind, relativePath, source, stem: basename(relativePath, extension) });
  }
  if (commandText) validateStaticSelectors(id, commandText, evidenceRecords);
}

for (const id of expectedIds) {
  if (!rows.has(id)) {
    failures.push(`required ledger row ${id} is missing`);
  }
}
for (const id of rows.keys()) {
  if (!expectedIdSet.has(id)) {
    failures.push(`unexpected ledger row ${id} is present`);
  }
}

if (!ledger.includes("Static evidence inventory, not a passing test manifest")) {
  failures.push("ledger must retain its non-passing-manifest warning");
}
if (failures.length > 0) {
  process.stderr.write(
    `Issue #240 acceptance ledger validation failed:\n${failures
      .map((failure) => `- ${failure}`)
      .join("\n")}\n`,
  );
  process.exitCode = 1;
} else {
  process.stdout.write(
    `Issue #240 acceptance ledger is structurally valid (${rows.size} required rows).\n`,
  );
}
