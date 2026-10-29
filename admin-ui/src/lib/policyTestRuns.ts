import { AdminApiError, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';
import {
  boundedCodes,
  isBoundedText,
  isCode,
  isCount,
  isJsonObject,
  isPointer,
  jsonObjectText,
  projectRunRefusal,
  type PolicyRunCandidate,
  type PolicyRunRefusal,
} from './policyRuns';

export const POLICY_TESTS_BUSY_REASON = 'policy_tests_busy';
export const POLICY_TESTS_DEADLINE_REASON = 'policy_tests_deadline_exceeded';

const MAX_CASES = 512;
const MAX_ID_LENGTH = 256;
const MAX_DIGEST_LENGTH = 256;
const MISMATCH_MEMBERS = new Set(['logical', 'effect', 'reason', 'matched', 'rate_override']);

export type PolicyTestRunStatus = 'passed' | 'failed' | 'incomplete' | 'error';
export type PolicyTestCaseStatus = 'passed' | 'failed' | 'incomplete' | 'error';

export type PolicyTestMatched =
  | 'none'
  | Readonly<{ rule: string }>
  | Readonly<{ route: number }>;

// What a case asserted, or what the evaluator answered, in stable codes.
// `rate_override` is undefined when not asserted and null for "no override".
export type PolicyTestOutcome = Readonly<{
  logical?: string;
  effect?: string;
  reason?: string;
  matched?: PolicyTestMatched;
  rate_override?: number | null;
}>;

export type PolicyTestActual = PolicyTestOutcome &
  Readonly<{ complete: boolean; limitation: string | null }>;

export type PolicyTestCaseResult = Readonly<{
  id: string;
  pointer: string;
  kind: string;
  status: PolicyTestCaseStatus;
  expected: PolicyTestOutcome;
  // Absent exactly when the evaluator refused the case.
  actual: PolicyTestActual | null;
  mismatches: readonly string[];
  error: string | null;
}>;

export type PolicyTestSummary = Readonly<{
  total: number;
  passed: number;
  failed: number;
  incomplete: number;
  errors: number;
}>;

export type PolicyTestReport = Readonly<{
  status: PolicyTestRunStatus;
  suite_digest: string;
  policy: Readonly<{
    source: 'active' | 'inline_candidate';
    etag: string;
    security_revision: number | null;
  }>;
  gateway_version: string | null;
  not_evaluated: readonly string[];
  summary: PolicyTestSummary;
  cases: readonly PolicyTestCaseResult[];
}>;

export type PolicyTestRunAnswer =
  | Readonly<{ kind: 'report'; report: PolicyTestReport }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

export type PolicyTestRunRequest = Readonly<{
  // The exact text of a `policy-tests.v1` suite.
  suiteSource: string;
  candidate: PolicyRunCandidate;
  // The live policy ETag reviewed, pinned with If-Match when the run judges
  // the live policy itself.
  liveEtag: string;
  signal?: AbortSignal;
}>;

// Run a suite against the live policy or a candidate, in the JSON format.
// Nothing is written or stored. A run that completed is a report whatever its
// outcome; a refusal with structured detail (`422`) is an answer.
export async function runPolicyTests(
  request: PolicyTestRunRequest,
): Promise<PolicyTestRunAnswer> {
  const suite = jsonObjectText(request.suiteSource);
  const policy =
    request.candidate.kind === 'inline'
      ? `,"policy":${jsonObjectText(request.candidate.source)}`
      : '';
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/tests/runs'),
    {
      method: 'POST',
      signal: request.signal,
      headers: {
        'Content-Type': 'application/json',
        // If-Match pins the live policy; the gateway refuses it beside a
        // candidate, which is judged as sent.
        ...(request.candidate.kind === 'active' ? { 'If-Match': request.liveEtag } : {}),
      },
      body: `{"suite":${suite}${policy},"format":"json"}`,
      answerStatuses: [422],
    },
  );
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the policy test run.');
    }
    return { kind: 'refused', refusal };
  }
  const report = projectTestReport(response.body);
  if (report === null) {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable policy test report.',
    );
  }
  return { kind: 'report', report };
}

export function projectTestReport(body: unknown): PolicyTestReport | null {
  if (
    !isJsonObject(body) ||
    body.schema_version !== 'policy-test-results.v1' ||
    body.mode !== 'test' ||
    !isRunStatus(body.status) ||
    !isJsonObject(body.suite) ||
    !isBoundedText(body.suite.digest, MAX_DIGEST_LENGTH) ||
    !isJsonObject(body.policy) ||
    (body.policy.source !== 'active' && body.policy.source !== 'inline_candidate') ||
    !isBoundedText(body.policy.etag, MAX_DIGEST_LENGTH) ||
    !isJsonObject(body.summary) ||
    !isCount(body.summary.total) ||
    !isCount(body.summary.passed) ||
    !isCount(body.summary.failed) ||
    !isCount(body.summary.incomplete) ||
    !isCount(body.summary.errors) ||
    !Array.isArray(body.cases) ||
    body.cases.length > MAX_CASES
  ) {
    return null;
  }
  const notEvaluated = boundedCodes(body.not_evaluated);
  if (notEvaluated === null) {
    return null;
  }
  const cases: PolicyTestCaseResult[] = [];
  for (const entry of body.cases) {
    const projected = projectCaseResult(entry);
    if (projected === null) {
      return null;
    }
    cases.push(projected);
  }
  return {
    status: body.status,
    suite_digest: body.suite.digest,
    policy: {
      source: body.policy.source,
      etag: body.policy.etag,
      security_revision: isCount(body.policy.security_revision)
        ? body.policy.security_revision
        : null,
    },
    gateway_version: isBoundedText(body.gateway_version, MAX_ID_LENGTH)
      ? body.gateway_version
      : null,
    not_evaluated: notEvaluated,
    summary: {
      total: body.summary.total,
      passed: body.summary.passed,
      failed: body.summary.failed,
      incomplete: body.summary.incomplete,
      errors: body.summary.errors,
    },
    cases,
  };
}

function projectCaseResult(value: unknown): PolicyTestCaseResult | null {
  if (
    !isJsonObject(value) ||
    !isBoundedText(value.id, MAX_ID_LENGTH) ||
    !isPointer(value.pointer) ||
    !isCode(value.kind) ||
    !isRunStatus(value.status) ||
    !Array.isArray(value.mismatches) ||
    !value.mismatches.every(
      (member): member is string => typeof member === 'string' && MISMATCH_MEMBERS.has(member),
    ) ||
    !(value.error === undefined || isCode(value.error))
  ) {
    return null;
  }
  const expected = projectOutcome(value.expected);
  if (expected === null) {
    return null;
  }
  let actual: PolicyTestActual | null = null;
  if (value.actual !== undefined) {
    const outcome = projectOutcome(value.actual);
    if (
      outcome === null ||
      !isJsonObject(value.actual) ||
      typeof value.actual.complete !== 'boolean' ||
      !(value.actual.limitation === null || isCode(value.actual.limitation))
    ) {
      return null;
    }
    actual = {
      ...outcome,
      complete: value.actual.complete,
      limitation: isCode(value.actual.limitation) ? value.actual.limitation : null,
    };
  }
  // A refused case, and only a refused one, has no answer.
  if ((value.status === 'error') !== (actual === null)) {
    return null;
  }
  return {
    id: value.id,
    pointer: value.pointer,
    kind: value.kind,
    status: value.status,
    expected,
    actual,
    mismatches: value.mismatches,
    error: isCode(value.error) ? value.error : null,
  };
}

function projectOutcome(value: unknown): PolicyTestOutcome | null {
  if (!isJsonObject(value)) {
    return null;
  }
  const outcome: {
    logical?: string;
    effect?: string;
    reason?: string;
    matched?: PolicyTestMatched;
    rate_override?: number | null;
  } = {};
  for (const member of ['logical', 'effect', 'reason'] as const) {
    const code = value[member];
    if (code === undefined) continue;
    if (!isCode(code)) return null;
    outcome[member] = code;
  }
  if (value.matched !== undefined) {
    const matched = projectMatched(value.matched);
    if (matched === null) return null;
    outcome.matched = matched;
  }
  if ('rate_override' in value) {
    const selected = value.rate_override;
    if (selected !== null && !isCount(selected)) return null;
    outcome.rate_override = selected;
  }
  return outcome;
}

function projectMatched(value: unknown): PolicyTestMatched | null {
  if (value === 'none') {
    return 'none';
  }
  if (isJsonObject(value)) {
    if (isBoundedText(value.rule, MAX_ID_LENGTH)) {
      return { rule: value.rule };
    }
    if (isCount(value.route)) {
      return { route: value.route };
    }
  }
  return null;
}

function isRunStatus(value: unknown): value is PolicyTestRunStatus {
  return (
    value === 'passed' || value === 'failed' || value === 'incomplete' || value === 'error'
  );
}
