import { hasUniqueMembers } from '../../../lib/policyRuns';
import type { SimulationDecision } from '../../../lib/policySimulations';
import type { PolicyTestMatched, PolicyTestOutcome } from '../../../lib/policyTestRuns';
import { decodePointer, isJsonObject, removeAt, type JsonObject } from '../model';

// The cases the Simulator and the Test view share are one `policy-tests.v1`
// suite, held as text in page memory only. A simulated case is a test case
// without its `expect`: the same facts ask the same question.
export const SUITE_SCHEMA_VERSION = 'policy-tests.v1';
export const MAX_SIMULATION_CASES = 256;
export const MAX_SUITE_CASES = 512;

export type CaseKind = 'http' | 'tool' | 'tool_http' | 'rate';

export const CASE_KINDS: ReadonlyArray<{
  value: CaseKind;
  label: string;
  description: string;
}> = [
  {
    value: 'http',
    label: 'HTTP request',
    description:
      'Asks the HTTP lane: direct rules, MCP alias identities, routes, host binding, defaults and shadow enforcement.',
  },
  {
    value: 'tool',
    label: 'Tool question',
    description: 'Asks the tool lane about invoking, listing or inventorying one tool.',
  },
  {
    value: 'tool_http',
    label: 'Rendered tool request',
    description: 'Asks whether the direct HTTP rules allow the request a tool would send.',
  },
  {
    value: 'rate',
    label: 'Rate-limit selection',
    description:
      'Asks which rate-limit override governs a request. Bucket capacity is not modelled.',
  },
];

export const HTTP_REASONS = [
  'matched_rule',
  'missing_permission',
  'missing_principal',
  'default_allow',
  'default_deny',
  'host_policy_required',
] as const;

export const TOOL_REASONS = [
  'unknown_tool',
  'disabled',
  'role_not_allowed',
  'matched_rule',
  'allowed',
  'not_in_policy',
  'policy_disabled',
  'principal_not_eligible',
  'policy_denied',
  'eligible',
  'no_http_rule',
] as const;

const SYNTHETIC_PRINCIPAL: JsonObject = {
  subject: 'synthetic-caller',
  roles: [],
  auth_method: 'bearer_token',
};

export type SuiteParse =
  | { ok: true; suite: JsonObject; cases: JsonObject[] }
  | { ok: false; message: string };

export function emptySuiteSource(): string {
  return formatSuite({ schema_version: SUITE_SCHEMA_VERSION, cases: [] });
}

export function formatSuite(suite: JsonObject): string {
  return JSON.stringify(suite, null, 2);
}

export function parseSuite(source: string): SuiteParse {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch (error) {
    return {
      ok: false,
      message:
        error instanceof Error
          ? `The suite is not valid JSON: ${error.message}`
          : 'The suite is not valid JSON.',
    };
  }
  if (!isJsonObject(value)) {
    return { ok: false, message: 'A policy-tests.v1 suite is a JSON object.' };
  }
  if (!hasUniqueMembers(source)) {
    return {
      ok: false,
      message: 'The suite names a member twice in one object, which the gateway refuses.',
    };
  }
  const cases = value.cases ?? [];
  if (!Array.isArray(cases) || !cases.every(isJsonObject)) {
    return { ok: false, message: 'The suite needs a cases array of JSON objects.' };
  }
  return { ok: true, suite: value, cases };
}

export function withCases(suite: JsonObject, cases: readonly JsonObject[]): JsonObject {
  return { ...suite, cases: [...cases] };
}

export function caseId(entry: JsonObject): string {
  return typeof entry.id === 'string' ? entry.id : '';
}

export function caseKind(entry: JsonObject): CaseKind | null {
  return entry.kind === 'http' ||
    entry.kind === 'tool' ||
    entry.kind === 'tool_http' ||
    entry.kind === 'rate'
    ? entry.kind
    : null;
}

export function caseKindLabel(kind: string | null): string {
  return CASE_KINDS.find((entry) => entry.value === kind)?.label ?? 'Unknown kind';
}

export function nextCaseId(cases: readonly JsonObject[]): string {
  const used = new Set(cases.map(caseId));
  for (let index = cases.length + 1; ; index += 1) {
    const candidate = `case-${index}`;
    if (!used.has(candidate)) {
      return candidate;
    }
  }
}

export function newCase(kind: CaseKind, cases: readonly JsonObject[]): JsonObject {
  return reshapeCase(
    { id: nextCaseId(cases), kind, principal: { ...SYNTHETIC_PRINCIPAL } },
    kind,
  );
}

// The case as `kind` asks it: the members that kind takes, kept where the
// old kind had them, and no expectation, since its shape depends on the kind.
export function reshapeCase(entry: JsonObject, kind: CaseKind): JsonObject {
  const request = isJsonObject(entry.request) ? entry.request : {};
  const tool = isJsonObject(entry.tool) ? entry.tool : {};
  const method = typeof request.method === 'string' ? request.method : 'GET';
  const path = typeof request.path === 'string' ? request.path : '/';
  const name = typeof tool.name === 'string' ? tool.name : '';
  const next: JsonObject = { id: entry.id ?? '', kind };
  if (typeof entry.description === 'string') {
    next.description = entry.description;
  }
  if (kind === 'http') {
    next.request =
      entry.kind === 'http' && isJsonObject(entry.request) ? request : { method, path };
  } else if (kind === 'tool') {
    next.tool =
      entry.kind === 'tool' && isJsonObject(entry.tool) ? tool : { name, operation: 'invocation' };
  } else if (kind === 'tool_http') {
    next.tool = { name };
    next.request = { method, path };
  } else {
    next.request = { method, path };
  }
  next.principal = entry.principal ?? { ...SYNTHETIC_PRINCIPAL };
  if (entry.kind === kind && entry.expect !== undefined) {
    next.expect = entry.expect;
  }
  return next;
}

export function duplicateCase(cases: readonly JsonObject[], index: number): JsonObject[] {
  const original = cases[index];
  if (original === undefined) {
    return [...cases];
  }
  const copy = { ...structuredClone(original), id: nextCaseId(cases) };
  return [...cases.slice(0, index + 1), copy, ...cases.slice(index + 1)];
}

export function removeCase(cases: readonly JsonObject[], index: number): JsonObject[] {
  return removeAt(cases, index);
}

// The cases a simulation asks: each test case without the expectation a
// simulation refuses.
export function simulationCases(cases: readonly JsonObject[]): JsonObject[] {
  return cases.map((entry) => {
    const next = { ...entry };
    delete next.expect;
    return next;
  });
}

// The cases a test run would refuse for having no expectation, by id (or
// position, for a case without one).
export function casesWithoutExpectation(cases: readonly JsonObject[]): string[] {
  return cases.flatMap((entry, index) =>
    isJsonObject(entry.expect) ? [] : [caseId(entry) || `#${index + 1}`],
  );
}

// The case a diagnostic about `/cases/<n>/...` is about.
export function caseIndexForPointer(pointer: string): number | null {
  const segments = decodePointer(pointer);
  if (segments === null || segments[0] !== 'cases' || segments.length < 2) {
    return null;
  }
  return /^(0|[1-9][0-9]*)$/.test(segments[1]) ? Number(segments[1]) : null;
}

// What a test case would assert to expect the answer the candidate gave
// as authored, or null when that answer is not one a test can expect: an
// undecided case never passes, so it cannot be an expectation.
export function expectationFromDecision(
  kind: CaseKind,
  decision: SimulationDecision,
): JsonObject | null {
  if (!decision.complete) {
    return null;
  }
  if (kind === 'rate') {
    if (decision.selected === 'override' && decision.rate_override !== null) {
      return { rate_override: decision.rate_override.position };
    }
    return decision.selected === 'no_override' ? { rate_override: null } : null;
  }
  if (decision.logical !== 'allow' && decision.logical !== 'deny') {
    return null;
  }
  const expect: JsonObject = { logical: decision.logical };
  const effect = effectOf(decision);
  if (effect !== null) {
    expect.effect = effect;
  }
  const reasons: readonly string[] = kind === 'http' ? HTTP_REASONS : TOOL_REASONS;
  if (decision.reason !== null && reasons.includes(decision.reason)) {
    expect.reason = decision.reason;
  }
  if (decision.matched === null) {
    expect.matched = 'none';
  } else if (decision.matched !== undefined) {
    const matched = decision.matched;
    // A rule is named by its id, or by its position when it has none; an id
    // too long to repeat cannot be named, so the match is not asserted.
    if (matched.kind === 'rule' && !matched.id_omitted) {
      expect.matched = { rule: matched.id ?? String(matched.position) };
    } else if (matched.kind === 'route' && kind === 'http') {
      expect.matched = { route: matched.position };
    }
  }
  return expect;
}

// The test vocabulary's effect for a decided answer: `observe` is a deny
// that shadow enforcement forwards.
export function effectOf(decision: SimulationDecision): string | null {
  if (decision.enforcement === 'shadowed') return 'observe';
  if (decision.effective_action === 'would_block') return 'block';
  if (decision.effective_action === 'would_forward') return 'allow';
  return null;
}

export function describeOutcome(outcome: PolicyTestOutcome | null): string {
  if (outcome === null) {
    return 'No answer';
  }
  const parts: string[] = [];
  if (outcome.logical !== undefined) parts.push(outcome.logical);
  if (outcome.effect !== undefined) parts.push(`effect ${outcome.effect}`);
  if (outcome.reason !== undefined) parts.push(outcome.reason);
  if (outcome.matched !== undefined) parts.push(describeMatched(outcome.matched));
  if (outcome.rate_override !== undefined) {
    parts.push(
      outcome.rate_override === null
        ? 'no rate override'
        : `rate override ${outcome.rate_override}`,
    );
  }
  return parts.length === 0 ? 'Nothing asserted' : parts.join(', ');
}

export function describeMatched(matched: PolicyTestMatched): string {
  if (matched === 'none') return 'nothing matched';
  if ('rule' in matched) return `rule ${matched.rule}`;
  return `route ${matched.route}`;
}
