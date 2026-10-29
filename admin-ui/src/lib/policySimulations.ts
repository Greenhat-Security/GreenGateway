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

export const POLICY_SIMULATION_SCHEMA_VERSION = 'policy-simulation.v1';
export const POLICY_SIMULATION_BASE_STALE_REASON = 'policy_simulation_base_stale';
export const POLICY_SIMULATION_BUSY_REASON = 'policy_simulation_busy';
export const POLICY_SIMULATION_DEADLINE_REASON = 'policy_simulation_deadline_exceeded';

export type SimulationTraceLevel = 'terminal' | 'matched' | 'full';
export type SimulationProjection = 'as_authored' | 'enforce_all_shadow';

export const SIMULATION_PROJECTIONS: readonly SimulationProjection[] = [
  'as_authored',
  'enforce_all_shadow',
];

const MAX_CASES = 256;
const MAX_STAGES_PER_DECISION = 16;
const MAX_ID_LENGTH = 256;
const MAX_DIGEST_LENGTH = 256;

// The policy element that decided, by position, with its bounded authored
// id and, for a route, the permission it requires. An id or permission too
// long to repeat is reported as omitted.
export type SimulationElement = Readonly<{
  kind: 'rule' | 'route';
  position: number;
  id: string | null;
  id_omitted: boolean;
  action: string | null;
  permission: string | null;
  permission_omitted: boolean;
  permission_granted: boolean | null;
}>;

// One evaluator stage of an HTTP decision, in evaluation order.
export type SimulationStage = Readonly<{
  stage: string;
  status: string;
  limitation: string | null;
  host: string | null;
  element: SimulationElement | null;
  action: string | null;
  deny_only: boolean;
  permission: string | null;
  enforcement_mode: string | null;
  mode_inherited: boolean | null;
  reason: string | null;
  default_action: string | null;
}>;

export type SimulationRateOverride = Readonly<{
  position: number;
  id: string | null;
  id_omitted: boolean;
  requests_per_second: number | null;
  burst: number | null;
}>;

// One evaluation of one case. The logical decision, whether a denial is
// enforced or only observed, and what the request would meet are three
// separate answers, so a shadowed deny is never read as an allow. `matched`
// is undefined when the trace level does not report it, which is not the
// same as no element matching (null).
export type SimulationDecision = Readonly<{
  lane: 'http' | 'tool' | 'rate_selection';
  operation: string | null;
  logical: 'allow' | 'deny' | 'indeterminate' | null;
  enforcement: 'enforced' | 'shadowed' | 'not_applicable' | null;
  effective_action: 'would_forward' | 'would_block' | 'unknown' | null;
  reason: string | null;
  complete: boolean;
  limitation: string | null;
  matched?: SimulationElement | null;
  observation?: SimulationElement | null;
  stages: readonly SimulationStage[] | null;
  stages_truncated: boolean;
  selected: 'override' | 'no_override' | 'indeterminate' | null;
  rate_override: SimulationRateOverride | null;
}>;

export type SimulationCaseResult = Readonly<{
  projection: SimulationProjection;
  // The live policy's answer under the same projection, when the candidate
  // is not the live policy itself.
  base: SimulationDecision | null;
  changed: boolean | null;
  candidate: SimulationDecision;
}>;

export type SimulationCase = Readonly<{
  id: string;
  pointer: string;
  kind: string;
  results: readonly SimulationCaseResult[];
  projection_changed: boolean | null;
}>;

export type SimulationCounts = Readonly<{
  would_forward: number;
  would_block: number;
  unknown: number;
  shadowed: number;
  rate_override: number;
  no_rate_override: number;
  rate_unknown: number;
  changed_from_base: number | null;
}>;

export type SimulationResult = Readonly<{
  request_digest: string;
  gateway_version: string | null;
  http_semantics_version: string | null;
  tool_semantics_version: string | null;
  base: Readonly<{ etag: string; security_revision: number | null }>;
  candidate: Readonly<{ source: string; etag: string }>;
  trace: Readonly<{
    level: SimulationTraceLevel;
    max_stages: number;
    stages_truncated: boolean;
  }>;
  projections: readonly SimulationProjection[];
  not_evaluated: readonly string[];
  summary: Readonly<{
    cases: number;
    projections: Readonly<Partial<Record<SimulationProjection, SimulationCounts>>>;
    projection_changed: number | null;
  }>;
  cases: readonly SimulationCase[];
}>;

export type SimulationAnswer =
  | Readonly<{ kind: 'result'; result: SimulationResult }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

export type SimulationRequest = Readonly<{
  baseEtag: string;
  candidate: PolicyRunCandidate;
  trace: SimulationTraceLevel;
  projections: readonly SimulationProjection[];
  // `policy-tests.v1` cases without `expect`.
  cases: readonly Record<string, unknown>[];
  signal?: AbortSignal;
}>;

// Ask what the live policy and the candidate decide for synthetic cases.
// Nothing is written, activated or stored; a refusal with structured detail
// (`422`) is an answer, every other failure an error.
export async function runPolicySimulation(
  request: SimulationRequest,
): Promise<SimulationAnswer> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/simulations'),
    {
      method: 'POST',
      signal: request.signal,
      headers: { 'Content-Type': 'application/json' },
      body: simulationRequestBody(request),
      answerStatuses: [422],
    },
  );
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the simulation.');
    }
    return { kind: 'refused', refusal };
  }
  const result = projectSimulationResult(response.body);
  if (result === null) {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable simulation result.',
    );
  }
  return { kind: 'result', result };
}

// The candidate's text is spliced in as the bytes the operator wrote; the
// rest of the request is serialized here.
function simulationRequestBody(request: SimulationRequest): string {
  const candidate =
    request.candidate.kind === 'active'
      ? '{"source":"active"}'
      : `{"source":"inline","policy":${jsonObjectText(request.candidate.source)}}`;
  return [
    '{"schema_version":',
    JSON.stringify(POLICY_SIMULATION_SCHEMA_VERSION),
    ',"base_etag":',
    JSON.stringify(request.baseEtag),
    ',"candidate":',
    candidate,
    ',"trace":',
    JSON.stringify(request.trace),
    ',"projections":',
    JSON.stringify(request.projections),
    ',"cases":',
    JSON.stringify(request.cases),
    '}',
  ].join('');
}

export function projectSimulationResult(body: unknown): SimulationResult | null {
  if (
    !isJsonObject(body) ||
    body.schema_version !== 'policy-simulation-results.v1' ||
    body.mode !== 'synthetic' ||
    !isBoundedText(body.request_digest, MAX_DIGEST_LENGTH) ||
    !isJsonObject(body.base) ||
    !isBoundedText(body.base.etag, MAX_DIGEST_LENGTH) ||
    !isJsonObject(body.candidate) ||
    !isCode(body.candidate.source) ||
    !isBoundedText(body.candidate.etag, MAX_DIGEST_LENGTH) ||
    !isJsonObject(body.trace) ||
    !isTraceLevel(body.trace.level) ||
    !isCount(body.trace.max_stages) ||
    typeof body.trace.stages_truncated !== 'boolean' ||
    !Array.isArray(body.projections) ||
    body.projections.length > SIMULATION_PROJECTIONS.length ||
    !body.projections.every(isProjection) ||
    !isJsonObject(body.summary) ||
    !isCount(body.summary.cases) ||
    !isJsonObject(body.summary.projections) ||
    !Array.isArray(body.cases) ||
    body.cases.length > MAX_CASES
  ) {
    return null;
  }
  const notEvaluated = boundedCodes(body.not_evaluated);
  if (notEvaluated === null) {
    return null;
  }
  const projections = body.projections as SimulationProjection[];
  const summaryProjections: Partial<Record<SimulationProjection, SimulationCounts>> = {};
  for (const projection of projections) {
    const counts = projectCounts(body.summary.projections[projection]);
    if (counts === null) {
      return null;
    }
    summaryProjections[projection] = counts;
  }
  const cases: SimulationCase[] = [];
  for (const entry of body.cases) {
    const projected = projectCase(entry);
    if (projected === null) {
      return null;
    }
    cases.push(projected);
  }
  const evaluator = isJsonObject(body.evaluator) ? body.evaluator : {};
  return {
    request_digest: body.request_digest,
    gateway_version: optionalText(evaluator.gateway_version),
    http_semantics_version: optionalText(evaluator.http_semantics_version),
    tool_semantics_version: optionalText(evaluator.tool_semantics_version),
    base: {
      etag: body.base.etag,
      security_revision: isCount(body.base.security_revision)
        ? body.base.security_revision
        : null,
    },
    candidate: { source: body.candidate.source, etag: body.candidate.etag },
    trace: {
      level: body.trace.level,
      max_stages: body.trace.max_stages,
      stages_truncated: body.trace.stages_truncated,
    },
    projections,
    not_evaluated: notEvaluated,
    summary: {
      cases: body.summary.cases,
      projections: summaryProjections,
      projection_changed: isCount(body.summary.projection_changed)
        ? body.summary.projection_changed
        : null,
    },
    cases,
  };
}

function projectCounts(value: unknown): SimulationCounts | null {
  if (
    !isJsonObject(value) ||
    !isCount(value.would_forward) ||
    !isCount(value.would_block) ||
    !isCount(value.unknown) ||
    !isCount(value.shadowed) ||
    !isCount(value.rate_override) ||
    !isCount(value.no_rate_override) ||
    !isCount(value.rate_unknown) ||
    !(value.changed_from_base === undefined || isCount(value.changed_from_base))
  ) {
    return null;
  }
  return {
    would_forward: value.would_forward,
    would_block: value.would_block,
    unknown: value.unknown,
    shadowed: value.shadowed,
    rate_override: value.rate_override,
    no_rate_override: value.no_rate_override,
    rate_unknown: value.rate_unknown,
    changed_from_base: isCount(value.changed_from_base) ? value.changed_from_base : null,
  };
}

function projectCase(value: unknown): SimulationCase | null {
  if (
    !isJsonObject(value) ||
    !isBoundedText(value.id, MAX_ID_LENGTH) ||
    !isPointer(value.pointer) ||
    !isCode(value.kind) ||
    !Array.isArray(value.results) ||
    value.results.length === 0 ||
    value.results.length > SIMULATION_PROJECTIONS.length ||
    !(value.projection_changed === undefined || typeof value.projection_changed === 'boolean')
  ) {
    return null;
  }
  const results: SimulationCaseResult[] = [];
  for (const entry of value.results) {
    if (!isJsonObject(entry) || !isProjection(entry.projection)) {
      return null;
    }
    const candidate = projectDecision(entry.candidate);
    const base = entry.base === undefined ? null : projectDecision(entry.base);
    if (
      candidate === null ||
      (entry.base !== undefined && base === null) ||
      !(entry.changed === undefined || typeof entry.changed === 'boolean')
    ) {
      return null;
    }
    results.push({
      projection: entry.projection,
      base,
      changed: typeof entry.changed === 'boolean' ? entry.changed : null,
      candidate,
    });
  }
  return {
    id: value.id,
    pointer: value.pointer,
    kind: value.kind,
    results,
    projection_changed:
      typeof value.projection_changed === 'boolean' ? value.projection_changed : null,
  };
}

function projectDecision(value: unknown): SimulationDecision | null {
  if (
    !isJsonObject(value) ||
    (value.lane !== 'http' && value.lane !== 'tool' && value.lane !== 'rate_selection') ||
    typeof value.complete !== 'boolean' ||
    !(value.limitation === undefined || isCode(value.limitation))
  ) {
    return null;
  }
  const decision = {
    lane: value.lane,
    operation: isCode(value.operation) ? value.operation : null,
    logical: null,
    enforcement: null,
    effective_action: null,
    reason: null,
    complete: value.complete,
    limitation: isCode(value.limitation) ? value.limitation : null,
    stages: null,
    stages_truncated: value.stages_truncated === true,
    selected: null,
    rate_override: null,
  } satisfies SimulationDecision;
  if (value.lane === 'rate_selection') {
    if (
      value.selected !== 'override' &&
      value.selected !== 'no_override' &&
      value.selected !== 'indeterminate'
    ) {
      return null;
    }
    const override =
      value.rate_override === null || value.rate_override === undefined
        ? null
        : projectRateOverride(value.rate_override);
    if (value.selected === 'override' && override === null) {
      return null;
    }
    return { ...decision, selected: value.selected, rate_override: override };
  }
  if (
    (value.logical !== 'allow' && value.logical !== 'deny' && value.logical !== 'indeterminate') ||
    (value.enforcement !== 'enforced' &&
      value.enforcement !== 'shadowed' &&
      value.enforcement !== 'not_applicable') ||
    (value.effective_action !== 'would_forward' &&
      value.effective_action !== 'would_block' &&
      value.effective_action !== 'unknown') ||
    !isCode(value.reason)
  ) {
    return null;
  }
  const matched = optionalElement(value, 'matched');
  const observation = optionalElement(value, 'observation');
  if (matched === false || observation === false) {
    return null;
  }
  let stages: SimulationStage[] | null = null;
  if (value.stages !== undefined) {
    if (!Array.isArray(value.stages) || value.stages.length > MAX_STAGES_PER_DECISION) {
      return null;
    }
    stages = [];
    for (const entry of value.stages) {
      const stage = projectStage(entry);
      if (stage === null) {
        return null;
      }
      stages.push(stage);
    }
  }
  return {
    ...decision,
    logical: value.logical,
    enforcement: value.enforcement,
    effective_action: value.effective_action,
    reason: value.reason,
    ...(matched === undefined ? {} : { matched }),
    ...(observation === undefined ? {} : { observation }),
    stages,
  };
}

// An element member a trace level may omit: undefined when it is absent,
// null when no element applied, false when it is not an element.
function optionalElement(
  value: Record<string, unknown>,
  member: string,
): SimulationElement | null | undefined | false {
  if (!(member in value)) {
    return undefined;
  }
  if (value[member] === null) {
    return null;
  }
  return projectElement(value[member]) ?? false;
}

function projectElement(value: unknown): SimulationElement | null {
  if (
    !isJsonObject(value) ||
    (value.kind !== 'rule' && value.kind !== 'route') ||
    !isCount(value.position)
  ) {
    return null;
  }
  return {
    kind: value.kind,
    position: value.position,
    id: isBoundedText(value.id, MAX_ID_LENGTH) ? value.id : null,
    id_omitted: value.id_omitted === true,
    action: isCode(value.action) ? value.action : null,
    permission: isBoundedText(value.permission, MAX_ID_LENGTH) ? value.permission : null,
    permission_omitted: value.permission_omitted === true,
    permission_granted:
      typeof value.permission_granted === 'boolean' ? value.permission_granted : null,
  };
}

function projectStage(value: unknown): SimulationStage | null {
  if (!isJsonObject(value) || !isCode(value.stage) || !isCode(value.status)) {
    return null;
  }
  const element =
    value.element === undefined ? null : projectElement(value.element);
  if (value.element !== undefined && element === null) {
    return null;
  }
  return {
    stage: value.stage,
    status: value.status,
    limitation: isCode(value.limitation) ? value.limitation : null,
    host: isCode(value.host) ? value.host : null,
    element,
    action: isCode(value.action) ? value.action : null,
    deny_only: value.deny_only === true,
    permission: isCode(value.permission) ? value.permission : null,
    enforcement_mode: isCode(value.enforcement_mode) ? value.enforcement_mode : null,
    mode_inherited: typeof value.mode_inherited === 'boolean' ? value.mode_inherited : null,
    reason: isCode(value.reason) ? value.reason : null,
    default_action: isCode(value.default_action) ? value.default_action : null,
  };
}

function projectRateOverride(value: unknown): SimulationRateOverride | null {
  if (!isJsonObject(value) || !isCount(value.position)) {
    return null;
  }
  return {
    position: value.position,
    id: isBoundedText(value.id, MAX_ID_LENGTH) ? value.id : null,
    id_omitted: value.id_omitted === true,
    requests_per_second: isPositiveNumber(value.requests_per_second)
      ? value.requests_per_second
      : null,
    burst: isCount(value.burst) ? value.burst : null,
  };
}

function isPositiveNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isTraceLevel(value: unknown): value is SimulationTraceLevel {
  return value === 'terminal' || value === 'matched' || value === 'full';
}

function isProjection(value: unknown): value is SimulationProjection {
  return value === 'as_authored' || value === 'enforce_all_shadow';
}

function optionalText(value: unknown): string | null {
  return isBoundedText(value, MAX_ID_LENGTH) ? value : null;
}
