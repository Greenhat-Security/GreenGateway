import { AdminApiError, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';
import {
  boundedCodes,
  isBoundedText,
  isCode,
  isCount,
  isJsonObject,
  jsonObjectText,
  projectCodeCounts,
  projectRunRefusal,
  type PolicyRunCandidate,
  type PolicyRunRefusal,
} from './policyRuns';

export const POLICY_REPLAY_SCHEMA_VERSION = 'policy-replay.v1';
export const POLICY_REPLAY_BASE_STALE_REASON = 'policy_replay_base_stale';
export const POLICY_REPLAY_BUSY_REASON = 'policy_replay_busy';
export const POLICY_REPLAY_QUOTA_REASON = 'policy_replay_quota_exhausted';
export const POLICY_REPLAY_NOT_FOUND_REASON = 'policy_replay_job_not_found';
export const POLICY_REPLAY_IDEMPOTENCY_CONFLICT_REASON = 'policy_replay_idempotency_conflict';
export const POLICY_REPLAY_UNSUPPORTED_IN_CLUSTER_REASON = 'policy_replay_unsupported_in_cluster';
export const POLICY_REPLAY_AUDIT_UNAVAILABLE_REASON = 'policy_replay_audit_unavailable';
export const AUDIT_EVIDENCE_UNAVAILABLE_REASON = 'audit_evidence_unavailable';
export const POLICY_REPLAY_MAX_RECORDS = 100_000;

const POLICY_REPLAY_JOB_ID_PATTERN = /^rpl_[0-9a-f]{32}$/;
const MAX_TEXT_LENGTH = 256;
const MAX_OUTCOMES = 256;

export type PolicyReplayState =
  | 'queued'
  | 'running'
  | 'completed'
  | 'completed_incomplete'
  | 'failed'
  | 'cancelled'
  | 'expired';

export type PolicyReplayCodeCount = Readonly<{ code: string; count: number }>;

// Decided records counted by the candidate's answer, in the simulation's
// vocabulary, so a shadowed deny is never counted as an allow.
export type PolicyReplayOutcome = Readonly<{
  logical: string;
  enforcement: string;
  effective_action: string;
  reason: string;
  count: number;
}>;

export type PolicyReplayLane = Readonly<{
  replayable: number;
  decided: number;
  indeterminate: number;
  refused: number;
  outcomes: readonly PolicyReplayOutcome[];
  limitations: readonly PolicyReplayCodeCount[];
  refusals: readonly PolicyReplayCodeCount[];
  egress_not_replayed: number;
}>;

export type PolicyReplayRate = Readonly<{
  no_override: number;
  override: number;
  indeterminate: number;
  refused: number;
  limitations: readonly PolicyReplayCodeCount[];
  refusals: readonly PolicyReplayCodeCount[];
}>;

export type PolicyReplayRecords = Readonly<{
  selected: number;
  scanned: number;
  replayable: number;
  duplicate: number;
  not_policy_evaluated: number;
  unsupported: number;
  malformed: number;
  not_request_record: number;
  unreadable: number;
  oversized: number;
  by_code: readonly PolicyReplayCodeCount[];
}>;

// What the candidate decided for one window of retained records. It holds
// counts and stable codes only, and it does not compare them with what was
// recorded or with the live policy.
export type PolicyReplayResult = Readonly<{
  complete: boolean;
  limitations: readonly string[];
  window: Readonly<{ from: string; to: string | null }>;
  high_water: number;
  max_records: number;
  records: PolicyReplayRecords;
  replayed: Readonly<{
    total: number;
    http: PolicyReplayLane;
    rate: PolicyReplayRate;
    tool: PolicyReplayLane;
  }>;
  not_replayed: readonly string[];
}>;

export type PolicyReplayJob = Readonly<{
  job_id: string;
  state: PolicyReplayState;
  cancel_requested: boolean;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  result_expires_at: string | null;
  request_digest: string;
  // `current` says whether the live policy is still the one the job was
  // pinned to; null when the gateway did not say.
  base: Readonly<{ etag: string; current: boolean | null }>;
  candidate: Readonly<{ source: string; etag: string }>;
  window: Readonly<{ from: string; to: string | null }>;
  selected_records: number;
  scanned_records: number;
  max_records: number;
  deadline_ms: number | null;
  failure: string | null;
  result_digest: string | null;
  result: PolicyReplayResult | null;
}>;

export type PolicyReplayWindow = Readonly<{ from: string; to?: string }>;

export type PolicyReplayStartRequest = Readonly<{
  baseEtag: string;
  candidate: PolicyRunCandidate;
  window: PolicyReplayWindow;
  maxRecords?: number;
  // Repeating a start with the same key and the same request names the job
  // it already started and starts nothing.
  idempotencyKey: string;
  signal?: AbortSignal;
}>;

export type PolicyReplayStart =
  | Readonly<{ kind: 'started' | 'existing'; job: PolicyReplayJob }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

export type PolicyReplayDeletion =
  | Readonly<{ kind: 'cancelling'; job: PolicyReplayJob }>
  | Readonly<{ kind: 'discarded' }>;

export function isPolicyReplayJobId(value: unknown): value is string {
  return typeof value === 'string' && POLICY_REPLAY_JOB_ID_PATTERN.test(value);
}

// A fresh idempotency key for one start: the same key goes with every retry
// of that start, and a new start gets a new key.
export function newReplayIdempotencyKey(): string {
  const random = new Uint8Array(16);
  crypto.getRandomValues(random);
  return `studio-${Array.from(random, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

export async function startPolicyReplay(
  request: PolicyReplayStartRequest,
): Promise<PolicyReplayStart> {
  const response = await adminFetchJsonResponse<unknown>(adminApiUrl('/policy/replays'), {
    method: 'POST',
    signal: request.signal,
    headers: { 'Content-Type': 'application/json' },
    body: replayRequestBody(request),
    answerStatuses: [422],
  });
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the replay.');
    }
    return { kind: 'refused', refusal };
  }
  const job = projectReplayJob(response.body);
  if (job === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable replay job.');
  }
  return { kind: response.status === 202 ? 'started' : 'existing', job };
}

export async function fetchPolicyReplay(
  jobId: string,
  signal?: AbortSignal,
): Promise<PolicyReplayJob> {
  const response = await adminFetchJsonResponse<unknown>(replayUrl(jobId), {
    signal,
    cache: 'no-store',
  });
  const job = projectReplayJob(response.body);
  if (job === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable replay job.');
  }
  return job;
}

// Cancel a job that has not finished (it stops before its next record), or
// discard one that has, with its result.
export async function deletePolicyReplay(jobId: string): Promise<PolicyReplayDeletion> {
  const response = await adminFetchJsonResponse<unknown>(replayUrl(jobId), {
    method: 'DELETE',
  });
  if (response.status === 204) {
    return { kind: 'discarded' };
  }
  const job = projectReplayJob(response.body);
  if (job === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable replay job.');
  }
  return { kind: 'cancelling', job };
}

function replayUrl(jobId: string): string {
  // The identifier comes from the gateway, but it still names a path
  // segment: refuse anything that is not one before building a URL.
  if (!isPolicyReplayJobId(jobId)) {
    throw new Error('Invalid policy replay job identifier.');
  }
  return adminApiUrl(`/policy/replays/${jobId}`);
}

function replayRequestBody(request: PolicyReplayStartRequest): string {
  const candidate =
    request.candidate.kind === 'active'
      ? '{"source":"active"}'
      : `{"source":"inline","policy":${jsonObjectText(request.candidate.source)}}`;
  const window: Record<string, string> = { from: request.window.from };
  if (request.window.to !== undefined) {
    window.to = request.window.to;
  }
  return [
    '{"schema_version":',
    JSON.stringify(POLICY_REPLAY_SCHEMA_VERSION),
    ',"base_etag":',
    JSON.stringify(request.baseEtag),
    ',"candidate":',
    candidate,
    ',"window":',
    JSON.stringify(window),
    request.maxRecords === undefined ? '' : `,"max_records":${JSON.stringify(request.maxRecords)}`,
    ',"idempotency_key":',
    JSON.stringify(request.idempotencyKey),
    '}',
  ].join('');
}

export function projectReplayJob(body: unknown): PolicyReplayJob | null {
  if (
    !isJsonObject(body) ||
    body.schema_version !== 'policy-replay-job.v1' ||
    !isPolicyReplayJobId(body.job_id) ||
    !isReplayState(body.state) ||
    typeof body.cancel_requested !== 'boolean' ||
    !isBoundedText(body.request_digest, MAX_TEXT_LENGTH) ||
    !isJsonObject(body.base) ||
    !isBoundedText(body.base.etag, MAX_TEXT_LENGTH) ||
    !(body.base.current === undefined || typeof body.base.current === 'boolean') ||
    !isJsonObject(body.candidate) ||
    !isCode(body.candidate.source) ||
    !isBoundedText(body.candidate.etag, MAX_TEXT_LENGTH) ||
    !isJsonObject(body.window) ||
    !isBoundedText(body.window.from, MAX_TEXT_LENGTH) ||
    !isJsonObject(body.cutoff) ||
    !isCount(body.cutoff.selected_records) ||
    !isJsonObject(body.limits) ||
    !isCount(body.limits.max_records) ||
    !isJsonObject(body.progress) ||
    !isCount(body.progress.scanned_records)
  ) {
    return null;
  }
  const failure = isJsonObject(body.failure) && isCode(body.failure.reason)
    ? body.failure.reason
    : null;
  if (body.state === 'failed' && failure === null) {
    return null;
  }
  let result: PolicyReplayResult | null = null;
  if (body.result !== undefined) {
    result = projectReplayResult(body.result);
    if (result === null) {
      return null;
    }
  }
  // Only a finished job with an answer carries a result, and every such job
  // carries one: a completed job without one is unreadable, never an empty
  // answer.
  const answered = body.state === 'completed' || body.state === 'completed_incomplete';
  if (answered !== (result !== null)) {
    return null;
  }
  // A job that read every record and called itself complete is a complete
  // answer; anything else stated as complete is not trusted as one.
  if (result !== null && (body.state === 'completed') !== result.complete) {
    return null;
  }
  return {
    job_id: body.job_id,
    state: body.state,
    cancel_requested: body.cancel_requested,
    created_at: optionalText(body.created_at),
    started_at: optionalText(body.started_at),
    finished_at: optionalText(body.finished_at),
    result_expires_at: optionalText(body.result_expires_at),
    request_digest: body.request_digest,
    base: {
      etag: body.base.etag,
      current: typeof body.base.current === 'boolean' ? body.base.current : null,
    },
    candidate: { source: body.candidate.source, etag: body.candidate.etag },
    window: { from: body.window.from, to: optionalText(body.window.to) },
    selected_records: body.cutoff.selected_records,
    scanned_records: body.progress.scanned_records,
    max_records: body.limits.max_records,
    deadline_ms: isCount(body.limits.deadline_ms) ? body.limits.deadline_ms : null,
    failure,
    result_digest: optionalText(body.result_digest),
    result,
  };
}

function projectReplayResult(value: unknown): PolicyReplayResult | null {
  if (
    !isJsonObject(value) ||
    value.schema_version !== 'policy-replay-results.v1' ||
    value.mode !== 'historical_replay' ||
    typeof value.complete !== 'boolean' ||
    !isJsonObject(value.source) ||
    !isJsonObject(value.source.window) ||
    !isBoundedText(value.source.window.from, MAX_TEXT_LENGTH) ||
    !isCount(value.source.high_water) ||
    !isCount(value.source.max_records) ||
    !isJsonObject(value.records) ||
    !isJsonObject(value.replayed) ||
    !isCount(value.replayed.total)
  ) {
    return null;
  }
  const limitations = boundedCodes(value.limitations);
  const notReplayed = boundedCodes(value.not_replayed);
  const records = projectRecords(value.records);
  const http = projectLane(value.replayed.http);
  const rate = projectRate(value.replayed.rate);
  const tool = projectLane(value.replayed.tool);
  if (
    limitations === null ||
    notReplayed === null ||
    records === null ||
    http === null ||
    rate === null ||
    tool === null ||
    // An incomplete result always says why; a complete one has no limitation.
    value.complete !== (limitations.length === 0)
  ) {
    return null;
  }
  return {
    complete: value.complete,
    limitations,
    window: {
      from: value.source.window.from,
      to: optionalText(value.source.window.to),
    },
    high_water: value.source.high_water,
    max_records: value.source.max_records,
    records,
    replayed: { total: value.replayed.total, http, rate, tool },
    not_replayed: notReplayed,
  };
}

function projectRecords(value: Record<string, unknown>): PolicyReplayRecords | null {
  const members = [
    'selected',
    'scanned',
    'replayable',
    'duplicate',
    'not_policy_evaluated',
    'unsupported',
    'malformed',
    'not_request_record',
    'unreadable',
    'oversized',
  ] as const;
  const counts: Partial<Record<(typeof members)[number], number>> = {};
  for (const member of members) {
    const count = value[member];
    if (!isCount(count)) {
      return null;
    }
    counts[member] = count;
  }
  const byCode = projectCodeCounts(value.by_code);
  if (byCode === null) {
    return null;
  }
  return { ...(counts as Record<(typeof members)[number], number>), by_code: byCode };
}

function projectLane(value: unknown): PolicyReplayLane | null {
  if (
    !isJsonObject(value) ||
    !isCount(value.replayable) ||
    !isCount(value.decided) ||
    !isCount(value.indeterminate) ||
    !isCount(value.refused) ||
    !isCount(value.egress_not_replayed) ||
    !Array.isArray(value.outcomes) ||
    value.outcomes.length > MAX_OUTCOMES
  ) {
    return null;
  }
  const outcomes: PolicyReplayOutcome[] = [];
  for (const entry of value.outcomes) {
    if (
      !isJsonObject(entry) ||
      !isCode(entry.logical) ||
      !isCode(entry.enforcement) ||
      !isCode(entry.effective_action) ||
      !isCode(entry.reason) ||
      !isCount(entry.count)
    ) {
      return null;
    }
    outcomes.push({
      logical: entry.logical,
      enforcement: entry.enforcement,
      effective_action: entry.effective_action,
      reason: entry.reason,
      count: entry.count,
    });
  }
  const limitations = projectCodeCounts(value.limitations);
  const refusals = projectCodeCounts(value.refusals);
  if (limitations === null || refusals === null) {
    return null;
  }
  return {
    replayable: value.replayable,
    decided: value.decided,
    indeterminate: value.indeterminate,
    refused: value.refused,
    outcomes,
    limitations,
    refusals,
    egress_not_replayed: value.egress_not_replayed,
  };
}

function projectRate(value: unknown): PolicyReplayRate | null {
  if (
    !isJsonObject(value) ||
    !isCount(value.no_override) ||
    !isCount(value.override) ||
    !isCount(value.indeterminate) ||
    !isCount(value.refused)
  ) {
    return null;
  }
  const limitations = projectCodeCounts(value.limitations);
  const refusals = projectCodeCounts(value.refusals);
  if (limitations === null || refusals === null) {
    return null;
  }
  return {
    no_override: value.no_override,
    override: value.override,
    indeterminate: value.indeterminate,
    refused: value.refused,
    limitations,
    refusals,
  };
}

function isReplayState(value: unknown): value is PolicyReplayState {
  return (
    value === 'queued' ||
    value === 'running' ||
    value === 'completed' ||
    value === 'completed_incomplete' ||
    value === 'failed' ||
    value === 'cancelled' ||
    value === 'expired'
  );
}

export function isReplayPending(state: PolicyReplayState): boolean {
  return state === 'queued' || state === 'running';
}

function optionalText(value: unknown): string | null {
  return isBoundedText(value, MAX_TEXT_LENGTH) ? value : null;
}
