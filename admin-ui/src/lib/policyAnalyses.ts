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

// The structural policy analyzer and the suppressions of its findings
// (issue #243). An analysis changes nothing; a suppression changes only how
// a finding is labeled, and only while it binds the analysis exactly.

export const POLICY_ANALYZE_PERMISSION = 'admin:policy:analyze';
export const POLICY_ANALYSIS_SCHEMA_VERSION = 'policy-analysis.v1';
export const POLICY_ANALYSIS_BUSY_REASON = 'policy_analysis_busy';
export const POLICY_ANALYSIS_SUPPRESSIONS_UNAVAILABLE_REASON =
  'policy_analysis_suppressions_unavailable';
export const POLICY_ANALYSIS_SUPPRESSION_EXISTS_REASON = 'policy_analysis_suppression_exists';
export const POLICY_ANALYSIS_SUPPRESSION_ENDED_REASON = 'policy_analysis_suppression_ended';
export const POLICY_ANALYSIS_SUPPRESSION_QUOTA_REASON =
  'policy_analysis_suppression_quota_exceeded';
export const POLICY_ANALYSIS_SUPPRESSION_EXPIRY_REASON =
  'policy_analysis_suppression_expiry_out_of_range';
export const RESOURCE_SNAPSHOT_STALE_REASON = 'resource_snapshot_stale';

// What the gateway allows a reason to be: 1 to this many bytes of text
// without control characters, not only whitespace.
export const MAX_SUPPRESSION_REASON_BYTES = 512;
// The longest a suppression may last, in days.
export const MAX_SUPPRESSION_DAYS = 90;

const MAX_FINDINGS = 1_000;
const MAX_SUPPRESSIONS = 256;
const MAX_TEXT_LENGTH = 4_096;
const MAX_ID_LENGTH = 256;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ETAG_PATTERN = /^"[!#-~]{1,1022}"$/;
const SUPPRESSION_ID_PATTERN = /^pas_[0-9a-f]{32}$/;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

export type AnalysisSeverity = 'high' | 'medium' | 'low';
export type AnalysisProofBasis = 'proven' | 'heuristic' | 'inconclusive';
export type FindingSuppressionState =
  | 'suppressed'
  | 'suppression_expired'
  | 'suppression_mismatched';

export type FindingSuppression = Readonly<{
  state: FindingSuppressionState;
  suppressionId: string;
  // For a mismatched suppression, what it binds differently.
  mismatched: readonly ('policy' | 'resource_snapshot')[];
}>;

export type AnalysisFinding = Readonly<{
  code: string;
  fingerprint: string;
  severity: AnalysisSeverity;
  proofBasis: AnalysisProofBasis;
  pointer: string;
  elementId: string | null;
  rationale: string;
  remediation: string;
  // The access effect of the advisory patch, when there is one.
  patchEffect: string | null;
  suppression: FindingSuppression | null;
}>;

export type AnalysisReport = Readonly<{
  analyzedEtag: string;
  complete: boolean;
  limitations: readonly string[];
  resourceSnapshotDigest: string | null;
  resourceSnapshotComplete: boolean;
  // Whether the deployment's suppressions were read at all. When false,
  // nothing is suppressed and the zero counts mean nothing.
  suppressionsAvailable: boolean;
  counts: Readonly<{
    suppressed: number;
    expired: number;
    mismatched: number;
  }>;
  findings: readonly AnalysisFinding[];
}>;

export type AnalysisAnswer =
  | Readonly<{ kind: 'result'; report: AnalysisReport }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

export type AnalysisSuppressionRecord = Readonly<{
  suppressionId: string;
  etag: string;
  state: 'active' | 'expired' | 'withdrawn';
  fingerprint: string;
  code: string;
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  withdrawnAt: string | null;
}>;

export type AnalysisSuppressionList = Readonly<{
  suppressions: readonly AnalysisSuppressionRecord[];
  maxSuppressions: number;
  maxTtlSeconds: number;
}>;

const SEVERITIES: readonly string[] = ['high', 'medium', 'low'];
const PROOF_BASES: readonly string[] = ['proven', 'heuristic', 'inconclusive'];
const SUPPRESSION_STATES: readonly string[] = [
  'suppressed',
  'suppression_expired',
  'suppression_mismatched',
];
const RECORD_STATES: readonly string[] = ['active', 'expired', 'withdrawn'];

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function isEtag(value: unknown): value is string {
  return typeof value === 'string' && ETAG_PATTERN.test(value);
}

function isSuppressionId(value: unknown): value is string {
  return typeof value === 'string' && SUPPRESSION_ID_PATTERN.test(value);
}

// Whether `reason` is one the gateway accepts, judged as it judges it.
export function isSuppressionReason(reason: string): boolean {
  return (
    reason.trim().length > 0 &&
    new TextEncoder().encode(reason).length <= MAX_SUPPRESSION_REASON_BYTES &&
    !CONTROL_CHARACTER.test(reason)
  );
}

export async function runPolicyAnalysis(request: {
  baseEtag: string;
  candidate: PolicyRunCandidate;
  signal?: AbortSignal;
}): Promise<AnalysisAnswer> {
  const candidate =
    request.candidate.kind === 'active'
      ? '{"source":"active"}'
      : `{"source":"inline","policy":${jsonObjectText(request.candidate.source)}}`;
  const response = await adminFetchJsonResponse<unknown>(adminApiUrl('/policy/analyses'), {
    method: 'POST',
    signal: request.signal,
    headers: { 'Content-Type': 'application/json' },
    body: [
      '{"schema_version":',
      JSON.stringify(POLICY_ANALYSIS_SCHEMA_VERSION),
      ',"base_etag":',
      JSON.stringify(request.baseEtag),
      ',"candidate":',
      candidate,
      ',"format":"json"}',
    ].join(''),
    answerStatuses: [422],
  });
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the analysis.');
    }
    return { kind: 'refused', refusal };
  }
  const report = projectAnalysisReport(response.body);
  if (report === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable analysis.');
  }
  return { kind: 'result', report };
}

function projectSuppression(value: unknown): FindingSuppression | null | undefined {
  if (value === null) {
    return null;
  }
  if (
    !isJsonObject(value) ||
    typeof value.state !== 'string' ||
    !SUPPRESSION_STATES.includes(value.state) ||
    !isSuppressionId(value.suppression_id)
  ) {
    return undefined;
  }
  const mismatched: Array<'policy' | 'resource_snapshot'> = [];
  if (value.mismatched !== undefined) {
    if (!Array.isArray(value.mismatched) || value.mismatched.length > 2) {
      return undefined;
    }
    for (const part of value.mismatched) {
      if (part !== 'policy' && part !== 'resource_snapshot') {
        return undefined;
      }
      mismatched.push(part);
    }
  }
  return {
    state: value.state as FindingSuppressionState,
    suppressionId: value.suppression_id,
    mismatched,
  };
}

function projectFinding(value: unknown): AnalysisFinding | null {
  if (
    !isJsonObject(value) ||
    !isCode(value.code) ||
    !isDigest(value.fingerprint) ||
    typeof value.severity !== 'string' ||
    !SEVERITIES.includes(value.severity) ||
    typeof value.proof_basis !== 'string' ||
    !PROOF_BASES.includes(value.proof_basis) ||
    !isJsonObject(value.element) ||
    !isPointer(value.element.pointer) ||
    !isBoundedText(value.rationale, MAX_TEXT_LENGTH) ||
    !isBoundedText(value.remediation, MAX_TEXT_LENGTH)
  ) {
    return null;
  }
  const suppression = projectSuppression(value.suppression ?? null);
  if (suppression === undefined) {
    return null;
  }
  const elementId = value.element.id;
  const patch = value.patch;
  return {
    code: value.code,
    fingerprint: value.fingerprint,
    severity: value.severity as AnalysisSeverity,
    proofBasis: value.proof_basis as AnalysisProofBasis,
    pointer: value.element.pointer,
    elementId: isBoundedText(elementId, MAX_ID_LENGTH) ? elementId : null,
    rationale: value.rationale,
    remediation: value.remediation,
    patchEffect: isJsonObject(patch) && isCode(patch.access_effect) ? patch.access_effect : null,
    suppression,
  };
}

export function projectAnalysisReport(body: unknown): AnalysisReport | null {
  if (
    !isJsonObject(body) ||
    body.schema_version !== 'policy-analysis-results.v1' ||
    !isJsonObject(body.analyzed) ||
    !isEtag(body.analyzed.etag) ||
    typeof body.complete !== 'boolean' ||
    !isJsonObject(body.resource_snapshot) ||
    typeof body.resource_snapshot.complete !== 'boolean' ||
    !isJsonObject(body.suppressions) ||
    typeof body.suppressions.available !== 'boolean' ||
    !isJsonObject(body.summary) ||
    !isJsonObject(body.summary.by_suppression_state) ||
    !Array.isArray(body.findings) ||
    body.findings.length > MAX_FINDINGS
  ) {
    return null;
  }
  const limitations = boundedCodes(body.limitations);
  const states = body.summary.by_suppression_state;
  if (
    limitations === null ||
    !isCount(states.suppressed) ||
    !isCount(states.suppression_expired) ||
    !isCount(states.suppression_mismatched)
  ) {
    return null;
  }
  const findings: AnalysisFinding[] = [];
  for (const entry of body.findings) {
    const finding = projectFinding(entry);
    if (finding === null) {
      return null;
    }
    findings.push(finding);
  }
  const digest = body.resource_snapshot.digest;
  return {
    analyzedEtag: body.analyzed.etag,
    complete: body.complete,
    limitations,
    resourceSnapshotDigest: isDigest(digest) ? digest : null,
    resourceSnapshotComplete: body.resource_snapshot.complete,
    suppressionsAvailable: body.suppressions.available,
    counts: {
      suppressed: states.suppressed,
      expired: states.suppression_expired,
      mismatched: states.suppression_mismatched,
    },
    findings,
  };
}

function projectRecord(value: unknown): AnalysisSuppressionRecord | null {
  if (
    !isJsonObject(value) ||
    !isSuppressionId(value.suppression_id) ||
    !isEtag(value.etag) ||
    typeof value.state !== 'string' ||
    !RECORD_STATES.includes(value.state) ||
    !isDigest(value.fingerprint) ||
    !isCode(value.code) ||
    !isBoundedText(value.reason, MAX_TEXT_LENGTH) ||
    !isJsonObject(value.created_by) ||
    !isBoundedText(value.created_by.subject, MAX_TEXT_LENGTH) ||
    !isBoundedText(value.created_at, 64) ||
    !isBoundedText(value.expires_at, 64)
  ) {
    return null;
  }
  return {
    suppressionId: value.suppression_id,
    etag: value.etag,
    state: value.state as AnalysisSuppressionRecord['state'],
    fingerprint: value.fingerprint,
    code: value.code,
    reason: value.reason,
    createdBy: value.created_by.subject,
    createdAt: value.created_at,
    expiresAt: value.expires_at,
    withdrawnAt: isBoundedText(value.withdrawn_at, 64) ? value.withdrawn_at : null,
  };
}

export function projectSuppressionList(body: unknown): AnalysisSuppressionList | null {
  if (
    !isJsonObject(body) ||
    !Array.isArray(body.suppressions) ||
    body.suppressions.length > MAX_SUPPRESSIONS ||
    !isJsonObject(body.limits) ||
    !isCount(body.limits.max_suppressions) ||
    !isCount(body.limits.max_ttl_seconds)
  ) {
    return null;
  }
  const suppressions: AnalysisSuppressionRecord[] = [];
  for (const entry of body.suppressions) {
    const record = projectRecord(entry);
    if (record === null) {
      return null;
    }
    suppressions.push(record);
  }
  return {
    suppressions,
    maxSuppressions: body.limits.max_suppressions,
    maxTtlSeconds: body.limits.max_ttl_seconds,
  };
}

export async function fetchAnalysisSuppressions(
  signal?: AbortSignal,
): Promise<AnalysisSuppressionList> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/analyses/suppressions'),
    { signal },
  );
  const list = projectSuppressionList(response.body);
  if (list === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable suppression list.');
  }
  return list;
}

function suppressionAnswer(status: number, body: unknown): AnalysisSuppressionRecord {
  const record = projectRecord(body);
  if (record === null) {
    throw new AdminApiError(status, 'The gateway returned an unreadable suppression.');
  }
  return record;
}

// Suppress one finding of the live policy, bound to the live ETag the
// analysis was pinned to and the resource snapshot it reported. Never
// retried: a lost answer is resolved by analyzing again.
export async function createAnalysisSuppression(request: {
  liveEtag: string;
  fingerprint: string;
  code: string;
  reason: string;
  expiresAt: string;
  resourceSnapshotDigest: string;
}): Promise<AnalysisSuppressionRecord> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/analyses/suppressions'),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'If-Match': request.liveEtag },
      body: JSON.stringify({
        fingerprint: request.fingerprint,
        code: request.code,
        reason: request.reason,
        expires_at: request.expiresAt,
        resource_snapshot_digest: request.resourceSnapshotDigest,
      }),
    },
  );
  return suppressionAnswer(response.status, response.body);
}

// End a suppression now, under the ETag it was listed with.
export async function expireAnalysisSuppression(request: {
  suppressionId: string;
  etag: string;
}): Promise<AnalysisSuppressionRecord> {
  if (!isSuppressionId(request.suppressionId)) {
    throw new Error('Not a suppression identifier.');
  }
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl(`/policy/analyses/suppressions/${request.suppressionId}`),
    { method: 'DELETE', headers: { 'If-Match': request.etag } },
  );
  return suppressionAnswer(response.status, response.body);
}
