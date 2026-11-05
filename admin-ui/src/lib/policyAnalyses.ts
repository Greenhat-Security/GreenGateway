import { AdminApiError, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';
import {
  boundedCodes,
  draftCandidateJson,
  isBoundedText,
  isCode,
  isCount,
  isJsonObject,
  isPointer,
  jsonObjectText,
  projectRunRefusal,
  type PolicyDraftRunCandidate,
  type PolicyRunCandidate,
  type PolicyRunRefusal,
} from './policyRuns';

// The conservative structural analyzer (`POST /policy/analyses`) and the
// suppressions of its findings (issue #243). It reads one policy and reports
// only what it can prove; an analysis changes nothing, a patch it proposes is
// returned, never applied, and a suppression changes only how a finding is
// labeled, and only while it binds the analysis exactly.
export const POLICY_ANALYSIS_SCHEMA_VERSION = 'policy-analysis.v1';
export const POLICY_ANALYZE_PERMISSION = 'admin:policy:analyze';
export const POLICY_ANALYSIS_BASE_STALE_REASON = 'policy_analysis_base_stale';
export const POLICY_ANALYSIS_BUSY_REASON = 'policy_analysis_busy';

const RESULT_SCHEMA_VERSION = 'policy-analysis-results.v1';
const MAX_FINDINGS = 1_000;
const MAX_TEXT_LENGTH = 4_096;
const MAX_ID_LENGTH = 256;
const MAX_DIGEST_LENGTH = 256;
const MAX_LANES = 16;

export type PolicyAnalysisSeverity = 'high' | 'medium' | 'low';

// An element a finding is about, by section, pointer and, where it has
// them, position and stable id; a finding never repeats a policy value.
export type PolicyAnalysisElement = Readonly<{
  section: string;
  pointer: string;
  position: number | null;
  id: string | null;
}>;

export type PolicyAnalysisFinding = Readonly<{
  code: string;
  severity: PolicyAnalysisSeverity;
  proof_basis: string;
  element: PolicyAnalysisElement;
  related: PolicyAnalysisElement | null;
  never_decides_in: readonly string[];
  may_decide_in: readonly string[];
  rationale: string;
  remediation: string;
  // The advisory patch's judged effect on access, when there is a patch.
  access_effect: string | null;
}>;

export type PolicyAnalysisResult = Readonly<{
  analyzer_version: string | null;
  analyzed: Readonly<{
    source: string;
    etag: string;
    draft_id: string | null;
    draft_revision: number | null;
  }>;
  // False when the analysis stopped at a bound `limitations` names; it then
  // says nothing about the elements it did not reach.
  complete: boolean;
  limitations: readonly string[];
  findings: readonly PolicyAnalysisFinding[];
}>;

export type PolicyAnalysisAnswer =
  | Readonly<{ kind: 'result'; result: PolicyAnalysisResult }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

export type PolicyAnalysisRequest = Readonly<{
  baseEtag: string;
  candidate: PolicyRunCandidate | PolicyDraftRunCandidate;
  signal?: AbortSignal;
}>;

// Analyze the live policy or a candidate, pinned to the live ETag the
// request was written against (`412` when it is no longer live). A refusal
// with structured detail (`422`) is an answer, every other failure an error.
export async function runPolicyAnalysis(
  request: PolicyAnalysisRequest,
): Promise<PolicyAnalysisAnswer> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/analyses'),
    {
      method: 'POST',
      signal: request.signal,
      headers: { 'Content-Type': 'application/json' },
      body: analysisRequestBody(request),
      answerStatuses: [422],
    },
  );
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the analysis.');
    }
    return { kind: 'refused', refusal };
  }
  const result = projectAnalysisResult(response.body);
  if (result === null) {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable analysis result.',
    );
  }
  return { kind: 'result', result };
}

function analysisRequestBody(request: PolicyAnalysisRequest): string {
  const candidate =
    request.candidate.kind === 'active'
      ? '{"source":"active"}'
      : request.candidate.kind === 'draft'
        ? draftCandidateJson(request.candidate)
        : `{"source":"inline","policy":${jsonObjectText(request.candidate.source)}}`;
  return [
    '{"schema_version":',
    JSON.stringify(POLICY_ANALYSIS_SCHEMA_VERSION),
    ',"base_etag":',
    JSON.stringify(request.baseEtag),
    ',"candidate":',
    candidate,
    ',"format":"json"}',
  ].join('');
}

export function projectAnalysisResult(body: unknown): PolicyAnalysisResult | null {
  if (
    !isJsonObject(body) ||
    body.schema_version !== RESULT_SCHEMA_VERSION ||
    body.mode !== 'structural' ||
    typeof body.complete !== 'boolean' ||
    !isJsonObject(body.analyzed) ||
    !isCode(body.analyzed.source) ||
    !isBoundedText(body.analyzed.etag, MAX_DIGEST_LENGTH) ||
    !Array.isArray(body.findings) ||
    body.findings.length > MAX_FINDINGS
  ) {
    return null;
  }
  const limitations = boundedCodes(body.limitations);
  if (limitations === null) {
    return null;
  }
  const findings: PolicyAnalysisFinding[] = [];
  for (const entry of body.findings) {
    const finding = projectFinding(entry);
    if (finding === null) {
      return null;
    }
    findings.push(finding);
  }
  const analyzed = body.analyzed;
  const analyzer = isJsonObject(body.analyzer) ? body.analyzer : {};
  return {
    analyzer_version: isBoundedText(analyzer.version, MAX_ID_LENGTH) ? analyzer.version : null,
    analyzed: {
      source: analyzed.source as string,
      etag: analyzed.etag as string,
      draft_id: isBoundedText(analyzed.draft_id, MAX_ID_LENGTH) ? analyzed.draft_id : null,
      draft_revision: isCount(analyzed.draft_revision) ? analyzed.draft_revision : null,
    },
    complete: body.complete,
    limitations,
    findings,
  };
}

function projectFinding(value: unknown): PolicyAnalysisFinding | null {
  if (
    !isJsonObject(value) ||
    !isCode(value.code) ||
    (value.severity !== 'high' && value.severity !== 'medium' && value.severity !== 'low') ||
    !isCode(value.proof_basis) ||
    !isBoundedText(value.rationale, MAX_TEXT_LENGTH) ||
    !isBoundedText(value.remediation, MAX_TEXT_LENGTH)
  ) {
    return null;
  }
  const element = projectElement(value.element);
  const related = value.related === undefined ? null : projectElement(value.related);
  const neverDecidesIn = boundedCodes(value.never_decides_in ?? [], MAX_LANES);
  const mayDecideIn = boundedCodes(value.may_decide_in ?? [], MAX_LANES);
  if (
    element === null ||
    (value.related !== undefined && related === null) ||
    neverDecidesIn === null ||
    mayDecideIn === null
  ) {
    return null;
  }
  const patch = isJsonObject(value.patch) ? value.patch : null;
  return {
    code: value.code,
    severity: value.severity,
    proof_basis: value.proof_basis,
    element,
    related,
    never_decides_in: neverDecidesIn,
    may_decide_in: mayDecideIn,
    rationale: value.rationale,
    remediation: value.remediation,
    access_effect: patch !== null && isCode(patch.access_effect) ? patch.access_effect : null,
  };
}

function projectElement(value: unknown): PolicyAnalysisElement | null {
  if (!isJsonObject(value) || !isCode(value.section) || !isPointer(value.pointer)) {
    return null;
  }
  return {
    section: value.section,
    pointer: value.pointer,
    position: isCount(value.position) ? value.position : null,
    id: isBoundedText(value.id, MAX_ID_LENGTH) ? value.id : null,
  };
}

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

const MAX_SUPPRESSIONS = 256;
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

// The same analysis as `runPolicyAnalysis`, read as the suppression-aware
// report the workbench lists: each finding's fingerprint and suppression
// state, the resource snapshot the analysis read, and whether the
// deployment's suppressions were consulted at all.
export async function runPolicyAnalysisReport(
  request: PolicyAnalysisRequest,
): Promise<AnalysisAnswer> {
  const response = await adminFetchJsonResponse<unknown>(adminApiUrl('/policy/analyses'), {
    method: 'POST',
    signal: request.signal,
    headers: { 'Content-Type': 'application/json' },
    body: analysisRequestBody(request),
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

function projectReportFinding(value: unknown): AnalysisFinding | null {
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
    body.schema_version !== RESULT_SCHEMA_VERSION ||
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
    const finding = projectReportFinding(entry);
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
