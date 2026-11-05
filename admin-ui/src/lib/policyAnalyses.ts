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

// The conservative structural analyzer (`POST /policy/analyses`). It reads
// one policy and reports only what it can prove; an analysis changes
// nothing, and a patch it proposes is returned, never applied.
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
