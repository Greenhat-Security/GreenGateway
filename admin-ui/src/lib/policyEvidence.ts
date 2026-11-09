import { adminFetchTextResponse } from './api';
import { adminApiUrl } from './config';
import { isBoundedText, isCode, isJsonObject } from './policyRuns';

export const POLICY_EVIDENCE_READ = 'admin:policy:evidence:read';
const MEDIA_TYPE = 'application/vnd.greengateway.policy-evidence+json';
const HEADER = 'x-greengateway-policy-evidence-';

export type EvidenceCandidate =
  | { publication: { version: number } }
  | { draft: { draft_id: string; draft_etag: string } };

export type EvidenceSections = {
  analysis?: true;
  suite?: Record<string, unknown>;
  simulation?: { cases: readonly Record<string, unknown>[] };
  replay_job_id?: string;
};

export type EvidencePackage = {
  packageBlob: Blob;
  filename: string;
  subject: string;
  completeness: 'complete' | 'incomplete';
  limitations: string[];
  digest: string;
  trustStatement: string;
  markdown: string;
};

export async function fetchPolicyEvidence(
  candidate: EvidenceCandidate,
  sections: EvidenceSections,
  signal: AbortSignal,
): Promise<EvidencePackage> {
  const { body, headers } = await adminFetchTextResponse(adminApiUrl('/policy/evidence'), {
    method: 'POST',
    cache: 'no-store',
    headers: { Accept: MEDIA_TYPE, 'Content-Type': 'application/json' },
    body: JSON.stringify({ schema_version: 'policy-evidence-request.v1', ...candidate, ...sections }),
    signal,
  });
  const invalid = () => new Error('The gateway returned an invalid or mismatched evidence package.');
  const packageBlob = new Blob([body], { type: MEDIA_TYPE });
  if (headers.get('content-type')?.split(';')[0] !== MEDIA_TYPE || packageBlob.size > 4 * 1024 * 1024) {
    throw invalid();
  }
  let value: unknown;
  try {
    value = JSON.parse(body) as unknown;
  } catch {
    throw invalid();
  }
  if (!isJsonObject(value) || value.schema_version !== 'policy-evidence.v1' ||
      !isJsonObject(value.report) || value.report.schema_version !== 'policy-evidence-report.v1' ||
      !Array.isArray(value.manifest) || !isBoundedText(value.report_markdown, 4 * 1024 * 1024)) {
    throw invalid();
  }
  const { report } = value;
  const kind = 'draft' in candidate ? 'draft' : 'publication';
  const completeness = report.completeness;
  const digest = headers.get(HEADER + 'digest');
  if (report.candidate_kind !== kind || headers.get(HEADER + 'candidate-kind') !== kind ||
      (completeness !== 'complete' && completeness !== 'incomplete') ||
      headers.get(HEADER + 'completeness') !== completeness ||
      !Array.isArray(report.limitations) || !report.limitations.every(isCode) ||
      (report.limitations.length === 0) !== (completeness === 'complete') ||
      !isJsonObject(report.trust) || report.trust.signed !== false ||
      !isBoundedText(report.trust.statement, 4096) ||
      !digest || !/^sha256:[0-9a-f]{64}$/.test(digest) ||
      !isJsonObject(value.manifest[0]) || value.manifest[0].name !== 'report' ||
      value.manifest[0].digest !== digest) {
    throw invalid();
  }
  let subject: string;
  if ('draft' in candidate) {
    if (!isJsonObject(report.draft) || report.draft.draft_id !== candidate.draft.draft_id ||
        report.draft.draft_etag !== candidate.draft.draft_etag ||
        typeof report.draft.revision !== 'number' || !Number.isSafeInteger(report.draft.revision) ||
        report.draft.revision < 1) throw invalid();
    subject = `Draft ${candidate.draft.draft_id}, revision ${report.draft.revision}`;
  } else {
    if (!isJsonObject(report.publication) || report.publication.version !== candidate.publication.version) {
      throw invalid();
    }
    subject = `Publication ${candidate.publication.version}`;
  }
  return {
    packageBlob, filename: kind === 'draft' ? 'policy-draft-evidence.json' : 'policy-evidence.json',
    subject, digest, completeness, limitations: report.limitations, trustStatement: report.trust.statement,
    markdown: value.report_markdown,
  };
}
