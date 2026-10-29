import { AdminApiError, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';
import type { PolicyDocument } from './policy';

// The draft ETag a publication presents. `If-Match` on that request names
// the live policy it is published over, so the draft's own strong ETag
// travels in this header.
const POLICY_DRAFT_ETAG_HEADER = 'X-GreenGateway-Policy-Draft-ETag';
const POLICY_DRAFT_WARNING_HEADER = 'X-GreenGateway-Policy-Draft-Warning';
const POLICY_DRAFT_STATE_NOT_RECORDED_WARNING = 'policy_draft_state_not_recorded';
const POLICY_HISTORY_WARNING_HEADER = 'X-GreenGateway-Policy-History-Warning';
const POLICY_HISTORY_APPEND_FAILED_WARNING = 'policy_history_append_failed';
// The resource snapshot a write was reviewed against, as validation
// reported its digest; the gateway refuses the write once it is stale.
const RESOURCE_SNAPSHOT_HEADER = 'X-GreenGateway-Resource-Snapshot';

// The gateway's stable reasons for refusing a draft request.
export const POLICY_DRAFTS_UNAVAILABLE_REASON = 'policy_drafts_unavailable';
export const POLICY_DRAFT_NOT_FOUND_REASON = 'policy_draft_not_found';
export const POLICY_DRAFT_EXPIRED_REASON = 'policy_draft_expired';
export const POLICY_DRAFT_PUBLISHED_REASON = 'policy_draft_published';
export const POLICY_DRAFT_ETAG_MISMATCH_REASON = 'policy_draft_etag_mismatch';
export const POLICY_DRAFT_BASE_STALE_REASON = 'policy_draft_base_stale';
export const POLICY_ETAG_MISMATCH_REASON = 'policy_etag_mismatch';
export const POLICY_DRAFT_TOO_LARGE_REASON = 'policy_draft_too_large';
export const POLICY_DRAFT_OWNER_QUOTA_REASON = 'policy_draft_owner_quota_exceeded';
export const POLICY_DRAFT_DEPLOYMENT_QUOTA_REASON =
  'policy_draft_deployment_quota_exceeded';
export const RESOURCE_SNAPSHOT_STALE_REASON = 'resource_snapshot_stale';

const POLICY_DRAFT_ID_PATTERN = /^pd_[0-9a-f]{32}$/;
const MAX_ETAG_LENGTH = 256;
const MAX_TIMESTAMP_LENGTH = 64;
const MAX_LISTED_DRAFTS = 256;
const MAX_DIAGNOSTICS = 512;
const MAX_DIAGNOSTIC_TEXT_LENGTH = 4_096;
const MAX_POINTER_LENGTH = 8_192;
const MAX_CONVERSION_CHANGES = 512;
const MAX_UNAVAILABLE_RESOURCES = 32;
const RESOURCE_SNAPSHOT_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export type PolicyDraftState = 'open' | 'published';

export type PolicyDraftSummary = Readonly<{
  draft_id: string;
  revision: number;
  state: PolicyDraftState;
  base_etag: string;
  candidate_etag: string;
  published_etag: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
}>;

// A draft as its owner reads it: the summary, the candidate document and
// the draft's strong ETag, which every write to it must present.
export type PolicyDraft = Readonly<{
  summary: PolicyDraftSummary;
  policy: PolicyDocument;
  etag: string;
}>;

export type PolicyDraftLimits = Readonly<{
  ttl_seconds: number;
  max_drafts_per_owner: number;
  max_drafts: number;
  max_candidate_bytes: number;
}>;

export type PolicyDraftList = Readonly<{
  drafts: readonly PolicyDraftSummary[];
  limits: PolicyDraftLimits;
}>;

export type PolicyDraftPublication = Readonly<{
  policy: PolicyDocument;
  etag: string | null;
  // False when the policy committed but the draft could not be marked
  // published afterwards: it stays open on the base it was published over.
  draftStateRecorded: boolean;
  historyAppendWarning: boolean;
}>;

// An error refuses the document (or, for some codes, only its
// publication); a warning states a limitation; a risk is an exposure the
// publisher should review, which nothing requires acknowledging yet.
export type PolicyDiagnosticSeverity = 'error' | 'warning' | 'risk';

// Which later uses a diagnostic stands in the way of, as the gateway says.
export type PolicyDiagnosticBlocks = Readonly<{
  simulation: boolean;
  tests: boolean;
  publication: boolean;
  evidence: boolean;
}>;

// One structured finding about a policy document. The message and
// remediation are the gateway's own fixed text for the code; the pointer
// is an RFC 6901 JSON Pointer into the document, empty for all of it.
export type PolicyDiagnostic = Readonly<{
  code: string;
  severity: PolicyDiagnosticSeverity;
  pointer: string;
  element_id?: string;
  message: string;
  remediation: string;
  blocks: PolicyDiagnosticBlocks;
}>;

// The resources the cross-resource checks read. Only a complete snapshot
// has a digest, and only a digest can bind a publication to it.
export type PolicyResourceSnapshot = Readonly<{
  digest: string | null;
  complete: boolean;
  unavailable: readonly string[];
}>;

// What `POST /policy/validate` established about one document.
export type PolicyInspection = Readonly<{
  valid: boolean;
  errors: readonly string[];
  schema_version: string | null;
  diagnostics: readonly PolicyDiagnostic[];
  source_digest: string | null;
  semantic_digest: string | null;
  resource_snapshot: PolicyResourceSnapshot | null;
}>;

// One thing the conversion changed, located in the 0.x document (the same
// place in the v1 one), with the gateway's fixed description of it.
export type PolicyConversionChange = Readonly<{
  code: string;
  pointer: string;
  element_id?: string;
  message: string;
}>;

// What `POST /policy/convert` made of a 0.x document. `policy` is set only
// when the conversion succeeded.
export type PolicyConversion = Readonly<{
  converted: boolean;
  errors: readonly string[];
  diagnostics: readonly PolicyDiagnostic[];
  changes: readonly PolicyConversionChange[];
  policy: PolicyDocument | null;
}>;

export function isPolicyDraftId(value: unknown): value is string {
  return typeof value === 'string' && POLICY_DRAFT_ID_PATTERN.test(value);
}

export async function fetchPolicyDrafts(
  signal?: AbortSignal,
): Promise<PolicyDraftList> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/drafts'),
    { signal, cache: 'no-store' },
  );
  return projectDraftList(response.body);
}

export async function fetchPolicyDraft(
  draftId: string,
  signal?: AbortSignal,
): Promise<PolicyDraft> {
  const response = await adminFetchJsonResponse<unknown>(draftUrl(draftId), {
    signal,
    cache: 'no-store',
  });
  return projectDraft(response.body, response.etag);
}

// A new draft pinned to the live policy `policyEtag` names: a copy of it,
// or the candidate `source` when one is given.
export async function createPolicyDraft(
  policyEtag: string,
  source?: string,
): Promise<PolicyDraft> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/drafts'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': policyEtag,
      },
      body: source === undefined ? '{}' : draftRequestBody({ source }),
    },
  );
  return projectDraft(response.body, response.etag);
}

// Replace a draft's candidate, re-pin it to the live policy ETag
// `baseEtag`, or both, under the draft ETag it was read with.
export async function updatePolicyDraft(
  draftId: string,
  draftEtag: string,
  change: { source?: string; baseEtag?: string },
): Promise<PolicyDraft> {
  const response = await adminFetchJsonResponse<unknown>(draftUrl(draftId), {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'If-Match': draftEtag,
    },
    body: draftRequestBody(change),
  });
  return projectDraft(response.body, response.etag);
}

export async function deletePolicyDraft(
  draftId: string,
  draftEtag: string,
): Promise<void> {
  await adminFetchJsonResponse<unknown>(draftUrl(draftId), {
    method: 'DELETE',
    headers: {
      'If-Match': draftEtag,
    },
  });
}

// Make the draft's candidate the live policy. Every precondition is one
// the operator reviewed: the draft revision on screen, the live policy
// revision its changes were compared with, and, when validation reported
// one, the resource snapshot its diagnostics were read from.
export async function publishPolicyDraft(
  draftId: string,
  draftEtag: string,
  policyEtag: string,
  resourceSnapshotDigest: string | null = null,
): Promise<PolicyDraftPublication> {
  const response = await adminFetchJsonResponse<unknown>(
    `${draftUrl(draftId)}/publish`,
    {
      method: 'POST',
      headers: {
        // Every POST carries an allowed media type, even with no body.
        'Content-Type': 'application/json',
        'If-Match': policyEtag,
        [POLICY_DRAFT_ETAG_HEADER]: draftEtag,
        ...(resourceSnapshotDigest === null
          ? {}
          : { [RESOURCE_SNAPSHOT_HEADER]: resourceSnapshotDigest }),
      },
    },
  );
  if (!isJsonObject(response.body)) {
    throw new Error('Invalid policy publication response.');
  }
  return {
    policy: response.body as PolicyDocument,
    etag: response.etag,
    draftStateRecorded:
      response.headers.get(POLICY_DRAFT_WARNING_HEADER) !==
      POLICY_DRAFT_STATE_NOT_RECORDED_WARNING,
    historyAppendWarning:
      response.headers.get(POLICY_HISTORY_WARNING_HEADER) ===
      POLICY_HISTORY_APPEND_FAILED_WARNING,
  };
}

// Inspect the exact text of a candidate. An invalid document is an answer
// (`400` with its diagnostics), not a failure.
export async function validatePolicySource(
  source: string,
  signal?: AbortSignal,
): Promise<PolicyInspection> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/validate'),
    {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
      },
      body: source,
      answerStatuses: [400],
    },
  );
  const inspection = projectInspection(response.body);
  if (inspection === null) {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable validation result.',
    );
  }
  return inspection;
}

// Convert a 0.x document to policy v1 without saving it. A document the
// conversion refuses is an answer with its diagnostics, not a failure.
export async function convertPolicySource(
  source: string,
  signal?: AbortSignal,
): Promise<PolicyConversion> {
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl('/policy/convert'),
    {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
      },
      body: source,
      answerStatuses: [400],
    },
  );
  const body = response.body;
  if (!isJsonObject(body) || typeof body.converted !== 'boolean') {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable conversion result.',
    );
  }
  const diagnostics = projectDiagnostics(body.diagnostics);
  const policy = body.converted && isJsonObject(body.policy)
    ? (body.policy as PolicyDocument)
    : null;
  if (diagnostics === null || (body.converted && policy === null)) {
    throw new AdminApiError(
      response.status,
      'The gateway returned an unreadable conversion result.',
    );
  }
  return {
    converted: body.converted,
    errors: boundedStrings(body.errors),
    diagnostics,
    changes: projectConversionChanges(body.changes),
    policy,
  };
}

function draftUrl(draftId: string): string {
  // The identifier comes from the gateway, but it still names a path
  // segment: refuse anything that is not one before building a URL.
  if (!isPolicyDraftId(draftId)) {
    throw new Error('Invalid policy draft identifier.');
  }
  return adminApiUrl(`/policy/drafts/${draftId}`);
}

// The candidate travels as the exact text the operator wrote, so the
// gateway judges the bytes it stores, including policy v1's exact-source
// rules: a repeated member name is refused instead of silently collapsed.
// The text is spliced into the request only after JSON.parse accepted it as
// one JSON object, so it cannot close the request object early or add a
// member beside `policy`.
function draftRequestBody(change: {
  source?: string;
  baseEtag?: string;
}): string {
  const members: string[] = [];
  if (change.source !== undefined) {
    if (!isJsonObjectText(change.source)) {
      throw new Error('The policy candidate is not a JSON object.');
    }
    members.push(`"policy":${change.source}`);
  }
  if (change.baseEtag !== undefined) {
    members.push(`"base_etag":${JSON.stringify(change.baseEtag)}`);
  }
  return `{${members.join(',')}}`;
}

function isJsonObjectText(source: string): boolean {
  try {
    return isJsonObject(JSON.parse(source) as unknown);
  } catch {
    return false;
  }
}

function projectDraftList(body: unknown): PolicyDraftList {
  if (
    !isJsonObject(body) ||
    !Array.isArray(body.drafts) ||
    body.drafts.length > MAX_LISTED_DRAFTS ||
    !isJsonObject(body.limits)
  ) {
    throw new Error('Invalid policy draft list response.');
  }
  const drafts: PolicyDraftSummary[] = [];
  for (const entry of body.drafts) {
    const summary = projectDraftSummary(entry);
    if (summary === null) {
      throw new Error('Invalid policy draft list response.');
    }
    drafts.push(summary);
  }
  const limits = body.limits;
  if (
    !isNonNegativeInteger(limits.ttl_seconds) ||
    !isNonNegativeInteger(limits.max_drafts_per_owner) ||
    !isNonNegativeInteger(limits.max_drafts) ||
    !isNonNegativeInteger(limits.max_candidate_bytes)
  ) {
    throw new Error('Invalid policy draft list response.');
  }
  return {
    drafts,
    limits: {
      ttl_seconds: limits.ttl_seconds,
      max_drafts_per_owner: limits.max_drafts_per_owner,
      max_drafts: limits.max_drafts,
      max_candidate_bytes: limits.max_candidate_bytes,
    },
  };
}

function projectDraft(body: unknown, etag: string | null): PolicyDraft {
  const summary = projectDraftSummary(body);
  if (
    summary === null ||
    !isJsonObject(body) ||
    !isJsonObject(body.policy) ||
    !isBoundedString(etag, MAX_ETAG_LENGTH)
  ) {
    throw new Error('Invalid policy draft response.');
  }
  return {
    summary,
    policy: body.policy as PolicyDocument,
    etag,
  };
}

function projectDraftSummary(value: unknown): PolicyDraftSummary | null {
  if (
    !isJsonObject(value) ||
    !isPolicyDraftId(value.draft_id) ||
    typeof value.revision !== 'number' ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1 ||
    (value.state !== 'open' && value.state !== 'published') ||
    !isBoundedString(value.base_etag, MAX_ETAG_LENGTH) ||
    !isBoundedString(value.candidate_etag, MAX_ETAG_LENGTH) ||
    !(
      value.published_etag === null ||
      value.published_etag === undefined ||
      isBoundedString(value.published_etag, MAX_ETAG_LENGTH)
    ) ||
    !isBoundedString(value.created_at, MAX_TIMESTAMP_LENGTH) ||
    !isBoundedString(value.updated_at, MAX_TIMESTAMP_LENGTH) ||
    !isBoundedString(value.expires_at, MAX_TIMESTAMP_LENGTH)
  ) {
    return null;
  }
  return {
    draft_id: value.draft_id,
    revision: value.revision,
    state: value.state,
    base_etag: value.base_etag,
    candidate_etag: value.candidate_etag,
    published_etag:
      typeof value.published_etag === 'string' ? value.published_etag : null,
    created_at: value.created_at,
    updated_at: value.updated_at,
    expires_at: value.expires_at,
  };
}

function projectInspection(body: unknown): PolicyInspection | null {
  if (!isJsonObject(body) || typeof body.valid !== 'boolean') {
    return null;
  }
  const diagnostics = projectDiagnostics(body.diagnostics);
  if (diagnostics === null) {
    return null;
  }
  return {
    valid: body.valid,
    errors: boundedStrings(body.errors),
    schema_version: optionalBoundedString(body.schema_version),
    diagnostics,
    source_digest: optionalBoundedString(body.source_digest),
    semantic_digest: optionalBoundedString(body.semantic_digest),
    resource_snapshot: projectResourceSnapshot(body.resource_snapshot),
  };
}

// The parts of a resource snapshot the Studio shows and binds to. A digest
// that is not one is dropped, so it is never sent as a binding.
function projectResourceSnapshot(value: unknown): PolicyResourceSnapshot | null {
  if (!isJsonObject(value) || typeof value.complete !== 'boolean') {
    return null;
  }
  const digest =
    typeof value.digest === 'string' &&
    RESOURCE_SNAPSHOT_DIGEST_PATTERN.test(value.digest)
      ? value.digest
      : null;
  return {
    digest: value.complete ? digest : null,
    complete: value.complete,
    unavailable: boundedStrings(value.unavailable).slice(0, MAX_UNAVAILABLE_RESOURCES),
  };
}

function projectDiagnostics(value: unknown): PolicyDiagnostic[] | null {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTICS) {
    return null;
  }
  const diagnostics: PolicyDiagnostic[] = [];
  for (const entry of value) {
    const diagnostic = projectDiagnostic(entry);
    if (diagnostic === null) {
      return null;
    }
    diagnostics.push(diagnostic);
  }
  return diagnostics;
}

function projectDiagnostic(value: unknown): PolicyDiagnostic | null {
  if (
    !isJsonObject(value) ||
    !isBoundedString(value.code, MAX_DIAGNOSTIC_TEXT_LENGTH) ||
    (value.severity !== 'error' &&
      value.severity !== 'warning' &&
      value.severity !== 'risk') ||
    typeof value.pointer !== 'string' ||
    value.pointer.length > MAX_POINTER_LENGTH ||
    !(
      value.element_id === undefined ||
      isBoundedString(value.element_id, MAX_DIAGNOSTIC_TEXT_LENGTH)
    ) ||
    !isBoundedString(value.message, MAX_DIAGNOSTIC_TEXT_LENGTH) ||
    !isBoundedString(value.remediation, MAX_DIAGNOSTIC_TEXT_LENGTH) ||
    !isJsonObject(value.blocks) ||
    typeof value.blocks.simulation !== 'boolean' ||
    typeof value.blocks.tests !== 'boolean' ||
    typeof value.blocks.publication !== 'boolean' ||
    typeof value.blocks.evidence !== 'boolean'
  ) {
    return null;
  }
  return {
    code: value.code,
    severity: value.severity,
    pointer: value.pointer,
    ...(typeof value.element_id === 'string'
      ? { element_id: value.element_id }
      : {}),
    message: value.message,
    remediation: value.remediation,
    blocks: {
      simulation: value.blocks.simulation,
      tests: value.blocks.tests,
      publication: value.blocks.publication,
      evidence: value.blocks.evidence,
    },
  };
}

function projectConversionChanges(value: unknown): PolicyConversionChange[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.slice(0, MAX_CONVERSION_CHANGES).flatMap((entry) => {
    if (
      !isJsonObject(entry) ||
      !isBoundedString(entry.code, MAX_DIAGNOSTIC_TEXT_LENGTH) ||
      typeof entry.pointer !== 'string' ||
      entry.pointer.length > MAX_POINTER_LENGTH ||
      !isBoundedString(entry.message, MAX_DIAGNOSTIC_TEXT_LENGTH)
    ) {
      return [];
    }
    return [
      {
        code: entry.code,
        pointer: entry.pointer,
        ...(isBoundedString(entry.element_id, MAX_DIAGNOSTIC_TEXT_LENGTH)
          ? { element_id: entry.element_id }
          : {}),
        message: entry.message,
      },
    ];
  });
}

function boundedStrings(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry): entry is string =>
      isBoundedString(entry, MAX_DIAGNOSTIC_TEXT_LENGTH),
    )
    .slice(0, MAX_DIAGNOSTICS);
}

function optionalBoundedString(value: unknown): string | null {
  return isBoundedString(value, MAX_DIAGNOSTIC_TEXT_LENGTH) ? value : null;
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= maxLength
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
