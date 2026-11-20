// The stored policy test suite: the one `policy-tests.v1` document kept
// beside the policy at `/v1{ADMIN_PREFIX}/policy/tests`, versioned, named by
// a strong ETag that is its semantic digest. Reading it needs
// admin:policy:read and admin:policy:simulate; storing one needs
// admin:policy:write. Storing a suite changes no enforcement; where the
// gateway requires the stored suite (POLICY_TESTS_REQUIRED), it is what
// every later policy publication must pass.

import { AdminApiError, adminFetchJsonResponse, type AdminJsonResponse } from './api';
import { adminApiUrl } from './config';
import {
  isJsonObject,
  jsonObjectText,
  projectRunRefusal,
  type PolicyRunRefusal,
} from './policyRuns';

export const POLICY_TESTS_NOT_FOUND_REASON = 'policy_tests_not_found';
export const POLICY_TESTS_ETAG_MISMATCH_REASON = 'policy_tests_etag_mismatch';
export const POLICY_TESTS_EXIST_REASON = 'policy_tests_exist';
export const POLICY_TESTS_UNAVAILABLE_REASON = 'policy_tests_unavailable';
// A publication refused because the stored suite the gateway requires did
// not pass against it; `required_tests` says how.
export const POLICY_TESTS_REQUIRED_FAILED_REASON = 'policy_tests_required_failed';

const SCHEMA_VERSION = 'policy-tests.v1';
const VERSION_HEADER = 'X-GreenGateway-Policy-Tests-Version';
const ACTIVE_STATUS_HEADER = 'X-GreenGateway-Policy-Tests-Active-Status';
const STRONG_ETAG = /^"[!#-~]{1,1022}"$/;
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_KINDS = 16;

export type StoredPolicyTests = Readonly<{
  kind: 'stored';
  // The stored document, formatted for the editors. Sent back unchanged it
  // stores the same ETag again.
  source: string;
  etag: string;
  version: number;
}>;

export type StoredPolicyTestsRead = StoredPolicyTests | Readonly<{ kind: 'none' }>;

// Exactly one precondition: the first suite, or a replacement of the
// stored version named by its ETag.
export type PolicyTestsPrecondition =
  | Readonly<{ kind: 'first' }>
  | Readonly<{ kind: 'replace'; etag: string }>;

export type PolicyTestsStoreAnswer =
  | Readonly<{
      kind: 'stored';
      stored: StoredPolicyTests;
      created: boolean;
      // What the activation gate would answer for the active policy under
      // the suite just stored, when the gateway requires one; null otherwise.
      activeStatus: string | null;
    }>
  | Readonly<{ kind: 'refused'; refusal: PolicyRunRefusal }>;

// Read the stored suite. No suite stored is an answer; no policy configured
// (a plain 404), a store that cannot be read (503) and anything else fail.
export async function fetchStoredPolicyTests(signal?: AbortSignal): Promise<StoredPolicyTestsRead> {
  let response: AdminJsonResponse<unknown>;
  try {
    response = await adminFetchJsonResponse<unknown>(adminApiUrl('/policy/tests'), {
      signal,
      cache: 'no-store',
    });
  } catch (error) {
    if (
      error instanceof AdminApiError &&
      error.status === 404 &&
      error.code === POLICY_TESTS_NOT_FOUND_REASON
    ) {
      return { kind: 'none' };
    }
    throw error;
  }
  const stored = projectStored(response);
  if (stored === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable stored suite.');
  }
  return stored;
}

// Store `source` as the stored suite, exactly as written, under exactly one
// precondition. A suite the gateway finds invalid (`422`) is an answer with
// its diagnostics, and nothing was stored. Never retried: an answer that
// did not arrive is resolved by reading the stored suite again.
export async function storePolicyTests(request: {
  source: string;
  precondition: PolicyTestsPrecondition;
  signal?: AbortSignal;
}): Promise<PolicyTestsStoreAnswer> {
  const response = await adminFetchJsonResponse<unknown>(adminApiUrl('/policy/tests'), {
    method: 'PUT',
    signal: request.signal,
    headers: policyTestsWriteHeaders(request.precondition),
    body: jsonObjectText(request.source),
    answerStatuses: [422],
  });
  if (response.status === 422) {
    const refusal = projectRunRefusal(response.body);
    if (refusal === null) {
      throw new AdminApiError(422, 'The gateway refused the policy test suite.');
    }
    return { kind: 'refused', refusal };
  }
  const stored = projectStored(response);
  if (stored === null) {
    throw new AdminApiError(response.status, 'The gateway returned an unreadable stored suite.');
  }
  const activeStatus = response.headers.get(ACTIVE_STATUS_HEADER);
  return {
    kind: 'stored',
    stored,
    created: response.status === 201,
    activeStatus: activeStatus !== null && CODE.test(activeStatus) ? activeStatus : null,
  };
}

// The headers of a suite write, built in one place.
function policyTestsWriteHeaders(precondition: PolicyTestsPrecondition): HeadersInit {
  return {
    'Content-Type': 'application/json',
    ...(precondition.kind === 'first'
      ? { 'If-None-Match': '*' }
      : { 'If-Match': precondition.etag }),
  };
}

function projectStored(response: AdminJsonResponse<unknown>): StoredPolicyTests | null {
  const { body, etag } = response;
  const version = Number(response.headers.get(VERSION_HEADER) ?? '');
  if (
    !isJsonObject(body) ||
    body.schema_version !== SCHEMA_VERSION ||
    !Array.isArray(body.cases) ||
    etag === null ||
    !STRONG_ETAG.test(etag) ||
    !Number.isSafeInteger(version) ||
    version < 1
  ) {
    return null;
  }
  return { kind: 'stored', source: JSON.stringify(body, null, 2), etag, version };
}

// Whether two suite texts are the same suite: equal once parsed, whatever
// the member order and whitespace, as the gateway's digest judges them. Case
// order counts. Used only to tell what an unconfirmed save did; the ETag is
// the authority for everything else.
export function sameSuite(left: string, right: string): boolean {
  const a = parse(left);
  const b = parse(right);
  return a !== undefined && b !== undefined && canonical(a) === canonical(b);
}

export type SuiteCaseCounts = Readonly<{
  total: number;
  byKind: ReadonlyArray<Readonly<{ kind: string; count: number }>>;
}>;

// How many cases a suite holds, by kind, for a confirmation that compares
// two suites. Null for text that is not a suite object.
export function suiteCaseCounts(source: string): SuiteCaseCounts | null {
  const value = parse(source);
  if (!isJsonObject(value) || !Array.isArray(value.cases)) {
    return null;
  }
  const counts = new Map<string, number>();
  for (const entry of value.cases) {
    const kind =
      isJsonObject(entry) && typeof entry.kind === 'string' && CODE.test(entry.kind)
        ? entry.kind
        : 'unknown';
    const key = counts.has(kind) || counts.size < MAX_KINDS ? kind : 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return {
    total: value.cases.length,
    byKind: [...counts.entries()]
      .map(([kind, count]) => ({ kind, count }))
      .sort((left, right) => left.kind.localeCompare(right.kind)),
  };
}

function parse(source: string): unknown {
  try {
    return JSON.parse(source) as unknown;
  } catch {
    return undefined;
  }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`;
  }
  if (isJsonObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
