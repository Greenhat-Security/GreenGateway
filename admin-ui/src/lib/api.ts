import { adminAuthenticationSucceeded, adminAuthorizationFailed, adminIdentityChanged, adminPolicyChanged, getAdminIdentityVersion } from './adminSession';
import { authHeaders, adminRequestCredentials, assertAdminRequestOrigin, clearMemoryToken } from './auth';
import { adminApiUrl } from './config';

const DEFAULT_CSRF_COOKIE_NAME = 'csrf_token';
const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token';
const CONNECTION_COLLECTION_ETAG_HEADER =
  'x-greengateway-connections-etag';
const CONNECTION_SECRET_COLLECTION_ETAG_HEADER =
  'x-greengateway-connection-secrets-etag';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const MAX_COMPOSITE_ORPHANS = 80;
const MAX_REQUEST_ID_BYTES = 256;
const MAX_COMPOSITE_STEP_ID_BYTES = 64;
const MAX_TOOL_NAME_BYTES = 128;
const MAX_TRANSFORM_PROBLEMS = 32;
const MAX_TRANSFORM_PROBLEM_FIELD_BYTES = 1_024;
const MAX_VALIDATION_ERRORS = 64;
const MAX_VALIDATION_ERROR_BYTES = 4_096;
// The fixed reasons the gateway refuses to attest a caller with. A
// compensation refused for one of them sent nothing, and the write it would
// have undone is reported as an orphan with that reason.
const CALLER_ASSERTION_REFUSAL_REASONS: ReadonlySet<string> = new Set([
  'caller_assertion_no_principal',
  'caller_assertion_claim_invalid',
  'caller_assertion_lifetime_invalid',
  'caller_assertion_key_unusable',
  'caller_assertion_key_unavailable',
  'caller_assertion_key_not_published',
  'caller_assertion_header_conflict',
  'caller_assertion_approval_required',
  'caller_assertion_signature_failed',
  'caller_assertion_token_too_long',
  'caller_assertion_not_enforced',
]);

export type AdminValidationProblem = {
  field: string;
  code: string;
};

export type AdminTransformProblem = Readonly<{
  path: string;
  keyword: 'codec';
  reason: string;
}>;

export type AdminCompositeOrphan = Readonly<{
  step: string;
  iteration?: number;
  tool: string;
  certainty: 'confirmed' | 'possible';
  reason: string;
  upstream_status?: number;
}>;

export type AdminApiErrorDetails = Readonly<{
  dependency_count?: number;
  request_id?: string;
  reason?:
    | 'composite_failed'
    | 'composite_failed_compensation_incomplete'
    | 'timeout'
    | 'cancelled'
    | 'lease_lost';
  failed_step?: string;
  failed_iteration?: number;
  compensation?: 'complete' | 'incomplete';
  orphans?: readonly AdminCompositeOrphan[];
  orphans_truncated?: true;
  composite?: 'pending_compensation';
}>;

export type AdminApiErrorCode =
  | 'conflict'
  | 'precondition_failed'
  | 'precondition_required'
  | 'request_failed'
  | string;

export class AdminApiError extends Error {
  readonly status: number;
  readonly code: AdminApiErrorCode;
  readonly problems: readonly AdminValidationProblem[];
  readonly transformProblems: readonly AdminTransformProblem[];
  // The free-text reasons a document write was refused for, from a
  // `{"valid":false,"errors":[...]}` body such as the policy API's.
  readonly validationErrors: readonly string[];
  readonly details: AdminApiErrorDetails;
  readonly etag: string | null;
  readonly collectionEtag: string | null;

  constructor(
    status: number,
    message: string,
    options: {
      code?: AdminApiErrorCode;
      problems?: readonly AdminValidationProblem[];
      transformProblems?: readonly AdminTransformProblem[];
      validationErrors?: readonly string[];
      details?: AdminApiErrorDetails;
      etag?: string | null;
      collectionEtag?: string | null;
    } = {},
  ) {
    super(message);
    this.name = 'AdminApiError';
    this.status = status;
    this.code = options.code ?? errorCodeForStatus(status);
    this.problems = options.problems ?? [];
    this.transformProblems = options.transformProblems ?? [];
    this.validationErrors = options.validationErrors ?? [];
    this.details = options.details ?? {};
    this.etag = options.etag ?? null;
    this.collectionEtag = options.collectionEtag ?? null;
  }
}

export type AdminFetchOptions = Omit<RequestInit, 'headers'> & {
  headers?: HeadersInit;
  // Error statuses that are this endpoint's answer rather than a failure,
  // such as the 400 a validation endpoint returns for an invalid document.
  // Their body is returned like a success's, for the caller to project;
  // 401 and 403 always fail.
  answerStatuses?: readonly number[];
};

export type AdminJsonResponse<T> = {
  body: T;
  headers: Headers;
  status: number;
  etag: string | null;
  collectionEtag: string | null;
};

export type AdminResource<T> = {
  value: T;
  etag: string | null;
  collectionEtag: string | null;
};

export async function adminFetchJson<T>(
  input: string,
  options: AdminFetchOptions = {},
): Promise<T> {
  const response = await adminFetchJsonResponse<T>(input, options);
  return response.body;
}

export async function adminFetchResource<T>(
  input: string,
  options: AdminFetchOptions = {},
): Promise<AdminResource<T>> {
  const response = await adminFetchJsonResponse<T>(input, options);
  return {
    value: response.body,
    etag: response.etag,
    collectionEtag: response.collectionEtag,
  };
}

export async function adminFetchJsonResponse<T>(
  input: string,
  options: AdminFetchOptions = {},
): Promise<AdminJsonResponse<T>> {
  assertAdminRequestOrigin(input);
  const { answerStatuses = [], ...requestOptions } = options;
  const requestIdentity = getAdminIdentityVersion();
  const headers = new Headers({
    Accept: 'application/json',
    ...authHeaders(),
  });
  new Headers(requestOptions.headers).forEach((value, name) => {
    headers.set(name, value);
  });
  addCsrfHeader(headers, requestOptions.method);

  const response = await fetch(input, {
    ...requestOptions,
    credentials: adminRequestCredentials(),
    redirect: 'error',
    headers,
  });
  const body = await parseJsonBody(response);
  if (requestOptions.signal?.aborted) {
    throw new DOMException('Admin request aborted.', 'AbortError');
  }
  if (requestIdentity !== getAdminIdentityVersion()) {
    throw new Error('Admin identity changed while the request was pending.');
  }
  const answered =
    response.status !== 401 &&
    response.status !== 403 &&
    answerStatuses.includes(response.status);
  if (!response.ok && !answered) {
    adminAuthorizationFailed(response.status, requestIdentity, input === adminApiUrl('/capabilities'));
    throw adminApiError(body, response);
  }
  const method = (requestOptions.method ?? 'GET').toUpperCase();
  if (response.ok && !SAFE_METHODS.has(method)) {
    const path = new URL(input, window.location.origin).pathname;
    if (path === adminApiUrl('/auth/logout')) {
      clearMemoryToken();
    } else if (path === adminApiUrl('/auth/callback')) {
      adminIdentityChanged();
    } else if (changesLivePolicy(path)) {
      adminPolicyChanged();
    }
  }

  return {
    body: body as T,
    headers: response.headers,
    status: response.status,
    etag: response.headers.get('etag'),
    collectionEtag: collectionEtag(response.headers),
  };
}

// Whether a successful write to this path can have changed the live policy.
// Previews, validation, conversion, simulations and test runs read only
// their request, and a replay job only reads retained records; saving,
// editing or deleting a draft changes no enforcement, and only a draft's
// publication does.
function changesLivePolicy(path: string): boolean {
  const policyPath = adminApiUrl('/policy');
  if (path !== policyPath && !path.startsWith(`${policyPath}/`)) {
    return false;
  }
  if (
    path.endsWith('/preview') ||
    path.endsWith('/validate') ||
    path.endsWith('/convert') ||
    path === adminApiUrl('/policy/simulations') ||
    path === adminApiUrl('/policy/tests/runs')
  ) {
    return false;
  }
  const replaysPath = adminApiUrl('/policy/replays');
  if (path === replaysPath || path.startsWith(`${replaysPath}/`)) {
    return false;
  }
  const draftsPath = adminApiUrl('/policy/drafts');
  if (path === draftsPath || path.startsWith(`${draftsPath}/`)) {
    return path.endsWith('/publish');
  }
  return true;
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim().length === 0) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function adminApiError(body: unknown, response: Response): AdminApiError {
  return new AdminApiError(response.status, errorMessage(body, response), {
    code: errorCode(body, response.status),
    problems: validationProblems(body),
    transformProblems: transformProblems(body),
    validationErrors: validationErrors(body),
    details: errorDetails(body),
    etag: response.headers.get('etag'),
    collectionEtag: collectionEtag(response.headers),
  });
}

function collectionEtag(headers: Headers): string | null {
  return (
    headers.get(CONNECTION_COLLECTION_ETAG_HEADER) ??
    headers.get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
  );
}

function errorMessage(body: unknown, response: Response): string {
  if (
    isJsonObject(body) &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }

  return response.statusText || `Request failed with status ${response.status}`;
}

function errorCode(body: unknown, status: number): AdminApiErrorCode {
  if (isJsonObject(body)) {
    if (typeof body.code === 'string' && body.code.trim().length > 0) {
      return body.code;
    }
    if (typeof body.reason === 'string' && body.reason.trim().length > 0) {
      return body.reason;
    }
  }

  return errorCodeForStatus(status);
}

function errorCodeForStatus(status: number): AdminApiErrorCode {
  if (status === 409) {
    return 'conflict';
  }
  if (status === 412) {
    return 'precondition_failed';
  }
  if (status === 428) {
    return 'precondition_required';
  }
  return 'request_failed';
}

function validationProblems(body: unknown): AdminValidationProblem[] {
  if (!isJsonObject(body) || !Array.isArray(body.problems)) {
    return [];
  }

  return body.problems.flatMap((problem) => {
    if (
      !isJsonObject(problem) ||
      typeof problem.field !== 'string' ||
      typeof problem.code !== 'string'
    ) {
      return [];
    }
    return [{ field: problem.field, code: problem.code }];
  });
}

function transformProblems(body: unknown): AdminTransformProblem[] {
  if (
    !isJsonObject(body) ||
    !Array.isArray(body.problems) ||
    body.problems.length > MAX_TRANSFORM_PROBLEMS
  ) {
    return [];
  }

  return body.problems.flatMap((problem) => {
    if (
      !isJsonObject(problem) ||
      !isBoundedNonEmptyString(
        problem.path,
        MAX_TRANSFORM_PROBLEM_FIELD_BYTES,
      ) ||
      problem.keyword !== 'codec' ||
      !isBoundedNonEmptyString(
        problem.reason,
        MAX_TRANSFORM_PROBLEM_FIELD_BYTES,
      )
    ) {
      return [];
    }
    return [
      {
        path: problem.path,
        keyword: 'codec' as const,
        reason: problem.reason,
      },
    ];
  });
}

function validationErrors(body: unknown): string[] {
  if (!isJsonObject(body) || !Array.isArray(body.errors)) {
    return [];
  }

  return body.errors
    .filter((error): error is string =>
      isBoundedNonEmptyString(error, MAX_VALIDATION_ERROR_BYTES),
    )
    .slice(0, MAX_VALIDATION_ERRORS);
}

function errorDetails(body: unknown): AdminApiErrorDetails {
  if (!isJsonObject(body)) {
    return {};
  }

  const source = isJsonObject(body.details) ? body.details : body;
  const details: {
    dependency_count?: number;
  } = {};
  const dependencyCount = source.dependency_count;
  if (
    typeof dependencyCount === 'number' &&
    Number.isSafeInteger(dependencyCount) &&
    dependencyCount >= 0
  ) {
    details.dependency_count = dependencyCount;
  }

  return {
    ...details,
    ...compositeErrorDetails(source),
  };
}

function compositeErrorDetails(
  source: Record<string, unknown>,
): AdminApiErrorDetails {
  if (
    source.composite === 'pending_compensation' &&
    isSafeRequestId(source.request_id) &&
    (source.reason === 'timeout' ||
      source.reason === 'cancelled' ||
      source.reason === 'lease_lost')
  ) {
    return {
      request_id: source.request_id,
      reason: source.reason,
      composite: 'pending_compensation',
    };
  }

  if (
    (source.reason !== 'composite_failed' &&
      source.reason !== 'composite_failed_compensation_incomplete') ||
    !isSafeRequestId(source.request_id) ||
    !isCompositeStepId(source.failed_step) ||
    !isOptionalCompositeIteration(source.failed_iteration) ||
    (source.compensation !== 'complete' &&
      source.compensation !== 'incomplete') ||
    !Array.isArray(source.orphans) ||
    source.orphans.length > MAX_COMPOSITE_ORPHANS
  ) {
    return {};
  }

  const orphans: AdminCompositeOrphan[] = [];
  for (const orphan of source.orphans) {
    const projected = projectCompositeOrphan(orphan);
    if (projected === null) {
      return {};
    }
    orphans.push(projected);
  }
  const failedIteration =
    source.failed_iteration === null ? undefined : source.failed_iteration;

  return {
    request_id: source.request_id,
    reason: source.reason,
    failed_step: source.failed_step,
    ...(failedIteration === undefined
      ? {}
      : { failed_iteration: failedIteration }),
    compensation: source.compensation,
    orphans,
    ...(source.orphans_truncated === true ? { orphans_truncated: true } : {}),
  };
}

function projectCompositeOrphan(value: unknown): AdminCompositeOrphan | null {
  if (
    !isJsonObject(value) ||
    !isCompositeStepId(value.step) ||
    !isOptionalCompositeIteration(value.iteration) ||
    !isToolName(value.tool) ||
    (value.certainty !== 'confirmed' && value.certainty !== 'possible') ||
    !isCompositeOrphanReason(value.reason) ||
    (value.upstream_status !== undefined &&
      !isHttpStatus(value.upstream_status))
  ) {
    return null;
  }

  return {
    step: value.step,
    ...(value.iteration === null || value.iteration === undefined
      ? {}
      : { iteration: value.iteration }),
    tool: value.tool,
    certainty: value.certainty,
    reason: value.reason,
    ...(value.upstream_status === undefined
      ? {}
      : { upstream_status: value.upstream_status }),
  };
}

function isSafeRequestId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    utf8Length(value) <= MAX_REQUEST_ID_BYTES &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

function isCompositeStepId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    utf8Length(value) <= MAX_COMPOSITE_STEP_ID_BYTES &&
    /^[A-Za-z][A-Za-z0-9_]*$/.test(value)
  );
}

function isToolName(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    utf8Length(value) <= MAX_TOOL_NAME_BYTES &&
    /^[A-Za-z0-9_.-]+$/.test(value)
  );
}

function isOptionalCompositeIteration(
  value: unknown,
): value is number | null | undefined {
  return (
    value === null ||
    value === undefined ||
    (typeof value === 'number' &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value < 64)
  );
}

function isCompositeOrphanReason(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  if (
    value === 'no_compensation' ||
    value === 'budget_exhausted' ||
    value === 'self_pointer_unresolved' ||
    value === 'compensation_timeout' ||
    value === 'compensation_transport_error' ||
    value === 'tool_disabled' ||
    value === 'http_rule_denied' ||
    value === 'transport_ambiguous' ||
    value === 'timeout_ambiguous' ||
    CALLER_ASSERTION_REFUSAL_REASONS.has(value)
  ) {
    return true;
  }
  const status = /^(?:ambiguous_status|compensation_status):(\d{3})$/.exec(
    value,
  )?.[1];
  return status !== undefined && isHttpStatus(Number(status));
}

function isHttpStatus(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 100 &&
    value <= 599
  );
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function isBoundedNonEmptyString(
  value: unknown,
  maxBytes: number,
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    utf8Length(value) <= maxBytes
  );
}

export function addCsrfHeader(headers: Headers, method: string | undefined): void {
  const normalizedMethod = (method ?? 'GET').toUpperCase();
  if (SAFE_METHODS.has(normalizedMethod) || bearerAuthorizationPresent(headers)) {
    return;
  }

  const cookieName = runtimeMetaValue(
    'greengateway-csrf-cookie-name',
    DEFAULT_CSRF_COOKIE_NAME,
    validCookieName,
  );
  const headerName = runtimeMetaValue(
    'greengateway-csrf-header-name',
    DEFAULT_CSRF_HEADER_NAME,
    validHeaderName,
  );
  const token = readCookie(cookieName);
  if (token !== null && token.length > 0) {
    headers.set(headerName, token);
  }
}

function bearerAuthorizationPresent(headers: Headers): boolean {
  const authorization = headers.get('Authorization')?.trimStart();
  if (!authorization) {
    return false;
  }
  const separator = authorization.search(/\s/);
  return (
    separator > 0 &&
    authorization.slice(0, separator).toLowerCase() === 'bearer' &&
    authorization.slice(separator).trim().length > 0
  );
}

function runtimeMetaValue(
  metaName: string,
  fallback: string,
  validate: (value: string) => boolean,
): string {
  if (typeof document === 'undefined') {
    return fallback;
  }

  const configured = document
    .querySelector<HTMLMetaElement>(`meta[name="${metaName}"]`)
    ?.content.trim();
  return configured && validate(configured) ? configured : fallback;
}

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') {
    return null;
  }

  for (const pair of document.cookie.split(';')) {
    const separator = pair.indexOf('=');
    if (separator < 0 || pair.slice(0, separator).trim() !== name) {
      continue;
    }
    return pair.slice(separator + 1).trim();
  }
  return null;
}

function validCookieName(value: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value);
}

function validHeaderName(value: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function fetchAdminCapabilities(signal?: AbortSignal): Promise<{ permissions: string[] }> {
  const identity = getAdminIdentityVersion();
  const value = await adminFetchJson<unknown>(adminApiUrl('/capabilities'), { signal, cache: 'no-store' });
  if (!isJsonObject(value) || !Array.isArray(value.permissions) || value.permissions.length > 256 ||
      !value.permissions.every((permission): permission is string =>
        typeof permission === 'string' && permission.length <= 128 && /^admin:(?:[a-z_]+:)+[a-z_]+$/.test(permission))) {
    throw new Error('Invalid admin capabilities response.');
  }
  adminAuthenticationSucceeded(identity);
  return { permissions: [...new Set(value.permissions)] };
}
