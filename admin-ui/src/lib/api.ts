import { authHeaders } from './auth';

const DEFAULT_CSRF_COOKIE_NAME = 'csrf_token';
const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token';
const CONNECTION_COLLECTION_ETAG_HEADER =
  'x-greengateway-connections-etag';
const CONNECTION_SECRET_COLLECTION_ETAG_HEADER =
  'x-greengateway-connection-secrets-etag';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export type AdminValidationProblem = {
  field: string;
  code: string;
};

export type AdminApiErrorDetails = Readonly<{
  dependency_count?: number;
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
  readonly details: AdminApiErrorDetails;
  readonly etag: string | null;
  readonly collectionEtag: string | null;

  constructor(
    status: number,
    message: string,
    options: {
      code?: AdminApiErrorCode;
      problems?: readonly AdminValidationProblem[];
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
    this.details = options.details ?? {};
    this.etag = options.etag ?? null;
    this.collectionEtag = options.collectionEtag ?? null;
  }
}

export type AdminFetchOptions = Omit<RequestInit, 'headers'> & {
  headers?: HeadersInit;
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
  const headers = new Headers({
    Accept: 'application/json',
    ...authHeaders(),
  });
  new Headers(options.headers).forEach((value, name) => {
    headers.set(name, value);
  });
  addCsrfHeader(headers, options.method);

  const response = await fetch(input, {
    ...options,
    credentials: options.credentials ?? 'same-origin',
    headers,
  });
  const body = await parseJsonBody(response);

  if (!response.ok) {
    throw adminApiError(body, response);
  }

  return {
    body: body as T,
    headers: response.headers,
    status: response.status,
    etag: response.headers.get('etag'),
    collectionEtag: collectionEtag(response.headers),
  };
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

function errorDetails(body: unknown): AdminApiErrorDetails {
  if (!isJsonObject(body)) {
    return {};
  }

  const source = isJsonObject(body.details) ? body.details : body;
  const dependencyCount = source.dependency_count;
  if (
    typeof dependencyCount === 'number' &&
    Number.isSafeInteger(dependencyCount) &&
    dependencyCount >= 0
  ) {
    return { dependency_count: dependencyCount };
  }

  return {};
}

function addCsrfHeader(headers: Headers, method: string | undefined): void {
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
