import { authHeaders } from './auth';

export class AdminApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'AdminApiError';
    this.status = status;
  }
}

export type AdminFetchOptions = Omit<RequestInit, 'headers'> & {
  headers?: Record<string, string>;
};

export type AdminJsonResponse<T> = {
  body: T;
  headers: Headers;
  status: number;
};

export async function adminFetchJson<T>(
  input: string,
  options: AdminFetchOptions = {},
): Promise<T> {
  const response = await adminFetchJsonResponse<T>(input, options);
  return response.body;
}

export async function adminFetchJsonResponse<T>(
  input: string,
  options: AdminFetchOptions = {},
): Promise<AdminJsonResponse<T>> {
  const headers = {
    Accept: 'application/json',
    ...authHeaders(),
    ...options.headers,
  };
  const response = await fetch(input, { ...options, headers });
  const body = await parseJsonBody(response);

  if (!response.ok) {
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  return {
    body: body as T,
    headers: response.headers,
    status: response.status,
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

function errorMessage(body: unknown, response: Response): string {
  if (
    body &&
    typeof body === 'object' &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }

  if (typeof body === 'string' && body.trim().length > 0) {
    return body;
  }

  return response.statusText || `Request failed with status ${response.status}`;
}
