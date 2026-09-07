import { getAdminIdentityVersion, adminAuthorizationFailed } from './adminSession';
import { AdminApiError } from './api';
import { AuditEvent } from './audit';
import { authHeaders, adminRequestCredentials, assertAdminRequestOrigin } from './auth';
import { adminApiUrl } from './config';

export type AuditEventStreamFilters = {
  eventType: string;
  path: string;
};

export type AuditEventStreamOptions = {
  signal: AbortSignal;
  onOpen?: () => void;
  onEvent: (event: AuditEvent, eventName: string) => void;
};

export function buildAuditEventStreamUrl(
  filters: AuditEventStreamFilters,
): string {
  const params = new URLSearchParams();
  appendTrimmed(params, 'event_type', filters.eventType);
  appendTrimmed(params, 'path', filters.path);

  const query = params.toString();
  return adminApiUrl(
    query.length > 0
      ? `/events/stream?${query}`
      : '/events/stream',
  );
}

export async function subscribeToAuditEvents(
  url: string,
  options: AuditEventStreamOptions,
): Promise<void> {
  assertAdminRequestOrigin(url);
  const identity = getAdminIdentityVersion();
  const response = await fetch(url, {
    credentials: adminRequestCredentials(),
    redirect: 'error',
    headers: {
      Accept: 'text/event-stream',
      ...authHeaders(),
    },
    signal: options.signal,
  });

  const assertCurrent = () => {
    if (options.signal.aborted || identity !== getAdminIdentityVersion()) {
      throw new DOMException('Admin stream session changed.', 'AbortError');
    }
  };
  try { assertCurrent(); } catch (error) {
    await response.body?.cancel();
    throw error;
  }
  if (!response.ok) {
    const body = await parseJsonBody(response);
    assertCurrent();
    adminAuthorizationFailed(response.status, identity, false);
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  if (!response.body) {
    throw new Error('Stream response did not include a readable body.');
  }

  assertCurrent();
  options.onOpen?.();

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      assertCurrent();
      if (done) {
        break;
      }

      buffer = normalizeLineEndings(
        buffer + decoder.decode(value, { stream: true }),
      );
      buffer = drainCompleteFrames(buffer, options.onEvent);
    }

    buffer = normalizeLineEndings(buffer + decoder.decode());
    drainCompleteFrames(buffer, options.onEvent);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function drainCompleteFrames(
  buffer: string,
  onEvent: (event: AuditEvent, eventName: string) => void,
): string {
  let remaining = buffer;
  let frameEnd = remaining.indexOf('\n\n');

  while (frameEnd !== -1) {
    const frame = remaining.slice(0, frameEnd);
    remaining = remaining.slice(frameEnd + 2);
    emitFrame(frame, onEvent);
    frameEnd = remaining.indexOf('\n\n');
  }

  return remaining;
}

function emitFrame(
  frame: string,
  onEvent: (event: AuditEvent, eventName: string) => void,
) {
  let eventName = 'message';
  const dataLines: string[] = [];

  for (const line of frame.split('\n')) {
    if (line.length === 0 || line.startsWith(':')) {
      continue;
    }

    if (line.startsWith('event:')) {
      eventName = sseFieldValue(line, 'event:');
    } else if (line.startsWith('data:')) {
      dataLines.push(sseFieldValue(line, 'data:'));
    }
  }

  if (dataLines.length === 0) {
    return;
  }

  onEvent(JSON.parse(dataLines.join('\n')) as AuditEvent, eventName);
}

function sseFieldValue(line: string, prefix: string): string {
  const value = line.slice(prefix.length);
  return value.startsWith(' ') ? value.slice(1) : value;
}

function normalizeLineEndings(value: string): string {
  return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
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

function appendTrimmed(
  params: URLSearchParams,
  name: string,
  value: string,
) {
  const trimmed = value.trim();
  if (trimmed.length > 0) {
    params.set(name, trimmed);
  }
}
