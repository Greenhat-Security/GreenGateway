import { AdminApiError } from './api';
import { AuditEvent } from './audit';
import { authHeaders } from './auth';

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
  return query.length > 0
    ? `/v1/admin/events/stream?${query}`
    : '/v1/admin/events/stream';
}

export async function subscribeToAuditEvents(
  url: string,
  options: AuditEventStreamOptions,
): Promise<void> {
  const response = await fetch(url, {
    headers: {
      Accept: 'text/event-stream',
      ...authHeaders(),
    },
    signal: options.signal,
  });

  if (!response.ok) {
    const body = await parseJsonBody(response);
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  if (!response.body) {
    throw new Error('Stream response did not include a readable body.');
  }

  options.onOpen?.();

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
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
