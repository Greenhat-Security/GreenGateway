import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import { AuditEvent } from '../lib/audit';
import type { PolicyDocument } from '../lib/policy';
import {
  LIVE_TAIL_EVENT_LIMIT,
  LIVE_TAIL_RECONNECT_DELAY_MS,
  LiveTail,
} from './LiveTail';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('LiveTail', () => {
  it('renders incoming events as split SSE chunks arrive', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();

    const first = auditEvent({
      event_id: 'first',
      event_type: 'audit.first',
      request_id: 'req-first',
    });
    const second = auditEvent({
      event_id: 'second',
      event_type: 'audit.second',
      request_id: 'req-second',
    });
    const third = auditEvent({
      event_id: 'third',
      event_type: 'audit.third',
      request_id: 'req-third',
    });
    const firstFrame = sseFrame(first);

    act(() => {
      stream.calls[0].enqueue(firstFrame.slice(0, 23));
    });
    expect(screen.queryByText('audit.first')).toBeNull();

    act(() => {
      stream.calls[0].enqueue(
        `${firstFrame.slice(23)}${sseFrame(second)}${sseFrame(third)}`,
      );
    });

    expect(await screen.findByText('audit.first')).toBeTruthy();
    expect(await screen.findByText('audit.second')).toBeTruthy();
    expect(await screen.findByText('audit.third')).toBeTruthy();
    expect(screen.getByText('3 events')).toBeTruthy();
  });

  it('navigates to a richly prefilled rule editor from an audit event row', async () => {
    const stream = sseFetchMock({
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', stream.fetch);
    const event = auditEvent({
      event_id: 'rich-event',
      request_id: 'rich-event',
      actor: {
        user_id: 'alice',
        roles: ['support', 'admin'],
        auth_mode: 'bearer_token',
      },
      payload: {
        method: 'POST',
        path: '/admin/users',
        status: 403,
      },
    });

    renderLiveTail({ token: jwtWithRoles(['writer']) });

    expect(await screen.findByText('Connected')).toBeTruthy();
    act(() => {
      stream.calls[0].enqueue(sseFrame(event));
    });

    expect(await screen.findByText('rich-event')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule from POST /admin/users',
    }) as HTMLButtonElement;
    await waitFor(() => expect(createRuleButton.disabled).toBe(false));

    fireEvent.click(createRuleButton);

    expect(screen.getByTestId('location').textContent).toBe(
      '/policy/rules/editor?prefill_method=POST&prefill_path=%2Fadmin%2Fusers&prefill_role=support&prefill_auth_method=bearer_token&prefill_principal_id=alice',
    );
  });

  it('creates a method-and-path-only prefill link when an audit event has no actor', async () => {
    const stream = sseFetchMock({
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', stream.fetch);
    const event = auditEvent({
      event_id: 'anonymous-event',
      request_id: 'anonymous-event',
      actor: null,
      payload: {
        method: 'GET',
        path: '/public/status',
        status: 200,
      },
    });

    renderLiveTail({ token: jwtWithRoles(['writer']) });

    expect(await screen.findByText('Connected')).toBeTruthy();
    act(() => {
      stream.calls[0].enqueue(sseFrame(event));
    });

    expect(await screen.findByText('anonymous-event')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule from GET /public/status',
    }) as HTMLButtonElement;
    await waitFor(() => expect(createRuleButton.disabled).toBe(false));

    fireEvent.click(createRuleButton);

    expect(screen.getByTestId('location').textContent).toBe(
      '/policy/rules/editor?prefill_method=GET&prefill_path=%2Fpublic%2Fstatus',
    );
  });

  it('disables audit-event rule creation for a read-only policy principal', async () => {
    const stream = sseFetchMock({
      policy: policyDocument({
        roles: {
          reader: { permissions: ['admin:policy:read'] },
        },
      }),
    });
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('Connected')).toBeTruthy();
    act(() => {
      stream.calls[0].enqueue(
        sseFrame(
          auditEvent({
            payload: {
              method: 'GET',
              path: '/readonly',
              status: 200,
            },
          }),
        ),
      );
    });

    const createRuleButton = (await screen.findByRole('button', {
      name: 'Create rule from GET /readonly',
    })) as HTMLButtonElement;

    expect(createRuleButton.disabled).toBe(true);
    expect(createRuleButton.getAttribute('title')).toBe(
      'Requires admin:policy:write',
    );
  });

  it('aborts the previous stream and reconnects when filters change', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();
    const firstCall = stream.calls[0];

    fireEvent.change(screen.getByLabelText('Event type'), {
      target: { value: 'auth.success' },
    });

    await waitFor(() => expect(stream.calls).toHaveLength(2));
    expect(firstCall.aborted).toBe(true);

    const secondCall = stream.calls[1];
    fireEvent.change(screen.getByLabelText('Path'), {
      target: { value: '/admin' },
    });

    await waitFor(() => expect(stream.calls).toHaveLength(3));
    expect(secondCall.aborted).toBe(true);

    const nextUrl = new URL(stream.calls[2].url, 'http://localhost');
    expect(nextUrl.pathname).toBe('/v1/admin/events/stream');
    expect(nextUrl.searchParams.get('event_type')).toBe('auth.success');
    expect(nextUrl.searchParams.get('path')).toBe('/admin');
  });

  it('drops incoming events while paused and appends again after resume', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();

    act(() => {
      stream.calls[0].enqueue(
        sseFrame(
          auditEvent({
            event_id: 'before-pause',
            event_type: 'audit.before_pause',
          }),
        ),
      );
    });
    expect(await screen.findByText('audit.before_pause')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    expect(await screen.findByText('Paused')).toBeTruthy();

    act(() => {
      stream.calls[0].enqueue(
        sseFrame(
          auditEvent({
            event_id: 'during-pause',
            event_type: 'audit.during_pause',
          }),
        ),
      );
    });
    await flushStreamWork();

    expect(screen.queryByText('audit.during_pause')).toBeNull();
    expect(screen.getByText('1 events')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Resume' }));

    act(() => {
      stream.calls[0].enqueue(
        sseFrame(
          auditEvent({
            event_id: 'after-resume',
            event_type: 'audit.after_resume',
          }),
        ),
      );
    });

    expect(await screen.findByText('audit.after_resume')).toBeTruthy();
    expect(screen.getByText('2 events')).toBeTruthy();
  });

  it.each([
    {
      status: 401,
      body: { error: 'unauthorized' },
      text: 'Bearer token required',
    },
    {
      status: 403,
      body: { error: 'forbidden' },
      text: 'Admin role required',
    },
  ])(
    'renders a distinct $status initial connection error',
    async ({ status, body, text }) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(jsonResponse(status, body)),
      );

      renderLiveTail();

      expect(await screen.findByText(text)).toBeTruthy();
      expect(screen.getByText('Disconnected')).toBeTruthy();
    },
  );

  it('reconnects after an established stream drops', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();

    act(() => {
      stream.calls[0].enqueue(
        sseFrame(
          auditEvent({
            event_id: 'before-drop',
            event_type: 'audit.before_drop',
          }),
        ),
      );
    });
    expect(await screen.findByText('audit.before_drop')).toBeTruthy();

    vi.useFakeTimers();
    act(() => {
      stream.calls[0].error(new Error('socket closed'));
    });
    await flushStreamWork();

    expect(screen.getByText('Reconnecting')).toBeTruthy();
    expect(screen.getByText('Stream disconnected')).toBeTruthy();

    await act(async () => {
      vi.advanceTimersByTime(LIVE_TAIL_RECONNECT_DELAY_MS);
    });
    await flushStreamWork();

    expect(stream.calls).toHaveLength(2);
    expect(screen.getByText('Connected')).toBeTruthy();
  });

  it('keeps only the most recent retained events', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();

    const frames = Array.from({ length: LIVE_TAIL_EVENT_LIMIT + 3 }, (_, i) =>
      sseFrame(
        auditEvent({
          event_id: `cap-${i}`,
          event_type: `audit.cap.${i}`,
        }),
      ),
    ).join('');

    act(() => {
      stream.calls[0].enqueue(frames);
    });

    expect(
      await screen.findByText(`audit.cap.${LIVE_TAIL_EVENT_LIMIT + 2}`),
    ).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByText(`${LIVE_TAIL_EVENT_LIMIT} events`)).toBeTruthy(),
    );
    expect(screen.queryByText('audit.cap.0')).toBeNull();
    expect(screen.queryByText('audit.cap.1')).toBeNull();
    expect(screen.queryByText('audit.cap.2')).toBeNull();
  });

  it('expands a row to reveal the complete event JSON', async () => {
    const stream = sseFetchMock();
    vi.stubGlobal('fetch', stream.fetch);
    const event = auditEvent({
      event_id: 'event-1',
      actor: {
        user_id: 'alice',
        roles: ['admin', 'operator'],
        auth_mode: 'bearer_token',
      },
      payload: {
        path: '/admin',
        status: 201,
        method: 'POST',
        latency_ms: 12,
      },
      schema_version: '0.1.0',
      user_agent: 'curl/8.8.0',
    });

    renderLiveTail();

    expect(await screen.findByText('Connected')).toBeTruthy();
    act(() => {
      stream.calls[0].enqueue(sseFrame(event));
    });

    expect(await screen.findByText('http.request_observed')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Expand event event-1' }),
    );

    const json = screen.getByTestId('event-json-event-1');
    expect(json.textContent).toContain('"schema_version": "0.1.0"');
    expect(json.textContent).toContain('"roles": [');
    expect(json.textContent).toContain('"user_agent": "curl/8.8.0"');
    expect(json.textContent).toContain('"latency_ms": 12');
  });
});

type StreamCall = {
  url: string;
  aborted: boolean;
  enqueue: (chunk: string) => void;
  close: () => void;
  error: (error: unknown) => void;
};

function renderLiveTail({
  token = null,
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter>
      <LiveTail />
      <LocationProbe />
    </MemoryRouter>,
  );
}

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location">
      {location.pathname}
      {location.search}
    </div>
  );
}

function sseFetchMock({
  policy = policyDocument(),
}: {
  policy?: PolicyDocument;
} = {}) {
  const encoder = new TextEncoder();
  const calls: StreamCall[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy, { ETag: '"policy-etag"' }));
    }

    if (url.pathname !== '/v1/admin/events/stream') {
      return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
    }

    let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
    let isClosed = false;
    const stream = new ReadableStream<Uint8Array>({
      start(nextController) {
        controller = nextController;
      },
    });
    const call: StreamCall = {
      url: String(input),
      aborted: false,
      enqueue(chunk: string) {
        if (!controller || isClosed) {
          throw new Error('stream is not writable');
        }
        controller.enqueue(encoder.encode(chunk));
      },
      close() {
        if (!controller || isClosed) {
          return;
        }
        isClosed = true;
        controller.close();
      },
      error(error: unknown) {
        if (!controller || isClosed) {
          return;
        }
        isClosed = true;
        controller.error(error);
      },
    };
    const signal = init?.signal;
    if (signal instanceof AbortSignal) {
      signal.addEventListener(
        'abort',
        () => {
          call.aborted = true;
          call.error(new DOMException('Aborted', 'AbortError'));
        },
        { once: true },
      );
    }
    calls.push(call);

    return Promise.resolve(
      new Response(stream, {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' },
      }),
    );
  });

  return { calls, fetch };
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

function sseFrame(event: AuditEvent): string {
  return `event: ${event.event_type}\ndata: ${JSON.stringify(event)}\n\n`;
}

async function flushStreamWork() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    event_id: 'event',
    event_type: 'http.request_observed',
    timestamp: '2024-06-01T12:00:00Z',
    schema_version: 1,
    request_id: 'req-1',
    source_ip: '127.0.0.1',
    user_agent: null,
    actor: {
      user_id: 'admin-user',
      roles: ['admin'],
      auth_mode: 'bearer_token',
    },
    payload: {
      path: '/health',
      status: 200,
      method: 'GET',
    },
    ...overrides,
  };
}

function policyDocument(
  overrides: Partial<PolicyDocument> = {},
): PolicyDocument {
  return {
    schema_version: '0.1.0',
    id: 'live-tail-test-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {},
    routes: [],
    rules: [],
    ...overrides,
  };
}

function jwtWithRoles(roles: string[]): string {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'test-user', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
