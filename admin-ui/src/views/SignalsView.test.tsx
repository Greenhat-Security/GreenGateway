import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import { AuditEvent } from '../lib/audit';
import { DiscoverySignal, SignalListResponse } from '../lib/signals';
import { SignalsView } from './SignalsView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('SignalsView', () => {
  it('renders signal rows and appends cursor pages', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        {
          signals: [
            signal({
              id: 'sig-1',
              signal_type: 'schema_mismatch',
              explanation: 'Request body no longer matches GET /users/{id}.',
              evidence: { expected: 'string', observed: 'number' },
            }),
          ],
          next_cursor: 'page-2',
        },
        {
          signals: [
            signal({
              id: 'sig-2',
              signal_type: 'volume_outlier',
              explanation: 'Traffic volume changed for POST /reports.',
              target: endpointTarget('POST', '/reports'),
            }),
          ],
          next_cursor: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView();

    expect(
      await screen.findByText('Request body no longer matches GET /users/{id}.'),
    ).toBeTruthy();
    expect(screen.getByText('schema_mismatch')).toBeTruthy();
    expect(screen.getByText('GET /users/{id}')).toBeTruthy();
    expect(screen.getByTestId('signal-evidence-sig-1').textContent).toContain(
      '"observed": "number"',
    );

    const firstListUrl = fetcher.listUrls[0];
    expect(firstListUrl.pathname).toBe('/v1/admin/signals');
    expect(firstListUrl.searchParams.get('state')).toBe('open');
    expect(firstListUrl.searchParams.get('limit')).toBe('50');

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('Traffic volume changed for POST /reports.')).toBeTruthy();
    expect(fetcher.listUrls[1].searchParams.get('cursor')).toBe('page-2');
  });

  it('filters by state and signal type', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        { signals: [], next_cursor: null },
        {
          signals: [
            signal({
              id: 'sig-filtered',
              signal_type: 'principal_new_to_endpoint',
              state: 'dismissed',
            }),
          ],
          next_cursor: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView();

    expect(await screen.findByText('No signals matched these filters.')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('State'), {
      target: { value: 'dismissed' },
    });
    fireEvent.change(screen.getByLabelText('Signal type'), {
      target: { value: ' principal_new_to_endpoint ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

    expect(await screen.findByText('principal_new_to_endpoint')).toBeTruthy();
    const secondListUrl = fetcher.listUrls[1];
    expect(secondListUrl.searchParams.get('state')).toBe('dismissed');
    expect(secondListUrl.searchParams.get('signal_type')).toBe(
      'principal_new_to_endpoint',
    );
  });

  it('acknowledges and dismisses signals', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        {
          signals: [
            signal({
              id: 'sig-action',
              signal_type: 'new_endpoint_seen',
            }),
          ],
          next_cursor: null,
        },
      ],
      transitions: [
        signal({ id: 'sig-action', state: 'acknowledged' }),
        signal({ id: 'sig-action', state: 'dismissed' }),
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView();

    expect(await screen.findByText('new_endpoint_seen')).toBeTruthy();

    fireEvent.click(
      screen.getByRole('button', { name: 'Acknowledge signal sig-action' }),
    );
    expect(await screen.findByText('acknowledged')).toBeTruthy();
    expect(fetcher.transitionUrls[0].pathname).toBe(
      '/v1/admin/signals/sig-action/acknowledge',
    );

    fireEvent.click(
      screen.getByRole('button', { name: 'Dismiss signal sig-action' }),
    );
    expect(await screen.findByText('dismissed')).toBeTruthy();
    expect(fetcher.transitionUrls[1].pathname).toBe(
      '/v1/admin/signals/sig-action/dismiss',
    );
  });

  it('prepends live signal.opened SSE events', async () => {
    const fetcher = signalsFetchMock({
      pages: [{ signals: [], next_cursor: null }],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView();

    expect(await screen.findByText('No signals matched these filters.')).toBeTruthy();
    act(() => {
      fetcher.stream.enqueue(
        sseFrame(
          auditEvent({
            event_type: 'signal.opened',
            payload: signal({
              id: 'sig-live',
              signal_type: 'schema_mismatch',
              explanation: 'Malformed caller sent an unexpected JSON shape.',
              evidence: { field: 'amount', observed: 'object' },
            }),
          }),
        ),
      );
    });

    expect(
      await screen.findByText('Malformed caller sent an unexpected JSON shape.'),
    ).toBeTruthy();
    expect(screen.getByText('New signal opened: schema_mismatch')).toBeTruthy();
  });
});

function renderSignalsView(initialPath = '/signals') {
  render(
    <MemoryRouter initialEntries={[initialPath]}>
      <SignalsView />
    </MemoryRouter>,
  );
}

function signalsFetchMock({
  pages,
  transitions = [],
}: {
  pages: SignalListResponse[];
  transitions?: DiscoverySignal[];
}) {
  const encoder = new TextEncoder();
  let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
  const listUrls: URL[] = [];
  const transitionUrls: URL[] = [];
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
    },
  });
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname === '/v1/admin/events/stream') {
      return Promise.resolve(
        new Response(stream, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        }),
      );
    }
    if (url.pathname === '/v1/admin/signals' && !init?.method) {
      listUrls.push(url);
      return Promise.resolve(jsonResponse(200, pages.shift() ?? emptyPage()));
    }
    if (url.pathname.startsWith('/v1/admin/signals/') && init?.method === 'POST') {
      transitionUrls.push(url);
      return Promise.resolve(
        jsonResponse(200, transitions.shift() ?? signal({ state: 'acknowledged' })),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return {
    fetch,
    listUrls,
    transitionUrls,
    stream: {
      enqueue(chunk: string) {
        if (!streamController) {
          throw new Error('stream is not ready');
        }
        streamController.enqueue(encoder.encode(chunk));
      },
    },
  };
}

function emptyPage(): SignalListResponse {
  return { signals: [], next_cursor: null };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

function sseFrame(event: AuditEvent): string {
  return `event: ${event.event_type}\ndata: ${JSON.stringify(event)}\n\n`;
}

function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    event_id: 'event-live',
    event_type: 'signal.opened',
    timestamp: '2026-07-04T12:00:00Z',
    schema_version: '0.1.0',
    request_id: 'request-live',
    source_ip: '127.0.0.1',
    user_agent: null,
    actor: null,
    payload: {},
    ...overrides,
  };
}

function signal(overrides: Partial<DiscoverySignal> = {}): DiscoverySignal {
  return {
    id: 'sig-1',
    signal_type: 'new_endpoint_seen',
    target: endpointTarget('GET', '/users/{id}'),
    explanation: 'New endpoint observed: GET /users/{id}.',
    evidence: {
      first_seen: '2026-07-04T10:00:00Z',
      initial_call_count: 1,
    },
    state: 'open',
    created_at: '2026-07-04T10:00:00Z',
    updated_at: '2026-07-04T10:00:00Z',
    transitioned_at: null,
    transitioned_by: null,
    ...overrides,
  };
}

function endpointTarget(method: string, endpointTemplate: string) {
  return {
    kind: 'endpoint',
    identity: {
      method,
      endpoint_template: endpointTemplate,
    },
  };
}
