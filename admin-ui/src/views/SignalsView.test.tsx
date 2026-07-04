import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import { AuditEvent } from '../lib/audit';
import type { PolicyDocument } from '../lib/policy';
import { DiscoverySignal, SignalListResponse } from '../lib/signals';
import { SignalsView } from './SignalsView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
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

  it('navigates to a shadow prefilled rule editor from an endpoint signal', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        {
          signals: [
            signal({
              id: 'sig-create-rule',
              target: endpointTarget('POST', '/reports/{id}'),
            }),
          ],
          next_cursor: null,
        },
      ],
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView('/signals', { token: jwtWithRoles(['writer']) });

    expect(await screen.findByText('POST /reports/{id}')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for signal sig-create-rule',
    }) as HTMLButtonElement;
    expect(createRuleButton.disabled).toBe(false);

    fireEvent.click(createRuleButton);

    expect(screen.getByTestId('location').textContent).toBe(
      '/policy/rules/editor?prefill_method=POST&prefill_path=%2Freports%2F%7Bid%7D&prefill_action=shadow',
    );
  });

  it('disables signal rule creation for a read-only policy principal', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        {
          signals: [
            signal({
              id: 'sig-readonly',
              target: endpointTarget('GET', '/readonly'),
            }),
          ],
          next_cursor: null,
        },
      ],
      policy: policyDocument({
        roles: {
          reader: { permissions: ['admin:policy:read'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView('/signals', { token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('GET /readonly')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for signal sig-readonly',
    }) as HTMLButtonElement;

    expect(createRuleButton.disabled).toBe(true);
    expect(createRuleButton.getAttribute('title')).toBe(
      'Requires admin:policy:write',
    );
  });

  it('does not render a create-rule action for a non-endpoint signal target', async () => {
    const fetcher = signalsFetchMock({
      pages: [
        {
          signals: [
            signal({
              id: 'sig-principal',
              target: {
                kind: 'principal',
                identity: { user_id: 'alice' },
              },
            }),
          ],
          next_cursor: null,
        },
      ],
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderSignalsView('/signals', { token: jwtWithRoles(['writer']) });

    expect(await screen.findByText(/principal/)).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: 'Create rule for signal sig-principal' }),
    ).toBeNull();
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

function renderSignalsView(
  initialPath = '/signals',
  {
    token = null,
  }: {
    token?: string | null;
  } = {},
) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter initialEntries={[initialPath]}>
      <SignalsView />
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

function signalsFetchMock({
  pages,
  transitions = [],
  policy = policyDocument(),
}: {
  pages: SignalListResponse[];
  transitions?: DiscoverySignal[];
  policy?: PolicyDocument;
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
    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy, { ETag: '"policy-etag"' }));
    }
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

function policyDocument(
  overrides: Partial<PolicyDocument> = {},
): PolicyDocument {
  return {
    schema_version: '0.1.0',
    id: 'signals-test-policy',
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
