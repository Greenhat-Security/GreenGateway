import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { PolicyDocument } from '../lib/policy';
import type { TrafficEndpoint } from '../lib/traffic';
import { TrafficInventory } from './TrafficInventory';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('TrafficInventory', () => {
  it('renders live endpoint inventory rows with lifecycle badges and computed error rate', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, {
        endpoints: [
          trafficEndpoint({
            method: 'GET',
            endpoint_template: '/users/{id}',
            call_count: 100,
            distinct_principal_count: 3,
            is_new: true,
            covered_by_rule: false,
            open_signals: {
              count: 2,
              signal_types: ['new_endpoint_seen', 'schema_mismatch'],
            },
            status_counts: [
              { status: 200, count: 80 },
              { status: 500, count: 20 },
            ],
          }),
        ],
        next_cursor: null,
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderTrafficInventory();

    expect(await screen.findByText('/users/{id}')).toBeTruthy();
    expect(screen.getAllByText('GET').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('100')).toBeTruthy();
    expect(screen.getByText('20.0%')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('NEW')).toBeTruthy();
    expect(screen.getByText('UNCOVERED')).toBeTruthy();
    expect(screen.getByText('2 open signals')).toBeTruthy();
    expect(screen.getByTitle('2026-07-04T10:00:00Z')).toBeTruthy();
    expect(
      screen
        .getByRole('link', {
          name: 'View detail for GET /users/{id}',
        })
        .getAttribute('href'),
    ).toBe(
      '/traffic/detail?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D',
    );
    const signalsLink = screen.getByRole('link', {
      name: 'View 2 open signals for GET /users/{id}',
    });
    expect(signalsLink.getAttribute('href')).toBe(
      '/signals?state=open&target_kind=endpoint&target_key=GET+%2Fusers%2F%7Bid%7D',
    );

    const firstUrl = trafficEndpointUrls(fetchMock)[0];
    expect(firstUrl.pathname).toBe('/v1/admin/traffic/endpoints');
    expect(firstUrl.searchParams.get('limit')).toBe('50');
    expect(firstUrl.searchParams.get('sort')).toBe('last_seen');
  });

  it('navigates to a prefilled rule editor from an endpoint row', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'POST',
          endpoint_template: '/reports/{id}',
        }),
      ],
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory({ token: jwtWithRoles(['writer']) });

    expect(await screen.findByText('/reports/{id}')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for POST /reports/{id}',
    }) as HTMLButtonElement;
    await waitFor(() => expect(createRuleButton.disabled).toBe(false));

    fireEvent.click(createRuleButton);

    expect(await screen.findByTestId('location')).toBeTruthy();
    expect(screen.getByTestId('location').textContent).toBe(
      '/policy/rules/editor?prefill_method=POST&prefill_path=%2Freports%2F%7Bid%7D',
    );
  });

  it('renders MCP tool traffic rows and navigates with a tool-name rule prefill', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/reports.export',
          call_count: 42,
          distinct_principal_count: 5,
          covered_by_rule: false,
          open_signals: {
            count: 1,
            signal_types: ['schema_mismatch'],
          },
          status_counts: [
            { status: 200, count: 40 },
            { status: 500, count: 2 },
          ],
        }),
      ],
      policy: policyDocument({
        roles: {
          writer: { permissions: ['admin:policy:write'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory({ token: jwtWithRoles(['writer']) });

    expect(await screen.findByText('reports.export')).toBeTruthy();
    expect(screen.getByText('MCP tool')).toBeTruthy();
    expect(screen.getByText('42')).toBeTruthy();
    expect(screen.getByText('4.8%')).toBeTruthy();
    expect(screen.getByText('5')).toBeTruthy();
    expect(screen.getByText('1 open signal')).toBeTruthy();

    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for tool reports.export',
    }) as HTMLButtonElement;
    await waitFor(() => expect(createRuleButton.disabled).toBe(false));

    fireEvent.click(createRuleButton);

    expect(screen.getByTestId('location').textContent).toBe(
      '/policy/rules/editor?prefill_tool_name=reports.export',
    );
  });

  it('disables tool rule creation for a read-only policy principal', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/reports.export',
        }),
      ],
      policy: policyDocument({
        roles: {
          reader: { permissions: ['admin:policy:read'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('reports.export')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for tool reports.export',
    }) as HTMLButtonElement;

    expect(createRuleButton.disabled).toBe(true);
    expect(createRuleButton.getAttribute('title')).toBe(
      'Requires admin:policy:write',
    );
  });

  it('disables endpoint rule creation for a read-only policy principal', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'GET',
          endpoint_template: '/readonly',
        }),
      ],
      policy: policyDocument({
        roles: {
          reader: { permissions: ['admin:policy:read'] },
        },
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('/readonly')).toBeTruthy();
    const createRuleButton = screen.getByRole('button', {
      name: 'Create rule for GET /readonly',
    }) as HTMLButtonElement;

    expect(createRuleButton.disabled).toBe(true);
    expect(createRuleButton.getAttribute('title')).toBe(
      'Requires admin:policy:write',
    );
  });

  it('renders a genuine empty state when no endpoints match', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          endpoints: [],
          next_cursor: null,
        }),
      ),
    );

    renderTrafficInventory();

    expect(
      await screen.findByText('No traffic endpoints matched these filters.'),
    ).toBeTruthy();
  });

  it('does not render a signal badge when open_signals is omitted', async () => {
    const { open_signals: _openSignals, ...endpoint } = trafficEndpoint({
      endpoint_template: '/traffic-only',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          endpoints: [endpoint],
          next_cursor: null,
        }),
      ),
    );

    renderTrafficInventory();

    expect(await screen.findByText('/traffic-only')).toBeTruthy();
    expect(screen.queryByText(/open signals/)).toBeNull();
    expect(
      screen.queryByRole('link', { name: /View .* open signals/ }),
    ).toBeNull();
  });

  it('marks traffic table cells with responsive data labels', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          endpoints: [
            trafficEndpoint({
              method: 'GET',
              endpoint_template: '/responsive',
              call_count: 64,
              distinct_principal_count: 8,
              status_counts: [
                { status: 200, count: 60 },
                { status: 500, count: 4 },
              ],
            }),
          ],
          next_cursor: null,
        }),
      ),
    );

    renderTrafficInventory();

    const endpointLink = await screen.findByRole('link', {
      name: 'View detail for GET /responsive',
    });
    const row = endpointLink.closest('tr');
    expect(row).not.toBeNull();
    expect(endpointLink.closest('td')?.getAttribute('data-label')).toBe('Endpoint');
    expect(screen.getByText('64').closest('td')?.getAttribute('data-label')).toBe(
      'Volume',
    );
    expect(screen.getByText('6.3%').closest('td')?.getAttribute('data-label')).toBe(
      'Error rate',
    );
    expect(screen.getByText('8').closest('td')?.getAttribute('data-label')).toBe(
      'Principals',
    );
    expect(screen.getByText('Unreviewed').closest('td')?.getAttribute('data-label')).toBe(
      'Review',
    );
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
      text: 'Traffic inventory permission required',
    },
    {
      status: 404,
      body: {
        error:
          'traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured',
      },
      text: 'Traffic inventory unavailable',
    },
  ])('renders a distinct $status error state', async ({ status, body, text }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(status, body)));

    renderTrafficInventory();

    expect(await screen.findByText(text)).toBeTruthy();
  });

  it('renders a network error state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));

    renderTrafficInventory();

    expect(await screen.findByText('Request failed')).toBeTruthy();
    expect(screen.getByText('Network request failed: offline')).toBeTruthy();
  });

  it('maps search, method, sort, and lifecycle filters onto API query parameters', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [],
          next_cursor: null,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [],
          next_cursor: null,
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderTrafficInventory();

    await screen.findByText('No traffic endpoints matched these filters.');

    fireEvent.change(screen.getByLabelText('Endpoint search'), {
      target: { value: ' users ' },
    });
    fireEvent.change(screen.getByLabelText('Method'), {
      target: { value: 'GET' },
    });
    fireEvent.change(screen.getByLabelText('Sort by'), {
      target: { value: 'call_count' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'New only' }));
    fireEvent.click(screen.getByRole('button', { name: 'Uncovered only' }));
    fireEvent.click(screen.getByRole('button', { name: 'Reviewed' }));
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

    const trafficUrls = trafficEndpointUrls(fetchMock);
    expect(trafficUrls).toHaveLength(2);
    const secondUrl = trafficUrls[1];
    expect(secondUrl.pathname).toBe('/v1/admin/traffic/endpoints');
    expect(secondUrl.searchParams.get('endpoint_template')).toBe('users');
    expect(secondUrl.searchParams.get('method')).toBe('GET');
    expect(secondUrl.searchParams.get('sort')).toBe('call_count');
    expect(secondUrl.searchParams.get('is_new')).toBe('true');
    expect(secondUrl.searchParams.get('covered_by_rule')).toBe('false');
    expect(secondUrl.searchParams.get('reviewed')).toBe('true');
    expect(secondUrl.searchParams.get('limit')).toBe('50');
  });

  it('loads the next cursor page and appends endpoints', async () => {
    const fetcher = trafficInventoryFetchMock({
      pages: [
        {
          endpoints: [
            trafficEndpoint({
              method: 'GET',
              endpoint_template: '/users/{id}',
            }),
          ],
          next_cursor: 'page-2',
        },
        {
          endpoints: [
            trafficEndpoint({
              method: 'POST',
              endpoint_template: '/reports',
            }),
          ],
          next_cursor: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory();

    expect(await screen.findByText('/users/{id}')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('/reports')).toBeTruthy();
    expect(screen.getByText('/users/{id}')).toBeTruthy();

    const secondUrl = trafficEndpointUrls(fetcher.fetch)[1];
    expect(secondUrl.searchParams.get('cursor')).toBe('page-2');
    expect(secondUrl.searchParams.get('sort')).toBe('last_seen');
  });

  it('marks and clears endpoint review state from the table', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'GET',
          endpoint_template: '/users/{id}',
          reviewed: false,
        }),
      ],
      reviewResponses: [
        {
          reviewed: true,
          reviewed_at: '2026-07-04T12:00:00Z',
          reviewed_by: 'admin-user',
        },
        {
          reviewed: false,
          reviewed_at: null,
          reviewed_by: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory();

    expect(await screen.findByText('/users/{id}')).toBeTruthy();

    fireEvent.click(
      screen.getByRole('button', {
        name: 'Mark reviewed GET /users/{id}',
      }),
    );

    expect(
      await screen.findByRole('button', {
        name: 'Clear review GET /users/{id}',
      }),
    ).toBeTruthy();
    expect(JSON.parse(String(reviewRequests(fetcher.fetch)[0][1]?.body))).toEqual({
      method: 'GET',
      endpoint_template: '/users/{id}',
      reviewed: true,
    });

    fireEvent.click(
      screen.getByRole('button', {
        name: 'Clear review GET /users/{id}',
      }),
    );

    expect(
      await screen.findByRole('button', {
        name: 'Mark reviewed GET /users/{id}',
      }),
    ).toBeTruthy();
    expect(JSON.parse(String(reviewRequests(fetcher.fetch)[1][1]?.body))).toEqual({
      method: 'GET',
      endpoint_template: '/users/{id}',
      reviewed: false,
    });
  });

  it('disables review controls after a write-permission denial', async () => {
    const fetcher = trafficInventoryFetchMock({
      endpoints: [
        trafficEndpoint({
          method: 'GET',
          endpoint_template: '/users/{id}',
          reviewed: false,
        }),
      ],
      reviewStatus: 403,
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTrafficInventory();

    expect(await screen.findByText('/users/{id}')).toBeTruthy();

    fireEvent.click(
      screen.getByRole('button', {
        name: 'Mark reviewed GET /users/{id}',
      }),
    );

    expect(await screen.findByText('Review permission required')).toBeTruthy();
    expect(
      (
        screen.getByRole('button', {
          name: 'Mark reviewed GET /users/{id}',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});

function renderTrafficInventory({
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
      <TrafficInventory />
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

function trafficEndpointUrls(fetchMock: ReturnType<typeof vi.fn>): URL[] {
  return fetchMock.mock.calls
    .map(([input]) => new URL(String(input), 'http://localhost'))
    .filter((url) => url.pathname === '/v1/admin/traffic/endpoints');
}

function reviewRequests(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.filter(([input, init]) => {
    const url = new URL(String(input), 'http://localhost');
    return (
      url.pathname === '/v1/admin/traffic/endpoints/review' &&
      init?.method === 'POST'
    );
  });
}

function trafficInventoryFetchMock({
  endpoints = [],
  pages,
  policy = policyDocument(),
  reviewResponses = [],
  reviewStatus = 200,
}: {
  endpoints?: TrafficEndpoint[];
  pages?: Array<{ endpoints: TrafficEndpoint[]; next_cursor: string | null }>;
  policy?: PolicyDocument;
  reviewResponses?: Array<{
    reviewed: boolean;
    reviewed_at: string | null;
    reviewed_by: string | null;
  }>;
  reviewStatus?: number;
}) {
  const trafficPages = [
    ...(pages ?? [
      {
        endpoints,
        next_cursor: null,
      },
    ]),
  ];
  const reviews = [...reviewResponses];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/traffic/endpoints' && !init?.method) {
      return Promise.resolve(jsonResponse(200, trafficPages.shift() ?? {
        endpoints: [],
        next_cursor: null,
      }));
    }

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy, { ETag: '"policy-etag"' }));
    }

    if (
      url.pathname === '/v1/admin/traffic/endpoints/review' &&
      init?.method === 'POST'
    ) {
      if (reviewStatus !== 200) {
        return Promise.resolve(jsonResponse(reviewStatus, { error: 'forbidden' }));
      }

      return Promise.resolve(
        jsonResponse(
          200,
          reviews.shift() ?? {
            reviewed: true,
            reviewed_at: '2026-07-04T12:00:00Z',
            reviewed_by: 'admin-user',
          },
        ),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch };
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

function policyDocument(
  overrides: Partial<PolicyDocument> = {},
): PolicyDocument {
  return {
    schema_version: '0.1.0',
    id: 'traffic-test-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {},
    routes: [],
    rules: [],
    ...overrides,
  };
}

function trafficEndpoint(
  overrides: Partial<TrafficEndpoint> = {},
): TrafficEndpoint {
  return {
    method: 'GET',
    endpoint_template: '/health',
    first_seen: '2026-07-04T09:00:00Z',
    last_seen: '2026-07-04T10:00:00Z',
    call_count: 1,
    distinct_principal_count: 0,
    is_new: false,
    reviewed: false,
    reviewed_at: null,
    reviewed_by: null,
    covered_by_rule: true,
    open_signals: {
      count: 0,
      signal_types: [],
    },
    latency: {
      count: 1,
      p50_ms: 5,
      p95_ms: 5,
      p99_ms: 5,
    },
    status_counts: [{ status: 200, count: 1 }],
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
