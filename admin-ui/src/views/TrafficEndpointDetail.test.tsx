import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { TrafficEndpointDetail as TrafficEndpointDetailData } from '../lib/traffic';
import { TrafficEndpointDetail } from './TrafficEndpointDetail';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TrafficEndpointDetail', () => {
  it('renders endpoint summary, charts, principals, audit activity, and the matched-rule gap note', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        200,
        trafficDetailResponse({
          endpoint: {
            ...trafficEndpoint(),
            call_count: 1234,
            distinct_principal_count: 2,
            is_new: true,
            reviewed: true,
            reviewed_at: '2026-07-04T10:30:00Z',
            reviewed_by: 'admin-user',
            covered_by_rule: false,
            coverage_scope: 'principal',
            routing_contexts: [
              {
                route_host: 'api.example.test',
                route_path_prefix: '/users',
                upstream_origin: 'https://api.internal',
                first_seen: '2026-07-04T08:00:00Z',
                last_seen: '2026-07-04T10:00:00Z',
                call_count: 1234,
                distinct_principal_count: 2,
                covered_by_rule: false,
                coverage_scope: 'principal',
              },
              {
                upstream_origin: null,
                first_seen: '2026-07-04T08:30:00Z',
                last_seen: '2026-07-04T09:30:00Z',
                call_count: 4,
                distinct_principal_count: 1,
                covered_by_rule: false,
                coverage_scope: 'none',
              },
            ],
            open_signals: {
              count: 3,
              signal_types: [
                'new_endpoint_seen',
                'schema_mismatch',
                'volume_outlier',
              ],
            },
            latency: {
              count: 1234,
              p50_ms: 12,
              p95_ms: 45,
              p99_ms: 90,
              sample_count: 100,
            },
            status_counts: [
              { status: 200, count: 1000 },
              { status: 500, count: 234 },
            ],
          },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderEndpointDetail();

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'GET /users/{id}',
      }),
    ).toBeTruthy();
    expect(screen.getAllByText('1,234').length).toBeGreaterThan(0);
    expect(screen.getByText('Upstream contexts')).toBeTruthy();
    expect(screen.getByText('api.example.test')).toBeTruthy();
    expect(screen.getByText('https://api.internal')).toBeTruthy();
    expect(screen.getByText('No proxy dispatch')).toBeTruthy();
    expect(screen.getAllByText('PRINCIPAL-SCOPED').length).toBeGreaterThan(0);
    const principalsStat = screen
      .getAllByText('Principals')
      .find((element) => element.classList.contains('stat-label'));
    expect(
      principalsStat?.parentElement?.querySelector('.stat-value')?.textContent,
    ).toBe('2');
    expect(screen.getAllByText('12 ms').length).toBeGreaterThan(0);
    expect(screen.getAllByText('45 ms').length).toBeGreaterThan(0);
    expect(screen.getAllByText('90 ms').length).toBeGreaterThan(0);
    expect(screen.getByText('NEW')).toBeTruthy();
    expect(screen.getByText('3 open signals')).toBeTruthy();
    expect(screen.getByText('Reviewed')).toBeTruthy();
    expect(screen.getAllByText('200').length).toBeGreaterThan(0);
    expect(screen.getAllByText('500').length).toBeGreaterThan(0);
    expect(screen.getAllByText('reader-1').length).toBeGreaterThan(0);
    expect(screen.getByText('reader-2')).toBeTruthy();
    expect(screen.getByText('https://idp-a.example')).toBeTruthy();
    expect(screen.getByText('bearer_token')).toBeTruthy();
    expect(screen.getByText('2026-07-04T09:00:00Z')).toBeTruthy();
    expect(screen.getByText('/users/123')).toBeTruthy();
    expect(screen.getByText('event-2')).toBeTruthy();
    expect(
      screen.getByText(/statefully learned slug templates/i),
    ).toBeTruthy();
    expect(
      screen.getByText(/Historical matched-rule data is not available/i),
    ).toBeTruthy();
    expect(
      screen
        .getByRole('link', {
          name: 'View 3 open signals for GET /users/{id}',
        })
        .getAttribute('href'),
    ).toBe(
      '/signals?state=open&target_kind=endpoint&target_key=GET+%2Fusers%2F%7Bid%7D',
    );

    const firstUrl = new URL(String(fetchMock.mock.calls[0][0]), 'http://localhost');
    expect(firstUrl.pathname).toBe('/v1/admin/traffic/endpoint');
    expect(firstUrl.searchParams.get('method')).toBe('GET');
    expect(firstUrl.searchParams.get('endpoint_template')).toBe('/users/{id}');
    expect(firstUrl.searchParams.get('principal_limit')).toBe('50');
    expect(firstUrl.searchParams.get('events_limit')).toBe('20');
    expect(firstUrl.searchParams.get('bucket')).toBe('hour');
  });

  it('loads another principal page and appends it to the breakdown', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          trafficDetailResponse({
            principals: {
              principals: [
                {
                  user_id: 'reader-1',
                  first_seen: '2026-07-04T09:00:00Z',
                  last_seen: '2026-07-04T10:00:00Z',
                },
              ],
              next_cursor: 'principal-page-2',
            },
          }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          trafficDetailResponse({
            principals: {
              principals: [
                {
                  user_id: 'reader-3',
                  first_seen: '2026-07-04T09:30:00Z',
                  last_seen: '2026-07-04T10:30:00Z',
                },
              ],
              next_cursor: null,
            },
          }),
        ),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderEndpointDetail();

    expect((await screen.findAllByText('reader-1')).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'Load more principals' }));

    expect(await screen.findByText('reader-3')).toBeTruthy();
    expect(screen.getAllByText('reader-1').length).toBeGreaterThan(0);

    const secondUrl = new URL(
      String(fetchMock.mock.calls[1][0]),
      'http://localhost',
    );
    expect(secondUrl.searchParams.get('principal_cursor')).toBe(
      'principal-page-2',
    );
    expect(secondUrl.searchParams.get('principal_limit')).toBe('50');
  });

  it('shows the omitted reason when audit enrichment is unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          trafficDetailResponse({
            audit: {
              available: false,
              match_strategy: 'stateless_path_template',
              match_limitations:
                'Matches literal paths and immediate well-known identifier templates; statefully learned slug templates are not reverse-mapped.',
              omitted_reason: 'AUDIT_SQLITE_PATH not configured',
            },
          }),
        ),
      ),
    );

    renderEndpointDetail();

    expect(await screen.findByText('Audit enrichment unavailable')).toBeTruthy();
    expect(screen.getByText('AUDIT_SQLITE_PATH not configured')).toBeTruthy();
    expect(
      screen.getByText(/statefully learned slug templates/i),
    ).toBeTruthy();
  });

  it('surfaces audit scan truncation flags', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          trafficDetailResponse({
            audit: {
              ...auditAvailable(),
              time_series_truncated: true,
              recent_events_scan_truncated: true,
            },
          }),
        ),
      ),
    );

    renderEndpointDetail();

    expect(
      await screen.findByText(
        'Time-series scan hit the safety cap; counts may be partial.',
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Recent-event scan hit the safety cap; newest matches may be incomplete.',
      ),
    ).toBeTruthy();
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
      text: 'Traffic detail permission required',
    },
    {
      status: 404,
      body: { error: 'traffic endpoint was not found' },
      text: 'Traffic endpoint unavailable',
    },
    {
      status: 400,
      body: { error: 'invalid query parameter: method' },
      text: 'Invalid query',
    },
    {
      status: 500,
      body: { error: 'traffic endpoint detail query failed' },
      text: 'Request failed',
    },
  ])('renders a distinct $status error state', async ({ status, body, text }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(status, body)));

    renderEndpointDetail();

    expect(await screen.findByText(text)).toBeTruthy();
  });

  it('renders a network error state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));

    renderEndpointDetail();

    expect(await screen.findByText('Request failed')).toBeTruthy();
    expect(screen.getByText('Network request failed: offline')).toBeTruthy();
  });

  it('does not render a signal badge when open_signals is omitted', async () => {
    const { open_signals: _openSignals, ...endpoint } = trafficEndpoint();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, trafficDetailResponse({ endpoint })),
      ),
    );

    renderEndpointDetail();

    expect(
      await screen.findByRole('heading', {
        name: 'GET /users/{id}',
      }),
    ).toBeTruthy();
    expect(screen.queryByText(/open signals/)).toBeNull();
    expect(
      screen.queryByRole('link', { name: /View .* open signals/ }),
    ).toBeNull();
  });
});

function renderEndpointDetail() {
  render(
    <MemoryRouter
      initialEntries={[
        '/traffic/detail?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D',
      ]}
    >
      <TrafficEndpointDetail />
    </MemoryRouter>,
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

function trafficDetailResponse(overrides: Partial<DetailResponseShape> = {}) {
  return {
    endpoint: trafficEndpoint(),
    principals: {
      principals: [
        {
          user_id: 'reader-1',
          issuer: 'https://idp-a.example',
          auth_method: 'bearer_token',
          first_seen: '2026-07-04T08:00:00Z',
          last_seen: '2026-07-04T10:00:00Z',
        },
        {
          user_id: 'reader-2',
          first_seen: '2026-07-04T08:15:00Z',
          last_seen: '2026-07-04T09:45:00Z',
        },
      ],
      next_cursor: null,
    },
    audit: auditAvailable(),
    ...overrides,
  };
}

function trafficEndpoint(): TrafficEndpointDetailData {
  return {
    method: 'GET',
    endpoint_template: '/users/{id}',
    first_seen: '2026-07-04T08:00:00Z',
    last_seen: '2026-07-04T10:00:00Z',
    call_count: 100,
    distinct_principal_count: 2,
    is_new: false,
    reviewed: false,
    reviewed_at: null as string | null,
    reviewed_by: null as string | null,
    covered_by_rule: true,
    coverage_scope: 'endpoint',
    routing_context_known: true,
    routing_context_known_since: '2026-07-04T08:00:00Z',
    routing_contexts: [],
    open_signals: {
      count: 0,
      signal_types: [] as string[],
    },
    latency: {
      count: 100,
      p50_ms: 10,
      p95_ms: 25,
      p99_ms: 40,
      sample_count: 100,
    },
    status_counts: [
      { status: 200, count: 90 },
      { status: 404, count: 10 },
    ],
    updated_at: '2026-07-04T10:01:00Z',
  };
}

function auditAvailable() {
  return {
    available: true,
    match_strategy: 'stateless_path_template',
    match_limitations:
      'Matches literal paths and immediate well-known identifier templates such as /users/{id}; statefully learned slug templates such as /catalog/{param} are not reverse-mapped from raw audit paths.',
    time_series_truncated: false,
    time_series: [
      {
        bucket_start: '2026-07-04T09:00:00Z',
        count: 40,
      },
      {
        bucket_start: '2026-07-04T10:00:00Z',
        count: 60,
      },
    ],
    recent_events: [
      {
        id: 2,
        event_id: 'event-2',
        request_id: 'request-2',
        timestamp: '2026-07-04T10:00:00Z',
        method: 'GET',
        path: '/users/123',
        status: 200,
        actor: 'reader-1',
      },
    ],
    recent_events_next_cursor: null,
    recent_events_scan_truncated: false,
  };
}

type TrafficEndpointFixture = ReturnType<typeof trafficEndpoint>;

type DetailResponseShape = {
  endpoint: TrafficEndpointFixture | Omit<TrafficEndpointFixture, 'open_signals'>;
  principals: {
    principals: Array<{
      user_id: string;
      first_seen: string;
      last_seen: string;
    }>;
    next_cursor: string | null;
  };
  audit:
    | ReturnType<typeof auditAvailable>
    | {
        available: false;
        match_strategy: string;
        match_limitations: string;
        omitted_reason: string;
      };
};
