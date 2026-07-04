import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import type { TrafficEndpoint } from '../lib/traffic';
import { TrafficInventory } from './TrafficInventory';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
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
    expect(screen.getByTitle('2026-07-04T10:00:00Z')).toBeTruthy();

    const firstUrl = new URL(String(fetchMock.mock.calls[0][0]), 'http://localhost');
    expect(firstUrl.pathname).toBe('/v1/admin/traffic/endpoints');
    expect(firstUrl.searchParams.get('limit')).toBe('50');
    expect(firstUrl.searchParams.get('sort')).toBe('last_seen');
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

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const secondUrl = new URL(
      String(fetchMock.mock.calls[1][0]),
      'http://localhost',
    );
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
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [
            trafficEndpoint({
              method: 'GET',
              endpoint_template: '/users/{id}',
            }),
          ],
          next_cursor: 'page-2',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [
            trafficEndpoint({
              method: 'POST',
              endpoint_template: '/reports',
            }),
          ],
          next_cursor: null,
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderTrafficInventory();

    expect(await screen.findByText('/users/{id}')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('/reports')).toBeTruthy();
    expect(screen.getByText('/users/{id}')).toBeTruthy();

    const secondUrl = new URL(
      String(fetchMock.mock.calls[1][0]),
      'http://localhost',
    );
    expect(secondUrl.searchParams.get('cursor')).toBe('page-2');
    expect(secondUrl.searchParams.get('sort')).toBe('last_seen');
  });

  it('marks and clears endpoint review state from the table', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [
            trafficEndpoint({
              method: 'GET',
              endpoint_template: '/users/{id}',
              reviewed: false,
            }),
          ],
          next_cursor: null,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          reviewed: true,
          reviewed_at: '2026-07-04T12:00:00Z',
          reviewed_by: 'admin-user',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          reviewed: false,
          reviewed_at: null,
          reviewed_by: null,
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

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
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({
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
    expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({
      method: 'GET',
      endpoint_template: '/users/{id}',
      reviewed: false,
    });
  });

  it('disables review controls after a write-permission denial', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          endpoints: [
            trafficEndpoint({
              method: 'GET',
              endpoint_template: '/users/{id}',
              reviewed: false,
            }),
          ],
          next_cursor: null,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(403, { error: 'forbidden' }));
    vi.stubGlobal('fetch', fetchMock);

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

function renderTrafficInventory() {
  render(
    <MemoryRouter>
      <TrafficInventory />
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
