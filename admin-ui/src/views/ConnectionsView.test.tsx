import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ConnectionsView } from './ConnectionsView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ConnectionsView', () => {
  it('renders safe connection inventory fields and obeys server actions', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          connectionPage({
            actions: {
              can_create: false,
              can_bind_secret: false,
              can_manage_secrets: false,
            },
            connections: [
              connectionSummary({
                id: 'managed-api',
                display_name: 'Billing API',
                sanitized_origin: 'https://billing.example',
                capability_count: 12,
                last_test_at: '2026-07-29T12:00:00Z',
                last_refresh_at: '2026-07-29T12:05:00Z',
                actions: {
                  can_update: true,
                  can_bind_secret: false,
                  can_manage_secrets: false,
                  can_test: true,
                  can_refresh: true,
                  can_delete: true,
                },
              }),
              connectionSummary({
                id: 'legacy-route',
                display_name: 'Legacy route',
                enabled: false,
                source: 'legacy_route',
                read_only: true,
                sanitized_origin: 'https://legacy.example',
                status: {
                  state: 'disabled',
                  reason: 'disabled',
                },
                actions: {
                  can_update: false,
                  can_bind_secret: false,
                  can_manage_secrets: false,
                  can_test: false,
                  can_refresh: false,
                  can_delete: false,
                },
              }),
            ],
          }),
        ),
      ),
    );

    renderConnections();

    expect(await screen.findByText('Billing API')).toBeTruthy();
    expect(screen.getByText('https://billing.example')).toBeTruthy();
    expect(screen.getByText('12')).toBeTruthy();
    expect(screen.getByText('Disabled draft')).toBeTruthy();
    expect(screen.getByText('Read only')).toBeTruthy();

    expect(
      screen.queryByRole('button', { name: 'Add connection' }),
    ).toBeNull();
    expect(
      screen.queryByRole('button', { name: 'Manage secrets' }),
    ).toBeNull();

    const legacyEdit = screen.getByRole('button', {
      name: 'Edit Legacy route, connection legacy-route',
    }) as HTMLButtonElement;
    expect(legacyEdit.disabled).toBe(true);
    const blockedReasonId = legacyEdit.getAttribute('aria-describedby');
    expect(blockedReasonId).toBeTruthy();
    expect(document.getElementById(blockedReasonId!)?.textContent).toBe(
      'Edit unavailable: Legacy connections are read only',
    );
    expect(legacyEdit.getAttribute('title')).toBeNull();

    const billingLink = screen.getByRole('link', {
      name: 'View Billing API, connection managed-api',
    });
    expect(billingLink.getAttribute('href')).toBe('/connections/managed-api');
    expect(
      screen.getByRole('button', {
        name: 'Edit Billing API, connection managed-api',
      }),
    ).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: /^View / }),
    ).toBeNull();
    expect(
      billingLink.closest('td')?.getAttribute('data-label'),
    ).toBe('Connection');
    expect(
      screen
        .getByText('https://billing.example')
        .closest('td')
        ?.getAttribute('data-label'),
    ).toBe('Origin');
    expect(
      screen.getByText(
        'Connection inventory loaded. 2 connections shown.',
      ),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain('secret_id');
  });

  it('sends operational state, kind, and source filters and supports creation when allowed', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(200, connectionPage()))
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          connectionPage({
            actions: {
              can_create: true,
              can_bind_secret: true,
              can_manage_secrets: true,
            },
            connections: [
              connectionSummary({
                id: 'mcp-reports',
                display_name: 'Reports MCP',
                kind: 'mcp_streamable_http',
                source: 'managed',
                status: {
                  state: 'degraded',
                  reason: 'request_failed',
                },
              }),
            ],
          }),
        ),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderConnections();
    await screen.findByText('No connections matched these filters.');
    expect(
      screen.getByText(
        'Connection inventory loaded. No connections matched these filters.',
      ),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Operational state'), {
      target: { value: 'degraded' },
    });
    fireEvent.change(screen.getByLabelText('Kind'), {
      target: { value: 'mcp_streamable_http' },
    });
    fireEvent.change(screen.getByLabelText('Source'), {
      target: { value: 'managed' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

    expect(await screen.findByText('Reports MCP')).toBeTruthy();
    const urls = connectionUrls(fetchMock);
    expect(urls).toHaveLength(2);
    expect(urls[1].searchParams.get('state')).toBe('degraded');
    expect(urls[1].searchParams.get('kind')).toBe('mcp_streamable_http');
    expect(urls[1].searchParams.get('source')).toBe('managed');
    expect(urls[1].searchParams.get('enabled')).toBeNull();

    const addButton = screen.getByRole('button', {
      name: 'Add connection',
    }) as HTMLButtonElement;
    expect(addButton.disabled).toBe(false);
    fireEvent.click(addButton);
    expect(screen.getByTestId('location').textContent).toBe('/connections/new');
  });

  it('exposes secret management without exposing connection creation', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          connectionPage({
            actions: {
              can_create: false,
              can_bind_secret: false,
              can_manage_secrets: true,
            },
          }),
        ),
      ),
    );

    renderConnections();
    expect(
      await screen.findByText('No connections matched these filters.'),
    ).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: 'Add connection' }),
    ).toBeNull();

    fireEvent.click(
      screen.getByRole('button', { name: 'Manage secrets' }),
    );
    expect(screen.getByTestId('location').textContent).toBe('/connections/new');
  });

  it('appends a cursor page and recovers explicitly from a stale cursor', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          connectionPage({
            connections: [
              connectionSummary({
                id: 'first',
                display_name: 'First API',
              }),
            ],
            next_cursor: 'page-2',
          }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(412, {
          error: 'connection inventory changed',
          code: 'precondition_failed',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          connectionPage({
            connections: [
              connectionSummary({
                id: 'current',
                display_name: 'Current API',
              }),
            ],
          }),
        ),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderConnections();
    expect(await screen.findByText('First API')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(
      await screen.findByText(
        'Connection inventory changed. The current first page was loaded.',
      ),
    ).toBeTruthy();
    expect(
      connectionUrls(fetchMock)[1].searchParams.get('cursor'),
    ).toBe('page-2');
    expect(await screen.findByText('Current API')).toBeTruthy();
    expect(screen.queryByText('First API')).toBeNull();
  });

  it('aborts an old cursor page before applying new filters', async () => {
    let resolveOldPage: ((response: Response) => void) | undefined;
    const oldPage = new Promise<Response>((resolve) => {
      resolveOldPage = resolve;
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          connectionPage({
            connections: [
              connectionSummary({
                id: 'first',
                display_name: 'First API',
              }),
            ],
            next_cursor: 'old-page',
          }),
        ),
      )
      .mockImplementationOnce(() => oldPage)
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          connectionPage({
            connections: [
              connectionSummary({
                id: 'filtered',
                display_name: 'Filtered API',
                status: {
                  state: 'degraded',
                  reason: 'request_failed',
                },
              }),
            ],
          }),
        ),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderConnections();
    expect(await screen.findByText('First API')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    fireEvent.change(screen.getByLabelText('Operational state'), {
      target: { value: 'degraded' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    expect(await screen.findByText('Filtered API')).toBeTruthy();
    expect(
      (fetchMock.mock.calls[1]?.[1] as RequestInit | undefined)?.signal
        ?.aborted,
    ).toBe(true);

    await act(async () => {
      resolveOldPage?.(
        jsonResponse(
          200,
          connectionPage({
            connections: [
              connectionSummary({
                id: 'stale',
                display_name: 'Stale cursor API',
              }),
            ],
          }),
        ),
      );
      await Promise.resolve();
    });

    expect(screen.queryByText('Stale cursor API')).toBeNull();
    expect(screen.getByText('Filtered API')).toBeTruthy();
  });

  it.each([
    {
      status: 401,
      heading: 'Bearer token required',
      body: { error: 'unauthorized' },
    },
    {
      status: 403,
      heading: 'Connection permission required',
      body: { error: 'forbidden' },
    },
    {
      status: 503,
      heading: 'Connection inventory unavailable',
      body: { error: 'connection store unavailable' },
    },
  ])(
    'renders a distinct $status inventory error',
    async ({ status, heading, body }) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(jsonResponse(status, body)),
      );

      renderConnections();
      expect(await screen.findByText(heading)).toBeTruthy();
    },
  );

  it('focuses and announces a new error once without stealing focus again', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(401, { error: 'unauthorized' }),
      ),
    );

    renderConnections();
    const alert = await screen.findByRole('alert');
    const focusTarget = alert.parentElement;
    expect(focusTarget).not.toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(focusTarget));

    const stateFilter = screen.getByLabelText('Operational state');
    stateFilter.focus();
    fireEvent.change(stateFilter, { target: { value: 'degraded' } });

    expect(document.activeElement).toBe(stateFilter);
    expect(screen.getByRole('alert')).toBe(alert);
  });

  it('announces omitted safe legacy projections', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          connectionPage({ omitted_legacy_projection_count: 3 }),
        ),
      ),
    );

    renderConnections();
    expect(
      await screen.findByText(/3 legacy projections were omitted/),
    ).toBeTruthy();
  });
});

function renderConnections() {
  render(
    <MemoryRouter initialEntries={['/connections']}>
      <ConnectionsView />
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

function connectionUrls(fetchMock: ReturnType<typeof vi.fn>): URL[] {
  return fetchMock.mock.calls
    .map(([input]) => new URL(String(input), 'http://localhost'))
    .filter((url) => url.pathname === '/v1/admin/connections');
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
      ETag: '"connections-etag"',
      ...headers,
    },
  });
}

function connectionPage(overrides: Record<string, unknown> = {}) {
  return {
    connections: [],
    omitted_legacy_projection_count: 0,
    actions: {
      can_create: false,
      can_bind_secret: false,
      can_manage_secrets: false,
    },
    ...overrides,
  };
}

function connectionSummary(overrides: Record<string, unknown> = {}) {
  return {
    id: 'example-api',
    display_name: 'Example API',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    sanitized_origin: 'https://example.test',
    authentication: 'none',
    endpoint_count: 1,
    capability_count: 0,
    last_test_at: null,
    last_refresh_at: null,
    revisions: {
      connection: 1,
      credential: 0,
      tls: 0,
      discovery: 0,
      status: 0,
    },
    status: {
      state: 'configured',
      reason: 'not_tested',
    },
    actions: {
      can_update: false,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: false,
      can_refresh: false,
      can_delete: false,
    },
    ...overrides,
  };
}
