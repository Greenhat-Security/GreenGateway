import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  Link,
  MemoryRouter,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ConnectionDetail } from './ConnectionDetail';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ConnectionDetail', () => {
  it('tests a disabled draft with its exact ETag and renders sanitized stages', async () => {
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (
          url.pathname === '/v1/admin/connections/draft-api' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionDetail({
                id: 'draft-api',
                display_name: 'Draft API',
                enabled: false,
                status: { state: 'disabled', reason: 'disabled' },
                actions: {
                  can_update: true,
                  can_bind_secret: false,
                  can_manage_secrets: false,
                  can_test: true,
                  can_refresh: false,
                  can_delete: true,
                },
              }),
              { ETag: '"connection-v7"' },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/draft-api/test' &&
          init?.method === 'POST'
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                ok: false,
                state: 'degraded',
                tested_at: '2026-07-29T12:30:00Z',
                latency_ms: 41,
                stages: [
                  { name: 'egress_policy', outcome: 'success' },
                  { name: 'secret_available', outcome: 'not_applicable' },
                  {
                    name: 'authenticated',
                    outcome: 'failure',
                    reason: 'authentication_failed',
                  },
                ],
              },
              { ETag: '"connection-v7"' },
            ),
          );
        }
        return Promise.reject(
          new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url.pathname}`),
        );
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderDetail('/connections/draft-api');

    expect(await screen.findByText('Disabled draft')).toBeTruthy();
    expect(
      screen.getByText(/Testing this disabled draft uses its saved settings/),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Test connection' }),
    );

    expect(await screen.findByText('Connection test failed')).toBeTruthy();
    expect(screen.getByText('Egress policy')).toBeTruthy();
    expect(screen.getByText('Authentication failed')).toBeTruthy();
    expect(screen.getByText('41 ms')).toBeTruthy();

    const testRequest = fetchMock.mock.calls.find(([input, init]) => {
      const url = new URL(String(input), 'http://localhost');
      return url.pathname.endsWith('/test') && init?.method === 'POST';
    });
    expect(testRequest).toBeTruthy();
    const testInit = testRequest?.[1];
    expect(new Headers(testInit?.headers).get('If-Match')).toBe(
      '"connection-v7"',
    );
    expect(testInit?.body).toBeUndefined();
  });

  it('refreshes inventory and reports bounded added, changed, and removed counts', async () => {
    const fetchMock = detailFetchMock({
      detail: connectionDetail({
        id: 'mcp-tools',
        display_name: 'MCP tools',
        kind: 'mcp_streamable_http',
        actions: {
          can_update: true,
          can_bind_secret: false,
          can_manage_secrets: false,
          can_test: true,
          can_refresh: true,
          can_delete: true,
        },
      }),
      refresh: {
        connection_id: 'mcp-tools',
        catalog_revision: 9,
        status: {
          state: 'healthy',
          reason: 'catalog_refreshed',
        },
        total_count: 20,
        added_count: 4,
        changed_count: 2,
        removed_count: 1,
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    renderDetail('/connections/mcp-tools');
    expect(await screen.findByText('MCP tools')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Refresh inventory' }),
    );

    expect(
      await screen.findByText('Capability inventory refreshed'),
    ).toBeTruthy();
    expect(screen.getByText('20 total')).toBeTruthy();
    expect(specValue('Added')).toBe('4');
    expect(specValue('Changed')).toBe('2');
    expect(specValue('Removed')).toBe('1');
    expect(specValue('Catalog revision')).toBe('9');

    const request = fetchMock.mock.calls.find(([input, init]) => {
      const url = new URL(String(input), 'http://localhost');
      return url.pathname.endsWith('/refresh') && init?.method === 'POST';
    });
    expect(new Headers(request?.[1]?.headers).get('If-Match')).toBe(
      '"connection-v1"',
    );
    expect(request?.[1]?.body).toBeUndefined();
  });

  it('renders legacy connections as read-only and trusts every server action boolean', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          connectionDetail({
            id: 'legacy-default-http',
            display_name: 'Legacy default HTTP',
            source: 'legacy_default_http',
            read_only: true,
            configuration: undefined,
            created_at: undefined,
            updated_at: undefined,
            actions: {
              can_update: false,
              can_bind_secret: false,
              can_manage_secrets: false,
              can_test: false,
              can_refresh: false,
              can_delete: false,
            },
          }),
          { ETag: '"collection-etag"' },
        ),
      ),
    );

    renderDetail('/connections/legacy-default-http');

    expect(
      await screen.findByText('Legacy connection - read only'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Legacy topology and secret settings are intentionally not exposed.',
      ),
    ).toBeTruthy();
    for (const [buttonName, description] of [
      ['Edit', 'Edit unavailable: Legacy connections are read only'],
      [
        'Test connection',
        'Test connection unavailable: Legacy connections are read only',
      ],
      [
        'Refresh inventory',
        'Refresh inventory unavailable: Legacy connections are read only',
      ],
      ['Delete', 'Delete unavailable: Legacy connections are read only'],
    ]) {
      const button = screen.getByRole('button', {
        name: buttonName,
      }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      const blockedReasonId = button.getAttribute('aria-describedby');
      expect(blockedReasonId).toBeTruthy();
      expect(document.getElementById(blockedReasonId!)?.textContent).toBe(
        description,
      );
      expect(button.getAttribute('title')).toBeNull();
    }
  });

  it('does not expose secret locators from safe configuration', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          connectionDetail({
            authentication: 'header_api_key',
            configuration: {
              description: 'Protected API',
              endpoint: {
                base_url: 'https://api.example',
                base_path: '/v1',
              },
              authentication: {
                type: 'header_api_key',
                header_name: 'x-api-key',
                secret_configured: true,
              },
              additional_headers: [
                {
                  header_name: 'cf-access-client-id',
                  secret_configured: true,
                  secret_id: 'ADDITIONAL_HEADER_SECRET_CANARY',
                },
                {
                  header_name: 'cf-access-client-secret',
                  secret_configured: false,
                },
              ],
              tls: {
                ca_bundle_configured: true,
                client_certificate_configured: false,
                client_private_key_configured: false,
              },
              test_profile: {
                method: 'GET',
                path: '/health',
                expected_statuses: [200],
              },
            },
          }),
          { ETag: '"connection-v1"' },
        ),
      ),
    );

    renderDetail();

    expect(await screen.findByText('x-api-key API key - configured')).toBeTruthy();
    expect(
      screen.getByText(
        'cf-access-client-id - configured; cf-access-client-secret - not configured',
      ),
    ).toBeTruthy();
    expect(screen.getByText('Custom CA').parentElement?.textContent).toContain(
      'Configured',
    );
    expect(
      screen.getByText(
        /Gateway egress host and port allowlists must still permit/,
      ),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain('secret_id');
    expect(document.body.textContent).not.toContain('ca_bundle_alias');
    expect(document.body.textContent).not.toContain('private_key_id');
    expect(document.body.textContent).not.toContain(
      'ADDITIONAL_HEADER_SECRET_CANARY',
    );
  });

  it('stops on an ETag conflict and reloads before allowing another operation', async () => {
    let getCount = 0;
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (
          url.pathname === '/v1/admin/connections/example-api' &&
          !init?.method
        ) {
          getCount += 1;
          return Promise.resolve(
            jsonResponse(200, connectionDetail(), {
              ETag: getCount === 1 ? '"connection-v1"' : '"connection-v2"',
            }),
          );
        }
        if (
          url.pathname.endsWith('/test') &&
          init?.method === 'POST'
        ) {
          return Promise.resolve(
            jsonResponse(
              412,
              {
                error: 'connection changed',
                code: 'precondition_failed',
              },
              { ETag: '"connection-v2"' },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected fetch ${url.pathname}`));
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderDetail();
    expect(await screen.findByText('Example API')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Test connection' }),
    );

    expect(await screen.findByText('Connection changed')).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    fireEvent.click(
      screen.getByRole('button', { name: 'Reload current version' }),
    );
    await waitFor(() => expect(getCount).toBe(2));

    const testRequest = fetchMock.mock.calls.find(
      ([, init]) => init?.method === 'POST',
    );
    expect(new Headers(testRequest?.[1]?.headers).get('If-Match')).toBe(
      '"connection-v1"',
    );
  });

  it('locks every mutation after an ambiguous successful response until an explicit reload', async () => {
    let getCount = 0;
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (
          url.pathname === '/v1/admin/connections/example-api' &&
          !init?.method
        ) {
          getCount += 1;
          return Promise.resolve(
            jsonResponse(200, connectionDetail(), {
              ETag:
                getCount === 1
                  ? '"connection-v1"'
                  : '"connection-v2"',
            }),
          );
        }
        if (url.pathname.endsWith('/test') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(200, {
              ok: true,
              state: 'healthy',
              tested_at: '2026-07-29T13:00:00Z',
              latency_ms: 5,
              stages: [
                { name: 'egress_policy', outcome: 'success' },
              ],
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/example-api' &&
          init?.method === 'DELETE'
        ) {
          return Promise.resolve(
            jsonResponse(200, {
              deleted_connection_id: 'different-connection',
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch ${url.pathname}`));
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderDetail();
    expect(await screen.findByText('Example API')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Test connection' }),
    );

    expect(
      await screen.findByText('Connection version unknown'),
    ).toBeTruthy();
    expect(
      (
        screen.getByRole('button', {
          name: 'Test connection',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    fireEvent.click(
      screen.getByRole('button', { name: 'Reload current version' }),
    );
    await waitFor(() => expect(getCount).toBe(2));
    expect(
      (
        screen.getByRole('button', {
          name: 'Test connection',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Confirm delete Example API',
      }),
    );
    expect(
      await screen.findByText('Connection version unknown'),
    ).toBeTruthy();
    expect(screen.getByTestId('location').textContent).toBe(
      '/connections/example-api',
    );
    expect(
      (
        screen.getByRole('button', {
          name: 'Delete',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      screen.queryByRole('button', {
        name: 'Confirm delete Example API',
      }),
    ).toBeNull();
  });

  it.each([
    {
      status: 409,
      error: 'connection has active dependencies',
      heading: 'Connection operation blocked',
    },
    {
      status: 428,
      error: 'if-match is required',
      heading: 'Connection version required',
    },
  ])(
    'distinguishes a $status mutation response from a stale ETag',
    async ({ status, error, heading }) => {
      const fetchMock = vi.fn(
        (input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input), 'http://localhost');
          if (
            url.pathname === '/v1/admin/connections/example-api' &&
            !init?.method
          ) {
            return Promise.resolve(
              jsonResponse(200, connectionDetail(), {
                ETag: '"connection-v1"',
              }),
            );
          }
          if (url.pathname.endsWith('/test') && init?.method === 'POST') {
            return Promise.resolve(
              jsonResponse(status, { error }, { ETag: '"connection-v1"' }),
            );
          }
          return Promise.reject(new Error(`unexpected fetch ${url.pathname}`));
        },
      );
      vi.stubGlobal('fetch', fetchMock);

      renderDetail();
      expect(await screen.findByText('Example API')).toBeTruthy();
      fireEvent.click(
        screen.getByRole('button', { name: 'Test connection' }),
      );

      expect(await screen.findByText(heading)).toBeTruthy();
      if (status === 409) {
        expect(screen.getByText(error)).toBeTruthy();
      }
      expect(screen.queryByText('Connection changed')).toBeNull();
    },
  );

  it('aborts an in-flight mutation and clears its result when the route ID changes', async () => {
    let resolveOldTest!: (response: Response | PromiseLike<Response>) => void;
    const oldTest = new Promise<Response>((resolve) => {
      resolveOldTest = resolve;
    });
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (
          url.pathname === '/v1/admin/connections/first-api' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionDetail({
                id: 'first-api',
                display_name: 'First API',
              }),
              { ETag: '"first-v1"' },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/second-api' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionDetail({
                id: 'second-api',
                display_name: 'Second API',
              }),
              { ETag: '"second-v1"' },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/first-api/test' &&
          init?.method === 'POST'
        ) {
          return oldTest;
        }
        return Promise.reject(new Error(`unexpected fetch ${url.pathname}`));
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    render(
      <MemoryRouter initialEntries={['/connections/first-api']}>
        <Routes>
          <Route path="/connections/:id" element={<ConnectionDetail />} />
        </Routes>
        <LinkToSecondConnection />
      </MemoryRouter>,
    );

    expect(await screen.findByText('First API')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Test connection' }),
    );
    fireEvent.click(screen.getByRole('link', { name: 'Open second API' }));
    expect(await screen.findByText('Second API')).toBeTruthy();

    resolveOldTest(
      jsonResponse(
        200,
        {
          ok: true,
          state: 'healthy',
          tested_at: '2026-07-29T13:00:00Z',
          latency_ms: 5,
          stages: [{ name: 'egress_policy', outcome: 'success' }],
        },
        { ETag: '"first-v2"' },
      ),
    );

    await waitFor(() => {
      expect(screen.queryByText('Connection test passed')).toBeNull();
      expect(screen.getByText('Second API')).toBeTruthy();
    });
  });

  it('clears a prior test result when a refresh starts', async () => {
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (
          url.pathname === '/v1/admin/connections/example-api' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionDetail({
                actions: {
                  can_update: true,
                  can_bind_secret: false,
                  can_manage_secrets: false,
                  can_test: true,
                  can_refresh: true,
                  can_delete: true,
                },
              }),
              { ETag: '"connection-v1"' },
            ),
          );
        }
        if (url.pathname.endsWith('/test') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                ok: true,
                state: 'healthy',
                tested_at: '2026-07-29T13:00:00Z',
                latency_ms: 5,
                stages: [{ name: 'egress_policy', outcome: 'success' }],
              },
              { ETag: '"connection-v1"' },
            ),
          );
        }
        if (url.pathname.endsWith('/refresh') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                connection_id: 'example-api',
                catalog_revision: 2,
                status: {
                  state: 'healthy',
                  reason: 'catalog_refreshed',
                },
                total_count: 3,
                added_count: 1,
                changed_count: 0,
                removed_count: 0,
              },
              { ETag: '"connection-v1"' },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected fetch ${url.pathname}`));
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderDetail();
    expect(await screen.findByText('Example API')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Test connection' }),
    );
    expect(await screen.findByText('Connection test passed')).toBeTruthy();

    fireEvent.click(
      screen.getByRole('button', { name: 'Refresh inventory' }),
    );
    expect(
      await screen.findByText('Capability inventory refreshed'),
    ).toBeTruthy();
    expect(screen.queryByText('Connection test passed')).toBeNull();
  });

  it('confirms deletion and returns to the list only after success', async () => {
    const fetchMock = detailFetchMock({
      detail: connectionDetail({
        actions: {
          can_update: true,
          can_bind_secret: false,
          can_manage_secrets: false,
          can_test: true,
          can_refresh: false,
          can_delete: true,
        },
      }),
      deleted: true,
    });
    vi.stubGlobal('fetch', fetchMock);

    renderDetail();
    expect(await screen.findByText('Example API')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(
      screen.getByRole('button', { name: 'Confirm delete Example API' }),
    );

    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe('/connections'),
    );
    const request = fetchMock.mock.calls.find(
      ([, init]) => init?.method === 'DELETE',
    );
    expect(new Headers(request?.[1]?.headers).get('If-Match')).toBe(
      '"connection-v1"',
    );
  });

  it('moves focus into delete confirmation and restores it on Escape or Cancel', async () => {
    vi.stubGlobal(
      'fetch',
      detailFetchMock({
        detail: connectionDetail(),
      }),
    );

    renderDetail();
    expect(await screen.findByText('Example API')).toBeTruthy();

    const deleteButton = screen.getByRole('button', { name: 'Delete' });
    deleteButton.focus();
    fireEvent.click(deleteButton);

    const confirmButton = screen.getByRole('button', {
      name: 'Confirm delete Example API',
    });
    await waitFor(() => expect(document.activeElement).toBe(confirmButton));

    fireEvent.keyDown(confirmButton, { key: 'Escape' });
    const restoredAfterEscape = screen.getByRole('button', {
      name: 'Delete',
    });
    await waitFor(() =>
      expect(document.activeElement).toBe(restoredAfterEscape),
    );

    fireEvent.click(restoredAfterEscape);
    const cancelButton = screen.getByRole('button', { name: 'Cancel' });
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', {
          name: 'Confirm delete Example API',
        }),
      ),
    );

    fireEvent.click(cancelButton);
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Delete' }),
      ),
    );
  });

  it.each([
    { status: 401, heading: 'Bearer token required' },
    { status: 403, heading: 'Connection permission required' },
    { status: 404, heading: 'Connection not found' },
    { status: 503, heading: 'Connection service unavailable' },
  ])(
    'renders a distinct $status detail error',
    async ({ status, heading }) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(
          jsonResponse(status, { error: `request failed with ${status}` }),
        ),
      );

      renderDetail();
      expect(await screen.findByText(heading)).toBeTruthy();
    },
  );
});

function renderDetail(path = '/connections/example-api') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/connections/:id" element={<ConnectionDetail />} />
      </Routes>
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

function LinkToSecondConnection() {
  return <Link to="/connections/second-api">Open second API</Link>;
}

function detailFetchMock({
  detail,
  refresh,
  deleted = false,
}: {
  detail: Record<string, unknown>;
  refresh?: Record<string, unknown>;
  deleted?: boolean;
}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    if (
      url.pathname === `/v1/admin/connections/${String(detail.id)}` &&
      !init?.method
    ) {
      return Promise.resolve(
        jsonResponse(200, detail, { ETag: '"connection-v1"' }),
      );
    }
    if (url.pathname.endsWith('/refresh') && init?.method === 'POST') {
      return Promise.resolve(
        jsonResponse(200, refresh ?? {}, { ETag: '"connection-v1"' }),
      );
    }
    if (
      url.pathname === `/v1/admin/connections/${String(detail.id)}` &&
      init?.method === 'DELETE' &&
      deleted
    ) {
      return Promise.resolve(
        jsonResponse(200, { deleted_connection_id: detail.id }),
      );
    }
    return Promise.reject(
      new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url.pathname}`),
    );
  });
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

function connectionDetail(overrides: Record<string, unknown> = {}) {
  return {
    id: 'example-api',
    display_name: 'Example API',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    sanitized_origin: 'https://api.example',
    authentication: 'none',
    endpoint_count: 1,
    capability_count: 0,
    last_test_at: undefined,
    last_refresh_at: undefined,
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
    configuration: {
      endpoint: {
        base_url: 'https://api.example',
        base_path: '/',
      },
      authentication: { type: 'none' },
      tls: {
        ca_bundle_configured: false,
        client_certificate_configured: false,
        client_private_key_configured: false,
      },
      test_profile: {
        method: 'GET',
        path: '/health',
        expected_statuses: [200],
      },
    },
    dependencies: [],
    actions: {
      can_update: true,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: true,
      can_refresh: false,
      can_delete: true,
    },
    created_at: '2026-07-29T10:00:00Z',
    updated_at: '2026-07-29T11:00:00Z',
    ...overrides,
  };
}

function specValue(label: string): string | null | undefined {
  return screen.getByText(label).parentElement?.querySelector('dd')?.textContent;
}
