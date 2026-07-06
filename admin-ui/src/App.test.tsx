import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminShell } from './App';
import { ADMIN_TOKEN_STORAGE_KEY } from './lib/auth';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.removeItem('greengateway_admin_theme');
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  window.history.replaceState(null, '', '/');
  delete document.documentElement.dataset.theme;
});

describe('AdminShell', () => {
  it('persists the selected color theme on the document element', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('light');

    fireEvent.click(
      screen.getByRole('button', { name: 'Switch to dark theme' }),
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(window.localStorage.getItem('greengateway_admin_theme')).toBe(
      'dark',
    );
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('rehydrates the selected color theme from localStorage on mount', () => {
    window.localStorage.setItem('greengateway_admin_theme', 'dark');

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('stores an OIDC completion fragment token and clears the fragment', async () => {
    vi.stubGlobal('fetch', versionFetchMock(false));
    window.history.replaceState(
      null,
      '',
      '/admin/#/auth/complete?token=oidc-fragment-token',
    );

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(window.sessionStorage.getItem(ADMIN_TOKEN_STORAGE_KEY)).toBe(
        'oidc-fragment-token',
      );
    });
    expect(window.location.hash).toBe('');
    expect(
      screen.getByText('Signed in with SSO for this browser session.'),
    ).toBeTruthy();
  });

  it('hides the SSO login link when admin login is not configured', async () => {
    vi.stubGlobal('fetch', versionFetchMock(false));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/version'));
    expect(screen.queryByRole('link', { name: 'Log in with SSO' })).toBeNull();
  });

  it('shows the SSO login link when admin login is configured', async () => {
    vi.stubGlobal('fetch', versionFetchMock(true));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    const link = await screen.findByRole('link', { name: 'Log in with SSO' });
    expect(link.getAttribute('href')).toBe('/v1/admin/auth/login');
  });

  it('registers the traffic inventory route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoints: [],
            next_cursor: null,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter initialEntries={['/traffic']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Traffic' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Traffic inventory',
      }),
    ).toBeTruthy();
  });

  it('registers the traffic endpoint detail route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoint: {
              method: 'GET',
              endpoint_template: '/users/{id}',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T10:00:00Z',
              call_count: 10,
              distinct_principal_count: 1,
              is_new: false,
              reviewed: false,
              reviewed_at: null,
              reviewed_by: null,
              covered_by_rule: true,
              latency: {
                count: 10,
                p50_ms: 8,
                p95_ms: 15,
                p99_ms: 20,
                sample_count: 10,
              },
              status_counts: [{ status: 200, count: 10 }],
              updated_at: '2026-07-04T10:01:00Z',
            },
            principals: {
              principals: [],
              next_cursor: null,
            },
            audit: {
              available: false,
              match_strategy: 'stateless_path_template',
              match_limitations:
                'Matches literal paths and immediate well-known identifier templates; statefully learned slug templates are not reverse-mapped.',
              omitted_reason: 'AUDIT_SQLITE_PATH not configured',
            },
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter
        initialEntries={[
          '/traffic/detail?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D',
        ]}
      >
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'GET /users/{id}',
      }),
    ).toBeTruthy();
  });

  it('registers the principal detail route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            principal: {
              subject: 'alice',
              issuer: '',
              auth_method: 'bearer',
              email: 'alice@example.test',
              org_id: 'org-a',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T10:00:00Z',
              request_count: 10,
            },
            endpoints_touched: [],
            rules_hit: [],
            anomaly_history: [],
            tools_called: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter
        initialEntries={[
          '/identities/detail?subject=alice&issuer=&auth_method=bearer',
        ]}
      >
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'alice',
      }),
    ).toBeTruthy();
  });

  it('registers the policy rules route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/policy/rules/hits') {
          return Promise.resolve(
            new Response(JSON.stringify({ rules: [] }), {
              status: 200,
              headers: {
                'Content-Type': 'application/json',
              },
            }),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/rules']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Rules' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Rule table',
      }),
    ).toBeTruthy();
  });

  it('registers the token management route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/tokens') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                tokens: [],
                next_cursor: null,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/tokens']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Tokens' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Service tokens',
      }),
    ).toBeTruthy();
  });

  it('registers the OpenAPI tools route, navigation entry, and dashboard link', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/tools/openapi']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'OpenAPI tools' })).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'OpenAPI tools',
      }),
    ).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 2,
        name: 'OpenAPI tools',
      }),
    ).toBeTruthy();

    cleanup();
    vi.stubGlobal('fetch', versionFetchMock(false));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByText('Preview and register generated tools')).toBeTruthy();
  });

  it('registers the identity directory route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/principals') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                principals: [],
                next_cursor: null,
                anonymous_request_count: 0,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/identities']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Identities' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Identity directory',
      }),
    ).toBeTruthy();
  });

  it('registers the policy history route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/policy/history') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                versions: [],
                next_cursor: null,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/policy/history']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'History' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Policy version history',
      }),
    ).toBeTruthy();
  });

  it('registers the shadow review route, title, navigation entry, and dashboard link', async () => {
    vi.stubGlobal('fetch', policyShadowReviewFetchMock());

    render(
      <MemoryRouter initialEntries={['/policy/shadow-review']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Shadow review' })).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Shadow review',
      }),
    ).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Shadow review queue',
      }),
    ).toBeTruthy();

    cleanup();
    vi.stubGlobal('fetch', policyShadowReviewFetchMock());

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      screen.getByText('Review would-deny events from shadow rules'),
    ).toBeTruthy();
  });
});

function policyShadowReviewFetchMock() {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname === '/v1/admin/policy') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            schema_version: '0.1.0',
            id: 'test-policy',
            default_action: 'deny',
            enforcement_mode: 'enforce',
            roles: {},
            routes: [],
            rules: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ETag: '"etag-initial"',
            },
          },
        ),
      );
    }
    if (url.pathname === '/v1/admin/policy/rules/shadow-review') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            scanned_event_count: 0,
            scan_truncated: false,
            rules: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}

function versionFetchMock(adminLoginConfigured: boolean) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname === '/version') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            version: '0.5.0',
            admin_login_configured: adminLoginConfigured,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}
