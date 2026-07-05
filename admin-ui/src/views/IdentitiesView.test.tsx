import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { PolicyDocument } from '../lib/policy';
import type { PrincipalPage, PrincipalRecord } from '../lib/principals';
import { IdentitiesView } from './IdentitiesView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('IdentitiesView', () => {
  it('renders principals with IdP and auth-method badges', async () => {
    vi.stubGlobal(
      'fetch',
      principalsFetchMock({
        page: principalPage({
          principals: [
            principalRecord({
              subject: 'alice',
              issuer: 'https://idp.example',
              auth_method: 'bearer',
              email: 'alice@example.test',
              org_id: 'org-a',
              request_count: 12,
            }),
            principalRecord({
              subject: 'bot/reporter',
              issuer: 'service-tokens',
              auth_method: 'service_token',
              email: null,
              org_id: null,
              request_count: 3,
            }),
          ],
          anonymous_request_count: 7,
        }),
      }).fetch,
    );

    renderIdentitiesView();

    expect(await screen.findByText('alice')).toBeTruthy();
    expect(screen.getByText('https://idp.example').className).toContain('badge');
    expect(screen.getByText('Bearer').className).toContain('badge');
    expect(screen.getByText('alice@example.test')).toBeTruthy();
    expect(screen.getByText('org-a')).toBeTruthy();
    expect(screen.getByText('12 requests')).toBeTruthy();
    expect(screen.getByText('bot/reporter')).toBeTruthy();
    expect(screen.getByText('service-tokens').className).toContain('badge');
    expect(screen.getByText('Service token').className).toContain('badge');
    expect(screen.getByText('3 requests')).toBeTruthy();
    expect(screen.getAllByText('Not set')).toHaveLength(2);
    expect(screen.getAllByText('—')).toHaveLength(2);
    expect(
      screen.getByText('2 principals, plus 7 anonymous/failed requests'),
    ).toBeTruthy();
  });

  it('refetches with issuer and principal type filters', async () => {
    const fetcher = principalsFetchMock({
      page: principalPage({ principals: [] }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderIdentitiesView();

    expect(
      await screen.findByText('No principals matched these filters.'),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Issuer search'), {
      target: { value: ' okta ' },
    });
    fireEvent.change(screen.getByLabelText('Principal type'), {
      target: { value: 'service' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() => {
      expect(fetcher.listQueries).toHaveLength(2);
    });
    expect(fetcher.listQueries).toEqual([
      {
        issuer: null,
        auth_method: null,
        principal_type: null,
        last_seen_after: null,
        last_seen_before: null,
        cursor: null,
        limit: '50',
      },
      {
        issuer: 'okta',
        auth_method: null,
        principal_type: 'service',
        last_seen_after: null,
        last_seen_before: null,
        cursor: null,
        limit: '50',
      },
    ]);
  });

  it('links each subject to the encoded principal detail route', async () => {
    vi.stubGlobal(
      'fetch',
      principalsFetchMock({
        page: principalPage({
          principals: [
            principalRecord({
              subject: 'bot/reporter@example.test',
              issuer: '',
              auth_method: 'service_token',
            }),
          ],
        }),
      }).fetch,
    );

    renderIdentitiesView();

    expect(
      (
        await screen.findByRole('link', {
          name: 'View detail for principal bot/reporter@example.test',
        })
      ).getAttribute('href'),
    ).toBe(
      '/identities/detail?subject=bot%2Freporter%40example.test&issuer=&auth_method=service_token',
    );
  });

  it('loads the next page and appends principal rows', async () => {
    const fetcher = principalsFetchMock({
      page: principalPage({
        principals: [principalRecord({ subject: 'first-user' })],
        next_cursor: 'cursor-2',
      }),
      nextPage: principalPage({
        principals: [
          principalRecord({
            subject: 'second-bot',
            auth_method: 'service_token',
          }),
        ],
        next_cursor: null,
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderIdentitiesView();

    expect(await screen.findByText('first-user')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('second-bot')).toBeTruthy();
    expect(screen.getByText('first-user')).toBeTruthy();
    expect(screen.getByText('No more principals')).toBeTruthy();
    expect(fetcher.listQueries.map((query) => query.cursor)).toEqual([
      null,
      'cursor-2',
    ]);
  });

  it('shows an inline read-permission error when the list request is forbidden', async () => {
    vi.stubGlobal(
      'fetch',
      principalsFetchMock({
        listStatus: 403,
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:tokens:read'] },
          },
        }),
      }).fetch,
    );

    renderIdentitiesView({ token: jwtWithRoles(['reader']) });

    expect(
      await screen.findByText('Principal directory permission required'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'This token is valid but does not include admin:principals:read.',
      ),
    ).toBeTruthy();
  });

  it('renders anonymous request counts separately from principal rows', async () => {
    vi.stubGlobal(
      'fetch',
      principalsFetchMock({
        page: principalPage({
          principals: [principalRecord({ subject: 'alice' })],
          anonymous_request_count: 42,
        }),
      }).fetch,
    );

    renderIdentitiesView();

    expect(await screen.findByText('alice')).toBeTruthy();
    expect(
      screen.getByText('1 principal, plus 42 anonymous/failed requests'),
    ).toBeTruthy();
  });

  it('renders an empty state when no principals match', async () => {
    vi.stubGlobal(
      'fetch',
      principalsFetchMock({
        page: principalPage({ principals: [], anonymous_request_count: 0 }),
      }).fetch,
    );

    renderIdentitiesView();

    expect(
      await screen.findByText('No principals matched these filters.'),
    ).toBeTruthy();
    expect(
      screen.getByText('0 principals, plus 0 anonymous/failed requests'),
    ).toBeTruthy();
  });
});

function renderIdentitiesView({
  token = jwtWithRoles(['identity-admin']),
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter>
      <IdentitiesView />
    </MemoryRouter>,
  );
}

function principalsFetchMock({
  policy = policyDocument(),
  page = principalPage(),
  nextPage,
  listStatus = 200,
}: {
  policy?: PolicyDocument;
  page?: PrincipalPage;
  nextPage?: PrincipalPage;
  listStatus?: number;
} = {}) {
  const listQueries: Array<{
    issuer: string | null;
    auth_method: string | null;
    principal_type: string | null;
    last_seen_after: string | null;
    last_seen_before: string | null;
    cursor: string | null;
    limit: string | null;
  }> = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy));
    }

    if (url.pathname === '/v1/admin/principals' && !init?.method) {
      listQueries.push({
        issuer: url.searchParams.get('issuer'),
        auth_method: url.searchParams.get('auth_method'),
        principal_type: url.searchParams.get('principal_type'),
        last_seen_after: url.searchParams.get('last_seen_after'),
        last_seen_before: url.searchParams.get('last_seen_before'),
        cursor: url.searchParams.get('cursor'),
        limit: url.searchParams.get('limit'),
      });

      if (listStatus !== 200) {
        return Promise.resolve(jsonResponse(listStatus, { error: 'forbidden' }));
      }

      return Promise.resolve(
        jsonResponse(200, listQueries.length > 1 && nextPage ? nextPage : page),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, listQueries };
}

function principalPage(overrides: Partial<PrincipalPage> = {}): PrincipalPage {
  return {
    principals: [],
    next_cursor: null,
    anonymous_request_count: 0,
    ...overrides,
  };
}

function principalRecord(
  overrides: Partial<PrincipalRecord> = {},
): PrincipalRecord {
  return {
    subject: 'alice',
    issuer: 'https://idp.example',
    auth_method: 'bearer',
    email: 'alice@example.test',
    org_id: 'org-a',
    first_seen: '2026-07-04T09:00:00Z',
    last_seen: '2026-07-04T10:00:00Z',
    request_count: 1,
    ...overrides,
  };
}

function policyDocument(
  overrides: Partial<PolicyDocument> = {},
): PolicyDocument {
  return {
    schema_version: '0.1.0',
    id: 'test-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {
      'identity-admin': {
        permissions: ['admin:principals:read'],
      },
    },
    routes: [],
    rules: [],
    ...overrides,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
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
