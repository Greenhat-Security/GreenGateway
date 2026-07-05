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
import type { CreatedToken, TokenPage, TokenRecord } from '../lib/tokens';
import { TokensView } from './TokensView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('TokensView', () => {
  it('renders tokens with active, expired, and revoked status badges', async () => {
    vi.stubGlobal(
      'fetch',
      tokensFetchMock({
        page: tokenPage({
          tokens: [
            tokenRecord({
              id: 'tok_active',
              token_prefix: 'ggw_active',
              scopes: ['admin:tokens:read'],
              expires_at: '2999-07-05T00:00:00Z',
            }),
            tokenRecord({
              id: 'tok_expired',
              token_prefix: 'ggw_expired',
              scopes: ['audit:read'],
              expires_at: '2000-07-03T23:59:59Z',
            }),
            tokenRecord({
              id: 'tok_revoked',
              token_prefix: 'ggw_revoked',
              scopes: ['admin:tokens:write'],
              revoked_at: '2026-07-04T11:00:00Z',
            }),
          ],
        }),
      }).fetch,
    );

    renderTokensView();

    expect(await screen.findByText('tok_active')).toBeTruthy();
    expect(screen.getByText('ggw_active')).toBeTruthy();
    expect(screen.getByText('admin:tokens:read')).toBeTruthy();
    expect(screen.getByText('tok_expired')).toBeTruthy();
    expect(screen.getByText('tok_revoked')).toBeTruthy();
    expect(screen.getAllByText('Never used')).toHaveLength(3);

    expect(screen.getByText('Active').className).toContain('success');
    expect(screen.getByText('Expired').className).toContain('warning');
    expect(screen.getByText('Revoked').className).toContain('danger');
  });

  it('loads the next token page and appends rows', async () => {
    const fetcher = tokensFetchMock({
      page: tokenPage({
        tokens: [tokenRecord({ id: 'tok_first', token_prefix: 'ggw_first' })],
        next_cursor: 'cursor-2',
      }),
      nextPage: tokenPage({
        tokens: [tokenRecord({ id: 'tok_second', token_prefix: 'ggw_second' })],
        next_cursor: null,
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTokensView();

    expect(await screen.findByText('tok_first')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('tok_second')).toBeTruthy();
    expect(fetcher.listQueries).toEqual([
      { cursor: null, limit: '50' },
      { cursor: 'cursor-2', limit: '50' },
    ]);
  });

  it('creates a token, shows the one-time plaintext panel, and clears it after dismissal', async () => {
    const fetcher = tokensFetchMock({
      page: tokenPage({ tokens: [] }),
      createResponse: createdToken({
        plaintext_token: 'ggw_plaintext_created',
        plaintext_token_notice:
          'Server notice: save this token because it is shown once.',
        token: tokenRecord({
          id: 'tok_created',
          token_prefix: 'ggw_created',
          scopes: ['admin:tokens:read', 'admin:tokens:write', 'audit:read'],
        }),
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);
    const rendered = renderTokensView();

    fireEvent.change(await screen.findByLabelText('Scopes'), {
      target: {
        value: 'admin:tokens:read, admin:tokens:write audit:read',
      },
    });
    fireEvent.change(screen.getByLabelText('Expires at'), {
      target: { value: '2026-12-31' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));

    await waitFor(() => {
      expect(fetcher.createBodies).toEqual([
        {
          scopes: ['admin:tokens:read', 'admin:tokens:write', 'audit:read'],
          expires_at: '2026-12-31T00:00:00.000Z',
        },
      ]);
    });
    expect(
      await screen.findByDisplayValue('ggw_plaintext_created'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Server notice: save this token because it is shown once.',
      ),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: "I've saved this" }));

    await waitFor(() => {
      expect(screen.queryByDisplayValue('ggw_plaintext_created')).toBeNull();
    });
    expect(screen.getByText('tok_created')).toBeTruthy();

    rendered.rerender(
      <MemoryRouter>
        <TokensView />
      </MemoryRouter>,
    );
    expect(screen.queryByDisplayValue('ggw_plaintext_created')).toBeNull();
  });

  it('requires confirming before revoking a token and supports canceling confirmation', async () => {
    const fetcher = tokensFetchMock({
      page: tokenPage({
        tokens: [tokenRecord({ id: 'tok_revoke', token_prefix: 'ggw_revoke' })],
      }),
      revokeResponse: tokenRecord({
        id: 'tok_revoke',
        token_prefix: 'ggw_revoke',
        revoked_at: '2026-07-04T12:10:00Z',
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTokensView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Revoke token tok_revoke' }),
    );

    expect(fetcher.revokeIds).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(
      await screen.findByRole('button', { name: 'Revoke token tok_revoke' }),
    ).toBeTruthy();
    expect(fetcher.revokeIds).toEqual([]);

    fireEvent.click(
      screen.getByRole('button', { name: 'Revoke token tok_revoke' }),
    );
    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Confirm revoke token tok_revoke',
      }),
    );

    await waitFor(() => {
      expect(fetcher.revokeIds).toEqual(['tok_revoke']);
    });
    expect(await screen.findByText('Revoked')).toBeTruthy();
  });

  it('requires confirming before rotating a token and shows the new plaintext once', async () => {
    const fetcher = tokensFetchMock({
      page: tokenPage({
        tokens: [tokenRecord({ id: 'tok_rotate', token_prefix: 'ggw_old' })],
      }),
      rotateResponse: createdToken({
        plaintext_token: 'ggw_plaintext_rotated',
        token: tokenRecord({
          id: 'tok_rotate',
          token_prefix: 'ggw_newprefix',
        }),
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderTokensView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Rotate token tok_rotate' }),
    );

    expect(fetcher.rotateIds).toEqual([]);
    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Confirm rotate token tok_rotate',
      }),
    );

    await waitFor(() => {
      expect(fetcher.rotateIds).toEqual(['tok_rotate']);
    });
    expect(
      await screen.findByDisplayValue('ggw_plaintext_rotated'),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: "I've saved this" }));

    await waitFor(() => {
      expect(screen.queryByDisplayValue('ggw_plaintext_rotated')).toBeNull();
    });
    expect(screen.getByText('ggw_newprefix')).toBeTruthy();
  });

  it('disables write controls when the current token lacks admin:tokens:write', async () => {
    vi.stubGlobal(
      'fetch',
      tokensFetchMock({
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:tokens:read'] },
          },
        }),
        page: tokenPage({
          tokens: [tokenRecord({ id: 'tok_read_only' })],
        }),
      }).fetch,
    );

    renderTokensView({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('Token write permission required')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole('button', {
          name: 'Revoke token tok_read_only',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole('button', {
          name: 'Rotate token tok_read_only',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });

  it('shows an inline read-permission error for a 403 list response', async () => {
    vi.stubGlobal(
      'fetch',
      tokensFetchMock({
        listStatus: 403,
      }).fetch,
    );

    renderTokensView();

    expect(await screen.findByText('Token permission required')).toBeTruthy();
    expect(
      screen.getByText(
        'This token is valid but does not include admin:tokens:read.',
      ),
    ).toBeTruthy();
  });
});

function renderTokensView({
  token = jwtWithRoles(['token-admin']),
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  return render(
    <MemoryRouter>
      <TokensView />
    </MemoryRouter>,
  );
}

function tokensFetchMock({
  policy = policyDocument(),
  page = tokenPage(),
  nextPage,
  createResponse = createdToken(),
  revokeResponse,
  rotateResponse = createdToken({
    plaintext_token: 'ggw_plaintext_rotated',
    token: tokenRecord({ token_prefix: 'ggw_rotated' }),
  }),
  listStatus = 200,
}: {
  policy?: PolicyDocument;
  page?: TokenPage;
  nextPage?: TokenPage;
  createResponse?: CreatedToken;
  revokeResponse?: TokenRecord;
  rotateResponse?: CreatedToken;
  listStatus?: number;
} = {}) {
  const listQueries: Array<{ cursor: string | null; limit: string | null }> = [];
  const createBodies: unknown[] = [];
  const revokeIds: string[] = [];
  const rotateIds: string[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy));
    }

    if (url.pathname === '/v1/admin/tokens' && !init?.method) {
      listQueries.push({
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

    if (url.pathname === '/v1/admin/tokens' && init?.method === 'POST') {
      createBodies.push(JSON.parse(String(init.body)));
      return Promise.resolve(jsonResponse(201, createResponse));
    }

    if (
      url.pathname.startsWith('/v1/admin/tokens/') &&
      init?.method === 'DELETE'
    ) {
      const tokenId = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      revokeIds.push(tokenId);
      return Promise.resolve(
        jsonResponse(
          200,
          revokeResponse ??
            tokenRecord({
              id: tokenId,
              revoked_at: '2026-07-04T12:00:00Z',
            }),
        ),
      );
    }

    if (
      url.pathname.startsWith('/v1/admin/tokens/') &&
      url.pathname.endsWith('/rotate') &&
      init?.method === 'POST'
    ) {
      const tokenId = decodeURIComponent(url.pathname.split('/').at(-2) ?? '');
      rotateIds.push(tokenId);
      return Promise.resolve(jsonResponse(200, rotateResponse));
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, listQueries, createBodies, revokeIds, rotateIds };
}

function tokenPage(overrides: Partial<TokenPage> = {}): TokenPage {
  return {
    tokens: [],
    next_cursor: null,
    ...overrides,
  };
}

function createdToken(overrides: Partial<CreatedToken> = {}): CreatedToken {
  return {
    plaintext_token: 'ggw_plaintext_created',
    plaintext_token_notice:
      'Save this token now; the plaintext will not be shown again.',
    token: tokenRecord({ id: 'tok_created', token_prefix: 'ggw_created' }),
    ...overrides,
  };
}

function tokenRecord(overrides: Partial<TokenRecord> = {}): TokenRecord {
  return {
    id: 'tok_active',
    token_prefix: 'ggw_1234567890',
    scopes: ['admin:tokens:read'],
    created_by: 'admin@example.test',
    created_at: '2026-07-04T10:00:00Z',
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
      'token-admin': {
        permissions: ['admin:tokens:read', 'admin:tokens:write'],
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
