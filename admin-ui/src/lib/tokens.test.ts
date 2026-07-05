import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from './auth';
import {
  createToken,
  fetchTokens,
  getToken,
  revokeToken,
  rotateToken,
} from './tokens';

afterEach(() => {
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('tokens API client', () => {
  it('lists tokens with auth headers and pagination query params', async () => {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, 'admin-token');
    const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');

      expect(url.pathname).toBe('/v1/admin/tokens');
      expect(url.searchParams.get('cursor')).toBe('opaque cursor');
      expect(url.searchParams.get('limit')).toBe('25');
      expect(requestHeader(init?.headers, 'Authorization')).toBe(
        'Bearer admin-token',
      );

      return Promise.resolve(
        jsonResponse(200, {
          tokens: [tokenRecord({ id: 'tok_1' })],
          next_cursor: 'next-page',
        }),
      );
    });
    vi.stubGlobal('fetch', fetch);

    const page = await fetchTokens('opaque cursor', 25);

    expect(page.tokens[0].id).toBe('tok_1');
    expect(page.next_cursor).toBe('next-page');
  });

  it('creates tokens with scopes and optional expiry', async () => {
    const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');

      expect(url.pathname).toBe('/v1/admin/tokens');
      expect(init?.method).toBe('POST');
      expect(requestHeader(init?.headers, 'Content-Type')).toBe(
        'application/json',
      );
      expect(JSON.parse(String(init?.body))).toEqual({
        scopes: ['admin:tokens:read', 'admin:tokens:write'],
        expires_at: '2026-12-31T00:00:00.000Z',
      });

      return Promise.resolve(
        jsonResponse(201, {
          plaintext_token: 'ggw_plaintext_created',
          plaintext_token_notice:
            'Save this token now; the plaintext will not be shown again.',
          token: tokenRecord({ id: 'tok_created' }),
        }),
      );
    });
    vi.stubGlobal('fetch', fetch);

    const created = await createToken(
      ['admin:tokens:read', 'admin:tokens:write'],
      '2026-12-31T00:00:00.000Z',
    );

    expect(created.plaintext_token).toBe('ggw_plaintext_created');
    expect(created.token.id).toBe('tok_created');
  });

  it('gets, revokes, and rotates a token by encoded id', async () => {
    const calls: Array<{ path: string; method: string | undefined }> = [];
    const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');
      calls.push({ path: url.pathname, method: init?.method });

      if (url.pathname === '/v1/admin/tokens/tok%2F1' && !init?.method) {
        return Promise.resolve(jsonResponse(200, tokenRecord({ id: 'tok/1' })));
      }
      if (url.pathname === '/v1/admin/tokens/tok%2F1' && init?.method === 'DELETE') {
        return Promise.resolve(
          jsonResponse(
            200,
            tokenRecord({
              id: 'tok/1',
              revoked_at: '2026-07-04T12:00:00Z',
            }),
          ),
        );
      }
      if (
        url.pathname === '/v1/admin/tokens/tok%2F1/rotate' &&
        init?.method === 'POST'
      ) {
        return Promise.resolve(
          jsonResponse(200, {
            plaintext_token: 'ggw_plaintext_rotated',
            plaintext_token_notice:
              'Save this token now; the plaintext will not be shown again.',
            token: tokenRecord({ id: 'tok/1', token_prefix: 'ggw_rotated' }),
          }),
        );
      }

      return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
    });
    vi.stubGlobal('fetch', fetch);

    await expect(getToken('tok/1')).resolves.toMatchObject({ id: 'tok/1' });
    await expect(revokeToken('tok/1')).resolves.toMatchObject({
      revoked_at: '2026-07-04T12:00:00Z',
    });
    await expect(rotateToken('tok/1')).resolves.toMatchObject({
      plaintext_token: 'ggw_plaintext_rotated',
      token: { token_prefix: 'ggw_rotated' },
    });
    expect(calls).toEqual([
      { path: '/v1/admin/tokens/tok%2F1', method: undefined },
      { path: '/v1/admin/tokens/tok%2F1', method: 'DELETE' },
      { path: '/v1/admin/tokens/tok%2F1/rotate', method: 'POST' },
    ]);
  });
});

function tokenRecord(overrides: Record<string, unknown> = {}) {
  return {
    id: 'tok_active',
    token_prefix: 'ggw_1234567890',
    scopes: ['admin:tokens:read'],
    created_by: 'admin@example.test',
    created_at: '2026-07-04T10:00:00Z',
    ...overrides,
  };
}

function requestHeader(
  headers: HeadersInit | undefined,
  name: string,
): string | null {
  if (!headers) {
    return null;
  }
  if (headers instanceof Headers) {
    return headers.get(name);
  }
  if (Array.isArray(headers)) {
    return headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? null;
  }

  return headers[name] ?? null;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
