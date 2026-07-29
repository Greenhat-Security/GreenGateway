import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  AdminApiError,
  adminFetchJson,
  adminFetchResource,
} from './api';
import { ADMIN_TOKEN_STORAGE_KEY } from './auth';

afterEach(() => {
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
  document.cookie = 'custom_csrf=; Max-Age=0; Path=/';
  document
    .querySelectorAll(
      'meta[name="greengateway-csrf-cookie-name"], meta[name="greengateway-csrf-header-name"]',
    )
    .forEach((element) => element.remove());
});

describe('admin API transport', () => {
  it('captures resource and collection ETags without exposing response bodies', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            200,
            { id: 'connection-1' },
            {
              ETag: '"connection:v2"',
              'x-greengateway-connections-etag': '"connections:v4"',
            },
          ),
        ),
      ),
    );

    await expect(adminFetchResource<{ id: string }>('/resource')).resolves.toEqual({
      value: { id: 'connection-1' },
      etag: '"connection:v2"',
      collectionEtag: '"connections:v4"',
    });
  });

  it('uses the secret collection ETag header for conditional secret workflows', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            201,
            { id: 'secret-1' },
            {
              ETag: '"connection-secret:secret-1:v1"',
              'x-greengateway-connection-secrets-etag':
                '"connection-secrets:v2"',
            },
          ),
        ),
      ),
    );

    const resource = await adminFetchResource<{ id: string }>('/secret', {
      method: 'POST',
    });
    expect(resource.etag).toBe('"connection-secret:secret-1:v1"');
    expect(resource.collectionEtag).toBe('"connection-secrets:v2"');
  });

  it.each([
    [409, 'conflict'],
    [412, 'precondition_failed'],
    [428, 'precondition_required'],
  ])('preserves the distinct %i concurrency response', async (status, code) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            status,
            {
              error: `safe ${code} message`,
              problems: [
                { field: 'endpoint.base_url', code: 'invalid_scheme' },
                { malformed: true },
              ],
              details: {
                dependency_count: 2,
                value: 'UNEXPECTED_ERROR_PLAINTEXT_CANARY',
                ciphertext: 'UNEXPECTED_ERROR_CIPHERTEXT_CANARY',
                locator: 'UNEXPECTED_ERROR_LOCATOR_CANARY',
              },
            },
            { ETag: '"current"' },
          ),
        ),
      ),
    );

    const error = await adminFetchJson('/mutation').catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(AdminApiError);
    expect(error).toMatchObject({
      status,
      code,
      message: `safe ${code} message`,
      problems: [{ field: 'endpoint.base_url', code: 'invalid_scheme' }],
      details: { dependency_count: 2 },
      etag: '"current"',
    });
    expect((error as AdminApiError).details).toEqual({
      dependency_count: 2,
    });
  });

  it('reads dynamic CSRF names and sends the matching cookie on session mutations', async () => {
    appendMeta('greengateway-csrf-cookie-name', 'custom_csrf');
    appendMeta('greengateway-csrf-header-name', 'x-custom-csrf');
    document.cookie = 'custom_csrf=token-123; Path=/';

    const fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('x-custom-csrf')).toBe('token-123');
      expect(init?.credentials).toBe('same-origin');
      return Promise.resolve(jsonResponse(200, { ok: true }));
    });
    vi.stubGlobal('fetch', fetch);

    await adminFetchJson('/mutation', { method: 'POST' });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('does not copy a CSRF cookie into safe or bearer-authenticated requests', async () => {
    document.cookie = 'csrf_token=token-123; Path=/';
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, 'admin-token');
    const observed: Headers[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        observed.push(new Headers(init?.headers));
        return Promise.resolve(jsonResponse(200, { ok: true }));
      }),
    );

    await adminFetchJson('/read');
    await adminFetchJson('/mutation', { method: 'POST' });

    expect(observed[0].has('x-csrf-token')).toBe(false);
    expect(observed[1].get('Authorization')).toBe('Bearer admin-token');
    expect(observed[1].has('x-csrf-token')).toBe(false);
  });
});

function appendMeta(name: string, content: string): void {
  const meta = document.createElement('meta');
  meta.name = name;
  meta.content = content;
  document.head.append(meta);
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
