import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearMemoryToken, getMemoryToken, setMemoryToken } from './auth';
import { subscribeToAuditEvents } from './eventStream';
import { registerOpenApiTools } from './openapiTools';

const canary = () => `test-${crypto.randomUUID()}`;
afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
  document.querySelectorAll('meta[data-auth-test]').forEach((meta) => meta.remove());
  document.cookie = 'custom_csrf=; Max-Age=0; Path=/';
});
function stream() {
  return subscribeToAuditEvents('/v1/admin/events/stream', {
    signal: new AbortController().signal,
    onEvent: () => { throw new Error('Unexpected stale event'); },
  });
}

describe('admin session boundaries outside JSON transport', () => {
  it.each(['stream', 'registration'])('clears memory on a current %s 401', async (kind) => {
    setMemoryToken(canary());
    const fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 401 }));
    vi.stubGlobal('fetch', fetch);
    await expect(kind === 'stream' ? stream() : registerOpenApiTools('{}', [], '"etag"')).rejects.toMatchObject({ status: 401 });
    expect(getMemoryToken()).toBeNull();
    expect(fetch.mock.calls[0][1]).toMatchObject({ credentials: 'omit', redirect: 'error' });
  });

  it.each(['stream', 'registration'])('discards an old %s response without clearing the replacement identity', async (kind) => {
    let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise<Response>((done) => { resolve = done; })));
    setMemoryToken(canary());
    const pending = kind === 'stream' ? stream() : registerOpenApiTools('{}', [], '"etag"');
    const current = canary();
    setMemoryToken(current);
    resolve(new Response('{}', { status: 401 }));
    await expect(pending).rejects.toThrow();
    expect(getMemoryToken() === current).toBe(true);
  });

  it('uses the configured prefix and CSRF names for cookie-authenticated registration', async () => {
    for (const [name, content] of [
      ['greengateway-admin-api-base', '/v1/ops'],
      ['greengateway-csrf-cookie-name', 'custom_csrf'],
      ['greengateway-csrf-header-name', 'x-custom-csrf'],
    ]) {
      const meta = document.createElement('meta');
      meta.name = name; meta.content = content; meta.dataset.authTest = '';
      document.head.append(meta);
    }
    document.cookie = 'custom_csrf=test-csrf; Path=/';
    const fetch = vi.fn().mockResolvedValue(new Response('{}'));
    vi.stubGlobal('fetch', fetch);
    await registerOpenApiTools('{}', [], '"etag"');
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe('/v1/ops/tools/openapi/register');
    expect(init.credentials).toBe('same-origin');
    expect(new Headers(init.headers).get('x-custom-csrf')).toBe('test-csrf');
    expect(new Headers(init.headers).has('Authorization')).toBe(false);
  });
});
