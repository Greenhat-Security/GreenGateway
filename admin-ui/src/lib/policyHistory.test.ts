import { afterEach, describe, expect, it, vi } from 'vitest';

import { rollbackPolicy } from './policyHistory';

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
});

describe('policy rollback', () => {
  it('sends the CSRF token on a cookie-session rollback', async () => {
    document.cookie = 'csrf_token=token-123; Path=/';
    const observed: Headers[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        observed.push(new Headers(init?.headers));
        return Promise.resolve(
          new Response(JSON.stringify({ schema_version: '1' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      }),
    );

    await rollbackPolicy(3, '"policy:v1"');

    expect(observed[0].get('x-csrf-token')).toBe('token-123');
  });
});
