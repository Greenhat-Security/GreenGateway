import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createPolicyRule,
  deletePolicyRule,
  patchPolicyRule,
  reorderPolicyRules,
} from './policy';

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
});

describe('policy writes', () => {
  it.each([
    [
      'create',
      () => createPolicyRule({ action: 'deny' }, '"policy:v1"'),
    ],
    [
      'patch',
      () => patchPolicyRule('rule-1', '"policy:v1"', { enabled: false }),
    ],
    ['delete', () => deletePolicyRule('rule-1', '"policy:v1"')],
    ['reorder', () => reorderPolicyRules(['rule-1'], '"policy:v1"')],
  ])(
    'sends the CSRF token on a cookie-session %s',
    async (_name, mutate) => {
      document.cookie = 'csrf_token=token-123; Path=/';
      const observed: Headers[] = [];
      vi.stubGlobal(
        'fetch',
        vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
          observed.push(new Headers(init?.headers));
          return Promise.resolve(jsonResponse(200, {}));
        }),
      );

      await mutate();

      expect(observed[0].get('x-csrf-token')).toBe('token-123');
    },
  );
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
