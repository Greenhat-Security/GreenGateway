import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import {
  fetchStoredPolicyTests,
  sameSuite,
  storePolicyTests,
  suiteCaseCounts,
} from './policyTests';

const SUITE_ETAG = '"sha256:suite-3"';
const STORED = {
  schema_version: 'policy-tests.v1',
  cases: [
    { id: 'a', kind: 'http', request: { method: 'GET', path: '/x' }, expect: { logical: 'deny' } },
  ],
};

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('stored policy test suite client', () => {
  it('reads the stored suite with its strong ETag and version', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(200, STORED, {
          ETag: SUITE_ETAG,
          'X-GreenGateway-Policy-Tests-Version': '3',
          'Cache-Control': 'private, no-store',
        }),
      ),
    );
    vi.stubGlobal('fetch', fetch);

    const read = await fetchStoredPolicyTests();

    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toBe('/v1/admin/policy/tests');
    expect(init?.method ?? 'GET').toBe('GET');
    expect(init?.cache).toBe('no-store');
    expect(read).toEqual({
      kind: 'stored',
      etag: SUITE_ETAG,
      version: 3,
      source: JSON.stringify(STORED, null, 2),
    });
  });

  it('answers none only for policy_tests_not_found', async () => {
    const answers = [
      jsonResponse(404, { error: 'no policy test suite is stored', reason: 'policy_tests_not_found' }),
      jsonResponse(404, { error: 'no policy is configured' }),
      jsonResponse(503, { error: 'unavailable', reason: 'policy_tests_unavailable' }),
      // A stored suite without its version or with a weak tag is not one.
      jsonResponse(200, STORED, { ETag: 'W/"sha256:suite-3"', 'X-GreenGateway-Policy-Tests-Version': '3' }),
    ];
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(answers.shift() as Response)));

    await expect(fetchStoredPolicyTests()).resolves.toEqual({ kind: 'none' });
    await expect(fetchStoredPolicyTests()).rejects.toMatchObject({ status: 404, code: 'request_failed' });
    await expect(fetchStoredPolicyTests()).rejects.toMatchObject({
      status: 503,
      code: 'policy_tests_unavailable',
    });
    await expect(fetchStoredPolicyTests()).rejects.toBeInstanceOf(AdminApiError);
  });

  it('stores the first suite under If-None-Match and a replacement under If-Match, never both', async () => {
    const answers = [
      jsonResponse(201, STORED, { ETag: SUITE_ETAG, 'X-GreenGateway-Policy-Tests-Version': '1' }),
      jsonResponse(200, STORED, { ETag: SUITE_ETAG, 'X-GreenGateway-Policy-Tests-Version': '2' }),
    ];
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(answers.shift() as Response),
    );
    vi.stubGlobal('fetch', fetch);
    const source = JSON.stringify(STORED, null, 2);

    const first = await storePolicyTests({ source, precondition: { kind: 'first' } });
    const second = await storePolicyTests({
      source,
      precondition: { kind: 'replace', etag: '"sha256:suite-1"' },
    });

    const [url, firstInit] = fetch.mock.calls[0];
    expect(String(url)).toBe('/v1/admin/policy/tests');
    expect(firstInit?.method).toBe('PUT');
    const firstHeaders = new Headers(firstInit?.headers);
    expect(firstHeaders.get('If-None-Match')).toBe('*');
    expect(firstHeaders.has('If-Match')).toBe(false);
    expect(firstInit?.body).toBe(source);
    const secondHeaders = new Headers(fetch.mock.calls[1][1]?.headers);
    expect(secondHeaders.get('If-Match')).toBe('"sha256:suite-1"');
    expect(secondHeaders.has('If-None-Match')).toBe(false);
    expect(first).toMatchObject({ kind: 'stored', created: true, stored: { version: 1, etag: SUITE_ETAG } });
    expect(second).toMatchObject({ kind: 'stored', created: false, stored: { version: 2 } });
  });

  it('returns policy_tests_invalid diagnostics as a refusal and stores nothing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(422, {
            error: 'policy test suite is invalid',
            reason: 'policy_tests_invalid',
            diagnostics: [{ code: 'missing_field', pointer: '/cases/0/expect', message: 'A required member is missing.' }],
            diagnostics_truncated: false,
          }),
        ),
      ),
    );
    await expect(
      storePolicyTests({ source: JSON.stringify(STORED), precondition: { kind: 'first' } }),
    ).resolves.toMatchObject({
      kind: 'refused',
      refusal: { reason: 'policy_tests_invalid', diagnostics: [{ pointer: '/cases/0/expect' }] },
    });
  });

  it('reports the required-suite active status after a save', async () => {
    const answers = [
      jsonResponse(200, STORED, {
        ETag: SUITE_ETAG,
        'X-GreenGateway-Policy-Tests-Version': '4',
        'X-GreenGateway-Policy-Tests-Active-Status': 'failed',
      }),
      jsonResponse(200, STORED, { ETag: SUITE_ETAG, 'X-GreenGateway-Policy-Tests-Version': '5' }),
    ];
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(answers.shift() as Response)));
    const request = {
      source: JSON.stringify(STORED),
      precondition: { kind: 'replace' as const, etag: SUITE_ETAG },
    };
    await expect(storePolicyTests(request)).resolves.toMatchObject({ activeStatus: 'failed' });
    await expect(storePolicyTests(request)).resolves.toMatchObject({ activeStatus: null });
  });

  it('does not count storing a suite as a live policy change', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(201, STORED, { ETag: SUITE_ETAG, 'X-GreenGateway-Policy-Tests-Version': '1' }),
        ),
      ),
    );
    await storePolicyTests({ source: JSON.stringify(STORED), precondition: { kind: 'first' } });
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });

  it('compares suites structurally, ignoring member order and whitespace', () => {
    const reordered = `{"cases":[{"expect":{"logical":"deny"},"request":{"path":"/x","method":"GET"},"kind":"http","id":"a"}],
      "schema_version":"policy-tests.v1"}`;
    expect(sameSuite(JSON.stringify(STORED, null, 2), reordered)).toBe(true);
    expect(sameSuite(JSON.stringify(STORED), reordered.replace('"/x"', '"/y"'))).toBe(false);
    // Case order is meaning, not formatting.
    const two = { ...STORED, cases: [STORED.cases[0], { ...STORED.cases[0], id: 'b' }] };
    const swapped = { ...STORED, cases: [two.cases[1], two.cases[0]] };
    expect(sameSuite(JSON.stringify(two), JSON.stringify(swapped))).toBe(false);
    expect(sameSuite('not json', 'not json')).toBe(false);
  });

  it('counts a suite’s cases by kind', () => {
    const suite = {
      schema_version: 'policy-tests.v1',
      cases: [{ kind: 'http' }, { kind: 'http' }, { kind: 'tool' }, { kind: 'egress' }, { kind: 7 }],
    };
    expect(suiteCaseCounts(JSON.stringify(suite))).toEqual({
      total: 5,
      byKind: [
        { kind: 'egress', count: 1 },
        { kind: 'http', count: 2 },
        { kind: 'tool', count: 1 },
        { kind: 'unknown', count: 1 },
      ],
    });
    expect(suiteCaseCounts('{')).toBeNull();
  });
});

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
