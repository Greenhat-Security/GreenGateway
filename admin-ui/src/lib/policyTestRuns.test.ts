import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { clearMemoryToken } from './auth';
import { projectTestReport, runPolicyTests } from './policyTestRuns';

const LIVE_ETAG = '"sha256:live-1"';
const SUITE = '{"schema_version":"policy-tests.v1","cases":[{"id":"a"}]}';

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('policy test run client', () => {
  it('pins the live policy with If-Match, and sends a candidate as written without one', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(200, report())),
    );
    vi.stubGlobal('fetch', fetch);

    await runPolicyTests({ suiteSource: SUITE, candidate: { kind: 'active' }, liveEtag: LIVE_ETAG });
    const candidate = '{"schema_version":"1.0.0", "rules":[]}';
    await runPolicyTests({
      suiteSource: SUITE,
      candidate: { kind: 'inline', source: candidate },
      liveEtag: LIVE_ETAG,
    });

    const [activeUrl, active] = fetch.mock.calls[0];
    expect(String(activeUrl)).toBe('/v1/admin/policy/tests/runs');
    expect(new Headers(active?.headers).get('If-Match')).toBe(LIVE_ETAG);
    expect(active?.body).toBe(`{"suite":${SUITE},"format":"json"}`);
    const [, inline] = fetch.mock.calls[1];
    expect(new Headers(inline?.headers).has('If-Match')).toBe(false);
    expect(inline?.body).toBe(`{"suite":${SUITE},"policy":${candidate},"format":"json"}`);
  });

  it('reads a completed run as a report whatever its outcome, and a 422 as a refusal', async () => {
    const answers = [
      jsonResponse(200, report()),
      jsonResponse(422, {
        error: 'policy test suite is invalid',
        reason: 'policy_tests_invalid',
        diagnostics: [{ code: 'missing_field', pointer: '/cases/0/expect', message: 'A required member is missing.' }],
        diagnostics_truncated: false,
      }),
    ];
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(answers.shift() as Response)));
    const request = { suiteSource: SUITE, candidate: { kind: 'active' } as const, liveEtag: LIVE_ETAG };

    const first = await runPolicyTests(request);
    expect(first.kind).toBe('report');
    if (first.kind === 'report') {
      expect(first.report.status).toBe('failed');
      expect(first.report.cases[0]).toMatchObject({
        status: 'failed',
        expected: { logical: 'deny', effect: 'block' },
        actual: { logical: 'deny', effect: 'observe', matched: { route: 0 }, complete: true },
        mismatches: ['effect'],
      });
      expect(first.report.cases[1]).toMatchObject({ status: 'error', actual: null, error: 'malformed_path' });
      expect(first.report.cases[2].expected).toEqual({ rate_override: null });
    }
    await expect(runPolicyTests(request)).resolves.toMatchObject({
      kind: 'refused',
      refusal: { reason: 'policy_tests_invalid', diagnostics: [{ pointer: '/cases/0/expect' }] },
    });
  });

  it('refuses a report whose cases contradict their status', () => {
    const refusedWithAnswer = report();
    (refusedWithAnswer.cases[1] as Record<string, unknown>).actual = {
      logical: 'allow',
      complete: true,
      limitation: null,
    };
    expect(projectTestReport(refusedWithAnswer)).toBeNull();
    const unknownMismatch = report();
    unknownMismatch.cases[0].mismatches = ['everything'];
    expect(projectTestReport(unknownMismatch)).toBeNull();
    expect(projectTestReport({ ...report(), status: 'ok' })).toBeNull();
  });

  it('does not count a test run as a live policy change', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(200, report()))));
    await runPolicyTests({ suiteSource: SUITE, candidate: { kind: 'active' }, liveEtag: LIVE_ETAG });
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });
});

function report() {
  return {
    schema_version: 'policy-test-results.v1',
    status: 'failed',
    mode: 'test',
    suite: { schema_version: 'policy-tests.v1', digest: 'sha256:suite' },
    policy: { source: 'active', etag: LIVE_ETAG },
    evaluator: { http_semantics_version: 'gg-http-alias-v1' },
    gateway_version: '1.0.1',
    not_evaluated: ['authentication', 'csrf'],
    summary: { total: 3, passed: 1, failed: 1, incomplete: 0, errors: 1 },
    cases: [
      {
        id: 'anonymous-blocked',
        pointer: '/cases/0',
        kind: 'http',
        status: 'failed',
        expected: { logical: 'deny', effect: 'block' },
        actual: {
          logical: 'deny',
          effect: 'observe',
          reason: 'missing_principal',
          matched: { route: 0 },
          complete: true,
          limitation: null,
        },
        mismatches: ['effect'],
      },
      {
        id: 'refused',
        pointer: '/cases/1',
        kind: 'tool_http',
        status: 'error',
        expected: { logical: 'allow' },
        mismatches: [],
        error: 'malformed_path',
      },
      {
        id: 'rate',
        pointer: '/cases/2',
        kind: 'rate',
        status: 'passed',
        expected: { rate_override: null },
        actual: { rate_override: null, complete: true, limitation: null },
        mismatches: [],
      },
    ] as Array<Record<string, unknown> & { mismatches: string[] }>,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
