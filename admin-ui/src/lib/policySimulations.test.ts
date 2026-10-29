import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import { projectSimulationResult, runPolicySimulation } from './policySimulations';

const LIVE_ETAG = '"sha256:live-1"';

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('policy simulation client', () => {
  it('sends the candidate as its exact text beside the serialized request', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(200, simulationResult())),
    );
    vi.stubGlobal('fetch', fetch);
    const source = '{ "schema_version": "1.0.0",\n  "rules": [] }';

    const answer = await runPolicySimulation({
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'inline', source },
      trace: 'full',
      projections: ['as_authored', 'enforce_all_shadow'],
      cases: [{ id: 'reader', kind: 'http', request: { method: 'GET', path: '/orders/1' }, principal: 'anonymous' }],
    });

    expect(answer.kind).toBe('result');
    const [input, init] = fetch.mock.calls[0];
    expect(String(input)).toBe('/v1/admin/policy/simulations');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(
      `{"schema_version":"policy-simulation.v1","base_etag":${JSON.stringify(LIVE_ETAG)},` +
        `"candidate":{"source":"inline","policy":${source}},"trace":"full",` +
        '"projections":["as_authored","enforce_all_shadow"],' +
        '"cases":[{"id":"reader","kind":"http","request":{"method":"GET","path":"/orders/1"},"principal":"anonymous"}]}',
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({ candidate: { policy: { rules: [] } } });
  });

  it('refuses to splice a candidate that is not one JSON object', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    await expect(
      runPolicySimulation({
        baseEtag: LIVE_ETAG,
        candidate: { kind: 'inline', source: '{"a":1},"cases":[]' },
        trace: 'terminal',
        projections: ['as_authored'],
        cases: [],
      }),
    ).rejects.toThrow('not a JSON object');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('reads a 422 as a refusal and every other failure as an error', async () => {
    const answers = [
      jsonResponse(422, {
        error: 'candidate policy is invalid',
        reason: 'policy_candidate_invalid',
        errors: ['/rules/0/path: invalid path'],
      }),
      jsonResponse(412, {
        error: 'stale',
        reason: 'policy_simulation_base_stale',
        current_etag: '"sha256:live-2"',
      }),
      jsonResponse(200, { ...simulationResult(), mode: 'historical_replay' }),
    ];
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(answers.shift() as Response)));
    const request = {
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'active' } as const,
      trace: 'terminal' as const,
      projections: ['as_authored'] as const,
      cases: [],
    };

    await expect(runPolicySimulation(request)).resolves.toEqual({
      kind: 'refused',
      refusal: expect.objectContaining({
        reason: 'policy_candidate_invalid',
        errors: ['/rules/0/path: invalid path'],
      }),
    });
    const stale = await runPolicySimulation(request).catch((error: unknown) => error);
    expect(stale).toBeInstanceOf(AdminApiError);
    expect((stale as AdminApiError).code).toBe('policy_simulation_base_stale');
    await expect(runPolicySimulation(request)).rejects.toThrow('unreadable simulation result');
  });

  it('keeps an unreported match apart from no match, and the three answers apart', () => {
    const result = projectSimulationResult(simulationResult());
    expect(result).not.toBeNull();
    const [authored, enforced] = result!.cases[0].results;
    expect(authored.base).toMatchObject({
      logical: 'allow',
      enforcement: 'not_applicable',
      effective_action: 'would_forward',
      matched: { kind: 'route', position: 0, permission: 'orders:read', permission_granted: true },
    });
    expect(authored.candidate).toMatchObject({
      logical: 'deny',
      enforcement: 'shadowed',
      effective_action: 'would_forward',
      matched: { kind: 'rule', position: 0, id: 'watch-orders', action: 'shadow' },
    });
    expect(authored.changed).toBe(true);
    expect(enforced.candidate.enforcement).toBe('enforced');

    const terminal = projectSimulationResult(
      simulationResult({ trace: 'terminal', withMatched: false }),
    );
    expect(terminal!.cases[0].results[0].candidate.matched).toBeUndefined();
    expect('matched' in terminal!.cases[0].results[0].candidate).toBe(false);

    const unmatched = simulationResult();
    (unmatched.cases[0].results[0].candidate as Record<string, unknown>).matched = null;
    expect(projectSimulationResult(unmatched)!.cases[0].results[0].candidate.matched).toBeNull();
  });

  it('refuses a result whose decision is not one of the stated answers', () => {
    const broken = simulationResult();
    (broken.cases[0].results[0].candidate as Record<string, unknown>).effective_action = 'allow';
    expect(projectSimulationResult(broken)).toBeNull();
    const rate = simulationResult();
    rate.cases[0].results[0].candidate = { lane: 'rate_selection', selected: 'override', complete: true };
    expect(projectSimulationResult(rate)).toBeNull();
  });

  it('does not count a simulation as a live policy change', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(200, simulationResult()))));
    await runPolicySimulation({
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'active' },
      trace: 'matched',
      projections: ['as_authored'],
      cases: [],
    });
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });
});

function simulationResult({
  trace = 'matched',
  withMatched = true,
}: { trace?: string; withMatched?: boolean } = {}) {
  const decision = (overrides: Record<string, unknown>) => ({
    lane: 'http',
    complete: true,
    ...overrides,
  });
  const matched = (value: unknown) => (withMatched ? { matched: value, observation: null } : {});
  return {
    schema_version: 'policy-simulation-results.v1',
    mode: 'synthetic',
    request_digest: 'sha256:request',
    evaluator: {
      http_semantics_version: 'gg-http-alias-v1',
      http_context_version: 3,
      tool_semantics_version: 'gg-tool-policy-v1',
      tool_context_version: 1,
      gateway_version: '1.0.1',
    },
    base: { source: 'active', etag: LIVE_ETAG },
    candidate: { source: 'inline', etag: '"sha256:candidate"' },
    trace: { level: trace, max_stages: 4096, stages_truncated: false },
    projections: ['as_authored', 'enforce_all_shadow'],
    not_evaluated: ['authentication', 'csrf'],
    summary: {
      cases: 1,
      projections: {
        as_authored: counts({ would_forward: 1, shadowed: 1, changed_from_base: 1 }),
        enforce_all_shadow: counts({ would_block: 1, changed_from_base: 1 }),
      },
      projection_changed: 1,
    },
    cases: [
      {
        id: 'reader',
        pointer: '/cases/0',
        kind: 'http',
        results: [
          {
            projection: 'as_authored',
            base: decision({
              logical: 'allow',
              enforcement: 'not_applicable',
              effective_action: 'would_forward',
              reason: 'matched_rule',
              ...matched({ kind: 'route', position: 0, permission: 'orders:read', permission_granted: true }),
            }),
            changed: true,
            candidate: decision({
              logical: 'deny',
              enforcement: 'shadowed',
              effective_action: 'would_forward',
              reason: 'matched_rule',
              ...matched({ kind: 'rule', position: 0, id: 'watch-orders', action: 'shadow' }),
            }) as Record<string, unknown>,
          },
          {
            projection: 'enforce_all_shadow',
            base: decision({
              logical: 'allow',
              enforcement: 'not_applicable',
              effective_action: 'would_forward',
              reason: 'matched_rule',
            }),
            changed: true,
            candidate: decision({
              logical: 'deny',
              enforcement: 'enforced',
              effective_action: 'would_block',
              reason: 'matched_rule',
            }),
          },
        ],
        projection_changed: true,
      },
    ],
  };
}

function counts(overrides: Record<string, number>) {
  return {
    would_forward: 0,
    would_block: 0,
    unknown: 0,
    shadowed: 0,
    rate_override: 0,
    no_rate_override: 0,
    rate_unknown: 0,
    ...overrides,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
