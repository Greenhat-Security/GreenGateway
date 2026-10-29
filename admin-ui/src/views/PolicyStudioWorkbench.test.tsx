import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { clearMemoryToken } from '../lib/auth';
import { PolicyStudioView } from './PolicyStudioView';

const DRAFT_ID = `pd_${'a'.repeat(32)}`;
const JOB_ID = `rpl_${'b'.repeat(32)}`;
const LIVE_ETAG = '"sha256:live-1"';
const READ = 'admin:policy:read';
const WRITE = 'admin:policy:write';
const SIMULATE = 'admin:policy:simulate';
const AUDIT = 'admin:audit:read';
const WAIT = { timeout: 4000 };
const SNAPSHOT_DIGEST = `sha256:${'0'.repeat(64)}`;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearMemoryToken();
});

describe('Policy Studio workbench', () => {
  it('simulates the unsaved draft against the live revision and shows each answer as a waterfall', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'unsaved-id' } });

    openView('Simulate');
    const panel = viewPanel('Simulate');
    expect((screen.getByRole('radio', { name: /The open draft/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(panel).getByRole('button', { name: 'Add case' }));
    fireEvent.change(within(panel).getByLabelText('Request path'), {
      target: { value: '/billing/7' },
    });
    fireEvent.click(within(panel).getByRole('button', { name: 'Run simulation' }));

    expect(await within(panel).findByText('Simulation result', undefined, WAIT)).toBeTruthy();
    const [request] = gateway.requests('POST', '/v1/admin/policy/simulations');
    const body = JSON.parse(request.body ?? '{}') as Record<string, unknown>;
    expect(body).toMatchObject({
      schema_version: 'policy-simulation.v1',
      base_etag: LIVE_ETAG,
      candidate: { source: 'inline', policy: { id: 'unsaved-id' } },
      trace: 'matched',
      projections: ['as_authored', 'enforce_all_shadow'],
    });
    expect(body.cases).toEqual([
      {
        id: 'case-1',
        kind: 'http',
        request: { method: 'GET', path: '/billing/7' },
        principal: { subject: 'synthetic-caller', roles: [], auth_method: 'bearer_token' },
      },
    ]);
    // The candidate travels as the exact text on screen.
    expect(request.body).toContain(`"policy":${JSON.stringify({ ...draftPolicy(), id: 'unsaved-id' }, null, 2)}`);

    const authored = within(panel).getByRole('region', { name: 'As authored, case case-1' });
    const candidate = within(authored).getByRole('list', { name: 'Candidate: decision' });
    expect(within(candidate).getByText('✕ Deny')).toBeTruthy();
    expect(within(candidate).getByText('Shadow: a would-deny that is only observed')).toBeTruthy();
    expect(within(candidate).getByText('→ Would forward')).toBeTruthy();
    expect(within(authored).getByText(/A shadowed deny is still a deny, never an allow/)).toBeTruthy();
    expect(within(authored).getByText(/rule #1 \(position 0\), id watch-billing, action shadow/)).toBeTruthy();
    const live = within(authored).getByRole('list', { name: 'Live policy: decision' });
    expect(within(live).getByText('✓ Allow')).toBeTruthy();
    expect(within(panel).getByText('Δ Changed from live')).toBeTruthy();
    const enforced = within(panel).getByRole('region', { name: 'Every shadow enforced, case case-1' });
    expect(within(enforced).getByText('■ Would block')).toBeTruthy();

    // The answer becomes the case's expectation, and the Test view runs it.
    fireEvent.click(within(panel).getByRole('button', { name: 'Expect the answer for case case-1 in tests' }));
    openView('Test');
    const tests = viewPanel('Test');
    expect((within(tests).getByLabelText('Expected decision') as HTMLSelectElement).value).toBe('deny');
    expect((within(tests).getByLabelText('Expected effect') as HTMLSelectElement).value).toBe('observe');
    fireEvent.click(within(tests).getByRole('button', { name: 'Run tests' }));

    expect(await within(tests).findByText('Test report', undefined, WAIT)).toBeTruthy();
    const [run] = gateway.requests('POST', '/v1/admin/policy/tests/runs');
    expect(run.headers.has('If-Match')).toBe(false);
    expect(JSON.parse(run.body ?? '{}')).toMatchObject({
      format: 'json',
      policy: { id: 'unsaved-id' },
      suite: {
        schema_version: 'policy-tests.v1',
        cases: [
          {
            id: 'case-1',
            expect: {
              logical: 'deny',
              effect: 'observe',
              reason: 'matched_rule',
              matched: { rule: 'watch-billing' },
            },
          },
        ],
      },
    });
    expect(within(tests).getAllByText('✓ Passed').length).toBeGreaterThan(0);
    // Nothing the workbench did is a write.
    expect(gateway.log.filter((entry) => entry.method === 'PATCH' || entry.method === 'PUT')).toEqual([]);
    expect(gateway.live.policy).toEqual(draftPolicy());
  });

  it('offers runs only for the permissions the server reports', async () => {
    const gateway = fakeGateway({ permissions: [READ, WRITE] });
    renderStudio(gateway);
    await openDraft();

    openView('Simulate');
    const simulate = viewPanel('Simulate');
    fireEvent.click(within(simulate).getByRole('button', { name: 'Add case' }));
    expect((within(simulate).getByRole('button', { name: 'Run simulation' }) as HTMLButtonElement).disabled).toBe(true);
    expect(
      within(simulate).getByText('Simulating needs admin:policy:read and admin:policy:simulate.'),
    ).toBeTruthy();

    openView('Impact');
    const impact = viewPanel('Impact');
    expect((within(impact).getByRole('button', { name: 'Start replay' }) as HTMLButtonElement).disabled).toBe(true);
    expect(
      within(impact).getByText(
        'Historical replay needs admin:policy:read, admin:policy:simulate and admin:audit:read.',
      ),
    ).toBeTruthy();
    expect(gateway.requests('POST', '/v1/admin/policy/simulations')).toHaveLength(0);
    expect(gateway.requests('POST', '/v1/admin/policy/replays')).toHaveLength(0);
  });

  it('reports a stale live revision and a refused case without a result', async () => {
    const gateway = fakeGateway();
    gateway.simulation = () =>
      jsonResponse(412, {
        error: 'stale',
        reason: 'policy_simulation_base_stale',
        current_etag: '"sha256:live-2"',
      });
    renderStudio(gateway);
    await openDraft();
    openView('Simulate');
    const panel = viewPanel('Simulate');
    fireEvent.click(within(panel).getByRole('button', { name: 'Add case' }));
    fireEvent.click(within(panel).getByRole('button', { name: 'Run simulation' }));

    expect(await within(panel).findByText('Live policy changed', undefined, WAIT)).toBeTruthy();
    const reads = gateway.requests('GET', '/v1/admin/policy').length;
    fireEvent.click(within(panel).getByRole('button', { name: 'Read the live policy again' }));
    await waitFor(() => expect(gateway.requests('GET', '/v1/admin/policy').length).toBe(reads + 1), WAIT);

    gateway.simulation = () =>
      jsonResponse(422, {
        error: 'policy simulation request is invalid',
        reason: 'policy_simulation_invalid',
        diagnostics: [
          { code: 'invalid_path', pointer: '/cases/0/request/path', message: 'The path is not a request path.' },
        ],
        diagnostics_truncated: false,
      });
    fireEvent.click(within(panel).getByRole('button', { name: 'Run simulation' }));

    expect(await within(panel).findByText('Simulation refused', undefined, WAIT)).toBeTruthy();
    expect(
      within(panel).getByText(/at case case-1 \(\/cases\/0\/request\/path\): The path is not a request path\./),
    ).toBeTruthy();
    expect(within(panel).getByRole('button', { name: 'Edit case case-1, 1 problem' })).toBeTruthy();
    expect(within(panel).queryByText('Simulation result')).toBeNull();
  });

  it('tests the live policy under If-Match and never reads an undecided case as a pass', async () => {
    const gateway = fakeGateway();
    gateway.testRun = () =>
      jsonResponse(200, {
        ...testReport('incomplete'),
        summary: { total: 1, passed: 0, failed: 0, incomplete: 1, errors: 0 },
        cases: [
          {
            id: 'case-1',
            pointer: '/cases/0',
            kind: 'http',
            status: 'incomplete',
            expected: { logical: 'allow' },
            actual: { logical: 'indeterminate', complete: false, limitation: 'missing_host_fact' },
            mismatches: ['logical'],
          },
        ],
      });
    renderStudio(gateway);
    await studioLoaded();
    openView('Test');
    expect((screen.getByRole('radio', { name: /The open draft/ }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('radio', { name: /The live policy/ }) as HTMLInputElement).checked).toBe(true);
    const tests = viewPanel('Test');
    fireEvent.click(within(tests).getByRole('button', { name: 'Add case' }));
    const run = within(tests).getByRole('button', { name: 'Run tests' }) as HTMLButtonElement;
    expect(run.disabled).toBe(true);
    expect(within(tests).getByText('Every case needs an expectation: case-1.')).toBeTruthy();

    fireEvent.change(within(tests).getByLabelText('Expected decision'), { target: { value: 'allow' } });
    expect(run.disabled).toBe(false);
    fireEvent.click(run);

    expect(await within(tests).findByText('Test report', undefined, WAIT)).toBeTruthy();
    const [request] = gateway.requests('POST', '/v1/admin/policy/tests/runs');
    expect(request.headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(JSON.parse(request.body ?? '{}')).not.toHaveProperty('policy');
    expect(within(tests).getAllByText('? Incomplete').length).toBeGreaterThan(0);
    expect(within(tests).getByText(/could not be decided\. An undecided case never passes/)).toBeTruthy();
    expect(within(tests).queryByText('✓ Passed')).toBeNull();
    expect(within(tests).getByText('missing_host_fact')).toBeTruthy();
  });

  it('replays a window as a job, polls it, and shows no data as its own state', async () => {
    const gateway = fakeGateway({ permissions: [READ, WRITE, SIMULATE, AUDIT] });
    renderStudio(gateway);
    await openDraft();
    openView('Impact');
    const impact = viewPanel('Impact');
    expect(within(impact).getByText(/shows\s+neither newly allowed nor newly denied traffic/)).toBeTruthy();
    fireEvent.change(within(impact).getByLabelText('Record bound'), { target: { value: '500' } });
    fireEvent.click(within(impact).getByRole('button', { name: 'Start replay' }));

    expect((await within(impact).findAllByText('… Queued', undefined, WAIT)).length).toBeGreaterThan(0);
    const [start] = gateway.requests('POST', '/v1/admin/policy/replays');
    const body = JSON.parse(start.body ?? '{}') as Record<string, unknown>;
    expect(body).toMatchObject({
      schema_version: 'policy-replay.v1',
      base_etag: LIVE_ETAG,
      candidate: { source: 'inline', policy: { id: 'billing-policy' } },
      max_records: 500,
    });
    expect(String(body.idempotency_key)).toMatch(/^studio-[0-9a-f]{32}$/);
    const window = body.window as { from: string; to?: string };
    expect(window.to).toBeUndefined();
    expect(Date.now() - Date.parse(window.from)).toBeGreaterThan(23 * 60 * 60 * 1000);

    expect(
      (await within(impact).findAllByText('◐ Completed, incomplete', undefined, { timeout: 6000 })).length,
    ).toBeGreaterThan(0);
    expect(gateway.requests('GET', `/v1/admin/policy/replays/${JOB_ID}`).length).toBeGreaterThan(0);
    expect(within(impact).getByText(/No decisions: nothing in this window could be replayed/)).toBeTruthy();
    expect(within(impact).getByText(/does not cover the whole window and satisfies no gate/)).toBeTruthy();
    expect(within(impact).getByText(/The live policy changed since this job was pinned/)).toBeTruthy();
    expect(within(impact).queryByRole('region', { name: 'HTTP decisions' })).toBeNull();

    fireEvent.click(within(impact).getByRole('button', { name: 'Discard replay' }));
    const confirmation = within(impact).getByRole('group', { name: 'Discard this replay?' });
    fireEvent.click(within(confirmation).getByRole('button', { name: 'Confirm discard' }));
    expect(await within(impact).findByText('No replay started in this page yet.', undefined, WAIT)).toBeTruthy();
    expect(gateway.requests('DELETE', `/v1/admin/policy/replays/${JOB_ID}`)).toHaveLength(1);
  });

  it('checks an unconfirmed replay start under the same key instead of starting another', async () => {
    const gateway = fakeGateway({ permissions: [READ, SIMULATE, AUDIT] });
    gateway.failNext('POST', '/v1/admin/policy/replays', new TypeError('Failed to fetch'));
    renderStudio(gateway);
    await studioLoaded();
    openView('Impact');
    const impact = viewPanel('Impact');
    fireEvent.click(within(impact).getByRole('button', { name: 'Start replay' }));

    expect(await within(impact).findByText('Replay start not confirmed', undefined, WAIT)).toBeTruthy();
    expect((within(impact).getByRole('button', { name: 'Start replay' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(impact).getByRole('button', { name: 'Check the unconfirmed replay' }));

    expect((await within(impact).findAllByText('… Queued', undefined, WAIT)).length).toBeGreaterThan(0);
    const starts = gateway.requests('POST', '/v1/admin/policy/replays');
    expect(starts).toHaveLength(2);
    expect(starts[1].body).toBe(starts[0].body);
    expect(JSON.parse(starts[0].body ?? '{}')).toMatchObject({ candidate: { source: 'active' } });
  });

  it('lists the validator findings for review and opens one in the draft editor', async () => {
    const gateway = fakeGateway();
    gateway.validate = () =>
      jsonResponse(200, {
        ...validInspection(),
        diagnostics: [
          {
            code: 'default_action_allow',
            severity: 'risk',
            pointer: '/default_action',
            message: 'Requests that no rule or route matches are allowed.',
            remediation: 'Set default_action to deny.',
            blocks: { simulation: false, tests: false, publication: false, evidence: false },
          },
        ],
      });
    renderStudio(gateway);
    await openDraft();
    await screen.findByText('Valid, with 1 risk.', undefined, WAIT);

    openView('Optimize');
    const optimize = viewPanel('Optimize');
    expect(within(optimize).getByText('Risks to review (1)')).toBeTruthy();
    expect(within(optimize).getByText('Set default_action to deny.')).toBeTruthy();
    expect(within(optimize).getByText(/is not available on this gateway yet/)).toBeTruthy();
    expect(within(optimize).getByText(/does not mean the policy has\s+none of those problems/)).toBeTruthy();
    fireEvent.click(
      within(optimize).getByRole('button', {
        name: 'Edit in the draft: default_action_allow at /default_action',
      }),
    );
    await waitFor(() =>
      expect(screen.getByRole('tab', { name: 'Edit' }).getAttribute('aria-selected')).toBe('true'),
    );
    expect(screen.getByRole('tab', { name: /Overview/ }).getAttribute('aria-selected')).toBe('true');

    // The live policy, as a candidate, is validated as the text it is.
    openView('Optimize');
    const validations = gateway.requests('POST', '/v1/admin/policy/validate').length;
    fireEvent.click(screen.getByRole('radio', { name: /The live policy/ }));
    await waitFor(
      () => expect(gateway.requests('POST', '/v1/admin/policy/validate').length).toBe(validations + 1),
      WAIT,
    );
    expect(gateway.requests('POST', '/v1/admin/policy/validate').at(-1)?.body).toBe(
      JSON.stringify(draftPolicy(), null, 2),
    );
    expect(within(viewPanel('Optimize')).queryByRole('button', { name: /Edit in the draft/ })).toBeNull();
  });

  it('keeps cases in page memory and asks before leaving with them', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const gateway = fakeGateway();
    renderStudio(gateway);
    await studioLoaded();
    openView('Simulate');
    const panel = viewPanel('Simulate');
    fireEvent.click(within(panel).getByRole('button', { name: 'Add case' }));
    fireEvent.change(within(panel).getByLabelText('Subject'), { target: { value: 'synthetic-auditor' } });
    fireEvent.click(within(panel).getByRole('button', { name: 'Run simulation' }));
    await within(panel).findByText('Simulation result', undefined, WAIT);

    fireEvent.click(screen.getByRole('link', { name: 'Rulebase' }));
    expect(confirm).toHaveBeenCalledWith(
      'Your simulation and test cases are kept only in this page. Leave the Policy Studio and discard them?',
    );
    expect(screen.getByRole('heading', { name: 'Policy Studio' })).toBeTruthy();
    expect(setItem).not.toHaveBeenCalled();
    for (const request of gateway.log) {
      expect(request.path).not.toContain('synthetic-auditor');
    }
  });
});

type LoggedRequest = {
  method: string;
  path: string;
  headers: Headers;
  body: string | null;
};

function fakeGateway({ permissions = [READ, WRITE, SIMULATE] }: { permissions?: string[] } = {}) {
  const gateway = {
    live: { policy: draftPolicy() as Record<string, unknown>, etag: LIVE_ETAG },
    log: [] as LoggedRequest[],
    failures: [] as Array<{ method: string; path: string; error: Error }>,
    validate: (_source: string): Response => jsonResponse(200, validInspection()),
    simulation: (body: string): Response => jsonResponse(200, simulationResult(body)),
    testRun: (): Response => jsonResponse(200, testReport('passed')),
    requests(method: string, path: string) {
      return gateway.log.filter((request) => request.method === method && request.path === path);
    },
    failNext(method: string, path: string, error: Error) {
      gateway.failures.push({ method, path, error });
    },
    fetch: vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? init.body : null;
      const headers = new Headers(init?.headers);
      gateway.log.push({ method, path: url.pathname, headers, body });
      const failure = gateway.failures.findIndex(
        (entry) => entry.method === method && entry.path === url.pathname,
      );
      if (failure >= 0) {
        const [{ error }] = gateway.failures.splice(failure, 1);
        return Promise.reject(error);
      }
      return Promise.resolve(gateway.answer(method, url.pathname, body));
    }),
    answer(method: string, path: string, body: string | null): Response {
      if (path === '/v1/admin/capabilities') {
        return jsonResponse(200, { permissions });
      }
      if (path === '/v1/admin/policy' && method === 'GET') {
        return jsonResponse(200, gateway.live.policy, { ETag: gateway.live.etag });
      }
      if (path === '/v1/admin/policy/validate') {
        return gateway.validate(body ?? '');
      }
      if (path === '/v1/admin/policy/simulations') {
        return gateway.simulation(body ?? '{}');
      }
      if (path === '/v1/admin/policy/tests/runs') {
        return gateway.testRun();
      }
      if (path === '/v1/admin/policy/replays' && method === 'POST') {
        return jsonResponse(202, replayJob('queued'));
      }
      if (path === `/v1/admin/policy/replays/${JOB_ID}`) {
        if (method === 'DELETE') {
          return new Response(null, { status: 204 });
        }
        return jsonResponse(200, replayJob('completed_incomplete'));
      }
      if (path === '/v1/admin/policy/drafts' && method === 'GET') {
        const { policy: _policy, ...summary } = draftView();
        return jsonResponse(200, {
          drafts: [summary],
          limits: {
            ttl_seconds: 86400,
            max_drafts_per_owner: 8,
            max_drafts: 128,
            max_candidate_bytes: 1048576,
          },
        });
      }
      if (path === `/v1/admin/policy/drafts/${DRAFT_ID}` && method === 'GET') {
        return jsonResponse(200, draftView(), { ETag: '"sha256:draft-r1"' });
      }
      return jsonResponse(405, { error: 'unexpected' });
    },
  };
  return gateway;
}

function draftView() {
  return {
    draft_id: DRAFT_ID,
    revision: 1,
    state: 'open',
    base_etag: LIVE_ETAG,
    candidate_etag: '"sha256:candidate-1"',
    published_etag: null,
    created_at: '2026-10-28T10:00:00Z',
    updated_at: '2026-10-28T10:05:00Z',
    expires_at: '2026-10-29T10:05:00Z',
    policy: draftPolicy(),
  };
}

function draftPolicy() {
  return {
    schema_version: '1.0.0',
    id: 'billing-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: { support: { permissions: ['billing:read'] } },
    routes: [
      { id: 'billing', methods: ['GET'], path_prefix: '/billing/', permission: 'billing:read' },
    ],
    rules: [
      {
        id: 'watch-billing',
        methods: ['GET'],
        path: '/billing/{id}',
        principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
        action: 'shadow',
      },
    ],
  };
}

function validInspection() {
  return {
    valid: true,
    schema_version: '1.0.0',
    diagnostics: [],
    source_digest: 'sha256:source',
    semantic_digest: 'sha256:semantic',
    resource_snapshot: { schema_version: '1', digest: SNAPSHOT_DIGEST, complete: true },
  };
}

function simulationResult(requestBody: string) {
  const request = JSON.parse(requestBody) as { cases: Array<{ id: string; kind: string }> };
  const http = (overrides: Record<string, unknown>) => ({
    lane: 'http',
    complete: true,
    reason: 'matched_rule',
    observation: null,
    ...overrides,
  });
  return {
    schema_version: 'policy-simulation-results.v1',
    mode: 'synthetic',
    request_digest: 'sha256:request',
    evaluator: { http_semantics_version: 'gg-http-alias-v1', gateway_version: '1.0.1' },
    base: { source: 'active', etag: LIVE_ETAG },
    candidate: { source: 'inline', etag: '"sha256:candidate-text"' },
    trace: { level: 'matched', max_stages: 4096, stages_truncated: false },
    projections: ['as_authored', 'enforce_all_shadow'],
    not_evaluated: ['authentication', 'csrf', 'rate_capacity'],
    summary: {
      cases: request.cases.length,
      projections: {
        as_authored: counts({ would_forward: request.cases.length, shadowed: request.cases.length, changed_from_base: request.cases.length }),
        enforce_all_shadow: counts({ would_block: request.cases.length, changed_from_base: request.cases.length }),
      },
      projection_changed: request.cases.length,
    },
    cases: request.cases.map((entry, index) => ({
      id: entry.id,
      pointer: `/cases/${index}`,
      kind: entry.kind,
      results: [
        {
          projection: 'as_authored',
          base: http({
            logical: 'allow',
            enforcement: 'not_applicable',
            effective_action: 'would_forward',
            matched: { kind: 'route', position: 0, id: 'billing', permission: 'billing:read', permission_granted: true },
          }),
          changed: true,
          candidate: http({
            logical: 'deny',
            enforcement: 'shadowed',
            effective_action: 'would_forward',
            matched: { kind: 'rule', position: 0, id: 'watch-billing', action: 'shadow' },
          }),
        },
        {
          projection: 'enforce_all_shadow',
          base: http({
            logical: 'allow',
            enforcement: 'not_applicable',
            effective_action: 'would_forward',
            matched: { kind: 'route', position: 0, id: 'billing', permission: 'billing:read', permission_granted: true },
          }),
          changed: true,
          candidate: http({
            logical: 'deny',
            enforcement: 'enforced',
            effective_action: 'would_block',
            matched: { kind: 'rule', position: 0, id: 'watch-billing', action: 'deny' },
          }),
        },
      ],
      projection_changed: true,
    })),
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

function testReport(status: string) {
  return {
    schema_version: 'policy-test-results.v1',
    status,
    mode: 'test',
    suite: { schema_version: 'policy-tests.v1', digest: 'sha256:suite' },
    policy: { source: 'inline_candidate', etag: '"sha256:candidate-text"' },
    gateway_version: '1.0.1',
    not_evaluated: ['authentication', 'csrf'],
    summary: { total: 1, passed: 1, failed: 0, incomplete: 0, errors: 0 },
    cases: [
      {
        id: 'case-1',
        pointer: '/cases/0',
        kind: 'http',
        status: 'passed',
        expected: { logical: 'deny', effect: 'observe' },
        actual: { logical: 'deny', effect: 'observe', reason: 'matched_rule', complete: true, limitation: null },
        mismatches: [],
      },
    ],
  };
}

function replayJob(state: 'queued' | 'completed_incomplete') {
  const finished = state === 'completed_incomplete';
  const lane = {
    replayable: 0,
    decided: 0,
    indeterminate: 0,
    refused: 0,
    outcomes: [],
    limitations: {},
    refusals: {},
    egress_not_replayed: 0,
  };
  return {
    schema_version: 'policy-replay-job.v1',
    job_id: JOB_ID,
    state,
    cancel_requested: false,
    created_at: '2026-10-28T10:00:00Z',
    started_at: null,
    finished_at: finished ? '2026-10-28T10:00:02Z' : null,
    result_expires_at: null,
    request_digest: 'sha256:request',
    base: { source: 'active', etag: LIVE_ETAG, ...(finished ? { current: false } : {}) },
    candidate: { source: 'inline', etag: '"sha256:candidate-text"' },
    window: { from: '2026-10-27T10:00:00Z', to: '2026-10-28T10:00:00Z' },
    cutoff: { high_water: 12, selected_records: 2 },
    limits: { max_records: 500, deadline_ms: 60000 },
    progress: { scanned_records: finished ? 2 : 0, selected_records: 2 },
    ...(finished
      ? {
          result_digest: 'sha256:result',
          result: {
            schema_version: 'policy-replay-results.v1',
            mode: 'historical_replay',
            complete: false,
            limitations: ['no_data'],
            source: {
              kind: 'standalone_audit_log',
              window: { from: '2026-10-27T10:00:00Z', to: '2026-10-28T10:00:00Z' },
              high_water: 12,
              max_records: 500,
            },
            records: {
              selected: 2,
              scanned: 2,
              replayable: 0,
              duplicate: 0,
              not_policy_evaluated: 2,
              unsupported: 0,
              malformed: 0,
              not_request_record: 0,
              unreadable: 0,
              oversized: 0,
              by_code: { not_policy_evaluated: 2 },
            },
            replayed: {
              total: 0,
              http: lane,
              rate: { no_override: 0, override: 0, indeterminate: 0, refused: 0, limitations: {}, refusals: {} },
              tool: lane,
            },
            not_replayed: ['authentication', 'egress'],
          },
        }
      : {}),
  };
}

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function renderStudio(gateway: ReturnType<typeof fakeGateway>) {
  vi.stubGlobal('fetch', gateway.fetch);
  render(
    <MemoryRouter initialEntries={['/policy/studio']}>
      <Routes>
        <Route path="/policy/studio" element={<PolicyStudioView />} />
        <Route path="/rules" element={<p>Rulebase page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function studioLoaded() {
  await screen.findByRole('button', { name: `Open draft ${DRAFT_ID}` }, WAIT);
  await waitFor(
    () => expect(screen.queryByText('Loading the live policy and your drafts')).toBeNull(),
    WAIT,
  );
  screen.getByRole('tablist', { name: 'Policy Studio views' });
}

async function openDraft() {
  fireEvent.click(await screen.findByRole('button', { name: `Open draft ${DRAFT_ID}` }, WAIT));
  await screen.findByRole('tablist', { name: 'Policy sections' }, WAIT);
}

function openView(name: string) {
  fireEvent.click(screen.getByRole('tab', { name }));
}

function viewPanel(name: string): HTMLElement {
  return screen.getByRole('tabpanel', { name });
}
