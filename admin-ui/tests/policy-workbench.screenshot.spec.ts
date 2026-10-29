import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const DRAFT_ID = `pd_${'d'.repeat(32)}`;
const JOB_ID = `rpl_${'e'.repeat(32)}`;
const LIVE_ETAG = '"sha256:workbench-live"';

const policy = {
  schema_version: '1.0.0',
  id: 'workbench-policy',
  default_action: 'allow',
  enforcement_mode: 'enforce',
  roles: { support: { permissions: ['billing:read'] } },
  routes: [
    { id: 'billing', methods: ['GET'], path_prefix: '/billing/', permission: 'billing:read' },
  ],
  rules: [
    {
      id: 'watch-billing-exports',
      methods: ['GET'],
      path: '/billing/exports/**',
      principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
      action: 'shadow',
    },
  ],
};

function decision(overrides: Record<string, unknown>) {
  return { lane: 'http', complete: true, reason: 'matched_rule', observation: null, ...overrides };
}

async function routeWorkbench(page: Page) {
  await page.route('**/v1/admin/capabilities', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        permissions: ['admin:policy:read', 'admin:policy:write', 'admin:policy:simulate', 'admin:audit:read'],
      }),
    });
  });
  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: LIVE_ETAG },
      body: JSON.stringify(policy),
    });
  });
  const draft = {
    draft_id: DRAFT_ID,
    revision: 2,
    state: 'open',
    base_etag: LIVE_ETAG,
    candidate_etag: '"sha256:workbench-candidate"',
    published_etag: null,
    created_at: '2026-10-28T09:00:00Z',
    updated_at: '2026-10-28T09:30:00Z',
    expires_at: '2026-10-29T09:30:00Z',
  };
  await page.route('**/v1/admin/policy/drafts', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        drafts: [draft],
        limits: { ttl_seconds: 86400, max_drafts_per_owner: 8, max_drafts: 128, max_candidate_bytes: 1048576 },
      }),
    });
  });
  await page.route(`**/v1/admin/policy/drafts/${DRAFT_ID}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: '"sha256:workbench-draft-r2"' },
      body: JSON.stringify({ ...draft, policy }),
    });
  });
  await page.route('**/v1/admin/policy/validate', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: true,
        schema_version: '1.0.0',
        diagnostics: [
          {
            code: 'default_action_allow',
            severity: 'risk',
            pointer: '/default_action',
            message: 'Requests that no rule or route matches are allowed.',
            remediation: 'Set default_action to deny and add routes for what should be reachable.',
            blocks: { simulation: false, tests: false, publication: false, evidence: false },
          },
        ],
        source_digest: 'sha256:workbench-source',
        semantic_digest: 'sha256:workbench-semantic',
        resource_snapshot: { schema_version: '1', digest: `sha256:${'0'.repeat(64)}`, complete: true },
      }),
    });
  });
  await page.route('**/v1/admin/policy/simulations', async (route) => {
    const request = JSON.parse(route.request().postData() ?? '{}') as {
      cases: Array<{ id: string; kind: string }>;
    };
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'policy-simulation-results.v1',
        mode: 'synthetic',
        request_digest: 'sha256:workbench-request',
        evaluator: { http_semantics_version: 'gg-http-alias-v1', gateway_version: '1.0.1' },
        base: { source: 'active', etag: LIVE_ETAG },
        candidate: { source: 'inline', etag: '"sha256:workbench-inline"' },
        trace: { level: 'full', max_stages: 4096, stages_truncated: false },
        projections: ['as_authored', 'enforce_all_shadow'],
        not_evaluated: ['authentication', 'csrf', 'request_admission', 'rate_capacity', 'egress', 'upstream'],
        summary: {
          cases: request.cases.length,
          projections: {
            as_authored: { would_forward: 1, would_block: 0, unknown: 0, shadowed: 1, rate_override: 0, no_rate_override: 0, rate_unknown: 0, changed_from_base: 1 },
            enforce_all_shadow: { would_forward: 0, would_block: 1, unknown: 0, shadowed: 0, rate_override: 0, no_rate_override: 0, rate_unknown: 0, changed_from_base: 1 },
          },
          projection_changed: 1,
        },
        cases: request.cases.map((entry, index) => ({
          id: entry.id,
          pointer: `/cases/${index}`,
          kind: entry.kind,
          results: [
            {
              projection: 'as_authored',
              base: decision({
                logical: 'allow',
                enforcement: 'not_applicable',
                effective_action: 'would_forward',
                matched: { kind: 'route', position: 0, id: 'billing', permission: 'billing:read', permission_granted: true },
                stages: [
                  { stage: 'facts', status: 'matched' },
                  { stage: 'request_host', status: 'not_applicable' },
                  { stage: 'direct_rules', status: 'no_match' },
                  { stage: 'upstream_host_binding', status: 'not_applicable' },
                  { stage: 'routes', status: 'matched', element: { kind: 'route', position: 0, id: 'billing', permission: 'billing:read' }, permission: 'granted', enforcement_mode: 'enforce', mode_inherited: true },
                  { stage: 'default', status: 'skipped' },
                ],
              }),
              changed: true,
              candidate: decision({
                logical: 'deny',
                enforcement: 'shadowed',
                effective_action: 'would_forward',
                matched: { kind: 'rule', position: 0, id: 'watch-billing-exports', action: 'shadow' },
              }),
            },
            {
              projection: 'enforce_all_shadow',
              base: decision({ logical: 'allow', enforcement: 'not_applicable', effective_action: 'would_forward' }),
              changed: true,
              candidate: decision({ logical: 'deny', enforcement: 'enforced', effective_action: 'would_block' }),
            },
          ],
          projection_changed: true,
        })),
      }),
    });
  });
  await page.route('**/v1/admin/policy/replays', async (route) => {
    await route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify(replayJob(false)) });
  });
  await page.route(`**/v1/admin/policy/replays/${JOB_ID}`, async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(replayJob(true)) });
  });
}

function replayJob(finished: boolean) {
  const lane = (replayable: number, outcomes: unknown[]) => ({
    replayable,
    decided: replayable,
    indeterminate: 0,
    refused: 0,
    outcomes,
    limitations: {},
    refusals: {},
    egress_not_replayed: 0,
  });
  return {
    schema_version: 'policy-replay-job.v1',
    job_id: JOB_ID,
    state: finished ? 'completed' : 'queued',
    cancel_requested: false,
    created_at: '2026-10-28T10:00:00Z',
    started_at: null,
    finished_at: finished ? '2026-10-28T10:00:03Z' : null,
    result_expires_at: null,
    request_digest: 'sha256:workbench-replay',
    base: { source: 'active', etag: LIVE_ETAG, current: true },
    candidate: { source: 'inline', etag: '"sha256:workbench-inline"' },
    window: { from: '2026-10-27T10:00:00Z', to: '2026-10-28T10:00:00Z' },
    cutoff: { high_water: 1840, selected_records: 412 },
    limits: { max_records: 100000, deadline_ms: 60000 },
    progress: { scanned_records: finished ? 412 : 0, selected_records: 412 },
    ...(finished
      ? {
          result_digest: 'sha256:workbench-result',
          result: {
            schema_version: 'policy-replay-results.v1',
            mode: 'historical_replay',
            complete: true,
            limitations: [],
            source: {
              kind: 'standalone_audit_log',
              window: { from: '2026-10-27T10:00:00Z', to: '2026-10-28T10:00:00Z' },
              high_water: 1840,
              max_records: 100000,
            },
            records: {
              selected: 412, scanned: 412, replayable: 380, duplicate: 20, not_policy_evaluated: 12,
              unsupported: 0, malformed: 0, not_request_record: 0, unreadable: 0, oversized: 0,
              by_code: { duplicate_http_decision: 20, not_policy_evaluated: 12, replayable: 380 },
            },
            replayed: {
              total: 380,
              http: lane(372, [
                { logical: 'allow', enforcement: 'not_applicable', effective_action: 'would_forward', reason: 'matched_rule', count: 340 },
                { logical: 'deny', enforcement: 'shadowed', effective_action: 'would_forward', reason: 'matched_rule', count: 22 },
                { logical: 'deny', enforcement: 'enforced', effective_action: 'would_block', reason: 'missing_principal', count: 10 },
              ]),
              rate: { no_override: 372, override: 0, indeterminate: 0, refused: 0, limitations: {}, refusals: {} },
              tool: lane(8, [
                { logical: 'allow', enforcement: 'not_applicable', effective_action: 'would_forward', reason: 'allowed', count: 8 },
              ]),
            },
            not_replayed: ['authentication', 'request_admission', 'rate_capacity', 'tool_leases', 'egress', 'transport', 'upstream'],
          },
        }
      : {}),
  };
}

test('captures the Policy Studio simulator, replay and findings views', async ({ page }) => {
  await routeWorkbench(page);
  await page.goto('/admin/policy/studio');
  await expect(page.getByRole('heading', { level: 2, name: 'Policy Studio' })).toBeVisible();
  await page.getByRole('button', { name: `Open draft ${DRAFT_ID}` }).click();
  await expect(page.getByText('Valid, with 1 risk.')).toBeVisible();

  await page.getByRole('tab', { name: 'Simulate' }).click();
  const simulate = page.getByRole('tabpanel', { name: 'Simulate' });
  await simulate.getByRole('button', { name: 'Add case' }).click();
  await simulate.getByLabel('Request path').fill('/billing/exports/2026');
  await simulate.getByLabel('Caller roles').fill('support');
  await simulate.getByLabel('Trace level').selectOption('full');
  await simulate.getByRole('button', { name: 'Run simulation' }).click();
  await expect(simulate.getByRole('heading', { name: 'Simulation result' })).toBeVisible();
  await simulate.getByText('Evaluation stages').first().click();

  // Cases, candidates and results never reach browser storage.
  expect(
    await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ local: ['greengateway_admin_theme'], session: [] });

  await page.screenshot({ path: path.join(screenshotDir, 'policy-workbench-simulate-light.png'), fullPage: true });

  await page.getByRole('tab', { name: 'Impact' }).click();
  const impact = page.getByRole('tabpanel', { name: 'Impact' });
  await impact.getByRole('button', { name: 'Start replay' }).click();
  await expect(impact.getByText('✓ Completed').first()).toBeVisible({ timeout: 10_000 });
  await page.screenshot({ path: path.join(screenshotDir, 'policy-workbench-impact-light.png'), fullPage: true });

  await page.getByRole('tab', { name: 'Optimize' }).click();
  await expect(page.getByRole('tabpanel', { name: 'Optimize' }).getByText('Risks to review (1)')).toBeVisible();
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await page.screenshot({ path: path.join(screenshotDir, 'policy-workbench-optimize-dark.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to light theme' }).click();

  await page.getByRole('tab', { name: 'Simulate' }).click();
  await page.setViewportSize({ width: 390, height: 900 });
  await expect(simulate.getByRole('heading', { name: 'Simulation result' })).toBeVisible();
  await page.screenshot({ path: path.join(screenshotDir, 'policy-workbench-simulate-mobile.png'), fullPage: true });
});
