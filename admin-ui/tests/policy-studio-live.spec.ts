import {
  expect,
  test,
  type APIRequestContext,
  type Browser,
  type Page,
} from '@playwright/test';

// The Policy Studio workbench against a real standalone gateway
// (tests/fixtures/policy-studio-live-server.mjs), driving the admin UI the
// gateway embeds and serves on its own origin. The gateway was built from
// this tree, so a local run needs `cargo build -p gateway` after a UI change.
//
// The tests share one gateway and run in order: each sets up the stored
// suite and drafts it needs through the API, under If-Match or
// If-None-Match: *, and removes the drafts it made, but the stored suite's
// version history and the retained audit records only grow.
const GATEWAY_ORIGIN = 'http://127.0.0.1:43222';
const FIXTURE_ORIGIN = 'http://127.0.0.1:43221';
const ADMIN_API = `${GATEWAY_ORIGIN}/v1/admin`;
const STUDIO_URL = `${GATEWAY_ORIGIN}/admin/`;
const CANARY = 'canary-subject-7f3a';

type Tokens = { operator: string; reader: string };
type Stored = { etag: string; version: number };

let tokens: Tokens;
let fixtureStartedAt: number;

test.describe.serial('Policy Studio workbench against a real gateway (#243 item 18)', () => {
  test.beforeAll(async ({ request }) => {
    const answer = await request.get(`${FIXTURE_ORIGIN}/__fixture/tokens`);
    expect(answer.ok()).toBe(true);
    tokens = (await answer.json()) as Tokens;
    const state = await (await request.get(`${FIXTURE_ORIGIN}/__fixture/state`)).json();
    fixtureStartedAt = Date.parse(state.startedAt);
    expect(Number.isFinite(fixtureStartedAt)).toBe(true);
  });

  test('simulates through the real evaluator and never shows a shadow would-deny as an allow', async ({ browser }) => {
    const { page, close } = await studio(browser, tokens.operator);
    try {
      await openView(page, 'Simulate');
      const panel = viewPanel(page, 'Simulate');
      await panel.getByRole('button', { name: 'Add case' }).click();
      await panel.getByLabel('Request path').fill('/upstream/watched');
      const [simulated] = await Promise.all([
        page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/admin/policy/simulations'),
        panel.getByRole('button', { name: 'Run simulation' }).click(),
      ]);
      expect(simulated.status()).toBe(200);
      const authored = panel.getByRole('region', { name: 'As authored, case case-1' });
      const decision = authored.getByRole('list', { name: 'Live policy: decision' });
      await expect(decision.getByText('✕ Deny')).toBeVisible();
      await expect(decision.getByText('Shadow: a would-deny that is only observed')).toBeVisible();
      await expect(decision.getByText('→ Would forward')).toBeVisible();
      await expect(decision.getByText('✓ Allow')).toHaveCount(0);
      await expect(authored.getByText(/id upstream-watched, action shadow/)).toBeVisible();
      const enforced = panel.getByRole('region', { name: 'Every shadow enforced, case case-1' });
      await expect(enforced.getByText('■ Would block')).toBeVisible();
    } finally {
      await close();
    }
  });

  test('stores the suite beside the policy and refuses a stale save with 412, keeping the on-screen cases', async ({ browser, request }) => {
    const first = await storeSuite(request, suite(['watched-observed']));
    const { page, close } = await studio(browser, tokens.operator);
    try {
      await openView(page, 'Test');
      const tests = viewPanel(page, 'Test');
      await expect(tests.getByText(`Stored suite: version ${first.version}`, { exact: false })).toBeVisible();
      await tests.getByRole('button', { name: 'Load the stored suite' }).click();
      await expect(tests.getByRole('button', { name: /Edit case watched-observed/ })).toBeVisible();
      await tests.getByRole('button', { name: 'Add case' }).click();
      await tests.getByLabel('Expected decision').selectOption('deny');

      // Another writer replaces the suite out of band.
      const theirs = await storeSuite(request, suite(['theirs-1', 'theirs-2']), first.etag);

      await tests.getByRole('button', { name: 'Save as the stored suite' }).click();
      const confirm = tests.getByRole('group', { name: 'Store these cases as the suite?' });
      await expect(confirm.getByText(/every later policy publication must pass the suite you store/)).toBeVisible();
      const [refused] = await Promise.all([
        page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/v1/admin/policy/tests' && response.request().method() === 'PUT'),
        confirm.getByRole('button', { name: 'Store the suite' }).click(),
      ]);
      expect(refused.status()).toBe(412);
      expect(await refused.request().headerValue('if-match')).toBe(first.etag);
      expect(await refused.request().headerValue('if-none-match')).toBeNull();
      await expect(tests.getByRole('heading', { name: 'Stored suite changed' })).toBeVisible();
      await expect(tests.getByRole('button', { name: /Edit case watched-observed/ })).toBeVisible();
      await expect(tests.getByRole('button', { name: /Edit case case-2/ })).toBeVisible();
      await expect(tests.getByRole('button', { name: /Edit case theirs-1/ })).toHaveCount(0);
      await expect(tests.getByText(`Stored suite: version ${theirs.version}`, { exact: false })).toBeVisible();
      // Nothing was stored over the other writer's version.
      expect((await readSuite(request))?.etag).toBe(theirs.etag);
    } finally {
      await close();
    }
  });

  test('blocks a failing draft publication under POLICY_TESTS_REQUIRED and shows why', async ({ browser, request }) => {
    // The live policy lets /upstream/secret through (the deny is shadowed),
    // so a suite expecting it blocked fails against a draft that keeps that.
    const stored = await storeSuite(request, {
      schema_version: 'policy-tests.v1',
      cases: [httpCase('secret-blocked', '/upstream/secret', { logical: 'deny', effect: 'block' })],
    });
    const live = await readLive(request);
    const draft = await createDraft(request, live.etag, { ...live.policy, id: 'policy-studio-live-next' });
    const { page, close } = await studio(browser, tokens.operator);
    try {
      await page.getByRole('button', { name: `Open draft ${draft.id}` }).click();
      const publish = page.getByRole('button', { name: 'Publish draft' });
      await expect(publish).toBeEnabled({ timeout: 20_000 });
      await publish.click();
      const [refused] = await Promise.all([
        page.waitForResponse((response) => new URL(response.url()).pathname.endsWith('/publish')),
        page.getByRole('group', { name: 'Publish this draft?' }).getByRole('button', { name: 'Confirm publish' }).click(),
      ]);
      expect(refused.status()).toBe(422);
      const problem = page.locator('.policy-studio-problem');
      await expect(problem.getByText('Not published: the required test suite did not pass')).toBeVisible();
      await expect(problem.getByText(/At least one case did not give the expected answer/)).toBeVisible();
      await expect(problem.getByText(`Judged by stored suite version ${stored.version}`, { exact: false })).toBeVisible();
      await expect(problem.getByText('1 case: 0 passed, 1 failed, 0 incomplete, 0 errors.')).toBeVisible();
      expect((await readLive(request)).etag).toBe(live.etag);

      await problem.getByRole('button', { name: 'Run the stored suite against this draft' }).click();
      const tests = viewPanel(page, 'Test');
      await expect(tests.getByText(`Ran the stored suite, version ${stored.version}.`, { exact: false })).toBeVisible();
      await expect(tests.getByText('✕ Failed').first()).toBeVisible();
      await expect(tests.locator('table').getByText('secret-blocked', { exact: true })).toBeVisible();
    } finally {
      await close();
      await deleteDraft(request, draft);
    }
  });

  test('replays retained traffic from the real audit log: an empty window is no_data, then observed decisions', async ({ browser, request }) => {
    for (const path of ['/upstream/health', '/upstream/watched', '/upstream/health']) {
      const answer = await request.get(`${GATEWAY_ORIGIN}${path}`, { headers: bearer(tokens.operator) });
      expect(answer.status()).toBe(200);
    }
    await waitForReplayableRecords(request);

    const { page, close } = await studio(browser, tokens.operator);
    try {
      await openView(page, 'Impact');
      const impact = viewPanel(page, 'Impact');
      // A window that ends before the fixture sent anything.
      await impact.getByLabel('Records from').selectOption('custom');
      await impact.getByLabel('Window start').fill(localMinute(fixtureStartedAt - 2 * 60 * 60 * 1000));
      await impact.getByLabel('Window end').fill(localMinute(fixtureStartedAt - 60 * 60 * 1000));
      const [started] = await Promise.all([
        page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/v1/admin/policy/replays' && response.request().method() === 'POST'),
        impact.getByRole('button', { name: 'Start replay' }).click(),
      ]);
      expect(started.status()).toBe(202);
      const emptyJob = (await started.json()).job_id as string;
      await expect(impact.getByText('◐ Completed, incomplete').first()).toBeVisible({ timeout: 30_000 });
      await expect(impact.getByText(/No decisions: nothing in this window could be replayed/)).toBeVisible();
      await expect(impact.getByRole('region', { name: 'HTTP decisions' })).toHaveCount(0);
      const empty = await (await request.get(`${ADMIN_API}/policy/replays/${emptyJob}`, { headers: bearer(tokens.operator) })).json();
      expect(empty.state).toBe('completed_incomplete');
      expect(empty.result.limitations).toContain('no_data');
      await discardJob(page);

      // The last hour holds the requests sent above.
      await impact.getByLabel('Records from').selectOption('1h');
      await impact.getByRole('button', { name: 'Start replay' }).click();
      await expect(impact.getByText('✓ Completed').first()).toBeVisible({ timeout: 30_000 });
      await expect(impact.getByRole('region', { name: 'HTTP decisions' })).toBeVisible();
      await expect(impact.getByText(/No decisions: nothing in this window could be replayed/)).toHaveCount(0);
      await discardJob(page);
    } finally {
      await close();
    }
  });

  test('opens an analyzer patch in a draft and leaves the live policy unchanged until publish', async ({ browser, request }) => {
    const live = await readLive(request);
    const before = await listDrafts(request);
    const { page, close } = await studio(browser, tokens.operator);
    try {
      await openView(page, 'Optimize');
      const optimize = viewPanel(page, 'Optimize');
      await optimize.getByRole('button', { name: 'Run analysis' }).click();
      const review = optimize.getByRole('button', {
        name: 'Review the advisory change for rule_shadowed at /rules/2',
      });
      await expect(review).toBeVisible({ timeout: 20_000 });
      await review.click();
      const group = optimize.getByRole('group', { name: 'Apply this advisory change?' });
      await expect(group.getByText('Move rule #3 (id upstream-secret-blocked) to position #2')).toBeVisible();
      const [created] = await Promise.all([
        page.waitForResponse((response) =>
          new URL(response.url()).pathname === '/v1/admin/policy/drafts' && response.request().method() === 'POST'),
        group.getByRole('button', { name: 'Start a draft with this change' }).click(),
      ]);
      expect(created.status()).toBe(201);
      expect(await created.request().headerValue('if-match')).toBe(live.etag);
      await expect(page.getByText('Draft created')).toBeVisible();
      const draft = (await created.json()) as { draft_id: string; policy: { rules: Array<{ id: string }> } };
      expect(draft.policy.rules.map((rule) => rule.id)).toEqual([
        'upstream-watched',
        'upstream-secret-blocked',
        'upstream-open',
      ]);
      expect((await readLive(request)).etag).toBe(live.etag);

      // Analyzed again, the draft no longer has the finding.
      await optimize.getByRole('button', { name: 'Run analysis again' }).click();
      await expect(optimize.getByText(/^Analyzed: draft /)).toBeVisible({ timeout: 20_000 });
      await expect(optimize.getByText('rule_shadowed')).toHaveCount(0);
    } finally {
      await close();
      for (const draft of await listDrafts(request)) {
        if (!before.some((entry) => entry.id === draft.id)) await deleteDraft(request, draft);
      }
    }
  });

  test('a principal without admin:policy:simulate sees runs disabled with the reason', async ({ browser }) => {
    const { page, close } = await studio(browser, tokens.reader);
    try {
      await openView(page, 'Test');
      const tests = viewPanel(page, 'Test');
      await expect(tests.getByRole('button', { name: 'Run tests' })).toBeDisabled();
      await expect(tests.getByText('Running policy tests needs admin:policy:read and admin:policy:simulate.')).toBeVisible();
      await expect(tests.getByText(/Reading or running the stored suite needs admin:policy:read and admin:policy:simulate/)).toBeVisible();
      await openView(page, 'Simulate');
      await expect(viewPanel(page, 'Simulate').getByRole('button', { name: 'Run simulation' })).toBeDisabled();
    } finally {
      await close();
    }
  });

  test('the gateway itself refuses that principal with 403', async ({ browser }) => {
    const { page, close } = await studio(browser, tokens.reader);
    try {
      const statuses = await page.evaluate(async (token) => {
        const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
        const read = await fetch('/v1/admin/policy/tests', { headers });
        const run = await fetch('/v1/admin/policy/tests/runs', {
          method: 'POST',
          headers,
          body: '{"suite":{"source":"stored"},"format":"json"}',
        });
        return [read.status, run.status];
      }, tokens.reader);
      expect(statuses).toEqual([403, 403]);
    } finally {
      await close();
    }
  });

  test('keeps hypothetical callers, cases and results out of URLs and browser storage', async ({ browser }) => {
    const { page, close } = await studio(browser, tokens.operator);
    try {
      await openView(page, 'Simulate');
      const panel = viewPanel(page, 'Simulate');
      await panel.getByRole('button', { name: 'Add case' }).click();
      await panel.getByLabel('Subject').fill(CANARY);
      await panel.getByLabel('Request path').fill(`/upstream/${CANARY}`);
      await panel.getByRole('button', { name: 'Run simulation' }).click();
      await expect(panel.getByText('Simulation result')).toBeVisible();
      for (const view of ['Test', 'Impact', 'Optimize', 'Evidence', 'Edit', 'Simulate']) {
        await openView(page, view);
        expect(page.url()).not.toContain(CANARY);
        const stored = await page.evaluate(() => {
          const values: string[] = [];
          for (const storage of [window.localStorage, window.sessionStorage]) {
            for (let index = 0; index < storage.length; index += 1) {
              const key = storage.key(index) ?? '';
              values.push(key, storage.getItem(key) ?? '');
            }
          }
          return values.join('\n');
        });
        expect(stored).not.toContain(CANARY);
      }
    } finally {
      await close();
    }
  });
});

async function studio(browser: Browser, token: string): Promise<{ page: Page; close: () => Promise<void> }> {
  // UTC, so a window typed into a local date-time field means what it says.
  const context = await browser.newContext({ timezoneId: 'UTC' });
  const page = await context.newPage();
  await page.goto(STUDIO_URL);
  await expect(page.getByRole('status').filter({ hasText: 'Session ended. Sign in again.' })).toBeVisible();
  await page.getByLabel('Token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Token active in this tab until reload or session expiry.' }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Policy Studio', exact: true }).click();
  await expect(page.getByRole('heading', { level: 2, name: 'Policy Studio' })).toBeVisible();
  await expect(page.getByText('Loading the live policy and your drafts')).toHaveCount(0, { timeout: 20_000 });
  return { page, close: () => context.close() };
}

async function openView(page: Page, name: string) {
  await page.getByRole('tablist', { name: 'Policy Studio views' }).getByRole('tab', { name, exact: true }).click();
}

function viewPanel(page: Page, name: string) {
  return page.getByRole('tabpanel', { name, exact: true });
}

async function discardJob(page: Page) {
  const impact = viewPanel(page, 'Impact');
  await impact.getByRole('button', { name: 'Discard replay' }).click();
  await impact.getByRole('group', { name: 'Discard this replay?' }).getByRole('button', { name: 'Confirm discard' }).click();
  await expect(impact.getByText('No replay started in this page yet.')).toBeVisible();
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function httpCase(id: string, path: string, expectation: Record<string, unknown>) {
  return {
    id,
    kind: 'http',
    request: { method: 'GET', path },
    principal: { subject: 'synthetic-caller', auth_method: 'bearer_token' },
    expect: expectation,
  };
}

function suite(ids: string[]) {
  return {
    schema_version: 'policy-tests.v1',
    cases: ids.map((id) => httpCase(id, '/upstream/watched', { logical: 'deny', effect: 'observe' })),
  };
}

async function readSuite(request: APIRequestContext): Promise<Stored | null> {
  const answer = await request.get(`${ADMIN_API}/policy/tests`, { headers: bearer(tokens.operator) });
  if (answer.status() === 404) return null;
  expect(answer.status()).toBe(200);
  return {
    etag: answer.headers().etag,
    version: Number(answer.headers()['x-greengateway-policy-tests-version']),
  };
}

// Store `document` under the exact precondition: If-None-Match: * when none
// is stored, otherwise If-Match with the ETag given or read now.
async function storeSuite(request: APIRequestContext, document: unknown, etag?: string): Promise<Stored> {
  const current = etag ?? (await readSuite(request))?.etag ?? null;
  const answer = await request.put(`${ADMIN_API}/policy/tests`, {
    headers: {
      ...bearer(tokens.operator),
      'Content-Type': 'application/json',
      ...(current === null ? { 'If-None-Match': '*' } : { 'If-Match': current }),
    },
    data: JSON.stringify(document),
  });
  expect([200, 201]).toContain(answer.status());
  return {
    etag: answer.headers().etag,
    version: Number(answer.headers()['x-greengateway-policy-tests-version']),
  };
}

async function readLive(request: APIRequestContext): Promise<{ etag: string; policy: Record<string, unknown> }> {
  const answer = await request.get(`${ADMIN_API}/policy`, { headers: bearer(tokens.operator) });
  expect(answer.status()).toBe(200);
  return { etag: answer.headers().etag, policy: await answer.json() };
}

type Draft = { id: string; etag: string };

async function createDraft(request: APIRequestContext, liveEtag: string, policy: unknown): Promise<Draft> {
  const answer = await request.post(`${ADMIN_API}/policy/drafts`, {
    headers: { ...bearer(tokens.operator), 'Content-Type': 'application/json', 'If-Match': liveEtag },
    data: JSON.stringify({ policy }),
  });
  expect(answer.status()).toBe(201);
  return { id: (await answer.json()).draft_id, etag: answer.headers().etag };
}

async function listDrafts(request: APIRequestContext): Promise<Draft[]> {
  const answer = await request.get(`${ADMIN_API}/policy/drafts`, { headers: bearer(tokens.operator) });
  expect(answer.status()).toBe(200);
  const drafts = (await answer.json()).drafts as Array<{ draft_id: string }>;
  const listed: Draft[] = [];
  for (const draft of drafts) {
    const read = await request.get(`${ADMIN_API}/policy/drafts/${draft.draft_id}`, { headers: bearer(tokens.operator) });
    listed.push({ id: draft.draft_id, etag: read.headers().etag });
  }
  return listed;
}

async function deleteDraft(request: APIRequestContext, draft: Draft) {
  const answer = await request.delete(`${ADMIN_API}/policy/drafts/${draft.id}`, {
    headers: { ...bearer(tokens.operator), 'If-Match': draft.etag },
  });
  expect(answer.ok()).toBe(true);
}

// The requests above are audited before they are answered under the default
// AUDIT_DURABILITY=required; replay them through the API until a job over
// the last hour completes with replayed records, so the UI run is not racing
// the audit writer.
async function waitForReplayableRecords(request: APIRequestContext) {
  const live = await readLive(request);
  await expect
    .poll(
      async () => {
        const started = await request.post(`${ADMIN_API}/policy/replays`, {
          headers: { ...bearer(tokens.operator), 'Content-Type': 'application/json' },
          data: JSON.stringify({
            schema_version: 'policy-replay.v1',
            base_etag: live.etag,
            candidate: { source: 'active' },
            window: { from: new Date(Date.now() - 60 * 60 * 1000).toISOString() },
            max_records: 1000,
          }),
        });
        expect(started.status()).toBe(202);
        const id = (await started.json()).job_id as string;
        let state = 'queued';
        for (let attempt = 0; attempt < 40 && (state === 'queued' || state === 'running'); attempt += 1) {
          await new Promise((resolve) => setTimeout(resolve, 250));
          const job = await request.get(`${ADMIN_API}/policy/replays/${id}`, { headers: bearer(tokens.operator) });
          state = (await job.json()).state;
        }
        await request.delete(`${ADMIN_API}/policy/replays/${id}`, { headers: bearer(tokens.operator) });
        return state;
      },
      { timeout: 30_000, intervals: [500, 1_000, 2_000] },
    )
    .toBe('completed');
}

// A moment as a datetime-local value, in UTC (the context's time zone).
function localMinute(epochMs: number): string {
  return new Date(epochMs).toISOString().slice(0, 16);
}
