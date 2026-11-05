import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const LIVE_ETAG = '"sha256:suggestions-live"';
const DRAFT_ID = `pd_${'f'.repeat(32)}`;
const DRAFT_ETAG = '"sha256:suggestions-draft-r1"';

const policy = {
  schema_version: '1.0.0',
  id: 'suggestions-policy',
  default_action: 'deny',
  enforcement_mode: 'enforce',
  roles: { support: { permissions: ['billing:read'] } },
  routes: [],
  rules: [
    {
      id: 'allow-health',
      methods: ['GET'],
      path: '/health',
      principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
      action: 'allow',
    },
  ],
};

const baseline = {
  id: 'sugg-billing-read',
  suggestion_type: 'baseline_allow',
  method: 'GET',
  path_pattern: '/billing/{id}',
  principal_key: 'role:support',
  rationale: 'Role support called GET /billing/{id} 12 times in the last 168 hours, and no rule or route covers it.',
  evidence: {
    source: 'audit_sqlite',
    lookback_window_hours: 168,
    from: '2026-10-25T10:00:00Z',
    to: '2026-11-01T10:00:00Z',
    observation_count: 12,
    error_count: 0,
    first_seen: '2026-10-26T08:12:00Z',
    last_seen: '2026-11-01T09:41:00Z',
    role: 'support',
    issuer: 'https://idp.example.test',
    auth_method: 'bearer_token',
    audit_scan_truncated: false,
  },
  proposed_rule: {
    methods: ['GET'],
    path: '/billing/{id}',
    dispatch: { kind: 'contextless' },
    principal: {
      roles: ['support'],
      issuers: ['https://idp.example.test'],
      auth_methods: ['bearer_token'],
      principal_ids: [],
    },
    action: 'allow',
  },
  state: 'open',
  created_at: '2026-11-01T10:00:00Z',
  updated_at: '2026-11-01T10:00:00Z',
  transitioned_at: null,
  transitioned_by: null,
  revision: 1,
};

const signal = {
  ...baseline,
  id: 'sugg-signal-exports',
  suggestion_type: 'signal_shadow_error_rate_spike',
  path_pattern: '/exports/{id}',
  principal_key: '',
  rationale:
    'Signal-derived shadow candidate: open signal sig-7 (error_rate_spike) targets GET /exports/{id}. Suggested Shadow rather than Deny because anomaly signals can be false positives.',
  evidence: {
    source: 'discovery_signal',
    source_signal_id: 'sig-7',
    source_signal_type: 'error_rate_spike',
    source_signal_explanation: 'The error rate of GET /exports/{id} rose sharply.',
    source_signal_evidence: { error_rate: 0.4 },
    mapped_action: 'shadow',
  },
  proposed_rule: {
    ...baseline.proposed_rule,
    path: '/exports/{id}',
    principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
    action: 'shadow',
  },
  source_signal_id: 'sig-7',
};

const drafted = { ...baseline.proposed_rule, id: 'rule-drafted' };
const draftSummary = {
  draft_id: DRAFT_ID,
  revision: 1,
  state: 'open',
  base_etag: LIVE_ETAG,
  candidate_etag: '"sha256:suggestions-candidate"',
  published_etag: null,
  created_at: '2026-11-05T10:00:00Z',
  updated_at: '2026-11-05T10:00:00Z',
  expires_at: '2026-11-06T10:00:00Z',
};
const draftPolicy = { ...policy, rules: [...policy.rules, drafted] };

async function routeSuggestions(page: Page) {
  let drafts: unknown[] = [];
  await page.route('**/v1/admin/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        permissions: [
          'admin:policy:read',
          'admin:policy:write',
          'admin:policy:simulate',
          'admin:policy:analyze',
          'admin:suggestions:read',
          'admin:suggestions:write',
        ],
      }),
    }),
  );
  await page.route('**/v1/admin/policy', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: LIVE_ETAG },
      body: JSON.stringify(policy),
    }),
  );
  await page.route('**/v1/admin/policy/drafts', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        drafts,
        limits: { ttl_seconds: 86400, max_drafts_per_owner: 8, max_drafts: 128, max_candidate_bytes: 1048576 },
      }),
    }),
  );
  await page.route(`**/v1/admin/policy/drafts/${DRAFT_ID}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: DRAFT_ETAG },
      body: JSON.stringify({ ...draftSummary, policy: draftPolicy }),
    }),
  );
  await page.route((url) => url.pathname === '/v1/admin/suggestions', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ suggestions: [baseline, signal], next_cursor: null }),
    }),
  );
  await page.route(`**/v1/admin/suggestions/${baseline.id}/draft`, (route) => {
    drafts = [draftSummary];
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      headers: { ETag: DRAFT_ETAG },
      body: JSON.stringify({
        draft: { ...draftSummary, policy: draftPolicy },
        suggestion: baseline,
        rule: drafted,
        position: 1,
      }),
    });
  });
  await page.route('**/v1/admin/policy/validate', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: true,
        schema_version: '1.0.0',
        diagnostics: [],
        source_digest: 'sha256:suggestions-source',
        semantic_digest: 'sha256:suggestions-semantic',
        resource_snapshot: { schema_version: '1', digest: `sha256:${'0'.repeat(64)}`, complete: true },
      }),
    }),
  );
  await page.route('**/v1/admin/policy/simulations', (route) => {
    const decision = (overrides: Record<string, unknown>) => ({
      lane: 'http',
      complete: true,
      reason: 'matched_rule',
      ...overrides,
    });
    const counts = { would_forward: 1, would_block: 0, unknown: 0, shadowed: 0, rate_override: 0, no_rate_override: 0, rate_unknown: 0, changed_from_base: 1 };
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'policy-simulation-results.v1',
        mode: 'synthetic',
        request_digest: 'sha256:suggestions-request',
        base: { source: 'active', etag: LIVE_ETAG },
        candidate: { source: 'draft', etag: '"sha256:suggestions-candidate"' },
        trace: { level: 'matched', max_stages: 4096, stages_truncated: false },
        projections: ['as_authored', 'enforce_all_shadow'],
        not_evaluated: ['authentication', 'csrf', 'request_admission', 'rate_capacity', 'egress', 'upstream'],
        summary: { cases: 1, projections: { as_authored: counts, enforce_all_shadow: counts } },
        cases: [
          {
            id: 'suggested-traffic',
            pointer: '/cases/0',
            kind: 'http',
            results: ['as_authored', 'enforce_all_shadow'].map((projection) => ({
              projection,
              base: decision({
                logical: 'deny',
                enforcement: 'enforced',
                effective_action: 'would_block',
                reason: 'default_deny',
                matched: null,
              }),
              changed: true,
              candidate: decision({
                logical: 'allow',
                enforcement: 'not_applicable',
                effective_action: 'would_forward',
                matched: { kind: 'rule', position: 1, id: 'rule-drafted', action: 'allow' },
              }),
            })),
          },
        ],
      }),
    });
  });
  await page.route('**/v1/admin/policy/analyses', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        schema_version: 'policy-analysis-results.v1',
        mode: 'structural',
        request_digest: 'sha256:suggestions-analysis',
        analyzer: { version: 'gg-policy-analyzer-v1' },
        base: { source: 'active', etag: LIVE_ETAG },
        analyzed: { source: 'draft', etag: '"sha256:suggestions-candidate"', draft_id: DRAFT_ID, draft_revision: 1 },
        complete: true,
        limitations: [],
        summary: { findings: 0 },
        findings: [],
      }),
    }),
  );
}

// The checks the live-UI suite runs: landmarks, unique ids, labelled
// controls, named buttons and references that resolve.
async function assertBasicAccessibility(page: Page) {
  const problems = await page.evaluate(() => {
    const found: string[] = [];
    if (document.querySelector('main') === null) found.push('missing main landmark');
    const ids = new Map<string, number>();
    for (const element of document.querySelectorAll<HTMLElement>('[id]')) {
      ids.set(element.id, (ids.get(element.id) ?? 0) + 1);
    }
    for (const [id, count] of ids) {
      if (count > 1) found.push(`duplicate id: ${id}`);
    }
    for (const control of document.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
      'input:not([type="hidden"]), select, textarea',
    )) {
      const labelled =
        (control.labels?.length ?? 0) > 0 ||
        Boolean(control.getAttribute('aria-label')?.trim()) ||
        Boolean(control.getAttribute('aria-labelledby')?.trim());
      if (!labelled) found.push(`unlabelled control: ${control.id || control.tagName.toLowerCase()}`);
    }
    for (const button of document.querySelectorAll('button')) {
      if (!(button.getAttribute('aria-label')?.trim() || button.textContent?.trim())) {
        found.push('button without an accessible name');
      }
    }
    for (const element of document.querySelectorAll('[aria-describedby], [aria-labelledby]')) {
      for (const attribute of ['aria-describedby', 'aria-labelledby']) {
        for (const id of (element.getAttribute(attribute) ?? '').split(/\s+/).filter(Boolean)) {
          if (document.getElementById(id) === null) found.push(`${attribute} names a missing id: ${id}`);
        }
      }
    }
    return found;
  });
  expect(problems).toEqual([]);
}

test('captures the Policy Studio suggestions workspace and a suggestion under review', async ({ page }) => {
  await routeSuggestions(page);
  await page.goto('/admin/policy/studio');
  await expect(page.getByRole('heading', { level: 2, name: 'Policy Studio' })).toBeVisible();

  // The view tabs are reachable by keyboard.
  await page.getByRole('tab', { name: 'Edit' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Suggestions' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'Suggestions' })).toBeFocused();

  const panel = page.getByRole('tabpanel', { name: 'Suggestions' });
  const row = panel.getByRole('listitem', { name: 'GET /billing/{id}' });
  await expect(row.getByText('Traffic baseline from the audit history')).toBeVisible();
  await expect(row.getByRole('button', { name: 'Review in draft' })).toBeEnabled();
  await expect(panel.getByRole('button', { name: /accept|apply/i })).toHaveCount(0);

  // Suggestions, drafts and candidates never reach browser storage.
  expect(
    await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) })),
  ).toEqual({ local: ['greengateway_admin_theme'], session: [] });
  await assertBasicAccessibility(page);
  await page.screenshot({ path: path.join(screenshotDir, 'policy-suggestions-light.png'), fullPage: true });

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await page.screenshot({ path: path.join(screenshotDir, 'policy-suggestions-dark.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to light theme' }).click();

  await row.getByRole('button', { name: 'Review in draft' }).click();
  await expect(page.getByText('Suggestion opened in a draft')).toBeVisible();
  const review = page.getByRole('region', { name: 'GET /billing/{id}' });
  await expect(review.getByText('✓ The suggested rule decides')).toBeVisible();
  await expect(review.getByText(/The analyzer reports nothing about the suggested rule/)).toBeVisible();
  await assertBasicAccessibility(page);
  await page.screenshot({ path: path.join(screenshotDir, 'policy-suggestions-review-light.png'), fullPage: true });

  await page.getByRole('tab', { name: 'Suggestions' }).click();
  await page.setViewportSize({ width: 390, height: 900 });
  await expect(row.getByText('Traffic baseline from the audit history')).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBe(true);
  await page.screenshot({ path: path.join(screenshotDir, 'policy-suggestions-mobile.png'), fullPage: true });
});
