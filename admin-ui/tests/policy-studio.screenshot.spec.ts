import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const DRAFT_ID = `pd_${'c'.repeat(32)}`;
const LIVE_ETAG = '"sha256:screenshot-live"';

const policy = {
  schema_version: '1.0.0',
  id: 'screenshot-policy',
  default_action: 'deny',
  enforcement_mode: 'enforce',
  roles: {
    support: { permissions: ['billing:read'], description: 'Support staff' },
  },
  routes: [
    {
      id: 'billing',
      methods: ['GET'],
      path_prefix: '/billing/',
      permission: 'billing:read',
    },
  ],
  rules: [
    {
      id: 'allow-billing-read',
      methods: ['GET'],
      path: '/billing/{id}',
      principal: { roles: ['support'], issuers: [], auth_methods: [], principal_ids: [] },
      action: 'allow',
    },
    {
      id: 'deny-exports',
      methods: [],
      tool_name: 'reports.export',
      principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
      action: 'deny',
    },
  ],
  egress: { hosts: ['api.example.com'] },
};

async function routeStudio(page: Page) {
  await page.route('**/v1/admin/capabilities', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ permissions: ['admin:policy:read', 'admin:policy:write'] }),
    });
  });
  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: LIVE_ETAG, 'X-GreenGateway-Policy-Write': 'true' },
      body: JSON.stringify(policy),
    });
  });
  const draft = {
    draft_id: DRAFT_ID,
    revision: 3,
    state: 'open',
    base_etag: LIVE_ETAG,
    candidate_etag: '"sha256:screenshot-candidate"',
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
        limits: {
          ttl_seconds: 86400,
          max_drafts_per_owner: 8,
          max_drafts: 128,
          max_candidate_bytes: 1048576,
        },
      }),
    });
  });
  await page.route(`**/v1/admin/policy/drafts/${DRAFT_ID}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: '"sha256:screenshot-draft-r3"' },
      body: JSON.stringify({ ...draft, policy }),
    });
  });
  await page.route('**/v1/admin/policy/validate', async (route) => {
    const source = route.request().postData() ?? '';
    const invalid = source.includes('"path": "billing');
    await route.fulfill({
      status: invalid ? 400 : 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: !invalid,
        schema_version: '1.0.0',
        diagnostics: invalid
          ? [
              {
                code: 'rule_path_invalid',
                severity: 'error',
                pointer: '/rules/0/path',
                element_id: 'allow-billing-read',
                message: 'The rule path is not an absolute path pattern.',
                remediation: 'Start the path with / and use *, ** or {name} segments.',
                blocks: { simulation: true, tests: true, publication: true, evidence: true },
              },
            ]
          : [],
        source_digest: 'sha256:screenshot-source',
        semantic_digest: 'sha256:screenshot-semantic',
        resource_snapshot: {
          schema_version: '1',
          digest: `sha256:${'0'.repeat(64)}`,
          complete: true,
        },
      }),
    });
  });
}

test('captures the Policy Studio rule editor with live diagnostics', async ({ page }) => {
  await routeStudio(page);
  await page.goto('/admin/policy/studio');
  await expect(page.getByRole('heading', { level: 2, name: 'Policy Studio' })).toBeVisible();
  await page.getByRole('button', { name: `Open draft ${DRAFT_ID}` }).click();
  await expect(page.getByText('Valid: the gateway reports no diagnostics.')).toBeVisible();

  await page.getByRole('tab', { name: 'HTTP and MCP rules' }).click();
  await page.getByLabel('Path pattern').fill('billing/{id}');
  await expect(page.getByText('Invalid: 1 error.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Publish draft' })).toBeDisabled();

  // Drafts and candidates never reach browser storage.
  expect(
    await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ local: ['greengateway_admin_theme'], session: [] });

  await page.screenshot({
    path: path.join(screenshotDir, 'policy-studio-light.png'),
    fullPage: true,
  });

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await page.screenshot({
    path: path.join(screenshotDir, 'policy-studio-dark.png'),
    fullPage: true,
  });
  await page.getByRole('button', { name: 'Switch to light theme' }).click();

  await page.setViewportSize({ width: 390, height: 900 });
  await expect(page.getByLabel('Path pattern')).toBeVisible();
  await page.screenshot({
    path: path.join(screenshotDir, 'policy-studio-mobile.png'),
    fullPage: true,
  });
});
