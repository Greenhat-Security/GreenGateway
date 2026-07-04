import { expect, test } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test('captures the rule table in light and dark themes', async ({ page }) => {
  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"screenshot-etag"',
      },
      body: JSON.stringify({
        schema_version: '0.1.0',
        id: 'screenshot-policy',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {},
        routes: [],
        rules: [
          {
            id: 'allow-billing-reader',
            enabled: true,
            methods: ['GET', 'HEAD'],
            path: '/billing/{invoice_id}',
            principal: {
              roles: ['billing-reader'],
              auth_methods: ['bearer_token'],
            },
            action: 'allow',
          },
          {
            id: 'shadow-schema-drift',
            enabled: true,
            methods: ['POST'],
            path: '/api/v2/reports/**',
            principal: {
              roles: ['analyst'],
            },
            action: 'shadow',
          },
          {
            id: 'deny-admin-public',
            enabled: false,
            methods: ['*'],
            path: '/admin/**',
            principal: {},
            action: 'deny',
          },
          {
            id: 'allow-service-health',
            enabled: true,
            methods: ['GET'],
            path: '/service/health',
            principal: {
              principal_ids: ['service-monitor'],
            },
            action: 'allow',
          },
        ],
      }),
    });
  });

  await page.route('**/v1/admin/policy/rules/hits', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        rules: [
          { rule_id: 'allow-billing-reader', hits: 1284 },
          { rule_id: 'shadow-schema-drift', hits: 42 },
          { rule_id: 'deny-admin-public', hits: 0 },
          { rule_id: 'allow-service-health', hits: 9088 },
        ],
      }),
    });
  });

  await page.goto('/admin/rules');
  await expect(
    page.getByRole('heading', { level: 2, name: 'Rule table' }),
  ).toBeVisible();
  await expect(page.getByText('Default action: Deny')).toBeVisible();

  await page.screenshot({
    path: path.join(screenshotDir, 'rule-table-light.png'),
    fullPage: true,
  });

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await page.screenshot({
    path: path.join(screenshotDir, 'rule-table-dark.png'),
    fullPage: true,
  });
});
