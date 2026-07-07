import { expect, test } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 1440, height: 900 } });

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
  await page.addStyleTag({
    content: '*, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; }',
  });
  await expect(
    page.getByRole('heading', { level: 2, name: 'Rulebase' }),
  ).toBeVisible();
  await expect(page.getByText('Default action: Deny')).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Operations' })).toBeInViewport();

  await page.screenshot({
    path: path.join(screenshotDir, 'rule-table-light.png'),
    fullPage: true,
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/admin/rules');
  await expect(page.getByText('allow-billing-reader')).toBeVisible();
  const mobileTableBox = await page.locator('.rule-table').boundingBox();
  const mobileFrameBox = await page.locator('.table-scroll').boundingBox();
  expect(mobileTableBox?.width).toBeLessThanOrEqual((mobileFrameBox?.width ?? 0) + 1);
  await page.screenshot({
    path: path.join(screenshotDir, 'rule-table-mobile.png'),
    fullPage: true,
  });

  await page.setViewportSize({ width: 1440, height: 900 });

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await page.screenshot({
    path: path.join(screenshotDir, 'rule-table-dark.png'),
    fullPage: true,
  });
});
