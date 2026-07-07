import { expect, test } from '@playwright/test';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 390, height: 844 } });

test('captures the traffic inventory as mobile cards', async ({ page }) => {
  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"traffic-mobile-policy"',
      },
      body: JSON.stringify({
        schema_version: '0.1.0',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {},
        routes: [],
        rules: [],
      }),
    });
  });

  await page.route('**/v1/admin/traffic/endpoints?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        endpoints: [
          {
            method: 'GET',
            endpoint_template: '/api/orders/{order_id}',
            first_seen: '2026-07-04T08:00:00Z',
            last_seen: '2026-07-04T10:30:00Z',
            call_count: 128,
            distinct_principal_count: 18,
            is_new: true,
            reviewed: false,
            reviewed_at: null,
            reviewed_by: null,
            covered_by_rule: false,
            latency: {
              count: 128,
              p50_ms: 18,
              p95_ms: 47,
              p99_ms: 72,
            },
            status_counts: [
              { status: 200, count: 119 },
              { status: 404, count: 9 },
            ],
          },
          {
            method: 'MCP',
            endpoint_template: '/mcp/tools/reports.export',
            first_seen: '2026-07-04T08:10:00Z',
            last_seen: '2026-07-04T10:05:00Z',
            call_count: 42,
            distinct_principal_count: 5,
            is_new: false,
            reviewed: true,
            reviewed_at: '2026-07-04T10:10:00Z',
            reviewed_by: 'operator',
            covered_by_rule: true,
            latency: {
              count: 42,
              p50_ms: 20,
              p95_ms: 55,
              p99_ms: 80,
            },
            status_counts: [
              { status: 200, count: 40 },
              { status: 500, count: 2 },
            ],
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.goto('/admin/traffic');
  await expect(
    page.getByRole('heading', { level: 2, name: 'Traffic inventory' }),
  ).toBeVisible();
  await expect(page.getByText('/api/orders/{order_id}')).toBeVisible();
  const mobileTableBox = await page.locator('.traffic-table').boundingBox();
  const mobileFrameBox = await page.locator('.table-scroll').boundingBox();
  expect(mobileTableBox?.width).toBeLessThanOrEqual((mobileFrameBox?.width ?? 0) + 1);

  await page.screenshot({
    path: path.join(screenshotDir, 'traffic-inventory-mobile.png'),
    fullPage: true,
  });
});
