import { expect, test } from '@playwright/test';
import { trafficOverviewFixture } from './fixtures/traffic-overview';

for (const theme of ['light', 'dark']) {
  test(`traffic overview ${theme} desktop and mobile`, async ({ page }) => {
    await page.addInitScript(value => localStorage.setItem('greengateway_admin_theme', value), theme);
    await page.route('**/version', route => route.fulfill({ json: { version: 'synthetic-fixture', admin_login_configured: false } }));
    await page.route('**/v1/admin/**', route => {
      if (route.request().url().includes('/traffic/endpoints')) return route.fulfill({ json: { endpoints: trafficOverviewFixture, next_cursor: null } });
      return route.fulfill({ json: { permissions: ['admin:traffic:read'] } });
    });
    await page.goto('/admin/');
    const overview = page.getByRole('region', { name: 'Traffic overview', exact: true });
    await expect(overview.getByRole('img')).toBeVisible();
    await overview.screenshot({ path: `.screenshots/traffic-overview-${theme}.png` });
    await overview.getByLabel('Method', { exact: true }).selectOption('MCP');
    await overview.getByRole('button', { name: 'Table', exact: true }).click();
    await expect(overview.getByRole('table')).toContainText('5,400');
    await expect(overview.getByRole('table')).not.toContainText('GET');
    await overview.getByLabel('Method', { exact: true }).selectOption('');
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(overview.getByRole('table')).toBeVisible();
    await overview.screenshot({ path: `.screenshots/traffic-overview-${theme}-mobile.png` });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await overview.getByRole('button', { name: /https:\/\/orders.example.test/ }).click();
    await expect(overview.getByRole('link', { name: 'GET /api/orders/{id}' })).toHaveAttribute('href', /endpoint_template=/);
  });
}
