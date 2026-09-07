import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

test.use({ trace: 'off' });
test('keeps the memory-only sign-in controls usable on desktop and mobile', async ({ page }) => {
  await page.route('**/version', (route) => route.fulfill({ json: { admin_login_configured: true } }));
  await page.goto('/admin/');
  await expect(page.getByRole('link', { name: 'Log in with SSO' })).toBeVisible();
  const token = `test-${randomUUID()}`;
  const input = page.getByLabel('Token', { exact: true });
  await input.fill(token);
  expect((await page.content()).includes(token)).toBe(false);
  await page.getByRole('button', { name: 'Show token' }).click();
  await expect(input).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(input).toHaveValue('');
  await expect(input).toHaveAttribute('type', 'password');
  expect((await page.content()).includes(token)).toBe(false);
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }))).toEqual({ local: ['greengateway_admin_theme'], session: [] });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect(page.getByRole('button', { name: 'Clear', exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: path.join('.screenshots', `admin-memory-auth-${width}.png`), fullPage: true });
  }
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(page.getByText('Token cleared.', { exact: true })).toBeVisible();
});
