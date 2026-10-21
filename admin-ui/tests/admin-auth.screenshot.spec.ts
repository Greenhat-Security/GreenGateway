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

const ADMIN_SESSION = {
  storage: 'standalone_memory', completion_mode: 'cookie', login_url: '/v1/admin/auth/login',
  completion_url: '/v1/admin/auth/callback', logout_url: '/v1/admin/auth/logout', max_age_seconds: 3600,
};

test('defaults to an advertised cookie session and keeps bearer mode explicit', async ({ context, page }) => {
  await page.route('**/version', (route) => route.fulfill({ json: {
    admin_login_configured: true,
    admin_session: ADMIN_SESSION,
  } }));
  const logouts: Record<string, string>[] = [];
  await page.route('**/v1/admin/auth/logout', (route) => {
    logouts.push(route.request().headers());
    return route.fulfill({ status: 204 });
  });
  const csrf = `test-${randomUUID()}`;
  await context.addCookies([{ name: 'csrf_token', value: csrf, url: 'http://127.0.0.1:43173' }]);
  await page.goto('/admin/');
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  await expect(page.getByLabel('Token', { exact: true })).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect(page.getByRole('button', { name: 'Use bearer token', exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: path.join('.screenshots', `admin-cookie-session-${width}.png`), fullPage: true });
  }
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await expect(page.getByText('Logged out. Sign in again to continue.', { exact: true })).toBeVisible();
  expect(logouts).toHaveLength(1);
  expect(logouts[0]['x-csrf-token']).toBe(csrf);
  expect(logouts[0].authorization).toBeUndefined();
  await page.getByRole('button', { name: 'Use bearer token', exact: true }).click();
  await expect(page.getByLabel('Token', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Use SSO session', exact: true })).toBeFocused();
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }))).toEqual({ local: ['greengateway_admin_theme'], session: [] });
});

test('keeps a cookie sign-in whose completion answers after the first permissions rejection', async ({ page }) => {
  await page.route('**/version', (route) => route.fulfill({ json: { admin_login_configured: true, admin_session: ADMIN_SESSION } }));
  const session = `test-${randomUUID()}`;
  let rejectedBeforeSignIn!: () => void;
  const rejection = new Promise<void>((resolve) => { rejectedBeforeSignIn = resolve; });
  const completions: string[] = [];
  await page.route('**/v1/admin/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/v1/admin/auth/callback') {
      completions.push(request.postData() ?? '');
      // The gateway answers only after the dashboard's cookie-less request was rejected.
      await rejection;
      return route.fulfill({
        json: { authenticated: true, expires_in: 3600 },
        headers: { 'set-cookie': `gg_test_session=${session}; Path=/; HttpOnly; SameSite=Lax` },
      });
    }
    if (path === '/v1/admin/traffic/endpoints') return route.fulfill({ json: { endpoints: [], next_cursor: null } });
    if ((await request.allHeaders()).cookie?.includes(`gg_test_session=${session}`)) {
      return route.fulfill({ json: { permissions: ['admin:traffic:read'] } });
    }
    rejectedBeforeSignIn();
    return route.fulfill({ status: 401, json: { error: 'unauthenticated' } });
  });

  await page.goto('/admin/#/auth/complete?code=code&state=state');

  await expect(page.getByText('Signed in with SSO. The session cookie lasts until logout or session expiry.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  expect(completions).toEqual([JSON.stringify({ code: 'code', state: 'state', mode: 'cookie' })]);
  expect(await page.evaluate(() => document.cookie.includes('gg_test_session'))).toBe(false);
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }))).toEqual({ local: ['greengateway_admin_theme'], session: [] });
});

test('keeps a bearer sign-in whose token answers after the first permissions rejection', async ({ page }) => {
  await page.route('**/version', (route) => route.fulfill({ json: { admin_login_configured: true } }));
  const token = `test-${randomUUID()}`;
  let rejectedBeforeSignIn!: () => void;
  const rejection = new Promise<void>((resolve) => { rejectedBeforeSignIn = resolve; });
  const completions: string[] = [];
  await page.route('**/v1/admin/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/v1/admin/auth/callback') {
      completions.push(request.postData() ?? '');
      // The gateway's token exchange answers only after the dashboard's
      // token-less request was rejected.
      await rejection;
      return route.fulfill({ json: { access_token: token } });
    }
    if (path === '/v1/admin/traffic/endpoints') return route.fulfill({ json: { endpoints: [], next_cursor: null } });
    if ((await request.allHeaders()).authorization === `Bearer ${token}`) {
      return route.fulfill({ json: { permissions: ['admin:traffic:read'] } });
    }
    rejectedBeforeSignIn();
    return route.fulfill({ status: 401, json: { error: 'unauthenticated' } });
  });

  await page.goto('/admin/#/auth/complete?code=code&state=state');

  await expect(page.getByText('Signed in with SSO in this tab until reload or session expiry.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  expect(completions).toEqual([JSON.stringify({ code: 'code', state: 'state' })]);
  expect((await page.content()).includes(token)).toBe(false);
  expect(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }))).toEqual({ local: ['greengateway_admin_theme'], session: [] });
});
