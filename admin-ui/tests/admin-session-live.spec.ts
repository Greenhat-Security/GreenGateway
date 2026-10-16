import { expect, test, type APIRequestContext, type Response } from '@playwright/test';

// A real gateway (HTTPS, ADMIN_SESSION_MODE=standalone_memory) serving the
// admin UI it was built with, signing in through a disposable OIDC provider.
// See tests/fixtures/admin-session-live-server.mjs.
const GATEWAY_ORIGIN = 'https://127.0.0.1:43212';
const PROVIDER_ORIGIN = 'http://127.0.0.1:43211';
const SESSION_COOKIE_PREFIX = '__Host-ggw-admin-session-';

type ProviderState = {
  authorizations: number;
  tokenExchanges: number;
  rejectedRequests: number;
  accessTokens: string[];
};

test.use({ baseURL: GATEWAY_ORIGIN, ignoreHTTPSErrors: true });

test('keeps a real cookie sign-in whose completion answers after the dashboard was rejected (#424)', async ({ context, page, request }) => {
  const events: string[] = [];
  const isCapabilities = (response: Response) =>
    new URL(response.url()).pathname === '/v1/admin/capabilities';
  page.on('response', (response) => {
    if (isCapabilities(response)) events.push(`capabilities ${response.status()}`);
  });

  const initialRejection = page.waitForResponse((response) => isCapabilities(response) && response.status() === 401);
  await page.goto('/admin/');
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  await initialRejection;

  // Hold the real completion POST until the returning page's cookie-less
  // permissions request has been rejected: the first-sign-in race.
  let rejectedBeforeCookie!: () => void;
  const rejection = new Promise<void>((resolve) => { rejectedBeforeCookie = resolve; });
  page.on('response', (response) => {
    if (isCapabilities(response) && response.status() === 401 && new URL(response.url()).origin === GATEWAY_ORIGIN) {
      rejectedBeforeCookie();
    }
  });
  await page.route('**/v1/admin/auth/callback', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }
    await rejection;
    events.push('completion sent');
    await route.continue();
  });
  const completion = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/v1/admin/auth/callback' && response.request().method() === 'POST');
  events.length = 0;

  await page.getByRole('link', { name: 'Log in with SSO' }).click();

  const completed = await completion;
  expect(completed.status()).toBe(200);
  const completionBody: unknown = await completed.json();
  expect(completionBody).toMatchObject({ authenticated: true });
  expect(Object.keys(completionBody as object).sort()).toEqual(['authenticated', 'expires_in']);
  await expect(page.getByText('Signed in with SSO. The session cookie lasts until logout or session expiry.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  expect(events.indexOf('capabilities 401')).toBeGreaterThanOrEqual(0);
  expect(events.indexOf('capabilities 401')).toBeLessThan(events.indexOf('completion sent'));
  expect(events.indexOf('completion sent')).toBeLessThan(events.indexOf('capabilities 200'));

  // The gateway set an HttpOnly cookie; no bearer credential reached the page.
  const session = (await context.cookies(GATEWAY_ORIGIN)).find((cookie) => cookie.name.startsWith(SESSION_COOKIE_PREFIX));
  expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', path: '/' });
  const provider = await providerState(request);
  expect(provider).toMatchObject({ authorizations: 1, tokenExchanges: 1, rejectedRequests: 0 });
  const pageState = await page.evaluate(() => ({
    cookie: document.cookie,
    html: document.documentElement.outerHTML,
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  expect(pageState.cookie).not.toContain(SESSION_COOKIE_PREFIX);
  expect(pageState.local.map(([key]) => key)).toEqual(['greengateway_admin_theme']);
  expect(pageState.session).toEqual([]);
  for (const token of provider.accessTokens) {
    expect(JSON.stringify(completionBody).includes(token)).toBe(false);
    expect(pageState.html.includes(token)).toBe(false);
    expect(pageState.cookie.includes(token)).toBe(false);
  }

  // The session survives a reload and is accepted by the gateway.
  await page.reload();
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  const cookieHeader = { Cookie: `${session?.name}=${session?.value}` };
  expect((await request.get('/v1/admin/capabilities', { headers: cookieHeader })).status()).toBe(200);

  // Logout revokes the server session, not only the browser cookie.
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await expect(page.getByText('Sign in with traffic read permission to view gateway observations.')).toBeVisible();
  expect((await context.cookies(GATEWAY_ORIGIN)).some((cookie) => cookie.name.startsWith(SESSION_COOKIE_PREFIX))).toBe(false);
  expect((await request.get('/v1/admin/capabilities', { headers: cookieHeader })).status()).toBe(401);
});

async function providerState(request: APIRequestContext): Promise<ProviderState> {
  const response = await request.get(`${PROVIDER_ORIGIN}/__fixture/state`);
  expect(response.ok()).toBeTruthy();
  return (await response.json()) as ProviderState;
}
