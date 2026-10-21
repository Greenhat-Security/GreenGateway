import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

import {
  expect,
  test,
  type BrowserContext,
  type Cookie,
  type Page,
  type Response,
} from '@playwright/test';

// Real gateways (HTTPS, ADMIN_SESSION_MODE=standalone_memory) serving the
// admin UI they were built with, signing in through a disposable OIDC
// provider. See tests/fixtures/admin-session-live-server.mjs.
//
// Chromium cannot be handed the run's throwaway CA without changing the
// runner's certificate store, so the browser context accepts the gateways'
// leaf. The page is still an HTTPS secure context, so the __Host-, Secure,
// HttpOnly and SameSite cookie rules apply exactly as in production. This
// spec's own requests to the gateways verify the leaf against that CA.
const PROVIDER_ORIGIN = 'http://127.0.0.1:43211';
const SESSION_COOKIE_PREFIX = '__Host-ggw-admin-session-';
const SIGNED_IN = 'Signed in with SSO. The session cookie lasts until logout or session expiry.';
const SIGNED_OUT = 'Sign in with traffic read permission to view gateway observations.';
const CSRF_REJECTED = { error: 'csrf token missing or invalid' };
const FOREIGN_ORIGIN = 'https://admin-session-attacker.example.test';
// A role the operator holds, so it may delegate it to a service token.
const DELEGATED_ROLE = 'admin-session-reader';

type Gateway = {
  name: 'standard' | 'split' | 'expiring';
  origin: string;
  prefix: string;
  csrfCookie: string;
  csrfHeader: string;
  ttlSeconds: number;
};

const STANDARD: Gateway = {
  name: 'standard',
  origin: 'https://127.0.0.1:43212',
  prefix: '/admin',
  csrfCookie: 'csrf_token',
  csrfHeader: 'x-csrf-token',
  ttlSeconds: 3600,
};
// A management listener whose configured public origin is not its listen
// address, beside a plain-HTTP data listener.
const SPLIT: Gateway = {
  name: 'split',
  origin: 'https://localhost:43214',
  prefix: '/ops-console',
  csrfCookie: '__Host-ggw-ops-csrf',
  csrfHeader: 'x-ggw-ops-csrf',
  ttlSeconds: 3600,
};
const SPLIT_LISTEN_ADDRESS_ORIGIN = 'https://127.0.0.1:43214';
const SPLIT_DATA_ORIGIN = 'http://127.0.0.1:43213';
const EXPIRING: Gateway = {
  name: 'expiring',
  origin: 'https://127.0.0.1:43215',
  prefix: '/admin',
  csrfCookie: 'csrf_token',
  csrfHeader: 'x-csrf-token',
  ttlSeconds: 5,
};

type ProviderState = {
  authorizations: number;
  tokenExchanges: number;
  rejectedRequests: number;
  accessTokens: string[];
  cookieNames: string[];
  artifacts: Record<Gateway['name'], { audit: string; output: string }>;
};

type SignedIn = {
  completion: Response;
  session: Cookie;
  csrf: Cookie;
};

type Answer = {
  status: number;
  body: unknown;
};

type AuditEvent = {
  event_type?: unknown;
  payload?: Record<string, unknown> | null;
};

test.use({
  ignoreHTTPSErrors: true,
  // The provider's browser-facing host; see IDP_BROWSER_AUTHORITY in the fixture.
  launchOptions: { args: ['--host-resolver-rules=MAP idp.admin-session-live.test 127.0.0.1'] },
});

test('keeps a real cookie sign-in whose completion answers after the dashboard was rejected (#424)', async ({ context, page }) => {
  const before = await providerState();
  const gatewayResponses = recordGatewayResponses(page, STANDARD);
  const events: string[] = [];
  const isCapabilities = (response: Response) =>
    new URL(response.url()).pathname === apiPath(STANDARD, '/capabilities');
  page.on('response', (response) => {
    if (isCapabilities(response)) events.push(`capabilities ${response.status()}`);
  });

  const initialRejection = page.waitForResponse((response) => isCapabilities(response) && response.status() === 401);
  await page.goto(uiUrl(STANDARD));
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  await initialRejection;

  // Hold the real completion POST until the returning page's cookie-less
  // permissions request has been rejected: the first-sign-in race.
  let rejectedBeforeCookie!: () => void;
  const rejection = new Promise<void>((resolve) => { rejectedBeforeCookie = resolve; });
  page.on('response', (response) => {
    if (isCapabilities(response) && response.status() === 401 && new URL(response.url()).origin === STANDARD.origin) {
      rejectedBeforeCookie();
    }
  });
  await page.route(`${STANDARD.origin}${apiPath(STANDARD, '/auth/callback')}`, async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }
    await rejection;
    events.push('completion sent');
    await route.continue();
  });
  const completion = page.waitForResponse((response) =>
    new URL(response.url()).pathname === apiPath(STANDARD, '/auth/callback') && response.request().method() === 'POST');
  events.length = 0;

  await page.getByRole('link', { name: 'Log in with SSO' }).click();

  const completed = await completion;
  expect(completed.status()).toBe(200);
  expect(await completed.json()).toEqual({ authenticated: true, expires_in: STANDARD.ttlSeconds });
  await expect(page.getByText(SIGNED_IN, { exact: true })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  expect(events.indexOf('capabilities 401')).toBeGreaterThanOrEqual(0);
  expect(events.indexOf('capabilities 401')).toBeLessThan(events.indexOf('completion sent'));
  expect(events.indexOf('completion sent')).toBeLessThan(events.indexOf('capabilities 200'));

  // The gateway set a production session cookie; no credential reached the page.
  await expectProductionSessionCookie(completed, STANDARD);
  const { session, csrf } = await gatewayCookies(context, STANDARD);
  const provider = await providerState();
  expect(provider.authorizations - before.authorizations).toBe(1);
  expect(provider.tokenExchanges - before.tokenExchanges).toBe(1);
  expect(provider.rejectedRequests).toBe(before.rejectedRequests);
  const credentials = [...provider.accessTokens, session.value];
  await expectNoCredentialInPage(page, credentials);

  // The session survives a reload and is accepted by the gateway.
  await page.reload();
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  await expect(page.getByLabel('Endpoint', { exact: true })).toBeVisible();
  expect((await capabilitiesWith(STANDARD, session)).status).toBe(200);

  // Logout revokes the server session, not only the browser cookie.
  await logOut(page, STANDARD, csrf);
  expect((await capabilitiesWith(STANDARD, session)).status).toBe(401);

  expectNoCredentialIn(await gatewayResponses(), credentials, 'gateway responses delivered to the page');
  await expectNoCredentialLeftTheGateway(STANDARD, credentials);
});

test('sends the CSRF pair with cookie-session mutations and refuses unsafe requests without it (#424)', async ({ page }) => {
  const gatewayResponses = recordGatewayResponses(page, STANDARD);
  const { session, csrf } = await signIn(page, STANDARD);
  const tokensPath = apiPath(STANDARD, '/tokens');

  // A protected mutation through the UI: the shared client echoes the
  // readable CSRF cookie into the configured header and sends no bearer.
  await openTokens(page);
  const created = await createServiceToken(page, STANDARD);
  await expectCookieSessionMutation(created, STANDARD, session, csrf);
  const tokenId = ((await created.json()) as { token: { id: string } }).token.id;
  await page.getByRole('button', { name: "I've saved this" }).click();
  const tokensBefore = await listTokenIds(page, STANDARD);
  expect(tokensBefore).toContain(tokenId);

  // The same request from this page without the header, or with a header
  // that does not match the cookie, is refused before it reaches the handler.
  const createBody = JSON.stringify({ scopes: [DELEGATED_ROLE] });
  for (const headers of [{}, { [STANDARD.csrfHeader]: 'admin-session-mismatched-csrf' }]) {
    expect(await pageFetch(page, tokensPath, { method: 'POST', headers, body: createBody }))
      .toEqual({ status: 403, body: CSRF_REJECTED });
  }
  // The double-submit pair is not enough without the exact management Origin.
  for (const origin of [FOREIGN_ORIGIN, null]) {
    const answer = await gatewayRequest(`${STANDARD.origin}${tokensPath}`, {
      method: 'POST',
      headers: {
        ...sessionHeaders(STANDARD, session, csrf),
        ...(origin ? { Origin: origin } : {}),
        'Content-Type': 'application/json',
      },
      body: createBody,
    });
    expect(answer).toEqual({ status: 403, body: { error: 'invalid_origin' } });
  }
  // None of the refused requests created a token.
  expect(await listTokenIds(page, STANDARD)).toEqual(tokensBefore);

  // A second protected mutation through the UI.
  await page.getByRole('button', { name: `Revoke token ${tokenId}` }).click();
  const [revoked] = await Promise.all([
    page.waitForResponse((response) =>
      new URL(response.url()).pathname === `${tokensPath}/${tokenId}` && response.request().method() === 'DELETE'),
    page.getByRole('button', { name: `Confirm revoke token ${tokenId}` }).click(),
  ]);
  expect(revoked.status()).toBe(200);
  await expectCookieSessionMutation(revoked, STANDARD, session, csrf);
  await expect(page.getByRole('row').filter({ hasText: tokenId }).getByText('Revoked', { exact: true })).toBeVisible();

  // Logout needs the pair and the exact Origin too; refused attempts keep
  // the session.
  expect(await pageFetch(page, apiPath(STANDARD, '/auth/logout'), { method: 'POST' }))
    .toEqual({ status: 403, body: CSRF_REJECTED });
  expect(await gatewayRequest(`${STANDARD.origin}${apiPath(STANDARD, '/auth/logout')}`, {
    method: 'POST',
    headers: { ...sessionHeaders(STANDARD, session, csrf), Origin: FOREIGN_ORIGIN },
  })).toEqual({ status: 403, body: { error: 'invalid_origin_or_csrf' } });
  expect((await capabilitiesWith(STANDARD, session)).status).toBe(200);

  await logOut(page, STANDARD, csrf);
  expect((await capabilitiesWith(STANDARD, session)).status).toBe(401);

  // The audit log records each decision. CSRF refusals of admin API requests
  // are recorded as observed requests that never reached authentication; the
  // session lifecycle routes also record their own denial reasons.
  await expect.poll(() => auditOutcomes(STANDARD), { timeout: 10_000 }).toEqual(expect.arrayContaining([
    'admin_login.transaction session accepted session_issued',
    `auth.success ${tokensPath} session_cookie`,
    `http.request_observed POST ${tokensPath} 201 authenticated`,
    `http.request_observed POST ${tokensPath} 403 not_evaluated`,
    `auth.failure ${tokensPath} admin_session_origin_mismatch`,
    `http.request_observed DELETE ${tokensPath}/${tokenId} 200 authenticated`,
    'admin_login.transaction logout denied csrf_rejected',
    'admin_login.transaction logout denied invalid_origin_or_csrf',
    'admin_login.transaction logout accepted session_revoked',
  ]));

  const credentials = [...(await providerState()).accessTokens, session.value];
  expectNoCredentialIn(await gatewayResponses(), credentials, 'gateway responses delivered to the page');
  await expectNoCredentialLeftTheGateway(STANDARD, credentials);
});

test('ends the cookie session at its deadline even while the browser still presents it (#424)', async ({ context, page }) => {
  const { completion, session } = await signIn(page, EXPIRING);
  const signedInAt = Date.now();
  await expectProductionSessionCookie(completion, EXPIRING);

  // The cookie's Max-Age matches the deadline, so a browser would drop it on
  // time. Keep presenting it, as a client with a skewed clock would: only the
  // server's deadline can end the session then.
  await context.addCookies([{
    name: session.name,
    value: session.value,
    url: EXPIRING.origin,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    expires: Math.floor(Date.now() / 1000) + 3600,
  }]);
  expect((await openTokens(page))?.status()).toBe(200);
  // Still inside the deadline, so the view above was served by the session.
  expect(Date.now() - signedInAt).toBeLessThan(EXPIRING.ttlSeconds * 1000);

  await expect.poll(async () => (await capabilitiesWith(EXPIRING, session)).status, {
    intervals: [250],
    timeout: (EXPIRING.ttlSeconds + 10) * 1000,
  }).toBe(401);

  // The next admin request from any view carries the cookie, is answered
  // 401, and the view says the session ended instead of showing stale data.
  const [rejected] = await Promise.all([
    page.waitForResponse((response) => isAdminRejection(response, EXPIRING)),
    page.getByRole('navigation', { name: 'Admin sections' }).getByRole('link', { name: 'Traffic', exact: true }).click(),
  ]);
  expect(cookieNames((await rejected.request().allHeaders()).cookie)).toContain(session.name);
  await expect(page.getByRole('heading', { level: 2, name: 'Admin session expired' })).toBeVisible();
  await page.getByRole('button', { name: 'Check session' }).click();
  await expect(page.getByText('Sign in again to continue.')).toBeVisible();

  // Signing in again issues a new session; the expired one stays refused.
  await page.getByRole('link', { name: 'Sign in', exact: true }).click();
  const renewed = await signIn(page, EXPIRING, { navigate: false });
  expect(renewed.session.value === session.value).toBe(false);
  expect((await capabilitiesWith(EXPIRING, session)).status).toBe(401);
  await expectNoCredentialLeftTheGateway(EXPIRING, [
    ...(await providerState()).accessTokens,
    session.value,
    renewed.session.value,
  ]);
});

test('ends the cookie session at the first access-token rejection, before its deadline (#424)', async ({ page }) => {
  // The provider's next access token for this gateway expires a few seconds
  // after issuance, long before the session's hour-long deadline.
  const shortened = await fetch(`${PROVIDER_ORIGIN}/__fixture/short-access-token?gateway=${STANDARD.name}`, {
    method: 'POST',
  });
  expect(shortened.status).toBe(200);
  const { remaining_seconds: remainingSeconds } = (await shortened.json()) as { remaining_seconds: number };

  const { session } = await signIn(page, STANDARD);
  expect((await capabilitiesWith(STANDARD, session)).status).toBe(200);
  await expect.poll(async () => (await capabilitiesWith(STANDARD, session)).status, {
    intervals: [250],
    timeout: (remainingSeconds + 10) * 1000,
  }).toBe(401);

  // The browser still holds the hour-long cookie and sends it; the gateway
  // refuses it because its access token no longer validates.
  const [rejected] = await Promise.all([
    page.waitForResponse((response) => isAdminRejection(response, STANDARD)),
    openTokens(page, { expectLoaded: false }),
  ]);
  expect(cookieNames((await rejected.request().allHeaders()).cookie)).toContain(session.name);
  await expect(page.getByRole('heading', { level: 2, name: 'Admin session expired' })).toBeVisible();
  await expectNoCredentialLeftTheGateway(STANDARD, [...(await providerState()).accessTokens, session.value]);
});

test('confines the session to the configured public origin, prefix and CSRF names on a split listener (#424)', async ({ page }) => {
  const gatewayResponses = recordGatewayResponses(page, SPLIT);
  // The management listener has no /version, so the UI asks auth/config.
  const version = page.waitForResponse((response) => response.url() === `${SPLIT.origin}/version`);
  const discovery = page.waitForResponse((response) =>
    response.url() === `${SPLIT.origin}${apiPath(SPLIT, '/auth/config')}`);
  const { completion, session, csrf } = await signIn(page, SPLIT);
  expect((await version).status()).toBe(404);
  expect((await discovery).status()).toBe(200);
  await expectProductionSessionCookie(completion, SPLIT);
  // The cookie names derive from this prefix and from CSRF_COOKIE_NAME.
  expect(session.name).not.toBe(sessionCookieName(STANDARD.prefix));
  expect(csrf.name).toBe(SPLIT.csrfCookie);

  await openTokens(page);
  const created = await createServiceToken(page, SPLIT);
  await expectCookieSessionMutation(created, SPLIT, session, csrf);
  expect((await created.request().allHeaders())[STANDARD.csrfHeader]).toBeUndefined();
  await page.getByRole('button', { name: "I've saved this" }).click();
  const tokensBefore = await listTokenIds(page, SPLIT);

  // The configured names are authoritative: the default header name, even
  // carrying the right value, is refused.
  const tokensPath = apiPath(SPLIT, '/tokens');
  const createBody = JSON.stringify({ scopes: [DELEGATED_ROLE] });
  expect(await pageFetch(page, tokensPath, {
    method: 'POST',
    headers: { [STANDARD.csrfHeader]: csrf.value },
    body: createBody,
  })).toEqual({ status: 403, body: CSRF_REJECTED });
  // The configured public origin, not the listen address, is the authority.
  expect(await gatewayRequest(`${SPLIT_LISTEN_ADDRESS_ORIGIN}${tokensPath}`, {
    method: 'POST',
    headers: {
      ...sessionHeaders(SPLIT, session, csrf),
      Origin: SPLIT_LISTEN_ADDRESS_ORIGIN,
      'Content-Type': 'application/json',
    },
    body: createBody,
  })).toEqual({ status: 403, body: { error: 'invalid_origin' } });
  // The same live session is no credential on the data listener, which has
  // no management routes at all.
  expect((await capabilitiesWith(SPLIT, session)).status).toBe(200);
  const onDataListener = (route: string, method = 'GET') =>
    gatewayRequest(`${SPLIT_DATA_ORIGIN}${apiPath(SPLIT, route)}`, {
      method,
      headers: {
        ...sessionHeaders(SPLIT, session, csrf),
        Origin: SPLIT.origin,
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
      body: method === 'POST' ? createBody : undefined,
    });
  expect((await onDataListener('/capabilities')).status).toBe(401);
  expect((await onDataListener('/tokens', 'POST')).status).toBe(401);
  expect((await onDataListener('/auth/config')).status).toBe(404);
  // The data listener did not consider the cookie a credential at all. (The
  // UI never requests the token list before sign-in, so this is that POST.)
  await expect.poll(() => auditOutcomes(SPLIT), { timeout: 10_000 })
    .toContain(`auth.failure ${tokensPath} missing_credential`);
  expect(await listTokenIds(page, SPLIT)).toEqual(tokensBefore);

  await logOut(page, SPLIT, csrf);
  expect((await capabilitiesWith(SPLIT, session)).status).toBe(401);

  const credentials = [...(await providerState()).accessTokens, session.value];
  expectNoCredentialIn(await gatewayResponses(), credentials, 'gateway responses delivered to the page');
  await expectNoCredentialLeftTheGateway(SPLIT, credentials);
});

function apiPath(gateway: Gateway, route: string): string {
  return `/v1${gateway.prefix}${route}`;
}

function uiUrl(gateway: Gateway): string {
  return `${gateway.origin}${gateway.prefix}/`;
}

/** The gateway namespaces its session cookie by the admin prefix. */
function sessionCookieName(prefix: string): string {
  return `${SESSION_COOKIE_PREFIX}${createHash('sha256').update(prefix).digest('hex').slice(0, 16)}`;
}

async function signIn(
  page: Page,
  gateway: Gateway,
  { navigate = true }: { navigate?: boolean } = {},
): Promise<SignedIn> {
  if (navigate) {
    await page.goto(uiUrl(gateway));
  }
  await expect(page.getByRole('heading', { level: 2, name: 'SSO session' })).toBeVisible();
  const completion = page.waitForResponse((response) =>
    new URL(response.url()).pathname === apiPath(gateway, '/auth/callback') && response.request().method() === 'POST');
  await page.getByRole('link', { name: 'Log in with SSO' }).click();
  const completed = await completion;
  expect(completed.status()).toBe(200);
  expect(await completed.json()).toEqual({ authenticated: true, expires_in: gateway.ttlSeconds });
  await expect(page.getByText(SIGNED_IN, { exact: true })).toBeVisible();
  return { completion: completed, ...(await gatewayCookies(page.context(), gateway)) };
}

async function logOut(page: Page, gateway: Gateway, csrf: Cookie) {
  await page.getByRole('navigation', { name: 'Admin sections' }).getByRole('link', { name: 'Token/Dashboard' }).click();
  const [loggedOut] = await Promise.all([
    page.waitForResponse((response) =>
      new URL(response.url()).pathname === apiPath(gateway, '/auth/logout') && response.request().method() === 'POST'),
    page.getByRole('button', { name: 'Log out', exact: true }).click(),
  ]);
  expect(loggedOut.status()).toBe(204);
  expect((await loggedOut.request().allHeaders())[gateway.csrfHeader] === csrf.value).toBe(true);
  // The session cookie is expired with the attributes it was issued with.
  const name = sessionCookieName(gateway.prefix);
  const expired = (await loggedOut.headerValues('set-cookie')).filter((value) => value.startsWith(`${name}=`));
  expect(expired.length).toBe(1);
  expect(cookieAttributes(expired[0])).toEqual(['httponly', 'max-age=0', 'path=/', 'samesite=lax', 'secure']);
  expect(expired[0].startsWith(`${name}=;`)).toBe(true);
  await expect(page.getByText(SIGNED_OUT)).toBeVisible();
  expect((await page.context().cookies(gateway.origin)).some((cookie) => cookie.name === name)).toBe(false);
}

/** The raw Set-Cookie header: production attributes, no Domain or Expires. */
async function expectProductionSessionCookie(completion: Response, gateway: Gateway) {
  const name = sessionCookieName(gateway.prefix);
  const values = (await completion.headerValues('set-cookie')).filter((value) => value.startsWith(`${name}=`));
  expect(values.length).toBe(1);
  const value = values[0].split(';')[0].slice(name.length + 1);
  expect(/^[0-9a-f]{64}$/.test(value), 'a 256-bit random session value').toBe(true);
  expect(cookieAttributes(values[0])).toEqual([
    'httponly',
    `max-age=${gateway.ttlSeconds}`,
    'path=/',
    'samesite=lax',
    'secure',
  ]);
}

function cookieAttributes(setCookie: string): string[] {
  return setCookie.split(';').slice(1).map((attribute) => attribute.trim().toLowerCase()).sort();
}

/** The browser's view of both cookies, for the gateway's own host only. */
async function gatewayCookies(context: BrowserContext, gateway: Gateway): Promise<{ session: Cookie; csrf: Cookie }> {
  const cookies = await context.cookies(gateway.origin);
  const host = new URL(gateway.origin).hostname;
  const session = cookies.find((cookie) => cookie.name === sessionCookieName(gateway.prefix));
  const csrf = cookies.find((cookie) => cookie.name === gateway.csrfCookie);
  if (!session || !csrf) {
    throw new Error('the gateway did not set its session and CSRF cookies');
  }
  expect(cookies.filter((cookie) => cookie.name.startsWith(SESSION_COOKIE_PREFIX)).length).toBe(1);
  expect({
    domain: session.domain,
    path: session.path,
    httpOnly: session.httpOnly,
    secure: session.secure,
    sameSite: session.sameSite,
  }).toEqual({ domain: host, path: '/', httpOnly: true, secure: true, sameSite: 'Lax' });
  // The CSRF cookie must stay readable by page script for the double submit.
  expect({
    domain: csrf.domain,
    path: csrf.path,
    httpOnly: csrf.httpOnly,
    secure: csrf.secure,
    sameSite: csrf.sameSite,
  }).toEqual({ domain: host, path: '/', httpOnly: false, secure: true, sameSite: 'Lax' });
  return { session, csrf };
}

/** Opens the Tokens view and, unless told otherwise, waits for its list. */
async function openTokens(
  page: Page,
  { expectLoaded = true }: { expectLoaded?: boolean } = {},
): Promise<Response | null> {
  const link = page.getByRole('navigation', { name: 'Admin sections' }).getByRole('link', { name: 'Tokens', exact: true });
  if (!expectLoaded) {
    await link.click();
    return null;
  }
  const [listed] = await Promise.all([
    page.waitForResponse((response) =>
      /\/tokens$/.test(new URL(response.url()).pathname) && response.request().method() === 'GET'),
    link.click(),
  ]);
  await expect(page.getByRole('heading', { level: 2, name: 'Service tokens' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create token' })).toBeVisible();
  return listed;
}

async function listTokenIds(page: Page, gateway: Gateway): Promise<string[]> {
  const listed = await pageFetch(page, `${apiPath(gateway, '/tokens')}?limit=200`);
  expect(listed.status).toBe(200);
  return (listed.body as { tokens: { id: string }[] }).tokens.map((token) => token.id).sort();
}

async function createServiceToken(page: Page, gateway: Gateway): Promise<Response> {
  await page.getByLabel('Scopes', { exact: true }).fill(DELEGATED_ROLE);
  const [created] = await Promise.all([
    page.waitForResponse((response) =>
      new URL(response.url()).pathname === apiPath(gateway, '/tokens') && response.request().method() === 'POST'),
    page.getByRole('button', { name: 'Create token' }).click(),
  ]);
  expect(created.status()).toBe(201);
  await expect(page.getByRole('heading', { level: 3, name: 'Save this token now' })).toBeVisible();
  return created;
}

async function expectCookieSessionMutation(response: Response, gateway: Gateway, session: Cookie, csrf: Cookie) {
  const headers = await response.request().allHeaders();
  expect(headers.origin).toBe(gateway.origin);
  expect(headers.authorization).toBeUndefined();
  expect(headers[gateway.csrfHeader] === csrf.value, 'the CSRF header echoes the CSRF cookie').toBe(true);
  expect(cookieNames(headers.cookie)).toEqual(expect.arrayContaining([session.name, csrf.name]));
}

function isAdminRejection(response: Response, gateway: Gateway): boolean {
  const url = new URL(response.url());
  return url.origin === gateway.origin && url.pathname.startsWith(apiPath(gateway, '/')) && response.status() === 401;
}

function cookieNames(header: string | undefined): string[] {
  return (header ?? '').split(';').map((pair) => pair.split('=')[0].trim()).filter(Boolean);
}

/** A same-origin request from the signed-in page with its ambient cookies. */
async function pageFetch(
  page: Page,
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Answer> {
  return page.evaluate(async ({ path: target, init: options }) => {
    const response = await fetch(target, {
      method: options.method ?? 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
      body: options.body,
    });
    const text = await response.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // Not JSON; keep the text.
    }
    return { status: response.status, body };
  }, { path, init });
}

function sessionHeaders(gateway: Gateway, session: Cookie, csrf: Cookie): Record<string, string> {
  return {
    Cookie: `${session.name}=${session.value}; ${csrf.name}=${csrf.value}`,
    [gateway.csrfHeader]: csrf.value,
  };
}

function capabilitiesWith(gateway: Gateway, session: Cookie): Promise<Answer> {
  return gatewayRequest(`${gateway.origin}${apiPath(gateway, '/capabilities')}`, {
    headers: { Cookie: `${session.name}=${session.value}` },
  });
}

let runCertificateAuthority: Promise<string> | undefined;

function certificateAuthority(): Promise<string> {
  runCertificateAuthority ??= fetch(`${PROVIDER_ORIGIN}/__fixture/ca.pem`).then(async (response) => {
    if (!response.ok) {
      throw new Error('the fixture did not provide its certificate authority');
    }
    return response.text();
  });
  return runCertificateAuthority;
}

/**
 * A request from outside the browser. HTTPS is verified against the run's
 * CA, including the host name. Every gateway listens on 127.0.0.1; the URL
 * host is sent as Host and, for a DNS name, as the TLS server name.
 */
async function gatewayRequest(
  target: string,
  { method = 'GET', headers = {}, body }: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Answer> {
  const url = new URL(target);
  const secure = url.protocol === 'https:';
  const ca = secure ? await certificateAuthority() : undefined;
  return new Promise((resolve, reject) => {
    const request = (secure ? httpsRequest : httpRequest)({
      host: '127.0.0.1',
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      headers: { ...headers, Host: url.host, Accept: 'application/json' },
      timeout: 5_000,
      ...(secure ? { ca, ...(isIP(url.hostname) ? {} : { servername: url.hostname }) } : {}),
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: unknown = text;
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch {
          // Not JSON; keep the text.
        }
        resolve({ status: response.statusCode ?? 0, body: parsed });
      });
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('gateway request timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

async function providerState(): Promise<ProviderState> {
  const response = await fetch(`${PROVIDER_ORIGIN}/__fixture/state`);
  expect(response.ok).toBe(true);
  return (await response.json()) as ProviderState;
}

/** Every header (except Set-Cookie) and body the page received from the gateway. */
function recordGatewayResponses(page: Page, gateway: Gateway): () => Promise<string[]> {
  const pending: Promise<string>[] = [];
  page.on('response', (response) => {
    if (new URL(response.url()).origin !== gateway.origin) {
      return;
    }
    pending.push((async () => {
      const headers = (await response.headersArray())
        .filter((header) => header.name.toLowerCase() !== 'set-cookie')
        .map((header) => `${header.name}: ${header.value}`);
      const body = await response.text().catch(() => '');
      return `${headers.join('\n')}\n${body}`;
    })().catch(() => ''));
  });
  return () => Promise.all(pending);
}

/** Counts only, so a failure never prints a credential. */
function expectNoCredentialIn(haystacks: string[], credentials: string[], where: string) {
  const leaked = credentials.filter((credential) =>
    credential.length > 0 && haystacks.some((haystack) => haystack.includes(credential))).length;
  expect(leaked, `credentials found in ${where}`).toBe(0);
}

async function expectNoCredentialInPage(page: Page, credentials: string[]) {
  const state = await page.evaluate(() => ({
    secureContext: window.isSecureContext,
    cookie: document.cookie,
    html: document.documentElement.outerHTML,
    location: window.location.href,
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    resources: performance.getEntries().map((entry) => entry.name),
  }));
  expect(state.secureContext).toBe(true);
  expect(cookieNames(state.cookie).some((name) => name.startsWith(SESSION_COOKIE_PREFIX))).toBe(false);
  expect(state.local.map(([key]) => key)).toEqual(['greengateway_admin_theme']);
  expect(state.session).toEqual([]);
  expectNoCredentialIn(
    [state.cookie, state.html, state.location, JSON.stringify(state.local), ...state.resources],
    credentials,
    'page script state',
  );
}

/**
 * Neither the provider nor the gateway's own artifacts saw a credential: the
 * provider received no cookie at all, and the audit log and process output
 * never carry an access token or a session value.
 */
async function expectNoCredentialLeftTheGateway(gateway: Gateway, credentials: string[]) {
  const state = await providerState();
  expect(state.cookieNames).toEqual([]);
  const files = state.artifacts[gateway.name];
  const contents = [files.audit, files.output].map((file) => readFileSync(file, 'utf8'));
  expect(contents[0].includes('"admin_login.transaction"'), 'the audit log was written').toBe(true);
  expectNoCredentialIn(contents, credentials, `the ${gateway.name} gateway audit log and output`);
}

/**
 * Bounded audit projections: the event type, then whichever of the request
 * method, path, status, lifecycle phase, outcome, reason, authentication
 * outcome and method it records. Identities and request ids are left out.
 */
async function auditOutcomes(gateway: Gateway): Promise<string[]> {
  const state = await providerState();
  let text = '';
  try {
    text = readFileSync(state.artifacts[gateway.name].audit, 'utf8');
  } catch {
    return [];
  }
  return text.split('\n').filter(Boolean).flatMap((line) => {
    try {
      const event = JSON.parse(line) as AuditEvent;
      const payload = event.payload ?? {};
      return [[
        event.event_type,
        payload.method,
        payload.path,
        payload.status,
        payload.phase,
        payload.outcome,
        payload.reason,
        payload.auth_outcome,
        payload.auth_mode,
      ]
        .filter((part) => typeof part === 'string' || typeof part === 'number')
        .join(' ')];
    } catch {
      return [];
    }
  });
}
