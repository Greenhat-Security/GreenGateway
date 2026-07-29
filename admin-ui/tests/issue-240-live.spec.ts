import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from '@playwright/test';

const ADMIN_ORIGIN = 'http://127.0.0.1:43203';
const GATEWAY_ORIGIN = 'http://127.0.0.1:43202';
const FIXTURE_ORIGIN = 'http://127.0.0.1:43201';
const CONNECTIONS_API = `${GATEWAY_ORIGIN}/v1/admin/connections`;
const SECRETS_API = `${GATEWAY_ORIGIN}/v1/admin/connection-secrets`;

type BearerTokens = {
  reader: string;
  writer: string;
  secretManager: string;
  superadmin: string;
};

type CreatedResource = {
  id: string;
  etag?: string;
};

type FixtureState = {
  introspectionCalls: number;
  introspectedSessions: string[];
  upstreamCalls: number;
  upstreamAuthorizationHeaders: number;
  upstreamPaths: string[];
};

let tokens: BearerTokens;
let managedConnectionId = '';

test.describe.serial('Issue #240 live admin acceptance', () => {
  test.beforeAll(async ({ request }) => {
    const response = await request.get(
      `${FIXTURE_ORIGIN}/__fixture/tokens`,
    );
    expect(response.ok()).toBeTruthy();
    tokens = (await response.json()) as BearerTokens;
    for (const token of Object.values(tokens)) {
      expect(token.split('.')).toHaveLength(3);
    }
  });

  test('uses real bearer auth, server permissions, read-only actions, themes, and accessible controls', async ({
    browser,
    page,
  }) => {
    await saveBearerToken(page, tokens.reader);

    const [readerRequest] = await Promise.all([
      page.waitForRequest(
        (request) =>
          request.method() === 'GET' &&
          new URL(request.url()).pathname === '/v1/admin/connections',
      ),
      page.goto('/admin/connections'),
    ]);
    expect(
      (await readerRequest.headerValue('authorization')) ===
        `Bearer ${tokens.reader}`,
    ).toBeTruthy();

    await expect(
      page.getByRole('heading', { level: 2, name: 'Connections' }),
    ).toBeVisible();
    await expect(
      page.getByRole('link', {
        name: 'View Legacy default HTTP, connection legacy-default-http',
      }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Add connection' }),
    ).toHaveCount(0);
    await expect(
      page.getByRole('button', { name: 'Manage secrets' }),
    ).toHaveCount(0);
    await expect(
      page.getByRole('button', {
        name: 'Edit Legacy default HTTP, connection legacy-default-http',
      }),
    ).toBeDisabled();
    await expect(
      page.getByText('Read only', { exact: true }),
    ).toBeVisible();

    await assertThemeChanges(page);
    await assertBasicAccessibility(page);

    await page
      .getByRole('link', {
        name: 'View Legacy default HTTP, connection legacy-default-http',
      })
      .click();
    await expect(
      page.getByRole('heading', {
        level: 2,
        name: 'Legacy default HTTP',
      }),
    ).toBeVisible();
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Legacy connection - read only',
      }),
    ).toBeVisible();
    for (const action of [
      'Edit',
      'Test connection',
      'Refresh inventory',
      'Delete',
    ]) {
      await expect(
        page.getByRole('button', { name: action }),
      ).toBeDisabled();
    }

    const writerPage = await browser.newPage();
    await saveBearerToken(writerPage, tokens.writer);
    await writerPage.goto('/admin/connections');
    await expect(
      writerPage.getByRole('button', { name: 'Add connection' }),
    ).toBeVisible();
    await expect(
      writerPage.getByRole('button', { name: 'Manage secrets' }),
    ).toHaveCount(0);
    await writerPage
      .getByRole('button', { name: 'Add connection' })
      .click();
    await expect(
      writerPage.getByRole('heading', {
        level: 2,
        name: 'New connection',
      }),
    ).toBeVisible();
    await expect(
      writerPage.getByLabel('Authentication type'),
    ).toBeDisabled();
    await expect(
      writerPage.getByRole('heading', {
        name: 'Local encrypted secrets',
      }),
    ).toHaveCount(0);
    await writerPage.close();

    const secretManagerPage = await browser.newPage();
    await saveBearerToken(secretManagerPage, tokens.secretManager);
    await secretManagerPage.goto('/admin/connections');
    await expect(
      secretManagerPage.getByRole('button', {
        name: 'Add connection',
      }),
    ).toHaveCount(0);
    await secretManagerPage
      .getByRole('button', { name: 'Manage secrets' })
      .click();
    await expect(
      secretManagerPage.getByRole('heading', {
        level: 2,
        name: 'Manage secrets',
      }),
    ).toBeVisible();
    await expect(
      secretManagerPage.getByRole('heading', {
        name: 'Local encrypted secrets',
      }),
    ).toBeVisible();
    await expect(
      secretManagerPage.getByRole('button', {
        name: 'Save disabled draft',
      }),
    ).toHaveCount(0);
    await secretManagerPage.close();
  });

  test('uses real cookie auth, rejects missing CSRF, accepts double-submit CSRF, and reaches the fake upstream', async ({
    context,
    page,
    request,
  }) => {
    await context.addCookies([
      {
        name: 'session',
        value: 'cookie-superadmin',
        url: ADMIN_ORIGIN,
      },
    ]);

    await page.goto('/admin/connections/new');
    await expect(
      page.getByRole('heading', { level: 2, name: 'New connection' }),
    ).toBeVisible();
    await page.getByLabel('Display name').fill('Issue 240 live upstream');
    await page
      .getByLabel('Base URL')
      .fill(`${FIXTURE_ORIGIN}`);
    await page
      .getByRole('checkbox', {
        name: 'Configure a safe HTTP test request',
      })
      .check();
    await page.getByLabel('Path', { exact: true }).fill('/upstream/health');
    await page.getByLabel('Expected statuses').fill('200');
    await context.clearCookies({ name: 'csrf_token' });
    await expect
      .poll(() => page.evaluate(() => document.cookie.includes('csrf_token=')))
      .toBeFalsy();

    const [csrfDenied] = await Promise.all([
      page.waitForResponse(isConnectionCreateResponse),
      page
        .getByRole('button', { name: 'Save disabled draft' })
        .click(),
    ]);
    expect(csrfDenied.status()).toBe(403);
    expect(
      await csrfDenied.request().headerValue('x-csrf-token'),
    ).toBeNull();
    expect(await csrfDenied.json()).toMatchObject({
      error: 'csrf token missing or invalid',
    });
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Connection permission required',
      }),
    ).toBeVisible();

    const csrfValue = 'issue-240-double-submit';
    await context.addCookies([
      {
        name: 'csrf_token',
        value: csrfValue,
        url: ADMIN_ORIGIN,
      },
    ]);
    await expect
      .poll(() =>
        page.evaluate(() => document.cookie.includes('csrf_token=')),
      )
      .toBeTruthy();

    const [createdResponse] = await Promise.all([
      page.waitForResponse(isConnectionCreateResponse),
      page
        .getByRole('button', { name: 'Save disabled draft' })
        .click(),
    ]);
    expect(createdResponse.status()).toBe(201);
    expect(
      await createdResponse.request().headerValue('x-csrf-token'),
    ).toBe(csrfValue);
    const created = (await createdResponse.json()) as CreatedResource;
    expect(created.id).toBeTruthy();
    managedConnectionId = created.id;
    await expect(page).toHaveURL(
      new RegExp(`/admin/connections/${escapeRegex(created.id)}$`),
    );

    const [testResponse] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname ===
            `/v1/admin/connections/${created.id}/test`,
      ),
      page
        .getByRole('button', { name: 'Test connection' })
        .click(),
    ]);
    expect(testResponse.status()).toBe(200);
    expect(
      await testResponse.request().headerValue('x-csrf-token'),
    ).toBe(csrfValue);
    expect(await testResponse.json()).toMatchObject({ ok: true });
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Connection test passed',
      }),
    ).toBeVisible();

    const state = await fixtureState(request);
    expect(state.introspectionCalls).toBeGreaterThan(0);
    expect(state.introspectedSessions).toContain('cookie-superadmin');
    expect(state.upstreamCalls).toBeGreaterThan(0);
    expect(state.upstreamPaths).toContain('/upstream/health');
    expect(state.upstreamAuthorizationHeaders).toBe(0);
  });

  test('rejects stale ETags and clears one-use secret values on success and conflict', async ({
    page,
    request,
  }) => {
    expect(managedConnectionId).toBeTruthy();
    await saveBearerToken(page, tokens.superadmin);

    await page.goto(
      `/admin/connections/${encodeURIComponent(managedConnectionId)}/edit`,
    );
    await expect(
      page.getByRole('heading', {
        level: 2,
        name: 'Edit connection',
      }),
    ).toBeVisible();

    const current = await authenticatedGet(
      request,
      `${CONNECTIONS_API}/${encodeURIComponent(managedConnectionId)}`,
      tokens.superadmin,
    );
    const currentEtag = current.headers()['etag'];
    expect(currentEtag).toBeTruthy();
    const externalUpdate = await request.put(
      `${CONNECTIONS_API}/${encodeURIComponent(managedConnectionId)}`,
      {
        headers: bearerHeaders(tokens.superadmin, {
          'Content-Type': 'application/json',
          'If-Match': currentEtag,
        }),
        data: managedConnectionWrite('Externally updated before UI save'),
      },
    );
    expect(externalUpdate.status()).toBe(200);

    await page
      .getByLabel('Display name')
      .fill('Issue 240 stale browser edit');
    const [staleSave] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === 'PUT' &&
          new URL(response.url()).pathname ===
            `/v1/admin/connections/${managedConnectionId}`,
      ),
      page
        .getByRole('button', { name: 'Save connection' })
        .click(),
    ]);
    expect(staleSave.status()).toBe(412);
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Connection changed',
      }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', {
        name: 'Reload latest connection',
      }),
    ).toBeFocused();

    await page.goto('/admin/connections/new');
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Local encrypted secrets',
      }),
    ).toBeVisible();
    const acceptedCanary = 'ISSUE_240_ACCEPTED_SECRET_CANARY';
    const secretLabel = `Issue 240 local secret ${Date.now()}`;
    await page.getByLabel('Safe label').fill(secretLabel);
    await page.getByLabel('Secret value').fill(acceptedCanary);

    const [createdSecretResponse] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname ===
            '/v1/admin/connection-secrets',
      ),
      page
        .getByRole('button', { name: 'Create and select' })
        .click(),
    ]);
    expect(createdSecretResponse.status()).toBe(201);
    expect(
      await createdSecretResponse.request().headerValue('authorization'),
    ).toBe(`Bearer ${tokens.superadmin}`);
    expect(
      await createdSecretResponse.request().headerValue('x-csrf-token'),
    ).toBeNull();
    const createdSecretBody = await createdSecretResponse.text();
    expect(createdSecretBody).not.toContain(acceptedCanary);
    const createdSecret = JSON.parse(
      createdSecretBody,
    ) as CreatedResource;
    expect(createdSecret.id).toBeTruthy();
    expect(createdSecret.etag).toBeTruthy();
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Local secret created',
      }),
    ).toBeVisible();
    await assertSecretAbsent(page, acceptedCanary);

    const externalRotationCanary =
      'ISSUE_240_EXTERNAL_ROTATION_CANARY';
    const externalRotation = await request.put(
      `${SECRETS_API}/${encodeURIComponent(createdSecret.id)}`,
      {
        headers: bearerHeaders(tokens.superadmin, {
          'Content-Type': 'application/json',
          'If-Match': requiredString(
            createdSecret.etag,
            'created secret ETag',
          ),
        }),
        data: {
          purpose: 'static_bearer',
          value: externalRotationCanary,
        },
      },
    );
    expect(externalRotation.status()).toBe(200);
    expect(await externalRotation.text()).not.toContain(
      externalRotationCanary,
    );

    const rejectedCanary = 'ISSUE_240_REJECTED_SECRET_CANARY';
    await page.getByLabel('New secret value').fill(rejectedCanary);
    const [staleRotation] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === 'PUT' &&
          new URL(response.url()).pathname ===
            `/v1/admin/connection-secrets/${createdSecret.id}`,
      ),
      page.getByRole('button', { name: 'Rotate' }).click(),
    ]);
    expect(staleRotation.status()).toBe(412);
    expect(await staleRotation.text()).not.toContain(rejectedCanary);
    await expect(
      page.getByRole('heading', {
        level: 3,
        name: 'Secret inventory reload required',
      }),
    ).toBeVisible();
    await assertSecretAbsent(page, rejectedCanary);
  });
});

async function saveBearerToken(page: Page, token: string) {
  await page.goto('/admin/');
  await page.getByLabel('Token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(
    page.getByRole('status').filter({
      hasText: 'Token saved for this browser session.',
    }),
  ).toBeVisible();
}

async function assertThemeChanges(page: Page) {
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    'light',
  );
  const lightPalette = await page.evaluate(() => {
    const style = getComputedStyle(document.body);
    return [style.backgroundColor, style.color];
  });
  await page
    .getByRole('button', { name: 'Switch to dark theme' })
    .click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    'dark',
  );
  const darkPalette = await page.evaluate(() => {
    const style = getComputedStyle(document.body);
    return [style.backgroundColor, style.color];
  });
  expect(darkPalette).not.toEqual(lightPalette);
  await page
    .getByRole('button', { name: 'Switch to light theme' })
    .click();
}

async function assertBasicAccessibility(page: Page) {
  const problems = await page.evaluate(() => {
    const found: string[] = [];
    if (document.querySelector('main') === null) {
      found.push('missing main landmark');
    }
    if (
      document.querySelector('nav[aria-label="Admin sections"]') ===
      null
    ) {
      found.push('missing named admin navigation');
    }

    const idCounts = new Map<string, number>();
    for (const element of document.querySelectorAll<HTMLElement>('[id]')) {
      idCounts.set(element.id, (idCounts.get(element.id) ?? 0) + 1);
    }
    for (const [id, count] of idCounts) {
      if (count > 1) {
        found.push(`duplicate id: ${id}`);
      }
    }

    for (const control of document.querySelectorAll<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >('input:not([type="hidden"]), select, textarea')) {
      const labelled =
        (control.labels?.length ?? 0) > 0 ||
        Boolean(control.getAttribute('aria-label')?.trim()) ||
        Boolean(control.getAttribute('aria-labelledby')?.trim());
      if (!labelled) {
        found.push(
          `unlabelled control: ${control.id || control.tagName.toLowerCase()}`,
        );
      }
    }

    for (const button of document.querySelectorAll('button')) {
      const name =
        button.getAttribute('aria-label')?.trim() ||
        button.textContent?.trim();
      if (!name) {
        found.push('button without an accessible name');
      }
    }
    return found;
  });
  expect(problems).toEqual([]);
}

async function assertSecretAbsent(page: Page, canary: string) {
  expect(page.url()).not.toContain(canary);
  expect(await page.locator('body').innerText()).not.toContain(canary);
  const values = await page
    .locator('input, textarea')
    .evaluateAll((elements) =>
      elements.map(
        (element) =>
          (element as HTMLInputElement | HTMLTextAreaElement).value,
      ),
    );
  expect(values).not.toContain(canary);
}

function isConnectionCreateResponse(response: {
  request(): { method(): string };
  url(): string;
}) {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/v1/admin/connections'
  );
}

async function fixtureState(
  request: APIRequestContext,
): Promise<FixtureState> {
  const response = await request.get(
    `${FIXTURE_ORIGIN}/__fixture/state`,
  );
  expect(response.ok()).toBeTruthy();
  return (await response.json()) as FixtureState;
}

async function authenticatedGet(
  request: APIRequestContext,
  url: string,
  token: string,
) {
  const response = await request.get(url, {
    headers: bearerHeaders(token),
  });
  expect(response.ok()).toBeTruthy();
  return response;
}

function bearerHeaders(
  token: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    Accept: 'application/json',
    Authorization: `Bearer ${token}`,
    ...extra,
  };
}

function managedConnectionWrite(description: string) {
  return {
    display_name: 'Issue 240 live upstream',
    description,
    enabled: false,
    kind: 'http_api',
    endpoint: {
      base_url: FIXTURE_ORIGIN,
      base_path: '/',
    },
    authentication: { type: 'none' },
    tls: {},
    test_profile: {
      method: 'GET',
      path: '/upstream/health',
      expected_statuses: [200],
    },
  };
}

function requiredString(
  value: string | undefined,
  label: string,
): string {
  if (!value) {
    throw new Error(`${label} is missing`);
  }
  return value;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
