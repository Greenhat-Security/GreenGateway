import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test } from '@playwright/test';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 1440, height: 1100 } });

test.beforeEach(async () => {
  await mkdir(screenshotDir, { recursive: true });
});

test('captures managed, degraded, disabled, and legacy connections', async ({
  page,
}) => {
  await page.route(/\/v1\/admin\/connections(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"connections-screenshot-collection"',
        'X-GreenGateway-Connections-ETag':
          '"connections-screenshot-collection"',
      },
      body: JSON.stringify({
        connections: [
          connectionSummary({
            id: 'billing-api',
            display_name: 'Billing API',
            enabled: true,
            kind: 'http_api',
            source: 'managed',
            read_only: false,
            authentication: 'static_bearer',
            endpoint_count: 4,
            sanitized_origin: 'https://billing.example',
            capability_count: 4,
            last_test_at: '2026-07-28T20:15:00Z',
            last_refresh_at: null,
            status: {
              state: 'healthy',
              reason: 'test_succeeded',
              observed_at: '2026-07-28T20:15:00Z',
              latency_ms: 42,
            },
            actions: {
              can_update: true,
              can_bind_secret: true,
              can_manage_secrets: true,
              can_test: true,
              can_refresh: false,
              can_delete: true,
            },
          }),
          connectionSummary({
            id: 'catalog-mcp',
            display_name: 'Catalog MCP',
            enabled: true,
            kind: 'mcp_streamable_http',
            source: 'managed',
            read_only: false,
            authentication: 'none',
            endpoint_count: 18,
            sanitized_origin: 'https://catalog.example',
            capability_count: 18,
            last_test_at: '2026-07-28T19:35:00Z',
            last_refresh_at: '2026-07-28T19:40:00Z',
            status: {
              state: 'degraded',
              reason: 'catalog_stale',
              observed_at: '2026-07-28T19:40:00Z',
              catalog_age_secs: 7_200,
              catalog_entry_count: 18,
            },
            actions: {
              can_update: true,
              can_bind_secret: false,
              can_manage_secrets: false,
              can_test: true,
              can_refresh: true,
              can_delete: false,
            },
          }),
          connectionSummary({
            id: 'shipping-draft',
            display_name: 'Shipping draft',
            enabled: false,
            kind: 'http_api',
            source: 'managed',
            read_only: false,
            authentication: 'header_api_key',
            endpoint_count: 0,
            sanitized_origin: 'https://shipping.example',
            capability_count: 0,
            last_test_at: null,
            last_refresh_at: null,
            status: {
              state: 'disabled',
              reason: 'disabled',
            },
            actions: {
              can_update: true,
              can_bind_secret: true,
              can_manage_secrets: true,
              can_test: true,
              can_refresh: false,
              can_delete: true,
            },
          }),
          connectionSummary({
            id: 'legacy-reporting-mcp',
            display_name: 'Legacy reporting MCP',
            enabled: true,
            kind: 'mcp_streamable_http',
            source: 'legacy_mcp',
            read_only: true,
            authentication: 'legacy_configured',
            endpoint_count: 6,
            sanitized_origin: 'https://legacy-reporting.example',
            capability_count: 6,
            last_test_at: null,
            last_refresh_at: null,
            revisions: {
              connection: 0,
              credential: 0,
              tls: 0,
              discovery: 0,
              status: 0,
            },
            status: {
              state: 'configured',
              reason: 'legacy_configured',
            },
            actions: {
              can_update: false,
              can_bind_secret: false,
              can_manage_secrets: false,
              can_test: false,
              can_refresh: false,
              can_delete: false,
            },
          }),
        ],
        omitted_legacy_projection_count: 2,
        actions: {
          can_create: true,
          can_bind_secret: true,
          can_manage_secrets: true,
        },
      }),
    });
  });

  await page.goto('/admin/connections');
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Connections' }),
  ).toBeVisible();
  await expect(page.getByText('Billing API')).toBeVisible();
  await expect(page.getByText('Catalog stale')).toBeVisible();
  await expect(page.getByText('Disabled draft', { exact: true })).toBeVisible();
  await expect(page.getByText('Read only', { exact: true })).toBeVisible();
  await expect(
    page.getByText(
      '2 legacy projections were omitted because the safe inventory limit was reached.',
    ),
  ).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(1);
  await expect(
    page.getByRole('columnheader', { name: 'Connection' }),
  ).toBeVisible();
  await assertThemeAndShellLayout(page, 'light');
  const lightPalette = await pagePalette(page);

  await capture(page, 'connections-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  const darkPalette = await pagePalette(page);
  expect(darkPalette).not.toEqual(lightPalette);
  await expect(page.getByText('Billing API')).toBeVisible();
  await capture(page, 'connections-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await expect(page.getByText('Legacy reporting MCP')).toBeVisible();

  const mobileTableBox = await page.locator('.connections-table').boundingBox();
  const mobileFrameBox = await page.locator('.table-scroll').boundingBox();
  expect(mobileTableBox?.width).toBeLessThanOrEqual(
    (mobileFrameBox?.width ?? 0) + 1,
  );
  await capture(page, 'connections-mobile.png');
});

test('captures connection inventory loading, empty, and unavailable states', async ({
  page,
}) => {
  let releaseInitialRequest: (() => void) | undefined;
  const initialRequestGate = new Promise<void>((resolve) => {
    releaseInitialRequest = resolve;
  });
  let responseMode: 'loading' | 'empty' | 'error' = 'loading';

  await page.route(/\/v1\/admin\/connections(?:\?.*)?$/, async (route) => {
    if (responseMode === 'loading') {
      await initialRequestGate;
    }

    if (responseMode === 'error') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Connection storage is temporarily unavailable.',
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"connections-empty-representation"',
        'X-GreenGateway-Connections-ETag': '"connections-empty-mutation"',
      },
      body: JSON.stringify({
        connections: [],
        omitted_legacy_projection_count: 0,
        actions: {
          can_create: false,
          can_bind_secret: false,
          can_manage_secrets: false,
        },
      }),
    });
  });

  await page.goto('/admin/connections');
  await disableAnimations(page);
  await expect(
    page.getByText('Loading connections', { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'connections-loading-light.png');

  responseMode = 'empty';
  releaseInitialRequest?.();
  await expect(
    page.getByText('No connections matched these filters.', { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'connections-empty-light.png');

  responseMode = 'error';
  await page.reload();
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', {
      level: 3,
      name: 'Connection inventory unavailable',
    }),
  ).toBeVisible();
  await expect(page.getByRole('alert')).toContainText(
    'Connection storage is temporarily unavailable.',
  );
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'connections-error-light.png');
});

test('captures managed and read-only connection detail states', async ({
  page,
}) => {
  const plaintextCanary = 'GG_DETAIL_PLAINTEXT_CANARY';
  const locatorCanary = 'GG_DETAIL_LOCATOR_CANARY';

  await page.route(
    /\/v1\/admin\/connections\/(?:billing-api|legacy-reporting-mcp)$/,
    async (route) => {
      const requestPath = new URL(route.request().url()).pathname;
      const isLegacy = requestPath.endsWith('/legacy-reporting-mcp');
      const detail = isLegacy
        ? connectionDetail({
            id: 'legacy-reporting-mcp',
            display_name: 'Legacy reporting MCP',
            enabled: true,
            kind: 'mcp_streamable_http',
            source: 'legacy_mcp',
            read_only: true,
            authentication: 'legacy_configured',
            endpoint_count: 6,
            revisions: {
              connection: 0,
              credential: 0,
              tls: 0,
              discovery: 0,
              status: 0,
            },
            status: {
              state: 'configured',
              reason: 'legacy_configured',
            },
            configuration: undefined,
            dependencies: [],
            actions: {
              can_update: false,
              can_bind_secret: false,
              can_manage_secrets: false,
              can_test: false,
              can_refresh: false,
              can_delete: false,
            },
            created_at: undefined,
            updated_at: undefined,
          })
        : connectionDetail({
            configuration: {
              description: 'Production billing upstream',
              endpoint: {
                base_url: 'https://billing.example',
                base_path: '/v1',
              },
              authentication: {
                type: 'static_bearer',
                secret_configured: true,
                locator: locatorCanary,
                value: plaintextCanary,
              },
              tls: {
                ca_bundle_configured: true,
                client_certificate_configured: true,
                client_private_key_configured: true,
                private_key_value: plaintextCanary,
              },
              test_profile: {
                method: 'HEAD',
                path: '/health',
                expected_statuses: [200, 204],
              },
            },
          });

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          ETag: isLegacy
            ? '"connection:legacy-reporting-mcp:c0:k0:t0:d0"'
            : '"connection:billing-api:c7:k3:t2:d1"',
        },
        body: JSON.stringify(detail),
      });
    },
  );

  await page.goto('/admin/connections/billing-api');
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Billing API' }),
  ).toBeVisible();
  for (const heading of ['Summary', 'Configuration', 'Dependencies', 'Actions']) {
    await expect(page.getByRole('heading', { level: 3, name: heading })).toBeVisible();
  }
  await expect(
    page.getByText(
      'Secret values and secret locators are never returned by this page.',
      { exact: false },
    ),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Test connection' })).toBeEnabled();
  await assertDomExcludes(page, plaintextCanary, locatorCanary);
  await assertThemeAndShellLayout(page, 'light');
  const managedLightPalette = await pagePalette(page);
  await capture(page, 'connection-detail-managed-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  expect(await pagePalette(page)).not.toEqual(managedLightPalette);
  await expect(
    page.getByRole('heading', { level: 3, name: 'Configuration' }),
  ).toBeVisible();
  await assertDomExcludes(page, plaintextCanary, locatorCanary);
  await capture(page, 'connection-detail-managed-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await expect(
    page.getByRole('heading', { level: 3, name: 'Actions' }),
  ).toBeVisible();
  await capture(page, 'connection-detail-managed-mobile.png');

  await page.goto('/admin/connections/legacy-reporting-mcp');
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Legacy reporting MCP' }),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', {
      level: 3,
      name: 'Legacy connection - read only',
    }),
  ).toBeVisible();
  await expect(
    page.getByText(
      'Legacy topology and secret settings are intentionally not exposed.',
    ),
  ).toBeVisible();
  for (const buttonName of [
    'Edit',
    'Test connection',
    'Refresh inventory',
    'Delete',
  ]) {
    await expect(page.getByRole('button', { name: buttonName })).toBeDisabled();
  }
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'connection-detail-read-only-mobile.png');
});

test('captures a secret-free configured connection editor', async ({
  page,
}) => {
  const plaintextCanary = 'GG_SCREENSHOT_PLAINTEXT_CANARY';
  const locatorCanary = 'GG_SCREENSHOT_LOCATOR_CANARY';

  await page.route(
    /\/v1\/admin\/connections\/billing-api$/,
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          ETag: '"connection:billing-api:v7"',
          'X-GreenGateway-Connections-ETag': '"connections:v12"',
        },
        body: JSON.stringify({
          id: 'billing-api',
          display_name: 'Billing API',
          enabled: false,
          kind: 'http_api',
          source: 'managed',
          read_only: false,
          authentication: 'static_bearer',
          endpoint_count: 4,
          revisions: {
            connection: 7,
            credential: 3,
            tls: 2,
            discovery: 1,
            status: 6,
          },
          status: {
            state: 'configured',
            reason: 'not_tested',
          },
          configuration: {
            description: 'Production billing upstream',
            endpoint: {
              base_url: 'https://billing.example',
              base_path: '/v1',
            },
            authentication: {
              type: 'static_bearer',
              secret_configured: true,
              locator: locatorCanary,
            },
            tls: {
              ca_bundle_configured: true,
              client_certificate_configured: true,
              client_private_key_configured: true,
              private_key_value: plaintextCanary,
            },
            test_profile: {
              method: 'HEAD',
              path: '/health',
              expected_statuses: [200, 204],
            },
          },
          dependencies: [],
          actions: {
            can_update: true,
            can_bind_secret: true,
            can_manage_secrets: true,
            can_test: true,
            can_refresh: false,
            can_delete: true,
          },
          created_at: '2026-07-27T18:00:00Z',
          updated_at: '2026-07-28T20:15:00Z',
        }),
      });
    },
  );

  await page.route(
    /\/v1\/admin\/connection-secrets$/,
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          ETag: '"connection-secrets:representation:v9"',
          'X-GreenGateway-Connection-Secrets-ETag':
            '"connection-secrets:mutation:v9"',
        },
        body: JSON.stringify({
          secrets: [
            secretMetadata({
              id: 'billing-bearer-alias',
              label: 'Billing bearer alias',
              provider: 'operator_environment',
              compatible_purposes: ['static_bearer'],
              dependency_count: 1,
              actions: {
                can_rotate: false,
                can_delete: false,
              },
              locator: locatorCanary,
              value: plaintextCanary,
            }),
            secretMetadata({
              id: 'trusted-ca-alias',
              label: 'Trusted CA alias',
              provider: 'operator_file',
              compatible_purposes: ['tls_ca_bundle'],
              dependency_count: 2,
              actions: {
                can_rotate: false,
                can_delete: false,
              },
              locator: locatorCanary,
              value: plaintextCanary,
            }),
            secretMetadata({
              id: 'rotatable-billing-token',
              label: 'Rotatable billing token',
              provider: 'local_encrypted',
              compatible_purposes: ['static_bearer'],
              dependency_count: 0,
              version: 4,
              rotated_at: '2026-07-28T18:30:00Z',
              actions: {
                can_rotate: true,
                can_delete: true,
              },
              locator: locatorCanary,
              value: plaintextCanary,
            }),
          ],
          actions: {
            can_create: false,
          },
          providers: {
            operator_aliases: true,
            local_encrypted: true,
          },
        }),
      });
    },
  );

  await page.goto('/admin/connections/billing-api/edit');
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Edit connection' }),
  ).toBeVisible();
  await expect(
    page.getByLabel('Authentication secret').getByText(
      'Keep configured value',
    ),
  ).toBeAttached();
  await page
    .getByLabel('Custom CA bundle')
    .selectOption('secret:trusted-ca-alias');
  await expect(page.getByLabel('Custom CA bundle')).toHaveValue(
    'secret:trusted-ca-alias',
  );
  await expect(page.locator('#local-secret-selection')).toHaveValue(
    'rotatable-billing-token',
  );
  await expect(page.locator('input[type="password"]')).toHaveCount(1);
  await assertSecretFreeEditor(page, plaintextCanary, locatorCanary);
  await assertThemeAndShellLayout(page, 'light');
  const lightPalette = await pagePalette(page);

  await capture(page, 'connection-editor-secret-free-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  expect(await pagePalette(page)).not.toEqual(lightPalette);
  await assertSecretFreeEditor(page, plaintextCanary, locatorCanary);
  await capture(page, 'connection-editor-secret-free-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await assertSecretFreeEditor(page, plaintextCanary, locatorCanary);
  await capture(page, 'connection-editor-secret-free-mobile.png');
});

function connectionSummary(
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  return {
    id: 'connection',
    display_name: 'Connection',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'none',
    endpoint_count: 1,
    sanitized_origin: 'https://connection.example',
    capability_count: 1,
    last_test_at: '2026-07-28T18:00:00Z',
    last_refresh_at: null,
    revisions: {
      connection: 3,
      credential: 1,
      tls: 1,
      discovery: 2,
      status: 4,
    },
    status: {
      state: 'configured',
      reason: 'not_tested',
    },
    actions: {
      can_update: true,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: false,
      can_refresh: false,
      can_delete: true,
    },
    ...overrides,
  };
}

function secretMetadata(
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  return {
    id: 'secret',
    etag: '"connection-secret:secret:v1"',
    label: 'Safe secret alias',
    provider: 'operator_environment',
    configured: true,
    compatible_purposes: ['static_bearer'],
    dependency_count: 0,
    actions: {
      can_rotate: false,
      can_delete: false,
    },
    ...overrides,
  };
}

function connectionDetail(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: 'billing-api',
    display_name: 'Billing API',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'static_bearer',
    endpoint_count: 4,
    revisions: {
      connection: 7,
      credential: 3,
      tls: 2,
      discovery: 1,
      status: 6,
    },
    status: {
      state: 'healthy',
      reason: 'test_succeeded',
      observed_at: '2026-07-28T20:15:00Z',
      latency_ms: 42,
    },
    configuration: {
      endpoint: {
        base_url: 'https://billing.example',
        base_path: '/v1',
      },
      authentication: {
        type: 'static_bearer',
        secret_configured: true,
      },
      tls: {
        ca_bundle_configured: true,
        client_certificate_configured: false,
        client_private_key_configured: false,
      },
      test_profile: {
        method: 'HEAD',
        path: '/health',
        expected_statuses: [200, 204],
      },
    },
    dependencies: [
      {
        kind: 'managed_tool',
        consumer_id: 'billing_get_invoice',
      },
    ],
    actions: {
      can_update: true,
      can_bind_secret: true,
      can_manage_secrets: true,
      can_test: true,
      can_refresh: false,
      can_delete: true,
    },
    created_at: '2026-07-27T18:00:00Z',
    updated_at: '2026-07-28T20:15:00Z',
    ...overrides,
  };
}

async function disableAnimations(page: import('@playwright/test').Page) {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; }',
  });
}

async function assertThemeAndShellLayout(
  page: import('@playwright/test').Page,
  theme: 'light' | 'dark',
) {
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await expect(
    page.getByRole('navigation', { name: 'Admin sections' }),
  ).toBeVisible();

  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth + 1);
}

async function pagePalette(page: import('@playwright/test').Page) {
  return page.locator('body').evaluate((body) => {
    const style = getComputedStyle(body);
    return {
      backgroundColor: style.backgroundColor,
      color: style.color,
    };
  });
}

async function capture(
  page: import('@playwright/test').Page,
  filename: string,
) {
  const screenshot = await page.screenshot({
    path: path.join(screenshotDir, filename),
    fullPage: true,
  });
  expect(screenshot.length).toBeGreaterThan(10_000);
}

async function assertSecretFreeEditor(
  page: import('@playwright/test').Page,
  ...canaries: string[]
) {
  const passwordValues = await page
    .locator('input[type="password"]')
    .evaluateAll((inputs) =>
      inputs.map((input) => (input as HTMLInputElement).value),
    );
  expect(passwordValues.every((value) => value === '')).toBe(true);
  const html = await page.content();
  for (const canary of canaries) {
    expect(html).not.toContain(canary);
  }
}

async function assertDomExcludes(
  page: import('@playwright/test').Page,
  ...canaries: string[]
) {
  const html = await page.content();
  for (const canary of canaries) {
    expect(html).not.toContain(canary);
  }
}
