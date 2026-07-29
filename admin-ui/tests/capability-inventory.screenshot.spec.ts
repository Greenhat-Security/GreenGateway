import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test } from '@playwright/test';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 1440, height: 1150 } });

test.beforeEach(async () => {
  await mkdir(screenshotDir, { recursive: true });
});

test('captures available, stale, and legacy capability inventory states', async ({
  page,
}) => {
  await page.route(/\/v1\/admin\/tools(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"capability-screenshot-collection"',
        'Cache-Control': 'no-store',
      },
      body: JSON.stringify({
        capabilities: [
          capabilitySummary({
            id: `cap_${'0'.repeat(64)}`,
            kind: 'tool',
            name: 'billing_get_invoice',
            title: 'Get billing invoice',
            description: 'Returns one invoice by its public identifier.',
            source: {
              type: 'openapi',
              connection_id: 'billing-api',
              operation_id: 'getInvoice',
              catalog_revision: 8,
              spec_revision: 3,
              spec_digest: 'a'.repeat(64),
            },
            connection: {
              id: 'billing-api',
              kind: 'http_api',
              management_source: 'managed',
            },
            schema_digest: 'b'.repeat(64),
            discovered_at: '2026-07-28T18:30:00Z',
            last_success_at: '2026-07-28T20:10:00Z',
            state: {
              enabled: true,
              available: true,
              stale: false,
              reason: 'available',
            },
            policy: {
              eligible: true,
              reason: 'eligible',
            },
          }),
          capabilitySummary({
            id: `cap_${'1'.repeat(64)}`,
            kind: 'tool',
            name: 'customers.search',
            title: 'Search customers',
            description: 'Last-known MCP tool metadata awaiting a refresh.',
            source: {
              type: 'mcp_discovery',
              connection_id: 'customer-mcp',
              remote_tool_name: 'customers.search',
            },
            connection: {
              id: 'customer-mcp',
              kind: 'mcp_streamable_http',
              management_source: 'managed',
            },
            schema_digest: 'c'.repeat(64),
            discovered_at: '2026-07-27T16:00:00Z',
            last_success_at: '2026-07-27T16:00:00Z',
            state: {
              enabled: true,
              available: false,
              stale: true,
              reason: 'catalog_stale',
            },
            policy: {
              eligible: false,
              reason: 'policy_denied',
            },
          }),
          capabilitySummary({
            id: `cap_${'2'.repeat(64)}`,
            kind: 'tool',
            name: 'legacy.reporting.summary',
            title: 'Legacy reporting summary',
            description:
              'Projected metadata from a read-only legacy MCP configuration.',
            source: {
              type: 'projected_legacy_config',
              connection_id: 'legacy-reporting-mcp',
              remote_tool_name: 'reporting.summary',
            },
            connection: {
              id: 'legacy-reporting-mcp',
              kind: 'mcp_streamable_http',
              management_source: 'legacy_mcp',
            },
            state: {
              enabled: true,
              available: true,
              stale: false,
              reason: 'available',
            },
            policy: {
              eligible: true,
              reason: 'eligible',
            },
          }),
          capabilitySummary({
            id: `cap_${'3'.repeat(64)}`,
            kind: 'resource_template',
            name: 'customer-profile-template',
            title: 'Customer profile template',
            uri_template: 'urn:customer:profile:{customer_id}',
            description:
              'Metadata remains visible while its connection is disabled.',
            source: {
              type: 'mcp_discovery',
              connection_id: 'customer-mcp-draft',
            },
            connection: {
              id: 'customer-mcp-draft',
              kind: 'mcp_streamable_http',
              management_source: 'managed',
            },
            discovered_at: '2026-07-26T12:00:00Z',
            last_success_at: '2026-07-26T12:00:00Z',
            state: {
              enabled: false,
              available: false,
              stale: true,
              reason: 'connection_disabled',
            },
            policy: {
              eligible: false,
              reason: 'metadata_only',
            },
          }),
        ],
        total_count: 4,
      }),
    });
  });

  await page.goto('/admin/tools');
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Capability inventory' }),
  ).toBeVisible();
  await expect(page.getByText('4 capabilities', { exact: true })).toBeVisible();
  await expect(page.getByText('Get billing invoice')).toBeVisible();
  await expect(page.getByText('Search customers')).toBeVisible();
  await expect(
    page
      .getByRole('table')
      .getByText('Projected legacy config', { exact: true }),
  ).toBeVisible();
  await expect(page.getByText('Catalog stale')).toBeVisible();
  await expect(page.getByText('Connection disabled')).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(1);
  await expect(
    page.getByRole('columnheader', { name: 'Capability' }),
  ).toBeVisible();
  await assertThemeAndShellLayout(page, 'light');
  const lightPalette = await pagePalette(page);

  await capture(page, 'capability-inventory-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  expect(await pagePalette(page)).not.toEqual(lightPalette);
  await expect(page.getByText('Get billing invoice')).toBeVisible();
  await capture(page, 'capability-inventory-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await expect(page.getByText('Customer profile template')).toBeVisible();

  const mobileTableBox = await page.locator('.capability-table').boundingBox();
  const mobileFrameBox = await page.locator('.table-scroll').boundingBox();
  expect(mobileTableBox?.width).toBeLessThanOrEqual(
    (mobileFrameBox?.width ?? 0) + 1,
  );
  await capture(page, 'capability-inventory-mobile.png');
});

test('captures capability inventory loading, empty, and unavailable states', async ({
  page,
}) => {
  let releaseInitialRequest: (() => void) | undefined;
  const initialRequestGate = new Promise<void>((resolve) => {
    releaseInitialRequest = resolve;
  });
  let responseMode: 'loading' | 'empty' | 'error' = 'loading';

  await page.route(/\/v1\/admin\/tools(?:\?.*)?$/, async (route) => {
    if (responseMode === 'loading') {
      await initialRequestGate;
    }

    if (responseMode === 'error') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Capability discovery storage is temporarily unavailable.',
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: '"capability-empty-representation"',
        'Cache-Control': 'no-store',
      },
      body: JSON.stringify({
        capabilities: [],
        total_count: 0,
      }),
    });
  });

  await page.goto('/admin/tools');
  await disableAnimations(page);
  await expect(
    page.getByText('Loading capability inventory', { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-inventory-loading-light.png');

  responseMode = 'empty';
  releaseInitialRequest?.();
  await expect(
    page.getByText('No capabilities matched these filters.', { exact: true }),
  ).toBeVisible();
  await expect(page.getByText('0 capabilities', { exact: true })).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-inventory-empty-light.png');

  responseMode = 'error';
  await page.reload();
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', {
      level: 3,
      name: 'Capability inventory unavailable',
    }),
  ).toBeVisible();
  await expect(page.getByRole('alert')).toContainText(
    'Capability discovery storage is temporarily unavailable.',
  );
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-inventory-error-light.png');
});

test('captures a secret-free capability detail in light, dark, and mobile layouts', async ({
  page,
}) => {
  const capabilityId = `cap_${'d'.repeat(64)}`;
  const plaintextCanary = 'GG_CAPABILITY_DETAIL_PLAINTEXT_CANARY';
  const locatorCanary = 'GG_CAPABILITY_DETAIL_LOCATOR_CANARY';

  await page.route(
    new RegExp(`/v1/admin/tools/${capabilityId}$`),
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          ETag: '"capability-screenshot-detail"',
          'Cache-Control': 'no-store',
        },
        body: JSON.stringify({
          id: capabilityId,
          kind: 'tool',
          name: 'billing_get_invoice',
          title: 'Get billing invoice',
          description:
            'Returns a billing invoice through its managed OpenAPI connection.',
          description_truncated: false,
          source: {
            type: 'openapi',
            connection_id: 'billing-api',
            operation_id: 'getInvoice',
            catalog_revision: 8,
            spec_revision: 3,
            spec_digest: 'd'.repeat(64),
            secret_locator: locatorCanary,
          },
          connection: {
            id: 'billing-api',
            kind: 'http_api',
            management_source: 'managed',
          },
          schema_digest: 'e'.repeat(64),
          discovered_at: '2026-07-28T18:30:00Z',
          last_success_at: '2026-07-28T20:10:00Z',
          state: {
            enabled: true,
            available: true,
            stale: false,
            reason: 'available',
          },
          policy: {
            eligible: true,
            reason: 'eligible',
          },
          mapping: {
            type: 'http',
            method: 'GET',
            path_template: '/invoices/{invoice_id}',
            query_params: [
              {
                arg_name: 'invoice_id',
                query_name: 'invoiceId',
                required: true,
              },
              {
                arg_name: 'include_archived',
                query_name: 'includeArchived',
                required: false,
              },
            ],
            body: {
              mode: 'whole_args_json',
            },
            credential_value: plaintextCanary,
          },
          input_json_schema: {
            type: 'object',
            additionalProperties: false,
            properties: {
              invoice_id: {
                type: 'string',
                description: 'Public invoice identifier.',
              },
              include_archived: {
                type: 'boolean',
                default: false,
              },
            },
            required: ['invoice_id'],
          },
          credential_value: plaintextCanary,
          secret_locator: locatorCanary,
        }),
      });
    },
  );

  await page.goto(`/admin/tools/${capabilityId}`);
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Get billing invoice' }),
  ).toBeVisible();
  for (const heading of [
    'Summary',
    'Provenance',
    'Safe mapping',
    'Input JSON schema',
  ]) {
    await expect(
      page.getByRole('heading', { level: 3, name: heading }),
    ).toBeVisible();
  }
  const queryMappingTable = page.getByRole('table', {
    name: 'Query parameter mappings',
  });
  await expect(queryMappingTable).toBeVisible();
  await expect(queryMappingTable.getByRole('row')).toHaveCount(3);
  await expect(
    page.getByRole('link', { name: 'billing-api' }),
  ).toHaveAttribute('href', '/admin/connections/billing-api');
  await expect(
    page.getByRole('link', { name: 'Back to inventory' }),
  ).toHaveAttribute('href', '/admin/tools');
  await expect(page.getByRole('button', { name: /invoke/i })).toHaveCount(0);
  await assertDomExcludes(page, plaintextCanary, locatorCanary);
  await assertThemeAndShellLayout(page, 'light');
  await assertDetailContentLayout(page);
  const lightPalette = await pagePalette(page);
  await capture(page, 'capability-detail-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  expect(await pagePalette(page)).not.toEqual(lightPalette);
  await expect(queryMappingTable).toBeVisible();
  await assertDomExcludes(page, plaintextCanary, locatorCanary);
  await assertDetailContentLayout(page);
  await capture(page, 'capability-detail-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await expect(
    page.getByRole('heading', { level: 3, name: 'Input JSON schema' }),
  ).toBeVisible();
  await assertDomExcludes(page, plaintextCanary, locatorCanary);
  await assertDetailContentLayout(page);
  await capture(page, 'capability-detail-mobile.png');
});

test('captures capability detail loading, unavailable, and not-found states', async ({
  page,
}) => {
  const capabilityId = `cap_${'e'.repeat(64)}`;
  let releaseInitialRequest: (() => void) | undefined;
  const initialRequestGate = new Promise<void>((resolve) => {
    releaseInitialRequest = resolve;
  });
  let responseMode: 'loading' | 'error' | 'not-found' = 'loading';

  await page.route(
    new RegExp(`/v1/admin/tools/${capabilityId}$`),
    async (route) => {
      if (responseMode === 'loading') {
        await initialRequestGate;
      }

      if (responseMode === 'error') {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'Capability discovery storage is temporarily unavailable.',
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'The requested capability is no longer in the inventory.',
        }),
      });
    },
  );

  await page.goto(`/admin/tools/${capabilityId}`);
  await disableAnimations(page);
  await expect(
    page.getByText('Loading capability detail', { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-detail-loading-light.png');

  responseMode = 'error';
  releaseInitialRequest?.();
  const unavailableAlert = page.getByRole('alert', {
    name: 'Capability inventory unavailable',
  });
  await expect(unavailableAlert).toBeVisible();
  await expect(unavailableAlert).toBeFocused();
  await expect(unavailableAlert).toContainText(
    'Capability discovery storage is temporarily unavailable.',
  );
  await expect(page.getByText('Loading capability detail')).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-detail-error-light.png');

  responseMode = 'not-found';
  await page.reload();
  await disableAnimations(page);
  const notFoundAlert = page.getByRole('alert', {
    name: 'Capability not found',
  });
  await expect(notFoundAlert).toBeVisible();
  await expect(notFoundAlert).toBeFocused();
  await expect(notFoundAlert).toContainText(
    'The requested capability is no longer in the inventory.',
  );
  await expect(page.getByRole('table')).toHaveCount(0);
  await assertThemeAndShellLayout(page, 'light');
  await capture(page, 'capability-detail-not-found-light.png');
});

function capabilitySummary(
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  return {
    id: `cap_${'9'.repeat(64)}`,
    kind: 'tool',
    name: 'capability',
    description_truncated: false,
    source: {
      type: 'manual_file',
    },
    state: {
      enabled: true,
      available: true,
      stale: false,
      reason: 'available',
    },
    policy: {
      eligible: true,
      reason: 'eligible',
    },
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

  const layout = await page.evaluate(() => {
    const clientWidth = document.documentElement.clientWidth;
    const offenders = Array.from(
      document.querySelectorAll<HTMLElement>('body *'),
    )
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          tag: element.tagName.toLowerCase(),
          className: element.className,
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          clientWidth: element.clientWidth,
          scrollWidth: element.scrollWidth,
        };
      })
      .filter(
        (element) => element.left < -1 || element.right > clientWidth + 1,
      )
      .slice(0, 12);

    return {
      clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      offenders,
    };
  });
  expect(
    layout.scrollWidth,
    `horizontal overflow: ${JSON.stringify(layout.offenders)}`,
  ).toBeLessThanOrEqual(layout.clientWidth + 1);
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

async function assertDetailContentLayout(
  page: import('@playwright/test').Page,
) {
  const layout = await page.evaluate(() => {
    const panel = document.querySelector<HTMLElement>(
      '.capability-detail-panel',
    );
    const scrollFrame = document.querySelector<HTMLElement>(
      '.capability-detail-page .table-scroll',
    );
    const schema = document.querySelector<HTMLElement>('.capability-schema');
    const viewportWidth = document.documentElement.clientWidth;

    return {
      panel:
        panel === null
          ? null
          : {
              left: panel.getBoundingClientRect().left,
              right: panel.getBoundingClientRect().right,
            },
      scrollFrame:
        scrollFrame === null
          ? null
          : {
              clientWidth: scrollFrame.clientWidth,
              scrollWidth: scrollFrame.scrollWidth,
              left: scrollFrame.getBoundingClientRect().left,
              right: scrollFrame.getBoundingClientRect().right,
            },
      schema:
        schema === null
          ? null
          : {
              clientWidth: schema.clientWidth,
              scrollWidth: schema.scrollWidth,
              left: schema.getBoundingClientRect().left,
              right: schema.getBoundingClientRect().right,
            },
      viewportWidth,
    };
  });

  expect(layout.panel).not.toBeNull();
  expect(layout.scrollFrame).not.toBeNull();
  expect(layout.schema).not.toBeNull();
  expect(layout.panel?.left ?? -1).toBeGreaterThanOrEqual(-1);
  expect(layout.panel?.right ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(
    layout.viewportWidth + 1,
  );
  expect(layout.scrollFrame?.clientWidth ?? 0).toBeGreaterThan(0);
  expect(layout.scrollFrame?.scrollWidth ?? 0).toBeGreaterThanOrEqual(
    layout.scrollFrame?.clientWidth ?? 0,
  );
  expect(layout.scrollFrame?.left ?? -1).toBeGreaterThanOrEqual(-1);
  expect(
    layout.scrollFrame?.right ?? Number.POSITIVE_INFINITY,
  ).toBeLessThanOrEqual(layout.viewportWidth + 1);
  expect(layout.schema?.clientWidth ?? 0).toBeGreaterThan(0);
  expect(layout.schema?.scrollWidth ?? 0).toBeGreaterThanOrEqual(
    layout.schema?.clientWidth ?? 0,
  );
  expect(layout.schema?.left ?? -1).toBeGreaterThanOrEqual(-1);
  expect(layout.schema?.right ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(
    layout.viewportWidth + 1,
  );
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

async function assertDomExcludes(
  page: import('@playwright/test').Page,
  ...canaries: string[]
) {
  const html = await page.content();
  for (const canary of canaries) {
    expect(html).not.toContain(canary);
  }
}
