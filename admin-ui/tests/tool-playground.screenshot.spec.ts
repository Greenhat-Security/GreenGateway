import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const allowedToolId = capabilityId('a');
const secondToolId = capabilityId('b');
const disabledToolId = capabilityId('c');
const readOnlyToolId = capabilityId('d');
const unavailableToolId = capabilityId('e');
const staleToolId = capabilityId('f');
const authFailureToolId = capabilityId('1');
const policyFailureToolId = capabilityId('2');
const preconditionFailureToolId = capabilityId('3');
const outputLimitToolId = capabilityId('4');

const plaintextCanary = 'GG_PLAYGROUND_PLAINTEXT_CANARY';
const locatorCanary = 'GG_PLAYGROUND_LOCATOR_CANARY';
const submittedArgumentCanary = 'GG_PLAYGROUND_SUBMITTED_ARGUMENT_CANARY';
const safeOutput =
  '<img src=x onerror="window.__ggPlaygroundInjected = true"> Invoice inv-42 is paid.';

test.use({ viewport: { width: 1440, height: 1100 } });

test.beforeEach(async ({ page }) => {
  await mkdir(screenshotDir, { recursive: true });
  await page.addInitScript(() => {
    Object.defineProperty(window, '__ggPlaygroundInjected', {
      configurable: true,
      value: false,
      writable: true,
    });
  });
});

test('invokes one registered tool without exposing an arbitrary request builder', async ({
  page,
}) => {
  const consoleEntries: string[] = [];
  page.on('console', (message) => {
    consoleEntries.push(message.text());
  });

  await installCapabilityRoutes(page, {
    [allowedToolId]: toolDetail({
      id: allowedToolId,
      name: 'billing_get_invoice',
      title: 'Get billing invoice',
      actions: executeAction(true, 'allowed'),
    }),
  });

  let executionCount = 0;
  let releaseExecution: (() => void) | undefined;
  const executionGate = new Promise<void>((resolve) => {
    releaseExecution = resolve;
  });
  let observedRequest:
    | {
        method: string;
        path: string;
        query: string;
        ifMatch: string | null;
        body: unknown;
      }
    | undefined;

  await page.route(
    new RegExp(`/v1/admin/tools/${allowedToolId}/execute$`),
    async (route) => {
      executionCount += 1;
      const request = route.request();
      const url = new URL(request.url());
      observedRequest = {
        method: request.method(),
        path: url.pathname,
        query: url.search,
        ifMatch: request.headers()['if-match'] ?? null,
        body: request.postDataJSON(),
      };
      await executionGate;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          'Cache-Control': 'no-store',
          ETag: capabilityEtag(allowedToolId),
        },
        body: JSON.stringify(successExecution(safeOutput)),
      });
    },
  );

  await page.goto(playgroundPath(allowedToolId));
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Tool playground' }),
  ).toBeVisible();
  await expect(page.getByText('Get billing invoice')).toBeVisible();

  const argumentsEditor = page.getByLabel('Arguments (JSON)');
  const runButton = runToolButton(page);
  await expect(argumentsEditor).toHaveValue('{}');
  await expect(runButton).toHaveAccessibleName('Run tool');
  await expect(runButton).toBeEnabled();
  await assertNoArbitraryRequestControls(page);

  await argumentsEditor.fill(
    JSON.stringify({
      invoice_id: 'inv-42',
      note: submittedArgumentCanary,
    }),
  );
  await runButton.focus();
  await expect(runButton).toBeFocused();
  await runButton.evaluate((button: HTMLButtonElement) => {
    button.click();
    button.click();
  });

  await expect.poll(() => executionCount).toBe(1);
  await expect(runButton).toBeDisabled();
  await expect(argumentsEditor).toHaveValue('{}');
  await expect(page.getByText(safeOutput, { exact: true })).toHaveCount(0);

  expect(observedRequest).toEqual({
    method: 'POST',
    path: `/v1/admin/tools/${allowedToolId}/execute`,
    query: '',
    ifMatch: capabilityEtag(allowedToolId),
    body: {
      arguments: {
        invoice_id: 'inv-42',
        note: submittedArgumentCanary,
      },
    },
  });

  releaseExecution?.();
  await expect(runButton).toBeEnabled();
  const output = page.getByRole('region', { name: /tool result/i });
  await expect(output).toContainText('Invoice inv-42 is paid.');
  await expect(output.locator('img, script, iframe, object, embed')).toHaveCount(
    0,
  );
  expect(
    await page.evaluate(
      () =>
        (
          window as Window & {
            __ggPlaygroundInjected?: boolean;
          }
        ).__ggPlaygroundInjected,
    ),
  ).toBe(false);
  await expect(page.getByRole('status')).toContainText(/complete|succeed/i);
  await assertNoArbitraryRequestControls(page);
  await assertCanariesAbsent(
    page,
    consoleEntries,
    plaintextCanary,
    locatorCanary,
    submittedArgumentCanary,
  );
  await assertThemeAndShellLayout(page, 'light');
  const lightPalette = await pagePalette(page);
  await capture(page, 'tool-playground-result-light.png');

  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await assertThemeAndShellLayout(page, 'dark');
  expect(await pagePalette(page)).not.toEqual(lightPalette);
  await expect(output).toContainText('Invoice inv-42 is paid.');
  await capture(page, 'tool-playground-result-dark.png');

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await assertThemeAndShellLayout(page, 'light');
  await expect(output).toContainText('Invoice inv-42 is paid.');
  await assertNoArbitraryRequestControls(page);
  await capture(page, 'tool-playground-mobile.png');

  await page.getByRole('button', { name: 'Clear result' }).click();
  await expect(output).toHaveCount(0);
  await expect(page.getByText('Invoice inv-42 is paid.')).toHaveCount(0);
});

test('clears submitted state on tool navigation and presents server-derived disabled states', async ({
  page,
}) => {
  const details = {
    [allowedToolId]: toolDetail({
      id: allowedToolId,
      name: 'billing_get_invoice',
      title: 'Get billing invoice',
      actions: executeAction(true, 'allowed'),
    }),
    [secondToolId]: toolDetail({
      id: secondToolId,
      name: 'catalog_lookup',
      title: 'Catalog lookup',
      actions: executeAction(true, 'allowed'),
    }),
    [disabledToolId]: toolDetail({
      id: disabledToolId,
      name: 'disabled_tool',
      title: 'Disabled tool',
      state: {
        enabled: false,
        available: false,
        stale: false,
        reason: 'disabled',
      },
      actions: executeAction(false, 'disabled'),
    }),
    [readOnlyToolId]: toolDetail({
      id: readOnlyToolId,
      name: 'legacy_read_only_tool',
      title: 'Legacy read-only tool',
      source: {
        type: 'projected_legacy_config',
        connection_id: 'legacy-mcp-reports',
        remote_tool_name: 'reports',
      },
      connection: {
        id: 'legacy-mcp-reports',
        kind: 'mcp_streamable_http',
        management_source: 'legacy_mcp',
      },
      actions: executeAction(false, 'metadata_only'),
    }),
    [unavailableToolId]: toolDetail({
      id: unavailableToolId,
      name: 'unavailable_tool',
      title: 'Unavailable tool',
      state: {
        enabled: true,
        available: false,
        stale: false,
        reason: 'connection_unavailable',
      },
      actions: executeAction(false, 'unavailable'),
    }),
    [staleToolId]: toolDetail({
      id: staleToolId,
      name: 'stale_tool',
      title: 'Stale tool',
      state: {
        enabled: true,
        available: false,
        stale: true,
        reason: 'catalog_stale',
      },
      actions: executeAction(false, 'stale'),
    }),
  };
  await installCapabilityRoutes(page, details);

  let executionCount = 0;
  let releaseSecondExecution: (() => void) | undefined;
  const secondExecutionGate = new Promise<void>((resolve) => {
    releaseSecondExecution = resolve;
  });
  await page.route(/\/v1\/admin\/tools\/[^/]+\/execute$/, async (route) => {
    executionCount += 1;
    const id = new URL(route.request().url()).pathname.split('/').at(-2) ?? '';
    if (executionCount === 2) {
      await secondExecutionGate;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        'Cache-Control': 'no-store',
        ETag: capabilityEtag(id),
      },
      body: JSON.stringify(
        successExecution(
          executionCount === 1 ? 'First result' : 'Second result',
        ),
      ),
    });
  });

  await page.goto(playgroundPath(allowedToolId));
  await disableAnimations(page);
  const argumentsEditor = page.getByLabel('Arguments (JSON)');
  await argumentsEditor.fill('{"invoice_id":"inv-navigation-canary"}');
  await runToolButton(page).click();
  await expect(page.getByText('First result')).toBeVisible();
  await expect(argumentsEditor).toHaveValue('{}');

  await argumentsEditor.fill('{"invoice_id":"inv-second-submit"}');
  await runToolButton(page).click();
  await expect(page.getByText('First result')).toHaveCount(0);
  await expect(argumentsEditor).toHaveValue('{}');
  await expect(runToolButton(page)).toBeDisabled();
  releaseSecondExecution?.();
  await expect(page.getByText('Second result')).toBeVisible();

  await page.goto(playgroundPath(secondToolId));
  await disableAnimations(page);
  await expect(
    page.getByRole('heading', { level: 2, name: 'Tool playground' }),
  ).toBeVisible();
  await expect(page.getByText('Catalog lookup')).toBeVisible();
  await expect(page.getByLabel('Arguments (JSON)')).toHaveValue('{}');
  await expect(page.getByText('First result')).toHaveCount(0);
  await expect(page.getByText('Second result')).toHaveCount(0);

  await page.goto(playgroundPath(allowedToolId));
  await expect(page.getByLabel('Arguments (JSON)')).toHaveValue('{}');
  await expect(page.getByText('First result')).toHaveCount(0);
  await expect(page.getByText('Second result')).toHaveCount(0);
  expect(executionCount).toBe(2);

  for (const [id, expectedReason] of [
    [disabledToolId, /disabled/i],
    [readOnlyToolId, /metadata.only|read.only|legacy/i],
    [unavailableToolId, /unavailable/i],
    [staleToolId, /stale/i],
  ] as const) {
    await page.goto(playgroundPath(id));
    await disableAnimations(page);
    await expect(
      page.getByRole('heading', { level: 2, name: 'Tool playground' }),
    ).toBeVisible();
    await expect(runToolButton(page)).toBeDisabled();
    await expect(page.getByText(expectedReason).first()).toBeVisible();
    await expect(page.getByLabel('Arguments (JSON)')).toHaveValue('{}');
    await expect(page.getByText('First result')).toHaveCount(0);
    await expect(page.getByText('Second result')).toHaveCount(0);
    await assertNoArbitraryRequestControls(page);
  }
  expect(executionCount).toBe(2);
});

test('does not retry authentication, policy, precondition, or output-limit failures', async ({
  page,
}) => {
  await installCapabilityRoutes(page, {
    [authFailureToolId]: toolDetail({
      id: authFailureToolId,
      name: 'auth_failure',
      title: 'Authentication failure',
      actions: executeAction(true, 'allowed'),
    }),
    [policyFailureToolId]: toolDetail({
      id: policyFailureToolId,
      name: 'policy_failure',
      title: 'Policy failure',
      actions: executeAction(true, 'allowed'),
    }),
    [preconditionFailureToolId]: toolDetail({
      id: preconditionFailureToolId,
      name: 'precondition_failure',
      title: 'Precondition failure',
      actions: executeAction(true, 'allowed'),
    }),
    [outputLimitToolId]: toolDetail({
      id: outputLimitToolId,
      name: 'output_limit_failure',
      title: 'Output limit failure',
      actions: executeAction(true, 'allowed'),
    }),
  });

  const attempts = new Map<string, number>();
  const failures = new Map<
    string,
    { status: number; error: string; reason: string }
  >([
    [
      authFailureToolId,
      {
        status: 401,
        error: 'Authentication is required to execute this tool.',
        reason: 'authentication_required',
      },
    ],
    [
      policyFailureToolId,
      {
        status: 403,
        error: 'Tool invocation is denied by policy.',
        reason: 'tool_policy_denied',
      },
    ],
    [
      preconditionFailureToolId,
      {
        status: 412,
        error: 'The registered tool changed before execution.',
        reason: 'tool_changed',
      },
    ],
    [
      outputLimitToolId,
      {
        status: 502,
        error: 'tool execution failed',
        reason: 'output_limit_exceeded',
      },
    ],
  ]);

  await page.route(/\/v1\/admin\/tools\/([^/]+)\/execute$/, async (route) => {
    const id = new URL(route.request().url()).pathname.split('/').at(-2) ?? '';
    attempts.set(id, (attempts.get(id) ?? 0) + 1);
    const failure = failures.get(id);
    expect(failure).toBeDefined();
    await route.fulfill({
      status: failure?.status ?? 500,
      contentType: 'application/json',
      headers: {
        'Cache-Control': 'no-store',
      },
      body: JSON.stringify({
        error: failure?.error,
        reason: failure?.reason,
      }),
    });
  });

  for (const [id, expectedMessage] of [
    [authFailureToolId, /authentication|required|sign in/i],
    [policyFailureToolId, /policy|denied|forbidden/i],
    [preconditionFailureToolId, /changed|precondition|refresh/i],
    [outputLimitToolId, /output.limit.exceeded|output.*limit/i],
  ] as const) {
    await page.goto(playgroundPath(id));
    await disableAnimations(page);
    const argumentsEditor = page.getByLabel('Arguments (JSON)');
    await argumentsEditor.fill('{"probe":"must-be-cleared"}');
    await runToolButton(page).click();

    const error = page.getByRole('alert');
    await expect(error).toBeVisible();
    await expect(error).toContainText(expectedMessage);
    await expect(error).toBeFocused();
    await expect(argumentsEditor).toHaveValue('{}');
    await expect.poll(() => attempts.get(id) ?? 0).toBe(1);
    await page.waitForTimeout(150);
    expect(attempts.get(id)).toBe(1);
    await expect(page.getByRole('region', { name: /tool result/i })).toHaveCount(
      0,
    );
  }
});

test('validates malformed and non-object JSON locally and submits only JSON objects', async ({
  page,
}) => {
  await installCapabilityRoutes(page, {
    [allowedToolId]: toolDetail({
      id: allowedToolId,
      name: 'billing_get_invoice',
      title: 'Get billing invoice',
      actions: executeAction(true, 'allowed'),
    }),
  });

  let executionCount = 0;
  await page.route(
    new RegExp(`/v1/admin/tools/${allowedToolId}/execute$`),
    async (route) => {
      executionCount += 1;
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Unexpected test request.' }),
      });
    },
  );

  await page.goto(playgroundPath(allowedToolId));
  await disableAnimations(page);
  const argumentsEditor = page.getByLabel('Arguments (JSON)');
  const runButton = runToolButton(page);

  for (const invalidArguments of ['{"invoice_id":', '[]', '"invoice"']) {
    await argumentsEditor.fill(invalidArguments);
    await runButton.click();
    const error = page.getByRole('alert');
    await expect(error).toBeVisible();
    await expect(error).toContainText(/json|object|arguments/i);
    expect(executionCount).toBe(0);
  }

  await argumentsEditor.focus();
  await expect(argumentsEditor).toBeFocused();
  await argumentsEditor.press('Tab');
  await expect(runButton).toBeFocused();
  await assertNoArbitraryRequestControls(page);
});

function capabilityId(hexCharacter: string): string {
  return `cap_${hexCharacter.repeat(64)}`;
}

function capabilityEtag(id: string): string {
  return `"capability:${id}:playground:v1"`;
}

function playgroundPath(id: string): string {
  return `/admin/tools/${id}/playground`;
}

function runToolButton(page: Page) {
  return page.locator('.tool-playground-form button[type="submit"]');
}

function executeAction(canExecute: boolean, reason: string) {
  return {
    can_execute: canExecute,
    reason,
  };
}

function toolDetail(
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  return {
    id: allowedToolId,
    kind: 'tool',
    name: 'billing_get_invoice',
    title: 'Get billing invoice',
    description: 'Returns a billing invoice through its registered mapping.',
    description_truncated: false,
    source: {
      type: 'openapi',
      connection_id: 'billing-api',
      operation_id: 'getInvoice',
      catalog_revision: 8,
      spec_revision: 3,
      spec_digest: 'd'.repeat(64),
    },
    connection: {
      id: 'billing-api',
      kind: 'http_api',
      management_source: 'managed',
    },
    schema_digest: 'e'.repeat(64),
    discovered_at: '2026-07-29T08:00:00Z',
    last_success_at: '2026-07-29T08:05:00Z',
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
      ],
    },
    input_json_schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        invoice_id: {
          type: 'string',
        },
        note: {
          type: 'string',
        },
      },
      required: ['invoice_id'],
    },
    actions: executeAction(true, 'allowed'),
    credential_value: plaintextCanary,
    secret_locator: locatorCanary,
    ...overrides,
  };
}

function successExecution(text: string) {
  return {
    kind: 'http',
    status: 200,
    body: {
      type: 'text',
      value: text,
    },
  };
}

async function installCapabilityRoutes(
  page: Page,
  details: Record<string, Record<string, unknown>>,
) {
  await page.route(/\/v1\/admin\/tools\/([^/?]+)$/, async (route) => {
    const id = new URL(route.request().url()).pathname.split('/').at(-1) ?? '';
    const detail = details[id];
    if (detail === undefined) {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'The requested capability is no longer registered.',
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        ETag: capabilityEtag(id),
        'Cache-Control': 'no-store',
      },
      body: JSON.stringify(detail),
    });
  });
}

async function assertNoArbitraryRequestControls(page: Page) {
  await expect(
    page.locator(
      [
        'input[type="url"]',
        'input[name*="url" i]',
        'textarea[name*="url" i]',
        'select[name*="method" i]',
        'input[name*="method" i]',
        'textarea[name*="header" i]',
        'input[name*="header" i]',
        'input[name*="credential" i]',
        'input[name*="secret" i]',
        'input[name*="tls" i]',
        'input[name*="timeout" i]',
        'input[name*="connection" i]',
      ].join(','),
    ),
  ).toHaveCount(0);

  for (const label of [
    /^url$/i,
    /^method$/i,
    /^headers?$/i,
    /^credentials?$/i,
    /^tls/i,
    /^timeout$/i,
    /^connection$/i,
  ]) {
    await expect(page.getByLabel(label)).toHaveCount(0);
  }
}

async function assertCanariesAbsent(
  page: Page,
  consoleEntries: string[],
  ...canaries: string[]
) {
  const visibleAndStored = await page.evaluate(() => ({
    html: document.documentElement.outerHTML,
    localStorage: Object.entries(window.localStorage),
    sessionStorage: Object.entries(window.sessionStorage),
  }));
  const rendered = JSON.stringify({
    visibleAndStored,
    consoleEntries,
  });
  for (const canary of canaries) {
    expect(rendered).not.toContain(canary);
  }
}

async function disableAnimations(page: Page) {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; }',
  });
}

async function assertThemeAndShellLayout(
  page: Page,
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

async function pagePalette(page: Page) {
  return page.locator('body').evaluate((body) => {
    const style = getComputedStyle(body);
    return {
      backgroundColor: style.backgroundColor,
      color: style.color,
    };
  });
}

async function capture(page: Page, filename: string) {
  const screenshot = await page.screenshot({
    path: path.join(screenshotDir, filename),
    fullPage: true,
  });
  expect(screenshot.length).toBeGreaterThan(10_000);
}
