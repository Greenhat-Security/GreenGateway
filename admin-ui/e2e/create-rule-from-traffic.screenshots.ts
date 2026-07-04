import { mkdir } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import path from 'node:path';

import { expect, test } from '@playwright/test';

import { ADMIN_TOKEN_STORAGE_KEY } from '../src/lib/auth';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 1440, height: 1200 } });

test('captures traffic inventory create-rule prefill journey', async ({
  page,
}) => {
  await mkdir(screenshotDir, { recursive: true });

  await page.addInitScript(
    ([storageKey, token]) => {
      window.sessionStorage.setItem(storageKey, token);
    },
    [ADMIN_TOKEN_STORAGE_KEY, jwtWithRoles(['writer'])],
  );

  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ETag: 'W/"create-rule-prefill-policy-1"',
      },
      body: JSON.stringify({
        schema_version: '0.1.0',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {
          writer: { permissions: ['admin:policy:read', 'admin:policy:write'] },
        },
        routes: [],
        rules: [],
      }),
    });
  });

  await page.route('**/v1/admin/traffic/endpoints?**', async (route) => {
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json' },
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
        ],
        next_cursor: null,
      }),
    });
  });

  await page.route('**/v1/admin/policy/rules/preview', async (route) => {
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_count: 14,
        scanned_event_count: 80,
        sample_strategy: 'newest_matches',
        samples: [
          {
            event_id: 'evt-orders-14',
            timestamp: '2026-07-04T10:29:00Z',
            request_id: 'req-orders-14',
            source_ip: '203.0.113.14',
            user_agent: 'Playwright screenshot',
            method: 'GET',
            path: '/api/orders/ord_123',
            actor: {
              user_id: 'user-123',
              auth_mode: 'bearer_token',
              roles: ['support'],
            },
            status: 200,
            policy_decision: 'allow',
            matched_rule_id: null,
          },
        ],
      }),
    });
  });

  await page.goto('/admin/traffic');
  await expect(
    page.getByRole('heading', { level: 2, name: 'Traffic inventory' }),
  ).toBeVisible();
  await expect(page.getByText('/api/orders/{order_id}')).toBeVisible();

  const createRuleButton = page.getByRole('button', {
    name: 'Create rule for GET /api/orders/{order_id}',
  });
  await expect(createRuleButton).toBeEnabled();
  await createRuleButton.click();

  await expect(page).toHaveURL(
    /\/admin\/policy\/rules\/editor\?prefill_method=GET&prefill_path=%2Fapi%2Forders%2F%7Border_id%7D/,
  );
  await expect(page.getByRole('heading', { name: 'Create policy rule' })).toBeVisible();
  await expect(page.getByLabel('Path pattern')).toHaveValue(
    '/api/orders/{order_id}',
  );

  const screenshot = await page.screenshot({
    path: path.join(screenshotDir, 'create-rule-from-traffic-editor.png'),
    fullPage: true,
  });
  expect(screenshot.length).toBeGreaterThan(10_000);
});

function jwtWithRoles(roles: string[]): string {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'screenshot-user', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
