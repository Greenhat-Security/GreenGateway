import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test } from '@playwright/test';

const screenshotDir = path.join(process.cwd(), '.screenshots');

test.use({ viewport: { width: 1440, height: 1400 } });

test('captures rule editor empty, filled, and preview states', async ({
  page,
}) => {
  await mkdir(screenshotDir, { recursive: true });

  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ETag: 'W/"screenshot-policy-1"',
      },
      body: JSON.stringify({
        schema_version: '0.1.0',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {
          admin: { permissions: ['*'] },
          support: { permissions: ['tickets:read'] },
          auditor: { permissions: ['audit:read'] },
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
            endpoint_template: '/api/users/{id}',
            first_seen: '2026-07-04T08:00:00Z',
            last_seen: '2026-07-04T10:00:00Z',
            call_count: 84,
            distinct_principal_count: 12,
            is_new: false,
            reviewed: true,
            reviewed_at: '2026-07-04T10:05:00Z',
            reviewed_by: 'operator',
            covered_by_rule: false,
            latency: {
              count: 84,
              p50_ms: 12,
              p95_ms: 38,
              p99_ms: 55,
            },
            status_counts: [
              { status: 200, count: 78 },
              { status: 404, count: 6 },
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
        match_count: 37,
        scanned_event_count: 91,
        sample_strategy: 'newest_matches',
        samples: [
          {
            event_id: 'evt-users-37',
            timestamp: '2026-07-04T10:30:00Z',
            request_id: 'req-users-37',
            source_ip: '203.0.113.37',
            user_agent: 'Playwright screenshot',
            method: 'GET',
            path: '/api/users/123',
            actor: {
              user_id: 'user-123',
              auth_mode: 'bearer_token',
              roles: ['support'],
            },
            status: 200,
            policy_decision: 'allow',
            matched_rule_id: 'current-support-read',
          },
          {
            event_id: 'evt-users-38',
            timestamp: '2026-07-04T10:25:00Z',
            request_id: 'req-users-38',
            source_ip: '203.0.113.38',
            method: 'GET',
            path: '/api/users/456',
            actor: {
              user_id: 'user-456',
              auth_mode: 'bearer_token',
              roles: ['support'],
            },
            status: 404,
            policy_decision: 'deny',
            matched_rule_id: 'current-support-read',
          },
        ],
      }),
    });
  });

  await page.goto('/admin/policy/rules/editor');
  await expect(page.getByRole('heading', { name: 'Create policy rule' })).toBeVisible();
  await expect(page.getByText('Rule summary')).toBeVisible();
  await expect(
    page.getByText('Enter a matcher to preview matched traffic.'),
  ).toBeVisible();

  await page.screenshot({
    path: path.join(screenshotDir, 'rule-editor-empty.png'),
    fullPage: true,
  });

  await page.getByLabel('GET').check();
  await page.getByLabel('Path pattern').fill('/api/users/{id}');
  await page.getByRole('combobox', { name: 'Role constraints' }).fill('support');
  await page.getByRole('button', { name: 'Add role' }).click();
  await page.getByLabel('Bearer token').check();
  await page.getByRole('textbox', { name: 'Principal IDs' }).fill('user-123');
  await page.getByRole('button', { name: 'Add principal ID' }).click();
  await page.getByRole('radio', { name: /Shadow/ }).check();
  await expect(page.getByLabel('Rule summary')).toContainText(
    'Log-only GET requests to /api/users/{id} for role support, auth method bearer token, and principal user-123.',
  );

  await expect(page.getByText('Refreshing preview')).toBeVisible();
  await page.screenshot({
    path: path.join(screenshotDir, 'rule-editor-filled.png'),
    fullPage: true,
  });

  await expect(page.locator('.rule-preview-stat .stat-value')).toHaveText('37');
  await expect(page.getByText('/api/users/123')).toBeVisible();
  await page.screenshot({
    path: path.join(screenshotDir, 'rule-editor-preview-result.png'),
    fullPage: true,
  });
});
