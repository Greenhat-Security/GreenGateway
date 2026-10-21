import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');

// The policy and the shadow review describe the same rules and the same
// revision, as they do when no write lands between the two reads; otherwise
// the queue blocks Promote and Disable. Each entry carries the evidence
// window and digest a change to it would be bound to.
const shadowRules = [
  {
    id: 'shadow-report-deletes',
    enabled: true,
    methods: ['DELETE'],
    path: '/reports/**',
    principal: {
      roles: ['analyst'],
    },
    action: 'shadow',
  },
  {
    id: 'shadow-admin-posts',
    enabled: true,
    methods: ['POST', 'PATCH'],
    path: '/admin/**',
    principal: {
      roles: ['support'],
    },
    action: 'shadow',
  },
];

test.beforeEach(async () => {
  await mkdir(screenshotDir, { recursive: true });
});

test('captures the shadow review queue', async ({ page }) => {
  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
        'X-GreenGateway-Policy-Write': 'true',
        ETag: '"screenshot-shadow-policy"',
      },
      body: JSON.stringify({
        schema_version: '0.1.0',
        id: 'screenshot-policy',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {
          admin: {
            permissions: ['admin:policy:read', 'admin:policy:write'],
          },
        },
        routes: [],
        rules: shadowRules,
      }),
    });
  });

  await page.route('**/v1/admin/policy/rules/shadow-review', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        scanned_event_count: 35,
        scan_truncated: false,
        policy_etag: '"screenshot-shadow-policy"',
        rules: [
          {
            rule_id: 'shadow-report-deletes',
            rule: shadowRules[0],
            would_deny_count: 28,
            affected_principals: [
              { user_id: 'analyst-ada', roles: ['analyst'] },
              { user_id: 'ops-mira', roles: ['ops', 'analyst'] },
            ],
            evidence_window: {
              from: '2026-07-04T09:41:00Z',
              to: '2026-07-04T17:12:00Z',
            },
            evidence_digest: `sha256:${'1'.repeat(64)}`,
            samples: [
              {
                event_id: 'sample-report-delete',
                timestamp: '2026-07-04T17:12:00Z',
                method: 'DELETE',
                path: '/reports/quarterly/42',
                actor: {
                  user_id: 'analyst-ada',
                  roles: ['analyst'],
                  auth_mode: 'bearer_token',
                },
              },
            ],
          },
          {
            rule_id: 'shadow-admin-posts',
            rule: shadowRules[1],
            would_deny_count: 7,
            affected_principals: [
              { user_id: 'support-jules', roles: ['support'] },
              { user_id: 'support-lee', roles: ['support', 'tier2'] },
            ],
            evidence_window: {
              from: '2026-07-04T11:20:00Z',
              to: '2026-07-04T17:02:00Z',
            },
            evidence_digest: `sha256:${'2'.repeat(64)}`,
            samples: [
              {
                event_id: 'sample-admin-patch',
                timestamp: '2026-07-04T17:02:00Z',
                method: 'PATCH',
                path: '/admin/users/117',
                actor: {
                  user_id: 'support-lee',
                  roles: ['support', 'tier2'],
                  auth_mode: 'bearer_token',
                },
              },
            ],
          },
        ],
      }),
    });
  });

  await page.goto('/admin/policy/shadow-review');
  await expect(
    page.getByRole('heading', { level: 2, name: 'Shadow review queue' }),
  ).toBeVisible();
  await expect(page.getByText('shadow-report-deletes')).toBeVisible();
  await expect(page.getByText('28 would-deny events')).toBeVisible();
  await expect(page.getByText('shadow-admin-posts')).toBeVisible();
  await expect(page.getByText('7 would-deny events')).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Promote shadow-report-deletes to deny' }),
  ).toBeEnabled();
  await expect(page.getByText('Policy changed during review')).toHaveCount(0);
  await expect(page.getByText('Evidence window', { exact: true })).toHaveCount(2);

  const screenshot = await page.screenshot({
    path: path.join(screenshotDir, 'shadow-review-queue.png'),
    fullPage: true,
  });
  expect(screenshot.length).toBeGreaterThan(10_000);
});
