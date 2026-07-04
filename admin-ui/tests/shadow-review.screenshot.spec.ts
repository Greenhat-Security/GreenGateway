import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const adminTokenStorageKey = 'greengateway_admin_token';

test.beforeEach(async () => {
  await mkdir(screenshotDir, { recursive: true });
});

test('captures the shadow review queue', async ({ page }) => {
  await page.addInitScript(
    ({ key, token }) => {
      window.sessionStorage.setItem(key, token);
    },
    {
      key: adminTokenStorageKey,
      token: jwtWithRoles(['admin']),
    },
  );

  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: {
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
        rules: [],
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
        rules: [
          {
            rule_id: 'shadow-report-deletes',
            rule: {
              id: 'shadow-report-deletes',
              enabled: true,
              methods: ['DELETE'],
              path: '/reports/**',
              principal: {
                roles: ['analyst'],
              },
              action: 'shadow',
            },
            would_deny_count: 28,
            affected_principals: [
              { user_id: 'analyst-ada', roles: ['analyst'] },
              { user_id: 'ops-mira', roles: ['ops', 'analyst'] },
            ],
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
            rule: {
              id: 'shadow-admin-posts',
              enabled: true,
              methods: ['POST', 'PATCH'],
              path: '/admin/**',
              principal: {
                roles: ['support'],
              },
              action: 'shadow',
            },
            would_deny_count: 7,
            affected_principals: [
              { user_id: 'support-jules', roles: ['support'] },
              { user_id: 'support-lee', roles: ['support', 'tier2'] },
            ],
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

  const screenshot = await page.screenshot({
    path: path.join(screenshotDir, 'shadow-review-queue.png'),
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
