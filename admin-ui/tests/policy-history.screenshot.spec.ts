import { expect, test } from '@playwright/test';
import { Buffer } from 'node:buffer';
import path from 'node:path';

const screenshotDir = path.join(process.cwd(), '.screenshots');
const adminTokenStorageKey = 'greengateway_admin_token';

test('captures the policy version history timeline', async ({ page }) => {
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
        ETag: '"screenshot-policy-etag"',
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
        rules: [
          {
            id: 'support-read',
            enabled: true,
            methods: ['GET'],
            path: '/support/**',
            principal: {
              roles: ['support'],
            },
            action: 'allow',
          },
        ],
      }),
    });
  });

  await page.route('**/v1/admin/policy/history*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        versions: [
          {
            version: 9,
            actor: 'ops-admin',
            created_at: '2026-07-04T12:00:00Z',
            diff_summary: {
              action: 'rule_updated',
              rule_id: 'support-read',
              changed_fields: ['path', 'action'],
            },
          },
          {
            version: 8,
            actor: 'ops-admin',
            created_at: '2026-07-04T11:42:00Z',
            diff_summary: {
              action: 'rules_reordered',
              new_order: ['support-read', 'billing-read'],
            },
          },
          {
            version: 7,
            actor: 'platform-lead',
            created_at: '2026-07-04T10:15:00Z',
            diff_summary: {
              action: 'policy_rolled_back',
              target_version: 4,
            },
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.goto('/admin/policy/history');
  await expect(
    page.getByRole('heading', { level: 2, name: 'Policy version history' }),
  ).toBeVisible();
  await expect(
    page.getByText('Rule support-read updated (path, action changed)'),
  ).toBeVisible();
  await expect(page.getByText('Rules reordered')).toBeVisible();
  await expect(page.getByText('Rolled back to version 4')).toBeVisible();

  await page.screenshot({
    path: path.join(screenshotDir, 'policy-history-light.png'),
    fullPage: true,
  });
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
