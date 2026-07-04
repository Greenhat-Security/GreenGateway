import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { PolicyDocument } from '../lib/policy';
import { PolicyHistoryView } from './PolicyHistoryView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('PolicyHistoryView', () => {
  it('renders a timeline sentence for every policy history action variant', async () => {
    vi.stubGlobal(
      'fetch',
      policyHistoryFetchMock({
        policy: policyDocument(),
        pages: [
          {
            versions: [
              historyVersion(7, {
                action: 'policy_replaced',
              }),
              historyVersion(6, {
                action: 'policy_rolled_back',
                target_version: 4,
              }),
              historyVersion(5, {
                action: 'rule_created',
                rule_id: 'support-read',
                position: 3,
              }),
              historyVersion(4, {
                action: 'rule_updated',
                rule_id: 'support-read',
                changed_fields: ['path', 'action'],
              }),
              historyVersion(3, {
                action: 'rule_deleted',
                rule_id: 'legacy-rule',
                position: 2,
              }),
              historyVersion(2, {
                action: 'rules_reordered',
                new_order: ['support-read', 'legacy-rule'],
              }),
            ],
            next_cursor: null,
          },
        ],
      }).fetch,
    );

    renderPolicyHistoryView();

    expect(await screen.findByText('Full policy replaced')).toBeTruthy();
    expect(screen.getByText('Rolled back to version 4')).toBeTruthy();
    expect(screen.getByText('Rule support-read created at position 3')).toBeTruthy();
    expect(
      screen.getByText('Rule support-read updated (path, action changed)'),
    ).toBeTruthy();
    expect(screen.getByText('Rule legacy-rule deleted from position 2')).toBeTruthy();
    expect(screen.getByText('Rules reordered')).toBeTruthy();
  });

  it('loads the next history page and appends entries to the timeline', async () => {
    const fetcher = policyHistoryFetchMock({
      policy: policyDocument(),
      pages: [
        {
          versions: [
            historyVersion(8, {
              action: 'rule_updated',
              rule_id: 'first-page',
              changed_fields: ['enabled'],
            }),
          ],
          next_cursor: '8',
        },
        {
          versions: [
            historyVersion(7, {
              action: 'rule_deleted',
              rule_id: 'second-page',
              position: 1,
            }),
          ],
          next_cursor: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderPolicyHistoryView();

    expect(await screen.findByText('Rule first-page updated (enabled changed)')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('Rule second-page deleted from position 1')).toBeTruthy();
    expect(fetcher.historyQueries).toContain('cursor=8&limit=20');
  });

  it('rolls back with a fresh current policy ETag and refreshes the first history page', async () => {
    const fetcher = policyHistoryFetchMock({
      policy: policyDocument(),
      policyEtags: ['"etag-stale"', '"etag-current"', '"etag-after-rollback"'],
      pages: [
        {
          versions: [
            historyVersion(5, {
              action: 'rule_updated',
              rule_id: 'support-read',
              changed_fields: ['path'],
            }),
            historyVersion(4, {
              action: 'policy_replaced',
            }),
          ],
          next_cursor: null,
        },
        {
          versions: [
            historyVersion(6, {
              action: 'policy_rolled_back',
              target_version: 4,
            }),
            historyVersion(5, {
              action: 'rule_updated',
              rule_id: 'support-read',
              changed_fields: ['path'],
            }),
            historyVersion(4, {
              action: 'policy_replaced',
            }),
          ],
          next_cursor: null,
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderPolicyHistoryView();

    fireEvent.click(await screen.findByRole('button', { name: 'Rollback to version 4' }));

    await waitFor(() => {
      expect(fetcher.rollbackHeaders).toEqual(['"etag-current"']);
    });
    expect(await screen.findByText('Rollback applied.')).toBeTruthy();
    expect(screen.getByText('Rolled back to version 4')).toBeTruthy();
  });

  it('surfaces a rollback history append warning as a non-fatal warning', async () => {
    const fetcher = policyHistoryFetchMock({
      policy: policyDocument(),
      policyEtags: ['"etag-stale"', '"etag-current"', '"etag-after-rollback"'],
      pages: [
        {
          versions: [
            historyVersion(3, {
              action: 'rule_updated',
              rule_id: 'changed-rule',
              changed_fields: ['methods'],
            }),
            historyVersion(2, {
              action: 'policy_replaced',
            }),
          ],
          next_cursor: null,
        },
        {
          versions: [
            historyVersion(4, {
              action: 'policy_rolled_back',
              target_version: 2,
            }),
            historyVersion(3, {
              action: 'rule_updated',
              rule_id: 'changed-rule',
              changed_fields: ['methods'],
            }),
          ],
          next_cursor: null,
        },
      ],
      rollbackWarning: true,
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderPolicyHistoryView();

    fireEvent.click(await screen.findByRole('button', { name: 'Rollback to version 2' }));

    expect(
      await screen.findByText(
        'Rollback applied, but it could not be recorded in version history.',
      ),
    ).toBeTruthy();
    expect(fetcher.rollbackHeaders).toEqual(['"etag-current"']);
  });

  it('shows the refresh-and-retry message when rollback hits a stale policy ETag response', async () => {
    const fetcher = policyHistoryFetchMock({
      policy: policyDocument(),
      policyEtags: ['"etag-stale"', '"etag-current"'],
      pages: [
        {
          versions: [
            historyVersion(2, {
              action: 'rule_created',
              rule_id: 'new-rule',
              position: 0,
            }),
            historyVersion(1, {
              action: 'policy_replaced',
            }),
          ],
          next_cursor: null,
        },
      ],
      rollbackStatus: 412,
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderPolicyHistoryView();

    fireEvent.click(await screen.findByRole('button', { name: 'Rollback to version 1' }));

    expect(
      await screen.findByText('Policy changed since this page loaded — refresh and retry.'),
    ).toBeTruthy();
  });

  it('renders read-only principals without enabled rollback controls', async () => {
    vi.stubGlobal(
      'fetch',
      policyHistoryFetchMock({
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:policy:read'] },
          },
        }),
        pages: [
          {
            versions: [
              historyVersion(2, {
                action: 'rule_updated',
                rule_id: 'read-only',
                changed_fields: ['enabled'],
              }),
              historyVersion(1, {
                action: 'policy_replaced',
              }),
            ],
            next_cursor: null,
          },
        ],
      }).fetch,
    );

    renderPolicyHistoryView({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('Policy write permission required')).toBeTruthy();
    const rollbackButtons = screen.getAllByRole('button', { name: /Rollback to version/ });
    expect(rollbackButtons.length).toBeGreaterThan(0);
    expect(rollbackButtons.every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
  });
});

function renderPolicyHistoryView({
  token = jwtWithRoles(['admin']),
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter>
      <PolicyHistoryView />
    </MemoryRouter>,
  );
}

function policyHistoryFetchMock({
  policy,
  pages,
  policyEtags = ['"etag-initial"'],
  rollbackStatus = 200,
  rollbackWarning = false,
}: {
  policy: PolicyDocument;
  pages: PolicyHistoryPageFixture[];
  policyEtags?: string[];
  rollbackStatus?: number;
  rollbackWarning?: boolean;
}) {
  let policyRequestCount = 0;
  let firstPageRequestCount = 0;
  const historyQueries: string[] = [];
  const rollbackHeaders: Array<string | null> = [];

  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      const etag =
        policyEtags[Math.min(policyRequestCount, policyEtags.length - 1)] ?? null;
      policyRequestCount += 1;
      return Promise.resolve(jsonResponse(200, policy, etag ? { ETag: etag } : {}));
    }

    if (url.pathname === '/v1/admin/policy/history') {
      historyQueries.push(url.searchParams.toString());
      if (url.searchParams.has('cursor')) {
        return Promise.resolve(jsonResponse(200, pages[1]));
      }

      const page = pages[Math.min(firstPageRequestCount, pages.length - 1)];
      firstPageRequestCount += 1;
      return Promise.resolve(jsonResponse(200, page));
    }

    if (
      url.pathname.startsWith('/v1/admin/policy/rollback/') &&
      init?.method === 'POST'
    ) {
      rollbackHeaders.push(requestHeader(init.headers, 'If-Match'));
      if (rollbackStatus !== 200) {
        return Promise.resolve(
          jsonResponse(rollbackStatus, {
            error: 'If-Match does not match the current policy ETag',
          }),
        );
      }

      return Promise.resolve(
        jsonResponse(200, policy, {
          ETag: '"etag-rollback"',
          ...(rollbackWarning
            ? {
                'X-GreenGateway-Policy-History-Warning':
                  'policy_history_append_failed',
              }
            : {}),
        }),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, historyQueries, rollbackHeaders };
}

type PolicyHistoryPageFixture = {
  versions: PolicyVersionFixture[];
  next_cursor: string | null;
};

type PolicyVersionFixture = {
  version: number;
  actor: string;
  created_at: string;
  diff_summary: Record<string, unknown>;
};

function historyVersion(
  version: number,
  diff_summary: Record<string, unknown>,
): PolicyVersionFixture {
  return {
    version,
    actor: 'user-123',
    created_at: '2026-07-04T12:00:00Z',
    diff_summary,
  };
}

function requestHeader(headers: HeadersInit | undefined, name: string): string | null {
  if (!headers) {
    return null;
  }
  if (headers instanceof Headers) {
    return headers.get(name);
  }
  if (Array.isArray(headers)) {
    return headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? null;
  }

  return headers[name] ?? null;
}

function policyDocument(
  overrides: Partial<PolicyDocument> = {},
): PolicyDocument {
  return {
    schema_version: '0.1.0',
    id: 'test-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {
      admin: { permissions: ['*'] },
    },
    routes: [],
    rules: [],
    ...overrides,
  };
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

function jwtWithRoles(roles: string[]): string {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'test-user', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
