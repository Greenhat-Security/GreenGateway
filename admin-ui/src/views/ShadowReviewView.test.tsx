import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { PolicyDocument, PolicyRule, PolicyRulePatch } from '../lib/policy';
import { ShadowReviewView } from './ShadowReviewView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('ShadowReviewView', () => {
  it('renders shadow-rule summaries with affected principals and sample requests', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        policy: policyDocument(),
        review: shadowReviewResponse({
          rules: [
            shadowSummary({
              rule_id: 'shadow-reports',
              would_deny_count: 2,
              affected_principals: [
                {
                  user_id: 'analyst-1',
                  issuer: 'https://idp-a.example',
                  auth_mode: 'bearer_token',
                  roles: ['analyst'],
                },
                {
                  user_id: 'manager-1',
                  issuer: 'https://idp-b.example',
                  auth_mode: 'session_cookie',
                  roles: ['manager', 'analyst'],
                },
              ],
              samples: [
                sample({
                  event_id: 'sample-1',
                  method: 'DELETE',
                  path: '/reports/42',
                  timestamp: '2026-07-04T16:10:00Z',
                  actor: {
                    user_id: 'analyst-1',
                    roles: ['analyst'],
                    auth_mode: 'bearer_token',
                  },
                }),
              ],
            }),
          ],
        }),
      }).fetch,
    );

    renderShadowReviewView();

    expect(await screen.findByText('Shadow review queue')).toBeTruthy();
    expect(screen.getByText('shadow-reports')).toBeTruthy();
    expect(screen.getByText('/reports/**')).toBeTruthy();
    expect(screen.getByText('2 would-deny events')).toBeTruthy();
    expect(screen.getAllByText('analyst-1').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('manager-1')).toBeTruthy();
    expect(
      screen.getByText('https://idp-a.example / bearer_token / analyst'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'https://idp-b.example / session_cookie / manager / analyst',
      ),
    ).toBeTruthy();
    expect(screen.getByText('DELETE /reports/42')).toBeTruthy();
    expect(screen.getByText('Jul 4, 2026, 4:10 PM UTC')).toBeTruthy();
  });

  it('requires confirming before promoting a shadow rule, with a freshly fetched current policy ETag', async () => {
    const fetcher = shadowReviewFetchMock({
      policy: policyDocument(),
      policyEtags: ['"etag-stale"', '"etag-current"'],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Promote shadow-reports to deny',
      }),
    );

    expect(fetcher.patchRuleIds).toEqual([]);
    const confirmButton = await screen.findByRole('button', {
      name: 'Confirm promote shadow-reports to deny',
    });

    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(fetcher.patchHeaders).toEqual(['"etag-current"']);
    });
    expect(fetcher.patchBodies).toEqual([{ action: 'deny' }]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
  });

  it('cancels a pending promote confirmation without patching the rule', async () => {
    const fetcher = shadowReviewFetchMock({
      policy: policyDocument(),
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Promote shadow-reports to deny',
      }),
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));

    expect(
      await screen.findByRole('button', {
        name: 'Promote shadow-reports to deny',
      }),
    ).toBeTruthy();
    expect(fetcher.patchRuleIds).toEqual([]);
  });

  it('demotes a shadow rule by disabling it with a freshly fetched current policy ETag', async () => {
    const fetcher = shadowReviewFetchMock({
      policy: policyDocument(),
      policyEtags: ['"etag-stale"', '"etag-current"'],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Disable shadow-reports',
      }),
    );

    await waitFor(() => {
      expect(fetcher.patchHeaders).toEqual(['"etag-current"']);
    });
    expect(fetcher.patchBodies).toEqual([{ enabled: false }]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
  });

  it('disables promote and demote controls for read-only principals', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:policy:read'] },
          },
        }),
        review: shadowReviewResponse({
          rules: [shadowSummary({ rule_id: 'read-only-shadow' })],
        }),
      }).fetch,
    );

    renderShadowReviewView({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('Policy write permission required')).toBeTruthy();
    expect(
      (
        screen.getByRole('button', {
          name: 'Promote read-only-shadow to deny',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole('button', {
          name: 'Disable read-only-shadow',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });

  it('renders the empty state when there are no enabled shadow rules', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        policy: policyDocument(),
        review: shadowReviewResponse({ rules: [] }),
      }).fetch,
    );

    renderShadowReviewView();

    expect(
      await screen.findByText('No rules are currently in shadow mode.'),
    ).toBeTruthy();
  });

  it('still renders a shadow rule whose would-deny count is zero', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        policy: policyDocument(),
        review: shadowReviewResponse({
          rules: [
            shadowSummary({
              rule_id: 'quiet-shadow',
              would_deny_count: 0,
              affected_principals: [],
              samples: [],
            }),
          ],
        }),
      }).fetch,
    );

    renderShadowReviewView();

    expect(await screen.findByText('quiet-shadow')).toBeTruthy();
    expect(screen.getByText('0 would-deny events')).toBeTruthy();
  });
});

function renderShadowReviewView({
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
      <ShadowReviewView />
    </MemoryRouter>,
  );
}

function shadowReviewFetchMock({
  policy,
  review,
  policyEtags = ['"etag-initial"'],
}: {
  policy: PolicyDocument;
  review: ShadowReviewResponseFixture;
  policyEtags?: string[];
}) {
  let policyRequestCount = 0;
  const patchBodies: PolicyRulePatch[] = [];
  const patchHeaders: Array<string | null> = [];
  const patchRuleIds: string[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      const etag =
        policyEtags[Math.min(policyRequestCount, policyEtags.length - 1)] ?? null;
      policyRequestCount += 1;
      return Promise.resolve(jsonResponse(200, policy, etag ? { ETag: etag } : {}));
    }

    if (url.pathname === '/v1/admin/policy/rules/shadow-review') {
      return Promise.resolve(jsonResponse(200, review));
    }

    if (
      url.pathname.startsWith('/v1/admin/policy/rules/') &&
      init?.method === 'PATCH'
    ) {
      const ruleId = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      const patch = JSON.parse(String(init.body)) as PolicyRulePatch;
      patchRuleIds.push(ruleId);
      patchBodies.push(patch);
      patchHeaders.push(requestHeader(init.headers, 'If-Match'));
      const rule = review.rules.find((item) => item.rule_id === ruleId)?.rule;
      return Promise.resolve(
        jsonResponse(200, { ...rule, ...patch }, { ETag: '"etag-after-patch"' }),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, patchBodies, patchHeaders, patchRuleIds };
}

type ShadowReviewResponseFixture = {
  scanned_event_count: number;
  scan_truncated: boolean;
  rules: ShadowReviewSummaryFixture[];
};

type ShadowReviewSummaryFixture = {
  rule_id: string;
  rule: PolicyRule;
  would_deny_count: number;
  affected_principals: Array<{
    user_id: string;
    issuer?: string;
    auth_mode: string;
    roles: string[];
  }>;
  samples: ShadowReviewSampleFixture[];
};

type ShadowReviewSampleFixture = {
  event_id: string;
  timestamp: string;
  method: string;
  path: string;
  actor: {
    user_id: string;
    roles?: string[];
    auth_mode: string;
  } | null;
};

function shadowReviewResponse(
  overrides: Partial<ShadowReviewResponseFixture> = {},
): ShadowReviewResponseFixture {
  return {
    scanned_event_count: 0,
    scan_truncated: false,
    rules: [],
    ...overrides,
  };
}

function shadowSummary(
  overrides: Partial<ShadowReviewSummaryFixture> = {},
): ShadowReviewSummaryFixture {
  const ruleId = overrides.rule_id ?? 'shadow-reports';

  return {
    rule_id: ruleId,
    rule: rule({
      id: ruleId,
      action: 'shadow',
      methods: ['GET'],
      path: '/reports/**',
      principal: { roles: ['analyst'] },
    }),
    would_deny_count: 1,
    affected_principals: [
      {
        user_id: 'analyst-1',
        issuer: 'provider:test',
        auth_mode: 'bearer_token',
        roles: ['analyst'],
      },
    ],
    samples: [sample()],
    ...overrides,
  };
}

function sample(
  overrides: Partial<ShadowReviewSampleFixture> = {},
): ShadowReviewSampleFixture {
  return {
    event_id: 'sample-event',
    timestamp: '2026-07-04T15:30:00Z',
    method: 'GET',
    path: '/reports/1',
    actor: {
      user_id: 'analyst-1',
      roles: ['analyst'],
      auth_mode: 'bearer_token',
    },
    ...overrides,
  };
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

function rule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: 'rule-id',
    enabled: true,
    methods: ['GET'],
    path: '/example',
    principal: {},
    action: 'shadow',
    ...overrides,
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
