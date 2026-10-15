import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { clearMemoryToken, setMemoryToken } from '../lib/auth';
import type { PolicyDocument, PolicyRule, PolicyRulePatch } from '../lib/policy';
import { ShadowReviewView } from './ShadowReviewView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('ShadowReviewView', () => {
  it('renders shadow-rule summaries with affected principals and sample requests', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
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

  it('requires confirming before promoting a shadow rule, sent with the reviewed policy ETag', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    const promoteButton = (await screen.findByRole('button', {
      name: 'Promote shadow-reports to deny',
    })) as HTMLButtonElement;
    expect(promoteButton.disabled).toBe(false);
    expect(promoteButton.getAttribute('aria-describedby')).toBeNull();
    fireEvent.click(promoteButton);

    expect(fetcher.patchRuleIds).toEqual([]);
    const confirmButton = await screen.findByRole('button', {
      name: 'Confirm promote shadow-reports to deny',
    });

    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(fetcher.patchHeaders).toEqual(['"etag-reviewed"']);
    });
    expect(fetcher.patchBodies).toEqual([{ action: 'deny' }]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
    expect(await screen.findByText('Rule promoted to deny.')).toBeTruthy();
    // The change is tied to the policy the operator reviewed, not to one
    // fetched just before sending it.
    expect(fetcher.policyRequestCount()).toBe(1);
  });

  it('cancels a pending promote confirmation without patching the rule', async () => {
    const fetcher = shadowReviewFetchMock({
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

  it('demotes a shadow rule by disabling it with the reviewed policy ETag', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
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
      expect(fetcher.patchHeaders).toEqual(['"etag-reviewed"']);
    });
    expect(fetcher.patchBodies).toEqual([{ enabled: false }]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
    expect(fetcher.policyRequestCount()).toBe(1);
  });

  it('sends the next change with the ETag the previous change returned', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
      review: shadowReviewResponse({
        rules: [
          shadowSummary({ rule_id: 'shadow-reports' }),
          shadowSummary({ rule_id: 'shadow-exports' }),
        ],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Disable shadow-reports' }),
    );
    expect(await screen.findByText('Shadow rule disabled.')).toBeTruthy();
    expect(screen.queryByText('shadow-reports')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Disable shadow-exports' }));

    await waitFor(() => {
      expect(fetcher.patchHeaders).toEqual([
        '"etag-reviewed"',
        '"etag-after-patch-1"',
      ]);
    });
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports', 'shadow-exports']);
    expect(fetcher.policyRequestCount()).toBe(1);
  });

  it('refuses a position-keyed promote with 412 after a concurrent change instead of patching another rule', async () => {
    const reviewedRule = rule({ id: null, action: 'shadow', path: '/reports/**' });
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: '0', rule: reviewedRule })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Promote 0 to deny' }),
    );
    // Another writer reorders the rules, so position 0 is now another rule.
    fetcher.setServerEtag('"etag-after-concurrent-reorder"');
    fireEvent.click(
      await screen.findByRole('button', { name: 'Confirm promote 0 to deny' }),
    );

    expect(await screen.findByText('Policy changed')).toBeTruthy();
    expect(
      screen.getByText('Policy changed since this page loaded; refresh and retry.'),
    ).toBeTruthy();
    expect(fetcher.patchHeaders).toEqual(['"etag-reviewed"']);
    expect(fetcher.appliedPatchRuleIds).toEqual([]);
    expect(screen.getByText('0')).toBeTruthy();
    expect(
      (
        screen.getByRole('button', {
          name: 'Confirm promote 0 to deny',
          description:
            'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (screen.getByRole('button', { name: 'Disable 0' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('blocks changes when the review and the policy were read from different versions', async () => {
    const fetcher = shadowReviewFetchMock({
      // A write landed between the two reads: position 0 holds another rule
      // in the policy whose ETag a change would be sent with.
      policy: policyDocument({
        rules: [rule({ id: null, action: 'shadow', path: '/exports/**' })],
      }),
      review: shadowReviewResponse({
        rules: [
          shadowSummary({
            rule_id: '0',
            rule: rule({ id: null, action: 'shadow', path: '/reports/**' }),
          }),
        ],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    expect(await screen.findByText('Policy changed during review')).toBeTruthy();
    const description =
      'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.';
    const promoteButton = screen.getByRole('button', {
      name: 'Promote 0 to deny',
      description,
    }) as HTMLButtonElement;
    const disableButton = screen.getByRole('button', {
      name: 'Disable 0',
      description,
    }) as HTMLButtonElement;
    expect(promoteButton.disabled).toBe(true);
    expect(disableButton.disabled).toBe(true);
    fireEvent.click(disableButton);
    expect(fetcher.patchRuleIds).toEqual([]);
  });

  it('blocks changes when the policy read returned no ETag', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: [],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    const promoteButton = (await screen.findByRole('button', {
      name: 'Promote shadow-reports to deny',
      description:
        'Promote and Disable are unavailable because the policy ETag was not returned, so a change could not be tied to the reviewed policy. Refresh and retry.',
    })) as HTMLButtonElement;
    expect(promoteButton.disabled).toBe(true);
    expect(
      (screen.getByRole('button', { name: 'Disable shadow-reports' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(fetcher.patchRuleIds).toEqual([]);
  });

  it('disables promote and demote controls for read-only principals', async () => {
    const summary = shadowSummary({ rule_id: 'read-only-shadow' });
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        canWrite: false,
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:policy:read'] },
          },
          rules: [summary.rule],
        }),
        review: shadowReviewResponse({ rules: [summary] }),
      }).fetch,
    );

    renderShadowReviewView({ token: jwtWithRoles(['reader']) });

    expect(await screen.findByText('Policy write permission required')).toBeTruthy();
    expect(screen.queryByText('Policy changed during review')).toBeNull();
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
    expect(screen.getByText('No affected principals recorded.')).toBeTruthy();
    expect(screen.queryByText('Evidence unavailable')).toBeNull();
    expect(screen.queryByText(/scan truncated/)).toBeNull();
  });

  it('marks counts from a truncated audit scan as lower bounds', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        review: shadowReviewResponse({
          scanned_event_count: 100_000,
          scan_truncated: true,
          rules: [
            shadowSummary({ rule_id: 'busy-shadow', would_deny_count: 2 }),
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

    expect(
      await screen.findByText('2 would-deny events (scan truncated)'),
    ).toBeTruthy();
    expect(screen.getByText('0 would-deny events (scan truncated)')).toBeTruthy();
    expect(screen.queryByText('0 would-deny events')).toBeNull();
    expect(
      screen.getByText(
        'Audit scan limit reached; counts, principals, and samples cover only the newest scanned events, so each count is a lower bound.',
      ),
    ).toBeTruthy();
  });

  it('lists enabled shadow rules with unavailable evidence instead of zero counts', async () => {
    const fetcher = shadowReviewFetchMock({
      policy: policyDocument({
        rules: [
          rule({ id: 'shadow-reports', action: 'shadow', path: '/reports/**' }),
          rule({ id: 'deny-exports', action: 'deny', path: '/exports/**' }),
          rule({
            id: 'shadow-disabled',
            action: 'shadow',
            enabled: false,
            path: '/disabled/**',
          }),
          rule({ id: null, action: 'shadow', path: '/unnamed/**' }),
        ],
      }),
      review: shadowReviewResponse(),
      reviewStatus: 503,
      reviewBody: {
        error: 'policy shadow review requires an audit query store',
        reason: 'audit_evidence_unavailable',
      },
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    expect(await screen.findByText('Shadow evidence unavailable')).toBeTruthy();
    expect(
      screen.getByText('policy shadow review requires an audit query store'),
    ).toBeTruthy();
    expect(screen.getByText('shadow-reports')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.queryByText('deny-exports')).toBeNull();
    expect(screen.queryByText('shadow-disabled')).toBeNull();
    expect(screen.getByText('2 rules')).toBeTruthy();
    expect(screen.getAllByText('Evidence unavailable')).toHaveLength(2);
    expect(screen.getAllByText('Evidence unavailable.')).toHaveLength(4);
    expect(screen.queryByText(/would-deny event/)).toBeNull();
    expect(screen.queryByText('No affected principals recorded.')).toBeNull();
    expect(screen.queryByText('Request failed')).toBeNull();
  });

  it('disables Promote and Disable while shadow evidence is unavailable, and says why', async () => {
    const fetcher = shadowReviewFetchMock({
      policy: policyDocument({
        rules: [
          rule({ id: 'shadow-reports', action: 'shadow', path: '/reports/**' }),
          rule({ id: null, action: 'shadow', path: '/unnamed/**' }),
        ],
      }),
      review: shadowReviewResponse(),
      reviewStatus: 503,
      reviewBody: {
        error: 'policy shadow review requires an audit query store',
        reason: 'audit_evidence_unavailable',
      },
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    expect(await screen.findByText('Shadow evidence unavailable')).toBeTruthy();
    const explanation =
      'Promote and Disable are unavailable while shadow evidence is unavailable: nothing shows which requests changing this rule would affect.';
    expect(screen.getAllByText(explanation)).toHaveLength(2);
    for (const ruleId of ['shadow-reports', '1']) {
      const promoteButton = screen.getByRole('button', {
        name: `Promote ${ruleId} to deny`,
        description: explanation,
      }) as HTMLButtonElement;
      const disableButton = screen.getByRole('button', {
        name: `Disable ${ruleId}`,
        description: explanation,
      }) as HTMLButtonElement;
      expect(promoteButton.disabled).toBe(true);
      expect(promoteButton.title).toBe(explanation);
      expect(disableButton.disabled).toBe(true);
      fireEvent.click(promoteButton);
      fireEvent.click(disableButton);
    }

    expect(
      screen.queryByRole('button', { name: /^Confirm promote/ }),
    ).toBeNull();
    expect(fetcher.patchRuleIds).toEqual([]);
    expect(screen.queryByText('Policy write permission required')).toBeNull();
  });

  it('still reports a shadow review failure that is not an evidence state', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        policy: policyDocument({
          rules: [rule({ id: 'shadow-reports', action: 'shadow' })],
        }),
        review: shadowReviewResponse(),
        reviewStatus: 500,
        reviewBody: { error: 'shadow rule review query failed' },
      }).fetch,
    );

    renderShadowReviewView();

    expect(await screen.findByText('Request failed')).toBeTruthy();
    expect(screen.getByText('shadow rule review query failed')).toBeTruthy();
    expect(screen.queryByText('Shadow evidence unavailable')).toBeNull();
    expect(screen.queryByText('shadow-reports')).toBeNull();
  });
});

function renderShadowReviewView({
  token = jwtWithRoles(['admin']),
}: {
  token?: string | null;
} = {}) {
  clearMemoryToken();
  if (token !== null) {
    setMemoryToken(token);
  }

  render(
    <MemoryRouter>
      <ShadowReviewView />
    </MemoryRouter>,
  );
}

// The policy defaults to the one the review describes: the rules the review
// lists, in order. Pass `policy` to model a review read from another version.
// PATCH checks If-Match against the server's current ETag the way the gateway
// does, answering 412 on any mismatch.
function shadowReviewFetchMock({
  canWrite = true,
  policy,
  review,
  reviewStatus = 200,
  reviewBody,
  policyEtags = ['"etag-initial"'],
}: {
  canWrite?: boolean;
  policy?: PolicyDocument;
  review: ShadowReviewResponseFixture;
  reviewStatus?: number;
  reviewBody?: unknown;
  policyEtags?: string[];
}) {
  const servedPolicy =
    policy ?? policyDocument({ rules: review.rules.map((summary) => summary.rule) });
  let policyRequestCount = 0;
  let serverEtag: string | null = policyEtags[0] ?? null;
  let patchCount = 0;
  const patchBodies: PolicyRulePatch[] = [];
  const patchHeaders: Array<string | null> = [];
  const patchRuleIds: string[] = [];
  const appliedPatchRuleIds: string[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      const etag =
        policyEtags[Math.min(policyRequestCount, policyEtags.length - 1)] ?? null;
      policyRequestCount += 1;
      serverEtag = etag;
      return Promise.resolve(jsonResponse(200, servedPolicy, { ...(etag ? { ETag: etag } : {}), 'x-greengateway-policy-write': String(canWrite) }));
    }

    if (url.pathname === '/v1/admin/policy/rules/shadow-review') {
      return Promise.resolve(jsonResponse(reviewStatus, reviewBody ?? review));
    }

    if (
      url.pathname.startsWith('/v1/admin/policy/rules/') &&
      init?.method === 'PATCH'
    ) {
      const ruleId = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      const patch = JSON.parse(String(init.body)) as PolicyRulePatch;
      const ifMatch = requestHeader(init.headers, 'If-Match');
      patchRuleIds.push(ruleId);
      patchBodies.push(patch);
      patchHeaders.push(ifMatch);
      if (ifMatch === null || ifMatch !== serverEtag) {
        return Promise.resolve(
          jsonResponse(412, {
            error: 'If-Match does not match the current policy ETag',
          }),
        );
      }
      patchCount += 1;
      serverEtag = `"etag-after-patch-${patchCount}"`;
      appliedPatchRuleIds.push(ruleId);
      const rule = review.rules.find((item) => item.rule_id === ruleId)?.rule;
      return Promise.resolve(
        jsonResponse(200, { ...rule, ...patch }, { ETag: serverEtag }),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return {
    fetch,
    patchBodies,
    patchHeaders,
    patchRuleIds,
    appliedPatchRuleIds,
    policyRequestCount: () => policyRequestCount,
    // Models another writer committing a change after the page loaded.
    setServerEtag: (etag: string) => {
      serverEtag = etag;
    },
  };
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
