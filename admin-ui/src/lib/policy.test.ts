import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminApiError } from './api';
import {
  PolicyRuleShadowReviewResponse,
  PolicyRuleShadowReviewSummary,
  changeShadowRule,
  createPolicyRule,
  fetchPolicy,
  fetchPolicyRuleHits,
  fetchPolicyRuleShadowReview,
  deletePolicyRule,
  hasExplicitPolicyRuleId,
  patchPolicyRule,
  policyRuleId,
  reorderPolicyRules,
  shadowReviewBinding,
} from './policy';

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
});

describe('policy permissions', () => {
  it.each([['true', true], ['false', false], [null, false], ['TRUE', false]])(
    'uses only an explicit server capability (%s)', async (header, expected) => {
      const headers = new Headers({'Content-Type': 'application/json'});
      if (header !== null) headers.set('x-greengateway-policy-write', header);
      vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({rules: []}), {headers}))));
      expect((await fetchPolicy()).canWrite).toBe(expected);
    },
  );
});

describe('policy writes', () => {
  it.each([
    [
      'create',
      () => createPolicyRule({ action: 'deny' }, '"policy:v1"'),
    ],
    [
      'patch',
      () => patchPolicyRule('rule-1', '"policy:v1"', { enabled: false }),
    ],
    ['delete', () => deletePolicyRule('rule-1', '"policy:v1"')],
    ['reorder', () => reorderPolicyRules(['rule-1'], '"policy:v1"')],
  ])(
    'sends the CSRF token on a cookie-session %s',
    async (_name, mutate) => {
      document.cookie = 'csrf_token=token-123; Path=/';
      const observed: Headers[] = [];
      vi.stubGlobal(
        'fetch',
        vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
          observed.push(new Headers(init?.headers));
          return Promise.resolve(jsonResponse(200, {}));
        }),
      );

      await mutate();

      expect(observed[0].get('x-csrf-token')).toBe('token-123');
    },
  );
});

describe('policy evidence', () => {
  const unavailableBody = {
    error: 'policy rule hit counts require an audit query store',
    reason: 'audit_evidence_unavailable',
  };

  it('returns counted hits, including a counted zero, as available evidence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            rules: [
              { rule_id: 'busy', hits: 3 },
              { rule_id: 'quiet', hits: 0 },
            ],
          }),
        ),
      ),
    );

    expect(await fetchPolicyRuleHits()).toEqual({
      status: 'available',
      value: { busy: 3, quiet: 0 },
    });
  });

  it.each([
    ['hit counts', fetchPolicyRuleHits],
    ['shadow review', fetchPolicyRuleShadowReview],
  ])(
    'reports %s without an audit store as unavailable, not empty',
    async (_name, fetchEvidence) => {
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.resolve(jsonResponse(503, unavailableBody))),
      );

      expect(await fetchEvidence()).toEqual({
        status: 'unavailable',
        message: unavailableBody.error,
      });
    },
  );

  it.each([
    ['a 503 without the evidence reason', 503, { error: 'policy control plane unavailable' }],
    ['a 500', 500, { error: 'policy rule hit count query failed' }],
    ['a 403', 403, { error: 'forbidden', reason: 'audit_evidence_unavailable' }],
  ])('rejects %s instead of reporting an evidence state', async (_name, status, body) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(status, body))),
    );

    await expect(fetchPolicyRuleHits()).rejects.toBeInstanceOf(AdminApiError);
    await expect(fetchPolicyRuleShadowReview()).rejects.toBeInstanceOf(
      AdminApiError,
    );
  });
});

describe('shadow review bindings', () => {
  const digest = `sha256:${'b'.repeat(64)}`;
  const summary: PolicyRuleShadowReviewSummary = {
    rule_id: 'shadow-reports',
    rule: { id: 'shadow-reports', action: 'shadow' },
    would_deny_count: 2,
    affected_principals: [],
    samples: [],
    evidence_window: {
      from: '2026-07-04T15:00:00Z',
      to: '2026-07-04T16:00:00Z',
    },
    evidence_digest: digest,
  };
  const review: PolicyRuleShadowReviewResponse = {
    scanned_event_count: 2,
    scan_truncated: false,
    policy_etag: '"policy:v1"',
    rules: [summary],
  };

  it('binds an entry to the revision, window and digest the review reported', () => {
    expect(shadowReviewBinding(review, summary)).toEqual({
      policy_etag: '"policy:v1"',
      evidence_window: {
        from: '2026-07-04T15:00:00Z',
        to: '2026-07-04T16:00:00Z',
      },
      evidence_digest: digest,
    });
    expect(
      shadowReviewBinding(review, {
        ...summary,
        evidence_window: { from: null, to: null },
      })?.evidence_window,
    ).toEqual({ from: null, to: null });
  });

  it.each([
    ['no policy revision', { ...review, policy_etag: undefined }, summary],
    ['an empty policy revision', { ...review, policy_etag: '' }, summary],
    ['no evidence digest', review, { ...summary, evidence_digest: undefined }],
    ['no evidence window', review, { ...summary, evidence_window: undefined }],
    [
      'a malformed evidence window',
      review,
      {
        ...summary,
        evidence_window: { from: 7, to: null } as unknown as PolicyRuleShadowReviewSummary['evidence_window'],
      },
    ],
  ])('has nothing to bind to when the review reports %s', (_name, reviewed, entry) => {
    expect(shadowReviewBinding(reviewed, entry)).toBeNull();
  });

  it.each([
    ['promote', { action: 'deny' }],
    ['disable', { enabled: false }],
  ] as const)(
    'sends a %s with the binding and the reviewed revision as If-Match',
    async (transition, change) => {
      const binding = shadowReviewBinding(review, summary);
      if (binding === null) {
        throw new Error('fixture should bind');
      }
      const requests: Array<{ url: string; init?: RequestInit }> = [];
      vi.stubGlobal(
        'fetch',
        vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
          requests.push({ url: String(input), init });
          return Promise.resolve(
            new Response(JSON.stringify({ id: 'shadow-reports' }), {
              status: 200,
              headers: { 'Content-Type': 'application/json', ETag: '"policy:v2"' },
            }),
          );
        }),
      );

      const result = await changeShadowRule('shadow-reports', transition, binding);

      expect(result.etag).toBe('"policy:v2"');
      expect(requests).toHaveLength(1);
      expect(requests[0].url).toContain('/policy/rules/shadow-reports');
      expect(requests[0].init?.method).toBe('PATCH');
      expect(new Headers(requests[0].init?.headers).get('If-Match')).toBe('"policy:v1"');
      expect(JSON.parse(String(requests[0].init?.body))).toEqual({
        ...change,
        shadow_review: binding,
      });
    },
  );

  it.each([
    [409, 'shadow_evidence_window_stale'],
    [409, 'shadow_evidence_digest_stale'],
    [412, 'shadow_review_revision_stale'],
    [503, 'audit_evidence_unavailable'],
  ])('surfaces a %s %s refusal with its stable reason', async (status, reason) => {
    const binding = shadowReviewBinding(review, summary);
    if (binding === null) {
      throw new Error('fixture should bind');
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(status, { error: 'refused', reason }))),
    );

    const refusal = await changeShadowRule('shadow-reports', 'promote', binding).catch(
      (error: unknown) => error,
    );

    expect(refusal).toBeInstanceOf(AdminApiError);
    expect((refusal as AdminApiError).status).toBe(status);
    expect((refusal as AdminApiError).code).toBe(reason);
  });
});

describe('policy rule ids', () => {
  it('addresses a rule without an explicit id by its position', () => {
    const positional = { id: null, action: 'deny' } as const;
    const omitted = { action: 'deny' } as const;
    const named = { id: 'named-rule', action: 'deny' } as const;
    const emptyNamed = { id: '', action: 'deny' } as const;

    expect(policyRuleId(positional, 2)).toBe('2');
    expect(policyRuleId(omitted, 3)).toBe('3');
    expect(policyRuleId(named, 4)).toBe('named-rule');
    expect(hasExplicitPolicyRuleId(positional)).toBe(false);
    expect(hasExplicitPolicyRuleId(omitted)).toBe(false);
    expect(hasExplicitPolicyRuleId(named)).toBe(true);
    // The gateway keeps an empty id as the rule's id, so it does not move
    // with the rule's position.
    expect(policyRuleId(emptyNamed, 5)).toBe('');
    expect(hasExplicitPolicyRuleId(emptyNamed)).toBe(true);
  });
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
