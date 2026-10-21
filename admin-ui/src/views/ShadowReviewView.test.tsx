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

  it('requires confirming before promoting a shadow rule, sent with the reviewed binding', async () => {
    const summary = shadowSummary({
      rule_id: 'shadow-reports',
      evidence_window: {
        from: '2026-07-04T15:00:00Z',
        to: '2026-07-04T16:10:00Z',
      },
      evidence_digest: digest('1'),
    });
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
      review: shadowReviewResponse({ rules: [summary] }),
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
    // The change names exactly what was on screen: the reviewed revision,
    // and the window and digest of this entry's evidence.
    expect(fetcher.patchBodies).toEqual([
      {
        action: 'deny',
        shadow_review: {
          policy_etag: '"etag-reviewed"',
          evidence_window: {
            from: '2026-07-04T15:00:00Z',
            to: '2026-07-04T16:10:00Z',
          },
          evidence_digest: digest('1'),
        },
      },
    ]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
    expect(await screen.findByText('Rule promoted to deny.')).toBeTruthy();
    // The change is tied to the policy the operator reviewed, not to one
    // fetched just before sending it; the policy is read again only after.
    expect(fetcher.requests().slice(0, 3)).toEqual([
      'GET policy',
      'GET shadow-review',
      'PATCH shadow-reports',
    ]);
  });

  it('shows the evidence window each entry is bound to', async () => {
    vi.stubGlobal(
      'fetch',
      shadowReviewFetchMock({
        review: shadowReviewResponse({
          rules: [
            shadowSummary({
              rule_id: 'busy-shadow',
              evidence_window: {
                from: '2026-07-03T09:00:00Z',
                to: '2026-07-04T16:10:00Z',
              },
            }),
            shadowSummary({
              rule_id: 'quiet-shadow',
              would_deny_count: 0,
              affected_principals: [],
              samples: [],
              evidence_window: { from: null, to: null },
            }),
          ],
        }),
      }).fetch,
    );

    renderShadowReviewView();

    expect(
      await screen.findByText('Jul 3, 2026, 9:00 AM UTC to Jul 4, 2026, 4:10 PM UTC'),
    ).toBeTruthy();
    expect(screen.getByText('No would-deny events recorded')).toBeTruthy();
    expect(screen.getAllByText('Evidence window')).toHaveLength(2);
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
    expect(fetcher.patchBodies).toEqual([
      {
        enabled: false,
        shadow_review: {
          policy_etag: '"etag-reviewed"',
          evidence_window: defaultEvidenceWindow,
          evidence_digest: digest('shadow-reports'),
        },
      },
    ]);
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports']);
    expect(fetcher.requests().slice(0, 3)).toEqual([
      'GET policy',
      'GET shadow-review',
      'PATCH shadow-reports',
    ]);
  });

  it('reads the review again after a change and binds the next change to the new revision', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"', '"etag-after-patch-1"'],
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
    // Every other entry was reviewed under the revision the change replaced,
    // so the review is read again before anything else can be changed.
    await waitFor(() => {
      expect(fetcher.reviewRequestCount()).toBe(2);
    });
    const disableExports = (await screen.findByRole('button', {
      name: 'Disable shadow-exports',
    })) as HTMLButtonElement;
    await waitFor(() => {
      expect(disableExports.disabled).toBe(false);
    });
    expect(screen.getByText('Shadow rule disabled.')).toBeTruthy();

    fireEvent.click(disableExports);

    await waitFor(() => {
      expect(fetcher.patchHeaders).toEqual([
        '"etag-reviewed"',
        '"etag-after-patch-1"',
      ]);
    });
    expect(fetcher.patchRuleIds).toEqual(['shadow-reports', 'shadow-exports']);
    expect(
      fetcher.patchBodies.map((body) => body.shadow_review?.policy_etag),
    ).toEqual(['"etag-reviewed"', '"etag-after-patch-1"']);
    expect(fetcher.appliedPatchRuleIds).toEqual(['shadow-reports', 'shadow-exports']);
  });

  it('reports a stale revision refusal and blocks changes until the review is reloaded', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-reviewed"'],
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
      patchRefusals: [
        {
          status: 412,
          body: {
            error: 'policy changed after this shadow review was read',
            reason: 'shadow_review_revision_stale',
          },
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Disable shadow-reports' }),
    );

    expect(await screen.findByText('Policy changed')).toBeTruthy();
    expect(
      screen.getByText('Policy changed since this page loaded; refresh and retry.'),
    ).toBeTruthy();
    expectActionsBlocked(
      'shadow-reports',
      'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.',
    );
    expect(fetcher.appliedPatchRuleIds).toEqual([]);

    fireEvent.click(screen.getByRole('button', { name: 'Reload review' }));

    await waitFor(() => {
      expect(
        (screen.getByRole('button', { name: 'Disable shadow-reports' }) as HTMLButtonElement)
          .disabled,
      ).toBe(false);
    });
    expect(screen.queryByText('Policy changed')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Reload review' })).toBeNull();
    expect(fetcher.reviewRequestCount()).toBe(2);
  });

  it.each([
    [
      'shadow_evidence_window_stale',
      'New would-deny events were recorded for this rule, or older ones left the review, after this review was read. Nothing was changed; reload the review and check the current evidence.',
    ],
    [
      'shadow_evidence_digest_stale',
      'The evidence for this rule changed after this review was read. Nothing was changed; reload the review and check the current evidence.',
    ],
  ])('reports a %s refusal and blocks changes until the review is reloaded', async (reason, message) => {
    const fetcher = shadowReviewFetchMock({
      review: shadowReviewResponse({
        rules: [
          shadowSummary({ rule_id: 'shadow-reports' }),
          shadowSummary({ rule_id: 'shadow-exports' }),
        ],
      }),
      patchRefusals: [
        { status: 409, body: { error: 'shadow evidence changed', reason } },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Promote shadow-reports to deny' }),
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Confirm promote shadow-reports to deny' }),
    );

    expect(await screen.findByText('Shadow evidence changed')).toBeTruthy();
    expect(screen.getByText(message)).toBeTruthy();
    const blocked =
      'Promote and Disable are unavailable because the shadow evidence changed after this review was read. Reload the review to see the current evidence.';
    expectActionsBlocked('shadow-exports', blocked);
    expect(
      (
        screen.getByRole('button', {
          name: 'Confirm promote shadow-reports to deny',
          description: blocked,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(fetcher.appliedPatchRuleIds).toEqual([]);
    expect(screen.getByText('shadow-reports')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Reload review' }));

    await waitFor(() => {
      expect(
        (screen.getByRole('button', { name: 'Disable shadow-exports' }) as HTMLButtonElement)
          .disabled,
      ).toBe(false);
    });
    expect(screen.queryByText('Shadow evidence changed')).toBeNull();
    // The reloaded review starts over: no confirmation is left pending.
    expect(
      screen.queryByRole('button', { name: 'Confirm promote shadow-reports to deny' }),
    ).toBeNull();
  });

  it('reports evidence that was unavailable when the change was sent and blocks changes', async () => {
    const fetcher = shadowReviewFetchMock({
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
      patchRefusals: [
        {
          status: 503,
          body: {
            error: 'shadow rule promotion and disable require an audit query store',
            reason: 'audit_evidence_unavailable',
          },
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Disable shadow-reports' }),
    );

    expect(await screen.findByText('Shadow evidence unavailable')).toBeTruthy();
    expect(
      screen.getByText(
        'The gateway could not read shadow evidence when the change was sent, so it refused the change. Nothing was changed.',
      ),
    ).toBeTruthy();
    expectActionsBlocked(
      'shadow-reports',
      'Promote and Disable are unavailable because the gateway could not read shadow evidence for the last change. Reload the review once evidence is available.',
    );
    expect(screen.getByRole('button', { name: 'Reload review' })).toBeTruthy();
    expect(fetcher.appliedPatchRuleIds).toEqual([]);
  });

  it('reports a rule that is no longer in shadow mode as a policy change', async () => {
    const fetcher = shadowReviewFetchMock({
      review: shadowReviewResponse({
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
      patchRefusals: [
        {
          status: 409,
          body: {
            error: 'rule is not an enabled shadow rule',
            reason: 'shadow_review_rule_not_shadow',
          },
        },
      ],
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Disable shadow-reports' }),
    );

    expect(await screen.findByText('Policy changed')).toBeTruthy();
    expect(
      screen.getByText(
        'This rule is no longer an enabled shadow rule, so nothing was changed. Reload the review.',
      ),
    ).toBeTruthy();
    expectActionsBlocked(
      'shadow-reports',
      'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.',
    );
  });

  it('blocks changes when the review names a different revision than the policy read beside it', async () => {
    const fetcher = shadowReviewFetchMock({
      policyEtags: ['"etag-policy-read"'],
      review: shadowReviewResponse({
        policy_etag: '"etag-review-read"',
        rules: [shadowSummary({ rule_id: 'shadow-reports' })],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    expect(await screen.findByText('Policy changed during review')).toBeTruthy();
    expectActionsBlocked(
      'shadow-reports',
      'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.',
    );
    expect(screen.getByRole('button', { name: 'Reload review' })).toBeTruthy();
    expect(fetcher.patchRuleIds).toEqual([]);
  });

  it('blocks changes to an entry the review gave nothing to bind to', async () => {
    const fetcher = shadowReviewFetchMock({
      review: shadowReviewResponse({
        rules: [
          shadowSummary({ rule_id: 'unbound-shadow', evidence_digest: undefined }),
          shadowSummary({ rule_id: 'bound-shadow' }),
        ],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderShadowReviewView();

    await screen.findByRole('button', { name: 'Disable unbound-shadow' });
    expectActionsBlocked(
      'unbound-shadow',
      'Promote and Disable are unavailable because the review did not say which policy revision and evidence it describes, so a change could not be bound to it. Refresh and retry.',
    );
    expect(
      (screen.getByRole('button', { name: 'Disable bound-shadow' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Disable unbound-shadow' }));
    expect(fetcher.patchRuleIds).toEqual([]);
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

// Both actions for `ruleId` are disabled and point at `description`.
function expectActionsBlocked(ruleId: string, description: string) {
  const promoteButton = screen.getByRole('button', {
    name: new RegExp(`^(Confirm promote|Promote) ${ruleId} to deny$`),
    description,
  }) as HTMLButtonElement;
  const disableButton = screen.getByRole('button', {
    name: `Disable ${ruleId}`,
    description,
  }) as HTMLButtonElement;
  expect(promoteButton.disabled).toBe(true);
  expect(disableButton.disabled).toBe(true);
}

function digest(seed: string): string {
  const hex = Array.from(seed)
    .map((character) => character.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex.padEnd(64, '0').slice(0, 64)}`;
}

const defaultEvidenceWindow = {
  from: '2026-07-04T15:30:00Z',
  to: '2026-07-04T15:30:00Z',
};

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
// The review reports the server's current ETag as its `policy_etag` unless
// the fixture sets one, and leaves out rules a PATCH already changed. PATCH
// checks If-Match and the binding's revision against the server's current
// ETag the way the gateway does, answering 412 on any mismatch;
// `patchRefusals` answers the next PATCHes with the given refusals instead.
function shadowReviewFetchMock({
  canWrite = true,
  policy,
  review,
  reviewStatus = 200,
  reviewBody,
  policyEtags = ['"etag-initial"'],
  patchRefusals = [],
}: {
  canWrite?: boolean;
  policy?: PolicyDocument;
  review: ShadowReviewResponseFixture;
  reviewStatus?: number;
  reviewBody?: unknown;
  policyEtags?: string[];
  patchRefusals?: Array<{ status: number; body: unknown }>;
}) {
  const servedPolicy =
    policy ?? policyDocument({ rules: review.rules.map((summary) => summary.rule) });
  let policyRequestCount = 0;
  let reviewRequestCount = 0;
  let serverEtag: string | null = policyEtags[0] ?? null;
  let patchCount = 0;
  const refusals = [...patchRefusals];
  const requests: string[] = [];
  const patchBodies: PolicyRulePatch[] = [];
  const patchHeaders: Array<string | null> = [];
  const patchRuleIds: string[] = [];
  const appliedPatchRuleIds: string[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      requests.push('GET policy');
      const etag =
        policyEtags[Math.min(policyRequestCount, policyEtags.length - 1)] ?? null;
      policyRequestCount += 1;
      serverEtag = etag;
      // A rule a PATCH already promoted or disabled is no longer listed as
      // an enabled shadow rule.
      const current = {
        ...servedPolicy,
        rules: servedPolicy.rules.filter(
          (rule) => !(rule.id && appliedPatchRuleIds.includes(rule.id)),
        ),
      };
      return Promise.resolve(jsonResponse(200, current, { ...(etag ? { ETag: etag } : {}), 'x-greengateway-policy-write': String(canWrite) }));
    }

    if (url.pathname === '/v1/admin/policy/rules/shadow-review') {
      requests.push('GET shadow-review');
      reviewRequestCount += 1;
      const served = {
        ...review,
        ...(review.policy_etag === undefined && serverEtag !== null
          ? { policy_etag: serverEtag }
          : {}),
        rules: review.rules.filter(
          (summary) => !appliedPatchRuleIds.includes(summary.rule_id),
        ),
      };
      return Promise.resolve(jsonResponse(reviewStatus, reviewBody ?? served));
    }

    if (
      url.pathname.startsWith('/v1/admin/policy/rules/') &&
      init?.method === 'PATCH'
    ) {
      const ruleId = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      requests.push(`PATCH ${ruleId}`);
      const patch = JSON.parse(String(init.body)) as PolicyRulePatch;
      const ifMatch = requestHeader(init.headers, 'If-Match');
      patchRuleIds.push(ruleId);
      patchBodies.push(patch);
      patchHeaders.push(ifMatch);
      const refusal = refusals.shift();
      if (refusal) {
        return Promise.resolve(jsonResponse(refusal.status, refusal.body));
      }
      if (
        ifMatch === null ||
        ifMatch !== serverEtag ||
        patch.shadow_review?.policy_etag !== serverEtag
      ) {
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
      const change: PolicyRulePatch = { ...patch };
      delete change.shadow_review;
      return Promise.resolve(
        jsonResponse(200, { ...rule, ...change }, { ETag: serverEtag }),
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
    requests: () => [...requests],
    policyRequestCount: () => policyRequestCount,
    reviewRequestCount: () => reviewRequestCount,
    // Models another writer committing a change after the page loaded.
    setServerEtag: (etag: string) => {
      serverEtag = etag;
    },
  };
}

type ShadowReviewResponseFixture = {
  scanned_event_count: number;
  scan_truncated: boolean;
  policy_etag?: string;
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
  evidence_window?: { from: string | null; to: string | null };
  evidence_digest?: string;
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
    evidence_window: defaultEvidenceWindow,
    evidence_digest: digest(ruleId),
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
