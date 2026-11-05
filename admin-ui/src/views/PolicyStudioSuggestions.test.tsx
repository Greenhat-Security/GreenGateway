import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { clearMemoryToken } from '../lib/auth';
import { releaseHeldPolicyEdits } from './policy-studio/heldEdits';
import { PolicyStudioView } from './PolicyStudioView';

const LIVE_ETAG = '"sha256:live-1"';
const NEW_DRAFT_ID = `pd_${'e'.repeat(32)}`;
const BILLING = 'sugg-billing-read';
const EXPORTS = 'sugg-signal-exports';
const DISMISSED = 'sugg-old-reports';
const READ = 'admin:policy:read';
const WRITE = 'admin:policy:write';
const SUGGESTIONS_READ = 'admin:suggestions:read';
const SUGGESTIONS_WRITE = 'admin:suggestions:write';
const SIMULATE = 'admin:policy:simulate';
const ANALYZE = 'admin:policy:analyze';
const ALL = [READ, WRITE, SUGGESTIONS_READ, SUGGESTIONS_WRITE, SIMULATE, ANALYZE];
const WAIT = { timeout: 4000 };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearMemoryToken();
  releaseHeldPolicyEdits();
});

describe('Policy Studio suggestions', () => {
  it('lists each suggestion with its evidence, freshness, routing and position, and labels superseded ones in text', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    const row = await openSuggestions(BILLING);

    expect(within(row).getByText('Traffic baseline from the audit history')).toBeTruthy();
    expect(within(row).getByText(/Role support called GET \/billing\/\{id\} 12 times/)).toBeTruthy();
    expect(within(row).getByText('Recorded')).toBeTruthy();
    expect(
      within(row).getByText(/Window: 2026-10-25T10:00:00Z to 2026-11-01T10:00:00Z \(168 hours\)/),
    ).toBeTruthy();
    expect(within(row).getByText(/Generated 2026-11-01T10:00:00Z and not recomputed since/)).toBeTruthy();
    expect(within(row).getByText('Contextless.')).toBeTruthy();
    expect(within(row).getByText(/Position 1 \(rule #2\), after the last rule of the live policy/)).toBeTruthy();
    expect(within(row).getByText('Not recorded by this gateway')).toBeTruthy();
    expect(screen.getByText(/the gateway records no policy revision,\s+resource snapshot, evidence schema or generator version/)).toBeTruthy();
    expect(within(row).getByText(/^1, updated/)).toBeTruthy();

    const signal = suggestionRow(EXPORTS);
    expect(within(signal).getByText('Discovery signal sig-7 (error_rate_spike)')).toBeTruthy();
    expect(within(signal).getByText(/shadow: a would-deny that is only observed/)).toBeTruthy();
    expect(within(signal).getByText(/The signal’s own detection/)).toBeTruthy();

    // There is no direct apply: acceptance is a bound publication.
    expect(screen.queryByRole('button', { name: /accept|apply/i })).toBeNull();

    fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'all' } });
    const dismissed = await screen.findByRole('listitem', { name: 'GET /reports' }, WAIT);
    expect(within(dismissed).getByText('Superseded: dismissed')).toBeTruthy();
    expect(within(dismissed).getByText(/Dismissed by alice at 2026-11-02T09:00:00Z/)).toBeTruthy();
    expect(within(dismissed).queryByRole('button', { name: 'Review in draft' })).toBeNull();
    expect(gateway.requests('GET', '/v1/admin/suggestions').at(-1)?.search).toBe('?limit=50');
    expect(accessibilityProblems()).toEqual([]);
  });

  it('reviews a suggestion in a new draft, opens it in the editors and checks it at its real position', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    const row = await openSuggestions(BILLING);

    fireEvent.click(within(row).getByRole('button', { name: 'Review in draft' }));

    expect(await screen.findByText('Suggestion opened in a draft', undefined, WAIT)).toBeTruthy();
    const [request] = gateway.requests('POST', `/v1/admin/suggestions/${BILLING}/draft`);
    expect(request.headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(request.headers.get('X-GreenGateway-Suggestion-Revision')).toBe('1');
    expect(request.headers.get('X-GreenGateway-Policy-Draft-ETag')).toBeNull();
    expect(request.body).toBe('{}');
    expect(screen.getByRole('tab', { name: 'Edit' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tab', { name: 'HTTP and MCP rules' }).getAttribute('aria-selected')).toBe('true');

    await waitFor(() => expect(document.activeElement?.textContent).toContain('#2 rule-drafted'), WAIT);
    const review = screen.getByRole('region', { name: 'GET /billing/{id}' });
    const position = within(review).getByText('Position in the saved draft').nextElementSibling;
    expect(position?.textContent).toContain('rule #2 (position 1), id rule-drafted');
    expect(await within(review).findByText('✓ The suggested rule decides', undefined, WAIT)).toBeTruthy();
    expect(
      await within(review).findByText(/The analyzer reports nothing about the suggested rule/, undefined, WAIT),
    ).toBeTruthy();
    const [simulation] = gateway.requests('POST', '/v1/admin/policy/simulations');
    expect(JSON.parse(simulation.body ?? '{}')).toMatchObject({
      base_etag: LIVE_ETAG,
      candidate: { source: 'draft', draft_id: NEW_DRAFT_ID, draft_etag: draftEtag(NEW_DRAFT_ID, 1) },
      cases: [
        {
          kind: 'http',
          request: { method: 'GET', path: '/billing/example' },
          principal: { roles: ['support'], issuer: 'https://idp.example.test', auth_method: 'bearer_token' },
        },
      ],
    });
    const [analysis] = gateway.requests('POST', '/v1/admin/policy/analyses');
    expect(JSON.parse(analysis.body ?? '{}').candidate).toEqual({
      source: 'draft',
      draft_id: NEW_DRAFT_ID,
      draft_etag: draftEtag(NEW_DRAFT_ID, 1),
    });
    // Nothing live changed and the suggestion is still open.
    expect(gateway.live.etag).toBe(LIVE_ETAG);
    expect(gateway.suggestion(BILLING).state).toBe('open');
    expect(gateway.requests('POST', `/v1/admin/suggestions/${BILLING}/accept`)).toHaveLength(0);
    expect(accessibilityProblems()).toEqual([]);
  });

  it('accepts the suggestion only by publishing its draft with the binding, after confirmation', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await reviewBilling();
    await screen.findByText('Valid: the gateway reports no diagnostics.', undefined, WAIT);

    const publish = screen.getByRole('button', { name: 'Publish draft' }) as HTMLButtonElement;
    await waitFor(() => expect(publish.disabled).toBe(false), WAIT);
    fireEvent.click(publish);
    const confirmation = screen.getByRole('group', { name: 'Publish this draft?' });
    expect(within(confirmation).getByText(/It also accepts suggestion sugg-billing-read at revision 1/)).toBeTruthy();
    const accept = within(confirmation).getByRole('radio', { name: /Accept suggestion sugg-billing-read/ });
    expect((accept as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(confirmation).getByRole('button', { name: 'Confirm publish' }));

    expect(await screen.findByText('Draft published and suggestion accepted', undefined, WAIT)).toBeTruthy();
    const [published] = gateway.requests('POST', `/v1/admin/policy/drafts/${NEW_DRAFT_ID}/publish`);
    expect(JSON.parse(published.body ?? '{}')).toEqual({ suggestion: { id: BILLING, revision: 1 } });
    expect(published.headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(gateway.suggestion(BILLING).state).toBe('accepted');
  });

  it('publishes without accepting when the operator chooses so, and explains a stale binding', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await reviewBilling();
    await screen.findByText('Valid: the gateway reports no diagnostics.', undefined, WAIT);
    // Dismissed elsewhere after it was drafted.
    gateway.suggestion(BILLING).state = 'dismissed';
    gateway.suggestion(BILLING).revision = 2;

    fireEvent.click(screen.getByRole('button', { name: 'Publish draft' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm publish' }));
    expect(await screen.findByText('Not published: the suggestion changed', undefined, WAIT)).toBeTruthy();
    expect(gateway.live.etag).toBe(LIVE_ETAG);

    fireEvent.click(screen.getByRole('button', { name: 'Publish draft' }));
    const confirmation = screen.getByRole('group', { name: 'Publish this draft?' });
    const stale = within(confirmation).getByRole('radio', { name: /Accept suggestion sugg-billing-read/ });
    expect((stale as HTMLInputElement).disabled).toBe(true);
    expect((within(confirmation).getByRole('radio', { name: /Accept no suggestion/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(confirmation).getByRole('button', { name: 'Confirm publish' }));

    expect(await screen.findByText('Draft published', undefined, WAIT)).toBeTruthy();
    const publications = gateway.requests('POST', `/v1/admin/policy/drafts/${NEW_DRAFT_ID}/publish`);
    expect(publications).toHaveLength(2);
    expect(publications[1].body).toBeNull();
  });

  it('keeps a moved suggestion, 412, 428 and 503 apart, writing and retrying nothing', async () => {
    const cases: Array<{ response: Response; expected: string; liveReads?: number }> = [
      {
        response: jsonResponse(409, {
          error: 'suggestion is not at the expected revision',
          reason: 'suggestion_revision_mismatch',
          suggestion: { ...billingSuggestion(), state: 'dismissed', revision: 2 },
        }),
        expected: 'The suggestion changed',
      },
      { response: refusal(412, 'policy_etag_mismatch'), expected: 'The live policy changed', liveReads: 2 },
      { response: jsonResponse(428, { error: 'If-Match is required' }), expected: 'Precondition missing' },
      { response: refusal(503, 'policy_drafts_unavailable'), expected: 'No new draft as of now' },
    ];
    for (const entry of cases) {
      const gateway = fakeGateway();
      gateway.draftAnswer = entry.response;
      renderStudio(gateway);
      const row = await openSuggestions(BILLING);
      const draftsRead = gateway.requests('GET', '/v1/admin/policy/drafts').length;

      fireEvent.click(within(row).getByRole('button', { name: 'Review in draft' }));

      expect(await within(row).findByText(entry.expected, undefined, WAIT)).toBeTruthy();
      expect(gateway.requests('POST', `/v1/admin/suggestions/${BILLING}/draft`)).toHaveLength(1);
      expect(gateway.drafts.has(NEW_DRAFT_ID)).toBe(false);
      if (entry.liveReads !== undefined) {
        expect(gateway.requests('GET', '/v1/admin/policy')).toHaveLength(entry.liveReads);
      }
      if (entry.expected === 'The suggestion changed') {
        expect(within(row).getByText('Stale: changed since listed')).toBeTruthy();
        expect(within(row).getByText('Superseded: dismissed')).toBeTruthy();
      }
      if (entry.expected === 'No new draft as of now') {
        expect(within(row).getByText(/The gateway answered 503/)).toBeTruthy();
        expect(gateway.requests('GET', '/v1/admin/policy/drafts').length).toBeGreaterThan(draftsRead);
      }
      cleanup();
      vi.unstubAllGlobals();
    }
  });

  it('after a lost answer reads the drafts again and never sends the request again', async () => {
    const gateway = fakeGateway();
    gateway.loseDraftAnswer = true;
    renderStudio(gateway);
    const row = await openSuggestions(BILLING);

    fireEvent.click(within(row).getByRole('button', { name: 'Review in draft' }));

    expect(await within(row).findByText('A new draft appeared', undefined, WAIT)).toBeTruthy();
    expect(within(row).getByText(/did not confirm the request/)).toBeTruthy();
    expect(gateway.requests('POST', `/v1/admin/suggestions/${BILLING}/draft`)).toHaveLength(1);
    fireEvent.click(within(row).getByRole('button', { name: `Open draft ${NEW_DRAFT_ID}` }));
    await screen.findByText(NEW_DRAFT_ID, { selector: '.policy-studio-revisions code' }, WAIT);
    expect(gateway.requests('POST', `/v1/admin/suggestions/${BILLING}/draft`)).toHaveLength(1);
  });

  it('marks a suggestion whose rule is already live as superseded', async () => {
    const gateway = fakeGateway();
    gateway.draftAnswer = jsonResponse(409, {
      error: 'the candidate already holds the rule this suggestion proposes',
      reason: 'suggestion_rule_already_present',
    });
    renderStudio(gateway);
    const row = await openSuggestions(BILLING);

    fireEvent.click(within(row).getByRole('button', { name: 'Review in draft' }));

    expect(await within(row).findByText('Superseded: rule already live', undefined, WAIT)).toBeTruthy();
    expect(within(row).getByText('Rule already live')).toBeTruthy();
    expect(
      (within(row).getByRole('button', { name: 'Review in draft' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('dismisses at the revision read after confirmation, and checks a lost dismissal by reading', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    const row = await openSuggestions(EXPORTS);

    const dismiss = within(row).getByRole('button', { name: 'Dismiss' });
    fireEvent.click(dismiss);
    const confirmation = within(row).getByRole('group', { name: 'Dismiss this suggestion?' });
    await waitFor(() =>
      expect(document.activeElement).toBe(within(confirmation).getByRole('button', { name: 'Confirm dismiss' })),
    );
    fireEvent.keyDown(confirmation, { key: 'Escape' });
    await waitFor(() => expect(document.activeElement).toBe(dismiss));
    expect(gateway.requests('POST', `/v1/admin/suggestions/${EXPORTS}/dismiss`)).toHaveLength(0);

    gateway.loseDismissAnswer = true;
    fireEvent.click(dismiss);
    fireEvent.click(within(row).getByRole('button', { name: 'Confirm dismiss' }));

    expect(await within(row).findByText('Suggestion dismissed', undefined, WAIT)).toBeTruthy();
    expect(within(row).getByText(/did not confirm the dismissal, so it was read again/)).toBeTruthy();
    const [sent] = gateway.requests('POST', `/v1/admin/suggestions/${EXPORTS}/dismiss`);
    expect(sent.headers.get('If-Match')).toBe('"1"');
    expect(gateway.requests('POST', `/v1/admin/suggestions/${EXPORTS}/dismiss`)).toHaveLength(1);
    expect(within(row).getByText('Superseded: dismissed')).toBeTruthy();
  });

  it('gates every action on the permissions the gateway reports', async () => {
    const reader = fakeGateway({ permissions: [READ, SUGGESTIONS_READ] });
    renderStudio(reader);
    const row = await openSuggestions(BILLING, false);
    await screen.findByText('You have no policy drafts. Create one from the live policy to start editing.', undefined, WAIT);
    expect((within(row).getByRole('button', { name: 'Review in draft' }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(row).getByText('Review in draft needs admin:policy:write, as every draft write does.')).toBeTruthy();
    expect((within(row).getByRole('button', { name: 'Dismiss' }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(row).getByText('Dismissing needs admin:suggestions:write.')).toBeTruthy();
    cleanup();
    vi.unstubAllGlobals();

    const writer = fakeGateway({ permissions: [READ, WRITE] });
    renderStudio(writer);
    fireEvent.click(await screen.findByRole('tab', { name: 'Suggestions' }, WAIT));
    expect(await screen.findByText('Listing suggestions needs admin:suggestions:read.', undefined, WAIT)).toBeTruthy();
    expect(writer.requests('GET', '/v1/admin/suggestions')).toHaveLength(0);
  });
});

type LoggedRequest = {
  method: string;
  path: string;
  search: string;
  headers: Headers;
  body: string | null;
};

type DraftRecord = {
  revision: number;
  state: 'open' | 'published';
  base_etag: string;
  published_etag: string | null;
  policy: Record<string, unknown>;
};

type SuggestionRecord = ReturnType<typeof billingSuggestion>;

function fakeGateway({ permissions = ALL }: { permissions?: string[] } = {}) {
  const gateway = {
    live: { policy: livePolicy() as Record<string, unknown>, etag: LIVE_ETAG },
    liveRevision: 1,
    drafts: new Map<string, DraftRecord>(),
    suggestions: [billingSuggestion(), signalSuggestion(), dismissedSuggestion()] as SuggestionRecord[],
    draftAnswer: null as Response | null,
    loseDraftAnswer: false,
    loseDismissAnswer: false,
    log: [] as LoggedRequest[],
    requests(method: string, path: string) {
      return gateway.log.filter((request) => request.method === method && request.path === path);
    },
    suggestion(id: string): SuggestionRecord {
      const found = gateway.suggestions.find((entry) => entry.id === id);
      if (!found) throw new Error(`no suggestion ${id}`);
      return found;
    },
    fetch: vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? init.body : null;
      const headers = new Headers(init?.headers);
      gateway.log.push({ method, path: url.pathname, search: url.search, headers, body });
      try {
        return Promise.resolve(gateway.answer(method, url, headers, body));
      } catch (error) {
        return Promise.reject(error);
      }
    }),
    answer(method: string, url: URL, headers: Headers, body: string | null): Response {
      const path = url.pathname;
      if (path === '/v1/admin/capabilities') return jsonResponse(200, { permissions });
      if (path === '/v1/admin/policy' && method === 'GET') {
        return jsonResponse(200, gateway.live.policy, { ETag: gateway.live.etag });
      }
      if (path === '/v1/admin/policy/validate') return jsonResponse(200, validInspection());
      if (path === '/v1/admin/policy/drafts' && method === 'GET') {
        return jsonResponse(200, {
          drafts: [...gateway.drafts.entries()].map(([id, record]) => {
            const { policy: _policy, ...summary } = draftView(id, record);
            return summary;
          }),
          limits: { ttl_seconds: 86400, max_drafts_per_owner: 8, max_drafts: 128, max_candidate_bytes: 1048576 },
        });
      }
      if (path === '/v1/admin/suggestions' && method === 'GET') {
        const state = url.searchParams.get('state');
        return jsonResponse(200, {
          suggestions: gateway.suggestions.filter((entry) => state === null || entry.state === state),
          next_cursor: null,
        });
      }
      const suggestionRoute = /^\/v1\/admin\/suggestions\/([^/]+)\/(draft|dismiss)$/.exec(path);
      if (suggestionRoute && method === 'POST') {
        const record = gateway.suggestion(suggestionRoute[1]);
        return suggestionRoute[2] === 'draft'
          ? gateway.openInDraft(record, headers)
          : gateway.dismiss(record, headers);
      }
      if (path === '/v1/admin/policy/simulations') return jsonResponse(200, simulationResult(body ?? '{}', gateway));
      if (path === '/v1/admin/policy/analyses') return jsonResponse(200, analysisResult(body ?? '{}'));
      const draftRoute = /^\/v1\/admin\/policy\/drafts\/(pd_[0-9a-f]{32})(\/publish)?$/.exec(path);
      const record = draftRoute ? gateway.drafts.get(draftRoute[1]) : undefined;
      if (!draftRoute || !record) return refusal(404, 'policy_draft_not_found');
      const id = draftRoute[1];
      if (draftRoute[2] && method === 'POST') return gateway.publish(id, record, headers, body);
      if (method === 'GET') return draftResponse(200, id, record);
      return jsonResponse(405, { error: 'unexpected' });
    },
    openInDraft(record: SuggestionRecord, headers: Headers): Response {
      if (gateway.draftAnswer !== null) return gateway.draftAnswer;
      if (headers.get('If-Match') !== gateway.live.etag) return refusal(412, 'policy_etag_mismatch');
      if (record.state !== 'open' || headers.get('X-GreenGateway-Suggestion-Revision') !== String(record.revision)) {
        return jsonResponse(409, { error: 'moved', reason: 'suggestion_revision_mismatch', suggestion: record });
      }
      const rule = { ...record.proposed_rule, id: 'rule-drafted', action: record.proposed_rule.action === 'deny' ? 'shadow' : record.proposed_rule.action };
      const policy = { ...gateway.live.policy, rules: [...(gateway.live.policy.rules as unknown[]), rule] };
      const draft: DraftRecord = { revision: 1, state: 'open', base_etag: gateway.live.etag, published_etag: null, policy };
      gateway.drafts.set(NEW_DRAFT_ID, draft);
      if (gateway.loseDraftAnswer) throw new TypeError('Failed to fetch');
      return jsonResponse(
        201,
        { draft: draftView(NEW_DRAFT_ID, draft), suggestion: record, rule, position: policy.rules.length - 1 },
        { ETag: draftEtag(NEW_DRAFT_ID, 1) },
      );
    },
    dismiss(record: SuggestionRecord, headers: Headers): Response {
      if (record.state !== 'open' || headers.get('If-Match') !== `"${record.revision}"`) {
        return jsonResponse(409, { error: 'moved', reason: 'suggestion_not_open', suggestion: record });
      }
      record.state = 'dismissed';
      record.revision += 1;
      if (gateway.loseDismissAnswer) throw new TypeError('Failed to fetch');
      return jsonResponse(200, record);
    },
    publish(id: string, record: DraftRecord, headers: Headers, body: string | null): Response {
      if (headers.get('X-GreenGateway-Policy-Draft-ETag') !== draftEtag(id, record.revision)) {
        return refusal(412, 'policy_draft_etag_mismatch');
      }
      if (headers.get('If-Match') !== gateway.live.etag) return refusal(412, 'policy_etag_mismatch');
      const binding = body === null ? null : (JSON.parse(body) as { suggestion: { id: string; revision: number } }).suggestion;
      const bound = binding === null ? null : gateway.suggestion(binding.id);
      if (bound !== null && (bound.state !== 'open' || bound.revision !== binding?.revision)) {
        return jsonResponse(409, { error: 'stale', reason: 'suggestion_stale', suggestion: bound });
      }
      gateway.liveRevision += 1;
      gateway.live = { policy: record.policy, etag: `"sha256:live-${gateway.liveRevision}"` };
      record.state = 'published';
      record.published_etag = gateway.live.etag;
      if (bound !== null) {
        bound.state = 'accepted';
        bound.revision += 1;
      }
      return jsonResponse(200, gateway.live.policy, { ETag: gateway.live.etag });
    },
  };
  return gateway;
}

function livePolicy() {
  return {
    schema_version: '1.0.0',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: { support: { permissions: ['billing:read'] } },
    routes: [],
    rules: [
      {
        id: 'allow-health',
        methods: ['GET'],
        path: '/health',
        principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
        action: 'allow',
      },
    ],
  };
}

function billingSuggestion() {
  return {
    id: BILLING,
    suggestion_type: 'baseline_allow',
    method: 'GET',
    path_pattern: '/billing/{id}',
    principal_key: 'role:support',
    rationale: 'Role support called GET /billing/{id} 12 times in the last 168 hours.',
    evidence: {
      source: 'audit_sqlite',
      lookback_window_hours: 168,
      from: '2026-10-25T10:00:00Z',
      to: '2026-11-01T10:00:00Z',
      observation_count: 12,
      error_count: 0,
      audit_scan_truncated: false,
    } as Record<string, unknown>,
    proposed_rule: {
      methods: ['GET'],
      path: '/billing/{id}',
      dispatch: { kind: 'contextless' },
      principal: {
        roles: ['support'],
        issuers: ['https://idp.example.test'],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'allow',
    },
    state: 'open',
    created_at: '2026-11-01T10:00:00Z',
    updated_at: '2026-11-01T10:00:00Z',
    transitioned_at: null as string | null,
    transitioned_by: null as string | null,
    revision: 1,
    source_signal_id: null as string | null,
  };
}

function signalSuggestion(): SuggestionRecord {
  return {
    ...billingSuggestion(),
    id: EXPORTS,
    suggestion_type: 'signal_shadow_error_rate_spike',
    method: 'GET',
    path_pattern: '/exports/{id}',
    rationale: 'Signal-derived shadow candidate: open signal sig-7 (error_rate_spike) targets GET /exports/{id}.',
    evidence: {
      source: 'discovery_signal',
      source_signal_id: 'sig-7',
      source_signal_type: 'error_rate_spike',
      source_signal_explanation: 'The error rate of GET /exports/{id} rose sharply.',
      source_signal_evidence: { error_rate: 0.4 },
      mapped_action: 'shadow',
    },
    proposed_rule: {
      ...billingSuggestion().proposed_rule,
      path: '/exports/{id}',
      principal: { roles: [], issuers: [], auth_methods: [], principal_ids: [] },
      action: 'shadow',
    },
    source_signal_id: 'sig-7',
  };
}

function dismissedSuggestion(): SuggestionRecord {
  return {
    ...billingSuggestion(),
    id: DISMISSED,
    path_pattern: '/reports',
    proposed_rule: { ...billingSuggestion().proposed_rule, path: '/reports' },
    state: 'dismissed',
    revision: 2,
    transitioned_at: '2026-11-02T09:00:00Z',
    transitioned_by: 'alice',
    evidence: {},
  };
}

function simulationResult(body: string, gateway: ReturnType<typeof fakeGateway>) {
  const request = JSON.parse(body) as { candidate: { draft_id: string }; cases: Array<{ id: string; kind: string }> };
  const draft = gateway.drafts.get(request.candidate.draft_id);
  const position = Array.isArray(draft?.policy.rules) ? draft.policy.rules.length - 1 : 0;
  const counts = { would_forward: 1, would_block: 0, unknown: 0, shadowed: 0, rate_override: 0, no_rate_override: 0, rate_unknown: 0, changed_from_base: 1 };
  const decision = (overrides: Record<string, unknown>) => ({
    lane: 'http',
    complete: true,
    reason: 'matched_rule',
    logical: 'allow',
    enforcement: 'not_applicable',
    effective_action: 'would_forward',
    ...overrides,
  });
  return {
    schema_version: 'policy-simulation-results.v1',
    mode: 'synthetic',
    request_digest: 'sha256:request',
    base: { source: 'active', etag: LIVE_ETAG },
    candidate: { source: 'draft', etag: '"sha256:candidate"' },
    trace: { level: 'matched', max_stages: 4096, stages_truncated: false },
    projections: ['as_authored', 'enforce_all_shadow'],
    not_evaluated: ['authentication', 'upstream'],
    summary: { cases: 1, projections: { as_authored: counts, enforce_all_shadow: counts } },
    cases: request.cases.map((entry, index) => ({
      id: entry.id,
      pointer: `/cases/${index}`,
      kind: entry.kind,
      results: ['as_authored', 'enforce_all_shadow'].map((projection) => ({
        projection,
        base: decision({ logical: 'deny', effective_action: 'would_block', reason: 'default_deny', matched: null }),
        changed: true,
        candidate: decision({ matched: { kind: 'rule', position, id: 'rule-drafted', action: 'allow' } }),
      })),
    })),
  };
}

function analysisResult(body: string) {
  const request = JSON.parse(body) as { candidate: Record<string, unknown> };
  return {
    schema_version: 'policy-analysis-results.v1',
    mode: 'structural',
    request_digest: 'sha256:analysis',
    analyzer: { version: 'gg-policy-analyzer-v1' },
    base: { source: 'active', etag: LIVE_ETAG },
    analyzed: { source: 'draft', etag: '"sha256:candidate"', draft_id: request.candidate.draft_id, draft_revision: 1 },
    complete: true,
    limitations: [],
    summary: { findings: 0 },
    findings: [],
  };
}

function draftView(id: string, record: DraftRecord) {
  return {
    draft_id: id,
    revision: record.revision,
    state: record.state,
    base_etag: record.base_etag,
    candidate_etag: `"sha256:candidate-${record.revision}"`,
    published_etag: record.published_etag,
    created_at: '2026-11-05T10:00:00Z',
    updated_at: '2026-11-05T10:00:00Z',
    expires_at: '2026-11-06T10:00:00Z',
    policy: record.policy,
  };
}

function draftResponse(status: number, id: string, record: DraftRecord): Response {
  return jsonResponse(status, draftView(id, record), { ETag: draftEtag(id, record.revision) });
}

function draftEtag(id: string, revision: number): string {
  return `"sha256:${id.slice(3, 7)}-r${revision}"`;
}

function validInspection() {
  return {
    valid: true,
    schema_version: '1.0.0',
    diagnostics: [],
    source_digest: 'sha256:source',
    semantic_digest: 'sha256:semantic',
    resource_snapshot: { schema_version: '1', digest: `sha256:${'0'.repeat(64)}`, complete: true },
  };
}

function refusal(status: number, reason: string): Response {
  return jsonResponse(status, { error: reason.replace(/_/g, ' '), reason });
}

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function renderStudio(gateway: ReturnType<typeof fakeGateway>) {
  vi.stubGlobal('fetch', gateway.fetch);
  render(
    <MemoryRouter initialEntries={['/policy/studio']}>
      <Routes>
        <Route path="/policy/studio" element={<PolicyStudioView />} />
      </Routes>
    </MemoryRouter>,
  );
}

function suggestionRow(id: string): HTMLElement {
  const title = id === BILLING ? 'GET /billing/{id}' : id === EXPORTS ? 'GET /exports/{id}' : 'GET /reports';
  return screen.getByRole('listitem', { name: title });
}

// Opens the Suggestions view and returns the row; with `ready`, once the
// live policy and the drafts are read and Review in draft is offered.
async function openSuggestions(id: string, ready = true): Promise<HTMLElement> {
  fireEvent.click(await screen.findByRole('tab', { name: 'Suggestions' }, WAIT));
  const title = id === BILLING ? 'GET /billing/{id}' : id === EXPORTS ? 'GET /exports/{id}' : 'GET /reports';
  const row = await screen.findByRole('listitem', { name: title }, WAIT);
  if (ready) {
    await waitFor(
      () =>
        expect(
          (within(row).getByRole('button', { name: 'Review in draft' }) as HTMLButtonElement).disabled,
        ).toBe(false),
      WAIT,
    );
  }
  return row;
}

async function reviewBilling() {
  const row = await openSuggestions(BILLING);
  fireEvent.click(within(row).getByRole('button', { name: 'Review in draft' }));
  await screen.findByText('Suggestion opened in a draft', undefined, WAIT);
}

// The checks the live-UI suite runs, over the rendered Studio: unique ids,
// a label for every control, a name for every button, references that
// resolve, and tab panels named by their tabs.
function accessibilityProblems(): string[] {
  const found: string[] = [];
  const counts = new Map<string, number>();
  for (const element of document.querySelectorAll<HTMLElement>('[id]')) {
    counts.set(element.id, (counts.get(element.id) ?? 0) + 1);
  }
  for (const [id, count] of counts) {
    if (count > 1) found.push(`duplicate id: ${id}`);
  }
  for (const control of document.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
    'input:not([type="hidden"]), select, textarea',
  )) {
    const labelled =
      (control.labels?.length ?? 0) > 0 ||
      Boolean(control.getAttribute('aria-label')?.trim()) ||
      Boolean(control.getAttribute('aria-labelledby')?.trim());
    if (!labelled) found.push(`unlabelled control: ${control.id || control.tagName.toLowerCase()}`);
  }
  for (const button of document.querySelectorAll('button')) {
    const name = button.getAttribute('aria-label')?.trim() || button.textContent?.trim();
    if (!name) found.push('button without an accessible name');
  }
  for (const element of document.querySelectorAll<HTMLElement>('[aria-describedby], [aria-labelledby], [aria-controls]')) {
    for (const attribute of ['aria-describedby', 'aria-labelledby', 'aria-controls']) {
      for (const id of (element.getAttribute(attribute) ?? '').split(/\s+/).filter(Boolean)) {
        if (document.getElementById(id) === null) found.push(`${attribute} names a missing id: ${id}`);
      }
    }
  }
  return found;
}
