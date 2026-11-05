import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import { runPolicyAnalysis } from './policyAnalyses';
import { publishPolicyDraft } from './policyDrafts';
import { runPolicySimulation } from './policySimulations';
import {
  SuggestionConflictError,
  dismissSuggestion,
  fetchSuggestions,
  locateSuggestion,
  openSuggestionInDraft,
} from './suggestions';

const SUGGESTION_ID = '5f0c2a8e-9d1b-4c7e-8a3f-2b6d4e1c9a70';
const DRAFT_ID = `pd_${'c'.repeat(32)}`;
const DRAFT_ETAG = '"sha256:draft-r1"';
const LIVE_ETAG = '"sha256:live-1"';

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('suggestions client', () => {
  it('lists suggestions with their state filter and projects the proposed rule', async () => {
    const fetch = stubFetch(() =>
      jsonResponse(200, { suggestions: [suggestion()], next_cursor: 'next-page' }),
    );

    const page = await fetchSuggestions({ state: 'open', cursor: 'cursor-1' });

    const [url] = fetch.mock.calls[0];
    expect(String(url)).toBe('/v1/admin/suggestions?state=open&limit=50&cursor=cursor-1');
    expect(page.next_cursor).toBe('next-page');
    expect(page.suggestions[0]).toMatchObject({
      id: SUGGESTION_ID,
      state: 'open',
      revision: 1,
      source_signal_id: null,
      proposed_rule: {
        id: null,
        methods: ['GET'],
        path: '/billing/{id}',
        action: 'allow',
        principal: { roles: ['support'], issuers: ['https://idp.example.test'] },
        dispatch: { kind: 'contextless', upstream_origin: null, route_id: null },
      },
    });
  });

  it('refuses a listing it cannot read, and an identifier that is not a path segment', async () => {
    stubFetch(() => jsonResponse(200, { suggestions: [{ ...suggestion(), state: 'pending' }] }));
    await expect(fetchSuggestions({ state: null })).rejects.toThrow('Invalid suggestion list response.');

    stubFetch(() => jsonResponse(200, {}));
    await expect(dismissSuggestion('../policy', 1)).rejects.toThrow('Invalid suggestion identifier.');
  });

  it('opens a suggestion in a new draft bound to the live ETag and the revision read', async () => {
    const fetch = stubFetch(() =>
      jsonResponse(
        201,
        {
          draft: draftView(),
          suggestion: suggestion(),
          rule: { ...suggestion().proposed_rule, id: 'rule-drafted' },
          position: 1,
        },
        { ETag: DRAFT_ETAG },
      ),
    );

    const opened = await openSuggestionInDraft({
      id: SUGGESTION_ID,
      revision: 1,
      policyEtag: LIVE_ETAG,
      target: null,
    });

    const [url, init] = fetch.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(String(url)).toBe(`/v1/admin/suggestions/${SUGGESTION_ID}/draft`);
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe('{}');
    expect(headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(headers.get('X-GreenGateway-Suggestion-Revision')).toBe('1');
    expect(headers.get('X-GreenGateway-Policy-Draft-ETag')).toBeNull();
    expect(opened.created).toBe(true);
    expect(opened.position).toBe(1);
    expect(opened.rule.id).toBe('rule-drafted');
    expect(opened.draft.etag).toBe(DRAFT_ETAG);
    expect(opened.draft.summary.draft_id).toBe(DRAFT_ID);
  });

  it('extends an open draft under its ETag', async () => {
    const fetch = stubFetch(() =>
      jsonResponse(
        200,
        { draft: draftView(), suggestion: suggestion(), rule: suggestion().proposed_rule, position: 3 },
        { ETag: DRAFT_ETAG },
      ),
    );

    const opened = await openSuggestionInDraft({
      id: SUGGESTION_ID,
      revision: 1,
      policyEtag: LIVE_ETAG,
      target: { draftId: DRAFT_ID, draftEtag: DRAFT_ETAG },
    });

    const [, init] = fetch.mock.calls[0];
    expect(JSON.parse(String(init?.body))).toEqual({ draft_id: DRAFT_ID });
    expect(new Headers(init?.headers).get('X-GreenGateway-Policy-Draft-ETag')).toBe(DRAFT_ETAG);
    expect(opened.created).toBe(false);
  });

  it('reports a moved suggestion with the row the gateway holds now', async () => {
    stubFetch(() =>
      jsonResponse(409, {
        error: 'suggestion is not at the expected revision',
        reason: 'suggestion_revision_mismatch',
        suggestion: { ...suggestion(), revision: 2 },
      }),
    );

    const failure = await openSuggestionInDraft({
      id: SUGGESTION_ID,
      revision: 1,
      policyEtag: LIVE_ETAG,
      target: null,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SuggestionConflictError);
    const conflict = failure as SuggestionConflictError;
    expect(conflict.status).toBe(409);
    expect(conflict.code).toBe('suggestion_revision_mismatch');
    expect(conflict.current?.revision).toBe(2);
  });

  it('keeps 412, 428 and 503 refusals apart', async () => {
    for (const [status, reason] of [
      [412, 'policy_etag_mismatch'],
      [428, 'precondition_required'],
      [503, 'policy_drafts_unavailable'],
    ] as const) {
      stubFetch(() => jsonResponse(status, { error: reason, reason }));
      const failure = await openSuggestionInDraft({
        id: SUGGESTION_ID,
        revision: 1,
        policyEtag: LIVE_ETAG,
        target: null,
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(AdminApiError);
      expect(failure).not.toBeInstanceOf(SuggestionConflictError);
      expect((failure as AdminApiError).status).toBe(status);
      expect((failure as AdminApiError).code).toBe(reason);
    }
  });

  it('dismisses at the revision read, which If-Match names on this route', async () => {
    const fetch = stubFetch(() =>
      jsonResponse(200, { ...suggestion(), state: 'dismissed', revision: 2 }),
    );

    const dismissed = await dismissSuggestion(SUGGESTION_ID, 1);

    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toBe(`/v1/admin/suggestions/${SUGGESTION_ID}/dismiss`);
    expect(new Headers(init?.headers).get('If-Match')).toBe('"1"');
    expect(dismissed.state).toBe('dismissed');
  });

  it('locates one suggestion across pages, and says when it is gone', async () => {
    const other = { ...suggestion(), id: 'other-suggestion' };
    const fetch = stubFetch((url) =>
      url.includes('cursor=page-2')
        ? jsonResponse(200, { suggestions: [{ ...suggestion(), state: 'dismissed' }], next_cursor: null })
        : jsonResponse(200, { suggestions: [other], next_cursor: 'page-2' }),
    );

    const located = await locateSuggestion(SUGGESTION_ID);

    expect(located).toMatchObject({ kind: 'found', suggestion: { state: 'dismissed' } });
    expect(String(fetch.mock.calls[0][0])).toBe('/v1/admin/suggestions?limit=500');

    stubFetch(() => jsonResponse(200, { suggestions: [other], next_cursor: null }));
    expect(await locateSuggestion(SUGGESTION_ID)).toEqual({ kind: 'gone' });
  });

  it('binds a publication to the suggestion it accepts', async () => {
    const fetch = stubFetch(() => jsonResponse(200, { schema_version: '1.0.0', rules: [] }, { ETag: '"sha256:live-2"' }));

    await publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG, null, {
      id: SUGGESTION_ID,
      revision: 1,
    });

    const [, init] = fetch.mock.calls[0];
    expect(JSON.parse(String(init?.body))).toEqual({
      suggestion: { id: SUGGESTION_ID, revision: 1 },
    });
    await expect(
      publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG, null, { id: SUGGESTION_ID, revision: 0 }),
    ).rejects.toThrow('Invalid suggestion binding.');
  });

  it('simulates and analyzes a saved draft by its id and ETag', async () => {
    const fetch = stubFetch((url) =>
      url.endsWith('/policy/analyses')
        ? jsonResponse(200, analysisResult())
        : jsonResponse(422, { reason: 'policy_candidate_invalid', errors: ['invalid'] }),
    );
    const candidate = { kind: 'draft' as const, draftId: DRAFT_ID, draftEtag: DRAFT_ETAG };

    const analysis = await runPolicyAnalysis({ baseEtag: LIVE_ETAG, candidate });
    const simulation = await runPolicySimulation({
      baseEtag: LIVE_ETAG,
      candidate,
      trace: 'matched',
      projections: ['as_authored'],
      cases: [],
    });

    const analysisBody = JSON.parse(String(fetch.mock.calls[0][1]?.body));
    expect(analysisBody).toEqual({
      schema_version: 'policy-analysis.v1',
      base_etag: LIVE_ETAG,
      candidate: { source: 'draft', draft_id: DRAFT_ID, draft_etag: DRAFT_ETAG },
      format: 'json',
    });
    expect(JSON.parse(String(fetch.mock.calls[1][1]?.body)).candidate).toEqual({
      source: 'draft',
      draft_id: DRAFT_ID,
      draft_etag: DRAFT_ETAG,
    });
    expect(analysis).toMatchObject({
      kind: 'result',
      result: {
        complete: true,
        analyzer_version: 'gg-policy-analyzer-v1',
        analyzed: { source: 'draft', draft_id: DRAFT_ID, draft_revision: 2 },
        findings: [
          {
            code: 'rule_shadowed',
            element: { section: 'rules', position: 1, id: 'rule-drafted' },
            related: { section: 'rules', position: 0 },
            access_effect: 'narrowing',
          },
        ],
      },
    });
    expect(simulation).toMatchObject({ kind: 'refused', refusal: { reason: 'policy_candidate_invalid' } });
  });

  it('does not count an analysis, a suggestion draft or a dismissal as a live policy change', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    stubFetch((url) =>
      url.endsWith('/policy/analyses')
        ? jsonResponse(200, analysisResult())
        : url.endsWith('/dismiss')
          ? jsonResponse(200, { ...suggestion(), state: 'dismissed', revision: 2 })
          : jsonResponse(
              201,
              { draft: draftView(), suggestion: suggestion(), rule: suggestion().proposed_rule, position: 0 },
              { ETag: DRAFT_ETAG },
            ),
    );
    await runPolicyAnalysis({ baseEtag: LIVE_ETAG, candidate: { kind: 'active' } });
    await openSuggestionInDraft({ id: SUGGESTION_ID, revision: 1, policyEtag: LIVE_ETAG, target: null });
    await dismissSuggestion(SUGGESTION_ID, 1);
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });
});

function suggestion() {
  return {
    id: SUGGESTION_ID,
    suggestion_type: 'baseline_allow',
    method: 'GET',
    path_pattern: '/billing/{id}',
    principal_key: 'role:support',
    rationale: 'Role support called GET /billing/{id} 12 times in the last 168 hours.',
    evidence: { source: 'audit_sqlite', lookback_window_hours: 168 },
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
    transitioned_at: null,
    transitioned_by: null,
    revision: 1,
  };
}

function draftView() {
  return {
    draft_id: DRAFT_ID,
    revision: 1,
    state: 'open',
    base_etag: LIVE_ETAG,
    candidate_etag: '"sha256:candidate-1"',
    published_etag: null,
    created_at: '2026-11-01T10:00:00Z',
    updated_at: '2026-11-01T10:00:00Z',
    expires_at: '2026-11-02T10:00:00Z',
    policy: { schema_version: '1.0.0', default_action: 'deny', rules: [] },
  };
}

function analysisResult() {
  return {
    schema_version: 'policy-analysis-results.v1',
    mode: 'structural',
    request_digest: 'sha256:request',
    analyzer: { version: 'gg-policy-analyzer-v1' },
    base: { source: 'active', etag: LIVE_ETAG },
    analyzed: { source: 'draft', etag: '"sha256:candidate-1"', draft_id: DRAFT_ID, draft_revision: 2 },
    complete: true,
    limitations: [],
    summary: { findings: 1 },
    findings: [
      {
        code: 'rule_shadowed',
        fingerprint: 'sha256:fingerprint',
        severity: 'high',
        proof_basis: 'proven',
        element: { section: 'rules', pointer: '/rules/1', position: 1, id: 'rule-drafted' },
        related: { section: 'rules', pointer: '/rules/0', position: 0 },
        never_decides_in: ['http'],
        may_decide_in: ['mcp_alias'],
        rationale: 'An earlier, less restrictive rule matches every request this rule matches.',
        remediation: 'Move the rule before the rule that covers it.',
        details: {},
        patch: { access_effect: 'narrowing', edits: [] },
        limitations: [],
      },
    ],
  };
}

function stubFetch(answer: (url: string) => Response) {
  const fetch = vi.fn((input: RequestInfo | URL, _init?: RequestInit) =>
    Promise.resolve(answer(String(input))),
  );
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
