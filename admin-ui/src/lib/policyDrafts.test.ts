import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import {
  convertPolicySource,
  createPolicyDraft,
  deletePolicyDraft,
  fetchPolicyDraft,
  fetchPolicyDrafts,
  publishPolicyDraft,
  updatePolicyDraft,
  validatePolicySource,
} from './policyDrafts';

const DRAFT_ID = `pd_${'a'.repeat(32)}`;
const DRAFT_ETAG = '"sha256:draft-r1"';
const LIVE_ETAG = '"sha256:live-1"';
const SNAPSHOT_DIGEST = `sha256:${'0'.repeat(64)}`;

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('policy drafts client', () => {
  it('validates the exact candidate text and reads an invalid document as an answer', async () => {
    const source = '{"schema_version":"1.0.0","rules":[],"rules":[]}';
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(400, {
          valid: false,
          errors: ['/rules: duplicate member'],
          schema_version: '1.0.0',
          diagnostics: [
            diagnostic({ code: 'duplicate_member', pointer: '/rules' }),
          ],
          source_digest: 'sha256:source',
        }),
      ),
    );
    vi.stubGlobal('fetch', fetch);

    const inspection = await validatePolicySource(source);

    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toBe('/v1/admin/policy/validate');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(source);
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json');
    expect(inspection).toEqual({
      valid: false,
      errors: ['/rules: duplicate member'],
      schema_version: '1.0.0',
      diagnostics: [diagnostic({ code: 'duplicate_member', pointer: '/rules' })],
      source_digest: 'sha256:source',
      semantic_digest: null,
      resource_snapshot: null,
    });
  });

  it('reads risks and the resource snapshot the cross-resource checks used', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            valid: true,
            diagnostics: [
              diagnostic({
                code: 'default_action_allow',
                severity: 'risk',
                pointer: '/default_action',
                blocks: { simulation: false, tests: false, publication: false, evidence: false },
              }),
            ],
            resource_snapshot: {
              schema_version: '1',
              digest: SNAPSHOT_DIGEST,
              complete: true,
              components: { gateway_build: 'test' },
            },
          }),
        ),
      ),
    );

    const inspection = await validatePolicySource('{}');

    expect(inspection.diagnostics[0].severity).toBe('risk');
    expect(inspection.resource_snapshot).toEqual({
      digest: SNAPSHOT_DIGEST,
      complete: true,
      unavailable: [],
    });
  });

  it('never keeps a digest for an incomplete or malformed resource snapshot', async () => {
    for (const snapshot of [
      { digest: SNAPSHOT_DIGEST, complete: false, unavailable: ['tools'] },
      { digest: 'sha256:short', complete: true },
    ]) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() =>
          Promise.resolve(
            jsonResponse(200, { valid: true, diagnostics: [], resource_snapshot: snapshot }),
          ),
        ),
      );
      const inspection = await validatePolicySource('{}');
      expect(inspection.resource_snapshot?.digest).toBeNull();
    }
  });

  it('keeps only the documented diagnostic fields', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            valid: true,
            diagnostics: [
              {
                ...diagnostic({ severity: 'warning' }),
                element_id: 'rule-1',
                unexpected: 'UNEXPECTED_DIAGNOSTIC_CANARY',
              },
            ],
          }),
        ),
      ),
    );

    const inspection = await validatePolicySource('{}');

    expect(inspection.diagnostics).toEqual([
      { ...diagnostic({ severity: 'warning' }), element_id: 'rule-1' },
    ]);
    expect(JSON.stringify(inspection)).not.toContain('UNEXPECTED_DIAGNOSTIC_CANARY');
  });

  it('refuses a validation answer it cannot read instead of reporting the document valid', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(400, { valid: false, diagnostics: [{ code: 'x' }] }),
        ),
      ),
    );

    await expect(validatePolicySource('{}')).rejects.toBeInstanceOf(AdminApiError);
  });

  it('still fails validation on permission and server errors', async () => {
    for (const status of [401, 403, 500]) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.resolve(jsonResponse(status, { error: 'refused' }))),
      );
      const error = await validatePolicySource('{}').catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(AdminApiError);
      expect((error as AdminApiError).status).toBe(status);
    }
  });

  it('saves the candidate as its own bytes beside the draft precondition', async () => {
    const source = '{\n  "schema_version": "1.0.0",\n  "rules": []\n}';
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(200, draftBody({ revision: 2 }), { ETag: '"sha256:draft-r2"' }),
      ),
    );
    vi.stubGlobal('fetch', fetch);

    const saved = await updatePolicyDraft(DRAFT_ID, DRAFT_ETAG, {
      source,
      baseEtag: LIVE_ETAG,
    });

    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toBe(`/v1/admin/policy/drafts/${DRAFT_ID}`);
    expect(init?.method).toBe('PATCH');
    expect(new Headers(init?.headers).get('If-Match')).toBe(DRAFT_ETAG);
    expect(init?.body).toBe(
      `{"policy":${source},"base_etag":${JSON.stringify(LIVE_ETAG)}}`,
    );
    expect(saved.etag).toBe('"sha256:draft-r2"');
    expect(saved.summary.revision).toBe(2);
  });

  it('never splices text that is not one JSON object into a draft request', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);

    for (const source of [
      '{"schema_version":"1.0.0"},"base_etag":"\\"x\\""',
      '[]',
      'null',
      '{',
    ]) {
      await expect(
        updatePolicyDraft(DRAFT_ID, DRAFT_ETAG, { source }),
      ).rejects.toThrow('The policy candidate is not a JSON object.');
      await expect(createPolicyDraft(LIVE_ETAG, source)).rejects.toThrow(
        'The policy candidate is not a JSON object.',
      );
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it('creates a copy of the live policy pinned to the live ETag', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(201, draftBody(), { ETag: DRAFT_ETAG })),
    );
    vi.stubGlobal('fetch', fetch);

    const created = await createPolicyDraft(LIVE_ETAG);

    const init = fetch.mock.calls[0][1];
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe('{}');
    expect(new Headers(init?.headers).get('If-Match')).toBe(LIVE_ETAG);
    expect(created.summary.draft_id).toBe(DRAFT_ID);
  });

  it('refuses a draft identifier that is not one before building a URL', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);

    await expect(fetchPolicyDraft('../policy')).rejects.toThrow(
      'Invalid policy draft identifier.',
    );
    await expect(deletePolicyDraft('pd_ABC', DRAFT_ETAG)).rejects.toThrow(
      'Invalid policy draft identifier.',
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it('refuses a draft response without its ETag or with a malformed identifier', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(200, draftBody()))));
    await expect(fetchPolicyDraft(DRAFT_ID)).rejects.toThrow('Invalid policy draft response.');

    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, { drafts: [{ ...draftBody(), draft_id: 'other' }], limits: limits() }),
        ),
      ),
    );
    await expect(fetchPolicyDrafts()).rejects.toThrow('Invalid policy draft list response.');
  });

  it('publishes under both preconditions with an empty body and reads its warnings', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(
          200,
          { schema_version: '1.0.0', rules: [] },
          {
            ETag: '"sha256:live-2"',
            'X-GreenGateway-Policy-Draft-Warning': 'policy_draft_state_not_recorded',
            'X-GreenGateway-Policy-History-Warning': 'policy_history_append_failed',
          },
        ),
      ),
    );
    vi.stubGlobal('fetch', fetch);

    const published = await publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG);

    const [url, init] = fetch.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(String(url)).toBe(`/v1/admin/policy/drafts/${DRAFT_ID}/publish`);
    expect(init?.method).toBe('POST');
    expect(init?.body).toBeUndefined();
    expect(headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(headers.get('X-GreenGateway-Policy-Draft-ETag')).toBe(DRAFT_ETAG);
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(published).toMatchObject({
      etag: '"sha256:live-2"',
      draftStateRecorded: false,
      historyAppendWarning: true,
    });
    expect(headers.has('X-GreenGateway-Resource-Snapshot')).toBe(false);

    await publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG, SNAPSHOT_DIGEST);
    expect(
      new Headers(fetch.mock.calls[1][1]?.headers).get('X-GreenGateway-Resource-Snapshot'),
    ).toBe(SNAPSHOT_DIGEST);
  });

  it('keeps the stable refusal reason of a draft write', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(409, {
            error: 'the live policy changed after this draft was pinned',
            reason: 'policy_draft_base_stale',
            base_etag: LIVE_ETAG,
            policy_etag: '"sha256:live-2"',
          }),
        ),
      ),
    );

    const error = await publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG).catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(AdminApiError);
    expect((error as AdminApiError).code).toBe('policy_draft_base_stale');
  });

  it('carries the reasons a candidate was refused for', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(400, {
            valid: false,
            errors: ['/rules/0/id: id is required', 42, ''],
          }),
        ),
      ),
    );

    const error = await updatePolicyDraft(DRAFT_ID, DRAFT_ETAG, { source: '{}' }).catch(
      (caught: unknown) => caught,
    );

    expect((error as AdminApiError).validationErrors).toEqual([
      '/rules/0/id: id is required',
    ]);
  });

  it('signals a live policy change for a publication but not for draft edits', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input);
        if (init?.method === 'DELETE') {
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        if (path.endsWith('/publish')) {
          return Promise.resolve(
            jsonResponse(200, { schema_version: '1.0.0' }, { ETag: '"sha256:live-2"' }),
          );
        }
        if (path.endsWith('/convert')) {
          return Promise.resolve(
            jsonResponse(200, {
              converted: true,
              diagnostics: [],
              changes: [],
              policy: { schema_version: '1.0.0' },
            }),
          );
        }
        return Promise.resolve(jsonResponse(200, draftBody(), { ETag: DRAFT_ETAG }));
      }),
    );

    try {
      await createPolicyDraft(LIVE_ETAG);
      await updatePolicyDraft(DRAFT_ID, DRAFT_ETAG, { source: '{}' });
      await deletePolicyDraft(DRAFT_ID, DRAFT_ETAG);
      await convertPolicySource('{"schema_version":"0.1.0"}');
      expect(events.filter((event) => event.kind === 'policy')).toHaveLength(0);

      await publishPolicyDraft(DRAFT_ID, DRAFT_ETAG, LIVE_ETAG);
      expect(events.filter((event) => event.kind === 'policy')).toHaveLength(1);
    } finally {
      unsubscribe();
    }
  });

  it('reads a refused conversion as an answer with its diagnostics', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(400, {
            converted: false,
            errors: ['already v1'],
            diagnostics: [diagnostic({ code: 'conversion_requires_v0' })],
            changes: [],
          }),
        ),
      ),
    );

    const conversion = await convertPolicySource('{"schema_version":"1.0.0"}');

    expect(conversion.converted).toBe(false);
    expect(conversion.policy).toBeNull();
    expect(conversion.diagnostics[0].code).toBe('conversion_requires_v0');
  });
});

function diagnostic(overrides: Record<string, unknown> = {}) {
  return {
    code: 'rule_id_missing',
    severity: 'error',
    pointer: '/rules/0',
    message: 'The rule has no id.',
    remediation: 'Give the rule an id.',
    blocks: { simulation: true, tests: true, publication: true, evidence: true },
    ...overrides,
  };
}

function draftBody(overrides: Record<string, unknown> = {}) {
  return {
    draft_id: DRAFT_ID,
    revision: 1,
    state: 'open',
    base_etag: LIVE_ETAG,
    candidate_etag: '"sha256:candidate-1"',
    published_etag: null,
    created_at: '2026-10-28T10:00:00Z',
    updated_at: '2026-10-28T10:00:00Z',
    expires_at: '2026-10-29T10:00:00Z',
    policy: { schema_version: '1.0.0', rules: [] },
    ...overrides,
  };
}

function limits() {
  return {
    ttl_seconds: 86400,
    max_drafts_per_owner: 8,
    max_drafts: 128,
    max_candidate_bytes: 1048576,
  };
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
