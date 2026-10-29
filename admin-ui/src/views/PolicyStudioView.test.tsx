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
import { PolicyStudioView } from './PolicyStudioView';

const DRAFT_ID = `pd_${'a'.repeat(32)}`;
const LIVE_ETAG = '"sha256:live-1"';
const READ = 'admin:policy:read';
const WRITE = 'admin:policy:write';
const WAIT = { timeout: 4000 };
const SNAPSHOT_DIGEST = `sha256:${'0'.repeat(64)}`;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearMemoryToken();
});

describe('PolicyStudioView', () => {
  it('edits a rule in a structured editor and validates the exact text as it is typed', async () => {
    const gateway = fakeGateway();
    gateway.validate = (source) => {
      const document = JSON.parse(source) as { rules: Array<{ path: string }> };
      return document.rules[0].path.includes(' ')
        ? jsonResponse(400, {
            valid: false,
            errors: ['/rules/0/path: invalid path'],
            schema_version: '1.0.0',
            diagnostics: [
              diagnostic({
                code: 'rule_path_invalid',
                pointer: '/rules/0/path',
                element_id: 'allow-billing',
                message: 'The path pattern is not valid.',
                remediation: 'Write an absolute path pattern without spaces.',
              }),
            ],
          })
        : jsonResponse(200, validInspection());
    };
    renderStudio(gateway);
    await openDraft();

    fireEvent.click(screen.getByRole('tab', { name: /HTTP and MCP rules/ }));
    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/billing/{id} x' },
    });

    // Beside the field, and in the diagnostics list.
    expect(
      await screen.findAllByText('The path pattern is not valid.', undefined, WAIT),
    ).toHaveLength(2);
    const sent = gateway.requests('POST', '/v1/admin/policy/validate').at(-1);
    expect(sent?.body).toBe(
      JSON.stringify(
        {
          ...draftPolicy(),
          rules: [{ ...draftPolicy().rules[0], path: '/billing/{id} x' }],
        },
        null,
        2,
      ),
    );
    const path = screen.getByLabelText('Path pattern');
    expect(path.getAttribute('aria-invalid')).toBe('true');
    expect(screen.getByText('Invalid: 1 error.')).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'HTTP and MCP rules, 1 problem' })).toBeTruthy();
    expect(screen.getAllByText('Write an absolute path pattern without spaces.').length).toBe(2);

    fireEvent.click(screen.getByRole('tab', { name: /Overview/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Show in editor: /rules/0/path' }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText('Path pattern')));
    expect(screen.getByText('Unsaved edits', { selector: '.result-count' })).toBeTruthy();
  });

  it('keeps only the validation answer for the text still on screen', async () => {
    const gateway = fakeGateway();
    const pending: Array<(response: Response) => void> = [];
    renderStudio(gateway);
    await openDraft();
    await screen.findByText('Valid: the gateway reports no diagnostics.', undefined, WAIT);
    gateway.validate = () =>
      new Promise<Response>((resolve) => {
        pending.push(resolve);
      });

    fireEvent.click(screen.getByRole('tab', { name: /Overview/ }));
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'first' } });
    await waitFor(() => expect(pending).toHaveLength(1), WAIT);
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'second' } });
    await waitFor(() => expect(pending).toHaveLength(2), WAIT);

    pending[1](jsonResponse(200, validInspection()));
    pending[0](
      jsonResponse(400, {
        valid: false,
        diagnostics: [diagnostic({ pointer: '/id', message: 'Stale answer.' })],
      }),
    );

    expect(
      await screen.findByText('Valid: the gateway reports no diagnostics.', undefined, WAIT),
    ).toBeTruthy();
    expect(screen.queryByText('Stale answer.')).toBeNull();
  });

  it('saves under the draft ETag and offers explicit choices when the draft changed elsewhere', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();

    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'renamed' } });
    gateway.bumpDraft(DRAFT_ID);
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));

    expect(await screen.findByText('The draft changed elsewhere', undefined, WAIT)).toBeTruthy();
    expect((screen.getByLabelText('Policy id') as HTMLInputElement).value).toBe('renamed');
    const firstPatch = gateway.requests('PATCH', `/v1/admin/policy/drafts/${DRAFT_ID}`)[0];
    expect(firstPatch.headers.get('If-Match')).toBe(draftEtag(DRAFT_ID, 1));

    fireEvent.click(screen.getByRole('button', { name: 'Keep my edits and save over it' }));

    expect(await screen.findByText('Revision 3 saved. The live policy is unchanged.', undefined, WAIT)).toBeTruthy();
    const patches = gateway.requests('PATCH', `/v1/admin/policy/drafts/${DRAFT_ID}`);
    expect(patches).toHaveLength(2);
    expect(patches[1].headers.get('If-Match')).toBe(draftEtag(DRAFT_ID, 2));
    expect(JSON.parse(patches[1].body ?? '{}')).toMatchObject({ policy: { id: 'renamed' } });
    expect(gateway.live.etag).toBe(LIVE_ETAG);
  });

  it('publishes only a saved, valid draft, after confirmation, bound to the reviewed revisions', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();

    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'next' } });
    const publish = screen.getByRole('button', { name: 'Publish draft' }) as HTMLButtonElement;
    expect(publish.disabled).toBe(true);
    expect(
      screen.getByText('Save your edits first: only the saved draft is published.'),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    await screen.findByText('Revision 2 saved. The live policy is unchanged.', undefined, WAIT);
    await screen.findByText('Valid: the gateway reports no diagnostics.', undefined, WAIT);
    await waitFor(() => expect(publish.disabled).toBe(false), WAIT);

    fireEvent.click(publish);
    const confirmation = screen.getByRole('group', { name: 'Publish this draft?' });
    expect(within(confirmation).getByText(/Changed sections: policy id\./)).toBeTruthy();
    fireEvent.keyDown(confirmation, { key: 'Escape' });
    await waitFor(() => expect(document.activeElement).toBe(publish));

    fireEvent.click(publish);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm publish' }));

    expect(await screen.findByText('Draft published', undefined, WAIT)).toBeTruthy();
    const [request] = gateway.requests('POST', `/v1/admin/policy/drafts/${DRAFT_ID}/publish`);
    expect(request.headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(request.headers.get('X-GreenGateway-Policy-Draft-ETag')).toBe(draftEtag(DRAFT_ID, 2));
    expect(request.headers.get('X-GreenGateway-Resource-Snapshot')).toBe(SNAPSHOT_DIGEST);
    expect(request.body).toBeNull();
    expect(gateway.live.policy).toMatchObject({ id: 'next' });
  });

  it('names the risks a publication carries and validates again when resources moved', async () => {
    const gateway = fakeGateway();
    gateway.validate = () =>
      jsonResponse(200, {
        ...validInspection(),
        diagnostics: [
          diagnostic({
            code: 'default_action_allow',
            severity: 'risk',
            pointer: '/default_action',
            message: 'Requests that no rule or route matches are allowed.',
            remediation: 'Set default_action to deny.',
            blocks: { simulation: false, tests: false, publication: false, evidence: false },
          }),
        ],
      });
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'next' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    await screen.findByText('Revision 2 saved. The live policy is unchanged.', undefined, WAIT);
    expect(await screen.findByText('Valid, with 1 risk.', undefined, WAIT)).toBeTruthy();
    const publish = screen.getByRole('button', { name: 'Publish draft' }) as HTMLButtonElement;
    await waitFor(() => expect(publish.disabled).toBe(false), WAIT);

    fireEvent.click(publish);
    const confirmation = screen.getByRole('group', { name: 'Publish this draft?' });
    expect(
      within(confirmation).getByText(/Requests that no rule or route matches are allowed\./),
    ).toBeTruthy();

    const validations = gateway.requests('POST', '/v1/admin/policy/validate').length;
    gateway.publishRefusal = refusal(409, 'resource_snapshot_stale');
    fireEvent.click(screen.getByRole('button', { name: 'Confirm publish' }));

    expect(
      await screen.findByText('Resources changed since validation', undefined, WAIT),
    ).toBeTruthy();
    await waitFor(
      () =>
        expect(gateway.requests('POST', '/v1/admin/policy/validate').length).toBeGreaterThan(
          validations,
        ),
      WAIT,
    );
    expect(gateway.live.etag).toBe(LIVE_ETAG);
  });

  it('shows a stale base and rebases only when asked, without merging', async () => {
    const gateway = fakeGateway();
    gateway.live = { policy: { ...draftPolicy(), default_action: 'allow' }, etag: '"sha256:live-2"' };
    renderStudio(gateway);
    await openDraft();

    expect(screen.getByText('Stale: the live policy changed')).toBeTruthy();
    expect(
      screen.getByText(
        'The live policy changed after this draft was pinned. Review it and rebase the draft first.',
      ),
    ).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Publish draft' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Rebase onto live policy' }));
    const confirmation = screen.getByRole('group', { name: 'Rebase this draft onto the live policy?' });
    expect(within(confirmation).getByText(/Rebasing does not merge/)).toBeTruthy();
    expect(within(confirmation).getByText(/default action/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm rebase' }));

    expect(await screen.findByText('Draft rebased', undefined, WAIT)).toBeTruthy();
    const [patch] = gateway.requests('PATCH', `/v1/admin/policy/drafts/${DRAFT_ID}`);
    expect(JSON.parse(patch.body ?? '{}')).toEqual({ base_etag: '"sha256:live-2"' });
    expect(screen.getByText('Current')).toBeTruthy();
  });

  it('reports a refused stale publication without changing anything', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'next' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    await screen.findByText('Revision 2 saved. The live policy is unchanged.', undefined, WAIT);
    const publish = screen.getByRole('button', { name: 'Publish draft' }) as HTMLButtonElement;
    await waitFor(() => expect(publish.disabled).toBe(false), WAIT);

    gateway.live = { policy: { ...draftPolicy(), default_action: 'allow' }, etag: '"sha256:live-9"' };
    fireEvent.click(publish);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm publish' }));

    expect(await screen.findByText('The live policy changed', undefined, WAIT)).toBeTruthy();
    expect(gateway.live.etag).toBe('"sha256:live-9"');
    await waitFor(() => expect(screen.getByText('Stale: the live policy changed')).toBeTruthy());
  });

  it('treats a lost save answer as unknown and reads the draft instead of retrying', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'lost' } });
    gateway.failNext('PATCH', new TypeError('Failed to fetch'));

    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));

    expect(await screen.findByText('Outcome unknown', undefined, WAIT)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Check the draft on the gateway' }));
    expect(await screen.findByText('Draft not saved', undefined, WAIT)).toBeTruthy();
    expect(gateway.requests('PATCH', `/v1/admin/policy/drafts/${DRAFT_ID}`)).toHaveLength(1);
    expect((screen.getByLabelText('Policy id') as HTMLInputElement).value).toBe('lost');
  });

  it('keeps the edits of an expired draft and saves them as a new draft only when asked', async () => {
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'kept' } });
    gateway.expire(DRAFT_ID);

    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));

    expect(
      await screen.findByText('This draft expired on the gateway. Your edits are kept here.', undefined, WAIT),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Save my edits as a new draft' }));
    expect(await screen.findByText('Draft created', undefined, WAIT)).toBeTruthy();
    const [create] = gateway.requests('POST', '/v1/admin/policy/drafts');
    expect(create.headers.get('If-Match')).toBe(LIVE_ETAG);
    expect(JSON.parse(create.body ?? '{}')).toMatchObject({ policy: { id: 'kept' } });
  });

  it('is read-only without admin:policy:write and shows egress without editing it', async () => {
    const gateway = fakeGateway({ permissions: [READ] });
    renderStudio(gateway);
    await openDraft();

    expect(screen.getByText('Read-only')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'New draft from live policy' })).toBeNull();
    expect((screen.getByLabelText('Policy id') as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Save draft' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('tab', { name: /Egress/ }));
    const panel = screen.getByRole('tabpanel', { name: /Egress/ });
    expect(within(panel).getByText('api.example.com')).toBeTruthy();
    expect(within(panel).queryAllByRole('textbox')).toHaveLength(0);
    expect(within(panel).getByText('Read-only here')).toBeTruthy();
  });

  it('converts a 0.x draft through the gateway and lists what changed', async () => {
    const gateway = fakeGateway();
    const legacy = { ...draftPolicy(), schema_version: '0.1.0' };
    gateway.drafts.get(DRAFT_ID)!.policy = legacy;
    renderStudio(gateway);
    await openDraft();

    expect(screen.getByText('Not policy v1')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Convert to policy v1' }));

    expect(await screen.findByText('Converted to policy v1', undefined, WAIT)).toBeTruthy();
    const [convert] = gateway.requests('POST', '/v1/admin/policy/convert');
    expect(convert.body).toBe(JSON.stringify(legacy, null, 2));
    expect(screen.getByText('Policy v1')).toBeTruthy();
    expect(screen.getByText('Gave the rule a stable id.')).toBeTruthy();
    expect(screen.getByText('Unsaved edits', { selector: '.result-count' })).toBeTruthy();
  });

  it('asks before leaving with unsaved edits and keeps the draft out of browser storage', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const gateway = fakeGateway();
    renderStudio(gateway);
    await openDraft();
    fireEvent.change(screen.getByLabelText('Policy id'), { target: { value: 'unsaved' } });

    fireEvent.click(screen.getByRole('link', { name: 'Rulebase' }));
    expect(confirm).toHaveBeenCalledOnce();
    expect(screen.getByRole('heading', { name: 'Policy Studio' })).toBeTruthy();

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole('link', { name: 'Rulebase' }));
    expect(await screen.findByText('Rulebase page')).toBeTruthy();
    expect(setItem).not.toHaveBeenCalled();
    for (const request of gateway.log) {
      expect(request.path).not.toContain('unsaved');
    }
  });

  it('explains that drafts are unavailable when the gateway has no draft store', async () => {
    const gateway = fakeGateway();
    gateway.draftsUnavailable = true;
    renderStudio(gateway);

    expect(await screen.findByText('Policy drafts unavailable', undefined, WAIT)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'New draft from live policy' })).toBeNull();
  });
});

type LoggedRequest = {
  method: string;
  path: string;
  headers: Headers;
  body: string | null;
};

type DraftRecord = {
  revision: number;
  state: 'open' | 'published';
  base_etag: string;
  published_etag: string | null;
  policy: Record<string, unknown>;
  expired: boolean;
};

function fakeGateway({ permissions = [READ, WRITE] }: { permissions?: string[] } = {}) {
  const gateway = {
    live: { policy: draftPolicy() as Record<string, unknown>, etag: LIVE_ETAG },
    drafts: new Map<string, DraftRecord>([
      [
        DRAFT_ID,
        {
          revision: 1,
          state: 'open',
          base_etag: LIVE_ETAG,
          published_etag: null,
          policy: draftPolicy(),
          expired: false,
        },
      ],
    ]),
    draftsUnavailable: false,
    publishRefusal: null as Response | null,
    validate: (_source: string): Response | Promise<Response> =>
      jsonResponse(200, validInspection()),
    log: [] as LoggedRequest[],
    failures: [] as Array<{ method: string; error: Error }>,
    liveRevision: 1,
    requests(method: string, path: string) {
      return gateway.log.filter(
        (request) => request.method === method && request.path === path,
      );
    },
    bumpDraft(id: string) {
      const record = gateway.drafts.get(id);
      if (record) record.revision += 1;
    },
    expire(id: string) {
      const record = gateway.drafts.get(id);
      if (record) record.expired = true;
    },
    failNext(method: string, error: Error) {
      gateway.failures.push({ method, error });
    },
    fetch: vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? init.body : null;
      const headers = new Headers(init?.headers);
      gateway.log.push({ method, path: url.pathname, headers, body });
      const failure = gateway.failures.findIndex((entry) => entry.method === method);
      if (failure >= 0) {
        const [{ error }] = gateway.failures.splice(failure, 1);
        return Promise.reject(error);
      }
      return Promise.resolve(gateway.answer(method, url.pathname, headers, body));
    }),
    answer(
      method: string,
      path: string,
      headers: Headers,
      body: string | null,
    ): Response | Promise<Response> {
      if (path === '/v1/admin/capabilities') {
        return jsonResponse(200, { permissions });
      }
      if (path === '/v1/admin/policy' && method === 'GET') {
        return jsonResponse(200, gateway.live.policy, {
          ETag: gateway.live.etag,
          'x-greengateway-policy-write': String(permissions.includes(WRITE)),
        });
      }
      if (path === '/v1/admin/policy/validate') {
        return gateway.validate(body ?? '');
      }
      if (path === '/v1/admin/policy/convert') {
        const source = JSON.parse(body ?? '{}') as Record<string, unknown>;
        return jsonResponse(200, {
          converted: true,
          source_schema_version: '0.1.0',
          schema_version: '1.0.0',
          diagnostics: [],
          parity: 'verified',
          changes: [
            {
              code: 'rule_id_assigned',
              pointer: '/rules/0',
              element_id: 'allow-billing',
              message: 'Gave the rule a stable id.',
            },
          ],
          policy: { ...source, schema_version: '1.0.0' },
        });
      }
      if (gateway.draftsUnavailable && path.startsWith('/v1/admin/policy/drafts')) {
        return jsonResponse(503, {
          error: 'policy drafts are unavailable',
          reason: 'policy_drafts_unavailable',
        });
      }
      if (path === '/v1/admin/policy/drafts' && method === 'GET') {
        return jsonResponse(200, {
          drafts: [...gateway.drafts.entries()]
            .filter(([, record]) => !record.expired)
            .map(([id, record]) => {
              const { policy: _policy, ...view } = draftView(id, record);
              return view;
            }),
          limits: {
            ttl_seconds: 86400,
            max_drafts_per_owner: 8,
            max_drafts: 128,
            max_candidate_bytes: 1048576,
          },
        });
      }
      if (path === '/v1/admin/policy/drafts' && method === 'POST') {
        if (headers.get('If-Match') !== gateway.live.etag) {
          return refusal(412, 'policy_etag_mismatch');
        }
        const request = JSON.parse(body ?? '{}') as { policy?: Record<string, unknown> };
        const id = `pd_${'b'.repeat(32)}`;
        const record: DraftRecord = {
          revision: 1,
          state: 'open',
          base_etag: gateway.live.etag,
          published_etag: null,
          policy: request.policy ?? gateway.live.policy,
          expired: false,
        };
        gateway.drafts.set(id, record);
        return draftResponse(201, id, record);
      }
      const match = /^\/v1\/admin\/policy\/drafts\/(pd_[0-9a-f]{32})(\/publish)?$/.exec(path);
      const id = match?.[1] ?? '';
      const record = gateway.drafts.get(id);
      if (!match || !record) {
        return match ? refusal(404, 'policy_draft_not_found') : jsonResponse(404, { error: 'not found' });
      }
      if (record.expired) {
        return refusal(410, 'policy_draft_expired');
      }
      if (match[2] && method === 'POST') {
        if (gateway.publishRefusal !== null) return gateway.publishRefusal;
        if (record.state === 'published') return refusal(409, 'policy_draft_published');
        if (headers.get('X-GreenGateway-Policy-Draft-ETag') !== draftEtag(id, record.revision)) {
          return refusal(412, 'policy_draft_etag_mismatch');
        }
        if (record.base_etag !== gateway.live.etag) return refusal(409, 'policy_draft_base_stale');
        if (headers.get('If-Match') !== gateway.live.etag) return refusal(412, 'policy_etag_mismatch');
        gateway.liveRevision += 1;
        gateway.live = { policy: record.policy, etag: `"sha256:live-${gateway.liveRevision}"` };
        record.state = 'published';
        record.published_etag = gateway.live.etag;
        return jsonResponse(200, gateway.live.policy, { ETag: gateway.live.etag });
      }
      if (method === 'GET') {
        return draftResponse(200, id, record);
      }
      if (headers.get('If-Match') !== draftEtag(id, record.revision)) {
        return refusal(412, 'policy_draft_etag_mismatch');
      }
      if (method === 'DELETE') {
        gateway.drafts.delete(id);
        return new Response(null, { status: 204 });
      }
      if (method === 'PATCH') {
        if (record.state === 'published') return refusal(409, 'policy_draft_published');
        const request = JSON.parse(body ?? '{}') as {
          policy?: Record<string, unknown>;
          base_etag?: string;
        };
        if (request.base_etag !== undefined && request.base_etag !== gateway.live.etag) {
          return refusal(412, 'policy_etag_mismatch');
        }
        record.revision += 1;
        record.policy = request.policy ?? record.policy;
        record.base_etag = request.base_etag ?? record.base_etag;
        return draftResponse(200, id, record);
      }
      return jsonResponse(405, { error: 'unexpected' });
    },
  };
  return gateway;
}

function draftView(id: string, record: DraftRecord) {
  return {
    draft_id: id,
    revision: record.revision,
    state: record.state,
    base_etag: record.base_etag,
    candidate_etag: `"sha256:candidate-${record.revision}"`,
    published_etag: record.published_etag,
    created_at: '2026-10-28T10:00:00Z',
    updated_at: '2026-10-28T10:05:00Z',
    expires_at: '2026-10-29T10:05:00Z',
    policy: record.policy,
  };
}

function draftResponse(status: number, id: string, record: DraftRecord): Response {
  return jsonResponse(status, draftView(id, record), {
    ETag: draftEtag(id, record.revision),
  });
}

function draftEtag(id: string, revision: number): string {
  return `"sha256:${id.slice(3, 7)}-r${revision}"`;
}

function refusal(status: number, reason: string): Response {
  return jsonResponse(status, { error: reason.replace(/_/g, ' '), reason });
}

function draftPolicy() {
  return {
    schema_version: '1.0.0',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: { support: { permissions: ['billing:read'] } },
    routes: [
      {
        id: 'billing',
        methods: ['GET'],
        path_prefix: '/billing/',
        permission: 'billing:read',
      },
    ],
    rules: [
      {
        id: 'allow-billing',
        methods: ['GET'],
        path: '/billing/{id}',
        principal: { roles: ['support'], issuers: [], auth_methods: [], principal_ids: [] },
        action: 'allow',
      },
    ],
    egress: { hosts: ['api.example.com'] },
  };
}

function validInspection() {
  return {
    valid: true,
    schema_version: '1.0.0',
    diagnostics: [],
    source_digest: 'sha256:source',
    semantic_digest: 'sha256:semantic',
    resource_snapshot: { schema_version: '1', digest: SNAPSHOT_DIGEST, complete: true },
  };
}

function diagnostic(overrides: Record<string, unknown> = {}) {
  return {
    code: 'test_code',
    severity: 'error',
    pointer: '/rules/0',
    message: 'Problem.',
    remediation: 'Fix it.',
    blocks: { simulation: true, tests: true, publication: true, evidence: true },
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
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function renderStudio(gateway: ReturnType<typeof fakeGateway>) {
  vi.stubGlobal('fetch', gateway.fetch);
  render(
    <MemoryRouter initialEntries={['/policy/studio']}>
      <Routes>
        <Route path="/policy/studio" element={<PolicyStudioView />} />
        <Route path="/rules" element={<p>Rulebase page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function openDraft() {
  fireEvent.click(
    await screen.findByRole('button', { name: `Open draft ${DRAFT_ID}` }, WAIT),
  );
  await screen.findByRole('tablist', { name: 'Policy sections' }, WAIT);
}
