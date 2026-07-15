import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { PolicyDocument, PolicyRule } from '../lib/policy';
import { RULE_PREVIEW_DEBOUNCE_MS, RuleEditor } from './RuleEditor';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('RuleEditor', () => {
  it('starts from the unchanged blank form when no prefill params are present', async () => {
    vi.stubGlobal('fetch', policyBackedFetch(policyFixture(), 'W/"policy-1"'));

    renderRuleEditor();

    const pathInput = (await screen.findByLabelText(
      'Path pattern',
    )) as HTMLInputElement;
    expect(pathInput.value).toBe('');
    expect((screen.getByLabelText('Any method') as HTMLInputElement).checked).toBe(
      true,
    );
    expect((screen.getByLabelText('GET') as HTMLInputElement).checked).toBe(
      false,
    );
    expect(screen.getByText('Any role')).toBeTruthy();
    expect(screen.getByText('Any issuer')).toBeTruthy();
    expect(screen.getByText('Any principal ID')).toBeTruthy();
    expect(
      (screen.getByLabelText('Bearer token') as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByLabelText('Session cookie') as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByLabelText('Service token') as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByRole('radio', { name: /Deny/ }) as HTMLInputElement).checked,
    ).toBe(true);
  });

  it('applies each valid prefill query param to a new rule form', async () => {
    vi.stubGlobal('fetch', policyBackedFetch(policyFixture(), 'W/"policy-1"'));

    renderRuleEditor(
      '/policy/rules/editor?prefill_method=post&prefill_path=%2Fapi%2Freports%2F%7Bid%7D&prefill_role=support&prefill_issuer=https%3A%2F%2Fidp.example%2F&prefill_auth_method=session_cookie&prefill_principal_id=user-123&prefill_action=shadow',
    );

    expect(await screen.findByDisplayValue('/api/reports/{id}')).toBeTruthy();
    expect((screen.getByLabelText('POST') as HTMLInputElement).checked).toBe(
      true,
    );
    expect(
      screen.getByLabelText('Role constraints selected values').textContent,
    ).toContain('support');
    expect(
      screen.getByLabelText('Issuers selected values').textContent,
    ).toContain('https://idp.example/');
    expect(
      (screen.getByLabelText('Session cookie') as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      screen.getByLabelText('Principal IDs selected values').textContent,
    ).toContain('user-123');
    expect(
      (screen.getByRole('radio', { name: /Shadow/ }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      screen.getByLabelText('Rule summary').textContent,
    ).toContain(
      'Log-only POST requests to /api/reports/{id} for role support, issuer https://idp.example/, auth method session cookie, and principal user-123.',
    );
    expect(
      screen.getByLabelText('Policy expression').textContent,
    ).toContain('request.method in ["POST"]');
    expect(
      screen.getByLabelText('Policy expression').textContent,
    ).toContain('request.path matches "/api/reports/{id}"');
    expect(
      screen.getByLabelText('Policy expression').textContent,
    ).toContain('principal.roles contains "support"');
    expect(
      screen.getByLabelText('Policy expression').textContent,
    ).toContain('principal.issuer in ["https://idp.example/"]');
    expect(
      screen.getByLabelText('Policy expression').textContent,
    ).toContain('decision = "shadow"');
  });

  it('saves a contextless dispatch binding from traffic prefill', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"');
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor(
      '/policy/rules/editor?prefill_method=GET&prefill_path=%2Flocal%2F%7Bid%7D&prefill_dispatch_kind=contextless',
    );

    expect(await screen.findByDisplayValue('/local/{id}')).toBeTruthy();
    expect(screen.getByLabelText('Policy expression').textContent).toContain(
      'proxy.dispatch_kind == "contextless"',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    expect(await screen.findByText('Rule saved.')).toBeTruthy();

    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules') && init?.method === 'POST',
    );
    expect(JSON.parse(String(createCall?.[1]?.body)).dispatch).toEqual({
      kind: 'contextless',
    });
  });

  it('saves a legacy dispatch binding from traffic prefill', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"');
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor(
      '/policy/rules/editor?prefill_method=GET&prefill_path=%2Flegacy%2F%7Bid%7D&prefill_dispatch_kind=legacy&prefill_upstream_origin=https%3A%2F%2Flegacy.internal',
    );

    expect(await screen.findByDisplayValue('/legacy/{id}')).toBeTruthy();
    expect(screen.getByLabelText('Policy expression').textContent).toContain(
      'proxy.upstream_origin == "https://legacy.internal"',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));
    expect(await screen.findByText('Rule saved.')).toBeTruthy();

    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules') && init?.method === 'POST',
    );
    expect(JSON.parse(String(createCall?.[1]?.body)).dispatch).toEqual({
      kind: 'legacy',
      upstream_origin: 'https://legacy.internal',
    });
  });

  it('applies a principal deny shortcut to a new rule form', async () => {
    vi.stubGlobal('fetch', policyBackedFetch(policyFixture(), 'W/"policy-1"'));

    renderRuleEditor(
      '/policy/rules/editor?prefill_principal_id=alice%2Fprod%40example.test&prefill_action=deny&prefill_path=%2F**',
    );

    expect(await screen.findByDisplayValue('/**')).toBeTruthy();
    expect((screen.getByLabelText('Any method') as HTMLInputElement).checked).toBe(
      true,
    );
    expect(
      screen.getByLabelText('Principal IDs selected values').textContent,
    ).toContain('alice/prod@example.test');
    expect(
      (screen.getByRole('radio', { name: /Deny/ }) as HTMLInputElement).checked,
    ).toBe(true);
  });

  it('saves a tool-name prefilled rule without HTTP method or path matchers', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"');
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor(
      '/policy/rules/editor?prefill_tool_name=reports.export&prefill_role=support&prefill_action=deny',
    );

    expect(await screen.findByDisplayValue('reports.export')).toBeTruthy();
    expect(
      (screen.getByLabelText('MCP tool') as HTMLInputElement).checked,
    ).toBe(true);
    expect(screen.queryByLabelText('Path pattern')).toBeNull();
    expect(
      screen.getByLabelText('Role constraints selected values').textContent,
    ).toContain('support');

    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(await screen.findByText('Rule saved.')).toBeTruthy();
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules') && init?.method === 'POST',
    );
    expect(createCall).toBeTruthy();
    expect(JSON.parse(String(createCall?.[1]?.body))).toEqual({
      methods: [],
      tool_name: 'reports.export',
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: [],
        principal_ids: [],
      },
      action: 'deny',
    });
  });

  it('ignores invalid prefill auth method and action values', async () => {
    vi.stubGlobal('fetch', policyBackedFetch(policyFixture(), 'W/"policy-1"'));

    renderRuleEditor(
      '/policy/rules/editor?prefill_path=%2Fapi%2Fusers&prefill_auth_method=api_key&prefill_action=block',
    );

    expect(await screen.findByDisplayValue('/api/users')).toBeTruthy();
    expect(
      (screen.getByLabelText('Bearer token') as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByLabelText('Session cookie') as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByRole('radio', { name: /Deny/ }) as HTMLInputElement).checked,
    ).toBe(true);
  });

  it('ignores prefill params when rule_id is present', async () => {
    const existingRule: PolicyRule = {
      id: 'support-read',
      methods: ['GET'],
      path: '/existing/{id}',
      dispatch: {
        kind: 'legacy',
        upstream_origin: 'https://api.example.test',
      },
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: ['bearer_token'],
        principal_ids: ['existing-user'],
      },
      action: 'allow',
    };
    vi.stubGlobal(
      'fetch',
      policyBackedFetch(policyFixture({ rules: [existingRule] }), 'W/"policy-1"'),
    );

    renderRuleEditor(
      '/policy/rules/editor?rule_id=support-read&prefill_method=POST&prefill_path=%2Fprefill&prefill_role=prefill-role&prefill_auth_method=session_cookie&prefill_principal_id=prefill-user&prefill_action=shadow',
    );

    expect(await screen.findByDisplayValue('/existing/{id}')).toBeTruthy();
    expect((screen.getByLabelText('GET') as HTMLInputElement).checked).toBe(
      true,
    );
    expect((screen.getByLabelText('POST') as HTMLInputElement).checked).toBe(
      false,
    );
    expect(
      screen.getByLabelText('Role constraints selected values').textContent,
    ).toContain('support');
    expect(
      screen.getByLabelText('Role constraints selected values').textContent,
    ).not.toContain('prefill-role');
    expect(
      (screen.getByLabelText('Bearer token') as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      screen.getByLabelText('Principal IDs selected values').textContent,
    ).toContain('existing-user');
    expect(
      (screen.getByRole('radio', { name: /Allow/ }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (screen.getByRole('radio', { name: 'MCP tool' }) as HTMLInputElement)
        .disabled,
    ).toBe(true);
    expect(screen.getByLabelText('Policy expression').textContent).toContain(
      'proxy.upstream_origin == "https://api.example.test"',
    );
  });

  it('validates path patterns before submitting', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"');
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    expect(await screen.findByLabelText('Path pattern')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(await screen.findByText('Path pattern is required.')).toBeTruthy();
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).endsWith('/policy/rules') && init?.method === 'POST',
      ),
    ).toBe(false);

    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/api/{bad-name}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(
      (
        await screen.findAllByText(
          'Capture names must start with a letter or underscore and contain only ASCII letters, digits, and underscores.',
        )
      ).length,
    ).toBeGreaterThan(0);
  });

  it('debounces preview requests and sends the candidate rule shape', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"', {
      preview: {
        match_count: 2,
        scanned_event_count: 9,
        sample_strategy: 'newest_matches',
        samples: [
          previewSample({
            event_id: 'evt-1',
            method: 'GET',
            path: '/api/users/123',
            status: 200,
            actor: {
              user_id: 'user-123',
              auth_mode: 'bearer_token',
              roles: ['support'],
            },
          }),
        ],
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    await screen.findByLabelText('Path pattern');
    vi.useFakeTimers();
    fillPreviewCandidate();

    await advanceTimersByTime(RULE_PREVIEW_DEBOUNCE_MS - 1);
    expect(previewRequests(fetchMock)).toHaveLength(0);

    await advanceTimersByTime(1);

    expect(previewRequests(fetchMock)).toHaveLength(1);
    vi.useRealTimers();
    const body = JSON.parse(
      String(previewRequests(fetchMock)[0][1]?.body),
    ) as Record<string, unknown>;

    expect(body).toMatchObject({
      rule: {
        methods: ['GET'],
        path: '/api/users/{id}',
        principal: {
          roles: ['support'],
          issuers: [],
          auth_methods: ['bearer_token'],
          principal_ids: ['user-123'],
        },
        action: 'shadow',
      },
      sample_limit: 5,
    });
    expect(typeof body.from).toBe('string');
    expect(typeof body.to).toBe('string');
    expect(await screen.findByText('2')).toBeTruthy();
    expect(
      screen.getByText((_, node) =>
        Boolean(
          node instanceof HTMLElement &&
            node.classList.contains('body-copy') &&
          node?.textContent?.includes(
            'This rule would have matched 2 requests in the last 24 hours.',
          ),
        ),
      ),
    ).toBeTruthy();
    expect(screen.getByText('/api/users/123')).toBeTruthy();
  });

  it('keeps the newest preview when an older preview resolves last', async () => {
    const previewCalls: Deferred<Response>[] = [];
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"', {
      previewResponse: () => {
        const deferred = createDeferred<Response>();
        previewCalls.push(deferred);
        return deferred.promise;
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    await screen.findByLabelText('Path pattern');
    vi.useFakeTimers();

    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/api/slow/{id}' },
    });
    await advanceTimersByTime(RULE_PREVIEW_DEBOUNCE_MS);
    expect(previewCalls).toHaveLength(1);

    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/api/fast/{id}' },
    });
    await advanceTimersByTime(RULE_PREVIEW_DEBOUNCE_MS);
    expect(previewCalls).toHaveLength(2);
    vi.useRealTimers();

    await act(async () => {
      previewCalls[1].resolve(
        jsonResponse(200, previewResponseFixture(8, '/api/fast/123')),
      );
    });
    expect(await screen.findByText('/api/fast/123')).toBeTruthy();
    expect(screen.getByText('8')).toBeTruthy();

    await act(async () => {
      previewCalls[0].resolve(
        jsonResponse(200, previewResponseFixture(1, '/api/slow/123')),
      );
    });

    expect(screen.getByText('/api/fast/123')).toBeTruthy();
    expect(screen.getByText('8')).toBeTruthy();
    expect(screen.queryByText('/api/slow/123')).toBeNull();
    expect(screen.queryByText('1')).toBeNull();
  });

  it('creates a rule with the current policy ETag', async () => {
    const createdRule: PolicyRule = {
      id: 'rule-generated-1',
      methods: [],
      path: '/reports/**',
      principal: {
        roles: [],
        issuers: [],
        auth_methods: [],
        principal_ids: [],
      },
      action: 'deny',
    };
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"', {
      createRule: createdRule,
      mutationEtag: 'W/"policy-2"',
    });
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    await screen.findByLabelText('Path pattern');
    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/reports/**' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(await screen.findByText('Rule saved.')).toBeTruthy();
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules') && init?.method === 'POST',
    );
    expect(createCall).toBeTruthy();
    expect(headerValue(createCall?.[1]?.headers, 'If-Match')).toBe('W/"policy-1"');
    expect(JSON.parse(String(createCall?.[1]?.body))).toEqual({
      methods: [],
      path: '/reports/**',
      principal: {
        roles: [],
        issuers: [],
        auth_methods: [],
        principal_ids: [],
      },
      action: 'deny',
    });
  });

  it('edits an existing rule with PATCH and the current policy ETag', async () => {
    const existingRule: PolicyRule = {
      id: 'support-read',
      methods: ['GET'],
      path: '/api/users/{id}',
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'allow',
    };
    const fetchMock = policyBackedFetch(
      policyFixture({ rules: [existingRule] }),
      'W/"policy-1"',
      {
        patchRule: {
          ...existingRule,
          action: 'shadow',
        },
        mutationEtag: 'W/"policy-2"',
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor('/policy/rules/editor?rule_id=support-read');

    expect(await screen.findByDisplayValue('/api/users/{id}')).toBeTruthy();
    fireEvent.click(screen.getByRole('radio', { name: /Shadow/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(await screen.findByText('Rule saved.')).toBeTruthy();
    const patchCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules/support-read') &&
        init?.method === 'PATCH',
    );
    expect(patchCall).toBeTruthy();
    expect(headerValue(patchCall?.[1]?.headers, 'If-Match')).toBe('W/"policy-1"');
    expect(JSON.parse(String(patchCall?.[1]?.body))).toEqual({
      methods: ['GET'],
      path: '/api/users/{id}',
      tool_name: null,
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'shadow',
    });
  });

  it('clears the old path matcher when editing an existing rule into a tool rule', async () => {
    const existingRule: PolicyRule = {
      id: 'support-read',
      methods: ['GET'],
      path: '/api/users/{id}',
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'allow',
    };
    const fetchMock = policyBackedFetch(
      policyFixture({ rules: [existingRule] }),
      'W/"policy-1"',
      {
        patchRule: {
          id: 'support-read',
          methods: [],
          tool_name: 'reports.export',
          principal: existingRule.principal,
          action: 'deny',
        },
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor('/policy/rules/editor?rule_id=support-read');

    expect(await screen.findByDisplayValue('/api/users/{id}')).toBeTruthy();
    fireEvent.click(screen.getByLabelText('MCP tool'));
    fireEvent.change(screen.getByLabelText('Tool name'), {
      target: { value: 'reports.export' },
    });
    fireEvent.click(screen.getByRole('radio', { name: /Deny/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(await screen.findByText('Rule saved.')).toBeTruthy();
    const patchCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/policy/rules/support-read') &&
        init?.method === 'PATCH',
    );
    expect(patchCall).toBeTruthy();
    expect(JSON.parse(String(patchCall?.[1]?.body))).toEqual({
      methods: [],
      path: null,
      tool_name: 'reports.export',
      principal: {
        roles: ['support'],
        issuers: [],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'deny',
    });
  });

  it('surfaces ETag conflicts as a policy refresh message', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"', {
      createStatus: 412,
      createBody: {
        error: 'If-Match does not match the current policy ETag',
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    await screen.findByLabelText('Path pattern');
    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/admin/**' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }));

    expect(
      await screen.findByText(
        'Policy changed while you were editing. Refresh the rule editor and retry with the latest policy.',
      ),
    ).toBeTruthy();
  });

  it('treats audit-unavailable preview responses as non-fatal', async () => {
    const fetchMock = policyBackedFetch(policyFixture(), 'W/"policy-1"', {
      previewStatus: 503,
      previewBody: {
        error: 'policy rule preview requires AUDIT_SQLITE_PATH to be configured',
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    renderRuleEditor();

    await screen.findByLabelText('Path pattern');
    vi.useFakeTimers();
    fireEvent.change(screen.getByLabelText('Path pattern'), {
      target: { value: '/api/**' },
    });

    await advanceTimersByTime(RULE_PREVIEW_DEBOUNCE_MS);
    vi.useRealTimers();

    expect(await screen.findByText('Live preview unavailable')).toBeTruthy();
    expect(
      screen.getByText(
        'Preview requires AUDIT_SQLITE_PATH to be configured. You can still save the rule.',
      ),
    ).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Save rule' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });
});

function fillPreviewCandidate() {
  fireEvent.click(screen.getByLabelText('GET'));
  fireEvent.change(screen.getByLabelText('Path pattern'), {
    target: { value: '/api/users/{id}' },
  });
  fireEvent.change(screen.getByLabelText('Role constraints'), {
    target: { value: 'support' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Add role' }));
  fireEvent.click(screen.getByLabelText('Bearer token'));
  fireEvent.change(screen.getByLabelText('Principal IDs'), {
    target: { value: 'user-123' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Add principal ID' }));
  fireEvent.click(screen.getByRole('radio', { name: /Shadow/ }));
}

function renderRuleEditor(initialEntry = '/policy/rules/editor') {
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <RuleEditor />
    </MemoryRouter>,
  );
}

async function advanceTimersByTime(milliseconds: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(milliseconds);
  });
}

type PolicyBackedFetchOptions = {
  preview?: unknown;
  previewResponse?: (
    input: RequestInfo | URL,
    init: RequestInit | undefined,
  ) => Promise<Response>;
  previewStatus?: number;
  previewBody?: unknown;
  createRule?: PolicyRule;
  createStatus?: number;
  createBody?: unknown;
  patchRule?: PolicyRule;
  mutationEtag?: string;
};

function policyBackedFetch(
  policy: PolicyDocument,
  policyEtag: string,
  options: PolicyBackedFetchOptions = {},
) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    const method = init?.method ?? 'GET';

    if (url.pathname === '/v1/admin/policy' && method === 'GET') {
      return Promise.resolve(jsonResponse(200, policy, { ETag: policyEtag }));
    }

    if (url.pathname === '/v1/admin/traffic/endpoints' && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          endpoints: [
            {
              method: 'GET',
              endpoint_template: '/api/users/{id}',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T09:00:00Z',
              call_count: 4,
              distinct_principal_count: 2,
              is_new: false,
              reviewed: true,
              reviewed_at: '2026-07-04T09:05:00Z',
              reviewed_by: 'operator',
              covered_by_rule: false,
              latency: {
                count: 4,
                p50_ms: 5,
                p95_ms: 8,
                p99_ms: 9,
              },
              status_counts: [{ status: 200, count: 4 }],
            },
          ],
          next_cursor: null,
        }),
      );
    }

    if (
      url.pathname === '/v1/admin/policy/rules/preview' &&
      method === 'POST'
    ) {
      if (options.previewResponse) {
        return options.previewResponse(input, init);
      }
      return Promise.resolve(
        jsonResponse(
          options.previewStatus ?? 200,
          options.preview ??
            options.previewBody ?? {
              match_count: 0,
              scanned_event_count: 0,
              sample_strategy: 'newest_matches',
              samples: [],
            },
        ),
      );
    }

    if (url.pathname === '/v1/admin/policy/rules' && method === 'POST') {
      return Promise.resolve(
        jsonResponse(
          options.createStatus ?? 201,
          options.createRule ??
            options.createBody ?? {
              id: 'rule-generated-1',
              methods: [],
              path: '/reports/**',
              principal: {
                roles: [],
                issuers: [],
                auth_methods: [],
                principal_ids: [],
              },
              action: 'deny',
            },
          { ETag: options.mutationEtag ?? 'W/"policy-2"' },
        ),
      );
    }

    if (
      url.pathname === '/v1/admin/policy/rules/support-read' &&
      method === 'PATCH'
    ) {
      return Promise.resolve(
        jsonResponse(
          200,
          options.patchRule ?? {
            id: 'support-read',
            methods: ['GET'],
            path: '/api/users/{id}',
            principal: {
              roles: ['support'],
              issuers: [],
              auth_methods: ['bearer_token'],
              principal_ids: [],
            },
            action: 'shadow',
          },
          { ETag: options.mutationEtag ?? 'W/"policy-2"' },
        ),
      );
    }

    return Promise.resolve(jsonResponse(404, { error: 'not found' }));
  });
}

function previewRequests(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.filter(
    ([input, init]) =>
      String(input).endsWith('/policy/rules/preview') && init?.method === 'POST',
  );
}

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
};

function createDeferred<T>(): Deferred<T> {
  let resolve: Deferred<T>['resolve'] | undefined;
  let reject: Deferred<T>['reject'] | undefined;
  const promise = new Promise<T>((innerResolve, innerReject) => {
    resolve = innerResolve;
    reject = innerReject;
  });

  if (!resolve || !reject) {
    throw new Error('Failed to create deferred promise');
  }

  return { promise, resolve, reject };
}

function previewResponseFixture(matchCount: number, path: string) {
  return {
    match_count: matchCount,
    scanned_event_count: 25,
    sample_strategy: 'newest_matches',
    samples: [
      previewSample({
        event_id: `evt-${matchCount}`,
        path,
      }),
    ],
  };
}

function policyFixture(overrides: Partial<PolicyDocument> = {}): PolicyDocument {
  return {
    schema_version: '0.1.0',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {
      support: { permissions: ['tickets:read'] },
      admin: { permissions: ['*'] },
    },
    routes: [],
    rules: [],
    ...overrides,
  };
}

function previewSample(overrides: Record<string, unknown> = {}) {
  return {
    event_id: 'evt-1',
    timestamp: '2026-07-04T10:00:00Z',
    request_id: 'req-1',
    source_ip: '203.0.113.10',
    user_agent: 'vitest',
    method: 'GET',
    path: '/api/users/123',
    actor: null,
    status: 200,
    policy_decision: 'allow',
    matched_rule_id: 'existing-rule',
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

function headerValue(
  headers: HeadersInit | undefined,
  name: string,
): string | null {
  if (!headers) {
    return null;
  }
  if (headers instanceof Headers) {
    return headers.get(name);
  }
  if (Array.isArray(headers)) {
    return (
      headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ??
      null
    );
  }
  const match = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  );
  return match?.[1] ?? null;
}
