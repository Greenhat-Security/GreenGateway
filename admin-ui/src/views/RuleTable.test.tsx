import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import type { PolicyDocument, PolicyRule } from '../lib/policy';
import { RuleTable } from './RuleTable';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('RuleTable', () => {
  it('renders policy rules with action badges, hit counts, enabled state, and the default action', async () => {
    const fetcher = policyFetchMock({
      policy: policyDocument({
        default_action: 'deny',
        rules: [
          rule({
            id: 'allow-billing',
            methods: ['GET', 'HEAD'],
            path: '/billing/{id}',
            principal: { roles: ['billing-reader'] },
            action: 'allow',
          }),
          rule({
            id: 'shadow-admin',
            methods: ['POST'],
            path: '/admin/**',
            principal: {},
            action: 'shadow',
            enabled: false,
          }),
          rule({
            id: 'deny-public',
            methods: [],
            path: '/public/**',
            principal: {},
            action: 'deny',
          }),
        ],
      }),
      hits: {
        'allow-billing': 12,
        'shadow-admin': 0,
        'deny-public': 4,
      },
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderRuleTable();

    expect(await screen.findByText('Default action: Deny')).toBeTruthy();
    expect(screen.getByText('role: billing-reader')).toBeTruthy();
    expect(screen.getAllByText('any principal')).toHaveLength(2);
    expect(screen.getByText('/billing/{id}')).toBeTruthy();
    expect(screen.getByText('12 hits')).toBeTruthy();
    expect(screen.getByText('never matched')).toBeTruthy();
    expect(screen.getByRole('switch', { name: 'Disable rule allow-billing' })).toBeTruthy();
    expect(
      screen.getByRole('switch', { name: 'Enable rule shadow-admin' }).getAttribute('aria-checked'),
    ).toBe('false');

    expect(screen.getByText('Allow').className).toContain('success');
    expect(screen.getByText('Shadow').className).toContain('warning');
    expect(screen.getByText('Deny').className).toContain('danger');
  });

  it('disables write controls after a policy write permission denial', async () => {
    const fetcher = policyFetchMock({
      policy: policyDocument({
        rules: [rule({ id: 'deny-admin', path: '/admin/**', action: 'deny' })],
      }),
      patchStatus: 403,
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderRuleTable();

    const toggle = await screen.findByRole('switch', {
      name: 'Disable rule deny-admin',
    });
    fireEvent.click(toggle);

    expect(await screen.findByText('Policy write permission required')).toBeTruthy();
    expect((toggle as HTMLButtonElement).disabled).toBe(true);
    expect(
      (
        screen.getByRole('button', {
          name: 'Delete rule deny-admin',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });

  it('sends a full rule-id permutation when a row is dropped before another row', async () => {
    const fetcher = policyFetchMock({
      policy: policyDocument({
        rules: [
          rule({ id: 'first', path: '/first', action: 'allow' }),
          rule({ id: 'second', path: '/second', action: 'deny' }),
          rule({ id: 'third', path: '/third', action: 'shadow' }),
        ],
      }),
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderRuleTable();

    const dragged = await screen.findByTestId('rule-row-third');
    const target = screen.getByTestId('rule-row-first');
    fireEvent.dragStart(dragged);
    fireEvent.dragOver(target);
    fireEvent.drop(target);

    await waitFor(() => {
      expect(fetcher.reorderBodies).toEqual([['third', 'first', 'second']]);
    });
    expect(fetcher.reorderHeaders[0]).toBe('"etag-initial"');
  });
});

function renderRuleTable() {
  render(
    <MemoryRouter>
      <RuleTable />
    </MemoryRouter>,
  );
}

function policyFetchMock({
  policy,
  hits = {},
  patchStatus = 200,
}: {
  policy: PolicyDocument;
  hits?: Record<string, number>;
  patchStatus?: number;
}) {
  let currentPolicy = policy;
  let currentEtag = '"etag-initial"';
  const reorderBodies: string[][] = [];
  const reorderHeaders: Array<string | null> = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, currentPolicy, { ETag: currentEtag }));
    }

    if (url.pathname === '/v1/admin/policy/rules/hits') {
      return Promise.resolve(
        jsonResponse(200, {
          rules: Object.entries(hits).map(([rule_id, ruleHits]) => ({
            rule_id,
            hits: ruleHits,
          })),
        }),
      );
    }

    if (
      url.pathname.startsWith('/v1/admin/policy/rules/') &&
      init?.method === 'PATCH'
    ) {
      if (patchStatus !== 200) {
        return Promise.resolve(jsonResponse(patchStatus, { error: 'forbidden' }));
      }
      const ruleId = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      const patch = JSON.parse(String(init.body)) as Partial<PolicyRule>;
      const updatedRule = currentPolicy.rules.find((item) => item.id === ruleId);
      if (!updatedRule) {
        return Promise.resolve(jsonResponse(404, { error: 'missing' }));
      }
      Object.assign(updatedRule, patch);
      currentEtag = '"etag-patch"';
      return Promise.resolve(jsonResponse(200, updatedRule, { ETag: currentEtag }));
    }

    if (url.pathname === '/v1/admin/policy/rules/order' && init?.method === 'PUT') {
      reorderBodies.push(JSON.parse(String(init.body)) as string[]);
      reorderHeaders.push(requestHeader(init.headers, 'If-Match'));
      const order = reorderBodies[reorderBodies.length - 1];
      currentPolicy = {
        ...currentPolicy,
        rules: order
          .map((id) => currentPolicy.rules.find((item, index) => (item.id ?? String(index)) === id))
          .filter((item): item is PolicyRule => Boolean(item)),
      };
      currentEtag = '"etag-reorder"';
      return Promise.resolve(jsonResponse(200, { order }, { ETag: currentEtag }));
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, reorderBodies, reorderHeaders };
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
    roles: {},
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
    action: 'allow',
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
