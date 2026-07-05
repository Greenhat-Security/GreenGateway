import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  PrincipalDetailResponse,
  PrincipalRecord,
} from '../lib/principals';
import type { DiscoverySignal } from '../lib/signals';
import { PrincipalDetail } from './PrincipalDetail';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('PrincipalDetail', () => {
  it('renders the principal summary, endpoint, rule, signal, and tool sections', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        200,
        principalDetailResponse({
          principal: principalRecord({
            subject: 'alice',
            issuer: 'https://idp.example',
            auth_method: 'bearer',
            email: 'alice@example.test',
            org_id: 'org-a',
            request_count: 42,
          }),
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderPrincipalDetail(
      '/identities/detail?subject=alice&issuer=https%3A%2F%2Fidp.example&auth_method=bearer',
    );

    expect(
      await screen.findByRole('heading', { level: 2, name: 'alice' }),
    ).toBeTruthy();
    expect(screen.getByText('Bearer').className).toContain('badge');
    expect(screen.getAllByText('https://idp.example').length).toBeGreaterThan(0);
    expect(screen.getByText('alice@example.test')).toBeTruthy();
    expect(screen.getByText('org-a')).toBeTruthy();
    expect(screen.getByText('42 requests')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Endpoints touched' })).toBeTruthy();
    expect(screen.getByText('/v1/widgets')).toBeTruthy();
    expect(screen.getByText('4 requests')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Rules hit' })).toBeTruthy();
    expect(
      screen.getByRole('link', { name: 'support-read' }).getAttribute('href'),
    ).toBe('/policy/rules/editor?rule_id=support-read');
    expect(screen.getByRole('heading', { name: 'Signals raised' })).toBeTruthy();
    expect(screen.getByText('principal_new_to_endpoint')).toBeTruthy();
    expect(screen.getByText('open').className).toContain('badge');
    expect(
      screen.getByTestId('principal-signal-evidence-signal-1').textContent,
    ).toContain('"threshold": 1');
    expect(screen.getByRole('heading', { name: 'Tools called' })).toBeTruthy();
    expect(
      screen.getByText('No tool calls recorded for this principal yet.'),
    ).toBeTruthy();

    const url = new URL(String(fetchMock.mock.calls[0][0]), 'http://localhost');
    expect(url.pathname).toBe('/v1/admin/principal');
    expect(url.searchParams.get('subject')).toBe('alice');
    expect(url.searchParams.get('issuer')).toBe('https://idp.example');
    expect(url.searchParams.get('auth_method')).toBe('bearer');
  });

  it('links to a deny rule prefilled for the current principal', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          principalDetailResponse({
            principal: principalRecord({
              subject: 'alice/prod@example.test',
              auth_method: 'service_token',
            }),
          }),
        ),
      ),
    );

    renderPrincipalDetail(
      '/identities/detail?subject=alice%2Fprod%40example.test&issuer=&auth_method=service_token',
    );

    const blockLink = await screen.findByRole('link', {
      name: 'Block this principal',
    });
    expect(blockLink.getAttribute('href')).toBe(
      '/policy/rules/editor?prefill_principal_id=alice%2Fprod%40example.test&prefill_action=deny&prefill_path=%2F**',
    );
  });

  it('shows a query error without fetching when required params are missing', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    renderPrincipalDetail('/identities/detail?issuer=&auth_method=bearer');

    expect(await screen.findByText('Invalid principal query')).toBeTruthy();
    expect(
      screen.getByText(
        'Principal detail requires subject, issuer, and auth_method query parameters.',
      ),
    ).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    {
      status: 403,
      body: { error: 'forbidden' },
      heading: 'Principal detail permission required',
      message: 'This token is valid but does not include admin:principals:read.',
    },
    {
      status: 404,
      body: { error: 'principal was not found' },
      heading: 'Principal not found',
      message: 'principal was not found',
    },
  ])(
    'renders a distinct $status error state',
    async ({ status, body, heading, message }) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(jsonResponse(status, body)),
      );

      renderPrincipalDetail();

      expect(await screen.findByText(heading)).toBeTruthy();
      expect(screen.getByText(message)).toBeTruthy();
    },
  );

  it('shows the principal-directory unavailable state when storage is not configured', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(404, {
          error:
            'principal directory requires PRINCIPAL_SQLITE_PATH to be configured',
        }),
      ),
    );

    renderPrincipalDetail();

    expect(await screen.findByText('Principal directory unavailable')).toBeTruthy();
    expect(
      screen.getByText(
        'principal directory requires PRINCIPAL_SQLITE_PATH to be configured',
      ),
    ).toBeTruthy();
  });

  it('renders a network error state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));

    renderPrincipalDetail();

    expect(await screen.findByText('Request failed')).toBeTruthy();
    expect(screen.getByText('Network request failed: offline')).toBeTruthy();
  });

  it('renders empty states for endpoints, rules, signals, and tools', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          principalDetailResponse({
            endpoints_touched: [],
            rules_hit: [],
            anomaly_history: [],
            tools_called: [],
          }),
        ),
      ),
    );

    renderPrincipalDetail();

    expect(
      await screen.findByRole('heading', { level: 2, name: 'alice' }),
    ).toBeTruthy();
    expect(
      screen.getByText('No endpoints recorded for this principal.'),
    ).toBeTruthy();
    expect(
      screen.getByText('No rule hits recorded for this principal.'),
    ).toBeTruthy();
    expect(screen.getByText('No signals raised for this principal.')).toBeTruthy();
    expect(
      screen.getByText('No tool calls recorded for this principal yet.'),
    ).toBeTruthy();
  });
});

function renderPrincipalDetail(
  initialEntry = '/identities/detail?subject=alice&issuer=&auth_method=bearer',
) {
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <PrincipalDetail />
    </MemoryRouter>,
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

function principalDetailResponse(
  overrides: Partial<PrincipalDetailResponse> = {},
): PrincipalDetailResponse {
  return {
    principal: principalRecord(),
    endpoints_touched: [
      {
        method: 'GET',
        path: '/v1/widgets',
        request_count: 4,
        last_seen: '2026-07-04T10:00:00Z',
      },
    ],
    rules_hit: ['support-read'],
    anomaly_history: [discoverySignal()],
    tools_called: [],
    ...overrides,
  };
}

function principalRecord(
  overrides: Partial<PrincipalRecord> = {},
): PrincipalRecord {
  return {
    subject: 'alice',
    issuer: '',
    auth_method: 'bearer',
    email: 'alice@example.test',
    org_id: 'org-a',
    first_seen: '2026-07-04T08:00:00Z',
    last_seen: '2026-07-04T10:00:00Z',
    request_count: 10,
    ...overrides,
  };
}

function discoverySignal(
  overrides: Partial<DiscoverySignal> = {},
): DiscoverySignal {
  return {
    id: 'signal-1',
    signal_type: 'principal_new_to_endpoint',
    target: {
      kind: 'principal_endpoint',
      identity: {
        method: 'GET',
        endpoint_template: '/v1/widgets',
        principal: 'alice',
      },
    },
    explanation:
      'Principal new to endpoint: principal alice first accessed GET /v1/widgets after 1 other distinct principal had already been observed.',
    evidence: {
      observed_at: '2026-07-04T09:30:00Z',
      principal: 'alice',
      prior_distinct_principal_count: 1,
      threshold: 1,
    },
    state: 'open',
    created_at: '2026-07-04T09:30:00Z',
    updated_at: '2026-07-04T09:30:00Z',
    transitioned_at: null,
    transitioned_by: null,
    ...overrides,
  };
}
