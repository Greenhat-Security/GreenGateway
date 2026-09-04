import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { StrictMode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  CapabilityDetail as CapabilityDetailRecord,
  CapabilitySummary,
} from '../lib/capabilityInventory';
import {
  CapabilityDetail,
  CapabilityInventoryView,
} from './CapabilityInventoryView';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CapabilityInventoryView', () => {
  it.each([
    {
      capabilities: [
        capabilitySummary({
          id: `cap_${'1'.repeat(64)}`,
          name: 'first.tool',
        }),
      ],
      totalCount: 1,
      announcement: '1 capability matched these filters.',
    },
    {
      capabilities: [],
      totalCount: 0,
      announcement:
        'Capability inventory loaded. No capabilities matched these filters.',
    },
  ])(
    'announces the first-page result count when total_count is $totalCount',
    async ({ capabilities, totalCount, announcement }) => {
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              200,
              capabilityPage(capabilities, null, totalCount),
            ),
          ),
      );

      renderInventory();

      await waitFor(() =>
        expect(screen.getByRole('status').textContent).toBe(announcement),
      );
    },
  );

  it('renders typed provenance, runtime, and policy state from the server', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        200,
        capabilityPage([
          capabilitySummary({
            id: `cap_${'a'.repeat(64)}`,
            name: 'billing.lookup',
            title: 'Look up invoice',
            description: 'Returns one invoice.',
            annotations: {
              readOnlyHint: true,
              destructiveHint: false,
            },
            source: {
              type: 'openapi',
              connection_id: 'billing-prod',
              operation_id: 'lookupInvoice',
              catalog_revision: 3,
              spec_revision: 7,
              spec_digest: 'sha256:spec',
            },
            state: {
              enabled: true,
              available: false,
              stale: true,
              reason: 'catalog_stale',
            },
            policy: {
              eligible: true,
              reason: 'allowed',
            },
          }),
        ]),
        { ETag: '"capabilities:sha256:first"' },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderInventory();

    const link = await screen.findByRole('link', {
      name: 'View detail for Look up invoice',
    });
    const row = link.closest('tr');
    expect(row).not.toBeNull();
    const rowQueries = within(row as HTMLTableRowElement);
    expect(link.getAttribute('href')).toBe(`/tools/cap_${'a'.repeat(64)}`);
    expect(screen.getByText('billing.lookup')).toBeTruthy();
    expect(rowQueries.getByText('OpenAPI')).toBeTruthy();
    expect(rowQueries.getByText('lookupInvoice')).toBeTruthy();
    expect(rowQueries.getByText('Enabled')).toBeTruthy();
    expect(rowQueries.getByText('Unavailable')).toBeTruthy();
    expect(rowQueries.getByText('Stale')).toBeTruthy();
    expect(rowQueries.getByText('Eligible')).toBeTruthy();
    expect(rowQueries.getByLabelText('MCP annotations').textContent).toContain(
      'Read only: yes',
    );

    expect(
      rowQueries
        .getByText('Look up invoice')
        .closest('td')
        ?.getAttribute('data-label'),
    ).toBe('Capability');
    expect(
      rowQueries
        .getByText('Tool')
        .closest('td')
        ?.getAttribute('data-label'),
    ).toBe('Kind');

    const url = requestUrls(fetchMock)[0];
    expect(url.pathname).toBe('/v1/admin/tools');
    expect(url.searchParams.get('limit')).toBe('50');
  });

  it('applies every supported filter without inferring token permissions', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, capabilityPage([])),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderInventory();
    await screen.findByText('No capabilities matched these filters.');

    fireEvent.change(screen.getByLabelText('Search'), {
      target: { value: 'invoice' },
    });
    fireEvent.change(screen.getByLabelText('Kind'), {
      target: { value: 'tool' },
    });
    fireEvent.change(screen.getByLabelText('Connection ID'), {
      target: { value: ' billing-prod ' },
    });
    fireEvent.change(screen.getByLabelText('Source'), {
      target: { value: 'openapi' },
    });
    fireEvent.change(screen.getByLabelText('Available flag'), {
      target: { value: 'false' },
    });
    fireEvent.change(screen.getByLabelText('Availability state'), {
      target: { value: 'stale' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const url = requestUrls(fetchMock)[1];
    expect(url.searchParams.get('text')).toBe('invoice');
    expect(url.searchParams.get('kind')).toBe('tool');
    expect(url.searchParams.get('connection_id')).toBe('billing-prod');
    expect(url.searchParams.get('source')).toBe('openapi');
    expect(url.searchParams.get('available')).toBe('false');
    expect(url.searchParams.get('availability')).toBe('stale');
    expect(url.searchParams.get('cursor')).toBeNull();
  });

  it('appends an opaque cursor page', async () => {
    const first = capabilitySummary({
      id: `cap_${'1'.repeat(64)}`,
      name: 'first.tool',
    });
    const second = capabilitySummary({
      id: `cap_${'2'.repeat(64)}`,
      name: 'second.tool',
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, capabilityPage([first], 'opaque cursor', 2)),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, capabilityPage([second], null, 2)),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderInventory();
    await screen.findByText('first.tool');
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('second.tool')).toBeTruthy();
    expect(requestUrls(fetchMock)[1].searchParams.get('cursor')).toBe(
      'opaque cursor',
    );
    expect(screen.getByText('No more capabilities')).toBeTruthy();
  });

  it('discards a stale cursor and refreshes page one after a 412', async () => {
    const original = capabilitySummary({
      id: `cap_${'1'.repeat(64)}`,
      name: 'original.tool',
    });
    const refreshed = capabilitySummary({
      id: `cap_${'9'.repeat(64)}`,
      name: 'refreshed.tool',
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, capabilityPage([original], 'stale-cursor', 2)),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          412,
          {
            error:
              'capability inventory cursor does not match the current collection',
          },
          { ETag: '"capabilities:sha256:current"' },
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, capabilityPage([refreshed], null, 1)),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderInventory();
    await screen.findByText('original.tool');
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('refreshed.tool')).toBeTruthy();
    expect(screen.queryByText('original.tool')).toBeNull();
    expect(
      screen.getByText(
        'The capability inventory changed. The list was refreshed from the first page.',
      ),
    ).toBeTruthy();
    expect(requestUrls(fetchMock)[1].searchParams.get('cursor')).toBe(
      'stale-cursor',
    );
    expect(requestUrls(fetchMock)[2].searchParams.get('cursor')).toBeNull();
  });

  it.each([
    {
      status: 401,
      heading: 'Bearer token required',
      body: { error: 'missing bearer token' },
    },
    {
      status: 403,
      heading: 'Capability inventory permission required',
      body: { error: 'forbidden' },
    },
    {
      status: 503,
      heading: 'Capability inventory unavailable',
      body: { error: 'capability inventory is unavailable' },
    },
  ])(
    'announces and focuses the distinct $status list error once',
    async ({ status, heading, body }) => {
      const focusSpy = vi.spyOn(HTMLElement.prototype, 'focus');
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockImplementation(() =>
            Promise.resolve(jsonResponse(status, body)),
          ),
      );

      renderInventory(true);

      const alert = await screen.findByRole('alert', { name: heading });
      await waitFor(() => expect(document.activeElement).toBe(alert));
      expect(focusSpy).toHaveBeenCalledTimes(1);

      fireEvent.change(screen.getByLabelText('Search'), {
        target: { value: 'unrelated rerender' },
      });
      expect(focusSpy).toHaveBeenCalledTimes(1);
    },
  );

  it('clears all filter controls and reloads the unfiltered collection', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, capabilityPage([])),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderInventory();
    await screen.findByText('No capabilities matched these filters.');
    fireEvent.change(screen.getByLabelText('Search'), {
      target: { value: 'invoice' },
    });
    fireEvent.change(screen.getByLabelText('Kind'), {
      target: { value: 'resource' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect((screen.getByLabelText('Search') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Kind') as HTMLSelectElement).value).toBe('');
    const url = requestUrls(fetchMock)[1];
    expect(url.searchParams.get('text')).toBeNull();
    expect(url.searchParams.get('kind')).toBeNull();
  });
});

describe('CapabilityDetail', () => {
  it('renders safe typed provenance, mapping, schema, and server state', async () => {
    const id = `cap_${'d'.repeat(64)}`;
    const detail = capabilityDetail({
      id,
      name: 'billing.lookup',
      title: 'Look up invoice',
      annotations: {
        title: 'Invoice lookup',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      source: {
        type: 'openapi',
        connection_id: 'billing-prod',
        operation_id: 'lookupInvoice',
        catalog_revision: 3,
        spec_revision: 7,
        spec_digest: 'sha256:spec',
      },
      mapping: {
        type: 'http',
        method: 'GET',
        path_template: '/invoices/{invoice_id}',
        query_params: [
          {
            arg_name: 'invoice_id',
            query_name: 'invoiceId',
            required: true,
          },
          {
            arg_name: 'include_archived',
            query_name: 'includeArchived',
            required: false,
          },
        ],
        body: { mode: 'whole_args_json' },
      },
      input_json_schema: {
        type: 'object',
        properties: { invoice_id: { type: 'string' } },
      },
      policy: { eligible: false, reason: 'not_in_policy' },
    });
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, detail, { ETag: '"capability:detail"' }),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderDetail(`/tools/${id}`);

    expect(
      await screen.findByRole('heading', { name: 'Look up invoice' }),
    ).toBeTruthy();
    expect(screen.getByText('Not eligible')).toBeTruthy();
    expect(screen.getByText('Not in policy')).toBeTruthy();
    expect(screen.getByText('OpenAPI')).toBeTruthy();
    expect(screen.getByText('lookupInvoice')).toBeTruthy();
    expect(screen.getByText('/invoices/{invoice_id}')).toBeTruthy();
    expect(screen.getByText('Whole args json')).toBeTruthy();
    expect(screen.getByText('Invoice lookup')).toBeTruthy();
    expect(screen.getAllByText('True')).toHaveLength(2);
    expect(screen.getAllByText('False')).toHaveLength(2);
    const queryMappingTable = screen.getByRole('table', {
      name: 'Query parameter mappings',
    });
    const queryMappingRows = within(queryMappingTable).getAllByRole('row');
    expect(queryMappingRows).toHaveLength(3);
    expect(within(queryMappingRows[1]).getByText('invoice_id')).toBeTruthy();
    expect(within(queryMappingRows[1]).getByText('invoiceId')).toBeTruthy();
    expect(within(queryMappingRows[1]).getByText('Yes')).toBeTruthy();
    expect(
      within(queryMappingRows[2]).getByText('include_archived'),
    ).toBeTruthy();
    expect(within(queryMappingRows[2]).getByText('includeArchived')).toBeTruthy();
    expect(within(queryMappingRows[2]).getByText('No')).toBeTruthy();
    expect(screen.getByText(/"invoice_id"/)).toBeTruthy();
    expect(
      screen.getByRole('link', { name: 'billing-prod' }).getAttribute('href'),
    ).toBe('/connections/billing-prod');
    expect(
      screen
        .getByRole('link', { name: 'Open playground' })
        .getAttribute('href'),
    ).toBe(`/tools/${id}/playground`);
    expect(screen.queryByRole('button', { name: /invoke/i })).toBeNull();

    const url = requestUrls(fetchMock)[0];
    expect(url.pathname).toBe(`/v1/admin/tools/${id}`);
  });

  it.each([
    {
      status: 401,
      heading: 'Bearer token required',
      body: { error: 'missing bearer token' },
    },
    {
      status: 403,
      heading: 'Capability inventory permission required',
      body: { error: 'forbidden' },
    },
    {
      status: 404,
      heading: 'Capability not found',
      body: { error: 'capability was not found' },
    },
  ])(
    'announces and focuses the distinct $status detail error',
    async ({ status, heading, body }) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(jsonResponse(status, body)),
      );

      renderDetail(`/tools/cap_${'0'.repeat(64)}`);

      const alert = await screen.findByRole('alert', { name: heading });
      await waitFor(() => expect(document.activeElement).toBe(alert));
    },
  );

  it('omits the playground link and explains the server-derived disabled reason', async () => {
    const id = `cap_${'e'.repeat(64)}`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          capabilityDetail({
            id,
            actions: {
              can_execute: false,
              reason: 'policy_denied',
            },
          }),
          { ETag: '"capability:detail"' },
        ),
      ),
    );

    renderDetail(`/tools/${id}`);

    expect(await screen.findByText('Playground unavailable:')).toBeTruthy();
    expect(screen.getByText('Policy denied')).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Open playground' })).toBeNull();
  });
});

function renderInventory(strict = false) {
  const inventory = (
    <MemoryRouter initialEntries={['/tools']}>
      <CapabilityInventoryView />
    </MemoryRouter>
  );
  render(strict ? <StrictMode>{inventory}</StrictMode> : inventory);
}

function renderDetail(initialEntry: string) {
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/tools/:id" element={<CapabilityDetail />} />
      </Routes>
    </MemoryRouter>,
  );
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

function requestUrls(fetchMock: ReturnType<typeof vi.fn>): URL[] {
  return fetchMock.mock.calls.map(
    ([input]) => new URL(String(input), 'http://localhost'),
  );
}

function capabilityPage(
  capabilities: CapabilitySummary[],
  nextCursor: string | null = null,
  totalCount = capabilities.length,
) {
  return {
    capabilities,
    ...(nextCursor === null ? {} : { next_cursor: nextCursor }),
    total_count: totalCount,
  };
}

function capabilitySummary(
  overrides: Partial<CapabilitySummary> = {},
): CapabilitySummary {
  return {
    id: `cap_${'a'.repeat(64)}`,
    kind: 'tool',
    name: 'widgets.get',
    description_truncated: false,
    source: { type: 'manual_file' },
    connection: {
      id: 'billing-prod',
      kind: 'http_api',
      management_source: 'managed',
    },
    schema_digest: 'sha256:schema',
    discovered_at: '2026-07-28T10:00:00Z',
    last_success_at: '2026-07-28T10:00:00Z',
    state: {
      enabled: true,
      available: true,
      stale: false,
      reason: 'ready',
    },
    policy: {
      eligible: true,
      reason: 'allowed',
    },
    ...overrides,
  };
}

function capabilityDetail(
  overrides: Partial<CapabilityDetailRecord> = {},
): CapabilityDetailRecord {
  return {
    ...capabilitySummary(),
    mapping: {
      type: 'mcp',
      remote_tool_name: 'widgets.get',
    },
    input_json_schema: { type: 'object' },
    actions: {
      can_execute: true,
      reason: 'allowed',
    },
    ...overrides,
  };
}
