import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminApiError } from './api';
import {
  CapabilityContractError,
  getCapability,
  listCapabilityInventory,
} from './capabilityInventory';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('capability inventory API client', () => {
  it('encodes every supported inventory filter and preserves the collection ETag', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        expect(url.pathname).toBe('/v1/admin/tools');
        expect(Object.fromEntries(url.searchParams)).toEqual({
          kind: 'tool',
          connection_id: 'connection/one',
          source: 'mcp_discovery',
          available: 'false',
          availability: 'stale',
          text: 'billing',
          limit: '30',
          cursor: 'opaque cursor',
        });
        return Promise.resolve(
          jsonResponse(
            200,
            {
              capabilities: [capabilitySummary()],
              next_cursor: 'next',
              total_count: 1,
            },
            { ETag: '"capabilities:v3"' },
          ),
        );
      }),
    );

    const result = await listCapabilityInventory({
      kind: 'tool',
      connectionId: 'connection/one',
      source: 'mcp_discovery',
      available: false,
      availability: 'stale',
      text: '  billing  ',
      limit: 30,
      cursor: 'opaque cursor',
    });

    expect(result.etag).toBe('"capabilities:v3"');
    expect(result.value.capabilities[0].source).toEqual({
      type: 'mcp_discovery',
      connection_id: 'connection/one',
      remote_tool_name: 'billing.get',
    });
  });

  it('loads a capability detail by encoded opaque ID', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        expect(new URL(String(input), 'http://localhost').pathname).toBe(
          '/v1/admin/tools/cap_abc%2Fdef',
        );
        expect(init?.cache).toBe('no-store');
        return Promise.resolve(
          jsonResponse(200, {
            ...capabilitySummary(),
            id: 'cap_abc/def',
            input_json_schema: { type: 'object' },
            mapping: {
              type: 'mcp',
              remote_tool_name: 'billing.get',
            },
            actions: capabilityActions(),
          }),
        );
      }),
    );

    const result = await getCapability('cap_abc/def');
    expect(result.value.mapping).toEqual({
      type: 'mcp',
      remote_tool_name: 'billing.get',
    });
  });

  it('projects list and detail responses onto fresh safe DTOs', async () => {
    const canary = 'UNEXPECTED_CAPABILITY_RESPONSE_CANARY';
    const summary = {
      ...capabilitySummary(),
      value: canary,
      ciphertext: canary,
      locator: canary,
      source: {
        ...capabilitySummary().source,
        private_key_value: canary,
      },
      connection: {
        ...capabilitySummary().connection,
        value: canary,
      },
      state: {
        ...capabilitySummary().state,
        ciphertext: canary,
      },
      policy: {
        ...capabilitySummary().policy,
        locator: canary,
      },
    };
    const responses = [
      jsonResponse(200, {
        capabilities: [summary],
        total_count: 1,
        value: canary,
      }),
      jsonResponse(200, {
        ...summary,
        input_json_schema: {
          type: 'object',
          properties: {
            invoice_id: { type: 'string' },
          },
        },
        mapping: {
          type: 'http',
          method: 'GET',
          path_template: '/invoices/{invoice_id}',
          query_params: [
            {
              arg_name: 'expand',
              query_name: 'expand',
              required: false,
              ciphertext: canary,
            },
          ],
          body: { mode: 'whole_args_json', locator: canary },
          private_key_value: canary,
        },
        actions: {
          ...capabilityActions(),
          ciphertext: canary,
        },
      }),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(responses.shift() as Response)),
    );

    const list = await listCapabilityInventory();
    const detail = await getCapability('cap_abc');

    expect(list.value.capabilities[0]).toEqual(capabilitySummary());
    expect(detail.value.mapping).toEqual({
      type: 'http',
      method: 'GET',
      path_template: '/invoices/{invoice_id}',
      query_params: [
        {
          arg_name: 'expand',
          query_name: 'expand',
          required: false,
        },
      ],
      body: { mode: 'whole_args_json' },
    });
    expect(detail.value.input_json_schema).toEqual({
      type: 'object',
      properties: {
        invoice_id: { type: 'string' },
      },
    });
    expect(JSON.stringify(list.value)).not.toContain(canary);
    expect(JSON.stringify(detail.value)).not.toContain(canary);
  });

  it('rejects malformed identities, nested contracts, mappings, and bounded schemas', async () => {
    let deepSchema: unknown = { type: 'string' };
    for (let depth = 0; depth < 130; depth += 1) {
      deepSchema = { allOf: [deepSchema] };
    }

    const cases: Array<{
      id?: string;
      body: unknown;
    }> = [
      {
        body: {
          capabilities: 'not-an-array',
          total_count: 0,
        },
      },
      {
        body: {
          capabilities: [capabilitySummary(), capabilitySummary()],
          total_count: 2,
        },
      },
      {
        body: {
          capabilities: [
            {
              ...capabilitySummary(),
              source: { type: 'untrusted_source' },
            },
          ],
          total_count: 1,
        },
      },
      {
        body: {
          capabilities: [
            {
              ...capabilitySummary(),
              connection: {
                ...capabilitySummary().connection,
                id: 'different-connection',
              },
            },
          ],
          total_count: 1,
        },
      },
      {
        body: {
          capabilities: [
            {
              ...capabilitySummary(),
              state: {
                ...capabilitySummary().state,
                reason: 17,
              },
            },
          ],
          total_count: 1,
        },
      },
      {
        id: 'cap_abc',
        body: {
          ...capabilitySummary(),
          id: 'different-capability',
          actions: capabilityActions(),
        },
      },
      {
        id: 'cap_abc',
        body: {
          ...capabilitySummary(),
        },
      },
      {
        id: 'cap_abc',
        body: {
          ...capabilitySummary(),
          actions: {
            can_execute: true,
            reason: 'stale',
          },
        },
      },
      {
        id: 'cap_abc',
        body: {
          ...capabilitySummary(),
          actions: capabilityActions(),
          mapping: {
            type: 'http',
            method: 'BREW',
            path_template: '/invoices',
            query_params: [],
          },
        },
      },
      {
        id: 'cap_abc',
        body: {
          ...capabilitySummary(),
          actions: capabilityActions(),
          input_json_schema: deepSchema,
        },
      },
    ];

    for (const contractCase of cases) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() =>
          Promise.resolve(jsonResponse(200, contractCase.body)),
        ),
      );
      const request =
        contractCase.id === undefined
          ? listCapabilityInventory()
          : getCapability(contractCase.id);
      await expect(request).rejects.toBeInstanceOf(CapabilityContractError);
    }
  });

  it('surfaces a stale cursor as a 412 with the current inventory ETag', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            412,
            { error: 'capability inventory cursor is stale' },
            { ETag: '"capabilities:current"' },
          ),
        ),
      ),
    );

    const error = await listCapabilityInventory({ cursor: 'stale' }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(AdminApiError);
    expect(error).toMatchObject({
      status: 412,
      code: 'precondition_failed',
      etag: '"capabilities:current"',
    });
  });
});

function capabilitySummary() {
  return {
    id: 'cap_abc',
    kind: 'tool',
    name: 'billing.get',
    description_truncated: false,
    source: {
      type: 'mcp_discovery',
      connection_id: 'connection/one',
      remote_tool_name: 'billing.get',
    },
    connection: {
      id: 'connection/one',
      kind: 'mcp_streamable_http',
      management_source: 'managed',
    },
    state: {
      enabled: true,
      available: true,
      stale: false,
      reason: 'available',
    },
    policy: {
      eligible: true,
      reason: 'eligible',
    },
  };
}

function capabilityActions() {
  return {
    can_execute: true,
    reason: 'allowed',
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
