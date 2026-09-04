import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ConnectionContractError,
  createConnection,
  deleteConnection,
  getConnection,
  listConnections,
  refreshConnection,
  testConnection,
  updateConnection,
  type ConnectionWrite,
} from './connections';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('connections API client', () => {
  it('lists connections with server filters, actions, cursor, and collection ETag', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        expect(url.pathname).toBe('/v1/admin/connections');
        expect(Object.fromEntries(url.searchParams)).toEqual({
          enabled: 'true',
          kind: 'mcp_streamable_http',
          source: 'managed',
          state: 'healthy',
          limit: '25',
          cursor: 'opaque cursor',
        });
        return Promise.resolve(
          jsonResponse(
            200,
            {
              connections: [],
              actions: {
                can_create: true,
                can_bind_secret: true,
                can_manage_secrets: true,
              },
              omitted_legacy_projection_count: 0,
            },
            {
              ETag: '"connections:current"',
              'x-greengateway-connections-etag': '"connections:current"',
            },
          ),
        );
      }),
    );

    const result = await listConnections({
      enabled: true,
      kind: 'mcp_streamable_http',
      source: 'managed',
      state: 'healthy',
      limit: 25,
      cursor: 'opaque cursor',
    });

    expect(result.value.actions.can_create).toBe(true);
    expect(result.value.actions.can_manage_secrets).toBe(true);
    expect(result.collectionEtag).toBe('"connections:current"');
  });

  it('gets a connection by an encoded opaque ID and captures its exact ETag', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        expect(new URL(String(input), 'http://localhost').pathname).toBe(
          '/v1/admin/connections/connection%2Fone',
        );
        return Promise.resolve(
          jsonResponse(200, connectionDetail(), {
            ETag: '"connection:v3"',
          }),
        );
      }),
    );

    const result = await getConnection('connection/one');
    expect(result.value.id).toBe('connection/one');
    expect(result.etag).toBe('"connection:v3"');

    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            ...connectionDetail(),
            id: 'different-connection',
          }),
        ),
      ),
    );
    await expect(getConnection('connection/one')).rejects.toMatchObject({
      name: ConnectionContractError.name,
      requiresReload: false,
    });
  });

  it('projects list responses onto fresh safe summaries', async () => {
    const canary = 'UNEXPECTED_CONNECTION_LIST_SECRET_CANARY';
    const tainted = connectionDetailWithCanary(canary);
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            connections: [
              {
                ...tainted,
                sanitized_origin: 'https://billing.example.test',
                capability_count: 3,
                last_test_at: '2026-07-29T12:00:00Z',
                last_refresh_at: null,
              },
            ],
            next_cursor: 'opaque-next-cursor',
            omitted_legacy_projection_count: 2,
            actions: {
              can_create: true,
              can_bind_secret: true,
              can_manage_secrets: true,
              value: canary,
              ciphertext: canary,
            },
            locator: canary,
          }),
        ),
      ),
    );

    const result = await listConnections();

    expect(result.value.connections[0]).toMatchObject({
      id: 'connection/one',
      sanitized_origin: 'https://billing.example.test',
      capability_count: 3,
      actions: { can_manage_secrets: false },
    });
    expect(result.value.connections[0]).not.toHaveProperty('configuration');
    expect(result.value.actions).not.toHaveProperty('value');
    expect(JSON.stringify(result.value)).not.toContain(canary);
  });

  it('projects get, create, and update responses onto fresh safe details', async () => {
    const canary = 'UNEXPECTED_CONNECTION_DETAIL_SECRET_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        Promise.resolve(
          jsonResponse(
            init?.method === 'POST' ? 201 : 200,
            connectionDetailWithCanary(canary),
            init?.method === 'POST'
              ? {
                  ETag: '"connection:created"',
                  'x-greengateway-connections-etag':
                    '"collection:v2"',
                }
              : init?.method === 'PUT'
                ? { ETag: '"connection:updated"' }
                : {},
          ),
        ),
      ),
    );

    const write = connectionWrite();
    const resources = [
      await getConnection('connection/one'),
      await createConnection(write, '"collection:v1"'),
      await updateConnection(
        'connection/one',
        write,
        '"connection:v1"',
      ),
    ];

    for (const { value } of resources) {
      expect(value.configuration?.authentication).toEqual({
        type: 'oauth2_client_credentials',
        client_id: 'billing-client',
        token_url: 'https://identity.example.test/token',
        scopes: ['billing.read'],
        audience: 'billing-api',
        resource: 'billing',
        client_auth_method: 'client_secret_basic',
        client_secret_configured: true,
      });
      expect(value.configuration?.additional_headers).toEqual([
        {
          header_name: 'cf-access-client-id',
          secret_configured: true,
        },
        {
          header_name: 'cf-access-client-secret',
          secret_configured: false,
        },
      ]);
      expect(value.configuration?.tls).toEqual({
        ca_bundle_configured: true,
        client_certificate_configured: true,
        client_private_key_configured: true,
      });
      expect(value.configuration?.endpoint).toEqual({
        base_url: 'https://billing.example.test',
        base_path: '/v1',
      });
      expect(value.dependencies).toEqual([
        { kind: 'proxy_route', consumer_id: 'billing-route' },
      ]);
      expect(value.actions.can_manage_secrets).toBe(false);
      expect(JSON.stringify(value)).not.toContain(canary);
    }
  });

  it('rejects malformed or oversized safe additional-header projections', async () => {
    const invalidLists: unknown[] = [
      {},
      Array.from({ length: 5 }, (_value, index) => ({
        header_name: `x-extra-${index}`,
        secret_configured: false,
      })),
      [{ header_name: '', secret_configured: false }],
      [{ header_name: 'x-extra', secret_configured: 'yes' }],
    ];

    for (const additionalHeaders of invalidLists) {
      const detail = connectionDetail();
      vi.stubGlobal(
        'fetch',
        vi.fn(() =>
          Promise.resolve(
            jsonResponse(200, {
              ...detail,
              configuration: {
                ...detail.configuration,
                additional_headers: additionalHeaders,
              },
            }),
          ),
        ),
      );
      await expect(getConnection('connection/one')).rejects.toMatchObject({
        name: ConnectionContractError.name,
        requiresReload: false,
      });
    }
  });

  it('projects delete, test, and refresh responses onto safe DTOs', async () => {
    const canary = 'UNEXPECTED_CONNECTION_OPERATION_SECRET_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const path = new URL(String(input), 'http://localhost').pathname;
        if (init?.method === 'DELETE') {
          return Promise.resolve(
            jsonResponse(200, {
              deleted_connection_id: 'connection-1',
              value: canary,
              ciphertext: canary,
            }),
          );
        }
        if (path.endsWith('/test')) {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                ok: false,
                state: 'unavailable',
                tested_at: '2026-07-29T12:00:00Z',
                latency_ms: 17,
                stages: [
                  {
                    name: 'authenticated',
                    outcome: 'failure',
                    reason: 'credential_unavailable',
                    locator: canary,
                  },
                ],
                private_key_value: canary,
              },
              { ETag: '"connection:v1"' },
            ),
          );
        }
        return Promise.resolve(
          jsonResponse(
            200,
            {
              connection_id: 'connection-1',
              catalog_revision: 4,
              status: {
                state: 'healthy',
                reason: 'catalog_refreshed',
                observed_at: '2026-07-29T12:00:00Z',
                catalog_entry_count: 2,
                ciphertext: canary,
              },
              total_count: 2,
              added_count: 1,
              changed_count: 1,
              removed_count: 0,
              spec_digest: 'a'.repeat(64),
              spec_revision: 3,
              registered_tool_names: [
                'billing_get',
                'billing_list',
              ],
              value: canary,
            },
            { ETag: '"connection:v1"' },
          ),
        );
      }),
    );

    const resources = [
      await deleteConnection('connection-1', '"connection:v1"'),
      await testConnection('connection-1', '"connection:v1"'),
      await refreshConnection('connection-1', '"connection:v1"'),
    ];

    expect(resources[0].value).toEqual({
      deleted_connection_id: 'connection-1',
    });
    expect(resources[1].value).toMatchObject({
      ok: false,
      stages: [
        {
          name: 'authenticated',
          outcome: 'failure',
          reason: 'credential_unavailable',
        },
      ],
    });
    expect(resources[2].value).toMatchObject({
      catalog_revision: 4,
      status: {
        state: 'healthy',
        reason: 'catalog_refreshed',
        catalog_entry_count: 2,
      },
      registered_tool_names: ['billing_get', 'billing_list'],
    });
    for (const resource of resources) {
      expect(JSON.stringify(resource.value)).not.toContain(canary);
    }

    for (const [body, request] of [
      [
        { deleted_connection_id: 'forged-connection' },
        () => deleteConnection('connection-1', '"connection:v1"'),
      ],
      [
        {
          connection_id: 'forged-connection',
          catalog_revision: 4,
          status: connectionStatus(),
          total_count: 0,
          added_count: 0,
          changed_count: 0,
          removed_count: 0,
        },
        () => refreshConnection('connection-1', '"connection:v1"'),
      ],
    ] as const) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.resolve(jsonResponse(200, body))),
      );
      await expect(request()).rejects.toMatchObject({
        name: ConnectionContractError.name,
        requiresReload: true,
      });
    }
  });

  it('requires unambiguous identities and versions after mutations', async () => {
    const detail = {
      ...connectionDetail(),
      id: 'connection-1',
    };
    const testResult = {
      ok: true,
      state: 'healthy',
      tested_at: '2026-07-29T12:00:00Z',
      latency_ms: 12,
      stages: [],
    };
    const refreshResult = {
      connection_id: 'connection-1',
      catalog_revision: 2,
      status: connectionStatus(),
      total_count: 0,
      added_count: 0,
      changed_count: 0,
      removed_count: 0,
    };
    const cases: Array<{
      body: unknown;
      headers: Record<string, string>;
      request: () => Promise<unknown>;
    }> = [
      {
        body: detail,
        headers: {
          'x-greengateway-connections-etag': '"collection:v2"',
        },
        request: () =>
          createConnection(connectionWrite(), '"collection:v1"'),
      },
      {
        body: detail,
        headers: {
          ETag: '"connection:created"',
          'x-greengateway-connections-etag': '"collection:v1"',
        },
        request: () =>
          createConnection(connectionWrite(), '"collection:v1"'),
      },
      {
        body: detail,
        headers: {},
        request: () =>
          updateConnection(
            'connection-1',
            connectionWrite(),
            '"connection:v1"',
          ),
      },
      {
        body: { ...detail, id: 'forged-connection' },
        headers: { ETag: '"connection:updated"' },
        request: () =>
          updateConnection(
            'connection-1',
            connectionWrite(),
            '"connection:v1"',
          ),
      },
      {
        body: testResult,
        headers: { ETag: '"different-connection-version"' },
        request: () =>
          testConnection('connection-1', '"connection:v1"'),
      },
      {
        body: refreshResult,
        headers: { ETag: '"different-connection-version"' },
        request: () =>
          refreshConnection('connection-1', '"connection:v1"'),
      },
    ];

    for (const contractCase of cases) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() =>
          Promise.resolve(
            jsonResponse(
              200,
              contractCase.body,
              contractCase.headers,
            ),
          ),
        ),
      );
      await expect(contractCase.request()).rejects.toMatchObject({
        name: ConnectionContractError.name,
        requiresReload: true,
      });
    }
  });

  it('rejects unsafe response origins, token URLs, and paths', async () => {
    const canary = 'UNSAFE_CONNECTION_URL_CANARY';
    const safeDetail = {
      ...connectionDetailWithCanary('UNEXPECTED_FIELD_CANARY'),
      id: 'connection-1',
    };
    const listSummary = {
      ...safeDetail,
      sanitized_origin: `https://operator:${canary}@billing.example.test`,
      capability_count: 1,
      last_test_at: null,
      last_refresh_at: null,
    };
    const unsafeCases: Array<{
      body: unknown;
      request: () => Promise<unknown>;
    }> = [
      {
        body: {
          connections: [listSummary],
          omitted_legacy_projection_count: 0,
          actions: {
            can_create: true,
            can_bind_secret: true,
            can_manage_secrets: true,
          },
        },
        request: () => listConnections(),
      },
      {
        body: {
          ...safeDetail,
          configuration: {
            ...safeDetail.configuration,
            endpoint: {
              ...safeDetail.configuration.endpoint,
              base_url: `https://billing.example.test?token=${canary}`,
            },
          },
        },
        request: () => getConnection('connection-1'),
      },
      {
        body: {
          ...safeDetail,
          configuration: {
            ...safeDetail.configuration,
            authentication: {
              ...safeDetail.configuration.authentication,
              token_url:
                `https://client:${canary}@identity.example.test/token`,
            },
          },
        },
        request: () => getConnection('connection-1'),
      },
      {
        body: {
          ...safeDetail,
          configuration: {
            ...safeDetail.configuration,
            endpoint: {
              ...safeDetail.configuration.endpoint,
              base_path: `/v1/%2e%2e/${canary}`,
            },
          },
        },
        request: () => getConnection('connection-1'),
      },
      {
        body: {
          ...safeDetail,
          configuration: {
            ...safeDetail.configuration,
            test_profile: {
              ...safeDetail.configuration.test_profile,
              method: 'POST',
            },
          },
        },
        request: () => getConnection('connection-1'),
      },
      {
        body: {
          ...safeDetail,
          configuration: {
            ...safeDetail.configuration,
            test_profile: {
              ...safeDetail.configuration.test_profile,
              expected_statuses: [600],
            },
          },
        },
        request: () => getConnection('connection-1'),
      },
    ];

    for (const unsafeCase of unsafeCases) {
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.resolve(jsonResponse(200, unsafeCase.body))),
      );
      await expect(unsafeCase.request()).rejects.toThrow(
        'invalid',
      );
    }
  });

  it('opens a connection whose persisted test profile uses the legacy OPTIONS method', async () => {
    // The managed store validates persisted records with `allow_legacy_options`,
    // so a connection created under an early release keeps serving
    // `test_profile.method: "OPTIONS"` on read even though writes refuse it.
    // Rejecting it here rejected the entire connection response, which left the
    // detail page and the editor permanently unopenable for that connection.
    const detail = {
      ...connectionDetailWithCanary('UNEXPECTED_FIELD_CANARY'),
      id: 'connection-1',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            ...detail,
            configuration: {
              ...detail.configuration,
              test_profile: {
                ...detail.configuration.test_profile,
                method: 'OPTIONS',
              },
            },
          }),
        ),
      ),
    );

    const result = await getConnection('connection-1');

    expect(result.value.configuration?.test_profile?.method).toBe(
      'OPTIONS',
    );
  });

  it('uses exact ETags and valid media types for every mutation', async () => {
    const calls: Array<{
      path: string;
      method: string | undefined;
      contentType: string | null;
      ifMatch: string | null;
      body: string | null;
    }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        calls.push({
          path: url.pathname,
          method: init?.method,
          contentType: new Headers(init?.headers).get('Content-Type'),
          ifMatch: new Headers(init?.headers).get('If-Match'),
          body: typeof init?.body === 'string' ? init.body : null,
        });

        if (init?.method === 'DELETE') {
          return Promise.resolve(
            jsonResponse(200, { deleted_connection_id: 'connection-1' }),
          );
        }
        if (url.pathname.endsWith('/test')) {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                ok: true,
                state: 'healthy',
                tested_at: '2026-07-29T12:00:00Z',
                latency_ms: 12,
                stages: [],
              },
              { ETag: '"connection:v2"' },
            ),
          );
        }
        if (url.pathname.endsWith('/refresh')) {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                connection_id: 'connection-1',
                catalog_revision: 2,
                status: connectionStatus(),
                total_count: 3,
                added_count: 1,
                changed_count: 0,
                removed_count: 0,
              },
              { ETag: '"connection:v2"' },
            ),
          );
        }
        return Promise.resolve(
          jsonResponse(
            init?.method === 'POST' ? 201 : 200,
            { ...connectionDetail(), id: 'connection-1' },
            init?.method === 'POST'
              ? {
                  ETag: '"connection:created"',
                  'x-greengateway-connections-etag':
                    '"collection:v2"',
                }
              : { ETag: '"connection:updated"' },
          ),
        );
      }),
    );

    const write = connectionWrite();
    await createConnection(write, '"collection:v1"');
    await updateConnection('connection-1', write, '"connection:v1"');
    await deleteConnection('connection-1', '"connection:v2"');
    await testConnection('connection-1', '"connection:v2"');
    await refreshConnection('connection-1', '"connection:v2"');

    expect(calls.map(({ path, method, ifMatch }) => ({ path, method, ifMatch }))).toEqual([
      {
        path: '/v1/admin/connections',
        method: 'POST',
        ifMatch: '"collection:v1"',
      },
      {
        path: '/v1/admin/connections/connection-1',
        method: 'PUT',
        ifMatch: '"connection:v1"',
      },
      {
        path: '/v1/admin/connections/connection-1',
        method: 'DELETE',
        ifMatch: '"connection:v2"',
      },
      {
        path: '/v1/admin/connections/connection-1/test',
        method: 'POST',
        ifMatch: '"connection:v2"',
      },
      {
        path: '/v1/admin/connections/connection-1/refresh',
        method: 'POST',
        ifMatch: '"connection:v2"',
      },
    ]);
    expect(calls.map((call) => call.contentType)).toEqual([
      'application/json',
      'application/json',
      null,
      'application/json',
      'application/json',
    ]);
    expect(JSON.parse(calls[0].body ?? '')).toEqual(write);
    expect(JSON.parse(calls[1].body ?? '')).toEqual(write);
    expect(calls.slice(2).every((call) => call.body === null)).toBe(true);
  });
});

function connectionWrite(): ConnectionWrite {
  return {
    display_name: 'Billing API',
    enabled: false,
    kind: 'http_api',
    endpoint: {
      base_url: 'https://billing.example.test',
      base_path: '/v1',
    },
    authentication: { type: 'none' },
    tls: {},
    test_profile: {
      method: 'HEAD',
      path: '/ready',
      expected_statuses: [200],
    },
  };
}

function connectionStatus() {
  return {
    state: 'configured',
    reason: 'not_tested',
  };
}

function connectionDetail() {
  return {
    id: 'connection/one',
    display_name: 'Billing API',
    enabled: false,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'none',
    endpoint_count: 1,
    sanitized_origin: 'https://billing.example.test',
    capability_count: 0,
    last_test_at: null,
    last_refresh_at: null,
    revisions: {
      connection: 1,
      credential: 1,
      tls: 1,
      discovery: 1,
      status: 1,
    },
    status: connectionStatus(),
    configuration: {
      endpoint: {
        base_url: 'https://billing.example.test',
        base_path: '/v1',
      },
      authentication: { type: 'none' },
      tls: {
        ca_bundle_configured: false,
        client_certificate_configured: false,
        client_private_key_configured: false,
      },
    },
    dependencies: [],
    actions: {
      can_update: true,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: true,
      can_refresh: false,
      can_delete: true,
    },
  };
}

function connectionDetailWithCanary(canary: string) {
  const detail = connectionDetail();
  return {
    ...detail,
    authentication: 'oauth2_client_credentials',
    value: canary,
    ciphertext: canary,
    locator: canary,
    private_key_value: canary,
    revisions: {
      ...detail.revisions,
      value: canary,
    },
    status: {
      ...detail.status,
      observed_at: '2026-07-29T12:00:00Z',
      latency_ms: 12,
      catalog_age_secs: 30,
      catalog_entry_count: 3,
      ciphertext: canary,
    },
    configuration: {
      description: 'Billing service',
      endpoint: {
        base_url: 'https://billing.example.test',
        base_path: '/v1',
        value: canary,
      },
      authentication: {
        type: 'oauth2_client_credentials',
        client_id: 'billing-client',
        token_url: 'https://identity.example.test/token',
        scopes: ['billing.read'],
        audience: 'billing-api',
        resource: 'billing',
        client_auth_method: 'client_secret_basic',
        client_secret_configured: true,
        client_secret_id: canary,
        value: canary,
        ciphertext: canary,
        locator: canary,
      },
      additional_headers: [
        {
          header_name: 'cf-access-client-id',
          secret_configured: true,
          secret_id: canary,
          value: canary,
        },
        {
          header_name: 'cf-access-client-secret',
          secret_configured: false,
          secret_id: canary,
          ciphertext: canary,
        },
      ],
      tls: {
        ca_bundle_configured: true,
        client_certificate_configured: true,
        client_private_key_configured: true,
        private_key_value: canary,
        locator: canary,
      },
      timeouts: {
        connect_timeout_ms: 1_000,
        request_timeout_ms: 5_000,
        response_idle_timeout_ms: 2_000,
        value: canary,
      },
      discovery: {
        type: 'managed_openapi',
        path: '/openapi.json',
        use_connection_authentication: true,
        ciphertext: canary,
      },
      test_profile: {
        method: 'HEAD',
        path: '/ready',
        expected_statuses: [200, 204],
        locator: canary,
      },
      private_key_value: canary,
    },
    dependencies: [
      {
        kind: 'proxy_route',
        consumer_id: 'billing-route',
        value: canary,
      },
    ],
    actions: {
      ...detail.actions,
      ciphertext: canary,
    },
    created_at: '2026-07-28T12:00:00Z',
    updated_at: '2026-07-29T12:00:00Z',
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
