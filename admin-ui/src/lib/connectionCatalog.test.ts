import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import {
  catalogRegisterRequest,
  catalogToolRows,
  defaultCatalogSelection,
  MAX_CATALOG_SPEC_BYTES,
  previewConnectionCatalog,
  registerConnectionCatalog,
  type ConnectionCatalogPreview,
  type ConnectionCatalogRegisterRequest,
} from './connectionCatalog';
import { ConnectionContractError } from './connections';

const CONNECTION_ID = 'mail-api';
const CONNECTION_ETAG = '"connection:mail-api:c3:k1:t0:d2"';
const SPEC_DIGEST = 'd'.repeat(64);
const SPEC = '{"discoveryVersion":"v1","kind":"discovery#restDescription"}';

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
  document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/';
});

describe('connection catalog preview', () => {
  it('posts only the document with CSRF and projects the whole report', async () => {
    document.cookie = 'csrf_token=catalog-csrf; Path=/';
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(200, previewBody(), { ETag: CONNECTION_ETAG }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const preview = await previewConnectionCatalog(CONNECTION_ID, SPEC);

    const [input, init] = fetchMock.mock.calls[0];
    expect(new URL(String(input), 'http://localhost').pathname).toBe(
      '/v1/admin/connections/mail-api/openapi/preview',
    );
    expect(init?.method).toBe('POST');
    const headers = new Headers(init?.headers);
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('x-csrf-token')).toBe('catalog-csrf');
    expect(headers.has('If-Match')).toBe(false);
    // Never a candidate overlay: the stored one is the only one compiled.
    expect(JSON.parse(String(init?.body))).toEqual({ spec: SPEC });

    expect(preview.etag).toBe(CONNECTION_ETAG);
    expect(preview.value.spec_digest).toBe(SPEC_DIGEST);
    expect(preview.value.spec_revision).toBe(2);
    expect(preview.value.catalog_revision).toBe(5);
    expect(preview.value.conversion).toEqual({
      source_format: 'google_discovery_v1',
      warnings: [
        {
          code: 'global_parameter_not_mapped',
          message: 'the document-level parameter is not a tool argument',
          operation_omitted: false,
          subject: 'alt',
        },
      ],
    });
    expect(preview.value.tools.map((tool) => tool.name)).toEqual([
      'gmail.users.messages.list',
      'gmail.users.messages.get',
      'gmail.users.labels.create',
    ]);
    expect(preview.value.tools[0]).toEqual({
      name: 'gmail.users.messages.list',
      description: 'List messages',
      target_type: 'http',
      upstream: {
        method: 'GET',
        path_template: '/gmail/v1/users/{userId}/messages',
      },
      visibility: 'listed',
    });
    expect(preview.value.incompatibilities).toEqual([
      {
        tool_name: 'gmail.users.messages.trash',
        reason: 'no_compatible_security_alternative',
        security_alternatives: [
          {
            scheme_names: ['Oauth2'],
            reason: 'missing_scopes',
            message:
              'the Connection does not request every scope the operation requires',
            missing_scopes: ['https://mail.google.com/'],
          },
        ],
        unexplained_security_alternatives: 2,
      },
    ]);
    expect(preview.value.skipped_operations).toEqual([
      {
        method: 'POST',
        path_template: '/upload/gmail/v1/users/{userId}/messages',
        reason: 'unsupported_request_body',
      },
    ]);
  });

  it('drops the gateway detail text of an invalid mapping path', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            200,
            previewBody({
              incompatibilities: [
                {
                  tool_name: 'odd_path',
                  reason: 'invalid_mapping_path',
                  path_template: '/a/../b',
                  detail: 'free text from the generator',
                },
              ],
            }),
            { ETag: CONNECTION_ETAG },
          ),
        ),
      ),
    );

    const preview = await previewConnectionCatalog(CONNECTION_ID, SPEC);
    expect(preview.value.incompatibilities).toEqual([
      {
        tool_name: 'odd_path',
        reason: 'invalid_mapping_path',
        path_template: '/a/../b',
      },
    ]);
  });

  it.each<[string, (body: Record<string, unknown>) => unknown]>([
    ['a different connection', (body) => ({ ...body, connection_id: 'other-api' })],
    ['an uppercase digest', (body) => ({ ...body, spec_digest: 'D'.repeat(64) })],
    ['a short digest', (body) => ({ ...body, spec_digest: 'd'.repeat(63) })],
    ['a negative revision', (body) => ({ ...body, spec_revision: -1 })],
    ['a fractional revision', (body) => ({ ...body, catalog_revision: 1.5 })],
    ['no tools list', (body) => omit(body, 'tools')],
    ['no overlay report', (body) => omit(body, 'overlay')],
    [
      'an overlay report without applied',
      (body) => ({ ...body, overlay: omit(overlayReport(), 'applied') }),
    ],
    [
      'too many tools',
      (body) => ({
        ...body,
        tools: Array.from({ length: 4097 }, (_, index) =>
          httpTool(`tool_${index}`, 'GET', `/t/${index}`),
        ),
      }),
    ],
    [
      'duplicate tool names',
      (body) => ({
        ...body,
        tools: [
          httpTool('same', 'GET', '/a'),
          httpTool('same', 'GET', '/b'),
        ],
      }),
    ],
    [
      'a tool for another connection',
      (body) => ({
        ...body,
        tools: [
          {
            ...httpTool('elsewhere', 'GET', '/a'),
            target: {
              type: 'http',
              connection_id: 'other-api',
              mapping: { method: 'GET', path_template: '/a' },
            },
          },
        ],
      }),
    ],
    [
      'a tool without an input schema',
      (body) => ({
        ...body,
        tools: [omit(httpTool('bare', 'GET', '/a'), 'input_json_schema')],
      }),
    ],
    [
      'a relative upstream path',
      (body) => ({ ...body, tools: [httpTool('relative', 'GET', 'a')] }),
    ],
    [
      'an HTTP tool claiming the composite sentinel',
      (body) => ({ ...body, tools: [httpTool('fake', 'COMPOSITE', '/')] }),
    ],
    [
      'duplicate security confirmations',
      (body) => ({
        ...body,
        security_confirmations: [
          { tool_name: 'a', selected_scheme_names: [] },
          { tool_name: 'a', selected_scheme_names: [] },
        ],
      }),
    ],
    [
      'a confirmation naming a scheme twice',
      (body) => ({
        ...body,
        security_confirmations: [
          { tool_name: 'a', selected_scheme_names: ['Oauth2', 'Oauth2'] },
        ],
      }),
    ],
    [
      'an unknown incompatibility reason',
      (body) => ({
        ...body,
        incompatibilities: [{ tool_name: 'a', reason: 'unknown_reason' }],
      }),
    ],
    [
      'an unknown security alternative reason',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({
            security_alternatives: [
              { scheme_names: ['X'], reason: 'nearly_binds', message: 'm' },
            ],
          }),
        ],
      }),
    ],
    [
      'missing scopes on another reason',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({
            security_alternatives: [
              {
                scheme_names: ['Basic'],
                reason: 'http_basic',
                message: 'm',
                missing_scopes: ['read'],
              },
            ],
          }),
        ],
      }),
    ],
    [
      'an empty missing scopes list',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({
            security_alternatives: [
              {
                scheme_names: ['Oauth2'],
                reason: 'missing_scopes',
                message: 'm',
                missing_scopes: [],
              },
            ],
          }),
        ],
      }),
    ],
    [
      'alternatives explained for missing metadata',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({
            reason: 'missing_security_metadata',
          }),
        ],
      }),
    ],
    [
      'more than 16 explained alternatives',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({
            security_alternatives: Array.from({ length: 17 }, () => ({
              scheme_names: ['Basic'],
              reason: 'http_basic',
              message: 'm',
            })),
          }),
        ],
      }),
    ],
    [
      'zero unexplained alternatives',
      (body) => ({
        ...body,
        incompatibilities: [
          incompatibility({ unexplained_security_alternatives: 0 }),
        ],
      }),
    ],
    [
      'an unknown source format',
      (body) => ({
        ...body,
        conversion: { source_format: 'raml_1_0', warnings: [] },
      }),
    ],
    [
      'an unknown conversion warning code',
      (body) => ({
        ...body,
        conversion: {
          source_format: 'swagger_2_0',
          warnings: [
            { code: 'new_code', message: 'm', operation_omitted: false },
          ],
        },
      }),
    ],
    [
      'a conversion warning without operation_omitted',
      (body) => ({
        ...body,
        conversion: {
          source_format: 'swagger_2_0',
          warnings: [{ code: 'consumes_defaulted', message: 'm' }],
        },
      }),
    ],
    [
      'an overlong conversion subject',
      (body) => ({
        ...body,
        conversion: {
          source_format: 'swagger_2_0',
          warnings: [
            {
              code: 'invalid_parameter',
              message: 'm',
              operation_omitted: true,
              subject: 'x'.repeat(257),
            },
          ],
        },
      }),
    ],
    [
      'a skipped operation without a reason',
      (body) => ({
        ...body,
        skipped_operations: [{ method: 'GET', path_template: '/a', reason: '' }],
      }),
    ],
    [
      'an unknown name fallback reason',
      (body) => ({
        ...body,
        operation_id_fallbacks: [
          {
            method: 'GET',
            path_template: '/a',
            generated_name: 'get_a',
            reason: 'renamed',
          },
        ],
      }),
    ],
    ['an array body', () => []],
  ])('rejects a preview with %s', async (_label, mutate) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, mutate(previewBody()), { ETag: CONNECTION_ETAG }),
        ),
      ),
    );

    await expect(
      previewConnectionCatalog(CONNECTION_ID, SPEC),
    ).rejects.toMatchObject({
      name: ConnectionContractError.name,
      requiresReload: false,
    });
  });

  it.each([
    ['no ETag', {}],
    ['an ETag the body disagrees with', { ETag: '"connection:mail-api:c4"' }],
  ])('rejects a preview with %s', async (_label, headers) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(200, previewBody(), headers))),
    );

    await expect(
      previewConnectionCatalog(CONNECTION_ID, SPEC),
    ).rejects.toBeInstanceOf(ConnectionContractError);
  });

  it('refuses an empty or oversized document without sending it', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(previewConnectionCatalog(CONNECTION_ID, '')).rejects.toBeInstanceOf(
      ConnectionContractError,
    );
    // Two bytes per character: within the limit in characters, over it in
    // UTF-8 bytes, which is how the gateway measures it.
    const oversized = 'é'.repeat(MAX_CATALOG_SPEC_BYTES / 2 + 1);
    await expect(
      previewConnectionCatalog(CONNECTION_ID, oversized),
    ).rejects.toBeInstanceOf(ConnectionContractError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('connection catalog selection', () => {
  it('selects only bindable GET and HEAD tools by default', async () => {
    const preview = await projectedPreview({
      tools: [
        httpTool('list', 'GET', '/items'),
        httpTool('probe', 'HEAD', '/items'),
        httpTool('create', 'POST', '/items'),
        httpTool('unconfirmed_read', 'GET', '/other'),
      ],
      security_confirmations: [
        { tool_name: 'list', selected_scheme_names: [] },
        { tool_name: 'probe', selected_scheme_names: ['Bearer'] },
        { tool_name: 'create', selected_scheme_names: ['Bearer'] },
      ],
    });

    expect([...defaultCatalogSelection(preview)]).toEqual(['list', 'probe']);
    expect(
      catalogToolRows(preview).map((row) => [row.name, row.kind]),
    ).toEqual([
      ['list', 'bound'],
      ['probe', 'bound'],
      ['create', 'bound'],
      ['unconfirmed_read', 'unconfirmed'],
      ['gmail.users.messages.trash', 'incompatible'],
    ]);
  });

  it('confirms renamed overlay tools under their generated names', async () => {
    const preview = await projectedPreview({
      tools: [
        httpTool('inbox_list', 'GET', '/messages'),
        compositeTool('inbox_digest'),
      ],
      security_confirmations: [
        { tool_name: 'gmail.users.messages.list', selected_scheme_names: ['Oauth2'] },
      ],
      overlay: {
        ...overlayReport(),
        applied: true,
        tools: [overlayTool('gmail.users.messages.list', 'inbox_list')],
        composites: [
          { name: 'inbox_digest', steps_max: 2, policy_entry_present: true },
        ],
      },
    });

    expect([...defaultCatalogSelection(preview)]).toEqual(['inbox_list']);
    expect(catalogRegisterRequest(preview, SPEC, ['inbox_list'])).toEqual({
      spec: SPEC,
      spec_digest: SPEC_DIGEST,
      expected_spec_revision: 2,
      expected_catalog_revision: 5,
      selected_tool_names: ['gmail.users.messages.list'],
      security_confirmations: [
        {
          tool_name: 'gmail.users.messages.list',
          selected_scheme_names: ['Oauth2'],
        },
      ],
    });
    expect(() =>
      catalogRegisterRequest(preview, SPEC, ['inbox_digest']),
    ).toThrow(ConnectionContractError);
  });

  it('refuses to register an incompatible tool', async () => {
    const preview = await projectedPreview();
    expect(() =>
      catalogRegisterRequest(preview, SPEC, ['gmail.users.messages.trash']),
    ).toThrow(ConnectionContractError);
  });
});

describe('connection catalog registration', () => {
  it('sends exactly the reviewed digest, revisions and confirmations with the preview ETag', async () => {
    document.cookie = 'csrf_token=catalog-csrf; Path=/';
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse(201, publishBody(), { ETag: CONNECTION_ETAG }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const preview = await projectedPreview();
    const request = catalogRegisterRequest(preview, SPEC, [
      'gmail.users.messages.list',
      'gmail.users.messages.get',
    ]);
    const result = await registerConnectionCatalog(
      CONNECTION_ID,
      request,
      CONNECTION_ETAG,
    );

    const [input, init] = fetchMock.mock.calls[0];
    expect(new URL(String(input), 'http://localhost').pathname).toBe(
      '/v1/admin/connections/mail-api/openapi/register',
    );
    expect(init?.method).toBe('POST');
    const headers = new Headers(init?.headers);
    expect(headers.get('If-Match')).toBe(CONNECTION_ETAG);
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('x-csrf-token')).toBe('catalog-csrf');
    expect(JSON.parse(String(init?.body))).toEqual({
      spec: SPEC,
      spec_digest: SPEC_DIGEST,
      expected_spec_revision: 2,
      expected_catalog_revision: 5,
      selected_tool_names: [
        'gmail.users.messages.list',
        'gmail.users.messages.get',
      ],
      security_confirmations: [
        {
          tool_name: 'gmail.users.messages.list',
          selected_scheme_names: ['Oauth2'],
        },
        {
          tool_name: 'gmail.users.messages.get',
          selected_scheme_names: ['Oauth2'],
        },
      ],
    });
    expect(result.value).toMatchObject({
      connection_id: CONNECTION_ID,
      spec_revision: 3,
      catalog_revision: 6,
      registered_tool_names: [
        'gmail.users.messages.list',
        'gmail.users.messages.get',
      ],
      added_count: 2,
    });
    expect(result.value.status.reason).toBe('catalog_refreshed');
  });

  it.each<[string, Partial<ConnectionCatalogRegisterRequest>]>([
    ['an unconfirmed selection', { security_confirmations: [] }],
    [
      'a confirmation for an unselected tool',
      {
        selected_tool_names: ['a'],
        security_confirmations: [
          { tool_name: 'b', selected_scheme_names: [] },
        ],
      },
    ],
    [
      'a repeated selection',
      {
        selected_tool_names: ['a', 'a'],
        security_confirmations: [
          { tool_name: 'a', selected_scheme_names: [] },
        ],
      },
    ],
    ['a malformed digest', { spec_digest: 'not-a-digest' }],
    ['a negative revision', { expected_catalog_revision: -1 }],
  ])('refuses to send %s', async (_label, change) => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const request = {
      ...catalogRegisterRequest(await projectedPreview(), SPEC, [
        'gmail.users.messages.list',
      ]),
      ...change,
    };

    await expect(
      registerConnectionCatalog(CONNECTION_ID, request, CONNECTION_ETAG),
    ).rejects.toBeInstanceOf(ConnectionContractError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each<[string, Record<string, unknown>, Record<string, string>]>([
    ['no registered tool names', omit(publishBody(), 'registered_tool_names'), { ETag: CONNECTION_ETAG }],
    ['another digest', { ...publishBody(), spec_digest: 'e'.repeat(64) }, { ETag: CONNECTION_ETAG }],
    ['another connection', { ...publishBody(), connection_id: 'other-api' }, { ETag: CONNECTION_ETAG }],
    ['an unknown status', { ...publishBody(), status: { state: 'fine', reason: 'ok' } }, { ETag: CONNECTION_ETAG }],
    ['a zero catalog revision', { ...publishBody(), catalog_revision: 0 }, { ETag: CONNECTION_ETAG }],
    ['a changed ETag', publishBody(), { ETag: '"connection:mail-api:c4"' }],
    ['no ETag', publishBody(), {}],
  ])('treats a registration answer with %s as an unknown outcome', async (_label, body, headers) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(201, body, headers))),
    );
    const request = catalogRegisterRequest(await projectedPreview(), SPEC, [
      'gmail.users.messages.list',
    ]);

    await expect(
      registerConnectionCatalog(CONNECTION_ID, request, CONNECTION_ETAG),
    ).rejects.toMatchObject({
      name: ConnectionContractError.name,
      requiresReload: true,
    });
  });

  it('surfaces a stale ETag as a 412 with no outcome to reconcile', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            412,
            { error: 'If-Match does not match the current connection ETag' },
            { ETag: '"connection:mail-api:c4"' },
          ),
        ),
      ),
    );
    const request = catalogRegisterRequest(await projectedPreview(), SPEC, [
      'gmail.users.messages.list',
    ]);

    const failure = await registerConnectionCatalog(
      CONNECTION_ID,
      request,
      CONNECTION_ETAG,
    ).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(AdminApiError);
    expect(failure).toMatchObject({
      status: 412,
      code: 'precondition_failed',
      etag: '"connection:mail-api:c4"',
    });
  });
});

async function projectedPreview(
  overrides: Record<string, unknown> = {},
): Promise<ConnectionCatalogPreview> {
  // Built through the real parser, so a fixture can never be a shape the
  // parser would refuse.
  const previous = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        jsonResponse(200, previewBody(overrides), { ETag: CONNECTION_ETAG }),
      ),
    ),
  );
  try {
    return (await previewConnectionCatalog(CONNECTION_ID, SPEC)).value;
  } finally {
    vi.stubGlobal('fetch', previous);
  }
}

function previewBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    connection_id: CONNECTION_ID,
    connection_etag: CONNECTION_ETAG,
    spec_digest: SPEC_DIGEST,
    spec_revision: 2,
    catalog_revision: 5,
    tools: [
      httpTool(
        'gmail.users.messages.list',
        'GET',
        '/gmail/v1/users/{userId}/messages',
        'List messages',
      ),
      httpTool(
        'gmail.users.messages.get',
        'GET',
        '/gmail/v1/users/{userId}/messages/{id}',
        'Get a message',
      ),
      httpTool(
        'gmail.users.labels.create',
        'POST',
        '/gmail/v1/users/{userId}/labels',
        'Create a label',
      ),
    ],
    security_confirmations: [
      {
        tool_name: 'gmail.users.messages.list',
        selected_scheme_names: ['Oauth2'],
      },
      {
        tool_name: 'gmail.users.messages.get',
        selected_scheme_names: ['Oauth2'],
      },
      {
        tool_name: 'gmail.users.labels.create',
        selected_scheme_names: ['Oauth2'],
      },
    ],
    incompatibilities: [incompatibility()],
    operation_id_fallbacks: [],
    skipped_operations: [
      {
        method: 'POST',
        path_template: '/upload/gmail/v1/users/{userId}/messages',
        reason: 'unsupported_request_body',
      },
    ],
    overlay: overlayReport(),
    conversion: {
      source_format: 'google_discovery_v1',
      warnings: [
        {
          code: 'global_parameter_not_mapped',
          message: 'the document-level parameter is not a tool argument',
          operation_omitted: false,
          subject: 'alt',
        },
      ],
    },
    ...overrides,
  };
}

function httpTool(
  name: string,
  method: string,
  path: string,
  description = `${name} description`,
): Record<string, unknown> {
  return {
    name,
    description,
    input_json_schema: { type: 'object', properties: {} },
    target: {
      type: 'http',
      connection_id: CONNECTION_ID,
      mapping: { method, path_template: path },
    },
    source: { type: 'open_api', connection_id: CONNECTION_ID, operation_id: name },
    upstream: { method, path_template: path },
  };
}

function compositeTool(name: string): Record<string, unknown> {
  return {
    name,
    description: `${name} composite`,
    input_json_schema: { type: 'object' },
    target: { type: 'composite', connection_id: CONNECTION_ID },
    source: { type: 'open_api', connection_id: CONNECTION_ID },
    upstream: { method: 'COMPOSITE', path_template: '/' },
    composite: { steps: [{ id: 'list', tool: 'inbox_list', arguments: {} }] },
  };
}

function incompatibility(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    tool_name: 'gmail.users.messages.trash',
    reason: 'no_compatible_security_alternative',
    security_alternatives: [
      {
        scheme_names: ['Oauth2'],
        reason: 'missing_scopes',
        message:
          'the Connection does not request every scope the operation requires',
        missing_scopes: ['https://mail.google.com/'],
      },
    ],
    unexplained_security_alternatives: 2,
    ...overrides,
  };
}

function overlayReport(): Record<string, unknown> {
  return {
    applied: false,
    problems: [],
    warnings: [],
    sources: [],
    tools: [],
    composites: [],
  };
}

function overlayTool(
  generatedName: string,
  servedName: string,
): Record<string, unknown> {
  return {
    generated_name: generatedName,
    served_name: servedName,
    visibility: 'listed',
    labels_found: 0,
    labels_from_source: 0,
    labels_from_title: 0,
    labels_from_description: 0,
    qualified_properties: [],
    label_summary: 'no labels',
  };
}

function publishBody(): Record<string, unknown> {
  return {
    connection_id: CONNECTION_ID,
    spec_digest: SPEC_DIGEST,
    spec_revision: 3,
    catalog_revision: 6,
    status: { state: 'healthy', reason: 'catalog_refreshed' },
    registered_tool_names: [
      'gmail.users.messages.list',
      'gmail.users.messages.get',
    ],
    total_count: 2,
    added_count: 2,
    changed_count: 0,
    removed_count: 0,
  };
}

function omit(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const copy = { ...value };
  delete copy[key];
  return copy;
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
