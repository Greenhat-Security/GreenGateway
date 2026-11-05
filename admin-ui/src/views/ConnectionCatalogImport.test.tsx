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

import { MAX_CATALOG_SPEC_BYTES } from '../lib/connectionCatalog';
import { ConnectionDetail } from './ConnectionDetail';

const CONNECTION_ID = 'mail-api';
const DETAIL_ETAG = '"connection:mail-api:c3:k1:t0:d2"';
const PREVIEW_ETAG = '"connection:mail-api:c4:k1:t0:d2"';
const SPEC_DIGEST = 'd'.repeat(64);
const SPEC = '{"discoveryVersion":"v1","kind":"discovery#restDescription"}';
const ALL_TOOL_PERMISSIONS = [
  'admin:connections:read',
  'admin:tools:read',
  'admin:tools:write',
];

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ConnectionCatalogImport', () => {
  it('previews a pasted document and selects only bindable reads', async () => {
    const backend = catalogBackend();
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    await pasteAndPreview(SPEC);

    expect(
      screen.getByText('Google Discovery v1, converted to OpenAPI 3.0'),
    ).toBeTruthy();
    expect(screen.getByText('global_parameter_not_mapped')).toBeTruthy();
    expect(
      screen.getByText('GET /gmail/v1/users/{userId}/messages'),
    ).toBeTruthy();

    expect(checkbox('gmail.users.messages.list').checked).toBe(true);
    expect(checkbox('gmail.users.messages.get').checked).toBe(true);
    // A bindable write is never selected for the operator.
    expect(checkbox('gmail.users.labels.create').checked).toBe(false);
    expect(checkbox('gmail.users.labels.create').disabled).toBe(false);
    // An incompatible operation shows why and cannot be selected.
    const trash = checkbox('gmail.users.messages.trash');
    expect(trash.checked).toBe(false);
    expect(trash.disabled).toBe(true);
    const trashRow = trash.closest('tr') as HTMLElement;
    expect(
      within(trashRow).getByText('no_compatible_security_alternative'),
    ).toBeTruthy();
    expect(within(trashRow).getByText('missing_scopes')).toBeTruthy();
    expect(within(trashRow).getByText('https://mail.google.com/')).toBeTruthy();
    expect(screen.getByText('2 of 3 bindable selected')).toBeTruthy();
    expect(screen.getByText('unsupported_request_body')).toBeTruthy();

    const previews = backend.calls('/openapi/preview');
    expect(previews).toHaveLength(1);
    expect(previews[0].init?.method).toBe('POST');
    // Only the document: this page never sends a candidate overlay.
    expect(JSON.parse(String(previews[0].init?.body))).toEqual({ spec: SPEC });
  });

  it('registers only after the operator confirms the security alternatives', async () => {
    const backend = catalogBackend();
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    await pasteAndPreview(SPEC);

    const register = registerButton();
    expect(register.disabled).toBe(true);
    const confirmation = confirmationCheckbox();
    fireEvent.click(confirmation);
    expect(registerButton().disabled).toBe(false);

    // Changing the selection withdraws the confirmation it covered.
    fireEvent.click(checkbox('gmail.users.labels.create'));
    expect(confirmationCheckbox().checked).toBe(false);
    expect(registerButton().disabled).toBe(true);
    expect(
      screen.getByText(/1 selected tool is not a GET or HEAD operation/),
    ).toBeTruthy();
    fireEvent.click(checkbox('gmail.users.labels.create'));

    fireEvent.click(confirmationCheckbox());
    fireEvent.click(registerButton());

    expect(await screen.findByText('Catalog registered')).toBeTruthy();
    const registrations = backend.calls('/openapi/register');
    expect(registrations).toHaveLength(1);
    const { init } = registrations[0];
    expect(init?.method).toBe('POST');
    // The preview's ETag, not the one the detail page loaded with.
    expect(new Headers(init?.headers).get('If-Match')).toBe(PREVIEW_ETAG);
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
    // A registered preview cannot be registered twice.
    expect(screen.queryByRole('checkbox', { name: /^Select / })).toBeNull();
  });

  it('forces a new preview when the connection ETag is stale', async () => {
    const backend = catalogBackend({
      register: () =>
        jsonResponse(
          412,
          { error: 'If-Match does not match the current connection ETag' },
          { ETag: '"connection:mail-api:c5:k1:t0:d2"' },
        ),
    });
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    await pasteAndPreview(SPEC);
    fireEvent.click(confirmationCheckbox());
    fireEvent.click(registerButton());

    expect(await screen.findByText('Catalog preview out of date')).toBeTruthy();
    // The reviewed preview is gone: nothing can be registered from it.
    expect(screen.queryByRole('checkbox', { name: /^Select / })).toBeNull();
    expect(screen.queryByRole('button', { name: /^Register / })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Preview again' }));
    await screen.findByRole('checkbox', {
      name: 'Select gmail.users.messages.list',
    });
    expect(backend.calls('/openapi/preview')).toHaveLength(2);
    expect(backend.calls('/openapi/register')).toHaveLength(1);
  });

  it.each([
    [
      409,
      'capability_not_advertised',
      /does not advertise support for catalogs converted/,
    ],
    [
      409,
      'authentication_not_supported',
      /A Google domain-wide delegation connection is refused this way/,
    ],
    [
      409,
      'caller_assertion_not_enforced',
      /registered from an uploaded document/,
    ],
  ])(
    'shows the %s %s refusal by its reason code without echoing the document',
    async (status, reason, text) => {
      const canary = 'GG_CATALOG_DOCUMENT_CANARY';
      const backend = catalogBackend({
        register: () =>
          jsonResponse(status, {
            error: `refused while reading ${canary}`,
            reason,
          }),
      });
      vi.stubGlobal('fetch', backend.fetch);

      renderDetail();
      const spec = `{"openapi":"3.1.0","info":{"title":"${canary}"}}`;
      await pasteAndPreview(spec);
      fireEvent.click(confirmationCheckbox());
      fireEvent.click(registerButton());

      expect(await screen.findByText('Catalog registration refused')).toBeTruthy();
      const alert = screen
        .getAllByRole('alert')
        .find((element) => element.textContent?.includes('Reason code')) as
        | HTMLElement
        | undefined;
      expect(alert).toBeTruthy();
      expect(within(alert as HTMLElement).getByText(reason)).toBeTruthy();
      expect(within(alert as HTMLElement).getByText(text)).toBeTruthy();
      expect(alert?.textContent).not.toContain(canary);
    },
  );

  it('shows a preview refusal by its reason code', async () => {
    const backend = catalogBackend({
      preview: () =>
        jsonResponse(409, {
          error: 'managed OpenAPI preview failed',
          reason: 'authentication_not_supported',
        }),
    });
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail({
      authentication: 'google_domain_wide_delegation',
    });
    expect(
      await screen.findByText(/No managed OpenAPI tool sends a domain-wide/),
    ).toBeTruthy();
    fireEvent.change(await screen.findByLabelText('Catalog document'), {
      target: { value: SPEC },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview catalog' }));

    expect(await screen.findByText('Catalog preview refused')).toBeTruthy();
    expect(screen.getByText('authentication_not_supported')).toBeTruthy();
  });

  it('checks the 2 MiB limit before anything is sent', async () => {
    const backend = catalogBackend();
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    const textarea = await screen.findByLabelText('Catalog document');
    fireEvent.change(textarea, {
      target: { value: 'x'.repeat(MAX_CATALOG_SPEC_BYTES + 1) },
    });

    expect(
      screen.getByText(
        'The document is larger than the 2 MiB managed OpenAPI limit.',
      ),
    ).toBeTruthy();
    const preview = screen.getByRole('button', {
      name: 'Preview catalog',
    }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    fireEvent.click(preview);
    expect(backend.calls('/openapi/preview')).toHaveLength(0);
  });

  it('loads an uploaded document and refuses an oversized file unread', async () => {
    const backend = catalogBackend();
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    const input = (await screen.findByLabelText(
      'Catalog document file',
    )) as HTMLInputElement;

    const oversized = new File(['x'], 'large.json', {
      type: 'application/json',
    });
    Object.defineProperty(oversized, 'size', {
      value: MAX_CATALOG_SPEC_BYTES + 1,
    });
    const readOversized = vi.spyOn(oversized, 'text');
    fireEvent.change(input, { target: { files: [oversized] } });
    expect(
      await screen.findByText(
        'The file is larger than the 2 MiB managed OpenAPI limit and was not read.',
      ),
    ).toBeTruthy();
    expect(readOversized).not.toHaveBeenCalled();

    fireEvent.change(input, {
      target: {
        files: [new File([SPEC], 'gmail.json', { type: 'application/json' })],
      },
    });
    await waitFor(() =>
      expect(
        (screen.getByLabelText('Catalog document') as HTMLTextAreaElement).value,
      ).toBe(SPEC),
    );
    expect(backend.calls('/openapi/preview')).toHaveLength(0);
  });

  it('previews without register controls for a principal without tools write', async () => {
    const backend = catalogBackend({
      permissions: ['admin:connections:read', 'admin:tools:read'],
    });
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    await pasteAndPreview(SPEC);

    expect(screen.getByText('Tools write permission required')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /^Register / })).toBeNull();
  });

  it('offers no import to a principal without tools read', async () => {
    const backend = catalogBackend({
      permissions: ['admin:connections:read'],
    });
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail();
    expect(
      await screen.findByText('Tools read permission required'),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Catalog document')).toBeNull();
  });

  it('asks for nothing on a connection without managed OpenAPI discovery', async () => {
    const backend = catalogBackend();
    vi.stubGlobal('fetch', backend.fetch);

    renderDetail({
      configuration: { ...connectionConfiguration(), discovery: undefined },
    });
    expect(
      await screen.findByText(/This connection has no managed OpenAPI discovery/),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Catalog document')).toBeNull();
    expect(backend.calls('/capabilities')).toHaveLength(0);
  });
});

async function pasteAndPreview(spec: string) {
  fireEvent.change(await screen.findByLabelText('Catalog document'), {
    target: { value: spec },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Preview catalog' }));
  await screen.findByRole('checkbox', {
    name: 'Select gmail.users.messages.list',
  });
}

function checkbox(toolName: string): HTMLInputElement {
  return screen.getByRole('checkbox', {
    name: `Select ${toolName}`,
  }) as HTMLInputElement;
}

function confirmationCheckbox(): HTMLInputElement {
  return screen.getByRole('checkbox', {
    name: /I confirm that each selected tool sends/,
  }) as HTMLInputElement;
}

function registerButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: /^Register / }) as HTMLButtonElement;
}

// What the detail fixture differs in for the test being rendered.
let catalogDetailOverrides: Record<string, unknown> = {};

function renderDetail(overrides: Record<string, unknown> = {}) {
  catalogDetailOverrides = overrides;
  render(
    <MemoryRouter initialEntries={[`/connections/${CONNECTION_ID}`]}>
      <Routes>
        <Route path="/connections/:id" element={<ConnectionDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

type RecordedCall = { url: URL; init?: RequestInit };

function catalogBackend({
  permissions = ALL_TOOL_PERMISSIONS,
  preview = () =>
    jsonResponse(200, previewBody(), { ETag: PREVIEW_ETAG }),
  register = () => jsonResponse(201, publishBody(), { ETag: PREVIEW_ETAG }),
}: {
  permissions?: string[];
  preview?: () => Response;
  register?: () => Response;
} = {}) {
  const recorded: RecordedCall[] = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    recorded.push({ url, init });
    if (url.pathname === '/v1/admin/capabilities' && !init?.method) {
      return Promise.resolve(jsonResponse(200, { permissions }));
    }
    if (url.pathname === `/v1/admin/connections/${CONNECTION_ID}` && !init?.method) {
      return Promise.resolve(
        jsonResponse(200, connectionDetail(catalogDetailOverrides), {
          ETag: DETAIL_ETAG,
        }),
      );
    }
    if (url.pathname.endsWith('/openapi/preview') && init?.method === 'POST') {
      return Promise.resolve(preview());
    }
    if (url.pathname.endsWith('/openapi/register') && init?.method === 'POST') {
      return Promise.resolve(register());
    }
    return Promise.reject(
      new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url.pathname}`),
    );
  });
  return {
    fetch,
    calls: (suffix: string) =>
      recorded.filter((call) => call.url.pathname.endsWith(suffix)),
  };
}

function connectionConfiguration(): Record<string, unknown> {
  return {
    endpoint: { base_url: 'https://gmail.googleapis.com', base_path: '/' },
    authentication: { type: 'none' },
    tls: {
      ca_bundle_configured: false,
      client_certificate_configured: false,
      client_private_key_configured: false,
    },
    discovery: { type: 'managed_openapi', use_connection_authentication: false },
  };
}

function connectionDetail(overrides: Record<string, unknown> = {}) {
  return {
    id: CONNECTION_ID,
    display_name: 'Mail API',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'none',
    endpoint_count: 1,
    revisions: { connection: 3, credential: 1, tls: 0, discovery: 2, status: 0 },
    status: { state: 'configured', reason: 'not_tested' },
    configuration: connectionConfiguration(),
    dependencies: [],
    actions: {
      can_update: true,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: false,
      can_refresh: true,
      can_delete: true,
    },
    created_at: '2026-11-01T10:00:00Z',
    updated_at: '2026-11-01T11:00:00Z',
    ...overrides,
  };
}

function previewBody(): Record<string, unknown> {
  return {
    connection_id: CONNECTION_ID,
    connection_etag: PREVIEW_ETAG,
    spec_digest: SPEC_DIGEST,
    spec_revision: 2,
    catalog_revision: 5,
    tools: [
      httpTool('gmail.users.messages.list', 'GET', '/gmail/v1/users/{userId}/messages'),
      httpTool('gmail.users.messages.get', 'GET', '/gmail/v1/users/{userId}/messages/{id}'),
      httpTool('gmail.users.labels.create', 'POST', '/gmail/v1/users/{userId}/labels'),
    ],
    security_confirmations: [
      'gmail.users.messages.list',
      'gmail.users.messages.get',
      'gmail.users.labels.create',
    ].map((name) => ({ tool_name: name, selected_scheme_names: ['Oauth2'] })),
    incompatibilities: [
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
      },
    ],
    operation_id_fallbacks: [],
    skipped_operations: [
      {
        method: 'POST',
        path_template: '/upload/gmail/v1/users/{userId}/messages',
        reason: 'unsupported_request_body',
      },
    ],
    overlay: {
      applied: false,
      problems: [],
      warnings: [],
      sources: [],
      tools: [],
      composites: [],
    },
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
  };
}

function httpTool(name: string, method: string, path: string) {
  return {
    name,
    description: `${name} description`,
    input_json_schema: { type: 'object' },
    target: {
      type: 'http',
      connection_id: CONNECTION_ID,
      mapping: { method, path_template: path },
    },
    source: { type: 'open_api', connection_id: CONNECTION_ID, operation_id: name },
    upstream: { method, path_template: path },
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
