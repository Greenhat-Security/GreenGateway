import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { PolicyDocument } from '../lib/policy';
import { OpenApiToolsView } from './OpenApiToolsView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('OpenApiToolsView', () => {
  it('previews pasted OpenAPI tools with skipped operations and upstream auth warnings', async () => {
    vi.stubGlobal('fetch', openApiToolsFetchMock().fetch);

    renderOpenApiToolsView();

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));

    expect(await screen.findByText('createWidget')).toBeTruthy();
    expect(screen.getByText('Create a widget')).toBeTruthy();
    expect(screen.getByText('POST /widgets')).toBeTruthy();
    expect(screen.getByText('getWidget')).toBeTruthy();
    expect(screen.getByText('GET /widgets/{widgetId}')).toBeTruthy();
    expect(screen.getByText('Requires upstream auth - not wired')).toBeTruthy();
    expect(screen.getByText('updateWidget')).toBeTruthy();
    expect(
      screen.getByText('body_property_parameter_name_collision: id'),
    ).toBeTruthy();

    const createCheckbox = screen.getByRole('checkbox', {
      name: 'Select createWidget',
    }) as HTMLInputElement;
    const authCheckbox = screen.getByRole('checkbox', {
      name: 'Select getWidget',
    }) as HTMLInputElement;
    expect(createCheckbox.checked).toBe(true);
    expect(authCheckbox.checked).toBe(false);
  });

  it('keeps auth-required tool checkboxes disabled and unselected', async () => {
    vi.stubGlobal('fetch', openApiToolsFetchMock().fetch);

    renderOpenApiToolsView();

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));

    await screen.findByText('getWidget');
    const authCheckbox = screen.getByRole('checkbox', {
      name: 'Select getWidget',
    }) as HTMLInputElement;

    expect(authCheckbox.disabled).toBe(true);
    expect(authCheckbox.checked).toBe(false);

    fireEvent.click(authCheckbox);

    expect(authCheckbox.checked).toBe(false);
    expect(screen.getByText('1 selected')).toBeTruthy();
  });

  it('registers selected tools with the preview ETag and shows success', async () => {
    const fetcher = openApiToolsFetchMock();
    vi.stubGlobal('fetch', fetcher.fetch);

    renderOpenApiToolsView();

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText('createWidget');

    fireEvent.click(screen.getByRole('button', { name: 'Register selected' }));

    expect(await screen.findByText('Registered 1 tool.')).toBeTruthy();
    expect(fetcher.registerBodies).toEqual([
      {
        spec: widgetSpec,
        selected_tool_names: ['createWidget'],
      },
    ]);
    expect(fetcher.registerIfMatches).toEqual(['"etag-preview"']);
  });

  it('blocks registration after the spec changes from the previewed text', async () => {
    const fetcher = openApiToolsFetchMock();
    vi.stubGlobal('fetch', fetcher.fetch);

    renderOpenApiToolsView();

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText('createWidget');

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: `${widgetSpec}\n# edited after preview\n` },
    });

    expect(
      (screen.getByRole('button', {
        name: 'Register selected',
      }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(fetcher.registerBodies).toEqual([]);
  });

  it('renders per-tool conflict errors from register failures', async () => {
    vi.stubGlobal(
      'fetch',
      openApiToolsFetchMock({
        registerStatus: 409,
        registerBody: {
          error: 'tool name collision',
          conflicts: ['createWidget'],
        },
      }).fetch,
    );

    renderOpenApiToolsView();

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText('createWidget');
    fireEvent.click(screen.getByRole('button', { name: 'Register selected' }));

    expect(await screen.findByText('Tool name collision')).toBeTruthy();
    expect(screen.getAllByText('createWidget').length).toBeGreaterThan(0);
  });

  it('hides the register action for a read-only principal', async () => {
    vi.stubGlobal(
      'fetch',
      openApiToolsFetchMock({
        policy: policyDocument({
          roles: {
            reader: { permissions: ['admin:tools:read'] },
          },
        }),
      }).fetch,
    );

    renderOpenApiToolsView({ token: jwtWithRoles(['reader']) });

    fireEvent.change(screen.getByLabelText('OpenAPI spec'), {
      target: { value: widgetSpec },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));

    expect(await screen.findByText('Tools write permission required')).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: 'Register selected' }),
    ).toBeNull();
  });
});

function renderOpenApiToolsView({
  token = jwtWithRoles(['tools-admin']),
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter>
      <OpenApiToolsView />
    </MemoryRouter>,
  );
}

function openApiToolsFetchMock({
  policy = policyDocument(),
  previewBody = previewResponse(),
  registerStatus = 201,
  registerBody = {
    registered_tool_names: ['createWidget'],
    tool_count: 1,
  },
}: {
  policy?: PolicyDocument;
  previewBody?: unknown;
  registerStatus?: number;
  registerBody?: unknown;
} = {}) {
  const registerBodies: unknown[] = [];
  const registerIfMatches: Array<string | null> = [];
  const fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy' && !init?.method) {
      return Promise.resolve(jsonResponse(200, policy));
    }

    if (
      url.pathname === '/v1/admin/tools/openapi/preview' &&
      init?.method === 'POST'
    ) {
      return Promise.resolve(
        jsonResponse(200, previewBody, { ETag: '"etag-preview"' }),
      );
    }

    if (
      url.pathname === '/v1/admin/tools/openapi/register' &&
      init?.method === 'POST'
    ) {
      registerBodies.push(JSON.parse(String(init.body)));
      registerIfMatches.push(requestHeader(init.headers, 'If-Match'));
      return Promise.resolve(jsonResponse(registerStatus, registerBody));
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return { fetch, registerBodies, registerIfMatches };
}

function previewResponse() {
  return {
    tools: [
      {
        name: 'createWidget',
        description: 'Create a widget',
        input_json_schema: {
          type: 'object',
          required: ['name'],
          properties: {
            name: { type: 'string' },
          },
          additionalProperties: false,
        },
        upstream: {
          method: 'POST',
          path_template: '/widgets',
          body: { mode: 'whole_args_json' },
        },
      },
      {
        name: 'getWidget',
        description: 'Fetch a widget',
        input_json_schema: {
          type: 'object',
          required: ['widgetId'],
          properties: {
            widgetId: { type: 'string' },
          },
          additionalProperties: false,
        },
        upstream: {
          method: 'GET',
          path_template: '/widgets/{widgetId}',
        },
      },
    ],
    operation_id_fallbacks: [],
    skipped_operations: [
      {
        method: 'PUT',
        path_template: '/widgets/{id}',
        original_operation_id: 'updateWidget',
        reason: 'body_property_parameter_name_collision',
        property_name: 'id',
      },
    ],
    api_key_header_auth_requirements: [
      {
        tool_name: 'getWidget',
        method: 'GET',
        path_template: '/widgets/{widgetId}',
        scheme_name: 'ApiKeyAuth',
        header_name: 'X-API-Key',
      },
    ],
  };
}

function requestHeader(
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
    roles: {
      'tools-admin': {
        permissions: ['admin:tools:read', 'admin:tools:write'],
      },
    },
    routes: [],
    rules: [],
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

function jwtWithRoles(roles: string[]): string {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'test-user', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

const widgetSpec = `openapi: 3.0.3
info:
  title: Widget API
  version: 1.0.0
paths:
  /widgets:
    post:
      operationId: createWidget
      summary: Create a widget
`;
