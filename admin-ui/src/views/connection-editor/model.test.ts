import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  getConnection,
  type ConnectionDetail,
  type ConnectionWrite,
} from '../../lib/connections';
import { formFromDetail, validateForm, writeFromForm } from './model';

afterEach(() => {
  vi.unstubAllGlobals();
});

// The admin contract the gateway publishes. Reading it here, rather than
// listing its fields by hand, makes a field added to the contract and not to
// this UI fail these tests instead of being silently dropped on save.
// Resolved from the vitest root (`admin-ui`), as the other doc-backed tests do.
const adminSchema = JSON.parse(
  readFileSync(
    resolve(process.cwd(), '../docs/schemas/connection-admin.v1.schema.json'),
    'utf8',
  ),
) as {
  $defs: Record<string, { properties: Record<string, unknown> }>;
};

function contractFields(definition: string): string[] {
  return Object.keys(adminSchema.$defs[definition].properties).sort();
}

describe('connection editor load and save', () => {
  it('writes back every stored field and leaves the caller assertion out', async () => {
    const stored = storedConnection();
    // The fixture has to cover the whole safe read for the checks below to
    // mean anything.
    expect(Object.keys(stored.configuration).sort()).toEqual(
      contractFields('SafeConfiguration'),
    );
    expect(Object.keys(stored.configuration.caller_assertion).sort()).toEqual(
      contractFields('SafeCallerAssertion'),
    );

    const detail = await loadThroughClient(stored);
    // Loaded byte for byte: the projection keeps every field and its order.
    expect(JSON.stringify(detail.configuration)).toBe(
      JSON.stringify(stored.configuration),
    );

    const write = writeFromForm(formFromDetail(detail));
    const { caller_assertion: _kept, ...writable } = stored.configuration;
    expect(write).toStrictEqual({
      display_name: stored.display_name,
      enabled: stored.enabled,
      kind: stored.kind,
      ...writable,
    });
    // Every field a replacement accepts is written back except
    // `caller_assertion`, which the gateway keeps because it is omitted.
    expect([...Object.keys(write), 'caller_assertion'].sort()).toEqual(
      contractFields('ConnectionReplaceRequest'),
    );
    expect(Object.hasOwn(write, 'caller_assertion')).toBe(false);
    expect(JSON.stringify(write)).not.toContain('caller_assertion');
  });

  it('keeps the caller assertion on the form unchanged and out of every write', async () => {
    const stored = storedConnection();
    const form = formFromDetail(await loadThroughClient(stored));

    expect(JSON.stringify(form.callerAssertion)).toBe(
      JSON.stringify(stored.configuration.caller_assertion),
    );

    // A routine edit, a disable and a credential rotation all leave it out.
    for (const edited of [
      { ...form, displayName: 'Billing API renamed' },
      { ...form, enabled: false },
      {
        ...form,
        authenticationBinding: {
          configured: true,
          intent: 'replace' as const,
          secretId: 'rotated-billing-key',
        },
      },
    ]) {
      expect(Object.hasOwn(writeFromForm(edited), 'caller_assertion')).toBe(
        false,
      );
      expect(edited.callerAssertion).toBe(form.callerAssertion);
    }
  });

  it('cannot express a caller assertion in a write', () => {
    // Checked by `tsc`: the write type rules the key out, `null` included,
    // because anything the UI could send would at best remove the block.
    const write: ConnectionWrite = {
      ...writeFromForm(formFromDetail(projectedPlainConnection())),
      // @ts-expect-error The admin UI never sends a caller assertion.
      caller_assertion: null,
    };
    expect(write.display_name).toBe('Plain API');
  });

  it('keeps a test profile an MCP connection was loaded with', async () => {
    const stored = storedConnection();
    const mcp = {
      ...stored,
      kind: 'mcp_streamable_http',
      configuration: {
        ...stored.configuration,
        discovery: {
          type: 'managed_mcp',
          use_connection_authentication: true,
        },
      },
    };

    const write = writeFromForm(formFromDetail(await loadThroughClient(mcp)));

    expect(write.kind).toBe('mcp_streamable_http');
    expect(write.test_profile).toStrictEqual(
      stored.configuration.test_profile,
    );
  });

  it('refuses a header name the caller assertion already uses', async () => {
    const form = formFromDetail(await loadThroughClient(storedConnection()));

    const primary = validateForm({ ...form, headerName: 'X-Caller-Assertion' });
    expect(primary['authentication.header_name']).toBe(
      'The API key header cannot use the caller assertion header name.',
    );

    const additional = validateForm({
      ...form,
      additionalHeaders: [
        ...form.additionalHeaders,
        {
          ...form.additionalHeaders[0],
          draftId: form.additionalHeaders[0].draftId + 1000,
          headerName: 'X-CALLER-ASSERTION',
          initialHeaderName: undefined,
        },
      ],
    });
    expect(additional['additional_headers.1.header_name']).toBe(
      'An additional header cannot use the caller assertion header name.',
    );

    expect(validateForm(form)).toEqual({});
  });

  it('explains why a block with legacy approval binding cannot be saved', async () => {
    const stored = storedConnection();
    const legacy = {
      ...stored,
      configuration: {
        ...stored.configuration,
        caller_assertion: {
          ...stored.configuration.caller_assertion,
          bind_approval: true,
        },
      },
    };

    const errors = validateForm(
      formFromDetail(await loadThroughClient(legacy)),
    );

    expect(errors.form).toMatch(/asks for approval binding/);
  });
});

async function loadThroughClient(
  stored: Record<string, unknown>,
): Promise<ConnectionDetail> {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(stored), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ETag: '"connection:v1"',
          },
        }),
      ),
    ),
  );
  return (await getConnection(String(stored.id))).value;
}

/**
 * A managed Connection as the gateway's safe read returns it, with every
 * optional configuration field set, in the gateway's serialization order.
 */
function storedConnection() {
  return {
    id: 'billing',
    display_name: 'Billing API',
    enabled: true,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'header_api_key',
    endpoint_count: 1,
    revisions: {
      connection: 3,
      credential: 2,
      tls: 1,
      discovery: 1,
      status: 4,
    },
    status: { state: 'unavailable', reason: 'request_failed' },
    configuration: {
      description: 'Billing service',
      endpoint: {
        base_url: 'https://billing.example.test',
        base_path: '/v1',
      },
      authentication: {
        type: 'header_api_key',
        header_name: 'x-api-key',
        secret_configured: true,
      },
      caller_assertion: {
        signing_key_configured: true,
        kid: 'gw-2026-09',
        algorithm: 'es256',
        issuer: 'https://gateway.example.test',
        audience: 'https://billing.example.test/api',
        token_type: 'at+jwt',
        header_name: 'x-caller-assertion',
        lifetime_seconds: 60,
        claims: ['email', 'roles'],
        bind_request: true,
        bind_approval: false,
      },
      additional_headers: [
        {
          header_name: 'cf-access-client-id',
          secret_configured: true,
        },
      ],
      tls: {
        ca_bundle_configured: true,
        client_certificate_configured: true,
        client_private_key_configured: true,
      },
      timeouts: {
        connect_timeout_ms: 1000,
        request_timeout_ms: 5000,
        response_idle_timeout_ms: 2000,
      },
      discovery: {
        type: 'managed_openapi',
        path: '/openapi.json',
        use_connection_authentication: true,
      },
      test_profile: {
        method: 'HEAD',
        path: '/ready',
        expected_statuses: [200, 204],
      },
    },
    dependencies: [],
    actions: {
      can_update: true,
      can_bind_secret: true,
      can_manage_secrets: false,
      can_test: true,
      can_refresh: true,
      can_delete: true,
    },
    created_at: '2026-10-01T12:00:00Z',
    updated_at: '2026-10-02T12:00:00Z',
  };
}

function projectedPlainConnection(): ConnectionDetail {
  return {
    id: 'plain',
    display_name: 'Plain API',
    enabled: false,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication: 'none',
    endpoint_count: 1,
    revisions: {
      connection: 1,
      credential: 1,
      tls: 1,
      discovery: 1,
      status: 1,
    },
    status: { state: 'disabled', reason: 'disabled' },
    configuration: {
      endpoint: {
        base_url: 'https://plain.example.test',
        base_path: '/',
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
      can_test: false,
      can_refresh: false,
      can_delete: true,
    },
  };
}
