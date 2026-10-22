import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  getConnection,
  type ConnectionDetail,
  type ConnectionWrite,
} from '../../lib/connections';
import {
  createWriteFromForm,
  DEFAULT_FORM,
  delegatedIssuerTokenOffered,
  fieldErrorsFromProblems,
  formFromDetail,
  validateForm,
  writeFromForm,
  type ConnectionFormState,
} from './model';

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

  it('loads and writes back a delegated issuer token without its caller assertion', async () => {
    const stored = delegatedConnection();
    const form = formFromDetail(await loadThroughClient(stored));
    expect(form.authenticationType).toBe('delegated_issuer_token');
    // A stored delegated Connection keeps its type: its block stays through
    // every save and would otherwise start going upstream.
    expect(delegatedIssuerTokenOffered(form, false)).toBe(true);
    expect(validateForm(form)).toEqual({});

    const write = writeFromForm(form);
    expect(write.authentication).toStrictEqual({
      type: 'delegated_issuer_token',
      token_exchange_url: 'https://issuer.example.test/oauth2/token-exchange',
      client_id: 'greengateway',
      requested_scopes: ['calendar.read', 'mail.read'],
      audience: 'https://mail.example.test',
      resource: 'https://mail.example.test/v1',
      revocation_url: 'https://issuer.example.test/oauth2/revoke',
      subject_token_source: 'caller_assertion',
      client_secret_configured: true,
    });
    expect(Object.hasOwn(write, 'caller_assertion')).toBe(false);
    // The revocation endpoint is optional: cleared, the write leaves it out.
    expect(
      Object.hasOwn(
        writeFromForm({ ...form, revocationUrl: '  ' }).authentication,
        'revocation_url',
      ),
    ).toBe(false);
    // The stored block is never re-sent, not even by the create body builder.
    expect(Object.hasOwn(createWriteFromForm(form), 'caller_assertion')).toBe(
      false,
    );
  });

  it('adds the subject-token caller assertion to a delegated create only', () => {
    const draft: ConnectionFormState = {
      ...DEFAULT_FORM,
      displayName: 'Mail API',
      baseUrl: 'https://mail.example.test',
      authenticationType: 'delegated_issuer_token',
      clientId: 'greengateway',
      tokenExchangeUrl: 'https://issuer.example.test/oauth2/token-exchange',
      subjectToken: {
        ...DEFAULT_FORM.subjectToken,
        signingKeyBinding: {
          configured: false,
          intent: 'replace',
          secretId: 'gateway-assertion-key',
        },
        kid: 'gw-2026-10',
        issuer: 'https://gateway.example.test',
        audience: 'https://issuer.example.test',
        tokenType: 'caller-assertion+jwt',
        claims: ['roles'],
      },
    };
    expect(delegatedIssuerTokenOffered(DEFAULT_FORM, true)).toBe(true);
    expect(delegatedIssuerTokenOffered(DEFAULT_FORM, false)).toBe(false);
    expect(
      validateForm(draft, [
        {
          id: 'gateway-assertion-key',
          etag: '"key-1"',
          label: 'Gateway assertion key',
          provider: 'operator_file',
          configured: true,
          compatible_purposes: ['assertion_signing_key'],
          dependency_count: 0,
          actions: { can_rotate: false, can_delete: false },
        },
      ]),
    ).toEqual({});

    expect(createWriteFromForm(draft).caller_assertion).toStrictEqual({
      signing_key_id: 'gateway-assertion-key',
      kid: 'gw-2026-10',
      algorithm: 'es256',
      issuer: 'https://gateway.example.test',
      audience: 'https://issuer.example.test',
      token_type: 'caller-assertion+jwt',
      header_name: 'x-caller-assertion',
      lifetime_seconds: 60,
      claims: ['roles'],
    });
    // Every field it writes is one the create contract's block accepts.
    for (const field of Object.keys(
      createWriteFromForm(draft).caller_assertion ?? {},
    )) {
      expect(contractFields('CallerAssertion')).toContain(field);
    }
    // A replacement never carries it, and no other type ever drafts one.
    expect(Object.hasOwn(writeFromForm(draft), 'caller_assertion')).toBe(false);
    expect(
      Object.hasOwn(
        createWriteFromForm({ ...draft, authenticationType: 'static_bearer' }),
        'caller_assertion',
      ),
    ).toBe(false);
  });

  it('refuses a delegated draft the gateway would refuse, naming the field', () => {
    const errors = validateForm({
      ...DEFAULT_FORM,
      displayName: 'Mail API',
      baseUrl: 'https://mail.example.test',
      kind: 'mcp_streamable_http',
      authenticationType: 'delegated_issuer_token',
      tokenExchangeUrl: 'https://issuer.example.test/token?tenant=1',
      revocationUrl: 'http://issuer.example.test/oauth2/revoke',
      scopes: 'mail.read mail.read',
      subjectToken: {
        ...DEFAULT_FORM.subjectToken,
        kid: 'k'.repeat(129),
        issuer: 'https://gateway.example.test\u0007',
        headerName: 'x-forwarded-user',
        lifetimeSeconds: '0',
      },
    });
    expect(Object.keys(errors).sort()).toEqual([
      'authentication.client_id',
      'authentication.requested_scopes',
      'authentication.revocation_url',
      'authentication.token_exchange_url',
      'authentication.type',
      'caller_assertion.audience',
      'caller_assertion.header_name',
      'caller_assertion.issuer',
      'caller_assertion.kid',
      'caller_assertion.lifetime_seconds',
      'caller_assertion.signing_key_id',
      'caller_assertion.token_type',
    ]);
  });

  it('shows a problem with the stored caller assertion form-wide', () => {
    const problems = [
      { field: 'caller_assertion.signing_key_id', code: 'invalid_signing_key' },
      { field: 'authentication.token_exchange_url', code: 'invalid_token_url' },
    ];
    expect(fieldErrorsFromProblems(problems, true)).toEqual({
      'caller_assertion.signing_key_id': 'Invalid signing key.',
      'authentication.token_exchange_url': 'Invalid token url.',
    });
    // Without the draft's fields the stored block has no control to show it.
    expect(fieldErrorsFromProblems(problems)).toEqual({
      form: 'Invalid signing key.',
      'authentication.token_exchange_url': 'Invalid token url.',
    });
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
        published_keys: [
          { signing_key_configured: true, kid: 'gw-2026-10', algorithm: 'rs256' },
        ],
        key_problem: {
          field: 'caller_assertion.published_keys.signing_key_id',
          code: 'binding_unavailable',
        },
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

/** A stored delegated issuer token Connection, as the safe read returns it. */
function delegatedConnection() {
  const stored = storedConnection();
  const {
    published_keys: _published,
    key_problem: _problem,
    ...assertion
  } = stored.configuration.caller_assertion;
  return {
    ...stored,
    authentication: 'delegated_issuer_token',
    configuration: {
      endpoint: stored.configuration.endpoint,
      authentication: {
        type: 'delegated_issuer_token',
        token_exchange_url: 'https://issuer.example.test/oauth2/token-exchange',
        client_id: 'greengateway',
        requested_scopes: ['calendar.read', 'mail.read'],
        audience: 'https://mail.example.test',
        resource: 'https://mail.example.test/v1',
        revocation_url: 'https://issuer.example.test/oauth2/revoke',
        subject_token_source: 'caller_assertion',
        client_secret_configured: true,
      },
      caller_assertion: {
        ...assertion,
        audience: 'https://issuer.example.test',
        bind_request: false,
      },
      tls: {
        ca_bundle_configured: false,
        client_certificate_configured: false,
        client_private_key_configured: false,
      },
      test_profile: stored.configuration.test_profile,
    },
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
