import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  getConnection,
  type ConnectionDetail,
  type ConnectionWrite,
} from '../../lib/connections';
import type { ConnectionSecretMetadata } from '../../lib/secrets';
import {
  assertionKeyWithPatch,
  callerAssertionDraftFromStored,
  callerAssertionDraftWithPromotedKey,
  callerAssertionSectionProblems,
  detailConfiguresCredentialAuthority,
  fieldErrorsFromProblems,
  formFromDetail,
  newCallerAssertionDraft,
  validateForm,
  writeFromForm,
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

  it('writes an edited block back with every kept key as a marker', async () => {
    const stored = storedConnection();
    const form = formFromDetail(await loadThroughClient(stored));
    const editing = {
      ...form,
      callerAssertionMode: 'edit' as const,
      callerAssertionDraft: callerAssertionDraftFromStored(
        form.callerAssertion!,
      ),
    };

    const write = writeFromForm(editing);
    expect(write.caller_assertion).toStrictEqual({
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
    });
    // Every field the replacement contract accepts for the block, and only
    // those: the safe read's `key_problem` is never sent back.
    expect(Object.keys(write.caller_assertion!).sort()).toEqual(
      contractFields('MutationCallerAssertion').filter(
        (field) => field !== 'signing_key_id',
      ),
    );
    expect(
      Object.keys(write.caller_assertion!.published_keys![0]).sort(),
    ).toEqual(
      contractFields('MutationCallerAssertionPublishedKey').filter(
        (field) => field !== 'signing_key_id',
      ),
    );
    expect(validateForm(editing)).toEqual({});

    // A newly bound key names its alias instead.
    const rebound = writeFromForm({
      ...editing,
      callerAssertionDraft: {
        ...editing.callerAssertionDraft,
        signingKey: assertionKeyWithPatch(
          editing.callerAssertionDraft.signingKey,
          {
            binding: {
              configured: true,
              intent: 'replace',
              secretId: 'assertion-key-next',
            },
          },
        ),
      },
    });
    expect(rebound.caller_assertion).toMatchObject({
      signing_key_id: 'assertion-key-next',
    });
    expect(Object.hasOwn(rebound.caller_assertion!, 'signing_key_configured')).toBe(
      false,
    );
  });

  it('removes the stored block only with an explicit null', async () => {
    const form = formFromDetail(await loadThroughClient(storedConnection()));

    const removed = writeFromForm({ ...form, callerAssertionMode: 'remove' });
    expect(Object.hasOwn(removed, 'caller_assertion')).toBe(true);
    expect(removed.caller_assertion).toBeNull();

    // With nothing stored there is nothing to remove, and nothing is sent.
    const plain = formFromDetail(projectedPlainConnection());
    const write: ConnectionWrite = writeFromForm({
      ...plain,
      callerAssertionMode: 'remove',
    });
    expect(Object.hasOwn(write, 'caller_assertion')).toBe(false);
  });

  it('drops a kept key binding when its kid or algorithm no longer names the stored key', async () => {
    const form = formFromDetail(await loadThroughClient(storedConnection()));
    const draft = callerAssertionDraftFromStored(form.callerAssertion!);
    const kept = draft.signingKey;
    expect(kept.binding.intent).toBe('preserve');

    const renamed = assertionKeyWithPatch(kept, { kid: 'gw-2026-11' });
    expect(renamed.binding.intent).toBe('none');
    expect(assertionKeyWithPatch(renamed, { kid: 'gw-2026-09' }).binding).toEqual(
      kept.binding,
    );

    const otherAlgorithm = assertionKeyWithPatch(kept, { algorithm: 'rs256' });
    expect(otherAlgorithm.binding.intent).toBe('none');
    expect(
      validateForm({
        ...form,
        callerAssertionMode: 'edit',
        callerAssertionDraft: { ...draft, signingKey: otherAlgorithm },
      })['caller_assertion.signing_key_id'],
    ).toBe('Select the secret alias that holds this key.');
  });

  it('promotes a published key to signing key with its kept binding', async () => {
    const form = formFromDetail(await loadThroughClient(storedConnection()));
    const draft = callerAssertionDraftWithPromotedKey(
      callerAssertionDraftFromStored(form.callerAssertion!),
      0,
    );

    const write = writeFromForm({
      ...form,
      callerAssertionMode: 'edit',
      callerAssertionDraft: draft,
    });
    expect(write.caller_assertion).toMatchObject({
      signing_key_configured: true,
      kid: 'gw-2026-10',
      algorithm: 'rs256',
      published_keys: [
        { signing_key_configured: true, kid: 'gw-2026-09', algorithm: 'es256' },
      ],
    });
  });

  it('validates a new caller assertion before writing it', () => {
    const plain = formFromDetail(projectedPlainConnection());
    const adding = {
      ...plain,
      callerAssertionMode: 'edit' as const,
      callerAssertionDraft: newCallerAssertionDraft(),
    };

    expect(validateForm(adding)).toEqual({
      'caller_assertion.signing_key_id':
        'Select the secret alias that holds this key.',
      'caller_assertion.kid':
        'Enter a key ID of 1 to 128 bytes with no control characters.',
      'caller_assertion.issuer':
        'Enter an issuer of 1 to 512 bytes with no control characters.',
      'caller_assertion.audience':
        'Enter an audience of 1 to 512 bytes with no control characters.',
      'caller_assertion.token_type':
        'Enter a token type of 1 to 128 bytes with no control characters.',
    });

    const secrets = [
      secretMetadata('assertion-key', ['assertion_signing_key']),
      secretMetadata('next-key', ['assertion_signing_key']),
      secretMetadata('bearer-only', ['static_bearer']),
    ];
    const complete = {
      ...adding,
      callerAssertionDraft: {
        ...adding.callerAssertionDraft,
        signingKey: {
          ...adding.callerAssertionDraft.signingKey,
          kid: 'gw-1',
          binding: replaceBinding('assertion-key'),
        },
        issuer: 'https://gateway.example.test',
        audience: 'https://plain.example.test',
        tokenType: 'caller-assertion+jwt',
      },
    };
    expect(validateForm(complete, secrets)).toEqual({});
    expect(writeFromForm(complete).caller_assertion).toStrictEqual({
      signing_key_id: 'assertion-key',
      kid: 'gw-1',
      algorithm: 'es256',
      issuer: 'https://gateway.example.test',
      audience: 'https://plain.example.test',
      token_type: 'caller-assertion+jwt',
      header_name: 'X-Caller-Assertion',
      lifetime_seconds: 60,
      bind_request: false,
      bind_approval: false,
    });

    const withDraft = (
      patch: Partial<typeof complete.callerAssertionDraft>,
      form: Partial<typeof complete> = {},
    ) =>
      validateForm(
        {
          ...complete,
          ...form,
          callerAssertionDraft: { ...complete.callerAssertionDraft, ...patch },
        },
        secrets,
      );

    // A local-store alias cannot hold a key, so the picker's purpose rules
    // it out and so does validation.
    expect(
      withDraft({
        signingKey: {
          ...complete.callerAssertionDraft.signingKey,
          binding: replaceBinding('bearer-only'),
        },
      })['caller_assertion.signing_key_id'],
    ).toBe(
      'Select a configured secret alias that can hold an assertion signing key.',
    );
    for (const lifetimeSeconds of ['0', '301', '1.5', '']) {
      expect(
        withDraft({ lifetimeSeconds })['caller_assertion.lifetime_seconds'],
      ).toBe('Enter a whole number of seconds from 1 to 300.');
    }
    expect(
      withDraft({ headerName: 'Authorization' })['caller_assertion.header_name'],
    ).toBe('Enter a valid, non-reserved HTTP header name of at most 64 bytes.');
    expect(
      withDraft(
        { headerName: 'X-Api-Key' },
        { authenticationType: 'header_api_key', headerName: 'x-api-key' },
      )['caller_assertion.header_name'],
    ).toBe('The assertion header must differ from the API key header.');
    expect(
      withDraft({ issuer: 'https://gateway.example.test\u0085' })[
        'caller_assertion.issuer'
      ],
    ).toBe('Enter an issuer of 1 to 512 bytes with no control characters.');

    const published = withDraft({
      publishedKeys: [
        {
          ...complete.callerAssertionDraft.signingKey,
          draftId: 900,
          binding: replaceBinding('next-key'),
        },
        {
          ...complete.callerAssertionDraft.signingKey,
          draftId: 901,
          kid: 'gw-3',
          binding: replaceBinding('assertion-key'),
        },
      ],
    });
    expect(published['caller_assertion.published_keys.0.kid']).toMatch(
      /needs its own key ID/,
    );
    expect(published['caller_assertion.published_keys.1.signing_key_id']).toBe(
      'Each secret alias may be published once.',
    );

    // An attested connection must use HTTPS.
    expect(
      validateForm({ ...complete, baseUrl: 'http://plain.example.test' }, secrets)[
        'endpoint.base_url'
      ],
    ).toBe('Connections with a caller assertion must use an HTTPS origin.');
  });

  it('shows the gateway caller-assertion codes beside what they mean', () => {
    const errors = fieldErrorsFromProblems([
      { field: 'caller_assertion.signing_key_id', code: 'algorithm_mismatch' },
      { field: 'caller_assertion.published_keys.kid', code: 'duplicate_kid' },
      {
        field: 'caller_assertion.signing_key_id',
        code: 'secret_purpose_conflict',
      },
      { field: 'caller_assertion.claims', code: 'something_new' },
    ]);

    expect(errors['caller_assertion.signing_key_id']).toBe(
      'The key is for the other algorithm. (algorithm_mismatch) This alias is bound as a delegated token-exchange client secret and cannot also hold an assertion key. (secret_purpose_conflict)',
    );
    expect(errors['caller_assertion.published_keys']).toBe(
      'Another key, on this connection or on another enabled one, is published under this key ID. (duplicate_kid)',
    );
    expect(errors['caller_assertion.claims']).toBe('Something new.');
    expect(errors.form).toBeUndefined();

    // Kept read only, every problem is listed in the section; while editing,
    // only those with no field of their own.
    expect(callerAssertionSectionProblems(errors, 'keep')).toHaveLength(3);
    expect(callerAssertionSectionProblems(errors, 'edit')).toEqual([
      errors['caller_assertion.published_keys'],
      errors['caller_assertion.claims'],
    ]);
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

    const form = formFromDetail(await loadThroughClient(legacy));
    const errors = validateForm(form);

    expect(errors.form).toMatch(/asks for approval binding/);

    // Editing the block turns approval binding off, and removing it is
    // always possible.
    const edited = {
      ...form,
      callerAssertionMode: 'edit' as const,
      callerAssertionDraft: callerAssertionDraftFromStored(
        form.callerAssertion!,
      ),
    };
    expect(validateForm(edited)).toEqual({});
    expect(writeFromForm(edited).caller_assertion?.bind_approval).toBe(false);
    expect(
      validateForm({ ...form, callerAssertionMode: 'remove' }),
    ).toEqual({});
  });

  it('reports a header clash on the edited block rather than on the other header', async () => {
    const form = formFromDetail(await loadThroughClient(storedConnection()));
    const errors = validateForm({
      ...form,
      callerAssertionMode: 'edit',
      callerAssertionDraft: {
        ...callerAssertionDraftFromStored(form.callerAssertion!),
        headerName: 'CF-Access-Client-Id',
      },
    });

    expect(errors).toEqual({
      'caller_assertion.header_name':
        'The assertion header must differ from every additional header.',
    });
  });

  it('treats a stored caller assertion as credential authority', async () => {
    const stored = storedConnection();
    const onlyAssertion = {
      ...stored,
      authentication: 'none',
      configuration: {
        ...stored.configuration,
        authentication: { type: 'none' },
        additional_headers: [],
        tls: {
          ca_bundle_configured: false,
          client_certificate_configured: false,
          client_private_key_configured: false,
        },
      },
    };
    const detail = await loadThroughClient(onlyAssertion);
    expect(detailConfiguresCredentialAuthority(detail)).toBe(true);
    expect(
      detailConfiguresCredentialAuthority(projectedPlainConnection()),
    ).toBe(false);
  });
});

function replaceBinding(secretId: string) {
  return { configured: false, intent: 'replace' as const, secretId };
}

function secretMetadata(
  id: string,
  compatible_purposes: ConnectionSecretMetadata['compatible_purposes'],
): ConnectionSecretMetadata {
  return {
    id,
    etag: `"${id}"`,
    label: id,
    provider: compatible_purposes.includes('assertion_signing_key')
      ? 'operator_file'
      : 'local_encrypted',
    configured: true,
    compatible_purposes,
    dependency_count: 0,
    actions: { can_rotate: false, can_delete: false },
  };
}

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
