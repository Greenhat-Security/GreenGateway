import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ConnectionSecretContractError,
  createConnectionSecret,
  deleteConnectionSecret,
  listConnectionSecrets,
  rotateConnectionSecret,
} from './secrets';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('connection secrets API client', () => {
  it('lists only safe metadata, server actions, providers, and item ETags', async () => {
    const canary = 'UNEXPECTED_SECRET_RESPONSE_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            200,
            {
              secrets: [
                secretMetadata({
                  value: canary,
                  ciphertext: canary,
                  locator: canary,
                }),
              ],
              actions: { can_create: true },
              providers: {
                operator_aliases: true,
                local_encrypted: true,
              },
            },
            {
              ETag: '"connection-secrets:representation:v1"',
              'x-greengateway-connection-secrets-etag':
                '"connection-secrets:mutation:v1"',
            },
          ),
        ),
      ),
    );

    const result = await listConnectionSecrets();
    expect(result.etag).toBe('"connection-secrets:representation:v1"');
    expect(result.collectionEtag).toBe(
      '"connection-secrets:mutation:v1"',
    );
    expect(result.value.actions.can_create).toBe(true);
    expect(result.value.secrets[0]).not.toHaveProperty('value');
    expect(result.value.secrets[0].etag).toBe(
      '"connection-secret:secret-1:v1"',
    );
    expect(JSON.stringify(result.value)).not.toContain(canary);
  });

  it('keeps the inventory usable when the gateway reports a provider this build does not know', async () => {
    // The gateway's SecretProviderKind has eight variants and every network
    // provider alias is listed unconditionally, so a deployment with one Vault
    // alias serves `provider: "vault_kv_v2"` here. Rejecting the row used to
    // abort the whole `secrets.map(...)`, which failed the entire request and
    // disabled every bind, create, rotate, and delete -- including for the
    // local secrets in the same response.
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            200,
            {
              secrets: [
                secretMetadata({
                  id: 'billing-api-key',
                  etag: '"connection-secret:billing-api-key:v1"',
                  label: 'Billing API key',
                  provider: 'vault_kv_v2',
                  actions: { can_rotate: false, can_delete: false },
                }),
                secretMetadata(),
                secretMetadata({
                  id: 'future-provider-secret',
                  etag: '"connection-secret:future-provider-secret:v1"',
                  label: 'Some later provider',
                  provider: 'provider_added_after_this_build',
                  actions: { can_rotate: false, can_delete: false },
                }),
              ],
              actions: { can_create: true },
              providers: {
                operator_aliases: true,
                local_encrypted: true,
              },
            },
            {
              ETag: '"connection-secrets:representation:v1"',
              'x-greengateway-connection-secrets-etag':
                '"connection-secrets:mutation:v1"',
            },
          ),
        ),
      ),
    );

    const result = await listConnectionSecrets();

    expect(result.value.secrets.map((secret) => secret.provider)).toEqual([
      'vault_kv_v2',
      'local_encrypted',
      'provider_added_after_this_build',
    ]);
    // The local secret in the same response stays fully manageable, which is
    // what the old behaviour took away.
    expect(result.value.secrets[1].actions).toEqual({
      can_rotate: true,
      can_delete: true,
    });
    expect(result.value.actions.can_create).toBe(true);
  });

  it('uses exact collection/item ETags and never expects plaintext in responses', async () => {
    const calls: Array<{
      path: string;
      method: string | undefined;
      ifMatch: string | null;
      body: unknown;
    }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        calls.push({
          path: url.pathname,
          method: init?.method,
          ifMatch: new Headers(init?.headers).get('If-Match'),
          body:
            typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
        });
        if (init?.method === 'DELETE') {
          return Promise.resolve(
            jsonResponse(
              200,
              { deleted_secret_id: 'secret/one' },
              {
                'x-greengateway-connection-secrets-etag':
                  '"connection-secrets:v4"',
              },
            ),
          );
        }
        const rotated = init?.method === 'PUT';
        return Promise.resolve(
          jsonResponse(
            rotated ? 200 : 201,
            secretMetadata({
              id: rotated ? 'secret/one' : 'secret-1',
              etag: rotated
                ? '"connection-secret:secret-1:v2"'
                : '"connection-secret:secret-1:v1"',
              version: rotated ? 2 : 1,
              value: 'response-plaintext-canary',
              ciphertext: 'response-ciphertext-canary',
              locator: 'response-locator-canary',
            }),
            {
              ETag: rotated
                ? '"connection-secret:secret-1:v2"'
                : '"connection-secret:secret-1:v1"',
              'x-greengateway-connection-secrets-etag': rotated
                ? '"connection-secrets:v3"'
                : '"connection-secrets:v2"',
            },
          ),
        );
      }),
    );

    const created = await createConnectionSecret(
      {
        label: '  Billing token  ',
        purpose: 'static_bearer',
        value: 'created-plaintext',
      },
      '"connection-secrets:v1"',
    );
    const rotated = await rotateConnectionSecret(
      'secret/one',
      {
        purpose: 'static_bearer',
        value: 'rotated-plaintext',
      },
      '"connection-secret:secret-1:v1"',
      '"connection-secrets:v2"',
      1,
    );
    const deleted = await deleteConnectionSecret(
      'secret/one',
      '"connection-secret:secret-1:v2"',
      '"connection-secrets:v3"',
    );

    expect(created.value).not.toHaveProperty('value');
    expect(rotated.value).not.toHaveProperty('value');
    expect(rotated.etag).toBe('"connection-secret:secret-1:v2"');
    expect(deleted.collectionEtag).toBe('"connection-secrets:v4"');
    expect(JSON.stringify(created.value)).not.toContain('canary');
    expect(JSON.stringify(rotated.value)).not.toContain('canary');
    expect(calls).toEqual([
      {
        path: '/v1/admin/connection-secrets',
        method: 'POST',
        ifMatch: '"connection-secrets:v1"',
        body: {
          label: 'Billing token',
          purpose: 'static_bearer',
          value: 'created-plaintext',
        },
      },
      {
        path: '/v1/admin/connection-secrets/secret%2Fone',
        method: 'PUT',
        ifMatch: '"connection-secret:secret-1:v1"',
        body: {
          purpose: 'static_bearer',
          value: 'rotated-plaintext',
        },
      },
      {
        path: '/v1/admin/connection-secrets/secret%2Fone',
        method: 'DELETE',
        ifMatch: '"connection-secret:secret-1:v2"',
        body: undefined,
      },
    ]);
  });

  it('treats missing or mismatched mutation versions as ambiguous and reload-required', async () => {
    const responses = [
      jsonResponse(
        201,
        secretMetadata({
          etag: '"connection-secret:secret-1:v2"',
          version: 2,
        }),
        { ETag: '"connection-secret:secret-1:v2"' },
      ),
      jsonResponse(
        200,
        secretMetadata({
          etag: '"connection-secret:secret-1:v3"',
          version: 3,
        }),
        {
          ETag: '"connection-secret:other:v3"',
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v3"',
        },
      ),
      jsonResponse(200, { deleted_secret_id: 'secret/one' }),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(responses.shift() as Response)),
    );

    for (const operation of [
      () => createConnectionSecret(
        {
          label: 'Billing token',
          purpose: 'static_bearer',
          value: 'created-plaintext',
        },
        '"connection-secrets:v1"',
      ),
      () => rotateConnectionSecret(
        'secret/one',
        {
          purpose: 'static_bearer',
          value: 'rotated-plaintext',
        },
        '"connection-secret:secret-1:v2"',
        '"connection-secrets:v2"',
        2,
      ),
      () => deleteConnectionSecret(
        'secret/one',
        '"connection-secret:secret-1:v3"',
        '"connection-secrets:v3"',
      ),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        name: ConnectionSecretContractError.name,
        requiresReload: true,
      });
    }
  });

  it('rejects an unchanged collection ETag after every mutation', async () => {
    const responses = [
      jsonResponse(
        201,
        secretMetadata({
          etag: '"connection-secret:secret-1:v2"',
          version: 2,
        }),
        {
          ETag: '"connection-secret:secret-1:v2"',
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v1"',
        },
      ),
      jsonResponse(
        200,
        secretMetadata({
          etag: '"connection-secret:secret-1:v3"',
          version: 3,
        }),
        {
          ETag: '"connection-secret:secret-1:v3"',
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v2"',
        },
      ),
      jsonResponse(
        200,
        { deleted_secret_id: 'secret/one' },
        {
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v3"',
        },
      ),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(responses.shift() as Response)),
    );

    const operations = [
      () =>
        createConnectionSecret(
          {
            label: 'Billing token',
            purpose: 'static_bearer',
            value: 'created-plaintext',
          },
          '"connection-secrets:v1"',
        ),
      () =>
        rotateConnectionSecret(
          'secret/one',
          {
            purpose: 'static_bearer',
            value: 'rotated-plaintext',
          },
          '"connection-secret:secret-1:v2"',
          '"connection-secrets:v2"',
          2,
        ),
      () =>
        deleteConnectionSecret(
          'secret/one',
          '"connection-secret:secret-1:v3"',
          '"connection-secrets:v3"',
        ),
    ];

    for (const operation of operations) {
      await expect(operation()).rejects.toMatchObject({
        name: ConnectionSecretContractError.name,
        requiresReload: true,
      });
    }
  });

  it('binds mutation metadata to the requested purpose and secret identity', async () => {
    const responses = [
      jsonResponse(
        201,
        secretMetadata({
          etag: '"connection-secret:secret-1:v2"',
          version: 2,
          compatible_purposes: ['header_api_key'],
        }),
        {
          ETag: '"connection-secret:secret-1:v2"',
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v2"',
        },
      ),
      jsonResponse(
        200,
        secretMetadata({
          id: 'different-secret',
          etag: '"connection-secret:different-secret:v3"',
          version: 3,
        }),
        {
          ETag: '"connection-secret:different-secret:v3"',
          'x-greengateway-connection-secrets-etag':
            '"connection-secrets:v3"',
        },
      ),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(responses.shift() as Response)),
    );

    await expect(
      createConnectionSecret(
        {
          label: 'Billing token',
          purpose: 'static_bearer',
          value: 'created-plaintext',
        },
        '"connection-secrets:v1"',
      ),
    ).rejects.toMatchObject({ requiresReload: true });
    await expect(
      rotateConnectionSecret(
        'secret-1',
        {
          purpose: 'static_bearer',
          value: 'rotated-plaintext',
        },
        '"connection-secret:secret-1:v2"',
        '"connection-secrets:v2"',
        2,
      ),
    ).rejects.toMatchObject({ requiresReload: true });
  });

  it('rejects forged successful mutation metadata without retrying', async () => {
    const forgedCreateMetadata = [
      { provider: 'operator_environment' },
      { configured: false },
      {
        compatible_purposes: [
          'static_bearer',
          'header_api_key',
        ],
      },
      { version: undefined },
      { version: 2 },
      { label: 'Different label' },
      {
        actions: {
          can_rotate: false,
          can_delete: true,
        },
      },
    ];
    const forgedRotateMetadata = [
      { version: 2 },
      { version: 4 },
    ];
    const responses = [
      ...forgedCreateMetadata.map((metadata) =>
        jsonResponse(
          201,
          secretMetadata(metadata),
          {
            ETag: '"connection-secret:secret-1:v1"',
            'x-greengateway-connection-secrets-etag':
              '"connection-secrets:v2"',
          },
        ),
      ),
      ...forgedRotateMetadata.map((metadata) =>
        jsonResponse(
          200,
          secretMetadata({
            etag: '"connection-secret:secret-1:v3"',
            ...metadata,
          }),
          {
            ETag: '"connection-secret:secret-1:v3"',
            'x-greengateway-connection-secrets-etag':
              '"connection-secrets:v3"',
          },
        ),
      ),
    ];
    const fetchMock = vi.fn(() =>
      Promise.resolve(responses.shift() as Response),
    );
    vi.stubGlobal('fetch', fetchMock);

    for (const _metadata of forgedCreateMetadata) {
      await expect(
        createConnectionSecret(
          {
            label: 'Billing token',
            purpose: 'static_bearer',
            value: 'created-plaintext',
          },
          '"connection-secrets:v1"',
        ),
      ).rejects.toMatchObject({
        name: ConnectionSecretContractError.name,
        requiresReload: true,
      });
    }
    for (const _metadata of forgedRotateMetadata) {
      await expect(
        rotateConnectionSecret(
          'secret-1',
          {
            purpose: 'static_bearer',
            value: 'rotated-plaintext',
          },
          '"connection-secret:secret-1:v2"',
          '"connection-secrets:v2"',
          2,
        ),
      ).rejects.toMatchObject({
        name: ConnectionSecretContractError.name,
        requiresReload: true,
      });
    }

    expect(fetchMock).toHaveBeenCalledTimes(
      forgedCreateMetadata.length + forgedRotateMetadata.length,
    );
  });

  it('requires a valid current local-secret version before rotation', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      rotateConnectionSecret(
        'secret-1',
        {
          purpose: 'static_bearer',
          value: 'rotated-plaintext',
        },
        '"connection-secret:secret-1:v2"',
        '"connection-secrets:v2"',
        0,
      ),
    ).rejects.toMatchObject({
      name: ConnectionSecretContractError.name,
      requiresReload: true,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

function secretMetadata(overrides: Record<string, unknown> = {}) {
  return {
    id: 'secret-1',
    etag: '"connection-secret:secret-1:v1"',
    label: 'Billing token',
    provider: 'local_encrypted',
    configured: true,
    compatible_purposes: ['static_bearer'],
    dependency_count: 0,
    version: 1,
    actions: {
      can_rotate: true,
      can_delete: true,
    },
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
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
