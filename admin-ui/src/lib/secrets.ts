import { adminFetchResource, type AdminResource } from './api';
import { adminApiUrl } from './config';

export type ConnectionSecretPurpose =
  | 'header_api_key'
  | 'static_bearer'
  | 'oauth_client_secret'
  | 'tls_private_key'
  | 'tls_certificate'
  | 'tls_ca_bundle';

export type ConnectionSecretProvider =
  | 'operator_environment'
  | 'operator_file'
  | 'local_encrypted';

export type ConnectionSecretActions = {
  can_rotate: boolean;
  can_delete: boolean;
};

export type ConnectionSecretMetadata = {
  id: string;
  etag: string;
  label: string;
  provider: ConnectionSecretProvider;
  configured: boolean;
  compatible_purposes: ConnectionSecretPurpose[];
  dependency_count: number;
  version?: number;
  rotated_at?: string;
  actions: ConnectionSecretActions;
};

export type ConnectionSecretCollectionActions = {
  can_create: boolean;
};

export type ConnectionSecretProviderAvailability = {
  operator_aliases: boolean;
  local_encrypted: boolean;
};

export type ConnectionSecretListResponse = {
  secrets: ConnectionSecretMetadata[];
  actions: ConnectionSecretCollectionActions;
  providers: ConnectionSecretProviderAvailability;
};

/**
 * `value` is write-only plaintext. The server returns metadata and never echoes
 * or exposes stored secret material.
 */
export type CreateConnectionSecretInput = {
  label: string;
  purpose: ConnectionSecretPurpose;
  value: string;
};

/**
 * `value` is write-only plaintext. Rotation has no automatic retry so a caller
 * cannot accidentally repeat a secret mutation after an ambiguous response.
 */
export type RotateConnectionSecretInput = {
  purpose: ConnectionSecretPurpose;
  value: string;
};

export type ConnectionSecretDeletedResponse = {
  deleted_secret_id: string;
};

export class ConnectionSecretContractError extends Error {
  readonly requiresReload: boolean;

  constructor(message: string, requiresReload = false) {
    super(message);
    this.name = 'ConnectionSecretContractError';
    this.requiresReload = requiresReload;
  }
}

export async function listConnectionSecrets(
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionSecretListResponse>> {
  const resource = await adminFetchResource<unknown>(
    adminApiUrl('/connection-secrets'),
    { signal },
  );
  return {
    ...resource,
    value: projectSecretListResponse(resource.value),
  };
}

export async function createConnectionSecret(
  input: CreateConnectionSecretInput,
  collectionEtag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionSecretMetadata>> {
  const normalizedInput = {
    ...input,
    label: input.label.trim(),
  };
  const resource = await adminFetchResource<unknown>(
    adminApiUrl('/connection-secrets'),
    {
      method: 'POST',
      signal,
      headers: jsonMutationHeaders(collectionEtag),
      body: JSON.stringify(normalizedInput),
    },
  );
  return projectSecretMutationResource(
    resource,
    'create',
    collectionEtag,
    collectionEtag,
    undefined,
    normalizedInput.purpose,
    normalizedInput.label,
    undefined,
  );
}

export async function rotateConnectionSecret(
  id: string,
  input: RotateConnectionSecretInput,
  etag: string,
  collectionEtag: string,
  previousVersion: number,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionSecretMetadata>> {
  if (
    !isPositiveInteger(previousVersion) ||
    previousVersion >= Number.MAX_SAFE_INTEGER
  ) {
    throw ambiguousMutationResponse('rotate precondition');
  }
  const resource = await adminFetchResource<unknown>(secretUrl(id), {
    method: 'PUT',
    signal,
    headers: jsonMutationHeaders(etag),
    body: JSON.stringify(input),
  });
  return projectSecretMutationResource(
    resource,
    'rotate',
    etag,
    collectionEtag,
    id,
    input.purpose,
    undefined,
    previousVersion,
  );
}

export async function deleteConnectionSecret(
  id: string,
  etag: string,
  collectionEtag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionSecretDeletedResponse>> {
  const resource = await adminFetchResource<unknown>(secretUrl(id), {
    method: 'DELETE',
    signal,
    headers: { 'If-Match': etag },
  });
  const value = projectDeletedSecret(resource.value, true);
  if (
    value.deleted_secret_id !== id ||
    resource.collectionEtag === null ||
    resource.collectionEtag === collectionEtag
  ) {
    throw ambiguousMutationResponse('delete');
  }
  return {
    value,
    etag: null,
    collectionEtag: resource.collectionEtag,
  };
}

function secretUrl(id: string): string {
  return adminApiUrl(`/connection-secrets/${encodeURIComponent(id)}`);
}

function jsonMutationHeaders(etag: string): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'If-Match': etag,
  };
}

function projectSecretListResponse(
  value: unknown,
): ConnectionSecretListResponse {
  const source = responseObject(value, 'secret list', false);
  if (!Array.isArray(source.secrets)) {
    throw invalidResponse('secret list');
  }
  const actions = responseObject(
    source.actions,
    'secret list actions',
    false,
  );
  const providers = responseObject(
    source.providers,
    'secret provider availability',
    false,
  );
  if (
    typeof actions.can_create !== 'boolean' ||
    typeof providers.operator_aliases !== 'boolean' ||
    typeof providers.local_encrypted !== 'boolean'
  ) {
    throw invalidResponse('secret list');
  }
  return {
    secrets: source.secrets.map((secret) =>
      projectSecretMetadata(secret, false),
    ),
    actions: {
      can_create: actions.can_create,
    },
    providers: {
      operator_aliases: providers.operator_aliases,
      local_encrypted: providers.local_encrypted,
    },
  };
}

function projectSecretMutationResource(
  resource: AdminResource<unknown>,
  operation: 'create' | 'rotate',
  previousEtag: string,
  previousCollectionEtag: string,
  expectedId: string | undefined,
  expectedPurpose: ConnectionSecretPurpose,
  expectedLabel: string | undefined,
  previousVersion: number | undefined,
): AdminResource<ConnectionSecretMetadata> {
  const value = projectSecretMetadata(resource.value, true);
  const versionMatches =
    operation === 'create'
      ? value.version === 1
      : previousVersion !== undefined &&
        value.version === previousVersion + 1;
  if (
    resource.etag === null ||
    resource.collectionEtag === null ||
    resource.etag !== value.etag ||
    resource.etag === resource.collectionEtag ||
    resource.etag === previousEtag ||
    resource.collectionEtag === previousCollectionEtag ||
    (expectedId !== undefined && value.id !== expectedId) ||
    (expectedLabel !== undefined && value.label !== expectedLabel) ||
    value.provider !== 'local_encrypted' ||
    value.configured !== true ||
    value.actions.can_rotate !== true ||
    value.compatible_purposes.length !== 1 ||
    value.compatible_purposes[0] !== expectedPurpose ||
    !versionMatches
  ) {
    throw ambiguousMutationResponse(operation);
  }
  return {
    value,
    etag: resource.etag,
    collectionEtag: resource.collectionEtag,
  };
}

function projectSecretMetadata(
  value: unknown,
  mutation: boolean,
): ConnectionSecretMetadata {
  const source = responseObject(value, 'secret metadata', mutation);
  const actions = responseObject(
    source.actions,
    'secret metadata actions',
    mutation,
  );
  if (
    typeof source.id !== 'string' ||
    source.id.length === 0 ||
    typeof source.etag !== 'string' ||
    source.etag.length === 0 ||
    typeof source.label !== 'string' ||
    !isSecretProvider(source.provider) ||
    typeof source.configured !== 'boolean' ||
    !Array.isArray(source.compatible_purposes) ||
    !source.compatible_purposes.every(isSecretPurpose) ||
    !isNonNegativeInteger(source.dependency_count) ||
    typeof actions.can_rotate !== 'boolean' ||
    typeof actions.can_delete !== 'boolean' ||
    (source.version !== undefined &&
      !isNonNegativeInteger(source.version)) ||
    (source.rotated_at !== undefined &&
      typeof source.rotated_at !== 'string')
  ) {
    throw mutation
      ? ambiguousMutationResponse('secret')
      : invalidResponse('secret metadata');
  }

  return {
    id: source.id,
    etag: source.etag,
    label: source.label,
    provider: source.provider,
    configured: source.configured,
    compatible_purposes: [...source.compatible_purposes],
    dependency_count: source.dependency_count,
    ...(source.version === undefined
      ? {}
      : { version: source.version }),
    ...(source.rotated_at === undefined
      ? {}
      : { rotated_at: source.rotated_at }),
    actions: {
      can_rotate: actions.can_rotate,
      can_delete: actions.can_delete,
    },
  };
}

function projectDeletedSecret(
  value: unknown,
  mutation: boolean,
): ConnectionSecretDeletedResponse {
  const source = responseObject(value, 'secret delete', mutation);
  if (
    typeof source.deleted_secret_id !== 'string' ||
    source.deleted_secret_id.length === 0
  ) {
    throw ambiguousMutationResponse('delete');
  }
  return {
    deleted_secret_id: source.deleted_secret_id,
  };
}

function responseObject(
  value: unknown,
  label: string,
  mutation: boolean,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw mutation
      ? ambiguousMutationResponse(label)
      : invalidResponse(label);
  }
  return value as Record<string, unknown>;
}

function isSecretProvider(
  value: unknown,
): value is ConnectionSecretProvider {
  return (
    value === 'operator_environment' ||
    value === 'operator_file' ||
    value === 'local_encrypted'
  );
}

function isSecretPurpose(
  value: unknown,
): value is ConnectionSecretPurpose {
  return (
    value === 'header_api_key' ||
    value === 'static_bearer' ||
    value === 'oauth_client_secret' ||
    value === 'tls_private_key' ||
    value === 'tls_certificate' ||
    value === 'tls_ca_bundle'
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value > 0;
}

function invalidResponse(label: string): ConnectionSecretContractError {
  return new ConnectionSecretContractError(
    `The gateway returned an invalid ${label} response.`,
  );
}

function ambiguousMutationResponse(
  operation: string,
): ConnectionSecretContractError {
  return new ConnectionSecretContractError(
    `The gateway accepted the secret ${operation} request without returning a complete, matching version. Reload secret metadata before any further mutation.`,
    true,
  );
}
