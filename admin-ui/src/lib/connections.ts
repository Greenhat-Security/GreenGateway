import { adminFetchResource, type AdminResource } from './api';
import { adminApiUrl } from './config';

export type ConnectionKind = 'http_api' | 'mcp_streamable_http';

export type ConnectionManagementSource =
  | 'managed'
  | 'legacy_default_http'
  | 'legacy_route'
  | 'legacy_mcp';

export type ConnectionAuthenticationKind =
  | 'none'
  | 'header_api_key'
  | 'static_bearer'
  | 'oauth2_client_credentials'
  | 'legacy_configured';

export type ConnectionOperationalState =
  | 'unknown'
  | 'configured'
  | 'healthy'
  | 'degraded'
  | 'unavailable'
  | 'disabled';

export type ConnectionStatusReason =
  | 'not_tested'
  | 'legacy_configured'
  | 'disabled'
  | 'test_succeeded'
  | 'catalog_refreshed'
  | 'request_failed'
  | 'egress_denied'
  | 'secret_unavailable'
  | 'invalid_response'
  | 'catalog_stale';

export type ConnectionRevisions = {
  connection: number;
  credential: number;
  tls: number;
  discovery: number;
  status: number;
};

export type ConnectionStatus = {
  state: ConnectionOperationalState;
  reason: ConnectionStatusReason;
  observed_at?: string;
  latency_ms?: number;
  catalog_age_secs?: number;
  catalog_entry_count?: number;
};

export type ConnectionActions = {
  can_update: boolean;
  can_bind_secret: boolean;
  can_manage_secrets: boolean;
  can_test: boolean;
  can_refresh: boolean;
  can_delete: boolean;
};

export type ConnectionCollectionActions = {
  can_create: boolean;
  can_bind_secret: boolean;
  can_manage_secrets: boolean;
};

export type ConnectionBaseSummary = {
  id: string;
  display_name: string;
  enabled: boolean;
  kind: ConnectionKind;
  source: ConnectionManagementSource;
  read_only: boolean;
  authentication: ConnectionAuthenticationKind;
  endpoint_count: number;
  revisions: ConnectionRevisions;
  status: ConnectionStatus;
};

export type ConnectionSummary = ConnectionBaseSummary & {
  sanitized_origin: string | null;
  capability_count: number;
  last_test_at: string | null;
  last_refresh_at: string | null;
  actions: ConnectionActions;
};

export type ConnectionListPage = {
  connections: ConnectionSummary[];
  next_cursor?: string;
  omitted_legacy_projection_count: number;
  actions: ConnectionCollectionActions;
};

export type ConnectionEndpoint = {
  base_url: string;
  base_path: string;
};

export type OAuthClientAuthMethod = 'client_secret_basic';

export type ConnectionAuthentication =
  | { type: 'none' }
  | {
      type: 'header_api_key';
      header_name: string;
      secret_id?: string;
      secret_configured?: boolean;
    }
  | {
      type: 'static_bearer';
      secret_id?: string;
      secret_configured?: boolean;
    }
  | {
      type: 'oauth2_client_credentials';
      client_id: string;
      client_secret_id?: string;
      client_secret_configured?: boolean;
      token_url: string;
      scopes?: string[];
      audience?: string;
      resource?: string;
      client_auth_method: OAuthClientAuthMethod;
    };

export type SafeConnectionAuthentication =
  | { type: 'none' }
  | {
      type: 'header_api_key';
      header_name: string;
      secret_configured: boolean;
    }
  | {
      type: 'static_bearer';
      secret_configured: boolean;
    }
  | {
      type: 'oauth2_client_credentials';
      client_id: string;
      token_url: string;
      scopes: string[];
      audience?: string;
      resource?: string;
      client_auth_method: OAuthClientAuthMethod;
      client_secret_configured: boolean;
    };

export type TlsProfile = {
  ca_bundle_alias?: string;
  client_certificate_id?: string;
  client_private_key_id?: string;
  ca_bundle_configured?: boolean;
  client_certificate_configured?: boolean;
  client_private_key_configured?: boolean;
};

export type SafeTlsConfiguration = {
  ca_bundle_configured: boolean;
  client_certificate_configured: boolean;
  client_private_key_configured: boolean;
};

export type ConnectionTimeouts = {
  connect_timeout_ms: number;
  request_timeout_ms: number;
  response_idle_timeout_ms: number;
};

export type DiscoveryConfig =
  | {
      type: 'managed_openapi';
      path?: string;
      use_connection_authentication: boolean;
    }
  | {
      type: 'managed_mcp';
      use_connection_authentication: boolean;
    };

export type ConnectionTestProfile = {
  method: string;
  path: string;
  expected_statuses: number[];
};

export type ConnectionWrite = {
  display_name: string;
  description?: string;
  enabled: boolean;
  kind: ConnectionKind;
  endpoint: ConnectionEndpoint;
  authentication: ConnectionAuthentication;
  tls: TlsProfile;
  timeouts?: ConnectionTimeouts;
  discovery?: DiscoveryConfig;
  test_profile?: ConnectionTestProfile;
};

export type SafeConnectionConfiguration = {
  description?: string;
  endpoint: ConnectionEndpoint;
  authentication: SafeConnectionAuthentication;
  tls: SafeTlsConfiguration;
  timeouts?: ConnectionTimeouts;
  discovery?: DiscoveryConfig;
  test_profile?: ConnectionTestProfile;
};

export type ConnectionDependencyKind =
  | 'proxy_route'
  | 'manual_tool'
  | 'managed_tool'
  | 'control_plane';

export type ConnectionDependency = {
  kind: ConnectionDependencyKind;
  consumer_id: string;
};

export type ConnectionDetail = ConnectionBaseSummary & {
  configuration?: SafeConnectionConfiguration;
  dependencies: ConnectionDependency[];
  actions: ConnectionActions;
  created_at?: string;
  updated_at?: string;
};

export type ConnectionDeletedResponse = {
  deleted_connection_id: string;
};

export type ConnectionTestStageName =
  | 'egress_policy'
  | 'secret_available'
  | 'connected'
  | 'tls_valid'
  | 'authenticated'
  | 'protocol_valid';

export type ConnectionTestStageOutcome =
  | 'success'
  | 'failure'
  | 'not_applicable';

export type ConnectionTestReason =
  | 'host_not_allowed'
  | 'port_not_allowed'
  | 'non_global_ip_blocked'
  | 'invalid_policy'
  | 'dns_resolution_failed'
  | 'invalid_url'
  | 'scheme_not_allowed'
  | 'request_body_too_large'
  | 'request_body_read_failed'
  | 'unexpected_status'
  | 'response_too_large'
  | 'response_idle_timeout'
  | 'http_timeout'
  | 'http_connect'
  | 'http_request'
  | 'http_body'
  | 'http_decode'
  | 'http_status'
  | 'http_other'
  | 'invalid_tls_ca_bundle'
  | 'invalid_tls_client_identity'
  | 'tls_invalid'
  | 'tls_unavailable'
  | 'authentication_not_supported'
  | 'credential_invalid'
  | 'credential_unavailable'
  | 'oauth_token_egress_denied'
  | 'oauth_token_unavailable'
  | 'oauth_token_rejected'
  | 'oauth_token_invalid_response'
  | 'authentication_failed'
  | 'transport_unavailable'
  | 'invalid_target_path'
  | 'connection_kind_mismatch'
  | 'connection_changed'
  | 'test_profile_not_configured'
  | 'protocol_error'
  | 'deadline_exceeded'
  | 'test_rate_limited'
  | 'test_busy'
  | 'test_capacity_reached'
  | 'internal_error';

export type ConnectionTestStage = {
  name: ConnectionTestStageName;
  outcome: ConnectionTestStageOutcome;
  reason?: ConnectionTestReason;
};

export type ConnectionTestResult = {
  ok: boolean;
  state: ConnectionOperationalState;
  tested_at: string;
  latency_ms: number;
  stages: ConnectionTestStage[];
};

export type ConnectionCatalogRefreshResult = {
  connection_id: string;
  catalog_revision: number;
  status: ConnectionStatus;
  total_count: number;
  added_count: number;
  changed_count: number;
  removed_count: number;
  spec_digest?: string;
  spec_revision?: number;
  registered_tool_names?: string[];
};

export class ConnectionContractError extends Error {
  readonly requiresReload: boolean;

  constructor(message: string, requiresReload = false) {
    super(message);
    this.name = 'ConnectionContractError';
    this.requiresReload = requiresReload;
  }
}

export type ConnectionListFilters = {
  enabled?: boolean;
  kind?: ConnectionKind;
  source?: ConnectionManagementSource;
  state?: ConnectionOperationalState;
  limit?: number;
  cursor?: string;
};

export async function listConnections(
  filters: ConnectionListFilters = {},
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionListPage>> {
  const params = new URLSearchParams();
  appendParam(params, 'enabled', filters.enabled);
  appendParam(params, 'kind', filters.kind);
  appendParam(params, 'source', filters.source);
  appendParam(params, 'state', filters.state);
  appendParam(params, 'limit', filters.limit);
  appendParam(params, 'cursor', filters.cursor);

  const query = params.toString();
  const resource = await adminFetchResource<unknown>(
    `${adminApiUrl('/connections')}${query ? `?${query}` : ''}`,
    { signal },
  );
  return {
    ...resource,
    value: projectConnectionListPage(resource.value),
  };
}

export async function getConnection(
  id: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionDetail>> {
  const resource = await adminFetchResource<unknown>(connectionUrl(id), {
    signal,
  });
  return {
    ...resource,
    value: projectConnectionDetail(resource.value, id),
  };
}

export async function createConnection(
  write: ConnectionWrite,
  collectionEtag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionDetail>> {
  const resource = await adminFetchResource<unknown>(
    adminApiUrl('/connections'),
    {
      method: 'POST',
      signal,
      headers: jsonMutationHeaders(collectionEtag),
      body: JSON.stringify(write),
    },
  );
  const value = projectConnectionMutationResponse('create', () =>
    projectConnectionDetail(resource.value),
  );
  if (
    resource.etag === null ||
    resource.collectionEtag === null ||
    resource.collectionEtag === collectionEtag ||
    resource.etag === resource.collectionEtag
  ) {
    throw ambiguousConnectionMutationResponse('create');
  }
  return {
    ...resource,
    value,
  };
}

export async function updateConnection(
  id: string,
  write: ConnectionWrite,
  etag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionDetail>> {
  const resource = await adminFetchResource<unknown>(connectionUrl(id), {
    method: 'PUT',
    signal,
    headers: jsonMutationHeaders(etag),
    body: JSON.stringify(write),
  });
  const value = projectConnectionMutationResponse('update', () =>
    projectConnectionDetail(resource.value, id),
  );
  if (resource.etag === null) {
    throw ambiguousConnectionMutationResponse('update');
  }
  return {
    ...resource,
    value,
  };
}

export async function deleteConnection(
  id: string,
  etag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionDeletedResponse>> {
  const resource = await adminFetchResource<unknown>(connectionUrl(id), {
    method: 'DELETE',
    signal,
    headers: { 'If-Match': etag },
  });
  const value = projectConnectionMutationResponse('delete', () =>
    projectConnectionDeletedResponse(resource.value, id),
  );
  return { ...resource, value };
}

export async function testConnection(
  id: string,
  etag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionTestResult>> {
  const resource = await adminFetchResource<unknown>(
    `${connectionUrl(id)}/test`,
    {
      method: 'POST',
      signal,
      headers: jsonMutationHeaders(etag),
    },
  );
  const value = projectConnectionMutationResponse('test', () =>
    projectConnectionTestResult(resource.value),
  );
  if (resource.etag !== etag) {
    throw ambiguousConnectionMutationResponse('test');
  }
  return { ...resource, value };
}

export async function refreshConnection(
  id: string,
  etag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionCatalogRefreshResult>> {
  const resource = await adminFetchResource<unknown>(
    `${connectionUrl(id)}/refresh`,
    {
      method: 'POST',
      signal,
      headers: jsonMutationHeaders(etag),
    },
  );
  const value = projectConnectionMutationResponse('refresh', () =>
    projectConnectionCatalogRefreshResult(resource.value, id),
  );
  if (resource.etag !== etag) {
    throw ambiguousConnectionMutationResponse('refresh');
  }
  return { ...resource, value };
}

function connectionUrl(id: string): string {
  return adminApiUrl(`/connections/${encodeURIComponent(id)}`);
}

function jsonMutationHeaders(etag: string): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'If-Match': etag,
  };
}

function appendParam(
  params: URLSearchParams,
  name: string,
  value: string | number | boolean | undefined,
): void {
  if (value !== undefined) {
    params.set(name, String(value));
  }
}

function projectConnectionListPage(value: unknown): ConnectionListPage {
  const source = responseObject(value, 'connection list');
  const actions = projectConnectionCollectionActions(source.actions);
  if (
    !Array.isArray(source.connections) ||
    !isNonNegativeInteger(source.omitted_legacy_projection_count) ||
    (source.next_cursor !== undefined &&
      typeof source.next_cursor !== 'string')
  ) {
    throw invalidConnectionResponse('connection list');
  }

  return {
    connections: source.connections.map(projectConnectionSummary),
    ...(source.next_cursor === undefined
      ? {}
      : { next_cursor: source.next_cursor }),
    omitted_legacy_projection_count:
      source.omitted_legacy_projection_count,
    actions,
  };
}

function projectConnectionSummary(value: unknown): ConnectionSummary {
  const source = responseObject(value, 'connection summary');
  if (
    (source.sanitized_origin !== null &&
      !isSanitizedHttpOrigin(source.sanitized_origin)) ||
    !isNonNegativeInteger(source.capability_count) ||
    !isNullableString(source.last_test_at) ||
    !isNullableString(source.last_refresh_at)
  ) {
    throw invalidConnectionResponse('connection summary');
  }

  return {
    ...projectConnectionBaseSummary(source),
    sanitized_origin: source.sanitized_origin,
    capability_count: source.capability_count,
    last_test_at: source.last_test_at,
    last_refresh_at: source.last_refresh_at,
    actions: projectConnectionActions(source.actions),
  };
}

function projectConnectionDetail(
  value: unknown,
  expectedId?: string,
): ConnectionDetail {
  const source = responseObject(value, 'connection detail');
  if (
    !Array.isArray(source.dependencies) ||
    (source.created_at !== undefined &&
      typeof source.created_at !== 'string') ||
    (source.updated_at !== undefined &&
      typeof source.updated_at !== 'string')
  ) {
    throw invalidConnectionResponse('connection detail');
  }
  const summary = projectConnectionBaseSummary(source);
  if (expectedId !== undefined && summary.id !== expectedId) {
    throw invalidConnectionResponse('connection detail');
  }

  return {
    ...summary,
    ...(source.configuration === undefined
      ? {}
      : {
          configuration: projectSafeConnectionConfiguration(
            source.configuration,
          ),
        }),
    dependencies: source.dependencies.map(projectConnectionDependency),
    actions: projectConnectionActions(source.actions),
    ...(source.created_at === undefined
      ? {}
      : { created_at: source.created_at }),
    ...(source.updated_at === undefined
      ? {}
      : { updated_at: source.updated_at }),
  };
}

function projectConnectionDeletedResponse(
  value: unknown,
  expectedId: string,
): ConnectionDeletedResponse {
  const source = responseObject(value, 'connection delete');
  if (
    typeof source.deleted_connection_id !== 'string' ||
    source.deleted_connection_id.length === 0 ||
    source.deleted_connection_id !== expectedId
  ) {
    throw invalidConnectionResponse('connection delete');
  }
  return {
    deleted_connection_id: source.deleted_connection_id,
  };
}

function projectConnectionTestResult(
  value: unknown,
): ConnectionTestResult {
  const source = responseObject(value, 'connection test');
  if (
    typeof source.ok !== 'boolean' ||
    !isConnectionOperationalState(source.state) ||
    typeof source.tested_at !== 'string' ||
    !isNonNegativeInteger(source.latency_ms) ||
    !Array.isArray(source.stages)
  ) {
    throw invalidConnectionResponse('connection test');
  }

  return {
    ok: source.ok,
    state: source.state,
    tested_at: source.tested_at,
    latency_ms: source.latency_ms,
    stages: source.stages.map(projectConnectionTestStage),
  };
}

function projectConnectionTestStage(
  value: unknown,
): ConnectionTestStage {
  const source = responseObject(value, 'connection test stage');
  if (
    !isConnectionTestStageName(source.name) ||
    !isConnectionTestStageOutcome(source.outcome) ||
    (source.reason !== undefined &&
      !isConnectionTestReason(source.reason))
  ) {
    throw invalidConnectionResponse('connection test stage');
  }

  return {
    name: source.name,
    outcome: source.outcome,
    ...(source.reason === undefined
      ? {}
      : { reason: source.reason }),
  };
}

function projectConnectionCatalogRefreshResult(
  value: unknown,
  expectedId: string,
): ConnectionCatalogRefreshResult {
  const source = responseObject(value, 'connection catalog refresh');
  if (
    typeof source.connection_id !== 'string' ||
    source.connection_id.length === 0 ||
    source.connection_id !== expectedId ||
    !isNonNegativeInteger(source.catalog_revision) ||
    !isNonNegativeInteger(source.total_count) ||
    !isNonNegativeInteger(source.added_count) ||
    !isNonNegativeInteger(source.changed_count) ||
    !isNonNegativeInteger(source.removed_count) ||
    (source.spec_digest !== undefined &&
      typeof source.spec_digest !== 'string') ||
    (source.spec_revision !== undefined &&
      !isNonNegativeInteger(source.spec_revision)) ||
    (source.registered_tool_names !== undefined &&
      (!Array.isArray(source.registered_tool_names) ||
        !source.registered_tool_names.every(
          (name) => typeof name === 'string',
        )))
  ) {
    throw invalidConnectionResponse('connection catalog refresh');
  }

  return {
    connection_id: source.connection_id,
    catalog_revision: source.catalog_revision,
    status: projectConnectionStatus(source.status),
    total_count: source.total_count,
    added_count: source.added_count,
    changed_count: source.changed_count,
    removed_count: source.removed_count,
    ...(source.spec_digest === undefined
      ? {}
      : { spec_digest: source.spec_digest }),
    ...(source.spec_revision === undefined
      ? {}
      : { spec_revision: source.spec_revision }),
    ...(source.registered_tool_names === undefined
      ? {}
      : {
          registered_tool_names: [
            ...source.registered_tool_names,
          ],
        }),
  };
}

function projectConnectionBaseSummary(
  value: unknown,
): ConnectionBaseSummary {
  const source = responseObject(value, 'connection base summary');
  if (
    typeof source.id !== 'string' ||
    source.id.length === 0 ||
    typeof source.display_name !== 'string' ||
    typeof source.enabled !== 'boolean' ||
    !isConnectionKind(source.kind) ||
    !isConnectionManagementSource(source.source) ||
    typeof source.read_only !== 'boolean' ||
    !isConnectionAuthenticationKind(source.authentication) ||
    !isNonNegativeInteger(source.endpoint_count)
  ) {
    throw invalidConnectionResponse('connection base summary');
  }

  return {
    id: source.id,
    display_name: source.display_name,
    enabled: source.enabled,
    kind: source.kind,
    source: source.source,
    read_only: source.read_only,
    authentication: source.authentication,
    endpoint_count: source.endpoint_count,
    revisions: projectConnectionRevisions(source.revisions),
    status: projectConnectionStatus(source.status),
  };
}

function projectConnectionRevisions(value: unknown): ConnectionRevisions {
  const source = responseObject(value, 'connection revisions');
  if (
    !isNonNegativeInteger(source.connection) ||
    !isNonNegativeInteger(source.credential) ||
    !isNonNegativeInteger(source.tls) ||
    !isNonNegativeInteger(source.discovery) ||
    !isNonNegativeInteger(source.status)
  ) {
    throw invalidConnectionResponse('connection revisions');
  }

  return {
    connection: source.connection,
    credential: source.credential,
    tls: source.tls,
    discovery: source.discovery,
    status: source.status,
  };
}

function projectConnectionStatus(value: unknown): ConnectionStatus {
  const source = responseObject(value, 'connection status');
  if (
    !isConnectionOperationalState(source.state) ||
    !isConnectionStatusReason(source.reason) ||
    (source.observed_at !== undefined &&
      typeof source.observed_at !== 'string') ||
    (source.latency_ms !== undefined &&
      !isNonNegativeInteger(source.latency_ms)) ||
    (source.catalog_age_secs !== undefined &&
      !isNonNegativeInteger(source.catalog_age_secs)) ||
    (source.catalog_entry_count !== undefined &&
      !isNonNegativeInteger(source.catalog_entry_count))
  ) {
    throw invalidConnectionResponse('connection status');
  }

  return {
    state: source.state,
    reason: source.reason,
    ...(source.observed_at === undefined
      ? {}
      : { observed_at: source.observed_at }),
    ...(source.latency_ms === undefined
      ? {}
      : { latency_ms: source.latency_ms }),
    ...(source.catalog_age_secs === undefined
      ? {}
      : { catalog_age_secs: source.catalog_age_secs }),
    ...(source.catalog_entry_count === undefined
      ? {}
      : { catalog_entry_count: source.catalog_entry_count }),
  };
}

function projectConnectionActions(value: unknown): ConnectionActions {
  const source = responseObject(value, 'connection actions');
  if (
    typeof source.can_update !== 'boolean' ||
    typeof source.can_bind_secret !== 'boolean' ||
    typeof source.can_manage_secrets !== 'boolean' ||
    typeof source.can_test !== 'boolean' ||
    typeof source.can_refresh !== 'boolean' ||
    typeof source.can_delete !== 'boolean'
  ) {
    throw invalidConnectionResponse('connection actions');
  }

  return {
    can_update: source.can_update,
    can_bind_secret: source.can_bind_secret,
    can_manage_secrets: source.can_manage_secrets,
    can_test: source.can_test,
    can_refresh: source.can_refresh,
    can_delete: source.can_delete,
  };
}

function projectConnectionCollectionActions(
  value: unknown,
): ConnectionCollectionActions {
  const source = responseObject(value, 'connection collection actions');
  if (
    typeof source.can_create !== 'boolean' ||
    typeof source.can_bind_secret !== 'boolean' ||
    typeof source.can_manage_secrets !== 'boolean'
  ) {
    throw invalidConnectionResponse('connection collection actions');
  }

  return {
    can_create: source.can_create,
    can_bind_secret: source.can_bind_secret,
    can_manage_secrets: source.can_manage_secrets,
  };
}

function projectSafeConnectionConfiguration(
  value: unknown,
): SafeConnectionConfiguration {
  const source = responseObject(value, 'safe connection configuration');
  if (
    source.description !== undefined &&
    typeof source.description !== 'string'
  ) {
    throw invalidConnectionResponse('safe connection configuration');
  }

  return {
    ...(source.description === undefined
      ? {}
      : { description: source.description }),
    endpoint: projectConnectionEndpoint(source.endpoint),
    authentication: projectSafeConnectionAuthentication(
      source.authentication,
    ),
    tls: projectSafeTlsConfiguration(source.tls),
    ...(source.timeouts === undefined
      ? {}
      : { timeouts: projectConnectionTimeouts(source.timeouts) }),
    ...(source.discovery === undefined
      ? {}
      : { discovery: projectDiscoveryConfig(source.discovery) }),
    ...(source.test_profile === undefined
      ? {}
      : {
          test_profile: projectConnectionTestProfile(
            source.test_profile,
          ),
        }),
  };
}

function projectConnectionEndpoint(value: unknown): ConnectionEndpoint {
  const source = responseObject(value, 'connection endpoint');
  if (
    !isSanitizedHttpOrigin(source.base_url) ||
    !isSafeOriginRelativePath(source.base_path)
  ) {
    throw invalidConnectionResponse('connection endpoint');
  }
  return {
    base_url: source.base_url,
    base_path: source.base_path,
  };
}

function projectSafeConnectionAuthentication(
  value: unknown,
): SafeConnectionAuthentication {
  const source = responseObject(value, 'safe connection authentication');
  if (source.type === 'none') {
    return { type: 'none' };
  }
  if (
    source.type === 'header_api_key' &&
    typeof source.header_name === 'string' &&
    typeof source.secret_configured === 'boolean'
  ) {
    return {
      type: 'header_api_key',
      header_name: source.header_name,
      secret_configured: source.secret_configured,
    };
  }
  if (
    source.type === 'static_bearer' &&
    typeof source.secret_configured === 'boolean'
  ) {
    return {
      type: 'static_bearer',
      secret_configured: source.secret_configured,
    };
  }
  if (
    source.type === 'oauth2_client_credentials' &&
    typeof source.client_id === 'string' &&
    isSafeHttpsTokenUrl(source.token_url) &&
    Array.isArray(source.scopes) &&
    source.scopes.every((scope) => typeof scope === 'string') &&
    (source.audience === undefined ||
      typeof source.audience === 'string') &&
    (source.resource === undefined ||
      typeof source.resource === 'string') &&
    source.client_auth_method === 'client_secret_basic' &&
    typeof source.client_secret_configured === 'boolean'
  ) {
    return {
      type: 'oauth2_client_credentials',
      client_id: source.client_id,
      token_url: source.token_url,
      scopes: [...source.scopes],
      ...(source.audience === undefined
        ? {}
        : { audience: source.audience }),
      ...(source.resource === undefined
        ? {}
        : { resource: source.resource }),
      client_auth_method: source.client_auth_method,
      client_secret_configured: source.client_secret_configured,
    };
  }

  throw invalidConnectionResponse('safe connection authentication');
}

function projectSafeTlsConfiguration(
  value: unknown,
): SafeTlsConfiguration {
  const source = responseObject(value, 'safe TLS configuration');
  if (
    typeof source.ca_bundle_configured !== 'boolean' ||
    typeof source.client_certificate_configured !== 'boolean' ||
    typeof source.client_private_key_configured !== 'boolean'
  ) {
    throw invalidConnectionResponse('safe TLS configuration');
  }
  return {
    ca_bundle_configured: source.ca_bundle_configured,
    client_certificate_configured:
      source.client_certificate_configured,
    client_private_key_configured:
      source.client_private_key_configured,
  };
}

function projectConnectionTimeouts(value: unknown): ConnectionTimeouts {
  const source = responseObject(value, 'connection timeouts');
  if (
    !isNonNegativeInteger(source.connect_timeout_ms) ||
    !isNonNegativeInteger(source.request_timeout_ms) ||
    !isNonNegativeInteger(source.response_idle_timeout_ms)
  ) {
    throw invalidConnectionResponse('connection timeouts');
  }
  return {
    connect_timeout_ms: source.connect_timeout_ms,
    request_timeout_ms: source.request_timeout_ms,
    response_idle_timeout_ms: source.response_idle_timeout_ms,
  };
}

function projectDiscoveryConfig(value: unknown): DiscoveryConfig {
  const source = responseObject(value, 'connection discovery');
  if (
    source.type === 'managed_openapi' &&
    (source.path === undefined ||
      isSafeOriginRelativePath(source.path)) &&
    typeof source.use_connection_authentication === 'boolean'
  ) {
    return {
      type: 'managed_openapi',
      ...(source.path === undefined ? {} : { path: source.path }),
      use_connection_authentication:
        source.use_connection_authentication,
    };
  }
  if (
    source.type === 'managed_mcp' &&
    typeof source.use_connection_authentication === 'boolean'
  ) {
    return {
      type: 'managed_mcp',
      use_connection_authentication:
        source.use_connection_authentication,
    };
  }

  throw invalidConnectionResponse('connection discovery');
}

function projectConnectionTestProfile(
  value: unknown,
): ConnectionTestProfile {
  const source = responseObject(value, 'connection test profile');
  if (
    (source.method !== 'GET' && source.method !== 'HEAD') ||
    !isSafeOriginRelativePath(source.path) ||
    !Array.isArray(source.expected_statuses) ||
    !source.expected_statuses.every(isHttpStatusCode)
  ) {
    throw invalidConnectionResponse('connection test profile');
  }
  return {
    method: source.method,
    path: source.path,
    expected_statuses: [...source.expected_statuses],
  };
}

function projectConnectionDependency(
  value: unknown,
): ConnectionDependency {
  const source = responseObject(value, 'connection dependency');
  if (
    !isConnectionDependencyKind(source.kind) ||
    typeof source.consumer_id !== 'string'
  ) {
    throw invalidConnectionResponse('connection dependency');
  }
  return {
    kind: source.kind,
    consumer_id: source.consumer_id,
  };
}

function responseObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidConnectionResponse(label);
  }
  return value as Record<string, unknown>;
}

function isConnectionKind(value: unknown): value is ConnectionKind {
  return value === 'http_api' || value === 'mcp_streamable_http';
}

function isConnectionManagementSource(
  value: unknown,
): value is ConnectionManagementSource {
  return (
    value === 'managed' ||
    value === 'legacy_default_http' ||
    value === 'legacy_route' ||
    value === 'legacy_mcp'
  );
}

function isConnectionAuthenticationKind(
  value: unknown,
): value is ConnectionAuthenticationKind {
  return (
    value === 'none' ||
    value === 'header_api_key' ||
    value === 'static_bearer' ||
    value === 'oauth2_client_credentials' ||
    value === 'legacy_configured'
  );
}

function isConnectionOperationalState(
  value: unknown,
): value is ConnectionOperationalState {
  return (
    value === 'unknown' ||
    value === 'configured' ||
    value === 'healthy' ||
    value === 'degraded' ||
    value === 'unavailable' ||
    value === 'disabled'
  );
}

function isConnectionStatusReason(
  value: unknown,
): value is ConnectionStatusReason {
  return (
    value === 'not_tested' ||
    value === 'legacy_configured' ||
    value === 'disabled' ||
    value === 'test_succeeded' ||
    value === 'catalog_refreshed' ||
    value === 'request_failed' ||
    value === 'egress_denied' ||
    value === 'secret_unavailable' ||
    value === 'invalid_response' ||
    value === 'catalog_stale'
  );
}

function isConnectionTestStageName(
  value: unknown,
): value is ConnectionTestStageName {
  return (
    value === 'egress_policy' ||
    value === 'secret_available' ||
    value === 'connected' ||
    value === 'tls_valid' ||
    value === 'authenticated' ||
    value === 'protocol_valid'
  );
}

function isConnectionTestStageOutcome(
  value: unknown,
): value is ConnectionTestStageOutcome {
  return (
    value === 'success' ||
    value === 'failure' ||
    value === 'not_applicable'
  );
}

function isConnectionTestReason(
  value: unknown,
): value is ConnectionTestReason {
  return (
    value === 'host_not_allowed' ||
    value === 'port_not_allowed' ||
    value === 'non_global_ip_blocked' ||
    value === 'invalid_policy' ||
    value === 'dns_resolution_failed' ||
    value === 'invalid_url' ||
    value === 'scheme_not_allowed' ||
    value === 'request_body_too_large' ||
    value === 'request_body_read_failed' ||
    value === 'unexpected_status' ||
    value === 'response_too_large' ||
    value === 'response_idle_timeout' ||
    value === 'http_timeout' ||
    value === 'http_connect' ||
    value === 'http_request' ||
    value === 'http_body' ||
    value === 'http_decode' ||
    value === 'http_status' ||
    value === 'http_other' ||
    value === 'invalid_tls_ca_bundle' ||
    value === 'invalid_tls_client_identity' ||
    value === 'tls_invalid' ||
    value === 'tls_unavailable' ||
    value === 'authentication_not_supported' ||
    value === 'credential_invalid' ||
    value === 'credential_unavailable' ||
    value === 'oauth_token_egress_denied' ||
    value === 'oauth_token_unavailable' ||
    value === 'oauth_token_rejected' ||
    value === 'oauth_token_invalid_response' ||
    value === 'authentication_failed' ||
    value === 'transport_unavailable' ||
    value === 'invalid_target_path' ||
    value === 'connection_kind_mismatch' ||
    value === 'connection_changed' ||
    value === 'test_profile_not_configured' ||
    value === 'protocol_error' ||
    value === 'deadline_exceeded' ||
    value === 'test_rate_limited' ||
    value === 'test_busy' ||
    value === 'test_capacity_reached' ||
    value === 'internal_error'
  );
}

function isConnectionDependencyKind(
  value: unknown,
): value is ConnectionDependencyKind {
  return (
    value === 'proxy_route' ||
    value === 'manual_tool' ||
    value === 'managed_tool' ||
    value === 'control_plane'
  );
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function isSanitizedHttpOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }

  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.hostname.length > 0 &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      parsed.pathname === '/' &&
      parsed.search.length === 0 &&
      parsed.hash.length === 0 &&
      value === parsed.origin
    );
  } catch {
    return false;
  }
}

function isSafeHttpsTokenUrl(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !value.startsWith('https://') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('\\') ||
    hasUnsafeAsciiCharacter(value)
  ) {
    return false;
  }

  try {
    const parsed = new URL(value);
    const rawPath = rawAbsoluteUrlPath(value);
    return (
      parsed.protocol === 'https:' &&
      parsed.hostname.length > 0 &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      parsed.search.length === 0 &&
      parsed.hash.length === 0 &&
      rawPath !== null &&
      isSafeOriginRelativePath(rawPath)
    );
  } catch {
    return false;
  }
}

function rawAbsoluteUrlPath(value: string): string | null {
  const schemeEnd = value.indexOf('://');
  if (schemeEnd < 0) {
    return null;
  }
  const afterScheme = value.slice(schemeEnd + 3);
  const pathStart = afterScheme.search(/[/?#]/);
  if (pathStart < 0) {
    return '/';
  }
  const suffix = afterScheme.slice(pathStart);
  return suffix.startsWith('/') ? suffix : null;
}

function isSafeOriginRelativePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('//') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('\\') ||
    hasUnsafeAsciiCharacter(value) ||
    hasInvalidPercentEscape(value)
  ) {
    return false;
  }

  for (const segment of value.split('/')) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return false;
    }
    if (
      decoded === '.' ||
      decoded === '..' ||
      decoded.includes('/') ||
      decoded.includes('\\') ||
      decoded.includes('\0')
    ) {
      return false;
    }
  }
  return true;
}

function hasUnsafeAsciiCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function hasInvalidPercentEscape(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '%') {
      continue;
    }
    if (
      index + 2 >= value.length ||
      !isHexDigit(value[index + 1]) ||
      !isHexDigit(value[index + 2])
    ) {
      return true;
    }
    index += 2;
  }
  return false;
}

function isHexDigit(value: string): boolean {
  return /^[0-9A-Fa-f]$/.test(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isHttpStatusCode(value: unknown): value is number {
  return (
    isNonNegativeInteger(value) &&
    value >= 100 &&
    value <= 599
  );
}

function projectConnectionMutationResponse<T>(
  operation: string,
  project: () => T,
): T {
  try {
    return project();
  } catch {
    throw ambiguousConnectionMutationResponse(operation);
  }
}

function invalidConnectionResponse(
  label: string,
): ConnectionContractError {
  return new ConnectionContractError(
    `The gateway returned an invalid ${label} response.`,
  );
}

function ambiguousConnectionMutationResponse(
  operation: string,
): ConnectionContractError {
  return new ConnectionContractError(
    `The gateway accepted the connection ${operation} request without returning a complete, matching version. Reload connection metadata before any further mutation.`,
    true,
  );
}
