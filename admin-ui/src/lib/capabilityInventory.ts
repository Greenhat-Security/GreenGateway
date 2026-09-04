import { adminFetchResource, type AdminResource } from './api';
import { adminApiUrl } from './config';
import type {
  ConnectionKind,
  ConnectionManagementSource,
} from './connections';

const MAX_CAPABILITY_PAGE_ITEMS = 100;
const MAX_CAPABILITY_TOTAL_COUNT = 8_192;
const MAX_CURSOR_BYTES = 4_096;
const MAX_PUBLIC_STRING_BYTES = 65_536;
const MAX_DESCRIPTION_BYTES = 8_192;
const MAX_MAPPING_QUERY_PARAMS = 4_096;
const MAX_INPUT_SCHEMA_BYTES = 2 * 1_048_576;
const MAX_INPUT_SCHEMA_DEPTH = 128;
const MAX_INPUT_SCHEMA_NODES = 65_536;
const MAX_INPUT_SCHEMA_OBJECT_KEYS = 16_384;
const MAX_INPUT_SCHEMA_KEY_BYTES = 4_096;

export type CapabilityKind = 'tool' | 'resource' | 'resource_template';

export type CapabilitySourceFilter =
  | 'manual_file'
  | 'openapi'
  | 'mcp_discovery'
  | 'projected_legacy_config';

export type CapabilityAvailabilityFilter =
  | 'available'
  | 'unavailable'
  | 'stale';

export type CapabilitySource =
  | { type: 'manual_file' }
  | {
      type: 'openapi';
      connection_id: string;
      operation_id?: string;
      catalog_revision: number;
      spec_revision: number;
      spec_digest: string;
    }
  | {
      type: 'mcp_discovery';
      connection_id: string;
      remote_tool_name?: string;
    }
  | {
      type: 'projected_legacy_config';
      connection_id: string;
      remote_tool_name: string;
    };

export type CapabilityConnection = {
  id: string;
  kind: ConnectionKind;
  management_source: ConnectionManagementSource;
};

export type CapabilityState = {
  enabled: boolean;
  available: boolean;
  stale: boolean;
  reason: string;
};

export type CapabilityPolicyEligibility = {
  eligible: boolean;
  reason: string;
};

export type ToolAnnotations = {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
};

export type CapabilitySummary = {
  id: string;
  kind: CapabilityKind;
  name: string;
  title?: string;
  annotations?: ToolAnnotations;
  uri?: string;
  uri_template?: string;
  description?: string;
  description_truncated: boolean;
  source: CapabilitySource;
  connection?: CapabilityConnection;
  schema_digest?: string;
  discovered_at?: string;
  last_success_at?: string;
  state: CapabilityState;
  policy: CapabilityPolicyEligibility;
};

export type CapabilityQueryParamMapping = {
  arg_name: string;
  query_name: string;
  required: boolean;
};

export type CapabilityBodyMapping = {
  mode: 'whole_args_json';
};

export type CapabilityMapping =
  | {
      type: 'http';
      method: string;
      path_template: string;
      query_params: CapabilityQueryParamMapping[];
      body?: CapabilityBodyMapping;
    }
  | {
      type: 'mcp';
      remote_tool_name: string;
    }
  | {
      type: 'resource';
      uri: string;
      mime_type?: string;
      size?: number;
    }
  | {
      type: 'resource_template';
      uri_template: string;
      mime_type?: string;
    };

export type CapabilityDetail = CapabilitySummary & {
  input_json_schema?: unknown;
  mapping?: CapabilityMapping;
  actions: CapabilityActions;
};

export type CapabilityActions = {
  can_execute: boolean;
  reason:
    | 'allowed'
    | 'permission_denied'
    | 'metadata_only'
    | 'disabled'
    | 'unavailable'
    | 'stale'
    | 'policy_denied'
    | 'executor_unavailable';
};

export type CapabilityListPage = {
  capabilities: CapabilitySummary[];
  next_cursor?: string;
  total_count: number;
};

export type CapabilityListFilters = {
  kind?: CapabilityKind;
  connectionId?: string;
  source?: CapabilitySourceFilter;
  available?: boolean;
  availability?: CapabilityAvailabilityFilter;
  text?: string;
  limit?: number;
  cursor?: string;
};

export class CapabilityContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CapabilityContractError';
  }
}

export async function listCapabilityInventory(
  filters: CapabilityListFilters = {},
  signal?: AbortSignal,
): Promise<AdminResource<CapabilityListPage>> {
  const params = new URLSearchParams();
  appendParam(params, 'kind', filters.kind);
  appendParam(params, 'connection_id', filters.connectionId);
  appendParam(params, 'source', filters.source);
  appendParam(params, 'available', filters.available);
  appendParam(params, 'availability', filters.availability);
  appendParam(params, 'text', filters.text?.trim() || undefined);
  appendParam(params, 'limit', filters.limit);
  appendParam(params, 'cursor', filters.cursor);

  const query = params.toString();
  const resource = await adminFetchResource<unknown>(
    `${adminApiUrl('/tools')}${query ? `?${query}` : ''}`,
    { signal },
  );
  return {
    ...resource,
    value: projectCapabilityListPage(resource.value),
  };
}

export async function getCapability(
  id: string,
  signal?: AbortSignal,
): Promise<AdminResource<CapabilityDetail>> {
  const resource = await adminFetchResource<unknown>(
    adminApiUrl(`/tools/${encodeURIComponent(id)}`),
    { signal, cache: 'no-store' },
  );
  return {
    ...resource,
    value: projectCapabilityDetail(resource.value, id),
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

function projectCapabilityListPage(value: unknown): CapabilityListPage {
  const source = responseObject(value, 'capability list');
  if (
    !Array.isArray(source.capabilities) ||
    source.capabilities.length > MAX_CAPABILITY_PAGE_ITEMS ||
    !isNonNegativeInteger(source.total_count) ||
    source.total_count > MAX_CAPABILITY_TOTAL_COUNT ||
    source.total_count < source.capabilities.length ||
    (source.next_cursor !== undefined &&
      !isBoundedNonEmptyString(source.next_cursor, MAX_CURSOR_BYTES))
  ) {
    throw invalidCapabilityResponse('capability list');
  }

  const capabilities = source.capabilities.map(projectCapabilitySummary);
  if (new Set(capabilities.map(({ id }) => id)).size !== capabilities.length) {
    throw invalidCapabilityResponse('capability list');
  }

  return {
    capabilities,
    ...(source.next_cursor === undefined
      ? {}
      : { next_cursor: source.next_cursor }),
    total_count: source.total_count,
  };
}

function projectCapabilityDetail(
  value: unknown,
  expectedId: string,
): CapabilityDetail {
  const source = responseObject(value, 'capability detail');
  const summary = projectCapabilitySummary(source);
  if (summary.id !== expectedId) {
    throw invalidCapabilityResponse('capability detail');
  }

  const inputJsonSchema =
    source.input_json_schema === undefined
      ? undefined
      : projectInputJsonSchema(source.input_json_schema);
  const mapping =
    source.mapping === undefined
      ? undefined
      : projectCapabilityMapping(source.mapping, summary);
  const actions = projectCapabilityActions(source.actions);

  return {
    ...summary,
    ...(inputJsonSchema === undefined
      ? {}
      : { input_json_schema: inputJsonSchema }),
    ...(mapping === undefined ? {} : { mapping }),
    actions,
  };
}

function projectCapabilityActions(value: unknown): CapabilityActions {
  const source = responseObject(value, 'capability actions');
  if (
    typeof source.can_execute !== 'boolean' ||
    !isCapabilityExecuteReason(source.reason) ||
    source.can_execute !== (source.reason === 'allowed')
  ) {
    throw invalidCapabilityResponse('capability actions');
  }
  return {
    can_execute: source.can_execute,
    reason: source.reason,
  };
}

function isCapabilityExecuteReason(
  value: unknown,
): value is CapabilityActions['reason'] {
  return (
    value === 'allowed' ||
    value === 'permission_denied' ||
    value === 'metadata_only' ||
    value === 'disabled' ||
    value === 'unavailable' ||
    value === 'stale' ||
    value === 'policy_denied' ||
    value === 'executor_unavailable'
  );
}

function projectCapabilitySummary(value: unknown): CapabilitySummary {
  const source = responseObject(value, 'capability summary');
  if (
    !isBoundedNonEmptyString(source.id, MAX_PUBLIC_STRING_BYTES) ||
    !isCapabilityKind(source.kind) ||
    !isBoundedNonEmptyString(source.name, MAX_PUBLIC_STRING_BYTES) ||
    !isOptionalBoundedString(source.title, MAX_PUBLIC_STRING_BYTES) ||
    !isOptionalBoundedNonEmptyString(source.uri, MAX_PUBLIC_STRING_BYTES) ||
    !isOptionalBoundedNonEmptyString(
      source.uri_template,
      MAX_PUBLIC_STRING_BYTES,
    ) ||
    !isOptionalBoundedString(source.description, MAX_DESCRIPTION_BYTES) ||
    typeof source.description_truncated !== 'boolean' ||
    !isOptionalSafeDigest(source.schema_digest) ||
    !isOptionalTimestamp(source.discovered_at) ||
    !isOptionalTimestamp(source.last_success_at)
  ) {
    throw invalidCapabilityResponse('capability summary');
  }

  const annotations =
    source.annotations === undefined
      ? undefined
      : projectToolAnnotations(source.annotations);

  if (
    (source.kind === 'tool' &&
      (source.uri !== undefined || source.uri_template !== undefined)) ||
    (source.kind !== 'tool' && annotations !== undefined) ||
    (source.kind === 'resource' &&
      (source.uri === undefined || source.uri_template !== undefined)) ||
    (source.kind === 'resource_template' &&
      (source.uri !== undefined || source.uri_template === undefined))
  ) {
    throw invalidCapabilityResponse('capability summary');
  }

  const projectedSource = projectCapabilitySource(source.source);
  const connection =
    source.connection === undefined
      ? undefined
      : projectCapabilityConnection(source.connection);
  if (
    connection !== undefined &&
    projectedSource.type !== 'manual_file' &&
    connection.id !== projectedSource.connection_id
  ) {
    throw invalidCapabilityResponse('capability summary');
  }

  return {
    id: source.id,
    kind: source.kind,
    name: source.name,
    ...(source.title === undefined ? {} : { title: source.title }),
    ...(annotations === undefined ? {} : { annotations }),
    ...(source.uri === undefined ? {} : { uri: source.uri }),
    ...(source.uri_template === undefined
      ? {}
      : { uri_template: source.uri_template }),
    ...(source.description === undefined
      ? {}
      : { description: source.description }),
    description_truncated: source.description_truncated,
    source: projectedSource,
    ...(connection === undefined ? {} : { connection }),
    ...(source.schema_digest === undefined
      ? {}
      : { schema_digest: source.schema_digest }),
    ...(source.discovered_at === undefined
      ? {}
      : { discovered_at: source.discovered_at }),
    ...(source.last_success_at === undefined
      ? {}
      : { last_success_at: source.last_success_at }),
    state: projectCapabilityState(source.state),
    policy: projectCapabilityPolicy(source.policy),
  };
}

function projectToolAnnotations(value: unknown): ToolAnnotations {
  const source = responseObject(value, 'tool annotations');
  if (
    !isOptionalBoundedString(source.title, MAX_PUBLIC_STRING_BYTES) ||
    !isOptionalBoolean(source.readOnlyHint) ||
    !isOptionalBoolean(source.destructiveHint) ||
    !isOptionalBoolean(source.idempotentHint) ||
    !isOptionalBoolean(source.openWorldHint)
  ) {
    throw invalidCapabilityResponse('tool annotations');
  }
  return {
    ...(source.title === undefined ? {} : { title: source.title }),
    ...(source.readOnlyHint === undefined
      ? {}
      : { readOnlyHint: source.readOnlyHint }),
    ...(source.destructiveHint === undefined
      ? {}
      : { destructiveHint: source.destructiveHint }),
    ...(source.idempotentHint === undefined
      ? {}
      : { idempotentHint: source.idempotentHint }),
    ...(source.openWorldHint === undefined
      ? {}
      : { openWorldHint: source.openWorldHint }),
  };
}

function projectCapabilitySource(value: unknown): CapabilitySource {
  const source = responseObject(value, 'capability source');
  if (source.type === 'manual_file') {
    return { type: 'manual_file' };
  }
  if (
    source.type === 'openapi' &&
    isBoundedNonEmptyString(source.connection_id, MAX_PUBLIC_STRING_BYTES) &&
    isOptionalBoundedNonEmptyString(
      source.operation_id,
      MAX_PUBLIC_STRING_BYTES,
    ) &&
    isNonNegativeInteger(source.catalog_revision) &&
    isNonNegativeInteger(source.spec_revision) &&
    isSafeDigest(source.spec_digest)
  ) {
    return {
      type: 'openapi',
      connection_id: source.connection_id,
      ...(source.operation_id === undefined
        ? {}
        : { operation_id: source.operation_id }),
      catalog_revision: source.catalog_revision,
      spec_revision: source.spec_revision,
      spec_digest: source.spec_digest,
    };
  }
  if (
    source.type === 'mcp_discovery' &&
    isBoundedNonEmptyString(source.connection_id, MAX_PUBLIC_STRING_BYTES) &&
    isOptionalBoundedNonEmptyString(
      source.remote_tool_name,
      MAX_PUBLIC_STRING_BYTES,
    )
  ) {
    return {
      type: 'mcp_discovery',
      connection_id: source.connection_id,
      ...(source.remote_tool_name === undefined
        ? {}
        : { remote_tool_name: source.remote_tool_name }),
    };
  }
  if (
    source.type === 'projected_legacy_config' &&
    isBoundedNonEmptyString(source.connection_id, MAX_PUBLIC_STRING_BYTES) &&
    isBoundedNonEmptyString(
      source.remote_tool_name,
      MAX_PUBLIC_STRING_BYTES,
    )
  ) {
    return {
      type: 'projected_legacy_config',
      connection_id: source.connection_id,
      remote_tool_name: source.remote_tool_name,
    };
  }

  throw invalidCapabilityResponse('capability source');
}

function projectCapabilityConnection(value: unknown): CapabilityConnection {
  const source = responseObject(value, 'capability connection');
  if (
    !isBoundedNonEmptyString(source.id, MAX_PUBLIC_STRING_BYTES) ||
    !isConnectionKind(source.kind) ||
    !isConnectionManagementSource(source.management_source)
  ) {
    throw invalidCapabilityResponse('capability connection');
  }
  return {
    id: source.id,
    kind: source.kind,
    management_source: source.management_source,
  };
}

function projectCapabilityState(value: unknown): CapabilityState {
  const source = responseObject(value, 'capability state');
  if (
    typeof source.enabled !== 'boolean' ||
    typeof source.available !== 'boolean' ||
    typeof source.stale !== 'boolean' ||
    !isCapabilityStateReason(source.reason)
  ) {
    throw invalidCapabilityResponse('capability state');
  }
  return {
    enabled: source.enabled,
    available: source.available,
    stale: source.stale,
    reason: source.reason,
  };
}

function projectCapabilityPolicy(
  value: unknown,
): CapabilityPolicyEligibility {
  const source = responseObject(value, 'capability policy');
  if (
    typeof source.eligible !== 'boolean' ||
    !isCapabilityPolicyReason(source.reason)
  ) {
    throw invalidCapabilityResponse('capability policy');
  }
  return {
    eligible: source.eligible,
    reason: source.reason,
  };
}

function projectCapabilityMapping(
  value: unknown,
  summary: CapabilitySummary,
): CapabilityMapping {
  const source = responseObject(value, 'capability mapping');
  if (
    source.type === 'http' &&
    summary.kind === 'tool' &&
    isKnownHttpMethod(source.method) &&
    isSafePathTemplate(source.path_template) &&
    Array.isArray(source.query_params) &&
    source.query_params.length <= MAX_MAPPING_QUERY_PARAMS
  ) {
    const queryParams = source.query_params.map(projectQueryParamMapping);
    return {
      type: 'http',
      method: source.method,
      path_template: source.path_template,
      query_params: queryParams,
      ...(source.body === undefined
        ? {}
        : { body: projectBodyMapping(source.body) }),
    };
  }
  if (
    source.type === 'mcp' &&
    summary.kind === 'tool' &&
    isBoundedNonEmptyString(
      source.remote_tool_name,
      MAX_PUBLIC_STRING_BYTES,
    )
  ) {
    return {
      type: 'mcp',
      remote_tool_name: source.remote_tool_name,
    };
  }
  if (
    source.type === 'resource' &&
    summary.kind === 'resource' &&
    isBoundedNonEmptyString(source.uri, MAX_PUBLIC_STRING_BYTES) &&
    source.uri === summary.uri &&
    isOptionalBoundedNonEmptyString(source.mime_type, MAX_PUBLIC_STRING_BYTES) &&
    (source.size === undefined || isNonNegativeInteger(source.size))
  ) {
    return {
      type: 'resource',
      uri: source.uri,
      ...(source.mime_type === undefined
        ? {}
        : { mime_type: source.mime_type }),
      ...(source.size === undefined ? {} : { size: source.size }),
    };
  }
  if (
    source.type === 'resource_template' &&
    summary.kind === 'resource_template' &&
    isBoundedNonEmptyString(source.uri_template, MAX_PUBLIC_STRING_BYTES) &&
    source.uri_template === summary.uri_template &&
    isOptionalBoundedNonEmptyString(source.mime_type, MAX_PUBLIC_STRING_BYTES)
  ) {
    return {
      type: 'resource_template',
      uri_template: source.uri_template,
      ...(source.mime_type === undefined
        ? {}
        : { mime_type: source.mime_type }),
    };
  }

  throw invalidCapabilityResponse('capability mapping');
}

function projectQueryParamMapping(value: unknown): CapabilityQueryParamMapping {
  const source = responseObject(value, 'query parameter mapping');
  if (
    !isBoundedNonEmptyString(source.arg_name, MAX_PUBLIC_STRING_BYTES) ||
    !isBoundedNonEmptyString(source.query_name, MAX_PUBLIC_STRING_BYTES) ||
    typeof source.required !== 'boolean'
  ) {
    throw invalidCapabilityResponse('query parameter mapping');
  }
  return {
    arg_name: source.arg_name,
    query_name: source.query_name,
    required: source.required,
  };
}

function projectBodyMapping(value: unknown): CapabilityBodyMapping {
  const source = responseObject(value, 'body mapping');
  if (source.mode !== 'whole_args_json') {
    throw invalidCapabilityResponse('body mapping');
  }
  return { mode: 'whole_args_json' };
}

/**
 * JSON Schema intentionally permits application-defined property names and
 * annotations, so it cannot use a fixed-key projector. Clone only JSON values
 * into fresh containers while enforcing explicit size, depth, node, and
 * per-object bounds. This prevents a response object from retaining aliases,
 * prototype setters, cycles, or unbounded structures.
 */
function projectInputJsonSchema(value: unknown): unknown {
  const budget = { nodes: 0 };
  const projected = projectBoundedJsonValue(value, 0, budget);
  let serialized: string;
  try {
    serialized = JSON.stringify(projected);
  } catch {
    throw invalidCapabilityResponse('input JSON schema');
  }
  if (utf8Length(serialized) > MAX_INPUT_SCHEMA_BYTES) {
    throw invalidCapabilityResponse('input JSON schema');
  }
  return projected;
}

function projectBoundedJsonValue(
  value: unknown,
  depth: number,
  budget: { nodes: number },
): unknown {
  budget.nodes += 1;
  if (
    budget.nodes > MAX_INPUT_SCHEMA_NODES ||
    depth > MAX_INPUT_SCHEMA_DEPTH
  ) {
    throw invalidCapabilityResponse('input JSON schema');
  }

  if (
    value === null ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (typeof value === 'string') {
    if (utf8Length(value) > MAX_INPUT_SCHEMA_BYTES) {
      throw invalidCapabilityResponse('input JSON schema');
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      projectBoundedJsonValue(item, depth + 1, budget),
    );
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > MAX_INPUT_SCHEMA_OBJECT_KEYS) {
      throw invalidCapabilityResponse('input JSON schema');
    }
    const projected: Record<string, unknown> = {};
    for (const [key, nestedValue] of entries) {
      if (utf8Length(key) > MAX_INPUT_SCHEMA_KEY_BYTES) {
        throw invalidCapabilityResponse('input JSON schema');
      }
      Object.defineProperty(projected, key, {
        configurable: true,
        enumerable: true,
        value: projectBoundedJsonValue(
          nestedValue,
          depth + 1,
          budget,
        ),
        writable: true,
      });
    }
    return projected;
  }

  throw invalidCapabilityResponse('input JSON schema');
}

function responseObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidCapabilityResponse(label);
  }
  return value as Record<string, unknown>;
}

function isCapabilityKind(value: unknown): value is CapabilityKind {
  return (
    value === 'tool' ||
    value === 'resource' ||
    value === 'resource_template'
  );
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

function isCapabilityStateReason(value: unknown): value is string {
  return isSafeReasonToken(value);
}

function isCapabilityPolicyReason(value: unknown): value is string {
  return isSafeReasonToken(value);
}

function isKnownHttpMethod(value: unknown): value is string {
  return (
    value === 'GET' ||
    value === 'HEAD' ||
    value === 'POST' ||
    value === 'PUT' ||
    value === 'PATCH' ||
    value === 'DELETE' ||
    value === 'OPTIONS' ||
    value === 'TRACE' ||
    value === 'CONNECT'
  );
}

function isSafePathTemplate(value: unknown): value is string {
  return (
    isBoundedNonEmptyString(value, MAX_PUBLIC_STRING_BYTES) &&
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.includes('?') &&
    !value.includes('#') &&
    !value.includes('\\') &&
    !hasUnsafeAsciiCharacter(value)
  );
}

function isSafeReasonToken(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 128 &&
    /^[a-z][a-z0-9_]*$/.test(value)
  );
}

function isOptionalSafeDigest(value: unknown): value is string | undefined {
  return value === undefined || isSafeDigest(value);
}

function isSafeDigest(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 256 &&
    /^[A-Za-z0-9:_-]+$/.test(value)
  );
}

function isOptionalTimestamp(value: unknown): value is string | undefined {
  return (
    value === undefined ||
    (isBoundedNonEmptyString(value, MAX_PUBLIC_STRING_BYTES) &&
      Number.isFinite(Date.parse(value)))
  );
}

function isOptionalBoundedString(
  value: unknown,
  maxBytes: number,
): value is string | undefined {
  return value === undefined || isBoundedString(value, maxBytes);
}

function isOptionalBoolean(value: unknown): value is boolean | undefined {
  return value === undefined || typeof value === 'boolean';
}

function isOptionalBoundedNonEmptyString(
  value: unknown,
  maxBytes: number,
): value is string | undefined {
  return value === undefined || isBoundedNonEmptyString(value, maxBytes);
}

function isBoundedNonEmptyString(
  value: unknown,
  maxBytes: number,
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    isBoundedString(value, maxBytes)
  );
}

function isBoundedString(value: unknown, maxBytes: number): value is string {
  return typeof value === 'string' && utf8Length(value) <= maxBytes;
}

function isNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
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

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function invalidCapabilityResponse(
  label: string,
): CapabilityContractError {
  return new CapabilityContractError(
    `The gateway returned an invalid ${label} response.`,
  );
}
