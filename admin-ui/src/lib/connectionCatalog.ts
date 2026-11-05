import { adminFetchResource, type AdminResource } from './api';
import { adminApiUrl } from './config';
import {
  ConnectionContractError,
  projectConnectionStatus,
  type ConnectionStatus,
} from './connections';

/**
 * The gateway's limit on a managed OpenAPI document, in UTF-8 bytes
 * (`MAX_MANAGED_SPEC_BYTES`). The UI checks it before sending anything; the
 * gateway checks it again and stays authoritative.
 */
export const MAX_CATALOG_SPEC_BYTES = 2 * 1024 * 1024;

// The bound every list in the preview and publication contracts carries.
const MAX_CATALOG_ENTRIES = 4096;
const MAX_EXPLAINED_SECURITY_ALTERNATIVES = 16;
const MAX_TOOL_NAME_LENGTH = 128;
const MAX_CONVERSION_FIELD_LENGTH = 256;
const MAX_OVERLAY_SOURCES = 128;
const MAX_OVERLAY_COMPOSITES = 256;
const MAX_OVERLAY_PATH_LENGTH = 1024;
const MAX_OVERLAY_MESSAGE_LENGTH = 4096;
const SPEC_DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const OVERLAY_SOURCE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

export type CatalogSourceFormat = 'swagger_2_0' | 'google_discovery_v1';

const CONVERSION_WARNING_CODES = [
  'base_path_not_in_paths',
  'unsupported_document_field',
  'unsupported_path_item_field',
  'security_definition_not_converted',
  'consumes_defaulted',
  'produces_defaulted',
  'request_body_not_mapped',
  'credential_parameter_not_mapped',
  'unsupported_operation_field',
  'invalid_parameter',
  'unsupported_parameter_location',
  'unsupported_parameter_field',
  'unsupported_collection_format',
  'file_parameter_outside_form',
  'multiple_body_parameters',
  'body_and_form_parameters',
  'global_parameter_not_mapped',
  'unsupported_schema_keyword',
  'media_upload_not_mapped',
  'invalid_method_definition',
  'unsupported_http_method',
  'unsupported_path_expansion',
  'repeated_path_parameter',
  'duplicate_operation',
  'recursive_request_schema',
  'warnings_truncated',
] as const;

export type CatalogConversionWarningCode =
  (typeof CONVERSION_WARNING_CODES)[number];

/**
 * One thing the gateway did, or could not do, while converting a Swagger 2.0
 * or Google Discovery document to OpenAPI 3.0. `message` is fixed text for
 * the code; `method`, `path_template` and `subject` name the document's own
 * operation and field.
 */
export type CatalogConversionWarning = {
  code: CatalogConversionWarningCode;
  message: string;
  operation_omitted: boolean;
  method?: string;
  path_template?: string;
  subject?: string;
};

export type CatalogConversionReport = {
  source_format: CatalogSourceFormat;
  warnings: CatalogConversionWarning[];
};

/**
 * A generated tool as a preview lists it: an HTTP tool bound to the
 * Connection's credential, or a composite the stored overlay declares.
 * Only the fields the import page shows are kept.
 */
export type CatalogPreviewTool = {
  name: string;
  title?: string;
  description: string;
  target_type: 'http' | 'composite';
  upstream: {
    method: string;
    path_template: string;
  };
  visibility: 'listed' | 'composite_only';
};

/**
 * The security alternative a bound tool sends the Connection's credential
 * for, keyed by the tool's generated name. An empty list is an operation
 * that declares no security. Registration must confirm exactly this.
 */
export type CatalogSecuritySelection = {
  tool_name: string;
  selected_scheme_names: string[];
};

export type CatalogIncompatibilityReason =
  | 'missing_security_metadata'
  | 'no_compatible_security_alternative'
  | 'invalid_mapping_path';

const SECURITY_MISMATCH_REASONS = [
  'multiple_schemes',
  'missing_security_scheme',
  'invalid_security_scheme',
  'api_key_query',
  'api_key_cookie',
  'api_key_unsupported_location',
  'http_basic',
  'http_unsupported_scheme',
  'oauth2_without_supported_flow',
  'mutual_tls',
  'unsupported_security_scheme_type',
  'requires_header_api_key',
  'api_key_header_mismatch',
  'requires_static_bearer',
  'requires_oauth2_client_credentials',
  'token_url_mismatch',
  'missing_scopes',
  'oauth2_without_client_credentials',
  'open_id_connect',
] as const;

export type CatalogSecurityMismatchReason =
  (typeof SECURITY_MISMATCH_REASONS)[number];

/**
 * Why one security alternative does not bind. The message is fixed per
 * reason and never contains document or Connection content.
 */
export type CatalogSecurityMismatch = {
  scheme_names: string[];
  reason: CatalogSecurityMismatchReason;
  message: string;
  missing_scopes?: string[];
};

/**
 * A generated operation that cannot be registered on this Connection. The
 * gateway's free-text `detail` is deliberately not kept.
 */
export type CatalogIncompatibility = {
  tool_name: string;
  reason: CatalogIncompatibilityReason;
  path_template?: string;
  security_alternatives?: CatalogSecurityMismatch[];
  unexplained_security_alternatives?: number;
};

export type CatalogNameFallback = {
  method: string;
  path_template: string;
  original_operation_id?: string;
  generated_name: string;
  reason: 'missing_operation_id' | 'invalid_operation_id' | 'duplicate_tool_name';
};

export type CatalogSkippedOperation = {
  method: string;
  path_template: string;
  original_operation_id?: string;
  reason: string;
  property_name?: string;
};

export type CatalogOverlayMessage = {
  path: string;
  message: string;
};

export type CatalogOverlaySource = {
  id: string;
  kind: 'enum' | 'label';
  state: string;
  item_count: number;
  resolved_at?: string;
};

/** How the stored overlay renamed or hid one generated tool. */
export type CatalogOverlayTool = {
  generated_name: string;
  served_name: string;
  visibility: 'listed' | 'composite_only';
};

export type CatalogOverlayComposite = {
  name: string;
  steps_max: number;
  policy_entry_present: boolean;
};

/**
 * The stored overlay compiled into a preview. The UI never sends a
 * candidate overlay, so `applied` says whether the Connection has one.
 */
export type CatalogOverlayReport = {
  applied: boolean;
  problems: CatalogOverlayMessage[];
  warnings: CatalogOverlayMessage[];
  sources: CatalogOverlaySource[];
  tools: CatalogOverlayTool[];
  composites: CatalogOverlayComposite[];
};

export type ConnectionCatalogPreview = {
  connection_id: string;
  connection_etag: string;
  spec_digest: string;
  spec_revision: number;
  catalog_revision: number;
  tools: CatalogPreviewTool[];
  security_confirmations: CatalogSecuritySelection[];
  incompatibilities: CatalogIncompatibility[];
  operation_id_fallbacks: CatalogNameFallback[];
  skipped_operations: CatalogSkippedOperation[];
  overlay: CatalogOverlayReport;
  /** Present only when the document was Swagger 2.0 or Google Discovery. */
  conversion?: CatalogConversionReport;
};

/** A preview and the Connection ETag a registration must send back. */
export type ConnectionCatalogPreviewResource = {
  value: ConnectionCatalogPreview;
  etag: string;
};

/**
 * A registration, bound to one reviewed preview: the same document, its
 * digest and both revisions, and a security confirmation for exactly the
 * selected tools.
 */
export type ConnectionCatalogRegisterRequest = {
  spec: string;
  spec_digest: string;
  expected_spec_revision: number;
  expected_catalog_revision: number;
  selected_tool_names: string[];
  security_confirmations: CatalogSecuritySelection[];
};

export type ConnectionCatalogPublishResult = {
  connection_id: string;
  spec_digest: string;
  spec_revision: number;
  catalog_revision: number;
  status: ConnectionStatus;
  registered_tool_names: string[];
  total_count: number;
  added_count: number;
  changed_count: number;
  removed_count: number;
};

/**
 * Preview a document against a Connection without storing anything. The
 * request carries only the document: this page never sends a candidate
 * overlay, so the gateway compiles the stored one, if any.
 */
export async function previewConnectionCatalog(
  id: string,
  spec: string,
  signal?: AbortSignal,
): Promise<ConnectionCatalogPreviewResource> {
  if (!isSpecWithinLimit(spec)) {
    throw new ConnectionContractError(
      'The document is empty or larger than the 2 MiB managed OpenAPI limit.',
    );
  }
  const resource = await adminFetchResource<unknown>(
    `${connectionUrl(id)}/openapi/preview`,
    {
      method: 'POST',
      signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ spec }),
    },
  );
  const value = projectConnectionCatalogPreview(resource.value, id);
  // The ETag is the precondition of the registration that follows; a preview
  // without one, or with one the body disagrees with, cannot be registered.
  if (resource.etag === null || resource.etag !== value.connection_etag) {
    throw invalidCatalogResponse('catalog preview');
  }
  return { value, etag: resource.etag };
}

/**
 * Register the selected tools of a reviewed preview. `previewEtag` is the
 * ETag that preview returned, sent as `If-Match`.
 */
export async function registerConnectionCatalog(
  id: string,
  request: ConnectionCatalogRegisterRequest,
  previewEtag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ConnectionCatalogPublishResult>> {
  const body = canonicalRegisterRequest(request);
  const resource = await adminFetchResource<unknown>(
    `${connectionUrl(id)}/openapi/register`,
    {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
        'If-Match': previewEtag,
      },
      body: JSON.stringify(body),
    },
  );
  // The catalog may already be published: a response this page cannot
  // verify requires a reload, not a retry.
  let value: ConnectionCatalogPublishResult;
  try {
    value = projectConnectionCatalogPublishResult(resource.value, id);
  } catch {
    throw ambiguousRegistrationResponse();
  }
  if (resource.etag !== previewEtag || value.spec_digest !== body.spec_digest) {
    throw ambiguousRegistrationResponse();
  }
  return { ...resource, value };
}

/** The UTF-8 size of a document, as the gateway measures its limit. */
export function catalogSpecBytes(spec: string): number {
  return new TextEncoder().encode(spec).length;
}

export function isSpecWithinLimit(spec: string): boolean {
  return spec.length > 0 && catalogSpecBytes(spec) <= MAX_CATALOG_SPEC_BYTES;
}

/** One row of the preview's tool table. */
export type CatalogToolRow =
  | {
      kind: 'bound';
      name: string;
      generated_name: string;
      tool: CatalogPreviewTool;
      confirmation: CatalogSecuritySelection;
      read: boolean;
    }
  | { kind: 'composite'; name: string; tool: CatalogPreviewTool }
  | { kind: 'unconfirmed'; name: string; tool: CatalogPreviewTool }
  | { kind: 'incompatible'; name: string; incompatibility: CatalogIncompatibility };

/**
 * Every tool of a preview with what registration can do with it. Tools are
 * listed by the name they are served under, while security confirmations
 * are keyed by generated name; the stored overlay's tool report maps one to
 * the other. An HTTP tool whose confirmation cannot be found unambiguously
 * is `unconfirmed` and cannot be selected.
 */
export function catalogToolRows(
  preview: ConnectionCatalogPreview,
): CatalogToolRow[] {
  const generatedByServed = new Map<string, string>();
  const ambiguous = new Set<string>();
  for (const tool of preview.overlay.tools) {
    if (generatedByServed.has(tool.served_name)) {
      ambiguous.add(tool.served_name);
    }
    generatedByServed.set(tool.served_name, tool.generated_name);
  }
  const confirmations = new Map(
    preview.security_confirmations.map((confirmation) => [
      confirmation.tool_name,
      confirmation,
    ]),
  );

  const rows: CatalogToolRow[] = preview.tools.map((tool) => {
    if (tool.target_type === 'composite') {
      return { kind: 'composite', name: tool.name, tool };
    }
    const generatedName = generatedByServed.get(tool.name) ?? tool.name;
    const confirmation = ambiguous.has(tool.name)
      ? undefined
      : confirmations.get(generatedName);
    if (confirmation === undefined) {
      return { kind: 'unconfirmed', name: tool.name, tool };
    }
    return {
      kind: 'bound',
      name: tool.name,
      generated_name: generatedName,
      tool,
      confirmation,
      read: isReadMethod(tool.upstream.method),
    };
  });
  for (const incompatibility of preview.incompatibilities) {
    rows.push({
      kind: 'incompatible',
      name: incompatibility.tool_name,
      incompatibility,
    });
  }
  return rows;
}

/**
 * The selection a preview starts with: only the bindable `GET` and `HEAD`
 * tools. Anything else is the operator's explicit choice.
 */
export function defaultCatalogSelection(
  preview: ConnectionCatalogPreview,
): Set<string> {
  return new Set(
    catalogToolRows(preview)
      .filter((row) => row.kind === 'bound' && row.read)
      .map((row) => row.name),
  );
}

/**
 * The registration for `selected` tools of `preview`, bound to the exact
 * document, digest and revisions that were reviewed. Tools are named by
 * their generated names, the names their confirmations carry, which the
 * gateway accepts beside the served ones. A name that is not a bound tool
 * of this preview is refused rather than dropped.
 */
export function catalogRegisterRequest(
  preview: ConnectionCatalogPreview,
  spec: string,
  selected: Iterable<string>,
): ConnectionCatalogRegisterRequest {
  const bound = new Map<string, Extract<CatalogToolRow, { kind: 'bound' }>>();
  for (const row of catalogToolRows(preview)) {
    if (row.kind === 'bound') {
      bound.set(row.name, row);
    }
  }
  const selectedToolNames: string[] = [];
  const confirmations: CatalogSecuritySelection[] = [];
  for (const name of new Set(selected)) {
    const row = bound.get(name);
    if (row === undefined) {
      throw new ConnectionContractError(
        'A selected tool is not a bound tool of the reviewed preview.',
      );
    }
    selectedToolNames.push(row.generated_name);
    confirmations.push({
      tool_name: row.confirmation.tool_name,
      selected_scheme_names: [...row.confirmation.selected_scheme_names],
    });
  }
  return {
    spec,
    spec_digest: preview.spec_digest,
    expected_spec_revision: preview.spec_revision,
    expected_catalog_revision: preview.catalog_revision,
    selected_tool_names: selectedToolNames,
    security_confirmations: confirmations,
  };
}

function isReadMethod(method: string): boolean {
  const normalized = method.toUpperCase();
  return normalized === 'GET' || normalized === 'HEAD';
}

/**
 * The register body exactly as the contract defines it, after checking
 * that it is internally consistent: a confirmation for each selected tool
 * and for nothing else.
 */
function canonicalRegisterRequest(
  request: ConnectionCatalogRegisterRequest,
): ConnectionCatalogRegisterRequest {
  const selected = new Set(request.selected_tool_names);
  const confirmed = new Set(
    request.security_confirmations.map((confirmation) => confirmation.tool_name),
  );
  if (
    !isSpecWithinLimit(request.spec) ||
    !SPEC_DIGEST_PATTERN.test(request.spec_digest) ||
    !isNonNegativeInteger(request.expected_spec_revision) ||
    !isNonNegativeInteger(request.expected_catalog_revision) ||
    request.selected_tool_names.length > MAX_CATALOG_ENTRIES ||
    selected.size !== request.selected_tool_names.length ||
    !request.selected_tool_names.every(isNonEmptyString) ||
    confirmed.size !== request.security_confirmations.length ||
    confirmed.size !== selected.size ||
    ![...selected].every((name) => confirmed.has(name)) ||
    !request.security_confirmations.every((confirmation) =>
      isUniqueNonEmptyStringList(confirmation.selected_scheme_names),
    )
  ) {
    throw new ConnectionContractError(
      'The registration does not match a reviewed preview.',
    );
  }
  return {
    spec: request.spec,
    spec_digest: request.spec_digest,
    expected_spec_revision: request.expected_spec_revision,
    expected_catalog_revision: request.expected_catalog_revision,
    selected_tool_names: [...request.selected_tool_names],
    security_confirmations: request.security_confirmations.map(
      (confirmation) => ({
        tool_name: confirmation.tool_name,
        selected_scheme_names: [...confirmation.selected_scheme_names],
      }),
    ),
  };
}

function projectConnectionCatalogPreview(
  value: unknown,
  expectedId: string,
): ConnectionCatalogPreview {
  const source = responseObject(value, 'catalog preview');
  if (
    source.connection_id !== expectedId ||
    typeof source.connection_etag !== 'string' ||
    source.connection_etag.length < 2 ||
    !isSpecDigest(source.spec_digest) ||
    !isNonNegativeInteger(source.spec_revision) ||
    !isNonNegativeInteger(source.catalog_revision)
  ) {
    throw invalidCatalogResponse('catalog preview');
  }

  const tools = boundedList(source.tools, 'catalog preview tools').map(
    (tool) => projectPreviewTool(tool, expectedId),
  );
  const securityConfirmations = boundedList(
    source.security_confirmations,
    'catalog security confirmations',
  ).map(projectSecuritySelection);
  const incompatibilities = boundedList(
    source.incompatibilities,
    'catalog incompatibilities',
  ).map(projectIncompatibility);
  if (
    !hasUniqueNames(tools.map((tool) => tool.name)) ||
    !hasUniqueNames(
      securityConfirmations.map((confirmation) => confirmation.tool_name),
    ) ||
    !hasUniqueNames(
      incompatibilities.map((incompatibility) => incompatibility.tool_name),
    )
  ) {
    throw invalidCatalogResponse('catalog preview');
  }

  return {
    connection_id: expectedId,
    connection_etag: source.connection_etag,
    spec_digest: source.spec_digest,
    spec_revision: source.spec_revision,
    catalog_revision: source.catalog_revision,
    tools,
    security_confirmations: securityConfirmations,
    incompatibilities,
    operation_id_fallbacks: boundedList(
      source.operation_id_fallbacks,
      'catalog name fallbacks',
    ).map(projectNameFallback),
    skipped_operations: boundedList(
      source.skipped_operations,
      'catalog skipped operations',
    ).map(projectSkippedOperation),
    overlay: projectOverlayReport(source.overlay),
    ...(source.conversion === undefined
      ? {}
      : { conversion: projectConversionReport(source.conversion) }),
  };
}

function projectPreviewTool(
  value: unknown,
  expectedId: string,
): CatalogPreviewTool {
  const source = responseObject(value, 'catalog preview tool');
  const target = responseObject(source.target, 'catalog preview tool');
  const toolSource = responseObject(source.source, 'catalog preview tool');
  const upstream = responseObject(source.upstream, 'catalog preview tool');
  if (
    !isToolName(source.name) ||
    (source.title !== undefined && !isBoundedString(source.title, 1, 256)) ||
    !isNonEmptyString(source.description) ||
    !isJsonObject(source.input_json_schema) ||
    (source.visibility !== undefined &&
      source.visibility !== 'listed' &&
      source.visibility !== 'composite_only') ||
    // Every tool of a managed OpenAPI preview is generated for, and targets,
    // the previewed Connection: an HTTP tool it binds, or an overlay
    // composite over its tools.
    (target.type !== 'http' && target.type !== 'composite') ||
    target.connection_id !== expectedId ||
    toolSource.type !== 'open_api' ||
    toolSource.connection_id !== expectedId ||
    !isNonEmptyString(upstream.method) ||
    typeof upstream.path_template !== 'string' ||
    !upstream.path_template.startsWith('/')
  ) {
    throw invalidCatalogResponse('catalog preview tool');
  }
  const isComposite = target.type === 'composite';
  if (
    isComposite !== isJsonObject(source.composite) ||
    isComposite !== (upstream.method === 'COMPOSITE')
  ) {
    throw invalidCatalogResponse('catalog preview tool');
  }

  return {
    name: source.name,
    ...(source.title === undefined ? {} : { title: source.title }),
    description: source.description,
    target_type: target.type,
    upstream: {
      method: upstream.method,
      path_template: upstream.path_template,
    },
    visibility: source.visibility ?? 'listed',
  };
}

function projectSecuritySelection(value: unknown): CatalogSecuritySelection {
  const source = responseObject(value, 'catalog security confirmation');
  if (
    !isNonEmptyString(source.tool_name) ||
    !isUniqueNonEmptyStringList(source.selected_scheme_names)
  ) {
    throw invalidCatalogResponse('catalog security confirmation');
  }
  return {
    tool_name: source.tool_name,
    selected_scheme_names: [...source.selected_scheme_names],
  };
}

function projectIncompatibility(value: unknown): CatalogIncompatibility {
  const source = responseObject(value, 'catalog incompatibility');
  if (
    typeof source.tool_name !== 'string' ||
    (source.reason !== 'missing_security_metadata' &&
      source.reason !== 'no_compatible_security_alternative' &&
      source.reason !== 'invalid_mapping_path') ||
    (source.path_template !== undefined &&
      typeof source.path_template !== 'string') ||
    (source.detail !== undefined && typeof source.detail !== 'string') ||
    (source.unexplained_security_alternatives !== undefined &&
      (!isNonNegativeInteger(source.unexplained_security_alternatives) ||
        source.unexplained_security_alternatives === 0))
  ) {
    throw invalidCatalogResponse('catalog incompatibility');
  }
  let alternatives: CatalogSecurityMismatch[] | undefined;
  if (source.security_alternatives !== undefined) {
    // Explained only for an operation none of whose alternatives binds.
    if (
      source.reason !== 'no_compatible_security_alternative' ||
      !Array.isArray(source.security_alternatives) ||
      source.security_alternatives.length === 0 ||
      source.security_alternatives.length > MAX_EXPLAINED_SECURITY_ALTERNATIVES
    ) {
      throw invalidCatalogResponse('catalog incompatibility');
    }
    alternatives = source.security_alternatives.map(projectSecurityMismatch);
  }

  return {
    tool_name: source.tool_name,
    reason: source.reason,
    ...(source.path_template === undefined
      ? {}
      : { path_template: source.path_template }),
    ...(alternatives === undefined
      ? {}
      : { security_alternatives: alternatives }),
    ...(source.unexplained_security_alternatives === undefined
      ? {}
      : {
          unexplained_security_alternatives:
            source.unexplained_security_alternatives,
        }),
  };
}

function projectSecurityMismatch(value: unknown): CatalogSecurityMismatch {
  const source = responseObject(value, 'catalog security alternative');
  if (
    !isStringList(source.scheme_names) ||
    !isSecurityMismatchReason(source.reason) ||
    !isNonEmptyString(source.message) ||
    (source.missing_scopes !== undefined &&
      (source.reason !== 'missing_scopes' ||
        !isStringList(source.missing_scopes) ||
        source.missing_scopes.length === 0))
  ) {
    throw invalidCatalogResponse('catalog security alternative');
  }
  return {
    scheme_names: [...source.scheme_names],
    reason: source.reason,
    message: source.message,
    ...(source.missing_scopes === undefined
      ? {}
      : { missing_scopes: [...source.missing_scopes] }),
  };
}

function projectNameFallback(value: unknown): CatalogNameFallback {
  const source = responseObject(value, 'catalog name fallback');
  if (
    typeof source.method !== 'string' ||
    typeof source.path_template !== 'string' ||
    (source.original_operation_id !== undefined &&
      typeof source.original_operation_id !== 'string') ||
    typeof source.generated_name !== 'string' ||
    (source.reason !== 'missing_operation_id' &&
      source.reason !== 'invalid_operation_id' &&
      source.reason !== 'duplicate_tool_name')
  ) {
    throw invalidCatalogResponse('catalog name fallback');
  }
  return {
    method: source.method,
    path_template: source.path_template,
    ...(source.original_operation_id === undefined
      ? {}
      : { original_operation_id: source.original_operation_id }),
    generated_name: source.generated_name,
    reason: source.reason,
  };
}

function projectSkippedOperation(value: unknown): CatalogSkippedOperation {
  const source = responseObject(value, 'catalog skipped operation');
  if (
    typeof source.method !== 'string' ||
    typeof source.path_template !== 'string' ||
    (source.original_operation_id !== undefined &&
      typeof source.original_operation_id !== 'string') ||
    !isNonEmptyString(source.reason) ||
    (source.property_name !== undefined &&
      typeof source.property_name !== 'string')
  ) {
    throw invalidCatalogResponse('catalog skipped operation');
  }
  return {
    method: source.method,
    path_template: source.path_template,
    ...(source.original_operation_id === undefined
      ? {}
      : { original_operation_id: source.original_operation_id }),
    reason: source.reason,
    ...(source.property_name === undefined
      ? {}
      : { property_name: source.property_name }),
  };
}

function projectConversionReport(value: unknown): CatalogConversionReport {
  const source = responseObject(value, 'catalog conversion report');
  if (
    source.source_format !== 'swagger_2_0' &&
    source.source_format !== 'google_discovery_v1'
  ) {
    throw invalidCatalogResponse('catalog conversion report');
  }
  return {
    source_format: source.source_format,
    warnings: boundedList(source.warnings, 'catalog conversion warnings').map(
      projectConversionWarning,
    ),
  };
}

function projectConversionWarning(value: unknown): CatalogConversionWarning {
  const source = responseObject(value, 'catalog conversion warning');
  if (
    !isConversionWarningCode(source.code) ||
    !isNonEmptyString(source.message) ||
    typeof source.operation_omitted !== 'boolean' ||
    (source.method !== undefined && typeof source.method !== 'string') ||
    (source.path_template !== undefined &&
      !isBoundedString(source.path_template, 0, MAX_CONVERSION_FIELD_LENGTH)) ||
    (source.subject !== undefined &&
      !isBoundedString(source.subject, 0, MAX_CONVERSION_FIELD_LENGTH))
  ) {
    throw invalidCatalogResponse('catalog conversion warning');
  }
  return {
    code: source.code,
    message: source.message,
    operation_omitted: source.operation_omitted,
    ...(source.method === undefined ? {} : { method: source.method }),
    ...(source.path_template === undefined
      ? {}
      : { path_template: source.path_template }),
    ...(source.subject === undefined ? {} : { subject: source.subject }),
  };
}

function projectOverlayReport(value: unknown): CatalogOverlayReport {
  const source = responseObject(value, 'catalog overlay report');
  if (
    typeof source.applied !== 'boolean' ||
    !Array.isArray(source.sources) ||
    source.sources.length > MAX_OVERLAY_SOURCES ||
    !Array.isArray(source.composites) ||
    source.composites.length > MAX_OVERLAY_COMPOSITES
  ) {
    throw invalidCatalogResponse('catalog overlay report');
  }
  return {
    applied: source.applied,
    problems: boundedList(source.problems, 'catalog overlay report').map(
      projectOverlayMessage,
    ),
    warnings: boundedList(source.warnings, 'catalog overlay report').map(
      projectOverlayMessage,
    ),
    sources: source.sources.map(projectOverlaySource),
    tools: boundedList(source.tools, 'catalog overlay report').map(
      projectOverlayTool,
    ),
    composites: source.composites.map(projectOverlayComposite),
  };
}

function projectOverlayMessage(value: unknown): CatalogOverlayMessage {
  const source = responseObject(value, 'catalog overlay message');
  if (
    !isBoundedString(source.path, 1, MAX_OVERLAY_PATH_LENGTH) ||
    !isBoundedString(source.message, 1, MAX_OVERLAY_MESSAGE_LENGTH)
  ) {
    throw invalidCatalogResponse('catalog overlay message');
  }
  return { path: source.path, message: source.message };
}

function projectOverlaySource(value: unknown): CatalogOverlaySource {
  const source = responseObject(value, 'catalog overlay source');
  if (
    typeof source.id !== 'string' ||
    !OVERLAY_SOURCE_ID_PATTERN.test(source.id) ||
    (source.kind !== 'enum' && source.kind !== 'label') ||
    !isBoundedString(source.state, 1, 64) ||
    !isNonNegativeInteger(source.item_count) ||
    source.item_count > 1024 ||
    (source.resolved_at !== undefined && typeof source.resolved_at !== 'string')
  ) {
    throw invalidCatalogResponse('catalog overlay source');
  }
  return {
    id: source.id,
    kind: source.kind,
    state: source.state,
    item_count: source.item_count,
    ...(source.resolved_at === undefined
      ? {}
      : { resolved_at: source.resolved_at }),
  };
}

function projectOverlayTool(value: unknown): CatalogOverlayTool {
  const source = responseObject(value, 'catalog overlay tool');
  const counts = [
    source.labels_found,
    source.labels_from_source,
    source.labels_from_title,
    source.labels_from_description,
  ];
  if (
    !isToolName(source.generated_name) ||
    !isToolName(source.served_name) ||
    (source.visibility !== 'listed' && source.visibility !== 'composite_only') ||
    (source.body_mode !== undefined &&
      source.body_mode !== 'whole_args_json' &&
      source.body_mode !== 'body_args_json') ||
    !counts.every((count) => isNonNegativeInteger(count) && count <= 256) ||
    !isStringList(source.qualified_properties) ||
    !isBoundedString(source.label_summary, 1, 1024)
  ) {
    throw invalidCatalogResponse('catalog overlay tool');
  }
  return {
    generated_name: source.generated_name,
    served_name: source.served_name,
    visibility: source.visibility,
  };
}

function projectOverlayComposite(value: unknown): CatalogOverlayComposite {
  const source = responseObject(value, 'catalog overlay composite');
  if (
    !isToolName(source.name) ||
    !isNonNegativeInteger(source.steps_max) ||
    typeof source.policy_entry_present !== 'boolean'
  ) {
    throw invalidCatalogResponse('catalog overlay composite');
  }
  return {
    name: source.name,
    steps_max: source.steps_max,
    policy_entry_present: source.policy_entry_present,
  };
}

function projectConnectionCatalogPublishResult(
  value: unknown,
  expectedId: string,
): ConnectionCatalogPublishResult {
  const source = responseObject(value, 'catalog registration');
  // A registration always publishes a managed OpenAPI catalog, so the
  // result's specification fields are required, not optional as for an MCP
  // refresh.
  if (
    source.connection_id !== expectedId ||
    !isSpecDigest(source.spec_digest) ||
    !isPositiveInteger(source.spec_revision) ||
    !isPositiveInteger(source.catalog_revision) ||
    !isNonNegativeInteger(source.total_count) ||
    !isNonNegativeInteger(source.added_count) ||
    !isNonNegativeInteger(source.changed_count) ||
    !isNonNegativeInteger(source.removed_count) ||
    !Array.isArray(source.registered_tool_names) ||
    source.registered_tool_names.length > MAX_CATALOG_ENTRIES ||
    !isUniqueNonEmptyStringList(source.registered_tool_names)
  ) {
    throw invalidCatalogResponse('catalog registration');
  }
  return {
    connection_id: expectedId,
    spec_digest: source.spec_digest,
    spec_revision: source.spec_revision,
    catalog_revision: source.catalog_revision,
    status: projectConnectionStatus(source.status),
    registered_tool_names: [...source.registered_tool_names],
    total_count: source.total_count,
    added_count: source.added_count,
    changed_count: source.changed_count,
    removed_count: source.removed_count,
  };
}

function connectionUrl(id: string): string {
  return adminApiUrl(`/connections/${encodeURIComponent(id)}`);
}

function boundedList(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value) || value.length > MAX_CATALOG_ENTRIES) {
    throw invalidCatalogResponse(label);
  }
  return value;
}

function responseObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!isJsonObject(value)) {
    throw invalidCatalogResponse(label);
  }
  return value;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isConversionWarningCode(
  value: unknown,
): value is CatalogConversionWarningCode {
  return (
    typeof value === 'string' &&
    (CONVERSION_WARNING_CODES as readonly string[]).includes(value)
  );
}

function isSecurityMismatchReason(
  value: unknown,
): value is CatalogSecurityMismatchReason {
  return (
    typeof value === 'string' &&
    (SECURITY_MISMATCH_REASONS as readonly string[]).includes(value)
  );
}

function isSpecDigest(value: unknown): value is string {
  return typeof value === 'string' && SPEC_DIGEST_PATTERN.test(value);
}

function isToolName(value: unknown): value is string {
  return isBoundedString(value, 1, MAX_TOOL_NAME_LENGTH);
}

function isBoundedString(
  value: unknown,
  minLength: number,
  maxLength: number,
): value is string {
  return (
    typeof value === 'string' &&
    value.length >= minLength &&
    value.length <= maxLength
  );
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isStringList(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === 'string')
  );
}

function isUniqueNonEmptyStringList(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.every(isNonEmptyString) &&
    new Set(value).size === value.length
  );
}

function hasUniqueNames(names: string[]): boolean {
  return new Set(names).size === names.length;
}

function isNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
  );
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value >= 1;
}

function invalidCatalogResponse(label: string): ConnectionContractError {
  return new ConnectionContractError(
    `The gateway returned an invalid ${label} response.`,
  );
}

function ambiguousRegistrationResponse(): ConnectionContractError {
  return new ConnectionContractError(
    'The gateway accepted the catalog registration without returning a complete, matching result. Reload the connection before registering again.',
    true,
  );
}
