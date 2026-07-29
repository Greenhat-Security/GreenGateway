import { adminFetchResource, type AdminResource } from './api';
import { adminApiUrl } from './config';

const MAX_EXECUTION_ETAG_BYTES = 1_024;
const MAX_EXECUTION_OUTPUT_BYTES = 65_536;
const MAX_EXECUTION_OUTPUT_DEPTH = 64;
const MAX_EXECUTION_OUTPUT_NODES = 32_768;
const MAX_EXECUTION_OBJECT_KEYS = 4_096;
const MAX_EXECUTION_KEY_BYTES = 4_096;
const MAX_MCP_CONTENT_BLOCKS = 256;

export type ToolHttpBody =
  | { type: 'json'; value: unknown }
  | { type: 'text'; value: string };

export type ToolMcpContentBlock =
  | { type: 'text'; text: string }
  | { type: 'image'; data: string; mime_type: string }
  | { type: 'audio'; data: string; mime_type: string }
  | {
      type: 'resource';
      resource:
        | { uri: string; mime_type?: string; text: string }
        | { uri: string; mime_type?: string; blob: string };
    }
  | {
      type: 'resource_link';
      uri: string;
      name: string;
      title?: string;
      description?: string;
      mime_type?: string;
      size?: number;
    };

export type ToolExecutionResult =
  | {
      kind: 'http';
      status: number;
      body: ToolHttpBody;
    }
  | {
      kind: 'mcp';
      content: ToolMcpContentBlock[];
      structured_content?: unknown;
      is_error: boolean;
    };

export class ToolExecutionContractError extends Error {
  readonly requiresReload: boolean;

  constructor(message: string, requiresReload = true) {
    super(message);
    this.name = 'ToolExecutionContractError';
    this.requiresReload = requiresReload;
  }
}

export async function executeCapability(
  capabilityId: string,
  args: Record<string, unknown>,
  etag: string,
  signal?: AbortSignal,
): Promise<AdminResource<ToolExecutionResult>> {
  if (
    capabilityId.trim().length === 0 ||
    !isStrongExecutionEtag(etag) ||
    !isPlainJsonObject(args)
  ) {
    throw invalidExecutionResponse('request contract');
  }

  const resource = await adminFetchResource<unknown>(
    adminApiUrl(
      `/tools/${encodeURIComponent(capabilityId)}/execute`,
    ),
    {
      method: 'POST',
      signal,
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify({ arguments: args }),
    },
  );

  if (resource.etag === null || resource.etag !== etag) {
    throw invalidExecutionResponse('response validator');
  }

  return {
    value: projectToolExecutionResult(resource.value),
    etag: resource.etag,
    collectionEtag: null,
  };
}

export function isStrongExecutionEtag(value: string | null): value is string {
  return (
    value !== null &&
    value.length <= MAX_EXECUTION_ETAG_BYTES &&
    /^"[\x21\x23-\x7e]*"$/.test(value)
  );
}

function projectToolExecutionResult(value: unknown): ToolExecutionResult {
  const source = responseObject(value, 'execution result');
  if (
    source.kind === 'http' &&
    isHttpStatus(source.status)
  ) {
    const result: Extract<ToolExecutionResult, { kind: 'http' }> = {
      kind: 'http',
      status: source.status,
      body: projectHttpBody(source.body),
    };
    ensureBoundedOutput(result, 'HTTP result');
    return result;
  }

  if (
    source.kind === 'mcp' &&
    Array.isArray(source.content) &&
    source.content.length <= MAX_MCP_CONTENT_BLOCKS &&
    typeof source.is_error === 'boolean'
  ) {
    const result: Extract<ToolExecutionResult, { kind: 'mcp' }> = {
      kind: 'mcp',
      content: source.content.map(projectMcpContentBlock),
      is_error: source.is_error,
    };
    if (source.structured_content !== undefined) {
      result.structured_content = projectBoundedJsonOutput(
        source.structured_content,
        'MCP structured content',
      );
    }
    ensureBoundedOutput(result, 'MCP result');
    return result;
  }

  throw invalidExecutionResponse('execution result');
}

function projectHttpBody(value: unknown): ToolHttpBody {
  const source = responseObject(value, 'HTTP result body');
  if (source.type === 'json') {
    return {
      type: 'json',
      value: projectBoundedJsonOutput(source.value, 'HTTP JSON body'),
    };
  }
  if (
    source.type === 'text' &&
    typeof source.value === 'string' &&
    utf8Length(source.value) <= MAX_EXECUTION_OUTPUT_BYTES
  ) {
    return { type: 'text', value: source.value };
  }
  throw invalidExecutionResponse('HTTP result body');
}

function projectMcpContentBlock(value: unknown): ToolMcpContentBlock {
  const source = responseObject(value, 'MCP content block');
  if (
    source.type === 'text' &&
    typeof source.text === 'string' &&
    utf8Length(source.text) <= MAX_EXECUTION_OUTPUT_BYTES
  ) {
    return { type: 'text', text: source.text };
  }
  if (
    (source.type === 'image' || source.type === 'audio') &&
    isBoundedString(source.data) &&
    isBoundedNonEmptyString(source.mime_type)
  ) {
    return {
      type: source.type,
      data: source.data,
      mime_type: source.mime_type,
    };
  }
  if (source.type === 'resource') {
    return {
      type: 'resource',
      resource: projectMcpResource(source.resource),
    };
  }
  if (
    source.type === 'resource_link' &&
    isBoundedNonEmptyString(source.uri) &&
    isBoundedNonEmptyString(source.name) &&
    isOptionalBoundedString(source.title) &&
    isOptionalBoundedString(source.description) &&
    isOptionalBoundedNonEmptyString(source.mime_type) &&
    (source.size === undefined || isNonNegativeInteger(source.size))
  ) {
    return {
      type: 'resource_link',
      uri: source.uri,
      name: source.name,
      ...(source.title === undefined ? {} : { title: source.title }),
      ...(source.description === undefined
        ? {}
        : { description: source.description }),
      ...(source.mime_type === undefined
        ? {}
        : { mime_type: source.mime_type }),
      ...(source.size === undefined ? {} : { size: source.size }),
    };
  }
  throw invalidExecutionResponse('MCP content block');
}

function projectMcpResource(
  value: unknown,
): Extract<ToolMcpContentBlock, { type: 'resource' }>['resource'] {
  const source = responseObject(value, 'MCP embedded resource');
  if (
    !isBoundedNonEmptyString(source.uri) ||
    !isOptionalBoundedNonEmptyString(source.mime_type)
  ) {
    throw invalidExecutionResponse('MCP embedded resource');
  }
  if (
    isBoundedString(source.text) &&
    source.blob === undefined
  ) {
    return {
      uri: source.uri,
      ...(source.mime_type === undefined
        ? {}
        : { mime_type: source.mime_type }),
      text: source.text,
    };
  }
  if (
    isBoundedString(source.blob) &&
    source.text === undefined
  ) {
    return {
      uri: source.uri,
      ...(source.mime_type === undefined
        ? {}
        : { mime_type: source.mime_type }),
      blob: source.blob,
    };
  }
  throw invalidExecutionResponse('MCP embedded resource');
}

function projectBoundedJsonOutput(value: unknown, label: string): unknown {
  const budget = { nodes: 0 };
  const result = cloneBoundedJson(value, 0, budget, label);
  ensureBoundedOutput(result, label);
  return result;
}

function cloneBoundedJson(
  value: unknown,
  depth: number,
  budget: { nodes: number },
  label: string,
): unknown {
  budget.nodes += 1;
  if (
    depth > MAX_EXECUTION_OUTPUT_DEPTH ||
    budget.nodes > MAX_EXECUTION_OUTPUT_NODES
  ) {
    throw invalidExecutionResponse(label);
  }
  if (
    value === null ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (typeof value === 'string') {
    if (utf8Length(value) > MAX_EXECUTION_OUTPUT_BYTES) {
      throw invalidExecutionResponse(label);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      cloneBoundedJson(item, depth + 1, budget, label),
    );
  }
  if (isPlainJsonObject(value)) {
    const entries = Object.entries(value);
    if (entries.length > MAX_EXECUTION_OBJECT_KEYS) {
      throw invalidExecutionResponse(label);
    }
    const result: Record<string, unknown> = {};
    for (const [key, nestedValue] of entries) {
      if (utf8Length(key) > MAX_EXECUTION_KEY_BYTES) {
        throw invalidExecutionResponse(label);
      }
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: cloneBoundedJson(
          nestedValue,
          depth + 1,
          budget,
          label,
        ),
        writable: true,
      });
    }
    return result;
  }
  throw invalidExecutionResponse(label);
}

function ensureBoundedOutput(value: unknown, label: string): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw invalidExecutionResponse(label);
  }
  if (utf8Length(serialized) > MAX_EXECUTION_OUTPUT_BYTES) {
    throw invalidExecutionResponse(label);
  }
}

function responseObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!isPlainJsonObject(value)) {
    throw invalidExecutionResponse(label);
  }
  return value;
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isHttpStatus(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 100 &&
    value <= 599
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isBoundedString(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    utf8Length(value) <= MAX_EXECUTION_OUTPUT_BYTES
  );
}

function isBoundedNonEmptyString(value: unknown): value is string {
  return isBoundedString(value) && value.length > 0;
}

function isOptionalBoundedString(
  value: unknown,
): value is string | undefined {
  return value === undefined || isBoundedString(value);
}

function isOptionalBoundedNonEmptyString(
  value: unknown,
): value is string | undefined {
  return value === undefined || isBoundedNonEmptyString(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function invalidExecutionResponse(label: string): ToolExecutionContractError {
  return new ToolExecutionContractError(
    `The gateway returned an invalid ${label}. Reload before running the tool again.`,
  );
}
