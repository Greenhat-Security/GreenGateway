import { AdminApiError, adminFetchJsonResponse } from './api';
import { authHeaders } from './auth';
import { adminApiUrl } from './config';

export type ToolDefinition = {
  name: string;
  description: string;
  input_json_schema: unknown;
  upstream: {
    method: string;
    path_template: string;
    query_params?: Array<{
      arg_name: string;
      query_name: string;
      required?: boolean;
    }>;
    body?: {
      mode: string;
    };
  };
};

export type OpenApiToolNameFallback = {
  method: string;
  path_template: string;
  original_operation_id?: string;
  generated_name: string;
  reason: string;
};

export type OpenApiSkippedOperation = {
  method: string;
  path_template: string;
  original_operation_id?: string;
  reason: string;
  property_name?: string;
};

export type OpenApiApiKeyHeaderAuthRequirement = {
  tool_name: string;
  method: string;
  path_template: string;
  scheme_name: string;
  header_name: string;
};

export type OpenApiToolsPreviewResponse = {
  tools: ToolDefinition[];
  operation_id_fallbacks: OpenApiToolNameFallback[];
  skipped_operations: OpenApiSkippedOperation[];
  api_key_header_auth_requirements: OpenApiApiKeyHeaderAuthRequirement[];
};

export type OpenApiToolsPreviewResult = {
  preview: OpenApiToolsPreviewResponse;
  etag: string | null;
};

export type OpenApiToolsRegisterResponse = {
  registered_tool_names: string[];
  tool_count: number;
};

export class OpenApiToolsConflictError extends AdminApiError {
  readonly conflicts: string[];

  constructor(message: string, conflicts: string[]) {
    super(409, message);
    this.name = 'OpenApiToolsConflictError';
    this.conflicts = conflicts;
  }
}

export async function previewOpenApiTools(
  spec: string,
): Promise<OpenApiToolsPreviewResult> {
  const response = await adminFetchJsonResponse<OpenApiToolsPreviewResponse>(
    adminApiUrl('/tools/openapi/preview'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
      },
      body: spec,
    },
  );

  return {
    preview: response.body,
    etag: response.headers.get('etag'),
  };
}

export async function registerOpenApiTools(
  spec: string,
  selectedToolNames: string[],
  etag: string,
): Promise<OpenApiToolsRegisterResponse> {
  const response = await fetch(adminApiUrl('/tools/openapi/register'), {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      ...authHeaders(),
      'Content-Type': 'application/json',
      'If-Match': etag,
    },
    body: JSON.stringify({
      spec,
      selected_tool_names: selectedToolNames,
    }),
  });
  const body = await parseJsonBody(response);

  if (!response.ok) {
    if (response.status === 409 && isConflictBody(body)) {
      throw new OpenApiToolsConflictError(body.error, body.conflicts);
    }
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  return body as OpenApiToolsRegisterResponse;
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim().length === 0) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function errorMessage(body: unknown, response: Response): string {
  if (
    body &&
    typeof body === 'object' &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }

  if (typeof body === 'string' && body.trim().length > 0) {
    return body;
  }

  return response.statusText || `Request failed with status ${response.status}`;
}

function isConflictBody(
  value: unknown,
): value is { error: string; conflicts: string[] } {
  return (
    value !== null &&
    typeof value === 'object' &&
    'error' in value &&
    typeof value.error === 'string' &&
    'conflicts' in value &&
    Array.isArray(value.conflicts) &&
    value.conflicts.every((conflict) => typeof conflict === 'string')
  );
}
