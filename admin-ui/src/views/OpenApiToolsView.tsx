import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { decodeJwtRolesClaim, getStoredToken } from '../lib/auth';
import {
  type OpenApiApiKeyHeaderAuthRequirement,
  type OpenApiSkippedOperation,
  type OpenApiToolsPreviewResponse,
  type ToolDefinition,
  OpenApiToolsConflictError,
  previewOpenApiTools,
  registerOpenApiTools,
} from '../lib/openapiTools';
import { fetchPolicy, type PolicyDocument } from '../lib/policy';

type OpenApiToolsViewError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'conflict'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
  conflicts?: string[];
};

const TOOLS_WRITE_PERMISSION = 'admin:tools:write';

export function OpenApiToolsView() {
  const [spec, setSpec] = useState('');
  const [preview, setPreview] = useState<OpenApiToolsPreviewResponse | null>(
    null,
  );
  const [previewEtag, setPreviewEtag] = useState<string | null>(null);
  const [selectedToolNames, setSelectedToolNames] = useState<Set<string>>(
    () => new Set(),
  );
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [loadError, setLoadError] = useState<OpenApiToolsViewError | null>(
    null,
  );
  const [mutationError, setMutationError] =
    useState<OpenApiToolsViewError | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [canWriteTools, setCanWriteTools] = useState(false);

  useEffect(() => {
    let isCurrent = true;

    async function loadWritePermission() {
      setCanWriteTools(false);

      try {
        const policyResult = await fetchPolicy();
        if (isCurrent) {
          setCanWriteTools(currentTokenCanWriteTools(policyResult.policy));
        }
      } catch {
        if (isCurrent) {
          setCanWriteTools(false);
        }
      }
    }

    void loadWritePermission();

    return () => {
      isCurrent = false;
    };
  }, []);

  const authRequirementByTool = useMemo(
    () => authRequirementMap(preview?.api_key_header_auth_requirements ?? []),
    [preview],
  );
  const generatedCount = preview?.tools.length ?? 0;
  const resultCount = `${generatedCount} ${
    generatedCount === 1 ? 'tool' : 'tools'
  }`;
  const selectedCount = selectedToolNames.size;
  const canPreview = spec.trim().length > 0 && !isPreviewing;
  const canRegister =
    canWriteTools &&
    preview !== null &&
    previewEtag !== null &&
    selectedCount > 0 &&
    !isRegistering;
  const showWritePermissionNotice =
    preview !== null && !canWriteTools && mutationError?.kind !== 'forbidden';

  async function submitPreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canPreview) {
      return;
    }

    setIsPreviewing(true);
    setLoadError(null);
    setMutationError(null);
    setSuccessMessage(null);

    try {
      const result = await previewOpenApiTools(spec);
      setPreview(result.preview);
      setPreviewEtag(result.etag);
      setSelectedToolNames(defaultSelectedTools(result.preview));
    } catch (error) {
      setPreview(null);
      setPreviewEtag(null);
      setSelectedToolNames(new Set());
      setLoadError(toOpenApiToolsViewError(error));
    } finally {
      setIsPreviewing(false);
    }
  }

  async function registerSelectedTools() {
    if (!canRegister || !previewEtag) {
      return;
    }

    setIsRegistering(true);
    setMutationError(null);
    setSuccessMessage(null);

    try {
      const registered = await registerOpenApiTools(
        spec,
        Array.from(selectedToolNames),
        previewEtag,
      );
      setSuccessMessage(
        `Registered ${registered.registered_tool_names.length} ${
          registered.registered_tool_names.length === 1 ? 'tool' : 'tools'
        }.`,
      );
    } catch (error) {
      const viewError = toOpenApiToolsViewError(error);
      if (viewError.kind === 'forbidden') {
        setCanWriteTools(false);
      }
      setMutationError(viewError);
    } finally {
      setIsRegistering(false);
    }
  }

  function toggleTool(toolName: string) {
    setSelectedToolNames((current) => {
      const next = new Set(current);
      if (next.has(toolName)) {
        next.delete(toolName);
      } else {
        next.add(toolName);
      }
      return next;
    });
  }

  return (
    <main className="logs-page openapi-tools-page">
      <section
        className="panel logs-panel openapi-tools-panel"
        aria-labelledby="openapi-tools-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Tools</p>
            <h2 id="openapi-tools-heading">OpenAPI tools</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        <form className="filter-form" onSubmit={submitPreview}>
          <label htmlFor="openapi-tools-spec">
            OpenAPI spec
            <textarea
              id="openapi-tools-spec"
              value={spec}
              placeholder="Paste an OpenAPI 3.x YAML or JSON document"
              spellCheck={false}
              onChange={(event) => setSpec(event.target.value)}
            />
          </label>

          <div className="form-actions">
            <button
              type="submit"
              className="primary-button"
              disabled={!canPreview}
            >
              {isPreviewing ? 'Previewing' : 'Preview'}
            </button>
            {canWriteTools ? (
              <button
                type="button"
                className="secondary-button"
                disabled={!canRegister}
                onClick={() => {
                  void registerSelectedTools();
                }}
              >
                {isRegistering ? 'Registering' : 'Register selected'}
              </button>
            ) : null}
            {preview ? (
              <span className="result-count">{selectedCount} selected</span>
            ) : null}
          </div>
        </form>

        {loadError ? <OpenApiToolsLoadErrorMessage error={loadError} /> : null}
        {showWritePermissionNotice ? <ToolsWritePermissionNotice /> : null}
        {mutationError ? (
          <OpenApiToolsMutationErrorMessage error={mutationError} />
        ) : null}
        {successMessage ? (
          <div className="error-panel alert success" role="status">
            <h3>Tools registered</h3>
            <p>{successMessage}</p>
          </div>
        ) : null}

        {preview ? (
          <>
            <div className="table-scroll">
              <table className="logs-table rule-table">
                <thead>
                  <tr>
                    <th>Select</th>
                    <th>Tool</th>
                    <th>Description</th>
                    <th>Upstream</th>
                    <th>Auth</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.tools.map((tool, index) => (
                    <OpenApiToolRow
                      key={tool.name}
                      authRequirement={authRequirementByTool.get(tool.name)}
                      isSelected={selectedToolNames.has(tool.name)}
                      rowIndex={index}
                      tool={tool}
                      onToggle={() => toggleTool(tool.name)}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            <SkippedOperationsList skipped={preview.skipped_operations} />
          </>
        ) : null}
      </section>
    </main>
  );
}

function OpenApiToolRow({
  tool,
  rowIndex,
  isSelected,
  authRequirement,
  onToggle,
}: {
  tool: ToolDefinition;
  rowIndex: number;
  isSelected: boolean;
  authRequirement?: OpenApiApiKeyHeaderAuthRequirement;
  onToggle: () => void;
}) {
  return (
    <tr className={`event-row ${rowIndex % 2 === 1 ? 'is-even' : ''}`}>
      <td>
        <input
          className="rule-checkbox"
          type="checkbox"
          aria-label={`Select ${tool.name}`}
          checked={isSelected}
          onChange={onToggle}
        />
      </td>
      <td>
        <code className="endpoint-template">{tool.name}</code>
      </td>
      <td>{tool.description}</td>
      <td>
        <span className="badge neutral">
          {tool.upstream.method} {tool.upstream.path_template}
        </span>
      </td>
      <td>
        {authRequirement ? (
          <span
            className="badge warning"
            title={`${authRequirement.scheme_name} uses ${authRequirement.header_name}`}
          >
            Requires upstream auth - not wired
          </span>
        ) : (
          <span className="badge success">No upstream auth flag</span>
        )}
      </td>
    </tr>
  );
}

function SkippedOperationsList({
  skipped,
}: {
  skipped: OpenApiSkippedOperation[];
}) {
  if (skipped.length === 0) {
    return null;
  }

  return (
    <section className="status-section" aria-labelledby="skipped-heading">
      <div className="section-heading">
        <p className="eyebrow">Review</p>
        <h3 id="skipped-heading">Skipped operations</h3>
      </div>
      <div className="table-scroll">
        <table className="logs-table rule-table">
          <thead>
            <tr>
              <th>Operation</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {skipped.map((operation, index) => (
              <tr
                className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                key={`${operation.method}:${operation.path_template}:${operation.original_operation_id ?? index}`}
              >
                <td>
                  <div className="traffic-endpoint-cell">
                    <span>
                      {operation.method} {operation.path_template}
                    </span>
                    <code className="endpoint-template">
                      {operation.original_operation_id ?? 'operationId missing'}
                    </code>
                  </div>
                </td>
                <td>{skippedReasonText(operation)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function OpenApiToolsLoadErrorMessage({
  error,
}: {
  error: OpenApiToolsViewError;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before previewing tools. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Tools permission required</h3>
        <p>This token is valid but does not include admin:tools:read.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>
        {error.kind === 'bad-request' ? 'Invalid OpenAPI spec' : 'Request failed'}
      </h3>
      <p>{error.message}</p>
    </div>
  );
}

function ToolsWritePermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Tools write permission required</h3>
      <p>This token can preview tools but does not include admin:tools:write.</p>
    </div>
  );
}

function OpenApiToolsMutationErrorMessage({
  error,
}: {
  error: OpenApiToolsViewError;
}) {
  if (error.kind === 'forbidden') {
    return <ToolsWritePermissionNotice />;
  }

  if (error.kind === 'conflict') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Tool name collision</h3>
        <p>{error.message}</p>
        {error.conflicts?.length ? (
          <div className="rule-method-list">
            {error.conflicts.map((conflict) => (
              <span className="badge warning" key={conflict}>
                {conflict}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>
        {error.kind === 'bad-request'
          ? 'Invalid registration request'
          : 'Tool registration failed'}
      </h3>
      <p>{error.message}</p>
    </div>
  );
}

function defaultSelectedTools(
  preview: OpenApiToolsPreviewResponse,
): Set<string> {
  const authRequired = authRequirementMap(
    preview.api_key_header_auth_requirements,
  );

  return new Set(
    preview.tools
      .filter((tool) => !authRequired.has(tool.name))
      .map((tool) => tool.name),
  );
}

function authRequirementMap(
  requirements: OpenApiApiKeyHeaderAuthRequirement[],
): Map<string, OpenApiApiKeyHeaderAuthRequirement> {
  return new Map(
    requirements.map((requirement) => [requirement.tool_name, requirement]),
  );
}

function skippedReasonText(operation: OpenApiSkippedOperation): string {
  if (operation.property_name) {
    return `${operation.reason}: ${operation.property_name}`;
  }

  return operation.reason;
}

function currentTokenCanWriteTools(policy: PolicyDocument): boolean {
  const token = getStoredToken();
  if (!token) {
    return false;
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return false;
  }

  return roles.some((roleName) => roleGrantsToolsWrite(policy.roles?.[roleName]));
}

function roleGrantsToolsWrite(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) => permission === TOOLS_WRITE_PERMISSION || permission === '*',
  );
}

function toOpenApiToolsViewError(error: unknown): OpenApiToolsViewError {
  if (error instanceof OpenApiToolsConflictError) {
    return {
      kind: 'conflict',
      message: 'Existing tools already use these names.',
      conflicts: error.conflicts,
    };
  }

  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 409) {
      return { kind: 'conflict', message: error.message };
    }
    if (error.status === 400) {
      return { kind: 'bad-request', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: `Network request failed: ${error.message}`,
    };
  }

  return { kind: 'network', message: 'Network request failed.' };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
