import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';

import { AdminApiError } from '../lib/api';
import {
  hasAdminPermission,
  useAdminCapabilities,
  useAdminIdentityVersion,
} from '../lib/adminCapabilities';
import { AdminCapabilitiesNotice } from '../lib/AdminCapabilitiesNotice';
import {
  type CatalogConversionReport,
  type CatalogIncompatibility,
  type CatalogNameFallback,
  type CatalogSkippedOperation,
  type CatalogToolRow,
  type ConnectionCatalogPreview,
  type ConnectionCatalogPublishResult,
  catalogRegisterRequest,
  catalogSpecBytes,
  catalogToolRows,
  defaultCatalogSelection,
  MAX_CATALOG_SPEC_BYTES,
  previewConnectionCatalog,
  registerConnectionCatalog,
} from '../lib/connectionCatalog';
import {
  ConnectionContractError,
  type ConnectionDetail,
} from '../lib/connections';

const TOOLS_READ_PERMISSION = 'admin:tools:read';
const TOOLS_WRITE_PERMISSION = 'admin:tools:write';
// A reason code is shown only when it has the shape of one: the gateway's
// codes are short snake_case words, and nothing else from an error body is
// ever displayed.
const SAFE_REASON_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

type Operation = 'preview' | 'register';

type ReviewedPreview = {
  value: ConnectionCatalogPreview;
  etag: string;
  // The exact document the preview judged; registration sends this text.
  spec: string;
};

type CatalogImportError = {
  operation: Operation;
  kind:
    | 'stale'
    | 'unauthorized'
    | 'forbidden'
    | 'refused'
    | 'too-large'
    | 'invalid'
    | 'overlay'
    | 'unavailable'
    | 'ambiguous'
    | 'contract'
    | 'network';
  status?: number;
  reason?: string;
};

/**
 * Preview and register a managed OpenAPI, Swagger 2.0 or Google Discovery
 * catalog for an HTTP API Connection. Only a Connection with managed OpenAPI
 * discovery takes one, and only that one mounts the workspace, so no other
 * detail page asks for admin permissions on its behalf.
 */
export function ConnectionCatalogImport({
  detail,
  onReloadConnection,
}: {
  detail: ConnectionDetail;
  onReloadConnection: () => void;
}) {
  const managedOpenApi =
    detail.configuration?.discovery?.type === 'managed_openapi';

  return (
    <section
      className="connection-detail-section"
      aria-labelledby="connection-catalog-import-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Managed OpenAPI</p>
          <h3 id="connection-catalog-import-heading">Import a catalog</h3>
        </div>
      </div>
      {managedOpenApi ? (
        <CatalogImportWorkspace
          detail={detail}
          onReloadConnection={onReloadConnection}
        />
      ) : (
        <p className="empty-state">
          This connection has no managed OpenAPI discovery. Edit it and choose
          managed OpenAPI discovery to preview and register an OpenAPI,
          Swagger 2.0 or Google Discovery catalog.
        </p>
      )}
    </section>
  );
}

function CatalogImportWorkspace({
  detail,
  onReloadConnection,
}: {
  detail: ConnectionDetail;
  onReloadConnection: () => void;
}) {
  const capabilities = useAdminCapabilities();
  const identityVersion = useAdminIdentityVersion();
  const [spec, setSpec] = useState('');
  const [uploadProblem, setUploadProblem] = useState<string | null>(null);
  const [preview, setPreview] = useState<ReviewedPreview | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [confirmed, setConfirmed] = useState(false);
  const [operation, setOperation] = useState<Operation | null>(null);
  const [error, setError] = useState<CatalogImportError | null>(null);
  const [result, setResult] = useState<ConnectionCatalogPublishResult | null>(
    null,
  );
  const [writeRejected, setWriteRejected] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const canRead = hasAdminPermission(capabilities, TOOLS_READ_PERMISSION);
  const canWrite =
    !writeRejected && hasAdminPermission(capabilities, TOOLS_WRITE_PERMISSION);
  const specBytes = useMemo(() => catalogSpecBytes(spec), [spec]);
  const specTooLarge = specBytes > MAX_CATALOG_SPEC_BYTES;
  const rows = useMemo(
    () => (preview === null ? [] : catalogToolRows(preview.value)),
    [preview],
  );
  const boundRows = rows.filter(
    (row): row is Extract<CatalogToolRow, { kind: 'bound' }> =>
      row.kind === 'bound',
  );
  const selectedRows = boundRows.filter((row) => selected.has(row.name));
  const selectedWrites = selectedRows.filter((row) => !row.read);
  const busy = operation !== null;
  const canPreview = canRead && spec.length > 0 && !specTooLarge && !busy;
  const canRegister =
    canWrite &&
    preview !== null &&
    preview.spec === spec &&
    selectedRows.length > 0 &&
    confirmed &&
    !busy;

  useEffect(
    () => () => {
      controller.current?.abort();
      controller.current = null;
    },
    [],
  );

  // A preview belongs to the identity that asked for it.
  useEffect(() => {
    controller.current?.abort();
    controller.current = null;
    setOperation(null);
    setPreview(null);
    setSelected(new Set());
    setConfirmed(false);
    setError(null);
    setResult(null);
    setWriteRejected(false);
  }, [identityVersion]);

  function begin(next: Operation): AbortController | null {
    if (controller.current !== null) {
      return null;
    }
    const active = new AbortController();
    controller.current = active;
    setOperation(next);
    setError(null);
    return active;
  }

  function finish(active: AbortController) {
    if (controller.current === active) {
      controller.current = null;
      setOperation(null);
    }
  }

  function discardPreview() {
    setPreview(null);
    setSelected(new Set());
    setConfirmed(false);
  }

  function updateSpec(next: string) {
    setSpec(next);
    setUploadProblem(null);
    if (preview !== null && next !== preview.spec) {
      discardPreview();
      setError(null);
    }
  }

  async function uploadDocument(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    input.value = '';
    if (file === undefined) {
      return;
    }
    // Checked before reading, so an oversized file is never loaded.
    if (file.size > MAX_CATALOG_SPEC_BYTES) {
      setUploadProblem(
        'The file is larger than the 2 MiB managed OpenAPI limit and was not read.',
      );
      return;
    }
    let text: string;
    try {
      text = await file.text();
    } catch {
      setUploadProblem('The file could not be read.');
      return;
    }
    updateSpec(text);
  }

  async function runPreview() {
    if (!canPreview) {
      return;
    }
    const active = begin('preview');
    if (active === null) {
      return;
    }
    const submitted = spec;
    discardPreview();
    setResult(null);
    try {
      const resource = await previewConnectionCatalog(
        detail.id,
        submitted,
        active.signal,
      );
      if (active.signal.aborted) {
        return;
      }
      setPreview({ value: resource.value, etag: resource.etag, spec: submitted });
      setSelected(defaultCatalogSelection(resource.value));
    } catch (failure) {
      if (!active.signal.aborted) {
        setError(toCatalogImportError('preview', failure));
      }
    } finally {
      finish(active);
    }
  }

  async function runRegister() {
    if (!canRegister || preview === null) {
      return;
    }
    const active = begin('register');
    if (active === null) {
      return;
    }
    try {
      const request = catalogRegisterRequest(
        preview.value,
        preview.spec,
        selectedRows.map((row) => row.name),
      );
      const resource = await registerConnectionCatalog(
        detail.id,
        request,
        preview.etag,
        active.signal,
      );
      if (active.signal.aborted) {
        return;
      }
      // Its revisions are spent: registering it again would be refused.
      discardPreview();
      setResult(resource.value);
    } catch (failure) {
      if (active.signal.aborted) {
        return;
      }
      const next = toCatalogImportError('register', failure);
      if (next.kind === 'stale' || next.kind === 'ambiguous') {
        discardPreview();
      }
      if (next.kind === 'forbidden') {
        setWriteRejected(true);
      }
      setError(next);
    } finally {
      finish(active);
    }
  }

  function toggle(name: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
    setConfirmed(false);
  }

  function replaceSelection(next: Set<string>) {
    setSelected(next);
    setConfirmed(false);
  }

  if (capabilities.status !== 'ready') {
    return <AdminCapabilitiesNotice state={capabilities} />;
  }

  if (!canRead) {
    return (
      <div className="error-panel alert warning" role="status">
        <h4>Tools read permission required</h4>
        <p>
          Previewing a catalog requires admin:tools:read, and registering it
          requires admin:tools:write.
        </p>
      </div>
    );
  }

  return (
    <>
      {detail.authentication === 'google_domain_wide_delegation' ? (
        <p className="alert info">
          No managed OpenAPI tool sends a domain-wide delegation credential,
          so the gateway refuses to preview or register a catalog on this
          connection (reason authentication_not_supported).
        </p>
      ) : null}
      {!detail.enabled ? (
        <p className="alert info">
          This connection is disabled, and the gateway refuses to preview or
          register a catalog on it (reason connection_disabled). Enable it
          first.
        </p>
      ) : null}

      <form
        className="filter-form"
        onSubmit={(event) => {
          event.preventDefault();
          void runPreview();
        }}
      >
        <label htmlFor="connection-catalog-spec">
          Catalog document
          <textarea
            id="connection-catalog-spec"
            value={spec}
            placeholder="Paste an OpenAPI 3.x, Swagger 2.0 or Google Discovery document in JSON or YAML"
            spellCheck={false}
            aria-describedby="connection-catalog-spec-limit"
            onChange={(event) => updateSpec(event.target.value)}
          />
        </label>
        <p id="connection-catalog-spec-limit" className="rule-hint">
          {formatBytes(specBytes)} of 2 MiB. The document is previewed and
          registered exactly as submitted; nothing is stored until you
          register.
        </p>
        {specTooLarge ? (
          <p className="rule-hint is-error" role="alert">
            The document is larger than the 2 MiB managed OpenAPI limit.
          </p>
        ) : null}
        {uploadProblem ? (
          <p className="rule-hint is-error" role="alert">
            {uploadProblem}
          </p>
        ) : null}
        <div className="form-actions">
          <button
            type="submit"
            className="primary-button"
            disabled={!canPreview}
          >
            {operation === 'preview' ? 'Previewing' : 'Preview catalog'}
          </button>
          <button
            type="button"
            className="secondary-button"
            disabled={busy}
            onClick={() => fileInput.current?.click()}
          >
            Upload document
          </button>
          <input
            ref={fileInput}
            type="file"
            hidden
            aria-label="Catalog document file"
            accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml"
            onChange={(event) => void uploadDocument(event)}
          />
        </div>
      </form>

      {error ? (
        <CatalogImportErrorMessage
          error={error}
          onPreviewAgain={
            error.kind === 'stale' && canPreview ? () => void runPreview() : undefined
          }
          onReloadConnection={onReloadConnection}
        />
      ) : null}

      {result ? (
        <CatalogRegisteredPanel
          result={result}
          onReloadConnection={onReloadConnection}
        />
      ) : null}

      {preview ? (
        <>
          <CatalogPreviewSummary preview={preview.value} />
          <CatalogConversion conversion={preview.value.conversion} />
          <CatalogOverlayNotice preview={preview.value} />
          <CatalogToolTable
            rows={rows}
            selected={selected}
            disabled={busy}
            onToggle={toggle}
          />
          <div className="form-actions">
            <button
              type="button"
              className="secondary-button"
              disabled={busy}
              onClick={() =>
                replaceSelection(defaultCatalogSelection(preview.value))
              }
            >
              Select bindable reads
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={busy || selected.size === 0}
              onClick={() => replaceSelection(new Set())}
            >
              Clear selection
            </button>
            <span className="result-count">
              {selectedRows.length} of {boundRows.length} bindable selected
            </span>
          </div>
          <CatalogSkippedOperations
            skipped={preview.value.skipped_operations}
          />
          <CatalogNameFallbacks fallbacks={preview.value.operation_id_fallbacks} />

          {canWrite ? (
            <section
              className="connection-detail-section"
              aria-labelledby="connection-catalog-register-heading"
            >
              <h4 id="connection-catalog-register-heading">
                Confirm and register
              </h4>
              {selectedWrites.length > 0 ? (
                <p className="alert warning" role="status">
                  {selectedWrites.length === 1
                    ? '1 selected tool is'
                    : `${selectedWrites.length} selected tools are`}{' '}
                  not a GET or HEAD operation and can change upstream state.
                </p>
              ) : null}
              {selectedRows.length === 0 ? (
                <p className="empty-state">
                  Select at least one bindable tool to register.
                </p>
              ) : (
                <>
                  <div className="table-scroll">
                    <table className="logs-table">
                      <thead>
                        <tr>
                          <th>Tool</th>
                          <th>Credential sent for</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedRows.map((row, index) => (
                          <tr
                            className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                            key={row.name}
                          >
                            <td>
                              <code>{row.name}</code>
                            </td>
                            <td>
                              {formatSchemes(
                                row.confirmation.selected_scheme_names,
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <label className="rule-check-row">
                    <input
                      type="checkbox"
                      checked={confirmed}
                      disabled={busy}
                      onChange={(event) => setConfirmed(event.target.checked)}
                    />
                    I confirm that each selected tool sends this
                    connection&apos;s credential for the security alternative
                    shown
                  </label>
                </>
              )}
              <dl className="traffic-metadata-grid">
                <SpecRow label="Spec digest" value={preview.value.spec_digest} code />
                <SpecRow
                  label="Expected spec revision"
                  value={String(preview.value.spec_revision)}
                />
                <SpecRow
                  label="Expected catalog revision"
                  value={String(preview.value.catalog_revision)}
                />
              </dl>
              <div className="form-actions">
                <button
                  type="button"
                  className="primary-button"
                  disabled={!canRegister}
                  onClick={() => void runRegister()}
                >
                  {operation === 'register'
                    ? 'Registering'
                    : `Register ${selectedRows.length} selected`}
                </button>
              </div>
            </section>
          ) : (
            <div className="error-panel alert warning" role="status">
              <h4>Tools write permission required</h4>
              <p>
                This principal can preview catalogs but does not have
                admin:tools:write, so it cannot register one.
              </p>
            </div>
          )}
        </>
      ) : null}
    </>
  );
}

function CatalogPreviewSummary({
  preview,
}: {
  preview: ConnectionCatalogPreview;
}) {
  const format =
    preview.conversion === undefined
      ? 'OpenAPI 3.x'
      : preview.conversion.source_format === 'swagger_2_0'
        ? 'Swagger 2.0, converted to OpenAPI 3.0'
        : 'Google Discovery v1, converted to OpenAPI 3.0';
  return (
    <dl className="traffic-metadata-grid">
      <SpecRow label="Detected format" value={format} />
      <SpecRow label="Generated tools" value={String(preview.tools.length)} />
      <SpecRow
        label="Incompatible operations"
        value={String(preview.incompatibilities.length)}
      />
      <SpecRow
        label="Skipped operations"
        value={String(preview.skipped_operations.length)}
      />
    </dl>
  );
}

function CatalogConversion({
  conversion,
}: {
  conversion: CatalogConversionReport | undefined;
}) {
  if (conversion === undefined) {
    return null;
  }
  return (
    <section aria-labelledby="connection-catalog-conversion-heading">
      <h4 id="connection-catalog-conversion-heading">Conversion warnings</h4>
      {conversion.warnings.length === 0 ? (
        <p className="empty-state">The conversion reported no warnings.</p>
      ) : (
        <div className="table-scroll">
          <table className="logs-table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Operation</th>
                <th>Subject</th>
                <th>Effect</th>
              </tr>
            </thead>
            <tbody>
              {conversion.warnings.map((warning, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={`${warning.code}:${index}`}
                >
                  <td>
                    <code>{warning.code}</code>
                    <br />
                    <small>{warning.message}</small>
                  </td>
                  <td>
                    {warning.method === undefined &&
                    warning.path_template === undefined ? (
                      '-'
                    ) : (
                      <code>
                        {[warning.method, warning.path_template]
                          .filter((part) => part !== undefined)
                          .join(' ')}
                      </code>
                    )}
                  </td>
                  <td>{warning.subject ? <code>{warning.subject}</code> : '-'}</td>
                  <td>
                    {warning.operation_omitted ? (
                      <span className="badge warning">Operation omitted</span>
                    ) : (
                      <span className="badge neutral">Kept</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function CatalogOverlayNotice({
  preview,
}: {
  preview: ConnectionCatalogPreview;
}) {
  if (!preview.overlay.applied) {
    return null;
  }
  const warnings = preview.overlay.warnings.length;
  return (
    <p className="alert info">
      This connection&apos;s stored overlay was compiled into the preview and
      is published with the registration
      {warnings === 0
        ? '.'
        : `; it reported ${warnings} ${warnings === 1 ? 'warning' : 'warnings'}.`}
    </p>
  );
}

function CatalogToolTable({
  rows,
  selected,
  disabled,
  onToggle,
}: {
  rows: CatalogToolRow[];
  selected: Set<string>;
  disabled: boolean;
  onToggle: (name: string) => void;
}) {
  if (rows.length === 0) {
    return <p className="empty-state">The document produced no tools.</p>;
  }
  return (
    <div className="table-scroll">
      <table className="logs-table">
        <thead>
          <tr>
            <th>Select</th>
            <th>Tool</th>
            <th>Method</th>
            <th>Binding</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
              key={`${row.kind}:${row.name}`}
            >
              <td>
                <input
                  className="rule-checkbox"
                  type="checkbox"
                  aria-label={`Select ${row.name}`}
                  checked={row.kind === 'bound' && selected.has(row.name)}
                  disabled={disabled || row.kind !== 'bound'}
                  onChange={() => onToggle(row.name)}
                />
              </td>
              <td>
                <code className="endpoint-template">{row.name}</code>
                {row.kind !== 'incompatible' ? (
                  <>
                    <br />
                    <small>{row.tool.title ?? row.tool.description}</small>
                  </>
                ) : null}
              </td>
              <td>{methodCell(row)}</td>
              <td>{bindingCell(row)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function methodCell(row: CatalogToolRow) {
  if (row.kind === 'incompatible') {
    return row.incompatibility.path_template ? (
      <code>{row.incompatibility.path_template}</code>
    ) : (
      '-'
    );
  }
  if (row.kind === 'composite') {
    return <span className="badge neutral">Composite</span>;
  }
  return (
    <span className={`badge ${row.kind === 'bound' && row.read ? 'neutral' : 'warning'}`}>
      {row.tool.upstream.method} {row.tool.upstream.path_template}
    </span>
  );
}

function bindingCell(row: CatalogToolRow) {
  switch (row.kind) {
    case 'bound':
      return (
        <span className="badge success">
          Binds: {formatSchemes(row.confirmation.selected_scheme_names)}
        </span>
      );
    case 'composite':
      return 'Declared by the stored overlay and published with it';
    case 'unconfirmed':
      return (
        <span className="badge warning">
          No security confirmation in this preview
        </span>
      );
    case 'incompatible':
      return <IncompatibilityDetail incompatibility={row.incompatibility} />;
  }
}

function IncompatibilityDetail({
  incompatibility,
}: {
  incompatibility: CatalogIncompatibility;
}) {
  return (
    <div>
      <span className="badge danger">
        Not bindable: <code>{incompatibility.reason}</code>
      </span>
      {incompatibility.security_alternatives ? (
        <ul>
          {incompatibility.security_alternatives.map((alternative, index) => (
            <li key={`${alternative.reason}:${index}`}>
              {formatSchemes(alternative.scheme_names)}:{' '}
              <code>{alternative.reason}</code> - {alternative.message}
              {alternative.missing_scopes ? (
                <>
                  {' '}
                  Missing scopes:{' '}
                  {alternative.missing_scopes.map((scope, scopeIndex) => (
                    <span key={scope}>
                      {scopeIndex > 0 ? ', ' : null}
                      <code>{scope}</code>
                    </span>
                  ))}
                </>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
      {incompatibility.unexplained_security_alternatives ? (
        <small>
          {incompatibility.unexplained_security_alternatives} more{' '}
          {incompatibility.unexplained_security_alternatives === 1
            ? 'alternative is'
            : 'alternatives are'}{' '}
          not explained.
        </small>
      ) : null}
    </div>
  );
}

function CatalogSkippedOperations({
  skipped,
}: {
  skipped: CatalogSkippedOperation[];
}) {
  if (skipped.length === 0) {
    return null;
  }
  return (
    <section aria-labelledby="connection-catalog-skipped-heading">
      <h4 id="connection-catalog-skipped-heading">Skipped operations</h4>
      <div className="table-scroll">
        <table className="logs-table">
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
                key={`${operation.method}:${operation.path_template}:${index}`}
              >
                <td>
                  <code>
                    {operation.method} {operation.path_template}
                  </code>
                  {operation.original_operation_id ? (
                    <>
                      <br />
                      <small>{operation.original_operation_id}</small>
                    </>
                  ) : null}
                </td>
                <td>
                  <code>{operation.reason}</code>
                  {operation.property_name ? (
                    <>
                      {' '}
                      (<code>{operation.property_name}</code>)
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CatalogNameFallbacks({
  fallbacks,
}: {
  fallbacks: CatalogNameFallback[];
}) {
  if (fallbacks.length === 0) {
    return null;
  }
  return (
    <section aria-labelledby="connection-catalog-fallbacks-heading">
      <h4 id="connection-catalog-fallbacks-heading">Generated tool names</h4>
      <ul>
        {fallbacks.map((fallback, index) => (
          <li key={`${fallback.generated_name}:${index}`}>
            <code>{fallback.generated_name}</code> for{' '}
            <code>
              {fallback.method} {fallback.path_template}
            </code>{' '}
            (<code>{fallback.reason}</code>)
          </li>
        ))}
      </ul>
    </section>
  );
}

function CatalogRegisteredPanel({
  result,
  onReloadConnection,
}: {
  result: ConnectionCatalogPublishResult;
  onReloadConnection: () => void;
}) {
  return (
    <section
      className="connection-detail-section alert success"
      aria-labelledby="connection-catalog-registered-heading"
      role="status"
      aria-live="polite"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">Catalog import</p>
          <h4 id="connection-catalog-registered-heading">Catalog registered</h4>
        </div>
        <span className="result-count">
          {result.registered_tool_names.length}{' '}
          {result.registered_tool_names.length === 1 ? 'tool' : 'tools'}
        </span>
      </div>
      <dl className="traffic-metadata-grid connection-refresh-counts">
        <SpecRow label="Added" value={result.added_count.toLocaleString()} />
        <SpecRow label="Changed" value={result.changed_count.toLocaleString()} />
        <SpecRow label="Removed" value={result.removed_count.toLocaleString()} />
        <SpecRow
          label="Catalog revision"
          value={result.catalog_revision.toLocaleString()}
        />
      </dl>
      <p>
        Registered:{' '}
        {result.registered_tool_names.map((name, index) => (
          <span key={name}>
            {index > 0 ? ', ' : null}
            <code>{name}</code>
          </span>
        ))}
      </p>
      <div className="form-actions">
        <button
          type="button"
          className="secondary-button"
          onClick={onReloadConnection}
        >
          Reload connection
        </button>
      </div>
    </section>
  );
}

function CatalogImportErrorMessage({
  error,
  onPreviewAgain,
  onReloadConnection,
}: {
  error: CatalogImportError;
  onPreviewAgain?: () => void;
  onReloadConnection: () => void;
}) {
  const { title, text } = describeCatalogImportError(error);
  return (
    <div
      className={`error-panel alert ${
        error.kind === 'unavailable' ||
        error.kind === 'network' ||
        error.kind === 'contract'
          ? 'error'
          : 'warning'
      }`}
      role="alert"
    >
      <h4>{title}</h4>
      <p>{text}</p>
      {error.reason ? (
        <p>
          Reason code: <code>{error.reason}</code>
        </p>
      ) : null}
      {onPreviewAgain ? (
        <button
          type="button"
          className="secondary-button"
          onClick={onPreviewAgain}
        >
          Preview again
        </button>
      ) : null}
      {error.kind === 'ambiguous' ? (
        <button
          type="button"
          className="secondary-button"
          onClick={onReloadConnection}
        >
          Reload connection
        </button>
      ) : null}
    </div>
  );
}

/**
 * Fixed text for every refusal. Nothing from the error body except a
 * reason code is shown, so no part of the submitted document can be echoed
 * back through an error.
 */
const REFUSAL_TEXT: Record<string, string> = {
  capability_not_advertised:
    'A live gateway replica does not advertise support for catalogs converted from this document format, so nothing was stored. Finish the rolling upgrade, or wait for earlier replicas to go stale, then preview and register again.',
  authentication_not_supported:
    "No managed OpenAPI tool sends this connection's credential, so no catalog is registered on it. A Google domain-wide delegation connection is refused this way.",
  caller_assertion_not_enforced:
    "Managed OpenAPI tools cannot attest the caller for this connection, so nothing was fetched or stored. A delegated connection's catalog is registered from an uploaded document, and a caller assertion block that those tools cannot honour is refused.",
  connection_disabled:
    'The connection is disabled. Enable it before previewing or registering a catalog.',
  discovery_not_configured:
    'The connection has no managed OpenAPI discovery. Edit it to configure discovery first.',
  connection_kind_mismatch: 'Only HTTP API connections take an OpenAPI catalog.',
  catalog_operation_in_progress:
    'Another catalog operation on this connection is in progress. Try again when it finishes.',
  tool_name_conflict:
    'A selected tool name is already used by another tool, and nothing was replaced.',
  catalog_not_registered: 'This connection has no registered catalog.',
  authority_evidence_unsupported:
    'This deployment requires authority evidence that it cannot record for a catalog change, so nothing was stored.',
  invalid_spec:
    'The gateway could not read the document as OpenAPI 3.x, Swagger 2.0 or a Google Discovery document.',
  invalid_selection:
    'The selection does not match the reviewed catalog. Preview the document again and reselect.',
  authentication_mismatch:
    "A confirmed security alternative no longer binds to the connection's credential. Preview the document again.",
};

function describeCatalogImportError(error: CatalogImportError): {
  title: string;
  text: string;
} {
  const action =
    error.operation === 'preview' ? 'Catalog preview' : 'Catalog registration';
  switch (error.kind) {
    case 'stale':
      return {
        title: 'Catalog preview out of date',
        text: 'The connection or its catalog changed after this preview, so nothing was registered. Preview the document again and review the new result before registering.',
      };
    case 'unauthorized':
      return {
        title: 'Sign-in required',
        text: 'Sign in again before importing a catalog.',
      };
    case 'forbidden':
      return {
        title: `${action} not permitted`,
        text:
          error.operation === 'preview'
            ? 'This principal cannot preview catalogs on this connection. Preview requires admin:tools:read, and admin:connections:secrets:write when the stored overlay declares raw source paths.'
            : 'This principal cannot register catalogs. Registration requires admin:tools:write.',
      };
    case 'too-large':
      return {
        title: 'Document too large',
        text: 'The gateway refused the document as larger than it accepts. Managed OpenAPI documents are limited to 2 MiB.',
      };
    case 'overlay':
      return {
        title: 'Stored overlay does not compile',
        text: "This connection's stored overlay does not compile against the document, so nothing was stored. Review the overlay before importing this document.",
      };
    case 'unavailable':
      return {
        title: `${action} unavailable`,
        text: 'The gateway could not complete this request safely right now, and nothing was stored. Try again later.',
      };
    case 'ambiguous':
      return {
        title: 'Registration outcome unknown',
        text: 'The gateway accepted the registration without returning a complete, matching result. The catalog may have been published. Reload the connection before registering again.',
      };
    case 'contract':
      return {
        title: `${action} not verifiable`,
        text: 'The gateway returned a response this page cannot verify, so it was discarded and nothing was registered.',
      };
    case 'network':
      return {
        title: `${action} did not complete`,
        text: 'The request did not reach the gateway or its answer was lost. Check the connection to the gateway and try again.',
      };
    case 'invalid':
    case 'refused':
      return {
        title: `${action} refused`,
        text:
          (error.reason ? REFUSAL_TEXT[error.reason] : undefined) ??
          'The gateway refused the request, and nothing was stored.',
      };
  }
}

function toCatalogImportError(
  operation: Operation,
  failure: unknown,
): CatalogImportError {
  if (failure instanceof ConnectionContractError) {
    return {
      operation,
      kind: failure.requiresReload ? 'ambiguous' : 'contract',
    };
  }
  if (!(failure instanceof AdminApiError)) {
    return { operation, kind: 'network' };
  }
  const reason = SAFE_REASON_PATTERN.test(failure.code)
    ? failure.code
    : undefined;
  const base = { operation, status: failure.status, reason };
  if (failure.status === 412 || reason === 'stale_preview') {
    return { ...base, kind: 'stale' };
  }
  if (failure.status === 401) {
    return { ...base, kind: 'unauthorized' };
  }
  if (failure.status === 403) {
    return { ...base, kind: 'forbidden' };
  }
  if (failure.status === 413 || reason === 'spec_too_large') {
    return { ...base, kind: 'too-large' };
  }
  if (failure.status === 422) {
    return { ...base, kind: 'overlay' };
  }
  if (failure.status === 400) {
    return { ...base, kind: 'invalid' };
  }
  if (failure.status === 502 || failure.status === 503 || failure.status === 500) {
    return { ...base, kind: 'unavailable' };
  }
  return { ...base, kind: 'refused' };
}

function formatSchemes(schemes: string[]): string {
  return schemes.length === 0 ? 'no security' : schemes.join(' + ');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} bytes`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function SpecRow({
  label,
  value,
  code = false,
}: {
  label: string;
  value: string;
  code?: boolean;
}) {
  return (
    <div className="spec-row">
      <dt className="k">{label}</dt>
      <dd className="v">{code ? <code>{value}</code> : value}</dd>
    </div>
  );
}
