import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  ConnectionContractError,
  type ConnectionCatalogRefreshResult,
  type ConnectionDetail as ConnectionDetailData,
  type ConnectionTestResult,
  deleteConnection,
  getConnection,
  refreshConnection,
  testConnection,
} from '../lib/connections';

type MutationKind = 'test' | 'refresh' | 'delete';

type ConnectionDetailError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'not-found'
    | 'conflict'
    | 'stale'
    | 'precondition'
    | 'ambiguous'
    | 'rate-limited'
    | 'timeout'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

export function ConnectionDetail() {
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<ConnectionDetailData | null>(null);
  const [etag, setEtag] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<ConnectionDetailError | null>(
    null,
  );
  const [mutationError, setMutationError] =
    useState<ConnectionDetailError | null>(null);
  const [mutationKind, setMutationKind] = useState<MutationKind | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(
    null,
  );
  const [refreshResult, setRefreshResult] =
    useState<ConnectionCatalogRefreshResult | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [reloadVersion, setReloadVersion] = useState(0);
  const mutationController = useRef<AbortController | null>(null);
  const routeConnectionId = useRef<string | null>(null);
  const feedbackRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const connectionId = id.trim();

    async function loadDetail() {
      if (routeConnectionId.current !== connectionId) {
        routeConnectionId.current = connectionId;
        mutationController.current?.abort();
        mutationController.current = null;
        setMutationKind(null);
        setDetail(null);
        setEtag(null);
        setTestResult(null);
        setRefreshResult(null);
        setConfirmingDelete(false);
      }
      setIsLoading(true);
      setLoadError(null);
      setMutationError(null);

      if (connectionId.length === 0) {
        setDetail(null);
        setEtag(null);
        setLoadError({
          kind: 'bad-request',
          message: 'A connection ID is required.',
        });
        setIsLoading(false);
        return;
      }

      try {
        const resource = await getConnection(connectionId, controller.signal);
        if (controller.signal.aborted) {
          return;
        }

        setDetail(resource.value);
        setEtag(resource.etag);
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }

        setDetail(null);
        setEtag(null);
        setLoadError(toConnectionDetailError(error));
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    }

    void loadDetail();
    return () => controller.abort();
  }, [id, reloadVersion]);

  useEffect(
    () => () => {
      mutationController.current?.abort();
      mutationController.current = null;
    },
    [id],
  );

  useEffect(() => {
    if (mutationError || testResult || refreshResult) {
      feedbackRef.current?.focus();
    }
  }, [mutationError, refreshResult, testResult]);

  function startMutation(kind: MutationKind): AbortController | null {
    if (
      mutationKind !== null ||
      mutationController.current !== null ||
      detail === null ||
      etag === null
    ) {
      return null;
    }

    const controller = new AbortController();
    mutationController.current = controller;
    setMutationKind(kind);
    setMutationError(null);
    return controller;
  }

  function finishMutation(controller: AbortController) {
    if (mutationController.current === controller) {
      mutationController.current = null;
      setMutationKind(null);
    }
  }

  async function runTest() {
    if (detail === null || !detail.actions.can_test || etag === null) {
      return;
    }

    const controller = startMutation('test');
    if (controller === null) {
      return;
    }

    setTestResult(null);
    setRefreshResult(null);
    try {
      const resource = await testConnection(
        detail.id,
        etag,
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }

      setTestResult(resource.value);
      setEtag(resource.etag);
      setReloadVersion((current) => current + 1);
    } catch (error) {
      if (!controller.signal.aborted) {
        handleMutationFailure(error);
      }
    } finally {
      finishMutation(controller);
    }
  }

  async function runRefresh() {
    if (detail === null || !detail.actions.can_refresh || etag === null) {
      return;
    }

    const controller = startMutation('refresh');
    if (controller === null) {
      return;
    }

    setRefreshResult(null);
    setTestResult(null);
    try {
      const resource = await refreshConnection(
        detail.id,
        etag,
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }

      setRefreshResult(resource.value);
      setEtag(resource.etag);
      setReloadVersion((current) => current + 1);
    } catch (error) {
      if (!controller.signal.aborted) {
        handleMutationFailure(error);
      }
    } finally {
      finishMutation(controller);
    }
  }

  async function runDelete() {
    if (detail === null || !detail.actions.can_delete || etag === null) {
      return;
    }

    const controller = startMutation('delete');
    if (controller === null) {
      return;
    }

    setTestResult(null);
    setRefreshResult(null);
    try {
      await deleteConnection(detail.id, etag, controller.signal);
      if (!controller.signal.aborted) {
        navigate('/connections', { replace: true });
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        handleMutationFailure(error);
        setConfirmingDelete(false);
      }
    } finally {
      finishMutation(controller);
    }
  }

  const heading = detail?.display_name ?? (id || 'Connection detail');

  function handleMutationFailure(error: unknown) {
    if (
      (error instanceof ConnectionContractError &&
        error.requiresReload) ||
      (error instanceof AdminApiError &&
        (error.status === 412 || error.status === 428))
    ) {
      setEtag(null);
    }
    setMutationError(
      error instanceof ConnectionContractError &&
        error.requiresReload
        ? {
            kind: 'ambiguous',
            message:
              'The operation may have changed gateway state, but its response did not include matching version metadata.',
          }
        : toConnectionDetailError(error),
    );
  }

  return (
    <main className="logs-page connection-detail-page">
      <section
        className="panel logs-panel connection-detail-panel"
        aria-labelledby="connection-detail-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Connection</p>
            <h2 id="connection-detail-heading">{heading}</h2>
          </div>
          <Link className="secondary-button" to="/connections">
            Back to connections
          </Link>
        </div>

        {loadError ? (
          <ConnectionErrorMessage
            error={loadError}
            context="load"
            onReload={() => setReloadVersion((current) => current + 1)}
          />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading connection detail
          </div>
        ) : null}

        {!isLoading && detail !== null ? (
          <>
            {detail.read_only ? (
              <div className="alert info" role="status">
                <h3>Legacy connection - read only</h3>
                <p>
                  This connection is projected from legacy configuration. Move
                  it to the managed connection store before editing, testing,
                  refreshing, or deleting it.
                </p>
              </div>
            ) : null}

            {!detail.enabled ? (
              <div className="alert warning" role="status">
                <h3>Disabled draft</h3>
                <p>
                  This connection cannot receive production traffic. You can
                  safely test the saved settings before enabling it.
                </p>
              </div>
            ) : null}

            <ConnectionSummary detail={detail} />
            <ConnectionConfiguration detail={detail} />
            <ConnectionDependencies detail={detail} />
            <ConnectionActionsPanel
              detail={detail}
              etag={etag}
              mutationKind={mutationKind}
              confirmingDelete={confirmingDelete}
              onConfirmingDelete={setConfirmingDelete}
              onEdit={() =>
                navigate(
                  `/connections/${encodeURIComponent(detail.id)}/edit`,
                )
              }
              onTest={() => void runTest()}
              onRefresh={() => void runRefresh()}
              onDelete={() => void runDelete()}
            />

            {mutationError || testResult || refreshResult ? (
              <div ref={feedbackRef} tabIndex={-1}>
                {mutationError ? (
                  <ConnectionErrorMessage
                    error={mutationError}
                    context="mutation"
                    onReload={() => {
                      setTestResult(null);
                      setRefreshResult(null);
                      setMutationError(null);
                      setReloadVersion((current) => current + 1);
                    }}
                  />
                ) : null}
                {testResult ? (
                  <ConnectionTestPanel result={testResult} />
                ) : null}
                {refreshResult ? (
                  <ConnectionRefreshPanel result={refreshResult} />
                ) : null}
              </div>
            ) : null}
          </>
        ) : null}
      </section>
    </main>
  );
}

function ConnectionSummary({ detail }: { detail: ConnectionDetailData }) {
  return (
    <section
      className="connection-detail-section"
      aria-labelledby="connection-summary-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Runtime</p>
          <h3 id="connection-summary-heading">Summary</h3>
        </div>
        <ConnectionStateBadge detail={detail} />
      </div>

      <dl className="traffic-metadata-grid connection-summary-grid">
        <SpecRow label="Connection ID" value={detail.id} code />
        <SpecRow
          label="Kind"
          value={
            detail.kind === 'http_api' ? 'HTTP API' : 'MCP streamable HTTP'
          }
        />
        <SpecRow
          label="Enabled"
          value={detail.enabled ? 'Yes' : 'No - disabled draft'}
        />
        <SpecRow label="Source" value={humanize(detail.source)} />
        <SpecRow
          label="Authentication"
          value={humanize(detail.authentication)}
        />
        <SpecRow
          label="Endpoints"
          value={detail.endpoint_count.toLocaleString()}
        />
        <SpecRow
          label="Catalog entries"
          value={
            detail.status.catalog_entry_count?.toLocaleString() ??
            'Not refreshed'
          }
        />
        <SpecRow
          label="Observed"
          value={detail.status.observed_at ?? 'Not observed yet'}
        />
        <SpecRow
          label="Latency"
          value={
            detail.status.latency_ms === undefined
              ? 'Not measured'
              : `${detail.status.latency_ms.toLocaleString()} ms`
          }
        />
        <SpecRow
          label="Created"
          value={detail.created_at ?? 'Legacy projection'}
        />
        <SpecRow
          label="Updated"
          value={detail.updated_at ?? 'Legacy projection'}
        />
      </dl>
    </section>
  );
}

function ConnectionConfiguration({
  detail,
}: {
  detail: ConnectionDetailData;
}) {
  const configuration = detail.configuration;

  return (
    <section
      className="connection-detail-section"
      aria-labelledby="connection-configuration-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Saved settings</p>
          <h3 id="connection-configuration-heading">Configuration</h3>
        </div>
      </div>

      {configuration === undefined ? (
        <div className="empty-state">
          Legacy topology and secret settings are intentionally not exposed.
        </div>
      ) : (
        <>
          <dl className="traffic-metadata-grid">
            <SpecRow
              label="Description"
              value={configuration.description ?? 'Not set'}
            />
            <SpecRow
              label="Base URL"
              value={configuration.endpoint.base_url}
              code
            />
            <SpecRow
              label="Base path"
              value={configuration.endpoint.base_path}
              code
            />
            <SpecRow
              label="Authentication"
              value={formatSafeAuthentication(configuration.authentication)}
            />
            <SpecRow
              label="Custom CA"
              value={
                configuration.tls.ca_bundle_configured
                  ? 'Configured'
                  : 'Not configured'
              }
            />
            <SpecRow
              label="Client certificate"
              value={
                configuration.tls.client_certificate_configured
                  ? 'Configured'
                  : 'Not configured'
              }
            />
            <SpecRow
              label="Client private key"
              value={
                configuration.tls.client_private_key_configured
                  ? 'Configured'
                  : 'Not configured'
              }
            />
            <SpecRow
              label="Discovery"
              value={
                configuration.discovery
                  ? humanize(configuration.discovery.type)
                  : 'Not configured'
              }
            />
            <SpecRow
              label="Test request"
              value={
                configuration.test_profile
                  ? `${configuration.test_profile.method} ${configuration.test_profile.path}`
                  : 'Not configured'
              }
              code={configuration.test_profile !== undefined}
            />
          </dl>
          <p className="alert info">
            Secret values and secret locators are never returned by this page.
            "Configured" only confirms that a protected binding exists.
          </p>
          <p className="alert info">
            A saved connection does not grant network reachability. Gateway
            egress host and port allowlists must still permit the destination.
          </p>
        </>
      )}
    </section>
  );
}

function ConnectionDependencies({
  detail,
}: {
  detail: ConnectionDetailData;
}) {
  return (
    <section
      className="connection-detail-section"
      aria-labelledby="connection-dependencies-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">References</p>
          <h3 id="connection-dependencies-heading">Dependencies</h3>
        </div>
        <span className="result-count">
          {detail.dependencies.length}{' '}
          {detail.dependencies.length === 1 ? 'dependency' : 'dependencies'}
        </span>
      </div>

      {detail.dependencies.length === 0 ? (
        <div className="empty-state">No active dependencies.</div>
      ) : (
        <div className="table-scroll">
          <table className="logs-table connections-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Consumer</th>
              </tr>
            </thead>
            <tbody>
              {detail.dependencies.map((dependency, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={`${dependency.kind}:${dependency.consumer_id}`}
                >
                  <td data-label="Kind">{humanize(dependency.kind)}</td>
                  <td data-label="Consumer">
                    <code>{dependency.consumer_id}</code>
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

function ConnectionActionsPanel({
  detail,
  etag,
  mutationKind,
  confirmingDelete,
  onConfirmingDelete,
  onEdit,
  onTest,
  onRefresh,
  onDelete,
}: {
  detail: ConnectionDetailData;
  etag: string | null;
  mutationKind: MutationKind | null;
  confirmingDelete: boolean;
  onConfirmingDelete: (confirming: boolean) => void;
  onEdit: () => void;
  onTest: () => void;
  onRefresh: () => void;
  onDelete: () => void;
}) {
  const isBusy = mutationKind !== null;
  const preconditionAvailable = etag !== null;
  const busyReason = isBusy
    ? 'A connection action is in progress. Wait for it to finish before starting another action.'
    : undefined;
  const updateBlockedReason = actionBlockedReason(
    detail,
    detail.actions.can_update,
    'update',
  );
  const testBlockedReason = preconditionAvailable
    ? actionBlockedReason(detail, detail.actions.can_test, 'test')
    : 'Reload this connection to obtain its current version';
  const refreshBlockedReason = preconditionAvailable
    ? actionBlockedReason(detail, detail.actions.can_refresh, 'refresh')
    : 'Reload this connection to obtain its current version';
  const deleteBlockedReason = preconditionAvailable
    ? actionBlockedReason(detail, detail.actions.can_delete, 'delete')
    : 'Reload this connection to obtain its current version';
  const deleteButtonRef = useRef<HTMLButtonElement | null>(null);
  const confirmDeleteButtonRef = useRef<HTMLButtonElement | null>(null);
  const restoreDeleteFocus = useRef(false);

  useEffect(() => {
    if (confirmingDelete) {
      confirmDeleteButtonRef.current?.focus();
      return;
    }

    if (restoreDeleteFocus.current) {
      restoreDeleteFocus.current = false;
      deleteButtonRef.current?.focus();
    }
  }, [confirmingDelete]);

  function cancelDeleteConfirmation() {
    if (isBusy) {
      return;
    }
    restoreDeleteFocus.current = true;
    onConfirmingDelete(false);
  }

  return (
    <section
      className="connection-detail-section"
      aria-labelledby="connection-actions-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Operations</p>
          <h3 id="connection-actions-heading">Actions</h3>
        </div>
      </div>

      <div className="connection-actions">
        <button
          type="button"
          className="secondary-button"
          disabled={!detail.actions.can_update || isBusy}
          aria-describedby={
            updateBlockedReason
              ? 'connection-update-blocked-reason'
              : busyReason
                ? 'connection-action-busy-reason'
                : undefined
          }
          onClick={onEdit}
        >
          Edit
        </button>
        <button
          type="button"
          className="primary-button"
          disabled={
            !detail.actions.can_test || !preconditionAvailable || isBusy
          }
          aria-describedby={
            testBlockedReason
              ? 'connection-test-blocked-reason'
              : busyReason
                ? 'connection-action-busy-reason'
                : undefined
          }
          onClick={onTest}
        >
          {mutationKind === 'test' ? 'Testing' : 'Test connection'}
        </button>
        <button
          type="button"
          className="secondary-button"
          disabled={
            !detail.actions.can_refresh || !preconditionAvailable || isBusy
          }
          aria-describedby={
            refreshBlockedReason
              ? 'connection-refresh-blocked-reason'
              : busyReason
                ? 'connection-action-busy-reason'
                : undefined
          }
          onClick={onRefresh}
        >
          {mutationKind === 'refresh' ? 'Refreshing' : 'Refresh inventory'}
        </button>

        {confirmingDelete ? (
          <div
            className="rule-delete-confirmation"
            role="group"
            aria-label="Delete connection confirmation"
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !isBusy) {
                event.preventDefault();
                event.stopPropagation();
                cancelDeleteConfirmation();
              }
            }}
          >
            <button
              ref={confirmDeleteButtonRef}
              type="button"
              className="rule-danger-button"
              aria-label={`Confirm delete ${detail.display_name}`}
              disabled={
                !detail.actions.can_delete ||
                !preconditionAvailable ||
                isBusy
              }
              aria-describedby={
                deleteBlockedReason
                  ? 'connection-delete-blocked-reason'
                  : busyReason
                    ? 'connection-action-busy-reason'
                    : undefined
              }
              onClick={onDelete}
            >
              {mutationKind === 'delete' ? 'Deleting' : 'Confirm delete'}
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={isBusy}
              aria-describedby={
                busyReason ? 'connection-action-busy-reason' : undefined
              }
              onClick={cancelDeleteConfirmation}
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            ref={deleteButtonRef}
            type="button"
            className="rule-danger-button"
            disabled={
              !detail.actions.can_delete ||
              !preconditionAvailable ||
              isBusy
            }
            aria-describedby={
              deleteBlockedReason
                ? 'connection-delete-blocked-reason'
                : busyReason
                  ? 'connection-action-busy-reason'
                  : undefined
            }
            onClick={() => onConfirmingDelete(true)}
          >
            Delete
          </button>
        )}
      </div>

      {updateBlockedReason ? (
        <p id="connection-update-blocked-reason" className="rule-hint">
          <strong>Edit unavailable:</strong> {updateBlockedReason}
        </p>
      ) : null}
      {testBlockedReason ? (
        <p id="connection-test-blocked-reason" className="rule-hint">
          <strong>Test connection unavailable:</strong> {testBlockedReason}
        </p>
      ) : null}
      {refreshBlockedReason ? (
        <p id="connection-refresh-blocked-reason" className="rule-hint">
          <strong>Refresh inventory unavailable:</strong>{' '}
          {refreshBlockedReason}
        </p>
      ) : null}
      {deleteBlockedReason ? (
        <p id="connection-delete-blocked-reason" className="rule-hint">
          <strong>Delete unavailable:</strong> {deleteBlockedReason}
        </p>
      ) : null}
      {busyReason ? (
        <p id="connection-action-busy-reason" className="rule-hint" role="status">
          {busyReason}
        </p>
      ) : null}

      {!detail.enabled && detail.actions.can_test ? (
        <p className="alert info" role="status">
          Testing this disabled draft uses its saved settings but does not
          enable it or route production requests to it.
        </p>
      ) : null}
    </section>
  );
}

function ConnectionTestPanel({ result }: { result: ConnectionTestResult }) {
  return (
    <section
      className={`connection-detail-section alert ${
        result.ok ? 'success' : 'warning'
      }`}
      aria-labelledby="connection-test-result-heading"
      role="status"
      aria-live="polite"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">Connection test</p>
          <h3 id="connection-test-result-heading">
            {result.ok ? 'Connection test passed' : 'Connection test failed'}
          </h3>
        </div>
        <span className="result-count">
          {result.latency_ms.toLocaleString()} ms
        </span>
      </div>
      <p>
        Tested {result.tested_at}. Operational state:{' '}
        <strong>{humanize(result.state)}</strong>.
      </p>
      <div className="table-scroll">
        <table className="logs-table connection-test-stages">
          <thead>
            <tr>
              <th>Stage</th>
              <th>Outcome</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {result.stages.map((stage, index) => (
              <tr
                className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                key={stage.name}
              >
                <td data-label="Stage">{humanize(stage.name)}</td>
                <td data-label="Outcome">
                  <span
                    className={`badge ${
                      stage.outcome === 'success'
                        ? 'success'
                        : stage.outcome === 'failure'
                          ? 'danger'
                          : 'neutral'
                    }`}
                  >
                    {humanize(stage.outcome)}
                  </span>
                </td>
                <td data-label="Reason">
                  {stage.reason ? humanize(stage.reason) : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ConnectionRefreshPanel({
  result,
}: {
  result: ConnectionCatalogRefreshResult;
}) {
  return (
    <section
      className="connection-detail-section alert success"
      aria-labelledby="connection-refresh-result-heading"
      role="status"
      aria-live="polite"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">Inventory refresh</p>
          <h3 id="connection-refresh-result-heading">
            Capability inventory refreshed
          </h3>
        </div>
        <span className="result-count">
          {result.total_count.toLocaleString()} total
        </span>
      </div>
      <dl className="traffic-metadata-grid connection-refresh-counts">
        <SpecRow
          label="Added"
          value={result.added_count.toLocaleString()}
        />
        <SpecRow
          label="Changed"
          value={result.changed_count.toLocaleString()}
        />
        <SpecRow
          label="Removed"
          value={result.removed_count.toLocaleString()}
        />
        <SpecRow
          label="Catalog revision"
          value={result.catalog_revision.toLocaleString()}
        />
      </dl>
    </section>
  );
}

function ConnectionStateBadge({
  detail,
}: {
  detail: ConnectionDetailData;
}) {
  const state = detail.status.state;
  const className =
    state === 'healthy'
      ? 'success'
      : state === 'unavailable'
        ? 'danger'
        : state === 'degraded' || state === 'disabled'
          ? 'warning'
          : 'neutral';

  return (
    <div className="connection-status">
      <span className={`badge ${className}`}>{humanize(state)}</span>
      <span>{humanize(detail.status.reason)}</span>
    </div>
  );
}

function ConnectionErrorMessage({
  error,
  context,
  onReload,
}: {
  error: ConnectionDetailError;
  context: 'load' | 'mutation';
  onReload: () => void;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before managing connections. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Connection permission required</h3>
        <p>
          This principal is authenticated but cannot perform this connection
          operation.
        </p>
      </div>
    );
  }

  if (error.kind === 'not-found') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection not found</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'stale') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection changed</h3>
        <p>
          Another administrator changed this connection. Reload the current
          saved version before trying again.
        </p>
        <button type="button" className="secondary-button" onClick={onReload}>
          Reload current version
        </button>
      </div>
    );
  }

  if (error.kind === 'conflict') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection operation blocked</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'precondition') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection version required</h3>
        <p>
          Reload this connection to obtain its current version before trying
          again.
        </p>
        <button type="button" className="secondary-button" onClick={onReload}>
          Reload current version
        </button>
      </div>
    );
  }

  if (error.kind === 'ambiguous') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection version unknown</h3>
        <p>
          {error.message} Reload the current saved version before any further
          test, refresh, or delete action.
        </p>
        <button type="button" className="secondary-button" onClick={onReload}>
          Reload current version
        </button>
      </div>
    );
  }

  const title =
    error.kind === 'rate-limited'
      ? 'Connection test is busy'
      : error.kind === 'timeout'
        ? 'Connection operation timed out'
        : error.kind === 'unavailable'
          ? 'Connection service unavailable'
          : error.kind === 'bad-request'
            ? 'Invalid connection request'
            : context === 'load'
              ? 'Connection request failed'
              : 'Connection operation failed';

  return (
    <div
      className={`error-panel alert ${
        error.kind === 'bad-request' || error.kind === 'rate-limited'
          ? 'warning'
          : 'error'
      }`}
      role="alert"
    >
      <h3>{title}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function actionBlockedReason(
  detail: ConnectionDetailData,
  allowed: boolean,
  action: 'update' | 'test' | 'refresh' | 'delete',
): string | undefined {
  if (allowed) {
    return undefined;
  }
  if (detail.read_only) {
    return 'Legacy connections are read only';
  }
  if (action === 'delete' && detail.dependencies.length > 0) {
    return "Remove this connection's dependencies before deleting it";
  }
  if (action === 'refresh' && !detail.enabled) {
    return 'Enable and test this connection before refreshing inventory';
  }
  if (action === 'test') {
    return 'Testing is not configured or you do not have test permission';
  }
  return `You do not have permission to ${action} this connection`;
}

function formatSafeAuthentication(
  authentication: NonNullable<
    ConnectionDetailData['configuration']
  >['authentication'],
): string {
  switch (authentication.type) {
    case 'none':
      return 'None';
    case 'header_api_key':
      return `${authentication.header_name} API key - ${
        authentication.secret_configured ? 'configured' : 'not configured'
      }`;
    case 'static_bearer':
      return `Static bearer - ${
        authentication.secret_configured ? 'configured' : 'not configured'
      }`;
    case 'oauth2_client_credentials':
      return `OAuth 2 client credentials - ${
        authentication.client_secret_configured
          ? 'secret configured'
          : 'secret not configured'
      }`;
  }
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

function toConnectionDetailError(error: unknown): ConnectionDetailError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404) {
      return { kind: 'not-found', message: error.message };
    }
    if (error.status === 409) {
      return { kind: 'conflict', message: error.message };
    }
    if (error.status === 412) {
      return { kind: 'stale', message: error.message };
    }
    if (error.status === 428) {
      return { kind: 'precondition', message: error.message };
    }
    if (error.status === 429) {
      return { kind: 'rate-limited', message: error.message };
    }
    if (error.status === 408) {
      return { kind: 'timeout', message: error.message };
    }
    if (error.status === 502 || error.status === 503) {
      return { kind: 'unavailable', message: error.message };
    }
    if (error.status === 400 || error.status === 422) {
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

function humanize(value: string): string {
  const text = value.replaceAll('_', ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}
