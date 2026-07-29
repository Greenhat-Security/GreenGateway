import { FormEvent, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  type ConnectionKind,
  type ConnectionListFilters,
  type ConnectionManagementSource,
  type ConnectionOperationalState,
  type ConnectionSummary,
  listConnections,
} from '../lib/connections';

type FilterDraft = {
  state: '' | ConnectionOperationalState;
  kind: '' | ConnectionKind;
  source: '' | ConnectionManagementSource;
};

type ConnectionsError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'conflict'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

const EMPTY_FILTERS: FilterDraft = {
  state: '',
  kind: '',
  source: '',
};

export function ConnectionsView() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<FilterDraft>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] =
    useState<FilterDraft>(EMPTY_FILTERS);
  const [connections, setConnections] = useState<ConnectionSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [omittedLegacyCount, setOmittedLegacyCount] = useState(0);
  const [canCreate, setCanCreate] = useState(false);
  const [canManageSecrets, setCanManageSecrets] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<ConnectionsError | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [inventoryNotice, setInventoryNotice] = useState<string | null>(null);
  const [reloadVersion, setReloadVersion] = useState(0);
  const errorRef = useRef<HTMLDivElement>(null);
  const focusedErrorRef = useRef<ConnectionsError | null>(null);
  const paginationControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = null;

    async function loadFirstPage() {
      setIsLoading(true);
      setIsLoadingMore(false);
      setLoadError(null);
      setAnnouncement('');

      try {
        const resource = await listConnections(
          toListFilters(appliedFilters),
          controller.signal,
        );
        if (controller.signal.aborted) {
          return;
        }

        setConnections(resource.value.connections);
        setNextCursor(resource.value.next_cursor ?? null);
        setOmittedLegacyCount(
          resource.value.omitted_legacy_projection_count ?? 0,
        );
        setCanCreate(resource.value.actions.can_create);
        setCanManageSecrets(
          resource.value.actions.can_manage_secrets,
        );
        setAnnouncement(
          resource.value.connections.length === 0
            ? 'Connection inventory loaded. No connections matched these filters.'
            : `Connection inventory loaded. ${resource.value.connections.length} ${
                resource.value.connections.length === 1
                  ? 'connection'
                  : 'connections'
              } shown.`,
        );
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }

        setConnections([]);
        setNextCursor(null);
        setOmittedLegacyCount(0);
        setCanCreate(false);
        setCanManageSecrets(false);
        setLoadError(toConnectionsError(error));
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    }

    void loadFirstPage();
    return () => {
      controller.abort();
      paginationControllerRef.current?.abort();
    };
  }, [appliedFilters, reloadVersion]);

  useEffect(() => {
    if (loadError === null) {
      focusedErrorRef.current = null;
      return;
    }

    if (focusedErrorRef.current === loadError) {
      return;
    }

    focusedErrorRef.current = loadError;
    if (
      errorRef.current !== null &&
      document.activeElement !== errorRef.current
    ) {
      errorRef.current.focus();
    }
  }, [loadError]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    cancelPagination();
    setInventoryNotice(null);
    setAppliedFilters({ ...filters });
  }

  function clearFilters() {
    cancelPagination();
    setInventoryNotice(null);
    setFilters(EMPTY_FILTERS);
    setAppliedFilters(EMPTY_FILTERS);
  }

  async function loadMore() {
    if (nextCursor === null || isLoadingMore || isLoading) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);
    setAnnouncement('');
    const controller = new AbortController();
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = controller;
    try {
      const resource = await listConnections(
        {
          ...toListFilters(appliedFilters),
          cursor: nextCursor,
        },
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }
      const shownCount =
        connections.length + resource.value.connections.length;
      setConnections((current) => [
        ...current,
        ...resource.value.connections,
      ]);
      setAnnouncement(
        `Loaded ${resource.value.connections.length} more ${
          resource.value.connections.length === 1
            ? 'connection'
            : 'connections'
        }. ${shownCount} shown.`,
      );
      setNextCursor(resource.value.next_cursor ?? null);
      setOmittedLegacyCount(
        resource.value.omitted_legacy_projection_count ?? 0,
      );
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (error instanceof AdminApiError && error.status === 412) {
        setInventoryNotice(
          'Connection inventory changed. The current first page was loaded.',
        );
        setReloadVersion((current) => current + 1);
      } else {
        setLoadError(toConnectionsError(error));
      }
    } finally {
      if (!controller.signal.aborted) {
        setIsLoadingMore(false);
      }
      if (paginationControllerRef.current === controller) {
        paginationControllerRef.current = null;
      }
    }
  }

  function cancelPagination() {
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = null;
    setIsLoadingMore(false);
  }

  return (
    <main className="logs-page connections-page">
      <section
        className="panel logs-panel connections-panel"
        aria-labelledby="connections-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Upstreams</p>
            <h2 id="connections-heading">Connections</h2>
          </div>
          <div className="connection-actions">
            <span className="result-count">
              {connections.length}{' '}
              {connections.length === 1 ? 'connection' : 'connections'}
            </span>
            {canManageSecrets ? (
              <button
                type="button"
                className="secondary-button"
                onClick={() => navigate('/connections/new')}
              >
                Manage secrets
              </button>
            ) : null}
            {canCreate ? (
              <button
                type="button"
                className="primary-button"
                onClick={() => navigate('/connections/new')}
              >
                Add connection
              </button>
            ) : null}
          </div>
        </div>

        <p>
          Manage saved HTTP API and MCP upstreams. New connections start as
          disabled drafts so you can test them before production traffic uses
          them.
        </p>

        <form
          className="filter-form connections-filter-form"
          onSubmit={applyFilters}
        >
          <div className="filter-grid connections-filter-grid">
            <label>
              Operational state
              <select
                value={filters.state}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    state: event.target.value as FilterDraft['state'],
                  }))
                }
              >
                <option value="">All states</option>
                <option value="unknown">Unknown</option>
                <option value="configured">Configured</option>
                <option value="healthy">Healthy</option>
                <option value="degraded">Degraded</option>
                <option value="unavailable">Unavailable</option>
                <option value="disabled">Disabled</option>
              </select>
            </label>
            <label>
              Kind
              <select
                value={filters.kind}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    kind: event.target.value as FilterDraft['kind'],
                  }))
                }
              >
                <option value="">All kinds</option>
                <option value="http_api">HTTP API</option>
                <option value="mcp_streamable_http">MCP</option>
              </select>
            </label>
            <label>
              Source
              <select
                value={filters.source}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    source: event.target.value as FilterDraft['source'],
                  }))
                }
              >
                <option value="">All sources</option>
                <option value="managed">Managed</option>
                <option value="legacy_default_http">
                  Legacy default HTTP
                </option>
                <option value="legacy_route">Legacy route</option>
                <option value="legacy_mcp">Legacy MCP</option>
              </select>
            </label>
          </div>
          <div className="form-actions">
            <button
              type="submit"
              className="primary-button"
              disabled={isLoading}
            >
              Apply filters
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={isLoading}
              onClick={clearFilters}
            >
              Clear
            </button>
          </div>
        </form>

        {omittedLegacyCount > 0 ? (
          <div className="alert warning" role="status">
            {omittedLegacyCount}{' '}
            {omittedLegacyCount === 1
              ? 'legacy projection was'
              : 'legacy projections were'}{' '}
            omitted because the safe inventory limit was reached.
          </div>
        ) : null}

        {inventoryNotice ? (
          <div className="alert info" role="status" aria-live="polite">
            {inventoryNotice}
          </div>
        ) : null}

        <div
          className="sr-only"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          {announcement}
        </div>

        {loadError ? (
          <div ref={errorRef} tabIndex={-1}>
            <ConnectionsErrorMessage
              error={loadError}
              onReload={() => setReloadVersion((current) => current + 1)}
            />
          </div>
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading connections
          </div>
        ) : null}

        {!isLoading && connections.length === 0 && !loadError ? (
          <div className="empty-state">
            No connections matched these filters.
          </div>
        ) : null}

        {connections.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table connections-table">
                <thead>
                  <tr>
                    <th>Connection</th>
                    <th>State</th>
                    <th>Kind</th>
                    <th>Origin</th>
                    <th>Authentication</th>
                    <th>Capabilities</th>
                    <th>Last test</th>
                    <th>Last refresh</th>
                    <th>Source</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map((connection, index) => (
                    <tr
                      className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      key={connection.id}
                    >
                      <td data-label="Connection">
                        <div className="connection-primary-cell">
                          <Link
                            className="endpoint-template endpoint-detail-link"
                            aria-label={`View ${connection.display_name}, connection ${connection.id}`}
                            to={`/connections/${encodeURIComponent(connection.id)}`}
                          >
                            {connection.display_name}
                          </Link>
                          <code>{connection.id}</code>
                          {!connection.enabled ? (
                            <span className="badge warning">
                              Disabled draft
                            </span>
                          ) : null}
                          {connection.read_only ? (
                            <span className="badge neutral">Read only</span>
                          ) : null}
                        </div>
                      </td>
                      <td data-label="State">
                        <ConnectionStatusBadge connection={connection} />
                      </td>
                      <td data-label="Kind">
                        {formatConnectionKind(connection.kind)}
                      </td>
                      <td data-label="Origin">
                        <code>
                          {connection.sanitized_origin ?? 'Not available'}
                        </code>
                      </td>
                      <td data-label="Authentication">
                        {humanize(connection.authentication)}
                      </td>
                      <td data-label="Capabilities">
                        {(connection.capability_count ?? 0).toLocaleString()}
                      </td>
                      <td data-label="Last test">
                        {formatTimestamp(connection.last_test_at)}
                      </td>
                      <td data-label="Last refresh">
                        {formatTimestamp(connection.last_refresh_at)}
                      </td>
                      <td data-label="Source">
                        {formatConnectionSource(connection.source)}
                      </td>
                      <td data-label="Actions">
                        <div className="connection-actions">
                          <button
                            type="button"
                            className="secondary-button row-action-button"
                            aria-label={`Edit ${connection.display_name}, connection ${connection.id}`}
                            aria-describedby={
                              connection.actions.can_update
                                ? undefined
                                : connectionEditBlockedReasonId(connection.id)
                            }
                            disabled={!connection.actions.can_update}
                            onClick={() =>
                              navigate(
                                `/connections/${encodeURIComponent(connection.id)}/edit`,
                              )
                            }
                          >
                            Edit
                          </button>
                        </div>
                        {!connection.actions.can_update ? (
                          <p
                            id={connectionEditBlockedReasonId(connection.id)}
                            className="rule-hint"
                          >
                            <strong>Edit unavailable:</strong>{' '}
                            {connectionEditBlockedReason(connection)}
                          </p>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination-row">
              {nextCursor !== null ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={isLoadingMore}
                  onClick={() => void loadMore()}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more connections</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function ConnectionStatusBadge({
  connection,
}: {
  connection: ConnectionSummary;
}) {
  const className =
    connection.status.state === 'healthy'
      ? 'success'
      : connection.status.state === 'configured' ||
          connection.status.state === 'unknown'
        ? 'neutral'
        : connection.status.state === 'disabled' ||
            connection.status.state === 'degraded'
          ? 'warning'
          : 'danger';

  return (
    <div className="connection-status">
      <span className={`badge ${className}`}>
        {humanize(connection.status.state)}
      </span>
      <span>{humanize(connection.status.reason)}</span>
    </div>
  );
}

function ConnectionsErrorMessage({
  error,
  onReload,
}: {
  error: ConnectionsError;
  onReload: () => void;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing connections. Open the{' '}
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
          This principal is authenticated but cannot read the connection
          inventory.
        </p>
      </div>
    );
  }

  if (error.kind === 'conflict') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Connection inventory changed</h3>
        <p>
          The list changed while this page was open. Reload it before
          continuing.
        </p>
        <button type="button" className="secondary-button" onClick={onReload}>
          Reload connections
        </button>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Connection inventory unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${
        error.kind === 'bad-request' ? 'warning' : 'error'
      }`}
      role="alert"
    >
      <h3>
        {error.kind === 'bad-request'
          ? 'Invalid connection filters'
          : 'Connection request failed'}
      </h3>
      <p>{error.message}</p>
    </div>
  );
}

function toListFilters(filters: FilterDraft): ConnectionListFilters {
  return {
    limit: 50,
    state: filters.state || undefined,
    kind: filters.kind || undefined,
    source: filters.source || undefined,
  };
}

function toConnectionsError(error: unknown): ConnectionsError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 409 || error.status === 412) {
      return { kind: 'conflict', message: error.message };
    }
    if (error.status === 400) {
      return { kind: 'bad-request', message: error.message };
    }
    if (error.status === 503) {
      return { kind: 'unavailable', message: error.message };
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

function formatConnectionKind(kind: ConnectionKind): string {
  return kind === 'http_api' ? 'HTTP API' : 'MCP streamable HTTP';
}

function formatConnectionSource(source: ConnectionManagementSource): string {
  switch (source) {
    case 'managed':
      return 'Managed';
    case 'legacy_default_http':
      return 'Legacy default HTTP';
    case 'legacy_route':
      return 'Legacy route';
    case 'legacy_mcp':
      return 'Legacy MCP';
  }
}

function connectionEditBlockedReason(connection: ConnectionSummary): string {
  return connection.read_only
    ? 'Legacy connections are read only'
    : 'You do not have permission to update this connection';
}

function connectionEditBlockedReasonId(connectionId: string): string {
  return `connection-edit-blocked-${encodeURIComponent(connectionId)}`;
}

function humanize(value: string): string {
  const text = value.replaceAll('_', ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return 'Never';
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZone: 'UTC',
        timeZoneName: 'short',
      }).format(date);
}
