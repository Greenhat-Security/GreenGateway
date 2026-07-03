import { FormEvent, Fragment, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  AuditEvent,
  AuditFilters,
  emptyAuditFilters,
  fetchAuditEvents,
} from '../lib/audit';

type AuditLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

export function LogExplorer() {
  const [filters, setFilters] = useState<AuditFilters>(() =>
    emptyAuditFilters(),
  );
  const [appliedFilters, setAppliedFilters] = useState<AuditFilters>(() =>
    emptyAuditFilters(),
  );
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [expandedEventIds, setExpandedEventIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [error, setError] = useState<AuditLoadError | null>(null);

  useEffect(() => {
    let isCurrent = true;

    async function loadFirstPage() {
      setIsLoading(true);
      setError(null);
      setExpandedEventIds(new Set());

      try {
        const response = await fetchAuditEvents(appliedFilters);
        if (!isCurrent) {
          return;
        }

        setEvents(response.events);
        setNextCursor(response.next_cursor);
      } catch (loadError) {
        if (!isCurrent) {
          return;
        }

        setEvents([]);
        setNextCursor(null);
        setError(toAuditLoadError(loadError));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadFirstPage();

    return () => {
      isCurrent = false;
    };
  }, [appliedFilters]);

  function updateFilter(name: keyof AuditFilters, value: string) {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppliedFilters({ ...filters });
  }

  function clearFilters() {
    const empty = emptyAuditFilters();
    setFilters(empty);
    setAppliedFilters(empty);
  }

  async function loadMore() {
    if (nextCursor === null || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setError(null);

    try {
      const response = await fetchAuditEvents(appliedFilters, nextCursor);
      setEvents((current) => [...current, ...response.events]);
      setNextCursor(response.next_cursor);
    } catch (loadError) {
      setError(toAuditLoadError(loadError));
    } finally {
      setIsLoadingMore(false);
    }
  }

  function toggleExpanded(eventId: string) {
    setExpandedEventIds((current) => {
      const next = new Set(current);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  }

  return (
    <main className="logs-page">
      <section className="panel logs-panel" aria-labelledby="logs-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Audit</p>
            <h2 id="logs-heading">Log explorer</h2>
          </div>
          <span className="result-count">{events.length} events</span>
        </div>

        <form className="filter-form" onSubmit={applyFilters}>
          <div className="filter-grid">
            <label>
              From
              <input
                type="datetime-local"
                value={filters.from}
                onChange={(event) => updateFilter('from', event.target.value)}
              />
            </label>
            <label>
              To
              <input
                type="datetime-local"
                value={filters.to}
                onChange={(event) => updateFilter('to', event.target.value)}
              />
            </label>
            <label>
              Event type
              <input
                type="text"
                value={filters.eventType}
                placeholder="http.request_observed"
                onChange={(event) =>
                  updateFilter('eventType', event.target.value)
                }
              />
            </label>
            <label>
              Principal
              <input
                type="text"
                value={filters.actor}
                placeholder="user id"
                onChange={(event) => updateFilter('actor', event.target.value)}
              />
            </label>
            <label>
              Path
              <input
                type="text"
                value={filters.path}
                placeholder="/admin"
                onChange={(event) => updateFilter('path', event.target.value)}
              />
            </label>
            <label>
              Status
              <input
                type="number"
                value={filters.status}
                placeholder="200"
                onChange={(event) => updateFilter('status', event.target.value)}
              />
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
              onClick={clearFilters}
              disabled={isLoading}
            >
              Clear
            </button>
          </div>
        </form>

        {error ? <AuditErrorMessage error={error} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading audit events
          </div>
        ) : null}

        {!isLoading && events.length === 0 && !error ? (
          <div className="empty-state">No audit events matched these filters.</div>
        ) : null}

        {events.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>
                      <span className="sr-only">Expand</span>
                    </th>
                    <th>Timestamp</th>
                    <th>Event type</th>
                    <th>Principal</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Request ID</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event, index) => {
                    const isExpanded = expandedEventIds.has(event.event_id);
                    return (
                      <Fragment key={event.event_id}>
                        <tr
                          className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                        >
                          <td>
                            <button
                              type="button"
                              className="expand-button"
                              aria-expanded={isExpanded}
                              aria-label={`${isExpanded ? 'Collapse' : 'Expand'} event ${event.event_id}`}
                              onClick={() => toggleExpanded(event.event_id)}
                            >
                              {isExpanded ? '-' : '+'}
                            </button>
                          </td>
                          <td>{event.timestamp}</td>
                          <td>{event.event_type}</td>
                          <td>{event.actor?.user_id ?? '-'}</td>
                          <td>{displayPayloadField(event, 'path')}</td>
                          <td>{displayPayloadField(event, 'status')}</td>
                          <td>{event.request_id}</td>
                        </tr>
                        {isExpanded ? (
                          <tr className="event-json-row">
                            <td colSpan={7}>
                              <pre data-testid={`event-json-${event.event_id}`}>
                                {JSON.stringify(event, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="pagination-row">
              {nextCursor !== null ? (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={loadMore}
                  disabled={isLoadingMore}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more events</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function AuditErrorMessage({ error }: { error: AuditLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before querying audit logs. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Admin role required</h3>
        <p>This token is valid but does not include the admin role.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Audit store unavailable</h3>
        <p>The SQLite audit store is not configured on this gateway.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid query' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toAuditLoadError(error: unknown): AuditLoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 503) {
      return { kind: 'unavailable', message: error.message };
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

function displayPayloadField(event: AuditEvent, field: string): string {
  const value = event.payload[field];
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value);
  }

  return '-';
}
