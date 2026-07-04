import { FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  TrafficEndpoint,
  TrafficFilters,
  TrafficEndpointSort,
  emptyTrafficFilters,
  fetchTrafficEndpoints,
  updateTrafficEndpointReview,
} from '../lib/traffic';

type TrafficLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

const METHOD_OPTIONS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
];

export function TrafficInventory() {
  const [filters, setFilters] = useState<TrafficFilters>(() =>
    emptyTrafficFilters(),
  );
  const [appliedFilters, setAppliedFilters] = useState<TrafficFilters>(() =>
    emptyTrafficFilters(),
  );
  const [endpoints, setEndpoints] = useState<TrafficEndpoint[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<TrafficLoadError | null>(null);
  const [reviewError, setReviewError] = useState<TrafficLoadError | null>(null);
  const [updatingReviewKey, setUpdatingReviewKey] = useState<string | null>(
    null,
  );
  const [canWriteReviews, setCanWriteReviews] = useState(true);

  useEffect(() => {
    let isCurrent = true;

    async function loadFirstPage() {
      setIsLoading(true);
      setLoadError(null);
      setReviewError(null);

      try {
        const response = await fetchTrafficEndpoints(appliedFilters);
        if (!isCurrent) {
          return;
        }

        setEndpoints(response.endpoints);
        setNextCursor(response.next_cursor);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setEndpoints([]);
        setNextCursor(null);
        setLoadError(toTrafficLoadError(error));
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

  function updateTextFilter(name: 'endpointTemplate' | 'method', value: string) {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function updateSortFilter(value: string) {
    if (isTrafficEndpointSort(value)) {
      setFilters((current) => ({ ...current, sort: value }));
    }
  }

  function toggleFilter(name: 'isNew' | 'uncovered' | 'reviewed') {
    setFilters((current) => ({ ...current, [name]: !current[name] }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppliedFilters({ ...filters });
  }

  function clearFilters() {
    const empty = emptyTrafficFilters();
    setFilters(empty);
    setAppliedFilters(empty);
  }

  async function loadMore() {
    if (nextCursor === null || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);

    try {
      const response = await fetchTrafficEndpoints(appliedFilters, nextCursor);
      setEndpoints((current) => [...current, ...response.endpoints]);
      setNextCursor(response.next_cursor);
    } catch (error) {
      setLoadError(toTrafficLoadError(error));
    } finally {
      setIsLoadingMore(false);
    }
  }

  async function toggleReviewed(endpoint: TrafficEndpoint) {
    if (!canWriteReviews || updatingReviewKey !== null) {
      return;
    }

    const key = endpointKey(endpoint);
    const reviewed = !endpoint.reviewed;
    setUpdatingReviewKey(key);
    setReviewError(null);

    try {
      const response = await updateTrafficEndpointReview({
        method: endpoint.method,
        endpoint_template: endpoint.endpoint_template,
        reviewed,
      });
      setEndpoints((current) =>
        current.map((item) =>
          endpointKey(item) === key
            ? {
                ...item,
                reviewed: response.reviewed,
                reviewed_at: response.reviewed_at,
                reviewed_by: response.reviewed_by,
              }
            : item,
        ),
      );
    } catch (error) {
      const trafficError = toTrafficLoadError(error);
      if (trafficError.kind === 'forbidden') {
        setCanWriteReviews(false);
      }
      setReviewError(trafficError);
    } finally {
      setUpdatingReviewKey(null);
    }
  }

  return (
    <main className="logs-page traffic-page">
      <section className="panel logs-panel traffic-panel" aria-labelledby="traffic-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Discovery</p>
            <h2 id="traffic-heading">Traffic inventory</h2>
          </div>
          <span className="result-count">{endpoints.length} endpoints</span>
        </div>

        <form className="filter-form traffic-filter-form" onSubmit={applyFilters}>
          <div className="filter-grid traffic-filter-grid">
            <label>
              Endpoint search
              <input
                type="text"
                value={filters.endpointTemplate}
                placeholder="/users"
                onChange={(event) =>
                  updateTextFilter('endpointTemplate', event.target.value)
                }
              />
            </label>
            <label>
              Method
              <select
                value={filters.method}
                onChange={(event) =>
                  updateTextFilter('method', event.target.value)
                }
              >
                <option value="">All methods</option>
                {METHOD_OPTIONS.map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Sort by
              <select
                value={filters.sort}
                onChange={(event) => updateSortFilter(event.target.value)}
              >
                <option value="last_seen">Last seen</option>
                <option value="call_count">Volume</option>
                <option value="first_seen">First seen</option>
              </select>
            </label>
          </div>

          <div
            className="filter-toggle-row"
            role="group"
            aria-label="Lifecycle filters"
          >
            <FilterToggle
              label="New only"
              pressed={filters.isNew}
              onClick={() => toggleFilter('isNew')}
            />
            <FilterToggle
              label="Uncovered only"
              pressed={filters.uncovered}
              onClick={() => toggleFilter('uncovered')}
            />
            <FilterToggle
              label="Reviewed"
              pressed={filters.reviewed}
              onClick={() => toggleFilter('reviewed')}
            />
          </div>

          <div className="form-actions">
            <button type="submit" className="primary-button" disabled={isLoading}>
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

        {loadError ? <TrafficErrorMessage error={loadError} /> : null}
        {reviewError ? <ReviewErrorMessage error={reviewError} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading traffic inventory
          </div>
        ) : null}

        {!isLoading && endpoints.length === 0 && !loadError ? (
          <div className="empty-state">
            No traffic endpoints matched these filters.
          </div>
        ) : null}

        {endpoints.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table traffic-table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Volume</th>
                    <th>Error rate</th>
                    <th>Principals</th>
                    <th>Last seen</th>
                    <th>Review</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((endpoint, index) => {
                    const key = endpointKey(endpoint);
                    const isUpdating = updatingReviewKey === key;
                    return (
                      <tr
                        key={key}
                        className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      >
                        <td>
                          <EndpointCell endpoint={endpoint} />
                        </td>
                        <td className="numeric-cell">
                          {formatCount(endpoint.call_count)}
                        </td>
                        <td className="numeric-cell">
                          {formatErrorRate(endpoint.status_counts)}
                        </td>
                        <td className="numeric-cell">
                          {formatCount(endpoint.distinct_principal_count)}
                        </td>
                        <td>
                          <time
                            className="timestamp-cell"
                            dateTime={endpoint.last_seen}
                            title={endpoint.last_seen}
                          >
                            {formatRelativeTimestamp(endpoint.last_seen)}
                          </time>
                        </td>
                        <td>
                          <div className="review-cell">
                            <span
                              className={`badge ${endpoint.reviewed ? 'success' : 'neutral'}`}
                            >
                              {endpoint.reviewed ? 'Reviewed' : 'Unreviewed'}
                            </span>
                            <button
                              type="button"
                              className="secondary-button row-action-button"
                              aria-label={`${endpoint.reviewed ? 'Clear review' : 'Mark reviewed'} ${endpoint.method} ${endpoint.endpoint_template}`}
                              title={
                                canWriteReviews
                                  ? undefined
                                  : 'Requires admin:traffic:write'
                              }
                              disabled={!canWriteReviews || isUpdating}
                              onClick={() => {
                                void toggleReviewed(endpoint);
                              }}
                            >
                              {isUpdating
                                ? 'Saving'
                                : endpoint.reviewed
                                  ? 'Clear review'
                                  : 'Mark reviewed'}
                            </button>
                          </div>
                        </td>
                      </tr>
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
                <span>No more endpoints</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function FilterToggle({
  label,
  pressed,
  onClick,
}: {
  label: string;
  pressed: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`filter-toggle ${pressed ? 'is-active' : ''}`}
      aria-pressed={pressed}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function EndpointCell({ endpoint }: { endpoint: TrafficEndpoint }) {
  return (
    <div className="traffic-endpoint-cell">
      <div className="endpoint-title">
        <span className="badge neutral">{endpoint.method}</span>
        <span className="endpoint-template">{endpoint.endpoint_template}</span>
      </div>
      {endpoint.is_new || !endpoint.covered_by_rule ? (
        <div className="endpoint-badges" aria-label="Endpoint lifecycle">
          {endpoint.is_new ? <span className="badge success">NEW</span> : null}
          {!endpoint.covered_by_rule ? (
            <span className="badge warning">UNCOVERED</span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function TrafficErrorMessage({ error }: { error: TrafficLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing traffic inventory. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Traffic inventory permission required</h3>
        <p>This token is valid but does not include admin:traffic:read.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Traffic inventory unavailable</h3>
        <p>{error.message}</p>
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

function ReviewErrorMessage({ error }: { error: TrafficLoadError }) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Review permission required</h3>
        <p>This token can read traffic inventory but does not include admin:traffic:write.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid review update' : 'Review update failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toTrafficLoadError(error: unknown): TrafficLoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404) {
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

function endpointKey(endpoint: TrafficEndpoint): string {
  return `${endpoint.method}\n${endpoint.endpoint_template}`;
}

function isTrafficEndpointSort(value: string): value is TrafficEndpointSort {
  return (
    value === 'last_seen' || value === 'call_count' || value === 'first_seen'
  );
}

function formatErrorRate(statusCounts: TrafficEndpoint['status_counts']): string {
  const total = statusCounts.reduce((sum, item) => sum + item.count, 0);
  if (total === 0) {
    return '0.0%';
  }

  const nonSuccess = statusCounts
    .filter((item) => item.status < 200 || item.status >= 300)
    .reduce((sum, item) => sum + item.count, 0);

  return `${((nonSuccess / total) * 100).toFixed(1)}%`;
}

function formatRelativeTimestamp(timestamp: string): string {
  const value = new Date(timestamp).valueOf();
  if (Number.isNaN(value)) {
    return timestamp;
  }

  const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (seconds < 60) {
    return 'just now';
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  if (days < 30) {
    return `${days}d ago`;
  }

  const months = Math.floor(days / 30);
  if (months < 12) {
    return `${months}mo ago`;
  }

  return `${Math.floor(months / 12)}y ago`;
}

function formatCount(value: number): string {
  return value.toLocaleString();
}
