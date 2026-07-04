import { CSSProperties, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  TrafficEndpointAuditEnrichment,
  TrafficEndpointDetailResponse,
  TrafficEndpointPrincipal,
  TrafficEndpointRecentEvent,
  TrafficEndpointTimeSeriesPoint,
  TrafficStatusCount,
  fetchTrafficEndpointDetail,
} from '../lib/traffic';
import {
  EndpointSignalBadge,
  EndpointLifecycleBadges,
  MethodBadge,
  ReviewBadge,
} from './trafficBadges';

type TrafficDetailLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

type BarStyle = CSSProperties & {
  '--bar-value': string;
};

export function TrafficEndpointDetail() {
  const [searchParams] = useSearchParams();
  const method = searchParams.get('method')?.trim() ?? '';
  const endpointTemplate =
    searchParams.get('endpoint_template')?.trim() ?? '';
  const [detail, setDetail] =
    useState<TrafficEndpointDetailResponse | null>(null);
  const [principals, setPrincipals] = useState<TrafficEndpointPrincipal[]>([]);
  const [nextPrincipalCursor, setNextPrincipalCursor] = useState<string | null>(
    null,
  );
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMorePrincipals, setIsLoadingMorePrincipals] = useState(false);
  const [loadError, setLoadError] = useState<TrafficDetailLoadError | null>(
    null,
  );

  useEffect(() => {
    let isCurrent = true;

    async function loadDetail() {
      setIsLoading(true);
      setLoadError(null);

      if (method.length === 0 || endpointTemplate.length === 0) {
        setDetail(null);
        setPrincipals([]);
        setNextPrincipalCursor(null);
        setLoadError({
          kind: 'bad-request',
          message:
            'Endpoint detail requires method and endpoint_template query parameters.',
        });
        setIsLoading(false);
        return;
      }

      try {
        const response = await fetchTrafficEndpointDetail({
          method,
          endpointTemplate,
        });
        if (!isCurrent) {
          return;
        }

        setDetail(response);
        setPrincipals(response.principals.principals);
        setNextPrincipalCursor(response.principals.next_cursor);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setDetail(null);
        setPrincipals([]);
        setNextPrincipalCursor(null);
        setLoadError(toTrafficDetailLoadError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadDetail();

    return () => {
      isCurrent = false;
    };
  }, [endpointTemplate, method]);

  async function loadMorePrincipals() {
    if (
      detail === null ||
      nextPrincipalCursor === null ||
      isLoadingMorePrincipals
    ) {
      return;
    }

    setIsLoadingMorePrincipals(true);
    setLoadError(null);

    try {
      const response = await fetchTrafficEndpointDetail({
        method: detail.endpoint.method,
        endpointTemplate: detail.endpoint.endpoint_template,
        principalCursor: nextPrincipalCursor,
      });
      setPrincipals((current) => [
        ...current,
        ...response.principals.principals,
      ]);
      setNextPrincipalCursor(response.principals.next_cursor);
    } catch (error) {
      setLoadError(toTrafficDetailLoadError(error));
    } finally {
      setIsLoadingMorePrincipals(false);
    }
  }

  const heading =
    detail !== null
      ? `${detail.endpoint.method} ${detail.endpoint.endpoint_template}`
      : method.length > 0 && endpointTemplate.length > 0
        ? `${method} ${endpointTemplate}`
        : 'Endpoint detail';

  return (
    <main className="logs-page traffic-page traffic-detail-page">
      <section
        className="panel logs-panel traffic-panel traffic-detail-panel"
        aria-labelledby="traffic-detail-heading"
      >
        <div className="section-heading logs-heading traffic-detail-heading">
          <div>
            <p className="eyebrow">Discovery</p>
            <h2 id="traffic-detail-heading">{heading}</h2>
          </div>
          <Link className="secondary-button" to="/traffic">
            Back to inventory
          </Link>
        </div>

        {loadError ? <TrafficDetailErrorMessage error={loadError} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading endpoint detail
          </div>
        ) : null}

        {!isLoading && detail !== null ? (
          <>
            <EndpointSummary response={detail} />
            <section
              className="traffic-detail-section"
              aria-labelledby="traffic-charts-heading"
            >
              <div className="section-heading">
                <p className="eyebrow">Charts</p>
                <h3 id="traffic-charts-heading">Status and latency</h3>
              </div>
              <div className="traffic-chart-grid">
                <StatusDistribution
                  statusCounts={detail.endpoint.status_counts}
                />
                <LatencyPercentiles detail={detail} />
              </div>
            </section>

            <PrincipalBreakdown
              principals={principals}
              nextCursor={nextPrincipalCursor}
              isLoadingMore={isLoadingMorePrincipals}
              onLoadMore={loadMorePrincipals}
            />

            <AuditActivity audit={detail.audit} />
          </>
        ) : null}
      </section>
    </main>
  );
}

function EndpointSummary({
  response,
}: {
  response: TrafficEndpointDetailResponse;
}) {
  const endpoint = response.endpoint;

  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="traffic-summary-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Endpoint</p>
        <h3 id="traffic-summary-heading">Summary</h3>
      </div>

      <div className="traffic-endpoint-summary">
        <div className="traffic-endpoint-cell">
          <div className="endpoint-title">
            <MethodBadge method={endpoint.method} />
            <span className="endpoint-template">{endpoint.endpoint_template}</span>
          </div>
          <div className="endpoint-badges">
            <EndpointLifecycleBadges endpoint={endpoint} />
            <EndpointSignalBadge endpoint={endpoint} />
            <ReviewBadge reviewed={endpoint.reviewed} />
          </div>
        </div>

        <div className="traffic-summary-grid">
          <StatCard label="Calls" value={formatCount(endpoint.call_count)} />
          <StatCard
            label="Principals"
            value={formatCount(endpoint.distinct_principal_count)}
          />
          <StatCard label="p50" value={formatLatency(endpoint.latency.p50_ms)} />
          <StatCard label="p95" value={formatLatency(endpoint.latency.p95_ms)} />
          <StatCard label="p99" value={formatLatency(endpoint.latency.p99_ms)} />
          <StatCard
            label="Samples"
            value={formatCount(endpoint.latency.sample_count)}
          />
        </div>

        <dl className="traffic-metadata-grid">
          <SpecRow label="First seen" value={endpoint.first_seen} />
          <SpecRow label="Last seen" value={endpoint.last_seen} />
          <SpecRow label="Updated" value={endpoint.updated_at} />
          <SpecRow label="Reviewed by" value={endpoint.reviewed_by ?? '-'} />
        </dl>

        <div className="alert info">
          <h3>Rule coverage</h3>
          <p>
            Current active-rule coverage:{' '}
            <strong>
              {endpoint.covered_by_rule ? 'covered' : 'not covered'}
            </strong>
            .
          </p>
          {/* The backend detail API exposes current coverage only. It does not
              return historical per-endpoint matched-rule records. */}
          <p>
            Historical matched-rule data is not available from this endpoint
            API, so this page does not render matched-rule history.
          </p>
        </div>
      </div>
    </section>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-card traffic-stat-card">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

function SpecRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="spec-row">
      <dt className="k">{label}</dt>
      <dd className="v">{value}</dd>
    </div>
  );
}

function StatusDistribution({
  statusCounts,
}: {
  statusCounts: TrafficStatusCount[];
}) {
  const total = statusCounts.reduce((sum, item) => sum + item.count, 0);

  return (
    <div
      className="traffic-chart-section"
      aria-labelledby="status-distribution-heading"
    >
      <div className="traffic-chart-heading">
        <h4 id="status-distribution-heading">Status distribution</h4>
        <span className="badge neutral">{formatCount(total)} calls</span>
      </div>
      {statusCounts.length === 0 ? (
        <div className="empty-state">No status counts recorded.</div>
      ) : (
        <div
          className="traffic-bar-list"
          role="list"
          aria-label="Status-code distribution"
        >
          {statusCounts.map((item) => {
            const percentage = total === 0 ? 0 : (item.count / total) * 100;
            return (
              <div className="traffic-bar-row" role="listitem" key={item.status}>
                <span className={`badge ${statusBadgeClass(item.status)}`}>
                  {item.status}
                </span>
                <div className="traffic-bar-track" aria-hidden="true">
                  <span
                    className="traffic-bar-fill"
                    style={barStyle(percentage)}
                  />
                </div>
                <span className="traffic-bar-value">
                  {formatCount(item.count)} ({percentage.toFixed(1)}%)
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function LatencyPercentiles({
  detail,
}: {
  detail: TrafficEndpointDetailResponse;
}) {
  const latency = detail.endpoint.latency;
  const rows = [
    ['p50', latency.p50_ms],
    ['p95', latency.p95_ms],
    ['p99', latency.p99_ms],
  ] as const;
  const max = Math.max(latency.p99_ms, latency.p95_ms, latency.p50_ms, 1);

  return (
    <div
      className="traffic-chart-section"
      aria-labelledby="latency-percentiles-heading"
    >
      <div className="traffic-chart-heading">
        <h4 id="latency-percentiles-heading">Latency percentiles</h4>
        <span className="badge neutral">
          {formatCount(latency.sample_count)} samples
        </span>
      </div>
      <div
        className="traffic-bar-list"
        role="list"
        aria-label="Latency percentile bars"
      >
        {rows.map(([label, value]) => (
          <div className="traffic-bar-row" role="listitem" key={label}>
            <span className="traffic-bar-label">{label}</span>
            <div className="traffic-bar-track" aria-hidden="true">
              <span
                className="traffic-bar-fill"
                style={barStyle((value / max) * 100)}
              />
            </div>
            <span className="traffic-bar-value">{formatLatency(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PrincipalBreakdown({
  principals,
  nextCursor,
  isLoadingMore,
  onLoadMore,
}: {
  principals: TrafficEndpointPrincipal[];
  nextCursor: string | null;
  isLoadingMore: boolean;
  onLoadMore: () => Promise<void>;
}) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-breakdown-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Principals</p>
          <h3 id="principal-breakdown-heading">Principal breakdown</h3>
        </div>
        <span className="result-count">{principals.length} principals</span>
      </div>

      {principals.length === 0 ? (
        <div className="empty-state">No principals recorded for this endpoint.</div>
      ) : (
        <>
          <div className="table-scroll">
            <table className="logs-table traffic-detail-table">
              <thead>
                <tr>
                  <th>User ID</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {principals.map((principal, index) => (
                  <tr
                    className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                    key={`${principal.user_id}\n${principal.first_seen}`}
                  >
                    <td>{principal.user_id}</td>
                    <td>
                      <time dateTime={principal.first_seen}>
                        {principal.first_seen}
                      </time>
                    </td>
                    <td>
                      <time dateTime={principal.last_seen}>
                        {principal.last_seen}
                      </time>
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
                onClick={() => {
                  void onLoadMore();
                }}
                disabled={isLoadingMore}
              >
                {isLoadingMore ? 'Loading principals' : 'Load more principals'}
              </button>
            ) : (
              <span>No more principals</span>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function AuditActivity({ audit }: { audit: TrafficEndpointAuditEnrichment }) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="audit-activity-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Audit</p>
        <h3 id="audit-activity-heading">Recent calls and time series</h3>
      </div>

      <div className="alert info">
        <h3>Audit match strategy</h3>
        <p>{audit.match_strategy}</p>
        <p>{audit.match_limitations}</p>
      </div>

      {!audit.available ? (
        <div className="alert warning">
          <h3>Audit enrichment unavailable</h3>
          <p>{audit.omitted_reason ?? 'Audit enrichment was omitted.'}</p>
        </div>
      ) : (
        <div className="traffic-audit-grid">
          <AuditTruncationFlags audit={audit} />
          <TimeSeriesChart points={audit.time_series ?? []} />
          <RecentEventsTable events={audit.recent_events ?? []} />
        </div>
      )}
    </section>
  );
}

function AuditTruncationFlags({
  audit,
}: {
  audit: TrafficEndpointAuditEnrichment;
}) {
  if (!audit.time_series_truncated && !audit.recent_events_scan_truncated) {
    return null;
  }

  return (
    <div className="traffic-warning-list">
      {audit.time_series_truncated ? (
        <div className="alert warning" role="status">
          Time-series scan hit the safety cap; counts may be partial.
        </div>
      ) : null}
      {audit.recent_events_scan_truncated ? (
        <div className="alert warning" role="status">
          Recent-event scan hit the safety cap; newest matches may be incomplete.
        </div>
      ) : null}
    </div>
  );
}

function TimeSeriesChart({
  points,
}: {
  points: TrafficEndpointTimeSeriesPoint[];
}) {
  const max = Math.max(...points.map((point) => point.count), 1);

  return (
    <div
      className="traffic-chart-section"
      aria-labelledby="time-series-heading"
    >
      <div className="traffic-chart-heading">
        <h4 id="time-series-heading">Time-series counts</h4>
        <span className="badge neutral">{points.length} buckets</span>
      </div>
      {points.length === 0 ? (
        <div className="empty-state">No audit events matched this endpoint.</div>
      ) : (
        <div
          className="traffic-bar-list"
          role="list"
          aria-label="Endpoint request time series"
        >
          {points.map((point) => (
            <div
              className="traffic-bar-row stacked"
              role="listitem"
              key={point.bucket_start}
            >
              <span className="traffic-bar-label">{point.bucket_start}</span>
              <div className="traffic-bar-track" aria-hidden="true">
                <span
                  className="traffic-bar-fill"
                  style={barStyle((point.count / max) * 100)}
                />
              </div>
              <span className="traffic-bar-value">
                {formatCount(point.count)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RecentEventsTable({ events }: { events: TrafficEndpointRecentEvent[] }) {
  return (
    <div
      className="traffic-chart-section"
      aria-labelledby="recent-events-heading"
    >
      <div className="traffic-chart-heading">
        <h4 id="recent-events-heading">Recent raw events</h4>
        <span className="badge neutral">{events.length} events</span>
      </div>
      {events.length === 0 ? (
        <div className="empty-state">No recent audit events matched.</div>
      ) : (
        <div className="table-scroll">
          <table className="logs-table traffic-detail-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Method</th>
                <th>Path</th>
                <th>Status</th>
                <th>Actor</th>
                <th>Event ID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={event.id}
                >
                  <td>
                    <time dateTime={event.timestamp}>{event.timestamp}</time>
                  </td>
                  <td>{event.method}</td>
                  <td className="endpoint-template">{event.path}</td>
                  <td>{event.status ?? '-'}</td>
                  <td>{event.actor ?? '-'}</td>
                  <td>{event.event_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function TrafficDetailErrorMessage({
  error,
}: {
  error: TrafficDetailLoadError;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing endpoint traffic. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Traffic detail permission required</h3>
        <p>This token is valid but does not include admin:traffic:read.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Traffic endpoint unavailable</h3>
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

function toTrafficDetailLoadError(error: unknown): TrafficDetailLoadError {
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

function statusBadgeClass(status: number): string {
  if (status >= 200 && status < 300) {
    return 'success';
  }
  if (status >= 400 && status < 500) {
    return 'warning';
  }
  if (status >= 500) {
    return 'danger';
  }

  return 'neutral';
}

function barStyle(value: number): BarStyle {
  return {
    '--bar-value': `${Math.max(0, Math.min(100, value)).toFixed(1)}%`,
  };
}

function formatLatency(value: number): string {
  return `${formatCount(value)} ms`;
}

function formatCount(value: number): string {
  return value.toLocaleString();
}
