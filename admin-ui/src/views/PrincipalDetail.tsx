import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  type PrincipalDetailResponse,
  type PrincipalEndpointTouch,
  fetchPrincipalDetail,
} from '../lib/principals';
import { type DiscoverySignal, displaySignalTarget } from '../lib/signals';
import { PrincipalAuthMethodBadge } from './IdentitiesView';
import { MethodBadge } from './trafficBadges';

type PrincipalDetailLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'not-found'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

export function PrincipalDetail() {
  const [searchParams] = useSearchParams();
  const subject = searchParams.get('subject')?.trim() ?? '';
  const issuer = searchParams.get('issuer') ?? '';
  const hasIssuer = searchParams.has('issuer');
  const authMethod = searchParams.get('auth_method')?.trim() ?? '';
  const [detail, setDetail] = useState<PrincipalDetailResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] =
    useState<PrincipalDetailLoadError | null>(null);

  useEffect(() => {
    let isCurrent = true;

    async function loadDetail() {
      setIsLoading(true);
      setLoadError(null);

      if (subject.length === 0 || !hasIssuer || authMethod.length === 0) {
        setDetail(null);
        setLoadError({
          kind: 'bad-request',
          message:
            'Principal detail requires subject, issuer, and auth_method query parameters.',
        });
        setIsLoading(false);
        return;
      }

      try {
        const response = await fetchPrincipalDetail({
          subject,
          issuer,
          authMethod,
        });
        if (!isCurrent) {
          return;
        }

        setDetail(response);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setDetail(null);
        setLoadError(toPrincipalDetailLoadError(error));
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
  }, [authMethod, hasIssuer, issuer, subject]);

  const heading =
    detail !== null
      ? detail.principal.subject
      : subject.length > 0
        ? subject
        : 'Principal detail';

  return (
    <main className="logs-page identities-page traffic-detail-page">
      <section
        className="panel logs-panel identities-panel traffic-detail-panel"
        aria-labelledby="principal-detail-heading"
      >
        <div className="section-heading logs-heading traffic-detail-heading">
          <div>
            <p className="eyebrow">Authentication</p>
            <h2 id="principal-detail-heading">{heading}</h2>
          </div>
          <Link className="secondary-button" to="/identities">
            Back to identities
          </Link>
        </div>

        {loadError ? <PrincipalDetailErrorMessage error={loadError} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading principal detail
          </div>
        ) : null}

        {!isLoading && detail !== null ? (
          <>
            <PrincipalSummary detail={detail} />
            <EndpointsTouched endpoints={detail.endpoints_touched} />
            <RulesHit ruleIds={detail.rules_hit} />
            <SignalsRaised signals={detail.anomaly_history} />
            <ToolsCalled tools={detail.tools_called} />
          </>
        ) : null}
      </section>
    </main>
  );
}

function PrincipalSummary({ detail }: { detail: PrincipalDetailResponse }) {
  const principal = detail.principal;

  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-summary-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Principal</p>
        <h3 id="principal-summary-heading">Summary</h3>
      </div>

      <div className="traffic-endpoint-summary">
        <div className="traffic-endpoint-cell">
          <div className="endpoint-title">
            <span className="endpoint-template">{principal.subject}</span>
            <PrincipalAuthMethodBadge authMethod={principal.auth_method} />
          </div>
          <div className="endpoint-badges">
            <span className="badge neutral">
              {principal.issuer || 'Unknown issuer'}
            </span>
          </div>
        </div>

        <div className="traffic-summary-grid">
          <StatCard
            label="Requests"
            value={formatCount(principal.request_count)}
          />
          <StatCard
            label="Endpoints"
            value={formatCount(detail.endpoints_touched.length)}
          />
          <StatCard
            label="Signals"
            value={formatCount(detail.anomaly_history.length)}
          />
        </div>

        <dl className="traffic-metadata-grid">
          <SpecRow label="Subject" value={principal.subject} />
          <SpecRow
            label="Issuer"
            value={principal.issuer || 'Unknown issuer'}
          />
          <SpecRow label="Auth method" value={principal.auth_method} />
          <SpecRow label="Email" value={principal.email || 'Not set'} />
          <SpecRow label="Org ID" value={principal.org_id || 'Not set'} />
          <SpecRow
            label="Request count"
            value={formatRequestCount(principal.request_count)}
          />
          <SpecRow label="First seen" value={principal.first_seen} />
          <SpecRow label="Last seen" value={principal.last_seen} />
        </dl>
      </div>
    </section>
  );
}

function EndpointsTouched({
  endpoints,
}: {
  endpoints: PrincipalEndpointTouch[];
}) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-endpoints-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Traffic</p>
          <h3 id="principal-endpoints-heading">Endpoints touched</h3>
        </div>
        <span className="result-count">
          {endpoints.length} {endpoints.length === 1 ? 'endpoint' : 'endpoints'}
        </span>
      </div>

      {endpoints.length === 0 ? (
        <div className="empty-state">
          No endpoints recorded for this principal.
        </div>
      ) : (
        <div className="table-scroll">
          <table className="logs-table traffic-detail-table">
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Requests</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={`${endpoint.method}\n${endpoint.path}`}
                >
                  <td>
                    <MethodBadge method={endpoint.method} />
                  </td>
                  <td className="endpoint-template">{endpoint.path}</td>
                  <td>{formatRequestCount(endpoint.request_count)}</td>
                  <td>
                    <time dateTime={endpoint.last_seen}>
                      {endpoint.last_seen}
                    </time>
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

function RulesHit({ ruleIds }: { ruleIds: string[] }) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-rules-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Policy</p>
          <h3 id="principal-rules-heading">Rules hit</h3>
        </div>
        <span className="result-count">
          {ruleIds.length} {ruleIds.length === 1 ? 'rule' : 'rules'}
        </span>
      </div>

      {ruleIds.length === 0 ? (
        <div className="empty-state">
          No rule hits recorded for this principal.
        </div>
      ) : (
        <div className="rule-method-list" aria-label="Rules hit">
          {ruleIds.map((ruleId) => (
            <Link
              className="badge neutral endpoint-detail-link"
              to={ruleEditorPathForRule(ruleId)}
              key={ruleId}
            >
              {ruleId}
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}

function SignalsRaised({ signals }: { signals: DiscoverySignal[] }) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-signals-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Discovery</p>
          <h3 id="principal-signals-heading">Signals raised</h3>
        </div>
        <span className="result-count">
          {signals.length} {signals.length === 1 ? 'signal' : 'signals'}
        </span>
      </div>

      {signals.length === 0 ? (
        <div className="empty-state">No signals raised for this principal.</div>
      ) : (
        <div className="table-scroll">
          <table className="logs-table signals-table">
            <thead>
              <tr>
                <th>Signal</th>
                <th>Target</th>
                <th>State</th>
                <th>Evidence</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((signal, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={signal.id}
                >
                  <td>
                    <div className="signal-primary-cell">
                      <span className="badge neutral">{signal.signal_type}</span>
                      <span>{signal.explanation}</span>
                    </div>
                  </td>
                  <td className="endpoint-template">
                    {displaySignalTarget(signal)}
                  </td>
                  <td>
                    <span
                      className={`badge ${signalStateBadgeClass(signal.state)}`}
                    >
                      {signal.state}
                    </span>
                  </td>
                  <td>
                    <pre
                      className="signal-evidence"
                      data-testid={`principal-signal-evidence-${signal.id}`}
                    >
                      {JSON.stringify(signal.evidence, null, 2)}
                    </pre>
                  </td>
                  <td>
                    <time
                      className="timestamp-cell"
                      dateTime={signal.updated_at}
                      title={signal.updated_at}
                    >
                      {signal.updated_at}
                    </time>
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

function ToolsCalled({ tools }: { tools: unknown[] }) {
  return (
    <section
      className="traffic-detail-section"
      aria-labelledby="principal-tools-heading"
    >
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">MCP</p>
          <h3 id="principal-tools-heading">Tools called</h3>
        </div>
        <span className="result-count">
          {tools.length} {tools.length === 1 ? 'tool call' : 'tool calls'}
        </span>
      </div>

      {tools.length === 0 ? (
        <div className="empty-state">
          No tool calls recorded for this principal yet.
        </div>
      ) : (
        <div className="table-scroll">
          <table className="logs-table traffic-detail-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Tool call</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool, index) => (
                <tr
                  className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                  key={`${index}-${JSON.stringify(tool)}`}
                >
                  <td>{index + 1}</td>
                  <td>
                    <pre className="signal-evidence">
                      {JSON.stringify(tool, null, 2)}
                    </pre>
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

function PrincipalDetailErrorMessage({
  error,
}: {
  error: PrincipalDetailLoadError;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing identities. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Principal detail permission required</h3>
        <p>This token is valid but does not include admin:principals:read.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Principal directory unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'not-found') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Principal not found</h3>
        <p>{error.message}</p>
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
          ? 'Invalid principal query'
          : 'Request failed'}
      </h3>
      <p>{error.message}</p>
    </div>
  );
}

function toPrincipalDetailLoadError(
  error: unknown,
): PrincipalDetailLoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404) {
      if (error.message.includes('PRINCIPAL_SQLITE_PATH')) {
        return { kind: 'unavailable', message: error.message };
      }

      return { kind: 'not-found', message: error.message };
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

function ruleEditorPathForRule(ruleId: string): string {
  const params = new URLSearchParams();
  params.set('rule_id', ruleId);

  return `/policy/rules/editor?${params.toString()}`;
}

function signalStateBadgeClass(state: DiscoverySignal['state']): string {
  switch (state) {
    case 'open':
      return 'warning';
    case 'acknowledged':
      return 'success';
    case 'dismissed':
      return 'neutral';
  }
}

function formatRequestCount(value: number): string {
  return `${formatCount(value)} ${value === 1 ? 'request' : 'requests'}`;
}

function formatCount(value: number): string {
  return value.toLocaleString();
}
