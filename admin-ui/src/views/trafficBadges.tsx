import type { TrafficEndpoint } from '../lib/traffic';
import { Link } from 'react-router-dom';

import { signalsPathForEndpoint } from '../lib/signals';

type TrafficEndpointBadgeState = Pick<
  TrafficEndpoint,
  | 'coverage_scope'
  | 'covered_by_rule'
  | 'is_new'
  | 'reviewed'
  | 'routing_context_known'
>;

type TrafficEndpointSignalBadgeState = Pick<
  TrafficEndpoint,
  'method' | 'endpoint_template' | 'open_signals'
>;

export function MethodBadge({ method }: { method: string }) {
  return <span className="badge neutral">{method}</span>;
}

export function EndpointLifecycleBadges({
  endpoint,
}: {
  endpoint: TrafficEndpointBadgeState;
}) {
  const coverageScope =
    endpoint.routing_context_known !== true
      ? 'unknown'
      : (endpoint.coverage_scope ??
        (endpoint.covered_by_rule ? 'endpoint' : 'none'));

  if (!endpoint.is_new && coverageScope === 'endpoint') {
    return null;
  }

  return (
    <div className="endpoint-badges" aria-label="Endpoint lifecycle">
      {endpoint.is_new ? <span className="badge success">NEW</span> : null}
      <CoverageBadge scope={coverageScope} />
    </div>
  );
}

export function CoverageBadge({
  scope,
}: {
  scope: TrafficEndpoint['coverage_scope'];
}) {
  if (scope === 'endpoint') {
    return null;
  }
  if (scope === 'principal') {
    return <span className="badge warning">PRINCIPAL-SCOPED</span>;
  }
  if (scope === 'mixed') {
    return <span className="badge warning">MIXED COVERAGE</span>;
  }
  if (scope === 'unknown') {
    return <span className="badge warning">UNKNOWN CONTEXT</span>;
  }
  return <span className="badge warning">UNCOVERED</span>;
}

export function ReviewBadge({ reviewed }: { reviewed: boolean }) {
  return (
    <span className={`badge ${reviewed ? 'success' : 'neutral'}`}>
      {reviewed ? 'Reviewed' : 'Unreviewed'}
    </span>
  );
}

export function EndpointSignalBadge({
  endpoint,
}: {
  endpoint: TrafficEndpointSignalBadgeState;
}) {
  const openSignals = endpoint.open_signals ?? {
    count: 0,
    signal_types: [],
  };

  if (openSignals.count === 0) {
    return null;
  }

  const label = `${openSignals.count} open ${
    openSignals.count === 1 ? 'signal' : 'signals'
  }`;

  return (
    <Link
      className="badge warning signal-badge"
      to={signalsPathForEndpoint(endpoint.method, endpoint.endpoint_template)}
      aria-label={`View ${label} for ${endpoint.method} ${endpoint.endpoint_template}`}
      title={openSignals.signal_types.join(', ')}
    >
      {label}
    </Link>
  );
}
