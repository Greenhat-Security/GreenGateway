import type { TrafficEndpoint } from '../lib/traffic';
import { Link } from 'react-router-dom';

import { signalsPathForEndpoint } from '../lib/signals';

type TrafficEndpointBadgeState = Pick<
  TrafficEndpoint,
  'covered_by_rule' | 'is_new' | 'reviewed'
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
  if (!endpoint.is_new && endpoint.covered_by_rule) {
    return null;
  }

  return (
    <div className="endpoint-badges" aria-label="Endpoint lifecycle">
      {endpoint.is_new ? <span className="badge success">NEW</span> : null}
      {!endpoint.covered_by_rule ? (
        <span className="badge warning">UNCOVERED</span>
      ) : null}
    </div>
  );
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
