import type { TrafficEndpoint } from '../lib/traffic';

type TrafficEndpointBadgeState = Pick<
  TrafficEndpoint,
  'covered_by_rule' | 'is_new' | 'reviewed'
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
