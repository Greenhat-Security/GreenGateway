import type { TrafficEndpoint } from '../../src/lib/traffic';

/** Synthetic observations only; no customer or deployment data. */
export function observation(method = 'GET', path = '/api/orders/{id}', calls = 120, origin: string | null = 'https://orders.example.test', covered = true): TrafficEndpoint {
  return { method, endpoint_template: path, call_count: calls, distinct_principal_count: 12,
    first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-09-09T10:00:00Z', is_new: false, reviewed: true,
    reviewed_at: null, reviewed_by: null, covered_by_rule: covered, coverage_scope: covered ? 'endpoint' : 'none',
    routing_context_known: true, routing_context_known_since: '2026-09-01T00:00:00Z',
    routing_contexts: [{ route_host: 'gateway.example.test', route_path_prefix: '/api', upstream_origin: origin,
      first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-09-09T10:00:00Z', call_count: calls,
      distinct_principal_count: 12, covered_by_rule: covered, coverage_scope: covered ? 'endpoint' : 'none' }],
    latency: { count: calls, p50_ms: 12, p95_ms: 28, p99_ms: 51 }, status_counts: [{ status: 200, count: calls }] };
}
export const trafficOverviewFixture = [
  observation('GET', '/api/orders/{id}', 8200),
  observation('POST', '/api/orders', 3600),
  observation('MCP', '/mcp/tools/search', 5400, 'https://search.example.test'),
  observation('GET', '/api/search', 2800, 'https://search.example.test', false),
  observation('POST', '/api/events', 1900, 'https://events.example.test', false),
  observation('MCP', '/mcp/tools/reports', 1200, 'https://reports.example.test'),
  observation('PUT', '/api/profile', 840, 'https://identity.example.test'),
  { ...observation('GET', '/legacy/{id}', 420), routing_contexts: [] },
];
