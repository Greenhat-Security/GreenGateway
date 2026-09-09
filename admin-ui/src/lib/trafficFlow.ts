import type { TrafficEndpoint } from './traffic';

export type Coverage = 'covered' | 'uncovered' | 'unknown';
export type Flow = { source: string; destination: string; count: number; coverage: Coverage; endpoint: TrafficEndpoint };
export const UNKNOWN_DESTINATION = 'Destination not recorded';
export function destinationLabel(value: string | null): string {
  if (!value) return UNKNOWN_DESTINATION;
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.origin : UNKNOWN_DESTINATION; }
  catch { return UNKNOWN_DESTINATION; }
}
const count = (value: number) => Number.isSafeInteger(value) && value > 0 ? value : 0;
export const endpointKey = (endpoint: TrafficEndpoint) => `${endpoint.method} ${endpoint.endpoint_template}`;

/** Keep legacy observations visible, without inventing a destination or decision. */
export function trafficFlows(endpoints: TrafficEndpoint[]): Flow[] {
  return endpoints.flatMap(endpoint => {
    let remaining = count(endpoint.call_count);
    const flows: Flow[] = [];
    for (const context of endpoint.routing_contexts ?? []) {
      const amount = Math.min(remaining, count(context.call_count));
      if (!amount) continue;
      remaining -= amount;
      // Principal-scoped rules cover only some callers; do not label them as
      // either endpoint-wide coverage or the absence of a matching rule.
      const coverage: Coverage = context.coverage_scope === 'endpoint' && context.covered_by_rule
        ? 'covered' : context.coverage_scope === 'none' ? 'uncovered' : 'unknown';
      flows.push({ source: endpoint.method, destination: destinationLabel(context.upstream_origin), count: amount, coverage, endpoint });
    }
    if (remaining) flows.push({ source: endpoint.method, destination: UNKNOWN_DESTINATION, count: remaining, coverage: 'unknown', endpoint });
    return flows;
  });
}

export function summarizeDestinations(flows: Flow[]) {
  const groups = new Map<string, { name: string; total: number; covered: number; uncovered: number; unknown: number; endpoints: Map<string, TrafficEndpoint> }>();
  for (const flow of flows) {
    const group = groups.get(flow.destination) ?? { name: flow.destination, total: 0, covered: 0, uncovered: 0, unknown: 0, endpoints: new Map() };
    group.total += flow.count; group[flow.coverage] += flow.count;
    group.endpoints.set(endpointKey(flow.endpoint), flow.endpoint);
    groups.set(group.name, group);
  }
  return [...groups.values()].sort((a, b) => b.total - a.total || a.name.localeCompare(b.name));
}

export function flowDiagram(flows: Flow[]) {
  const destinations = summarizeDestinations(flows);
  const top = new Set(destinations.slice(0, 6).map(d => d.name));
  const sourceTotals = new Map<string, number>();
  const targetTotals = new Map<string, number>();
  const links = new Map<string, { source: string; target: string; count: number }>();
  for (const flow of flows) {
    const target = top.has(flow.destination) ? flow.destination : 'Other destinations';
    sourceTotals.set(flow.source, (sourceTotals.get(flow.source) ?? 0) + flow.count);
    targetTotals.set(target, (targetTotals.get(target) ?? 0) + flow.count);
    const key = JSON.stringify([flow.source, target]);
    const link = links.get(key) ?? { source: flow.source, target, count: 0 };
    link.count += flow.count; links.set(key, link);
  }
  const total = [...sourceTotals.values()].reduce((a, b) => a + b, 0);
  const height = Math.max(380, Math.max(sourceTotals.size, targetTotals.size) * 56);
  const gap = 24;
  const scale = total ? (height - 70 - gap * (Math.max(sourceTotals.size, targetTotals.size, 1) - 1)) / total : 0;
  function layout(totals: Map<string, number>) {
    let y = 40;
    return [...totals].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([name, value]) => {
      const node = { name, value, y, height: value * scale }; y += node.height + gap; return node;
    });
  }
  const sources = layout(sourceTotals), targets = layout(targetTotals);
  const sy = new Map(sources.map(n => [n.name, n.y])), ty = new Map(targets.map(n => [n.name, n.y]));
  const ribbons = [...links.values()].sort((a, b) => sources.findIndex(n => n.name === a.source) - sources.findIndex(n => n.name === b.source)
    || targets.findIndex(n => n.name === a.target) - targets.findIndex(n => n.name === b.target)).map(link => {
    const y1 = sy.get(link.source)!, y2 = ty.get(link.target)!, thickness = link.count * scale;
    sy.set(link.source, y1 + thickness); ty.set(link.target, y2 + thickness);
    return { ...link, path: `M 152 ${y1} C 370 ${y1} 490 ${y2} 688 ${y2} L 688 ${y2 + thickness} C 490 ${y2 + thickness} 370 ${y1 + thickness} 152 ${y1 + thickness} Z` };
  });
  return { sources, targets, ribbons, height, total };
}
