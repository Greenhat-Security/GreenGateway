import { describe, expect, it } from 'vitest';
import { observation } from '../../tests/fixtures/traffic-overview';
import { destinationLabel, flowDiagram, summarizeDestinations, trafficFlows, UNKNOWN_DESTINATION, NO_PROXY_DISPATCH } from './trafficFlow';

describe('traffic flow accounting', () => {
  it('preserves unrecorded historical calls and distinguishes mixed coverage', () => {
    const endpoint = observation(); endpoint.routing_contexts[0].call_count = 80;
    endpoint.routing_contexts[0].coverage_scope = 'mixed';
    const flows = trafficFlows([endpoint]);
    expect(flows.map(f => [f.count, f.coverage])).toEqual([[80, 'unknown'], [40, 'unknown']]);
    expect(flows[1].destination).toBe(UNKNOWN_DESTINATION);
    expect(flowDiagram(flows).ribbons.reduce((sum, r) => sum + r.count, 0)).toBe(120);
  });
  it('does not double count endpoint identities across routing contexts', () => {
    const endpoint = observation(); endpoint.routing_contexts[0].call_count = 60;
    endpoint.routing_contexts.push({ ...endpoint.routing_contexts[0], covered_by_rule: false, coverage_scope: 'none' });
    const [summary] = summarizeDestinations(trafficFlows([endpoint]));
    expect([summary.total, summary.covered, summary.uncovered, summary.endpoints.size]).toEqual([120, 60, 60, 1]);
  });
  it('keeps principal-scoped coverage out of endpoint-wide and no-rule totals', () => {
    const endpoint = observation();
    endpoint.routing_contexts[0].coverage_scope = 'principal';
    endpoint.routing_contexts[0].covered_by_rule = false;
    const [summary] = summarizeDestinations(trafficFlows([endpoint]));
    expect([summary.covered, summary.uncovered, summary.unknown]).toEqual([0, 0, 120]);
  });
  it('keeps unevaluated contexts unknown when routing history is incomplete', () => {
    const endpoint = observation();
    endpoint.routing_context_known = false;
    endpoint.routing_contexts[0].coverage_scope = 'none';
    endpoint.routing_contexts[0].covered_by_rule = false;
    const [summary] = summarizeDestinations(trafficFlows([endpoint]));
    expect([summary.covered, summary.uncovered, summary.unknown]).toEqual([0, 0, 120]);
  });
  it('separates recorded local requests from absent routing history', () => {
    const local = observation('GET', '/health', 30, null);
    const legacy = { ...observation('GET', '/legacy', 20), routing_contexts: [] };
    const groups = summarizeDestinations(trafficFlows([local, legacy]));
    expect(groups.map(g => [g.name, g.total])).toEqual([[NO_PROXY_DISPATCH, 30], [UNKNOWN_DESTINATION, 20]]);
  });
  it('never draws negative, nonfinite, or excess request counts', () => {
    expect(trafficFlows([observation('GET', '/a', -1), observation('GET', '/b', NaN)])).toEqual([]);
    const endpoint = observation(); endpoint.routing_contexts[0].call_count = 999;
    expect(trafficFlows([endpoint]).reduce((sum, f) => sum + f.count, 0)).toBe(120);
  });
  it('groups smaller destinations without losing their counts', () => {
    const flows = trafficFlows(Array.from({ length: 12 }, (_, i) => observation('GET', `/a/${i}`, i + 1, `https://app${i}.example.test`)));
    const diagram = flowDiagram(flows);
    expect(diagram.targets).toHaveLength(7);
    expect(diagram.targets.find(t => t.name === 'Other destinations')?.value).toBe(21);
    expect(diagram.ribbons.reduce((sum, r) => sum + r.count, 0)).toBe(78);
    expect(diagram.ribbons.every(r => !/NaN|Infinity/.test(r.path))).toBe(true);
  });
  it('uses origins and never exposes credentials, query strings, or URL paths', () => {
    expect(destinationLabel('https://fixture:placeholder@example.test/private?key=synthetic')).toBe('https://example.test');
    expect(destinationLabel('javascript:alert(1)')).toBe(UNKNOWN_DESTINATION);
    expect(destinationLabel(null)).toBe(NO_PROXY_DISPATCH);
  });
});
