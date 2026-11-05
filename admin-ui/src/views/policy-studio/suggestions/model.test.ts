import { describe, expect, it } from 'vitest';

import { projectSuggestion, type RuleSuggestion } from '../../../lib/suggestions';
import {
  evidenceFacts,
  matchingRulePosition,
  reviewCase,
  routingFacts,
  stateLabels,
  witnessPath,
} from './model';

describe('suggestion presentation', () => {
  it('names one request path a rule pattern matches, or none', () => {
    expect(witnessPath('/billing/{id}')).toBe('/billing/example');
    expect(witnessPath('/files/*/raw')).toBe('/files/example/raw');
    expect(witnessPath('/exports/**')).toBe('/exports');
    expect(witnessPath('/')).toBe('/');
    expect(witnessPath('/encoded/%2F')).toBeNull();
    expect(witnessPath('/dots/../up')).toBeNull();
    expect(witnessPath('relative')).toBeNull();
  });

  it('describes the suggested traffic as a credential-free synthetic case', () => {
    const rule = suggestion().proposed_rule;
    expect(reviewCase(rule)).toEqual({
      case: {
        id: 'suggested-traffic',
        kind: 'http',
        request: { method: 'GET', path: '/billing/example' },
        principal: {
          subject: 'synthetic-suggestion-caller',
          roles: ['support'],
          auth_method: 'bearer_token',
          issuer: 'https://idp.example.test',
        },
      },
      note: 'Simulated as GET /billing/example, one path the pattern matches.',
    });
    const legacy = suggestion({
      proposed_rule: {
        ...suggestionBody().proposed_rule,
        dispatch: { kind: 'legacy', upstream_origin: 'https://api.example.test' },
      },
    }).proposed_rule;
    expect(reviewCase(legacy).case).toMatchObject({
      request: { target: { kind: 'proxy_dispatch', upstream_origin: 'https://api.example.test' } },
    });
    const tool = suggestion({
      proposed_rule: { tool_name: 'reports.export', principal: {}, action: 'shadow' },
    }).proposed_rule;
    expect(reviewCase(tool).case).toMatchObject({
      kind: 'tool',
      tool: { name: 'reports.export', operation: 'invocation' },
    });
    const routed = suggestion({
      proposed_rule: { ...suggestionBody().proposed_rule, dispatch: { kind: 'route', route_id: 'orders' } },
    }).proposed_rule;
    expect(reviewCase(routed).case).toBeNull();
  });

  it('keeps recorded, incomplete and missing evidence apart', () => {
    expect(evidenceFacts(suggestion()).availability).toBe('recorded');
    expect(evidenceFacts(suggestion()).window).toBe(
      '2026-10-25T10:00:00Z to 2026-11-01T10:00:00Z (168 hours)',
    );
    const truncated = evidenceFacts(
      suggestion({ evidence: { ...suggestionBody().evidence, audit_scan_truncated: true, audit_scanned_event_count: 100000 } }),
    );
    expect(truncated.availability).toBe('incomplete');
    expect(truncated.facts).toContain(
      'The audit scan stopped at its row bound after 100000 records, so the window was not read completely.',
    );
    expect(evidenceFacts(suggestion({ evidence: {} })).availability).toBe('not_recorded');
  });

  it('labels stale and superseded suggestions in text', () => {
    expect(stateLabels(suggestion(), null).map((label) => label.text)).toEqual(['Open']);
    expect(
      stateLabels(
        suggestion({ state: 'dismissed', revision: 2, transitioned_by: 'alice', transitioned_at: '2026-11-02T09:00:00Z' }),
        { kind: 'changed', listedRevision: 1, listedState: 'open' },
      ).map((label) => `${label.text}: ${label.detail}`),
    ).toEqual([
      'Superseded: dismissed: Dismissed by alice at 2026-11-02T09:00:00Z. It can no longer be reviewed or accepted.',
      'Stale: changed since listed: Listed at revision 1 (open); the gateway now holds revision 2 (dismissed). This row shows what it holds now.',
    ]);
    expect(stateLabels(suggestion(), { kind: 'rule_live' }).map((label) => label.text)).toEqual([
      'Open',
      'Superseded: rule already live',
    ]);
  });

  it('classifies the routing the proposal is bound to', () => {
    expect(routingFacts(suggestion().proposed_rule).label).toBe('Contextless');
    expect(
      routingFacts(
        suggestion({ proposed_rule: { ...suggestionBody().proposed_rule, dispatch: undefined } })
          .proposed_rule,
      ).label,
    ).toBe('Not classified');
  });

  it('finds a drafted rule by meaning, a shadow proposal held as deny included', () => {
    const signal = suggestion({
      source_signal_id: 'sig-1',
      proposed_rule: { ...suggestionBody().proposed_rule, action: 'deny' },
    });
    const document = {
      rules: [
        { id: 'other', methods: ['POST'], path: '/billing/{id}', principal: {}, action: 'allow' },
        {
          id: 'drafted',
          methods: ['GET'],
          path: '/billing/{id}',
          principal: {
            roles: ['support'],
            issuers: ['https://idp.example.test'],
            auth_methods: ['bearer_token'],
            principal_ids: [],
          },
          action: 'deny',
        },
      ],
    };
    expect(matchingRulePosition(document, signal)).toBe(1);
    expect(matchingRulePosition({ rules: [document.rules[0]] }, signal)).toBeNull();
  });
});

function suggestionBody() {
  return {
    id: 'suggestion-1',
    suggestion_type: 'baseline_allow',
    method: 'GET',
    path_pattern: '/billing/{id}',
    principal_key: 'role:support',
    rationale: 'Role support called GET /billing/{id}.',
    evidence: {
      source: 'audit_sqlite',
      lookback_window_hours: 168,
      from: '2026-10-25T10:00:00Z',
      to: '2026-11-01T10:00:00Z',
      observation_count: 12,
      error_count: 0,
    },
    proposed_rule: {
      methods: ['GET'],
      path: '/billing/{id}',
      dispatch: { kind: 'contextless' } as Record<string, unknown> | undefined,
      principal: {
        roles: ['support'],
        issuers: ['https://idp.example.test'],
        auth_methods: ['bearer_token'],
        principal_ids: [],
      },
      action: 'allow',
    },
    state: 'open',
    created_at: '2026-11-01T10:00:00Z',
    updated_at: '2026-11-01T10:00:00Z',
    transitioned_at: null,
    transitioned_by: null,
    revision: 1,
    source_signal_id: null,
  };
}

function suggestion(overrides: Record<string, unknown> = {}): RuleSuggestion {
  const projected = projectSuggestion({ ...suggestionBody(), ...overrides });
  if (projected === null) {
    throw new Error('test suggestion does not project');
  }
  return projected;
}
