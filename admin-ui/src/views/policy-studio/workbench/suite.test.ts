import { describe, expect, it } from 'vitest';

import type { SimulationDecision } from '../../../lib/policySimulations';
import {
  caseIndexForPointer,
  casesWithoutExpectation,
  duplicateCase,
  emptySuiteSource,
  expectationFromDecision,
  newCase,
  parseSuite,
  reshapeCase,
  simulationCases,
} from './suite';

describe('workbench suite model', () => {
  it('parses a suite and refuses one the gateway would refuse before reading it', () => {
    const empty = parseSuite(emptySuiteSource());
    expect(empty).toMatchObject({ ok: true, cases: [] });
    expect(parseSuite('{"schema_version":"policy-tests.v1"}')).toMatchObject({ ok: true, cases: [] });
    expect(parseSuite('[]')).toMatchObject({ ok: false });
    expect(parseSuite('{"cases":[1]}')).toMatchObject({ ok: false });
    expect(parseSuite('{"cases":[{"id":"a","id":"b"}]}')).toEqual({
      ok: false,
      message: 'The suite names a member twice in one object, which the gateway refuses.',
    });
  });

  it('asks a simulation the cases without their expectations, and finds the cases a run would refuse', () => {
    const cases = [
      { id: 'a', kind: 'http', expect: { logical: 'allow' } },
      { id: 'b', kind: 'rate' },
      { kind: 'tool' },
    ];
    expect(simulationCases(cases)).toEqual([
      { id: 'a', kind: 'http' },
      { id: 'b', kind: 'rate' },
      { kind: 'tool' },
    ]);
    expect(cases[0].expect).toEqual({ logical: 'allow' });
    expect(casesWithoutExpectation(cases)).toEqual(['b', '#3']);
  });

  it('adds, reshapes and duplicates cases with unique ids and no stale expectation', () => {
    const first = newCase('http', []);
    expect(first).toEqual({
      id: 'case-1',
      kind: 'http',
      request: { method: 'GET', path: '/' },
      principal: { subject: 'synthetic-caller', roles: [], auth_method: 'bearer_token' },
    });
    const expected = { ...first, request: { method: 'POST', path: '/orders' }, expect: { logical: 'deny' } };
    expect(reshapeCase(expected, 'rate')).toEqual({
      id: 'case-1',
      kind: 'rate',
      request: { method: 'POST', path: '/orders' },
      principal: first.principal,
    });
    expect(reshapeCase(expected, 'http')).toEqual(expected);
    const copies = duplicateCase([expected, newCase('tool', [expected])], 0);
    expect(copies.map((entry) => entry.id)).toEqual(['case-1', 'case-3', 'case-2']);
  });

  it('locates a diagnostic in its case', () => {
    expect(caseIndexForPointer('/cases/3/request/path')).toBe(3);
    expect(caseIndexForPointer('/cases/0')).toBe(0);
    expect(caseIndexForPointer('/cases/01')).toBeNull();
    expect(caseIndexForPointer('/candidate/edits/0')).toBeNull();
    expect(caseIndexForPointer('')).toBeNull();
  });

  it('turns only a decided answer into an expectation, in the test vocabulary', () => {
    const shadowed = decision({
      logical: 'deny',
      enforcement: 'shadowed',
      effective_action: 'would_forward',
      reason: 'matched_rule',
      matched: rule({ id: 'watch-orders' }),
    });
    expect(expectationFromDecision('http', shadowed)).toEqual({
      logical: 'deny',
      effect: 'observe',
      reason: 'matched_rule',
      matched: { rule: 'watch-orders' },
    });
    // A rule without an id is named by its position; one whose id was too
    // long to repeat is not asserted at all.
    expect(
      expectationFromDecision('tool', decision({ matched: rule({ id: null, position: 4 }) })),
    ).toMatchObject({ matched: { rule: '4' } });
    expect(
      expectationFromDecision('tool', decision({ matched: rule({ id: null, id_omitted: true }) })),
    ).not.toHaveProperty('matched');
    // Not reported at this trace level is not "nothing matched".
    expect(expectationFromDecision('http', decision({}))).not.toHaveProperty('matched');
    expect(expectationFromDecision('http', decision({ matched: null }))).toMatchObject({
      matched: 'none',
    });
    expect(
      expectationFromDecision(
        'http',
        decision({ logical: 'indeterminate', effective_action: 'unknown', complete: false }),
      ),
    ).toBeNull();
    expect(
      expectationFromDecision('rate', {
        ...decision({}),
        lane: 'rate_selection',
        selected: 'override',
        rate_override: { position: 2, id: null, id_omitted: false, requests_per_second: 5, burst: 10 },
      }),
    ).toEqual({ rate_override: 2 });
    expect(
      expectationFromDecision('rate', { ...decision({}), lane: 'rate_selection', selected: 'indeterminate' }),
    ).toBeNull();
  });
});

function decision(overrides: Partial<SimulationDecision>): SimulationDecision {
  return {
    lane: 'http',
    operation: null,
    logical: 'allow',
    enforcement: 'not_applicable',
    effective_action: 'would_forward',
    reason: 'default_allow',
    complete: true,
    limitation: null,
    stages: null,
    stages_truncated: false,
    selected: null,
    rate_override: null,
    ...overrides,
  };
}

function rule(overrides: Partial<NonNullable<SimulationDecision['matched']>>) {
  return {
    kind: 'rule' as const,
    position: 0,
    id: 'rule',
    id_omitted: false,
    action: 'deny',
    permission: null,
    permission_omitted: false,
    permission_granted: null,
    ...overrides,
  };
}
