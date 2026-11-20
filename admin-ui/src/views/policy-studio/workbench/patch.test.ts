import { describe, expect, it } from 'vitest';

import type { AdvisoryEdit } from '../../../lib/policyAnalyses';
import type { JsonObject } from '../model';
import { applyPatch, describeEdit } from './patch';

// The base document of gateway/src/policy_simulation/tests.rs, whose edit
// vectors these mirror for the three operations the analyzer proposes.
function baseDocument(): JsonObject {
  return {
    schema_version: '0.1.0',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: { reader: { permissions: ['orders:read'] } },
    rules: [
      { id: 'public', methods: ['GET'], path: '/public/**', action: 'allow' },
      { id: 'watched', methods: ['GET'], path: '/orders/watched', action: 'shadow' },
      { id: 'search-tool', tool_name: 'search', action: 'allow' },
    ],
    routes: [
      { path_prefix: '/orders', permission: 'orders:read' },
      { path_prefix: '/reports', permission: 'reports:read', enforcement_mode: 'shadow' },
    ],
    rate_limits: [{ path: '/orders/**', requests_per_second: 2.5, burst: 5 }],
    tools: { search: { enabled: true } },
  };
}

function ruleIds(document: JsonObject): string[] {
  return (document.rules as JsonObject[]).map((rule) => String(rule.id ?? ''));
}

describe('advisory patch application', () => {
  it('applies move, delete and set as the gateway’s edits do', () => {
    const base = baseDocument();
    const before = JSON.stringify(base);
    const result = applyPatch(base, [
      { op: 'move', section: 'rules', from: 1, to: 0, expectId: 'watched' },
      { op: 'delete', section: 'rules', position: 2, expectId: 'search-tool' },
      { op: 'delete', section: 'routes', position: 1, expectId: null },
      { op: 'move', section: 'rate_limits', from: 0, to: 0, expectId: null },
      { op: 'set', field: 'enforcement_mode', value: 'shadow' },
      { op: 'set', field: 'default_action', value: 'allow' },
    ]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Each edit sees the result of the ones before it.
    expect(ruleIds(result.document)).toEqual(['watched', 'public']);
    expect(result.document.routes).toEqual([{ path_prefix: '/orders', permission: 'orders:read' }]);
    expect(result.document.enforcement_mode).toBe('shadow');
    expect(result.document.default_action).toBe('allow');
    // The input is never edited in place.
    expect(JSON.stringify(base)).toBe(before);

    // A move takes the element out, then inserts it at `to` in what remains.
    const moved = applyPatch(baseDocument(), [
      { op: 'move', section: 'rules', from: 0, to: 2, expectId: 'public' },
    ]);
    expect(moved.ok && ruleIds(moved.document)).toEqual(['watched', 'search-tool', 'public']);
  });

  it('refuses the whole patch on expect_id mismatch or out-of-range position and leaves the source unchanged', () => {
    const cases: Array<[AdvisoryEdit[], { index: number; member: string; code: string }]> = [
      [
        [
          { op: 'delete', section: 'rules', position: 0, expectId: null },
          { op: 'delete', section: 'rules', position: 0, expectId: 'public' },
        ],
        { index: 1, member: 'expect_id', code: 'edit_target_mismatch' },
      ],
      [
        [{ op: 'move', section: 'routes', from: 0, to: 2, expectId: null }],
        { index: 0, member: 'to', code: 'position_out_of_range' },
      ],
      [
        [{ op: 'move', section: 'routes', from: 2, to: 0, expectId: null }],
        { index: 0, member: 'from', code: 'position_out_of_range' },
      ],
      [
        [{ op: 'delete', section: 'rules', position: 3, expectId: null }],
        { index: 0, member: 'position', code: 'position_out_of_range' },
      ],
      // A 0.x route has no id, so naming one is a mismatch, never ignored.
      [
        [{ op: 'delete', section: 'routes', position: 0, expectId: 'orders' }],
        { index: 0, member: 'expect_id', code: 'edit_target_mismatch' },
      ],
    ];
    for (const [edits, refusal] of cases) {
      const base = baseDocument();
      const before = JSON.stringify(base);
      expect(applyPatch(base, edits)).toEqual({ ok: false, ...refusal });
      expect(JSON.stringify(base)).toBe(before);
    }

    // A section the base omits is an empty one: nothing is at position 0.
    const withoutRates = baseDocument();
    delete withoutRates.rate_limits;
    expect(
      applyPatch(withoutRates, [{ op: 'delete', section: 'rate_limits', position: 0, expectId: null }]),
    ).toEqual({ ok: false, index: 0, member: 'position', code: 'position_out_of_range' });
    expect('rate_limits' in withoutRates).toBe(false);
  });

  it('describes each edit for review', () => {
    expect(
      describeEdit({ op: 'delete', section: 'rules', position: 2, expectId: 'allow-everything' }),
    ).toBe('Delete rule #3 (id allow-everything)');
    expect(describeEdit({ op: 'move', section: 'routes', from: 1, to: 0, expectId: null })).toBe(
      'Move route #2 to position #1',
    );
    expect(
      describeEdit({ op: 'move', section: 'rate_limits', from: 3, to: 1, expectId: 'orders-rate' }),
    ).toBe('Move rate-limit override #4 (id orders-rate) to position #2');
    expect(describeEdit({ op: 'set', field: 'default_action', value: 'deny' })).toBe(
      'Set default_action to deny',
    );
  });
});
