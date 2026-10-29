import { describe, expect, it } from 'vitest';

import type { PolicyDiagnostic } from '../../lib/policyDrafts';
import {
  blocksPublication,
  changedMembers,
  decodePointer,
  diagnosticsInSection,
  diagnosticsWithin,
  egressChanged,
  moveItem,
  nextElementId,
  parseCandidate,
  pointerTo,
  renameMember,
  sectionForPointer,
  shortEtag,
} from './model';

describe('policy studio model', () => {
  it('round-trips RFC 6901 pointers, escapes included', () => {
    const pointer = pointerTo('tools', 'reports/export~v2', 'allowed_roles', 0);
    expect(pointer).toBe('/tools/reports~1export~0v2/allowed_roles/0');
    expect(decodePointer(pointer)).toEqual([
      'tools',
      'reports/export~v2',
      'allowed_roles',
      '0',
    ]);
    expect(decodePointer('')).toEqual([]);
    expect(decodePointer('rules')).toBeNull();
    expect(decodePointer('/rules/~2')).toBeNull();
  });

  it('places each diagnostic in the section that edits it, and the rest in Source', () => {
    expect(sectionForPointer('/default_action')).toBe('overview');
    expect(sectionForPointer('/schema_version')).toBe('overview');
    expect(sectionForPointer('/roles/admin/permissions/0')).toBe('roles');
    expect(sectionForPointer('/rules/3/path')).toBe('rules');
    expect(sectionForPointer('/rate_limits/0/burst')).toBe('rate_limits');
    expect(sectionForPointer('/tools/a~1b')).toBe('tools');
    expect(sectionForPointer('/egress/hosts/0')).toBe('egress');
    expect(sectionForPointer('')).toBe('source');
    expect(sectionForPointer('/unknown_member')).toBe('source');
    expect(sectionForPointer('not a pointer')).toBe('source');

    const diagnostics = [
      diagnostic('/rules/1/path'),
      diagnostic('/rules/10'),
      diagnostic('/routes/0/id'),
    ];
    expect(diagnosticsInSection(diagnostics, 'rules')).toHaveLength(2);
    expect(diagnosticsWithin(diagnostics, '/rules/1')).toEqual([diagnostics[0]]);
  });

  it('blocks publication only for a diagnostic that says so', () => {
    expect(blocksPublication([diagnostic('/rules/0', { publication: false })])).toBe(false);
    expect(blocksPublication([diagnostic('/rules/0')])).toBe(true);
  });

  it('compares sections with the gateway defaults, maps unordered and lists ordered', () => {
    const live = {
      schema_version: '1.0.0',
      default_action: 'deny',
      enforcement_mode: 'enforce',
      roles: { a: { permissions: ['x'] }, b: { permissions: ['y'] } },
      routes: [],
      rules: [{ id: 'r1' }, { id: 'r2' }],
    };

    expect(
      changedMembers(live, {
        ...live,
        roles: { b: { permissions: ['y'] }, a: { permissions: ['x'] } },
        rate_limits: [],
        tools: {},
        egress: {},
      }),
    ).toEqual([]);
    expect(
      changedMembers(live, { ...live, rules: [{ id: 'r2' }, { id: 'r1' }] }),
    ).toEqual(['rules']);
    expect(changedMembers(live, { ...live, default_action: 'allow', extra: 1 })).toEqual([
      'default action',
      'extra',
    ]);
    expect(egressChanged(live, { ...live, egress: { hosts: ['a.example'] } })).toBe(true);
    expect(egressChanged(live, { ...live, egress: {} })).toBe(false);
  });

  it('chooses an element id unused across rules, routes and rate limits', () => {
    const document = {
      rules: [{ id: 'rule-1' }],
      routes: [{ id: 'rule-2' }],
      rate_limits: [{ id: 'rule-3' }],
    };
    expect(nextElementId(document, 'rule')).toBe('rule-4');
  });

  it('renames a map member in place and refuses a rename that would drop an entry', () => {
    const map = { first: 1, second: 2, third: 3 };
    expect(Object.keys(renameMember(map, 'second', 'middle') ?? {})).toEqual([
      'first',
      'middle',
      'third',
    ]);
    expect(renameMember(map, 'second', 'first')).toBeNull();
    expect(renameMember(map, 'second', '')).toBeNull();
  });

  it('moves an element within bounds only', () => {
    expect(moveItem(['a', 'b', 'c'], 2, 0)).toEqual(['c', 'a', 'b']);
    expect(moveItem(['a', 'b'], 1, 2)).toEqual(['a', 'b']);
  });

  it('accepts only a JSON object as a candidate', () => {
    expect(parseCandidate('{"schema_version":"1.0.0"}').ok).toBe(true);
    expect(parseCandidate('[]')).toEqual({
      ok: false,
      message: 'A policy document is a JSON object.',
    });
    expect(parseCandidate('{').ok).toBe(false);
  });

  it('shortens an opaque ETag for display without inventing one', () => {
    expect(shortEtag(`"sha256:${'0123456789ab'.repeat(5)}"`)).toBe('0123456789ab');
    expect(shortEtag('"custom"')).toBe('"custom"');
    expect(shortEtag(null)).toBe('unknown');
  });
});

function diagnostic(
  pointer: string,
  blocks: Partial<PolicyDiagnostic['blocks']> = {},
): PolicyDiagnostic {
  return {
    code: 'test_code',
    severity: 'error',
    pointer,
    message: 'message',
    remediation: 'remediation',
    blocks: {
      simulation: true,
      tests: true,
      publication: true,
      evidence: true,
      ...blocks,
    },
  };
}
