import { describe, expect, it } from 'vitest';

import {
  hasUniqueMembers,
  jsonObjectText,
  projectCodeCounts,
  projectRunRefusal,
} from './policyRuns';

describe('policy run helpers', () => {
  it('finds a member named twice in any object, and only there', () => {
    expect(hasUniqueMembers('{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}')).toBe(true);
    expect(hasUniqueMembers('{"a":1,"a":2}')).toBe(false);
    expect(hasUniqueMembers('{"cases":[{"id":"x","kind":"http","id":"y"}]}')).toBe(false);
    expect(hasUniqueMembers('{"a":{},"a":[]}')).toBe(false);
    // Strings that look like members are values, and escapes do not end one.
    expect(hasUniqueMembers('{"a":"a","b":["a","a"],"c":"\\"a\\":1,"}')).toBe(true);
    expect(hasUniqueMembers('{"a\\u0062":1,"ab":2}')).toBe(false);
  });

  it('splices only the text of one JSON object', () => {
    expect(jsonObjectText(' {"a":1} ')).toBe(' {"a":1} ');
    expect(() => jsonObjectText('[1]')).toThrow();
    expect(() => jsonObjectText('{"a":1},"b":{')).toThrow();
    expect(() => jsonObjectText('null')).toThrow();
  });

  it('projects a structured refusal with bounded, well-formed detail only', () => {
    const refusal = projectRunRefusal({
      error: 'policy simulation request is invalid',
      reason: 'policy_simulation_invalid',
      diagnostics: [
        { code: 'missing_field', pointer: '/cases/1/principal', message: 'A required member is missing.' },
        { code: 'Not A Code', pointer: '/cases/0', message: 'dropped' },
        { code: 'invalid_value', pointer: 'no-slash', message: 'dropped' },
      ],
      diagnostics_truncated: true,
      errors: ['first', 7, ''],
    });
    expect(refusal).toEqual({
      reason: 'policy_simulation_invalid',
      diagnostics: [
        { code: 'missing_field', pointer: '/cases/1/principal', message: 'A required member is missing.' },
      ],
      diagnosticsTruncated: true,
      errors: ['first'],
      pointer: null,
      code: null,
    });
    expect(projectRunRefusal({ error: 'no reason' })).toBeNull();
    expect(
      projectRunRefusal({ reason: 'policy_simulation_case_refused', pointer: '/cases/2', code: 'malformed_path' }),
    ).toMatchObject({ pointer: '/cases/2', code: 'malformed_path' });
  });

  it('reads code counts sorted, and refuses anything else', () => {
    expect(projectCodeCounts({ replayable: 8, duplicate_http_decision: 1 })).toEqual([
      { code: 'duplicate_http_decision', count: 1 },
      { code: 'replayable', count: 8 },
    ]);
    expect(projectCodeCounts({ replayable: -1 })).toBeNull();
    expect(projectCodeCounts({ 'Not a code': 1 })).toBeNull();
    expect(projectCodeCounts([])).toBeNull();
  });
});
