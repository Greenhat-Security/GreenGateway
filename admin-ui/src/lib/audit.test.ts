import { describe, expect, it } from 'vitest';

import { buildAuditQueryParams, emptyAuditFilters } from './audit';

describe('buildAuditQueryParams', () => {
  it('omits empty filters and converts datetime-local fields to RFC3339', () => {
    const params = buildAuditQueryParams({
      ...emptyAuditFilters(),
      from: '2024-06-01T12:34',
      to: '2024-06-02T01:02',
      eventType: '  ',
      actor: ' alice ',
      path: '',
      status: ' 403 ',
    });

    expect(params.has('event_type')).toBe(false);
    expect(params.has('path')).toBe(false);
    expect(params.get('actor')).toBe('alice');
    expect(params.get('status')).toBe('403');

    const from = params.get('from');
    const to = params.get('to');
    expect(from).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(to).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Number.isNaN(Date.parse(from ?? ''))).toBe(false);
    expect(Number.isNaN(Date.parse(to ?? ''))).toBe(false);
  });

  it('threads a keyset pagination cursor as before_id', () => {
    const params = buildAuditQueryParams(emptyAuditFilters(), 42);

    expect(params.get('before_id')).toBe('42');
  });
});
