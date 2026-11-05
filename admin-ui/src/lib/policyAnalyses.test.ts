import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { AdminApiError } from './api';
import { clearMemoryToken } from './auth';
import {
  createAnalysisSuppression,
  expireAnalysisSuppression,
  isSuppressionReason,
  projectAnalysisReport,
  projectSuppressionList,
  runPolicyAnalysisReport,
} from './policyAnalyses';

const LIVE_ETAG = '"sha256:live-1"';
const FINGERPRINT = `sha256:${'f'.repeat(64)}`;
const SNAPSHOT = `sha256:${'0'.repeat(64)}`;
const SUPPRESSION_ID = `pas_${'c'.repeat(32)}`;

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

function finding(suppression: unknown = null) {
  return {
    code: 'rule_shadowed',
    fingerprint: FINGERPRINT,
    severity: 'high',
    proof_basis: 'proven',
    element: { section: 'rules', pointer: '/rules/1', position: 1, id: 'deny-admin' },
    rationale: 'an earlier rule decides first',
    remediation: 'move the rule',
    patch: { access_effect: 'narrowing' },
    suppression,
  };
}

function report(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: 'policy-analysis-results.v1',
    analyzed: { source: 'active', etag: LIVE_ETAG },
    resource_snapshot: { digest: SNAPSHOT, complete: true },
    complete: true,
    limitations: [],
    suppressions: { available: true, records: 1 },
    summary: {
      findings: 1,
      by_suppression_state: { suppressed: 1, suppression_expired: 0, suppression_mismatched: 0 },
    },
    findings: [finding({ state: 'suppressed', suppression_id: SUPPRESSION_ID })],
    ...overrides,
  };
}

function record(state = 'active') {
  return {
    suppression_id: SUPPRESSION_ID,
    etag: '"sha256:suppression-r1"',
    revision: 1,
    state,
    fingerprint: FINGERPRINT,
    code: 'rule_shadowed',
    reason: 'kept on purpose',
    created_by: { subject: 'reviewer' },
    created_at: '2026-10-28T10:30:00Z',
    expires_at: '2026-11-27T23:59:59Z',
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('policy analysis client', () => {
  it('pins the analysis to the live ETag and sends a draft as its exact text', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(200, report())),
    );
    vi.stubGlobal('fetch', fetch);
    const source = '{ "schema_version": "1.0.0",\n  "rules": [] }';
    const answer = await runPolicyAnalysisReport({
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'inline', source },
    });
    expect(answer.kind).toBe('result');
    const [input, init] = fetch.mock.calls[0];
    expect(String(input)).toBe('/v1/admin/policy/analyses');
    expect(init?.body).toBe(
      `{"schema_version":"policy-analysis.v1","base_etag":${JSON.stringify(LIVE_ETAG)},` +
        `"candidate":{"source":"inline","policy":${source}},"format":"json"}`,
    );
    if (answer.kind === 'result') {
      expect(answer.report.findings[0].suppression).toEqual({
        state: 'suppressed',
        suppressionId: SUPPRESSION_ID,
        mismatched: [],
      });
      expect(answer.report.counts).toEqual({ suppressed: 1, expired: 0, mismatched: 0 });
      expect(answer.report.resourceSnapshotDigest).toBe(SNAPSHOT);
    }
  });

  it('reads every suppression state and refuses a report it cannot trust', () => {
    const mismatched = projectAnalysisReport(
      report({
        findings: [
          finding({
            state: 'suppression_mismatched',
            suppression_id: SUPPRESSION_ID,
            mismatched: ['policy', 'resource_snapshot'],
          }),
        ],
      }),
    );
    expect(mismatched?.findings[0].suppression?.mismatched).toEqual(['policy', 'resource_snapshot']);
    expect(projectAnalysisReport(report({ suppressions: { available: false, records: 0 } }))?.suppressionsAvailable).toBe(false);
    for (const broken of [
      report({ findings: [finding({ state: 'ignored', suppression_id: SUPPRESSION_ID })] }),
      report({ findings: [finding({ state: 'suppressed', suppression_id: 'everything' })] }),
      report({
        findings: [finding({ state: 'suppression_mismatched', suppression_id: SUPPRESSION_ID, mismatched: ['all'] })],
      }),
      report({ suppressions: undefined }),
      report({ schema_version: 'policy-analysis-results.v2' }),
      report({ findings: [{ ...finding(), fingerprint: 'sha256:short' }] }),
    ]) {
      expect(projectAnalysisReport(broken)).toBeNull();
    }
  });

  it('judges a reason as the gateway does', () => {
    expect(isSuppressionReason('kept on purpose')).toBe(true);
    expect(isSuppressionReason('é'.repeat(256))).toBe(true);
    for (const reason of ['', '   ', 'two\nlines', 'é'.repeat(257)]) {
      expect(isSuppressionReason(reason)).toBe(false);
    }
  });

  it('creates a suppression bound to the live ETag and expires one under its ETag', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? jsonResponse(200, { ...record('withdrawn'), withdrawn_at: '2026-10-29T00:00:00Z' })
          : jsonResponse(201, record()),
      ),
    );
    vi.stubGlobal('fetch', fetch);
    const created = await createAnalysisSuppression({
      liveEtag: LIVE_ETAG,
      fingerprint: FINGERPRINT,
      code: 'rule_shadowed',
      reason: 'kept on purpose',
      expiresAt: '2026-11-27T23:59:59Z',
      resourceSnapshotDigest: SNAPSHOT,
    });
    expect(created.state).toBe('active');
    const [, init] = fetch.mock.calls[0];
    expect(new Headers(init?.headers).get('If-Match')).toBe(LIVE_ETAG);
    expect(JSON.parse(String(init?.body))).toEqual({
      fingerprint: FINGERPRINT,
      code: 'rule_shadowed',
      reason: 'kept on purpose',
      expires_at: '2026-11-27T23:59:59Z',
      resource_snapshot_digest: SNAPSHOT,
    });

    const withdrawn = await expireAnalysisSuppression({
      suppressionId: SUPPRESSION_ID,
      etag: created.etag,
    });
    expect(withdrawn.state).toBe('withdrawn');
    expect(withdrawn.withdrawnAt).toBe('2026-10-29T00:00:00Z');
    const [input, deleteInit] = fetch.mock.calls[1];
    expect(String(input)).toBe(`/v1/admin/policy/analyses/suppressions/${SUPPRESSION_ID}`);
    expect(new Headers(deleteInit?.headers).get('If-Match')).toBe('"sha256:suppression-r1"');
    await expect(
      expireAnalysisSuppression({ suppressionId: '../policy', etag: created.etag }),
    ).rejects.toThrow('Not a suppression identifier.');
  });

  it('surfaces a stale binding as the error it is', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(409, { error: 'stale', reason: 'resource_snapshot_stale' }),
        ),
      ),
    );
    const refused = createAnalysisSuppression({
      liveEtag: LIVE_ETAG,
      fingerprint: FINGERPRINT,
      code: 'rule_shadowed',
      reason: 'kept on purpose',
      expiresAt: '2026-11-27T23:59:59Z',
      resourceSnapshotDigest: SNAPSHOT,
    });
    await expect(refused).rejects.toBeInstanceOf(AdminApiError);
    await expect(refused).rejects.toMatchObject({ status: 409, code: 'resource_snapshot_stale' });
  });

  it('does not report an analysis or a suppression write as a live policy change', async () => {
    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        Promise.resolve(
          String(input).endsWith('/policy/analyses')
            ? jsonResponse(200, report())
            : init?.method === 'DELETE'
              ? jsonResponse(200, { ...record('withdrawn'), withdrawn_at: '2026-10-29T00:00:00Z' })
              : jsonResponse(201, record()),
        ),
      ),
    );
    await runPolicyAnalysisReport({ baseEtag: LIVE_ETAG, candidate: { kind: 'active' } });
    await createAnalysisSuppression({
      liveEtag: LIVE_ETAG,
      fingerprint: FINGERPRINT,
      code: 'rule_shadowed',
      reason: 'kept on purpose',
      expiresAt: '2026-11-27T23:59:59Z',
      resourceSnapshotDigest: SNAPSHOT,
    });
    await expireAnalysisSuppression({ suppressionId: SUPPRESSION_ID, etag: '"sha256:suppression-r1"' });
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });

  it('reads the suppression listing and refuses one it cannot trust', () => {
    const list = projectSuppressionList({
      suppressions: [record(), record('expired')],
      limits: { max_suppressions: 256, max_ttl_seconds: 7776000, max_reason_bytes: 512 },
    });
    expect(list?.suppressions.map((entry) => entry.state)).toEqual(['active', 'expired']);
    expect(
      projectSuppressionList({
        suppressions: [{ ...record(), state: 'ignored' }],
        limits: { max_suppressions: 256, max_ttl_seconds: 7776000 },
      }),
    ).toBeNull();
  });
});
