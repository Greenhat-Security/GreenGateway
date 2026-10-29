import { afterEach, describe, expect, it, vi } from 'vitest';

import { subscribeAdminSession, type AdminSessionEvent } from './adminSession';
import { clearMemoryToken } from './auth';
import {
  deletePolicyReplay,
  fetchPolicyReplay,
  newReplayIdempotencyKey,
  projectReplayJob,
  startPolicyReplay,
} from './policyReplays';

const LIVE_ETAG = '"sha256:live-1"';
const JOB_ID = `rpl_${'a'.repeat(32)}`;

afterEach(() => {
  vi.unstubAllGlobals();
  clearMemoryToken();
});

describe('policy replay client', () => {
  it('starts a job with the exact candidate text, its window, bound and key', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(202, replayJob('queued'))),
    );
    vi.stubGlobal('fetch', fetch);
    const source = '{"schema_version":"1.0.0",  "rules":[]}';

    const started = await startPolicyReplay({
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'inline', source },
      window: { from: '2026-10-27T00:00:00Z', to: '2026-10-28T00:00:00Z' },
      maxRecords: 500,
      idempotencyKey: 'studio-key',
    });

    expect(started).toMatchObject({ kind: 'started', job: { job_id: JOB_ID, state: 'queued' } });
    const [input, init] = fetch.mock.calls[0];
    expect(String(input)).toBe('/v1/admin/policy/replays');
    expect(init?.body).toBe(
      `{"schema_version":"policy-replay.v1","base_etag":${JSON.stringify(LIVE_ETAG)},` +
        `"candidate":{"source":"inline","policy":${source}},` +
        '"window":{"from":"2026-10-27T00:00:00Z","to":"2026-10-28T00:00:00Z"},' +
        '"max_records":500,"idempotency_key":"studio-key"}',
    );
  });

  it('names an idempotent retry as the job it already started', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(200, replayJob('running')))));
    await expect(
      startPolicyReplay({
        baseEtag: LIVE_ETAG,
        candidate: { kind: 'active' },
        window: { from: '2026-10-27T00:00:00Z' },
        idempotencyKey: 'studio-key',
      }),
    ).resolves.toMatchObject({ kind: 'existing', job: { state: 'running' } });
  });

  it('reads a finished job only with the result its state promises', () => {
    expect(projectReplayJob(replayJob('completed'))?.result?.complete).toBe(true);
    expect(projectReplayJob(replayJob('completed_incomplete', ['no_data']))?.result).toMatchObject({
      complete: false,
      limitations: ['no_data'],
    });
    // A completed job without its result, or one whose result says it is
    // incomplete, is unreadable rather than an empty answer.
    const withoutResult: Record<string, unknown> = replayJob('completed');
    delete withoutResult.result;
    expect(projectReplayJob(withoutResult)).toBeNull();
    expect(projectReplayJob({ ...replayJob('completed_incomplete', ['no_data']), state: 'completed' })).toBeNull();
    expect(projectReplayJob({ ...replayJob('failed'), failure: undefined })).toBeNull();
    expect(projectReplayJob({ ...replayJob('queued'), job_id: 'rpl_../../x' })).toBeNull();
  });

  it('polls, cancels and discards only well-formed job ids', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? new Response(null, { status: 204 })
          : jsonResponse(200, replayJob('completed')),
      ),
    );
    vi.stubGlobal('fetch', fetch);

    await expect(fetchPolicyReplay(JOB_ID)).resolves.toMatchObject({ state: 'completed' });
    await expect(deletePolicyReplay(JOB_ID)).resolves.toEqual({ kind: 'discarded' });
    await expect(fetchPolicyReplay('rpl_not/an-id')).rejects.toThrow('Invalid policy replay job identifier');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(String(fetch.mock.calls[0][0])).toBe(`/v1/admin/policy/replays/${JOB_ID}`);
    expect(fetch.mock.calls[0][1]?.cache).toBe('no-store');
  });

  it('makes a fresh key for every start, and none of it counts as a policy change', async () => {
    const first = newReplayIdempotencyKey();
    expect(first).toMatch(/^studio-[0-9a-f]{32}$/);
    expect(newReplayIdempotencyKey()).not.toBe(first);

    const events: AdminSessionEvent[] = [];
    const unsubscribe = subscribeAdminSession((event) => events.push(event));
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        Promise.resolve(
          init?.method === 'DELETE'
            ? jsonResponse(202, { ...replayJob('running'), cancel_requested: true })
            : jsonResponse(202, replayJob('queued')),
        ),
      ),
    );
    await startPolicyReplay({
      baseEtag: LIVE_ETAG,
      candidate: { kind: 'active' },
      window: { from: '2026-10-27T00:00:00Z' },
      idempotencyKey: first,
    });
    await expect(deletePolicyReplay(JOB_ID)).resolves.toMatchObject({
      kind: 'cancelling',
      job: { cancel_requested: true },
    });
    unsubscribe();
    expect(events.filter((event) => event.kind === 'policy')).toEqual([]);
  });
});

function replayJob(state: string, limitations: string[] = []): Record<string, unknown> {
  const finished = state === 'completed' || state === 'completed_incomplete';
  return {
    schema_version: 'policy-replay-job.v1',
    job_id: JOB_ID,
    state,
    cancel_requested: false,
    created_at: '2026-10-28T10:00:00Z',
    started_at: state === 'queued' ? null : '2026-10-28T10:00:01Z',
    finished_at: finished ? '2026-10-28T10:00:02Z' : null,
    result_expires_at: finished ? '2026-10-28T10:15:02Z' : null,
    request_digest: 'sha256:request',
    evaluator: { http_semantics_version: 'gg-http-alias-v1' },
    base: { source: 'active', etag: LIVE_ETAG, current: true },
    candidate: { source: 'active', etag: LIVE_ETAG },
    window: { from: '2026-10-27T00:00:00Z', to: '2026-10-28T00:00:00Z' },
    cutoff: { high_water: 90, selected_records: 9 },
    limits: { max_records: 100000, deadline_ms: 60000, page_records: 500 },
    progress: { scanned_records: finished ? 9 : 0, selected_records: 9 },
    ...(state === 'failed' ? { failure: { reason: 'source_unavailable' } } : {}),
    ...(finished
      ? { result_digest: 'sha256:result', result: replayResult(state === 'completed', limitations) }
      : {}),
  };
}

function replayResult(complete: boolean, limitations: string[]) {
  const lane = {
    replayable: 7,
    decided: 7,
    indeterminate: 0,
    refused: 0,
    outcomes: [
      { logical: 'deny', enforcement: 'shadowed', effective_action: 'would_forward', reason: 'matched_rule', count: 3 },
    ],
    limitations: {},
    refusals: {},
    egress_not_replayed: 0,
  };
  return {
    schema_version: 'policy-replay-results.v1',
    mode: 'historical_replay',
    complete,
    limitations,
    source: {
      kind: 'standalone_audit_log',
      window: { from: '2026-10-27T00:00:00Z', to: '2026-10-28T00:00:00Z' },
      high_water: 90,
      max_records: 100000,
    },
    records: {
      selected: 9,
      scanned: 9,
      replayable: 8,
      duplicate: 1,
      not_policy_evaluated: 0,
      unsupported: 0,
      malformed: 0,
      not_request_record: 0,
      unreadable: 0,
      oversized: 0,
      by_code: { duplicate_http_decision: 1, replayable: 8 },
    },
    replayed: {
      total: 8,
      http: lane,
      rate: { no_override: 3, override: 4, indeterminate: 0, refused: 0, limitations: {}, refusals: {} },
      tool: { ...lane, replayable: 1, decided: 1, outcomes: [] },
    },
    not_replayed: ['authentication', 'egress'],
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
