import { useEffect, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import type { PolicyRunRefusal } from '../../../lib/policyRuns';
import {
  AUDIT_EVIDENCE_UNAVAILABLE_REASON,
  POLICY_REPLAY_AUDIT_UNAVAILABLE_REASON,
  POLICY_REPLAY_MAX_RECORDS,
  POLICY_REPLAY_NOT_FOUND_REASON,
  POLICY_REPLAY_UNSUPPORTED_IN_CLUSTER_REASON,
  deletePolicyReplay,
  fetchPolicyReplay,
  isReplayPending,
  newReplayIdempotencyKey,
  startPolicyReplay,
  type PolicyReplayCodeCount,
  type PolicyReplayJob,
  type PolicyReplayLane,
  type PolicyReplayResult,
  type PolicyReplayStartRequest,
  type PolicyReplayState,
} from '../../../lib/policyReplays';
import { shortEtag } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { SelectInput } from './CasesEditor';
import {
  AUDIT_READ_PERMISSION,
  CountList,
  POLICY_SIMULATE_PERMISSION,
  RefusalPanel,
  RunBlockers,
  StaleNotice,
  candidateLabel,
  codeLabel,
  isAbort,
  plural,
  runAlert,
  runCandidate,
  type WorkbenchCandidate,
} from './common';
import { effectLabel, logicalLabel } from './Decision';

const PERMISSIONS = `admin:policy:read, ${POLICY_SIMULATE_PERMISSION} and ${AUDIT_READ_PERMISSION}`;
const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;
const MAX_JOBS_SHOWN = 8;
const FAST_POLLS = 10;
const FAST_POLL_MS = 1_000;
const SLOW_POLL_MS = 3_000;

const WINDOW_PRESETS: ReadonlyArray<{ value: string; label: string; ms: number }> = [
  { value: '1h', label: 'The last hour', ms: 60 * 60 * 1000 },
  { value: '24h', label: 'The last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { value: '7d', label: 'The last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { value: 'custom', label: 'A window I set', ms: 0 },
];

const STATE_TEXT: Record<PolicyReplayState, { label: string; badge: string }> = {
  queued: { label: '… Queued', badge: 'neutral' },
  running: { label: '▶ Running', badge: 'neutral' },
  completed: { label: '✓ Completed', badge: 'success' },
  completed_incomplete: { label: '◐ Completed, incomplete', badge: 'warning' },
  failed: { label: '✕ Failed', badge: 'danger' },
  cancelled: { label: '■ Cancelled', badge: 'neutral' },
  expired: { label: '⌛ Expired', badge: 'neutral' },
};

const LIMITATION_TEXT: Record<string, string> = {
  scan_truncated: 'The record bound stopped the scan before the whole window was read.',
  deadline_exceeded: 'The run-time bound stopped the scan before the whole window was read.',
  source_changed:
    'Retention removed records from the window while the job read it, so the result does not cover the snapshot it was pinned to.',
  no_data: 'Nothing in the window could be replayed.',
};

const FAILURE_TEXT: Record<string, string> = {
  source_unavailable: 'The audit log could not be read.',
  compile_failed: 'The candidate policy could not be compiled.',
  evaluator_failed: 'The evaluator broke its own contract; nothing it counted is an answer.',
  result_too_large: 'The result exceeded its size bound.',
  audit_unavailable: 'The audit log did not accept the record of this job completing.',
  internal: 'The gateway failed internally.',
};

type JobEntry = { job: PolicyReplayJob; subject: string; gone: boolean };

// The Impact view: bounded historical replay of retained audit records
// under the live policy or the candidate. Jobs are read-only on the policy
// and the log; the gateway keeps them in memory, and this page lists only
// the ones started here.
export function ImpactPanel({
  candidate,
  candidateProblem,
  canReplay,
  validationBlocker,
  onReloadLive,
}: {
  candidate: WorkbenchCandidate | null;
  candidateProblem: string | null;
  canReplay: boolean;
  validationBlocker: string | null;
  onReloadLive: () => void;
}) {
  const headingId = useId();
  const blockersId = useId();
  const [preset, setPreset] = useState('24h');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [maxRecords, setMaxRecords] = useState('');
  const [jobs, setJobs] = useState<JobEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState<'start' | 'delete' | null>(null);
  const busyRef = useRef(false);
  const [rejected, setRejected] = useState(false);
  const [alert, setAlert] = useState<StudioAlert | null>(null);
  const [baseStale, setBaseStale] = useState(false);
  const [refusal, setRefusal] = useState<PolicyRunRefusal | null>(null);
  // A start whose answer was lost: checking resends exactly this request,
  // under the same idempotency key, which never starts a second job.
  const [unconfirmed, setUnconfirmed] = useState<{ request: PolicyReplayStartRequest; subject: string } | null>(null);
  const [confirmDiscard, setConfirmDiscard] = useState<string | null>(null);
  const [pollRound, setPollRound] = useState(0);
  const [pollProblem, setPollProblem] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Poll the jobs started here while they are queued or running.
  useEffect(() => {
    const pending = jobs.filter((entry) => !entry.gone && isReplayPending(entry.job.state));
    if (pending.length === 0 || rejected) {
      return;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(
      () => {
        void (async () => {
          const answers = await Promise.allSettled(
            pending.map((entry) => fetchPolicyReplay(entry.job.job_id, controller.signal)),
          );
          if (controller.signal.aborted) {
            return;
          }
          const updates = new Map<string, PolicyReplayJob | 'gone'>();
          let unanswered = false;
          let refused = false;
          answers.forEach((answer, index) => {
            const id = pending[index].job.job_id;
            if (answer.status === 'fulfilled') {
              updates.set(id, answer.value);
            } else if (
              answer.reason instanceof AdminApiError &&
              answer.reason.code === POLICY_REPLAY_NOT_FOUND_REASON
            ) {
              updates.set(id, 'gone');
            } else if (
              answer.reason instanceof AdminApiError &&
              (answer.reason.status === 401 || answer.reason.status === 403)
            ) {
              // No longer allowed to read the job: stop asking.
              refused = true;
            } else if (!isAbort(answer.reason)) {
              unanswered = true;
            }
          });
          if (refused) setRejected(true);
          setPollProblem(unanswered || refused);
          setJobs((current) =>
            current.map((entry) => {
              const update = updates.get(entry.job.job_id);
              if (update === undefined) return entry;
              return update === 'gone' ? { ...entry, gone: true } : { ...entry, job: update };
            }),
          );
          setPollRound((round) => round + 1);
        })();
      },
      pollRound < FAST_POLLS ? FAST_POLL_MS : SLOW_POLL_MS,
    );
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [jobs, pollRound, rejected]);

  const window_ = resolveWindow(preset, from, to);
  const maxRecordsValue = parseMaxRecords(maxRecords);

  const blockers: string[] = [];
  if (!canReplay || rejected) blockers.push(`Historical replay needs ${PERMISSIONS}.`);
  if (candidate === null) blockers.push(candidateProblem ?? 'There is no candidate to replay.');
  if (typeof window_ === 'string') blockers.push(window_);
  if (maxRecordsValue === null) {
    blockers.push(`The record bound is a whole number from 1 to ${POLICY_REPLAY_MAX_RECORDS}.`);
  }
  if (validationBlocker !== null) blockers.push(validationBlocker);

  function upsert(job: PolicyReplayJob, subject: string) {
    setJobs((current) => {
      const rest = current.filter((entry) => entry.job.job_id !== job.job_id);
      return [{ job, subject, gone: false }, ...rest].slice(0, MAX_JOBS_SHOWN);
    });
    setSelectedId(job.job_id);
    setPollRound(0);
  }

  function beginBusy(action: 'start' | 'delete'): boolean {
    if (busyRef.current) return false;
    busyRef.current = true;
    setBusy(action);
    return true;
  }

  function endBusy() {
    busyRef.current = false;
    if (mounted.current) setBusy(null);
  }

  async function send(request: PolicyReplayStartRequest, subject: string) {
    if (!beginBusy('start')) return;
    setAlert(null);
    setBaseStale(false);
    setRefusal(null);
    try {
      const answer = await startPolicyReplay(request);
      if (!mounted.current) return;
      setUnconfirmed(null);
      if (answer.kind === 'refused') {
        setRefusal(answer.refusal);
      } else {
        upsert(answer.job, subject);
        if (answer.kind === 'existing') {
          setAlert({
            title: 'Replay already started',
            message: 'The gateway already holds the job this request started; nothing new was started.',
            tone: 'info',
          });
        }
      }
    } catch (error) {
      if (isAbort(error) || !mounted.current) return;
      if (isAmbiguousStart(error)) {
        setUnconfirmed({ request, subject });
        setAlert({
          title: 'Replay start not confirmed',
          message:
            'The gateway did not confirm the start, so a job may or may not be running. Check it: that sends the same request under the same key, which never starts a second job.',
          tone: 'warning',
        });
        return;
      }
      setUnconfirmed(null);
      if (error instanceof AdminApiError && error.status === 403) setRejected(true);
      setBaseStale(error instanceof AdminApiError && error.status === 412);
      setAlert(runAlert(error, 'Replay not started', PERMISSIONS));
    } finally {
      endBusy();
    }
  }

  function start() {
    // A preset window is fixed when the job is asked for, not when the page
    // last rendered.
    const requested = resolveWindow(preset, from, to);
    if (
      candidate === null ||
      typeof requested === 'string' ||
      maxRecordsValue === null ||
      blockers.length > 0 ||
      busy !== null ||
      unconfirmed !== null
    ) {
      return;
    }
    void send(
      {
        baseEtag: candidate.liveEtag,
        candidate: runCandidate(candidate),
        window: requested,
        ...(maxRecordsValue === undefined ? {} : { maxRecords: maxRecordsValue }),
        idempotencyKey: newReplayIdempotencyKey(),
      },
      candidateLabel(candidate),
    );
  }

  async function remove(entry: JobEntry) {
    if (!beginBusy('delete')) return;
    setConfirmDiscard(null);
    setAlert(null);
    try {
      const answer = await deletePolicyReplay(entry.job.job_id);
      if (!mounted.current) return;
      if (answer.kind === 'discarded') {
        setJobs((current) => current.filter((item) => item.job.job_id !== entry.job.job_id));
        setSelectedId(null);
      } else {
        upsert(answer.job, entry.subject);
      }
    } catch (error) {
      if (isAbort(error) || !mounted.current) return;
      if (error instanceof AdminApiError && error.code === POLICY_REPLAY_NOT_FOUND_REASON) {
        setJobs((current) =>
          current.map((item) =>
            item.job.job_id === entry.job.job_id ? { ...item, gone: true } : item,
          ),
        );
      }
      setAlert(runAlert(error, isReplayPending(entry.job.state) ? 'Replay not cancelled' : 'Result not discarded', PERMISSIONS));
    } finally {
      endBusy();
    }
  }

  const selected = jobs.find((entry) => entry.job.job_id === selectedId) ?? jobs[0] ?? null;

  return (
    <section className="workbench-panel" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Historical replay</p>
          <h3 id={headingId}>Impact</h3>
        </div>
      </div>
      <p className="rule-hint">
        Decides a window of the retained audit records again under the live policy or the
        candidate, through the gateway’s own evaluator, as a bounded job. It reads the audit
        log and nothing else: no policy, bucket, tool permit or upstream is touched.
      </p>
      <div className="error-panel alert info" role="note">
        <h3>What a replay can and cannot show</h3>
        <p>
          A replay counts the candidate’s decisions for retained records. This view does not
          yet show the job’s comparison with what the gateway recorded or with the live
          policy, so it shows neither newly allowed nor newly denied traffic. Retained
          records cover only what the audit log kept, and no replay result says a policy is
          safe.
        </p>
      </div>

      <fieldset className="rule-fieldset workbench-options">
        <legend>Replay window</legend>
        <SelectInput
          label="Records from"
          value={preset}
          options={WINDOW_PRESETS.map((option) => ({ value: option.value, label: option.label }))}
          hint="Audit timestamps in [from, to). A window covers at most 31 days."
          onChange={setPreset}
        />
        {preset === 'custom' ? (
          <div className="studio-element-fields">
            <DateTimeInput label="Window start" value={from} onChange={setFrom} />
            <DateTimeInput
              label="Window end"
              value={to}
              hint="Empty means the moment the job is created."
              onChange={setTo}
            />
          </div>
        ) : null}
        <TextInputSmall
          label="Record bound"
          value={maxRecords}
          hint={`The most records the job reads, up to ${POLICY_REPLAY_MAX_RECORDS}. Empty means ${POLICY_REPLAY_MAX_RECORDS}. A scan the bound stops is an incomplete result.`}
          onChange={setMaxRecords}
        />
      </fieldset>

      <div className="form-actions">
        <button
          type="button"
          className="primary-button"
          disabled={blockers.length > 0 || busy !== null || unconfirmed !== null}
          aria-describedby={blockers.length > 0 ? blockersId : undefined}
          onClick={start}
        >
          {busy === 'start' ? 'Starting replay' : 'Start replay'}
        </button>
        {unconfirmed !== null ? (
          <button
            type="button"
            className="secondary-button"
            disabled={busy !== null}
            onClick={() => void send(unconfirmed.request, unconfirmed.subject)}
          >
            Check the unconfirmed replay
          </button>
        ) : null}
      </div>
      <RunBlockers id={blockersId} blockers={blockers} />
      {unconfirmed !== null ? (
        <p className="rule-hint">
          A new replay can start once the unconfirmed one has been checked.
        </p>
      ) : null}

      {alert ? (
        <>
          <StudioAlertPanel alert={alert} />
          {baseStale ? (
            <div className="form-actions">
              <button type="button" className="secondary-button" onClick={onReloadLive}>
                Read the live policy again
              </button>
            </div>
          ) : null}
        </>
      ) : null}
      {refusal ? <RefusalPanel title="Replay refused" refusal={refusal} cases={[]} /> : null}

      {jobs.length > 0 ? (
        <section className="workbench-jobs" aria-label="Replay jobs started here">
          <ol className="workbench-case-list">
            {jobs.map((entry) => {
              const state = STATE_TEXT[entry.job.state];
              const isSelected = selected?.job.job_id === entry.job.job_id;
              return (
                <li key={entry.job.job_id}>
                  <button
                    type="button"
                    className={`workbench-case-button ${isSelected ? 'is-selected' : ''}`}
                    aria-current={isSelected ? 'true' : undefined}
                    onClick={() => setSelectedId(entry.job.job_id)}
                  >
                    <code className="workbench-case-name">{entry.job.job_id}</code>
                    <span className={`badge ${state.badge}`}>{state.label}</span>
                    {entry.gone ? <span className="badge warning">No longer held</span> : null}
                  </button>
                </li>
              );
            })}
          </ol>
          {pollProblem ? (
            <p className="rule-hint" role="status">
              The gateway did not answer the last progress check; the state shown may be out
              of date. Checking continues.
            </p>
          ) : null}
        </section>
      ) : (
        <p className="empty-state">No replay started in this page yet.</p>
      )}

      {selected ? (
        <JobView
          entry={selected}
          busy={busy !== null}
          confirmingDiscard={confirmDiscard === selected.job.job_id}
          onCancel={() => void remove(selected)}
          onAskDiscard={() => setConfirmDiscard(selected.job.job_id)}
          onKeep={() => setConfirmDiscard(null)}
          onDiscard={() => void remove(selected)}
        />
      ) : null}
    </section>
  );
}

// A failure after which a job may or may not exist: no answer, or a server
// error other than the refusals that say no job was started.
function isAmbiguousStart(error: unknown): boolean {
  if (!(error instanceof AdminApiError)) {
    return !isAbort(error);
  }
  return (
    error.status >= 500 &&
    error.code !== AUDIT_EVIDENCE_UNAVAILABLE_REASON &&
    error.code !== POLICY_REPLAY_AUDIT_UNAVAILABLE_REASON &&
    error.code !== POLICY_REPLAY_UNSUPPORTED_IN_CLUSTER_REASON
  );
}

// The window to send, or why there is none. A preset ends when the job is
// created; a set window is local time converted to UTC.
function resolveWindow(
  preset: string,
  from: string,
  to: string,
): { from: string; to?: string } | string {
  const option = WINDOW_PRESETS.find((entry) => entry.value === preset);
  if (option && option.value !== 'custom') {
    return { from: rfc3339(new Date(Date.now() - option.ms)) };
  }
  const start = parseLocal(from);
  if (start === null) {
    return 'Set the window start.';
  }
  const end = to.trim() === '' ? null : parseLocal(to);
  if (to.trim() !== '' && end === null) {
    return 'The window end is not a date and time.';
  }
  const endTime = end?.getTime() ?? Date.now();
  if (start.getTime() >= endTime) {
    return 'The window must begin before it ends.';
  }
  if (end !== null && end.getTime() > Date.now()) {
    return 'The window may not end in the future.';
  }
  if (endTime - start.getTime() > MAX_WINDOW_MS) {
    return 'A window covers at most 31 days.';
  }
  return end === null ? { from: rfc3339(start) } : { from: rfc3339(start), to: rfc3339(end) };
}

function parseLocal(value: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value.trim())) {
    return null;
  }
  const date = new Date(value.trim());
  return Number.isNaN(date.getTime()) ? null : date;
}

function rfc3339(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// Undefined for the gateway's default, null for a bound that is not one.
function parseMaxRecords(text: string): number | undefined | null {
  const value = text.trim();
  if (value === '') return undefined;
  if (!/^[1-9][0-9]{0,5}$/.test(value)) return null;
  const count = Number(value);
  return count <= POLICY_REPLAY_MAX_RECORDS ? count : null;
}

function JobView({
  entry,
  busy,
  confirmingDiscard,
  onCancel,
  onAskDiscard,
  onKeep,
  onDiscard,
}: {
  entry: JobEntry;
  busy: boolean;
  confirmingDiscard: boolean;
  onCancel: () => void;
  onAskDiscard: () => void;
  onKeep: () => void;
  onDiscard: () => void;
}) {
  const headingId = useId();
  const { job } = entry;
  const state = STATE_TEXT[job.state];
  const pending = isReplayPending(job.state);
  return (
    <article className="workbench-results" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Replay job</p>
          <h3 id={headingId}>
            Job <code>{job.job_id}</code>
          </h3>
        </div>
        <span className={`badge ${state.badge}`} role="status">
          {state.label}
        </span>
      </div>
      {entry.gone ? (
        <StaleNotice>
          The gateway no longer holds this job: it expired, was discarded elsewhere, or the
          gateway restarted, which forgets every job. What is shown is the last state read.
        </StaleNotice>
      ) : null}
      {job.base.current === false ? (
        <StaleNotice>
          The live policy changed since this job was pinned. Its result still answers for
          the policies it was pinned to, not for the live policy now.
        </StaleNotice>
      ) : null}
      <p>
        Candidate: {entry.subject}. Pinned to live revision{' '}
        <code title={job.base.etag}>{shortEtag(job.base.etag)}</code>
        {job.candidate.source !== 'active' ? (
          <>
            ; the candidate would be revision{' '}
            <code title={job.candidate.etag}>{shortEtag(job.candidate.etag)}</code>
          </>
        ) : null}
        .
      </p>
      <CountList
        label="Replay scope"
        items={[
          { term: 'Window', value: `${job.window.from} to ${job.window.to ?? 'job creation'}` },
          { term: 'Records the cutoff selected', value: job.selected_records },
          { term: 'Record bound', value: job.max_records },
          {
            term: 'Read so far',
            value: (
              <>
                {job.scanned_records} of {job.selected_records}
                {pending && job.selected_records > 0 ? (
                  <progress
                    className="workbench-progress"
                    max={job.selected_records}
                    value={Math.min(job.scanned_records, job.selected_records)}
                    aria-label="Records read"
                  />
                ) : null}
              </>
            ),
          },
        ]}
      />
      {job.cancel_requested && pending ? (
        <p className="rule-hint">Cancellation requested: the job stops before its next record.</p>
      ) : null}
      {job.state === 'failed' ? (
        <div className="error-panel alert error" role="alert">
          <h3>Replay failed: there is no result</h3>
          <p>
            {FAILURE_TEXT[job.failure ?? ''] ?? 'The job stopped without a result.'}{' '}
            <code>{job.failure}</code>
          </p>
        </div>
      ) : null}
      {job.state === 'cancelled' ? (
        <p className="empty-state">Cancelled. A cancelled job has no result.</p>
      ) : null}
      {job.state === 'expired' ? (
        <p className="empty-state">
          The result expired 15 minutes after the job finished and is gone. Start the replay
          again to see one.
        </p>
      ) : null}
      {job.result ? <ReplayResultView result={job.result} digest={job.result_digest} /> : null}

      <div className="form-actions">
        {pending ? (
          <button
            type="button"
            className="secondary-button"
            disabled={busy || job.cancel_requested || entry.gone}
            onClick={onCancel}
          >
            Cancel replay
          </button>
        ) : confirmingDiscard ? (
          <div className="policy-studio-confirmation" role="group" aria-label="Discard this replay?">
            <p>
              Discarding removes this job and its result from the gateway. Nothing else
              changes; the replay can be started again.
            </p>
            <div className="form-actions">
              <button type="button" className="rule-danger-button" disabled={busy} onClick={onDiscard}>
                Confirm discard
              </button>
              <button type="button" className="secondary-button" onClick={onKeep}>
                Keep it
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            className="secondary-button"
            disabled={busy || entry.gone}
            onClick={onAskDiscard}
          >
            Discard replay
          </button>
        )}
      </div>
    </article>
  );
}

function ReplayResultView({
  result,
  digest,
}: {
  result: PolicyReplayResult;
  digest: string | null;
}) {
  const noData = result.limitations.includes('no_data');
  const records = result.records;
  return (
    <section className="workbench-replay-result" aria-label="Replay result">
      {result.complete ? (
        <p>
          <span className="badge success">✓ Complete</span> Every record the cutoff selected was
          read and classified. Complete describes the scan, not the policy.
        </p>
      ) : (
        <div className="error-panel alert warning" role="note">
          <h3>Incomplete result</h3>
          <p>This result does not cover the whole window and satisfies no gate:</p>
          <ul>
            {result.limitations.map((limitation) => (
              <li key={limitation}>
                <code>{limitation}</code>: {LIMITATION_TEXT[limitation] ?? codeLabel(limitation)}
              </li>
            ))}
          </ul>
        </div>
      )}

      <h4>Records read</h4>
      <CountList
        label="Records by classification"
        items={[
          { term: 'Selected by the cutoff', value: records.selected },
          { term: 'Read', value: records.scanned },
          { term: 'Replayable', value: records.replayable },
          { term: 'Duplicates of a replayed decision', value: records.duplicate },
          { term: 'Not decided by policy', value: records.not_policy_evaluated },
          { term: 'Unsupported', value: records.unsupported },
          { term: 'Malformed', value: records.malformed },
          { term: 'Not a request record', value: records.not_request_record },
          { term: 'Unreadable', value: records.unreadable },
          { term: 'Oversized', value: records.oversized },
        ]}
      />
      {records.by_code.length > 0 ? (
        <details className="workbench-stages">
          <summary>Records by adapter code</summary>
          <CodeCounts label="Records by adapter code" counts={records.by_code} />
        </details>
      ) : null}

      {noData ? (
        <p className="empty-state">
          No decisions: nothing in this window could be replayed. That is not a result of zero
          denials, and it satisfies no gate.
        </p>
      ) : (
        <>
          <LaneView title="HTTP decisions" lane={result.replayed.http} />
          <LaneView title="Tool decisions" lane={result.replayed.tool} />
          <h4>Rate-limit selection</h4>
          <CountList
            label="Rate-limit selection"
            items={[
              { term: 'An override selected', value: result.replayed.rate.override },
              { term: 'No override', value: result.replayed.rate.no_override },
              { term: 'Undecided', value: result.replayed.rate.indeterminate },
              { term: 'Refused', value: result.replayed.rate.refused },
            ]}
          />
          <p className="rule-hint">
            Which override would govern each request, never whether its bucket had capacity.
          </p>
        </>
      )}
      <p className="rule-hint">
        Not replayed: {result.not_replayed.map(codeLabel).join(', ')}.
        {digest ? (
          <>
            {' '}
            Result digest <code title={digest}>{shortEtag(digest)}</code>.
          </>
        ) : null}
      </p>
    </section>
  );
}

function LaneView({ title, lane }: { title: string; lane: PolicyReplayLane }) {
  return (
    <section className="workbench-lane" aria-label={title}>
      <h4>{title}</h4>
      {lane.replayable === 0 ? (
        <p className="rule-hint">No replayable record in this lane.</p>
      ) : (
        <>
          <CountList
            label={`${title}: counts`}
            items={[
              { term: 'Replayable', value: lane.replayable },
              { term: 'Decided', value: lane.decided },
              { term: 'Undecided', value: lane.indeterminate },
              { term: 'Refused', value: lane.refused },
            ]}
          />
          {lane.outcomes.length > 0 ? (
            <div className="table-scroll">
              <table className="logs-table workbench-table">
                <caption className="sr-only">{title} by outcome</caption>
                <thead>
                  <tr>
                    <th scope="col">Decision</th>
                    <th scope="col">Enforcement</th>
                    <th scope="col">Effect</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Records</th>
                  </tr>
                </thead>
                <tbody>
                  {lane.outcomes.map((outcome) => (
                    <tr
                      key={`${outcome.logical}:${outcome.enforcement}:${outcome.effective_action}:${outcome.reason}`}
                    >
                      <td>{logicalLabel(outcome.logical).text}</td>
                      <td>{codeLabel(outcome.enforcement)}</td>
                      <td>{effectLabel(outcome.effective_action).text}</td>
                      <td>
                        <code>{outcome.reason}</code>
                      </td>
                      <td>{outcome.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {lane.limitations.length > 0 ? (
            <CodeCounts label={`${title}: undecided by limitation`} counts={lane.limitations} />
          ) : null}
          {lane.refusals.length > 0 ? (
            <CodeCounts label={`${title}: refused by code`} counts={lane.refusals} />
          ) : null}
          {lane.egress_not_replayed > 0 ? (
            <p className="rule-hint">
              {plural(lane.egress_not_replayed, 'record')} stated an egress destination, which a
              replay does not decide.
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}

function CodeCounts({
  label,
  counts,
}: {
  label: string;
  counts: readonly PolicyReplayCodeCount[];
}) {
  return (
    <ul className="workbench-code-counts" aria-label={label}>
      {counts.map((entry) => (
        <li key={entry.code}>
          <code>{entry.code}</code>: {entry.count}
        </li>
      ))}
    </ul>
  );
}

function DateTimeInput({
  label,
  value,
  hint,
  onChange,
}: {
  label: string;
  value: string;
  hint?: string;
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="rule-input"
        type="datetime-local"
        value={value}
        aria-describedby={hint ? `${id}-hint` : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

function TextInputSmall({
  label,
  value,
  hint,
  onChange,
}: {
  label: string;
  value: string;
  hint: string;
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="rule-input"
        type="text"
        inputMode="numeric"
        value={value}
        placeholder={String(POLICY_REPLAY_MAX_RECORDS)}
        aria-describedby={`${id}-hint`}
        onChange={(event) => onChange(event.target.value)}
      />
      <p className="rule-hint" id={`${id}-hint`}>
        {hint}
      </p>
    </div>
  );
}
