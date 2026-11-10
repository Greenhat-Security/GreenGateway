import { useCallback, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import {
  MAX_SUPPRESSION_DAYS,
  MAX_SUPPRESSION_REASON_BYTES,
  POLICY_ANALYSIS_SUPPRESSION_ENDED_REASON,
  POLICY_ANALYSIS_SUPPRESSION_EXISTS_REASON,
  POLICY_ANALYSIS_SUPPRESSION_EXPIRY_REASON,
  POLICY_ANALYSIS_SUPPRESSION_QUOTA_REASON,
  POLICY_ANALYSIS_SUPPRESSIONS_UNAVAILABLE_REASON,
  RESOURCE_SNAPSHOT_STALE_REASON,
  createAnalysisSuppression,
  expireAnalysisSuppression,
  fetchAnalysisSuppressions,
  isSuppressionReason,
  runPolicyAnalysisReport,
  type AnalysisFinding,
  type AnalysisReport,
  type ObservedReplay,
  type AnalysisSuppressionRecord,
} from '../../../lib/policyAnalyses';
import type { PolicyRunRefusal } from '../../../lib/policyRuns';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import {
  RefusalPanel,
  StaleNotice,
  candidateKey,
  candidateLabel,
  isAbort,
  plural,
  runAlert,
  type WorkbenchCandidate,
} from './common';

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SUPPRESSION_DAYS = 30;

type Analysis = Readonly<{
  key: string;
  replayJobId: string;
  label: string;
  live: boolean;
  liveEtag: string;
  report: AnalysisReport;
}>;

type RunState =
  | { kind: 'idle' }
  | { kind: 'running' }
  | { kind: 'refused'; refusal: PolicyRunRefusal }
  | { kind: 'failed'; alert: StudioAlert };

// A date `days` from today, as the value of a date input (UTC).
function dateIn(days: number): string {
  return new Date(Date.now() + days * DAY_MS).toISOString().slice(0, 10);
}

function severityText(severity: AnalysisFinding['severity']): string {
  return severity === 'high' ? 'High' : severity === 'medium' ? 'Medium' : 'Low';
}

function severityClass(severity: AnalysisFinding['severity']): string {
  return severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'neutral';
}

// Why a suppression write did not happen, in the operator's terms. Nothing
// is retried: an answer that never came is resolved by analyzing again.
function suppressionAlert(error: unknown, title: string): StudioAlert {
  if (!(error instanceof AdminApiError)) {
    return {
      title,
      message:
        'The gateway did not answer, so it is not known whether anything changed. Run the analysis again to see each finding’s current state.',
      tone: 'error',
    };
  }
  switch (error.code) {
    case RESOURCE_SNAPSHOT_STALE_REASON:
      return {
        title,
        message:
          'The resources this analysis was judged against have changed. Run the analysis again and review the finding as it reads now.',
        tone: 'warning',
      };
    case 'policy_etag_mismatch':
      return {
        title,
        message:
          'The live policy changed since this analysis. Run the analysis again and review the finding as it reads now.',
        tone: 'warning',
      };
    case POLICY_ANALYSIS_SUPPRESSION_EXISTS_REASON:
      return {
        title,
        message: 'This finding is already suppressed under the same binding.',
        tone: 'info',
      };
    case POLICY_ANALYSIS_SUPPRESSION_ENDED_REASON:
      return { title, message: 'This suppression has already ended.', tone: 'info' };
    case POLICY_ANALYSIS_SUPPRESSION_QUOTA_REASON:
      return {
        title,
        message:
          'The deployment already holds as many active suppressions as it allows. Expire one that is no longer needed first.',
        tone: 'warning',
      };
    case POLICY_ANALYSIS_SUPPRESSION_EXPIRY_REASON:
      return {
        title,
        message: `A suppression must expire after today and within ${MAX_SUPPRESSION_DAYS} days.`,
        tone: 'warning',
      };
    case POLICY_ANALYSIS_SUPPRESSIONS_UNAVAILABLE_REASON:
      return {
        title,
        message: 'This gateway cannot store suppressions right now. Nothing was changed.',
        tone: 'error',
      };
    default:
      return runAlert(error, title, 'admin:policy:write');
  }
}

function stateText(finding: AnalysisFinding): string | null {
  const suppression = finding.suppression;
  if (suppression === null) {
    return null;
  }
  switch (suppression.state) {
    case 'suppressed':
      return '◌ Suppressed: reviewed, still reported';
    case 'suppression_expired':
      return '↺ Suppression ended: the finding is open again';
    case 'suppression_mismatched':
      return `≠ Suppression no longer matches: the ${suppression.mismatched
        .map((part) => (part === 'policy' ? 'policy' : 'resources'))
        .join(' and ')} changed since it was reviewed`;
  }
}

function ReplayObservations({ replay }: { replay: ObservedReplay }) {
  const heading = useId();
  const projectionName = (name: string) => name === 'as_authored' ? 'As authored' : 'Enforce all shadow';
  return (
    <section className="workbench-findings" aria-labelledby={heading}>
      <h5 id={heading}>Observed replay expansions</h5>
      <p>
        From <time>{replay.from}</time> up to <time>{replay.to}</time>. The replay selected {replay.selected} records,
        scanned {replay.scanned} and found {replay.replayable} replayable. Its record limit was {replay.maxRecords}
        {' '}and its high-water cutoff was {replay.highWater}.
      </p>
      {!replay.complete && <p role="status">Incomplete replay. {replay.limitations.join(', ')}.</p>}
      {replay.findings.length === 0 ? (
        <p>{replay.coverage.some((lane) => lane.compared > 0)
          ? 'No access expansions were observed among the decisions compared.'
          : 'No decisions could be compared in this replay.'}</p>
      ) : (
        <ul>{replay.findings.map((finding) => (
          <li key={`${finding.projection}-${finding.lane}-${finding.code}`}>
            {projectionName(finding.projection)}, {finding.lane === 'http' ? 'HTTP' : 'tool'} — {finding.count}{' '}
            {finding.code === 'newly_allowed' ? 'changed from logical deny to allow' : 'changed from blocked to forwarded'}.
          </li>
        ))}</ul>
      )}
      <table>
        <caption>Replay coverage</caption>
        <thead><tr><th>Projection</th><th>Lane</th><th>Records</th><th>Compared</th><th>Indeterminate</th><th>Unsupported</th></tr></thead>
        <tbody>{replay.coverage.map((row) => (
          <tr key={`${row.projection}-${row.lane}`}><td>{projectionName(row.projection)}</td><td>{row.lane}</td>
            <td>{row.records}</td><td>{row.compared}</td><td>{row.indeterminate}</td><td>{row.unsupported}</td></tr>
        ))}</tbody>
      </table>
      <p className="rule-hint">Outside replay coverage: {replay.notReplayed.join(', ')}.</p>
      <p>Replay result digest <code>{replay.resultDigest}</code></p>
    </section>
  );
}

// The analyzer's findings about the candidate, each with its suppression
// state, and the suppressions a policy writer may create or expire. Nothing
// here changes the policy; a suppression changes only how a finding is
// labeled, and only while it binds the live policy and resources exactly.
export function AnalyzerFindings({
  candidate,
  canAnalyze,
  canReplay,
  canWritePolicy,
}: {
  candidate: WorkbenchCandidate | null;
  canAnalyze: boolean;
  canReplay: boolean;
  canWritePolicy: boolean;
}) {
  const headingId = useId();
  const [run, setRun] = useState<RunState>({ kind: 'idle' });
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [replayInput, setReplayInput] = useState('');
  const replayJobId = canReplay ? replayInput.trim() : '';
  const [records, setRecords] = useState<ReadonlyMap<string, AnalysisSuppressionRecord>>(
    new Map(),
  );
  const [writeAlert, setWriteAlert] = useState<StudioAlert | null>(null);
  const [writing, setWriting] = useState(false);
  const [suppressing, setSuppressing] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  const analyze = useCallback(async () => {
    if (candidate === null) return;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    const key = candidateKey(candidate);
    setRun({ kind: 'running' });
    setWriteAlert(null);
    try {
      const answer = await runPolicyAnalysisReport({
        baseEtag: candidate.liveEtag,
        ...(replayJobId ? { replayJobId } : {}),
        candidate:
          candidate.kind === 'live'
            ? { kind: 'active' }
            : { kind: 'inline', source: candidate.source },
        signal: abort.signal,
      });
      if (abort.signal.aborted) return;
      if (answer.kind === 'refused') {
        setRun({ kind: 'refused', refusal: answer.refusal });
        return;
      }
      // The reasons and expiries live in the listing; a listing that cannot
      // be read leaves the states the report gave, which stand on their own.
      let listed = new Map<string, AnalysisSuppressionRecord>();
      try {
        const list = await fetchAnalysisSuppressions(abort.signal);
        listed = new Map(list.suppressions.map((record) => [record.suppressionId, record]));
      } catch (error) {
        if (isAbort(error) || abort.signal.aborted) return;
      }
      setRecords(listed);
      setAnalysis({
        key,
        replayJobId,
        label: candidateLabel(candidate),
        live: candidate.kind === 'live',
        liveEtag: candidate.liveEtag,
        report: answer.report,
      });
      setSuppressing(null);
      setRun({ kind: 'idle' });
    } catch (error) {
      if (isAbort(error) || abort.signal.aborted) return;
      setRun({
        kind: 'failed',
        alert: runAlert(error, 'Analysis unavailable', 'admin:policy:read and admin:policy:analyze'),
      });
    }
  }, [candidate, replayJobId]);

  const write = useCallback(
    async (action: () => Promise<unknown>, title: string) => {
      setWriting(true);
      setWriteAlert(null);
      try {
        await action();
        setWriting(false);
        await analyze();
      } catch (error) {
        setWriting(false);
        setWriteAlert(suppressionAlert(error, title));
      }
    },
    [analyze],
  );

  if (!canAnalyze) {
    return (
      <section className="workbench-findings" aria-labelledby={headingId}>
        <h4 id={headingId}>Analyzer findings</h4>
        <p className="rule-hint">
          Running the analyzer needs admin:policy:read and admin:policy:analyze, which this
          session does not hold.
        </p>
      </section>
    );
  }

  const stale = analysis !== null && candidate !== null &&
    (analysis.key !== candidateKey(candidate) || analysis.replayJobId !== replayJobId);
  const report = analysis?.report ?? null;
  const canSuppress =
    canWritePolicy &&
    analysis !== null &&
    analysis.live &&
    !stale &&
    report !== null &&
    report.resourceSnapshotComplete &&
    report.resourceSnapshotDigest !== null;

  return (
    <section className="workbench-findings" aria-labelledby={headingId}>
      <h4 id={headingId}>Analyzer findings</h4>
      <p className="rule-hint">
        The conservative analyzer reports entries it can prove are shadowed, unreachable or
        overbroad, each with how it was established. A finding a reviewer has suppressed is
        still listed. An empty list means the analyzer proved none of these problems, not that
        the policy has none.
      </p>
      {canReplay && (
        <label>
          Completed replay ID (optional)
          <input value={replayInput} maxLength={64} onChange={(event) => setReplayInput(event.target.value)} />
        </label>
      )}
      <button
        type="button"
        className="secondary-button"
        disabled={candidate === null || run.kind === 'running' || writing}
        onClick={() => void analyze()}
      >
        {analysis === null ? 'Run analysis' : 'Run analysis again'}
      </button>
      <p className="policy-studio-validation-status" role="status" aria-live="polite">
        {run.kind === 'running'
          ? 'Asking the gateway to analyze the candidate.'
          : report === null
            ? ''
            : `${plural(report.findings.length, 'finding')}: ${report.counts.suppressed} suppressed, ${report.counts.expired} with an ended suppression, ${report.counts.mismatched} with a suppression that no longer matches.`}
      </p>
      {run.kind === 'failed' ? <StudioAlertPanel alert={run.alert} /> : null}
      {run.kind === 'refused' ? (
        <RefusalPanel title="Analysis refused" refusal={run.refusal} cases={[]} />
      ) : null}
      {writeAlert !== null ? <StudioAlertPanel alert={writeAlert} /> : null}
      {analysis !== null && report !== null ? (
        <>
          <p className="rule-hint">Analyzed: {analysis.label}.</p>
          {stale ? (
            <StaleNotice>
              The candidate, live revision or replay selection changed after this analysis. Run it again before
              acting on it.
            </StaleNotice>
          ) : null}
          {canReplay && report.observedReplay !== null && <ReplayObservations replay={report.observedReplay} />}
          {!report.complete ? (
            <p className="rule-hint">
              The analysis stopped at a bound ({report.limitations.join(', ')}). It says nothing
              about the elements it did not reach.
            </p>
          ) : null}
          {!report.suppressionsAvailable ? (
            <p className="rule-hint">
              The gateway could not read its suppressions, so none is applied: every finding
              below reads as open, whatever was suppressed.
            </p>
          ) : null}
          {!analysis.live && canWritePolicy ? (
            <p className="rule-hint">
              Suppressions are bound to the live policy. Analyze the live policy to suppress a
              finding; a suppression of the live policy reads as no longer matching here.
            </p>
          ) : null}
          {analysis.live && canWritePolicy && !report.resourceSnapshotComplete ? (
            <p className="rule-hint">
              Some resources could not be read, so no finding can be suppressed against them.
            </p>
          ) : null}
          {report.findings.length === 0 ? (
            <p className="empty-state">The analyzer proved no findings for this candidate.</p>
          ) : (
            <ol className="policy-studio-diagnostic-list">
              {report.findings.map((finding) => (
                <FindingItem
                  key={`${finding.fingerprint}:${finding.code}`}
                  finding={finding}
                  record={
                    finding.suppression === null
                      ? null
                      : (records.get(finding.suppression.suppressionId) ?? null)
                  }
                  canSuppress={canSuppress && finding.suppression?.state !== 'suppressed'}
                  canExpire={canWritePolicy && !writing}
                  suppressing={suppressing === finding.fingerprint}
                  writing={writing}
                  onStartSuppress={() => setSuppressing(finding.fingerprint)}
                  onCancelSuppress={() => setSuppressing(null)}
                  onSuppress={(reason, expiresOn) =>
                    void write(
                      () =>
                        createAnalysisSuppression({
                          liveEtag: analysis.liveEtag,
                          fingerprint: finding.fingerprint,
                          code: finding.code,
                          reason,
                          expiresAt: `${expiresOn}T23:59:59Z`,
                          resourceSnapshotDigest: report.resourceSnapshotDigest ?? '',
                        }),
                      'Suppression not saved',
                    )
                  }
                  onExpire={(record) =>
                    void write(
                      () =>
                        expireAnalysisSuppression({
                          suppressionId: record.suppressionId,
                          etag: record.etag,
                        }),
                      'Suppression not expired',
                    )
                  }
                />
              ))}
            </ol>
          )}
        </>
      ) : null}
    </section>
  );
}

function FindingItem({
  finding,
  record,
  canSuppress,
  canExpire,
  suppressing,
  writing,
  onStartSuppress,
  onCancelSuppress,
  onSuppress,
  onExpire,
}: {
  finding: AnalysisFinding;
  record: AnalysisSuppressionRecord | null;
  canSuppress: boolean;
  canExpire: boolean;
  suppressing: boolean;
  writing: boolean;
  onStartSuppress: () => void;
  onCancelSuppress: () => void;
  onSuppress: (reason: string, expiresOn: string) => void;
  onExpire: (record: AnalysisSuppressionRecord) => void;
}) {
  const where = `${finding.code} at ${finding.pointer || 'the whole document'}`;
  const state = stateText(finding);
  const suppressed = finding.suppression?.state === 'suppressed';
  return (
    <li className={suppressed ? 'warning' : 'risk'}>
      <div className="policy-studio-diagnostic-head">
        <span className={`badge ${severityClass(finding.severity)}`}>
          {severityText(finding.severity)}
        </span>
        <code>{finding.code}</code>
        <span className="badge neutral">{finding.proofBasis}</span>
      </div>
      <p>{finding.rationale}</p>
      <p>
        <strong>Remediation:</strong> {finding.remediation}
        {finding.patchEffect !== null
          ? ` An advisory change is available (access effect: ${finding.patchEffect}).`
          : ''}
      </p>
      <p className="rule-hint">
        Found at <code>{finding.pointer || '(whole document)'}</code>
        {finding.elementId !== null ? (
          <>
            {' '}in <code>{finding.elementId}</code>
          </>
        ) : null}
        .
      </p>
      {state !== null ? (
        <p>
          <span className={`badge ${suppressed ? 'neutral' : 'warning'}`}>{state}</span>
          {record !== null ? (
            <>
              {' '}
              {record.state === 'active'
                ? `Until ${record.expiresAt}`
                : record.state === 'withdrawn'
                  ? `Expired early at ${record.withdrawnAt ?? record.expiresAt}`
                  : `Expired at ${record.expiresAt}`}
              , by <code>{record.createdBy}</code>: {record.reason}
            </>
          ) : null}
        </p>
      ) : null}
      {suppressed && record !== null && record.state === 'active' && canExpire ? (
        <button
          type="button"
          className="secondary-button"
          aria-label={`Expire the suppression of ${where}`}
          onClick={() => onExpire(record)}
        >
          Expire suppression now
        </button>
      ) : null}
      {canSuppress && !suppressing ? (
        <button
          type="button"
          className="secondary-button"
          aria-label={`Suppress ${where}`}
          disabled={writing}
          onClick={onStartSuppress}
        >
          Suppress…
        </button>
      ) : null}
      {canSuppress && suppressing ? (
        <SuppressForm
          where={where}
          writing={writing}
          onCancel={onCancelSuppress}
          onSubmit={onSuppress}
        />
      ) : null}
    </li>
  );
}

function SuppressForm({
  where,
  writing,
  onCancel,
  onSubmit,
}: {
  where: string;
  writing: boolean;
  onCancel: () => void;
  onSubmit: (reason: string, expiresOn: string) => void;
}) {
  const reasonId = useId();
  const dateId = useId();
  const hintId = useId();
  const [reason, setReason] = useState('');
  const [expiresOn, setExpiresOn] = useState(() => dateIn(DEFAULT_SUPPRESSION_DAYS));
  const minimum = dateIn(1);
  const maximum = dateIn(MAX_SUPPRESSION_DAYS - 1);
  const reasonValid = isSuppressionReason(reason);
  const dateValid = expiresOn >= minimum && expiresOn <= maximum;
  return (
    <form
      className="workbench-suppress"
      aria-label={`Suppress ${where}`}
      onSubmit={(event) => {
        event.preventDefault();
        if (reasonValid && dateValid) onSubmit(reason, expiresOn);
      }}
    >
      <p className="rule-hint" id={hintId}>
        A suppression marks this finding as reviewed for the live policy and the resources this
        analysis read, and nothing else. Any change to either makes it no longer match, and it
        ends on the date you choose (at most {MAX_SUPPRESSION_DAYS} days). The finding stays
        listed. The reason is shown to reviewers, never written to the audit log.
      </p>
      <label htmlFor={reasonId}>Reason</label>
      <textarea
        id={reasonId}
        value={reason}
        maxLength={MAX_SUPPRESSION_REASON_BYTES}
        aria-describedby={hintId}
        aria-invalid={reason !== '' && !reasonValid}
        onChange={(event) => setReason(event.target.value.replace(/[\r\n\t]+/g, ' '))}
      />
      <label htmlFor={dateId}>Expires on (UTC)</label>
      <input
        id={dateId}
        type="date"
        value={expiresOn}
        min={minimum}
        max={maximum}
        aria-invalid={!dateValid}
        onChange={(event) => setExpiresOn(event.target.value)}
      />
      <div className="workbench-actions">
        <button type="submit" disabled={writing || !reasonValid || !dateValid}>
          Suppress finding
        </button>
        <button type="button" className="secondary-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
