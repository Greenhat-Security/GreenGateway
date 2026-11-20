import { useEffect, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import type { PolicyRunRefusal } from '../../../lib/policyRuns';
import {
  runPolicyTests,
  type PolicyTestCaseResult,
  type PolicyTestReport,
  type PolicyTestRunStatus,
  type PolicyTestRunSuite,
} from '../../../lib/policyTestRuns';
import { POLICY_TESTS_ETAG_MISMATCH_REASON } from '../../../lib/policyTests';
import { shortEtag, type JsonObject } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { CasesEditor } from './CasesEditor';
import {
  StoredSuite,
  type StoredRunOutcome,
  type StoredRunRequest,
  type StoredRunTarget,
} from './StoredSuite';
import {
  CheckboxOption,
  CountList,
  POLICY_SIMULATE_PERMISSION,
  RefusalPanel,
  RunBlockers,
  StaleNotice,
  candidateKey,
  candidateLabel,
  codeLabel,
  isAbort,
  plural,
  runAlert,
  runCandidate,
  type WorkbenchCandidate,
} from './common';
import {
  MAX_SUITE_CASES,
  caseIndexForPointer,
  caseKindLabel,
  casesWithoutExpectation,
  describeOutcome,
  parseSuite,
} from './suite';

const PERMISSIONS = `admin:policy:read and ${POLICY_SIMULATE_PERMISSION}`;
const LISTED_MISSING_EXPECTATIONS = 8;

// A run is stale once what it ran is no longer on screen: the candidate and
// the cases for a run of the cases on screen (`key`), the candidate and the
// stored version for a run of the stored suite (`key` is then the candidate
// alone, and the report names the stored ETag it ran).
type TestRun = { key: string; subject: string; report: PolicyTestReport };
type TestRefusal = { refusal: PolicyRunRefusal; cases: readonly JsonObject[] };

// The Test view: run the shared cases as a policy-tests.v1 suite, or the
// suite stored beside the policy, against the live policy or the candidate.
// A run never passes by default and changes nothing; storing the cases as
// the stored suite is a separate, confirmed write.
export function TestsPanel({
  active,
  candidate,
  candidateProblem,
  canSimulate,
  canWritePolicy,
  validationBlocker,
  suiteSource,
  onSuiteChange,
  onReloadLive,
  storedRunRequest,
}: {
  active: boolean;
  candidate: WorkbenchCandidate | null;
  candidateProblem: string | null;
  canSimulate: boolean;
  canWritePolicy: boolean;
  validationBlocker: string | null;
  suiteSource: string;
  onSuiteChange: (source: string) => void;
  onReloadLive: () => void;
  storedRunRequest: StoredRunRequest;
}) {
  const headingId = useId();
  const blockersId = useId();
  const [busy, setBusy] = useState(false);
  // What the run in progress runs, for the status line.
  const [runningText, setRunningText] = useState('');
  // The ETag of the stored suite as last read here; null for none.
  const [storedEtag, setStoredEtag] = useState<string | null>(null);
  const [rejected, setRejected] = useState(false);
  const [run, setRun] = useState<TestRun | null>(null);
  const [refusal, setRefusal] = useState<TestRefusal | null>(null);
  const [alert, setAlert] = useState<StudioAlert | null>(null);
  const [baseStale, setBaseStale] = useState(false);
  const [onlyProblems, setOnlyProblems] = useState(false);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const parsed = parseSuite(suiteSource);
  const cases = parsed.ok ? parsed.cases : [];
  const missing = casesWithoutExpectation(cases);
  const key = candidate === null ? null : `${candidateKey(candidate)}\n${suiteSource}`;
  const storedKey = candidate === null ? null : candidateKey(candidate);
  const stale =
    run !== null &&
    (run.report.suite_stored !== null
      ? run.key !== storedKey || run.report.suite_stored.etag !== storedEtag
      : run.key !== key);

  // What any run needs; a run of the cases on screen also needs the cases.
  const common: string[] = [];
  if (!canSimulate || rejected) common.push(`Running policy tests needs ${PERMISSIONS}.`);
  if (candidate === null) common.push(candidateProblem ?? 'There is no candidate to test.');
  const storedRunBlockers =
    validationBlocker === null ? common : [...common, validationBlocker];
  const blockers: string[] = [...common];
  if (!parsed.ok) blockers.push('Fix the suite source first.');
  else if (cases.length === 0) blockers.push('Add a case first.');
  else if (cases.length > MAX_SUITE_CASES) {
    blockers.push(`A suite holds at most ${MAX_SUITE_CASES} cases.`);
  } else if (missing.length > 0) {
    const listed = missing.slice(0, LISTED_MISSING_EXPECTATIONS).join(', ');
    blockers.push(
      `Every case needs an expectation: ${listed}${missing.length > LISTED_MISSING_EXPECTATIONS ? ` and ${missing.length - LISTED_MISSING_EXPECTATIONS} more` : ''}.`,
    );
  }
  if (validationBlocker !== null) blockers.push(validationBlocker);

  // Run the cases on screen, or the stored suite pinned to `target`.
  // Resolves to whether the gateway answered that the stored suite is no
  // longer that version.
  async function execute(suite: PolicyTestRunSuite, target?: StoredRunTarget): Promise<boolean> {
    const runKey = suite.kind === 'stored' ? storedKey : key;
    if (candidate === null || runKey === null || busy) {
      return false;
    }
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setBusy(true);
    setRunningText(
      suite.kind === 'stored'
        ? target !== undefined && target.version !== null
          ? `Running stored suite version ${target.version}.`
          : 'Running the stored suite.'
        : `Running ${plural(cases.length, 'case')}.`,
    );
    setAlert(null);
    setBaseStale(false);
    setRefusal(null);
    const sentCases = suite.kind === 'inline' && parsed.ok ? parsed.cases : [];
    try {
      const answer = await runPolicyTests({
        suite,
        candidate: runCandidate(candidate),
        liveEtag: candidate.liveEtag,
        signal: current.signal,
      });
      if (answer.kind === 'refused') {
        setRefusal({ refusal: answer.refusal, cases: sentCases });
      } else {
        setRun({ key: runKey, subject: candidateLabel(candidate), report: answer.report });
      }
      return false;
    } catch (error) {
      if (isAbort(error)) return false;
      if (error instanceof AdminApiError && error.status === 403) setRejected(true);
      const suiteChanged =
        error instanceof AdminApiError && error.code === POLICY_TESTS_ETAG_MISMATCH_REASON;
      setBaseStale(error instanceof AdminApiError && error.status === 412 && !suiteChanged);
      setAlert(
        suiteChanged && target?.fromRefusal === true
          ? {
              title: 'Stored suite changed',
              message: `The stored suite is no longer ${target.version !== null ? `version ${target.version}, ` : 'the version '}which refused the publication, so nothing ran. Run the stored suite to see how this draft fares against the version stored now.`,
              tone: 'warning',
            }
          : runAlert(error, 'Policy tests did not run', PERMISSIONS),
      );
      return suiteChanged;
    } finally {
      if (controller.current === current) {
        controller.current = null;
        setBusy(false);
      }
    }
  }

  async function runTests() {
    if (!parsed.ok || blockers.length > 0) {
      return;
    }
    await execute({ kind: 'inline', source: suiteSource });
  }

  async function runStored(target: StoredRunTarget): Promise<StoredRunOutcome> {
    if (storedRunBlockers.length > 0) {
      // Only a run asked from elsewhere gets here: the button is disabled.
      setRefusal(null);
      setAlert({
        title: 'The stored suite did not run',
        message: 'It cannot run against this candidate now:',
        details: storedRunBlockers,
        tone: 'warning',
      });
      return 'blocked';
    }
    return (await execute({ kind: 'stored', etag: target.etag }, target)) ? 'changed' : 'ran';
  }

  const problems = new Map<number, string[]>();
  for (const diagnostic of refusal?.refusal.diagnostics ?? []) {
    const index = caseIndexForPointer(diagnostic.pointer);
    if (index !== null) {
      problems.set(index, [...(problems.get(index) ?? []), `${diagnostic.code}: ${diagnostic.message}`]);
    }
  }

  return (
    <section className="workbench-panel" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Policy tests</p>
          <h3 id={headingId}>Test</h3>
        </div>
      </div>
      <p className="rule-hint">
        Runs the cases as a policy-tests.v1 suite through the gateway’s own evaluator. A
        case passes only when the policy gives the answer it expects; an undecided or
        refused case never passes. A run writes and stores nothing. Where the gateway
        requires the stored suite (POLICY_TESTS_REQUIRED), every policy publication must pass
        the stored suite; running it here shows whether this candidate would.
      </p>

      <StoredSuite
        active={active}
        canRead={canSimulate}
        canWrite={canWritePolicy}
        suiteSource={suiteSource}
        onSuiteChange={onSuiteChange}
        runBlockers={storedRunBlockers}
        running={busy}
        onRunStored={runStored}
        onStoredEtag={setStoredEtag}
        runRequest={storedRunRequest}
      />

      <CasesEditor
        suiteSource={suiteSource}
        onChange={onSuiteChange}
        showExpectations
        problems={problems}
      />

      <div className="form-actions">
        <button
          type="button"
          className="primary-button"
          disabled={blockers.length > 0 || busy}
          aria-describedby={blockers.length > 0 ? blockersId : undefined}
          onClick={() => void runTests()}
        >
          {busy ? 'Running tests' : 'Run tests'}
        </button>
      </div>
      <RunBlockers id={blockersId} blockers={blockers} />

      <div className="policy-studio-status" role="status" aria-live="polite">
        {busy ? <p className="rule-hint">{runningText}</p> : null}
      </div>
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
      {refusal ? (
        <RefusalPanel title="Policy tests refused" refusal={refusal.refusal} cases={refusal.cases} />
      ) : null}

      {run ? (
        <TestReportView
          run={run}
          stale={stale}
          onlyProblems={onlyProblems}
          onOnlyProblems={setOnlyProblems}
        />
      ) : null}
    </section>
  );
}

const STATUS_TEXT: Record<PolicyTestRunStatus, { label: string; badge: string }> = {
  passed: { label: '✓ Passed', badge: 'success' },
  failed: { label: '✕ Failed', badge: 'danger' },
  incomplete: { label: '? Incomplete', badge: 'warning' },
  error: { label: '! Error', badge: 'danger' },
};

function statusSentence(report: PolicyTestReport): string {
  const { summary } = report;
  switch (report.status) {
    case 'passed':
      return summary.total === 1
        ? 'The case gave the expected answer.'
        : `All ${summary.total} cases gave the expected answer.`;
    case 'failed':
      return `${summary.failed} of ${plural(summary.total, 'case')} did not give the expected answer.`;
    case 'incomplete':
      return `${plural(summary.incomplete, 'case')} could not be decided. An undecided case never passes, so the run is not passed.`;
    case 'error':
      return `The evaluator refused ${plural(summary.errors, 'case')}. A refusal never counts as a passing assertion, so the run is not passed.`;
  }
}

function TestReportView({
  run,
  stale,
  onlyProblems,
  onOnlyProblems,
}: {
  run: TestRun;
  stale: boolean;
  onlyProblems: boolean;
  onOnlyProblems: (value: boolean) => void;
}) {
  const headingId = useId();
  const { report } = run;
  const status = STATUS_TEXT[report.status];
  const shown = onlyProblems
    ? report.cases.filter((entry) => entry.status !== 'passed')
    : report.cases;
  return (
    <section className="workbench-results" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Report</p>
          <h3 id={headingId}>Test report</h3>
        </div>
        <span className={`badge ${status.badge}`}>{status.label}</span>
      </div>
      {stale ? (
        <StaleNotice>
          The suite, the candidate or the live policy changed since this run. It still
          reports on what it ran; run the tests again for what is on screen now.
        </StaleNotice>
      ) : null}
      <p>
        <strong>{status.label}.</strong> {statusSentence(report)}
      </p>
      <p>
        {report.suite_stored !== null
          ? `Ran the stored suite, version ${report.suite_stored.version}. `
          : 'Ran the cases on screen. '}
        Tested {run.subject}
        {report.policy.source === 'inline_candidate' ? ', as a candidate that was not stored' : ''}
        : revision <code title={report.policy.etag}>{shortEtag(report.policy.etag)}</code>.
      </p>
      <p className="rule-hint">
        A pass means the policy gives the expected answers for the facts the cases state. It
        does not mean a real request would succeed: {report.not_evaluated.map(codeLabel).join(', ')}{' '}
        are not evaluated.
      </p>
      <CountList
        label="Test summary"
        items={[
          { term: 'Cases', value: report.summary.total },
          { term: 'Passed', value: report.summary.passed },
          { term: 'Failed', value: report.summary.failed },
          { term: 'Incomplete', value: report.summary.incomplete },
          { term: 'Errors', value: report.summary.errors },
        ]}
      />
      <CheckboxOption
        label="Only cases that did not pass"
        checked={onlyProblems}
        onChange={onOnlyProblems}
      />
      {shown.length === 0 ? (
        <p className="empty-state">Every case passed.</p>
      ) : (
        <div className="table-scroll">
          <table className="logs-table workbench-table">
            <caption className="sr-only">Policy test cases</caption>
            <thead>
              <tr>
                <th scope="col">Case</th>
                <th scope="col">Kind</th>
                <th scope="col">Result</th>
                <th scope="col">Expected</th>
                <th scope="col">Answered</th>
                <th scope="col">Did not hold</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((entry) => (
                <TestCaseRow key={entry.pointer} entry={entry} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="rule-hint">
        Suite digest <code title={report.suite_digest}>{shortEtag(report.suite_digest)}</code>
        {report.gateway_version ? `, gateway ${report.gateway_version}` : ''}.
      </p>
    </section>
  );
}

function TestCaseRow({ entry }: { entry: PolicyTestCaseResult }) {
  const status = STATUS_TEXT[entry.status];
  return (
    <tr>
      <th scope="row">
        <code>{entry.id}</code>
      </th>
      <td>{caseKindLabel(entry.kind)}</td>
      <td>
        <span className={`badge ${status.badge}`}>{status.label}</span>
      </td>
      <td>{describeOutcome(entry.expected)}</td>
      <td>
        {entry.actual === null ? (
          <>
            Refused by the evaluator{entry.error ? <>: <code>{entry.error}</code></> : null}
          </>
        ) : (
          <>
            {describeOutcome(entry.actual)}
            {!entry.actual.complete ? (
              <>
                {' '}
                (undecided{entry.actual.limitation ? <>: <code>{entry.actual.limitation}</code></> : null})
              </>
            ) : null}
          </>
        )}
      </td>
      <td>{entry.mismatches.length > 0 ? entry.mismatches.join(', ') : '—'}</td>
    </tr>
  );
}
