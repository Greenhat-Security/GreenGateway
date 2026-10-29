import { useEffect, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import type { PolicyRunRefusal } from '../../../lib/policyRuns';
import {
  runPolicySimulation,
  type SimulationCase,
  type SimulationCounts,
  type SimulationProjection,
  type SimulationResult,
  type SimulationTraceLevel,
} from '../../../lib/policySimulations';
import { replaceAt, shortEtag, type JsonObject } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { CasesEditor, SelectInput } from './CasesEditor';
import {
  CheckboxOption,
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
import { DecisionView, projectionLabel } from './Decision';
import {
  MAX_SIMULATION_CASES,
  caseIndexForPointer,
  caseKind,
  caseKindLabel,
  expectationFromDecision,
  formatSuite,
  parseSuite,
  simulationCases,
  withCases,
} from './suite';

const PERMISSIONS = `admin:policy:read and ${POLICY_SIMULATE_PERMISSION}`;

type SimulationRun = {
  key: string;
  subject: string;
  result: SimulationResult;
};

type SimulationRefusal = { refusal: PolicyRunRefusal; cases: readonly JsonObject[] };

// The Simulator: what the live policy and the candidate decide for the
// shared synthetic cases, as authored and with every shadow projected as
// enforced. A simulation changes nothing; its result lives in this page.
export function SimulatorPanel({
  candidate,
  candidateProblem,
  canSimulate,
  validationBlocker,
  suiteSource,
  onSuiteChange,
  onReloadLive,
}: {
  candidate: WorkbenchCandidate | null;
  candidateProblem: string | null;
  canSimulate: boolean;
  // Why the candidate's current validation already rules a simulation out.
  validationBlocker: string | null;
  suiteSource: string;
  onSuiteChange: (source: string) => void;
  onReloadLive: () => void;
}) {
  const headingId = useId();
  const blockersId = useId();
  const [trace, setTrace] = useState<SimulationTraceLevel>('matched');
  const [projections, setProjections] = useState<Record<SimulationProjection, boolean>>({
    as_authored: true,
    enforce_all_shadow: true,
  });
  const [busy, setBusy] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [run, setRun] = useState<SimulationRun | null>(null);
  const [refusal, setRefusal] = useState<SimulationRefusal | null>(null);
  const [alert, setAlert] = useState<StudioAlert | null>(null);
  const [baseStale, setBaseStale] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [onlyChanged, setOnlyChanged] = useState(false);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const parsed = parseSuite(suiteSource);
  const cases = parsed.ok ? simulationCases(parsed.cases) : [];
  const selectedProjections = (['as_authored', 'enforce_all_shadow'] as const).filter(
    (projection) => projections[projection],
  );
  const key = candidate === null ? null : `${candidateKey(candidate)}\n${JSON.stringify(cases)}`;
  const stale = run !== null && run.key !== key;

  const blockers: string[] = [];
  if (!canSimulate || rejected) blockers.push(`Simulating needs ${PERMISSIONS}.`);
  if (candidate === null) blockers.push(candidateProblem ?? 'There is no candidate to simulate.');
  if (!parsed.ok) blockers.push('Fix the suite source first.');
  else if (cases.length === 0) blockers.push('Add a case first.');
  else if (cases.length > MAX_SIMULATION_CASES) {
    blockers.push(`A simulation takes at most ${MAX_SIMULATION_CASES} cases.`);
  }
  if (selectedProjections.length === 0) blockers.push('Choose at least one projection.');
  if (validationBlocker !== null) blockers.push(validationBlocker);

  async function simulate() {
    if (candidate === null || key === null || !parsed.ok || busy || blockers.length > 0) {
      return;
    }
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setBusy(true);
    setAlert(null);
    setBaseStale(false);
    setRefusal(null);
    setNotice(null);
    const sentCases = parsed.cases;
    try {
      const answer = await runPolicySimulation({
        baseEtag: candidate.liveEtag,
        candidate: runCandidate(candidate),
        trace,
        projections: selectedProjections,
        cases,
        signal: current.signal,
      });
      if (answer.kind === 'refused') {
        setRefusal({ refusal: answer.refusal, cases: sentCases });
      } else {
        setRun({ key, subject: candidateLabel(candidate), result: answer.result });
      }
    } catch (error) {
      if (isAbort(error)) return;
      if (error instanceof AdminApiError && error.status === 403) setRejected(true);
      setBaseStale(error instanceof AdminApiError && error.status === 412);
      setAlert(runAlert(error, 'Simulation did not run', PERMISSIONS));
    } finally {
      if (controller.current === current) {
        controller.current = null;
        setBusy(false);
      }
    }
  }

  // A decided answer becomes the case's test expectation; only the suite in
  // this page changes.
  function expectAnswer(index: number, expect: JsonObject, id: string) {
    if (!parsed.ok || parsed.cases[index] === undefined) return;
    onSuiteChange(
      formatSuite(
        withCases(parsed.suite, replaceAt(parsed.cases, index, { ...parsed.cases[index], expect })),
      ),
    );
    setNotice(`Case ${id} now expects this answer. The Test view checks it against any candidate.`);
  }

  const problems = new Map<number, string[]>();
  for (const diagnostic of refusal?.refusal.diagnostics ?? []) {
    const index = caseIndexForPointer(diagnostic.pointer);
    if (index !== null) {
      problems.set(index, [...(problems.get(index) ?? []), `${diagnostic.code}: ${diagnostic.message}`]);
    }
  }
  if (refusal?.refusal.pointer) {
    const index = caseIndexForPointer(refusal.refusal.pointer);
    if (index !== null) {
      problems.set(index, [
        ...(problems.get(index) ?? []),
        `The evaluator refused this case${refusal.refusal.code ? `: ${refusal.refusal.code}` : ''}.`,
      ]);
    }
  }

  return (
    <section className="workbench-panel" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Synthetic simulation</p>
          <h3 id={headingId}>Simulator</h3>
        </div>
      </div>
      <p className="rule-hint">
        Asks the gateway’s own evaluator what the live policy and the candidate decide for
        each case. Nothing is written, activated or stored, no rate bucket is charged and
        no upstream is contacted.
      </p>

      <CasesEditor
        suiteSource={suiteSource}
        onChange={onSuiteChange}
        showExpectations={false}
        problems={problems}
      />

      <fieldset className="rule-fieldset workbench-options">
        <legend>Simulation options</legend>
        <SelectInput
          label="Trace level"
          value={trace}
          options={[
            { value: 'terminal', label: 'Outcome only' },
            { value: 'matched', label: 'Outcome and the deciding element' },
            { value: 'full', label: 'Every HTTP evaluation stage' },
          ]}
          onChange={(value) => setTrace(value as SimulationTraceLevel)}
        />
        <CheckboxOption
          label="As authored"
          checked={projections.as_authored}
          hint="The policy exactly as written."
          onChange={(checked) => setProjections((current) => ({ ...current, as_authored: checked }))}
        />
        <CheckboxOption
          label="Every shadow enforced"
          checked={projections.enforce_all_shadow}
          hint="What would block if every shadow rule and shadow mode were promoted. It cannot preview an allow a shadow rule was meant to become."
          onChange={(checked) =>
            setProjections((current) => ({ ...current, enforce_all_shadow: checked }))
          }
        />
      </fieldset>

      <div className="form-actions">
        <button
          type="button"
          className="primary-button"
          disabled={blockers.length > 0 || busy}
          aria-describedby={blockers.length > 0 ? blockersId : undefined}
          onClick={() => void simulate()}
        >
          {busy ? 'Simulating' : 'Run simulation'}
        </button>
      </div>
      <RunBlockers id={blockersId} blockers={blockers} />

      <div className="policy-studio-status" role="status" aria-live="polite">
        {busy ? <p className="rule-hint">Simulating {plural(cases.length, 'case')}.</p> : null}
        {notice ? <p className="rule-hint">{notice}</p> : null}
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
        <RefusalPanel title="Simulation refused" refusal={refusal.refusal} cases={refusal.cases} />
      ) : null}

      {run ? (
        <SimulationResultView
          run={run}
          stale={stale}
          onlyChanged={onlyChanged}
          onOnlyChanged={setOnlyChanged}
          suiteCases={parsed.ok ? parsed.cases : []}
          onExpect={stale ? null : expectAnswer}
        />
      ) : null}
    </section>
  );
}

function SimulationResultView({
  run,
  stale,
  onlyChanged,
  onOnlyChanged,
  suiteCases,
  onExpect,
}: {
  run: SimulationRun;
  stale: boolean;
  onlyChanged: boolean;
  onOnlyChanged: (value: boolean) => void;
  suiteCases: readonly JsonObject[];
  onExpect: ((index: number, expect: JsonObject, id: string) => void) | null;
}) {
  const headingId = useId();
  const { result } = run;
  const compared = result.candidate.source !== 'active';
  const shown = onlyChanged
    ? result.cases.filter(
        (entry) =>
          entry.results.some((item) => item.changed === true) || entry.projection_changed === true,
      )
    : result.cases;
  return (
    <section className="workbench-results" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Result</p>
          <h3 id={headingId}>Simulation result</h3>
        </div>
        <span className="result-count">{plural(result.summary.cases, 'case')}</span>
      </div>
      {stale ? (
        <StaleNotice>
          The candidate, its cases or the live policy changed since this simulation ran. It
          still answers for what it ran on; run it again for what is on screen now.
        </StaleNotice>
      ) : null}
      <p>
        Simulated against {run.subject}.{' '}
        {compared ? (
          <>
            Each answer is compared with live revision{' '}
            <code title={result.base.etag}>{shortEtag(result.base.etag)}</code>; the candidate
            would be revision <code title={result.candidate.etag}>{shortEtag(result.candidate.etag)}</code>.
          </>
        ) : (
          'The candidate is the live policy itself, so nothing is compared.'
        )}
      </p>
      <p className="rule-hint">
        Each answer is the policy’s decision for the facts a case states, not a prediction
        that a real request would succeed. Not evaluated:{' '}
        {result.not_evaluated.map(codeLabel).join(', ')}.
      </p>
      {result.trace.stages_truncated ? (
        <p className="rule-hint">
          The full trace reached its bound of {result.trace.max_stages} stage steps; later
          evaluations show their decision without their stages.
        </p>
      ) : null}

      <div className="table-scroll">
        <table className="logs-table workbench-table">
          <caption className="sr-only">Candidate answers by projection</caption>
          <thead>
            <tr>
              <th scope="col">Projection</th>
              <th scope="col">Would forward</th>
              <th scope="col">Would block</th>
              <th scope="col">Unknown</th>
              <th scope="col">Shadowed denials</th>
              <th scope="col">Changed from live</th>
              <th scope="col">Rate override</th>
              <th scope="col">No rate override</th>
              <th scope="col">Rate undecided</th>
            </tr>
          </thead>
          <tbody>
            {result.projections.map((projection) => {
              const counts: SimulationCounts | undefined = result.summary.projections[projection];
              return counts ? (
                <tr key={projection}>
                  <th scope="row">{projectionLabel(projection)}</th>
                  <td>{counts.would_forward}</td>
                  <td>{counts.would_block}</td>
                  <td>{counts.unknown}</td>
                  <td>{counts.shadowed}</td>
                  <td>{counts.changed_from_base ?? 'Not compared'}</td>
                  <td>{counts.rate_override}</td>
                  <td>{counts.no_rate_override}</td>
                  <td>{counts.rate_unknown}</td>
                </tr>
              ) : null;
            })}
          </tbody>
        </table>
      </div>
      {result.summary.projection_changed !== null ? (
        <p className="rule-hint">
          Promoting every shadow changes the candidate’s answer for{' '}
          {plural(result.summary.projection_changed, 'case')}.
        </p>
      ) : null}

      <CheckboxOption
        label="Only cases whose answer changed"
        checked={onlyChanged}
        onChange={onOnlyChanged}
      />
      {shown.length === 0 ? (
        <p className="empty-state">
          {onlyChanged ? 'No case’s answer changed.' : 'The simulation returned no cases.'}
        </p>
      ) : (
        <ol className="workbench-case-results" aria-label="Simulated cases">
          {shown.map((entry) => (
            <li key={entry.pointer}>
              <SimulatedCaseView
                entry={entry}
                compared={compared}
                suiteCases={suiteCases}
                onExpect={onExpect}
              />
            </li>
          ))}
        </ol>
      )}
      <p className="rule-hint">
        Request digest <code title={result.request_digest}>{shortEtag(result.request_digest)}</code>
        {result.http_semantics_version ? `, evaluator ${result.http_semantics_version}` : ''}
        {result.gateway_version ? `, gateway ${result.gateway_version}` : ''}.
      </p>
    </section>
  );
}

function SimulatedCaseView({
  entry,
  compared,
  suiteCases,
  onExpect,
}: {
  entry: SimulationCase;
  compared: boolean;
  suiteCases: readonly JsonObject[];
  onExpect: ((index: number, expect: JsonObject, id: string) => void) | null;
}) {
  const headingId = useId();
  const index = caseIndexForPointer(entry.pointer);
  const suiteCase = index === null ? undefined : suiteCases[index];
  const kind = suiteCase && suiteCase.id === entry.id ? caseKind(suiteCase) : null;
  const authored = entry.results.find((item) => item.projection === 'as_authored');
  const expectation =
    kind !== null && authored ? expectationFromDecision(kind, authored.candidate) : null;
  const changed = entry.results.some((item) => item.changed === true);
  return (
    <article className="studio-element workbench-case-result" aria-labelledby={headingId}>
      <div className="studio-element-head">
        <h4 id={headingId}>Case {entry.id}</h4>
        <span className="rule-hint">{caseKindLabel(entry.kind)}</span>
        {compared ? (
          <span className={`badge ${changed ? 'warning' : 'neutral'}`}>
            {changed ? 'Δ Changed from live' : '= Same as live'}
          </span>
        ) : null}
      </div>
      {entry.results.map((item) => (
        <section
          key={item.projection}
          className="workbench-projection"
          aria-label={`${projectionLabel(item.projection)}, case ${entry.id}`}
        >
          <h5>{projectionLabel(item.projection)}</h5>
          <div className="workbench-compare">
            {item.base ? <DecisionView title="Live policy" decision={item.base} /> : null}
            <DecisionView title={item.base ? 'Candidate' : 'Live policy'} decision={item.candidate} />
          </div>
        </section>
      ))}
      {entry.projection_changed !== null ? (
        <p className="rule-hint">
          {entry.projection_changed
            ? 'Promoting every shadow changes this answer.'
            : 'Promoting every shadow does not change this answer.'}
        </p>
      ) : null}
      {onExpect !== null && index !== null && expectation !== null ? (
        <div className="form-actions">
          <button
            type="button"
            className="secondary-button"
            aria-label={`Expect the answer for case ${entry.id} in tests`}
            onClick={() => onExpect(index, expectation, entry.id)}
          >
            Expect this answer in tests
          </button>
        </div>
      ) : null}
    </article>
  );
}
