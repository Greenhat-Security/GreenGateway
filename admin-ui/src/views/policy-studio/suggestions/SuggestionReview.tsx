import { useCallback, useEffect, useId, useRef, useState } from 'react';

import {
  POLICY_ANALYZE_PERMISSION,
  runPolicyAnalysis,
  type PolicyAnalysisAnswer,
  type PolicyAnalysisFinding,
} from '../../../lib/policyAnalyses';
import type { PolicyDiagnostic, PolicyDraft, PolicyInspection } from '../../../lib/policyDrafts';
import {
  runPolicySimulation,
  type SimulationAnswer,
  type SimulationDecision,
} from '../../../lib/policySimulations';
import { projectProposedRule, type RuleSuggestion } from '../../../lib/suggestions';
import { diagnosticsWithin, pointerTo, severityBadge, severityLabel } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { codeLabel, isAbort, plural, RefusalPanel, runAlert } from '../workbench/common';
import { DecisionView, elementText, positionText, projectionLabel } from '../workbench/Decision';
import {
  matchingRulePosition,
  reviewCase,
  rulePosition,
  targetText,
} from './model';

// A suggestion whose rule a draft in this page holds: written there by
// Review in draft, or found there and bound by the operator. Publishing
// that draft with this binding is the suggestion's acceptance. Held in page
// memory only.
export type SuggestionBinding = Readonly<{
  draftId: string;
  // The suggestion as the gateway answered when the binding was made; its
  // id and revision are what a publication binds.
  suggestion: RuleSuggestion;
  ruleId: string | null;
  drafted: boolean;
}>;

type CheckRun<T> =
  | Readonly<{ kind: 'idle' }>
  | Readonly<{ kind: 'running' }>
  | Readonly<{ kind: 'skipped'; reason: string }>
  | Readonly<{ kind: 'answer'; answer: T }>
  | Readonly<{ kind: 'failed'; alert: StudioAlert }>;

type Checks = Readonly<{
  key: string;
  simulation: CheckRun<SimulationAnswer>;
  analysis: CheckRun<PolicyAnalysisAnswer>;
}>;

// The review of one bound suggestion in the open draft: where its rule is,
// what validation says there, what the policy decides for the traffic the
// rule describes, and what the analyzer proves about it. Simulation and
// analysis read the saved draft revision by its ETag and change nothing,
// so they run by themselves whenever that revision changes.
export function SuggestionReview({
  binding,
  draft,
  liveEtag,
  dirty,
  inspection,
  checking,
  staleReason,
  canSimulate,
  canAnalyze,
  canAccept,
  onShowRule,
}: {
  binding: SuggestionBinding;
  draft: PolicyDraft;
  liveEtag: string | null;
  dirty: boolean;
  // The Studio's validation of the text on screen, when it is current.
  inspection: PolicyInspection | null;
  checking: boolean;
  // Why a publication bound to this suggestion would be refused, as far as
  // the Studio has learned since the binding was made.
  staleReason: string | null;
  canSimulate: boolean;
  canAnalyze: boolean;
  canAccept: boolean;
  onShowRule: (position: number) => void;
}) {
  const headingId = useId();
  const suggestion = binding.suggestion;
  const position =
    rulePosition(draft.policy, binding.ruleId) ?? matchingRulePosition(draft.policy, suggestion);
  const rules = Array.isArray(draft.policy.rules) ? draft.policy.rules : [];
  const savedRule = position === null ? null : projectProposedRule(rules[position]);
  const checksKey = `${draft.etag}\n${liveEtag ?? ''}\n${position ?? ''}`;
  const [checks, setChecks] = useState<Checks>({
    key: '',
    simulation: { kind: 'idle' },
    analysis: { kind: 'idle' },
  });
  const controller = useRef<AbortController | null>(null);

  const run = useCallback(() => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    const key = checksKey;
    if (liveEtag === null) {
      setChecks({
        key,
        simulation: { kind: 'skipped', reason: 'The live policy has not been read.' },
        analysis: { kind: 'skipped', reason: 'The live policy has not been read.' },
      });
      return;
    }
    const candidate = { kind: 'draft' as const, draftId: draft.summary.draft_id, draftEtag: draft.etag };
    const built = savedRule === null ? null : reviewCase(savedRule);
    const simulation: CheckRun<SimulationAnswer> = !canSimulate
      ? { kind: 'skipped', reason: 'Simulating needs admin:policy:read and admin:policy:simulate.' }
      : savedRule === null
        ? { kind: 'skipped', reason: 'The draft does not hold the suggested rule, so there is nothing to simulate.' }
        : built === null || built.case === null
          ? { kind: 'skipped', reason: built?.note ?? 'No synthetic case describes this rule.' }
          : { kind: 'running' };
    const analysis: CheckRun<PolicyAnalysisAnswer> = canAnalyze
      ? { kind: 'running' }
      : { kind: 'skipped', reason: `Analyzing needs admin:policy:read and ${POLICY_ANALYZE_PERMISSION}.` };
    setChecks({ key, simulation, analysis });
    const update = (change: Partial<Omit<Checks, 'key'>>) =>
      setChecks((previous) => (previous.key === key ? { ...previous, ...change } : previous));
    if (simulation.kind === 'running' && built !== null && built.case !== null) {
      const reviewed = built.case;
      void (async () => {
        try {
          const answer = await runPolicySimulation({
            baseEtag: liveEtag,
            candidate,
            trace: 'matched',
            projections: ['as_authored', 'enforce_all_shadow'],
            cases: [reviewed],
            signal: current.signal,
          });
          if (!current.signal.aborted) update({ simulation: { kind: 'answer', answer } });
        } catch (error) {
          if (isAbort(error) || current.signal.aborted) return;
          update({
            simulation: {
              kind: 'failed',
              alert: runAlert(error, 'Simulation did not run', 'admin:policy:read and admin:policy:simulate'),
            },
          });
        }
      })();
    }
    if (analysis.kind === 'running') {
      void (async () => {
        try {
          const answer = await runPolicyAnalysis({
            baseEtag: liveEtag,
            candidate,
            signal: current.signal,
          });
          if (!current.signal.aborted) update({ analysis: { kind: 'answer', answer } });
        } catch (error) {
          if (isAbort(error) || current.signal.aborted) return;
          update({
            analysis: {
              kind: 'failed',
              alert: runAlert(error, 'Analysis did not run', `admin:policy:read and ${POLICY_ANALYZE_PERMISSION}`),
            },
          });
        }
      })();
    }
  }, [checksKey, liveEtag, draft, savedRule, canSimulate, canAnalyze]);

  // Run once per saved revision, live revision and position.
  const lastRun = useRef<string | null>(null);
  useEffect(() => {
    if (lastRun.current !== checksKey) {
      lastRun.current = checksKey;
      run();
    }
  }, [checksKey, run]);
  useEffect(
    () => () => {
      // A remount (StrictMode does one) runs the checks again.
      controller.current?.abort();
      lastRun.current = null;
    },
    [],
  );

  const diagnostics =
    position === null || inspection === null
      ? []
      : diagnosticsWithin(inspection.diagnostics, pointerTo('rules', position));
  const running = checks.simulation.kind === 'running' || checks.analysis.kind === 'running';

  return (
    <section className="policy-studio-suggestion-review" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Suggestion under review</p>
          <h3 id={headingId}>{targetText(suggestion.proposed_rule)}</h3>
        </div>
        <span className={`badge ${staleReason === null ? 'success' : 'warning'}`}>
          {staleReason === null
            ? `Open at revision ${suggestion.revision}`
            : 'Stale: publishing with it is refused'}
        </span>
      </div>
      <p className="rule-hint">
        Suggestion {suggestion.id}, revision {suggestion.revision}.{' '}
        {binding.drafted
          ? 'Its rule was written into this draft by Review in draft.'
          : 'This draft already held its rule, and you chose to publish it as the acceptance.'}{' '}
        Nothing live has changed, and the suggestion stays open until this draft is published
        with it.
      </p>
      {staleReason !== null ? (
        <StudioAlertPanel
          alert={{ title: 'This suggestion moved', message: staleReason, tone: 'warning' }}
        />
      ) : null}
      {!canAccept ? (
        <p className="rule-hint">
          Publishing this draft as the suggestion’s acceptance needs admin:suggestions:write as
          well as admin:policy:write; without it the draft can still be published, and the
          suggestion stays open.
        </p>
      ) : null}

      <dl className="workbench-facts">
        <div>
          <dt>Position in the saved draft</dt>
          <dd>
            {position === null ? (
              <>
                <span className="badge warning">Not found</span> The saved draft does not hold a
                rule like this suggestion’s. A publication bound to it would be refused until it
                does.
              </>
            ) : (
              <>
                {positionText('rule', position)}
                {binding.ruleId !== null ? `, id ${binding.ruleId}` : ''}{' '}
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => onShowRule(position)}
                >
                  Show the rule
                </button>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Validation</dt>
          <dd>
            {checking
              ? 'Checking the text on screen with the gateway.'
              : inspection === null
                ? 'Not validated yet.'
                : `${inspection.valid ? 'Valid' : 'Invalid'}${
                    position === null
                      ? ''
                      : diagnostics.length === 0
                        ? '; nothing reported at the suggested rule'
                        : `; ${plural(diagnostics.length, 'diagnostic')} at the suggested rule`
                  }.`}
            {dirty ? ' This is the text on screen, with unsaved edits; simulation and analysis below read the saved revision.' : ''}
          </dd>
        </div>
      </dl>
      {diagnostics.length > 0 ? (
        <ul className="studio-field-problems">
          {diagnostics.map((diagnostic: PolicyDiagnostic, index) => (
            <li className={`studio-problem ${diagnostic.severity}`} key={`${index}:${diagnostic.code}`}>
              <span className={`badge ${severityBadge(diagnostic.severity)}`}>
                {severityLabel(diagnostic.severity)}
              </span>{' '}
              {diagnostic.message} {diagnostic.remediation}
            </li>
          ))}
        </ul>
      ) : null}

      <p className="policy-studio-validation-status" role="status" aria-live="polite">
        {running
          ? `Checking saved revision ${draft.summary.revision} with the gateway.`
          : `Checks below are for saved revision ${draft.summary.revision} of draft ${draft.summary.draft_id}.`}
      </p>

      <div className="policy-studio-suggestion-checks">
        <section aria-labelledby={`${headingId}-simulation`}>
          <h4 id={`${headingId}-simulation`}>The traffic it describes</h4>
          <SimulationCheck run={checks.simulation} position={position} />
        </section>
        <section aria-labelledby={`${headingId}-analysis`}>
          <h4 id={`${headingId}-analysis`}>Policy analyzer</h4>
          <AnalysisCheck run={checks.analysis} position={position} />
        </section>
      </div>
      <div className="form-actions">
        <button type="button" className="secondary-button" disabled={running} onClick={run}>
          Run the checks again
        </button>
      </div>
    </section>
  );
}

function SimulationCheck({
  run,
  position,
}: {
  run: CheckRun<SimulationAnswer>;
  position: number | null;
}) {
  if (run.kind === 'idle' || run.kind === 'running') {
    return <p className="rule-hint">Simulating one request the rule matches.</p>;
  }
  if (run.kind === 'skipped') {
    return <p className="rule-hint">Not run. {run.reason}</p>;
  }
  if (run.kind === 'failed') {
    return <StudioAlertPanel alert={run.alert} live={false} />;
  }
  if (run.answer.kind === 'refused') {
    return <RefusalPanel title="Simulation refused" refusal={run.answer.refusal} cases={[]} />;
  }
  const result = run.answer.result;
  const entry = result.cases[0];
  if (entry === undefined) {
    return <p className="rule-hint">The gateway returned no answer for the case.</p>;
  }
  const authored = entry.results.find((result) => result.projection === 'as_authored');
  return (
    <>
      {authored !== undefined ? (
        <Verdict decision={authored.candidate} position={position} />
      ) : null}
      {entry.results.map((answer) => (
        <div key={answer.projection} className="policy-studio-suggestion-decision">
          <DecisionView
            title={`${projectionLabel(answer.projection)}: the draft`}
            decision={answer.candidate}
          />
          {answer.base !== null ? (
            <p className="rule-hint">
              The live policy now:{' '}
              {answer.base.logical ?? 'undecided'}
              {answer.base.matched ? `, by ${elementText(answer.base.matched)}` : ''}.{' '}
              {answer.changed === true
                ? 'The draft changes this answer.'
                : answer.changed === false
                  ? 'The draft does not change this answer.'
                  : ''}
            </p>
          ) : null}
        </div>
      ))}
      <p className="rule-hint">
        One synthetic request from a hypothetical caller the rule’s principal constraints admit;
        not evaluated: {result.not_evaluated.map(codeLabel).join(', ') || 'nothing'}.
      </p>
    </>
  );
}

function Verdict({ decision, position }: { decision: SimulationDecision; position: number | null }) {
  const matched = decision.matched;
  if (matched === undefined) {
    return <p className="rule-hint">The trace level did not report which element decided.</p>;
  }
  if (matched !== null && matched.kind === 'rule' && matched.position === position) {
    return (
      <p className="workbench-stale">
        <span className="badge success">✓ The suggested rule decides</span> As authored, the
        rule at position {position} decides this request.
      </p>
    );
  }
  return (
    <p className="workbench-stale">
      <span className="badge warning">! Another element decides</span>{' '}
      {matched === null
        ? 'No rule or route decides this request; the default or a fact does.'
        : `${elementText(matched)} decides this request first.`}{' '}
      The suggested rule {position === null ? 'is not in the draft' : `at position ${position} does not decide it`}
      : publishing it would change nothing for this traffic.
    </p>
  );
}

function AnalysisCheck({
  run,
  position,
}: {
  run: CheckRun<PolicyAnalysisAnswer>;
  position: number | null;
}) {
  if (run.kind === 'idle' || run.kind === 'running') {
    return <p className="rule-hint">Analyzing the saved draft.</p>;
  }
  if (run.kind === 'skipped') {
    return <p className="rule-hint">Not run. {run.reason}</p>;
  }
  if (run.kind === 'failed') {
    return <StudioAlertPanel alert={run.alert} live={false} />;
  }
  if (run.answer.kind === 'refused') {
    return <RefusalPanel title="Analysis refused" refusal={run.answer.refusal} cases={[]} />;
  }
  const result = run.answer.result;
  const about = (finding: PolicyAnalysisFinding) =>
    position !== null &&
    ((finding.element.section === 'rules' && finding.element.position === position) ||
      (finding.related?.section === 'rules' && finding.related.position === position));
  const relevant = result.findings.filter(about);
  const others = result.findings.length - relevant.length;
  return (
    <>
      {!result.complete ? (
        <p className="workbench-stale">
          <span className="badge warning">Incomplete</span> The analysis stopped at{' '}
          {result.limitations.map(codeLabel).join(', ') || 'a bound'}; it says nothing about the
          elements it did not reach.
        </p>
      ) : null}
      {relevant.length === 0 ? (
        <p className="rule-hint">
          {position === null
            ? 'The suggested rule is not in the saved draft.'
            : 'The analyzer reports nothing about the suggested rule. It reports only what it can prove, so this is not a statement that the rule is needed or safe.'}
        </p>
      ) : (
        <ol className="policy-studio-diagnostic-list" aria-label="Findings about the suggested rule">
          {relevant.map((finding) => (
            <li key={`${finding.code}:${finding.element.pointer}:${finding.related?.pointer ?? ''}`}>
              <div className="policy-studio-diagnostic-head">
                <span className={`badge ${finding.severity === 'high' ? 'danger' : 'warning'}`}>
                  {finding.severity === 'high' ? 'High' : finding.severity === 'medium' ? 'Medium' : 'Low'}
                </span>
                <code>{finding.code}</code>
                <span className="rule-hint">Proof basis: {codeLabel(finding.proof_basis)}</span>
              </div>
              <p>{finding.rationale}</p>
              <p>
                <strong>Remediation:</strong> {finding.remediation}
              </p>
              <p className="rule-hint">
                About <code>{finding.element.pointer}</code>
                {finding.related !== null ? (
                  <>
                    , established by <code>{finding.related.pointer}</code>
                  </>
                ) : null}
                .{' '}
                {finding.access_effect !== null
                  ? `Its advisory patch’s access effect: ${codeLabel(finding.access_effect)}; nothing is applied.`
                  : 'No advisory patch.'}
              </p>
            </li>
          ))}
        </ol>
      )}
      <p className="rule-hint">
        {others > 0 ? `${plural(others, 'other finding')} about the rest of the draft. ` : ''}
        Analyzer {result.analyzer_version ?? '(version not reported)'}, on saved revision{' '}
        {result.analyzed.draft_revision ?? '(not reported)'}.
      </p>
    </>
  );
}
