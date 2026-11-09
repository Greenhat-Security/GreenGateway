import { useEffect, useRef, useState, type FormEvent } from 'react';

import { AdminApiError } from '../../../lib/api';
import type { PolicyDraft } from '../../../lib/policyDrafts';
import {
  fetchPolicyEvidence, type EvidenceCandidate, type EvidencePackage,
} from '../../../lib/policyEvidence';
import { CheckboxOption } from './common';
import {
  casesWithoutExpectation,
  MAX_SIMULATION_CASES,
  MAX_SUITE_CASES,
  simulationCases,
  type SuiteParse,
} from './suite';

export function EvidencePanel({
  draft, draftBlocked, suite, canSimulate, canAnalyze, canReplay,
}: {
  draft: PolicyDraft | null;
  draftBlocked: boolean;
  suite: SuiteParse;
  canSimulate: boolean;
  canAnalyze: boolean;
  canReplay: boolean;
}) {
  const [kind, setKind] = useState<'draft' | 'publication'>(draft ? 'draft' : 'publication');
  const [version, setVersion] = useState('');
  const [tests, setTests] = useState(false);
  const [simulate, setSimulate] = useState(false);
  const [analysis, setAnalysis] = useState(false);
  const [replay, setReplay] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<EvidencePackage | null>(null);
  const [error, setError] = useState('');
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);

  function discard() {
    pending.current?.abort();
    pending.current = null;
    setBusy(false);
    setResult(null);
    setError('');
  }

  const candidate: EvidenceCandidate | null = kind === 'draft'
    ? draft && !draftBlocked ? { draft: { draft_id: draft.summary.draft_id, draft_etag: draft.etag } } : null
    : /^[1-9]\d*$/.test(version) && Number.isSafeInteger(Number(version))
      ? { publication: { version: Number(version) } } : null;
  const hasCases = suite.ok && suite.cases.length > 0;
  const testsAvailable = canSimulate && hasCases && suite.cases.length <= MAX_SUITE_CASES &&
    casesWithoutExpectation(suite.cases).length === 0;
  const simulationAvailable = canSimulate && hasCases && suite.cases.length <= MAX_SIMULATION_CASES;

  async function generate(event: FormEvent) {
    event.preventDefault();
    if (!candidate || pending.current) return;
    const request = new AbortController();
    pending.current = request;
    setBusy(true);
    setResult(null);
    setError('');
    try {
      const evidence = await fetchPolicyEvidence(candidate, {
        ...(tests && testsAvailable && suite.ok ? { suite: suite.suite } : {}),
        ...(simulate && simulationAvailable && suite.ok ? { simulation: { cases: simulationCases(suite.cases) } } : {}),
        ...(analysis && canAnalyze ? { analysis: true } : {}),
        ...(canReplay && replay.trim() ? { replay_job_id: replay.trim() } : {}),
      }, request.signal);
      if (!request.signal.aborted) setResult(evidence);
    } catch (failure) {
      if (!request.signal.aborted) {
        setError(evidenceFailure(failure));
      }
    } finally {
      if (pending.current === request) {
        pending.current = null;
        if (!request.signal.aborted) setBusy(false);
      }
    }
  }

  return (
    <section className="workbench-panel">
      <h2>Policy evidence</h2>
      <form className="workbench-options" onSubmit={(event) => void generate(event)} onChange={discard}>
        <fieldset className="rule-fieldset workbench-options" disabled={busy}>
          <legend>Evidence source</legend>
          <label className="rule-field"><span className="field-label">Candidate</span>
            <select className="rule-input" value={kind}
              onChange={(event) => setKind(event.target.value === 'draft' ? 'draft' : 'publication')}>
              <option value="publication">Published policy version</option>
              <option value="draft" disabled={!draft}>Open saved draft</option>
            </select>
          </label>
          {kind === 'publication' ? (
            <label className="rule-field"><span className="field-label">Version from policy history</span>
              <input className="rule-input" type="text" inputMode="numeric" value={version}
                onChange={(event) => setVersion(event.target.value)} />
            </label>
          ) : draft && (
            <p>{draft.summary.draft_id}, revision {draft.summary.revision}. {draftBlocked ?
              'Open a current, saved draft to package its evidence.' : 'The gateway will check the saved draft ETag.'}</p>
          )}
        </fieldset>
        <fieldset className="rule-fieldset workbench-options" disabled={busy}>
          <legend>Optional evidence</legend>
          <CheckboxOption label="Test suite from the Test tab" checked={tests && testsAvailable}
            disabled={!testsAvailable} onChange={setTests}
            hint={!canSimulate ? 'Requires admin:policy:simulate.' : 'Each case needs an expectation.'} />
          <CheckboxOption label="Synthetic cases from the Simulate tab" checked={simulate && simulationAvailable}
            disabled={!simulationAvailable} onChange={setSimulate}
            hint={!canSimulate ? 'Requires admin:policy:simulate.' : 'Includes 1 to 256 cases, evaluated as authored.'} />
          <CheckboxOption label="Structural analysis" checked={analysis && canAnalyze} disabled={!canAnalyze}
            onChange={setAnalysis} hint={!canAnalyze ? 'Requires admin:policy:analyze.' : undefined} />
          <label className="rule-field"><span className="field-label">Completed replay job ID</span>
            <input className="rule-input" value={replay} maxLength={64}
              disabled={!canReplay} onChange={(event) => setReplay(event.target.value)} />
          </label>
          {!canReplay && <p className="rule-hint">Requires admin:policy:simulate and admin:audit:read.</p>}
        </fieldset>
        <button type="submit" className="primary-button" disabled={!candidate || busy}>
          {busy ? 'Generating package…' : 'Generate evidence package'}
        </button>
      </form>
      {error && <p className="error-panel alert" role="alert">{error}</p>}
      {result && <EvidenceResult result={result} />}
    </section>
  );
}

function evidenceFailure(error: unknown): string {
  // The response can contain unreviewed diagnostic text, including values
  // from an intermediate proxy. Only fixed UI text and HTTP status are shown.
  if (!(error instanceof AdminApiError)) return 'The package could not be read for this candidate.';
  switch (error.status) {
    case 401: return 'Sign in again to generate evidence.';
    case 403: return 'This session cannot generate evidence with the selected sections.';
    case 404: case 410: return 'The selected candidate or replay job is unavailable.';
    case 409: case 412: return 'The candidate or replay binding changed. Review your selection and try again.';
    case 422: return 'The gateway could not generate a package from these inputs. Review the candidate and optional evidence.';
    case 429: return 'The gateway is already generating evidence. Try again after the current request finishes.';
    default: return `The gateway could not release the evidence package (HTTP ${error.status}).`;
  }
}

function EvidenceResult({ result }: { result: EvidencePackage }) {
  const [download, setDownload] = useState('');
  useEffect(() => {
    const url = URL.createObjectURL(result.packageBlob);
    setDownload(url);
    return () => URL.revokeObjectURL(url);
  }, [result]);
  return (
    <section className="workbench-results" aria-label="Evidence package">
      <h3>{result.subject}</h3>
      <p role="status">Evidence {result.completeness} · Unsigned</p>
      <p>{result.trustStatement}</p>
      {result.limitations.length > 0 && (
        <ul aria-label="Evidence limitations">
          {result.limitations.map((code) => <li key={code}><code>{code}</code></li>)}
        </ul>
      )}
      <p>Report digest <code>{result.digest}</code></p>
      <details className="workbench-stages rule-expression-box">
        <summary>Read the report</summary>
        <pre>{result.markdown}</pre>
      </details>
      {download && <a href={download} download={result.filename}>Download canonical JSON</a>}
      <p className="rule-hint">Check artifact integrity offline with <code>ggctl evidence verify {result.filename}</code>.</p>
    </section>
  );
}
