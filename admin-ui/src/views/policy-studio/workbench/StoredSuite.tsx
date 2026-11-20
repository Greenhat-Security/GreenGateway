import { useCallback, useEffect, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import type { PolicyRunRefusal } from '../../../lib/policyRuns';
import {
  POLICY_TESTS_ETAG_MISMATCH_REASON,
  POLICY_TESTS_EXIST_REASON,
  fetchStoredPolicyTests,
  sameSuite,
  storePolicyTests,
  suiteCaseCounts,
  type PolicyTestsPrecondition,
  type StoredPolicyTests,
  type SuiteCaseCounts,
} from '../../../lib/policyTests';
import { shortEtag, type JsonObject } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { RefusalPanel, RunBlockers, isAbort, plural, runAlert } from './common';
import { caseKindLabel, parseSuite } from './suite';

const WRITE_PERMISSION = 'admin:policy:write';

type ReadState =
  | { kind: 'unread' }
  | { kind: 'reading' }
  | { kind: 'none' }
  | { kind: 'stored'; stored: StoredPolicyTests }
  | { kind: 'failed'; alert: StudioAlert };

// A save whose answer did not arrive: what was sent, and the ETag stored
// before it (null for none), so a fresh read can tell what happened.
type UnconfirmedSave = { sent: string; before: string | null };

// The stored suite beside the policy, in the Test view: read it, load it
// into the cases on screen, run it by reference, or store the cases on
// screen as its next version under the exact precondition. A save whose
// answer is lost is resolved by reading the stored suite, never by sending
// it again. Nothing here is kept in browser storage.
export function StoredSuite({
  active,
  canRead,
  canWrite,
  suiteSource,
  onSuiteChange,
  runBlockers,
  running,
  onRunStored,
  runRequest,
}: {
  // Whether the Test view is shown: the suite is first read then.
  active: boolean;
  // admin:policy:read and admin:policy:simulate, which reading needs.
  canRead: boolean;
  canWrite: boolean;
  suiteSource: string;
  onSuiteChange: (source: string) => void;
  // Why a run cannot start now, from the Test view.
  runBlockers: readonly string[];
  running: boolean;
  // Run the stored suite pinned to `stored`; resolves to whether the gateway
  // answered that the stored suite is no longer that version.
  onRunStored: (stored: StoredPolicyTests) => Promise<boolean>;
  // Bumped to read the stored suite again and run it at once.
  runRequest: number;
}) {
  const headingId = useId();
  const statusId = useId();
  const saveBlockersId = useId();
  const runBlockersId = useId();
  const [read, setRead] = useState<ReadState>({ kind: 'unread' });
  // The version the cases on screen were loaded from or saved as.
  const [loaded, setLoaded] = useState<StoredPolicyTests | null>(null);
  const [confirming, setConfirming] = useState<'load' | 'save' | null>(null);
  const [saving, setSaving] = useState(false);
  const [unconfirmed, setUnconfirmed] = useState<UnconfirmedSave | null>(null);
  const [outcome, setOutcome] = useState<StudioAlert | null>(null);
  const [refusal, setRefusal] = useState<{ refusal: PolicyRunRefusal; cases: readonly JsonObject[] } | null>(null);
  const controller = useRef<AbortController | null>(null);
  const handledRunRequest = useRef(runRequest);

  useEffect(() => () => controller.current?.abort(), []);

  const readStored = useCallback(async (): Promise<ReadState> => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setRead({ kind: 'reading' });
    let next: ReadState;
    try {
      const answer = await fetchStoredPolicyTests(current.signal);
      next = answer.kind === 'none' ? { kind: 'none' } : { kind: 'stored', stored: answer };
    } catch (error) {
      if (isAbort(error) || current.signal.aborted) return { kind: 'unread' };
      next = {
        kind: 'failed',
        alert: runAlert(error, 'Stored suite unavailable', 'admin:policy:read and admin:policy:simulate'),
      };
    }
    if (controller.current === current) controller.current = null;
    setRead(next);
    return next;
  }, []);

  useEffect(() => {
    if (active && canRead && read.kind === 'unread') {
      void readStored();
    }
  }, [active, canRead, read.kind, readStored]);

  // Asked from elsewhere (a publication the required suite refused): read
  // the stored suite as it is now and run it against the candidate.
  useEffect(() => {
    if (runRequest === handledRunRequest.current || !canRead) return;
    handledRunRequest.current = runRequest;
    void (async () => {
      const next = await readStored();
      if (next.kind === 'stored') await onRunStored(next.stored);
    })();
  }, [runRequest, canRead, readStored, onRunStored]);

  if (!canRead) {
    return (
      <section className="workbench-stored-suite" aria-labelledby={headingId}>
        <h4 id={headingId}>Stored suite</h4>
        <p className="rule-hint">
          Reading or running the stored suite needs admin:policy:read and admin:policy:simulate,
          which this session does not hold.
        </p>
      </section>
    );
  }

  const parsed = parseSuite(suiteSource);
  const onScreenCount = parsed.ok ? parsed.cases.length : null;
  const stored = read.kind === 'stored' ? read.stored : null;
  const loadedIsStored = stored !== null && loaded !== null && loaded.etag === stored.etag;
  const editedSinceLoad = loaded !== null && !sameSuite(suiteSource, loaded.source);
  const busy = saving || read.kind === 'reading';

  const saveBlockers: string[] = [];
  if (!canWrite) saveBlockers.push(`Storing the suite needs ${WRITE_PERMISSION}.`);
  if (unconfirmed !== null) {
    saveBlockers.push('Check the stored suite first: the last save was not confirmed.');
  } else if (read.kind !== 'none' && read.kind !== 'stored') {
    saveBlockers.push('Read the stored suite first, so a save names the version it replaces.');
  }
  if (!parsed.ok) saveBlockers.push('Fix the suite source first.');
  else if (parsed.cases.length === 0) saveBlockers.push('Add a case first.');
  if (loadedIsStored && !editedSinceLoad) {
    saveBlockers.push('The cases on screen are the stored suite.');
  }

  const storedRunBlockers = [...runBlockers];
  if (stored === null) storedRunBlockers.push('There is no stored suite to run.');
  // With no stored suite, the status line already says why.
  const showRunBlockers = stored !== null && storedRunBlockers.length > 0;

  function load() {
    if (stored === null) return;
    onSuiteChange(stored.source);
    setLoaded(stored);
    setConfirming(null);
    setOutcome(null);
    setRefusal(null);
  }

  function askToLoad() {
    if (stored === null) return;
    const holdsCases = !parsed.ok || parsed.cases.length > 0;
    if (holdsCases && !sameSuite(suiteSource, stored.source)) {
      setConfirming('load');
    } else {
      load();
    }
  }

  // The precondition a save sends: the first suite when the read said none
  // is stored; otherwise exactly the version the confirmation names.
  const precondition: PolicyTestsPrecondition | null =
    read.kind === 'none'
      ? { kind: 'first' }
      : stored !== null
        ? { kind: 'replace', etag: stored.etag }
        : null;

  async function save() {
    if (precondition === null || saveBlockers.length > 0 || busy) return;
    const sent = suiteSource;
    const before = stored?.etag ?? null;
    setConfirming(null);
    setSaving(true);
    setOutcome(null);
    setRefusal(null);
    try {
      const answer = await storePolicyTests({ source: sent, precondition });
      if (answer.kind === 'refused') {
        setRefusal({ refusal: answer.refusal, cases: parsed.ok ? parsed.cases : [] });
        return;
      }
      setRead({ kind: 'stored', stored: answer.stored });
      setLoaded(answer.stored);
      setOutcome({
        title: answer.created ? 'Suite stored' : 'Suite replaced',
        message: `Stored as version ${answer.stored.version}. ${activeStatusText(answer.activeStatus)}`,
        tone: answer.activeStatus === null || answer.activeStatus === 'passed' ? 'info' : 'warning',
      });
    } catch (error) {
      if (
        error instanceof AdminApiError &&
        error.status === 412 &&
        (error.code === POLICY_TESTS_ETAG_MISMATCH_REASON || error.code === POLICY_TESTS_EXIST_REASON)
      ) {
        // Someone stored another version: keep the cases on screen, show
        // what is stored now, and make the next save name it explicitly.
        setLoaded(null);
        setOutcome({
          title: 'Stored suite changed',
          message:
            'The stored suite changed since it was read here, so nothing was stored. The cases on screen are kept. Review the version stored now: load it to see it, or save again to replace it.',
          tone: 'warning',
        });
        await readStored();
      } else if (!(error instanceof AdminApiError) || error.status >= 500) {
        setUnconfirmed({ sent, before });
        setOutcome({
          title: 'Save not confirmed',
          message:
            'The gateway did not confirm the save, so the suite may or may not have been stored. Nothing is sent again on your behalf: check the stored suite before saving again.',
          tone: 'error',
        });
      } else {
        setOutcome(runAlert(error, 'Suite not stored', WRITE_PERMISSION));
      }
    } finally {
      setSaving(false);
    }
  }

  async function checkUnconfirmed() {
    if (unconfirmed === null) return;
    const next = await readStored();
    if (next.kind === 'failed') {
      setOutcome({ ...next.alert, message: `${next.alert.message} The save is still not confirmed.` });
      return;
    }
    if (next.kind !== 'none' && next.kind !== 'stored') return;
    const now = next.kind === 'stored' ? next.stored : null;
    setUnconfirmed(null);
    if ((now?.etag ?? null) === unconfirmed.before) {
      setOutcome({
        title: 'Not stored',
        message: 'Your save was not stored: the stored suite is unchanged. You can save again.',
        tone: 'info',
      });
    } else if (now !== null && sameSuite(now.source, unconfirmed.sent)) {
      setLoaded(now);
      setOutcome({
        title: 'Suite stored',
        message: `Your save was stored as version ${now.version}.`,
        tone: 'info',
      });
    } else {
      setLoaded(null);
      setOutcome({
        title: 'Stored suite changed',
        message: `The stored suite changed, possibly after your save, and is not the suite on screen${now !== null ? `: it is now version ${now.version}` : ''}. Load it before saving again.`,
        tone: 'warning',
      });
    }
  }

  async function runStored() {
    if (stored === null || storedRunBlockers.length > 0 || running) return;
    const changed = await onRunStored(stored);
    if (changed) await readStored();
  }

  return (
    <section className="workbench-stored-suite" aria-labelledby={headingId}>
      <h4 id={headingId}>Stored suite</h4>
      <p className="rule-hint">
        The gateway keeps at most one suite beside the policy, versioned. Storing one changes no
        enforcement now; where the gateway requires the stored suite, every policy publication
        must pass it. Nothing here is kept in the browser.
      </p>
      <p id={statusId} className="policy-studio-validation-status" role="status" aria-live="polite">
        {statusText(read, loaded, editedSinceLoad)}
      </p>
      {read.kind === 'failed' ? <StudioAlertPanel alert={read.alert} /> : null}

      <div className="form-actions">
        <button
          type="button"
          className="secondary-button"
          disabled={busy || unconfirmed !== null}
          onClick={() => void readStored()}
        >
          {read.kind === 'unread' ? 'Read the stored suite' : 'Read the stored suite again'}
        </button>
        <button
          type="button"
          className="secondary-button"
          disabled={stored === null || busy || confirming !== null}
          onClick={askToLoad}
        >
          Load the stored suite
        </button>
        <button
          type="button"
          className="secondary-button"
          disabled={storedRunBlockers.length > 0 || running || busy}
          aria-describedby={showRunBlockers ? runBlockersId : undefined}
          onClick={() => void runStored()}
        >
          Run the stored suite
        </button>
        <button
          type="button"
          className="secondary-button"
          disabled={saveBlockers.length > 0 || busy || confirming !== null}
          aria-describedby={saveBlockers.length > 0 ? saveBlockersId : undefined}
          onClick={() => setConfirming('save')}
        >
          {saving ? 'Storing the suite' : 'Save as the stored suite'}
        </button>
      </div>
      {showRunBlockers ? (
        <RunBlockers id={runBlockersId} blockers={storedRunBlockers} />
      ) : null}
      {saveBlockers.length > 0 ? (
        <div className="policy-studio-blockers" id={saveBlockersId}>
          <p className="rule-hint">Saving is unavailable:</p>
          <ul>
            {saveBlockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {confirming === 'load' && stored !== null ? (
        <div className="policy-studio-confirmation" role="group" aria-label="Replace the cases on screen?">
          <p>
            {onScreenCount === null
              ? 'The suite source on screen is not a suite.'
              : `${plural(onScreenCount, 'case')} on screen.`}{' '}
            Loading replaces them with stored version {stored.version} (
            {plural(suiteCaseCounts(stored.source)?.total ?? 0, 'case')}). The cases on screen are
            not kept anywhere.
          </p>
          <div className="form-actions">
            <button type="button" className="primary-button" onClick={load}>
              Replace them with the stored suite
            </button>
            <button type="button" className="secondary-button" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {confirming === 'save' && precondition !== null ? (
        <SaveConfirmation
          stored={stored}
          loadedIsStored={loadedIsStored}
          suiteSource={suiteSource}
          onConfirm={() => void save()}
          onCancel={() => setConfirming(null)}
        />
      ) : null}

      {unconfirmed !== null ? (
        <div className="form-actions">
          <button
            type="button"
            className="secondary-button"
            disabled={read.kind === 'reading'}
            onClick={() => void checkUnconfirmed()}
          >
            Check the stored suite
          </button>
        </div>
      ) : null}
      {outcome !== null ? <StudioAlertPanel alert={outcome} /> : null}
      {refusal !== null ? (
        <RefusalPanel title="Suite not stored" refusal={refusal.refusal} cases={refusal.cases} />
      ) : null}
    </section>
  );
}

function statusText(read: ReadState, loaded: StoredPolicyTests | null, edited: boolean): string {
  switch (read.kind) {
    case 'unread':
      return 'The stored suite has not been read.';
    case 'reading':
      return 'Reading the stored suite.';
    case 'failed':
      return 'The stored suite could not be read.';
    case 'none':
      return 'No suite is stored beside the policy.';
    case 'stored': {
      const { stored } = read;
      const counts = suiteCaseCounts(stored.source);
      const head = `Stored suite: version ${stored.version} (${shortEtag(stored.etag)}), ${plural(counts?.total ?? 0, 'case')}.`;
      if (loaded === null) {
        return `${head} The cases on screen were not loaded from it.`;
      }
      if (loaded.etag !== stored.etag) {
        return `${head} The cases on screen were loaded from version ${loaded.version}, and the stored suite has changed since.`;
      }
      return `${head} The cases on screen were loaded from version ${stored.version}${edited ? ', and edited since' : ''}.`;
    }
  }
}

function countsText(counts: SuiteCaseCounts | null): string {
  if (counts === null) return 'not a suite';
  const kindName = (kind: string) => {
    if (kind === 'unknown') return 'of an unknown kind';
    const label = caseKindLabel(kind);
    return label === 'Unknown kind' ? kind : label;
  };
  const kinds = counts.byKind.map((entry) => `${entry.count} ${kindName(entry.kind)}`).join(', ');
  return `${plural(counts.total, 'case')}${kinds ? ` (${kinds})` : ''}`;
}

function activeStatusText(status: string | null): string {
  if (status === null) return '';
  if (status === 'passed') {
    return 'The live policy passes the suite just stored.';
  }
  return `The live policy does not pass the suite just stored (${status.replace(/_/g, ' ')}). Storing it changed nothing live, but the next policy publication must pass it.`;
}

function SaveConfirmation({
  stored,
  loadedIsStored,
  suiteSource,
  onConfirm,
  onCancel,
}: {
  stored: StoredPolicyTests | null;
  loadedIsStored: boolean;
  suiteSource: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div
      className="policy-studio-confirmation"
      role="group"
      aria-label="Store these cases as the suite?"
    >
      {stored === null ? (
        <p>No suite is stored: these cases become the first version.</p>
      ) : loadedIsStored ? (
        <p>
          Replaces stored version {stored.version}, which the cases on screen were loaded from.
        </p>
      ) : (
        <>
          <p className="alert warning">
            Saving replaces stored version {stored.version}, which the cases on screen were not
            loaded from. Compare them before you store:
          </p>
          <ul>
            <li>{`Stored version ${stored.version}: ${countsText(suiteCaseCounts(stored.source))}.`}</li>
            <li>{`On screen: ${countsText(suiteCaseCounts(suiteSource))}.`}</li>
          </ul>
        </>
      )}
      <p className="rule-hint">
        Storing a suite changes no enforcement now. Where this gateway requires the stored suite
        (POLICY_TESTS_REQUIRED), every later policy publication must pass the suite you store, so
        replacing it with fewer or weaker cases loosens that gate. Each save is a new version;
        nothing is edited in place.
      </p>
      <div className="form-actions">
        <button type="button" className="primary-button" onClick={onConfirm}>
          Store the suite
        </button>
        <button type="button" className="secondary-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
