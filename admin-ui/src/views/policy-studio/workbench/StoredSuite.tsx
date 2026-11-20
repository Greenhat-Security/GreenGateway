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

// A save whose answer did not arrive, or arrived unreadable: what was sent,
// and the version stored before it (null for none), so a fresh read can tell
// what happened. The ETag alone cannot: it is the suite's semantic digest, so
// a save of the suite already stored is a new version under the same ETag.
type UnconfirmedSave = {
  sent: string;
  before: Readonly<{ etag: string; version: number }> | null;
};

// The stored suite version a run is pinned to. `version` is null when it is
// not known; `fromRefusal` marks the version that refused a publication.
export type StoredRunTarget = Readonly<{
  etag: string;
  version: number | null;
  fromRefusal?: boolean;
}>;

// What became of a stored run: it ran (or was refused with an answer shown),
// the stored suite is no longer the pinned version, or it could not start
// (the Test view says why).
export type StoredRunOutcome = 'ran' | 'changed' | 'blocked';

// A request from elsewhere (a publication the required suite refused) to run
// the stored suite against the candidate: pinned to the version that refused
// it when the refusal named one. `seq` changes with each request.
export type StoredRunRequest = Readonly<{
  seq: number;
  etag: string | null;
  version: number | null;
}>;

export const NO_STORED_RUN_REQUEST: StoredRunRequest = { seq: 0, etag: null, version: null };

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
  onStoredEtag,
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
  // Run the stored suite pinned to `target`.
  onRunStored: (target: StoredRunTarget) => Promise<StoredRunOutcome>;
  // The ETag of the stored suite each time a read or save settles it; null
  // when none is stored.
  onStoredEtag: (etag: string | null) => void;
  runRequest: StoredRunRequest;
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
  const handledRunRequest = useRef(runRequest.seq);
  // Focus: the button a cancelled confirmation returns to, and the answer
  // that replaces a confirmation once a save settles.
  const loadButton = useRef<HTMLButtonElement>(null);
  const saveButton = useRef<HTMLButtonElement>(null);
  const restoreFocusTo = useRef<'load' | 'save' | null>(null);
  const outcomeRef = useRef<HTMLDivElement>(null);
  const refusalRef = useRef<HTMLDivElement>(null);

  useEffect(() => () => controller.current?.abort(), []);

  useEffect(() => {
    if (confirming !== null || restoreFocusTo.current === null) return;
    (restoreFocusTo.current === 'load' ? loadButton : saveButton).current?.focus();
    restoreFocusTo.current = null;
  }, [confirming]);

  useEffect(() => {
    if (outcome !== null) outcomeRef.current?.focus();
  }, [outcome]);

  useEffect(() => {
    if (refusal !== null) refusalRef.current?.focus();
  }, [refusal]);

  const readStored = useCallback(async (): Promise<ReadState> => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    // A confirmation names what was read; a new read withdraws it.
    setConfirming(null);
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
    if (next.kind === 'stored') onStoredEtag(next.stored.etag);
    else if (next.kind === 'none') onStoredEtag(null);
    return next;
  }, [onStoredEtag]);

  useEffect(() => {
    if (active && canRead && read.kind === 'unread') {
      void readStored();
    }
  }, [active, canRead, read.kind, readStored]);

  // Asked from elsewhere (a publication the required suite refused): read
  // the stored suite as it is now, and run the version that refused the
  // publication when the refusal named it, otherwise the version read.
  useEffect(() => {
    if (runRequest.seq === handledRunRequest.current || !canRead) return;
    handledRunRequest.current = runRequest.seq;
    const { etag, version } = runRequest;
    void (async () => {
      const next = await readStored();
      if (etag !== null) {
        const ran = await onRunStored({ etag, version, fromRefusal: true });
        if (ran === 'changed') await readStored();
      } else if (next.kind === 'stored') {
        const ran = await onRunStored({ etag: next.stored.etag, version: next.stored.version });
        if (ran === 'changed') await readStored();
      } else if (next.kind === 'none') {
        setOutcome({
          title: 'Nothing to run',
          message:
            'No suite is stored beside the policy, so there is nothing to run. Store one with Save as the stored suite.',
          tone: 'warning',
        });
      }
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
    if (confirming === 'load') restoreFocusTo.current = 'load';
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

  function cancel() {
    restoreFocusTo.current = confirming;
    setConfirming(null);
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
    const before = stored === null ? null : { etag: stored.etag, version: stored.version };
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
      onStoredEtag(answer.stored.etag);
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
      } else if (error instanceof AdminApiError && error.status >= 400 && error.status < 500) {
        // A refusal: the gateway answered that nothing was stored.
        setOutcome(runAlert(error, 'Suite not stored', WRITE_PERMISSION));
      } else {
        // No answer, a server error, or a success this page could not read
        // (a 2xx without the stored suite's ETag or version): the suite may
        // or may not have been stored.
        setUnconfirmed({ sent, before });
        setOutcome({
          title: 'Save not confirmed',
          message:
            'The gateway did not confirm the save, so the suite may or may not have been stored. Nothing is sent again on your behalf: check the stored suite before saving again.',
          tone: 'error',
        });
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
    const { before, sent } = unconfirmed;
    setUnconfirmed(null);
    // Decided by version: the save could only have become the version after
    // the one it named.
    const unchanged =
      now === null
        ? before === null
        : before !== null && now.version === before.version && now.etag === before.etag;
    if (unchanged) {
      setOutcome({
        title: 'Not stored',
        message: 'Your save was not stored: the stored suite is unchanged. You can save again.',
        tone: 'info',
      });
    } else if (
      now !== null &&
      now.version === (before?.version ?? 0) + 1 &&
      sameSuite(now.source, sent)
    ) {
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
    const ran = await onRunStored({ etag: stored.etag, version: stored.version });
    if (ran === 'changed') await readStored();
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
          ref={loadButton}
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
          ref={saveButton}
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
        <LoadConfirmation
          stored={stored}
          onScreenCount={onScreenCount}
          onConfirm={load}
          onCancel={cancel}
        />
      ) : null}

      {confirming === 'save' && precondition !== null ? (
        <SaveConfirmation
          stored={stored}
          loadedIsStored={loadedIsStored}
          suiteSource={suiteSource}
          onConfirm={() => void save()}
          onCancel={cancel}
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
      {outcome !== null ? (
        <div ref={outcomeRef} tabIndex={-1}>
          <StudioAlertPanel alert={outcome} />
        </div>
      ) : null}
      {refusal !== null ? (
        <div ref={refusalRef} tabIndex={-1}>
          <RefusalPanel title="Suite not stored" refusal={refusal.refusal} cases={refusal.cases} />
        </div>
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

function kindName(kind: string): string {
  if (kind === 'unknown') return 'of an unknown kind';
  const label = caseKindLabel(kind);
  return label === 'Unknown kind' ? kind : label;
}

function countsText(counts: SuiteCaseCounts | null): string {
  if (counts === null) return 'not a suite';
  const kinds = counts.byKind.map((entry) => `${entry.count} ${kindName(entry.kind)}`).join(', ');
  return `${plural(counts.total, 'case')}${kinds ? ` (${kinds})` : ''}`;
}

// Where the cases on screen hold fewer cases than the stored suite, in all
// or of any kind; empty when none.
function fewerCases(stored: SuiteCaseCounts | null, onScreen: SuiteCaseCounts | null): string[] {
  if (stored === null || onScreen === null) return [];
  const fewer: string[] = [];
  if (onScreen.total < stored.total) {
    fewer.push(`${onScreen.total} instead of ${stored.total} in all`);
  }
  for (const entry of stored.byKind) {
    const now = onScreen.byKind.find((other) => other.kind === entry.kind)?.count ?? 0;
    if (now < entry.count) fewer.push(`${now} instead of ${entry.count} ${kindName(entry.kind)}`);
  }
  return fewer;
}

function activeStatusText(status: string | null): string {
  if (status === null) return '';
  if (status === 'passed') {
    return 'The live policy passes the suite just stored.';
  }
  return `The live policy does not pass the suite just stored (${status.replace(/_/g, ' ')}). Storing it changed nothing live, but the next policy publication must pass it.`;
}

function LoadConfirmation({
  stored,
  onScreenCount,
  onConfirm,
  onCancel,
}: {
  stored: StoredPolicyTests;
  onScreenCount: number | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
  }, []);
  return (
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
        <button ref={confirmRef} type="button" className="primary-button" onClick={onConfirm}>
          Replace them with the stored suite
        </button>
        <button type="button" className="secondary-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
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
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
  }, []);
  const storedCounts = stored === null ? null : suiteCaseCounts(stored.source);
  const onScreenCounts = suiteCaseCounts(suiteSource);
  const fewer = fewerCases(storedCounts, onScreenCounts);
  return (
    <div
      className="policy-studio-confirmation"
      role="group"
      aria-label="Store these cases as the suite?"
    >
      {stored === null ? (
        <p>No suite is stored: these cases become the first version.</p>
      ) : (
        <>
          {loadedIsStored ? (
            <p>
              Replaces stored version {stored.version}, which the cases on screen were loaded from
              and have been edited since. Compare them before you store:
            </p>
          ) : (
            <p className="alert warning">
              Saving replaces stored version {stored.version}, which the cases on screen were not
              loaded from. Compare them before you store:
            </p>
          )}
          <ul>
            <li>{`Stored version ${stored.version}: ${countsText(storedCounts)}.`}</li>
            <li>{`On screen: ${countsText(onScreenCounts)}.`}</li>
          </ul>
          {fewer.length > 0 ? (
            <p className="alert warning">
              {`The cases on screen hold fewer cases than stored version ${stored.version}: ${fewer.join(', ')}.`}
            </p>
          ) : null}
        </>
      )}
      <p className="rule-hint">
        Storing a suite changes no enforcement now. Where this gateway requires the stored suite
        (POLICY_TESTS_REQUIRED), every later policy publication must pass the suite you store, so
        replacing it with fewer or weaker cases loosens that gate. Each save is a new version;
        nothing is edited in place.
      </p>
      <div className="form-actions">
        <button ref={confirmRef} type="button" className="primary-button" onClick={onConfirm}>
          Store the suite
        </button>
        <button type="button" className="secondary-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
