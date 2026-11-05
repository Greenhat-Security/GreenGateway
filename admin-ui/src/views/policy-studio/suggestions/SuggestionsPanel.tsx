import { useEffect, useId, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import {
  SuggestionConflictError,
  dismissSuggestion,
  locateSuggestion,
  type RuleSuggestion,
} from '../../../lib/suggestions';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { isAbort } from '../workbench/common';
import {
  draftedActionText,
  evidenceAvailabilityText,
  evidenceFacts,
  freshnessText,
  principalText,
  routingFacts,
  sourceText,
  stateLabels,
  targetText,
  type SuggestionMark,
} from './model';
import type { SuggestionFilter, SuggestionListHandle } from './useSuggestionList';

// Where Review in draft writes the rule: a new draft copied from the live
// policy, or the draft open in the Studio.
export type ReviewInto = 'new' | 'open';

// What to read again after a review request whose answer was lost: the
// drafts listed before it, and the draft it named.
export type ReviewVerification = Readonly<{
  into: ReviewInto;
  knownDraftIds: readonly string[];
  target: Readonly<{ draftId: string; revision: number }> | null;
}>;

export type ReviewOutcome =
  | Readonly<{ kind: 'opened' }>
  | Readonly<{
      kind: 'problem';
      alert: StudioAlert;
      // The suggestion as the gateway answered it, when that answer moved it.
      current?: RuleSuggestion;
      mark?: SuggestionMark;
      // The open draft already holds the rule; it can be bound instead.
      offerBind?: boolean;
      // Drafts that appeared while the outcome was unknown.
      newDrafts?: readonly string[];
      // Offer reading the authoritative state again.
      verification?: ReviewVerification;
      refresh?: boolean;
    }>;

type RowAlert = Readonly<{
  alert: StudioAlert;
  offerBind: boolean;
  newDrafts: readonly string[];
  verification: ReviewVerification | null;
  dismissCheck: RuleSuggestion | null;
}>;

const FILTERS: ReadonlyArray<{ value: SuggestionFilter; label: string }> = [
  { value: 'open', label: 'Open' },
  { value: 'accepted', label: 'Accepted' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'all', label: 'All states' },
];

const GENERATOR_VERSION_TEXT = 'Not recorded by this gateway';

export function SuggestionsPanel({
  handle,
  canList,
  canDismiss,
  reviewBlockers,
  into,
  onIntoChange,
  openDraft,
  positions,
  bindings,
  busy,
  onReview,
  onVerifyReview,
  onBind,
  onOpenDraft,
}: {
  handle: SuggestionListHandle;
  canList: boolean;
  canDismiss: boolean;
  // Why Review in draft is unavailable for every suggestion now.
  reviewBlockers: readonly string[];
  into: ReviewInto;
  onIntoChange: (into: ReviewInto) => void;
  // The draft open in the Studio, and why it cannot take a rule, if not.
  openDraft: Readonly<{ id: string; revision: number; blocker: string | null }> | null;
  // Where the gateway appends a drafted rule: after the last rule of the
  // live policy, or of the open draft's saved candidate.
  positions: Readonly<{ live: number | null; open: number | null }>;
  // Suggestion id to the id of the draft in this page that holds its rule.
  bindings: ReadonlyMap<string, string>;
  busy: boolean;
  onReview: (suggestion: RuleSuggestion, into: ReviewInto) => Promise<ReviewOutcome>;
  onVerifyReview: (verification: ReviewVerification) => Promise<ReviewOutcome>;
  onBind: (suggestion: RuleSuggestion) => void;
  onOpenDraft: (id: string) => void;
}) {
  const headingId = useId();
  const filterId = useId();
  const { list } = handle;
  const [pending, setPending] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<ReadonlyMap<string, RowAlert>>(new Map());
  const [confirmingDismiss, setConfirmingDismiss] = useState<string | null>(null);
  const dismissButtons = useRef(new Map<string, HTMLButtonElement>());
  const restoreDismissFocus = useRef<string | null>(null);
  const openUsable = openDraft !== null && openDraft.blocker === null;
  const effectiveInto: ReviewInto = into === 'open' && openDraft !== null ? 'open' : 'new';

  useEffect(() => {
    if (confirmingDismiss === null && restoreDismissFocus.current !== null) {
      dismissButtons.current.get(restoreDismissFocus.current)?.focus();
      restoreDismissFocus.current = null;
    }
  }, [confirmingDismiss]);

  function setRowAlert(id: string, alert: RowAlert | null) {
    setAlerts((current) => {
      const next = new Map(current);
      if (alert === null) next.delete(id);
      else next.set(id, alert);
      return next;
    });
  }

  function rowAlert(alert: StudioAlert, extra: Partial<RowAlert> = {}): RowAlert {
    return {
      alert,
      offerBind: false,
      newDrafts: [],
      verification: null,
      dismissCheck: null,
      ...extra,
    };
  }

  function applyOutcome(listed: RuleSuggestion, outcome: ReviewOutcome) {
    if (outcome.kind === 'opened') {
      setRowAlert(listed.id, null);
      return;
    }
    if (outcome.current !== undefined) {
      const moved =
        outcome.current.revision !== listed.revision || outcome.current.state !== listed.state;
      handle.update(
        outcome.current,
        outcome.mark ??
          (moved
            ? { kind: 'changed', listedRevision: listed.revision, listedState: listed.state }
            : null),
      );
    } else if (outcome.mark !== undefined) {
      handle.mark(listed.id, outcome.mark);
    }
    setRowAlert(
      listed.id,
      rowAlert(outcome.alert, {
        offerBind: outcome.offerBind ?? false,
        newDrafts: outcome.newDrafts ?? [],
        verification: outcome.verification ?? null,
      }),
    );
    if (outcome.refresh) {
      void handle.refresh();
    }
  }

  async function review(suggestion: RuleSuggestion) {
    if (pending !== null) return;
    setPending(suggestion.id);
    setRowAlert(suggestion.id, null);
    try {
      applyOutcome(suggestion, await onReview(suggestion, effectiveInto));
    } finally {
      setPending(null);
    }
  }

  async function verifyReview(suggestion: RuleSuggestion, verification: ReviewVerification) {
    if (pending !== null) return;
    setPending(suggestion.id);
    try {
      applyOutcome(suggestion, await onVerifyReview(verification));
    } finally {
      setPending(null);
    }
  }

  async function dismiss(suggestion: RuleSuggestion) {
    if (pending !== null) return;
    setConfirmingDismiss(null);
    setPending(suggestion.id);
    setRowAlert(suggestion.id, null);
    try {
      const dismissed = await dismissSuggestion(suggestion.id, suggestion.revision);
      handle.update(dismissed, null);
      setRowAlert(
        suggestion.id,
        rowAlert({
          title: 'Suggestion dismissed',
          message: `Revision ${dismissed.revision} is dismissed. The policy is unchanged.`,
          tone: 'info',
        }),
      );
    } catch (error) {
      if (isAbort(error)) return;
      if (error instanceof SuggestionConflictError) {
        const current = error.current;
        if (current !== null) {
          handle.update(current, {
            kind: 'changed',
            listedRevision: suggestion.revision,
            listedState: suggestion.state,
          });
        }
        setRowAlert(
          suggestion.id,
          rowAlert({
            title: 'Not dismissed',
            message:
              current !== null
                ? `The suggestion changed since it was listed: the gateway now holds revision ${current.revision}, ${current.state}. Nothing was changed; review it as it is now.`
                : `${error.message}. Nothing was changed.`,
            tone: 'warning',
          }),
        );
      } else if (error instanceof AdminApiError && error.status < 500) {
        if (error.status === 404) handle.mark(suggestion.id, { kind: 'gone' });
        setRowAlert(suggestion.id, rowAlert(dismissRefusal(error)));
      } else if (error instanceof AdminApiError && error.status === 503) {
        setRowAlert(
          suggestion.id,
          rowAlert({
            title: 'Not dismissed: the gateway is unavailable',
            message:
              'The gateway could not settle the suggestion’s pending acceptances (503), so it changed nothing. The suggestions are read again; nothing is sent again.',
            tone: 'error',
          }),
        );
        void handle.refresh();
      } else {
        // The answer was lost, or a server error came after the request may
        // have been carried out: read what the gateway holds, never resend.
        await verifyDismiss(suggestion, true);
      }
    } finally {
      setPending(null);
    }
  }

  async function verifyDismiss(sent: RuleSuggestion, first: boolean) {
    const prefix = first
      ? 'The gateway did not confirm the dismissal, so it was read again instead of being sent again. '
      : '';
    try {
      const located = await locateSuggestion(sent.id);
      if (located.kind === 'gone') {
        handle.mark(sent.id, { kind: 'gone' });
        setRowAlert(
          sent.id,
          rowAlert({
            title: 'Suggestion gone',
            message: `${prefix}The gateway no longer lists this suggestion.`,
            tone: 'warning',
          }),
        );
      } else if (located.kind === 'unknown') {
        setRowAlert(
          sent.id,
          rowAlert(
            {
              title: 'Outcome unknown',
              message: `${prefix}The suggestion was not among the newest suggestions the Studio reads, so its state is not established. Check again before dismissing it again.`,
              tone: 'warning',
            },
            { dismissCheck: sent },
          ),
        );
      } else if (located.suggestion.state === 'dismissed') {
        handle.update(located.suggestion, null);
        setRowAlert(
          sent.id,
          rowAlert({
            title: 'Suggestion dismissed',
            message: `${prefix}The gateway holds it dismissed at revision ${located.suggestion.revision}.`,
            tone: 'info',
          }),
        );
      } else if (
        located.suggestion.state === 'open' &&
        located.suggestion.revision === sent.revision
      ) {
        setRowAlert(
          sent.id,
          rowAlert(
            {
              title: 'Not dismissed as of now',
              message: `${prefix}The gateway still holds it open at revision ${sent.revision}. The request may still be in progress: check again before dismissing it again.`,
              tone: 'warning',
            },
            { dismissCheck: sent },
          ),
        );
      } else {
        handle.update(located.suggestion, {
          kind: 'changed',
          listedRevision: sent.revision,
          listedState: sent.state,
        });
        setRowAlert(
          sent.id,
          rowAlert({
            title: 'Suggestion changed',
            message: `${prefix}The gateway now holds revision ${located.suggestion.revision}, ${located.suggestion.state}.`,
            tone: 'warning',
          }),
        );
      }
    } catch (error) {
      if (isAbort(error)) return;
      setRowAlert(
        sent.id,
        rowAlert(
          {
            title: 'Outcome unknown',
            message: `${prefix}The suggestions could not be read either. Check again when the connection is back, before dismissing it again.`,
            tone: 'error',
          },
          { dismissCheck: sent },
        ),
      );
    }
  }

  async function checkDismiss(sent: RuleSuggestion) {
    if (pending !== null) return;
    setPending(sent.id);
    try {
      await verifyDismiss(sent, false);
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="workbench-panel policy-studio-suggestions" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Discovery</p>
          <h3 id={headingId}>Suggestions</h3>
        </div>
        {canList && list.loadedAt !== null ? (
          <span className="result-count">
            {list.rows.length}
            {list.nextCursor !== null ? '+' : ''} {list.rows.length === 1 ? 'suggestion' : 'suggestions'}
          </span>
        ) : null}
      </div>
      <div className="error-panel alert info" role="note">
        <h3>Suggestions change nothing by themselves</h3>
        <p>
          Review in draft writes the rule a suggestion proposes into a server-side draft, opens
          it in the editors, and checks it there with validation, a simulation of the traffic it
          describes and the policy analyzer. The live policy and the suggestion stay as they
          are. The suggestion is accepted only when that draft is published with it, after the
          ordinary publish review; there is no direct apply.
        </p>
      </div>

      {!canList ? (
        <StudioAlertPanel
          alert={{
            title: 'Suggestions permission required',
            message: 'Listing suggestions needs admin:suggestions:read.',
            tone: 'warning',
          }}
        />
      ) : (
        <>
          <div className="workbench-controls policy-studio-suggestion-controls">
            <div className="rule-field">
              <label htmlFor={filterId}>Show</label>
              <select
                id={filterId}
                value={list.filter}
                disabled={list.loading}
                onChange={(event) => handle.setFilter(event.target.value as SuggestionFilter)}
              >
                {FILTERS.map((filter) => (
                  <option key={filter.value} value={filter.value}>
                    {filter.label}
                  </option>
                ))}
              </select>
            </div>
            <fieldset className="rule-fieldset policy-studio-suggestion-target">
              <legend>Review in</legend>
              <label className="policy-studio-suggestion-choice">
                <input
                  type="radio"
                  name="policy-studio-suggestion-target"
                  value="new"
                  checked={effectiveInto === 'new'}
                  onChange={() => onIntoChange('new')}
                />
                A new draft from the live policy
              </label>
              <label className="policy-studio-suggestion-choice">
                <input
                  type="radio"
                  name="policy-studio-suggestion-target"
                  value="open"
                  checked={effectiveInto === 'open'}
                  disabled={openDraft === null}
                  aria-describedby={openDraft !== null && !openUsable ? `${filterId}-open-blocker` : undefined}
                  onChange={() => onIntoChange('open')}
                />
                {openDraft === null
                  ? 'The open draft (none is open)'
                  : `The open draft ${openDraft.id}, revision ${openDraft.revision}`}
              </label>
              {openDraft !== null && openDraft.blocker !== null ? (
                <p className="rule-hint" id={`${filterId}-open-blocker`}>
                  {openDraft.blocker}
                </p>
              ) : null}
            </fieldset>
            <div className="form-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={list.loading || pending !== null}
                onClick={() => void handle.refresh()}
              >
                {list.loading ? 'Reading suggestions' : 'Read suggestions again'}
              </button>
            </div>
          </div>
          <p className="rule-hint" role="status" aria-live="polite">
            {list.loading
              ? 'Reading the suggestions from the gateway.'
              : list.loadedAt !== null
                ? `Listed at ${list.loadedAt}, as of the gateway’s most recent generation run. The list is read again only when you ask, or after an answer that may have moved a suggestion.`
                : ''}
          </p>
          <p className="rule-hint">
            Listing does not recompute a suggestion, and the gateway records no policy revision,
            resource snapshot, evidence schema or generator version with one. So a listed
            suggestion is not known to fit the live policy until it is opened in a draft, which
            checks it against the live policy and current routing and refuses it, writing nothing,
            when it no longer fits.
          </p>
          {list.alert !== null ? <StudioAlertPanel alert={list.alert} /> : null}
          {list.loadedAt !== null && list.rows.length === 0 && !list.loading ? (
            <p className="empty-state">
              {list.filter === 'open'
                ? 'No open suggestions. Suggestions appear after the gateway’s suggestion generator runs; an empty list is not a finding that the policy needs no change.'
                : 'No suggestions in this state.'}
            </p>
          ) : null}
          {list.rows.length > 0 ? (
            <ol className="policy-studio-suggestion-list" aria-label="Suggestions">
              {list.rows.map((suggestion) => (
                <SuggestionRow
                  key={suggestion.id}
                  suggestion={suggestion}
                  mark={list.marks.get(suggestion.id) ?? null}
                  alert={alerts.get(suggestion.id) ?? null}
                  boundDraft={bindings.get(suggestion.id) ?? null}
                  openDraftId={openDraft?.id ?? null}
                  into={effectiveInto}
                  position={effectiveInto === 'open' ? positions.open : positions.live}
                  reviewBlockers={[
                    ...reviewBlockers,
                    ...(effectiveInto === 'open' && openDraft?.blocker ? [openDraft.blocker] : []),
                  ]}
                  canDismiss={canDismiss}
                  busy={busy || pending !== null}
                  pending={pending === suggestion.id}
                  confirmingDismiss={confirmingDismiss === suggestion.id}
                  dismissRef={(element) => {
                    if (element) dismissButtons.current.set(suggestion.id, element);
                    else dismissButtons.current.delete(suggestion.id);
                  }}
                  onReview={() => void review(suggestion)}
                  onAskDismiss={() => setConfirmingDismiss(suggestion.id)}
                  onCancelDismiss={() => {
                    restoreDismissFocus.current = suggestion.id;
                    setConfirmingDismiss(null);
                  }}
                  onDismiss={() => void dismiss(suggestion)}
                  onBind={() => {
                    onBind(suggestion);
                    setRowAlert(suggestion.id, null);
                  }}
                  onOpenDraft={onOpenDraft}
                  onVerifyReview={(verification) => void verifyReview(suggestion, verification)}
                  onCheckDismiss={(sent) => void checkDismiss(sent)}
                  onCloseAlert={() => setRowAlert(suggestion.id, null)}
                />
              ))}
            </ol>
          ) : null}
          {list.nextCursor !== null ? (
            <div className="form-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={list.loading}
                onClick={() => void handle.loadMore()}
              >
                Show more suggestions
              </button>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}

function SuggestionRow({
  suggestion,
  mark,
  alert,
  boundDraft,
  openDraftId,
  into,
  position,
  reviewBlockers,
  canDismiss,
  busy,
  pending,
  confirmingDismiss,
  dismissRef,
  onReview,
  onAskDismiss,
  onCancelDismiss,
  onDismiss,
  onBind,
  onOpenDraft,
  onVerifyReview,
  onCheckDismiss,
  onCloseAlert,
}: {
  suggestion: RuleSuggestion;
  mark: SuggestionMark | null;
  alert: RowAlert | null;
  boundDraft: string | null;
  openDraftId: string | null;
  into: ReviewInto;
  position: number | null;
  reviewBlockers: readonly string[];
  canDismiss: boolean;
  busy: boolean;
  pending: boolean;
  confirmingDismiss: boolean;
  dismissRef: (element: HTMLButtonElement | null) => void;
  onReview: () => void;
  onAskDismiss: () => void;
  onCancelDismiss: () => void;
  onDismiss: () => void;
  onBind: () => void;
  onOpenDraft: (id: string) => void;
  onVerifyReview: (verification: ReviewVerification) => void;
  onCheckDismiss: (sent: RuleSuggestion) => void;
  onCloseAlert: () => void;
}) {
  const id = useId();
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (confirmingDismiss) confirmRef.current?.focus();
  }, [confirmingDismiss]);

  const rule = suggestion.proposed_rule;
  const labels = stateLabels(suggestion, mark);
  const evidence = evidenceFacts(suggestion);
  const routing = routingFacts(rule);
  const open = suggestion.state === 'open' && mark?.kind !== 'gone';
  const rowBlockers = [
    ...(mark?.kind === 'rule_live'
      ? ['The live policy already holds this rule; dismiss the suggestion instead.']
      : []),
    ...reviewBlockers,
  ];
  const dismissBlocker = canDismiss ? null : 'Dismissing needs admin:suggestions:write.';
  const title = targetText(rule);

  return (
    <li className="policy-studio-suggestion" aria-labelledby={`${id}-title`}>
      <div className="policy-studio-suggestion-head">
        <h4 id={`${id}-title`}>{title}</h4>
        {labels.map((label) => (
          <span key={label.text} className={`badge ${label.badge}`}>
            {label.text}
          </span>
        ))}
        {boundDraft !== null ? (
          <span className="badge neutral">In draft {boundDraft}, not published</span>
        ) : null}
      </div>
      {labels.some((label) => label.detail !== null) ? (
        <ul className="policy-studio-suggestion-states">
          {labels
            .filter((label) => label.detail !== null)
            .map((label) => (
              <li key={label.text}>{label.detail}</li>
            ))}
        </ul>
      ) : null}
      <dl className="workbench-facts policy-studio-suggestion-facts">
        <div>
          <dt>Source signal</dt>
          <dd>{sourceText(suggestion)}</dd>
        </div>
        <div>
          <dt>Rationale</dt>
          <dd>{suggestion.rationale}</dd>
        </div>
        <div>
          <dt>Evidence</dt>
          <dd>
            <span
              className={`badge ${evidence.availability === 'recorded' ? 'neutral' : 'warning'}`}
            >
              {evidenceAvailabilityText(evidence.availability)}
            </span>{' '}
            Window: {evidence.window}
            {evidence.facts.length > 0 ? (
              <ul>
                {evidence.facts.map((fact, index) => (
                  <li key={index}>{fact}</li>
                ))}
              </ul>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>Freshness</dt>
          <dd>{freshnessText(suggestion)}</dd>
        </div>
        <div>
          <dt>Routing classification</dt>
          <dd>
            <strong>{routing.label}.</strong> {routing.detail} The gateway recomputes the binding
            from current routing when it drafts the rule.
          </dd>
        </div>
        <div>
          <dt>Proposed rule</dt>
          <dd>
            {title}, for {principalText(rule)}. Action: {draftedActionText(suggestion)}.
            {rule.id !== null ? ` Proposed id ${rule.id}.` : ' A fresh id is given when drafted.'}
          </dd>
        </div>
        <div>
          <dt>Proposed position</dt>
          <dd>
            {position === null
              ? 'After the last rule of the candidate; the gateway names the position when it drafts the rule.'
              : `Position ${position} (rule #${position + 1}), after the last rule of ${
                  into === 'open' ? 'the open draft' : 'the live policy'
                }. Earlier rules decide first; the review simulation shows whether one does.`}
          </dd>
        </div>
        <div>
          <dt>Generator version</dt>
          <dd>{GENERATOR_VERSION_TEXT}</dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>
            {suggestion.revision}, updated <time dateTime={suggestion.updated_at}>{suggestion.updated_at}</time>
          </dd>
        </div>
      </dl>
      <details className="workbench-stages">
        <summary>Evidence and proposed rule as recorded</summary>
        <pre className="policy-studio-suggestion-json">
          {JSON.stringify({ evidence: suggestion.evidence, proposed_rule: rule.document }, null, 2)}
        </pre>
      </details>

      {alert !== null ? (
        <div className="policy-studio-suggestion-alert">
          <StudioAlertPanel alert={alert.alert} />
          <div className="form-actions">
            {alert.offerBind && openDraftId !== null ? (
              <button type="button" className="secondary-button" disabled={busy} onClick={onBind}>
                Publish the open draft as this suggestion’s acceptance
              </button>
            ) : null}
            {alert.newDrafts.map((draftId) => (
              <button
                key={draftId}
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => onOpenDraft(draftId)}
              >
                Open draft {draftId}
              </button>
            ))}
            {alert.verification !== null ? (
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => {
                  if (alert.verification !== null) onVerifyReview(alert.verification);
                }}
              >
                Check the drafts again
              </button>
            ) : null}
            {alert.dismissCheck !== null ? (
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => {
                  if (alert.dismissCheck !== null) onCheckDismiss(alert.dismissCheck);
                }}
              >
                Check the suggestion again
              </button>
            ) : null}
            <button type="button" className="secondary-button" disabled={pending} onClick={onCloseAlert}>
              Close
            </button>
          </div>
        </div>
      ) : null}

      {confirmingDismiss ? (
        <div
          className="policy-studio-confirmation"
          role="group"
          aria-labelledby={`${id}-dismiss-title`}
          aria-describedby={`${id}-dismiss-message`}
          onKeyDown={(event) => {
            if (event.key === 'Escape' && !pending) {
              event.preventDefault();
              event.stopPropagation();
              onCancelDismiss();
            }
          }}
        >
          <h3 id={`${id}-dismiss-title`}>Dismiss this suggestion?</h3>
          <p id={`${id}-dismiss-message`}>
            Revision {suggestion.revision} moves to dismissed and cannot be reopened or accepted.
            The policy is unchanged. If its rule is in a draft, publishing that draft no longer
            accepts it.
          </p>
          <div className="rule-delete-confirmation">
            <button
              ref={confirmRef}
              type="button"
              className="rule-danger-button"
              disabled={pending}
              onClick={onDismiss}
            >
              Confirm dismiss
            </button>
            <button type="button" className="secondary-button" disabled={pending} onClick={onCancelDismiss}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {open ? (
        <>
          <div className="form-actions">
            <button
              type="button"
              className="primary-button"
              disabled={rowBlockers.length > 0 || busy}
              aria-describedby={rowBlockers.length > 0 ? `${id}-review-blockers` : undefined}
              onClick={onReview}
            >
              {pending ? 'Working' : 'Review in draft'}
            </button>
            <button
              ref={dismissRef}
              type="button"
              className="secondary-button"
              disabled={dismissBlocker !== null || busy || confirmingDismiss}
              aria-describedby={dismissBlocker !== null ? `${id}-dismiss-blocker` : undefined}
              onClick={onAskDismiss}
            >
              Dismiss
            </button>
            {boundDraft !== null && boundDraft !== openDraftId ? (
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => onOpenDraft(boundDraft)}
              >
                Open its draft
              </button>
            ) : null}
          </div>
          {rowBlockers.length > 0 ? (
            <div className="policy-studio-blockers" id={`${id}-review-blockers`}>
              <p className="rule-hint">Review in draft is unavailable:</p>
              <ul>
                {rowBlockers.map((blocker) => (
                  <li key={blocker}>{blocker}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {dismissBlocker !== null ? (
            <p className="rule-hint" id={`${id}-dismiss-blocker`}>
              {dismissBlocker}
            </p>
          ) : null}
        </>
      ) : (
        <p className="rule-hint">
          {mark?.kind === 'gone'
            ? 'Nothing can be done with a suggestion the gateway no longer holds.'
            : 'Only an open suggestion can be reviewed or dismissed.'}
        </p>
      )}
    </li>
  );
}

function dismissRefusal(error: AdminApiError): StudioAlert {
  if (error.status === 403) {
    return {
      title: 'Not dismissed',
      message: 'This session does not hold admin:suggestions:write.',
      tone: 'error',
    };
  }
  if (error.status === 404) {
    return {
      title: 'Not dismissed',
      message: 'The gateway no longer holds this suggestion, or keeps no suggestions.',
      tone: 'warning',
    };
  }
  if (error.status === 412 || error.status === 428) {
    return {
      title: 'Not dismissed',
      message: `The gateway refused the revision this dismissal was bound to (${error.status}). Read the suggestions again and review it as it is now.`,
      tone: 'warning',
    };
  }
  return {
    title: 'Not dismissed',
    message: `${error.message} (${error.status}). Nothing was changed.`,
    tone: 'error',
  };
}
