import {
  type KeyboardEvent,
  type RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import { AdminApiError } from '../lib/api';
import { hasAdminPermission, useAdminCapabilities } from '../lib/adminCapabilities';
import { AdminCapabilitiesNotice } from '../lib/AdminCapabilitiesNotice';
import { subscribeAdminSession } from '../lib/adminSession';
import { fetchPolicy, type PolicyDocument } from '../lib/policy';
import { POLICY_ANALYZE_PERMISSION } from '../lib/policyAnalyses';
import {
  POLICY_DRAFT_BASE_STALE_REASON,
  POLICY_DRAFT_DEPLOYMENT_QUOTA_REASON,
  POLICY_DRAFT_ETAG_MISMATCH_REASON,
  POLICY_DRAFT_EXPIRED_REASON,
  POLICY_DRAFT_NOT_FOUND_REASON,
  POLICY_DRAFT_OWNER_QUOTA_REASON,
  POLICY_DRAFT_PUBLISHED_REASON,
  POLICY_DRAFT_TOO_LARGE_REASON,
  POLICY_DRAFTS_UNAVAILABLE_REASON,
  POLICY_ETAG_MISMATCH_REASON,
  RESOURCE_SNAPSHOT_STALE_REASON,
  convertPolicySource,
  createPolicyDraft,
  deletePolicyDraft,
  fetchPolicyDraft,
  fetchPolicyDrafts,
  publishPolicyDraft,
  updatePolicyDraft,
  validatePolicySource,
  type PolicyConversion,
  type PolicyDiagnostic,
  type PolicyDraft,
  type PolicyDraftList,
  type PolicyInspection,
} from '../lib/policyDrafts';
import {
  SUGGESTIONS_READ_PERMISSION,
  SUGGESTIONS_WRITE_PERMISSION,
  SUGGESTION_NOT_OPEN_REASON,
  SUGGESTION_REVISION_MISMATCH_REASON,
  SUGGESTION_RULE_ABSENT_REASON,
  SUGGESTION_RULE_ALREADY_PRESENT_REASON,
  SUGGESTION_RULE_ID_TAKEN_REASON,
  SUGGESTION_STALE_REASON,
  SuggestionConflictError,
  openSuggestionInDraft,
  type RuleSuggestion,
} from '../lib/suggestions';
import {
  STUDIO_SECTIONS,
  blockedUses,
  blocksPublication,
  changedMembers,
  countBySeverity,
  decodePointer,
  diagnosticsInSection,
  egressChanged,
  formatCandidate,
  isPolicyV1,
  parseCandidate,
  pointerTo,
  sectionForPointer,
  severityBadge,
  severityLabel,
  severitySummary,
  shortEtag,
  utf8Length,
  type JsonObject,
  type StudioSection,
} from './policy-studio/model';
import {
  EgressSection,
  OverviewSection,
  RateLimitsSection,
  RolesSection,
  RoutesSection,
  RulesSection,
  SourceSection,
  ToolsSection,
  type FieldRegistrar,
} from './policy-studio/sections';
import {
  heldPolicyEdits,
  holdPolicyEdits,
  releaseHeldPolicyEdits,
  type HeldPolicyEdits,
} from './policy-studio/heldEdits';
import { StudioAlertPanel, type StudioAlert } from './policy-studio/StudioAlert';
import {
  AUDIT_READ_PERMISSION,
  POLICY_SIMULATE_PERMISSION,
  type WorkbenchCandidate,
} from './policy-studio/workbench/common';
import { ImpactPanel } from './policy-studio/workbench/ImpactPanel';
import { OptimizePanel } from './policy-studio/workbench/OptimizePanel';
import { SimulatorPanel } from './policy-studio/workbench/SimulatorPanel';
import { emptySuiteSource, parseSuite } from './policy-studio/workbench/suite';
import { TestsPanel } from './policy-studio/workbench/TestsPanel';
import { targetText } from './policy-studio/suggestions/model';
import {
  SuggestionReview,
  type SuggestionBinding,
} from './policy-studio/suggestions/SuggestionReview';
import {
  SuggestionsPanel,
  type ReviewInto,
  type ReviewOutcome,
  type ReviewVerification,
} from './policy-studio/suggestions/SuggestionsPanel';
import { useSuggestionList } from './policy-studio/suggestions/useSuggestionList';
import { RuleWorkspaceNav } from './RuleWorkspaceNav';

export const POLICY_VALIDATE_DEBOUNCE_MS = 400;

const POLICY_READ_PERMISSION = 'admin:policy:read';
const POLICY_WRITE_PERMISSION = 'admin:policy:write';
const LEAVE_WARNING =
  'This draft has unsaved edits. Leave the Policy Studio and discard them?';
const CASES_LEAVE_WARNING =
  'Your simulation and test cases are kept only in this page. Leave the Policy Studio and discard them?';

// The Studio's views: the editors, the discovery suggestions that open into
// drafts, and the workbench that simulates, tests, replays and reviews a
// candidate without changing anything.
type StudioView = 'edit' | 'suggestions' | 'simulate' | 'test' | 'impact' | 'optimize';

const STUDIO_VIEWS: ReadonlyArray<{ id: StudioView; label: string }> = [
  { id: 'edit', label: 'Edit' },
  { id: 'suggestions', label: 'Suggestions' },
  { id: 'simulate', label: 'Simulate' },
  { id: 'test', label: 'Test' },
  { id: 'impact', label: 'Impact' },
  { id: 'optimize', label: 'Optimize' },
];

type LivePolicy = { policy: PolicyDocument; etag: string };

// A refusal the operator has to resolve, with the ways out it offers. The
// local candidate is kept in every one of them.
type StudioProblem =
  | { kind: 'draft-changed'; message: string }
  | { kind: 'base-stale'; message: string }
  | { kind: 'draft-gone'; message: string }
  | { kind: 'save-unknown'; message: string }
  | { kind: 'publish-unknown'; message: string }
  | { kind: 'alert'; alert: StudioAlert };

type ValidationState =
  | { kind: 'idle' }
  | { kind: 'checking'; previous: PolicyInspection | null }
  | { kind: 'ready'; source: string; inspection: PolicyInspection }
  | { kind: 'failed'; source: string; alert: StudioAlert };

type BusyAction =
  | 'open'
  | 'create'
  | 'save'
  | 'rebase'
  | 'publish'
  | 'delete'
  | 'convert'
  | 'check'
  | 'suggestion';

type Confirmation = 'publish' | 'rebase' | 'delete';

// What a publish confirmation shows, read when it opens: the saved draft
// revision, the live revision it replaces, and the validation answer for
// that exact text, with the changes and risks taken from it. Confirming
// publishes exactly this, or nothing.
type PublishReview = Readonly<{
  draftId: string;
  draftEtag: string;
  revision: number;
  liveEtag: string;
  source: string;
  inspection: PolicyInspection;
  changed: readonly string[];
  risks: readonly PolicyDiagnostic[];
  // The suggestion this publication also accepts, chosen in the
  // confirmation; null publishes without accepting one.
  binding: SuggestionBinding | null;
}>;

export function PolicyStudioView() {
  const capabilities = useAdminCapabilities();
  const [writeRejected, setWriteRejected] = useState(false);
  const canRead = hasAdminPermission(capabilities, POLICY_READ_PERMISSION);
  const canWrite =
    !writeRejected && hasAdminPermission(capabilities, POLICY_WRITE_PERMISSION);
  const canSimulate =
    canRead && hasAdminPermission(capabilities, POLICY_SIMULATE_PERMISSION);
  const canReplay = canSimulate && hasAdminPermission(capabilities, AUDIT_READ_PERMISSION);
  const canAnalyze = canRead && hasAdminPermission(capabilities, POLICY_ANALYZE_PERMISSION);
  const canReadSuggestions = hasAdminPermission(capabilities, SUGGESTIONS_READ_PERMISSION);
  const [suggestionWriteRejected, setSuggestionWriteRejected] = useState(false);
  const canWriteSuggestions =
    !suggestionWriteRejected && hasAdminPermission(capabilities, SUGGESTIONS_WRITE_PERMISSION);
  // Load once after the first grant; a resource 403 must not loop.
  const [readRequested, setReadRequested] = useState(false);
  useEffect(() => {
    if (canRead) setReadRequested(true);
  }, [canRead]);

  const [live, setLive] = useState<LivePolicy | null>(null);
  const [liveAlert, setLiveAlert] = useState<StudioAlert | null>(null);
  const [draftList, setDraftList] = useState<PolicyDraftList | null>(null);
  const [draftListAlert, setDraftListAlert] = useState<StudioAlert | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const [draft, setDraftState] = useState<PolicyDraft | null>(null);
  const [serverSource, setServerSourceState] = useState('');
  const [source, setSourceState] = useState('');
  // The same three values as they are now, for the session listener that
  // holds unsaved edits: it runs before the next render.
  const draftRef = useRef<PolicyDraft | null>(null);
  const serverSourceRef = useRef('');
  const sourceRef = useRef('');
  const [activeSection, setActiveSection] = useState<StudioSection>('overview');
  const [validation, setValidation] = useState<ValidationState>({ kind: 'idle' });
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const busyRef = useRef(false);
  const [problem, setProblem] = useState<StudioProblem | null>(null);
  const [notice, setNotice] = useState<StudioAlert | null>(null);
  const [confirming, setConfirming] = useState<Confirmation | null>(null);
  const [publishReview, setPublishReview] = useState<PublishReview | null>(null);
  const [conversion, setConversion] = useState<PolicyConversion | null>(null);
  // Asks for the same text to be validated again: the resources the
  // cross-resource checks read can change while the text does not.
  const [validationRound, setValidationRound] = useState(0);
  const fieldElements = useRef(new Map<string, HTMLElement>());
  const fieldCallbacks = useRef(
    new Map<string, (element: HTMLElement | null) => void>(),
  );
  const [pendingFocus, setPendingFocus] = useState<string | null>(null);
  const problemRef = useRef<HTMLDivElement>(null);
  const tabRefs = useRef(new Map<StudioSection, HTMLButtonElement>());
  const actionRefs = useRef(new Map<Confirmation, HTMLButtonElement>());
  const restoreFocusTo = useRef<Confirmation | null>(null);
  const [view, setView] = useState<StudioView>('edit');
  const viewRefs = useRef(new Map<StudioView, HTMLButtonElement>());
  const [candidateChoice, setCandidateChoice] = useState<'draft' | 'live'>('draft');
  // The cases the Simulator and the Test view share, in page memory only.
  const [suiteSource, setSuiteSource] = useState(emptySuiteSource);
  // The suggestions, read once their view is first shown, and the drafts in
  // this page that hold a suggestion's rule. Page memory only.
  const suggestions = useSuggestionList(canReadSuggestions && view === 'suggestions');
  const [bindings, setBindings] = useState<readonly SuggestionBinding[]>([]);
  // What the gateway answered about a bound suggestion since it was bound.
  const [bindingProblems, setBindingProblems] = useState<ReadonlyMap<string, string>>(new Map());
  const [reviewInto, setReviewInto] = useState<ReviewInto>('new');

  const setSource = useCallback((next: string) => {
    sourceRef.current = next;
    setSourceState(next);
  }, []);

  const setDraft = useCallback((next: PolicyDraft | null, nextServerSource: string) => {
    draftRef.current = next;
    serverSourceRef.current = nextServerSource;
    setDraftState(next);
    setServerSourceState(nextServerSource);
  }, []);

  const parsed = useMemo(() => parseCandidate(source), [source]);
  const draftId = draft?.summary.draft_id ?? null;
  const isPublished = draft?.summary.state === 'published';
  const dirty = draft !== null && source !== serverSource;
  const editable = canWrite && draft !== null && !isPublished;
  const maxCandidateBytes = draftList?.limits.max_candidate_bytes ?? null;
  const baseStale =
    draft !== null && live !== null && draft.summary.base_etag !== live.etag;
  const currentInspection =
    validation.kind === 'ready' && validation.source === source
      ? validation.inspection
      : null;
  const shownInspection =
    validation.kind === 'ready'
      ? validation.inspection
      : validation.kind === 'checking'
        ? validation.previous
        : null;
  const diagnostics = shownInspection?.diagnostics ?? [];
  const changed =
    live !== null && parsed.ok ? changedMembers(live.policy, parsed.document) : [];
  const changesEgress =
    live !== null && parsed.ok && egressChanged(live.policy, parsed.document);
  const publishBlockers = publicationBlockers({
    canWrite,
    isPublished,
    dirty,
    live,
    baseStale,
    inspection: currentInspection,
    changesEgress,
  });

  // Whether a reviewed publication is still exactly what would be
  // published: nothing blocks it, and the text on screen, its validation
  // answer, the saved draft and the live revision are the ones reviewed.
  function reviewIsCurrent(review: PublishReview | null, shownSource: string): boolean {
    return (
      review !== null &&
      publishBlockers.length === 0 &&
      currentInspection === review.inspection &&
      shownSource === review.source &&
      draft !== null &&
      draft.summary.draft_id === review.draftId &&
      draft.etag === review.draftEtag &&
      live !== null &&
      live.etag === review.liveEtag
    );
  }

  const suite = useMemo(() => parseSuite(suiteSource), [suiteSource]);
  const holdsCases = suite.ok ? suite.cases.length > 0 : suiteSource !== emptySuiteSource();
  useLeaveWarning(dirty || holdsCases, dirty ? LEAVE_WARNING : CASES_LEAVE_WARNING);

  // What the workbench judges: the open draft's text on screen, unsaved
  // edits included, or the live policy. Either is pinned to the live
  // revision read here.
  const draftChosen = candidateChoice === 'draft' && draft !== null;
  const workbenchCandidate: WorkbenchCandidate | null =
    live === null
      ? null
      : draftChosen
        ? parsed.ok && draft !== null
          ? {
              kind: 'draft',
              liveEtag: live.etag,
              draftId: draft.summary.draft_id,
              revision: draft.summary.revision,
              dirty,
              source,
            }
          : null
        : { kind: 'live', liveEtag: live.etag };
  const candidateProblem =
    live === null
      ? 'The live policy has not been read, so nothing can be pinned to it.'
      : draftChosen && !parsed.ok
        ? 'Fix the draft source first: the candidate is not a JSON object.'
        : null;
  const liveSource = useMemo(
    () => (live === null ? null : formatCandidate(live.policy)),
    [live],
  );

  // Suggestions: the open draft's bound suggestions, where Review in draft
  // may write, and why it may not.
  const openBindings =
    draftId === null ? [] : bindings.filter((binding) => binding.draftId === draftId);
  const boundDrafts = useMemo(() => {
    const bound = new Map<string, string>();
    for (const binding of bindings) bound.set(binding.suggestion.id, binding.draftId);
    return bound;
  }, [bindings]);
  const suggestionRows = suggestions.list.rows;
  // Why a publication bound to this suggestion would be refused, from what
  // the gateway has said about it since it was bound.
  function bindingStaleReason(binding: SuggestionBinding): string | null {
    const known = bindingProblems.get(binding.suggestion.id);
    if (known !== undefined) {
      return known;
    }
    const row = suggestionRows.find((entry) => entry.id === binding.suggestion.id);
    if (
      row !== undefined &&
      (row.state !== 'open' || row.revision !== binding.suggestion.revision)
    ) {
      return `The gateway now holds this suggestion at revision ${row.revision}, ${row.state}, so a publication bound to revision ${binding.suggestion.revision} is refused and changes nothing.`;
    }
    return null;
  }
  const openDraftBlocker =
    draft === null
      ? null
      : isPublished
        ? 'The open draft was published and accepts no change.'
        : baseStale
          ? 'The open draft is pinned to an older live revision. Rebase it first; the gateway never rebases a draft to take a rule.'
          : null;
  const draftLimitReached =
    draftList !== null && draftList.drafts.length >= draftList.limits.max_drafts_per_owner;
  const suggestionReviewBlockers: string[] = [];
  if (!canReadSuggestions) {
    suggestionReviewBlockers.push('Review in draft needs admin:suggestions:read.');
  }
  if (!canWrite) {
    suggestionReviewBlockers.push('Review in draft needs admin:policy:write, as every draft write does.');
  }
  if (live === null) {
    suggestionReviewBlockers.push('The live policy has not been read, so no draft can be pinned to it.');
  }
  if (draftList === null) {
    suggestionReviewBlockers.push('Policy drafts are unavailable, so there is nowhere to review a suggestion.');
  }
  if (dirty) {
    suggestionReviewBlockers.push('Save or discard the edits in the open draft first.');
  }
  if ((reviewInto === 'new' || draft === null) && draftLimitReached) {
    suggestionReviewBlockers.push(
      `You already hold the maximum of ${draftList?.limits.max_drafts_per_owner ?? 0} drafts. Delete one, or review into the open draft.`,
    );
  }

  const register: FieldRegistrar = useCallback((pointer: string) => {
    let callback = fieldCallbacks.current.get(pointer);
    if (!callback) {
      callback = (element: HTMLElement | null) => {
        if (element) {
          fieldElements.current.set(pointer, element);
        } else {
          fieldElements.current.delete(pointer);
        }
      };
      fieldCallbacks.current.set(pointer, callback);
    }
    return callback;
  }, []);

  // Move focus to what shows the value a diagnostic points at, or the
  // closest element that contains it.
  useEffect(() => {
    if (pendingFocus === null) {
      return;
    }
    setPendingFocus(null);
    const segments = decodePointer(pendingFocus) ?? [];
    for (let length = segments.length; length >= 0; length -= 1) {
      const element = fieldElements.current.get(
        pointerTo(...segments.slice(0, length)),
      );
      if (element) {
        element.focus();
        return;
      }
    }
    tabRefs.current.get(activeSection)?.focus();
  }, [pendingFocus, activeSection]);

  useEffect(() => {
    if (problem !== null) {
      problemRef.current?.focus();
    }
  }, [problem]);

  // A cancelled confirmation returns focus to the action that opened it.
  useEffect(() => {
    if (confirming === null && restoreFocusTo.current !== null) {
      actionRefs.current.get(restoreFocusTo.current)?.focus();
      restoreFocusTo.current = null;
    }
  }, [confirming]);

  // A publish confirmation is for the candidate, validation and revisions
  // it shows: a change to any of them withdraws it, so it has to be
  // reviewed again.
  useEffect(() => {
    setConfirming((current) => (current === 'publish' ? null : current));
  }, [source, validation, draft, live]);

  // Any admin request answered 401 ends the session and replaces this view.
  // The unsaved edits are held for the next session first: this listener
  // runs when the session ends, before the view goes.
  useEffect(
    () =>
      subscribeAdminSession((event) => {
        const shown = draftRef.current;
        if (
          event.kind === 'unauthenticated' &&
          shown !== null &&
          sourceRef.current !== serverSourceRef.current
        ) {
          holdPolicyEdits({
            draft: shown,
            serverSource: serverSourceRef.current,
            source: sourceRef.current,
          });
        }
      }),
    [],
  );

  function actionRef(action: Confirmation) {
    return (element: HTMLButtonElement | null) => {
      if (element) actionRefs.current.set(action, element);
      else actionRefs.current.delete(action);
    };
  }

  const loadLive = useCallback(async (): Promise<LivePolicy | null> => {
    try {
      const result = await fetchPolicy();
      if (!result.etag) {
        setLive(null);
        setLiveAlert({
          title: 'Live policy revision unknown',
          message:
            'The gateway did not return the live policy ETag, so no draft can be pinned or published. Reload the page.',
          tone: 'error',
        });
        return null;
      }
      const next = { policy: result.policy, etag: result.etag };
      setLive(next);
      setLiveAlert(null);
      return next;
    } catch (error) {
      setLive(null);
      setLiveAlert(readAlert(error, 'Live policy could not be read'));
      return null;
    }
  }, []);

  const loadDraftList = useCallback(async () => {
    try {
      setDraftList(await fetchPolicyDrafts());
      setDraftListAlert(null);
    } catch (error) {
      setDraftList(null);
      setDraftListAlert(
        error instanceof AdminApiError &&
          error.code === POLICY_DRAFTS_UNAVAILABLE_REASON
          ? {
              title: 'Policy drafts unavailable',
              message:
                'This gateway has no draft store to keep drafts in, so the Policy Studio cannot save or publish. Policy history configuration enables it.',
              tone: 'warning',
            }
          : readAlert(error, 'Policy drafts could not be read'),
      );
    }
  }, []);

  useEffect(() => {
    if (!readRequested) {
      return;
    }
    let isCurrent = true;
    setIsLoading(true);
    void Promise.all([loadLive(), loadDraftList()]).finally(() => {
      if (isCurrent) setIsLoading(false);
    });
    return () => {
      isCurrent = false;
    };
  }, [readRequested, loadLive, loadDraftList]);

  // Edits held when the last session ended come back only once the gateway
  // answers their draft to this session. Drafts are owner-scoped and
  // another owner's answers 404, so a different principal never sees them.
  useEffect(() => {
    const held = heldPolicyEdits();
    if (!readRequested || held === null || !beginBusy('open')) {
      return;
    }
    let isCurrent = true;
    void (async () => {
      try {
        const current = await fetchPolicyDraft(held.draft.summary.draft_id);
        if (!isCurrent) return;
        releaseHeldPolicyEdits();
        restoreHeldEdits(held, current);
      } catch (error) {
        if (!isCurrent) return;
        if (refusal(error) === POLICY_DRAFT_EXPIRED_REASON) {
          // Only the owner is told a draft expired.
          releaseHeldPolicyEdits();
          restoreHeldEdits(held, null);
        } else if (error instanceof AdminApiError && error.status === 401) {
          // Still signed out: they stay held for the next session.
        } else if (error instanceof AdminApiError && error.status < 500) {
          releaseHeldPolicyEdits();
        } else {
          setProblem({
            kind: 'alert',
            alert: {
              title: 'Unsaved edits not restored yet',
              message:
                'The draft your unsaved edits belong to could not be read. They are still held in this page; open the Policy Studio again to retry.',
              tone: 'warning',
            },
          });
        }
      } finally {
        if (isCurrent) endBusy();
      }
    })();
    return () => {
      isCurrent = false;
      endBusy();
    };
  }, [readRequested]);

  // Validation as you type: the exact text, debounced, and only the answer
  // for the text still on screen is kept.
  const validationGeneration = useRef(0);
  useEffect(() => {
    const generation = ++validationGeneration.current;
    if (draftId === null || source.trim().length === 0) {
      setValidation({ kind: 'idle' });
      return;
    }
    if (maxCandidateBytes !== null && utf8Length(source) > maxCandidateBytes) {
      setValidation({
        kind: 'failed',
        source,
        alert: {
          title: 'Candidate too large',
          message: `A draft candidate may be at most ${formatBytes(maxCandidateBytes)}; this one is ${formatBytes(utf8Length(source))}.`,
          tone: 'error',
        },
      });
      return;
    }
    setValidation((current) => ({
      kind: 'checking',
      previous:
        current.kind === 'ready'
          ? current.inspection
          : current.kind === 'checking'
            ? current.previous
            : null,
    }));
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const inspection = await validatePolicySource(source, controller.signal);
          if (generation === validationGeneration.current) {
            setValidation({ kind: 'ready', source, inspection });
          }
        } catch (error) {
          if (controller.signal.aborted || generation !== validationGeneration.current) {
            return;
          }
          setValidation({
            kind: 'failed',
            source,
            alert: validationAlert(error),
          });
        }
      })();
    }, POLICY_VALIDATE_DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [draftId, source, maxCandidateBytes, validationRound]);

  function revalidate() {
    setValidationRound((round) => round + 1);
  }

  function beginBusy(action: BusyAction): boolean {
    if (busyRef.current) {
      return false;
    }
    busyRef.current = true;
    setBusy(action);
    return true;
  }

  function endBusy() {
    busyRef.current = false;
    setBusy(null);
  }

  function showServerDraft(next: PolicyDraft, replaceLocal: boolean) {
    const formatted = formatCandidate(next.policy);
    setDraft(next, formatted);
    if (replaceLocal) {
      setSource(formatted);
    }
  }

  // Held edits come back as unsaved edits, never saved on the operator's
  // behalf. `current` is the draft as the gateway holds it now, or null
  // when it expired.
  function restoreHeldEdits(held: HeldPolicyEdits, current: PolicyDraft | null) {
    setActiveSection('overview');
    if (current !== null && current.summary.state === 'published') {
      showServerDraft(current, false);
      setSource(held.source);
      setProblem({
        kind: 'draft-gone',
        message:
          'Your unsaved edits are restored, but this draft was published while you were signed out and accepts no further change.',
      });
    } else if (current !== null && current.etag === held.draft.etag) {
      showServerDraft(current, false);
      setSource(held.source);
      setNotice({
        title: 'Unsaved edits restored',
        message:
          'The edits you had not saved when your session ended are back. Nothing was saved or published; review them and save the draft.',
        tone: 'info',
      });
    } else {
      // Keep the revision the edits were made on, so saving them is
      // refused rather than written over a newer one.
      setDraft(held.draft, held.serverSource);
      setSource(held.source);
      setProblem(
        current === null
          ? {
              kind: 'draft-gone',
              message:
                'Your unsaved edits are restored, but this draft expired on the gateway while you were signed out.',
            }
          : {
              kind: 'draft-changed',
              message:
                'Your unsaved edits are restored, but the draft changed in another tab or session while you were signed out. They were not saved.',
            },
      );
    }
  }

  function noteWriteError(error: unknown) {
    if (error instanceof AdminApiError && error.status === 403) {
      setWriteRejected(true);
    }
  }

  async function openDraft(id: string) {
    if (dirty || !beginBusy('open')) {
      return;
    }
    setProblem(null);
    setNotice(null);
    setConfirming(null);
    setConversion(null);
    try {
      showServerDraft(await fetchPolicyDraft(id), true);
      setActiveSection('overview');
    } catch (error) {
      setProblem({ kind: 'alert', alert: readAlert(error, 'Draft could not be opened') });
      if (isDraftGone(error)) {
        await loadDraftList();
      }
    } finally {
      endBusy();
    }
  }

  // A new draft on the live revision on screen: a copy of it, or the local
  // candidate when it outlived the draft it was edited in.
  async function createDraft(fromLocal: boolean) {
    if (!canWrite || live === null || !beginBusy('create')) {
      return;
    }
    const candidate = fromLocal ? sourceRef.current : undefined;
    if (candidate !== undefined && !parseCandidate(candidate).ok) {
      endBusy();
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Fix the source first',
          message: 'Only a JSON object can be saved as a draft candidate.',
          tone: 'warning',
        },
      });
      return;
    }
    setProblem(null);
    setNotice(null);
    setConfirming(null);
    try {
      const created = await createPolicyDraft(live.etag, candidate);
      showServerDraft(created, sourceRef.current === candidate || candidate === undefined);
      setConversion(null);
      setNotice({
        title: 'Draft created',
        message: `Draft ${created.summary.draft_id} is pinned to live revision ${shortEtag(created.summary.base_etag)}. Nothing changes until it is published.`,
        tone: 'info',
      });
      if (!fromLocal) setActiveSection('overview');
    } catch (error) {
      noteWriteError(error);
      if (refusal(error) === POLICY_ETAG_MISMATCH_REASON) {
        await loadLive();
        setProblem({
          kind: 'alert',
          alert: {
            title: 'Live policy changed',
            message:
              'The live policy changed since it was read here. It has been read again; review it and create the draft again.',
            tone: 'warning',
          },
        });
      } else {
        setProblem({ kind: 'alert', alert: writeAlert(error, 'Draft could not be created') });
      }
    } finally {
      endBusy();
      await loadDraftList();
    }
  }

  async function saveDraft(overwrite = false) {
    if (!editable || draft === null || !beginBusy('save')) {
      return;
    }
    const sent = sourceRef.current;
    if (!parseCandidate(sent).ok) {
      endBusy();
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Fix the source first',
          message: 'Only a JSON object can be saved as a draft candidate.',
          tone: 'warning',
        },
      });
      return;
    }
    setProblem(null);
    setNotice(null);
    setConfirming(null);
    let target = draft;
    try {
      if (overwrite) {
        // The operator chose to replace the newer revision: read its ETag
        // now, and keep the local candidate.
        target = await fetchPolicyDraft(draft.summary.draft_id);
        showServerDraft(target, false);
      }
      const saved = await updatePolicyDraft(target.summary.draft_id, target.etag, {
        source: sent,
      });
      showServerDraft(saved, sourceRef.current === sent);
      setNotice({
        title: 'Draft saved',
        message: `Revision ${saved.summary.revision} saved. The live policy is unchanged.`,
        tone: 'info',
      });
    } catch (error) {
      noteWriteError(error);
      await handleDraftWriteError(error, target, 'save');
    } finally {
      endBusy();
    }
  }

  async function rebaseDraft() {
    if (!editable || draft === null || live === null || !beginBusy('rebase')) {
      return;
    }
    const sent = dirty ? sourceRef.current : undefined;
    if (sent !== undefined && !parseCandidate(sent).ok) {
      endBusy();
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Fix the source first',
          message: 'Only a JSON object can be saved as a draft candidate.',
          tone: 'warning',
        },
      });
      return;
    }
    setConfirming(null);
    setProblem(null);
    setNotice(null);
    try {
      const saved = await updatePolicyDraft(draft.summary.draft_id, draft.etag, {
        baseEtag: live.etag,
        source: sent,
      });
      showServerDraft(saved, sent === undefined || sourceRef.current === sent);
      setNotice({
        title: 'Draft rebased',
        message: `The draft is now pinned to live revision ${shortEtag(saved.summary.base_etag)}. Publishing it replaces that revision with this candidate.`,
        tone: 'info',
      });
    } catch (error) {
      noteWriteError(error);
      await handleDraftWriteError(error, draft, 'rebase');
    } finally {
      endBusy();
      await loadDraftList();
    }
  }

  // Opens the publish confirmation on what would be published now.
  function reviewPublication() {
    if (
      publishBlockers.length > 0 ||
      draft === null ||
      live === null ||
      currentInspection === null
    ) {
      return;
    }
    const acceptable = canWriteSuggestions
      ? openBindings.filter((binding) => bindingStaleReason(binding) === null)
      : [];
    setPublishReview({
      draftId: draft.summary.draft_id,
      draftEtag: draft.etag,
      revision: draft.summary.revision,
      liveEtag: live.etag,
      source,
      inspection: currentInspection,
      changed,
      risks: currentInspection.diagnostics.filter(
        (diagnostic) => diagnostic.severity === 'risk',
      ),
      binding: acceptable.length > 0 ? acceptable[acceptable.length - 1] : null,
    });
    setConfirming('publish');
  }

  function chooseAcceptance(suggestionId: string | null) {
    setPublishReview((review) =>
      review === null
        ? null
        : {
            ...review,
            binding:
              suggestionId === null
                ? null
                : (openBindings.find((binding) => binding.suggestion.id === suggestionId) ?? null),
          },
    );
  }

  async function publishDraft() {
    const review = publishReview;
    if (!editable || draft === null || live === null || review === null) {
      return;
    }
    // Publish exactly what was reviewed, or nothing: the confirmation is
    // withdrawn on any change, and this refuses one that slipped through.
    if (!reviewIsCurrent(review, sourceRef.current)) {
      setConfirming(null);
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Not published',
          message:
            'The draft, its validation or the live policy changed after the publication was reviewed, so nothing was sent. Review the publication again.',
          tone: 'warning',
        },
      });
      return;
    }
    if (!beginBusy('publish')) {
      return;
    }
    setConfirming(null);
    setProblem(null);
    setNotice(null);
    const published = draft;
    const accepted = review.binding;
    try {
      const result = await publishPolicyDraft(
        review.draftId,
        review.draftEtag,
        review.liveEtag,
        review.inspection.resource_snapshot?.digest ?? null,
        accepted === null
          ? null
          : { id: accepted.suggestion.id, revision: accepted.suggestion.revision },
      );
      const warnings: string[] = [];
      const others = bindings.filter(
        (binding) =>
          binding.draftId === review.draftId &&
          binding.suggestion.id !== accepted?.suggestion.id,
      );
      for (const other of others) {
        warnings.push(
          `Suggestion ${other.suggestion.id} was not accepted and stays open. If its rule went live with this draft, dismiss it.`,
        );
      }
      if (!result.draftStateRecorded) {
        warnings.push(
          'The draft could not be marked published, so it stays open on a base that is no longer live. Delete it, or rebase it before reusing it.',
        );
      }
      if (result.historyAppendWarning) {
        warnings.push('The change could not be recorded in policy version history.');
      }
      setNotice({
        title: accepted === null ? 'Draft published' : 'Draft published and suggestion accepted',
        message: `The live policy is now revision ${shortEtag(result.etag)}.${
          accepted === null
            ? ''
            : ` Suggestion ${accepted.suggestion.id} was accepted in the same commit.`
        }`,
        tone: warnings.length > 0 ? 'warning' : 'info',
        details: warnings,
      });
      setBindings((current) => current.filter((binding) => binding.draftId !== review.draftId));
      await refreshAfterPublication(published.summary.draft_id);
      refreshSuggestionsIfListed();
    } catch (error) {
      if (accepted !== null && error instanceof AdminApiError && error.status === 403) {
        // The draft publication itself is allowed; accepting a suggestion
        // with it also needs admin:suggestions:write.
        setSuggestionWriteRejected(true);
      } else {
        noteWriteError(error);
      }
      await handlePublishError(error, published, accepted);
    } finally {
      endBusy();
      await loadDraftList();
    }
  }

  async function deleteDraft() {
    if (!canWrite || draft === null || !beginBusy('delete')) {
      return;
    }
    setConfirming(null);
    setProblem(null);
    setNotice(null);
    const deleted = draft;
    try {
      await deletePolicyDraft(deleted.summary.draft_id, deleted.etag);
      setBindings((current) =>
        current.filter((binding) => binding.draftId !== deleted.summary.draft_id),
      );
      closeDraft();
      setNotice({
        title: 'Draft deleted',
        message: `Draft ${deleted.summary.draft_id} was deleted. The live policy is unchanged.`,
        tone: 'info',
      });
    } catch (error) {
      noteWriteError(error);
      if (isDraftGone(error)) {
        closeDraft();
        setNotice({
          title: 'Draft already gone',
          message: 'The draft had already expired or been deleted.',
          tone: 'info',
        });
      } else if (refusal(error) === POLICY_DRAFT_ETAG_MISMATCH_REASON) {
        setProblem({
          kind: 'draft-changed',
          message:
            'The draft changed in another tab or session since it was opened here, so it was not deleted. Load the saved draft to review it first.',
        });
      } else {
        setProblem({ kind: 'alert', alert: writeAlert(error, 'Draft could not be deleted') });
      }
    } finally {
      endBusy();
      await loadDraftList();
    }
  }

  async function convertDraft() {
    if (!editable || !beginBusy('convert')) {
      return;
    }
    const sent = sourceRef.current;
    setProblem(null);
    setNotice(null);
    try {
      const result = await convertPolicySource(sent);
      if (sourceRef.current !== sent) {
        setNotice({
          title: 'Conversion discarded',
          message: 'The source changed while it was being converted. Convert it again.',
          tone: 'warning',
        });
        return;
      }
      if (result.converted && result.policy !== null) {
        setSource(formatCandidate(result.policy));
        setConversion(result);
        setNotice({
          title: 'Converted to policy v1',
          message:
            'The gateway converted this candidate and verified that it authorizes exactly as before. Review the changes below, then save the draft.',
          tone: 'info',
        });
      } else {
        setConversion(result);
        setProblem({
          kind: 'alert',
          alert: {
            title: 'Conversion refused',
            message: 'The gateway could not convert this candidate. Its diagnostics say why.',
            tone: 'warning',
            details: result.diagnostics.map((d) => `${d.message} ${d.remediation}`),
          },
        });
      }
    } catch (error) {
      setProblem({ kind: 'alert', alert: readAlert(error, 'Conversion failed') });
    } finally {
      endBusy();
    }
  }

  // After a lost answer, read what the gateway holds now; never send the
  // write again on the operator's behalf.
  async function checkDraftState() {
    if (draft === null || !beginBusy('check')) {
      return;
    }
    const known = draft;
    try {
      const current = await fetchPolicyDraft(known.summary.draft_id);
      if (problem?.kind === 'publish-unknown') {
        const latestLive = await loadLive();
        if (
          current.summary.state === 'published' ||
          (latestLive !== null && latestLive.etag === current.summary.candidate_etag)
        ) {
          showServerDraft(current, true);
          setBindings((bound) =>
            bound.filter((binding) => binding.draftId !== known.summary.draft_id),
          );
          setProblem(null);
          setNotice({
            title: 'Draft published',
            message: `The gateway confirms the publication: the live policy is revision ${shortEtag(latestLive?.etag)}.${
              openBindings.length > 0
                ? ' Read the suggestions again to see whether one was accepted with it.'
                : ''
            }`,
            tone: 'info',
          });
        } else {
          setProblem({
            kind: 'publish-unknown',
            message:
              'As of now the draft is still open and the live policy is not its candidate. The request may still be in progress; check again before publishing again.',
          });
        }
      } else if (current.summary.revision !== known.summary.revision) {
        setProblem({
          kind: 'draft-changed',
          message: `The gateway now holds revision ${current.summary.revision} of this draft, which may be your save. Your edits are kept here.`,
        });
      } else {
        setProblem(null);
        setNotice({
          title: 'Draft not saved',
          message: 'The gateway still holds the revision opened here. Your edits are kept; save them again.',
          tone: 'warning',
        });
      }
    } catch (error) {
      if (isDraftGone(error)) {
        setProblem({
          kind: 'draft-gone',
          message: 'The draft no longer exists on the gateway. Your edits are kept here.',
        });
      } else {
        setProblem({ kind: 'alert', alert: readAlert(error, 'Draft could not be read') });
      }
    } finally {
      endBusy();
      await loadDraftList();
      refreshSuggestionsIfListed();
    }
  }

  async function reloadSavedDraft() {
    if (draft === null || !beginBusy('open')) {
      return;
    }
    try {
      showServerDraft(await fetchPolicyDraft(draft.summary.draft_id), true);
      setProblem(null);
      setConversion(null);
    } catch (error) {
      if (isDraftGone(error)) {
        setProblem({
          kind: 'draft-gone',
          message: 'The draft no longer exists on the gateway. Your edits are kept here.',
        });
      } else {
        setProblem({ kind: 'alert', alert: readAlert(error, 'Draft could not be read') });
      }
    } finally {
      endBusy();
    }
  }

  async function refreshLive() {
    if (!beginBusy('check')) {
      return;
    }
    try {
      await loadLive();
      if (problem?.kind === 'base-stale') setProblem(null);
    } finally {
      endBusy();
    }
  }

  async function refreshAfterPublication(id: string) {
    await loadLive();
    try {
      showServerDraft(await fetchPolicyDraft(id), true);
    } catch {
      // The publication itself is confirmed; a draft that cannot be read
      // back is shown as it was.
    }
  }

  function closeDraft() {
    setDraft(null, '');
    setSource('');
    setConversion(null);
    setValidation({ kind: 'idle' });
  }

  async function handleDraftWriteError(
    error: unknown,
    target: PolicyDraft,
    action: 'save' | 'rebase',
  ) {
    const reason = refusal(error);
    if (isAmbiguous(error)) {
      setProblem({
        kind: 'save-unknown',
        message:
          'The gateway did not confirm the save, so it may or may not have been written. Your edits are kept here. Check the draft before saving again.',
      });
    } else if (reason === POLICY_DRAFT_ETAG_MISMATCH_REASON) {
      setProblem({
        kind: 'draft-changed',
        message:
          'The draft changed in another tab or session since it was opened here. Your edits are kept here and were not saved.',
      });
    } else if (reason === POLICY_ETAG_MISMATCH_REASON) {
      await loadLive();
      setProblem({
        kind: 'base-stale',
        message:
          'The live policy changed again before the draft could be rebased. It has been read again; review the changes and rebase again.',
      });
    } else if (reason === POLICY_DRAFT_PUBLISHED_REASON) {
      try {
        showServerDraft(await fetchPolicyDraft(target.summary.draft_id), false);
      } catch {
        // Shown as it was.
      }
      setProblem({
        kind: 'draft-gone',
        message:
          'This draft was already published and accepts no further change. Your edits are kept here.',
      });
    } else if (isDraftGone(error)) {
      setProblem({
        kind: 'draft-gone',
        message:
          reason === POLICY_DRAFT_EXPIRED_REASON
            ? 'This draft expired on the gateway. Your edits are kept here.'
            : 'This draft no longer exists on the gateway. Your edits are kept here.',
      });
    } else {
      setProblem({
        kind: 'alert',
        alert: writeAlert(error, action === 'save' ? 'Draft not saved' : 'Draft not rebased'),
      });
    }
  }

  async function handlePublishError(
    error: unknown,
    published: PolicyDraft,
    accepted: SuggestionBinding | null,
  ) {
    const reason = refusal(error);
    if (accepted !== null && reason === SUGGESTION_STALE_REASON) {
      setBindingProblems((current) =>
        new Map(current).set(
          accepted.suggestion.id,
          `The gateway refused the publication because this suggestion is no longer open at revision ${accepted.suggestion.revision}. It may have been dismissed or accepted elsewhere.`,
        ),
      );
      refreshSuggestionsIfListed();
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Not published: the suggestion changed',
          message: `Suggestion ${accepted.suggestion.id} is no longer open at revision ${accepted.suggestion.revision}, so nothing was published and nothing changed. Review the publication again; you can publish the draft without accepting the suggestion.`,
          tone: 'warning',
        },
      });
      return;
    }
    if (accepted !== null && reason === SUGGESTION_RULE_ABSENT_REASON) {
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Not published: the draft no longer holds the suggested rule',
          message: `The saved draft does not hold the rule suggestion ${accepted.suggestion.id} proposes (an edit changed it), so publishing it would not accept the suggestion. Nothing was published. Restore the rule, or publish without accepting the suggestion.`,
          tone: 'warning',
        },
      });
      return;
    }
    if (accepted !== null && error instanceof AdminApiError && error.status === 403) {
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Not published',
          message:
            'Accepting a suggestion with a publication needs admin:suggestions:write, which this session does not hold. Nothing was published; you can publish without accepting the suggestion.',
          tone: 'error',
        },
      });
      return;
    }
    if (isAmbiguous(error)) {
      setProblem({
        kind: 'publish-unknown',
        message:
          'The gateway did not confirm the publication, so the live policy may or may not have changed. Check the draft before doing anything else.',
      });
    } else if (reason === POLICY_DRAFT_BASE_STALE_REASON || reason === POLICY_ETAG_MISMATCH_REASON) {
      await loadLive();
      setProblem({
        kind: 'base-stale',
        message:
          'The live policy changed after this draft was pinned, so it was not published and nothing changed. Review the live policy, then rebase the draft explicitly.',
      });
    } else if (reason === POLICY_DRAFT_ETAG_MISMATCH_REASON) {
      setProblem({
        kind: 'draft-changed',
        message:
          'The draft changed in another tab or session since it was opened here, so it was not published. Load the saved draft and review it first.',
      });
    } else if (reason === POLICY_DRAFT_PUBLISHED_REASON) {
      await refreshAfterPublication(published.summary.draft_id);
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Already published',
          message: 'This draft was already published; nothing changed now.',
          tone: 'info',
        },
      });
    } else if (isDraftGone(error)) {
      setProblem({
        kind: 'draft-gone',
        message: 'This draft no longer exists on the gateway, so nothing was published. Your edits are kept here.',
      });
    } else if (reason === RESOURCE_SNAPSHOT_STALE_REASON) {
      revalidate();
      setProblem({
        kind: 'alert',
        alert: {
          title: 'Resources changed since validation',
          message:
            'The tools, Connections, configuration or egress controls this draft was validated against have changed, so it was not published and nothing changed. It is being validated again; review the diagnostics before publishing.',
          tone: 'warning',
        },
      });
    } else {
      if (error instanceof AdminApiError && error.status === 400) {
        revalidate();
      }
      setProblem({ kind: 'alert', alert: writeAlert(error, 'Draft not published') });
    }
  }

  // Review in draft: write the suggestion's rule into a new draft from the
  // live policy on screen, or into the open draft, and open the result in
  // the editors. Nothing live changes and the suggestion stays open; a
  // refusal writes nothing, and a lost answer is checked by reading the
  // drafts again, never by sending the request again.
  async function reviewSuggestion(
    suggestion: RuleSuggestion,
    into: ReviewInto,
  ): Promise<ReviewOutcome> {
    const target =
      into === 'open' && draft !== null
        ? { draftId: draft.summary.draft_id, draftEtag: draft.etag, revision: draft.summary.revision }
        : null;
    const blockers = [
      ...suggestionReviewBlockers,
      ...(target !== null && openDraftBlocker !== null ? [openDraftBlocker] : []),
    ];
    if (blockers.length > 0 || live === null) {
      return {
        kind: 'problem',
        alert: {
          title: 'Not reviewed',
          message: blockers.join(' ') || 'The live policy has not been read.',
          tone: 'warning',
        },
      };
    }
    if (!beginBusy('suggestion')) {
      return {
        kind: 'problem',
        alert: {
          title: 'Not reviewed',
          message: 'Another Policy Studio action is still in progress. Try again when it ends.',
          tone: 'info',
        },
      };
    }
    const verification: ReviewVerification = {
      into,
      knownDraftIds: draftList?.drafts.map((summary) => summary.draft_id) ?? [],
      target: target === null ? null : { draftId: target.draftId, revision: target.revision },
    };
    setProblem(null);
    setNotice(null);
    setConfirming(null);
    try {
      const opened = await openSuggestionInDraft({
        id: suggestion.id,
        revision: suggestion.revision,
        policyEtag: live.etag,
        target: target === null ? null : { draftId: target.draftId, draftEtag: target.draftEtag },
      });
      const openedId = opened.draft.summary.draft_id;
      showServerDraft(opened.draft, true);
      setConversion(null);
      setBindings((current) => [
        ...current.filter(
          (binding) =>
            !(binding.draftId === openedId && binding.suggestion.id === opened.suggestion.id),
        ),
        { draftId: openedId, suggestion: opened.suggestion, ruleId: opened.rule.id, drafted: true },
      ]);
      setBindingProblems((current) => withoutKey(current, opened.suggestion.id));
      setView('edit');
      setActiveSection('rules');
      setPendingFocus(pointerTo('rules', opened.position));
      setNotice({
        title: 'Suggestion opened in a draft',
        message: `${opened.created ? 'New draft' : 'Draft'} ${openedId} holds the suggested rule at position ${opened.position}${
          opened.rule.id !== null ? ` (id ${opened.rule.id})` : ''
        }, revision ${opened.draft.summary.revision}. Nothing live changed, and the suggestion stays open until this draft is published with it.`,
        tone: 'info',
      });
      return { kind: 'opened' };
    } catch (error) {
      return await suggestionReviewRefused(error, suggestion, verification);
    } finally {
      endBusy();
      await loadDraftList();
    }
  }

  async function suggestionReviewRefused(
    error: unknown,
    suggestion: RuleSuggestion,
    verification: ReviewVerification,
  ): Promise<ReviewOutcome> {
    const reason = refusal(error);
    const nothing = 'Nothing was written.';
    if (error instanceof SuggestionConflictError) {
      if (
        error.current !== null &&
        (reason === SUGGESTION_NOT_OPEN_REASON || reason === SUGGESTION_REVISION_MISMATCH_REASON)
      ) {
        return {
          kind: 'problem',
          current: error.current,
          alert: {
            title: 'The suggestion changed',
            message: `It is no longer open at revision ${suggestion.revision}: the gateway holds revision ${error.current.revision}, ${error.current.state}. ${nothing}`,
            tone: 'warning',
          },
        };
      }
      if (reason === SUGGESTION_RULE_ALREADY_PRESENT_REASON) {
        return verification.target === null
          ? {
              kind: 'problem',
              mark: { kind: 'rule_live' },
              alert: {
                title: 'Rule already live',
                message:
                  'The live policy already holds the rule this suggestion proposes, so no draft was written. The suggestion is superseded: dismiss it. Accepting it would add the rule twice.',
                tone: 'warning',
              },
            }
          : {
              kind: 'problem',
              offerBind: true,
              alert: {
                title: 'Rule already in the open draft',
                message:
                  'The open draft already holds the rule this suggestion proposes, so nothing was written. You can publish that draft as this suggestion’s acceptance.',
                tone: 'info',
              },
            };
      }
      if (reason === SUGGESTION_RULE_ID_TAKEN_REASON) {
        return {
          kind: 'problem',
          alert: {
            title: 'Rule id already used',
            message: `The candidate already uses the rule id this suggestion proposes. Rename that rule in the draft, save it, and review the suggestion again. ${nothing}`,
            tone: 'warning',
          },
        };
      }
      if (reason === POLICY_DRAFT_BASE_STALE_REASON) {
        await loadLive();
        return {
          kind: 'problem',
          alert: {
            title: 'The open draft is on an older live revision',
            message: `The gateway does not rebase a draft to take a rule. ${nothing} The live policy has been read again: rebase the draft, then review the suggestion again.`,
            tone: 'warning',
          },
        };
      }
      if (reason === POLICY_DRAFT_PUBLISHED_REASON && verification.target !== null) {
        await reloadDraftWithoutEdits(verification.target.draftId);
        return {
          kind: 'problem',
          alert: {
            title: 'The open draft was published',
            message: `It accepts no further change. ${nothing} Review the suggestion into a new draft.`,
            tone: 'warning',
          },
        };
      }
      return {
        kind: 'problem',
        alert: {
          title: 'The gateway cannot draft this suggestion',
          message: `${error.message}. ${nothing}`,
          tone: 'warning',
        },
      };
    }
    if (error instanceof AdminApiError) {
      if (error.status === 412) {
        if (reason === POLICY_DRAFT_ETAG_MISMATCH_REASON && verification.target !== null) {
          await reloadDraftWithoutEdits(verification.target.draftId);
          return {
            kind: 'problem',
            alert: {
              title: 'The open draft changed elsewhere',
              message: `It changed in another tab or session since it was opened here, and has been read again. ${nothing} Review it, then review the suggestion again.`,
              tone: 'warning',
            },
          };
        }
        await loadLive();
        return {
          kind: 'problem',
          alert: {
            title: 'The live policy changed',
            message: `The suggestion was reviewed against a live revision that is no longer current (412). ${nothing} The live policy has been read again; review the suggestion against it.`,
            tone: 'warning',
          },
        };
      }
      if (error.status === 428) {
        return {
          kind: 'problem',
          alert: {
            title: 'Precondition missing',
            message: `The request lacked a revision it must be bound to (428). ${nothing} Reload the Policy Studio.`,
            tone: 'error',
          },
        };
      }
      if (error.status === 503) {
        const unavailable =
          reason === POLICY_DRAFTS_UNAVAILABLE_REASON
            ? 'The gateway answered 503: its draft store did not complete the request.'
            : 'The gateway answered 503: it could not settle the suggestion’s pending acceptances.';
        return verifyReview(
          verification,
          `${unavailable} Your drafts were read again instead of sending it again. `,
        );
      }
      if (error.status === 404 && reason !== POLICY_DRAFT_NOT_FOUND_REASON) {
        return {
          kind: 'problem',
          mark: { kind: 'gone' },
          refresh: true,
          alert: {
            title: 'Suggestion not found',
            message: `The gateway no longer holds this suggestion, or keeps no suggestions. ${nothing}`,
            tone: 'warning',
          },
        };
      }
      if (isDraftGone(error)) {
        return {
          kind: 'problem',
          alert: {
            title: 'The open draft is gone',
            message: `It expired or was deleted on the gateway. ${nothing} Review the suggestion into a new draft.`,
            tone: 'warning',
          },
        };
      }
      if (error.status === 403) {
        return {
          kind: 'problem',
          alert: {
            title: 'Permission required',
            message: `Review in draft needs admin:suggestions:read and admin:policy:write. ${nothing}`,
            tone: 'error',
          },
        };
      }
      if (error.status < 500) {
        const alert = writeAlert(error, 'Not reviewed');
        return { kind: 'problem', alert: { ...alert, message: `${alert.message} ${nothing}` } };
      }
    }
    return verifyReview(
      verification,
      'The gateway did not confirm the request, so it may or may not have written a draft. Your drafts were read again instead of sending it again. ',
    );
  }

  // Read the drafts to learn what a review request whose answer was lost
  // did. Only reads; the request is never sent again on the operator's
  // behalf.
  async function verifyReview(
    verification: ReviewVerification,
    prefix = '',
  ): Promise<ReviewOutcome> {
    try {
      const listed = await fetchPolicyDrafts();
      setDraftList(listed);
      setDraftListAlert(null);
      if (verification.target !== null) {
        const current = await fetchPolicyDraft(verification.target.draftId);
        if (current.summary.revision !== verification.target.revision) {
          if (
            draftRef.current?.summary.draft_id === current.summary.draft_id &&
            sourceRef.current === serverSourceRef.current
          ) {
            showServerDraft(current, true);
          }
          return {
            kind: 'problem',
            offerBind: true,
            alert: {
              title: 'The open draft changed',
              message: `${prefix}The open draft is now at revision ${current.summary.revision} (it was ${verification.target.revision}) and may hold the suggested rule; it is shown as the gateway holds it. Look for the rule under HTTP and MCP rules: if it is there, you can publish the draft as this suggestion’s acceptance.`,
              tone: 'warning',
            },
          };
        }
        return {
          kind: 'problem',
          verification,
          alert: {
            title: 'Not written as of now',
            message: `${prefix}The open draft is still at revision ${verification.target.revision}. The request may still be in progress: check again before reviewing the suggestion again.`,
            tone: 'warning',
          },
        };
      }
      const known = new Set(verification.knownDraftIds);
      const appeared = listed.drafts
        .map((summary) => summary.draft_id)
        .filter((id) => !known.has(id));
      if (appeared.length > 0) {
        return {
          kind: 'problem',
          newDrafts: appeared,
          alert: {
            title: appeared.length === 1 ? 'A new draft appeared' : 'New drafts appeared',
            message: `${prefix}The gateway now lists ${appeared.join(', ')}, which ${
              appeared.length === 1 ? 'was' : 'were'
            } not there before and may hold the suggested rule. Open it to check before reviewing the suggestion again.`,
            tone: 'warning',
          },
        };
      }
      return {
        kind: 'problem',
        verification,
        alert: {
          title: 'No new draft as of now',
          message: `${prefix}No draft that was not there before is listed. The request may still be in progress: check again before reviewing the suggestion again.`,
          tone: 'warning',
        },
      };
    } catch {
      return {
        kind: 'problem',
        verification,
        alert: {
          title: 'Outcome unknown',
          message: `${prefix}Your drafts could not be read either. Check again when the connection is back, before reviewing the suggestion again.`,
          tone: 'error',
        },
      };
    }
  }

  async function verifyReviewAgain(verification: ReviewVerification): Promise<ReviewOutcome> {
    if (!beginBusy('check')) {
      return {
        kind: 'problem',
        verification,
        alert: {
          title: 'Not checked',
          message: 'Another Policy Studio action is still in progress. Check again when it ends.',
          tone: 'info',
        },
      };
    }
    try {
      return await verifyReview(verification);
    } finally {
      endBusy();
    }
  }

  // The open draft already holds the suggestion's rule: publishing it bound
  // to the suggestion accepts it, if the gateway still finds the rule then.
  function bindSuggestionToOpenDraft(suggestion: RuleSuggestion) {
    if (draft === null) {
      return;
    }
    const boundId = draft.summary.draft_id;
    setBindings((current) => [
      ...current.filter(
        (binding) => !(binding.draftId === boundId && binding.suggestion.id === suggestion.id),
      ),
      { draftId: boundId, suggestion, ruleId: null, drafted: false },
    ]);
    setBindingProblems((current) => withoutKey(current, suggestion.id));
    setView('edit');
    setActiveSection('rules');
    setNotice({
      title: 'Suggestion bound to the open draft',
      message: `Publishing draft ${boundId} will accept suggestion ${suggestion.id} at revision ${suggestion.revision}, if the gateway still finds its rule in the draft then. Nothing changed now.`,
      tone: 'info',
    });
  }

  async function reloadDraftWithoutEdits(id: string) {
    try {
      const current = await fetchPolicyDraft(id);
      if (
        draftRef.current?.summary.draft_id === id &&
        sourceRef.current === serverSourceRef.current
      ) {
        showServerDraft(current, true);
      }
    } catch {
      // Shown as it was.
    }
  }

  function showRule(position: number) {
    setView('edit');
    setActiveSection('rules');
    setPendingFocus(pointerTo('rules', position));
  }

  function refreshSuggestionsIfListed() {
    if (canReadSuggestions && suggestions.list.loadedAt !== null) {
      void suggestions.refresh();
    }
  }

  function updateDocument(next: JsonObject) {
    setSource(formatCandidate(next));
  }

  function showDiagnostic(diagnostic: PolicyDiagnostic) {
    const section = sectionForPointer(diagnostic.pointer);
    setView('edit');
    setActiveSection(section);
    setPendingFocus(section === 'source' ? '' : diagnostic.pointer);
  }

  function onViewKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = rovingIndex(event.key, index, STUDIO_VIEWS.length);
    if (next === null) {
      return;
    }
    event.preventDefault();
    const target = STUDIO_VIEWS[next].id;
    setView(target);
    viewRefs.current.get(target)?.focus();
  }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = STUDIO_SECTIONS.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? (index + 1) % STUDIO_SECTIONS.length
        : event.key === 'ArrowLeft'
          ? (index + last) % STUDIO_SECTIONS.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    if (next === null) {
      return;
    }
    event.preventDefault();
    const section = STUDIO_SECTIONS[next].id;
    setActiveSection(section);
    tabRefs.current.get(section)?.focus();
  }

  const ownedDrafts = draftList?.drafts.length ?? 0;
  const ownerLimit = draftList?.limits.max_drafts_per_owner ?? null;
  const createBlocked =
    !canWrite ||
    live === null ||
    draftList === null ||
    dirty ||
    busy !== null ||
    (ownerLimit !== null && ownedDrafts >= ownerLimit);

  return (
    <main className="logs-page policy-studio-page">
      <section
        className="panel logs-panel policy-studio-panel"
        aria-labelledby="policy-studio-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Policy</p>
            <h2 id="policy-studio-heading">Policy Studio</h2>
          </div>
          <span className="result-count">
            {draft === null
              ? 'No draft open'
              : isPublished
                ? 'Published draft'
                : dirty
                  ? 'Unsaved edits'
                  : 'Draft saved'}
          </span>
        </div>

        <RuleWorkspaceNav />
        <AdminCapabilitiesNotice state={capabilities} />

        {capabilities.status === 'ready' && !canRead ? (
          <StudioAlertPanel
            alert={{
              title: 'Policy read permission required',
              message: 'The Policy Studio needs admin:policy:read.',
              tone: 'warning',
            }}
          />
        ) : null}
        {capabilities.status === 'ready' && canRead && !canWrite ? (
          <StudioAlertPanel
            alert={{
              title: 'Read-only',
              message:
                'You can read your policy drafts, but creating, editing, publishing or deleting one requires admin:policy:write.',
              tone: 'info',
            }}
          />
        ) : null}

        {readRequested && isLoading ? (
          <div className="loading-state" role="status">
            Loading the live policy and your drafts
          </div>
        ) : null}
        {liveAlert ? <StudioAlertPanel alert={liveAlert} /> : null}
        {draftListAlert ? <StudioAlertPanel alert={draftListAlert} /> : null}

        <div className="policy-studio-status" role="status" aria-live="polite">
          {notice ? <StudioAlertPanel alert={notice} live={false} /> : null}
        </div>

        {problem ? (
          <ProblemPanel
            panelRef={problemRef}
            problem={problem}
            busy={busy !== null}
            canWrite={canWrite}
            canCreate={canWrite && live !== null && parsed.ok}
            onReloadDraft={() => void reloadSavedDraft()}
            onOverwrite={() => void saveDraft(true)}
            onRefreshLive={() => void refreshLive()}
            onRebase={() => setConfirming('rebase')}
            onSaveAsNew={() => void createDraft(true)}
            onCheck={() => void checkDraftState()}
            onDismiss={() => setProblem(null)}
          />
        ) : null}

        {draftList !== null ? (
          <DraftListPanel
            list={draftList}
            liveEtag={live?.etag ?? null}
            openDraftId={draftId}
            busy={busy !== null}
            dirty={dirty}
            createBlocked={createBlocked}
            canWrite={canWrite}
            onOpen={(id) => void openDraft(id)}
            onCreate={() => void createDraft(false)}
          />
        ) : null}

        {canRead ? (
          <div
            className="policy-studio-tabs policy-studio-views"
            role="tablist"
            aria-label="Policy Studio views"
          >
            {STUDIO_VIEWS.map((entry, index) => {
              const selected = view === entry.id;
              return (
                <button
                  key={entry.id}
                  ref={(element) => {
                    if (element) viewRefs.current.set(entry.id, element);
                    else viewRefs.current.delete(entry.id);
                  }}
                  type="button"
                  role="tab"
                  id={`policy-studio-view-${entry.id}`}
                  aria-controls={`policy-studio-view-panel-${entry.id}`}
                  aria-selected={selected}
                  tabIndex={selected ? 0 : -1}
                  className={`rule-workspace-tab ${selected ? 'is-active' : ''}`}
                  onClick={() => setView(entry.id)}
                  onKeyDown={(event) => onViewKeyDown(event, index)}
                >
                  {entry.label}
                </button>
              );
            })}
          </div>
        ) : null}

        {canRead && view !== 'edit' && view !== 'suggestions' ? (
          <CandidatePicker
            choice={candidateChoice}
            draft={draft}
            dirty={dirty}
            live={live}
            onChoose={setCandidateChoice}
          />
        ) : null}

        <div
          className="policy-studio-view"
          role="tabpanel"
          id="policy-studio-view-panel-edit"
          aria-labelledby="policy-studio-view-edit"
          hidden={view !== 'edit'}
        >
          {draft !== null ? (
            <div className="policy-studio-layout">
              <div className="policy-studio-main">
                <RevisionSummary
                  draft={draft}
                  live={live}
                  baseStale={baseStale}
                  dirty={dirty}
                  inspection={currentInspection}
                />

                {openBindings.map((binding) => (
                  <SuggestionReview
                    key={binding.suggestion.id}
                    binding={binding}
                    draft={draft}
                    liveEtag={live?.etag ?? null}
                    dirty={dirty}
                    inspection={currentInspection}
                    checking={validation.kind === 'checking' || (validation.kind === 'ready' && validation.source !== source)}
                    staleReason={bindingStaleReason(binding)}
                    canSimulate={canSimulate}
                    canAnalyze={canAnalyze}
                    canAccept={canWriteSuggestions}
                    onShowRule={showRule}
                  />
                ))}

                <div className="form-actions policy-studio-actions">
                  <button
                    type="button"
                    className="primary-button"
                    disabled={!editable || !dirty || !parsed.ok || busy !== null}
                    onClick={() => void saveDraft()}
                  >
                    {busy === 'save' ? 'Saving draft' : 'Save draft'}
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={!dirty || busy !== null}
                    onClick={() => {
                      setSource(serverSource);
                      setConversion(null);
                    }}
                  >
                    Discard edits
                  </button>
                  <button
                    ref={actionRef('rebase')}
                    type="button"
                    className="secondary-button"
                    disabled={!editable || !baseStale || busy !== null}
                    onClick={() => setConfirming('rebase')}
                  >
                    Rebase onto live policy
                  </button>
                  <button
                    ref={actionRef('publish')}
                    type="button"
                    className="primary-button"
                    disabled={publishBlockers.length > 0 || busy !== null}
                    aria-describedby={
                      publishBlockers.length > 0 ? 'policy-studio-publish-blockers' : undefined
                    }
                    onClick={reviewPublication}
                  >
                    {busy === 'publish' ? 'Publishing' : 'Publish draft'}
                  </button>
                  <button
                    ref={actionRef('delete')}
                    type="button"
                    className="rule-danger-button"
                    disabled={!canWrite || busy !== null}
                    onClick={() => setConfirming('delete')}
                  >
                    Delete draft
                  </button>
                </div>
                {publishBlockers.length > 0 ? (
                  <div className="policy-studio-blockers" id="policy-studio-publish-blockers">
                    <p className="rule-hint">Publishing is unavailable:</p>
                    <ul>
                      {publishBlockers.map((blocker) => (
                        <li key={blocker}>{blocker}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}

                {confirming !== null &&
                live !== null &&
                (confirming !== 'publish' || publishReview !== null) ? (
                  <ConfirmationPanel
                    kind={confirming}
                    draft={draft}
                    live={live}
                    changed={changed}
                    review={confirming === 'publish' ? publishReview : null}
                    acceptance={
                      confirming === 'publish' && openBindings.length > 0
                        ? {
                            bindings: openBindings.map((binding) => ({
                              binding,
                              stale: bindingStaleReason(binding),
                            })),
                            canAccept: canWriteSuggestions,
                            onChoose: chooseAcceptance,
                          }
                        : null
                    }
                    confirmable={
                      confirming !== 'publish' || reviewIsCurrent(publishReview, source)
                    }
                    dirty={dirty}
                    busy={busy !== null}
                    onConfirm={() => {
                      if (confirming === 'publish') void publishDraft();
                      else if (confirming === 'rebase') void rebaseDraft();
                      else void deleteDraft();
                    }}
                    onCancel={() => {
                      restoreFocusTo.current = confirming;
                      setConfirming(null);
                    }}
                  />
                ) : null}

                <div className="policy-studio-tabs" role="tablist" aria-label="Policy sections">
                  {STUDIO_SECTIONS.map((section, index) => {
                    const count = parsed.ok
                      ? diagnosticsInSection(diagnostics, section.id).length
                      : 0;
                    const selected = activeSection === section.id;
                    return (
                      <button
                        key={section.id}
                        ref={(element) => {
                          if (element) tabRefs.current.set(section.id, element);
                          else tabRefs.current.delete(section.id);
                        }}
                        type="button"
                        role="tab"
                        id={`policy-studio-tab-${section.id}`}
                        aria-controls={selected ? `policy-studio-panel-${section.id}` : undefined}
                        aria-selected={selected}
                        aria-label={
                          count > 0
                            ? `${section.label}, ${count} ${count === 1 ? 'problem' : 'problems'}`
                            : undefined
                        }
                        tabIndex={selected ? 0 : -1}
                        className={`rule-workspace-tab ${selected ? 'is-active' : ''}`}
                        onClick={() => setActiveSection(section.id)}
                        onKeyDown={(event) => onTabKeyDown(event, index)}
                      >
                        {section.label}
                        {count > 0 ? (
                          <span className="badge warning policy-studio-tab-count" aria-hidden="true">
                            {count}
                          </span>
                        ) : null}
                      </button>
                    );
                  })}
                </div>

                <div
                  className="policy-studio-section"
                  role="tabpanel"
                  id={`policy-studio-panel-${activeSection}`}
                  aria-labelledby={`policy-studio-tab-${activeSection}`}
                >
                  {activeSection === 'source' ? (
                    <SourceSection
                      source={source}
                      parseError={parsed.ok ? null : parsed.message}
                      disabled={!editable}
                      register={register}
                      onChange={setSource}
                    />
                  ) : !parsed.ok ? (
                    <StudioAlertPanel
                      alert={{
                        title: 'Fix the source first',
                        message: `${parsed.message} The structured editors show the document again once Source holds a JSON object.`,
                        tone: 'warning',
                      }}
                    />
                  ) : activeSection === 'overview' ? (
                    <OverviewSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                      conversion={
                        <ConversionPanel
                          document={parsed.document}
                          conversion={conversion}
                          canConvert={editable && busy === null}
                          converting={busy === 'convert'}
                          onConvert={() => void convertDraft()}
                        />
                      }
                    />
                  ) : activeSection === 'roles' ? (
                    <RolesSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                    />
                  ) : activeSection === 'routes' ? (
                    <RoutesSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                    />
                  ) : activeSection === 'rules' ? (
                    <RulesSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                    />
                  ) : activeSection === 'tools' ? (
                    <ToolsSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                    />
                  ) : activeSection === 'rate_limits' ? (
                    <RateLimitsSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      disabled={!editable}
                      register={register}
                      onChange={updateDocument}
                    />
                  ) : (
                    <EgressSection
                      document={parsed.document}
                      diagnostics={diagnostics}
                      register={register}
                      changed={changesEgress}
                    />
                  )}
                </div>
              </div>

              <aside className="policy-studio-aside" aria-label="Validation and changes">
                <DiagnosticsPanel
                  validation={validation}
                  current={currentInspection !== null}
                  parseError={parsed.ok ? null : parsed.message}
                  onShow={showDiagnostic}
                  onRevalidate={revalidate}
                />
                <ChangesPanel live={live} changed={changed} parsed={parsed.ok} />
              </aside>
            </div>
          ) : null}

          {draft === null && draftList !== null && !isLoading ? (
            <div className="empty-state">
              {draftList.drafts.length === 0
                ? 'You have no policy drafts. Create one from the live policy to start editing.'
                : 'Open a draft to edit it.'}
            </div>
          ) : null}
        </div>

        {canRead ? (
          <div
            className="policy-studio-view"
            role="tabpanel"
            id="policy-studio-view-panel-suggestions"
            aria-labelledby="policy-studio-view-suggestions"
            hidden={view !== 'suggestions'}
          >
            <SuggestionsPanel
              handle={suggestions}
              canList={canReadSuggestions}
              canDismiss={canWriteSuggestions}
              reviewBlockers={suggestionReviewBlockers}
              into={reviewInto}
              onIntoChange={setReviewInto}
              openDraft={
                draft === null
                  ? null
                  : {
                      id: draft.summary.draft_id,
                      revision: draft.summary.revision,
                      blocker: openDraftBlocker,
                    }
              }
              positions={{
                live: live === null ? null : live.policy.rules.length,
                open:
                  draft === null || !Array.isArray(draft.policy.rules)
                    ? null
                    : draft.policy.rules.length,
              }}
              bindings={boundDrafts}
              busy={busy !== null}
              onReview={reviewSuggestion}
              onVerifyReview={verifyReviewAgain}
              onBind={bindSuggestionToOpenDraft}
              onOpenDraft={(id) => void openDraft(id)}
            />
          </div>
        ) : null}

        {canRead ? (
          <>
            {/* The workbench views stay mounted while hidden, so their cases,
                results and replay jobs survive a switch between views. */}
            <div
              className="policy-studio-view"
              role="tabpanel"
              id="policy-studio-view-panel-simulate"
              aria-labelledby="policy-studio-view-simulate"
              hidden={view !== 'simulate'}
            >
              <SimulatorPanel
                candidate={workbenchCandidate}
                candidateProblem={candidateProblem}
                canSimulate={canSimulate}
                validationBlocker={runBlocker(workbenchCandidate, currentInspection, 'simulation')}
                suiteSource={suiteSource}
                onSuiteChange={setSuiteSource}
                onReloadLive={() => void refreshLive()}
              />
            </div>
            <div
              className="policy-studio-view"
              role="tabpanel"
              id="policy-studio-view-panel-test"
              aria-labelledby="policy-studio-view-test"
              hidden={view !== 'test'}
            >
              <TestsPanel
                candidate={workbenchCandidate}
                candidateProblem={candidateProblem}
                canSimulate={canSimulate}
                validationBlocker={runBlocker(workbenchCandidate, currentInspection, 'tests')}
                suiteSource={suiteSource}
                onSuiteChange={setSuiteSource}
                onReloadLive={() => void refreshLive()}
              />
            </div>
            <div
              className="policy-studio-view"
              role="tabpanel"
              id="policy-studio-view-panel-impact"
              aria-labelledby="policy-studio-view-impact"
              hidden={view !== 'impact'}
            >
              <ImpactPanel
                candidate={workbenchCandidate}
                candidateProblem={candidateProblem}
                canReplay={canReplay}
                validationBlocker={runBlocker(workbenchCandidate, currentInspection, 'simulation')}
                onReloadLive={() => void refreshLive()}
              />
            </div>
            <div
              className="policy-studio-view"
              role="tabpanel"
              id="policy-studio-view-panel-optimize"
              aria-labelledby="policy-studio-view-optimize"
              hidden={view !== 'optimize'}
            >
              {view === 'optimize' ? (
                <OptimizePanel
                  candidate={workbenchCandidate}
                  candidateProblem={candidateProblem}
                  liveSource={liveSource}
                  draftValidation={{
                    checking:
                      validation.kind === 'checking' ||
                      (validation.kind === 'ready' && validation.source !== source),
                    inspection: currentInspection,
                    alert: validation.kind === 'failed' ? validation.alert : null,
                  }}
                  canEditDraft={editable}
                  canAnalyze={canAnalyze}
                  canWritePolicy={canWrite}
                  onShowInEditor={showDiagnostic}
                />
              ) : null}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function DraftListPanel({
  list,
  liveEtag,
  openDraftId,
  busy,
  dirty,
  createBlocked,
  canWrite,
  onOpen,
  onCreate,
}: {
  list: PolicyDraftList;
  liveEtag: string | null;
  openDraftId: string | null;
  busy: boolean;
  dirty: boolean;
  createBlocked: boolean;
  canWrite: boolean;
  onOpen: (id: string) => void;
  onCreate: () => void;
}) {
  const limits = list.limits;
  const atLimit = list.drafts.length >= limits.max_drafts_per_owner;
  return (
    <section className="policy-studio-drafts" aria-labelledby="policy-studio-drafts-heading">
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Workspace</p>
          <h3 id="policy-studio-drafts-heading">Your drafts</h3>
        </div>
        <span className="result-count">
          {list.drafts.length} of {limits.max_drafts_per_owner}
        </span>
      </div>
      <p className="rule-hint">
        Drafts are kept on the gateway, visible only to you, and expire{' '}
        {formatDuration(limits.ttl_seconds)} after their last save. Editing one
        changes nothing live; only publishing does.
      </p>
      {list.drafts.length > 0 ? (
        <ul className="policy-studio-draft-list" aria-label="Your policy drafts">
          {list.drafts.map((summary) => {
            const isOpen = summary.draft_id === openDraftId;
            const stale = liveEtag !== null && summary.base_etag !== liveEtag;
            return (
              <li key={summary.draft_id} className={isOpen ? 'is-open' : undefined}>
                <code>{summary.draft_id}</code>
                <span className={`badge ${summary.state === 'published' ? 'neutral' : 'success'}`}>
                  {summary.state === 'published' ? 'Published' : 'Open'}
                </span>
                {summary.state === 'open' && stale ? (
                  <span className="badge warning">Base stale</span>
                ) : null}
                <span className="rule-hint">
                  Revision {summary.revision}, saved{' '}
                  <time dateTime={summary.updated_at}>{summary.updated_at}</time>, expires{' '}
                  <time dateTime={summary.expires_at}>{summary.expires_at}</time>
                </span>
                <button
                  type="button"
                  className="secondary-button"
                  aria-label={`Open draft ${summary.draft_id}`}
                  disabled={isOpen || busy || dirty}
                  onClick={() => onOpen(summary.draft_id)}
                >
                  {isOpen ? 'Open now' : 'Open'}
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
      {canWrite ? (
        <div className="form-actions">
          <button
            type="button"
            className="secondary-button"
            disabled={createBlocked}
            aria-describedby="policy-studio-create-hint"
            onClick={onCreate}
          >
            New draft from live policy
          </button>
          <p className="rule-hint" id="policy-studio-create-hint">
            {dirty
              ? 'Save or discard the edits in the open draft first.'
              : atLimit
                ? `You already hold the maximum of ${limits.max_drafts_per_owner} drafts. Delete one first.`
                : 'Copies the live policy into a new draft pinned to its current revision.'}
          </p>
        </div>
      ) : null}
    </section>
  );
}

function RevisionSummary({
  draft,
  live,
  baseStale,
  dirty,
  inspection,
}: {
  draft: PolicyDraft;
  live: LivePolicy | null;
  baseStale: boolean;
  dirty: boolean;
  inspection: PolicyInspection | null;
}) {
  const summary = draft.summary;
  return (
    <dl className="policy-studio-revisions" aria-label="Draft revisions">
      <div>
        <dt>Draft</dt>
        <dd>
          <code>{summary.draft_id}</code>
        </dd>
      </div>
      <div>
        <dt>Revision</dt>
        <dd>
          {summary.revision}
          <span className={`badge ${summary.state === 'published' ? 'neutral' : 'success'}`}>
            {summary.state === 'published' ? 'Published' : 'Open'}
          </span>
          <span className={`badge ${dirty ? 'warning' : 'neutral'}`}>
            {dirty ? 'Unsaved edits' : 'Saved'}
          </span>
        </dd>
      </div>
      <div>
        <dt>Live policy</dt>
        <dd>
          <code title={live?.etag}>{shortEtag(live?.etag)}</code>
        </dd>
      </div>
      <div>
        <dt>Pinned base</dt>
        <dd>
          <code title={summary.base_etag}>{shortEtag(summary.base_etag)}</code>{' '}
          {summary.state === 'published' ? null : baseStale ? (
            <span className="badge warning">Stale: the live policy changed</span>
          ) : (
            <span className="badge success">Current</span>
          )}
        </dd>
      </div>
      <div>
        <dt>Saved candidate</dt>
        <dd>
          <code title={summary.candidate_etag}>{shortEtag(summary.candidate_etag)}</code>
        </dd>
      </div>
      {summary.published_etag ? (
        <div>
          <dt>Published as</dt>
          <dd>
            <code title={summary.published_etag}>{shortEtag(summary.published_etag)}</code>
          </dd>
        </div>
      ) : null}
      <div>
        <dt>Semantic digest</dt>
        <dd>
          {inspection?.semantic_digest ? (
            <code title={inspection.semantic_digest}>{shortEtag(inspection.semantic_digest)}</code>
          ) : (
            <span className="rule-hint">After validation of a v1 candidate</span>
          )}
        </dd>
      </div>
      <div>
        <dt>Resource snapshot</dt>
        <dd>
          {inspection?.resource_snapshot?.digest ? (
            <code title={inspection.resource_snapshot.digest}>
              {shortEtag(inspection.resource_snapshot.digest)}
            </code>
          ) : inspection?.resource_snapshot ? (
            <span className="badge warning">Incomplete</span>
          ) : (
            <span className="rule-hint">
              {inspection === null ? 'After validation' : 'Not reported'}
            </span>
          )}
        </dd>
      </div>
      <div>
        <dt>Expires</dt>
        <dd>
          <time dateTime={summary.expires_at}>{summary.expires_at}</time>
        </dd>
      </div>
    </dl>
  );
}

function ConversionPanel({
  document,
  conversion,
  canConvert,
  converting,
  onConvert,
}: {
  document: JsonObject;
  conversion: PolicyConversion | null;
  canConvert: boolean;
  converting: boolean;
  onConvert: () => void;
}) {
  const changes = conversion?.converted ? conversion.changes : [];
  return (
    <>
      {!isPolicyV1(document) ? (
        <div className="error-panel alert info" role="note">
          <h3>This candidate is a 0.x document</h3>
          <p>
            Policy v1 gives every rule, route and rate override a stable id and
            refuses unknown members. The gateway converts it and verifies the
            result authorizes exactly as before; the draft changes only when
            you save it.
          </p>
          <button
            type="button"
            className="secondary-button"
            disabled={!canConvert}
            onClick={onConvert}
          >
            {converting ? 'Converting' : 'Convert to policy v1'}
          </button>
        </div>
      ) : null}
      {changes.length > 0 ? (
        <section className="policy-studio-conversion" aria-label="Conversion changes">
          <h4>What the conversion changed</h4>
          <ul>
            {changes.map((change, index) => (
              <li key={index}>
                <code>{change.pointer || '/'}</code>{' '}
                {change.element_id ? <code>{change.element_id}</code> : null} {change.message}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </>
  );
}

function DiagnosticsPanel({
  validation,
  current,
  parseError,
  onShow,
  onRevalidate,
}: {
  validation: ValidationState;
  current: boolean;
  parseError: string | null;
  onShow: (diagnostic: PolicyDiagnostic) => void;
  onRevalidate: () => void;
}) {
  const inspection =
    validation.kind === 'ready'
      ? validation.inspection
      : validation.kind === 'checking'
        ? validation.previous
        : null;
  const diagnostics = inspection?.diagnostics ?? [];
  const counts = countBySeverity(diagnostics);
  const summary = severitySummary(counts);
  const snapshot = inspection?.resource_snapshot ?? null;
  const status =
    validation.kind === 'idle'
      ? 'Nothing to validate.'
      : validation.kind === 'failed'
        ? `${validation.alert.title}.`
        : validation.kind === 'checking' || !current
          ? 'Checking the latest edit with the gateway.'
          : inspection?.valid
            ? summary === ''
              ? 'Valid: the gateway reports no diagnostics.'
              : `Valid, with ${summary}.`
            : `Invalid: ${summary === '' ? 'refused' : summary}.`;

  return (
    <section className="policy-studio-diagnostics" aria-labelledby="policy-studio-diagnostics-heading">
      <div className="section-heading">
        <p className="eyebrow">Validation</p>
        <h3 id="policy-studio-diagnostics-heading">Diagnostics</h3>
      </div>
      <p className="policy-studio-validation-status" role="status" aria-live="polite">
        {status}
      </p>
      {parseError ? <p className="rule-hint is-error">{parseError}</p> : null}
      {validation.kind === 'failed' ? <StudioAlertPanel alert={validation.alert} /> : null}
      {validation.kind === 'checking' && inspection !== null ? (
        <p className="rule-hint">The list below is from the previous check.</p>
      ) : null}
      {inspection !== null && inspection.errors.length > 0 && diagnostics.length === 0 ? (
        <ul className="studio-field-problems">
          {inspection.errors.map((error, index) => (
            <li className="studio-problem error" key={index}>
              {error}
            </li>
          ))}
        </ul>
      ) : null}
      {diagnostics.length > 0 ? (
        <ol className="policy-studio-diagnostic-list" aria-label="Policy diagnostics">
          {diagnostics.map((diagnostic, index) => {
            const uses = blockedUses(diagnostic);
            return (
              <li key={`${index}:${diagnostic.code}:${diagnostic.pointer}`} className={diagnostic.severity}>
                <div className="policy-studio-diagnostic-head">
                  <span className={`badge ${severityBadge(diagnostic.severity)}`}>
                    {severityLabel(diagnostic.severity)}
                  </span>
                  <code>{diagnostic.code}</code>
                </div>
                <p>{diagnostic.message}</p>
                <p className="rule-hint">{diagnostic.remediation}</p>
                <p className="rule-hint">
                  At <code>{diagnostic.pointer || '(whole document)'}</code>
                  {diagnostic.element_id ? (
                    <>
                      {' '}in <code>{diagnostic.element_id}</code>
                    </>
                  ) : null}
                  {uses.length > 0 ? `. Blocks ${uses.join(', ')}.` : '.'}
                </p>
                <button
                  type="button"
                  className="secondary-button"
                  aria-label={`Show in editor: ${diagnostic.pointer || 'the whole document'}`}
                  onClick={() => onShow(diagnostic)}
                >
                  Show in editor
                </button>
              </li>
            );
          })}
        </ol>
      ) : null}
      {snapshot !== null && !snapshot.complete ? (
        <p className="rule-hint">
          Some resources could not be read, so the checks that need them did not run
          {snapshot.unavailable.length > 0 ? `: ${snapshot.unavailable.join(', ')}` : ''}.
        </p>
      ) : null}
      {inspection?.source_digest ? (
        <p className="rule-hint">
          Source digest <code title={inspection.source_digest}>{shortEtag(inspection.source_digest)}</code>
        </p>
      ) : null}
      {validation.kind !== 'idle' ? (
        <div className="form-actions">
          <button
            type="button"
            className="secondary-button"
            disabled={validation.kind === 'checking'}
            onClick={onRevalidate}
          >
            Validate again
          </button>
        </div>
      ) : null}
    </section>
  );
}

function ChangesPanel({
  live,
  changed,
  parsed,
}: {
  live: LivePolicy | null;
  changed: readonly string[];
  parsed: boolean;
}) {
  return (
    <section className="policy-studio-changes" aria-labelledby="policy-studio-changes-heading">
      <div className="section-heading">
        <p className="eyebrow">Compared with live</p>
        <h3 id="policy-studio-changes-heading">Changes</h3>
      </div>
      {live === null ? (
        <p className="rule-hint">The live policy has not been read.</p>
      ) : !parsed ? (
        <p className="rule-hint">Shown again once Source holds a JSON object.</p>
      ) : changed.length === 0 ? (
        <p className="rule-hint">
          This candidate is the same as live revision {shortEtag(live.etag)}.
        </p>
      ) : (
        <>
          <p className="rule-hint">
            Publishing replaces live revision {shortEtag(live.etag)}; these
            sections differ from it:
          </p>
          <ul className="rule-chip-list" aria-label="Changed sections">
            {changed.map((member) => (
              <li className="rule-chip" key={member}>
                {member}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

// A publish confirmation shows only its review, read when it opened; the
// others describe the draft as it is now.
function ConfirmationPanel({
  kind,
  draft,
  live,
  changed,
  review,
  acceptance,
  confirmable,
  dirty,
  busy,
  onConfirm,
  onCancel,
}: {
  kind: Confirmation;
  draft: PolicyDraft;
  live: LivePolicy;
  changed: readonly string[];
  review: PublishReview | null;
  // The suggestions whose rules this draft holds, one of which the
  // publication may accept.
  acceptance: Readonly<{
    bindings: ReadonlyArray<Readonly<{ binding: SuggestionBinding; stale: string | null }>>;
    canAccept: boolean;
    onChoose: (suggestionId: string | null) => void;
  }> | null;
  confirmable: boolean;
  dirty: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
  }, [kind]);

  const risks = kind === 'publish' ? (review?.risks ?? []) : [];
  const title =
    kind === 'publish'
      ? 'Publish this draft?'
      : kind === 'rebase'
        ? 'Rebase this draft onto the live policy?'
        : 'Delete this draft?';
  const message =
    kind === 'publish'
      ? review === null
        ? 'Nothing has been reviewed for publication.'
        : `Publishing replaces live revision ${shortEtag(review.liveEtag)} with revision ${review.revision} of this draft, for every request, at once. ${
            review.changed.length > 0
              ? `Changed sections: ${review.changed.join(', ')}.`
              : 'The candidate is the same as the live policy.'
          }${
            review.binding !== null
              ? ` It also accepts suggestion ${review.binding.suggestion.id} at revision ${review.binding.suggestion.revision}, in the same commit: if that suggestion moved, or the draft no longer holds its rule, nothing is published.`
              : ''
          }`
      : kind === 'rebase'
        ? `The draft will be pinned to live revision ${shortEtag(live.etag)}${
            dirty ? ', with your unsaved edits saved,' : ''
          } and no longer to ${shortEtag(draft.summary.base_etag)}. Rebasing does not merge: changes made to the live policy since the old base are replaced when this draft is published. ${
            changed.length > 0
              ? `Sections that differ from the live policy now: ${changed.join(', ')}.`
              : 'The candidate is the same as the live policy.'
          }`
        : `Draft ${draft.summary.draft_id} will be deleted from the gateway${
            dirty ? ', and the unsaved edits here discarded' : ''
          }. The live policy is unchanged.`;
  const confirmLabel =
    kind === 'publish' ? 'Confirm publish' : kind === 'rebase' ? 'Confirm rebase' : 'Confirm delete';

  return (
    <div
      className="policy-studio-confirmation"
      role="group"
      aria-labelledby="policy-studio-confirmation-title"
      aria-describedby="policy-studio-confirmation-message"
      onKeyDown={(event) => {
        if (event.key === 'Escape' && !busy) {
          event.preventDefault();
          event.stopPropagation();
          onCancel();
        }
      }}
    >
      <h3 id="policy-studio-confirmation-title">{title}</h3>
      <p id="policy-studio-confirmation-message">{message}</p>
      {kind === 'publish' && acceptance !== null && review !== null ? (
        <fieldset className="rule-fieldset policy-studio-acceptance">
          <legend>Suggestion this publication accepts</legend>
          {acceptance.bindings.map(({ binding, stale }) => (
            <label key={binding.suggestion.id} className="policy-studio-suggestion-choice">
              <input
                type="radio"
                name="policy-studio-acceptance"
                checked={review.binding?.suggestion.id === binding.suggestion.id}
                disabled={busy || !acceptance.canAccept || stale !== null}
                onChange={() => acceptance.onChoose(binding.suggestion.id)}
              />
              Accept suggestion {binding.suggestion.id} ({targetText(binding.suggestion.proposed_rule)},
              revision {binding.suggestion.revision})
              {stale !== null ? ` — stale: ${stale}` : ''}
            </label>
          ))}
          <label className="policy-studio-suggestion-choice">
            <input
              type="radio"
              name="policy-studio-acceptance"
              checked={review.binding === null}
              disabled={busy}
              onChange={() => acceptance.onChoose(null)}
            />
            Accept no suggestion: they stay open
          </label>
          {!acceptance.canAccept ? (
            <p className="rule-hint">Accepting a suggestion needs admin:suggestions:write.</p>
          ) : null}
          <p className="rule-hint">
            A publication accepts at most one suggestion. One it does not accept stays open even
            though its rule goes live; dismiss it afterwards.
          </p>
        </fieldset>
      ) : null}
      {kind === 'publish' && risks.length > 0 ? (
        <div>
          <p>
            The gateway reports {risks.length === 1 ? 'a risk' : `${risks.length} risks`} this
            publication carries:
          </p>
          <ul>
            {risks.map((risk, index) => (
              <li key={`${index}:${risk.code}:${risk.pointer}`}>
                {risk.message} <code>{risk.pointer || '/'}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="rule-delete-confirmation">
        <button
          ref={confirmRef}
          type="button"
          className={kind === 'delete' ? 'rule-danger-button' : 'primary-button'}
          disabled={busy || !confirmable}
          onClick={onConfirm}
        >
          {confirmLabel}
        </button>
        <button type="button" className="secondary-button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function ProblemPanel({
  panelRef,
  problem,
  busy,
  canWrite,
  canCreate,
  onReloadDraft,
  onOverwrite,
  onRefreshLive,
  onRebase,
  onSaveAsNew,
  onCheck,
  onDismiss,
}: {
  panelRef: RefObject<HTMLDivElement | null>;
  problem: StudioProblem;
  busy: boolean;
  canWrite: boolean;
  canCreate: boolean;
  onReloadDraft: () => void;
  onOverwrite: () => void;
  onRefreshLive: () => void;
  onRebase: () => void;
  onSaveAsNew: () => void;
  onCheck: () => void;
  onDismiss: () => void;
}) {
  if (problem.kind === 'alert') {
    return (
      <div ref={panelRef} tabIndex={-1} className="policy-studio-problem">
        <StudioAlertPanel alert={problem.alert} />
        <div className="form-actions">
          <button type="button" className="secondary-button" onClick={onDismiss}>
            Dismiss
          </button>
        </div>
      </div>
    );
  }

  const title =
    problem.kind === 'draft-changed'
      ? 'The draft changed elsewhere'
      : problem.kind === 'base-stale'
        ? 'The live policy changed'
        : problem.kind === 'draft-gone'
          ? 'The draft cannot take this change'
          : 'Outcome unknown';

  return (
    <div
      ref={panelRef}
      tabIndex={-1}
      className="policy-studio-problem error-panel alert warning"
      role="alert"
    >
      <h3>{title}</h3>
      <p>{problem.message}</p>
      <div className="form-actions">
        {problem.kind === 'draft-changed' ? (
          <>
            <button type="button" className="secondary-button" disabled={busy} onClick={onReloadDraft}>
              Load the saved draft (discard my edits)
            </button>
            {canWrite ? (
              <button type="button" className="secondary-button" disabled={busy} onClick={onOverwrite}>
                Keep my edits and save over it
              </button>
            ) : null}
          </>
        ) : null}
        {problem.kind === 'base-stale' ? (
          <>
            <button type="button" className="secondary-button" disabled={busy} onClick={onRefreshLive}>
              Read the live policy again
            </button>
            {canWrite ? (
              <button type="button" className="secondary-button" disabled={busy} onClick={onRebase}>
                Review rebase
              </button>
            ) : null}
          </>
        ) : null}
        {problem.kind === 'draft-gone' && canCreate ? (
          <button type="button" className="secondary-button" disabled={busy} onClick={onSaveAsNew}>
            Save my edits as a new draft
          </button>
        ) : null}
        {problem.kind === 'save-unknown' || problem.kind === 'publish-unknown' ? (
          <button type="button" className="secondary-button" disabled={busy} onClick={onCheck}>
            Check the draft on the gateway
          </button>
        ) : null}
        <button type="button" className="secondary-button" disabled={busy} onClick={onDismiss}>
          Dismiss
        </button>
      </div>
    </div>
  );
}

// The draft's current validation already answers that the gateway would
// refuse to simulate or test the candidate.
function runBlocker(
  candidate: WorkbenchCandidate | null,
  inspection: PolicyInspection | null,
  use: 'simulation' | 'tests',
): string | null {
  if (candidate === null || candidate.kind !== 'draft' || inspection === null) {
    return null;
  }
  const blocked =
    inspection.diagnostics.some((diagnostic) => diagnostic.blocks[use]) ||
    (!inspection.valid && inspection.diagnostics.length === 0);
  return blocked
    ? `The candidate’s validation reports problems that rule out ${use === 'tests' ? 'a test run' : 'a simulation or replay'}. Fix them in the editors first.`
    : null;
}

// Arrow keys, Home and End move between tabs, wrapping at the ends.
function rovingIndex(key: string, index: number, count: number): number | null {
  if (key === 'ArrowRight') return (index + 1) % count;
  if (key === 'ArrowLeft') return (index + count - 1) % count;
  if (key === 'Home') return 0;
  if (key === 'End') return count - 1;
  return null;
}

function CandidatePicker({
  choice,
  draft,
  dirty,
  live,
  onChoose,
}: {
  choice: 'draft' | 'live';
  draft: PolicyDraft | null;
  dirty: boolean;
  live: LivePolicy | null;
  onChoose: (choice: 'draft' | 'live') => void;
}) {
  const effective = choice === 'draft' && draft !== null ? 'draft' : 'live';
  return (
    <fieldset className="rule-fieldset workbench-candidate">
      <legend>Candidate</legend>
      <div className="studio-choice-grid">
        <label className={`studio-choice ${effective === 'draft' ? 'is-selected' : ''}`}>
          <input
            type="radio"
            name="policy-studio-candidate"
            value="draft"
            checked={effective === 'draft'}
            disabled={draft === null}
            onChange={() => onChoose('draft')}
          />
          <span className="studio-choice-label">The open draft</span>
          <span className="rule-hint">
            {draft === null
              ? 'Open a draft to use its candidate.'
              : `Draft ${draft.summary.draft_id}, revision ${draft.summary.revision}${dirty ? ', with the unsaved edits on screen' : ''}.`}
          </span>
        </label>
        <label className={`studio-choice ${effective === 'live' ? 'is-selected' : ''}`}>
          <input
            type="radio"
            name="policy-studio-candidate"
            value="live"
            checked={effective === 'live'}
            onChange={() => onChoose('live')}
          />
          <span className="studio-choice-label">The live policy</span>
          <span className="rule-hint">The policy the gateway enforces now, unchanged.</span>
        </label>
      </div>
      <p className="rule-hint">
        {live === null
          ? 'The live policy has not been read.'
          : `Runs are pinned to live revision ${shortEtag(live.etag)}; a candidate is sent as written and never stored.`}
      </p>
    </fieldset>
  );
}

function publicationBlockers({
  canWrite,
  isPublished,
  dirty,
  live,
  baseStale,
  inspection,
  changesEgress,
}: {
  canWrite: boolean;
  isPublished: boolean;
  dirty: boolean;
  live: LivePolicy | null;
  baseStale: boolean;
  inspection: PolicyInspection | null;
  changesEgress: boolean;
}): string[] {
  const blockers: string[] = [];
  if (!canWrite) blockers.push('Publishing requires admin:policy:write.');
  if (isPublished) {
    blockers.push('This draft was already published.');
    return blockers;
  }
  if (dirty) blockers.push('Save your edits first: only the saved draft is published.');
  if (live === null) blockers.push('The live policy has not been read.');
  if (baseStale) {
    blockers.push('The live policy changed after this draft was pinned. Review it and rebase the draft first.');
  }
  if (!dirty) {
    if (inspection === null) {
      blockers.push('Wait for the gateway to validate the saved draft.');
    } else if (!inspection.valid || blocksPublication(inspection.diagnostics)) {
      blockers.push('Resolve the diagnostics that block publication.');
    }
  }
  if (changesEgress) {
    blockers.push('This draft changes egress, which the policy API cannot apply.');
  }
  return blockers;
}

function refusal(error: unknown): string | null {
  return error instanceof AdminApiError ? error.code : null;
}

function withoutKey<T>(map: ReadonlyMap<string, T>, key: string): ReadonlyMap<string, T> {
  if (!map.has(key)) {
    return map;
  }
  const next = new Map(map);
  next.delete(key);
  return next;
}

function isDraftGone(error: unknown): boolean {
  const reason = refusal(error);
  return reason === POLICY_DRAFT_NOT_FOUND_REASON || reason === POLICY_DRAFT_EXPIRED_REASON;
}

// A write whose outcome the client cannot know: the answer was lost, or a
// server error may have come after something was written.
function isAmbiguous(error: unknown): boolean {
  if (error instanceof AdminApiError) {
    return error.status >= 500 && error.code !== POLICY_DRAFTS_UNAVAILABLE_REASON;
  }
  return !(error instanceof DOMException && error.name === 'AbortError');
}

function readAlert(error: unknown, title: string): StudioAlert {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        title: 'Sign in required',
        message: 'Your admin session ended. Sign in again to use the Policy Studio.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        title: 'Policy read permission required',
        message: 'This session does not include admin:policy:read.',
        tone: 'error',
      };
    }
    if (error.status === 404 && error.code === POLICY_DRAFT_NOT_FOUND_REASON) {
      return { title, message: 'The draft no longer exists.', tone: 'warning' };
    }
    if (error.status === 410) {
      return { title, message: 'The draft expired.', tone: 'warning' };
    }
    return { title, message: error.message, tone: error.status === 404 ? 'warning' : 'error' };
  }
  return {
    title,
    message:
      error instanceof Error
        ? `Network request failed: ${error.message}`
        : 'Network request failed.',
    tone: 'error',
  };
}

function writeAlert(error: unknown, title: string): StudioAlert {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        title: 'Sign in required',
        message:
          'Your admin session ended. Sign in again without leaving this page: your unsaved edits are held until then, and come back when the gateway confirms the new session owns this draft.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        title: 'Policy write permission required',
        message: 'This session does not include admin:policy:write.',
        tone: 'error',
      };
    }
    if (error.status === 400 && error.validationErrors.length > 0) {
      return {
        title,
        message: 'The gateway refused the candidate:',
        tone: 'warning',
        details: error.validationErrors,
      };
    }
    if (error.code === POLICY_DRAFT_TOO_LARGE_REASON || error.status === 413) {
      return { title, message: 'The candidate is larger than a draft may be.', tone: 'error' };
    }
    if (
      error.code === POLICY_DRAFT_OWNER_QUOTA_REASON ||
      error.code === POLICY_DRAFT_DEPLOYMENT_QUOTA_REASON
    ) {
      return {
        title,
        message:
          error.code === POLICY_DRAFT_OWNER_QUOTA_REASON
            ? 'You already hold the maximum number of drafts. Delete one first.'
            : 'The gateway already holds the maximum number of drafts. Ask another operator to delete one.',
        tone: 'warning',
      };
    }
    if (error.status === 428) {
      return {
        title,
        message: 'The request lacked the revision it is bound to. Reload the Policy Studio.',
        tone: 'error',
      };
    }
    return { title, message: error.message, tone: error.status === 409 ? 'warning' : 'error' };
  }
  return readAlert(error, title);
}

function validationAlert(error: unknown): StudioAlert {
  if (error instanceof AdminApiError && error.status === 413) {
    return {
      title: 'Too large to validate',
      message: 'The candidate is larger than the gateway accepts in one request.',
      tone: 'error',
    };
  }
  return readAlert(error, 'Validation unavailable');
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(bytes % (1024 * 1024) === 0 ? 0 : 1)} MiB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(bytes % 1024 === 0 ? 0 : 1)} KiB`;
  }
  return `${bytes} bytes`;
}

function formatDuration(seconds: number): string {
  if (seconds % 3600 === 0) {
    const hours = seconds / 3600;
    return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  }
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  }
  return `${seconds} seconds`;
}

// Leaving with unsaved edits asks first: closing or reloading the page, and
// following a link out of the Studio. The candidate lives only in memory.
function useLeaveWarning(active: boolean, message: string) {
  useEffect(() => {
    if (!active) {
      return;
    }
    function beforeUnload(event: BeforeUnloadEvent) {
      event.preventDefault();
      event.returnValue = '';
    }
    function linkClick(event: MouseEvent) {
      if (
        event.defaultPrevented ||
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      ) {
        return;
      }
      const link =
        event.target instanceof Element ? event.target.closest('a[href]') : null;
      if (link === null || link.getAttribute('target') === '_blank') {
        return;
      }
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    }
    window.addEventListener('beforeunload', beforeUnload);
    document.addEventListener('click', linkClick, true);
    return () => {
      window.removeEventListener('beforeunload', beforeUnload);
      document.removeEventListener('click', linkClick, true);
    };
  }, [active, message]);
}
