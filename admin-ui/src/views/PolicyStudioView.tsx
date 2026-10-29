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
import { fetchPolicy, type PolicyDocument } from '../lib/policy';
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
import { RuleWorkspaceNav } from './RuleWorkspaceNav';

export const POLICY_VALIDATE_DEBOUNCE_MS = 400;

const POLICY_READ_PERMISSION = 'admin:policy:read';
const POLICY_WRITE_PERMISSION = 'admin:policy:write';
const LEAVE_WARNING =
  'This draft has unsaved edits. Leave the Policy Studio and discard them?';

type LivePolicy = { policy: PolicyDocument; etag: string };

type StudioAlert = {
  title: string;
  message: string;
  tone: 'info' | 'warning' | 'error';
  details?: readonly string[];
};

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
  | 'check';

type Confirmation = 'publish' | 'rebase' | 'delete';

export function PolicyStudioView() {
  const capabilities = useAdminCapabilities();
  const [writeRejected, setWriteRejected] = useState(false);
  const canRead = hasAdminPermission(capabilities, POLICY_READ_PERMISSION);
  const canWrite =
    !writeRejected && hasAdminPermission(capabilities, POLICY_WRITE_PERMISSION);
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

  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [serverSource, setServerSource] = useState('');
  const [source, setSourceState] = useState('');
  const sourceRef = useRef('');
  const [activeSection, setActiveSection] = useState<StudioSection>('overview');
  const [validation, setValidation] = useState<ValidationState>({ kind: 'idle' });
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const busyRef = useRef(false);
  const [problem, setProblem] = useState<StudioProblem | null>(null);
  const [notice, setNotice] = useState<StudioAlert | null>(null);
  const [confirming, setConfirming] = useState<Confirmation | null>(null);
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

  const setSource = useCallback((next: string) => {
    sourceRef.current = next;
    setSourceState(next);
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

  useLeaveWarning(dirty, LEAVE_WARNING);

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
    setDraft(next);
    setServerSource(formatted);
    if (replaceLocal) {
      setSource(formatted);
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

  async function publishDraft() {
    if (!editable || draft === null || live === null || !beginBusy('publish')) {
      return;
    }
    setConfirming(null);
    setProblem(null);
    setNotice(null);
    const published = draft;
    try {
      const result = await publishPolicyDraft(
        published.summary.draft_id,
        published.etag,
        live.etag,
        currentInspection?.resource_snapshot?.digest ?? null,
      );
      const warnings: string[] = [];
      if (!result.draftStateRecorded) {
        warnings.push(
          'The draft could not be marked published, so it stays open on a base that is no longer live. Delete it, or rebase it before reusing it.',
        );
      }
      if (result.historyAppendWarning) {
        warnings.push('The change could not be recorded in policy version history.');
      }
      setNotice({
        title: 'Draft published',
        message: `The live policy is now revision ${shortEtag(result.etag)}.`,
        tone: warnings.length > 0 ? 'warning' : 'info',
        details: warnings,
      });
      await refreshAfterPublication(published.summary.draft_id);
    } catch (error) {
      noteWriteError(error);
      await handlePublishError(error, published);
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
          setProblem(null);
          setNotice({
            title: 'Draft published',
            message: `The gateway confirms the publication: the live policy is revision ${shortEtag(latestLive?.etag)}.`,
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
    setDraft(null);
    setServerSource('');
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

  async function handlePublishError(error: unknown, published: PolicyDraft) {
    const reason = refusal(error);
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

  function updateDocument(next: JsonObject) {
    setSource(formatCandidate(next));
  }

  function showDiagnostic(diagnostic: PolicyDiagnostic) {
    const section = sectionForPointer(diagnostic.pointer);
    setActiveSection(section);
    setPendingFocus(section === 'source' ? '' : diagnostic.pointer);
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

  const publishBlockers = publicationBlockers({
    canWrite,
    isPublished,
    dirty,
    live,
    baseStale,
    inspection: currentInspection,
    changesEgress,
  });
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
                  onClick={() => setConfirming('publish')}
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

              {confirming !== null && live !== null ? (
                <ConfirmationPanel
                  kind={confirming}
                  draft={draft}
                  live={live}
                  changed={changed}
                  risks={
                    currentInspection?.diagnostics.filter(
                      (diagnostic) => diagnostic.severity === 'risk',
                    ) ?? []
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

function ConfirmationPanel({
  kind,
  draft,
  live,
  changed,
  risks,
  dirty,
  busy,
  onConfirm,
  onCancel,
}: {
  kind: Confirmation;
  draft: PolicyDraft;
  live: LivePolicy;
  changed: readonly string[];
  risks: readonly PolicyDiagnostic[];
  dirty: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
  }, [kind]);

  const title =
    kind === 'publish'
      ? 'Publish this draft?'
      : kind === 'rebase'
        ? 'Rebase this draft onto the live policy?'
        : 'Delete this draft?';
  const message =
    kind === 'publish'
      ? `Publishing replaces live revision ${shortEtag(live.etag)} with revision ${draft.summary.revision} of this draft, for every request, at once. ${
          changed.length > 0
            ? `Changed sections: ${changed.join(', ')}.`
            : 'The candidate is the same as the live policy.'
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
          disabled={busy}
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

function StudioAlertPanel({ alert, live = true }: { alert: StudioAlert; live?: boolean }) {
  return (
    <div
      className={`error-panel alert ${alert.tone}`}
      role={live ? (alert.tone === 'info' ? 'status' : 'alert') : undefined}
    >
      <h3>{alert.title}</h3>
      <p>{alert.message}</p>
      {alert.details && alert.details.length > 0 ? (
        <ul>
          {alert.details.map((detail, index) => (
            <li key={index}>{detail}</li>
          ))}
        </ul>
      ) : null}
    </div>
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
        message: 'Your admin session ended. Sign in again; your edits are kept until you leave the page.',
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
