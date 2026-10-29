import { useId, type ReactNode } from 'react';

import { AdminApiError } from '../../../lib/api';
import {
  POLICY_CANDIDATE_INVALID_REASON,
  type PolicyRunCandidate,
  type PolicyRunRefusal,
} from '../../../lib/policyRuns';
import {
  POLICY_REPLAY_AUDIT_UNAVAILABLE_REASON,
  POLICY_REPLAY_IDEMPOTENCY_CONFLICT_REASON,
  POLICY_REPLAY_NOT_FOUND_REASON,
  POLICY_REPLAY_QUOTA_REASON,
  POLICY_REPLAY_UNSUPPORTED_IN_CLUSTER_REASON,
  AUDIT_EVIDENCE_UNAVAILABLE_REASON,
} from '../../../lib/policyReplays';
import { POLICY_SIMULATION_DEADLINE_REASON } from '../../../lib/policySimulations';
import { POLICY_TESTS_DEADLINE_REASON } from '../../../lib/policyTestRuns';
import { shortEtag, type JsonObject } from '../model';
import type { StudioAlert } from '../StudioAlert';
import { caseId, caseIndexForPointer } from './suite';

export const POLICY_SIMULATE_PERMISSION = 'admin:policy:simulate';
export const AUDIT_READ_PERMISSION = 'admin:audit:read';

// What the Simulator, Test and Impact views judge: the live policy itself,
// or the open draft's candidate text as it is on screen, unsaved edits
// included. Either one is compared with, or pinned to, the live revision
// the Studio read.
export type WorkbenchCandidate =
  | Readonly<{ kind: 'live'; liveEtag: string }>
  | Readonly<{
      kind: 'draft';
      liveEtag: string;
      draftId: string;
      revision: number;
      dirty: boolean;
      source: string;
    }>;

export function runCandidate(candidate: WorkbenchCandidate): PolicyRunCandidate {
  return candidate.kind === 'live'
    ? { kind: 'active' }
    : { kind: 'inline', source: candidate.source };
}

// Identifies what a result answered for: a result is stale once the live
// revision or the candidate text on screen is no longer the one it ran on.
export function candidateKey(candidate: WorkbenchCandidate): string {
  return candidate.kind === 'live'
    ? `live\n${candidate.liveEtag}`
    : `draft\n${candidate.liveEtag}\n${candidate.draftId}\n${candidate.source}`;
}

export function candidateLabel(candidate: WorkbenchCandidate): string {
  if (candidate.kind === 'live') {
    return `the live policy (revision ${shortEtag(candidate.liveEtag)})`;
  }
  return `draft ${candidate.draftId}, revision ${candidate.revision}${
    candidate.dirty ? ' with unsaved edits' : ''
  }`;
}

export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

// The alert for a run that did not answer. A simulation or test run changes
// nothing, so running it again is always safe; the operator decides when.
export function runAlert(
  error: unknown,
  title: string,
  permissions: string,
): StudioAlert {
  if (!(error instanceof AdminApiError)) {
    return {
      title,
      message:
        'The gateway did not answer, so nothing is known about this run. It changes nothing; run it again when the connection is back.',
      tone: 'error',
    };
  }
  switch (error.status) {
    case 401:
      return {
        title: 'Sign in required',
        message: 'Your admin session ended. Sign in again; your cases are kept until you leave the page.',
        tone: 'warning',
      };
    case 403:
      return {
        title: 'Permission required',
        message: `This session does not hold ${permissions}.`,
        tone: 'error',
      };
    case 404:
      return error.code === POLICY_REPLAY_NOT_FOUND_REASON
        ? {
            title,
            message:
              'The gateway no longer holds this job. Jobs live in the memory of the replica that ran them, and an expired or restarted job is forgotten.',
            tone: 'warning',
          }
        : { title, message: 'No policy is configured on this gateway.', tone: 'warning' };
    case 408:
      return {
        title,
        message: 'The request did not reach the gateway in time, so nothing ran. Try again.',
        tone: 'warning',
      };
    case 409:
      return {
        title,
        message:
          error.code === POLICY_REPLAY_IDEMPOTENCY_CONFLICT_REASON
            ? 'The gateway already holds a different replay under this request key. Start a new replay.'
            : error.message,
        tone: 'warning',
      };
    case 412:
      return {
        title: 'Live policy changed',
        message:
          'The live policy is no longer the revision this run was pinned to, so nothing ran. Read the live policy again, review it, and run again.',
        tone: 'warning',
      };
    case 413:
      return {
        title,
        message: 'The request is larger than the gateway accepts. Use fewer cases or a smaller candidate.',
        tone: 'error',
      };
    case 428:
      return {
        title,
        message: 'The gateway asked for the revision this run is bound to. Reload the Policy Studio.',
        tone: 'error',
      };
    case 429:
      return {
        title: 'Gateway busy',
        message:
          error.code === POLICY_REPLAY_QUOTA_REASON
            ? 'The gateway already holds as many replay results as it keeps. Discard finished jobs, or wait for them to expire.'
            : 'Another run of yours, or too many runs on this replica, are in progress. Nothing was queued; try again when they finish.',
        tone: 'warning',
      };
    case 503:
      return { title, message: unavailableMessage(error), tone: 'error' };
    default:
      return {
        title,
        message: `The gateway could not complete the request (${error.status}). There is no partial result.`,
        tone: 'error',
      };
  }
}

function unavailableMessage(error: AdminApiError): string {
  switch (error.code) {
    case POLICY_SIMULATION_DEADLINE_REASON:
    case POLICY_TESTS_DEADLINE_REASON:
      return 'The evaluation did not finish within its deadline, so there is no result. Use fewer cases or a lower trace level.';
    case AUDIT_EVIDENCE_UNAVAILABLE_REASON:
      return 'This gateway has no standalone audit log it can read, so there are no retained records to replay. That is not the same as a window with no traffic.';
    case POLICY_REPLAY_AUDIT_UNAVAILABLE_REASON:
      return 'The audit log did not accept the record of this replay starting, so no job was started.';
    case POLICY_REPLAY_UNSUPPORTED_IN_CLUSTER_REASON:
      return 'Historical replay is not available in cluster mode yet.';
    default:
      return 'The gateway could not read what this run needs. There is no result.';
  }
}

// A structured refusal, each diagnostic located by the case it is about.
export function RefusalPanel({
  title,
  refusal,
  cases,
}: {
  title: string;
  refusal: PolicyRunRefusal;
  cases: readonly JsonObject[];
}) {
  const where = (pointer: string): string => {
    const index = caseIndexForPointer(pointer);
    if (index === null) {
      return pointer === '' ? 'the request' : pointer;
    }
    const id = cases[index] ? caseId(cases[index]) : '';
    return `case ${id || `#${index + 1}`} (${pointer})`;
  };
  const message =
    refusal.reason === POLICY_CANDIDATE_INVALID_REASON
      ? 'The candidate policy does not validate, so nothing ran. Fix it in the editors first.'
      : refusal.pointer !== null
        ? `The evaluator refused ${where(refusal.pointer)}${refusal.code ? ` (${refusal.code})` : ''}, so nothing ran.`
        : refusal.diagnostics.length > 0
          ? 'The gateway refused the request, so nothing ran:'
          : `The gateway refused the request (${refusal.reason}), so nothing ran.`;
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>{title}</h3>
      <p>{message}</p>
      {refusal.diagnostics.length > 0 ? (
        <ul>
          {refusal.diagnostics.map((diagnostic, index) => (
            <li key={index}>
              <code>{diagnostic.code}</code> at {where(diagnostic.pointer)}: {diagnostic.message}
            </li>
          ))}
        </ul>
      ) : null}
      {refusal.diagnosticsTruncated ? (
        <p className="rule-hint">The gateway reported more problems than it lists.</p>
      ) : null}
      {refusal.errors.length > 0 ? (
        <ul>
          {refusal.errors.map((error, index) => (
            <li key={index}>{error}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

// The run's subject and why it may not be run now, beside the run action.
export function RunBlockers({ id, blockers }: { id: string; blockers: readonly string[] }) {
  if (blockers.length === 0) {
    return null;
  }
  return (
    <div className="policy-studio-blockers" id={id}>
      <p className="rule-hint">Running is unavailable:</p>
      <ul>
        {blockers.map((blocker) => (
          <li key={blocker}>{blocker}</li>
        ))}
      </ul>
    </div>
  );
}

export function StaleNotice({ children }: { children: ReactNode }) {
  return (
    <p className="workbench-stale" role="note">
      <span className="badge warning">Stale</span> {children}
    </p>
  );
}

// A count beside its label, in a definition list a screen reader reads in
// order.
export function CountList({
  label,
  items,
}: {
  label: string;
  items: ReadonlyArray<{ term: string; value: ReactNode }>;
}) {
  return (
    <dl className="workbench-counts" aria-label={label}>
      {items.map((item) => (
        <div key={item.term}>
          <dt>{item.term}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CheckboxOption({
  label,
  checked,
  disabled = false,
  hint,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  hint?: string;
  onChange: (checked: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="workbench-check">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        aria-describedby={hint ? `${id}-hint` : undefined}
        onChange={(event) => onChange(event.target.checked)}
      />
      <label htmlFor={id}>{label}</label>
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function codeLabel(code: string): string {
  return code.replace(/_/g, ' ');
}

export function plural(count: number, noun: string, nouns = `${noun}s`): string {
  return `${count} ${count === 1 ? noun : nouns}`;
}
