import { useEffect, useId, useState } from 'react';

import {
  validatePolicySource,
  type PolicyDiagnostic,
  type PolicyDiagnosticSeverity,
  type PolicyInspection,
} from '../../../lib/policyDrafts';
import { blockedUses, severityBadge, severityLabel } from '../model';
import { StudioAlertPanel, type StudioAlert } from '../StudioAlert';
import { isAbort, plural, runAlert, type WorkbenchCandidate } from './common';

export type DraftValidation = Readonly<{
  checking: boolean;
  inspection: PolicyInspection | null;
  alert: StudioAlert | null;
}>;

const GROUPS: ReadonlyArray<{
  severity: PolicyDiagnosticSeverity;
  title: string;
  description: string;
}> = [
  {
    severity: 'risk',
    title: 'Risks to review',
    description: 'Accepted, but publishing carries an exposure: an allowing default, global shadow mode, a wildcard permission.',
  },
  {
    severity: 'warning',
    title: 'Warnings',
    description: 'Accepted, with a limitation or a cross-resource finding: a role, permission, tool or Connection the policy names but this deployment does not match.',
  },
  {
    severity: 'error',
    title: 'Errors',
    description: 'The candidate cannot be accepted, or cannot be published here, until these are fixed.',
  },
];

// The Optimize view: the findings the gateway's validator reports about the
// candidate, each with its remediation, for review. Nothing here changes the
// policy; a remediation is an edit made in a draft and published through the
// ordinary review.
export function OptimizePanel({
  candidate,
  candidateProblem,
  liveSource,
  draftValidation,
  canEditDraft,
  onShowInEditor,
}: {
  candidate: WorkbenchCandidate | null;
  candidateProblem: string | null;
  // The live policy as text, validated here when it is the candidate.
  liveSource: string | null;
  // The Studio's validation of the draft text on screen.
  draftValidation: DraftValidation;
  canEditDraft: boolean;
  onShowInEditor: (diagnostic: PolicyDiagnostic) => void;
}) {
  const headingId = useId();
  const liveCandidate = candidate?.kind === 'live';
  const [liveCheck, setLiveCheck] = useState<{
    source: string;
    inspection: PolicyInspection | null;
    alert: StudioAlert | null;
  } | null>(null);

  useEffect(() => {
    if (!liveCandidate || liveSource === null) {
      return;
    }
    const controller = new AbortController();
    setLiveCheck(null);
    void (async () => {
      try {
        const inspection = await validatePolicySource(liveSource, controller.signal);
        if (!controller.signal.aborted) {
          setLiveCheck({ source: liveSource, inspection, alert: null });
        }
      } catch (error) {
        if (isAbort(error) || controller.signal.aborted) return;
        setLiveCheck({
          source: liveSource,
          inspection: null,
          alert: runAlert(error, 'Validation unavailable', 'admin:policy:read'),
        });
      }
    })();
    return () => controller.abort();
  }, [liveCandidate, liveSource]);

  const checking = liveCandidate
    ? liveCheck === null || liveCheck.source !== liveSource
    : draftValidation.checking;
  const inspection = liveCandidate ? (liveCheck?.inspection ?? null) : draftValidation.inspection;
  const alert = liveCandidate ? (liveCheck?.alert ?? null) : draftValidation.alert;
  const diagnostics = checking ? [] : (inspection?.diagnostics ?? []);
  const snapshot = inspection?.resource_snapshot ?? null;

  return (
    <section className="workbench-panel" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Findings to review</p>
          <h3 id={headingId}>Optimize</h3>
        </div>
        {!checking && inspection !== null ? (
          <span className="result-count">{plural(diagnostics.length, 'finding')}</span>
        ) : null}
      </div>
      <div className="error-panel alert info" role="note">
        <h3>The validator’s checks, not a policy analysis</h3>
        <p>
          The conservative analyzer, which finds shadowed, unreachable and overbroad entries
          with a proof basis, an access effect and an advisory change for each, answers on
          the gateway’s policy analyses endpoint, but this view does not run it yet. This
          view lists what the validator’s structural, cross-resource and risk checks report
          about the candidate.
          An empty list means those checks found nothing; it does not mean the policy has
          none of those problems.
        </p>
      </div>
      <p className="rule-hint">
        Nothing here changes the policy. A remediation is an edit you make in a draft,
        validate, test and publish through the ordinary review.
      </p>

      {candidate === null ? (
        <p className="empty-state">{candidateProblem ?? 'There is no candidate to review.'}</p>
      ) : (
        <>
          <p className="policy-studio-validation-status" role="status" aria-live="polite">
            {checking
              ? 'Asking the gateway to validate the candidate.'
              : alert !== null
                ? `${alert.title}.`
                : inspection === null
                  ? 'The candidate has not been validated.'
                  : diagnostics.length === 0
                    ? 'The validator reports no findings for this candidate.'
                    : `The validator reports ${plural(diagnostics.length, 'finding')}.`}
          </p>
          {alert !== null && !checking ? <StudioAlertPanel alert={alert} /> : null}
          {snapshot !== null && !snapshot.complete && !checking ? (
            <p className="rule-hint">
              Some resources could not be read, so the cross-resource checks that need them did
              not run
              {snapshot.unavailable.length > 0 ? `: ${snapshot.unavailable.join(', ')}` : ''}. Their
              absence from this list is not a finding that they pass.
            </p>
          ) : null}
          {liveCandidate && diagnostics.length > 0 ? (
            <p className="rule-hint">
              These are findings about the live policy. To change it, open or create a draft;
              the findings then follow the draft as you edit it.
            </p>
          ) : null}
          {GROUPS.map((group) => {
            const found = diagnostics.filter((diagnostic) => diagnostic.severity === group.severity);
            return found.length > 0 ? (
              <FindingGroup
                key={group.severity}
                title={group.title}
                description={group.description}
                findings={found}
                canEdit={canEditDraft && candidate.kind === 'draft'}
                onShowInEditor={onShowInEditor}
              />
            ) : null;
          })}
        </>
      )}
    </section>
  );
}

function FindingGroup({
  title,
  description,
  findings,
  canEdit,
  onShowInEditor,
}: {
  title: string;
  description: string;
  findings: readonly PolicyDiagnostic[];
  canEdit: boolean;
  onShowInEditor: (diagnostic: PolicyDiagnostic) => void;
}) {
  const headingId = useId();
  return (
    <section className="workbench-findings" aria-labelledby={headingId}>
      <h4 id={headingId}>
        {title} ({findings.length})
      </h4>
      <p className="rule-hint">{description}</p>
      <ol className="policy-studio-diagnostic-list">
        {findings.map((finding, index) => {
          const uses = blockedUses(finding);
          return (
            <li key={`${index}:${finding.code}:${finding.pointer}`} className={finding.severity}>
              <div className="policy-studio-diagnostic-head">
                <span className={`badge ${severityBadge(finding.severity)}`}>
                  {severityLabel(finding.severity)}
                </span>
                <code>{finding.code}</code>
              </div>
              <p>{finding.message}</p>
              <p>
                <strong>Remediation:</strong> {finding.remediation}
              </p>
              <p className="rule-hint">
                Found at <code>{finding.pointer || '(whole document)'}</code>
                {finding.element_id ? (
                  <>
                    {' '}in <code>{finding.element_id}</code>
                  </>
                ) : null}
                {uses.length > 0 ? `. It blocks ${uses.join(', ')}.` : '. It blocks nothing.'}
              </p>
              {canEdit ? (
                <button
                  type="button"
                  className="secondary-button"
                  aria-label={`Edit in the draft: ${finding.code} at ${finding.pointer || 'the whole document'}`}
                  onClick={() => onShowInEditor(finding)}
                >
                  Edit in the draft
                </button>
              ) : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
