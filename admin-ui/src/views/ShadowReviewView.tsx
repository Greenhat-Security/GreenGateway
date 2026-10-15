import { useEffect, useId, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  PolicyDocument,
  PolicyRule,
  PolicyRulePatch,
  PolicyRuleShadowReviewResponse,
  PolicyRuleShadowReviewSummary,
  fetchPolicy,
  fetchPolicyRuleShadowReview,
  isPolicyRuleEnabled,
  patchPolicyRule,
  policyRuleId,
} from '../lib/policy';
import { MethodList, formatPrincipal, ruleTarget } from './RuleTable';
import { RuleWorkspaceNav } from './RuleWorkspaceNav';

type ShadowReviewError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'policy-changed'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

const POLICY_CHANGED_MESSAGE =
  'Policy changed since this page loaded; refresh and retry.';
const EVIDENCE_REQUIRED_ACTION_MESSAGE =
  'Promote and Disable are unavailable while shadow evidence is unavailable: nothing shows which requests changing this rule would affect.';
const POLICY_CHANGED_ACTION_MESSAGE =
  'Promote and Disable are unavailable because the policy changed after this review was read. Refresh to review the current rules.';
const MISSING_ETAG_ACTION_MESSAGE =
  'Promote and Disable are unavailable because the policy ETag was not returned, so a change could not be tied to the reviewed policy. Refresh and retry.';

type ShadowReviewItem = {
  ruleId: string;
  rule: PolicyRule;
  // Null when audit evidence is unavailable: nothing is known about what the
  // rule would have denied, which is not the same as "nothing".
  summary: PolicyRuleShadowReviewSummary | null;
};

type ShadowReviewEvidence =
  | { status: 'complete' }
  | { status: 'truncated' }
  | { status: 'unavailable'; message: string };

export function ShadowReviewView() {
  const [items, setItems] = useState<ShadowReviewItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<ShadowReviewError | null>(null);
  const [mutationError, setMutationError] = useState<ShadowReviewError | null>(null);
  const [mutationNotice, setMutationNotice] = useState<string | null>(null);
  const [canWritePolicy, setCanWritePolicy] = useState(false);
  const [mutatingRuleId, setMutatingRuleId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<ShadowReviewEvidence>({
    status: 'complete',
  });
  // The ETag of the policy the listed rules were read from. Every change is
  // sent with it, never with a freshly fetched one: the gateway compares
  // If-Match against the whole policy, so a write made since the operator
  // reviewed a rule answers 412 instead of changing whatever rule holds that
  // id now. Rules without an explicit id are addressed by position, which
  // any other write can move.
  const [policyEtag, setPolicyEtag] = useState<string | null>(null);
  const [policyChanged, setPolicyChanged] = useState(false);
  const [confirmingPromoteId, setConfirmingPromoteId] = useState<string | null>(
    null,
  );

  useEffect(() => {
    let isCurrent = true;

    async function loadReview() {
      setIsLoading(true);
      setLoadError(null);
      setMutationError(null);
      setMutationNotice(null);
      setCanWritePolicy(false);
      setEvidence({ status: 'complete' });
      setPolicyEtag(null);
      setPolicyChanged(false);

      try {
        const [policyResult, review] = await Promise.all([
          fetchPolicy(),
          fetchPolicyRuleShadowReview(),
        ]);
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(policyResult.canWrite);
        setPolicyEtag(policyResult.etag);
        if (review.status === 'available') {
          setItems(
            review.value.rules.map((summary) => ({
              ruleId: summary.rule_id,
              rule: summary.rule,
              summary,
            })),
          );
          setEvidence(
            review.value.scan_truncated
              ? { status: 'truncated' }
              : { status: 'complete' },
          );
          setPolicyChanged(
            !reviewDescribesPolicy(review.value, policyResult.policy),
          );
        } else {
          setItems(enabledShadowRules(policyResult.policy));
          setEvidence({ status: 'unavailable', message: review.message });
        }
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(false);
        setItems([]);
        setEvidence({ status: 'complete' });
        setPolicyEtag(null);
        setPolicyChanged(false);
        setLoadError(toShadowReviewError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadReview();

    return () => {
      isCurrent = false;
    };
  }, []);

  const resultCount = useMemo(() => {
    return `${items.length} ${items.length === 1 ? 'rule' : 'rules'}`;
  }, [items.length]);
  const showWritePermissionNotice =
    !isLoading &&
    !loadError &&
    items.length > 0 &&
    !canWritePolicy &&
    mutationError?.kind !== 'forbidden';
  const actionBlockReason = shadowActionBlockReason({
    evidence,
    policyEtag,
    policyChanged,
  });

  async function promoteRule(ruleId: string) {
    const succeeded = await mutateRule(
      ruleId,
      { action: 'deny' },
      'Rule promoted to deny.',
    );
    if (succeeded) {
      setConfirmingPromoteId(null);
    }
  }

  async function disableRule(ruleId: string) {
    await mutateRule(ruleId, { enabled: false }, 'Shadow rule disabled.');
  }

  async function mutateRule(
    ruleId: string,
    patch: PolicyRulePatch,
    successMessage: string,
  ): Promise<boolean> {
    const reviewedEtag = policyEtag;
    if (
      !canWritePolicy ||
      mutatingRuleId !== null ||
      actionBlockReason !== null ||
      reviewedEtag === null
    ) {
      return false;
    }

    setMutatingRuleId(ruleId);
    setMutationError(null);
    setMutationNotice(null);

    try {
      const response = await patchPolicyRule(ruleId, reviewedEtag, patch);
      // A patch changes one rule in place and moves none, so the returned
      // ETag describes exactly the rules still listed here.
      setPolicyEtag(response.etag);
      setItems((current) => current.filter((item) => item.ruleId !== ruleId));
      setMutationNotice(successMessage);
      return true;
    } catch (error) {
      const reviewError = toShadowReviewError(error);
      if (reviewError.kind === 'forbidden') {
        setCanWritePolicy(false);
      }
      if (reviewError.kind === 'policy-changed') {
        setPolicyChanged(true);
      }
      setMutationError(reviewError);
      return false;
    } finally {
      setMutatingRuleId(null);
    }
  }

  return (
    <main className="logs-page shadow-review-page">
      <section
        className="panel logs-panel shadow-review-panel"
        aria-labelledby="shadow-review-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Policy</p>
            <h2 id="shadow-review-heading">Shadow review queue</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        <RuleWorkspaceNav />

        {loadError ? <ShadowReviewErrorMessage error={loadError} /> : null}
        {showWritePermissionNotice ? <PolicyWritePermissionNotice /> : null}
        {mutationError ? <ShadowReviewMutationError error={mutationError} /> : null}
        {policyChanged && mutationError?.kind !== 'policy-changed' ? (
          <div className="error-panel alert warning" role="alert">
            <h3>Policy changed during review</h3>
            <p>
              The shadow review and the policy were read from different versions.
              Refresh to review the current rules before promoting or disabling one.
            </p>
          </div>
        ) : null}
        {mutationNotice ? (
          <div className="error-panel alert success" role="status">
            <p>{mutationNotice}</p>
          </div>
        ) : null}
        {evidence.status === 'truncated' ? (
          <div className="error-panel alert warning" role="status">
            <p>
              Audit scan limit reached; counts, principals, and samples cover only the
              newest scanned events, so each count is a lower bound.
            </p>
          </div>
        ) : null}
        {evidence.status === 'unavailable' ? (
          <div className="error-panel alert warning" role="status">
            <h3>Shadow evidence unavailable</h3>
            <p>{evidence.message}</p>
            <p>
              Would-deny counts, affected principals, and samples were not read. A
              rule without evidence has not been shown to be safe to promote.
            </p>
          </div>
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading shadow review queue
          </div>
        ) : null}

        {!isLoading && items.length === 0 && !loadError ? (
          <div className="empty-state">No rules are currently in shadow mode.</div>
        ) : null}

        {items.length > 0 ? (
          <ol className="policy-history-list shadow-review-list" aria-label="Shadow review queue">
            {items.map((item) => (
              <ShadowReviewEntry
                actionBlockReason={actionBlockReason}
                canWritePolicy={canWritePolicy}
                confirmingPromoteId={confirmingPromoteId}
                evidence={evidence}
                isMutating={mutatingRuleId === item.ruleId}
                isMutationBusy={mutatingRuleId !== null}
                item={item}
                key={item.ruleId}
                onConfirmingPromoteChange={setConfirmingPromoteId}
                onDisable={() => {
                  void disableRule(item.ruleId);
                }}
                onPromote={() => {
                  void promoteRule(item.ruleId);
                }}
              />
            ))}
          </ol>
        ) : null}
      </section>
    </main>
  );
}

function ShadowReviewEntry({
  item,
  evidence,
  actionBlockReason,
  canWritePolicy,
  confirmingPromoteId,
  isMutating,
  isMutationBusy,
  onConfirmingPromoteChange,
  onPromote,
  onDisable,
}: {
  item: ShadowReviewItem;
  evidence: ShadowReviewEvidence;
  actionBlockReason: string | null;
  canWritePolicy: boolean;
  confirmingPromoteId: string | null;
  isMutating: boolean;
  isMutationBusy: boolean;
  onConfirmingPromoteChange: (ruleId: string | null) => void;
  onPromote: () => void;
  onDisable: () => void;
}) {
  const { summary } = item;
  const actionNoteId = useId();
  const actionControl: ShadowActionControl = {
    disabled: !canWritePolicy || isMutationBusy || actionBlockReason !== null,
    title: !canWritePolicy
      ? 'Requires admin:policy:write'
      : (actionBlockReason ?? undefined),
    describedBy: actionBlockReason === null ? undefined : actionNoteId,
  };

  return (
    <li className="policy-history-entry shadow-review-entry">
      <div className="policy-history-marker" aria-hidden="true" />
      <div className="policy-history-content shadow-review-content">
        <div className="policy-history-entry-heading shadow-review-entry-heading">
          <div>
            <span className="badge warning">Shadow</span>
            <h3>{item.ruleId}</h3>
          </div>
          <span className="badge neutral">
            {formatWouldDenyEvidence(summary, evidence)}
          </span>
        </div>

        <dl className="policy-history-meta shadow-review-rule-meta">
          <div>
            <dt>Methods</dt>
            <dd>
              {item.rule.tool_name ? (
                <span className="badge neutral">MCP tool</span>
              ) : (
                <MethodList methods={item.rule.methods ?? []} />
              )}
            </dd>
          </div>
          <div>
            <dt>Target</dt>
            <dd>
              <code className="endpoint-template rule-path">
                {ruleTarget(item.rule)}
              </code>
            </dd>
          </div>
          <div>
            <dt>Principal</dt>
            <dd>{formatPrincipal(item.rule.principal)}</dd>
          </div>
        </dl>

        <div className="shadow-review-section">
          <h4>Affected principals</h4>
          {summary === null ? (
            <p className="shadow-review-muted">Evidence unavailable.</p>
          ) : summary.affected_principals.length > 0 ? (
            <div className="shadow-review-chip-list" aria-label="Affected principals">
              {summary.affected_principals.map((principal) => (
                <span
                  className="badge neutral"
                  key={`${principal.user_id}:${principal.issuer ?? ''}:${principal.auth_mode}`}
                >
                  {principal.user_id}
                  <small>
                    {[principal.issuer ?? 'no issuer', principal.auth_mode]
                      .concat(principal.roles)
                      .join(' / ')}
                  </small>
                </span>
              ))}
            </div>
          ) : (
            <p className="shadow-review-muted">No affected principals recorded.</p>
          )}
        </div>

        <div className="shadow-review-section">
          <h4>Sample requests</h4>
          {summary === null ? (
            <p className="shadow-review-muted">Evidence unavailable.</p>
          ) : summary.samples.length > 0 ? (
            <ul className="shadow-review-sample-list">
              {summary.samples.map((sample) => (
                <li className="shadow-review-sample" key={sample.event_id}>
                  <span className="shadow-review-request">
                    {sample.method} {sample.path}
                  </span>
                  <span>{formatUtcTimestamp(sample.timestamp)}</span>
                  <span>{sample.actor?.user_id ?? 'Unauthenticated'}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="shadow-review-muted">No sample requests recorded.</p>
          )}
        </div>

        {actionBlockReason !== null ? (
          <p className="shadow-review-muted" id={actionNoteId}>
            {actionBlockReason}
          </p>
        ) : null}
        <div className="policy-history-actions shadow-review-actions">
          <ShadowRulePromoteControl
            ruleId={item.ruleId}
            control={actionControl}
            confirmingPromoteId={confirmingPromoteId}
            isMutating={isMutating}
            onConfirmingPromoteChange={onConfirmingPromoteChange}
            onPromote={onPromote}
          />
          <button
            type="button"
            className="secondary-button"
            aria-label={`Disable ${item.ruleId}`}
            aria-describedby={actionControl.describedBy}
            title={actionControl.title}
            disabled={actionControl.disabled}
            onClick={onDisable}
          >
            {isMutating ? 'Disabling' : 'Disable'}
          </button>
        </div>
      </div>
    </li>
  );
}

// Promote and Disable share one availability: both change what happens to
// the requests this rule matches, so both need the same evidence and the same
// policy version behind them.
type ShadowActionControl = {
  disabled: boolean;
  title: string | undefined;
  describedBy: string | undefined;
};

function ShadowRulePromoteControl({
  ruleId,
  control,
  confirmingPromoteId,
  isMutating,
  onConfirmingPromoteChange,
  onPromote,
}: {
  ruleId: string;
  control: ShadowActionControl;
  confirmingPromoteId: string | null;
  isMutating: boolean;
  onConfirmingPromoteChange: (ruleId: string | null) => void;
  onPromote: () => void;
}) {
  if (confirmingPromoteId === ruleId) {
    return (
      <div className="rule-delete-confirmation">
        <button
          type="button"
          className="primary-button row-action-button"
          aria-label={`Confirm promote ${ruleId} to deny`}
          aria-describedby={control.describedBy}
          title={control.title}
          disabled={control.disabled}
          onClick={onPromote}
        >
          {isMutating ? 'Promoting' : 'Confirm'}
        </button>
        <button
          type="button"
          className="secondary-button row-action-button"
          onClick={() => onConfirmingPromoteChange(null)}
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <button
      type="button"
      className="primary-button"
      aria-label={`Promote ${ruleId} to deny`}
      aria-describedby={control.describedBy}
      title={control.title}
      disabled={control.disabled}
      onClick={() => onConfirmingPromoteChange(ruleId)}
    >
      Promote
    </button>
  );
}

function PolicyWritePermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Policy write permission required</h3>
      <p>This token can review shadow rules but does not include admin:policy:write.</p>
    </div>
  );
}

function ShadowReviewErrorMessage({ error }: { error: ShadowReviewError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before reviewing shadow rules. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Policy permission required</h3>
        <p>This token is valid but does not include admin:policy:read.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'unavailable' ? 'Policy API unavailable' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function ShadowReviewMutationError({ error }: { error: ShadowReviewError }) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy write permission required</h3>
        <p>This token can review shadow rules but does not include admin:policy:write.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'policy-changed' || error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'policy-changed' ? 'Policy changed' : 'Rule update failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

// Unread evidence, a truncated scan, and a complete count must read
// differently: only the last can say a rule would have denied nothing.
function formatWouldDenyEvidence(
  summary: PolicyRuleShadowReviewSummary | null,
  evidence: ShadowReviewEvidence,
): string {
  if (summary === null || evidence.status === 'unavailable') {
    return 'Evidence unavailable';
  }

  const count = formatWouldDenyCount(summary.would_deny_count);
  return evidence.status === 'truncated' ? `${count} (scan truncated)` : count;
}

function formatWouldDenyCount(value: number): string {
  return `${value.toLocaleString()} would-deny ${value === 1 ? 'event' : 'events'}`;
}

// Why Promote and Disable cannot run, or null when they may. Unread evidence
// is no basis for changing a rule, and a change must be checked against the
// policy version the operator reviewed.
function shadowActionBlockReason({
  evidence,
  policyEtag,
  policyChanged,
}: {
  evidence: ShadowReviewEvidence;
  policyEtag: string | null;
  policyChanged: boolean;
}): string | null {
  if (evidence.status === 'unavailable') {
    return EVIDENCE_REQUIRED_ACTION_MESSAGE;
  }
  if (policyChanged) {
    return POLICY_CHANGED_ACTION_MESSAGE;
  }
  if (policyEtag === null) {
    return MISSING_ETAG_ACTION_MESSAGE;
  }
  return null;
}

// The selection the gateway's review makes -- enabled shadow rules, keyed by
// the id live audit attribution uses -- for listing them when no evidence
// about them could be read.
function enabledShadowRules(policy: PolicyDocument): ShadowReviewItem[] {
  return policy.rules.flatMap((rule, index) =>
    isPolicyRuleEnabled(rule) && rule.action === 'shadow'
      ? [{ ruleId: policyRuleId(rule, index), rule, summary: null }]
      : [],
  );
}

// The review and the policy (with its ETag) are separate reads, so a write
// landing between them leaves the listed rules describing a different policy
// than the ETag a change would be sent with. Only when the review lists
// exactly the policy's enabled shadow rules, under the same ids, does that
// ETag stand for the rules on screen.
function reviewDescribesPolicy(
  review: PolicyRuleShadowReviewResponse,
  policy: PolicyDocument,
): boolean {
  const policyShadowRules = enabledShadowRules(policy);
  return (
    policyShadowRules.length === review.rules.length &&
    policyShadowRules.every((item, index) => {
      const summary = review.rules[index];
      return (
        summary !== undefined &&
        summary.rule_id === item.ruleId &&
        canonicalJson(summary.rule) === canonicalJson(item.rule)
      );
    })
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortedJsonValue(value));
}

function sortedJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortedJsonValue);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, item]) => [key, sortedJsonValue(item)]),
    );
  }
  return value;
}

function formatUtcTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  }).format(date);
}

function toShadowReviewError(error: unknown): ShadowReviewError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404) {
      return { kind: 'unavailable', message: error.message };
    }
    if (error.status === 412) {
      return { kind: 'policy-changed', message: POLICY_CHANGED_MESSAGE };
    }
    if (error.status === 400) {
      return { kind: 'bad-request', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: `Network request failed: ${error.message}`,
    };
  }

  return { kind: 'network', message: 'Network request failed.' };
}
