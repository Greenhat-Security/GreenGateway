import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  PolicyDocument,
  PolicyRule,
  PolicyRulePatch,
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

      try {
        const [policyResult, review] = await Promise.all([
          fetchPolicy(),
          fetchPolicyRuleShadowReview(),
        ]);
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(policyResult.canWrite);
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
    if (!canWritePolicy || mutatingRuleId !== null) {
      return false;
    }

    setMutatingRuleId(ruleId);
    setMutationError(null);
    setMutationNotice(null);

    try {
      const policyResult = await fetchPolicy();
      if (!policyResult.etag) {
        throw new Error('Current policy ETag was not returned; refresh and retry.');
      }

      await patchPolicyRule(ruleId, policyResult.etag, patch);
      setCanWritePolicy(policyResult.canWrite);
      setItems((current) => current.filter((item) => item.ruleId !== ruleId));
      setMutationNotice(successMessage);
      return true;
    } catch (error) {
      const reviewError = toShadowReviewError(error);
      if (reviewError.kind === 'forbidden') {
        setCanWritePolicy(false);
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
  canWritePolicy: boolean;
  confirmingPromoteId: string | null;
  isMutating: boolean;
  isMutationBusy: boolean;
  onConfirmingPromoteChange: (ruleId: string | null) => void;
  onPromote: () => void;
  onDisable: () => void;
}) {
  const { summary } = item;

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

        <div className="policy-history-actions shadow-review-actions">
          <ShadowRulePromoteControl
            ruleId={item.ruleId}
            canWritePolicy={canWritePolicy}
            confirmingPromoteId={confirmingPromoteId}
            isMutating={isMutating}
            isMutationBusy={isMutationBusy}
            onConfirmingPromoteChange={onConfirmingPromoteChange}
            onPromote={onPromote}
          />
          <button
            type="button"
            className="secondary-button"
            aria-label={`Disable ${item.ruleId}`}
            title={canWritePolicy ? undefined : 'Requires admin:policy:write'}
            disabled={!canWritePolicy || isMutationBusy}
            onClick={onDisable}
          >
            {isMutating ? 'Disabling' : 'Disable'}
          </button>
        </div>
      </div>
    </li>
  );
}

function ShadowRulePromoteControl({
  ruleId,
  canWritePolicy,
  confirmingPromoteId,
  isMutating,
  isMutationBusy,
  onConfirmingPromoteChange,
  onPromote,
}: {
  ruleId: string;
  canWritePolicy: boolean;
  confirmingPromoteId: string | null;
  isMutating: boolean;
  isMutationBusy: boolean;
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
          disabled={!canWritePolicy || isMutationBusy}
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
      title={canWritePolicy ? undefined : 'Requires admin:policy:write'}
      disabled={!canWritePolicy || isMutationBusy}
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
