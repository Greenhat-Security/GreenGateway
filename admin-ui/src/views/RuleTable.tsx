import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  PolicyDefaultAction,
  PolicyDocument,
  PolicyRule,
  currentTokenCanWritePolicy,
  deletePolicyRule,
  fetchPolicy,
  fetchPolicyRuleHits,
  isPolicyRuleEnabled,
  patchPolicyRule,
  policyRuleId,
  reorderPolicyRules,
} from '../lib/policy';
import { MethodBadge } from './trafficBadges';

type PolicyLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

type RuleRow = {
  rule: PolicyRule;
  id: string;
  index: number;
};

export function RuleTable() {
  const [policy, setPolicy] = useState<PolicyDocument | null>(null);
  const [etag, setEtag] = useState<string | null>(null);
  const [hits, setHits] = useState<Record<string, number>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<PolicyLoadError | null>(null);
  const [mutationError, setMutationError] = useState<PolicyLoadError | null>(
    null,
  );
  const [canWritePolicy, setCanWritePolicy] = useState(false);
  const [mutatingRuleId, setMutatingRuleId] = useState<string | null>(null);
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(
    null,
  );
  const [draggingRuleId, setDraggingRuleId] = useState<string | null>(null);

  useEffect(() => {
    let isCurrent = true;

    async function loadRules() {
      setIsLoading(true);
      setLoadError(null);
      setMutationError(null);
      setCanWritePolicy(false);

      try {
        const [policyResult, hitCounts] = await Promise.all([
          fetchPolicy(),
          fetchPolicyRuleHits(),
        ]);
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(currentTokenCanWritePolicy(policyResult.policy));
        setPolicy(policyResult.policy);
        setEtag(policyResult.etag);
        setHits(hitCounts);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setPolicy(null);
        setEtag(null);
        setHits({});
        setCanWritePolicy(false);
        setLoadError(toPolicyLoadError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadRules();

    return () => {
      isCurrent = false;
    };
  }, []);

  const rows = useMemo<RuleRow[]>(() => {
    return (
      policy?.rules.map((rule, index) => ({
        rule,
        id: policyRuleId(rule, index),
        index,
      })) ?? []
    );
  }, [policy]);
  const showWritePermissionNotice =
    policy !== null &&
    !canWritePolicy &&
    mutationError?.kind !== 'forbidden';

  async function toggleRule(row: RuleRow) {
    const currentEtag = etag;
    if (!canWritePolicy || currentEtag === null) {
      return;
    }

    const nextEnabled = !isPolicyRuleEnabled(row.rule);
    setMutatingRuleId(row.id);
    setMutationError(null);

    try {
      const response = await patchPolicyRule(row.id, currentEtag, {
        enabled: nextEnabled,
      });
      setEtag(response.etag);
      updateRule(row.id, response.value);
    } catch (error) {
      handleMutationError(error);
    } finally {
      setMutatingRuleId(null);
    }
  }

  async function deleteRule(row: RuleRow) {
    const currentEtag = etag;
    if (!canWritePolicy || currentEtag === null) {
      return;
    }

    setMutatingRuleId(row.id);
    setMutationError(null);

    try {
      const response = await deletePolicyRule(row.id, currentEtag);
      setEtag(response.etag);
      removeRule(row.id);
      setConfirmingDeleteId(null);
    } catch (error) {
      handleMutationError(error);
    } finally {
      setMutatingRuleId(null);
    }
  }

  async function dropRule(targetId: string) {
    const currentEtag = etag;
    if (!policy || !canWritePolicy || currentEtag === null || !draggingRuleId) {
      setDraggingRuleId(null);
      return;
    }

    const nextOrder = ruleOrderAfterDrop(policy.rules, draggingRuleId, targetId);
    setDraggingRuleId(null);
    if (nextOrder.length === 0 || sameOrder(nextOrder, rows.map((row) => row.id))) {
      return;
    }

    setMutatingRuleId(draggingRuleId);
    setMutationError(null);

    try {
      const response = await reorderPolicyRules(nextOrder, currentEtag);
      setEtag(response.etag);
      setPolicy((current) =>
        current
          ? {
              ...current,
              rules: reorderRulesById(current.rules, response.value.order),
            }
          : current,
      );
    } catch (error) {
      handleMutationError(error);
    } finally {
      setMutatingRuleId(null);
    }
  }

  function canMutate(): boolean {
    return canWritePolicy && etag !== null;
  }

  function updateRule(ruleId: string, nextRule: PolicyRule) {
    setPolicy((current) =>
      current
        ? {
            ...current,
            rules: current.rules.map((rule, index) =>
              policyRuleId(rule, index) === ruleId ? nextRule : rule,
            ),
          }
        : current,
    );
  }

  function removeRule(ruleId: string) {
    setPolicy((current) =>
      current
        ? {
            ...current,
            rules: current.rules.filter(
              (rule, index) => policyRuleId(rule, index) !== ruleId,
            ),
          }
        : current,
    );
  }

  function handleMutationError(error: unknown) {
    const policyError = toPolicyLoadError(error);
    if (policyError.kind === 'forbidden') {
      setCanWritePolicy(false);
    }
    setMutationError(policyError);
  }

  return (
    <main className="logs-page rule-page">
      <section className="panel logs-panel rule-panel" aria-labelledby="rule-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Policy</p>
            <h2 id="rule-heading">Rule table</h2>
          </div>
          <span className="result-count">{rows.length} rules</span>
        </div>

        {policy ? <DefaultActionBanner action={policy.default_action} /> : null}

        {loadError ? <PolicyErrorMessage error={loadError} /> : null}
        {showWritePermissionNotice ? <PolicyWritePermissionNotice /> : null}
        {mutationError ? <PolicyMutationErrorMessage error={mutationError} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading policy rules
          </div>
        ) : null}

        {!isLoading && rows.length === 0 && !loadError ? (
          <div className="empty-state">
            No direct firewall rules are configured.
          </div>
        ) : null}

        {rows.length > 0 ? (
          <div className="table-scroll">
            <table className="logs-table rule-table">
              <thead>
                <tr>
                  <th aria-label="Reorder" />
                  <th>Methods</th>
                  <th>Target</th>
                  <th>Principal</th>
                  <th>Action</th>
                  <th>Hits</th>
                  <th>Enabled</th>
                  <th>Delete</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr
                    className={`event-row rule-row ${index % 2 === 1 ? 'is-even' : ''} ${
                      draggingRuleId === row.id ? 'is-dragging' : ''
                    }`}
                    data-testid={`rule-row-${row.id}`}
                    draggable={canMutate()}
                    key={`${row.id}-${row.index}`}
                    onDragStart={(event) => {
                      if (!canMutate()) {
                        event.preventDefault();
                        return;
                      }
                      setDraggingRuleId(row.id);
                      if (event.dataTransfer) {
                        event.dataTransfer.effectAllowed = 'move';
                      }
                    }}
                    onDragOver={(event) => {
                      if (canMutate()) {
                        event.preventDefault();
                      }
                    }}
                    onDrop={(event) => {
                      event.preventDefault();
                      void dropRule(row.id);
                    }}
                  >
                    <td className="rule-drag-cell">
                      <span className="rule-drag-handle" aria-hidden="true">
                        ::
                      </span>
                    </td>
                    <td>
                      {row.rule.tool_name ? (
                        <span className="badge neutral">MCP tool</span>
                      ) : (
                        <MethodList methods={row.rule.methods ?? []} />
                      )}
                    </td>
                    <td>
                      <code className="endpoint-template rule-path">
                        {ruleTarget(row.rule)}
                      </code>
                    </td>
                    <td>{formatPrincipal(row.rule.principal)}</td>
                    <td>
                      <ActionBadge action={row.rule.action} />
                    </td>
                    <td className="numeric-cell">{formatRuleHits(hits[row.id] ?? 0)}</td>
                    <td>
                      <RuleEnabledSwitch
                        row={row}
                        canWritePolicy={canWritePolicy}
                        isMutating={mutatingRuleId === row.id}
                        onToggle={() => {
                          void toggleRule(row);
                        }}
                      />
                    </td>
                    <td>
                      <RuleDeleteControl
                        row={row}
                        canWritePolicy={canWritePolicy}
                        confirmingDeleteId={confirmingDeleteId}
                        isMutating={mutatingRuleId === row.id}
                        onConfirmingChange={setConfirmingDeleteId}
                        onDelete={() => {
                          void deleteRule(row);
                        }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </main>
  );
}

function DefaultActionBanner({ action }: { action: PolicyDefaultAction }) {
  const title = actionTitle(action);
  const alertClass = action === 'allow' ? 'success' : 'error';

  return (
    <div className={`rule-default-banner alert ${alertClass}`} role="status">
      <span className={`badge ${actionBadgeClass(action)}`}>
        Default action: {title}
      </span>
      <span>
        Requests that miss every enabled rule are {action === 'allow' ? 'allowed' : 'denied'}.
      </span>
    </div>
  );
}

export function MethodList({ methods }: { methods: string[] }) {
  if (methods.length === 0 || methods.some((method) => method.trim() === '*')) {
    return <span className="badge neutral">Any method</span>;
  }

  return (
    <div className="rule-method-list" aria-label="Matched methods">
      {methods.map((method) => (
        <MethodBadge method={method} key={method} />
      ))}
    </div>
  );
}

export function ruleTarget(rule: PolicyRule): string {
  return rule.tool_name ?? rule.path ?? '-';
}

function ActionBadge({ action }: { action: PolicyRule['action'] }) {
  return <span className={`badge ${actionBadgeClass(action)}`}>{actionTitle(action)}</span>;
}

function RuleEnabledSwitch({
  row,
  canWritePolicy,
  isMutating,
  onToggle,
}: {
  row: RuleRow;
  canWritePolicy: boolean;
  isMutating: boolean;
  onToggle: () => void;
}) {
  const enabled = isPolicyRuleEnabled(row.rule);

  return (
    <button
      type="button"
      role="switch"
      className={`rule-toggle ${enabled ? 'is-on' : ''}`}
      aria-checked={enabled}
      aria-label={`${enabled ? 'Disable' : 'Enable'} rule ${row.id}`}
      title={canWritePolicy ? undefined : 'Requires admin:policy:write'}
      disabled={!canWritePolicy || isMutating}
      onClick={onToggle}
    >
      <span className="rule-toggle-track" aria-hidden="true">
        <span className="rule-toggle-thumb" />
      </span>
      <span>{enabled ? 'Enabled' : 'Disabled'}</span>
    </button>
  );
}

function RuleDeleteControl({
  row,
  canWritePolicy,
  confirmingDeleteId,
  isMutating,
  onConfirmingChange,
  onDelete,
}: {
  row: RuleRow;
  canWritePolicy: boolean;
  confirmingDeleteId: string | null;
  isMutating: boolean;
  onConfirmingChange: (ruleId: string | null) => void;
  onDelete: () => void;
}) {
  if (confirmingDeleteId === row.id) {
    return (
      <div className="rule-delete-confirmation">
        <button
          type="button"
          className="rule-danger-button row-action-button"
          aria-label={`Confirm delete rule ${row.id}`}
          disabled={!canWritePolicy || isMutating}
          onClick={onDelete}
        >
          Confirm
        </button>
        <button
          type="button"
          className="secondary-button row-action-button"
          onClick={() => onConfirmingChange(null)}
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <button
      type="button"
      className="secondary-button row-action-button"
      aria-label={`Delete rule ${row.id}`}
      title={canWritePolicy ? undefined : 'Requires admin:policy:write'}
      disabled={!canWritePolicy || isMutating}
      onClick={() => onConfirmingChange(row.id)}
    >
      Delete
    </button>
  );
}

function PolicyErrorMessage({ error }: { error: PolicyLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing policy rules. Open the{' '}
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

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Policy API unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid policy query' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function PolicyWritePermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Policy write permission required</h3>
      <p>This token can read policy rules but does not include admin:policy:write.</p>
    </div>
  );
}

function PolicyMutationErrorMessage({ error }: { error: PolicyLoadError }) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy write permission required</h3>
        <p>This token can read policy rules but does not include admin:policy:write.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid rule update' : 'Rule update failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

export function ruleOrderAfterDrop(
  rules: PolicyRule[],
  draggedRuleId: string,
  targetRuleId: string,
): string[] {
  if (draggedRuleId === targetRuleId) {
    return [];
  }

  const ids = rules.map(policyRuleId);
  if (!ids.includes(draggedRuleId) || !ids.includes(targetRuleId)) {
    return [];
  }

  const withoutDragged = ids.filter((id) => id !== draggedRuleId);
  const targetIndex = withoutDragged.indexOf(targetRuleId);
  withoutDragged.splice(targetIndex, 0, draggedRuleId);
  return withoutDragged;
}

function reorderRulesById(rules: PolicyRule[], order: string[]): PolicyRule[] {
  return order
    .map((ruleId) =>
      rules.find((rule, index) => policyRuleId(rule, index) === ruleId),
    )
    .filter((rule): rule is PolicyRule => Boolean(rule));
}

function sameOrder(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function formatPrincipal(principal: PolicyRule['principal']): string {
  const roles = principal?.roles ?? [];
  const authMethods = principal?.auth_methods ?? [];
  const principalIds = principal?.principal_ids ?? [];
  const parts: string[] = [];

  if (roles.length > 0) {
    parts.push(`${roles.length === 1 ? 'role' : 'roles'}: ${roles.join(', ')}`);
  }
  if (authMethods.length > 0) {
    parts.push(`auth: ${authMethods.map(formatAuthMethod).join(', ')}`);
  }
  if (principalIds.length > 0) {
    parts.push(
      `${principalIds.length === 1 ? 'principal' : 'principals'}: ${principalIds.join(', ')}`,
    );
  }

  return parts.length > 0 ? parts.join(' + ') : 'any principal';
}

function formatAuthMethod(value: string): string {
  switch (value) {
    case 'bearer_token':
      return 'bearer token';
    case 'session_cookie':
      return 'session cookie';
    default:
      return value;
  }
}

function formatRuleHits(value: number): string {
  if (value === 0) {
    return 'never matched';
  }

  return `${value.toLocaleString()} ${value === 1 ? 'hit' : 'hits'}`;
}

function actionBadgeClass(action: PolicyRule['action'] | PolicyDefaultAction): string {
  switch (action) {
    case 'allow':
      return 'success';
    case 'shadow':
      return 'warning';
    case 'deny':
      return 'danger';
  }
}

function actionTitle(action: PolicyRule['action'] | PolicyDefaultAction): string {
  switch (action) {
    case 'allow':
      return 'Allow';
    case 'shadow':
      return 'Shadow';
    case 'deny':
      return 'Deny';
  }
}

function toPolicyLoadError(error: unknown): PolicyLoadError {
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
