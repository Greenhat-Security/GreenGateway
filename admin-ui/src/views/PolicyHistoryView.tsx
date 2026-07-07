import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { decodeJwtRolesClaim, getStoredToken } from '../lib/auth';
import { fetchPolicy, type PolicyDocument } from '../lib/policy';
import {
  fetchPolicyHistory,
  rollbackPolicy,
  type PolicyDiffSummary,
  type PolicyVersion,
} from '../lib/policyHistory';
import { RuleWorkspaceNav } from './RuleWorkspaceNav';

type HistoryViewError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'history-unavailable'
    | 'policy-changed'
    | 'not-found'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

const HISTORY_PAGE_SIZE = 20;
const POLICY_WRITE_PERMISSION = 'admin:policy:write';
const POLICY_CHANGED_MESSAGE =
  'Policy changed since this page loaded — refresh and retry.';

export function PolicyHistoryView() {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<HistoryViewError | null>(null);
  const [rollbackError, setRollbackError] = useState<HistoryViewError | null>(
    null,
  );
  const [rollbackNotice, setRollbackNotice] = useState<string | null>(null);
  const [rollbackWarning, setRollbackWarning] = useState<string | null>(null);
  const [canWritePolicy, setCanWritePolicy] = useState(false);
  const [rollingBackVersion, setRollingBackVersion] = useState<number | null>(
    null,
  );

  useEffect(() => {
    let isCurrent = true;

    async function loadInitialHistory() {
      setIsLoading(true);
      setLoadError(null);
      setRollbackError(null);
      setRollbackNotice(null);
      setRollbackWarning(null);
      setCanWritePolicy(false);

      try {
        const [policyResult, historyPage] = await Promise.all([
          fetchPolicy(),
          fetchPolicyHistory({ limit: HISTORY_PAGE_SIZE }),
        ]);
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(currentTokenCanWritePolicy(policyResult.policy));
        setVersions(historyPage.versions);
        setNextCursor(historyPage.next_cursor);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setCanWritePolicy(false);
        setVersions([]);
        setNextCursor(null);
        setLoadError(toHistoryLoadError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadInitialHistory();

    return () => {
      isCurrent = false;
    };
  }, []);

  const showWritePermissionNotice =
    !isLoading &&
    !loadError &&
    !canWritePolicy &&
    rollbackError?.kind !== 'forbidden';

  const resultCount = useMemo(() => {
    return `${versions.length} ${versions.length === 1 ? 'version' : 'versions'}`;
  }, [versions.length]);

  async function loadMoreHistory() {
    if (!nextCursor || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);

    try {
      const page = await fetchPolicyHistory({
        cursor: nextCursor,
        limit: HISTORY_PAGE_SIZE,
      });
      setVersions((current) => [...current, ...page.versions]);
      setNextCursor(page.next_cursor);
    } catch (error) {
      setLoadError(toHistoryLoadError(error));
    } finally {
      setIsLoadingMore(false);
    }
  }

  async function rollbackToVersion(version: number) {
    if (!canWritePolicy || rollingBackVersion !== null) {
      return;
    }

    setRollingBackVersion(version);
    setRollbackError(null);
    setRollbackNotice(null);
    setRollbackWarning(null);

    try {
      const policyResult = await fetchPolicy();
      if (!policyResult.etag) {
        throw new Error('Current policy ETag was not returned; refresh and retry.');
      }

      const rollback = await rollbackPolicy(version, policyResult.etag);
      setCanWritePolicy(currentTokenCanWritePolicy(rollback.policy));
      setRollbackNotice('Rollback applied.');
      setRollbackWarning(
        rollback.historyAppendWarning
          ? 'Rollback applied, but it could not be recorded in version history.'
          : null,
      );
      await refreshFirstHistoryPage();
    } catch (error) {
      const historyError = toRollbackError(error);
      if (historyError.kind === 'forbidden') {
        setCanWritePolicy(false);
      }
      setRollbackError(historyError);
    } finally {
      setRollingBackVersion(null);
    }
  }

  async function refreshFirstHistoryPage() {
    const page = await fetchPolicyHistory({ limit: HISTORY_PAGE_SIZE });
    setVersions(page.versions);
    setNextCursor(page.next_cursor);
  }

  return (
    <main className="logs-page policy-history-page">
      <section
        className="panel logs-panel policy-history-panel"
        aria-labelledby="policy-history-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Policy</p>
            <h2 id="policy-history-heading">Policy version history</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        <RuleWorkspaceNav />

        {loadError ? <HistoryLoadErrorMessage error={loadError} /> : null}
        {showWritePermissionNotice ? <PolicyWritePermissionNotice /> : null}
        {rollbackError ? <RollbackErrorMessage error={rollbackError} /> : null}
        {rollbackNotice ? (
          <div className="error-panel alert success" role="status">
            <p>{rollbackNotice}</p>
          </div>
        ) : null}
        {rollbackWarning ? (
          <div className="error-panel alert warning" role="alert">
            <p>{rollbackWarning}</p>
          </div>
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading policy version history
          </div>
        ) : null}

        {!isLoading && versions.length === 0 && !loadError ? (
          <div className="empty-state">No policy versions have been recorded.</div>
        ) : null}

        {versions.length > 0 ? (
          <ol className="policy-history-list" aria-label="Policy version history">
            {versions.map((version, index) => (
              <PolicyHistoryEntry
                canWritePolicy={canWritePolicy}
                isCurrentVersion={index === 0}
                isRollingBack={rollingBackVersion === version.version}
                isRollbackBusy={rollingBackVersion !== null}
                key={version.version}
                version={version}
                onRollback={() => {
                  void rollbackToVersion(version.version);
                }}
              />
            ))}
          </ol>
        ) : null}

        {nextCursor ? (
          <div className="policy-history-footer">
            <button
              type="button"
              className="secondary-button"
              disabled={isLoadingMore}
              onClick={() => {
                void loadMoreHistory();
              }}
            >
              {isLoadingMore ? 'Loading more' : 'Load more'}
            </button>
          </div>
        ) : null}
      </section>
    </main>
  );
}

function PolicyHistoryEntry({
  version,
  canWritePolicy,
  isCurrentVersion,
  isRollingBack,
  isRollbackBusy,
  onRollback,
}: {
  version: PolicyVersion;
  canWritePolicy: boolean;
  isCurrentVersion: boolean;
  isRollingBack: boolean;
  isRollbackBusy: boolean;
  onRollback: () => void;
}) {
  return (
    <li
      className="policy-history-entry"
      data-testid={`policy-history-entry-${version.version}`}
    >
      <div className="policy-history-marker" aria-hidden="true" />
      <div className="policy-history-content">
        <div className="policy-history-entry-heading">
          <div>
            <span className="badge neutral">Version {version.version}</span>
            <h3>{diffSummarySentence(version.diff_summary)}</h3>
          </div>
          <span className={`badge ${diffActionBadgeClass(version.diff_summary.action)}`}>
            {diffActionLabel(version.diff_summary.action)}
          </span>
        </div>

        <dl className="policy-history-meta">
          <div>
            <dt>Actor</dt>
            <dd>{version.actor}</dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>{formatHistoryTimestamp(version.created_at)}</dd>
          </div>
        </dl>

        {!isCurrentVersion ? (
          <div className="policy-history-actions">
            <button
              type="button"
              className="secondary-button"
              aria-label={`Rollback to version ${version.version}`}
              title={canWritePolicy ? undefined : 'Requires admin:policy:write'}
              disabled={!canWritePolicy || isRollbackBusy}
              onClick={onRollback}
            >
              {isRollingBack ? 'Rolling back' : 'Rollback'}
            </button>
          </div>
        ) : null}
      </div>
    </li>
  );
}

function currentTokenCanWritePolicy(policy: PolicyDocument): boolean {
  const token = getStoredToken();
  if (!token) {
    return false;
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return false;
  }

  return roles.some((roleName) => roleGrantsPolicyWrite(policy.roles?.[roleName]));
}

function roleGrantsPolicyWrite(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) => permission === POLICY_WRITE_PERMISSION || permission === '*',
  );
}

function diffSummarySentence(summary: PolicyDiffSummary): string {
  switch (summary.action) {
    case 'policy_replaced':
      return 'Full policy replaced';
    case 'policy_rolled_back':
      return `Rolled back to version ${summary.target_version}`;
    case 'rule_created':
      return `Rule ${summary.rule_id} created at position ${summary.position}`;
    case 'rule_updated':
      return ruleUpdatedSentence(summary.rule_id, summary.changed_fields);
    case 'rule_deleted':
      return `Rule ${summary.rule_id} deleted from position ${summary.position}`;
    case 'rules_reordered':
      return 'Rules reordered';
  }
}

function ruleUpdatedSentence(ruleId: string, changedFields: string[]): string {
  if (changedFields.length === 0) {
    return `Rule ${ruleId} updated`;
  }

  return `Rule ${ruleId} updated (${changedFields.join(', ')} changed)`;
}

function diffActionLabel(action: PolicyDiffSummary['action']): string {
  switch (action) {
    case 'policy_replaced':
      return 'Policy';
    case 'policy_rolled_back':
      return 'Rollback';
    case 'rule_created':
      return 'Created';
    case 'rule_updated':
      return 'Updated';
    case 'rule_deleted':
      return 'Deleted';
    case 'rules_reordered':
      return 'Reordered';
  }
}

function diffActionBadgeClass(action: PolicyDiffSummary['action']): string {
  switch (action) {
    case 'policy_replaced':
    case 'rules_reordered':
      return 'neutral';
    case 'policy_rolled_back':
      return 'warning';
    case 'rule_created':
      return 'success';
    case 'rule_updated':
      return 'warning';
    case 'rule_deleted':
      return 'danger';
  }
}

function formatHistoryTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function HistoryLoadErrorMessage({ error }: { error: HistoryViewError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing policy history. Open the{' '}
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

  if (error.kind === 'history-unavailable') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy history unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid history query' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function PolicyWritePermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Policy write permission required</h3>
      <p>This token can read policy history but does not include admin:policy:write.</p>
    </div>
  );
}

function RollbackErrorMessage({ error }: { error: HistoryViewError }) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy write permission required</h3>
        <p>This token can read policy history but does not include admin:policy:write.</p>
      </div>
    );
  }

  if (error.kind === 'policy-changed') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy changed</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'not-found') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy version not found</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'history-unavailable') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Policy history unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid rollback request' : 'Rollback failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toHistoryLoadError(error: unknown): HistoryViewError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404 && isHistoryUnavailableMessage(error.message)) {
      return { kind: 'history-unavailable', message: error.message };
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

function toRollbackError(error: unknown): HistoryViewError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 412 || error.status === 428) {
      return { kind: 'policy-changed', message: POLICY_CHANGED_MESSAGE };
    }
    if (error.status === 404 && isHistoryUnavailableMessage(error.message)) {
      return { kind: 'history-unavailable', message: error.message };
    }
    if (error.status === 404) {
      return { kind: 'not-found', message: error.message };
    }
    if (error.status === 400) {
      return { kind: 'bad-request', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: error.message,
    };
  }

  return { kind: 'network', message: 'Rollback request failed.' };
}

function isHistoryUnavailableMessage(message: string): boolean {
  return message.includes('policy history requires');
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
