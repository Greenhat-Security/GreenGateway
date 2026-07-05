import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { decodeJwtRolesClaim, getStoredToken } from '../lib/auth';
import { fetchPolicy, type PolicyDocument } from '../lib/policy';
import {
  type CreatedToken,
  type TokenRecord,
  createToken,
  fetchTokens,
  revokeToken,
  rotateToken,
} from '../lib/tokens';

type TokensViewError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'conflict'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

const TOKEN_PAGE_LIMIT = 50;
const TOKEN_WRITE_PERMISSION = 'admin:tokens:write';

export function TokensView() {
  const [tokens, setTokens] = useState<TokenRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<TokensViewError | null>(null);
  const [mutationError, setMutationError] =
    useState<TokensViewError | null>(null);
  const [oneTimeToken, setOneTimeToken] = useState<CreatedToken | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [canWriteTokens, setCanWriteTokens] = useState(false);
  const [scopeDraft, setScopeDraft] = useState('');
  const [expiresDate, setExpiresDate] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [mutatingTokenId, setMutatingTokenId] = useState<string | null>(null);
  const [confirmingRevokeId, setConfirmingRevokeId] = useState<string | null>(
    null,
  );
  const [confirmingRotateId, setConfirmingRotateId] = useState<string | null>(
    null,
  );

  useEffect(() => {
    let isCurrent = true;

    async function loadFirstPage() {
      setIsLoading(true);
      setLoadError(null);
      setMutationError(null);

      try {
        const page = await fetchTokens(undefined, TOKEN_PAGE_LIMIT);
        if (!isCurrent) {
          return;
        }

        setTokens(page.tokens);
        setNextCursor(page.next_cursor);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setTokens([]);
        setNextCursor(null);
        setLoadError(toTokensViewError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadFirstPage();

    return () => {
      isCurrent = false;
    };
  }, []);

  useEffect(() => {
    let isCurrent = true;

    async function loadWritePermission() {
      setCanWriteTokens(false);

      try {
        const policyResult = await fetchPolicy();
        if (isCurrent) {
          setCanWriteTokens(currentTokenCanWriteTokens(policyResult.policy));
        }
      } catch {
        if (isCurrent) {
          setCanWriteTokens(false);
        }
      }
    }

    void loadWritePermission();

    return () => {
      isCurrent = false;
    };
  }, []);

  const normalizedScopes = useMemo(
    () => normalizeScopes(scopeDraft),
    [scopeDraft],
  );
  const resultCount = useMemo(
    () => `${tokens.length} ${tokens.length === 1 ? 'token' : 'tokens'}`,
    [tokens.length],
  );
  const isMutationBusy =
    isCreating || mutatingTokenId !== null || oneTimeToken !== null;
  const canSubmitCreate =
    canWriteTokens &&
    !isCreating &&
    oneTimeToken === null &&
    normalizedScopes.length > 0;
  const showWritePermissionNotice =
    !isLoading &&
    !loadError &&
    !canWriteTokens &&
    mutationError?.kind !== 'forbidden';

  async function loadMoreTokens() {
    if (!nextCursor || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);

    try {
      const page = await fetchTokens(nextCursor, TOKEN_PAGE_LIMIT);
      setTokens((current) => [...current, ...page.tokens]);
      setNextCursor(page.next_cursor);
    } catch (error) {
      setLoadError(toTokensViewError(error));
    } finally {
      setIsLoadingMore(false);
    }
  }

  async function submitCreateToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteTokens || isCreating || oneTimeToken !== null) {
      return;
    }

    const scopes = normalizeScopes(scopeDraft);
    if (scopes.length === 0) {
      setMutationError({
        kind: 'bad-request',
        message: 'Enter at least one scope.',
      });
      return;
    }

    const expiresAt = expiresDateToRfc3339(expiresDate);
    if (expiresAt === null) {
      setMutationError({
        kind: 'bad-request',
        message: 'Expires at must be a valid date.',
      });
      return;
    }

    setIsCreating(true);
    setMutationError(null);
    setCopyStatus(null);

    try {
      const created = await createToken(scopes, expiresAt);
      setOneTimeToken(created);
      setScopeDraft('');
      setExpiresDate('');
    } catch (error) {
      handleMutationError(error);
    } finally {
      setIsCreating(false);
    }
  }

  async function revokeExistingToken(token: TokenRecord) {
    if (!canWriteTokens || mutatingTokenId !== null || oneTimeToken !== null) {
      return;
    }

    setMutatingTokenId(token.id);
    setMutationError(null);

    try {
      const revoked = await revokeToken(token.id);
      upsertToken(revoked);
      setConfirmingRevokeId(null);
    } catch (error) {
      handleMutationError(error);
    } finally {
      setMutatingTokenId(null);
    }
  }

  async function rotateExistingToken(token: TokenRecord) {
    if (!canWriteTokens || mutatingTokenId !== null || oneTimeToken !== null) {
      return;
    }

    setMutatingTokenId(token.id);
    setMutationError(null);
    setCopyStatus(null);

    try {
      const rotated = await rotateToken(token.id);
      setOneTimeToken(rotated);
      setConfirmingRotateId(null);
    } catch (error) {
      handleMutationError(error);
    } finally {
      setMutatingTokenId(null);
    }
  }

  function dismissOneTimeToken() {
    if (oneTimeToken) {
      upsertToken(oneTimeToken.token);
    }
    setOneTimeToken(null);
    setCopyStatus(null);
  }

  async function copyPlaintextToken() {
    if (!oneTimeToken) {
      return;
    }
    if (!navigator.clipboard) {
      setCopyStatus('Copy unavailable');
      return;
    }

    try {
      await navigator.clipboard.writeText(oneTimeToken.plaintext_token);
      setCopyStatus('Copied');
    } catch {
      setCopyStatus('Copy failed');
    }
  }

  function upsertToken(nextToken: TokenRecord) {
    setTokens((current) => {
      const existingIndex = current.findIndex(
        (token) => token.id === nextToken.id,
      );
      if (existingIndex === -1) {
        return [nextToken, ...current];
      }

      const next = [...current];
      next[existingIndex] = nextToken;
      return next;
    });
  }

  function handleMutationError(error: unknown) {
    const tokenError = toTokensViewError(error);
    if (tokenError.kind === 'forbidden') {
      setCanWriteTokens(false);
    }
    setMutationError(tokenError);
  }

  return (
    <main className="logs-page tokens-page">
      <section
        className="panel logs-panel tokens-panel"
        aria-labelledby="tokens-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Authentication</p>
            <h2 id="tokens-heading">Service tokens</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        {oneTimeToken ? (
          <OneTimeTokenPanel
            created={oneTimeToken}
            copyStatus={copyStatus}
            onCopy={() => {
              void copyPlaintextToken();
            }}
            onDismiss={dismissOneTimeToken}
          />
        ) : null}

        <form
          className="filter-form"
          aria-labelledby="token-create-heading"
          onSubmit={submitCreateToken}
        >
          <div className="section-heading">
            <p className="eyebrow">Lifecycle</p>
            <h3 id="token-create-heading">Create token</h3>
          </div>
          <div className="filter-grid signal-filter-grid">
            <label htmlFor="token-scopes">
              Scopes
              <input
                id="token-scopes"
                type="text"
                value={scopeDraft}
                placeholder="admin:tokens:read admin:tokens:write"
                onChange={(event) => setScopeDraft(event.target.value)}
              />
            </label>
            <label htmlFor="token-expires-at">
              Expires at
              <input
                id="token-expires-at"
                type="date"
                value={expiresDate}
                onChange={(event) => setExpiresDate(event.target.value)}
              />
            </label>
          </div>
          <div className="form-actions">
            <button
              type="submit"
              className="primary-button"
              title={canWriteTokens ? undefined : 'Requires admin:tokens:write'}
              disabled={!canSubmitCreate}
            >
              {isCreating ? 'Creating' : 'Create token'}
            </button>
          </div>
        </form>

        {loadError ? <TokensLoadErrorMessage error={loadError} /> : null}
        {showWritePermissionNotice ? <TokensWritePermissionNotice /> : null}
        {mutationError ? (
          <TokensMutationErrorMessage error={mutationError} />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading service tokens
          </div>
        ) : null}

        {!isLoading && tokens.length === 0 && !loadError ? (
          <div className="empty-state">No service tokens have been created.</div>
        ) : null}

        {tokens.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table rule-table">
                <thead>
                  <tr>
                    <th>Token</th>
                    <th>Scopes</th>
                    <th>Created by</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Last used</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token, index) => (
                    <tr
                      className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      key={token.id}
                    >
                      <td>
                        <div className="traffic-endpoint-cell">
                          <span>{token.id}</span>
                          <code className="endpoint-template">
                            {token.token_prefix}
                          </code>
                        </div>
                      </td>
                      <td>
                        <ScopeList token={token} />
                      </td>
                      <td>{token.created_by}</td>
                      <td>{formatUtcTimestamp(token.created_at)}</td>
                      <td>{formatOptionalTimestamp(token.expires_at, 'Never')}</td>
                      <td>
                        {formatOptionalTimestamp(
                          token.last_used_at,
                          'Never used',
                        )}
                      </td>
                      <td>
                        <TokenStatusBadge token={token} />
                      </td>
                      <td>
                        <div className="signal-actions">
                          <TokenRevokeControl
                            token={token}
                            canWriteTokens={canWriteTokens}
                            confirmingRevokeId={confirmingRevokeId}
                            isMutating={mutatingTokenId === token.id}
                            isMutationBusy={isMutationBusy}
                            onConfirmingChange={setConfirmingRevokeId}
                            onRevoke={() => {
                              void revokeExistingToken(token);
                            }}
                          />
                          <TokenRotateControl
                            token={token}
                            canWriteTokens={canWriteTokens}
                            confirmingRotateId={confirmingRotateId}
                            isMutating={mutatingTokenId === token.id}
                            isMutationBusy={isMutationBusy}
                            onConfirmingChange={setConfirmingRotateId}
                            onRotate={() => {
                              void rotateExistingToken(token);
                            }}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination-row">
              {nextCursor ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={isLoadingMore}
                  onClick={() => {
                    void loadMoreTokens();
                  }}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more tokens</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function OneTimeTokenPanel({
  created,
  copyStatus,
  onCopy,
  onDismiss,
}: {
  created: CreatedToken;
  copyStatus: string | null;
  onCopy: () => void;
  onDismiss: () => void;
}) {
  return (
    <div className="error-panel alert warning" role="status">
      <h3>Save this token now</h3>
      <p>{created.plaintext_token_notice}</p>
      <div className="token-row">
        <input
          aria-label="Plaintext token"
          className="endpoint-template"
          readOnly
          spellCheck={false}
          value={created.plaintext_token}
          onFocus={(event) => event.currentTarget.select()}
        />
        <button type="button" className="secondary-button" onClick={onCopy}>
          {copyStatus ?? 'Copy'}
        </button>
        <button type="button" className="primary-button" onClick={onDismiss}>
          I've saved this
        </button>
      </div>
    </div>
  );
}

function ScopeList({ token }: { token: TokenRecord }) {
  if (token.scopes.length === 0) {
    return <span className="badge neutral">No scopes</span>;
  }

  return (
    <div className="rule-method-list" aria-label={`Scopes for ${token.id}`}>
      {token.scopes.map((scope) => (
        <span className="badge neutral" key={scope}>
          {scope}
        </span>
      ))}
    </div>
  );
}

function TokenStatusBadge({ token }: { token: TokenRecord }) {
  const status = tokenStatus(token);
  return <span className={`badge ${status.className}`}>{status.label}</span>;
}

function TokenRevokeControl({
  token,
  canWriteTokens,
  confirmingRevokeId,
  isMutating,
  isMutationBusy,
  onConfirmingChange,
  onRevoke,
}: {
  token: TokenRecord;
  canWriteTokens: boolean;
  confirmingRevokeId: string | null;
  isMutating: boolean;
  isMutationBusy: boolean;
  onConfirmingChange: (tokenId: string | null) => void;
  onRevoke: () => void;
}) {
  if (confirmingRevokeId === token.id) {
    return (
      <div className="rule-delete-confirmation">
        <button
          type="button"
          className="rule-danger-button row-action-button"
          aria-label={`Confirm revoke token ${token.id}`}
          disabled={!canWriteTokens || isMutationBusy}
          onClick={onRevoke}
        >
          {isMutating ? 'Revoking' : 'Confirm'}
        </button>
        <button
          type="button"
          className="secondary-button row-action-button"
          disabled={isMutationBusy}
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
      aria-label={`Revoke token ${token.id}`}
      title={canWriteTokens ? undefined : 'Requires admin:tokens:write'}
      disabled={!canWriteTokens || isMutationBusy}
      onClick={() => onConfirmingChange(token.id)}
    >
      Revoke
    </button>
  );
}

function TokenRotateControl({
  token,
  canWriteTokens,
  confirmingRotateId,
  isMutating,
  isMutationBusy,
  onConfirmingChange,
  onRotate,
}: {
  token: TokenRecord;
  canWriteTokens: boolean;
  confirmingRotateId: string | null;
  isMutating: boolean;
  isMutationBusy: boolean;
  onConfirmingChange: (tokenId: string | null) => void;
  onRotate: () => void;
}) {
  if (confirmingRotateId === token.id) {
    return (
      <div className="rule-delete-confirmation">
        <button
          type="button"
          className="primary-button row-action-button"
          aria-label={`Confirm rotate token ${token.id}`}
          disabled={!canWriteTokens || isMutationBusy}
          onClick={onRotate}
        >
          {isMutating ? 'Rotating' : 'Confirm'}
        </button>
        <button
          type="button"
          className="secondary-button row-action-button"
          disabled={isMutationBusy}
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
      aria-label={`Rotate token ${token.id}`}
      title={canWriteTokens ? undefined : 'Requires admin:tokens:write'}
      disabled={!canWriteTokens || isMutationBusy}
      onClick={() => onConfirmingChange(token.id)}
    >
      Rotate
    </button>
  );
}

function TokensLoadErrorMessage({ error }: { error: TokensViewError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before managing service tokens. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Token permission required</h3>
        <p>This token is valid but does not include admin:tokens:read.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid token query' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function TokensWritePermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Token write permission required</h3>
      <p>This token can read service tokens but does not include admin:tokens:write.</p>
    </div>
  );
}

function TokensMutationErrorMessage({ error }: { error: TokensViewError }) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Token write permission required</h3>
        <p>This token can read service tokens but does not include admin:tokens:write.</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${
        error.kind === 'bad-request' || error.kind === 'conflict'
          ? 'warning'
          : 'error'
      }`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid token request' : 'Token update failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function currentTokenCanWriteTokens(policy: PolicyDocument): boolean {
  const token = getStoredToken();
  if (!token) {
    return false;
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return false;
  }

  return roles.some((roleName) => roleGrantsTokensWrite(policy.roles?.[roleName]));
}

function roleGrantsTokensWrite(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) =>
      permission === TOKEN_WRITE_PERMISSION || permission === '*',
  );
}

function normalizeScopes(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[,\s]+/)
        .map((scope) => scope.trim())
        .filter(Boolean),
    ),
  );
}

function expiresDateToRfc3339(value: string): string | undefined | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  const date = new Date(`${trimmed}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function tokenStatus(token: TokenRecord): {
  label: 'Active' | 'Expired' | 'Revoked';
  className: 'success' | 'warning' | 'danger';
} {
  if (token.revoked_at) {
    return { label: 'Revoked', className: 'danger' };
  }
  if (token.expires_at && new Date(token.expires_at).getTime() <= Date.now()) {
    return { label: 'Expired', className: 'warning' };
  }

  return { label: 'Active', className: 'success' };
}

function formatOptionalTimestamp(
  value: string | null | undefined,
  fallback: string,
): string {
  return value ? formatUtcTimestamp(value) : fallback;
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

function toTokensViewError(error: unknown): TokensViewError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 409) {
      return { kind: 'conflict', message: error.message };
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

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
