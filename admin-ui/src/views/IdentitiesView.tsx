import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { decodeJwtRolesClaim, getStoredToken } from '../lib/auth';
import { fetchPolicy, type PolicyDocument } from '../lib/policy';
import {
  type PrincipalFilters,
  type PrincipalRecord,
  type PrincipalTypeFilter,
  fetchPrincipals,
} from '../lib/principals';

type PrincipalLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

type PrincipalFilterDraft = {
  issuer: string;
  principalType: PrincipalTypeFilter | '';
};

const PRINCIPAL_PAGE_LIMIT = 50;
const PRINCIPAL_READ_PERMISSION = 'admin:principals:read';
const EMPTY_FILTERS: PrincipalFilterDraft = {
  issuer: '',
  principalType: '',
};

export function IdentitiesView() {
  const [filters, setFilters] = useState<PrincipalFilterDraft>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] =
    useState<PrincipalFilters>(() => ({}));
  const [principals, setPrincipals] = useState<PrincipalRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [anonymousRequestCount, setAnonymousRequestCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<PrincipalLoadError | null>(null);
  const [canReadPrincipals, setCanReadPrincipals] = useState(false);

  useEffect(() => {
    let isCurrent = true;

    async function loadFirstPage() {
      setIsLoading(true);
      setLoadError(null);

      try {
        const page = await fetchPrincipals(
          appliedFilters,
          undefined,
          PRINCIPAL_PAGE_LIMIT,
        );
        if (!isCurrent) {
          return;
        }

        setPrincipals(page.principals);
        setNextCursor(page.next_cursor);
        setAnonymousRequestCount(page.anonymous_request_count);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setPrincipals([]);
        setNextCursor(null);
        setAnonymousRequestCount(0);
        setLoadError(toPrincipalLoadError(error));
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
  }, [appliedFilters]);

  useEffect(() => {
    let isCurrent = true;

    async function loadReadPermission() {
      setCanReadPrincipals(false);

      try {
        const policyResult = await fetchPolicy();
        if (isCurrent) {
          setCanReadPrincipals(
            currentTokenCanReadPrincipals(policyResult.policy),
          );
        }
      } catch {
        if (isCurrent) {
          setCanReadPrincipals(false);
        }
      }
    }

    void loadReadPermission();

    return () => {
      isCurrent = false;
    };
  }, []);

  const resultCount = useMemo(
    () =>
      `${principals.length} ${
        principals.length === 1 ? 'principal' : 'principals'
      }, plus ${formatCount(anonymousRequestCount)} anonymous/failed requests`,
    [anonymousRequestCount, principals.length],
  );
  const showReadPermissionNotice =
    !isLoading && !loadError && !canReadPrincipals;

  function updateIssuerFilter(value: string) {
    setFilters((current) => ({ ...current, issuer: value }));
  }

  function updatePrincipalTypeFilter(value: string) {
    if (value === '' || value === 'human' || value === 'service') {
      setFilters((current) => ({ ...current, principalType: value }));
    }
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppliedFilters(normalizeFilters(filters));
  }

  function clearFilters() {
    setFilters(EMPTY_FILTERS);
    setAppliedFilters({});
  }

  async function loadMorePrincipals() {
    if (!nextCursor || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);

    try {
      const page = await fetchPrincipals(
        appliedFilters,
        nextCursor,
        PRINCIPAL_PAGE_LIMIT,
      );
      setPrincipals((current) => [...current, ...page.principals]);
      setNextCursor(page.next_cursor);
      setAnonymousRequestCount(page.anonymous_request_count);
    } catch (error) {
      setLoadError(toPrincipalLoadError(error));
    } finally {
      setIsLoadingMore(false);
    }
  }

  return (
    <main className="logs-page identities-page">
      <section
        className="panel logs-panel identities-panel"
        aria-labelledby="identities-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Authentication</p>
            <h2 id="identities-heading">Identity directory</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        <form className="filter-form" onSubmit={applyFilters}>
          <div className="filter-grid signal-filter-grid">
            <label>
              Issuer search
              <input
                type="text"
                value={filters.issuer}
                placeholder="https://idp.example"
                onChange={(event) => updateIssuerFilter(event.target.value)}
              />
            </label>
            <label>
              Principal type
              <select
                value={filters.principalType}
                onChange={(event) =>
                  updatePrincipalTypeFilter(event.target.value)
                }
              >
                <option value="">All principals</option>
                <option value="human">Humans</option>
                <option value="service">Service principals</option>
              </select>
            </label>
          </div>

          <div className="form-actions">
            <button type="submit" className="primary-button" disabled={isLoading}>
              Apply filters
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={clearFilters}
              disabled={isLoading}
            >
              Clear
            </button>
          </div>
        </form>

        {loadError ? <PrincipalLoadErrorMessage error={loadError} /> : null}
        {showReadPermissionNotice ? <PrincipalReadPermissionNotice /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading identity directory
          </div>
        ) : null}

        {!isLoading && principals.length === 0 && !loadError ? (
          <div className="empty-state">
            No principals matched these filters.
          </div>
        ) : null}

        {principals.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table rule-table">
                <thead>
                  <tr>
                    <th>Identity</th>
                    <th>IdP</th>
                    <th>Auth Method</th>
                    <th>Email</th>
                    <th>Org ID</th>
                    <th>Activity</th>
                    <th>Anomalies</th>
                  </tr>
                </thead>
                <tbody>
                  {principals.map((principal, index) => (
                    <tr
                      className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      key={principalKey(principal)}
                    >
                      <td>
                        <div className="traffic-endpoint-cell">
                          <span className="endpoint-template">
                            {principal.subject}
                          </span>
                          <time
                            className="timestamp-cell"
                            dateTime={principal.first_seen}
                            title={principal.first_seen}
                          >
                            First seen {formatRelativeTimestamp(principal.first_seen)}
                          </time>
                        </div>
                      </td>
                      <td>
                        <span className="badge neutral">
                          {principal.issuer || 'Unknown issuer'}
                        </span>
                      </td>
                      <td>
                        <PrincipalAuthMethodBadge
                          authMethod={principal.auth_method}
                        />
                      </td>
                      <td>{principal.email || 'Not set'}</td>
                      <td>{principal.org_id || 'Not set'}</td>
                      <td>
                        <div className="rule-method-list">
                          <time
                            className="timestamp-cell"
                            dateTime={principal.last_seen}
                            title={principal.last_seen}
                          >
                            Last active{' '}
                            {formatRelativeTimestamp(principal.last_seen)}
                          </time>
                          <span className="badge neutral">
                            {formatRequestCount(principal.request_count)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          className="badge neutral"
                          title="Per-principal anomaly counts require a list-response summary."
                        >
                          —
                        </span>
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
                    void loadMorePrincipals();
                  }}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more principals</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function PrincipalAuthMethodBadge({
  authMethod,
}: {
  authMethod: string;
}) {
  const badge = authMethodBadge(authMethod);
  return <span className={`badge ${badge.className}`}>{badge.label}</span>;
}

function PrincipalLoadErrorMessage({
  error,
}: {
  error: PrincipalLoadError;
}) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing identities. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Principal directory permission required</h3>
        <p>This token is valid but does not include admin:principals:read.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Principal directory unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>
        {error.kind === 'bad-request' ? 'Invalid principal query' : 'Request failed'}
      </h3>
      <p>{error.message}</p>
    </div>
  );
}

function PrincipalReadPermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Principal directory permission required</h3>
      <p>This token does not appear to include admin:principals:read.</p>
    </div>
  );
}

function currentTokenCanReadPrincipals(policy: PolicyDocument): boolean {
  const token = getStoredToken();
  if (!token) {
    return false;
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return false;
  }

  return roles.some((roleName) =>
    roleGrantsPrincipalsRead(policy.roles?.[roleName]),
  );
}

function roleGrantsPrincipalsRead(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) =>
      permission === PRINCIPAL_READ_PERMISSION || permission === '*',
  );
}

function normalizeFilters(filters: PrincipalFilterDraft): PrincipalFilters {
  const normalized: PrincipalFilters = {};
  const issuer = filters.issuer.trim();
  if (issuer.length > 0) {
    normalized.issuer = issuer;
  }
  if (filters.principalType) {
    normalized.principalType = filters.principalType;
  }

  return normalized;
}

function principalKey(principal: PrincipalRecord): string {
  return `${principal.subject}\n${principal.issuer}\n${principal.auth_method}`;
}

function authMethodBadge(authMethod: string): {
  label: string;
  className: 'success' | 'warning' | 'neutral';
} {
  if (authMethod === 'service_token') {
    return { label: 'Service token', className: 'warning' };
  }
  if (authMethod === 'bearer') {
    return { label: 'Bearer', className: 'success' };
  }
  if (authMethod === 'cookie') {
    return { label: 'Cookie', className: 'success' };
  }

  return { label: authMethod || 'Unknown', className: 'neutral' };
}

function formatRequestCount(value: number): string {
  return `${formatCount(value)} ${value === 1 ? 'request' : 'requests'}`;
}

function formatRelativeTimestamp(timestamp: string): string {
  const value = new Date(timestamp).valueOf();
  if (Number.isNaN(value)) {
    return timestamp;
  }

  const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (seconds < 60) {
    return 'just now';
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  if (days < 30) {
    return `${days}d ago`;
  }

  const months = Math.floor(days / 30);
  if (months < 12) {
    return `${months}mo ago`;
  }

  return `${Math.floor(months / 12)}y ago`;
}

function formatCount(value: number): string {
  return value.toLocaleString();
}

function toPrincipalLoadError(error: unknown): PrincipalLoadError {
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

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
