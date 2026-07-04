import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { AuditEvent, JsonObject } from '../lib/audit';
import {
  buildAuditEventStreamUrl,
  subscribeToAuditEvents,
} from '../lib/eventStream';
import {
  DiscoverySignal,
  SignalFilters,
  SignalState,
  acknowledgeSignal,
  dismissSignal,
  displaySignalTarget,
  emptySignalFilters,
  fetchSignals,
  signalMatchesFilters,
} from '../lib/signals';

type SignalsLoadError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'unavailable'
    | 'bad-request'
    | 'network'
    | 'generic';
  message: string;
};

type SignalToast = {
  id: string;
  message: string;
};

type SignalLifecyclePayload = {
  id: string;
  signal_type?: string;
  target?: unknown;
  state?: SignalState;
  transitioned_at?: string | null;
  transitioned_by?: string | null;
};

const SIGNAL_RECONNECT_DELAY_MS = 750;

export function SignalsView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialFilters = useMemo(
    () => signalFiltersFromSearchParams(searchParams),
    [searchParams],
  );
  const [filters, setFilters] = useState<SignalFilters>(initialFilters);
  const [appliedFilters, setAppliedFilters] =
    useState<SignalFilters>(initialFilters);
  const [signals, setSignals] = useState<DiscoverySignal[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [transitioningId, setTransitioningId] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<SignalsLoadError | null>(null);
  const [transitionError, setTransitionError] =
    useState<SignalsLoadError | null>(null);
  const [toasts, setToasts] = useState<SignalToast[]>([]);

  useEffect(() => {
    setFilters(initialFilters);
    setAppliedFilters(initialFilters);
  }, [initialFilters]);

  useEffect(() => {
    let isCurrent = true;

    async function loadFirstPage() {
      setIsLoading(true);
      setLoadError(null);
      setTransitionError(null);

      try {
        const response = await fetchSignals(appliedFilters);
        if (!isCurrent) {
          return;
        }

        setSignals(response.signals);
        setNextCursor(response.next_cursor);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setSignals([]);
        setNextCursor(null);
        setLoadError(toSignalsLoadError(error));
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
    const controller = new AbortController();
    let isCurrent = true;
    let reconnectTimer: number | undefined;

    function scheduleReconnect() {
      if (!isCurrent || controller.signal.aborted) {
        return;
      }
      reconnectTimer = window.setTimeout(() => {
        void connect();
      }, SIGNAL_RECONNECT_DELAY_MS);
    }

    async function connect() {
      try {
        await subscribeToAuditEvents(
          buildAuditEventStreamUrl({ eventType: '', path: '' }),
          {
            signal: controller.signal,
            onEvent: (event) => {
              if (!isCurrent) {
                return;
              }
              handleSignalStreamEvent(event, appliedFilters);
            },
          },
        );
        scheduleReconnect();
      } catch (error) {
        if (!isCurrent || controller.signal.aborted) {
          return;
        }
        const streamError = toSignalsLoadError(error);
        if (
          streamError.kind !== 'unauthorized' &&
          streamError.kind !== 'forbidden'
        ) {
          scheduleReconnect();
        }
      }
    }

    void connect();

    return () => {
      isCurrent = false;
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
      }
      controller.abort();
    };
  }, [appliedFilters]);

  function updateFilter(name: keyof SignalFilters, value: string) {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next = normalizeSignalFilters(filters);
    setSearchParams(signalFiltersToSearchParams(next));
  }

  function clearFilters() {
    const empty = emptySignalFilters();
    setSearchParams(signalFiltersToSearchParams(empty));
  }

  async function loadMore() {
    if (nextCursor === null || isLoadingMore) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);

    try {
      const response = await fetchSignals(appliedFilters, nextCursor);
      setSignals((current) => [...current, ...response.signals]);
      setNextCursor(response.next_cursor);
    } catch (error) {
      setLoadError(toSignalsLoadError(error));
    } finally {
      setIsLoadingMore(false);
    }
  }

  async function transitionSignal(
    signal: DiscoverySignal,
    transition: 'acknowledge' | 'dismiss',
  ) {
    setTransitioningId(signal.id);
    setTransitionError(null);

    try {
      const updated =
        transition === 'acknowledge'
          ? await acknowledgeSignal(signal.id)
          : await dismissSignal(signal.id);
      upsertSignal(updated, true);
      addToast(
        `Signal ${transition === 'acknowledge' ? 'acknowledged' : 'dismissed'}: ${updated.signal_type}`,
      );
    } catch (error) {
      setTransitionError(toSignalsLoadError(error));
    } finally {
      setTransitioningId(null);
    }
  }

  function handleSignalStreamEvent(
    event: AuditEvent,
    currentFilters: SignalFilters,
  ) {
    if (event.event_type === 'signal.opened') {
      const signal = signalFromOpenedEvent(event.payload);
      if (!signal || !signalMatchesFilters(signal, currentFilters)) {
        return;
      }

      upsertSignal(signal, false);
      addToast(`New signal opened: ${signal.signal_type}`);
      return;
    }

    if (event.event_type === 'signal.lifecycle_changed') {
      const payload = lifecyclePayload(event.payload);
      if (!payload) {
        return;
      }

      setSignals((current) =>
        current.map((signal) =>
          signal.id === payload.id
            ? {
                ...signal,
                state: payload.state ?? signal.state,
                transitioned_at:
                  payload.transitioned_at ?? signal.transitioned_at,
                transitioned_by:
                  payload.transitioned_by ?? signal.transitioned_by,
                updated_at: event.timestamp,
              }
            : signal,
        ),
      );
      addToast(
        `Signal ${payload.state ?? 'transitioned'}: ${
          payload.signal_type ?? payload.id
        }`,
      );
    }
  }

  function upsertSignal(signal: DiscoverySignal, replaceOnly: boolean) {
    setSignals((current) => {
      const existingIndex = current.findIndex((item) => item.id === signal.id);
      if (existingIndex !== -1) {
        const next = [...current];
        next[existingIndex] = signal;
        return next;
      }
      if (replaceOnly) {
        return current;
      }
      return [signal, ...current];
    });
  }

  function addToast(message: string) {
    const id =
      typeof crypto !== 'undefined' && 'randomUUID' in crypto
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random()}`;
    setToasts((current) => [{ id, message }, ...current].slice(0, 3));
  }

  const hasTargetFilter =
    appliedFilters.targetKind.trim().length > 0 ||
    appliedFilters.targetKey.trim().length > 0;

  return (
    <main className="logs-page signals-page">
      <section className="panel logs-panel signals-panel" aria-labelledby="signals-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Discovery</p>
            <h2 id="signals-heading">Signals</h2>
          </div>
          <span className="result-count">{signals.length} signals</span>
        </div>

        <form className="filter-form signal-filter-form" onSubmit={applyFilters}>
          <div className="filter-grid signal-filter-grid">
            <label>
              State
              <select
                value={filters.state}
                onChange={(event) => updateFilter('state', event.target.value)}
              >
                <option value="">All states</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="dismissed">Dismissed</option>
              </select>
            </label>
            <label>
              Signal type
              <input
                type="text"
                value={filters.signalType}
                placeholder="schema_mismatch"
                onChange={(event) =>
                  updateFilter('signalType', event.target.value)
                }
              />
            </label>
          </div>

          {hasTargetFilter ? (
            <div className="signal-target-filter" role="status">
              Target filter:{' '}
              <code>
                {appliedFilters.targetKind || 'any'}{' '}
                {appliedFilters.targetKey || 'any'}
              </code>
            </div>
          ) : null}

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

        <SignalToastRegion toasts={toasts} />
        {loadError ? <SignalsErrorMessage error={loadError} /> : null}
        {transitionError ? (
          <SignalsTransitionErrorMessage error={transitionError} />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading signals
          </div>
        ) : null}

        {!isLoading && signals.length === 0 && !loadError ? (
          <div className="empty-state">No signals matched these filters.</div>
        ) : null}

        {signals.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table signals-table">
                <thead>
                  <tr>
                    <th>Signal</th>
                    <th>Target</th>
                    <th>State</th>
                    <th>Evidence</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {signals.map((signal, index) => (
                    <tr
                      className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      key={signal.id}
                    >
                      <td>
                        <div className="signal-primary-cell">
                          <span className="badge neutral">{signal.signal_type}</span>
                          <span>{signal.explanation}</span>
                        </div>
                      </td>
                      <td className="endpoint-template">
                        {displaySignalTarget(signal)}
                      </td>
                      <td>
                        <span className={`badge ${signalStateBadgeClass(signal.state)}`}>
                          {signal.state}
                        </span>
                      </td>
                      <td>
                        <pre
                          className="signal-evidence"
                          data-testid={`signal-evidence-${signal.id}`}
                        >
                          {JSON.stringify(signal.evidence, null, 2)}
                        </pre>
                      </td>
                      <td>
                        <time
                          className="timestamp-cell"
                          dateTime={signal.updated_at}
                          title={signal.updated_at}
                        >
                          {signal.updated_at}
                        </time>
                      </td>
                      <td>
                        <div className="signal-actions">
                          <button
                            type="button"
                            className="secondary-button row-action-button"
                            aria-label={`Acknowledge signal ${signal.id}`}
                            disabled={transitioningId === signal.id}
                            onClick={() => {
                              void transitionSignal(signal, 'acknowledge');
                            }}
                          >
                            Acknowledge
                          </button>
                          <button
                            type="button"
                            className="secondary-button row-action-button"
                            aria-label={`Dismiss signal ${signal.id}`}
                            disabled={transitioningId === signal.id}
                            onClick={() => {
                              void transitionSignal(signal, 'dismiss');
                            }}
                          >
                            Dismiss
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination-row">
              {nextCursor !== null ? (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={loadMore}
                  disabled={isLoadingMore}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more signals</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function SignalToastRegion({ toasts }: { toasts: SignalToast[] }) {
  if (toasts.length === 0) {
    return null;
  }

  return (
    <div className="signal-toast-region" role="status" aria-live="polite">
      {toasts.map((toast) => (
        <div className="signal-toast alert info" key={toast.id}>
          {toast.message}
        </div>
      ))}
    </div>
  );
}

function SignalsErrorMessage({ error }: { error: SignalsLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing signals. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Signals permission required</h3>
        <p>This token is valid but does not include admin:signals:read.</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Signals unavailable</h3>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      className={`error-panel alert ${error.kind === 'bad-request' ? 'warning' : 'error'}`}
      role="alert"
    >
      <h3>{error.kind === 'bad-request' ? 'Invalid query' : 'Request failed'}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function SignalsTransitionErrorMessage({
  error,
}: {
  error: SignalsLoadError;
}) {
  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Signal write permission required</h3>
        <p>This token can read signals but does not include admin:signals:write.</p>
      </div>
    );
  }

  return (
    <div className="error-panel alert error" role="alert">
      <h3>Signal update failed</h3>
      <p>{error.message}</p>
    </div>
  );
}

function signalFiltersFromSearchParams(params: URLSearchParams): SignalFilters {
  return normalizeSignalFilters({
    state: signalStateOrDefault(params.get('state')),
    signalType: params.get('signal_type') ?? '',
    targetKind: params.get('target_kind') ?? '',
    targetKey: params.get('target_key') ?? '',
  });
}

function signalFiltersToSearchParams(filters: SignalFilters): URLSearchParams {
  const params = new URLSearchParams();
  params.set('state', filters.state);
  appendTrimmed(params, 'signal_type', filters.signalType);
  appendTrimmed(params, 'target_kind', filters.targetKind);
  appendTrimmed(params, 'target_key', filters.targetKey);
  return params;
}

function normalizeSignalFilters(filters: SignalFilters): SignalFilters {
  return {
    state: filters.state,
    signalType: filters.signalType.trim(),
    targetKind: filters.targetKind.trim(),
    targetKey: filters.targetKey.trim(),
  };
}

function signalStateOrDefault(value: string | null): SignalState | '' {
  if (value === 'acknowledged' || value === 'dismissed' || value === 'open') {
    return value;
  }
  if (value === '') {
    return '';
  }

  return 'open';
}

function appendTrimmed(
  params: URLSearchParams,
  name: string,
  value: string,
) {
  const trimmed = value.trim();
  if (trimmed.length > 0) {
    params.set(name, trimmed);
  }
}

function signalStateBadgeClass(state: SignalState): string {
  switch (state) {
    case 'open':
      return 'warning';
    case 'acknowledged':
      return 'success';
    case 'dismissed':
      return 'neutral';
  }
}

function signalFromOpenedEvent(payload: JsonObject): DiscoverySignal | null {
  if (
    typeof payload.id !== 'string' ||
    typeof payload.signal_type !== 'string' ||
    typeof payload.explanation !== 'string' ||
    !isSignalState(payload.state) ||
    typeof payload.created_at !== 'string' ||
    typeof payload.updated_at !== 'string' ||
    !isJsonObject(payload.target) ||
    !isJsonObject(payload.evidence)
  ) {
    return null;
  }

  const target = payload.target;
  if (typeof target.kind !== 'string' || !isJsonObject(target.identity)) {
    return null;
  }

  return {
    id: payload.id,
    signal_type: payload.signal_type,
    target: {
      kind: target.kind,
      identity: target.identity,
    },
    explanation: payload.explanation,
    evidence: payload.evidence,
    state: payload.state,
    created_at: payload.created_at,
    updated_at: payload.updated_at,
    transitioned_at:
      typeof payload.transitioned_at === 'string'
        ? payload.transitioned_at
        : null,
    transitioned_by:
      typeof payload.transitioned_by === 'string'
        ? payload.transitioned_by
        : null,
  };
}

function lifecyclePayload(payload: JsonObject): SignalLifecyclePayload | null {
  if (typeof payload.id !== 'string') {
    return null;
  }

  return {
    id: payload.id,
    signal_type:
      typeof payload.signal_type === 'string' ? payload.signal_type : undefined,
    target: payload.target,
    state: isSignalState(payload.state) ? payload.state : undefined,
    transitioned_at:
      typeof payload.transitioned_at === 'string'
        ? payload.transitioned_at
        : null,
    transitioned_by:
      typeof payload.transitioned_by === 'string'
        ? payload.transitioned_by
        : null,
  };
}

function isSignalState(value: unknown): value is SignalState {
  return (
    value === 'open' || value === 'acknowledged' || value === 'dismissed'
  );
}

function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function toSignalsLoadError(error: unknown): SignalsLoadError {
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
