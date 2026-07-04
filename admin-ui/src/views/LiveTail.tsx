import { Fragment, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { AuditEvent } from '../lib/audit';
import {
  AuditEventStreamFilters,
  buildAuditEventStreamUrl,
  subscribeToAuditEvents,
} from '../lib/eventStream';
import {
  currentTokenCanWritePolicy,
  fetchPolicy,
  isAuthMethodName,
} from '../lib/policy';

export const LIVE_TAIL_EVENT_LIMIT = 500;
export const LIVE_TAIL_RECONNECT_DELAY_MS = 500;

type ConnectionState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'error';

type LiveTailError = {
  kind: 'unauthorized' | 'forbidden' | 'network' | 'generic';
  message: string;
};

const emptyFilters: AuditEventStreamFilters = {
  eventType: '',
  path: '',
};

export function LiveTail() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<AuditEventStreamFilters>(emptyFilters);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [expandedEventIds, setExpandedEventIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [connectionState, setConnectionState] =
    useState<ConnectionState>('connecting');
  const [error, setError] = useState<LiveTailError | null>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [canCreateRules, setCanCreateRules] = useState(false);
  const isPausedRef = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    let isCurrent = true;
    let reconnectTimer: number | undefined;
    let reconnectAttempt = 0;

    function scheduleReconnect() {
      if (!isCurrent || controller.signal.aborted) {
        return;
      }

      reconnectAttempt += 1;
      const delay = Math.min(
        LIVE_TAIL_RECONNECT_DELAY_MS * reconnectAttempt,
        3000,
      );
      setConnectionState('reconnecting');
      reconnectTimer = window.setTimeout(() => {
        void connect();
      }, delay);
    }

    async function connect() {
      if (!isCurrent || controller.signal.aborted) {
        return;
      }

      let opened = false;
      setConnectionState(reconnectAttempt > 0 ? 'reconnecting' : 'connecting');

      try {
        await subscribeToAuditEvents(buildAuditEventStreamUrl(filters), {
          signal: controller.signal,
          onOpen: () => {
            opened = true;
            reconnectAttempt = 0;
            if (isCurrent) {
              setConnectionState('connected');
              setError(null);
            }
          },
          onEvent: (event) => {
            // Keep the stream open while paused and drop incoming frames.
            // This avoids reconnect churn while guaranteeing the visible list
            // does not grow during pause.
            if (!isCurrent || isPausedRef.current) {
              return;
            }

            setEvents((current) =>
              [event, ...current].slice(0, LIVE_TAIL_EVENT_LIMIT),
            );
          },
        });

        if (opened) {
          scheduleReconnect();
        }
      } catch (streamError) {
        if (!isCurrent || controller.signal.aborted) {
          return;
        }

        const liveTailError = toLiveTailError(streamError);
        setError(liveTailError);

        if (
          liveTailError.kind === 'unauthorized' ||
          liveTailError.kind === 'forbidden'
        ) {
          setConnectionState('error');
          return;
        }

        scheduleReconnect();
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
  }, [filters]);

  useEffect(() => {
    let isCurrent = true;

    async function loadPolicyWritePermission() {
      try {
        const response = await fetchPolicy();
        if (isCurrent) {
          setCanCreateRules(currentTokenCanWritePolicy(response.policy));
        }
      } catch {
        if (isCurrent) {
          setCanCreateRules(false);
        }
      }
    }

    void loadPolicyWritePermission();

    return () => {
      isCurrent = false;
    };
  }, []);

  function updateFilter(name: keyof AuditEventStreamFilters, value: string) {
    setFilters((current) => ({ ...current, [name]: value }));
    setEvents([]);
    setExpandedEventIds(new Set());
    setError(null);
  }

  function clearFilters() {
    setFilters(emptyFilters);
    setEvents([]);
    setExpandedEventIds(new Set());
    setError(null);
  }

  function togglePaused() {
    setIsPaused((current) => {
      const next = !current;
      isPausedRef.current = next;
      return next;
    });
  }

  function toggleExpanded(eventId: string) {
    setExpandedEventIds((current) => {
      const next = new Set(current);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  }

  function createRuleFromEvent(event: AuditEvent) {
    if (!canCreateRules) {
      return;
    }

    navigate(ruleEditorPathForAuditEvent(event));
  }

  const visibleConnectionState = isPaused ? 'paused' : connectionState;

  return (
    <main className="logs-page">
      <section className="panel logs-panel" aria-labelledby="live-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Audit</p>
            <h2 id="live-heading">Live tail</h2>
          </div>
          <div className="live-summary">
            <span
              className={`stream-state badge ${connectionBadgeClass(visibleConnectionState)} ${visibleConnectionState}`}
            >
              {connectionLabel(visibleConnectionState)}
            </span>
            <span className="result-count">{events.length} events</span>
          </div>
        </div>

        <div className="filter-form live-filter-form">
          <div className="filter-grid live-filter-grid">
            <label>
              Event type
              <input
                type="text"
                value={filters.eventType}
                placeholder="http.request_observed"
                onChange={(event) =>
                  updateFilter('eventType', event.target.value)
                }
              />
            </label>
            <label>
              Path
              <input
                type="text"
                value={filters.path}
                placeholder="/admin"
                onChange={(event) => updateFilter('path', event.target.value)}
              />
            </label>
          </div>
          <div className="form-actions">
            <button
              type="button"
              className="primary-button"
              onClick={togglePaused}
            >
              {isPaused ? 'Resume' : 'Pause'}
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={clearFilters}
              disabled={
                filters.eventType.trim().length === 0 &&
                filters.path.trim().length === 0
              }
            >
              Clear filters
            </button>
          </div>
        </div>

        {error ? <LiveTailErrorMessage error={error} /> : null}

        {events.length === 0 && !error ? (
          <div className="empty-state">Waiting for audit events.</div>
        ) : null}

        {events.length > 0 ? (
          <div className="table-scroll">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>
                    <span className="sr-only">Expand</span>
                  </th>
                  <th>Timestamp</th>
                  <th>Event type</th>
                  <th>Principal</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>Request ID</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, index) => {
                  const isExpanded = expandedEventIds.has(event.event_id);
                  return (
                    <Fragment key={event.event_id}>
                      <tr
                        className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                      >
                        <td>
                          <button
                            type="button"
                            className="expand-button"
                            aria-expanded={isExpanded}
                            aria-label={`${isExpanded ? 'Collapse' : 'Expand'} event ${event.event_id}`}
                            onClick={() => toggleExpanded(event.event_id)}
                          >
                            {isExpanded ? '-' : '+'}
                          </button>
                        </td>
                        <td>{event.timestamp}</td>
                        <td>{event.event_type}</td>
                        <td>{event.actor?.user_id ?? '-'}</td>
                        <td>{displayPayloadField(event, 'path')}</td>
                        <td>{displayPayloadField(event, 'status')}</td>
                        <td>{event.request_id}</td>
                        <td>
                          <div className="signal-actions">
                            <button
                              type="button"
                              className="secondary-button row-action-button"
                              aria-label={createRuleEventLabel(event)}
                              title={
                                canCreateRules
                                  ? undefined
                                  : 'Requires admin:policy:write'
                              }
                              disabled={!canCreateRules}
                              onClick={() => createRuleFromEvent(event)}
                            >
                              Create rule
                            </button>
                          </div>
                        </td>
                      </tr>
                      {isExpanded ? (
                        <tr className="event-json-row">
                          <td colSpan={8}>
                            <pre data-testid={`event-json-${event.event_id}`}>
                              {JSON.stringify(event, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </main>
  );
}

function LiveTailErrorMessage({ error }: { error: LiveTailError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before opening the live tail. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Admin role required</h3>
        <p>This token is valid but does not include the admin role.</p>
      </div>
    );
  }

  return (
    <div className="error-panel alert error" role="alert">
      <h3>Stream disconnected</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toLiveTailError(error: unknown): LiveTailError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: `Network stream failed: ${error.message}`,
    };
  }

  return { kind: 'network', message: 'Network stream failed.' };
}

function connectionLabel(state: ConnectionState | 'paused'): string {
  switch (state) {
    case 'connecting':
      return 'Connecting';
    case 'connected':
      return 'Connected';
    case 'paused':
      return 'Paused';
    case 'reconnecting':
      return 'Reconnecting';
    case 'error':
      return 'Disconnected';
  }
}

function connectionBadgeClass(state: ConnectionState | 'paused'): string {
  switch (state) {
    case 'connected':
      return 'success';
    case 'reconnecting':
    case 'connecting':
      return 'warning';
    case 'paused':
      return 'neutral';
    case 'error':
      return 'danger';
  }
}

function displayPayloadField(event: AuditEvent, field: string): string {
  const value = event.payload[field];
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value);
  }

  return '-';
}

function createRuleEventLabel(event: AuditEvent): string {
  const method = payloadStringField(event, 'method');
  const path = payloadStringField(event, 'path');
  if (method && path) {
    return `Create rule from ${method} ${path}`;
  }

  return `Create rule from event ${event.event_id}`;
}

function ruleEditorPathForAuditEvent(event: AuditEvent): string {
  const params = new URLSearchParams();
  appendTrimmed(params, 'prefill_method', payloadStringField(event, 'method'));
  appendTrimmed(params, 'prefill_path', payloadStringField(event, 'path'));

  const actor = event.actor;
  if (actor) {
    const role = actor.roles?.find((value) => value.trim().length > 0) ?? null;
    appendTrimmed(params, 'prefill_role', role);
    if (isAuthMethodName(actor.auth_mode)) {
      params.set('prefill_auth_method', actor.auth_mode);
    }
    appendTrimmed(params, 'prefill_principal_id', actor.user_id);
  }

  const query = params.toString();
  return query.length > 0
    ? `/policy/rules/editor?${query}`
    : '/policy/rules/editor';
}

function payloadStringField(event: AuditEvent, field: string): string | null {
  const value = event.payload[field];
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

function appendTrimmed(
  params: URLSearchParams,
  name: string,
  value: string | null,
) {
  const trimmed = value?.trim();
  if (trimmed && trimmed.length > 0) {
    params.set(name, trimmed);
  }
}
