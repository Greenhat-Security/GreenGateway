import { adminFetchJson } from './api';
import { JsonObject } from './audit';
import { adminApiUrl } from './config';

export const SIGNAL_PAGE_LIMIT = 50;

export type SignalState = 'open' | 'acknowledged' | 'dismissed';

export type SignalTarget = {
  kind: string;
  identity: JsonObject;
};

export type DiscoverySignal = {
  id: string;
  signal_type: string;
  target: SignalTarget;
  explanation: string;
  evidence: JsonObject;
  state: SignalState;
  created_at: string;
  updated_at: string;
  transitioned_at: string | null;
  transitioned_by: string | null;
};

export type SignalListResponse = {
  signals: DiscoverySignal[];
  next_cursor: string | null;
};

export type SignalFilters = {
  state: SignalState | '';
  signalType: string;
  targetKind: string;
  targetKey: string;
};

export function emptySignalFilters(): SignalFilters {
  return {
    state: 'open',
    signalType: '',
    targetKind: '',
    targetKey: '',
  };
}

export function endpointSignalTargetKey(
  method: string,
  endpointTemplate: string,
): string {
  return `${method} ${endpointTemplate}`;
}

export function signalsPathForEndpoint(
  method: string,
  endpointTemplate: string,
): string {
  const params = new URLSearchParams();
  params.set('state', 'open');
  params.set('target_kind', 'endpoint');
  params.set('target_key', endpointSignalTargetKey(method, endpointTemplate));

  return `/signals?${params.toString()}`;
}

export function buildSignalQueryParams(
  filters: SignalFilters,
  cursor?: string | null,
): URLSearchParams {
  const params = new URLSearchParams();

  if (filters.state) {
    params.set('state', filters.state);
  }
  appendTrimmed(params, 'signal_type', filters.signalType);
  appendTrimmed(params, 'target_kind', filters.targetKind);
  appendTrimmed(params, 'target_key', filters.targetKey);
  params.set('limit', String(SIGNAL_PAGE_LIMIT));

  if (cursor) {
    params.set('cursor', cursor);
  }

  return params;
}

export function fetchSignals(
  filters: SignalFilters,
  cursor?: string | null,
): Promise<SignalListResponse> {
  const params = buildSignalQueryParams(filters, cursor);

  return adminFetchJson<SignalListResponse>(
    adminApiUrl(`/signals?${params.toString()}`),
  );
}

export function acknowledgeSignal(id: string): Promise<DiscoverySignal> {
  return transitionSignal(id, 'acknowledge');
}

export function dismissSignal(id: string): Promise<DiscoverySignal> {
  return transitionSignal(id, 'dismiss');
}

export function signalMatchesFilters(
  signal: DiscoverySignal,
  filters: SignalFilters,
): boolean {
  if (filters.state && signal.state !== filters.state) {
    return false;
  }
  if (
    filters.signalType.trim().length > 0 &&
    signal.signal_type !== filters.signalType.trim()
  ) {
    return false;
  }
  if (filters.targetKind.trim().length > 0) {
    if (signal.target.kind !== filters.targetKind.trim()) {
      return false;
    }
  }
  if (filters.targetKey.trim().length > 0) {
    if (targetKeyForSignal(signal) !== filters.targetKey.trim()) {
      return false;
    }
  }

  return true;
}

export function targetKeyForSignal(signal: DiscoverySignal): string | null {
  if (signal.target.kind === 'endpoint') {
    const method = signal.target.identity.method;
    const endpointTemplate = signal.target.identity.endpoint_template;
    if (typeof method === 'string' && typeof endpointTemplate === 'string') {
      return endpointSignalTargetKey(method, endpointTemplate);
    }
  }

  return null;
}

export function displaySignalTarget(signal: DiscoverySignal): string {
  if (signal.target.kind === 'endpoint') {
    const method = signal.target.identity.method;
    const endpointTemplate = signal.target.identity.endpoint_template;
    if (typeof method === 'string' && typeof endpointTemplate === 'string') {
      return `${method} ${endpointTemplate}`;
    }
  }

  return `${signal.target.kind} ${JSON.stringify(signal.target.identity)}`;
}

function transitionSignal(
  id: string,
  transition: 'acknowledge' | 'dismiss',
): Promise<DiscoverySignal> {
  return adminFetchJson<DiscoverySignal>(
    adminApiUrl(`/signals/${encodeURIComponent(id)}/${transition}`),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    },
  );
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
