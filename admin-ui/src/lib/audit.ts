import { adminFetchJson } from './api';

export type JsonObject = Record<string, unknown>;

export type AuditActor = {
  user_id: string;
  roles: string[] | null;
  auth_mode: string;
};

export type AuditEvent = {
  event_id: string;
  event_type: string;
  timestamp: string;
  schema_version: number;
  request_id: string;
  source_ip: string;
  user_agent?: string | null;
  actor?: AuditActor | null;
  payload: JsonObject;
};

export type AuditQueryResponse = {
  events: AuditEvent[];
  next_cursor: number | null;
};

export type AuditFilters = {
  from: string;
  to: string;
  eventType: string;
  actor: string;
  path: string;
  status: string;
};

export function emptyAuditFilters(): AuditFilters {
  return {
    from: '',
    to: '',
    eventType: '',
    actor: '',
    path: '',
    status: '',
  };
}

export function buildAuditQueryParams(
  filters: AuditFilters,
  beforeId?: number | null,
): URLSearchParams {
  const params = new URLSearchParams();

  appendDatetimeLocal(params, 'from', filters.from);
  appendDatetimeLocal(params, 'to', filters.to);
  appendTrimmed(params, 'event_type', filters.eventType);
  appendTrimmed(params, 'actor', filters.actor);
  appendTrimmed(params, 'path', filters.path);
  appendTrimmed(params, 'status', filters.status);

  if (beforeId !== undefined && beforeId !== null) {
    params.set('before_id', String(beforeId));
  }

  return params;
}

export function datetimeLocalToRfc3339(value: string): string {
  const trimmed = value.trim();
  const date = new Date(trimmed);
  return Number.isNaN(date.valueOf()) ? trimmed : date.toISOString();
}

export function fetchAuditEvents(
  filters: AuditFilters,
  beforeId?: number | null,
): Promise<AuditQueryResponse> {
  const params = buildAuditQueryParams(filters, beforeId);
  const query = params.toString();
  const path = query.length > 0 ? `/v1/admin/audit?${query}` : '/v1/admin/audit';

  return adminFetchJson<AuditQueryResponse>(path);
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

function appendDatetimeLocal(
  params: URLSearchParams,
  name: string,
  value: string,
) {
  const trimmed = value.trim();
  if (trimmed.length > 0) {
    params.set(name, datetimeLocalToRfc3339(trimmed));
  }
}
