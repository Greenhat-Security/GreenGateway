import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

export const TRAFFIC_ENDPOINT_PAGE_LIMIT = 50;
export const TRAFFIC_ENDPOINT_PRINCIPAL_PAGE_LIMIT = 50;
export const TRAFFIC_ENDPOINT_RECENT_EVENTS_LIMIT = 20;

export type TrafficEndpointSort = 'last_seen' | 'call_count' | 'first_seen';
export type TrafficEndpointAuditBucket = 'hour' | 'day';

export type TrafficEndpointLatency = {
  count: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
};

export type TrafficEndpointLatencyDetail = TrafficEndpointLatency & {
  sample_count: number;
};

export type TrafficStatusCount = {
  status: number;
  count: number;
};

export type TrafficOpenSignalSummary = {
  count: number;
  signal_types: string[];
};

export type TrafficEndpoint = {
  method: string;
  endpoint_template: string;
  first_seen: string;
  last_seen: string;
  call_count: number;
  distinct_principal_count: number;
  is_new: boolean;
  reviewed: boolean;
  reviewed_at: string | null;
  reviewed_by: string | null;
  covered_by_rule: boolean;
  open_signals?: TrafficOpenSignalSummary;
  latency: TrafficEndpointLatency;
  status_counts: TrafficStatusCount[];
};

export type TrafficEndpointDetail = Omit<TrafficEndpoint, 'latency'> & {
  latency: TrafficEndpointLatencyDetail;
  updated_at: string;
};

export type TrafficEndpointPrincipal = {
  user_id: string;
  first_seen: string;
  last_seen: string;
};

export type TrafficEndpointPrincipalPage = {
  principals: TrafficEndpointPrincipal[];
  next_cursor: string | null;
};

export type TrafficEndpointTimeSeriesPoint = {
  bucket_start: string;
  count: number;
};

export type TrafficEndpointRecentEvent = {
  id: number;
  event_id: string;
  request_id: string;
  timestamp: string;
  method: string;
  path: string;
  status: number | null;
  actor: string | null;
};

export type TrafficEndpointAuditEnrichment = {
  available: boolean;
  match_strategy: string;
  match_limitations: string;
  omitted_reason?: string;
  time_series_truncated?: boolean;
  time_series?: TrafficEndpointTimeSeriesPoint[];
  recent_events?: TrafficEndpointRecentEvent[];
  recent_events_next_cursor?: number | null;
  recent_events_scan_truncated?: boolean;
};

export type TrafficEndpointDetailResponse = {
  endpoint: TrafficEndpointDetail;
  principals: TrafficEndpointPrincipalPage;
  audit: TrafficEndpointAuditEnrichment;
};

export type TrafficEndpointListResponse = {
  endpoints: TrafficEndpoint[];
  next_cursor: string | null;
};

export type TrafficFilters = {
  endpointTemplate: string;
  method: string;
  sort: TrafficEndpointSort;
  isNew: boolean;
  uncovered: boolean;
  reviewed: boolean;
};

export type TrafficEndpointReviewRequest = {
  method: string;
  endpoint_template: string;
  reviewed: boolean;
};

export type TrafficEndpointDetailRequest = {
  method: string;
  endpointTemplate: string;
  principalCursor?: string | null;
  bucket?: TrafficEndpointAuditBucket;
};

export type TrafficEndpointReviewResponse = {
  reviewed: boolean;
  reviewed_at: string | null;
  reviewed_by: string | null;
};

export function emptyTrafficFilters(): TrafficFilters {
  return {
    endpointTemplate: '',
    method: '',
    sort: 'last_seen',
    isNew: false,
    uncovered: false,
    reviewed: false,
  };
}

export function buildTrafficEndpointQueryParams(
  filters: TrafficFilters,
  cursor?: string | null,
): URLSearchParams {
  const params = new URLSearchParams();

  appendTrimmed(params, 'endpoint_template', filters.endpointTemplate);
  appendTrimmed(params, 'method', filters.method);
  params.set('sort', filters.sort);
  params.set('limit', String(TRAFFIC_ENDPOINT_PAGE_LIMIT));

  if (filters.isNew) {
    params.set('is_new', 'true');
  }
  if (filters.uncovered) {
    params.set('covered_by_rule', 'false');
  }
  if (filters.reviewed) {
    params.set('reviewed', 'true');
  }
  if (cursor) {
    params.set('cursor', cursor);
  }

  return params;
}

export function fetchTrafficEndpoints(
  filters: TrafficFilters,
  cursor?: string | null,
): Promise<TrafficEndpointListResponse> {
  const params = buildTrafficEndpointQueryParams(filters, cursor);

  return adminFetchJson<TrafficEndpointListResponse>(
    adminApiUrl(`/traffic/endpoints?${params.toString()}`),
  );
}

export function buildTrafficEndpointDetailQueryParams(
  request: TrafficEndpointDetailRequest,
): URLSearchParams {
  const params = new URLSearchParams();

  appendTrimmed(params, 'method', request.method);
  appendTrimmed(params, 'endpoint_template', request.endpointTemplate);
  params.set(
    'principal_limit',
    String(TRAFFIC_ENDPOINT_PRINCIPAL_PAGE_LIMIT),
  );
  params.set('events_limit', String(TRAFFIC_ENDPOINT_RECENT_EVENTS_LIMIT));
  params.set('bucket', request.bucket ?? 'hour');

  if (request.principalCursor) {
    params.set('principal_cursor', request.principalCursor);
  }

  return params;
}

export function fetchTrafficEndpointDetail(
  request: TrafficEndpointDetailRequest,
): Promise<TrafficEndpointDetailResponse> {
  const params = buildTrafficEndpointDetailQueryParams(request);

  return adminFetchJson<TrafficEndpointDetailResponse>(
    adminApiUrl(`/traffic/endpoint?${params.toString()}`),
  );
}

export function updateTrafficEndpointReview(
  request: TrafficEndpointReviewRequest,
): Promise<TrafficEndpointReviewResponse> {
  return adminFetchJson<TrafficEndpointReviewResponse>(
    adminApiUrl('/traffic/endpoints/review'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
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
