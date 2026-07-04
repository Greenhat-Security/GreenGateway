import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

export const TRAFFIC_ENDPOINT_PAGE_LIMIT = 50;

export type TrafficEndpointSort = 'last_seen' | 'call_count' | 'first_seen';

export type TrafficEndpointLatency = {
  count: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
};

export type TrafficStatusCount = {
  status: number;
  count: number;
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
  latency: TrafficEndpointLatency;
  status_counts: TrafficStatusCount[];
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
