import { adminFetchJson } from './api';
import { adminApiUrl } from './config';
import type { DiscoverySignal } from './signals';

export type PrincipalTypeFilter = 'human' | 'service';

export type PrincipalRecord = {
  subject: string;
  issuer: string;
  auth_method: string;
  email?: string | null;
  org_id?: string | null;
  first_seen: string;
  last_seen: string;
  request_count: number;
};

export type PrincipalPage = {
  principals: PrincipalRecord[];
  next_cursor: string | null;
  anonymous_request_count: number;
};

export type PrincipalEndpointTouch = {
  method: string;
  path: string;
  request_count: number;
  last_seen: string;
};

export type PrincipalDetailResponse = {
  principal: PrincipalRecord;
  endpoints_touched: PrincipalEndpointTouch[];
  rules_hit: string[];
  anomaly_history: DiscoverySignal[];
  tools_called: unknown[];
};

export type PrincipalFilters = {
  issuer?: string;
  authMethod?: string;
  principalType?: PrincipalTypeFilter;
  lastSeenAfter?: string;
  lastSeenBefore?: string;
};

export type PrincipalDetailRequest = {
  subject: string;
  issuer: string;
  authMethod: string;
};

export function fetchPrincipals(
  filters: PrincipalFilters = {},
  cursor?: string,
  limit?: number,
): Promise<PrincipalPage> {
  const params = new URLSearchParams();

  appendTrimmed(params, 'issuer', filters.issuer);
  appendTrimmed(params, 'auth_method', filters.authMethod);
  appendTrimmed(params, 'principal_type', filters.principalType);
  appendTrimmed(params, 'last_seen_after', filters.lastSeenAfter);
  appendTrimmed(params, 'last_seen_before', filters.lastSeenBefore);
  if (cursor) {
    params.set('cursor', cursor);
  }
  if (typeof limit === 'number') {
    params.set('limit', String(limit));
  }

  const query = params.toString();
  return adminFetchJson<PrincipalPage>(
    `${adminApiUrl('/principals')}${query ? `?${query}` : ''}`,
  );
}

export function buildPrincipalDetailQueryParams(
  request: PrincipalDetailRequest,
): URLSearchParams {
  const params = new URLSearchParams();

  params.set('subject', request.subject.trim());
  params.set('issuer', request.issuer);
  params.set('auth_method', request.authMethod.trim());

  return params;
}

export function fetchPrincipalDetail(
  request: PrincipalDetailRequest,
): Promise<PrincipalDetailResponse> {
  const params = buildPrincipalDetailQueryParams(request);

  return adminFetchJson<PrincipalDetailResponse>(
    adminApiUrl(`/principal?${params.toString()}`),
  );
}

export function principalDetailPath(
  principal: Pick<PrincipalRecord, 'subject' | 'issuer' | 'auth_method'>,
): string {
  const params = new URLSearchParams();
  params.set('subject', principal.subject);
  params.set('issuer', principal.issuer);
  params.set('auth_method', principal.auth_method);

  return `/identities/detail?${params.toString()}`;
}

function appendTrimmed(
  params: URLSearchParams,
  name: string,
  value: string | undefined,
) {
  const trimmed = value?.trim();
  if (trimmed) {
    params.set(name, trimmed);
  }
}
