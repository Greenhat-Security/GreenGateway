import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

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

export type PrincipalFilters = {
  issuer?: string;
  authMethod?: string;
  principalType?: PrincipalTypeFilter;
  lastSeenAfter?: string;
  lastSeenBefore?: string;
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
