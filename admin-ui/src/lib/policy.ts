import { AdminApiError, adminFetchJson } from './api';
import { authHeaders, decodeJwtRolesClaim, getStoredToken } from './auth';
import { adminApiUrl } from './config';

export type PolicyDefaultAction = 'allow' | 'deny';
export type PolicyRuleAction = 'allow' | 'deny' | 'shadow';
export type AuthMethodName =
  | 'bearer_token'
  | 'session_cookie'
  | 'service_token';

export type PrincipalMatcher = {
  roles?: string[];
  issuers?: string[];
  auth_methods?: string[];
  principal_ids?: string[];
};

export type PolicyRule = {
  id?: string | null;
  enabled?: boolean;
  methods?: string[];
  path?: string;
  tool_name?: string;
  principal?: PrincipalMatcher;
  action: PolicyRuleAction;
};

export type PolicyDocument = {
  schema_version: string;
  id?: string | null;
  default_action: PolicyDefaultAction;
  enforcement_mode?: 'enforce' | 'shadow';
  roles?: Record<string, unknown>;
  routes?: unknown[];
  rules: PolicyRule[];
  [key: string]: unknown;
};

export type PolicyReadResult = {
  policy: PolicyDocument;
  etag: string | null;
};

export type PolicyMutationResult<T> = {
  value: T;
  etag: string | null;
};

export type PolicyRulePatch = {
  enabled?: boolean;
  methods?: string[];
  path?: string | null;
  tool_name?: string | null;
  principal?: PrincipalMatcher;
  action?: PolicyRuleAction;
};

export type PolicyRulePreviewSample = {
  event_id: string;
  timestamp: string;
  request_id: string;
  source_ip: string;
  user_agent?: string;
  method: string;
  path: string;
  actor: {
    user_id?: string;
    auth_mode?: string;
    roles?: string[];
  } | null;
  status: number | null;
  policy_decision?: string;
  matched_rule_id?: string;
};

export type PolicyRulePreviewRequest = {
  rule: PolicyRule;
  from?: string;
  to?: string;
  sample_limit?: number;
};

export type PolicyRulePreviewResponse = {
  match_count: number;
  scanned_event_count: number;
  sample_strategy: string;
  samples: PolicyRulePreviewSample[];
};

export type PolicyRuleShadowReviewPrincipal = {
  user_id: string;
  roles: string[];
};

export type PolicyRuleShadowReviewSample = {
  event_id: string;
  timestamp: string;
  method: string;
  path: string;
  actor: {
    user_id: string;
    auth_mode: string;
    roles?: string[];
  } | null;
};

export type PolicyRuleShadowReviewSummary = {
  rule_id: string;
  rule: PolicyRule;
  would_deny_count: number;
  affected_principals: PolicyRuleShadowReviewPrincipal[];
  samples: PolicyRuleShadowReviewSample[];
};

export type PolicyRuleShadowReviewResponse = {
  scanned_event_count: number;
  scan_truncated: boolean;
  rules: PolicyRuleShadowReviewSummary[];
};

type PolicyRuleHitsResponse =
  | {
      rules: Array<{
        rule_id: string;
        hits: number;
      }>;
    }
  | Record<string, number>;

type AdminFetchWithMetaOptions = Omit<RequestInit, 'headers'> & {
  headers?: Record<string, string>;
};

export async function fetchPolicy(): Promise<PolicyReadResult> {
  const response = await adminFetchJsonWithEtag<PolicyDocument>(
    adminApiUrl('/policy'),
  );

  return {
    policy: normalizePolicy(response.value),
    etag: response.etag,
  };
}

export async function previewPolicyRule(
  request: PolicyRulePreviewRequest,
  signal?: AbortSignal,
): Promise<PolicyRulePreviewResponse> {
  return adminFetchJson<PolicyRulePreviewResponse>(
    adminApiUrl('/policy/rules/preview'),
    {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    },
  );
}

export async function createPolicyRule(
  rule: PolicyRule,
  etag: string,
): Promise<PolicyMutationResult<PolicyRule>> {
  return adminFetchJsonWithEtag<PolicyRule>(adminApiUrl('/policy/rules'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'If-Match': etag,
    },
    body: JSON.stringify(rule),
  });
}

export async function patchPolicyRule(
  ruleId: string,
  etag: string,
  patch: PolicyRulePatch,
): Promise<PolicyMutationResult<PolicyRule>> {
  return adminFetchJsonWithEtag<PolicyRule>(
    adminApiUrl(`/policy/rules/${encodeURIComponent(ruleId)}`),
    {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify(patch),
    },
  );
}

export async function deletePolicyRule(
  ruleId: string,
  etag: string,
): Promise<PolicyMutationResult<{ deleted_rule_id: string }>> {
  return adminFetchJsonWithEtag<{ deleted_rule_id: string }>(
    adminApiUrl(`/policy/rules/${encodeURIComponent(ruleId)}`),
    {
      method: 'DELETE',
      headers: {
        'If-Match': etag,
      },
    },
  );
}

export async function reorderPolicyRules(
  order: string[],
  etag: string,
): Promise<PolicyMutationResult<{ order: string[] }>> {
  return adminFetchJsonWithEtag<{ order: string[] }>(
    adminApiUrl('/policy/rules/order'),
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify(order),
    },
  );
}

export async function fetchPolicyRuleHits(): Promise<Record<string, number>> {
  const response = await adminFetchJson<PolicyRuleHitsResponse>(
    adminApiUrl('/policy/rules/hits'),
  );

  if (isPolicyRuleHitsListResponse(response)) {
    return Object.fromEntries(
      response.rules.map((rule) => [rule.rule_id, rule.hits]),
    );
  }

  return response;
}

export async function fetchPolicyRuleShadowReview(): Promise<PolicyRuleShadowReviewResponse> {
  return adminFetchJson<PolicyRuleShadowReviewResponse>(
    adminApiUrl('/policy/rules/shadow-review'),
  );
}

export function policyRuleId(rule: PolicyRule, index: number): string {
  return rule.id ?? String(index);
}

export function isPolicyRuleEnabled(rule: PolicyRule): boolean {
  return rule.enabled !== false;
}

export function currentTokenCanWritePolicy(policy: PolicyDocument): boolean {
  const token = getStoredToken();
  if (!token) {
    return false;
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return false;
  }

  return roles.some((roleName) =>
    roleGrantsPolicyWrite(policy.roles?.[roleName]),
  );
}

export function isAuthMethodName(value: string): value is AuthMethodName {
  return (
    value === 'bearer_token' ||
    value === 'session_cookie' ||
    value === 'service_token'
  );
}

export function isPolicyRuleAction(value: string): value is PolicyRuleAction {
  return value === 'allow' || value === 'deny' || value === 'shadow';
}

function normalizePolicy(policy: PolicyDocument): PolicyDocument {
  return {
    ...policy,
    rules: policy.rules ?? [],
  };
}

function roleGrantsPolicyWrite(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) => permission === 'admin:policy:write' || permission === '*',
  );
}

function isPolicyRuleHitsListResponse(
  response: PolicyRuleHitsResponse,
): response is {
  rules: Array<{
    rule_id: string;
    hits: number;
  }>;
} {
  return Array.isArray((response as { rules?: unknown }).rules);
}

async function adminFetchJsonWithEtag<T>(
  input: string,
  options: AdminFetchWithMetaOptions = {},
): Promise<PolicyMutationResult<T>> {
  const headers = {
    Accept: 'application/json',
    ...authHeaders(),
    ...options.headers,
  };
  const response = await fetch(input, { ...options, headers });
  const body = await parseJsonBody(response);

  if (!response.ok) {
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  return {
    value: body as T,
    etag: response.headers.get('etag'),
  };
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim().length === 0) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function errorMessage(body: unknown, response: Response): string {
  if (
    body &&
    typeof body === 'object' &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }

  if (typeof body === 'string' && body.trim().length > 0) {
    return body;
  }

  return response.statusText || `Request failed with status ${response.status}`;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
