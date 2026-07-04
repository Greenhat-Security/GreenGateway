import { adminFetchJson, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';

export type RuleAction = 'allow' | 'deny' | 'shadow';
export type AuthMethodName = 'bearer_token' | 'session_cookie';

export type PrincipalMatcher = {
  roles: string[];
  auth_methods: AuthMethodName[];
  principal_ids: string[];
};

export type Rule = {
  id?: string;
  methods: string[];
  path: string;
  principal: PrincipalMatcher;
  action: RuleAction;
};

export type RoleEntry = {
  permissions: string[];
};

export type Policy = {
  schema_version: string;
  id?: string;
  default_action?: 'allow' | 'deny';
  enforcement_mode?: 'enforce' | 'shadow';
  roles: Record<string, RoleEntry>;
  routes: unknown[];
  rules: Rule[];
  egress?: unknown;
  rate_limits?: unknown[];
};

export type PolicyFetchResponse = {
  policy: Policy;
  etag: string | null;
};

export type PolicyRulePatch = {
  methods?: string[];
  path?: string;
  principal?: PrincipalMatcher;
  action?: RuleAction;
};

export type PolicyRuleMutationResponse = {
  rule: Rule;
  etag: string | null;
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
  rule: Rule;
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

export async function fetchPolicy(): Promise<PolicyFetchResponse> {
  const response = await adminFetchJsonResponse<Policy>(adminApiUrl('/policy'));

  return {
    policy: response.body,
    etag: response.headers.get('ETag'),
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
  rule: Rule,
  etag: string,
): Promise<PolicyRuleMutationResponse> {
  const response = await adminFetchJsonResponse<Rule>(
    adminApiUrl('/policy/rules'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify(rule),
    },
  );

  return {
    rule: response.body,
    etag: response.headers.get('ETag'),
  };
}

export async function patchPolicyRule(
  ruleId: string,
  patch: PolicyRulePatch,
  etag: string,
): Promise<PolicyRuleMutationResponse> {
  const response = await adminFetchJsonResponse<Rule>(
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

  return {
    rule: response.body,
    etag: response.headers.get('ETag'),
  };
}
