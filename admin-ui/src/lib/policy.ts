import { AdminApiError, adminFetchJson, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';

// The gateway's stable reason when a policy evidence endpoint has no audit
// store to read. It answers 503 instead of zeros, so the UI can say the
// evidence is missing rather than imply a rule never matched.
export const POLICY_EVIDENCE_UNAVAILABLE_REASON = 'audit_evidence_unavailable';

// The gateway's stable reasons for refusing a promotion or disable bound to
// a shadow review. Each means the review on screen no longer describes what
// the change would act on.
export const SHADOW_REVIEW_REVISION_STALE_REASON = 'shadow_review_revision_stale';
export const SHADOW_EVIDENCE_WINDOW_STALE_REASON = 'shadow_evidence_window_stale';
export const SHADOW_EVIDENCE_DIGEST_STALE_REASON = 'shadow_evidence_digest_stale';
export const SHADOW_REVIEW_RULE_NOT_SHADOW_REASON = 'shadow_review_rule_not_shadow';

export type PolicyDefaultAction = 'allow' | 'deny';
export type PolicyRuleAction = 'allow' | 'deny' | 'shadow';
export type AuthMethodName =
  | 'bearer_token'
  | 'session_cookie'
  | 'service_token'
  | 'client_certificate';

export type PrincipalMatcher = {
  roles?: string[];
  issuers?: string[];
  auth_methods?: string[];
  principal_ids?: string[];
};

export type PolicyRuleDispatchMatcher = {
  kind: 'contextless' | 'legacy';
  upstream_origin?: string;
};

export type PolicyRule = {
  id?: string | null;
  enabled?: boolean;
  methods?: string[];
  path?: string;
  tool_name?: string;
  dispatch?: PolicyRuleDispatchMatcher;
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
  canWrite: boolean;
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
  shadow_review?: PolicyRuleShadowReviewBinding;
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
    issuer?: string;
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
  // True when the window held more observations than one preview scans;
  // match_count then covers only the newest scanned_event_count of them.
  scan_truncated: boolean;
  complete: boolean;
  sample_strategy: string;
  samples: PolicyRulePreviewSample[];
};

export type PolicyRuleShadowReviewPrincipal = {
  user_id: string;
  issuer?: string;
  auth_mode: string;
  roles: string[];
};

export type PolicyRuleShadowReviewSample = {
  event_id: string;
  timestamp: string;
  method: string;
  path: string;
  actor: {
    user_id: string;
    issuer?: string;
    auth_mode: string;
    roles?: string[];
  } | null;
};

// The recorded timestamps of the oldest and newest would-deny events a
// review read for one rule; both null when it read none. It describes what
// was read: after a truncated scan the rule can have older events outside it,
// so a null window is not proof that none were recorded.
export type PolicyRuleShadowEvidenceWindow = {
  from: string | null;
  to: string | null;
};

export type PolicyRuleShadowReviewSummary = {
  rule_id: string;
  rule: PolicyRule;
  would_deny_count: number;
  affected_principals: PolicyRuleShadowReviewPrincipal[];
  samples: PolicyRuleShadowReviewSample[];
  evidence_window?: PolicyRuleShadowEvidenceWindow;
  // Opaque; sent back unchanged, never computed here.
  evidence_digest?: string;
};

export type PolicyRuleShadowReviewResponse = {
  scanned_event_count: number;
  scan_truncated: boolean;
  // The policy revision the review was read from.
  policy_etag?: string;
  rules: PolicyRuleShadowReviewSummary[];
};

// What a promotion or disable is bound to: the revision, evidence window and
// evidence digest of the review entry the operator acted on. The gateway
// refuses the change once any of them no longer describes current evidence.
export type PolicyRuleShadowReviewBinding = {
  policy_etag: string;
  evidence_window: PolicyRuleShadowEvidenceWindow;
  evidence_digest: string;
};

export type ShadowRuleTransition = 'promote' | 'disable';

// Evidence read from the audit store, or an explicit statement that there was
// none to read. Never collapse `unavailable` into an empty or zero `value`.
export type PolicyEvidence<T> =
  | { status: 'available'; value: T }
  | { status: 'unavailable'; message: string };

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
  const response = await adminFetchJsonResponse<PolicyDocument>(
    adminApiUrl('/policy'),
  );

  return {
    policy: normalizePolicy(response.body),
    etag: response.etag,
    canWrite: response.headers.get('x-greengateway-policy-write') === 'true',
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

// The binding for one review entry, or null when the review did not say
// which revision and evidence it describes. Without one a change cannot be
// tied to what was reviewed, so the caller must not send it.
export function shadowReviewBinding(
  review: PolicyRuleShadowReviewResponse,
  summary: PolicyRuleShadowReviewSummary,
): PolicyRuleShadowReviewBinding | null {
  const window = summary.evidence_window;
  if (
    typeof review.policy_etag !== 'string' ||
    review.policy_etag.length === 0 ||
    typeof summary.evidence_digest !== 'string' ||
    summary.evidence_digest.length === 0 ||
    window === undefined ||
    window === null ||
    !isWindowBound(window.from) ||
    !isWindowBound(window.to)
  ) {
    return null;
  }

  return {
    policy_etag: review.policy_etag,
    evidence_window: { from: window.from, to: window.to },
    evidence_digest: summary.evidence_digest,
  };
}

function isWindowBound(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

// Promote (enforce deny) or disable a shadow rule, bound to the review entry
// the operator read. If-Match is the reviewed revision itself, so the change
// can only apply to the policy that review described.
export async function changeShadowRule(
  ruleId: string,
  transition: ShadowRuleTransition,
  binding: PolicyRuleShadowReviewBinding,
): Promise<PolicyMutationResult<PolicyRule>> {
  const patch: PolicyRulePatch =
    transition === 'promote'
      ? { action: 'deny', shadow_review: binding }
      : { enabled: false, shadow_review: binding };
  return patchPolicyRule(ruleId, binding.policy_etag, patch);
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

export async function fetchPolicyRuleHits(): Promise<
  PolicyEvidence<Record<string, number>>
> {
  let response: PolicyRuleHitsResponse;
  try {
    response = await adminFetchJson<PolicyRuleHitsResponse>(
      adminApiUrl('/policy/rules/hits'),
    );
  } catch (error) {
    return unavailablePolicyEvidence(error);
  }

  if (isPolicyRuleHitsListResponse(response)) {
    return {
      status: 'available',
      value: Object.fromEntries(
        response.rules.map((rule) => [rule.rule_id, rule.hits]),
      ),
    };
  }

  return { status: 'available', value: response };
}

export async function fetchPolicyRuleShadowReview(): Promise<
  PolicyEvidence<PolicyRuleShadowReviewResponse>
> {
  try {
    return {
      status: 'available',
      value: await adminFetchJson<PolicyRuleShadowReviewResponse>(
        adminApiUrl('/policy/rules/shadow-review'),
      ),
    };
  } catch (error) {
    return unavailablePolicyEvidence(error);
  }
}

export function isPolicyEvidenceUnavailableError(
  error: unknown,
): error is AdminApiError {
  return (
    error instanceof AdminApiError &&
    error.status === 503 &&
    error.code === POLICY_EVIDENCE_UNAVAILABLE_REASON
  );
}

// Only the gateway's explicit "no audit store" answer becomes unavailable
// evidence. Every other failure, including other 503s, still rejects so the
// caller reports it as an error instead of an evidence state.
function unavailablePolicyEvidence(error: unknown): {
  status: 'unavailable';
  message: string;
} {
  if (isPolicyEvidenceUnavailableError(error)) {
    return { status: 'unavailable', message: error.message };
  }
  throw error;
}

export function policyRuleId(rule: PolicyRule, index: number): string {
  return rule.id ?? String(index);
}

// A rule without an explicit id is addressed, and attributed in audit
// history, by its array position, so that id names a different rule as
// soon as a delete or reorder moves it.
export function hasExplicitPolicyRuleId(rule: PolicyRule): boolean {
  return rule.id !== undefined && rule.id !== null;
}

export function isPolicyRuleEnabled(rule: PolicyRule): boolean {
  return rule.enabled !== false;
}

export function isAuthMethodName(value: string): value is AuthMethodName {
  return (
    value === 'bearer_token' ||
    value === 'session_cookie' ||
    value === 'service_token' ||
    value === 'client_certificate'
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

// Policy writes go through the shared admin transport rather than raw `fetch`
// so they carry the CSRF header the gateway demands from any state-changing
// request that is not bearer-authenticated.
async function adminFetchJsonWithEtag<T>(
  input: string,
  options: AdminFetchWithMetaOptions = {},
): Promise<PolicyMutationResult<T>> {
  const response = await adminFetchJsonResponse<T>(input, options);

  return {
    value: response.body,
    etag: response.etag,
  };
}
