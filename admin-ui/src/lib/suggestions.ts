import { AdminApiError, adminFetchJsonResponse } from './api';
import { adminApiUrl } from './config';
import {
  POLICY_DRAFT_ETAG_HEADER,
  isPolicyDraftId,
  projectPolicyDraft,
  type PolicyDraft,
} from './policyDrafts';

// The discovery rule suggestions (`/suggestions`). A suggestion is advisory:
// the Studio opens its rule in a server-side draft for review, and only a
// publication of that draft bound to the suggestion accepts it.
export const SUGGESTIONS_READ_PERMISSION = 'admin:suggestions:read';
export const SUGGESTIONS_WRITE_PERMISSION = 'admin:suggestions:write';
export const SUGGESTION_PAGE_LIMIT = 50;
// Locating one suggestion reads whole pages, newest first, and stops after
// this many rows: past them its state is reported as not established.
const LOCATE_PAGE_LIMIT = 500;
const LOCATE_MAX_PAGES = 10;

// The expected suggestion revision when `If-Match` already names the live
// policy, as it does when a suggestion is opened in a draft.
const SUGGESTION_REVISION_HEADER = 'X-GreenGateway-Suggestion-Revision';

// The gateway's stable reasons for refusing a suggestion request.
export const SUGGESTION_NOT_OPEN_REASON = 'suggestion_not_open';
export const SUGGESTION_REVISION_MISMATCH_REASON = 'suggestion_revision_mismatch';
export const SUGGESTION_STALE_REASON = 'suggestion_stale';
export const SUGGESTION_RULE_ALREADY_PRESENT_REASON = 'suggestion_rule_already_present';
export const SUGGESTION_RULE_ID_TAKEN_REASON = 'suggestion_rule_id_taken';
export const SUGGESTION_RULE_ABSENT_REASON = 'suggestion_rule_absent';

const SUGGESTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_LISTED_SUGGESTIONS = 1_000;
const MAX_TEXT_LENGTH = 4_096;
const MAX_FIELD_LENGTH = 1_024;
const MAX_TIMESTAMP_LENGTH = 64;
const MAX_CURSOR_LENGTH = 1_024;
const MAX_LIST_ENTRIES = 64;
const MAX_VERSION_LENGTH = 64;
const MAX_FRESHNESS_REASONS = 16;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const REASON_CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
// The text an unrecognised reason code is kept as when it is not even a
// well-formed code.
export const UNRECOGNISED_FRESHNESS_REASON = 'unrecognised';

export type RuleSuggestionState = 'open' | 'dismissed' | 'accepted';

export type ProposedRulePrincipal = Readonly<{
  roles: readonly string[];
  issuers: readonly string[];
  auth_methods: readonly string[];
  principal_ids: readonly string[];
}>;

export type ProposedRuleDispatch = Readonly<{
  kind: string;
  upstream_origin: string | null;
  route_id: string | null;
}>;

// The rule a suggestion proposes, as the gateway stores it. `document` is
// the rule object itself, shown as JSON text and never interpreted further.
export type ProposedRule = Readonly<{
  id: string | null;
  enabled: boolean;
  methods: readonly string[];
  path: string | null;
  tool_name: string | null;
  principal: ProposedRulePrincipal;
  action: string;
  dispatch: ProposedRuleDispatch | null;
  document: Readonly<Record<string, unknown>>;
}>;

// What the run that wrote or last rebound a suggestion judged it against
// (issue #243, item 19), as the gateway reports it. The policy ETag and
// resource components it compares are kept server-side.
export type SuggestionGeneration = Readonly<{
  generator_version: string;
  evidence_schema_version: string;
  evidence_cutoff: string;
  evidence_digest: string;
  resource_snapshot_digest: string | null;
  resource_snapshot_complete: boolean;
}>;

export type FreshnessStatus = 'current' | 'stale' | 'superseded' | 'unbound' | 'unknown';

// The reason codes this view describes in words. Any other code is kept and
// shown as unrecognised, never dropped.
export const KNOWN_FRESHNESS_REASONS = [
  'policy_changed',
  'generator_changed',
  'evidence_schema_changed',
  'configuration_changed',
  'tools_changed',
  'connections_changed',
  'egress_changed',
  'evaluator_changed',
  'gateway_build_changed',
  'resource_snapshot_incomplete',
  'rule_already_live',
  'binding_not_recorded',
  'policy_unavailable',
] as const;

// Whether an open suggestion is still bound to the live policy and
// resources, computed by the gateway on every read. `status` is null for a
// suggestion that is not open.
export type SuggestionFreshness = Readonly<{
  status: FreshnessStatus | null;
  reasons: readonly string[];
}>;

export type RuleSuggestion = Readonly<{
  id: string;
  suggestion_type: string;
  method: string;
  path_pattern: string;
  principal_key: string;
  rationale: string;
  evidence: Readonly<Record<string, unknown>>;
  proposed_rule: ProposedRule;
  state: RuleSuggestionState;
  created_at: string;
  updated_at: string;
  transitioned_at: string | null;
  transitioned_by: string | null;
  revision: number;
  source_signal_id: string | null;
  generation: SuggestionGeneration | null;
  // As the listing reports it; null where a route does not.
  freshness: SuggestionFreshness | null;
}>;

export type RuleSuggestionPage = Readonly<{
  suggestions: readonly RuleSuggestion[];
  next_cursor: string | null;
}>;

// A suggestion's rule written into a draft: the draft as its owner reads
// it, the suggestion as the gateway read it, and the drafted rule with its
// index in the candidate's `rules`.
export type SuggestionDraftOpening = Readonly<{
  draft: PolicyDraft;
  created: boolean;
  suggestion: RuleSuggestion;
  rule: ProposedRule;
  position: number;
  // The suggestion's freshness when it was drafted.
  freshness: SuggestionFreshness | null;
}>;

// Where a suggestion's rule goes: a new draft copied from the live policy,
// or an open draft of the caller's, named by its current ETag.
export type SuggestionDraftTarget = Readonly<{
  draftId: string;
  draftEtag: string;
}>;

// A `409` from a suggestion route. When the suggestion itself moved, the
// gateway sends the row as it stands now, so the caller re-reads instead of
// retrying.
export class SuggestionConflictError extends AdminApiError {
  readonly current: RuleSuggestion | null;

  constructor(message: string, reason: string | null, current: RuleSuggestion | null) {
    super(409, message, reason === null ? {} : { code: reason });
    this.name = 'SuggestionConflictError';
    this.current = current;
  }
}

export function isSuggestionId(value: unknown): value is string {
  return typeof value === 'string' && SUGGESTION_ID_PATTERN.test(value);
}

export async function fetchSuggestions(
  filters: { state: RuleSuggestionState | null; cursor?: string | null; limit?: number },
  signal?: AbortSignal,
): Promise<RuleSuggestionPage> {
  const params = new URLSearchParams();
  if (filters.state !== null) {
    params.set('state', filters.state);
  }
  params.set('limit', String(filters.limit ?? SUGGESTION_PAGE_LIMIT));
  if (filters.cursor) {
    params.set('cursor', filters.cursor);
  }
  const response = await adminFetchJsonResponse<unknown>(
    adminApiUrl(`/suggestions?${params.toString()}`),
    { signal, cache: 'no-store' },
  );
  return projectSuggestionPage(response.body);
}

export type SuggestionLocation =
  | Readonly<{ kind: 'found'; suggestion: RuleSuggestion }>
  | Readonly<{ kind: 'gone' }>
  | Readonly<{ kind: 'unknown' }>;

// The suggestion as the gateway holds it now, read from the listing in every
// state (there is no route for one suggestion). Only a listing read to its
// end establishes that a suggestion is gone.
export async function locateSuggestion(
  id: string,
  signal?: AbortSignal,
): Promise<SuggestionLocation> {
  let cursor: string | null = null;
  for (let page = 0; page < LOCATE_MAX_PAGES; page += 1) {
    const result = await fetchSuggestions(
      { state: null, cursor, limit: LOCATE_PAGE_LIMIT },
      signal,
    );
    const found = result.suggestions.find((suggestion) => suggestion.id === id);
    if (found !== undefined) {
      return { kind: 'found', suggestion: found };
    }
    if (result.next_cursor === null) {
      return { kind: 'gone' };
    }
    cursor = result.next_cursor;
  }
  return { kind: 'unknown' };
}

// Write the suggestion's rule into a draft for review. The live policy, the
// suggestion and the draft stay exactly as they are otherwise: nothing live
// changes and the suggestion stays open. Every binding is one the operator
// read: the live policy ETag, the suggestion revision and, for an open
// draft, its ETag.
export async function openSuggestionInDraft(request: {
  id: string;
  revision: number;
  policyEtag: string;
  target: SuggestionDraftTarget | null;
}): Promise<SuggestionDraftOpening> {
  if (request.target !== null && !isPolicyDraftId(request.target.draftId)) {
    throw new Error('Invalid policy draft identifier.');
  }
  const response = await adminFetchJsonResponse<unknown>(
    `${suggestionUrl(request.id)}/draft`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': request.policyEtag,
        [SUGGESTION_REVISION_HEADER]: String(request.revision),
        ...(request.target === null
          ? {}
          : { [POLICY_DRAFT_ETAG_HEADER]: request.target.draftEtag }),
      },
      body:
        request.target === null
          ? '{}'
          : JSON.stringify({ draft_id: request.target.draftId }),
      answerStatuses: [409],
    },
  );
  if (response.status === 409) {
    throw conflictError(response.body);
  }
  const body = response.body;
  if (!isJsonObject(body)) {
    throw new Error('Invalid suggestion draft response.');
  }
  const suggestion = projectSuggestion(body.suggestion);
  const rule = projectProposedRule(body.rule);
  const freshness = projectFreshness(body.freshness);
  if (
    suggestion === null ||
    rule === null ||
    freshness === undefined ||
    !isCount(body.position) ||
    (response.status !== 200 && response.status !== 201)
  ) {
    throw new Error('Invalid suggestion draft response.');
  }
  return {
    draft: projectPolicyDraft(body.draft, response.etag),
    created: response.status === 201,
    suggestion,
    rule,
    position: body.position,
    freshness,
  };
}

// Move an open suggestion to dismissed, at the revision it was read at:
// `If-Match` on this route is the expected suggestion revision. Dismissing
// changes no policy.
export async function dismissSuggestion(
  id: string,
  revision: number,
): Promise<RuleSuggestion> {
  const response = await adminFetchJsonResponse<unknown>(
    `${suggestionUrl(id)}/dismiss`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': `"${revision}"`,
      },
      answerStatuses: [409],
    },
  );
  if (response.status === 409) {
    throw conflictError(response.body);
  }
  const suggestion = projectSuggestion(response.body);
  if (suggestion === null) {
    throw new Error('Invalid suggestion response.');
  }
  return suggestion;
}

function suggestionUrl(id: string): string {
  // The identifier comes from the gateway, but it still names a path
  // segment: refuse anything that is not one before building a URL.
  if (!isSuggestionId(id)) {
    throw new Error('Invalid suggestion identifier.');
  }
  return adminApiUrl(`/suggestions/${encodeURIComponent(id)}`);
}

function conflictError(body: unknown): SuggestionConflictError {
  const message =
    isJsonObject(body) && isBoundedString(body.error, MAX_TEXT_LENGTH)
      ? body.error
      : 'The gateway refused the request.';
  const reason =
    isJsonObject(body) && isBoundedString(body.reason, MAX_FIELD_LENGTH) ? body.reason : null;
  const current = isJsonObject(body) ? projectSuggestion(body.suggestion) : null;
  return new SuggestionConflictError(message, reason, current);
}

export function projectSuggestionPage(body: unknown): RuleSuggestionPage {
  if (
    !isJsonObject(body) ||
    !Array.isArray(body.suggestions) ||
    body.suggestions.length > MAX_LISTED_SUGGESTIONS ||
    !(
      body.next_cursor === null ||
      body.next_cursor === undefined ||
      isBoundedString(body.next_cursor, MAX_CURSOR_LENGTH)
    )
  ) {
    throw new Error('Invalid suggestion list response.');
  }
  const suggestions: RuleSuggestion[] = [];
  for (const entry of body.suggestions) {
    const suggestion = projectSuggestion(entry);
    if (suggestion === null) {
      throw new Error('Invalid suggestion list response.');
    }
    suggestions.push(suggestion);
  }
  return {
    suggestions,
    next_cursor: typeof body.next_cursor === 'string' ? body.next_cursor : null,
  };
}

export function projectSuggestion(value: unknown): RuleSuggestion | null {
  if (
    !isJsonObject(value) ||
    !isSuggestionId(value.id) ||
    !isBoundedString(value.suggestion_type, MAX_FIELD_LENGTH) ||
    !isBoundedString(value.method, MAX_FIELD_LENGTH) ||
    !isBoundedString(value.path_pattern, MAX_TEXT_LENGTH) ||
    typeof value.principal_key !== 'string' ||
    value.principal_key.length > MAX_TEXT_LENGTH ||
    !isBoundedString(value.rationale, MAX_TEXT_LENGTH) ||
    (value.state !== 'open' && value.state !== 'dismissed' && value.state !== 'accepted') ||
    !isBoundedString(value.created_at, MAX_TIMESTAMP_LENGTH) ||
    !isBoundedString(value.updated_at, MAX_TIMESTAMP_LENGTH) ||
    !isOptionalString(value.transitioned_at, MAX_TIMESTAMP_LENGTH) ||
    !isOptionalString(value.transitioned_by, MAX_TEXT_LENGTH) ||
    !isOptionalString(value.source_signal_id, MAX_FIELD_LENGTH) ||
    typeof value.revision !== 'number' ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1
  ) {
    return null;
  }
  const rule = projectProposedRule(value.proposed_rule);
  const generation = projectGeneration(value.generation);
  const freshness = projectFreshness(value.freshness);
  if (rule === null || generation === undefined || freshness === undefined) {
    return null;
  }
  return {
    id: value.id,
    suggestion_type: value.suggestion_type,
    method: value.method,
    path_pattern: value.path_pattern,
    principal_key: value.principal_key,
    rationale: value.rationale,
    evidence: isJsonObject(value.evidence) ? value.evidence : {},
    proposed_rule: rule,
    state: value.state,
    created_at: value.created_at,
    updated_at: value.updated_at,
    transitioned_at: typeof value.transitioned_at === 'string' ? value.transitioned_at : null,
    transitioned_by: typeof value.transitioned_by === 'string' ? value.transitioned_by : null,
    revision: value.revision,
    source_signal_id: typeof value.source_signal_id === 'string' ? value.source_signal_id : null,
    generation,
    freshness,
  };
}

// A suggestion's generation binding: null when the gateway recorded none,
// undefined (an invalid response) when what it sent is malformed.
export function projectGeneration(value: unknown): SuggestionGeneration | null | undefined {
  if (value === null || value === undefined) {
    return null;
  }
  if (
    !isJsonObject(value) ||
    !isBoundedString(value.generator_version, MAX_VERSION_LENGTH) ||
    !isBoundedString(value.evidence_schema_version, MAX_VERSION_LENGTH) ||
    !isBoundedString(value.evidence_cutoff, MAX_TIMESTAMP_LENGTH) ||
    typeof value.evidence_digest !== 'string' ||
    !DIGEST_PATTERN.test(value.evidence_digest) ||
    !(
      value.resource_snapshot_digest === null ||
      value.resource_snapshot_digest === undefined ||
      (typeof value.resource_snapshot_digest === 'string' &&
        DIGEST_PATTERN.test(value.resource_snapshot_digest))
    ) ||
    typeof value.resource_snapshot_complete !== 'boolean'
  ) {
    return undefined;
  }
  return {
    generator_version: value.generator_version,
    evidence_schema_version: value.evidence_schema_version,
    evidence_cutoff: value.evidence_cutoff,
    evidence_digest: value.evidence_digest,
    resource_snapshot_digest:
      typeof value.resource_snapshot_digest === 'string' ? value.resource_snapshot_digest : null,
    resource_snapshot_complete: value.resource_snapshot_complete,
  };
}

// A suggestion's freshness: null when the route reports none, undefined (an
// invalid response) when what it sent is malformed. A reason code this view
// does not know is kept, and one that is not even a code is kept as
// `unrecognised`.
export function projectFreshness(value: unknown): SuggestionFreshness | null | undefined {
  if (value === undefined) {
    return null;
  }
  if (
    !isJsonObject(value) ||
    !(
      value.status === null ||
      value.status === 'current' ||
      value.status === 'stale' ||
      value.status === 'superseded' ||
      value.status === 'unbound' ||
      value.status === 'unknown'
    ) ||
    !Array.isArray(value.reasons) ||
    value.reasons.length > MAX_FRESHNESS_REASONS
  ) {
    return undefined;
  }
  return {
    status: value.status,
    reasons: value.reasons.map((reason) =>
      typeof reason === 'string' && REASON_CODE_PATTERN.test(reason)
        ? reason
        : UNRECOGNISED_FRESHNESS_REASON,
    ),
  };
}

// A rule object as the suggestion routes render one, or null.
export function projectProposedRule(value: unknown): ProposedRule | null {
  if (!isJsonObject(value) || !isBoundedString(value.action, MAX_FIELD_LENGTH)) {
    return null;
  }
  const principal = isJsonObject(value.principal) ? value.principal : {};
  const dispatch = isJsonObject(value.dispatch) ? value.dispatch : null;
  const methods = stringList(value.methods);
  const roles = stringList(principal.roles);
  const issuers = stringList(principal.issuers);
  const authMethods = stringList(principal.auth_methods);
  const principalIds = stringList(principal.principal_ids);
  if (
    methods === null ||
    roles === null ||
    issuers === null ||
    authMethods === null ||
    principalIds === null ||
    !isOptionalString(value.id, MAX_FIELD_LENGTH) ||
    !isOptionalString(value.path, MAX_TEXT_LENGTH) ||
    !isOptionalString(value.tool_name, MAX_FIELD_LENGTH) ||
    (value.enabled !== undefined && typeof value.enabled !== 'boolean') ||
    (dispatch !== null && !isBoundedString(dispatch.kind, MAX_FIELD_LENGTH))
  ) {
    return null;
  }
  return {
    id: typeof value.id === 'string' ? value.id : null,
    enabled: value.enabled !== false,
    methods,
    path: typeof value.path === 'string' && value.path.length > 0 ? value.path : null,
    tool_name: typeof value.tool_name === 'string' ? value.tool_name : null,
    principal: {
      roles,
      issuers,
      auth_methods: authMethods,
      principal_ids: principalIds,
    },
    action: value.action,
    dispatch:
      dispatch === null
        ? null
        : {
            kind: dispatch.kind as string,
            upstream_origin: isBoundedString(dispatch.upstream_origin, MAX_TEXT_LENGTH)
              ? dispatch.upstream_origin
              : null,
            route_id: isBoundedString(dispatch.route_id, MAX_FIELD_LENGTH)
              ? dispatch.route_id
              : null,
          },
    document: value,
  };
}

function stringList(value: unknown): string[] | null {
  if (value === undefined || value === null) {
    return [];
  }
  if (
    !Array.isArray(value) ||
    value.length > MAX_LIST_ENTRIES ||
    !value.every((entry) => isBoundedString(entry, MAX_TEXT_LENGTH))
  ) {
    return null;
  }
  return [...value];
}

function isOptionalString(value: unknown, maxLength: number): boolean {
  return value === null || value === undefined || isBoundedString(value, maxLength);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
