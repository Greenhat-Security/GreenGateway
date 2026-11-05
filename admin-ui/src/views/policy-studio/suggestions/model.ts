import type { ProposedRule, RuleSuggestion } from '../../../lib/suggestions';
import { isJsonObject, type JsonObject } from '../model';

// What the Studio knows about a listed suggestion beyond the row the
// gateway sent: what an answer since the listing said about it. Each is
// labelled in text; none is inferred.
export type SuggestionMark =
  | Readonly<{ kind: 'changed'; listedRevision: number; listedState: string }>
  | Readonly<{ kind: 'rule_live' }>
  | Readonly<{ kind: 'gone' }>;

export type Badge = 'success' | 'warning' | 'neutral' | 'danger';

export type StateLabel = Readonly<{ text: string; badge: Badge; detail: string | null }>;

const AUTH_METHODS = new Set([
  'bearer_token',
  'session_cookie',
  'service_token',
  'client_certificate',
]);

export function isSignalDerived(suggestion: RuleSuggestion): boolean {
  return suggestion.source_signal_id !== null;
}

// The lifecycle state as text, with what made a row stale or superseded.
// The badge colour repeats the text; it never carries the meaning alone.
export function stateLabels(
  suggestion: RuleSuggestion,
  mark: SuggestionMark | null,
): StateLabel[] {
  const labels: StateLabel[] = [];
  if (mark?.kind === 'gone') {
    labels.push({
      text: 'Gone',
      badge: 'neutral',
      detail: 'The gateway no longer holds this suggestion.',
    });
    return labels;
  }
  if (suggestion.state === 'open') {
    labels.push({ text: 'Open', badge: 'success', detail: null });
  } else {
    const who = suggestion.transitioned_by ? ` by ${suggestion.transitioned_by}` : '';
    const when = suggestion.transitioned_at ? ` at ${suggestion.transitioned_at}` : '';
    labels.push({
      text: suggestion.state === 'accepted' ? 'Superseded: accepted' : 'Superseded: dismissed',
      badge: 'neutral',
      detail: `${suggestion.state === 'accepted' ? 'Accepted' : 'Dismissed'}${who}${when}. It can no longer be reviewed or accepted.`,
    });
  }
  if (mark?.kind === 'changed') {
    labels.push({
      text: 'Stale: changed since listed',
      badge: 'warning',
      detail: `Listed at revision ${mark.listedRevision} (${mark.listedState}); the gateway now holds revision ${suggestion.revision} (${suggestion.state}). This row shows what it holds now.`,
    });
  }
  if (mark?.kind === 'rule_live' && suggestion.state === 'open') {
    labels.push({
      text: 'Superseded: rule already live',
      badge: 'warning',
      detail:
        'The live policy already holds the rule this suggestion proposes, so opening it in a draft would add nothing and accepting it would add the rule twice. Dismiss it.',
    });
  }
  return labels;
}

export function sourceText(suggestion: RuleSuggestion): string {
  const evidence = suggestion.evidence;
  if (isSignalDerived(suggestion) || evidence.source === 'discovery_signal') {
    const type = stringFact(evidence.source_signal_type);
    return `Discovery signal ${suggestion.source_signal_id ?? stringFact(evidence.source_signal_id) ?? '(id not recorded)'}${type ? ` (${type})` : ''}`;
  }
  if (suggestion.suggestion_type === 'baseline_allow') {
    return 'Traffic baseline from the audit history';
  }
  return suggestion.suggestion_type;
}

export type EvidenceFacts = Readonly<{
  // `recorded`: the evidence the generator kept is complete for its window;
  // `incomplete`: it says itself that it is not; `not_recorded`: the
  // suggestion carries none.
  availability: 'recorded' | 'incomplete' | 'not_recorded';
  window: string;
  facts: readonly string[];
}>;

export function evidenceFacts(suggestion: RuleSuggestion): EvidenceFacts {
  const evidence = suggestion.evidence;
  if (Object.keys(evidence).length === 0) {
    return {
      availability: 'not_recorded',
      window: 'Not recorded with this suggestion.',
      facts: [],
    };
  }
  if (evidence.source === 'discovery_signal') {
    const facts: string[] = [];
    const explanation = stringFact(evidence.source_signal_explanation);
    if (explanation) facts.push(`Signal: ${explanation}`);
    const signalEvidence = isJsonObject(evidence.source_signal_evidence)
      ? evidence.source_signal_evidence
      : null;
    facts.push(
      signalEvidence === null || Object.keys(signalEvidence).length === 0
        ? 'The signal recorded no evidence of its own.'
        : `The signal recorded ${Object.keys(signalEvidence).length} evidence ${Object.keys(signalEvidence).length === 1 ? 'fact' : 'facts'}, shown in the raw evidence.`,
    );
    const reason = stringFact(evidence.mapping_reason);
    if (reason) facts.push(reason);
    return {
      availability: 'recorded',
      window: 'The signal’s own detection; the suggestion records no traffic window of its own.',
      facts,
    };
  }
  const facts: string[] = [];
  const count = countFact(evidence.observation_count);
  const errors = countFact(evidence.error_count);
  if (count !== null) {
    facts.push(
      `${count} matching ${count === 1 ? 'request' : 'requests'}${errors !== null ? `, ${errors} with an error status` : ''}.`,
    );
  }
  const firstSeen = stringFact(evidence.first_seen);
  const lastSeen = stringFact(evidence.last_seen);
  if (firstSeen && lastSeen) facts.push(`First seen ${firstSeen}, last seen ${lastSeen}.`);
  const role = stringFact(evidence.role);
  const issuer = stringFact(evidence.issuer);
  const authMethod = stringFact(evidence.auth_method);
  if (role || issuer || authMethod) {
    facts.push(
      `Caller: ${[role ? `role ${role}` : null, issuer ? `issuer ${issuer}` : null, authMethod ? `authenticated by ${authMethod}` : null]
        .filter((part) => part !== null)
        .join(', ')}.`,
    );
  }
  const truncated = evidence.audit_scan_truncated === true;
  const scanned = countFact(evidence.audit_scanned_event_count);
  if (truncated) {
    facts.push(
      `The audit scan stopped at its row bound${scanned !== null ? ` after ${scanned} records` : ''}, so the window was not read completely.`,
    );
  }
  const limitations = stringFact(evidence.match_limitations);
  if (limitations) facts.push(limitations);
  const hours = countFact(evidence.lookback_window_hours);
  const from = stringFact(evidence.from);
  const to = stringFact(evidence.to);
  const window =
    from && to
      ? `${from} to ${to}${hours !== null ? ` (${hours} ${hours === 1 ? 'hour' : 'hours'})` : ''}`
      : hours !== null
        ? `The last ${hours} ${hours === 1 ? 'hour' : 'hours'} before generation; the bounds were not recorded.`
        : 'Not recorded with this suggestion.';
  return {
    availability: truncated ? 'incomplete' : 'recorded',
    window,
    facts,
  };
}

export function evidenceAvailabilityText(availability: EvidenceFacts['availability']): string {
  if (availability === 'incomplete') return 'Incomplete';
  if (availability === 'not_recorded') return 'Not recorded';
  return 'Recorded';
}

export type RoutingFacts = Readonly<{ label: string; detail: string }>;

// The routing context the proposal is bound to. The gateway recomputes the
// binding from current routing whenever it drafts or accepts the rule, so
// this is what was proposed, not what will be written.
export function routingFacts(rule: ProposedRule): RoutingFacts {
  if (rule.tool_name !== null) {
    return {
      label: 'MCP tool rule',
      detail: 'Applies to calls of this tool by name; HTTP routing does not apply.',
    };
  }
  const dispatch = rule.dispatch;
  if (dispatch === null) {
    return {
      label: 'Not classified',
      detail:
        'The proposal carries no routing binding. The gateway decides from current routing when it opens the suggestion, and refuses one it cannot bind.',
    };
  }
  if (dispatch.kind === 'contextless') {
    return {
      label: 'Contextless',
      detail: 'Traffic the gateway served itself, with no proxy dispatch.',
    };
  }
  if (dispatch.kind === 'legacy') {
    return {
      label: 'Legacy upstream',
      detail: `The configured fallback upstream${dispatch.upstream_origin ? ` ${dispatch.upstream_origin}` : ''}, with no routed host or path.`,
    };
  }
  if (dispatch.kind === 'route') {
    return {
      label: 'Proxy route',
      detail: `Route ${dispatch.route_id ?? '(id not recorded)'}.`,
    };
  }
  return { label: dispatch.kind, detail: 'A routing binding this view does not describe.' };
}

// A suggestion is as of its generation run. The gateway keeps no policy
// revision, resource snapshot or generator version with it, so nothing here
// can say it still fits the live policy; opening it in a draft checks that.
export function freshnessText(suggestion: RuleSuggestion): string {
  return `Generated ${suggestion.created_at} and not recomputed since. Opening it in a draft checks it against the live policy and current routing.`;
}

export function principalText(rule: ProposedRule): string {
  const principal = rule.principal;
  const parts: string[] = [];
  if (principal.roles.length > 0) parts.push(`roles ${principal.roles.join(', ')}`);
  if (principal.issuers.length > 0) parts.push(`issuers ${principal.issuers.join(', ')}`);
  if (principal.auth_methods.length > 0) {
    parts.push(`authenticated by ${principal.auth_methods.join(', ')}`);
  }
  if (principal.principal_ids.length > 0) {
    parts.push(`principals ${principal.principal_ids.join(', ')}`);
  }
  return parts.length === 0 ? 'Any caller, including anonymous ones' : parts.join('; ');
}

export function targetText(rule: ProposedRule): string {
  if (rule.tool_name !== null) {
    return `Tool ${rule.tool_name}`;
  }
  const methods =
    rule.methods.length === 0 || rule.methods.includes('*') ? 'Any method' : rule.methods.join(', ');
  return `${methods} ${rule.path ?? '(no path)'}`;
}

// What the draft will hold: a signal-derived deny is drafted as shadow,
// never as an enforcing deny inferred from traffic.
export function draftedActionText(suggestion: RuleSuggestion): string {
  const action = suggestion.proposed_rule.action;
  if (isSignalDerived(suggestion) && action === 'deny') {
    return 'deny, drafted as shadow: a deny inferred from a signal starts as a would-deny that is only observed';
  }
  if (action === 'shadow') {
    return 'shadow: a would-deny that is only observed, never enforced by this rule';
  }
  return action;
}

// The candidate's `rules` index of the rule with this id, or null.
export function rulePosition(document: JsonObject, ruleId: string | null): number | null {
  if (ruleId === null || !Array.isArray(document.rules)) {
    return null;
  }
  const index = document.rules.findIndex(
    (rule) => isJsonObject(rule) && rule.id === ruleId,
  );
  return index >= 0 ? index : null;
}

// The candidate's `rules` index of a rule that looks like this proposal --
// the same methods (as a set), path or tool and principal constraints,
// under any id -- with the action the draft gives it, or a shadow proposal
// held as deny. It is only for showing where the rule is: the gateway, which
// also compares the dispatch binding it recomputes from current routing,
// decides whether a publication accepts the suggestion.
export function matchingRulePosition(
  document: JsonObject,
  suggestion: RuleSuggestion,
): number | null {
  if (!Array.isArray(document.rules)) {
    return null;
  }
  const proposed = suggestion.proposed_rule;
  const drafted =
    isSignalDerived(suggestion) && proposed.action === 'deny' ? 'shadow' : proposed.action;
  const actions = drafted === 'shadow' ? ['shadow', 'deny'] : [drafted];
  const index = document.rules.findIndex((entry) => {
    if (!isJsonObject(entry) || !actions.includes(String(entry.action))) {
      return false;
    }
    const principal = isJsonObject(entry.principal) ? entry.principal : {};
    return (
      sameSet(entry.methods, proposed.methods) &&
      (entry.path ?? null) === (proposed.path ?? null) &&
      (entry.tool_name ?? null) === proposed.tool_name &&
      sameSet(principal.roles, proposed.principal.roles) &&
      sameSet(principal.issuers, proposed.principal.issuers) &&
      sameSet(principal.auth_methods, proposed.principal.auth_methods) &&
      sameSet(principal.principal_ids, proposed.principal.principal_ids)
    );
  });
  return index >= 0 ? index : null;
}

function sameSet(value: unknown, expected: readonly string[]): boolean {
  const actual = Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : [];
  const left = new Set(actual);
  const right = new Set(expected);
  return left.size === right.size && [...left].every((entry) => right.has(entry));
}

export const REVIEW_CASE_ID = 'suggested-traffic';

// A synthetic case for the traffic the rule describes: one request (or tool
// call) the rule itself matches, from a hypothetical caller its principal
// constraints admit. It carries no credential and is never stored. Null,
// with the reason, when no such case can be written.
export function reviewCase(
  rule: ProposedRule,
): Readonly<{ case: JsonObject; note: string | null }> | Readonly<{ case: null; note: string }> {
  const principal: JsonObject = {
    subject: rule.principal.principal_ids[0] ?? 'synthetic-suggestion-caller',
    roles: [...rule.principal.roles],
    auth_method:
      rule.principal.auth_methods.find((method) => AUTH_METHODS.has(method)) ?? 'bearer_token',
  };
  if (rule.principal.issuers.length > 0) {
    principal.issuer = rule.principal.issuers[0];
  }
  if (rule.tool_name !== null) {
    return {
      case: {
        id: REVIEW_CASE_ID,
        kind: 'tool',
        tool: { name: rule.tool_name, operation: 'invocation' },
        principal,
      },
      note: null,
    };
  }
  const path = rule.path === null ? null : witnessPath(rule.path);
  if (path === null) {
    return {
      case: null,
      note: 'The rule’s path pattern has no request path a synthetic case can name, so it was not simulated.',
    };
  }
  const method =
    rule.methods.find((candidate) => candidate !== '*' && candidate.trim().length > 0) ?? 'GET';
  const request: JsonObject = { method, path };
  const dispatch = rule.dispatch;
  if (dispatch?.kind === 'legacy' && dispatch.upstream_origin !== null) {
    request.target = { kind: 'proxy_dispatch', upstream_origin: dispatch.upstream_origin };
  } else if (dispatch !== null && dispatch.kind !== 'contextless') {
    return {
      case: null,
      note: 'The rule is bound to a routing context a synthetic case does not describe, so it was not simulated.',
    };
  }
  return {
    case: { id: REVIEW_CASE_ID, kind: 'http', request, principal },
    note: path !== rule.path ? `Simulated as ${method} ${path}, one path the pattern matches.` : null,
  };
}

// One request path a rule path pattern matches: literal segments as they
// are, one placeholder segment for `*` and `{name}`, and none for `**`. A
// pattern whose literal segments a request path cannot carry gives null.
export function witnessPath(pattern: string): string | null {
  if (!pattern.startsWith('/')) {
    return null;
  }
  const segments: string[] = [];
  for (const segment of pattern.split('/').slice(1)) {
    if (segment === '**') {
      continue;
    }
    if (segment === '*' || /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(segment)) {
      segments.push('example');
      continue;
    }
    if (segment === '.' || segment === '..' || /[%?#\s{}*]/.test(segment)) {
      return null;
    }
    segments.push(segment);
  }
  return `/${segments.join('/')}`;
}

function stringFact(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

function countFact(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
