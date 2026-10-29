import type { PolicyDocument } from '../../lib/policy';
import type { PolicyDiagnostic } from '../../lib/policyDrafts';

// The candidate the Studio edits is the JSON text itself: the structured
// editors read it and write it back, and the text is what the gateway is
// asked to validate and save. A JSON object as JavaScript reads it.
export type JsonObject = Record<string, unknown>;

export type CandidateParse =
  | { ok: true; document: JsonObject }
  | { ok: false; message: string };

export type StudioSection =
  | 'overview'
  | 'roles'
  | 'routes'
  | 'rules'
  | 'tools'
  | 'rate_limits'
  | 'egress'
  | 'source';

export const STUDIO_SECTIONS: ReadonlyArray<{
  id: StudioSection;
  label: string;
}> = [
  { id: 'overview', label: 'Overview' },
  { id: 'roles', label: 'Roles' },
  { id: 'routes', label: 'Routes' },
  { id: 'rules', label: 'HTTP and MCP rules' },
  { id: 'tools', label: 'Tools' },
  { id: 'rate_limits', label: 'Rate limits' },
  { id: 'egress', label: 'Egress' },
  { id: 'source', label: 'Source' },
];

// The top-level members of a policy document, in schema order, and the
// value the gateway gives each one it omits.
const POLICY_MEMBERS: ReadonlyArray<{
  member: string;
  label: string;
  absent: unknown;
}> = [
  { member: 'schema_version', label: 'schema version', absent: undefined },
  { member: 'id', label: 'policy id', absent: undefined },
  { member: 'default_action', label: 'default action', absent: 'deny' },
  { member: 'enforcement_mode', label: 'enforcement mode', absent: 'enforce' },
  { member: 'roles', label: 'roles', absent: {} },
  { member: 'routes', label: 'routes', absent: [] },
  { member: 'rules', label: 'rules', absent: [] },
  { member: 'egress', label: 'egress', absent: {} },
  { member: 'rate_limits', label: 'rate limits', absent: [] },
  { member: 'tools', label: 'tools', absent: {} },
];

const OVERVIEW_MEMBERS = new Set([
  'schema_version',
  'id',
  'default_action',
  'enforcement_mode',
]);

export const POLICY_V1_SCHEMA_VERSION = '1.0.0';

export const AUTH_METHOD_OPTIONS: ReadonlyArray<{
  value: string;
  label: string;
}> = [
  { value: 'bearer_token', label: 'Bearer token' },
  { value: 'session_cookie', label: 'Session cookie' },
  { value: 'service_token', label: 'Service token' },
  { value: 'client_certificate', label: 'Client certificate' },
];

export function parseCandidate(source: string): CandidateParse {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch (error) {
    return {
      ok: false,
      message:
        error instanceof Error
          ? `The source is not valid JSON: ${error.message}`
          : 'The source is not valid JSON.',
    };
  }
  if (!isJsonObject(value)) {
    return { ok: false, message: 'A policy document is a JSON object.' };
  }
  return { ok: true, document: value };
}

export function formatCandidate(document: JsonObject | PolicyDocument): string {
  return JSON.stringify(document, null, 2);
}

export function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isPolicyV1(document: JsonObject): boolean {
  return document.schema_version === POLICY_V1_SCHEMA_VERSION;
}

// RFC 6901: `~1` is `/` and `~0` is `~`, decoded in that order. Null for a
// pointer that is not one.
export function decodePointer(pointer: string): string[] | null {
  if (pointer === '') {
    return [];
  }
  if (!pointer.startsWith('/')) {
    return null;
  }
  const segments = pointer.slice(1).split('/');
  if (segments.some((segment) => /~(?![01])/.test(segment))) {
    return null;
  }
  return segments.map((segment) =>
    segment.replace(/~1/g, '/').replace(/~0/g, '~'),
  );
}

export function pointerTo(...segments: ReadonlyArray<string | number>): string {
  return segments
    .map(
      (segment) =>
        `/${String(segment).replace(/~/g, '~0').replace(/\//g, '~1')}`,
    )
    .join('');
}

// The editor section a diagnostic belongs in. Anything the structured
// editors do not show, the whole document included, is in Source.
export function sectionForPointer(pointer: string): StudioSection {
  const segments = decodePointer(pointer);
  const member = segments?.[0];
  if (member === undefined) {
    return 'source';
  }
  if (OVERVIEW_MEMBERS.has(member)) {
    return 'overview';
  }
  if (
    member === 'roles' ||
    member === 'routes' ||
    member === 'rules' ||
    member === 'tools' ||
    member === 'rate_limits' ||
    member === 'egress'
  ) {
    return member;
  }
  return 'source';
}

export function diagnosticsInSection(
  diagnostics: readonly PolicyDiagnostic[],
  section: StudioSection,
): PolicyDiagnostic[] {
  return diagnostics.filter(
    (diagnostic) => sectionForPointer(diagnostic.pointer) === section,
  );
}

// The diagnostics at `pointer` or anywhere inside the value it names.
export function diagnosticsWithin(
  diagnostics: readonly PolicyDiagnostic[],
  pointer: string,
): PolicyDiagnostic[] {
  return diagnostics.filter(
    (diagnostic) =>
      diagnostic.pointer === pointer ||
      diagnostic.pointer.startsWith(`${pointer}/`),
  );
}

export function blocksPublication(
  diagnostics: readonly PolicyDiagnostic[],
): boolean {
  return diagnostics.some((diagnostic) => diagnostic.blocks.publication);
}

export function countBySeverity(diagnostics: readonly PolicyDiagnostic[]): {
  errors: number;
  warnings: number;
  risks: number;
} {
  let errors = 0;
  let warnings = 0;
  let risks = 0;
  for (const diagnostic of diagnostics) {
    if (diagnostic.severity === 'error') {
      errors += 1;
    } else if (diagnostic.severity === 'warning') {
      warnings += 1;
    } else {
      risks += 1;
    }
  }
  return { errors, warnings, risks };
}

// "2 errors, 1 warning": the counts that are not zero, for a sentence.
export function severitySummary(counts: {
  errors: number;
  warnings: number;
  risks: number;
}): string {
  return [
    plural(counts.errors, 'error'),
    plural(counts.warnings, 'warning'),
    plural(counts.risks, 'risk'),
  ]
    .filter((part): part is string => part !== null)
    .join(', ');
}

function plural(count: number, noun: string): string | null {
  return count === 0 ? null : `${count} ${noun}${count === 1 ? '' : 's'}`;
}

export function severityLabel(severity: PolicyDiagnostic['severity']): string {
  return severity === 'error' ? 'Error' : severity === 'warning' ? 'Warning' : 'Risk';
}

export function severityBadge(severity: PolicyDiagnostic['severity']): string {
  return severity === 'error' ? 'danger' : severity === 'warning' ? 'warning' : 'neutral';
}

export function blockedUses(diagnostic: PolicyDiagnostic): string[] {
  const uses: string[] = [];
  if (diagnostic.blocks.publication) uses.push('publication');
  if (diagnostic.blocks.simulation) uses.push('simulation');
  if (diagnostic.blocks.tests) uses.push('tests');
  if (diagnostic.blocks.evidence) uses.push('evidence');
  return uses;
}

// The top-level members whose value differs between the live policy and
// the candidate, by label in schema order. A member either side omits is
// compared as the value the gateway gives it, objects regardless of key
// order and arrays in order, since order is what rules and routes mean.
export function changedMembers(
  live: PolicyDocument | JsonObject,
  candidate: JsonObject,
): string[] {
  const known = new Set(POLICY_MEMBERS.map((entry) => entry.member));
  const changed = POLICY_MEMBERS.filter(
    ({ member, absent }) =>
      canonicalJson(live[member] ?? absent) !==
      canonicalJson(candidate[member] ?? absent),
  ).map((entry) => entry.label);
  const unknown = [...new Set([...Object.keys(live), ...Object.keys(candidate)])]
    .filter((member) => !known.has(member))
    .filter(
      (member) => canonicalJson(live[member]) !== canonicalJson(candidate[member]),
    )
    .sort();
  return [...changed, ...unknown];
}

export function egressChanged(
  live: PolicyDocument | JsonObject,
  candidate: JsonObject,
): boolean {
  return canonicalJson(live.egress ?? {}) !== canonicalJson(candidate.egress ?? {});
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (isJsonObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return value === undefined ? 'undefined' : JSON.stringify(value);
}

// Every id already used by a rule, route or rate override: the gateway
// requires them unique across all three.
export function usedElementIds(document: JsonObject): Set<string> {
  const ids = new Set<string>();
  for (const member of ['rules', 'routes', 'rate_limits']) {
    for (const element of arrayMember(document, member)) {
      if (isJsonObject(element) && typeof element.id === 'string') {
        ids.add(element.id);
      }
    }
  }
  return ids;
}

export function nextElementId(document: JsonObject, prefix: string): string {
  const used = usedElementIds(document);
  for (let index = 1; ; index += 1) {
    const candidate = `${prefix}-${index}`;
    if (!used.has(candidate)) {
      return candidate;
    }
  }
}

export function nextMemberName(existing: JsonObject, prefix: string): string {
  for (let index = 1; ; index += 1) {
    const candidate = `${prefix}-${index}`;
    if (!Object.prototype.hasOwnProperty.call(existing, candidate)) {
      return candidate;
    }
  }
}

// The member as an array, empty when it is absent or not an array; check
// memberShapeIsEditable first, since only Source can show another shape.
export function arrayMember(document: JsonObject, member: string): unknown[] {
  const value = document[member];
  return Array.isArray(value) ? value : [];
}

export function memberShapeIsEditable(
  document: JsonObject,
  member: string,
  shape: 'array' | 'object',
): boolean {
  const value = document[member];
  if (value === undefined) {
    return true;
  }
  return shape === 'array' ? Array.isArray(value) : isJsonObject(value);
}

export function objectMember(document: JsonObject, member: string): JsonObject {
  const value = document[member];
  return isJsonObject(value) ? value : {};
}

export function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : [];
}

export function withMember(
  document: JsonObject,
  member: string,
  value: unknown,
): JsonObject {
  if (value === undefined) {
    const next = { ...document };
    delete next[member];
    return next;
  }
  return { ...document, [member]: value };
}

export function replaceAt<T>(items: readonly T[], index: number, item: T): T[] {
  return items.map((current, position) => (position === index ? item : current));
}

export function removeAt<T>(items: readonly T[], index: number): T[] {
  return items.filter((_, position) => position !== index);
}

export function moveItem<T>(items: readonly T[], from: number, to: number): T[] {
  if (
    from === to ||
    from < 0 ||
    to < 0 ||
    from >= items.length ||
    to >= items.length
  ) {
    return [...items];
  }
  const next = [...items];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next;
}

// Rename one member of a map, keeping its position so the editor list does
// not jump. Null when the new name is empty or already taken: the edit
// would drop or merge an entry.
export function renameMember(
  map: JsonObject,
  from: string,
  to: string,
): JsonObject | null {
  if (from === to) {
    return map;
  }
  if (to.length === 0 || Object.prototype.hasOwnProperty.call(map, to)) {
    return null;
  }
  const next: JsonObject = {};
  for (const [name, value] of Object.entries(map)) {
    next[name === from ? to : name] = value;
  }
  return next;
}

// All permission names roles grant, for suggestions.
export function grantedPermissions(document: JsonObject): string[] {
  const permissions = new Set<string>();
  for (const role of Object.values(objectMember(document, 'roles'))) {
    if (isJsonObject(role)) {
      for (const permission of stringList(role.permissions)) {
        permissions.add(permission);
      }
    }
  }
  return [...permissions].sort((left, right) => left.localeCompare(right));
}

export function roleNames(document: JsonObject): string[] {
  return Object.keys(objectMember(document, 'roles')).sort((left, right) =>
    left.localeCompare(right),
  );
}

export function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

// A short, still unambiguous form of an opaque ETag for display; the full
// value is shown beside it for anyone comparing revisions.
export function shortEtag(etag: string | null | undefined): string {
  if (!etag) {
    return 'unknown';
  }
  const match = /^"?(?:sha256:)?([0-9a-f]{12})[0-9a-f]*"?$/.exec(etag);
  return match ? match[1] : etag;
}
