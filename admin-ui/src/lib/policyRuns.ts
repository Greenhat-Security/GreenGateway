// Shared parts of the clients for the policy run endpoints: synthetic
// simulations, policy test runs and historical replay jobs. Each of them
// reads only its request and the policy; none changes the live policy.

// What a run judges: the live policy itself, or a candidate document sent
// as the exact text the operator wrote, so the gateway holds it to the
// same exact-source rules a policy write applies.
export type PolicyRunCandidate =
  | Readonly<{ kind: 'active' }>
  | Readonly<{ kind: 'inline'; source: string }>;

// One problem with a run request, located by an RFC 6901 pointer into the
// request. The message is the gateway's fixed text; it never repeats an
// input value.
export type PolicyRunDiagnostic = Readonly<{
  code: string;
  pointer: string;
  message: string;
}>;

// A refusal the run endpoints answer with structured detail (`422`): the
// request's own diagnostics, the policy validator's messages for a
// candidate, or the one case the evaluator refused.
export type PolicyRunRefusal = Readonly<{
  reason: string;
  diagnostics: readonly PolicyRunDiagnostic[];
  diagnosticsTruncated: boolean;
  errors: readonly string[];
  pointer: string | null;
  code: string | null;
}>;

export const POLICY_CANDIDATE_INVALID_REASON = 'policy_candidate_invalid';

const MAX_DIAGNOSTICS = 64;
const MAX_ERRORS = 64;
const MAX_TEXT_LENGTH = 4_096;
const MAX_POINTER_LENGTH = 8_192;
const CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

export function isCode(value: unknown): value is string {
  return typeof value === 'string' && CODE_PATTERN.test(value);
}

export function isBoundedText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

export function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function isPointer(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= MAX_POINTER_LENGTH &&
    (value === '' || value.startsWith('/'))
  );
}

export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// The text of one JSON object, for splicing into a request as a member's
// value. Only text JSON.parse accepted as an object is spliced, so it cannot
// close the request object early or add a member beside its own.
export function jsonObjectText(source: string): string {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error('The document is not a JSON object.');
  }
  if (!isJsonObject(value)) {
    throw new Error('The document is not a JSON object.');
  }
  return source;
}

// Whether every object in a JSON text names each member once. The gateway
// refuses a repeated member anywhere, and JSON.parse would silently keep the
// last one, so text that is re-serialized is checked first. The text must be
// JSON that JSON.parse accepts.
export function hasUniqueMembers(text: string): boolean {
  const scopes: Array<Set<string> | null> = [];
  let expectKey = false;
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    if (character === '"') {
      let end = index + 1;
      while (end < text.length && text[end] !== '"') {
        end += text[end] === '\\' ? 2 : 1;
      }
      if (expectKey) {
        const scope = scopes[scopes.length - 1];
        const key = JSON.parse(text.slice(index, end + 1)) as string;
        if (scope) {
          if (scope.has(key)) {
            return false;
          }
          scope.add(key);
        }
        expectKey = false;
      }
      index = end + 1;
      continue;
    }
    if (character === '{') {
      scopes.push(new Set());
      expectKey = true;
    } else if (character === '[') {
      scopes.push(null);
      expectKey = false;
    } else if (character === '}' || character === ']') {
      scopes.pop();
      expectKey = false;
    } else if (character === ',') {
      expectKey = scopes[scopes.length - 1] instanceof Set;
    }
    index += 1;
  }
  return true;
}

// The structured detail of a `422` from a run endpoint, or null for a body
// that is not one.
export function projectRunRefusal(body: unknown): PolicyRunRefusal | null {
  if (!isJsonObject(body) || !isCode(body.reason)) {
    return null;
  }
  const diagnostics: PolicyRunDiagnostic[] = [];
  if (Array.isArray(body.diagnostics)) {
    for (const entry of body.diagnostics.slice(0, MAX_DIAGNOSTICS)) {
      if (
        isJsonObject(entry) &&
        isCode(entry.code) &&
        isPointer(entry.pointer) &&
        isBoundedText(entry.message, MAX_TEXT_LENGTH)
      ) {
        diagnostics.push({
          code: entry.code,
          pointer: entry.pointer,
          message: entry.message,
        });
      }
    }
  }
  const errors = Array.isArray(body.errors)
    ? body.errors
        .filter((error): error is string => isBoundedText(error, MAX_TEXT_LENGTH))
        .slice(0, MAX_ERRORS)
    : [];
  return {
    reason: body.reason,
    diagnostics,
    diagnosticsTruncated:
      body.diagnostics_truncated === true ||
      (Array.isArray(body.diagnostics) && body.diagnostics.length > MAX_DIAGNOSTICS),
    errors,
    pointer: isPointer(body.pointer) ? body.pointer : null,
    code: isCode(body.code) ? body.code : null,
  };
}

// Stable codes keyed by count, as a run reports a closed set of them,
// sorted by code. Null for anything that is not one.
export function projectCodeCounts(
  value: unknown,
  maxEntries = 64,
): Array<{ code: string; count: number }> | null {
  if (!isJsonObject(value)) {
    return null;
  }
  const entries = Object.entries(value);
  if (entries.length > maxEntries) {
    return null;
  }
  const counts: Array<{ code: string; count: number }> = [];
  for (const [code, count] of entries) {
    if (!isCode(code) || !isCount(count)) {
      return null;
    }
    counts.push({ code, count });
  }
  return counts.sort((left, right) => left.code.localeCompare(right.code));
}

export function boundedCodes(value: unknown, maxEntries = 32): string[] | null {
  if (!Array.isArray(value) || value.length > maxEntries || !value.every(isCode)) {
    return null;
  }
  return [...value];
}
