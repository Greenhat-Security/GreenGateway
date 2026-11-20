import type { AdvisoryEdit, AdvisorySection } from '../../../lib/policyAnalyses';
import { isJsonObject, type JsonObject } from '../model';

// An analyzer's advisory patch, applied to a document the way
// gateway/src/policy_simulation/edits.rs `apply_edits` applies the same
// edits, for the three operations the analyzer emits: each edit sees the
// result of the ones before it, a section the document omits is an empty
// one, a position must exist, a move's destination must be an existing
// position, and `expect_id` must name the element at the position. The first
// edit that cannot apply refuses the whole patch, and the input is never
// changed. The gateway validates the result again when it is saved as a
// draft; nothing here writes anything.

export type PatchResult =
  | Readonly<{ ok: true; document: JsonObject }>
  | Readonly<{ ok: false; index: number; member: string; code: string }>;

type Refusal = Readonly<{ member: string; code: string }>;

export function applyPatch(document: JsonObject, edits: readonly AdvisoryEdit[]): PatchResult {
  const candidate = structuredClone(document);
  for (const [index, edit] of edits.entries()) {
    const refusal = applyEdit(candidate, edit);
    if (refusal !== null) {
      return { ok: false, index, ...refusal };
    }
  }
  return { ok: true, document: candidate };
}

function applyEdit(document: JsonObject, edit: AdvisoryEdit): Refusal | null {
  if (edit.op === 'set') {
    document[edit.field] = edit.value;
    return null;
  }
  const items = sectionItems(document, edit.section);
  if (items === null) {
    return { member: 'section', code: 'internal_error' };
  }
  if (edit.op === 'delete') {
    if (edit.position >= items.length) {
      return { member: 'position', code: 'position_out_of_range' };
    }
    if (!carriesId(items[edit.position], edit.expectId)) {
      return { member: 'expect_id', code: 'edit_target_mismatch' };
    }
    items.splice(edit.position, 1);
    return null;
  }
  if (edit.from >= items.length) {
    return { member: 'from', code: 'position_out_of_range' };
  }
  if (!carriesId(items[edit.from], edit.expectId)) {
    return { member: 'expect_id', code: 'edit_target_mismatch' };
  }
  if (edit.to >= items.length) {
    return { member: 'to', code: 'position_out_of_range' };
  }
  const [element] = items.splice(edit.from, 1);
  items.splice(edit.to, 0, element);
  return null;
}

// The section's array, created empty when the document omits it.
function sectionItems(document: JsonObject, section: AdvisorySection): unknown[] | null {
  if (!(section in document)) {
    document[section] = [];
  }
  const items = document[section];
  return Array.isArray(items) ? items : null;
}

function carriesId(element: unknown, expected: string | null): boolean {
  return expected === null || (isJsonObject(element) && element.id === expected);
}

const SECTION_NOUNS: Record<AdvisorySection, string> = {
  rules: 'rule',
  routes: 'route',
  rate_limits: 'rate-limit override',
};

// One edit in words, positions counted from 1 as the editors show them.
export function describeEdit(edit: AdvisoryEdit): string {
  if (edit.op === 'set') {
    return `Set ${edit.field} to ${edit.value}`;
  }
  const noun = SECTION_NOUNS[edit.section];
  const id = edit.expectId === null ? '' : ` (id ${edit.expectId})`;
  return edit.op === 'delete'
    ? `Delete ${noun} #${edit.position + 1}${id}`
    : `Move ${noun} #${edit.from + 1}${id} to position #${edit.to + 1}`;
}
