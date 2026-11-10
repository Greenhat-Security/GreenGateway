import { isJsonObject, type JsonObject } from './model';

// Structural bounds in gateway-config/src/rbac/conditions.rs. The gateway
// owns validation of matcher values, eligibility and evaluation.
export const MAX_CONDITION_DEPTH = 4;
export const MAX_CONDITION_NODES = 32;
export const MAX_CONDITION_BRANCHES = 16;
export const MAX_CONDITION_VALUES = 32;

export type ConditionTree = {
  operator: string;
  value: JsonObject;
  children: ConditionTree[];
  height: number;
  size: number;
};

// Only these wire shapes can be moved without interpreting their contents.
// Unknown operators and members stay in Source.
const leafMembers: Record<string, readonly string[]> = {
  organization: ['issuer', 'in'],
  scope: ['issuer', 'in'],
  claim: ['issuer', 'name', 'in'],
  source_network: ['cidrs'],
  header: ['name', 'in'],
  query: ['name', 'in'],
  tool_argument: ['pointer', 'in'],
  time_window: ['from', 'until'],
};

function editableLeaf(operator: string, value: unknown): boolean {
  if (!isJsonObject(value) || !Object.hasOwn(leafMembers, operator)) return false;
  const members = leafMembers[operator];
  if (operator !== 'time_window' && !members.every((key) => Object.hasOwn(value, key))) return false;
  return Object.entries(value).every(([key, member]) => {
    if (!members.includes(key)) return false;
    if (key === 'in' || key === 'cidrs') {
      if (!Array.isArray(member) || member.length > MAX_CONDITION_VALUES) return false;
      return member.every((entry: unknown) => {
        if (typeof entry === 'string') return true;
        if (operator !== 'claim' && operator !== 'tool_argument') return false;
        return typeof entry === 'boolean' || (typeof entry === 'number' &&
          Number.isFinite(entry) && (!Number.isInteger(entry) || Number.isSafeInteger(entry)));
      });
    }
    return typeof member === 'string' || (operator === 'time_window' && member === null);
  });
}

export function conditionTree(value: unknown): ConditionTree | null {
  let visited = 0;
  function read(node: unknown, depth: number): ConditionTree | null {
    visited += 1;
    if (depth > MAX_CONDITION_DEPTH || visited > MAX_CONDITION_NODES || !isJsonObject(node)) {
      return null;
    }
    const operators = Object.keys(node);
    if (operators.length !== 1) return null;
    const operator = operators[0];
    const operand = node[operator];
    let operands: unknown[] = [];
    if (operator === 'all' || operator === 'any') {
      if (!Array.isArray(operand) || operand.length === 0 || operand.length > MAX_CONDITION_BRANCHES) return null;
      operands = operand;
    } else if (operator === 'not') {
      operands = [operand];
    } else if (!editableLeaf(operator, operand)) {
      return null;
    }

    const children: ConditionTree[] = [];
    let height = 1;
    let size = 1;
    for (const item of operands) {
      const child = read(item, depth + 1);
      if (child === null) return null;
      children.push(child);
      height = Math.max(height, child.height + 1);
      size += child.size;
    }
    return { operator, value: node, children, height, size };
  }
  return read(value, 1);
}
