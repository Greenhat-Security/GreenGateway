import { describe, expect, it } from 'vitest';
import { conditionTree } from './conditionTree';
import { changedMembers, type JsonObject } from './model';

const leaf = { query: { name: 'region', in: ['north', ''] } };

describe('condition tree editor bounds', () => {
  it('counts the root, its operands and the height of each preserved subtree', () => {
    const raw = { not: { any: [leaf, { all: [leaf, leaf] }] } };
    const tree = conditionTree(raw);
    expect(tree).toMatchObject({ operator: 'not', height: 4, size: 6 });
    expect(tree?.children[0].children[0].value).toBe(leaf);
    expect(conditionTree({ not: raw })).toBeNull();
  });

  it('accepts at most 16 operands per group and 32 nodes in the whole tree', () => {
    const group = (count: number) => ({ all: Array.from({ length: count }, () => leaf) });
    expect(conditionTree(group(16))?.size).toBe(17);
    expect(conditionTree(group(17))).toBeNull();
    expect(conditionTree({ any: [group(15), group(14)] })?.size).toBe(32);
    expect(conditionTree({ any: [group(15), group(15)] })).toBeNull();
  });

  it.each([
    {}, { any: [] }, { all: 1 }, { not: [] }, { not: null },
    { all: [leaf], not: leaf }, { next_operator: {} }, { query: null },
    { query: { name: 'a', in: [], extra: true } }, { query: { name: 'a', in: [true] } },
    { source_network: {} }, { claim: { in: [] } },
    { tool_argument: { pointer: '/a', in: [null] } },
    { claim: { issuer: 'example', name: 'a', in: [{ nested: true }] } },
    { claim: { issuer: 'example', name: 'a', in: [Number.MAX_SAFE_INTEGER + 1] } },
  ])('leaves a malformed or unrepresentable node in Source', (value) => {
    expect(conditionTree(value)).toBeNull();
  });

  it('preserves exact mixed scalar types and permits unfinished typed fields in a draft', () => {
    const typed = { claim: { issuer: 'example', name: 'division', in: [true, 'true', 2, '2'] } };
    const raw = { all: [typed, { time_window: {} }, { source_network: { cidrs: [] } }] };
    const tree = conditionTree(raw);
    expect(tree?.children.map((child) => child.value)).toEqual(raw.all);
    expect(tree?.children[0].value).toBe(typed);
  });

  it('keeps deeply nested Source text comparable while the gateway validates it', () => {
    const nest = () => {
      let node: JsonObject = leaf;
      for (let depth = 0; depth < 5000; depth += 1) node = { not: node };
      return { rules: [{ id: 'example', conditions: node }] };
    };
    const candidate = nest();
    expect(conditionTree(candidate.rules[0].conditions)).toBeNull();
    expect(changedMembers(nest(), candidate)).toEqual([]);
  });
});
