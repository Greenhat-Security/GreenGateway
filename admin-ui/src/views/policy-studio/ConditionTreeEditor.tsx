import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import {
  conditionTree, MAX_CONDITION_BRANCHES, MAX_CONDITION_DEPTH, MAX_CONDITION_NODES,
  type ConditionTree,
} from './conditionTree';
import type { JsonObject } from './model';
import type { FieldRegistrar } from './sections';

type ConditionChange = (next: JsonObject | undefined) => void;

type Props = {
  value: unknown;
  sourceReady: boolean;
  pointer: string;
  disabled: boolean;
  register: FieldRegistrar;
  onChange: ConditionChange;
  renderLeaf: (value: unknown, pointer: string, topLevel: boolean, change: ConditionChange) => ReactNode;
  renderProblems: (pointer: string, children: readonly string[]) => ReactNode;
};

const groups = [
  { operator: 'all', label: 'All' },
  { operator: 'any', label: 'Any' },
  { operator: 'not', label: 'Not' },
] as const;

export function ConditionTreeEditor({
  value, sourceReady, pointer, disabled, register, onChange, renderLeaf, renderProblems,
}: Props) {
  const container = useRef<HTMLDivElement>(null);
  const pendingFocus = useRef<string | null>(null);
  // Structural edits change which operand a position denotes. Reset staged
  // leaf inputs and give focus to the surviving node at the edited position.
  const [structureVersion, setStructureVersion] = useState(0);
  const root = conditionTree(value);
  useLayoutEffect(() => {
    if (pendingFocus.current === null || !container.current) return;
    const nodes = container.current.querySelectorAll<HTMLElement>('[data-condition-pointer]');
    const target = Array.from(nodes).find((element) => element.dataset.conditionPointer === pendingFocus.current);
    (target?.querySelector('fieldset') ?? container.current).focus();
    pendingFocus.current = null;
  }, [structureVersion]);

  function changeRoot(next: JsonObject | undefined, focus?: string) {
    if (disabled || !sourceReady || (next !== undefined && conditionTree(next) === null)) return;
    if (focus !== undefined) {
      pendingFocus.current = focus;
      setStructureVersion((revision) => revision + 1);
    }
    onChange(next);
  }

  function renderNode(
    node: ConditionTree,
    location: string,
    depth: number,
    replace: (next: JsonObject, focus?: string) => void,
  ): ReactNode {
    const { operator, children } = node;
    const topLevel = depth === 1;
    const grouped = operator === 'all' || operator === 'any';
    const childLocations = children.map((_, index) =>
      operator === 'not' ? `${location}/not` : `${location}/${operator}/${index}`);
    const operands = children.map((child) => child.value);
    const space = root !== null && root.size < MAX_CONDITION_NODES;
    const canWrap = space && depth + node.height <= MAX_CONDITION_DEPTH;
    const canAdd = space && depth < MAX_CONDITION_DEPTH && children.length < MAX_CONDITION_BRANCHES;
    return (
      <div className="studio-section-body" data-condition-pointer={location}>
        {children.length === 0 ? renderLeaf(node.value, location, topLevel, (next) => {
          if (next !== undefined) replace(next);
          else if (topLevel) changeRoot(undefined, location);
        }) : (
          <fieldset className="rule-fieldset" tabIndex={-1} ref={register(location)}>
            <legend>{topLevel ? 'Additional policy condition' : 'Condition group'}</legend>
            <p className="rule-hint">{operator === 'all' ? 'All operands must match.'
              : operator === 'any' ? 'At least one operand must match.'
              : 'Negate this operand. An unknown result stays unknown.'}</p>
            {renderProblems(location, childLocations)}
            <ol className="studio-condition-operands">
              {children.map((child, index) => (
                <li key={childLocations[index]}>
                  {renderNode(child, childLocations[index], depth + 1, (next, focus) => {
                    if (operator === 'not') replace({ not: next }, focus);
                    else replace({ [operator]: operands.map((entry, i) => i === index ? next : entry) }, focus);
                  })}
                  {grouped && children.length > 1 ? (
                    <button type="button" className="rule-danger-button" disabled={disabled}
                      aria-label={`Remove operand ${index + 1}`}
                      onClick={() => replace({ [operator]: operands.filter((_, i) => i !== index) }, location)}>
                      Remove operand
                    </button>
                  ) : null}
                </li>
              ))}
            </ol>
          </fieldset>
        )}
        <details className="studio-condition-actions">
          <summary>Change condition structure</summary>
          {!canWrap || (grouped && !canAdd) ? (
            <p className="rule-hint">A condition can have four levels and 32 nodes. Each group accepts up to 16 operands.</p>
          ) : null}
          <div className="form-actions">
            {groups.map(({ operator: wrapper, label }) => (
              <button key={wrapper} type="button" className="secondary-button"
                disabled={disabled || !canWrap}
                onClick={() => replace({ [wrapper]: wrapper === 'not' ? node.value : [node.value] }, location)}>
                Wrap in {label}
              </button>
            ))}
            {grouped ? (
              <>
                <button type="button" className="secondary-button" disabled={disabled}
                  onClick={() => replace({ [operator === 'all' ? 'any' : 'all']: operands }, location)}>
                  Change to {operator === 'all' ? 'Any' : 'All'}
                </button>
                <button type="button" className="secondary-button" disabled={disabled || !canAdd}
                  onClick={() => replace({ [operator]: [...operands, { source_network: { cidrs: [] } }] },
                    `${location}/${operator}/${operands.length}`)}>
                  Add source network operand
                </button>
                <button type="button" className="secondary-button" disabled={disabled || !canAdd}
                  onClick={() => replace({ [operator]: [...operands, { time_window: {} }] },
                    `${location}/${operator}/${operands.length}`)}>
                  Add time window operand
                </button>
              </>
            ) : null}
            {children.length === 1 ? (
              <button type="button" className="secondary-button" disabled={disabled}
                onClick={() => replace(children[0].value, location)}>
                {operator === 'not' ? 'Remove negation' : 'Unwrap single operand'}
              </button>
            ) : null}
            {topLevel && children.length > 0 ? (
              <button type="button" className="rule-danger-button" disabled={disabled}
                onClick={() => changeRoot(undefined, location)}>Remove policy condition</button>
            ) : null}
          </div>
        </details>
      </div>
    );
  }

  return (
    <div ref={container} tabIndex={-1}>
      <div key={structureVersion}>
        {!sourceReady ? (
          <fieldset className="rule-fieldset" tabIndex={-1} ref={register(pointer)}>
            <legend>Additional policy condition</legend>
            <p className="rule-hint">Validate the edits in Source before changing this condition here.</p>
            {renderProblems(pointer, [])}
          </fieldset>
        ) : value == null ? (
          <div data-condition-pointer={pointer}>
            {renderLeaf(value, pointer, true, (next) => changeRoot(next, pointer))}
          </div>
        ) : root !== null ? renderNode(root, pointer, 1, changeRoot) : (
          <fieldset className="rule-fieldset" tabIndex={-1} ref={register(pointer)}>
            <legend>Additional policy condition</legend>
            <p className="rule-hint">Review this condition in Source at <code>{pointer}</code>. The tree editor supports up to four levels, 32 nodes and 16 operands per group.</p>
            {renderProblems(pointer, [])}
          </fieldset>
        )}
      </div>
    </div>
  );
}
