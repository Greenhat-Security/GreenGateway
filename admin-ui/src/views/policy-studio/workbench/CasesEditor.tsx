import { useEffect, useId, useState } from 'react';

import { AUTH_METHOD_OPTIONS, isJsonObject, moveItem, replaceAt, stringList, type JsonObject } from '../model';
import {
  CASE_KINDS,
  HTTP_REASONS,
  TOOL_REASONS,
  caseId,
  caseKind,
  caseKindLabel,
  duplicateCase,
  formatSuite,
  newCase,
  parseSuite,
  removeCase,
  reshapeCase,
  withCases,
  type CaseKind,
} from './suite';

const METHOD_SUGGESTIONS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

// The cases of the shared suite: a list, an editor for the selected case,
// and the suite's JSON source. Structured edits rewrite the source and keep
// every member they do not show.
export function CasesEditor({
  suiteSource,
  onChange,
  showExpectations,
  problems,
}: {
  suiteSource: string;
  onChange: (source: string) => void;
  showExpectations: boolean;
  // What the last refusal said about each case, by index.
  problems: ReadonlyMap<number, readonly string[]>;
}) {
  const headingId = useId();
  const [mode, setMode] = useState<'structured' | 'source'>('structured');
  const [selected, setSelected] = useState(0);
  const [newKind, setNewKind] = useState<CaseKind>('http');
  const parsed = parseSuite(suiteSource);
  const cases = parsed.ok ? parsed.cases : [];
  const current = Math.min(selected, Math.max(cases.length - 1, 0));
  const entry = cases[current];

  function writeCases(next: readonly JsonObject[]) {
    if (parsed.ok) {
      onChange(formatSuite(withCases(parsed.suite, next)));
    }
  }

  return (
    <section className="workbench-cases" aria-labelledby={headingId}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Synthetic cases</p>
          <h3 id={headingId}>Cases</h3>
        </div>
        <span className="result-count">
          {parsed.ok ? `${cases.length} ${cases.length === 1 ? 'case' : 'cases'}` : 'Suite invalid'}
        </span>
      </div>
      <p className="rule-hint">
        Each case states a hypothetical request or tool question and the identity facts of
        a hypothetical caller, never a token, cookie, header or other credential. The
        Simulator and the Test view share these cases, and they are kept in this page only:
        copy the suite source to keep it.
      </p>
      <div className="workbench-mode" role="group" aria-label="Case editing mode">
        <button
          type="button"
          className="secondary-button"
          aria-pressed={mode === 'structured'}
          onClick={() => setMode('structured')}
        >
          Case editor
        </button>
        <button
          type="button"
          className="secondary-button"
          aria-pressed={mode === 'source'}
          onClick={() => setMode('source')}
        >
          Suite source
        </button>
      </div>

      {mode === 'source' ? (
        <SuiteSource
          source={suiteSource}
          error={parsed.ok ? null : parsed.message}
          onChange={onChange}
        />
      ) : !parsed.ok ? (
        <div className="error-panel alert warning" role="note">
          <h3>Fix the suite source first</h3>
          <p>{parsed.message} The case editor shows the cases again once the source is a valid suite.</p>
        </div>
      ) : (
        <div className="workbench-case-layout">
          <div className="workbench-case-index">
            {cases.length > 0 ? (
              <ol className="workbench-case-list" aria-label="Cases">
                {cases.map((item, index) => {
                  const count = problems.get(index)?.length ?? 0;
                  const name = caseId(item) || `#${index + 1}`;
                  return (
                    <li key={index}>
                      <button
                        type="button"
                        className={`workbench-case-button ${index === current ? 'is-selected' : ''}`}
                        aria-current={index === current ? 'true' : undefined}
                        aria-label={`Edit case ${name}${count > 0 ? `, ${count} ${count === 1 ? 'problem' : 'problems'}` : ''}`}
                        onClick={() => setSelected(index)}
                      >
                        <span className="workbench-case-name">{name}</span>
                        <span className="rule-hint">{caseKindLabel(caseKind(item))}</span>
                        {count > 0 ? (
                          <span className="badge warning" aria-hidden="true">
                            {count}
                          </span>
                        ) : null}
                      </button>
                    </li>
                  );
                })}
              </ol>
            ) : (
              <p className="empty-state">No cases yet. Add one to simulate or test it.</p>
            )}
            <div className="workbench-add-case">
              <SelectInput
                label="New case kind"
                value={newKind}
                options={CASE_KINDS.map((kind) => ({ value: kind.value, label: kind.label }))}
                onChange={(value) => setNewKind(value as CaseKind)}
              />
              <button
                type="button"
                className="secondary-button"
                onClick={() => {
                  writeCases([...cases, newCase(newKind, cases)]);
                  setSelected(cases.length);
                }}
              >
                Add case
              </button>
            </div>
          </div>
          {entry ? (
            <CaseForm
              key={current}
              entry={entry}
              position={current}
              count={cases.length}
              showExpectations={showExpectations}
              problems={problems.get(current) ?? []}
              onChange={(next) => writeCases(replaceAt(cases, current, next))}
              onMove={(to) => {
                writeCases(moveItem(cases, current, to));
                setSelected(to);
              }}
              onDuplicate={() => {
                writeCases(duplicateCase(cases, current));
                setSelected(current + 1);
              }}
              onRemove={() => {
                writeCases(removeCase(cases, current));
                setSelected(Math.max(current - 1, 0));
              }}
            />
          ) : null}
        </div>
      )}
    </section>
  );
}

function SuiteSource({
  source,
  error,
  onChange,
}: {
  source: string;
  error: string | null;
  onChange: (source: string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        Suite source (policy-tests.v1)
      </label>
      <textarea
        id={id}
        className={`studio-source workbench-suite-source ${error ? 'is-error' : ''}`}
        value={source}
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-hint`}
        onChange={(event) => onChange(event.target.value)}
      />
      <p className={`rule-hint ${error ? 'is-error' : ''}`} id={`${id}-hint`}>
        {error ??
          'A policy-tests.v1 document. A simulation sends each case without its expect member.'}
      </p>
    </div>
  );
}

function CaseForm({
  entry,
  position,
  count,
  showExpectations,
  problems,
  onChange,
  onMove,
  onDuplicate,
  onRemove,
}: {
  entry: JsonObject;
  position: number;
  count: number;
  showExpectations: boolean;
  problems: readonly string[];
  onChange: (next: JsonObject) => void;
  onMove: (to: number) => void;
  onDuplicate: () => void;
  onRemove: () => void;
}) {
  const headingId = useId();
  const kind = caseKind(entry);
  const request = isJsonObject(entry.request) ? entry.request : {};
  const tool = isJsonObject(entry.tool) ? entry.tool : {};
  const name = caseId(entry) || `#${position + 1}`;

  const setMember = (member: string, value: unknown) => {
    const next = { ...entry };
    if (value === undefined || value === '') {
      delete next[member];
    } else {
      next[member] = value;
    }
    onChange(next);
  };
  const setNested = (member: 'request' | 'tool', field: string, value: unknown) => {
    const container = isJsonObject(entry[member]) ? { ...(entry[member] as JsonObject) } : {};
    if (value === undefined || value === '') {
      delete container[field];
    } else {
      container[field] = value;
    }
    onChange({ ...entry, [member]: container });
  };

  return (
    <article className="studio-element workbench-case" aria-labelledby={headingId}>
      <div className="studio-element-head">
        <h4 id={headingId}>Case {name}</h4>
        <div className="studio-element-tools">
          <button
            type="button"
            className="secondary-button"
            disabled={position === 0}
            onClick={() => onMove(position - 1)}
          >
            Move up
          </button>
          <button
            type="button"
            className="secondary-button"
            disabled={position >= count - 1}
            onClick={() => onMove(position + 1)}
          >
            Move down
          </button>
          <button type="button" className="secondary-button" onClick={onDuplicate}>
            Duplicate
          </button>
          <button type="button" className="rule-danger-button" onClick={onRemove}>
            Remove case
          </button>
        </div>
      </div>
      {problems.length > 0 ? (
        <ul className="studio-field-problems" aria-label={`Problems with case ${name}`}>
          {problems.map((problem, index) => (
            <li className="studio-problem error" key={index}>
              {problem}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="studio-element-fields">
        <TextInput
          label="Case id"
          value={typeof entry.id === 'string' ? entry.id : ''}
          hint="Unique in the suite. Results name the case by this id."
          onChange={(value) => onChange({ ...entry, id: value })}
        />
        <TextInput
          label="Case description"
          value={typeof entry.description === 'string' ? entry.description : ''}
          hint="Optional. Never repeated in results."
          onChange={(value) => setMember('description', value)}
        />
        <SelectInput
          label="Case kind"
          value={kind ?? ''}
          options={[
            ...(kind === null ? [{ value: '', label: 'Unknown kind' }] : []),
            ...CASE_KINDS.map((option) => ({ value: option.value, label: option.label })),
          ]}
          hint={CASE_KINDS.find((option) => option.value === kind)?.description}
          onChange={(value) => onChange(reshapeCase(entry, value as CaseKind))}
        />
      </div>

      {kind === 'tool' || kind === 'tool_http' ? (
        <div className="studio-element-fields">
          <TextInput
            label="Tool"
            value={typeof tool.name === 'string' ? tool.name : ''}
            hint="The registered tool name, exactly as the policy names it."
            onChange={(value) => setNested('tool', 'name', value)}
          />
          {kind === 'tool' ? (
            <SelectInput
              label="Tool operation"
              value={typeof tool.operation === 'string' ? tool.operation : 'invocation'}
              options={[
                { value: 'invocation', label: 'Invocation' },
                { value: 'visibility', label: 'Visibility in a tool listing' },
                { value: 'eligibility', label: 'Inventory eligibility' },
              ]}
              onChange={(value) => setNested('tool', 'operation', value)}
            />
          ) : null}
        </div>
      ) : null}

      {kind === 'http' || kind === 'tool_http' || kind === 'rate' ? (
        <div className="studio-element-fields">
          <TextInput
            label="Request method"
            value={typeof request.method === 'string' ? request.method : ''}
            suggestions={METHOD_SUGGESTIONS}
            onChange={(value) => setNested('request', 'method', value)}
          />
          <TextInput
            label="Request path"
            value={typeof request.path === 'string' ? request.path : ''}
            hint={
              kind === 'tool_http'
                ? 'The rendered request path, which may carry percent-escapes.'
                : 'An absolute path with no query, fragment, dot segments or percent-escapes.'
            }
            onChange={(value) => setNested('request', 'path', value)}
          />
          {kind === 'http' ? (
            <TextInput
              label="Request host"
              value={typeof request.host === 'string' ? request.host : ''}
              hint="Optional, without a port. Empty means a request with no Host header."
              onChange={(value) => setNested('request', 'host', value)}
            />
          ) : null}
        </div>
      ) : null}

      {kind === 'http' ? (
        <TargetFields
          target={request.target}
          onChange={(target) => setNested('request', 'target', target)}
        />
      ) : null}

      <PrincipalFields
        principal={entry.principal}
        onChange={(principal) => onChange({ ...entry, principal })}
      />

      {showExpectations && kind !== null ? (
        <ExpectationFields
          kind={kind}
          expect={entry.expect}
          onChange={(expect) => setMember('expect', expect)}
        />
      ) : null}
    </article>
  );
}

function TargetFields({
  target,
  onChange,
}: {
  target: unknown;
  onChange: (target: JsonObject | undefined) => void;
}) {
  const value = isJsonObject(target) ? target : { kind: 'contextless' };
  const kind = typeof value.kind === 'string' ? value.kind : 'contextless';
  const text = (member: string) => (typeof value[member] === 'string' ? (value[member] as string) : '');
  const set = (member: string, next: string) => {
    const updated = { ...value };
    if (next === '') delete updated[member];
    else updated[member] = next;
    onChange(updated);
  };
  return (
    <fieldset className="rule-fieldset">
      <legend>Request target</legend>
      <SelectInput
        label="Target kind"
        value={kind}
        options={[
          { value: 'contextless', label: 'Served by the gateway itself' },
          { value: 'mcp_alias', label: 'MCP endpoint alias' },
          { value: 'proxy_dispatch', label: 'Proxied to an upstream' },
        ]}
        hint="Routing facts are hypothetical: an upstream origin is only compared with rule matchers and is never contacted."
        onChange={(next) =>
          onChange(
            next === 'contextless'
              ? undefined
              : next === 'mcp_alias'
                ? { kind: next, canonical_path: '/mcp' }
                : { kind: next, upstream_origin: '' },
          )
        }
      />
      {kind === 'mcp_alias' ? (
        <TextInput
          label="Canonical MCP path"
          value={text('canonical_path')}
          onChange={(next) => set('canonical_path', next)}
        />
      ) : null}
      {kind === 'proxy_dispatch' ? (
        <div className="studio-element-fields">
          <TextInput
            label="Upstream origin"
            value={text('upstream_origin')}
            hint="An http or https origin, or pool:<route id>. No credentials or path."
            onChange={(next) => set('upstream_origin', next)}
          />
          <TextInput label="Route id" value={text('route_id')} onChange={(next) => set('route_id', next)} />
          <TextInput
            label="Route host"
            value={text('route_host')}
            hint="Selects a virtual upstream: only a host-bound route can authorize it."
            onChange={(next) => set('route_host', next)}
          />
          <TextInput
            label="Route path prefix"
            value={text('route_path_prefix')}
            onChange={(next) => set('route_path_prefix', next)}
          />
        </div>
      ) : null}
    </fieldset>
  );
}

function PrincipalFields({
  principal,
  onChange,
}: {
  principal: unknown;
  onChange: (principal: JsonObject | 'anonymous') => void;
}) {
  const anonymousId = useId();
  const anonymous = principal === 'anonymous';
  const value = isJsonObject(principal) ? principal : {};
  const set = (member: string, next: unknown) => {
    const updated = { ...value };
    if (next === '' || next === undefined) delete updated[member];
    else updated[member] = next;
    onChange(updated);
  };
  return (
    <fieldset className="rule-fieldset">
      <legend>Hypothetical caller</legend>
      <div className="workbench-check">
        <input
          id={anonymousId}
          type="checkbox"
          checked={anonymous}
          onChange={(event) =>
            onChange(
              event.target.checked
                ? 'anonymous'
                : { subject: 'synthetic-caller', roles: [], auth_method: 'bearer_token' },
            )
          }
        />
        <label htmlFor={anonymousId}>Anonymous caller</label>
      </div>
      {anonymous ? null : (
        <div className="studio-element-fields">
          <TextInput
            label="Subject"
            value={typeof value.subject === 'string' ? value.subject : ''}
            hint="A synthetic identifier, not a real user's."
            onChange={(next) => set('subject', next)}
          />
          <TextInput
            label="Issuer"
            value={typeof value.issuer === 'string' ? value.issuer : ''}
            hint="Optional. Canonicalized as authentication does: a trailing / is dropped."
            onChange={(next) => set('issuer', next)}
          />
          <ListInput
            label="Caller roles"
            values={stringList(value.roles)}
            hint="Comma-separated role names."
            onChange={(roles) => set('roles', roles)}
          />
          <SelectInput
            label="Authentication method"
            value={typeof value.auth_method === 'string' ? value.auth_method : 'bearer_token'}
            options={AUTH_METHOD_OPTIONS}
            onChange={(next) => set('auth_method', next)}
          />
        </div>
      )}
    </fieldset>
  );
}

function ExpectationFields({
  kind,
  expect,
  onChange,
}: {
  kind: CaseKind;
  expect: unknown;
  onChange: (expect: JsonObject | undefined) => void;
}) {
  const value = isJsonObject(expect) ? expect : null;
  if (kind === 'rate') {
    const selected =
      value === null || !('rate_override' in value)
        ? ''
        : value.rate_override === null
          ? 'none'
          : 'position';
    return (
      <fieldset className="rule-fieldset">
        <legend>Expectation</legend>
        <div className="studio-element-fields">
          <SelectInput
            label="Expected rate override"
            value={selected}
            options={[
              { value: '', label: 'Not set: the test run refuses the case' },
              { value: 'none', label: 'No override' },
              { value: 'position', label: 'The override at a position' },
            ]}
            onChange={(next) =>
              onChange(
                next === ''
                  ? undefined
                  : { rate_override: next === 'none' ? null : 0 },
              )
            }
          />
          {selected === 'position' ? (
            <PositionInput
              label="Expected override position"
              value={value?.rate_override}
              onChange={(position) => onChange({ rate_override: position })}
            />
          ) : null}
        </div>
      </fieldset>
    );
  }

  const reasons: readonly string[] = kind === 'http' ? HTTP_REASONS : TOOL_REASONS;
  const matched = value?.matched;
  const matchKind =
    matched === undefined
      ? ''
      : matched === 'none'
        ? 'none'
        : isJsonObject(matched) && 'route' in matched
          ? 'route'
          : 'rule';
  const update = (member: string, next: unknown) => {
    if (value === null) return;
    const updated = { ...value };
    if (next === undefined || next === '') delete updated[member];
    else updated[member] = next;
    onChange(updated);
  };
  return (
    <fieldset className="rule-fieldset">
      <legend>Expectation</legend>
      <div className="studio-element-fields">
        <SelectInput
          label="Expected decision"
          value={typeof value?.logical === 'string' ? value.logical : ''}
          options={[
            { value: '', label: 'Not set: the test run refuses the case' },
            { value: 'allow', label: 'Allow' },
            { value: 'deny', label: 'Deny (a shadow rule’s would-deny included)' },
          ]}
          onChange={(next) =>
            next === '' ? onChange(undefined) : onChange({ ...(value ?? {}), logical: next })
          }
        />
        <SelectInput
          label="Expected effect"
          value={typeof value?.effect === 'string' ? value.effect : ''}
          disabled={value === null}
          options={[
            { value: '', label: 'Not asserted' },
            { value: 'allow', label: 'Allow: forwarded' },
            { value: 'block', label: 'Block: refused' },
            { value: 'observe', label: 'Observe: denied, but forwarded by shadow enforcement' },
          ]}
          onChange={(next) => update('effect', next)}
        />
        <SelectInput
          label="Expected reason"
          value={typeof value?.reason === 'string' ? value.reason : ''}
          disabled={value === null}
          options={[
            { value: '', label: 'Not asserted' },
            ...reasons.map((reason) => ({ value: reason, label: reason })),
          ]}
          onChange={(next) => update('reason', next)}
        />
        <SelectInput
          label="Expected match"
          value={matchKind}
          disabled={value === null}
          options={[
            { value: '', label: 'Not asserted' },
            { value: 'none', label: 'Nothing matched' },
            { value: 'rule', label: 'A direct rule' },
            ...(kind === 'http' ? [{ value: 'route', label: 'A route, by position' }] : []),
          ]}
          onChange={(next) =>
            update(
              'matched',
              next === ''
                ? undefined
                : next === 'none'
                  ? 'none'
                  : next === 'route'
                    ? { route: 0 }
                    : { rule: '' },
            )
          }
        />
        {matchKind === 'rule' && isJsonObject(matched) ? (
          <TextInput
            label="Expected rule"
            value={typeof matched.rule === 'string' ? matched.rule : ''}
            hint="The rule's id, or its position for a rule without one."
            onChange={(next) => update('matched', { rule: next })}
          />
        ) : null}
        {matchKind === 'route' && isJsonObject(matched) ? (
          <PositionInput
            label="Expected route position"
            value={matched.route}
            onChange={(position) => update('matched', { route: position })}
          />
        ) : null}
      </div>
    </fieldset>
  );
}

function TextInput({
  label,
  value,
  hint,
  suggestions,
  onChange,
}: {
  label: string;
  value: string;
  hint?: string;
  suggestions?: readonly string[];
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="rule-input"
        type="text"
        value={value}
        spellCheck={false}
        autoComplete="off"
        list={suggestions ? `${id}-suggestions` : undefined}
        aria-describedby={hint ? `${id}-hint` : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {suggestions ? (
        <datalist id={`${id}-suggestions`}>
          {suggestions.map((suggestion) => (
            <option key={suggestion} value={suggestion} />
          ))}
        </datalist>
      ) : null}
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

// A position edited as text: a whole number is stored as one, anything else
// as the text typed, so the gateway reports the member's type instead of the
// editor guessing a value.
function PositionInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: unknown;
  onChange: (value: number | string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="rule-input"
        type="text"
        inputMode="numeric"
        value={typeof value === 'number' ? String(value) : typeof value === 'string' ? value : ''}
        onChange={(event) => {
          const text = event.target.value.trim();
          onChange(/^(0|[1-9][0-9]{0,6})$/.test(text) ? Number(text) : text);
        }}
      />
    </div>
  );
}

// A list edited as comma-separated text. The text is kept as typed, so a
// trailing comma survives until the next name is written.
function ListInput({
  label,
  values,
  hint,
  onChange,
}: {
  label: string;
  values: readonly string[];
  hint?: string;
  onChange: (values: string[]) => void;
}) {
  const id = useId();
  const joined = values.join(', ');
  const [text, setText] = useState(joined);
  useEffect(() => {
    setText((current) => (splitList(current).join(', ') === joined ? current : joined));
  }, [joined]);
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="rule-input"
        type="text"
        value={text}
        spellCheck={false}
        autoComplete="off"
        aria-describedby={hint ? `${id}-hint` : undefined}
        onChange={(event) => {
          setText(event.target.value);
          onChange(splitList(event.target.value));
        }}
      />
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

function splitList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

export function SelectInput({
  label,
  value,
  options,
  hint,
  disabled = false,
  onChange,
}: {
  label: string;
  value: string;
  options: ReadonlyArray<{ value: string; label: string }>;
  hint?: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="rule-input"
        value={value}
        disabled={disabled}
        aria-describedby={hint ? `${id}-hint` : undefined}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}
