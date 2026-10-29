import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import type { PolicyDiagnostic } from '../../lib/policyDrafts';
import {
  AUTH_METHOD_OPTIONS,
  arrayMember,
  countBySeverity,
  diagnosticsWithin,
  grantedPermissions,
  isJsonObject,
  isPolicyV1,
  memberShapeIsEditable,
  moveItem,
  nextElementId,
  nextMemberName,
  objectMember,
  pointerTo,
  removeAt,
  renameMember,
  replaceAt,
  roleNames,
  severityBadge,
  severityLabel,
  stringList,
  withMember,
  type JsonObject,
} from './model';

// Registers the element that shows the value at a JSON Pointer, so a
// diagnostic can move focus to it.
export type FieldRegistrar = (
  pointer: string,
) => (element: HTMLElement | null) => void;

type SectionProps = {
  document: JsonObject;
  diagnostics: readonly PolicyDiagnostic[];
  disabled: boolean;
  register: FieldRegistrar;
  onChange: (next: JsonObject) => void;
};

const HTTP_METHOD_SUGGESTIONS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
];

const RULE_ACTIONS: ReadonlyArray<{
  value: string;
  label: string;
  description: string;
}> = [
  { value: 'allow', label: 'Allow', description: 'Forward matching requests.' },
  { value: 'deny', label: 'Deny', description: 'Reject matching requests.' },
  {
    value: 'shadow',
    label: 'Shadow',
    description: 'Forward, and record a would-deny decision.',
  },
];

export function OverviewSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
  conversion,
}: SectionProps & {
  conversion: ReactNode;
}) {
  const schemaVersion =
    typeof document.schema_version === 'string'
      ? document.schema_version
      : 'missing';
  const policyId = typeof document.id === 'string' ? document.id : '';

  return (
    <div className="studio-section-body">
      <div className="studio-schema-row">
        <span className="field-label">Schema version</span>
        <code
          className="studio-schema-version"
          ref={register(pointerTo('schema_version'))}
          tabIndex={-1}
        >
          {schemaVersion}
        </code>
        <span className={`badge ${isPolicyV1(document) ? 'success' : 'warning'}`}>
          {isPolicyV1(document) ? 'Policy v1' : 'Not policy v1'}
        </span>
      </div>
      <FieldProblems
        id="studio-schema-version-problems"
        diagnostics={diagnosticsWithin(diagnostics, pointerTo('schema_version'))}
      />
      {conversion}

      <TextField
        label="Policy id"
        pointer={pointerTo('id')}
        value={policyId}
        placeholder="production"
        hint="Optional. Names this document in history and evidence."
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(value) =>
          onChange(withMember(document, 'id', value === '' ? undefined : value))
        }
      />

      <ChoiceField
        legend="Default action"
        pointer={pointerTo('default_action')}
        value={
          typeof document.default_action === 'string'
            ? document.default_action
            : 'deny'
        }
        options={[
          {
            value: 'deny',
            label: 'Deny',
            description: 'Refuse a request no route or rule decides.',
          },
          {
            value: 'allow',
            label: 'Allow',
            description: 'Forward a request no route or rule decides.',
          },
        ]}
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(value) => onChange(withMember(document, 'default_action', value))}
      />

      <ChoiceField
        legend="Enforcement mode"
        pointer={pointerTo('enforcement_mode')}
        value={
          typeof document.enforcement_mode === 'string'
            ? document.enforcement_mode
            : 'enforce'
        }
        options={[
          {
            value: 'enforce',
            label: 'Enforce',
            description: 'A deny decision blocks the request.',
          },
          {
            value: 'shadow',
            label: 'Shadow',
            description:
              'A deny decision is recorded as would-deny and the request is forwarded.',
          },
        ]}
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(value) =>
          onChange(withMember(document, 'enforcement_mode', value))
        }
      />
    </div>
  );
}

export function RolesSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
}: SectionProps) {
  const addRef = useRef<HTMLButtonElement>(null);
  if (!memberShapeIsEditable(document, 'roles', 'object')) {
    return <ShapeNotice member="roles" />;
  }
  const roles = objectMember(document, 'roles');
  const names = Object.keys(roles);

  function updateRoles(next: JsonObject) {
    onChange(withMember(document, 'roles', next));
  }

  function updateRole(name: string, entry: JsonObject) {
    updateRoles({ ...roles, [name]: entry });
  }

  function addRole() {
    const name = nextMemberName(roles, 'role');
    updateRoles({ ...roles, [name]: { permissions: [] } });
  }

  function removeRole(name: string) {
    const next = { ...roles };
    delete next[name];
    updateRoles(next);
    addRef.current?.focus();
  }

  return (
    <div className="studio-section-body">
      <p className="rule-hint">
        A role grants permissions to principals whose verified roles name it.
        Renaming a role does not update the routes, rules or tools that name
        it.
      </p>
      {names.length === 0 ? (
        <div className="empty-state">This policy defines no roles.</div>
      ) : null}
      {names.map((name, index) => {
        const entry = isJsonObject(roles[name]) ? roles[name] : {};
        const pointer = pointerTo('roles', name);
        const label = `role ${name}`;
        return (
          <ElementCard
            key={index}
            title={`Role ${name}`}
            pointer={pointer}
            diagnostics={diagnostics}
            register={register}
            covered={[
              pointerTo('roles', name, 'permissions'),
              pointerTo('roles', name, 'issuers'),
              pointerTo('roles', name, 'auth_methods'),
              pointerTo('roles', name, 'description'),
            ]}
            tools={
              <button
                type="button"
                className="rule-danger-button"
                aria-label={`Remove ${label}`}
                disabled={disabled}
                onClick={() => removeRole(name)}
              >
                Remove
              </button>
            }
          >
            <MemberNameField
              label="Role name"
              name={name}
              existing={names}
              disabled={disabled}
              onRename={(next) => {
                const renamed = renameMember(roles, name, next);
                if (renamed !== null) updateRoles(renamed);
              }}
            />
            <TokenListField
              label="Permissions"
              pointer={pointerTo('roles', name, 'permissions')}
              values={stringList(entry.permissions)}
              placeholder="admin:policy:read"
              emptyText="No permissions"
              suggestions={grantedPermissions(document)}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) => updateRole(name, { ...entry, permissions: values })}
            />
            <TokenListField
              label="Issuers"
              pointer={pointerTo('roles', name, 'issuers')}
              values={stringList(entry.issuers)}
              placeholder="https://idp.example/"
              emptyText="Any issuer"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) =>
                updateRole(name, optionalList(entry, 'issuers', values))
              }
            />
            <AuthMethodsField
              legend="Auth methods"
              pointer={pointerTo('roles', name, 'auth_methods')}
              values={stringList(entry.auth_methods)}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) =>
                updateRole(name, optionalList(entry, 'auth_methods', values))
              }
            />
            <TextField
              label="Description"
              pointer={pointerTo('roles', name, 'description')}
              value={typeof entry.description === 'string' ? entry.description : ''}
              placeholder="Support staff, read-only"
              hint="Optional. Explains the role to maintainers; it grants nothing."
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(value) =>
                updateRole(
                  name,
                  withMember(entry, 'description', value === '' ? undefined : value),
                )
              }
            />
          </ElementCard>
        );
      })}
      <div className="form-actions">
        <button
          ref={addRef}
          type="button"
          className="secondary-button"
          disabled={disabled}
          onClick={addRole}
        >
          Add role
        </button>
      </div>
    </div>
  );
}

export function RoutesSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
}: SectionProps) {
  const list = useOrderedList(document, 'routes', onChange);
  if (!memberShapeIsEditable(document, 'routes', 'array')) {
    return <ShapeNotice member="routes" />;
  }
  const routes = arrayMember(document, 'routes');
  const permissions = grantedPermissions(document);

  return (
    <div className="studio-section-body" ref={list.containerRef}>
      <p className="rule-hint">
        Routes are evaluated top to bottom; the first route whose method, host
        and path prefix match decides which permission a request needs.
      </p>
      {routes.length === 0 ? (
        <div className="empty-state">This policy defines no routes.</div>
      ) : null}
      {routes.map((value, index) => {
        const route = isJsonObject(value) ? value : {};
        const routeId = typeof route.id === 'string' ? route.id : '';
        const pointer = pointerTo('routes', index);
        const label = `route ${routeId || index + 1}`;
        const update = (next: JsonObject) => list.replace(index, next);
        return (
          <ElementCard
            key={index}
            title={`#${index + 1} ${routeId || 'Route without id'}`}
            pointer={pointer}
            diagnostics={diagnostics}
            register={register}
            covered={['id', 'path_prefix', 'permission', 'methods', 'hosts', 'enforcement_mode'].map(
              (member) => pointerTo('routes', index, member),
            )}
            tools={
              <OrderTools
                label={label}
                index={index}
                count={routes.length}
                focusPrefix={pointer}
                disabled={disabled}
                onMove={list.move}
                onRemove={list.remove}
              />
            }
          >
            <TextField
              label="Id"
              pointer={pointerTo('routes', index, 'id')}
              value={routeId}
              placeholder="billing-read"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...route, id: next })}
            />
            <TextField
              label="Path prefix"
              pointer={pointerTo('routes', index, 'path_prefix')}
              value={typeof route.path_prefix === 'string' ? route.path_prefix : ''}
              placeholder="/billing/"
              hint="Matched with starts-with against the request path."
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...route, path_prefix: next })}
            />
            <TextField
              label="Required permission"
              pointer={pointerTo('routes', index, 'permission')}
              value={typeof route.permission === 'string' ? route.permission : ''}
              placeholder="billing:read"
              suggestions={permissions}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...route, permission: next })}
            />
            <TokenListField
              label="Methods"
              pointer={pointerTo('routes', index, 'methods')}
              values={stringList(route.methods)}
              placeholder="GET"
              emptyText="Any method"
              suggestions={HTTP_METHOD_SUGGESTIONS}
              normalize={(method) => method.toUpperCase()}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) => update({ ...route, methods: values })}
            />
            <TokenListField
              label="Hosts"
              pointer={pointerTo('routes', index, 'hosts')}
              values={stringList(route.hosts)}
              placeholder="api.example.com"
              emptyText="Routes without a host qualifier"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) => update(optionalList(route, 'hosts', values))}
            />
            <SelectField
              label="Enforcement mode"
              pointer={pointerTo('routes', index, 'enforcement_mode')}
              value={
                typeof route.enforcement_mode === 'string'
                  ? route.enforcement_mode
                  : ''
              }
              options={[
                { value: '', label: 'Policy default' },
                { value: 'enforce', label: 'Enforce' },
                { value: 'shadow', label: 'Shadow' },
              ]}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) =>
                update(
                  withMember(route, 'enforcement_mode', next === '' ? undefined : next),
                )
              }
            />
          </ElementCard>
        );
      })}
      <div className="form-actions">
        <button
          ref={list.addRef}
          type="button"
          className="secondary-button"
          disabled={disabled}
          onClick={() =>
            list.append({
              id: nextElementId(document, 'route'),
              methods: [],
              path_prefix: '/',
              permission: '',
            })
          }
        >
          Add route
        </button>
      </div>
    </div>
  );
}

export function RulesSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
}: SectionProps) {
  const list = useOrderedList(document, 'rules', onChange);
  if (!memberShapeIsEditable(document, 'rules', 'array')) {
    return <ShapeNotice member="rules" />;
  }
  const rules = arrayMember(document, 'rules');
  const roles = roleNames(document);

  return (
    <div className="studio-section-body" ref={list.containerRef}>
      <p className="rule-hint">
        HTTP path rules and MCP tool-name rules are each evaluated top to
        bottom; the first match of its kind wins. A disabled rule is skipped as
        if it were absent.
      </p>
      {rules.length === 0 ? (
        <div className="empty-state">This policy defines no direct rules.</div>
      ) : null}
      {rules.map((value, index) => {
        const rule = isJsonObject(value) ? value : {};
        const ruleId = typeof rule.id === 'string' ? rule.id : '';
        const pointer = pointerTo('rules', index);
        const label = `rule ${ruleId || index + 1}`;
        const isTool = typeof rule.tool_name === 'string';
        const hasDispatch = rule.dispatch !== undefined;
        const principal = isJsonObject(rule.principal) ? rule.principal : {};
        const update = (next: JsonObject) => list.replace(index, next);
        return (
          <ElementCard
            key={index}
            title={`#${index + 1} ${ruleId || 'Rule without id'}`}
            subtitle={
              <span className={`badge ${rule.enabled === false ? 'neutral' : 'success'}`}>
                {rule.enabled === false ? 'Disabled' : 'Enabled'}
              </span>
            }
            pointer={pointer}
            diagnostics={diagnostics}
            register={register}
            covered={[
              'id',
              'enabled',
              'methods',
              'path',
              'tool_name',
              'principal',
              'action',
            ].map((member) => pointerTo('rules', index, member))}
            tools={
              <OrderTools
                label={label}
                index={index}
                count={rules.length}
                focusPrefix={pointer}
                disabled={disabled}
                onMove={list.move}
                onRemove={list.remove}
              />
            }
          >
            <TextField
              label="Id"
              pointer={pointerTo('rules', index, 'id')}
              value={ruleId}
              placeholder="allow-billing-read"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...rule, id: next })}
            />
            <CheckboxField
              label="Enabled"
              pointer={pointerTo('rules', index, 'enabled')}
              checked={rule.enabled !== false}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(checked) =>
                update(withMember(rule, 'enabled', checked ? undefined : false))
              }
            />
            <ChoiceField
              legend="Rule target"
              pointer={pointerTo('rules', index, isTool ? 'tool_name' : 'path')}
              value={isTool ? 'tool' : 'path'}
              options={[
                {
                  value: 'path',
                  label: 'HTTP path',
                  description: 'Inbound requests and rendered tool HTTP operations.',
                },
                {
                  value: 'tool',
                  label: 'MCP tool',
                  description: hasDispatch
                    ? 'Unavailable while the rule is bound to a dispatch context.'
                    : 'MCP tool calls with this exact name.',
                  disabled: hasDispatch,
                },
              ]}
              disabled={disabled}
              diagnostics={[]}
              register={() => () => undefined}
              onChange={(target) => {
                if (target === 'tool') {
                  const next = withMember(withMember(rule, 'path', undefined), 'methods', []);
                  update({ ...next, tool_name: '' });
                } else {
                  update({ ...withMember(rule, 'tool_name', undefined), path: '/' });
                }
              }}
            />
            {isTool ? (
              <TextField
                label="Tool name"
                pointer={pointerTo('rules', index, 'tool_name')}
                value={String(rule.tool_name)}
                placeholder="reports.export"
                hint="Matches one exact MCP tool name."
                disabled={disabled}
                diagnostics={diagnostics}
                register={register}
                onChange={(next) => update({ ...rule, tool_name: next })}
              />
            ) : (
              <>
                <TokenListField
                  label="Methods"
                  pointer={pointerTo('rules', index, 'methods')}
                  values={stringList(rule.methods)}
                  placeholder="GET"
                  emptyText="Any method"
                  suggestions={HTTP_METHOD_SUGGESTIONS}
                  normalize={(method) => method.toUpperCase()}
                  disabled={disabled}
                  diagnostics={diagnostics}
                  register={register}
                  onChange={(values) => update({ ...rule, methods: values })}
                />
                <TextField
                  label="Path pattern"
                  pointer={pointerTo('rules', index, 'path')}
                  value={typeof rule.path === 'string' ? rule.path : ''}
                  placeholder="/api/users/{id}"
                  hint="Segment-based and anchored: * is one segment, ** zero or more, {name} one named segment."
                  disabled={disabled}
                  diagnostics={diagnostics}
                  register={register}
                  onChange={(next) => update({ ...rule, path: next })}
                />
              </>
            )}
            {hasDispatch ? (
              <DispatchSummary
                dispatch={rule.dispatch}
                pointer={pointerTo('rules', index, 'dispatch')}
                diagnostics={diagnostics}
                register={register}
              />
            ) : null}
            <PrincipalFields
              pointer={pointerTo('rules', index, 'principal')}
              principal={principal}
              roleSuggestions={roles}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...rule, principal: next })}
            />
            <ChoiceField
              legend="Action"
              pointer={pointerTo('rules', index, 'action')}
              value={typeof rule.action === 'string' ? rule.action : ''}
              options={RULE_ACTIONS}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...rule, action: next })}
            />
          </ElementCard>
        );
      })}
      <div className="form-actions">
        <button
          ref={list.addRef}
          type="button"
          className="secondary-button"
          disabled={disabled}
          onClick={() =>
            list.append({
              id: nextElementId(document, 'rule'),
              methods: [],
              path: '/',
              principal: {},
              action: 'deny',
            })
          }
        >
          Add rule
        </button>
      </div>
    </div>
  );
}

export function ToolsSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
}: SectionProps) {
  const addRef = useRef<HTMLButtonElement>(null);
  if (!memberShapeIsEditable(document, 'tools', 'object')) {
    return <ShapeNotice member="tools" />;
  }
  const tools = objectMember(document, 'tools');
  const names = Object.keys(tools);
  const roles = roleNames(document);

  function updateTools(next: JsonObject) {
    onChange(
      withMember(document, 'tools', Object.keys(next).length === 0 ? undefined : next),
    );
  }

  function updateTool(name: string, entry: JsonObject) {
    updateTools({ ...tools, [name]: entry });
  }

  function removeTool(name: string) {
    const next = { ...tools };
    delete next[name];
    updateTools(next);
    addRef.current?.focus();
  }

  return (
    <div className="studio-section-body">
      <p className="rule-hint">
        Per-tool admission for MCP tool calls: whether a tool is enabled, who
        may call it, and how long and how often it may run. Direct tool-name
        rules still apply on top of it.
      </p>
      {names.length === 0 ? (
        <div className="empty-state">This policy sets no per-tool policy.</div>
      ) : null}
      {names.map((name, index) => {
        const entry = isJsonObject(tools[name]) ? tools[name] : {};
        const pointer = pointerTo('tools', name);
        return (
          <ElementCard
            key={index}
            title={`Tool ${name}`}
            subtitle={
              <span className={`badge ${entry.enabled === false ? 'neutral' : 'success'}`}>
                {entry.enabled === false ? 'Disabled' : 'Enabled'}
              </span>
            }
            pointer={pointer}
            diagnostics={diagnostics}
            register={register}
            covered={[
              'enabled',
              'allowed_roles',
              'issuers',
              'auth_methods',
              'timeout_ms',
              'max_concurrent',
            ].map((member) => pointerTo('tools', name, member))}
            tools={
              <button
                type="button"
                className="rule-danger-button"
                aria-label={`Remove tool ${name}`}
                disabled={disabled}
                onClick={() => removeTool(name)}
              >
                Remove
              </button>
            }
          >
            <MemberNameField
              label="Tool name"
              name={name}
              existing={names}
              disabled={disabled}
              onRename={(next) => {
                const renamed = renameMember(tools, name, next);
                if (renamed !== null) updateTools(renamed);
              }}
            />
            <CheckboxField
              label="Enabled"
              pointer={pointerTo('tools', name, 'enabled')}
              checked={entry.enabled !== false}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(checked) => updateTool(name, { ...entry, enabled: checked })}
            />
            <TokenListField
              label="Allowed roles"
              pointer={pointerTo('tools', name, 'allowed_roles')}
              values={stringList(entry.allowed_roles)}
              placeholder="support"
              emptyText="No role constraint beyond enabled"
              suggestions={roles}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) => updateTool(name, { ...entry, allowed_roles: values })}
            />
            <TokenListField
              label="Issuers"
              pointer={pointerTo('tools', name, 'issuers')}
              values={stringList(entry.issuers)}
              placeholder="https://idp.example/"
              emptyText="Any issuer"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) =>
                updateTool(name, optionalList(entry, 'issuers', values))
              }
            />
            <AuthMethodsField
              legend="Auth methods"
              pointer={pointerTo('tools', name, 'auth_methods')}
              values={stringList(entry.auth_methods)}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) =>
                updateTool(name, optionalList(entry, 'auth_methods', values))
              }
            />
            <NumberField
              label="Timeout (ms)"
              pointer={pointerTo('tools', name, 'timeout_ms')}
              value={entry.timeout_ms}
              placeholder="30000"
              hint="Leave empty for the gateway default."
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => updateTool(name, withMember(entry, 'timeout_ms', next))}
            />
            <NumberField
              label="Maximum concurrent calls"
              pointer={pointerTo('tools', name, 'max_concurrent')}
              value={entry.max_concurrent}
              placeholder="16"
              hint="Leave empty for the gateway default."
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) =>
                updateTool(name, withMember(entry, 'max_concurrent', next))
              }
            />
          </ElementCard>
        );
      })}
      <div className="form-actions">
        <button
          ref={addRef}
          type="button"
          className="secondary-button"
          disabled={disabled}
          onClick={() =>
            updateTools({
              ...tools,
              [nextMemberName(tools, 'tool')]: { enabled: true, allowed_roles: [] },
            })
          }
        >
          Add tool policy
        </button>
      </div>
    </div>
  );
}

export function RateLimitsSection({
  document,
  diagnostics,
  disabled,
  register,
  onChange,
}: SectionProps) {
  const list = useOrderedList(document, 'rate_limits', onChange, true);
  if (!memberShapeIsEditable(document, 'rate_limits', 'array')) {
    return <ShapeNotice member="rate_limits" />;
  }
  const overrides = arrayMember(document, 'rate_limits');
  const roles = roleNames(document);

  return (
    <div className="studio-section-body" ref={list.containerRef}>
      <p className="rule-hint">
        Overrides are evaluated top to bottom and the first match applies, to
        authenticated requests only. They are layered on the global
        RATE_LIMIT_READ_* and RATE_LIMIT_WRITE_* lanes, which still apply to
        every request.
      </p>
      {overrides.length === 0 ? (
        <div className="empty-state">This policy sets no rate-limit overrides.</div>
      ) : null}
      {overrides.map((value, index) => {
        const override = isJsonObject(value) ? value : {};
        const overrideId = typeof override.id === 'string' ? override.id : '';
        const pointer = pointerTo('rate_limits', index);
        const label = `rate limit ${overrideId || index + 1}`;
        const principal = isJsonObject(override.principal) ? override.principal : {};
        const update = (next: JsonObject) => list.replace(index, next);
        return (
          <ElementCard
            key={index}
            title={`#${index + 1} ${overrideId || 'Override without id'}`}
            pointer={pointer}
            diagnostics={diagnostics}
            register={register}
            covered={[
              'id',
              'path',
              'methods',
              'principal',
              'requests_per_second',
              'burst',
            ].map((member) => pointerTo('rate_limits', index, member))}
            tools={
              <OrderTools
                label={label}
                index={index}
                count={overrides.length}
                focusPrefix={pointer}
                disabled={disabled}
                onMove={list.move}
                onRemove={list.remove}
              />
            }
          >
            <TextField
              label="Id"
              pointer={pointerTo('rate_limits', index, 'id')}
              value={overrideId}
              placeholder="partner-burst"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...override, id: next })}
            />
            <TextField
              label="Path pattern"
              pointer={pointerTo('rate_limits', index, 'path')}
              value={typeof override.path === 'string' ? override.path : ''}
              placeholder="/api/**"
              hint="Optional. Leave empty to match any path."
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) =>
                update(withMember(override, 'path', next === '' ? undefined : next))
              }
            />
            <TokenListField
              label="Methods"
              pointer={pointerTo('rate_limits', index, 'methods')}
              values={stringList(override.methods)}
              placeholder="POST"
              emptyText="Any method"
              suggestions={HTTP_METHOD_SUGGESTIONS}
              normalize={(method) => method.toUpperCase()}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(values) => update({ ...override, methods: values })}
            />
            <PrincipalFields
              pointer={pointerTo('rate_limits', index, 'principal')}
              principal={principal}
              roleSuggestions={roles}
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update({ ...override, principal: next })}
            />
            <NumberField
              label="Requests per second"
              pointer={pointerTo('rate_limits', index, 'requests_per_second')}
              value={override.requests_per_second}
              placeholder="10"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) =>
                update(withMember(override, 'requests_per_second', next))
              }
            />
            <NumberField
              label="Burst"
              pointer={pointerTo('rate_limits', index, 'burst')}
              value={override.burst}
              placeholder="20"
              disabled={disabled}
              diagnostics={diagnostics}
              register={register}
              onChange={(next) => update(withMember(override, 'burst', next))}
            />
          </ElementCard>
        );
      })}
      <div className="form-actions">
        <button
          ref={list.addRef}
          type="button"
          className="secondary-button"
          disabled={disabled}
          onClick={() =>
            list.append({
              id: nextElementId(document, 'rate'),
              methods: [],
              principal: {},
              requests_per_second: 10,
              burst: 20,
            })
          }
        >
          Add rate-limit override
        </button>
      </div>
    </div>
  );
}

// Egress is shown, never edited: the policy API refuses an egress change
// (it needs a POLICY_FILE edit and a restart), so an editor here could only
// produce drafts that cannot be saved.
export function EgressSection({
  document,
  diagnostics,
  register,
  changed,
}: {
  document: JsonObject;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  changed: boolean;
}) {
  const egress = objectMember(document, 'egress');
  const lists: ReadonlyArray<{ member: string; label: string; empty: string }> = [
    { member: 'hosts', label: 'Host patterns', empty: 'No policy host patterns' },
    { member: 'cidrs', label: 'CIDR ranges', empty: 'No policy CIDR ranges' },
    { member: 'ports', label: 'Ports', empty: 'Any port' },
  ];

  return (
    <div className="studio-section-body">
      <div className="error-panel alert info" role="note">
        <h3>Read-only here</h3>
        <p>
          Policy egress rules are layered on EGRESS_ALLOWED_HOSTS. The policy
          API cannot change them: edit POLICY_FILE and restart the gateway.
          A draft that changes egress is refused when it is saved or published.
        </p>
      </div>
      {changed ? (
        <div className="error-panel alert warning" role="alert">
          <h3>This draft changes egress</h3>
          <p>
            Its egress rules differ from the live policy, so the gateway will
            refuse to save or publish it. Restore the live egress rules in
            Source.
          </p>
        </div>
      ) : null}
      {!memberShapeIsEditable(document, 'egress', 'object') ? (
        <ShapeNotice member="egress" />
      ) : (
        <dl className="studio-readonly-list">
          {lists.map(({ member, label, empty }) => {
            const values = Array.isArray(egress[member])
              ? (egress[member] as unknown[]).map((entry) => String(entry))
              : [];
            return (
              <div
                key={member}
                ref={register(pointerTo('egress', member))}
                tabIndex={-1}
              >
                <dt>{label}</dt>
                <dd>
                  {values.length === 0 ? (
                    <span className="badge neutral">{empty}</span>
                  ) : (
                    values.map((entry, index) => (
                      <code className="rule-chip" key={index}>
                        {entry}
                      </code>
                    ))
                  )}
                </dd>
              </div>
            );
          })}
        </dl>
      )}
      <FieldProblems
        id="studio-egress-problems"
        diagnostics={diagnosticsWithin(diagnostics, pointerTo('egress'))}
      />
    </div>
  );
}

export function SourceSection({
  source,
  parseError,
  disabled,
  register,
  onChange,
}: {
  source: string;
  parseError: string | null;
  disabled: boolean;
  register: FieldRegistrar;
  onChange: (source: string) => void;
}) {
  const id = useId();
  return (
    <div className="studio-section-body">
      <label className="field-label" htmlFor={id}>
        Policy document (JSON)
      </label>
      <textarea
        id={id}
        ref={register('')}
        className={`studio-source ${parseError ? 'is-error' : ''}`}
        value={source}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        readOnly={disabled}
        aria-invalid={parseError ? true : undefined}
        aria-describedby={`${id}-hint`}
        onChange={(event) => onChange(event.target.value)}
      />
      <p className={`rule-hint ${parseError ? 'is-error' : ''}`} id={`${id}-hint`}>
        {parseError ??
          'The gateway validates exactly this text, and saves it as the draft candidate.'}
      </p>
    </div>
  );
}

function PrincipalFields({
  pointer,
  principal,
  roleSuggestions,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  pointer: string;
  principal: JsonObject;
  roleSuggestions: string[];
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (next: JsonObject) => void;
}) {
  const legendId = useId();
  return (
    <fieldset
      className="rule-fieldset studio-principal"
      aria-labelledby={legendId}
      ref={register(pointer)}
      tabIndex={-1}
    >
      <legend id={legendId}>Principal constraints</legend>
      <p className="rule-hint">Leave a list empty to match any value.</p>
      <TokenListField
        label="Roles"
        pointer={`${pointer}/roles`}
        values={stringList(principal.roles)}
        placeholder="support"
        emptyText="Any role"
        suggestions={roleSuggestions}
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(values) => onChange({ ...principal, roles: values })}
      />
      <TokenListField
        label="Issuers"
        pointer={`${pointer}/issuers`}
        values={stringList(principal.issuers)}
        placeholder="https://idp.example/"
        emptyText="Any issuer"
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(values) => onChange({ ...principal, issuers: values })}
      />
      <AuthMethodsField
        legend="Auth methods"
        pointer={`${pointer}/auth_methods`}
        values={stringList(principal.auth_methods)}
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(values) => onChange({ ...principal, auth_methods: values })}
      />
      <TokenListField
        label="Principal ids"
        pointer={`${pointer}/principal_ids`}
        values={stringList(principal.principal_ids)}
        placeholder="user-123"
        emptyText="Any principal id"
        disabled={disabled}
        diagnostics={diagnostics}
        register={register}
        onChange={(values) => onChange({ ...principal, principal_ids: values })}
      />
    </fieldset>
  );
}

function DispatchSummary({
  dispatch,
  pointer,
  diagnostics,
  register,
}: {
  dispatch: unknown;
  pointer: string;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
}) {
  const value = isJsonObject(dispatch) ? dispatch : {};
  const summary =
    value.kind === 'route' && typeof value.route_id === 'string'
      ? `Only requests dispatched to upstream route ${value.route_id}.`
      : value.kind === 'legacy' && typeof value.upstream_origin === 'string'
        ? `Only requests dispatched to the fallback upstream ${value.upstream_origin}.`
        : value.kind === 'contextless'
          ? 'Only requests classified without proxy dispatch.'
          : 'A dispatch binding this editor cannot describe.';
  return (
    <div className="rule-field" ref={register(pointer)} tabIndex={-1}>
      <span className="field-label">Dispatch binding</span>
      <p className="body-copy">{summary}</p>
      <p className="rule-hint">Change or remove the dispatch binding in Source.</p>
      <FieldProblems
        id={`${pointer}-problems`}
        diagnostics={diagnosticsWithin(diagnostics, pointer)}
      />
    </div>
  );
}

function ElementCard({
  title,
  subtitle,
  pointer,
  diagnostics,
  register,
  covered,
  tools,
  children,
}: {
  title: string;
  subtitle?: ReactNode;
  pointer: string;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  covered: readonly string[];
  tools: ReactNode;
  children: ReactNode;
}) {
  const headingId = useId();
  const within = diagnosticsWithin(diagnostics, pointer);
  // What no field of the card shows: the element as a whole, or a member
  // only Source edits.
  const uncovered = within.filter(
    (diagnostic) =>
      !covered.some(
        (field) =>
          diagnostic.pointer === field ||
          diagnostic.pointer.startsWith(`${field}/`),
      ),
  );
  const counts = countBySeverity(within);

  return (
    <article
      className={`studio-element ${counts.errors > 0 ? 'has-error' : ''}`}
      aria-labelledby={headingId}
      ref={register(pointer)}
      tabIndex={-1}
    >
      <header className="studio-element-head">
        <h4 id={headingId}>{title}</h4>
        {subtitle}
        {counts.errors > 0 ? (
          <span className="badge danger">
            {counts.errors} {counts.errors === 1 ? 'error' : 'errors'}
          </span>
        ) : null}
        {counts.warnings > 0 ? (
          <span className="badge warning">
            {counts.warnings} {counts.warnings === 1 ? 'warning' : 'warnings'}
          </span>
        ) : null}
        {counts.risks > 0 ? (
          <span className="badge neutral">
            {counts.risks} {counts.risks === 1 ? 'risk' : 'risks'}
          </span>
        ) : null}
        <div className="studio-element-tools">{tools}</div>
      </header>
      <FieldProblems id={`${headingId}-problems`} diagnostics={uncovered} />
      <div className="studio-element-fields">{children}</div>
    </article>
  );
}

function OrderTools({
  label,
  index,
  count,
  focusPrefix,
  disabled,
  onMove,
  onRemove,
}: {
  label: string;
  index: number;
  count: number;
  focusPrefix: string;
  disabled: boolean;
  onMove: (from: number, to: number) => void;
  onRemove: (index: number) => void;
}) {
  return (
    <>
      <button
        type="button"
        className="secondary-button"
        aria-label={`Move ${label} up`}
        data-studio-focus={`${focusPrefix}:up`}
        disabled={disabled || index === 0}
        onClick={() => onMove(index, index - 1)}
      >
        Up
      </button>
      <button
        type="button"
        className="secondary-button"
        aria-label={`Move ${label} down`}
        data-studio-focus={`${focusPrefix}:down`}
        disabled={disabled || index === count - 1}
        onClick={() => onMove(index, index + 1)}
      >
        Down
      </button>
      <button
        type="button"
        className="rule-danger-button"
        aria-label={`Remove ${label}`}
        disabled={disabled}
        onClick={() => onRemove(index)}
      >
        Remove
      </button>
    </>
  );
}

// Editing an ordered member, keeping keyboard focus with the element that
// moved (the cards are keyed by position, since ids are editable).
function useOrderedList(
  document: JsonObject,
  member: string,
  onChange: (next: JsonObject) => void,
  omitWhenEmpty = false,
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const addRef = useRef<HTMLButtonElement>(null);
  const [pendingFocus, setPendingFocus] = useState<string | null>(null);
  const items = arrayMember(document, member);

  useLayoutEffect(() => {
    if (pendingFocus === null) {
      return;
    }
    setPendingFocus(null);
    const target = containerRef.current?.querySelector<HTMLElement>(
      `[data-studio-focus="${pendingFocus}"]`,
    );
    if (target && !(target as HTMLButtonElement).disabled) {
      target.focus();
      return;
    }
    // At the end of the list the same direction is disabled; the other one
    // still belongs to the moved element.
    const [prefix, direction] = pendingFocus.split(':');
    const other = direction === 'up' ? 'down' : 'up';
    containerRef.current
      ?.querySelector<HTMLElement>(`[data-studio-focus="${prefix}:${other}"]`)
      ?.focus();
  }, [pendingFocus]);

  function write(next: unknown[]) {
    onChange(
      withMember(document, member, omitWhenEmpty && next.length === 0 ? undefined : next),
    );
  }

  return {
    containerRef,
    addRef,
    replace(index: number, item: JsonObject) {
      write(replaceAt(items, index, item));
    },
    append(item: JsonObject) {
      write([...items, item]);
    },
    move(from: number, to: number) {
      write(moveItem(items, from, to));
      setPendingFocus(`${pointerTo(member, to)}:${to < from ? 'up' : 'down'}`);
    },
    remove(index: number) {
      write(removeAt(items, index));
      addRef.current?.focus();
    },
  };
}

function TextField({
  label,
  pointer,
  value,
  placeholder,
  hint,
  suggestions,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  label: string;
  pointer: string;
  value: string;
  placeholder?: string;
  hint?: string;
  suggestions?: readonly string[];
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (value: string) => void;
}) {
  const id = useId();
  const problems = diagnosticsWithin(diagnostics, pointer);
  const hasError = problems.some((problem) => problem.severity === 'error');
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        ref={register(pointer)}
        className={`rule-input ${hasError ? 'is-error' : ''}`}
        type="text"
        value={value}
        placeholder={placeholder}
        list={suggestions && suggestions.length > 0 ? `${id}-suggestions` : undefined}
        spellCheck={false}
        disabled={disabled}
        aria-invalid={hasError ? true : undefined}
        aria-describedby={describedBy(id, Boolean(hint), problems.length > 0)}
        onChange={(event) => onChange(event.target.value)}
      />
      {suggestions && suggestions.length > 0 ? (
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
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </div>
  );
}

// A numeric member edited as text, so a half-typed "1." survives. Text
// that is not a number is kept as a string: the gateway then reports the
// member's type instead of the editor guessing a value.
function NumberField({
  label,
  pointer,
  value,
  placeholder,
  hint,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  label: string;
  pointer: string;
  value: unknown;
  placeholder?: string;
  hint?: string;
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (value: number | string | undefined) => void;
}) {
  const id = useId();
  const [text, setText] = useState(() => numberText(value));
  const problems = diagnosticsWithin(diagnostics, pointer);
  const hasError = problems.some((problem) => problem.severity === 'error');

  useEffect(() => {
    setText((current) => (numberValue(current) === value ? current : numberText(value)));
  }, [value]);

  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        ref={register(pointer)}
        className={`rule-input ${hasError ? 'is-error' : ''}`}
        type="text"
        inputMode="decimal"
        value={text}
        placeholder={placeholder}
        spellCheck={false}
        disabled={disabled}
        aria-invalid={hasError ? true : undefined}
        aria-describedby={describedBy(id, Boolean(hint), problems.length > 0)}
        onChange={(event) => {
          setText(event.target.value);
          onChange(numberValue(event.target.value));
        }}
      />
      {hint ? (
        <p className="rule-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </div>
  );
}

function numberText(value: unknown): string {
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value;
  return '';
}

function numberValue(text: string): number | string | undefined {
  const trimmed = text.trim();
  if (trimmed === '') {
    return undefined;
  }
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : text;
}

function SelectField({
  label,
  pointer,
  value,
  options,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  label: string;
  pointer: string;
  value: string;
  options: ReadonlyArray<{ value: string; label: string }>;
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (value: string) => void;
}) {
  const id = useId();
  const problems = diagnosticsWithin(diagnostics, pointer);
  const known = options.some((option) => option.value === value);
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        ref={register(pointer)}
        className="rule-input"
        value={value}
        disabled={disabled}
        aria-describedby={describedBy(id, false, problems.length > 0)}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
        {known ? null : <option value={value}>{value}</option>}
      </select>
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </div>
  );
}

function ChoiceField({
  legend,
  pointer,
  value,
  options,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  legend: string;
  pointer: string;
  value: string;
  options: ReadonlyArray<{
    value: string;
    label: string;
    description: string;
    disabled?: boolean;
  }>;
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (value: string) => void;
}) {
  const name = useId();
  const problems = diagnosticsWithin(diagnostics, pointer);
  return (
    <fieldset
      className="rule-fieldset"
      ref={register(pointer)}
      tabIndex={-1}
      aria-describedby={problems.length > 0 ? `${name}-problems` : undefined}
    >
      <legend>{legend}</legend>
      <div className="studio-choice-grid">
        {options.map((option) => (
          <label
            className={`studio-choice ${value === option.value ? 'is-selected' : ''}`}
            key={option.value}
          >
            <input
              type="radio"
              className="rule-radio"
              name={name}
              value={option.value}
              checked={value === option.value}
              disabled={disabled || option.disabled === true}
              onChange={() => onChange(option.value)}
            />
            <span className="studio-choice-label">{option.label}</span>
            <span className="rule-hint">{option.description}</span>
          </label>
        ))}
      </div>
      <FieldProblems id={`${name}-problems`} diagnostics={problems} />
    </fieldset>
  );
}

function CheckboxField({
  label,
  pointer,
  checked,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  label: string;
  pointer: string;
  checked: boolean;
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (checked: boolean) => void;
}) {
  const id = useId();
  const problems = diagnosticsWithin(diagnostics, pointer);
  return (
    <div className="rule-field">
      <label className="rule-check-row" htmlFor={id}>
        <input
          id={id}
          ref={register(pointer)}
          type="checkbox"
          className="rule-checkbox"
          checked={checked}
          disabled={disabled}
          aria-describedby={describedBy(id, false, problems.length > 0)}
          onChange={(event) => onChange(event.target.checked)}
        />
        {label}
      </label>
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </div>
  );
}

function AuthMethodsField({
  legend,
  pointer,
  values,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  legend: string;
  pointer: string;
  values: string[];
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (values: string[]) => void;
}) {
  const id = useId();
  const problems = diagnosticsWithin(diagnostics, pointer);
  // A value the editor does not know is kept as it is, so toggling a known
  // method never drops it; the gateway reports it if it is invalid.
  const unknown = values.filter(
    (value) => !AUTH_METHOD_OPTIONS.some((option) => option.value === value),
  );
  return (
    <fieldset
      className="rule-fieldset"
      ref={register(pointer)}
      tabIndex={-1}
      aria-describedby={problems.length > 0 ? `${id}-problems` : undefined}
    >
      <legend>{legend}</legend>
      <div className="rule-check-grid two-column">
        {AUTH_METHOD_OPTIONS.map((option) => (
          <label className="rule-check-row" key={option.value}>
            <input
              type="checkbox"
              className="rule-checkbox"
              checked={values.includes(option.value)}
              disabled={disabled}
              onChange={(event) =>
                onChange(
                  event.target.checked
                    ? [...values, option.value]
                    : values.filter((value) => value !== option.value),
                )
              }
            />
            {option.label}
          </label>
        ))}
      </div>
      {unknown.length > 0 ? (
        <p className="rule-hint">Also listed: {unknown.join(', ')}</p>
      ) : null}
      <p className="rule-hint">Leave every method unchecked for any auth method.</p>
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </fieldset>
  );
}

function TokenListField({
  label,
  pointer,
  values,
  placeholder,
  emptyText,
  suggestions,
  normalize,
  disabled,
  diagnostics,
  register,
  onChange,
}: {
  label: string;
  pointer: string;
  values: string[];
  placeholder: string;
  emptyText: string;
  suggestions?: readonly string[];
  normalize?: (value: string) => string;
  disabled: boolean;
  diagnostics: readonly PolicyDiagnostic[];
  register: FieldRegistrar;
  onChange: (values: string[]) => void;
}) {
  const id = useId();
  const [draft, setDraft] = useState('');
  const problems = diagnosticsWithin(diagnostics, pointer);
  const hasError = problems.some((problem) => problem.severity === 'error');

  function add() {
    const trimmed = draft.trim();
    if (trimmed.length === 0) {
      return;
    }
    const value = normalize ? normalize(trimmed) : trimmed;
    if (!values.includes(value)) {
      onChange([...values, value]);
    }
    setDraft('');
  }

  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <div className="rule-token-row">
        <input
          id={id}
          ref={register(pointer)}
          className={`rule-input ${hasError ? 'is-error' : ''}`}
          type="text"
          value={draft}
          placeholder={placeholder}
          list={suggestions && suggestions.length > 0 ? `${id}-suggestions` : undefined}
          spellCheck={false}
          disabled={disabled}
          aria-invalid={hasError ? true : undefined}
          aria-describedby={`${id}-values${problems.length > 0 ? ` ${id}-problems` : ''}`}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              add();
            }
          }}
        />
        <button
          type="button"
          className="secondary-button"
          aria-label={`Add to ${label}`}
          disabled={disabled || draft.trim().length === 0}
          onClick={add}
        >
          Add
        </button>
      </div>
      {suggestions && suggestions.length > 0 ? (
        <datalist id={`${id}-suggestions`}>
          {suggestions.map((suggestion) => (
            <option key={suggestion} value={suggestion} />
          ))}
        </datalist>
      ) : null}
      <div className="rule-chip-list" id={`${id}-values`} aria-label={`${label} values`}>
        {values.length === 0 ? (
          <span className="badge neutral">{emptyText}</span>
        ) : (
          values.map((value, index) => (
            <span className="rule-chip" key={`${index}:${value}`}>
              {value}
              <button
                type="button"
                aria-label={`Remove ${value} from ${label}`}
                disabled={disabled}
                onClick={() => onChange(removeAt(values, index))}
              >
                x
              </button>
            </span>
          ))
        )}
      </div>
      <FieldProblems id={`${id}-problems`} diagnostics={problems} />
    </div>
  );
}

// The name of a map member (a role or a tool). A rename that would empty
// the name or collide with another entry is held back and explained, so an
// edit never drops or merges an entry.
function MemberNameField({
  label,
  name,
  existing,
  disabled,
  onRename,
}: {
  label: string;
  name: string;
  existing: readonly string[];
  disabled: boolean;
  onRename: (next: string) => void;
}) {
  const id = useId();
  const [text, setText] = useState(name);
  useEffect(() => {
    setText(name);
  }, [name]);
  const error =
    text === name
      ? null
      : text.length === 0
        ? 'A name is required; the previous name is kept until you enter one.'
        : existing.includes(text)
          ? 'Another entry already has this name; the previous name is kept.'
          : null;
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className={`rule-input ${error ? 'is-error' : ''}`}
        type="text"
        value={text}
        spellCheck={false}
        disabled={disabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : undefined}
        onChange={(event) => {
          const next = event.target.value;
          setText(next);
          if (next !== name && next.length > 0 && !existing.includes(next)) {
            onRename(next);
          }
        }}
      />
      {error ? (
        <p className="rule-hint is-error" id={`${id}-error`}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function FieldProblems({
  id,
  diagnostics,
}: {
  id: string;
  diagnostics: readonly PolicyDiagnostic[];
}) {
  if (diagnostics.length === 0) {
    return null;
  }
  return (
    <ul className="studio-field-problems" id={id}>
      {diagnostics.map((diagnostic, index) => (
        <li
          className={`studio-problem ${diagnostic.severity}`}
          key={`${index}:${diagnostic.code}:${diagnostic.pointer}`}
        >
          <span className={`badge ${severityBadge(diagnostic.severity)}`}>
            {severityLabel(diagnostic.severity)}
          </span>
          <span>{diagnostic.message}</span>
          <span className="rule-hint">{diagnostic.remediation}</span>
        </li>
      ))}
    </ul>
  );
}

function ShapeNotice({ member }: { member: string }) {
  return (
    <div className="error-panel alert warning" role="note">
      <h3>Edit {member} in Source</h3>
      <p>
        The {member} member is not in a shape this editor can show. Correct it
        in Source; the gateway's diagnostics say what it expects.
      </p>
    </div>
  );
}

function optionalList(entry: JsonObject, member: string, values: string[]): JsonObject {
  return withMember(entry, member, values.length === 0 ? undefined : values);
}

function describedBy(id: string, hint: boolean, problems: boolean): string | undefined {
  const ids = [hint ? `${id}-hint` : null, problems ? `${id}-problems` : null].filter(
    (value): value is string => value !== null,
  );
  return ids.length > 0 ? ids.join(' ') : undefined;
}
