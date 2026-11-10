import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { useState, type ComponentType } from 'react';
import { afterEach, describe, expect, it } from 'vitest';

import type { PolicyDiagnostic } from '../../lib/policyDrafts';
import type { JsonObject } from './model';
import {
  IdentityMappingsSection,
  RateLimitsSection,
  RolesSection,
  RulesSection,
  ToolsSection,
  type FieldRegistrar,
} from './sections';

type SectionComponent = ComponentType<{
  document: JsonObject;
  diagnostics: readonly PolicyDiagnostic[];
  disabled: boolean;
  register: FieldRegistrar;
  onChange: (next: JsonObject) => void;
}>;

afterEach(() => {
  cleanup();
});

describe('policy studio section editors', () => {
  it('keeps mapped-role mode after removing the last mapping until claimed roles are explicitly selected', () => {
    const initial = {
      schema_version: '1.0.0',
      rules: [{ id: 'mapping-1', path: '/billing', action: 'deny' }],
    };
    const latest = renderSection(IdentityMappingsSection, initial);

    fireEvent.click(screen.getByRole('button', { name: 'Use identity mappings' }));
    expect(latest()).toEqual({ ...initial, identity_mappings: [] });

    fireEvent.click(screen.getByRole('button', { name: 'Add mapping' }));
    expect(latest().identity_mappings).toEqual([{ id: 'mapping-2', issuer: '', grant_roles: [] }]);

    fireEvent.click(screen.getByRole('button', { name: 'Remove mapping mapping-2' }));
    expect(latest()).toEqual({ ...initial, identity_mappings: [] });

    fireEvent.click(screen.getByRole('button', { name: 'Use claimed roles' }));
    expect(latest()).toEqual(initial);
  });

  it('edits issuer-bound matchers and granted roles without dropping other draft fields', () => {
    const mapping = {
      id: 'mapped-read',
      issuer: 'https://first.example',
      subjects: ['reader'],
      organizations: ['acme'],
      claimed_roles: ['staff'],
      auth_methods: ['bearer_token'],
      scopes: ['read'],
      grant_roles: ['readers'],
      future_field: 'retained',
    };
    const initial = {
      schema_version: '1.0.0',
      roles: { readers: { permissions: [] }, writers: { permissions: [] } },
      identity_mappings: [mapping],
    };
    const latest = renderSection(IdentityMappingsSection, initial);
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'https://updated.example' } });
    for (const [label, value] of [
      ['Subjects', ' reviewer '],
      ['Scopes', 'write'],
      ['Granted roles', 'writers'],
    ]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
      fireEvent.keyDown(screen.getByLabelText(label), { key: 'Enter' });
    }

    expect(latest()).toEqual({
      ...initial,
      identity_mappings: [{
        ...mapping,
        issuer: 'https://updated.example',
        subjects: ['reader', ' reviewer '],
        scopes: ['read', 'write'],
        grant_roles: ['readers', 'writers'],
      }],
    });
  });

  it('clears unstaged grants when the mapping changes issuer and labels exact padded subjects', () => {
    const latest = renderSection(IdentityMappingsSection, {
      schema_version: '1.0.0',
      identity_mappings: [{ id: 'shared', issuer: 'https://one.example', subjects: [' sam '], grant_roles: ['reader'] }],
    });
    expect(screen.getByRole('button', { name: 'Remove "\\u0020sam\\u0020" from Subjects' })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Granted roles'), { target: { value: 'writer' } });
    fireEvent.change(screen.getByLabelText('Issuer'), { target: { value: 'https://two.example' } });
    expect((screen.getByLabelText('Granted roles') as HTMLInputElement).value).toBe('');
    expect(latest().identity_mappings).toEqual([
      { id: 'shared', issuer: 'https://two.example', subjects: [' sam '], grant_roles: ['reader'] },
    ]);
  });

  it('cannot enable mappings in a v0 draft', () => {
    const document = { schema_version: '0.1.0' };
    const latest = renderSection(IdentityMappingsSection, document);
    const enable = screen.queryByRole<HTMLButtonElement>('button', { name: 'Use identity mappings' });
    expect(enable === null || enable.disabled).toBe(true);
    expect(latest()).toEqual(document);
  });

  it('reorders rules and keeps focus with the rule that moved', () => {
    const latest = renderSection(RulesSection, {
      rules: [
        { id: 'first', path: '/a', methods: [], action: 'allow' },
        { id: 'second', path: '/b', methods: [], action: 'deny' },
      ],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Move rule first down' }));

    expect(ids(latest().rules)).toEqual(['second', 'first']);
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: 'Move rule first up' }),
    );
  });

  it('keeps members the editor does not show when a field changes', () => {
    const latest = renderSection(RulesSection, {
      rules: [
        {
          id: 'kept',
          path: '/a',
          methods: [],
          action: 'allow',
          dispatch: { kind: 'route', route_id: 'billing' },
        },
      ],
      future_member: { untouched: true },
    });

    fireEvent.change(screen.getByLabelText('Path pattern'), { target: { value: '/b' } });

    expect(latest()).toEqual({
      rules: [
        {
          id: 'kept',
          path: '/b',
          methods: [],
          action: 'allow',
          dispatch: { kind: 'route', route_id: 'billing' },
        },
      ],
      future_member: { untouched: true },
    });
    expect(
      screen.getByText('Only requests dispatched to upstream route billing.'),
    ).toBeTruthy();
    expect(
      (screen.getByRole('radio', { name: /MCP tool/ }) as HTMLInputElement).disabled,
    ).toBe(true);
  });

  it('switches a rule between an HTTP path and an MCP tool without leaving both', () => {
    const latest = renderSection(RulesSection, {
      rules: [{ id: 'r', path: '/a', methods: ['GET'], action: 'deny' }],
    });

    fireEvent.click(screen.getByRole('radio', { name: /MCP tool/ }));
    expect(latest().rules).toEqual([
      { id: 'r', methods: [], action: 'deny', tool_name: '' },
    ]);

    fireEvent.change(screen.getByLabelText('Tool name'), {
      target: { value: 'reports.export' },
    });
    fireEvent.click(screen.getByRole('radio', { name: /HTTP path/ }));
    expect(latest().rules).toEqual([
      { id: 'r', methods: [], action: 'deny', path: '/' },
    ]);
  });

  it('adds a rule with a fresh id that denies by default', () => {
    const latest = renderSection(RulesSection, {
      routes: [{ id: 'rule-1', path_prefix: '/', permission: 'p' }],
      rules: [],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));

    expect(latest().rules).toEqual([
      { id: 'rule-2', methods: [], path: '/', principal: {}, action: 'deny' },
    ]);
  });

  it('adds principal constraints and normalizes methods', () => {
    const latest = renderSection(RulesSection, {
      rules: [{ id: 'r', path: '/a', methods: [], principal: {}, action: 'allow' }],
    });
    const card = screen.getByRole('article');

    fireEvent.change(within(card).getByLabelText('Methods'), { target: { value: 'post' } });
    fireEvent.keyDown(within(card).getByLabelText('Methods'), { key: 'Enter' });
    fireEvent.change(within(card).getByLabelText('Roles'), { target: { value: 'support' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Add to Roles' }));
    fireEvent.click(within(card).getByRole('checkbox', { name: 'Service token' }));

    expect(latest().rules).toEqual([
      {
        id: 'r',
        path: '/a',
        methods: ['POST'],
        principal: { roles: ['support'], auth_methods: ['service_token'] },
        action: 'allow',
      },
    ]);

    fireEvent.click(within(card).getByRole('button', { name: 'Remove support from Roles' }));
    expect((latest().rules as JsonObject[])[0].principal).toEqual({
      roles: [],
      auth_methods: ['service_token'],
    });
  });

  it('renames a role in place and never merges two roles', () => {
    const latest = renderSection(RolesSection, {
      roles: { admin: { permissions: ['a'] }, support: { permissions: ['s'] } },
    });
    const [, supportName] = screen.getAllByLabelText('Role name') as HTMLInputElement[];

    fireEvent.change(supportName, { target: { value: 'admin' } });
    expect(Object.keys(latest().roles as JsonObject)).toEqual(['admin', 'support']);
    expect(
      screen.getByText('Another entry already has this name; the previous name is kept.'),
    ).toBeTruthy();

    fireEvent.change(supportName, { target: { value: 'helpdesk' } });
    expect(latest().roles).toEqual({
      admin: { permissions: ['a'] },
      helpdesk: { permissions: ['s'] },
    });
  });

  it('retains an empty network matcher until the operator explicitly removes the condition', () => {
    const rule = { id: 'office', path: '/reports', action: 'deny' };
    const latest = renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] });
    fireEvent.click(screen.getByRole('button', { name: 'Add source network condition' }));
    const input = screen.getByLabelText('Source networks');
    fireEvent.change(input, { target: { value: '192.0.2.0/24' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(latest().rules).toEqual([
      { ...rule, conditions: { source_network: { cidrs: ['192.0.2.0/24'] } } },
    ]);
    fireEvent.click(screen.getByRole('button', { name: 'Remove 192.0.2.0/24 from Source networks' }));
    expect(latest().rules).toEqual([{ ...rule, conditions: { source_network: { cidrs: [] } } }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remove policy condition' }));
    expect(latest().rules).toEqual([rule]);
  });

  it('exposes nested condition source without replacing the tree when another field changes', () => {
    const conditions = { not: { any: [{ claim: { issuer: 'example', name: 'team', in: [true, 'true'] } }] } };
    const rule = { id: 'nested', path: '/a', action: 'deny', conditions };
    const latest = renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] });
    expect(screen.getByText('View condition source')).toBeTruthy();
    expect(screen.getByText('Negate this operand. An unknown result stays unknown.')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Path pattern'), { target: { value: '/b' } });
    expect(latest().rules).toEqual([{ ...rule, path: '/b' }]);
  });

  it('wraps, switches and unwraps groups without changing opaque matcher values or sibling order', () => {
    const claim = { claim: { issuer: 'example', name: 'team', in: [true, 'true', 2, '2'] } };
    const rule = { id: 'grouped', path: '/a', action: 'deny', conditions: claim };
    const latest = renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] });
    const condition = () => (latest().rules as JsonObject[])[0].conditions;
    const action = (name: string) => {
      const root = document.querySelector('[data-condition-pointer="/rules/0/conditions"]')!;
      const details = root.querySelector<HTMLDetailsElement>(':scope > details')!;
      if (!details.open) fireEvent.click(details.querySelector('summary')!);
      fireEvent.click(within(details).getByRole('button', { name }));
    };
    action('Wrap in All');
    action('Add time window operand');
    fireEvent.change(screen.getByLabelText('Until (exclusive)'), { target: { value: '2027-01-01T00:00:00Z' } });
    const time = { time_window: { until: '2027-01-01T00:00:00Z' } };
    expect(condition()).toEqual({ all: [claim, time] });
    action('Change to Any');
    expect(condition()).toEqual({ any: [claim, time] });
    expect(screen.queryByRole('button', { name: 'Unwrap single operand' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Remove operand 2' }));
    expect(screen.queryByRole('button', { name: 'Remove operand 1' })).toBeNull();
    action('Unwrap single operand');
    action('Wrap in Not');
    expect(condition()).toEqual({ not: claim });
    action('Remove negation');
    expect(condition()).toEqual(claim);
  });

  it('clears uncommitted operand text when removing a sibling', () => {
    const network = { source_network: { cidrs: ['192.0.2.0/24'] } };
    const rule = { id: 'networks', path: '/a', action: 'deny', conditions: { all: [network, network] } };
    renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] });
    const inputs = screen.getAllByLabelText('Source networks');
    fireEvent.change(inputs[0], { target: { value: '198.51.100.0/24' } });
    fireEvent.click(screen.getByRole('button', { name: 'Remove operand 1' }));
    expect((screen.getByLabelText('Source networks') as HTMLInputElement).value).toBe('');
  });

  it('keeps network removals available at the 32-value limit', () => {
    const cidrs = Array.from({ length: 32 }, (_, index) => `192.0.2.${index}/32`);
    const rule = { id: 'networks', path: '/', action: 'deny', conditions: { source_network: { cidrs } } };
    renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] });
    const input = screen.getByLabelText('Source networks') as HTMLInputElement;
    expect(input.readOnly).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Remove 192.0.2.0/32 from Source networks' }));
    expect(input.readOnly).toBe(false);
  });

  it('prevents wrapping an entire four-level subtree, while allowing it to shrink', () => {
    const limit = { not: { not: { not: { time_window: {} } } } };
    const latest = renderSection(RulesSection, {
      schema_version: '1.0.0', rules: [{ id: 'bounded', path: '/', action: 'deny', conditions: limit }],
    });
    const actions = document.querySelector<HTMLDetailsElement>('[data-condition-pointer="/rules/0/conditions"] > details')!;
    fireEvent.click(actions.querySelector('summary')!);
    expect((within(actions).getByRole('button', { name: 'Wrap in All' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(actions).getByRole('button', { name: 'Remove negation' }));
    expect((latest().rules as JsonObject[])[0].conditions).toEqual(limit.not);
  });

  it('disables every structural mutation for a read-only rule', () => {
    const conditions = { all: [{ source_network: { cidrs: [] } }, { time_window: {} }] };
    const rule = { id: 'read-only', path: '/', action: 'deny', conditions };
    const latest = renderSection(RulesSection, { schema_version: '1.0.0', rules: [rule] }, [], true);
    const actions = document.querySelector<HTMLDetailsElement>('[data-condition-pointer="/rules/0/conditions"] > details')!;
    fireEvent.click(actions.querySelector('summary')!);
    for (const button of within(actions).getAllByRole('button')) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
    expect((screen.getByRole('button', { name: 'Remove operand 1' }) as HTMLButtonElement).disabled).toBe(true);
    expect(latest().rules).toEqual([rule]);
  });

  it('edits numbers as text, keeps text that is not a number for the gateway to judge, and drops an empty optional value', () => {
    const latest = renderSection(ToolsSection, {
      tools: { 'reports.export': { enabled: true, allowed_roles: [], timeout_ms: 1000 } },
    });
    const timeout = screen.getByLabelText('Timeout (ms)') as HTMLInputElement;

    fireEvent.change(timeout, { target: { value: '2500' } });
    expect(tool(latest()).timeout_ms).toBe(2500);

    fireEvent.change(timeout, { target: { value: 'soon' } });
    expect(tool(latest()).timeout_ms).toBe('soon');
    expect(timeout.value).toBe('soon');

    fireEvent.change(timeout, { target: { value: '' } });
    expect(tool(latest())).not.toHaveProperty('timeout_ms');
  });

  it('keeps a half-typed decimal on screen while storing the number', () => {
    const latest = renderSection(RateLimitsSection, {
      rate_limits: [{ id: 'r', requests_per_second: 5, burst: 10 }],
    });
    const rate = screen.getByLabelText('Requests per second') as HTMLInputElement;

    fireEvent.change(rate, { target: { value: '2.' } });
    expect(rate.value).toBe('2.');
    expect((latest().rate_limits as JsonObject[])[0].requests_per_second).toBe(2);

    fireEvent.click(screen.getByRole('button', { name: 'Remove rate limit r' }));
    expect(latest()).not.toHaveProperty('rate_limits');
  });

  it('shows the gateway diagnostics beside the field they point at', () => {
    renderSection(
      RulesSection,
      { schema_version: '0.1.0', rules: [{ id: 'r', path: 'nope', methods: [], action: 'allow', conditions: {} }] },
      [
        {
          code: 'rule_path_invalid',
          severity: 'error',
          pointer: '/rules/0/path',
          element_id: 'r',
          message: 'The path must be absolute.',
          remediation: 'Start the path with /.',
          blocks: { simulation: true, tests: true, publication: true, evidence: true },
        },
        {
          code: 'rule_unknown_member',
          severity: 'warning',
          pointer: '/rules/0/conditions',
          message: 'Unknown member.',
          remediation: 'Remove it.',
          blocks: { simulation: false, tests: false, publication: false, evidence: true },
        },
      ],
    );

    const path = screen.getByLabelText('Path pattern');
    expect(path.getAttribute('aria-invalid')).toBe('true');
    const described = (path.getAttribute('aria-describedby') ?? '').split(' ');
    const problems = described
      .map((id) => document.getElementById(id))
      .find((element) => element?.textContent?.includes('The path must be absolute.'));
    expect(problems).toBeTruthy();
    expect(screen.getByText('1 error')).toBeTruthy();
    expect(screen.getByText('1 warning')).toBeTruthy();
    // A member no field shows is reported on the card itself.
    expect(within(screen.getByRole('article')).getByText('Unknown member.')).toBeTruthy();
  });

  it('disables every control when the draft cannot be edited', () => {
    renderSection(
      RulesSection,
      { rules: [{ id: 'r', path: '/a', methods: [], action: 'allow' }] },
      [],
      true,
    );

    for (const control of [
      ...screen.getAllByRole('textbox'),
      ...screen.getAllByRole('radio'),
      ...screen.getAllByRole('checkbox'),
    ]) {
      expect((control as HTMLInputElement).disabled).toBe(true);
    }
    expect((screen.getByRole('button', { name: 'Add rule' }) as HTMLButtonElement).disabled).toBe(true);
  });
});

function renderSection(
  Section: SectionComponent,
  initial: JsonObject,
  diagnostics: readonly PolicyDiagnostic[] = [],
  disabled = false,
): () => JsonObject {
  let latest = initial;
  function Harness() {
    const [document, setDocument] = useState(initial);
    return (
      <Section
        document={document}
        diagnostics={diagnostics}
        disabled={disabled}
        register={() => () => undefined}
        onChange={(next) => {
          latest = next;
          setDocument(next);
        }}
      />
    );
  }
  render(<Harness />);
  return () => latest;
}

function ids(value: unknown): unknown[] {
  return (value as JsonObject[]).map((entry) => entry.id);
}

function tool(document: JsonObject): JsonObject {
  return (document.tools as Record<string, JsonObject>)['reports.export'];
}
