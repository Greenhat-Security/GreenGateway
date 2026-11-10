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
      { rules: [{ id: 'r', path: 'nope', methods: [], action: 'allow' }] },
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
          pointer: '/rules/0/extra',
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
