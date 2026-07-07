import { NavLink } from 'react-router-dom';

const RULE_WORKSPACE_LINKS = [
  { label: 'Rulebase', to: '/rules' },
  { label: 'Builder', to: '/policy/rules/editor' },
  { label: 'Shadow review', to: '/policy/shadow-review' },
  { label: 'History', to: '/policy/history' },
];

const PLANNED_RULE_WORKSPACE_ITEMS = ['Optimize', 'Test', 'Evidence', 'Export'];

export function RuleWorkspaceNav() {
  return (
    <nav className="rule-workspace-nav" aria-label="Rules workspace">
      {RULE_WORKSPACE_LINKS.map((link) => (
        <NavLink
          className={({ isActive }) =>
            isActive ? 'rule-workspace-tab is-active' : 'rule-workspace-tab'
          }
          end={link.to === '/rules'}
          key={link.to}
          to={link.to}
        >
          {link.label}
        </NavLink>
      ))}
      {PLANNED_RULE_WORKSPACE_ITEMS.map((label) => (
        <span
          aria-disabled="true"
          className="rule-workspace-tab is-planned"
          key={label}
          title="Planned in issue #218"
        >
          {label}
        </span>
      ))}
    </nav>
  );
}
