import { NavLink } from 'react-router-dom';

const RULE_WORKSPACE_LINKS = [
  { label: 'Rulebase', to: '/rules' },
  { label: 'Builder', to: '/policy/rules/editor' },
  { label: 'Shadow review', to: '/policy/shadow-review' },
  { label: 'History', to: '/policy/history' },
];

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
    </nav>
  );
}
