import type {
  SimulationDecision,
  SimulationElement,
  SimulationProjection,
  SimulationStage,
} from '../../../lib/policySimulations';
import { codeLabel } from './common';

// Labels for the three answers a decision states. Each carries text and a
// symbol besides its colour, and none reads a shadowed deny as an allow.
export function logicalLabel(logical: string | null): { text: string; badge: string } {
  if (logical === 'allow') return { text: '✓ Allow', badge: 'success' };
  if (logical === 'deny') return { text: '✕ Deny', badge: 'danger' };
  return { text: '? Undecided', badge: 'warning' };
}

export function enforcementLabel(decision: Pick<SimulationDecision, 'enforcement' | 'logical'>): string {
  if (decision.enforcement === 'enforced') return 'Enforced: the denial blocks';
  if (decision.enforcement === 'shadowed') return 'Shadow: a would-deny that is only observed';
  return decision.logical === 'indeterminate'
    ? 'Not applicable: nothing was decided'
    : 'Not applicable: nothing to enforce';
}

export function effectLabel(effectiveAction: string | null): { text: string; badge: string } {
  if (effectiveAction === 'would_forward') return { text: '→ Would forward', badge: 'success' };
  if (effectiveAction === 'would_block') return { text: '■ Would block', badge: 'danger' };
  return { text: '? Unknown: not a forward', badge: 'warning' };
}

export function projectionLabel(projection: SimulationProjection): string {
  return projection === 'as_authored' ? 'As authored' : 'Every shadow enforced';
}

// An element as the editors number it, beside the position the gateway's
// results and test expectations use.
export function positionText(kind: 'rule' | 'route' | 'rate override', position: number): string {
  return `${kind} #${position + 1} (position ${position})`;
}

export function elementText(element: SimulationElement): string {
  const parts = [positionText(element.kind, element.position)];
  if (element.id !== null) {
    parts.push(`id ${element.id}`);
  } else if (element.id_omitted) {
    parts.push('id too long to show');
  }
  if (element.action !== null) {
    parts.push(`action ${element.action}`);
  }
  if (element.permission !== null) {
    parts.push(`requires ${element.permission}`);
  } else if (element.permission_omitted) {
    parts.push('permission too long to show');
  }
  if (element.permission_granted !== null) {
    parts.push(element.permission_granted ? 'permission granted' : 'permission not granted');
  }
  return parts.join(', ');
}

const STAGE_NAMES: Record<string, string> = {
  facts: 'Facts',
  request_host: 'Request host',
  direct_rules: 'Direct rules',
  upstream_host_binding: 'Upstream host binding',
  routes: 'Routes',
  default: 'Default',
};

const STAGE_STATUSES: Record<string, string> = {
  matched: 'matched',
  no_match: 'no match',
  not_applicable: 'not applicable',
  skipped: 'skipped: decided at an earlier stage',
  unknown: 'unknown: undecided at an earlier stage',
};

function stageText(stage: SimulationStage): string {
  const details: string[] = [];
  if (stage.element !== null) details.push(elementText(stage.element));
  if (stage.action !== null && stage.element?.action !== stage.action) {
    details.push(`action ${stage.action}`);
  }
  if (stage.host !== null) details.push(`host: ${codeLabel(stage.host)}`);
  if (stage.deny_only) details.push('only a deny can apply');
  if (stage.permission !== null) details.push(`permission ${codeLabel(stage.permission)}`);
  if (stage.enforcement_mode !== null) {
    details.push(
      `mode ${stage.enforcement_mode}${stage.mode_inherited ? ' (inherited)' : stage.mode_inherited === false ? ' (the route’s own)' : ''}`,
    );
  }
  if (stage.default_action !== null) details.push(`default ${stage.default_action}`);
  if (stage.reason !== null) details.push(codeLabel(stage.reason));
  if (stage.limitation !== null) details.push(`limitation ${stage.limitation}`);
  const name = STAGE_NAMES[stage.stage] ?? codeLabel(stage.stage);
  const status = STAGE_STATUSES[stage.status] ?? codeLabel(stage.status);
  return `${name}: ${status}${details.length > 0 ? ` (${details.join('; ')})` : ''}`;
}

// One decision as a waterfall: what the policy decided, whether a denial is
// enforced or only observed, and what the request would meet, in that order.
export function DecisionView({
  title,
  decision,
}: {
  title: string;
  decision: SimulationDecision;
}) {
  if (decision.lane === 'rate_selection') {
    return (
      <div className="workbench-decision">
        <p className="workbench-decision-title">{title}</p>
        <RateSelection decision={decision} />
      </div>
    );
  }
  const logical = logicalLabel(decision.logical);
  const effect = effectLabel(decision.effective_action);
  return (
    <div className="workbench-decision">
      <p className="workbench-decision-title">{title}</p>
      <ol className="workbench-waterfall" aria-label={`${title}: decision`}>
        <li>
          <span className="workbench-step">Policy decision</span>
          <span className={`badge ${logical.badge}`}>{logical.text}</span>
        </li>
        <li>
          <span className="workbench-step">Enforcement</span>
          <span>{enforcementLabel(decision)}</span>
        </li>
        <li>
          <span className="workbench-step">Effect at this stage</span>
          <span className={`badge ${effect.badge}`}>{effect.text}</span>
        </li>
      </ol>
      {decision.enforcement === 'shadowed' ? (
        <p className="rule-hint">
          Forwarded only because enforcement is shadow. A shadowed deny is still a deny,
          never an allow.
        </p>
      ) : null}
      <dl className="workbench-facts">
        <div>
          <dt>Reason</dt>
          <dd>
            <code>{decision.reason}</code>
          </dd>
        </div>
        <div>
          <dt>Decided by</dt>
          <dd>
            {decision.matched === undefined
              ? 'Not reported at this trace level'
              : decision.matched === null
                ? 'No element: the default or a fact decided'
                : elementText(decision.matched)}
          </dd>
        </div>
        {decision.observation ? (
          <div>
            <dt>Shadow observation</dt>
            <dd>{elementText(decision.observation)} would deny, observed beside the decision</dd>
          </div>
        ) : null}
        {decision.operation !== null ? (
          <div>
            <dt>Tool operation</dt>
            <dd>{codeLabel(decision.operation)}</dd>
          </div>
        ) : null}
        {!decision.complete || decision.limitation !== null ? (
          <div>
            <dt>Limitation</dt>
            <dd>
              {decision.limitation !== null ? <code>{decision.limitation}</code> : null}
              {decision.complete ? '' : ' The answer is incomplete.'}
            </dd>
          </div>
        ) : null}
      </dl>
      {decision.stages_truncated ? (
        <p className="rule-hint">
          This evaluation’s stages were left out: the simulation reached its bound on
          stage steps. The decision above is complete.
        </p>
      ) : null}
      {decision.stages !== null && decision.stages.length > 0 ? (
        <details className="workbench-stages">
          <summary>Evaluation stages</summary>
          <ol aria-label={`${title}: evaluation stages`}>
            {decision.stages.map((stage, index) => (
              <li key={`${stage.stage}:${index}`}>{stageText(stage)}</li>
            ))}
          </ol>
        </details>
      ) : null}
    </div>
  );
}

function RateSelection({ decision }: { decision: SimulationDecision }) {
  const override = decision.rate_override;
  return (
    <>
      <p>
        {decision.selected === 'override' && override !== null ? (
          <>
            <span className="badge neutral">Override</span>{' '}
            {positionText('rate override', override.position)}
            {override.id !== null ? `, id ${override.id}` : ''}
            {override.requests_per_second !== null
              ? `, ${override.requests_per_second} requests per second`
              : ''}
            {override.burst !== null ? `, burst ${override.burst}` : ''}
          </>
        ) : decision.selected === 'no_override' ? (
          <>
            <span className="badge neutral">No override</span> The default rate lane applies.
          </>
        ) : (
          <>
            <span className="badge warning">? Undecided</span>
            {decision.limitation !== null ? (
              <>
                {' '}
                <code>{decision.limitation}</code>
              </>
            ) : null}
          </>
        )}
      </p>
      <p className="rule-hint">Selection only: bucket capacity is not modelled.</p>
    </>
  );
}
