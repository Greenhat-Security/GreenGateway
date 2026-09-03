import { type ReactNode, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { decodeJwtRolesClaim, getStoredToken } from '../lib/auth';
import {
  fetchClusterStatus,
  type ClusterLeaderTaskView,
  type ClusterState,
  type ClusterStatus,
} from '../lib/cluster';
import { fetchPolicy } from '../lib/policy';

const CLUSTER_READ_PERMISSION = 'admin:cluster:read';

/**
 * Where a reason's remediation is written up. The gateway's reasons are a
 * fixed vocabulary, so each one can point at the section of the PostgreSQL
 * deployment guide that says what to do about it.
 */
const DEPLOYMENT_GUIDE =
  'https://github.com/Greenhat-Security/GreenGateway/blob/main/docs/deployment/postgres.md';

type ClusterLoadError = {
  kind: 'unauthorized' | 'forbidden' | 'network' | 'generic';
  message: string;
};

/**
 * Whether this console could prove, from the policy document and the
 * token's roles claim, that the principal may read cluster status.
 * `unknown` means the question could not be answered here (no token, no
 * roles claim, an unreadable policy) and the API is left to answer it.
 */
type ClusterReadPermission = 'granted' | 'denied' | 'unknown';

type ReasonDetail = {
  /** The short label rendered beside the state badge. */
  label: string;
  /** What the reason means, in the operator's terms. */
  description: string;
  /** The remediation section of the deployment guide. */
  anchor: string;
  /** The link text for that section. */
  remediation: string;
};

/**
 * The fixed reason vocabulary, exactly as `cluster_status.rs` reports it:
 * the readiness chain's own strings first (`/readyz` and this page must
 * never disagree about a word), then the four degraded reasons a serving
 * replica can carry.
 *
 * A reason outside this map is rendered through `UNRECOGNIZED_REASON`.
 * The raw string is never put on the page: it arrives from a shared table
 * any replica in the deployment can write to, and this console is not the
 * place to find out whether the gateway's redaction held.
 */
const REASON_DETAILS: Record<string, ReasonDetail> = {
  starting: {
    label: 'Starting',
    description:
      'This replica is still starting and has not finished its first readiness pass.',
    anchor: '#readiness-and-status',
    remediation: 'Readiness and status',
  },
  draining: {
    label: 'Draining',
    description:
      'This replica is shutting down and is refusing new traffic while in-flight work finishes.',
    anchor: '#readiness-and-status',
    remediation: 'Readiness and status',
  },
  config_fingerprint_mismatch: {
    label: 'Configuration fingerprint mismatch',
    description:
      'Another replica in this deployment is running a different static configuration, so this one refuses traffic until the fleet agrees.',
    anchor: '#enabling-cluster-mode',
    remediation: 'Enabling cluster mode',
  },
  storage_unavailable: {
    label: 'Storage unavailable',
    description:
      'The database could not be checked out, or the session this replica got cannot be written to (a standby, or a primary put into read-only).',
    anchor: '#pool-sizing-and-timeouts',
    remediation: 'Pool sizing and timeouts',
  },
  schema_incompatible: {
    label: 'Schema incompatible',
    description:
      'The migration ledger no longer covers the range this binary serves on: the database was migrated by a different gateway version.',
    anchor: '#schema-migrations',
    remediation: 'Schema migrations',
  },
  instance_lease_invalid: {
    label: 'Instance lease invalid',
    description:
      'This replica’s membership heartbeat has not landed inside the stale window, so the roster no longer counts it as live.',
    anchor: '#membership-and-maintenance',
    remediation: 'Membership and maintenance',
  },
  security_revision_not_compiled: {
    label: 'Security revision not compiled',
    description:
      'The security gate has been refusing every admission for longer than the reconcile deadline, so protected requests are failing closed here.',
    anchor: '#the-policy-control-plane',
    remediation: 'The policy control plane',
  },
  required_upstream_unavailable: {
    label: 'Required upstream unavailable',
    description:
      'A proxy pool this gateway requires has no healthy upstream, so it cannot serve the routes that depend on it.',
    anchor: '#the-deployment-shape',
    remediation: 'The deployment shape',
  },
  replicas_unavailable: {
    label: 'Replica roster unavailable',
    description:
      'This replica is serving, but the membership roster could not be read, so nothing below can be judged against the rest of the deployment.',
    anchor: '#membership-and-maintenance',
    remediation: 'Membership and maintenance',
  },
  security_revision_lagging: {
    label: 'Security revision lagging',
    description:
      'This replica’s compiled security watermark is behind the authority’s counter and is still reconciling.',
    anchor: '#the-policy-control-plane',
    remediation: 'The policy control plane',
  },
  maintenance_job_failing: {
    label: 'Maintenance job failing',
    description:
      'A background job owned by the maintenance singleton recorded a failure on its last run.',
    anchor: '#membership-and-maintenance',
    remediation: 'Membership and maintenance',
  },
  member_error_reported: {
    label: 'Member error reported',
    description:
      'A live replica in the roster is carrying a classified failure on its membership row.',
    anchor: '#membership-and-maintenance',
    remediation: 'Membership and maintenance',
  },
};

const UNRECOGNIZED_REASON: ReasonDetail = {
  label: 'Unrecognized reason',
  description:
    'The gateway reported a reason this console does not recognize. Check the gateway logs and /readyz for the current answer.',
  anchor: '#readiness-and-status',
  remediation: 'Readiness and status',
};

/**
 * The repository classifier's fixed error kinds, which are the only values
 * a leader task's `last_failure_code` can carry once the gateway has
 * redacted it. Anything else is reported as an unknown class rather than
 * echoed onto the page.
 */
const FAILURE_CODE_LABELS: Record<string, string> = {
  unavailable: 'Database unavailable',
  timeout: 'Statement timed out',
  conflict: 'Write conflict',
  'invalid data': 'Invalid data',
  'incompatible schema': 'Incompatible schema',
  internal: 'Internal error',
};

const UNKNOWN_FAILURE_LABEL = 'Unknown error class';

export function ClusterView() {
  const [status, setStatus] = useState<ClusterStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [permission, setPermission] = useState<ClusterReadPermission>('unknown');
  const [loadError, setLoadError] = useState<ClusterLoadError | null>(null);

  useEffect(() => {
    let isCurrent = true;

    async function loadClusterStatus() {
      setIsLoading(true);
      setLoadError(null);
      setStatus(null);

      const readPermission = await resolveClusterReadPermission();
      if (!isCurrent) {
        return;
      }

      setPermission(readPermission);
      if (readPermission === 'denied') {
        setIsLoading(false);
        return;
      }

      try {
        const response = await fetchClusterStatus();
        if (!isCurrent) {
          return;
        }

        setStatus(response);
      } catch (error) {
        if (!isCurrent) {
          return;
        }

        setStatus(null);
        setLoadError(toClusterLoadError(error));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadClusterStatus();

    return () => {
      isCurrent = false;
    };
  }, []);

  const permissionRequired =
    permission === 'denied' || loadError?.kind === 'forbidden';

  return (
    <main className="logs-page cluster-page">
      <section
        className="panel logs-panel cluster-panel"
        aria-labelledby="cluster-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Deployment</p>
            <h2 id="cluster-heading">Cluster status</h2>
          </div>
          {status ? <ClusterModeBadge status={status} /> : null}
        </div>

        {permissionRequired ? <ClusterPermissionNotice /> : null}
        {loadError && loadError.kind !== 'forbidden' ? (
          <ClusterErrorMessage error={loadError} />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading cluster status
          </div>
        ) : null}

        {/*
         * Mounted before the first response and kept mounted, because a
         * live region only announces changes made after it is already in
         * the accessibility tree: a region inserted with its sentence
         * already in it is silent, which is the whole announcement this
         * page has to make.
         */}
        <ClusterStatePanel status={status} />

        {status ? <ClusterSummary status={status} /> : null}
      </section>
    </main>
  );
}

function ClusterModeBadge({ status }: { status: ClusterStatus }) {
  const isCluster = status.mode === 'cluster';
  return (
    <span
      className={`badge ${isCluster ? 'success' : 'neutral'}`}
      data-testid="cluster-mode-badge"
    >
      {isCluster ? 'Cluster mode' : 'Standalone mode'}
    </span>
  );
}

function ClusterSummary({ status }: { status: ClusterStatus }) {
  const reason = reasonDetail(status.reason);

  return (
    <div className="cluster-summary">
      <div className="cluster-section-grid">
        <ClusterSection title="Replicas and versions">
          <ClusterItem
            label="Ready replicas"
            value={`${status.replicas.ready} of ${status.replicas.total} ready`}
          />
          <ClusterItem
            label="Live replicas"
            value={countLabel(status.replicas.total, 'replica', 'replicas')}
          />
          <ClusterItem
            label="Binary versions"
            value={binaryVersionsLabel(status)}
          />
        </ClusterSection>

        <ClusterSection title="Schema compatibility">
          <ClusterItem
            label="Compatibility"
            value={
              status.schema.compatible
                ? 'Compatible: the ledger is in this binary’s range'
                : 'Incompatible: the ledger is outside this binary’s range'
            }
          />
          <ClusterItem
            label="Ledger version"
            value={
              status.schema.current_version === null
                ? 'Not reported'
                : String(status.schema.current_version)
            }
          />
          <ClusterItem
            label="Binary range"
            value={`${status.schema.binary_min} to ${status.schema.binary_max}`}
          />
        </ClusterSection>

        <ClusterSection title="Security revisions">
          <ClusterItem
            label="Authority revision"
            value={String(status.local.observed_security_revision)}
          />
          <ClusterItem
            label="Locally compiled revision"
            value={String(status.local.compiled_security_revision)}
          />
          <ClusterItem
            label="Revision lag"
            value={
              status.local.revision_lag === 0
                ? 'None: this replica is current'
                : countLabel(status.local.revision_lag, 'revision', 'revisions')
            }
          />
          <ClusterItem
            label="Last reconcile pass"
            value={formatAge(status.reconcile.last_pass_age_secs)}
          />
          <ClusterItem
            label="Reconcile failures"
            value={String(status.reconcile.failures_total)}
          />
        </ClusterSection>

        <ClusterSection title="Durable events and projector">
          {status.projector ? (
            <>
              <ClusterItem
                label="Projector lag"
                value={
                  status.projector.lag_events === null
                    ? 'Unknown: the audit stream head could not be read'
                    : countLabel(
                        status.projector.lag_events,
                        'event',
                        'events',
                      )
                }
              />
              <ClusterItem
                label="Checkpoint position"
                value={String(status.projector.checkpoint_position)}
              />
              <ClusterItem
                label="Audit stream head"
                value={
                  status.projector.stream_head === null
                    ? 'Not reported'
                    : String(status.projector.stream_head)
                }
              />
              <ClusterItem
                label="Projector leader"
                value={
                  status.projector.leader_present
                    ? 'Present: a live replica holds the projector'
                    : 'Absent: waiting for a replica to claim the projector'
                }
              />
              <ClusterItem
                label="Fence"
                value={String(status.projector.fence)}
              />
              <ClusterItem
                label="Last flush"
                value={formatAge(status.projector.last_flush_age_secs)}
              />
            </>
          ) : (
            <ClusterItem
              label="Projector"
              value={
                status.mode === 'standalone'
                  ? 'Not reported: standalone deployments have no projector'
                  : 'Not reported: the projector row could not be read'
              }
            />
          )}
        </ClusterSection>

        <ClusterSection title="Audit queue">
          <ClusterItem
            label="Queue depth"
            value={`${status.audit.queue_depth} of ${status.audit.queue_capacity} queued`}
          />
          <ClusterItem
            label="Oldest queued event"
            value={
              // The gateway reports zero while the writer is idle, and an
              // age of zero renders as "Under a second ago" — a fresh
              // event, which is the opposite of an empty queue. Every
              // other absent value on this page says so in words.
              status.audit.queue_depth === 0
                ? 'Nothing queued'
                : formatAge(status.audit.oldest_age_secs)
            }
          />
          <ClusterItem
            label="Dropped events"
            value={String(status.audit.dropped_total)}
          />
        </ClusterSection>

        <ClusterSection title="Database pool">
          {status.pools.database ? (
            <>
              <ClusterItem
                label="Connections"
                value={`${status.pools.database.available} available of ${status.pools.database.size}`}
              />
              <ClusterItem
                label="Waiting"
                value={String(status.pools.database.waiting)}
              />
              <ClusterItem
                label="Checkout timeouts"
                value={String(status.pools.database.timeouts_total)}
              />
            </>
          ) : (
            <ClusterItem
              label="Pool"
              value={
                status.mode === 'standalone'
                  ? 'Not reported: standalone deployments have no shared pool'
                  : 'Not reported: the pool could not be read'
              }
            />
          )}
        </ClusterSection>
      </div>

      <LeaderTaskTable tasks={status.leader_tasks} mode={status.mode} />

      <RemediationPanel reason={reason} />

      <ClusterSection title="This replica">
        <ClusterItem label="Instance ID" value={status.local.instance_id} />
        <ClusterItem label="Boot ID" value={status.local.boot_id} />
        {/*
          Only shown when the deployment opted in with
          CLUSTER_STATUS_EXPOSE_HOSTNAMES: an absent hostname is the
          default, not a fault, so it gets no "not reported" row.
        */}
        {status.local.hostname ? (
          <ClusterItem label="Hostname" value={status.local.hostname} />
        ) : null}
        <ClusterItem
          label="Uptime"
          value={formatAge(status.local.boot_age_secs)}
        />
        <ClusterItem
          label="Lifecycle"
          value={
            status.local.draining
              ? 'Draining'
              : status.local.instance_ready
                ? 'Ready'
                : 'Not ready'
          }
        />
      </ClusterSection>
    </div>
  );
}

/**
 * The state line. The badge carries the state as a word, the sentence
 * beneath it is announced when it changes, and nothing here depends on
 * colour to be read.
 *
 * It renders with `status` still `null` — before the first response, and
 * when the request was refused — so that the live region is already
 * mounted when the state arrives and the arrival is a change a screen
 * reader announces. The badge waits for a state to name.
 */
function ClusterStatePanel({ status }: { status: ClusterStatus | null }) {
  const reason = status ? reasonDetail(status.reason) : null;

  return (
    <section className="cluster-state" aria-label="Deployment state">
      {status ? (
        <span
          className={`badge ${stateBadgeClass(status.state)}`}
          data-testid="cluster-state-badge"
        >
          {stateLabel(status.state)}
        </span>
      ) : null}
      <div className="cluster-state-body">
        <p
          className="cluster-state-text"
          role="status"
          aria-live="polite"
          data-testid="cluster-state-text"
        >
          {status
            ? stateSentence(status, reason)
            : 'State: not read yet. This console has no answer from the gateway.'}
        </p>
        {reason ? (
          <p className="cluster-state-reason">{reason.description}</p>
        ) : null}
      </div>
    </section>
  );
}

function LeaderTaskTable({
  tasks,
  mode,
}: {
  tasks: ClusterLeaderTaskView[] | null;
  mode: ClusterStatus['mode'];
}) {
  if (tasks === null) {
    return (
      <ClusterSection title="Leader tasks">
        <ClusterItem
          label="Background jobs"
          value={
            mode === 'standalone'
              ? 'Not reported: standalone deployments have no maintenance singleton'
              : 'Not reported: the job ledger could not be read'
          }
        />
      </ClusterSection>
    );
  }

  if (tasks.length === 0) {
    return (
      <ClusterSection title="Leader tasks">
        <ClusterItem
          label="Background jobs"
          value="No maintenance job has run yet."
        />
      </ClusterSection>
    );
  }

  return (
    <section className="panel cluster-section" aria-label="Leader tasks">
      <h3>Leader tasks</h3>
      <div
        className="table-scroll cluster-table-scroll"
        role="region"
        aria-label="Leader task health"
        tabIndex={0}
      >
        <table className="logs-table cluster-table">
          <thead>
            <tr>
              <th scope="col">Job</th>
              <th scope="col">Health</th>
              <th scope="col">Held by</th>
              <th scope="col">Last success</th>
              <th scope="col">Fence</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((task, index) => (
              <tr
                className={`event-row ${index % 2 === 1 ? 'is-even' : ''}`}
                key={`${task.name}-${task.fence}-${index}`}
              >
                <td>{task.name}</td>
                <td>
                  <span
                    className={`badge ${
                      task.last_failure_code === null ? 'success' : 'danger'
                    }`}
                  >
                    {task.last_failure_code === null
                      ? 'Healthy'
                      : `Failing: ${failureCodeLabel(task.last_failure_code)}`}
                  </span>
                </td>
                <td>
                  {/*
                   * `held_by_this_instance` is one bit about this
                   * process. It says nothing about any other replica, so
                   * `false` cannot be reported as "another replica holds
                   * it" — during the incident this table exists to show
                   * (a wedged lease, a leader that died with no
                   * successor) that bit is false everywhere and the
                   * reassuring answer would be on every screen in the
                   * fleet.
                   */}
                  {task.held_by_this_instance
                    ? 'This replica'
                    : 'Not this replica'}
                </td>
                <td>{formatAge(task.last_success_age_secs)}</td>
                <td>{task.fence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function RemediationPanel({ reason }: { reason: ReasonDetail | null }) {
  if (!reason) {
    return null;
  }

  return (
    <section className="panel cluster-section" aria-label="Remediation">
      <h3>Remediation</h3>
      <p className="body-copy">{reason.description}</p>
      <p className="body-copy">
        <a
          className="cluster-doc-link"
          href={`${DEPLOYMENT_GUIDE}${reason.anchor}`}
          rel="noreferrer"
          target="_blank"
        >
          {`Deployment guide: ${reason.remediation}`}
        </a>
      </p>
    </section>
  );
}

function ClusterSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="panel cluster-section" aria-label={title}>
      <h3>{title}</h3>
      <dl className="cluster-grid">{children}</dl>
    </section>
  );
}

function ClusterItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="cluster-item spec-row">
      <dt className="k">{label}</dt>
      <dd className="v">{value}</dd>
    </div>
  );
}

function ClusterPermissionNotice() {
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>Cluster permission required</h3>
      <p>
        This token is valid but does not include {CLUSTER_READ_PERMISSION}.
      </p>
    </div>
  );
}

function ClusterErrorMessage({ error }: { error: ClusterLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing cluster status. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  return (
    <div className="error-panel alert error" role="alert">
      <h3>Cluster status request failed</h3>
      <p>{error.message}</p>
    </div>
  );
}

function stateLabel(state: ClusterState): string {
  switch (state) {
    case 'ready':
      return 'Ready';
    case 'degraded':
      return 'Degraded';
    case 'draining':
      return 'Draining';
    case 'not_ready':
      return 'Not ready';
  }
}

function stateBadgeClass(state: ClusterState): string {
  switch (state) {
    case 'ready':
      return 'success';
    case 'degraded':
    case 'draining':
      return 'warning';
    case 'not_ready':
      return 'danger';
  }
}

/**
 * The sentence the live region announces: the state, whether the replica
 * is serving traffic, and the reason's label — never the reason string
 * the API sent.
 */
function stateSentence(
  status: ClusterStatus,
  reason: ReasonDetail | null,
): string {
  const serving = status.ready
    ? 'This replica is serving traffic.'
    : 'This replica is not serving traffic.';
  const because = reason ? ` Reason: ${reason.label}.` : '';
  return `State: ${stateLabel(status.state)}. ${serving}${because}`;
}

function reasonDetail(reason: string | null): ReasonDetail | null {
  if (reason === null) {
    return null;
  }

  return REASON_DETAILS[reason] ?? UNRECOGNIZED_REASON;
}

function failureCodeLabel(code: string): string {
  return FAILURE_CODE_LABELS[code] ?? UNKNOWN_FAILURE_LABEL;
}

function binaryVersionsLabel(status: ClusterStatus): string {
  if (status.binary_versions.length === 0) {
    return 'None reported';
  }

  return status.binary_versions
    .map((entry) => `${entry.version} (${entry.count})`)
    .join(', ');
}

function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function formatAge(seconds: number | null | undefined): string {
  if (
    seconds === null ||
    seconds === undefined ||
    !Number.isFinite(seconds) ||
    seconds < 0
  ) {
    return 'Not reported';
  }

  if (seconds < 1) {
    return 'Under a second ago';
  }
  if (seconds < 60) {
    return `${Math.floor(seconds)}s ago`;
  }
  if (seconds < 3_600) {
    return `${Math.floor(seconds / 60)}m ago`;
  }
  if (seconds < 86_400) {
    return `${Math.floor(seconds / 3_600)}h ago`;
  }

  return `${Math.floor(seconds / 86_400)}d ago`;
}

/**
 * The in-view permission gate, the same shape `PolicyHistoryView` uses:
 * the token's roles claim read against the policy document's roles. A
 * question this console cannot answer is left to the API, whose 403 is
 * handled in the fetch error path.
 */
async function resolveClusterReadPermission(): Promise<ClusterReadPermission> {
  const token = getStoredToken();
  if (!token) {
    return 'unknown';
  }

  const roles = decodeJwtRolesClaim(token);
  if (roles === null) {
    return 'unknown';
  }

  try {
    const policyResult = await fetchPolicy();
    return roles.some((roleName) =>
      roleGrantsClusterRead(policyResult.policy.roles?.[roleName]),
    )
      ? 'granted'
      : 'denied';
  } catch {
    return 'unknown';
  }
}

function roleGrantsClusterRead(role: unknown): boolean {
  if (!isJsonObject(role) || !Array.isArray(role.permissions)) {
    return false;
  }

  return role.permissions.some(
    (permission) => permission === CLUSTER_READ_PERMISSION || permission === '*',
  );
}

function toClusterLoadError(error: unknown): ClusterLoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: `Network request failed: ${error.message}`,
    };
  }

  return { kind: 'network', message: 'Network request failed.' };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
