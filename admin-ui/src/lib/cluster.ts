import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

/**
 * The read-only cluster status view served by
 * `GET /v1{ADMIN_PREFIX}/cluster` (issue #241, PR 14).
 *
 * The field names and nullability mirror `gateway/src/cluster_status.rs`
 * exactly: every section the gateway can fail to read comes back `null`
 * rather than absent, and standalone mode leaves the sections that only
 * exist in a cluster (the projector, the singleton's jobs, the shared
 * pool, the shared migration ledger) `null` too.
 */
export type ClusterMode = 'standalone' | 'cluster';

export type ClusterState = 'ready' | 'degraded' | 'draining' | 'not_ready';

export type ClusterSchemaView = {
  /** How many migrations the shared ledger carries; `null` in standalone. */
  current_version: number | null;
  binary_min: number;
  binary_max: number;
  compatible: boolean;
};

export type ClusterReplicaCounts = {
  ready: number;
  total: number;
};

export type ClusterBinaryVersionCount = {
  version: string;
  count: number;
};

export type ClusterLocalView = {
  instance_id: string;
  boot_id: string;
  boot_age_secs: number;
  /**
   * This replica's own hostname. `null` unless the deployment sets
   * `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`; never another replica's.
   */
  hostname: string | null;
  instance_ready: boolean;
  draining: boolean;
  compiled_security_revision: number;
  observed_security_revision: number;
  revision_lag: number;
};

export type ClusterReconcileView = {
  last_pass_age_secs: number | null;
  failures_total: number;
};

export type ClusterProjectorView = {
  fence: number;
  checkpoint_position: number;
  stream_head: number | null;
  lag_events: number | null;
  leader_present: boolean;
  last_flush_age_secs: number;
};

export type ClusterLeaderTaskView = {
  name: string;
  held_by_this_instance: boolean;
  fence: number;
  last_success_age_secs: number | null;
  last_failure_code: string | null;
};

export type ClusterAuditQueueView = {
  queue_depth: number;
  queue_capacity: number;
  oldest_age_secs: number;
  dropped_total: number;
};

export type ClusterPoolView = {
  size: number;
  available: number;
  waiting: number;
  timeouts_total: number;
};

export type ClusterStatus = {
  mode: ClusterMode;
  /** Whether `/readyz` would answer 200 right now. */
  ready: boolean;
  state: ClusterState;
  /** One of a fixed reason vocabulary, never free text. */
  reason: string | null;
  schema: ClusterSchemaView;
  replicas: ClusterReplicaCounts;
  binary_versions: ClusterBinaryVersionCount[];
  local: ClusterLocalView;
  reconcile: ClusterReconcileView;
  projector: ClusterProjectorView | null;
  leader_tasks: ClusterLeaderTaskView[] | null;
  audit: ClusterAuditQueueView;
  pools: { database: ClusterPoolView | null };
};

export function fetchClusterStatus(): Promise<ClusterStatus> {
  return adminFetchJson<ClusterStatus>(adminApiUrl('/cluster'));
}
