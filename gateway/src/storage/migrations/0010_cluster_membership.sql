-- Migration 10: cluster membership and singleton maintenance ownership
-- (issue #241, PR 13).
--
-- cluster_members is the deployment's roster: one row per live replica,
-- written by that replica alone. A row is created at boot (started_at),
-- refreshed on every heartbeat (last_heartbeat_at, the security revisions
-- the replica has compiled and last observed), stamped when the replica
-- becomes ready (ready_at) and when it begins draining (draining_at), and
-- removed by the maintenance singleton once its heartbeat is older than
-- the configured stale window -- never by request handling and never by
-- the member itself, so a partitioned replica's row is reaped only by
-- database time.
--
-- What the columns are for:
--
-- - instance_id / boot_id are the replica's foundation identity: the
--   instance distinguishes live replicas, the boot distinguishes restarts
--   of the same instance so nothing a previous boot owned is inherited.
-- - fingerprint is the hex SHA-256 static-configuration fingerprint. A
--   replica that finds a live member with a different fingerprint refuses
--   readiness (HA state model invariant 14) until the members agree; it
--   does not exit, so a rolling change completes.
-- - schema_version_min/max is the migration-manifest range this binary
--   accepts; document_version_min/max is the policy/tools document schema
--   range it enforces. Both are what an operator (and PR 14's status API)
--   read to see whether a rolling window is compatible.
-- - compiled_security_revision is the watermark the replica has confirmed
--   every security resource current at; observed_security_revision is the
--   authority's counter as the replica last read it. The gap between them
--   is the replica's reconciliation lag, and it is the revision
--   acknowledgement PR 14 renders.
-- - last_error_code is the last classified failure the replica's own
--   background work recorded, bounded to a short code, never a message.
--
-- Every timestamp is database time (HA state model): a replica's wall
-- clock never decides whether another replica is live.
CREATE TABLE greengateway.cluster_members (
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    instance_id uuid PRIMARY KEY,
    boot_id uuid NOT NULL,
    binary_version text NOT NULL CHECK (octet_length(binary_version) BETWEEN 1 AND 64),
    schema_version_min integer NOT NULL CHECK (schema_version_min >= 0),
    schema_version_max integer NOT NULL CHECK (schema_version_max >= schema_version_min),
    document_version_min integer NOT NULL CHECK (document_version_min >= 0),
    document_version_max integer NOT NULL CHECK (document_version_max >= document_version_min),
    fingerprint text NOT NULL CHECK (octet_length(fingerprint) = 64),
    started_at timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
    ready_at timestamptz,
    draining_at timestamptz,
    compiled_security_revision bigint NOT NULL DEFAULT 0 CHECK (compiled_security_revision >= 0),
    observed_security_revision bigint NOT NULL DEFAULT 0 CHECK (observed_security_revision >= 0),
    last_error_code text CHECK (last_error_code IS NULL OR octet_length(last_error_code) BETWEEN 1 AND 64)
);

CREATE INDEX idx_ggw_cluster_members_heartbeat
    ON greengateway.cluster_members(deployment_id, last_heartbeat_at);

-- maintenance_jobs records the outcome of every singleton maintenance job
-- (JWT revocation cleanup, rate-limit idle sweep, pending-login prune,
-- stale member sweep, audit retention, lease reaping). One replica holds
-- the maintenance lease (execution_leases scope 'maintenance', capacity
-- 1) and runs the jobs; fence is the lease fence the current leader
-- adopted the rows at.
--
-- The fence is the whole point of the table's write discipline: the
-- leader adopts the rows by raising fence to its lease fence (never
-- lowering it), and every later write of a job's timestamps and outcome
-- carries WHERE fence = <the writer's lease fence>. A leader that lost its
-- lease, was superseded, and then resumed finds its fence below the
-- successor's and its late write matches no row -- refused by the
-- predicate, not by hoping it arrived first.
CREATE TABLE greengateway.maintenance_jobs (
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    job text NOT NULL CHECK (octet_length(job) BETWEEN 1 AND 64),
    fence bigint NOT NULL CHECK (fence >= 0),
    last_started_at timestamptz,
    last_success_at timestamptz,
    last_failure_code text CHECK (last_failure_code IS NULL OR octet_length(last_failure_code) BETWEEN 1 AND 64),
    last_duration_ms bigint CHECK (last_duration_ms IS NULL OR last_duration_ms >= 0),
    PRIMARY KEY (deployment_id, job)
);
