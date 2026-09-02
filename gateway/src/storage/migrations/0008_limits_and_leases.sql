-- Migration 8: distributed rate limiting and execution leases (issue #241,
-- PR 10).
--
-- Rate-limit buckets. In standalone mode a bucket lives in one process,
-- so N replicas each grant the configured burst -- N times the limit the
-- operator set. Cluster mode makes one bucket per (lane, caller) here and
-- decides every request with one atomic statement on database time, so
-- one configured burst of N permits N requests across the cluster.
--
-- What is stored and what is not:
--
-- - key_digest is HMAC-SHA-256 under the deployment's rate-limit keyring
--   over (deployment id, lane, caller key). The caller key -- a client IP
--   for the global lanes, an issuer-and-method-qualified principal for the
--   policy lane -- never reaches the database, and a reader of the table
--   (or of a backup) cannot enumerate the IPv4 space against it without
--   the key.
-- - tat is the GCRA "theoretical arrival time": the instant the bucket's
--   allowance is next whole. The decision is GREATEST(tat, now()) - now()
--   against the burst tolerance, and the store advances tat by the
--   emission interval on every allowed request. That is exactly the local
--   token bucket (burst B, starting full, refilling at rps) expressed as
--   one comparison and one assignment, so a replica never keeps a private
--   count that could drift from the shared one.
-- - allowed is the last decision, kept so the statement can RETURN it
--   without a second read.
-- - updated_at orders eviction (oldest first) and the idle sweep. Every
--   comparison is against now(): database time is authoritative for rate
--   math (HA state model).
--
-- rate_limit_cardinality is the exact count of live buckets per
-- deployment, moved in the same statement that inserts or deletes rows,
-- so it cannot drift. It is the hard global bound: when a new key pushes
-- the count past the configured maximum, the store evicts the oldest
-- buckets in one bounded statement. A spray of fresh identities therefore
-- displaces idle buckets, never grows the table without limit.
CREATE TABLE greengateway.rate_limit_buckets (
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    lane text NOT NULL CHECK (lane IN ('read', 'write', 'policy')),
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    tat timestamptz NOT NULL,
    allowed boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, lane, key_digest)
);

CREATE INDEX idx_ggw_rate_limit_buckets_updated
    ON greengateway.rate_limit_buckets(deployment_id, updated_at);

CREATE TABLE greengateway.rate_limit_cardinality (
    deployment_id text PRIMARY KEY CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    live bigint NOT NULL DEFAULT 0 CHECK (live >= 0)
);

-- Execution leases: the cluster-wide bound on running tool invocations.
-- Standalone mode bounds concurrency with process-local semaphores; with N
-- replicas that is N times the configured global and per-tool limits.
-- Cluster mode makes each permitted concurrent invocation a slot in a
-- scope ('global', or 'tool:<name>') and a running invocation the holder
-- of one slot's lease.
--
-- - fence is drawn from execution_lease_fence, one sequence for the whole
--   deployment, so every acquisition -- of any slot in any scope -- carries
--   a strictly larger token than every earlier one. A holder that lost its
--   lease and a successor that reclaimed the slot are told apart by fence,
--   never by time, and a stale holder's late write is refused by comparing
--   fences (assert_current), not by hoping it arrives first.
-- - holder_instance is the replica's foundation instance ID; invocation is
--   the bounded request ID, for operators correlating a held slot with a
--   request.
-- - expires_at is database time. A renewal moves it only while the holder
--   still owns the slot at its fence; a slot whose expires_at has passed is
--   reclaimable by anyone. The runtime renews well inside the TTL and
--   cancels its local work on the first failed renewal, so the work stops
--   before the slot can be reclaimed, never after.
CREATE SEQUENCE greengateway.execution_lease_fence AS bigint START WITH 1;

CREATE TABLE greengateway.execution_leases (
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    scope text NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 320),
    slot integer NOT NULL CHECK (slot >= 0),
    fence bigint NOT NULL CHECK (fence >= 1),
    holder_instance uuid NOT NULL,
    invocation text NOT NULL CHECK (octet_length(invocation) BETWEEN 1 AND 128),
    acquired_at timestamptz NOT NULL DEFAULT now(),
    renewed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, scope, slot)
);

CREATE INDEX idx_ggw_execution_leases_expiry
    ON greengateway.execution_leases(deployment_id, expires_at);
