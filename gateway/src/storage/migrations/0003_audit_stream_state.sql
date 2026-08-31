-- Migration 3: persistent stream position state (issue #241, PR 6).
--
-- PR 5 assigned stream positions from max(position) of the committed rows.
-- That regresses to 1 if retention ever deletes every audit_stream row,
-- which would silently strand every durable cursor (a client holding
-- position 50 would wait forever for positions that get renumbered from
-- 1). This migration introduces a single-row counter that retention never
-- deletes; writers reserve positions from it inside the append
-- transaction, so the number space is strictly monotonic for the life of
-- the deployment while remaining rollback-safe (an aborted append's
-- reservation is rolled back with it -- the property a bare sequence
-- does not have). See storage/postgres_audit.rs for the protocol.

CREATE TABLE greengateway.audit_stream_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_position bigint NOT NULL
);

INSERT INTO greengateway.audit_stream_state (singleton, last_position)
VALUES (true, 0);

-- A deployment mid-PR-5 may already have stream rows: their maximum must
-- become the counter's floor so numbering continues rather than restarts.
UPDATE greengateway.audit_stream_state
SET last_position = greatest(
    last_position,
    coalesce((SELECT max(position) FROM greengateway.audit_stream), 0)
);
