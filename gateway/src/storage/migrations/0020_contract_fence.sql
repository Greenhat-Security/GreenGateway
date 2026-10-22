-- Migration 20: the durable contract fence and the backfill ledger (issue
-- #426, PR 3).
--
-- The operation gate (migration 17, storage/compatibility.rs) admits a
-- write only while every live member advertises what it requires. Liveness
-- is judged on the database clock against the stale window, so a member
-- that lacks the capability can be stopped, swept, and started again
-- after the write, and a member paused past the window comes back with
-- its heartbeat. A stale row disappearing is not proof that the member
-- retired. Live-roster agreement is therefore enough only for data a
-- lacking member refuses; data it would misread, and any schema
-- contraction, need a fence that outlives the roster. This table is that
-- fence.
--
-- - contract_fence is one row, and it only ever moves forward. It names
--   the lowest schema version a member's serving range must reach
--   (minimum_schema) and the capabilities a member must implement
--   (capabilities: the same closed, comma-separated vocabulary and bounds
--   as cluster_members.capabilities, migration 17). A gateway that does
--   not satisfy it refuses to start, writes no heartbeat, so it cannot
--   rejoin the roster, and admits no gated operation. The capability set
--   is read by the gateway that checks it: a name it was not built with is
--   one it lacks, so an unknown name always excludes it.
-- - Raising it is one transaction on the replica that admits an operation
--   declaring a durable activation fence: the row is locked FOR UPDATE,
--   the roster, the ledger and any backfill the operation needs are read
--   under that lock, and the fence is raised only if every live member
--   already satisfies the raised fence. Every heartbeat takes FOR SHARE on
--   the same row inside its own statement, so a member's boot or rejoin
--   either lands before the raise reads the roster (and holds the raise
--   off) or after it commits (and is refused). generation counts raises;
--   raised_at (database clock) and raised_by (the operation that raised
--   it) are for operators. All three are NULL-or-zero until the first
--   raise.
-- - The trigger below makes forward-only a property of the database, not
--   a convention of the writer: an UPDATE that lowers minimum_schema, drops
--   a capability, or changes anything without advancing generation is
--   refused, and so are DELETE and TRUNCATE. The runtime role holds DML on
--   every table in this schema (roles-and-grants.md), so without the
--   trigger a buggy or hostile writer could reopen the door for a retired
--   build. Only the schema owner (the migration role) can drop the
--   trigger, which is DDL, and restoring an older backup to make an older
--   binary start is exactly what the deployment guide forbids.
-- - schema_backfills records the progress of a named backfill: running
--   until it finishes, then verified (its own verification found nothing
--   left to backfill) or failed. An operation that depends on a backfill is
--   admitted only once its row says verified. A missing row, a running one
--   -- including one whose backfill was interrupted and never finished --
--   and a failed one all refuse, so an absent or partial backfill can
--   never be read as a complete one. No backfill ships with this
--   migration; the table is empty until one does.
-- - Additive only. No existing table changes. Nothing is backfilled: the
--   fence starts at generation 0 with no requirement, which every gateway
--   that can serve this schema satisfies.

CREATE TABLE greengateway.contract_fence (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    minimum_schema integer NOT NULL DEFAULT 0 CHECK (minimum_schema >= 0),
    capabilities text NOT NULL DEFAULT '' CHECK (
        capabilities ~ '^([a-z][a-z0-9_]{0,63}(,[a-z][a-z0-9_]{0,63}){0,31})?$'
    ),
    raised_at timestamptz,
    raised_by text CHECK (raised_by IS NULL OR raised_by ~ '^[a-z][a-z0-9_.]{0,63}$'),
    CHECK ((generation = 0) = (raised_at IS NULL)),
    CHECK ((raised_at IS NULL) = (raised_by IS NULL))
);

INSERT INTO greengateway.contract_fence (singleton) VALUES (true);

CREATE FUNCTION greengateway.contract_fence_moves_forward() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'the contract fence is never removed'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
        OR NEW.generation <= OLD.generation
        OR NEW.minimum_schema < OLD.minimum_schema
        OR NOT (string_to_array(OLD.capabilities, ',') <@ string_to_array(NEW.capabilities, ','))
    THEN
        RAISE EXCEPTION 'the contract fence only moves forward'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER contract_fence_moves_forward
    BEFORE UPDATE OR DELETE ON greengateway.contract_fence
    FOR EACH ROW EXECUTE FUNCTION greengateway.contract_fence_moves_forward();

CREATE TRIGGER contract_fence_is_never_truncated
    BEFORE TRUNCATE ON greengateway.contract_fence
    FOR EACH STATEMENT EXECUTE FUNCTION greengateway.contract_fence_moves_forward();

CREATE TABLE greengateway.schema_backfills (
    name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    state text NOT NULL CHECK (state IN ('running', 'verified', 'failed')),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    CHECK ((state = 'running') = (finished_at IS NULL))
);
