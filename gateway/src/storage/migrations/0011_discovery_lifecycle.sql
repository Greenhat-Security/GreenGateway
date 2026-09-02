-- Migration 11: revisions on the discovery lifecycle rows (issue #241,
-- PR 12).
--
-- Signals, rule suggestions, and endpoint reviews are the discovery rows an
-- admin transitions (acknowledge, dismiss, accept, mark reviewed). Migration
-- 9 created them with the SQLite shape, where a transition is an
-- unconditional UPDATE by id: last writer wins, and two admins moving the
-- same row from two replicas both "succeed". This migration gives each of
-- those tables a revision so a transition can be one conditional statement
-- -- UPDATE ... SET state = to, revision = revision + 1 WHERE id = ? AND
-- state = from AND revision = expected -- that affects zero rows when the
-- row already moved, in which case the caller answers 409 with the current
-- row and never overwrites.
--
-- What is stored and why:
--
-- - revision starts at 1 for every existing and every new row (the DEFAULT
--   covers the projector's signal inserts and the suggestion engine's
--   inserts unchanged) and increments on every lifecycle write. It is the
--   value the admin API exposes as the row's ETag-style `revision` and
--   accepts back as the expected value; it is per row, never a shared
--   counter, so it says nothing about ordering across rows.
-- - An endpoint review's revision lives with the review row, and that row
--   outlives the review: clearing one nulls reviewed_at and bumps the
--   revision instead of deleting the row, so an endpoint's review revision
--   only ever increases. Deleting it would restart revisions at 1, and a
--   stale "If-Match: 1" held against a review that has since been cleared
--   would then match an unrelated later one and overwrite it -- the ABA the
--   precondition exists to refuse. A row with a NULL reviewed_at reads
--   exactly as no row at all: every read already spells "unreviewed"
--   "reviewed_at IS NULL". An endpoint that was never reviewed has no row
--   and reports revision 0, so "expect 0" is the precondition for the very
--   first mark and two first marks get exactly one winner; after a clear
--   the endpoint is unreviewed at a non-zero revision, and re-marking it
--   expects THAT revision.
--
-- Standalone SQLite adds the same columns in place on open, and rebuilds a
-- review table that predates the nullable reviewed_at (SQLite cannot drop a
-- column constraint in place).

ALTER TABLE greengateway.discovery_signals
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

ALTER TABLE greengateway.discovery_rule_suggestions
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

ALTER TABLE greengateway.discovery_endpoint_reviews
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

-- A cleared review keeps its row (and its revision) with no reviewed_at.
ALTER TABLE greengateway.discovery_endpoint_reviews
    ALTER COLUMN reviewed_at DROP NOT NULL;
