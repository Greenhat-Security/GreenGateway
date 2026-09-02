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
-- - An endpoint review's revision lives with the review row: clearing a
--   review deletes the row (the migration 9 shape the reads depend on),
--   and a later mark starts a new row at 1. The unreviewed state is
--   reported as revision 0, so "expect 0" is the precondition for the
--   first mark and two first marks get exactly one winner.
--
-- Standalone SQLite adds the same columns in place on open.

ALTER TABLE greengateway.discovery_signals
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

ALTER TABLE greengateway.discovery_rule_suggestions
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

ALTER TABLE greengateway.discovery_endpoint_reviews
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);
