-- Migration 17: capability advertisements on the cluster roster (issue
-- #426, PR 1).
--
-- A replica's schema and document ranges say which ledger it can serve and
-- which document majors it parses. They do not say which *operations* it
-- understands, and an operation can write data an older replica cannot
-- interpret or enforce while both serve the same schema. This column is
-- where each replica says what it can do, so a write that needs every live
-- member to understand it can be held until they all do
-- (storage/compatibility.rs; ha-state-model.md section 7).
--
-- - capabilities is a comma-separated list of names from a closed,
--   compiled-in vocabulary, sorted and deduplicated by the writer. Each
--   replica writes only its own row, on every heartbeat, and instance IDs
--   are generated per boot, so a row's advertisement is always the running
--   process's own.
-- - The check is the whole bound: at most 32 names, each a lowercase
--   letter followed by at most 63 lowercase letters, digits or
--   underscores. A reader still recognizes only the names it was built
--   with; an unknown name grants nothing, so the check bounds the column
--   rather than deciding what any name means.
-- - The default is the empty list. A row written by a gateway that
--   predates this migration -- one still heartbeating while the upgrade
--   runs -- therefore advertises nothing, and holds every gated operation
--   until it stops and its row goes stale. Nothing is backfilled: an
--   absent advertisement must never be read as a present one.
-- - Additive only. No existing column changes, and no existing reader
--   names this column.

ALTER TABLE greengateway.cluster_members
    ADD COLUMN capabilities text NOT NULL DEFAULT '' CHECK (
        capabilities ~ '^([a-z][a-z0-9_]{0,63}(,[a-z][a-z0-9_]{0,63}){0,31})?$'
    );
