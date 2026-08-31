-- Migration 5: the versioned tools control plane (issue #241, PR 8).
--
-- The tools document is the TOOLS_FILE's local lane -- one singleton
-- document (`schema_version` + `tools[]`) -- managed with exactly the
-- model migration 4 established for the policy document:
--
-- - tool_documents holds the immutable versions. Each row is also the
--   history entry (actor, diff summary, full snapshot); a rollback or
--   re-registration writes a NEW version, never an edit.
-- - tool_active is the singleton active pointer; its security_revision is
--   the revision the compiled tool snapshot must be keyed by.
-- - Every commit advances the shared greengateway.security_revision_state
--   counter (the same counter policy commits advance) and appends one
--   greengateway.security_outbox row with resource_type 'tools', in the
--   same transaction: two writers with the same expected ETag produce one
--   winner, and a mutation cannot succeed without its durable record.
--
-- Unlike the policy control plane, a deployment seeds an empty tools
-- document idempotently at first boot (an empty local lane is a valid
-- tools state -- standalone without TOOLS_FILE serves exactly that), so
-- there is no uninitialized-deployment failure mode for this resource.

CREATE TABLE greengateway.tool_documents (
    version bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    diff_summary jsonb NOT NULL,
    document jsonb NOT NULL,
    document_etag text NOT NULL
);

CREATE INDEX idx_ggw_tool_documents_created_at
    ON greengateway.tool_documents(created_at DESC);

CREATE TABLE greengateway.tool_active (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active_version bigint NOT NULL
        REFERENCES greengateway.tool_documents(version),
    document_etag text NOT NULL,
    security_revision bigint NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT now()
);
