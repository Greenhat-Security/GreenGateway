-- Migration 4: the versioned policy/history control plane (issue #241, PR 7).
--
-- Four tables implement the HA state model's section 2 transaction for the
-- policy document:
--
-- - policy_documents holds the immutable versioned documents. Each row is
--   also the history entry: actor, diff summary, and the full validated
--   snapshot append together, newest-last, and rows are never updated or
--   deleted (a rollback writes the old document as a NEW version).
-- - security_revision_state is the monotonic security-revision counter.
--   Like audit_stream_state, the reservation is a plain row UPDATE inside
--   the mutation transaction, so an aborted mutation's revision rolls back
--   with it (the property a bare sequence does not have). Every
--   security-relevant control-plane mutation -- policy today, tools,
--   tokens, and revocations in later #241 PRs -- advances this one
--   counter, so a replica's compiled snapshot is keyed by a single
--   revision that identifies the exact active combination of shared
--   security state.
-- - policy_active is the singleton active pointer. Its security_revision
--   column records the revision at which the pointed-to document was
--   activated: the number a replica must hold to serve under that
--   document, and the number a strict request reads to decide whether its
--   compiled snapshot is current.
-- - security_outbox is the durable change record. One row per committed
--   security revision, written in the same transaction as the mutation it
--   describes (the state model's "a mutation is not successful unless its
--   audit is durable" rule). Replicas poll it to reconcile; notifications
--   may later make that poll cheaper but can never replace it. Payload
--   columns are identifiers and revisions only -- no principals, no
--   policy content (the state model's privacy section). Cleanup of
--   consumed rows is fenced singleton work that arrives with #241 PR 13;
--   until then the table grows one small row per committed mutation,
--   which is to say: at the rate administrators edit policy.
--
-- A mutation transaction therefore: locks policy_active FOR UPDATE ->
-- rejects a stale expected ETag -> inserts the new immutable version ->
-- reserves the next security revision -> advances the active pointer ->
-- appends the outbox row -> commits once. Two writers holding the same
-- expected ETag serialize on the row lock; the second sees the first's
-- pointer and fails its precondition. Nothing partial can commit.

CREATE TABLE greengateway.policy_documents (
    version bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    diff_summary jsonb NOT NULL,
    document jsonb NOT NULL,
    document_etag text NOT NULL
);

CREATE INDEX idx_ggw_policy_documents_created_at
    ON greengateway.policy_documents(created_at DESC);

CREATE TABLE greengateway.security_revision_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_revision bigint NOT NULL
);

INSERT INTO greengateway.security_revision_state (singleton, last_revision)
VALUES (true, 0);

CREATE TABLE greengateway.policy_active (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active_version bigint NOT NULL
        REFERENCES greengateway.policy_documents(version),
    document_etag text NOT NULL,
    security_revision bigint NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE greengateway.security_outbox (
    revision bigint PRIMARY KEY,
    resource_type text NOT NULL,
    from_version bigint,
    to_version bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_ggw_security_outbox_created_at
    ON greengateway.security_outbox(created_at DESC);
