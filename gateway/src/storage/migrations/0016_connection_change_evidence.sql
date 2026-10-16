-- Migration 16: durable Connection change evidence (issue #425, PR 2).
--
-- A Connection delete already commits a security_outbox tombstone
-- (resource_type 'connection', to_version 0) naming the Connection, its
-- prior specification version and the shared security revision. What it
-- did not keep was WHO deleted it: the store ignored the actor, the admin
-- audit event that names one is emitted after the commit, and the only
-- actor-bearing rows (connection_documents) cascade with the record. This
-- table is the evidence that outlives the Connection.
--
-- - One row per committed change, written in the SAME transaction as the
--   mutation it describes (ha-state-model.md section 2, rule 2). A change
--   whose evidence cannot be inserted rolls back and reports failure; a
--   rejected change -- stale ETag, dependency conflict, missing record, a
--   lost race -- writes nothing.
-- - connection_id deliberately has NO foreign key. The evidence must
--   survive the deletion it records, so it can neither cascade with the
--   record nor restrict its removal.
-- - actor_user_id follows connection_documents and jwt_revocations: the
--   authenticated principal's user ID as text, with no foreign key. Its
--   bound is exactly the principal subject bound authentication already
--   enforces (auth/principal.rs MAX_PRINCIPAL_SUBJECT_BYTES), so no
--   principal a validator accepted is refused here.
-- - event_id identifies this record and operation_id the logical operation
--   that produced it. The writer generates both and never regenerates
--   them; an operation records each action at most once.
-- - prior_version is the specification version the change replaced
--   (connection_records.connection_revision, the outbox from_version);
--   security_revision is the shared revision the change took, the same
--   value as its outbox row's revision. No foreign key to the outbox:
--   outbox maintenance must never cascade into evidence.
-- - committed_at is the database clock at transaction acceptance, never a
--   replica's wall clock.
-- - Identifiers, revisions and the actor only. No specification, endpoint,
--   secret ID, credential binding, ciphertext or provider locator is
--   stored, so nothing here needs the secret-handling rules of the tables
--   it describes.
-- - action is a closed vocabulary using the proposed authority-event
--   operation codes (docs/schemas/authority_event.v1.schema.json); a later
--   migration extends it when another change records evidence.
-- - Rows are append-only by contract: no gateway path updates or deletes
--   them. Delivery and retention belong to later #425 slices, and the
--   retention rule there is that undelivered evidence is never erased.

CREATE TABLE greengateway.connection_change_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 4096
    ),
    action text NOT NULL CHECK (action IN ('connection.delete')),
    connection_id uuid NOT NULL,
    prior_version bigint NOT NULL CHECK (prior_version >= 1),
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    committed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (operation_id, action)
);

-- Reconciliation reads one Connection's evidence in commit order: an
-- ambiguous delete response is resolved by asking whether the Connection
-- has a committed deletion, not by retrying the mutation.
CREATE INDEX idx_ggw_connection_change_evidence_connection
    ON greengateway.connection_change_evidence(connection_id, security_revision);
