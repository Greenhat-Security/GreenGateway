-- Migration 18: durable service-token and JWT revocation change evidence
-- (issue #425, PR 2b).
--
-- Service-token rotate and revoke already commit a token row change, a
-- shared security revision and a security_outbox row together. None of
-- them named WHO made the change: the store took a token ID only, the
-- token row's created_by is the original creator, and the admin audit
-- event that names the actor is emitted after the commit. A JWT revoke
-- did store an actor on its jwt_revocations row, but a later extension or
-- reactivation overwrites it and expiry cleanup deletes the row. These
-- two tables are the evidence that outlives both.
--
-- - One row per committed change, written in the SAME transaction as the
--   mutation it describes (ha-state-model.md section 2, rule 2). A change
--   whose evidence cannot be inserted rolls back and reports failure. A
--   change that does nothing writes nothing: a repeat revoke of a revoked
--   token, a rotate of a revoked token (a conflict), an unknown token, and
--   a JWT revoke already covered by an effective row.
-- - No foreign keys. token_id names a service_tokens row and (issuer,
--   jti_hash) a jwt_revocations row, but the evidence must survive that
--   row's removal (JWT expiry cleanup deletes rows; a token row could be
--   removed by an operator), so it can neither cascade nor restrict.
--   Nothing references the outbox either: outbox maintenance must never
--   cascade into evidence.
-- - actor_user_id follows connection_change_evidence (migration 16): the
--   actor as text, no foreign key, bounded by exactly the principal
--   subject bound authentication enforces (auth/principal.rs
--   MAX_PRINCIPAL_SUBJECT_BYTES), so no principal a validator accepted is
--   refused here. The only JWT revoke caller today is the revoke-jwt
--   operator command, which records its fixed system label
--   'operator:revoke-jwt': system provenance, not an authenticated human.
-- - event_id identifies this record and operation_id the logical operation
--   that produced it. The writer generates both and never regenerates
--   them; an operation records each action at most once.
-- - Service tokens: prior_version and new_version are the token row's
--   revision before and after the change, the same values as its outbox
--   row's from_version and to_version; security_revision is the shared
--   revision the change took, the same value as its outbox row's revision.
-- - JWT revocations: issuer and jti_hash are the row's key, the digest
--   the store already derives under the deployment ID and issuer, never
--   the raw jti. expires_at is the row's effective expiry after the change
--   (NULL means until an operator cleans it up), so an extension or a
--   reactivation is a second row for the same key with its own actor,
--   expiry and revision, not an overwrite of the first.
-- - committed_at is the database clock at transaction acceptance, never a
--   replica's wall clock.
-- - Identifiers, revisions, the actor and the JWT expiry only. No
--   plaintext token, token hash, display prefix, scope list or raw jti is
--   stored, so nothing here needs the secret-handling rules of the tables
--   it describes.
-- - action is a closed vocabulary using the proposed authority-event
--   operation codes (docs/schemas/authority_event.v1.schema.json); a later
--   migration extends it when another change records evidence.
-- - Rows are append-only by contract: no gateway path updates or deletes
--   them, and JWT expiry cleanup does not touch this table. Delivery and
--   retention belong to later #425 slices, and the retention rule there is
--   that undelivered evidence is never erased.

CREATE TABLE greengateway.service_token_change_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 4096
    ),
    action text NOT NULL CHECK (
        action IN ('service_token.rotate', 'service_token.revoke')
    ),
    token_id text NOT NULL CHECK (octet_length(token_id) BETWEEN 1 AND 128),
    prior_version bigint NOT NULL CHECK (prior_version >= 1),
    new_version bigint NOT NULL CHECK (new_version > prior_version),
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    committed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (operation_id, action)
);

-- Reconciliation reads one token's evidence in commit order: an ambiguous
-- rotate or revoke response is resolved by asking what committed, not by
-- retrying the mutation.
CREATE INDEX idx_ggw_service_token_change_evidence_token
    ON greengateway.service_token_change_evidence(token_id, security_revision);

CREATE TABLE greengateway.jwt_revocation_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 4096
    ),
    action text NOT NULL CHECK (action IN ('jwt.revoke')),
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    jti_hash text NOT NULL CHECK (
        octet_length(jti_hash) = 64 AND jti_hash ~ '^[0-9a-f]+$'
    ),
    expires_at timestamptz,
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    committed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (operation_id, action)
);

CREATE INDEX idx_ggw_jwt_revocation_evidence_key
    ON greengateway.jwt_revocation_evidence(issuer, jti_hash, security_revision);
