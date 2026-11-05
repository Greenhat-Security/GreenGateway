-- Migration 27: service-token issue evidence (issue #425).
--
-- Migration 18 made every committed service-token rotate and revoke write one
-- append-only service_token_change_evidence row in the change's own
-- transaction, and migration 21 journals each row for delivery. Issuing a
-- token wrote none: its token row's created_by named the creator and its
-- outbox row the shared revision, and nothing recorded the issue as an
-- authority change with its actor, its operation identity or a delivery. This
-- migration lets the same table record the issue:
--
-- - action admits 'service_token.issue', the proposed authority-event
--   operation code (docs/schemas/authority_event.v1.schema.json), beside
--   'service_token.rotate' and 'service_token.revoke'.
-- - prior_version becomes nullable, because an issue has no revision before
--   it. The version rule moves from two column CHECKs to one table CHECK
--   that names each action's transition: an issue records no prior version
--   and new_version 1, the token row's first revision and its create outbox
--   row's to_version; a rotate or a revoke records a prior version of at
--   least 1 and a strictly greater new one, as before.
-- - The issue's row is written in the create's transaction, after the token
--   row and the outbox row, carrying the outbox row's shared revision, and is
--   journaled in the same transaction under the row's own event_id
--   (service_token_change_evidence is already a journal source). A full
--   journal refuses the create, which rolls back with everything else.
-- - Identifiers, revisions and the actor only, as for the other two actions:
--   never the plaintext the create returns, nor its hash, display prefix or
--   scopes.
--
-- Nothing is backfilled. A token issued before this migration keeps its
-- created_by as the only record of who issued it, and evidence is
-- append-only, so no row is guessed for it: its first evidence row, if any,
-- is a later rotate or revoke. Every existing row is a rotate or a revoke and
-- already satisfies the new CHECK. The journal and the delivery cursor are
-- unchanged.

ALTER TABLE greengateway.service_token_change_evidence
    DROP CONSTRAINT service_token_change_evidence_action_check,
    DROP CONSTRAINT service_token_change_evidence_prior_version_check,
    DROP CONSTRAINT service_token_change_evidence_check,
    ALTER COLUMN prior_version DROP NOT NULL,
    ADD CONSTRAINT service_token_change_evidence_action_check CHECK (
        action IN ('service_token.issue', 'service_token.rotate', 'service_token.revoke')
    ),
    ADD CONSTRAINT service_token_change_evidence_versions CHECK (
        (action = 'service_token.issue' AND prior_version IS NULL AND new_version = 1)
        OR (action <> 'service_token.issue' AND prior_version IS NOT NULL
            AND prior_version >= 1 AND new_version > prior_version)
    );
