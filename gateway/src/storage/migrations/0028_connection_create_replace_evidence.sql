-- Migration 28: Connection create, replace and credential binding change
-- evidence (issue #425).
--
-- Migration 16 made every committed Connection delete write one append-only
-- connection_change_evidence row in the deleting transaction, migration 21
-- journals it for delivery and migration 24 records the whole actor. A
-- create or a replace wrote none: its connection_documents row names the
-- writing subject and its outbox row the shared revision, but that history
-- cascades with the Connection, records no issuer, actor kind, auth mode or
-- operation identity, and is never delivered. Changes to credential
-- authority (the credential revision a replace advances) were recorded
-- nowhere apart from the new revision itself. This migration lets the same
-- table record all three, as the standalone Connections database's
-- migration 12 already does:
--
-- - action admits 'connection.create', 'connection.replace' and
--   'credential.binding_change', the proposed authority-event operation
--   codes (docs/schemas/authority_event.v1.schema.json), beside
--   'connection.delete'.
-- - revision_axis names the revision chain prior_version and new_version
--   belong to: 'connection' (connection_records.connection_revision, the
--   specification version and the outbox's from/to version) or 'credential'
--   (connection_records.credential_revision). It is closed, and each action
--   has exactly one axis: credential.binding_change is on the credential
--   axis, every connection.* action on the connection axis. Every existing
--   row is a connection.delete, whose prior_version migration 16 defines as
--   the connection revision, so the column is added with that value for
--   them; the default exists only for this ALTER and is dropped below, so
--   every writer names its axis.
-- - new_version is the revision after the change on that axis (nullable),
--   and prior_version becomes nullable. One table CHECK names each action's
--   transition, and guards every comparison with IS NOT NULL because a CHECK
--   whose expression is NULL passes:
--     connection.create          no prior version, new version 1;
--     connection.replace         a prior version of at least 1 and a
--                                strictly greater new one;
--     credential.binding_change  a prior version of at least 0 (a Connection
--                                created without credential authority has
--                                credential revision 0) and a strictly
--                                greater new one;
--     connection.delete          a prior version of at least 1 and no new
--                                one, as before.
-- - A create writes its row and a replace its connection.replace row in the
--   change's transaction, after the outbox row and carrying its shared
--   revision; a replace that advances the credential revision also writes a
--   credential.binding_change row under the same operation_id and the same
--   shared revision (UNIQUE (operation_id, action) admits both). Every row
--   is journaled in the same transaction under its own event_id
--   (connection_change_evidence is already a journal source), so a full
--   journal refuses the change. A refused change and an identical replace,
--   which commits nothing, write none.
-- - Identifiers, revisions and the actor only, as for a delete: no
--   specification, endpoint, binding identifier, bound secret ID, provider
--   locator or ciphertext. A credential change is recorded by the
--   Connection's identity and credential revision alone.
--
-- Nothing is backfilled. A Connection created or replaced before this
-- migration keeps its connection_documents rows as the only record of who
-- wrote it, and evidence is append-only, so no row is guessed for it. Every
-- existing row already satisfies the new CHECK. The journal and the delivery
-- cursor are unchanged.

ALTER TABLE greengateway.connection_change_evidence
    DROP CONSTRAINT connection_change_evidence_action_check,
    DROP CONSTRAINT connection_change_evidence_prior_version_check,
    ALTER COLUMN prior_version DROP NOT NULL,
    ADD COLUMN new_version bigint,
    ADD COLUMN revision_axis text NOT NULL DEFAULT 'connection',
    ADD CONSTRAINT connection_change_evidence_action_check CHECK (
        action IN (
            'connection.create', 'connection.replace', 'credential.binding_change',
            'connection.delete'
        )
    ),
    ADD CONSTRAINT connection_change_evidence_revision_axis_check CHECK (
        revision_axis IN ('connection', 'credential')
    ),
    ADD CONSTRAINT connection_change_evidence_versions CHECK (
        (action = 'connection.create' AND revision_axis = 'connection'
            AND prior_version IS NULL
            AND new_version IS NOT NULL AND new_version = 1)
        OR (action = 'connection.replace' AND revision_axis = 'connection'
            AND prior_version IS NOT NULL AND prior_version >= 1
            AND new_version IS NOT NULL AND new_version > prior_version)
        OR (action = 'credential.binding_change' AND revision_axis = 'credential'
            AND prior_version IS NOT NULL AND prior_version >= 0
            AND new_version IS NOT NULL AND new_version > prior_version)
        OR (action = 'connection.delete' AND revision_axis = 'connection'
            AND prior_version IS NOT NULL AND prior_version >= 1
            AND new_version IS NULL)
    );

ALTER TABLE greengateway.connection_change_evidence
    ALTER COLUMN revision_axis DROP DEFAULT;
