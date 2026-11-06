-- Migration 32: policy, tools and catalog change evidence in the
-- authority-event journal, and the document actor in migration 24's
-- vocabulary (issue #425).
--
-- Migration 23 writes one document_change_evidence row for every committed
-- policy, tools and (since migration 29) policy test suite commit, and one
-- catalog_change_evidence row for every managed MCP or OpenAPI catalog
-- publication, in the change's own transaction. Neither table was a journal
-- source, so the dispatcher delivered none of them. This migration makes them
-- the fifth and sixth sources:
--
-- - From now on every document commit and every catalog publication journals
--   its evidence row in the same transaction, under the row's own event_id,
--   after the evidence insert, exactly as the Connection, service-token and
--   JWT revocation producers do: one unit of capacity, and only while
--   retained_events < capacity. A full journal refuses the commit or the
--   publication, which rolls back whole. The first-boot tools seed and the
--   offline import's policy and tools activations are document commits too.
-- - Evidence committed before this migration is journaled after every row
--   already in the journal, both tables together in their own commit order
--   (committed_at, then event ID), with its own commit time as journaled_at,
--   so retention judges it by its real age. As in migration 26, those
--   positions follow the rows already journaled instead of interleaving with
--   them, and committed_at still says when each one committed. Each row takes
--   one unit of retained_events. The capacity is not changed: a deployment
--   whose units in use now exceed it refuses every journaled change except an
--   admin session withdrawal until retention frees room.
--
-- document_change_evidence recorded its actor in migration 23's own
-- vocabulary: actor_kind 'principal' for every authenticated caller, a
-- service token included (only its auth mode 'service_token' told it apart),
-- and the issuer as the principal carried it rather than in canonical form.
-- Migration 24's tables name a service token by kind 'service_token' and
-- record the canonical issuer. This migration aligns the table for new rows:
--
-- - actor_kind admits 'service_token'.
-- - document_change_evidence_actor_metadata pairs every new row's kind with
--   its auth mode exactly as migration 24's CHECK does: a principal
--   authenticated by bearer token, session cookie or client certificate; a
--   service token by its own mode and with no issuer; the gateway by 'system'
--   and with no issuer. It is added NOT VALID on purpose. Evidence is
--   append-only and old rows stay exactly as written, so a row a schema-31
--   build committed for a service-token caller keeps (principal,
--   service_token), and its issuer keeps the form it was written in; the
--   constraint holds every row written from now on and is never validated
--   over the old ones. Every writer of this release records the kind and the
--   canonical issuer of auth::change_actor::ChangeActor.
-- - The dispatcher reads an old row in the new vocabulary: (principal,
--   service_token) is delivered as kind service_token, and the issuer is
--   canonicalized as authentication canonicalizes it before it is referenced.
--   Nothing in the stored row changes.
--
-- Identifiers only, as before. The evidence rows themselves are not changed,
-- and catalog_change_evidence keeps migration 25's actor columns and CHECK.

ALTER TABLE greengateway.authority_event_journal
    DROP CONSTRAINT authority_event_journal_source_check,
    ADD CONSTRAINT authority_event_journal_source_check CHECK (
        source IN (
            'connection_change_evidence',
            'service_token_change_evidence',
            'jwt_revocation_evidence',
            'admin_session_evidence',
            'document_change_evidence',
            'catalog_change_evidence'
        )
    );

ALTER TABLE greengateway.document_change_evidence
    DROP CONSTRAINT document_change_evidence_actor_kind_check,
    ADD CONSTRAINT document_change_evidence_actor_kind_check CHECK (
        actor_kind IN ('principal', 'service_token', 'system')
    ),
    ADD CONSTRAINT document_change_evidence_actor_metadata CHECK (
        (actor_kind = 'principal'
            AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
        OR (actor_kind = 'service_token'
            AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
        OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
    ) NOT VALID;

INSERT INTO greengateway.authority_event_journal (position, event_id, source, journaled_at)
SELECT state.last_position
           + row_number() OVER (ORDER BY evidence.committed_at, evidence.event_id),
       evidence.event_id, evidence.source, evidence.committed_at
FROM (
    SELECT event_id, committed_at, 'document_change_evidence' AS source
    FROM greengateway.document_change_evidence
    UNION ALL
    SELECT event_id, committed_at, 'catalog_change_evidence' AS source
    FROM greengateway.catalog_change_evidence
) AS evidence
CROSS JOIN greengateway.authority_event_state AS state
WHERE state.singleton;

UPDATE greengateway.authority_event_state
SET last_position = last_position + existing.journaled,
    retained_events = retained_events + existing.journaled
FROM (
    SELECT (SELECT count(*) FROM greengateway.document_change_evidence)
           + (SELECT count(*) FROM greengateway.catalog_change_evidence) AS journaled
) AS existing
WHERE singleton;
