-- Migration 25: the whole actor on catalog change evidence (issue #425), and
-- the first migration approved as an additive extension before any build
-- applies it (issue #426).
--
-- Migration 23 records who published a managed MCP or OpenAPI catalog, or
-- replaced or deleted its overlay, as one identifier: the publishing subject.
-- Equal subjects from two identity providers are then one actor, and a
-- service token's synthetic `service-token:<id>` subject reads like a
-- person's. Migration 24 gave the three journaled evidence tables the rest of
-- the actor and left catalog_change_evidence to a later slice. This migration
-- adds the same three columns, in the same vocabulary and under the same
-- rule, to catalog_change_evidence:
--
-- - actor_kind: 'principal' (a session cookie, bearer JWT or client
--   certificate that an identity provider or the inbound TLS handshake
--   vouched for), 'service_token' (a gateway-issued service token) or
--   'system' (the deployment's own authority under a fixed label; nobody
--   authenticated it).
-- - actor_auth_mode: how the actor authenticated, in the audit vocabulary
--   (bearer_token, session_cookie, client_certificate, service_token), or
--   'system' for a system actor. It always agrees with actor_kind.
-- - actor_issuer: the canonical issuer of a principal that has one, bounded
--   by exactly the principal issuer bound authentication enforces
--   (auth/principal.rs MAX_PRINCIPAL_ISSUER_BYTES). A service token and a
--   system actor have none.
--
-- The columns are nullable, have no default, and nothing is backfilled. A row
-- committed before this migration recorded none of the three, and evidence is
-- append-only: no value is guessed into it, so such a row says "not recorded"
-- rather than something nobody knows. The CHECK refuses a row that records
-- some but not all of the three, or a pairing authentication cannot produce.
--
-- The change is purely additive, so it can commit while schema-24 replicas
-- serve. A schema-24 build prepared for it carries this file's exact checksum
-- as an approved extension: it serves a ledger that holds this migration but
-- never applies it. Its catalog writes name every column they set, so the rows
-- it writes record none of the three, which the CHECK admits, and nothing it
-- reads changes. A schema-24 build without that approval refuses the ledger.
--
-- Nothing on the request path reads or writes the table, so the ACCESS
-- EXCLUSIVE lock this statement takes, and the one read of the table that
-- validating the CHECK costs, briefly hold back Connection control-plane
-- writes and nothing else: a catalog publication waits for the lock while it
-- holds the lock that serializes Connection mutations.
--
-- Identifiers only, as before: no credential, session identifier, role or
-- email address is added. The table is still not an authority-event journal
-- source, and document_change_evidence is not changed.

ALTER TABLE greengateway.catalog_change_evidence
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_auth_mode text,
    ADD COLUMN actor_issuer text CHECK (
        actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096
    ),
    ADD CONSTRAINT catalog_change_evidence_actor_metadata CHECK (
        (actor_kind IS NULL AND actor_auth_mode IS NULL AND actor_issuer IS NULL)
        OR (actor_kind IS NOT NULL AND actor_auth_mode IS NOT NULL AND (
            (actor_kind = 'principal'
                AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
            OR (actor_kind = 'service_token'
                AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
            OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
        ))
    );
