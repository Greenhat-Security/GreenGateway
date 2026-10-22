-- Migration 22: the whole actor on every authority-evidence row (issue #425,
-- the v1 contract metadata).
--
-- Migrations 16 and 18 record the actor of a Connection delete, a
-- service-token rotate or revoke and a JWT revoke as one identifier: the
-- acting principal's subject, or an operator command's fixed system label.
-- Equal subjects from two identity providers are then one actor, a service
-- token's synthetic `service-token:<id>` subject reads like a person's, and
-- the revoke-jwt command's label is told apart from a person only by
-- convention. The proposed authority_event.v1 contract names an actor by its
-- kind, its subject, its issuer and its authentication mode, and the
-- dispatcher of migration 21 could deliver only the subject. This migration
-- adds the three missing facts to each of the three evidence tables:
--
-- - actor_kind: 'principal' (a session cookie, bearer JWT or client
--   certificate that an identity provider or the inbound TLS handshake
--   vouched for), 'service_token' (a gateway-issued service token) or
--   'system' (an operator command acting on the deployment's own authority
--   under a fixed label; nobody authenticated it).
-- - actor_auth_mode: how the actor authenticated, in the audit vocabulary
--   (bearer_token, session_cookie, client_certificate, service_token), or
--   'system' for a system actor. It always agrees with actor_kind.
-- - actor_issuer: the canonical issuer of a principal that has one, bounded
--   by exactly the principal issuer bound authentication enforces
--   (auth/principal.rs MAX_PRINCIPAL_ISSUER_BYTES), so no principal a
--   validator accepted is refused here. A service token and a system actor
--   have none. On jwt_revocation_evidence this is the ACTOR's issuer; the
--   existing issuer column stays the revoked token's.
--
-- The columns are nullable and nothing is backfilled. A row committed before
-- this migration recorded none of the three, and evidence is append-only: no
-- value is guessed into it, so such a row says "not recorded" rather than
-- something nobody knows. Every writer in this release records all three,
-- and the CHECK on each table refuses a row that records some but not all,
-- or a pairing authentication cannot produce.
--
-- Identifiers only, as before: no credential, session identifier, role or
-- email address is added. The journal of migration 21 is unchanged; the
-- dispatcher reads the new columns through the evidence row it already joins.

ALTER TABLE greengateway.connection_change_evidence
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_auth_mode text,
    ADD COLUMN actor_issuer text CHECK (
        actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096
    ),
    ADD CONSTRAINT connection_change_evidence_actor_metadata CHECK (
        (actor_kind IS NULL AND actor_auth_mode IS NULL AND actor_issuer IS NULL)
        OR (actor_kind IS NOT NULL AND actor_auth_mode IS NOT NULL AND (
            (actor_kind = 'principal'
                AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
            OR (actor_kind = 'service_token'
                AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
            OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
        ))
    );

ALTER TABLE greengateway.service_token_change_evidence
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_auth_mode text,
    ADD COLUMN actor_issuer text CHECK (
        actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096
    ),
    ADD CONSTRAINT service_token_change_evidence_actor_metadata CHECK (
        (actor_kind IS NULL AND actor_auth_mode IS NULL AND actor_issuer IS NULL)
        OR (actor_kind IS NOT NULL AND actor_auth_mode IS NOT NULL AND (
            (actor_kind = 'principal'
                AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
            OR (actor_kind = 'service_token'
                AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
            OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
        ))
    );

ALTER TABLE greengateway.jwt_revocation_evidence
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_auth_mode text,
    ADD COLUMN actor_issuer text CHECK (
        actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096
    ),
    ADD CONSTRAINT jwt_revocation_evidence_actor_metadata CHECK (
        (actor_kind IS NULL AND actor_auth_mode IS NULL AND actor_issuer IS NULL)
        OR (actor_kind IS NOT NULL AND actor_auth_mode IS NOT NULL AND (
            (actor_kind = 'principal'
                AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
            OR (actor_kind = 'service_token'
                AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
            OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
        ))
    );
