-- Keep the acting identity separate from the owner of the affected session.
-- A sign-in can replace a different subject's session. Rejection and expiry
-- are gateway decisions. Logout accepts a cookie or a pending-login binding
-- without authenticating a principal. Historical rows have no actor columns.
ALTER TABLE greengateway.admin_session_evidence
    ADD COLUMN actor_subject text,
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_auth_mode text,
    ADD COLUMN actor_issuer text,
    ADD CONSTRAINT admin_session_evidence_actor CHECK (
        CASE reason
            WHEN 'logout' THEN
                actor_subject IS NULL AND actor_kind IS NULL
                AND actor_auth_mode IS NULL AND actor_issuer IS NULL
            WHEN 'issued' THEN
                actor_subject IS NOT NULL AND actor_subject = user_id
                AND actor_kind IS NOT NULL AND actor_kind = 'principal'
                AND actor_auth_mode IS NOT NULL AND actor_auth_mode = 'bearer_token'
            WHEN 'replaced' THEN
                actor_subject IS NOT NULL AND actor_kind IS NOT NULL AND actor_kind = 'principal'
                AND actor_auth_mode IS NOT NULL AND actor_auth_mode = 'bearer_token'
            ELSE
                actor_subject IS NOT NULL AND actor_subject = 'system:admin-session'
                AND actor_kind IS NOT NULL AND actor_kind = 'system'
                AND actor_auth_mode IS NOT NULL AND actor_auth_mode = 'system'
                AND actor_issuer IS NULL
        END
        AND (actor_subject IS NULL OR octet_length(actor_subject) BETWEEN 1 AND 4096)
        AND (actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096)
    ) NOT VALID;
