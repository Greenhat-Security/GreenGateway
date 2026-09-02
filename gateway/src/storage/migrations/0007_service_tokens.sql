-- Migration 7: shared authentication state (issue #241, PR 9): service
-- tokens, JWT revocations, and admin pending logins.
--
-- Service tokens are the first authentication resource on the shared
-- ledger. In standalone mode they live in SERVICE_TOKEN_SQLITE_PATH and a
-- revoke invalidates only the process that handled it; cluster mode
-- rejects that path and serves every replica from this table, so the
-- next request after a committed revoke -- on any replica -- refuses the
-- token.
--
-- What is stored and what is not:
--
-- - token_hash is the SHA-256 of the plaintext token, hex-encoded, exactly
--   as the SQLite store computes it (auth/tokens.rs hash_token). The
--   plaintext appears once, in the response to create and rotate, and is
--   never stored, logged, or written to the outbox.
-- - token_prefix is the bounded display prefix ("ggw_" + 10 hex chars,
--   40 of 256 random bits) the admin API lists for operator correlation.
-- - scopes_json is text, not jsonb: it is only ever round-tripped through
--   serde, and the SQLite reference stores it as TEXT. The bound keeps the
--   row bounded; the policy layer bounds scope names on the way in.
-- - Every timestamp is timestamptz and every comparison against one uses
--   the database clock (now()), never a replica's wall clock: expiry and
--   "was this revoked before that verify" must mean the same thing on
--   every replica (HA state model: database time is authoritative).
--
-- The two mutations that change what a token authorizes -- revoke and
-- rotate -- and the create that grants one are committed control-plane
-- mutations exactly like a policy commit: one transaction that locks
-- service_token_state_revision (the resource's high-water mark, first in
-- the lock order), locks the token row, advances the shared
-- security_revision_state counter, SETS the high-water mark to that same
-- revision, and appends a security_outbox row identifying the token by
-- id. The high-water mark is set, not incremented: the strict gate
-- compares it against a watermark of the SHARED counter, which policy,
-- tools, and Connection commits also advance, so a private count would
-- drift below the watermark and this resource would silently stop
-- reconciling (the defect PR 8 found and pinned for Connections).
--
-- verify and touch_last_used are observational: they update last_used_at
-- and advance nothing. Their statements carry the revoked/expired guard in
-- the WHERE clause, so a verify racing a revoke can never write
-- last_used_at onto a row the revoke has already closed -- the "old token
-- can never be resurrected" rule holds by construction, not by ordering.
--
-- revision is the per-row change counter the race tests observe: it moves
-- by exactly one per committed revoke or rotate, so two rotations that
-- both succeed leave it advanced by exactly two and exactly one plaintext
-- alive.

CREATE TABLE greengateway.service_tokens (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 128),
    token_hash text NOT NULL UNIQUE CHECK (
        octet_length(token_hash) = 64 AND token_hash ~ '^[0-9a-f]+$'
    ),
    token_prefix text NOT NULL CHECK (octet_length(token_prefix) BETWEEN 1 AND 64),
    scopes_json text NOT NULL CHECK (octet_length(scopes_json) BETWEEN 2 AND 65536),
    created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    security_revision bigint NOT NULL CHECK (security_revision >= 1)
);

-- The admin listing is keyset-paginated newest-first, tie-broken by id,
-- exactly as the SQLite index orders it.
CREATE INDEX idx_ggw_service_tokens_created
    ON greengateway.service_tokens(created_at DESC, id ASC);

CREATE INDEX idx_ggw_service_tokens_revoked
    ON greengateway.service_tokens(revoked_at);

CREATE TABLE greengateway.service_token_state_revision (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_revision bigint NOT NULL
);

INSERT INTO greengateway.service_token_state_revision (singleton, last_revision)
VALUES (true, 0);

-- JWT revocations: the production denylist behind auth/jwt.rs's
-- RevocationStore in cluster mode (standalone mode keeps the no-op store).
--
-- A row means "this JWT was withdrawn"; its absence means nothing. A jti
-- is not consume-once and bearer reuse stays valid. The key is the
-- normalized issuer plus a SHA-256 over (deployment id, issuer, jti), so
-- the raw jti never reaches the database and an equal jti from two
-- issuers cannot collide. expires_at is the token's own exp when the
-- caller knows it; a row past it is ignored on read (database time) and
-- removed by bounded cleanup. Every revoke is a committed control-plane
-- mutation: it reserves the shared security revision and appends a
-- security_outbox row with resource_type 'jwt_revocation'.

CREATE TABLE greengateway.jwt_revocations (
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    jti_hash text NOT NULL CHECK (
        octet_length(jti_hash) = 64 AND jti_hash ~ '^[0-9a-f]+$'
    ),
    revoked_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    actor_user_id text NOT NULL CHECK (octet_length(actor_user_id) BETWEEN 1 AND 512),
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    PRIMARY KEY (issuer, jti_hash)
);

CREATE INDEX idx_ggw_jwt_revocations_expires
    ON greengateway.jwt_revocations(expires_at);

-- Admin pending logins: the OIDC login flow's state between /auth/login
-- and /auth/callback, so the callback can land on any replica.
--
-- The state itself is never stored: the row is found by
-- SHA-256(deployment id, "state", state). The PKCE verifier and the nonce
-- are sealed with XChaCha20-Poly1305 under the operator's login keyring
-- (key_id names the key; a decrypt_only predecessor still opens rows
-- sealed before a rotation), with the deployment id, the row id, and the
-- field's purpose bound as associated data. The client is a digest of its
-- canonical IP, for the per-client quota only. Consumption is one DELETE
-- ... RETURNING guarded by the database clock, so exactly one concurrent
-- callback -- anywhere -- gets the row. Admissions serialize on a
-- transaction-scoped advisory lock so the quotas hold across replicas;
-- each admission prunes a bounded number of expired rows.

CREATE TABLE greengateway.admin_pending_logins (
    id uuid PRIMARY KEY,
    state_hash text NOT NULL UNIQUE CHECK (
        octet_length(state_hash) = 64 AND state_hash ~ '^[0-9a-f]+$'
    ),
    client_key text NOT NULL CHECK (
        octet_length(client_key) = 64 AND client_key ~ '^[0-9a-f]+$'
    ),
    key_id text NOT NULL CHECK (octet_length(key_id) BETWEEN 1 AND 128),
    verifier_nonce bytea NOT NULL CHECK (octet_length(verifier_nonce) = 24),
    verifier_ct bytea NOT NULL CHECK (octet_length(verifier_ct) BETWEEN 17 AND 1024),
    nonce_nonce bytea NOT NULL CHECK (octet_length(nonce_nonce) = 24),
    nonce_ct bytea NOT NULL CHECK (octet_length(nonce_ct) BETWEEN 17 AND 1024),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX idx_ggw_admin_pending_logins_expires
    ON greengateway.admin_pending_logins(expires_at);

CREATE INDEX idx_ggw_admin_pending_logins_client
    ON greengateway.admin_pending_logins(client_key);

-- The deployment this database is bound to. Every authoritative pointer
-- and counter in this schema is a singleton, so a database holds exactly
-- one logical deployment's state: the first boot records its DEPLOYMENT_ID
-- here, and every later boot and every one-shot command refuses to run
-- against a database bound to another. The deployment ID remains the
-- domain separator for every digest, sealed envelope, and lock namespace,
-- so state restored under another ID cannot be mistaken for it.
CREATE TABLE greengateway.deployment_binding (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    deployment_id text NOT NULL CHECK (octet_length(deployment_id) BETWEEN 1 AND 128),
    bound_at timestamptz NOT NULL DEFAULT now()
);
