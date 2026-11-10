-- Migration 34: one durable review per proposed managed OpenAPI mutation (#757).
-- The Connection owns each occurrence. Deletion takes its decisions with it,
-- so recreating a Connection with overlapping revisions cannot revive a grant.
CREATE TABLE greengateway.connection_mutation_approvals (
    id uuid PRIMARY KEY,
    connection_id uuid NOT NULL REFERENCES greengateway.connection_records(id) ON DELETE CASCADE,
    connection_etag text NOT NULL CHECK (octet_length(connection_etag) BETWEEN 1 AND 256),
    catalog_revision bigint NOT NULL CHECK (catalog_revision > 0),
    tool_name text NOT NULL CHECK (octet_length(tool_name) BETWEEN 1 AND 512),
    operation text NOT NULL CHECK (octet_length(operation) BETWEEN 1 AND 1024),
    method text NOT NULL CHECK (method IN ('POST','PUT','PATCH','DELETE')),
    definition_sha256 text NOT NULL CHECK (definition_sha256 ~ '^[0-9a-f]{64}$'),
    target_sha256 text NOT NULL CHECK (target_sha256 ~ '^[0-9a-f]{64}$'),
    body_sha256 text NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    caller_issuer text NOT NULL CHECK (octet_length(caller_issuer) BETWEEN 1 AND 512),
    caller_subject text NOT NULL CHECK (octet_length(caller_subject) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'consumed')),
    -- Authority-clock seconds since the Unix epoch. Expiry is checked in the
    -- transaction consuming a decision, even if a cleanup has never run.
    created_at bigint NOT NULL CHECK (created_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at - created_at = 900),
    reviewer_issuer text CHECK (octet_length(reviewer_issuer) BETWEEN 1 AND 512),
    reviewer_subject text CHECK (octet_length(reviewer_subject) BETWEEN 1 AND 256),
    reviewed_at bigint CHECK (reviewed_at >= created_at AND reviewed_at < expires_at),
    revoker_issuer text CHECK (octet_length(revoker_issuer) BETWEEN 1 AND 512),
    revoker_subject text CHECK (octet_length(revoker_subject) BETWEEN 1 AND 256),
    revoked_at bigint CHECK (revoked_at >= COALESCE(reviewed_at, created_at) AND revoked_at < expires_at),
    consumed_at bigint CHECK (consumed_at >= reviewed_at AND consumed_at < expires_at),
    CHECK ((reviewed_at IS NULL) = (reviewer_issuer IS NULL)
       AND (reviewed_at IS NULL) = (reviewer_subject IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoker_issuer IS NULL)
       AND (revoked_at IS NULL) = (revoker_subject IS NULL)),
    CHECK (reviewed_at IS NULL OR (caller_issuer, caller_subject) <> (reviewer_issuer, reviewer_subject)),
    CHECK (revoked_at IS NULL OR (caller_issuer, caller_subject) <> (revoker_issuer, revoker_subject)),
    CHECK ((status = 'pending' AND reviewed_at IS NULL AND revoked_at IS NULL AND consumed_at IS NULL)
        OR (status IN ('approved','rejected') AND reviewed_at IS NOT NULL AND revoked_at IS NULL AND consumed_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND consumed_at IS NULL)
        OR (status = 'consumed' AND reviewed_at IS NOT NULL AND consumed_at IS NOT NULL AND revoked_at IS NULL))
);

CREATE INDEX idx_connection_approvals_connection
    ON greengateway.connection_mutation_approvals(connection_id);
CREATE INDEX idx_connection_approvals_expiry
    ON greengateway.connection_mutation_approvals(expires_at);
CREATE INDEX idx_connection_approvals_caller
    ON greengateway.connection_mutation_approvals(caller_issuer, caller_subject);
