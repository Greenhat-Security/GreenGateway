-- Caller-assigned operation IDs are shared by actions so that a retry cannot
-- take effect on a second endpoint. RFC UUIDv7 distinguishes them from the
-- gateway-assigned v4 IDs already in the evidence tables.
CREATE TABLE greengateway.authority_caller_operation_ids (
    operation_id uuid PRIMARY KEY CHECK (
        (get_byte(uuid_send(operation_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(operation_id), 8) >> 6) = 2
    ),
    action text NOT NULL CHECK (action IN ('service_token.revoke', 'mutation_approval.prepare'))
);

-- The schema-34 keyed revocation endpoint already used this namespace.
INSERT INTO greengateway.authority_caller_operation_ids (operation_id, action)
SELECT operation_id, action
FROM greengateway.service_token_change_evidence
WHERE action = 'service_token.revoke'
    AND (get_byte(uuid_send(operation_id), 6) >> 4) = 7
    AND (get_byte(uuid_send(operation_id), 8) >> 6) = 2;

-- The receipt survives approval expiry, cleanup and Connection deletion.
-- Schema-34 approvals had no caller operation ID or preparation receipt.
CREATE TABLE greengateway.mutation_approval_prepare_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid UNIQUE NOT NULL,
    occurrence_id uuid UNIQUE NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    action_digest text NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 256 AND actor_user_id !~ '[[:cntrl:]]'
    ),
    actor_issuer text NOT NULL CHECK (
        octet_length(actor_issuer) BETWEEN 1 AND 512 AND actor_issuer !~ '[[:cntrl:]#]'
    ),
    actor_auth_mode text NOT NULL CHECK (
        actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate')
    ),
    created_at bigint NOT NULL CHECK (created_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at - created_at = 900),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE greengateway.authority_event_journal
    DROP CONSTRAINT authority_event_journal_source_check,
    ADD CONSTRAINT authority_event_journal_source_check CHECK (
        source IN (
            'connection_change_evidence',
            'service_token_change_evidence',
            'jwt_revocation_evidence',
            'admin_session_evidence',
            'document_change_evidence',
            'catalog_change_evidence',
            'mutation_approval_prepare_evidence'
        )
    );
