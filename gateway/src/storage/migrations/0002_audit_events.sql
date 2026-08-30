-- Migration 2: the durable audit event log and its commit-safe stream
-- (issue #241, PR 5; subsumes the remaining PostgreSQL audit-sink work of
-- issue #11).
--
-- audit_events mirrors the standalone SQLite sink's column set with
-- PostgreSQL-native types: event_id is the idempotency key (replayed
-- batches store exactly once), occurred_at preserves the application
-- timestamp while ingested_at records database receipt, and the payload
-- columns that the admin audit API filters on are real indexed columns.
-- instance_id/boot_id record which replica ingested each event; they are
-- nullable because the contract adapter and the import workflow can write
-- without one.
--
-- audit_stream is the durable cursor source for consumers (the SSE
-- transport of PR 6, retention coordination, the import verifier). Its
-- positions are NOT an identity sequence: sequences do not roll back, so
-- an aborted append would burn a position and leave a permanent gap that a
-- contiguous reader could never cross. Instead, writers assign positions
-- from max(position)+row_number() inside the transaction-scoped advisory
-- lock they already hold, so assignment order is commit order, an aborted
-- transaction's numbers are immediately reused by the next append, and the
-- committed stream is gapless by construction. See storage/postgres_audit.rs
-- for the protocol and the tests that pin it under concurrency and aborts.

CREATE TABLE greengateway.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id text NOT NULL UNIQUE,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    instance_id uuid,
    boot_id uuid,
    schema_version text NOT NULL,
    request_id text NOT NULL,
    source_ip text NOT NULL,
    user_agent text,
    actor_user_id text,
    actor_issuer text,
    actor_auth_mode text,
    actor_json jsonb,
    payload_method text,
    payload_path text,
    payload_status integer,
    payload_matched_rule_id text,
    payload_json jsonb NOT NULL
);

CREATE INDEX idx_ggw_audit_event_type ON greengateway.audit_events(event_type);
CREATE INDEX idx_ggw_audit_occurred_at ON greengateway.audit_events(occurred_at);
CREATE INDEX idx_ggw_audit_actor_user_id ON greengateway.audit_events(actor_user_id);
CREATE INDEX idx_ggw_audit_actor_issuer ON greengateway.audit_events(actor_issuer);
CREATE INDEX idx_ggw_audit_actor_auth_mode ON greengateway.audit_events(actor_auth_mode);
CREATE INDEX idx_ggw_audit_payload_method ON greengateway.audit_events(payload_method);
CREATE INDEX idx_ggw_audit_payload_path ON greengateway.audit_events(payload_path);
CREATE INDEX idx_ggw_audit_payload_status ON greengateway.audit_events(payload_status);
CREATE INDEX idx_ggw_audit_payload_matched_rule_id
    ON greengateway.audit_events(payload_matched_rule_id);

CREATE TABLE greengateway.audit_stream (
    position bigint NOT NULL PRIMARY KEY,
    event_id text NOT NULL UNIQUE
        REFERENCES greengateway.audit_events(event_id) ON DELETE CASCADE,
    appended_at timestamptz NOT NULL DEFAULT now()
);
