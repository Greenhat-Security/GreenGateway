-- Migration 6: the Connection control plane (issue #241, PR 8).
--
-- The #240 managed-connection store's tables, ported to PostgreSQL with
-- the same shapes and bounds the SQLite schema established (store.rs
-- MIGRATION_1..7): connection records with per-axis revisions, derived
-- credential-binding rows, dependencies, current status plus history,
-- and the MCP/OpenAPI catalogs with their own revisioned CAS.
--
-- Differences from standalone, by design:
--
-- - Every committed control-plane mutation (record create/replace/delete,
--   catalog replacement) also advances the shared
--   greengateway.security_revision_state counter and appends a
--   greengateway.security_outbox row with resource_type 'connection', so
--   the strict per-request security gate covers connection state and
--   replicas reconcile it exactly like policy and tools.
-- - greengateway.connection_documents keeps the immutable version history
--   of each record's specification (the issue's versioned-document
--   contract); connection_records is the active row and carries the
--   computed per-axis revisions that make up the ConnectionEtag.
-- - greengateway.connection_state_revision is the connections resource's
--   high-water mark for the gate (the audit_stream_state pattern): bumped
--   inside every connection commit, never deleted, so the reconciler's
--   activation read is one row.
-- - connection_local_secrets is deliberately NOT ported: the local
--   keyring is bound to CONNECTIONS_SQLITE_PATH, which cluster mode
--   rejects; cluster deployments use the external secret providers.
-- - Status observations and dependency rows do NOT advance the security
--   revision: status is observational state, and dependencies are derived
--   from other authoritative state (policy, tools, configured routes).
--   Their writes still commit atomically with what they describe.

CREATE TABLE greengateway.connection_records (
    id uuid PRIMARY KEY,
    schema_version text NOT NULL,
    source text NOT NULL CHECK (source = 'managed'),
    spec_json jsonb NOT NULL CHECK (octet_length(spec_json::text) BETWEEN 2 AND 2097152),
    connection_revision bigint NOT NULL CHECK (connection_revision >= 1),
    credential_revision bigint NOT NULL CHECK (credential_revision >= 0),
    tls_revision bigint NOT NULL CHECK (tls_revision >= 0),
    discovery_revision bigint NOT NULL CHECK (discovery_revision >= 0),
    status_revision bigint NOT NULL CHECK (status_revision >= 0),
    created_at text NOT NULL,
    updated_at text NOT NULL,
    last_test_at text,
    last_refresh_at text,
    activation_revision bigint NOT NULL
);

CREATE INDEX idx_ggw_connection_records_updated
    ON greengateway.connection_records(updated_at DESC);

-- Immutable specification versions: one row per create and per replacing
-- write. The actor/diff columns give the history surface the tools and
-- policy documents have; reads reconstruct any prior specification.
CREATE TABLE greengateway.connection_documents (
    connection_id uuid NOT NULL,
    version bigint NOT NULL,
    spec jsonb NOT NULL,
    document_etag text NOT NULL,
    actor_user_id text NOT NULL,
    diff_summary jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, version),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

-- The connections resource's activation high-water mark (one row).
CREATE TABLE greengateway.connection_state_revision (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_revision bigint NOT NULL
);

INSERT INTO greengateway.connection_state_revision (singleton, last_revision)
VALUES (true, 0);

CREATE TABLE greengateway.connection_credential_bindings (
    connection_id uuid NOT NULL,
    purpose text NOT NULL,
    secret_id text NOT NULL,
    binding_version bigint NOT NULL CHECK (binding_version >= 1),
    updated_at text NOT NULL,
    PRIMARY KEY (connection_id, purpose),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_dependencies (
    connection_id uuid NOT NULL,
    consumer_kind text NOT NULL CHECK (
        consumer_kind IN ('proxy_route', 'manual_tool', 'managed_tool', 'control_plane')
    ),
    consumer_id text NOT NULL CHECK (
        octet_length(consumer_id) BETWEEN 1 AND 256
    ),
    created_at text NOT NULL,
    PRIMARY KEY (connection_id, consumer_kind, consumer_id),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE RESTRICT
);

CREATE INDEX idx_ggw_connection_dependencies_connection
    ON greengateway.connection_dependencies(connection_id, consumer_kind, consumer_id);

CREATE TABLE greengateway.connection_current_status (
    connection_id uuid PRIMARY KEY,
    status_revision bigint NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision bigint NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision bigint NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision bigint NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision bigint NOT NULL CHECK (observed_discovery_revision >= 0),
    state text NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason text NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied',
            'secret_unavailable', 'invalid_response', 'catalog_stale'
        )
    ),
    observed_at text NOT NULL CHECK (octet_length(observed_at) BETWEEN 1 AND 64),
    latency_ms bigint CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs bigint CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count bigint CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_status_history (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    connection_id uuid NOT NULL,
    status_revision bigint NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision bigint NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision bigint NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision bigint NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision bigint NOT NULL CHECK (observed_discovery_revision >= 0),
    state text NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason text NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied',
            'secret_unavailable', 'invalid_response', 'catalog_stale'
        )
    ),
    observed_at text NOT NULL CHECK (octet_length(observed_at) BETWEEN 1 AND 64),
    latency_ms bigint CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs bigint CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count bigint CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_ggw_connection_status_revision
    ON greengateway.connection_status_history(connection_id, status_revision);

CREATE INDEX idx_ggw_connection_status_latest
    ON greengateway.connection_status_history(connection_id, status_revision DESC);

CREATE TABLE greengateway.connection_mcp_catalogs (
    connection_id uuid PRIMARY KEY,
    catalog_revision bigint NOT NULL CHECK (catalog_revision >= 1),
    observed_etag text NOT NULL CHECK (
        octet_length(observed_etag) BETWEEN 1 AND 512
    ),
    refreshed_at text NOT NULL CHECK (octet_length(refreshed_at) BETWEEN 1 AND 64),
    entry_count bigint NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
    resource_count bigint NOT NULL DEFAULT 0 CHECK (resource_count BETWEEN 0 AND 4096),
    resource_template_count bigint NOT NULL DEFAULT 0 CHECK (
        resource_template_count BETWEEN 0 AND 4096
        AND entry_count + resource_count + resource_template_count <= 4096
    ),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_mcp_catalog_entries (
    connection_id uuid NOT NULL,
    remote_tool_name text NOT NULL CHECK (
        octet_length(remote_tool_name) BETWEEN 1 AND 128
    ),
    description text NOT NULL CHECK (
        octet_length(description) BETWEEN 1 AND 1024
    ),
    input_schema_json jsonb NOT NULL CHECK (
        octet_length(input_schema_json::text) BETWEEN 2 AND 262144
    ),
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, remote_tool_name),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_ggw_connection_mcp_catalog_ordinal
    ON greengateway.connection_mcp_catalog_entries(connection_id, ordinal);

CREATE TABLE greengateway.connection_mcp_catalog_resources (
    connection_id uuid NOT NULL,
    uri text NOT NULL CHECK (
        octet_length(uri) BETWEEN 1 AND 2048
    ),
    name text NOT NULL CHECK (
        octet_length(name) BETWEEN 1 AND 128
    ),
    title text CHECK (title IS NULL OR octet_length(title) BETWEEN 1 AND 256),
    description text CHECK (
        description IS NULL OR octet_length(description) BETWEEN 1 AND 1024
    ),
    mime_type text CHECK (
        mime_type IS NULL OR octet_length(mime_type) BETWEEN 1 AND 256
    ),
    size bigint CHECK (size IS NULL OR size >= 0),
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, uri),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_ggw_connection_mcp_catalog_resource_ordinal
    ON greengateway.connection_mcp_catalog_resources(connection_id, ordinal);

CREATE TABLE greengateway.connection_mcp_catalog_resource_templates (
    connection_id uuid NOT NULL,
    uri_template text NOT NULL CHECK (
        octet_length(uri_template) BETWEEN 1 AND 2048
    ),
    name text NOT NULL CHECK (
        octet_length(name) BETWEEN 1 AND 128
    ),
    title text CHECK (title IS NULL OR octet_length(title) BETWEEN 1 AND 256),
    description text CHECK (
        description IS NULL OR octet_length(description) BETWEEN 1 AND 1024
    ),
    mime_type text CHECK (
        mime_type IS NULL OR octet_length(mime_type) BETWEEN 1 AND 256
    ),
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, uri_template),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_ggw_connection_mcp_catalog_resource_template_ordinal
    ON greengateway.connection_mcp_catalog_resource_templates(connection_id, ordinal);

CREATE TABLE greengateway.connection_openapi_catalogs (
    connection_id uuid PRIMARY KEY,
    spec_revision bigint NOT NULL CHECK (spec_revision >= 1),
    catalog_revision bigint NOT NULL CHECK (catalog_revision >= 1),
    observed_etag text NOT NULL CHECK (
        octet_length(observed_etag) BETWEEN 1 AND 512
    ),
    spec_digest text NOT NULL CHECK (
        octet_length(spec_digest) = 64
        AND spec_digest ~ '^[0-9a-f]+$'
    ),
    spec jsonb NOT NULL CHECK (octet_length(spec::text) BETWEEN 1 AND 2097152),
    refreshed_at text NOT NULL CHECK (octet_length(refreshed_at) BETWEEN 1 AND 64),
    entry_count bigint NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_openapi_catalog_entries (
    connection_id uuid NOT NULL,
    tool_name text NOT NULL CHECK (
        octet_length(tool_name) BETWEEN 1 AND 128
    ),
    operation_id text CHECK (
        operation_id IS NULL OR octet_length(operation_id) BETWEEN 1 AND 256
    ),
    selected_scheme_names_json jsonb NOT NULL CHECK (
        octet_length(selected_scheme_names_json::text) BETWEEN 2 AND 16384
    ),
    definition_json jsonb NOT NULL CHECK (
        octet_length(definition_json::text) BETWEEN 2 AND 262144
    ),
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, tool_name),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_openapi_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_ggw_connection_openapi_catalog_ordinal
    ON greengateway.connection_openapi_catalog_entries(connection_id, ordinal);

-- Control-plane mutations append one durable change record identifying
-- the connection and versions (identifiers and revisions only).
ALTER TABLE greengateway.security_outbox
    ADD COLUMN resource_id text;
