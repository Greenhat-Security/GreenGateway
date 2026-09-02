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
--   greengateway.security_outbox row, so the strict per-request security
--   gate covers connection state and replicas reconcile it exactly like
--   policy and tools. Two resource_type labels are used, because the
--   outbox's from_version/to_version pair carries a different quantity in
--   each case and a consumer must not have to guess which:
--     * 'connection' -- a specification-version transition. from_version
--       and to_version are greengateway.connection_documents.version
--       values, so 'connection' rows for one resource_id are that
--       Connection's version chain; to_version 0 marks the deletion.
--     * 'connection_catalog' -- a catalog replacement. from_version and
--       to_version are the per-connection catalog revision
--       (connection_mcp_catalogs.catalog_revision or
--       connection_openapi_catalogs.catalog_revision), an unrelated
--       counter that must not be interleaved into the version chain.
--   Both label rows identify the Connection through resource_id.
-- - greengateway.connection_documents keeps every version of each record's
--   specification for as long as the record exists (the issue's
--   versioned-document contract): versions are never rewritten, and a
--   replacing write appends. A deleted record takes its versions with it,
--   as the standalone store does; the deletion itself is attributed by the
--   admin audit event the handler records with its actor. connection_records
--   is the active row and carries the computed per-axis revisions that make
--   up the ConnectionEtag.
-- - greengateway.tool_name_reservations is the authority's own guarantee of
--   the one invariant every replica's tool registry enforces only
--   process-locally: one tool name, one publisher, across the local tools
--   document, every managed OpenAPI catalog, and every managed MCP catalog.
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

-- Character versus byte limits: a CHECK below uses char_length exactly
-- where the Rust validator counts characters (store.rs
-- validate_mcp_catalog_entries and validate_mcp_resources), and
-- octet_length where it counts bytes. The two must agree, because the
-- validator runs first: a limit PostgreSQL enforces more tightly than Rust
-- turns a request Rust accepted into an opaque storage error instead of a
-- Validation one (a 300-emoji description is 300 characters and 1,200
-- bytes).

CREATE TABLE greengateway.connection_records (
    id uuid PRIMARY KEY,
    schema_version text NOT NULL,
    source text NOT NULL CHECK (source = 'managed'),
    -- Verbatim spec bytes, NOT jsonb, for the byte-budget reason the
    -- catalog columns document: this bound is exactly
    -- MAX_MANAGED_SPEC_BYTES (model.rs), which the writer already checked
    -- against serde_json's compact encoding, so measuring jsonb's output
    -- form instead would reject a maximum-size specification the Rust check
    -- just accepted -- as an opaque Postgres error rather than a Validation
    -- one. The read-side guard in RawConnectionRow would mis-measure it the
    -- same way. Nothing but serde_json consumes this column, and the SQLite
    -- reference declares it TEXT with the identical bound (store.rs
    -- MIGRATION_1).
    spec_json text NOT NULL CHECK (octet_length(spec_json) BETWEEN 2 AND 2097152),
    connection_revision bigint NOT NULL CHECK (connection_revision >= 1),
    credential_revision bigint NOT NULL CHECK (credential_revision >= 0),
    tls_revision bigint NOT NULL CHECK (tls_revision >= 0),
    discovery_revision bigint NOT NULL CHECK (discovery_revision >= 0),
    status_revision bigint NOT NULL CHECK (status_revision >= 0),
    created_at text NOT NULL,
    updated_at text NOT NULL,
    last_test_at text,
    last_refresh_at text
    -- No per-record activation column. The connections resource's
    -- activation high-water mark is the singleton
    -- greengateway.connection_state_revision below, which is what
    -- security_cluster.rs's ConnectionsResource::activation_revision
    -- reads; the SQLite reference's connection_records (store.rs
    -- MIGRATION_1) carries no such column either. A per-record copy has
    -- no consumer, and one that is written but never maintained is worse
    -- than absent -- a future reader would trust it.
);

CREATE INDEX idx_ggw_connection_records_updated
    ON greengateway.connection_records(updated_at DESC);

-- Immutable specification versions: one row per create and per replacing
-- write. The actor/diff columns give the history surface the tools and
-- policy documents have; reads reconstruct any prior specification.
CREATE TABLE greengateway.connection_documents (
    connection_id uuid NOT NULL,
    version bigint NOT NULL,
    -- Verbatim spec bytes for the same reason: document_etag is a SHA-256
    -- over (id, version, spec bytes), so normalizing the stored value would
    -- break the guard against out-of-band edits.
    spec text NOT NULL,
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
    -- The security revision of the document that derived this set (0 for
    -- sets no revision produces, such as proxy routes from static
    -- configuration). Replicas flush their derived sets independently, and
    -- a flush from an older tools document must never replace the guards a
    -- newer document derived: the store keeps the newest source's rows.
    source_revision bigint NOT NULL DEFAULT 0 CHECK (source_revision >= 0),
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
    -- Who published this catalog. An audit column with the same contract
    -- (and the same deliberate absence of a length CHECK) as
    -- connection_documents.actor_user_id: a catalog replacement is a
    -- committed control-plane mutation, so it is attributable like the
    -- record writes are. Written on every replacement; the history read
    -- surface that serves it arrives with the rest of the versioned-
    -- document API.
    actor_user_id text NOT NULL,
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_mcp_catalog_entries (
    connection_id uuid NOT NULL,
    remote_tool_name text NOT NULL CHECK (
        char_length(remote_tool_name) BETWEEN 1 AND 128
    ),
    description text NOT NULL CHECK (
        char_length(description) BETWEEN 1 AND 1024
    ),
    -- Verbatim schema bytes, NOT jsonb. The whole catalog byte budget is
    -- shared between this backend and the SQLite one, and both sides of
    -- every comparison must measure the same thing: the candidate side is
    -- serde_json's compact encoding (store.rs validate_mcp_catalog_entries)
    -- and this bound is exactly MAX_MCP_CATALOG_ENTRY_BYTES, so jsonb's
    -- output form -- which re-inserts a space after every ':' and ',' --
    -- would reject entries the Rust check just accepted, as an opaque
    -- Postgres error instead of a Validation one. jsonb would also reorder
    -- object keys and rewrite numeric literals, so a schema read back here
    -- would not be the schema SQLite reads back. Nothing but serde_json
    -- ever consumes this column (pg_store.rs load_mcp_entries), so text
    -- costs nothing and matches the reference column type exactly
    -- (store.rs MIGRATION_4: input_schema_json TEXT).
    input_schema_json text NOT NULL CHECK (
        octet_length(input_schema_json) BETWEEN 2 AND 262144
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
        char_length(name) BETWEEN 1 AND 128 AND octet_length(name) <= 512
    ),
    title text CHECK (
        title IS NULL
        OR (char_length(title) BETWEEN 1 AND 256 AND octet_length(title) <= 1024)
    ),
    description text CHECK (
        description IS NULL
        OR (char_length(description) BETWEEN 1 AND 1024 AND octet_length(description) <= 4096)
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
        char_length(name) BETWEEN 1 AND 128 AND octet_length(name) <= 512
    ),
    title text CHECK (
        title IS NULL
        OR (char_length(title) BETWEEN 1 AND 256 AND octet_length(title) <= 1024)
    ),
    description text CHECK (
        description IS NULL
        OR (char_length(description) BETWEEN 1 AND 1024 AND octet_length(description) <= 4096)
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
    -- Verbatim spec bytes, NOT jsonb: spec_digest is a SHA-256 over the
    -- exact bytes the caller published (store.rs validate_openapi_spec) and
    -- reads re-verify it. jsonb would reorder keys, drop duplicates, rewrite
    -- whitespace and numeric literals, so the digest would stop describing
    -- the stored value -- and a YAML spec (which the generator accepts) could
    -- not be stored at all. The bound is on the stored bytes so it agrees
    -- with the Rust MAX_MANAGED_SPEC_BYTES check.
    spec text NOT NULL CHECK (octet_length(spec) BETWEEN 1 AND 2097152),
    refreshed_at text NOT NULL CHECK (octet_length(refreshed_at) BETWEEN 1 AND 64),
    entry_count bigint NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
    -- Who published this catalog; see connection_mcp_catalogs above.
    actor_user_id text NOT NULL,
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

CREATE TABLE greengateway.connection_openapi_catalog_entries (
    connection_id uuid NOT NULL,
    tool_name text NOT NULL CHECK (
        char_length(tool_name) BETWEEN 1 AND 128
    ),
    operation_id text CHECK (
        operation_id IS NULL OR char_length(operation_id) BETWEEN 1 AND 256
    ),
    -- Verbatim bytes, NOT jsonb, for the reason input_schema_json above
    -- carries: these bounds are exactly the Rust ones
    -- (MAX_OPENAPI_SECURITY_SCHEMES_JSON_BYTES and
    -- MAX_OPENAPI_CATALOG_ENTRY_BYTES, both applied to serde_json's compact
    -- string in store.rs validate_openapi_catalog_entries), and
    -- definition_json is also what the retained-byte half of
    -- MAX_MANAGED_OPENAPI_CATALOG_BYTES is summed from. Both columns are
    -- read back only through serde_json (pg_store.rs load_openapi_entries).
    selected_scheme_names_json text NOT NULL CHECK (
        octet_length(selected_scheme_names_json) BETWEEN 2 AND 16384
    ),
    definition_json text NOT NULL CHECK (
        octet_length(definition_json) BETWEEN 2 AND 262144
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

-- Tool-name reservations. Each lane's commit replaces its own rows inside
-- its transaction; the primary key refuses a name another lane holds, so
-- two lanes racing to publish one name produce exactly one winner and an
-- authority every replica can compile. Without it, two commits could both
-- survive holding a conflict no replica's registry can install, and the
-- security gate would fail closed on every replica.
--
-- Lanes: 'local' (the tools document; owner_id 'tools'), 'openapi' and
-- 'mcp' (owner_id is the Connection id). MCP names are the registry's
-- "<connection id>:<remote tool name>" form.
CREATE TABLE greengateway.tool_name_reservations (
    tool_name text PRIMARY KEY CHECK (octet_length(tool_name) BETWEEN 1 AND 512),
    lane text NOT NULL CHECK (lane IN ('local', 'openapi', 'mcp')),
    owner_id text NOT NULL CHECK (octet_length(owner_id) BETWEEN 1 AND 128)
);

CREATE INDEX idx_ggw_tool_name_reservations_owner
    ON greengateway.tool_name_reservations(lane, owner_id);
