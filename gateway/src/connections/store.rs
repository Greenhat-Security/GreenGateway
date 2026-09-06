use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::tools::definitions::ToolDefinition;

use super::{
    model::{
        ConnectionAuthentication, ConnectionId, ConnectionKind, ConnectionManagementSource,
        ConnectionWrite, DiscoveryConfig, CONNECTION_SCHEMA_VERSION, MAX_CATALOG_ENTRIES,
        MAX_CONNECTIONS, MAX_CREDENTIALS, MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        MAX_MANAGED_SPEC_BYTES, MAX_STATUS_HISTORY_ROWS,
    },
    status::{
        ConnectionOperationalState, ConnectionRevisions, ConnectionStatusReason,
        SafeAuthenticationKind, SafeConnectionStatus, SafeConnectionSummary,
    },
};

const CONFIGURE_SQL: &str = r#"
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
"#;
const DEFAULT_SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const CREATE_MIGRATIONS_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS connection_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"#;

const MIGRATION_1_SQL: &str = r#"
CREATE TABLE connection_records (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source = 'managed'),
    spec_json TEXT NOT NULL CHECK (length(CAST(spec_json AS BLOB)) BETWEEN 2 AND 2097152),
    connection_revision INTEGER NOT NULL CHECK (connection_revision >= 1),
    credential_revision INTEGER NOT NULL CHECK (credential_revision >= 0),
    tls_revision INTEGER NOT NULL CHECK (tls_revision >= 0),
    discovery_revision INTEGER NOT NULL CHECK (discovery_revision >= 0),
    status_revision INTEGER NOT NULL CHECK (status_revision >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(id) BETWEEN 1 AND 128)
);

CREATE TABLE connection_credential_bindings (
    connection_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    secret_id TEXT NOT NULL,
    binding_version INTEGER NOT NULL CHECK (binding_version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, purpose),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_dependencies (
    connection_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL CHECK (
        consumer_kind IN ('proxy_route', 'manual_tool', 'managed_tool', 'control_plane')
    ),
    consumer_id TEXT NOT NULL CHECK (
        length(CAST(consumer_id AS BLOB)) BETWEEN 1 AND 256
        AND instr(consumer_id, char(0)) = 0
    ),
    created_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, consumer_kind, consumer_id),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE RESTRICT
);

CREATE INDEX idx_connection_dependencies_connection
ON connection_dependencies(connection_id, consumer_kind, consumer_id);
"#;

const MIGRATION_2_SQL: &str = r#"
CREATE TABLE connection_current_status (
    connection_id TEXT PRIMARY KEY,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_status_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_status_revision
ON connection_status_history(connection_id, status_revision);

CREATE INDEX idx_connection_status_latest
ON connection_status_history(connection_id, status_revision DESC);
"#;

const MIGRATION_3_SQL: &str = r#"
CREATE TABLE connection_local_secrets (
    id TEXT PRIMARY KEY CHECK (length(CAST(id AS BLOB)) BETWEEN 1 AND 128),
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    label TEXT NOT NULL CHECK (
        length(label) BETWEEN 1 AND 128
        AND instr(label, char(0)) = 0
    ),
    purpose TEXT NOT NULL CHECK (
        purpose IN (
            'header_api_key', 'static_bearer', 'oauth_client_secret',
            'tls_private_key', 'tls_certificate', 'tls_ca_bundle'
        )
    ),
    secret_version INTEGER NOT NULL CHECK (secret_version >= 1),
    algorithm TEXT NOT NULL CHECK (
        length(CAST(algorithm AS BLOB)) BETWEEN 1 AND 64
        AND instr(algorithm, char(0)) = 0
    ),
    key_id TEXT NOT NULL CHECK (
        length(CAST(key_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(key_id, char(0)) = 0
    ),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 1048592),
    created_at TEXT NOT NULL CHECK (
        length(CAST(created_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(created_at, char(0)) = 0
    ),
    rotated_at TEXT CHECK (
        rotated_at IS NULL
        OR (
            length(CAST(rotated_at AS BLOB)) BETWEEN 1 AND 64
            AND instr(rotated_at, char(0)) = 0
        )
    ),
    updated_at TEXT NOT NULL CHECK (
        length(CAST(updated_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(updated_at, char(0)) = 0
    )
);

CREATE INDEX idx_connection_local_secrets_key
ON connection_local_secrets(key_id, id);
"#;

const MIGRATION_4_SQL: &str = r#"
CREATE TABLE connection_mcp_catalogs (
    connection_id TEXT PRIMARY KEY,
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 1),
    observed_etag TEXT NOT NULL CHECK (
        length(CAST(observed_etag AS BLOB)) BETWEEN 1 AND 512
        AND instr(observed_etag, char(0)) = 0
    ),
    refreshed_at TEXT NOT NULL CHECK (
        length(CAST(refreshed_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(refreshed_at, char(0)) = 0
    ),
    entry_count INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_mcp_catalog_entries (
    connection_id TEXT NOT NULL,
    remote_tool_name TEXT NOT NULL CHECK (
        length(remote_tool_name) BETWEEN 1 AND 128
        AND instr(remote_tool_name, char(0)) = 0
    ),
    description TEXT NOT NULL CHECK (
        length(description) BETWEEN 1 AND 1024
        AND instr(description, char(0)) = 0
    ),
    input_schema_json TEXT NOT NULL CHECK (
        length(CAST(input_schema_json AS BLOB)) BETWEEN 2 AND 262144
    ),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, remote_tool_name),
    FOREIGN KEY (connection_id)
        REFERENCES connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_mcp_catalog_ordinal
ON connection_mcp_catalog_entries(connection_id, ordinal);

ALTER TABLE connection_current_status RENAME TO connection_current_status_v1;
CREATE TABLE connection_current_status (
    connection_id TEXT PRIMARY KEY,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);
INSERT INTO connection_current_status
SELECT * FROM connection_current_status_v1;
DROP TABLE connection_current_status_v1;

ALTER TABLE connection_status_history RENAME TO connection_status_history_v1;
CREATE TABLE connection_status_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);
INSERT INTO connection_status_history
SELECT * FROM connection_status_history_v1;
DROP TABLE connection_status_history_v1;
CREATE UNIQUE INDEX idx_connection_status_revision
ON connection_status_history(connection_id, status_revision);
CREATE INDEX idx_connection_status_latest
ON connection_status_history(connection_id, status_revision DESC);
"#;

const MIGRATION_5_SQL: &str = r#"
CREATE TABLE connection_openapi_catalogs (
    connection_id TEXT PRIMARY KEY,
    spec_revision INTEGER NOT NULL CHECK (spec_revision >= 1),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 1),
    observed_etag TEXT NOT NULL CHECK (
        length(CAST(observed_etag AS BLOB)) BETWEEN 1 AND 512
        AND instr(observed_etag, char(0)) = 0
    ),
    spec_digest TEXT NOT NULL CHECK (
        length(spec_digest) = 64
        AND spec_digest NOT GLOB '*[^0-9a-f]*'
    ),
    spec TEXT NOT NULL CHECK (
        length(CAST(spec AS BLOB)) BETWEEN 1 AND 2097152
    ),
    refreshed_at TEXT NOT NULL CHECK (
        length(CAST(refreshed_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(refreshed_at, char(0)) = 0
    ),
    entry_count INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_openapi_catalog_entries (
    connection_id TEXT NOT NULL,
    tool_name TEXT NOT NULL CHECK (
        length(tool_name) BETWEEN 1 AND 128
        AND instr(tool_name, char(0)) = 0
    ),
    operation_id TEXT CHECK (
        operation_id IS NULL
        OR (
            length(operation_id) BETWEEN 1 AND 256
            AND instr(operation_id, char(0)) = 0
        )
    ),
    selected_scheme_names_json TEXT NOT NULL CHECK (
        length(CAST(selected_scheme_names_json AS BLOB)) BETWEEN 2 AND 16384
    ),
    definition_json TEXT NOT NULL CHECK (
        length(CAST(definition_json AS BLOB)) BETWEEN 2 AND 262144
    ),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, tool_name),
    FOREIGN KEY (connection_id)
        REFERENCES connection_openapi_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_openapi_catalog_ordinal
ON connection_openapi_catalog_entries(connection_id, ordinal);
"#;

const MIGRATION_6_SQL: &str = r#"
ALTER TABLE connection_mcp_catalogs
ADD COLUMN resource_count INTEGER NOT NULL DEFAULT 0
CHECK (resource_count BETWEEN 0 AND 4096);

ALTER TABLE connection_mcp_catalogs
ADD COLUMN resource_template_count INTEGER NOT NULL DEFAULT 0
CHECK (
    resource_template_count BETWEEN 0 AND 4096
    AND entry_count + resource_count + resource_template_count <= 4096
);

CREATE TABLE connection_mcp_catalog_resources (
    connection_id TEXT NOT NULL,
    uri TEXT NOT NULL CHECK (
        length(CAST(uri AS BLOB)) BETWEEN 1 AND 2048
        AND instr(uri, char(0)) = 0
    ),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 128
        AND length(CAST(name AS BLOB)) BETWEEN 1 AND 512
        AND instr(name, char(0)) = 0
    ),
    title TEXT CHECK (
        title IS NULL
        OR (
            length(title) BETWEEN 1 AND 256
            AND length(CAST(title AS BLOB)) BETWEEN 1 AND 1024
            AND instr(title, char(0)) = 0
        )
    ),
    description TEXT CHECK (
        description IS NULL
        OR (
            length(description) BETWEEN 1 AND 1024
            AND length(CAST(description AS BLOB)) BETWEEN 1 AND 4096
            AND instr(description, char(0)) = 0
        )
    ),
    mime_type TEXT CHECK (
        mime_type IS NULL
        OR (
            length(CAST(mime_type AS BLOB)) BETWEEN 1 AND 256
            AND instr(mime_type, char(0)) = 0
        )
    ),
    size INTEGER CHECK (size IS NULL OR size >= 0),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, uri),
    FOREIGN KEY (connection_id)
        REFERENCES connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_mcp_catalog_resource_ordinal
ON connection_mcp_catalog_resources(connection_id, ordinal);

CREATE TABLE connection_mcp_catalog_resource_templates (
    connection_id TEXT NOT NULL,
    uri_template TEXT NOT NULL CHECK (
        length(CAST(uri_template AS BLOB)) BETWEEN 1 AND 2048
        AND instr(uri_template, char(0)) = 0
    ),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 128
        AND length(CAST(name AS BLOB)) BETWEEN 1 AND 512
        AND instr(name, char(0)) = 0
    ),
    title TEXT CHECK (
        title IS NULL
        OR (
            length(title) BETWEEN 1 AND 256
            AND length(CAST(title AS BLOB)) BETWEEN 1 AND 1024
            AND instr(title, char(0)) = 0
        )
    ),
    description TEXT CHECK (
        description IS NULL
        OR (
            length(description) BETWEEN 1 AND 1024
            AND length(CAST(description AS BLOB)) BETWEEN 1 AND 4096
            AND instr(description, char(0)) = 0
        )
    ),
    mime_type TEXT CHECK (
        mime_type IS NULL
        OR (
            length(CAST(mime_type AS BLOB)) BETWEEN 1 AND 256
            AND instr(mime_type, char(0)) = 0
        )
    ),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    PRIMARY KEY (connection_id, uri_template),
    FOREIGN KEY (connection_id)
        REFERENCES connection_mcp_catalogs(connection_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_mcp_catalog_resource_template_ordinal
ON connection_mcp_catalog_resource_templates(connection_id, ordinal);
"#;

const MIGRATION_7_SQL: &str = r#"
ALTER TABLE connection_records
ADD COLUMN last_test_at TEXT CHECK (
    last_test_at IS NULL
    OR (
        length(CAST(last_test_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(last_test_at, char(0)) = 0
    )
);

ALTER TABLE connection_records
ADD COLUMN last_refresh_at TEXT CHECK (
    last_refresh_at IS NULL
    OR (
        length(CAST(last_refresh_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(last_refresh_at, char(0)) = 0
    )
);

UPDATE connection_records
SET last_test_at = COALESCE(
    (
        SELECT current.observed_at
        FROM connection_current_status AS current
        WHERE current.connection_id = connection_records.id
          AND (
              current.reason = 'test_succeeded'
              OR (
                  current.reason IN (
                      'request_failed', 'egress_denied',
                      'secret_unavailable', 'invalid_response'
                  )
                  AND current.catalog_entry_count IS NULL
              )
          )
        LIMIT 1
    ),
    (
        SELECT history.observed_at
        FROM connection_status_history AS history
        WHERE history.connection_id = connection_records.id
          AND (
              history.reason = 'test_succeeded'
              OR (
                  history.reason IN (
                      'request_failed', 'egress_denied',
                      'secret_unavailable', 'invalid_response'
                  )
                  AND history.catalog_entry_count IS NULL
              )
          )
        ORDER BY history.status_revision DESC
        LIMIT 1
    )
);

UPDATE connection_records
SET last_refresh_at = COALESCE(
    (
        SELECT current.observed_at
        FROM connection_current_status AS current
        WHERE current.connection_id = connection_records.id
          AND (
              current.reason IN ('catalog_refreshed', 'catalog_stale')
              OR (
                  current.reason IN (
                      'request_failed', 'egress_denied',
                      'secret_unavailable', 'invalid_response'
                  )
                  AND current.catalog_entry_count IS NOT NULL
              )
          )
        LIMIT 1
    ),
    (
        SELECT history.observed_at
        FROM connection_status_history AS history
        WHERE history.connection_id = connection_records.id
          AND (
              history.reason IN ('catalog_refreshed', 'catalog_stale')
              OR (
                  history.reason IN (
                      'request_failed', 'egress_denied',
                      'secret_unavailable', 'invalid_response'
                  )
                  AND history.catalog_entry_count IS NOT NULL
              )
          )
        ORDER BY history.status_revision DESC
        LIMIT 1
    )
);
"#;

// Migration 8: additional secret headers on a Connection (issue #360, PR A).
//
// A Connection may now bind up to four secret-backed headers beyond its
// primary credential, each under the `additional_header` binding purpose,
// so the binding key must carry the header name: `(connection_id, purpose)`
// can hold only one row per purpose. SQLite cannot change a primary key in
// place, so the table is rebuilt: every existing row is copied with an
// empty `header_name` (the primary and TLS bindings have none), which keeps
// a single-binding Connection's rows byte-for-byte what they were, and the
// foreign key and cascade are re-declared unchanged.
const MIGRATION_8_SQL: &str = r#"
CREATE TABLE connection_credential_bindings_v8 (
    connection_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    header_name TEXT NOT NULL DEFAULT '' CHECK (
        length(CAST(header_name AS BLOB)) <= 64
        AND instr(header_name, char(0)) = 0
    ),
    secret_id TEXT NOT NULL,
    binding_version INTEGER NOT NULL CHECK (binding_version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, purpose, header_name),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

INSERT INTO connection_credential_bindings_v8 (
    connection_id, purpose, header_name, secret_id, binding_version, updated_at
)
SELECT connection_id, purpose, '', secret_id, binding_version, updated_at
FROM connection_credential_bindings;

DROP TABLE connection_credential_bindings;

ALTER TABLE connection_credential_bindings_v8 RENAME TO connection_credential_bindings;
"#;

/// Issue #360: the per-Connection OpenAPI overlay document, the overlay
/// revision a compiled catalog was produced under, and the last-known-good
/// dynamic enum values (created now so the dynamic-enum PR needs no
/// migration). PostgreSQL twin: `storage/migrations/0013_connection_overlays.sql`.
const MIGRATION_9_SQL: &str = r#"
CREATE TABLE connection_openapi_overlays (
    connection_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL CHECK (
        length(CAST(schema_version AS BLOB)) BETWEEN 1 AND 32
        AND instr(schema_version, char(0)) = 0
    ),
    overlay_revision INTEGER NOT NULL CHECK (overlay_revision >= 1),
    overlay_json TEXT NOT NULL CHECK (
        length(CAST(overlay_json AS BLOB)) BETWEEN 2 AND 1048576
    ),
    source_reports_json TEXT CHECK (
        source_reports_json IS NULL OR
        length(CAST(source_reports_json AS BLOB)) BETWEEN 2 AND 262144
    ),
    actor_user_id TEXT,
    updated_at TEXT NOT NULL CHECK (
        length(CAST(updated_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(updated_at, char(0)) = 0
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

ALTER TABLE connection_openapi_catalogs
ADD COLUMN overlay_revision INTEGER NOT NULL DEFAULT 0
CHECK (overlay_revision >= 0);

CREATE TABLE connection_enum_source_values (
    connection_id TEXT NOT NULL,
    source_id TEXT NOT NULL CHECK (
        length(source_id) BETWEEN 1 AND 64
        AND instr(source_id, char(0)) = 0
    ),
    overlay_revision INTEGER NOT NULL CHECK (overlay_revision >= 1),
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64
        AND source_digest NOT GLOB '*[^0-9a-f]*'
    ),
    values_revision INTEGER NOT NULL CHECK (values_revision >= 1),
    connection_revision INTEGER NOT NULL CHECK (connection_revision >= 0),
    credential_revision INTEGER NOT NULL CHECK (credential_revision >= 0),
    credential_generation_digest TEXT CHECK (
        credential_generation_digest IS NULL OR (
            length(credential_generation_digest) = 64
            AND credential_generation_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    values_json TEXT NOT NULL CHECK (
        length(CAST(values_json AS BLOB)) BETWEEN 2 AND 262144
    ),
    resolved_at TEXT NOT NULL CHECK (
        length(CAST(resolved_at AS BLOB)) BETWEEN 1 AND 64
        AND instr(resolved_at, char(0)) = 0
    ),
    PRIMARY KEY (connection_id, source_id),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_enum_source_overlay
ON connection_enum_source_values(connection_id, overlay_revision);
"#;

// Migration 10: preserve optional MCP tool display metadata and client hints
// in the durable managed-discovery catalog. NULL keeps every existing row's
// logical representation unchanged.
const MIGRATION_10_SQL: &str = r#"
ALTER TABLE connection_mcp_catalog_entries
ADD COLUMN title TEXT CHECK (
    title IS NULL OR (
        length(title) BETWEEN 1 AND 256
        AND length(CAST(title AS BLOB)) <= 1024
        AND instr(title, char(0)) = 0
    )
);

ALTER TABLE connection_mcp_catalog_entries
ADD COLUMN annotations_json TEXT CHECK (
    annotations_json IS NULL OR
    length(CAST(annotations_json AS BLOB)) BETWEEN 2 AND 2048
);
"#;

// Migration 11: retain precise, bounded MCP upstream failure categories in
// Connection status. SQLite cannot alter a CHECK constraint in place, so
// both status tables are rebuilt with their rows and revision keys intact.
const MIGRATION_11_SQL: &str = r#"
ALTER TABLE connection_current_status RENAME TO connection_current_status_v10;

CREATE TABLE connection_current_status (
    connection_id TEXT PRIMARY KEY,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'upstream_method_not_found', 'upstream_error',
            'upstream_transport_failure', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

INSERT INTO connection_current_status
SELECT * FROM connection_current_status_v10;
DROP TABLE connection_current_status_v10;

ALTER TABLE connection_status_history RENAME TO connection_status_history_v10;

CREATE TABLE connection_status_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'upstream_method_not_found', 'upstream_error',
            'upstream_transport_failure', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

INSERT INTO connection_status_history
SELECT * FROM connection_status_history_v10;
DROP TABLE connection_status_history_v10;

CREATE UNIQUE INDEX idx_connection_status_revision
ON connection_status_history(connection_id, status_revision);

CREATE INDEX idx_connection_status_latest
ON connection_status_history(connection_id, status_revision DESC);
"#;

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: MIGRATION_1_SQL,
    },
    Migration {
        version: 2,
        sql: MIGRATION_2_SQL,
    },
    Migration {
        version: 3,
        sql: MIGRATION_3_SQL,
    },
    Migration {
        version: 4,
        sql: MIGRATION_4_SQL,
    },
    Migration {
        version: 5,
        sql: MIGRATION_5_SQL,
    },
    Migration {
        version: 6,
        sql: MIGRATION_6_SQL,
    },
    Migration {
        version: 7,
        sql: MIGRATION_7_SQL,
    },
    Migration {
        version: 8,
        sql: MIGRATION_8_SQL,
    },
    Migration {
        version: 9,
        sql: MIGRATION_9_SQL,
    },
    Migration {
        version: 10,
        sql: MIGRATION_10_SQL,
    },
    Migration {
        version: 11,
        sql: MIGRATION_11_SQL,
    },
];

pub(crate) const SOURCE_MANAGED: &str = "managed";
const MAX_DEPENDENCY_FIELD_BYTES: usize = 256;
pub const MAX_CONNECTION_DEPENDENCIES: usize = 4_096;
const MAX_MCP_CATALOG_ENTRY_BYTES: usize = 262_144;
pub(crate) const MAX_MANAGED_MCP_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_TOOL_NAME_CHARS: usize = 128;
const MAX_MCP_TOOL_DESCRIPTION_CHARS: usize = 1_024;
const MAX_MCP_TOOL_TITLE_CHARS: usize = 256;
const MAX_MCP_TOOL_TITLE_BYTES: usize = 1_024;
const MAX_MCP_TOOL_ANNOTATIONS_BYTES: usize = 2_048;
const MAX_MCP_RESOURCE_URI_BYTES: usize = 2_048;
const MAX_MCP_RESOURCE_NAME_CHARS: usize = 128;
const MAX_MCP_RESOURCE_NAME_BYTES: usize = 512;
const MAX_MCP_RESOURCE_TITLE_CHARS: usize = 256;
const MAX_MCP_RESOURCE_TITLE_BYTES: usize = 1_024;
const MAX_MCP_RESOURCE_DESCRIPTION_CHARS: usize = 1_024;
const MAX_MCP_RESOURCE_DESCRIPTION_BYTES: usize = 4_096;
const MAX_MCP_RESOURCE_MIME_TYPE_BYTES: usize = 256;
const MAX_OPENAPI_CATALOG_ENTRY_BYTES: usize = 262_144;
/// Issue #360: the stored overlay document (`tools/overlay.rs`
/// `MAX_OVERLAY_BYTES`, mirrored by the column CHECK in migration 9).
pub(crate) const MAX_OPENAPI_OVERLAY_BYTES: usize = 1_048_576;
pub(crate) const OPENAPI_OVERLAY_SCHEMA_VERSION: &str = "0.1.0";
pub(crate) const MAX_OPENAPI_SOURCE_REPORTS_BYTES: usize = 262_144;
pub(crate) const OPENAPI_SOURCE_REPORTS_SCHEMA_VERSION: &str = "0.1.0";
pub(crate) const MAX_OPENAPI_ENUM_SOURCE_VALUES_BYTES: usize = 262_144;
pub(crate) const OPENAPI_ENUM_SOURCE_VALUES_VERSION: u32 = 1;
pub(crate) const MAX_OPENAPI_ENUM_SOURCES: usize = 64;
pub(crate) const MAX_OPENAPI_SOURCE_REPORTS: usize = 128;
const MAX_OPENAPI_SOURCE_ITEMS: u64 = 1_024;
const MAX_OPENAPI_TOOL_NAME_CHARS: usize = 128;
const MAX_OPENAPI_OPERATION_ID_CHARS: usize = 256;
const MAX_OPENAPI_SECURITY_SCHEMES: usize = 64;
const MAX_OPENAPI_SECURITY_SCHEME_NAME_CHARS: usize = 128;
const MAX_OPENAPI_SECURITY_SCHEMES_JSON_BYTES: usize = 16_384;
const SHA256_HEX_CHARS: usize = 64;

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

#[derive(Clone)]
pub struct SqliteConnectionStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    maximum_connections: usize,
}

pub trait ConnectionStore: Send + Sync {
    fn count(&self) -> Result<usize, ConnectionStoreError>;
    fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError>;
    fn get(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, ConnectionStoreError>;
    fn create(&self, candidate: ConnectionWrite) -> Result<StoredConnection, ConnectionStoreError>;
    fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionStoreError>;
    fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
    ) -> Result<(), ConnectionStoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEtag(String);

impl ConnectionEtag {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rebuild an etag read back from a store, verbatim. Stores persist the
    /// canonical string; no parsing or validation happens here, matching
    /// the SQLite store's opaque round-trip.
    pub(crate) fn from_stored(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn for_record(id: &ConnectionId, revisions: &ConnectionRevisions) -> Self {
        Self(format!(
            "\"connection:{}:c{}:k{}:t{}:d{}\"",
            id.as_str(),
            revisions.connection,
            revisions.credential,
            revisions.tls,
            revisions.discovery
        ))
    }
}

impl fmt::Display for ConnectionEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The strong ETag of a Connection's stored OpenAPI overlay (issue #360):
/// `"overlay:{connection_id}:c{connection_revision}:r{catalog_revision}:o{overlay_revision}"`,
/// quoted the way [`ConnectionEtag::for_record`] quotes, with `o0` meaning
/// "no overlay stored". The monotonically increasing catalog revision prevents
/// an ETag from becoming valid again after PUT -> DELETE -> recreate, while the
/// monotonically increasing Connection revision also covers a compatible-ID
/// kind replacement that removes and later recreates the OpenAPI catalog. A
/// full Connection DELETE followed by a new POST is a replacement of the
/// Connection resource itself and is governed by that resource's contract.
/// PUT and DELETE of the overlay require an exact `If-Match`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayEtag(String);

impl OverlayEtag {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn for_revisions(
        connection_id: &str,
        connection_revision: u64,
        catalog_revision: u64,
        overlay_revision: u64,
    ) -> Self {
        Self(format!(
            "\"overlay:{connection_id}:c{connection_revision}:r{catalog_revision}:o{overlay_revision}\""
        ))
    }
}

impl fmt::Display for OverlayEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredConnection {
    pub id: ConnectionId,
    pub write: ConnectionWrite,
    pub revisions: ConnectionRevisions,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionActivityTimes {
    pub last_test_at: Option<String>,
    pub last_refresh_at: Option<String>,
}

impl StoredConnection {
    pub fn etag(&self) -> ConnectionEtag {
        ConnectionEtag::for_record(&self.id, &self.revisions)
    }

    pub fn safe_summary(&self, status: Option<SafeConnectionStatus>) -> SafeConnectionSummary {
        let status = status.unwrap_or({
            if self.write.enabled {
                SafeConnectionStatus {
                    state: ConnectionOperationalState::Unknown,
                    reason: ConnectionStatusReason::NotTested,
                    observed_at: None,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                }
            } else {
                SafeConnectionStatus {
                    state: ConnectionOperationalState::Disabled,
                    reason: ConnectionStatusReason::Disabled,
                    observed_at: None,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                }
            }
        });
        SafeConnectionSummary {
            id: self.id.clone(),
            display_name: self.write.display_name.clone(),
            enabled: self.write.enabled,
            kind: self.write.kind,
            source: ConnectionManagementSource::Managed,
            read_only: false,
            authentication: safe_authentication_kind(&self.write.authentication),
            endpoint_count: 1,
            revisions: self.revisions.clone(),
            status,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDependencyKind {
    ProxyRoute,
    ManualTool,
    ManagedTool,
    ControlPlane,
}

impl ConnectionDependencyKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ProxyRoute => "proxy_route",
            Self::ManualTool => "manual_tool",
            Self::ManagedTool => "managed_tool",
            Self::ControlPlane => "control_plane",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "proxy_route" => Some(Self::ProxyRoute),
            "manual_tool" => Some(Self::ManualTool),
            "managed_tool" => Some(Self::ManagedTool),
            "control_plane" => Some(Self::ControlPlane),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDependency {
    pub kind: ConnectionDependencyKind,
    pub consumer_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionStatusUpdate {
    pub state: ConnectionOperationalState,
    pub reason: ConnectionStatusReason,
    pub latency_ms: Option<u64>,
    pub catalog_age_secs: Option<u64>,
    pub catalog_entry_count: Option<usize>,
}

/// One status observation exactly as it is persisted.
///
/// [`SafeConnectionStatus`] is the SAFE PROJECTION of these rows: it drops
/// the revision columns the row is keyed and validated by, and it ages
/// `catalog_age_secs` forward to the moment of the read (store.rs
/// `RawStatus::into_safe_status`) so a UI shows how stale a catalog is
/// now. Neither is what a copy of the durable state may carry: an import
/// that wrote the aged value would record a catalog age that grew every
/// time the row was read, and one that could not carry the revisions
/// could not write `connection_status_history` at all. This is the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedConnectionStatus {
    pub connection_id: ConnectionId,
    pub status_revision: u64,
    pub observed_connection_revision: u64,
    pub observed_credential_revision: u64,
    pub observed_tls_revision: u64,
    pub observed_discovery_revision: u64,
    pub state: ConnectionOperationalState,
    pub reason: ConnectionStatusReason,
    pub observed_at: String,
    pub latency_ms: Option<u64>,
    pub catalog_age_secs: Option<u64>,
    pub catalog_entry_count: Option<u64>,
}

/// Both status tables of a standalone deployment, read together.
///
/// They are separate tables and not one derivable from the other: history
/// is pruned against a global budget while a current-status row never is,
/// so a Connection can hold a current status whose history row was pruned
/// away (store.rs `append_status`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportedConnectionStatuses {
    /// One per Connection that has ever been observed, keyed by ID.
    pub current: Vec<PersistedConnectionStatus>,
    /// Oldest first, in the order the observations were appended.
    pub history: Vec<PersistedConnectionStatus>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredMcpCatalogEntry {
    pub remote_tool_name: String,
    pub title: Option<String>,
    pub description: String,
    pub input_schema: Value,
    pub annotations: Option<crate::tools::definitions::ToolAnnotations>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMcpResource {
    pub uri: String,
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMcpResourceTemplate {
    pub uri_template: String,
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredMcpCatalog {
    pub connection_id: ConnectionId,
    pub catalog_revision: u64,
    pub observed_etag: ConnectionEtag,
    pub refreshed_at: String,
    pub entries: Vec<StoredMcpCatalogEntry>,
    pub resources: Vec<StoredMcpResource>,
    pub resource_templates: Vec<StoredMcpResourceTemplate>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredOpenApiCatalogEntry {
    pub tool_name: String,
    pub operation_id: Option<String>,
    pub selected_scheme_names: Vec<String>,
    pub definition: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredOpenApiCatalog {
    pub connection_id: ConnectionId,
    pub spec_revision: u64,
    pub catalog_revision: u64,
    pub observed_etag: ConnectionEtag,
    pub spec_digest: String,
    pub spec: String,
    pub refreshed_at: String,
    pub entries: Vec<StoredOpenApiCatalogEntry>,
    /// The overlay revision this catalog was compiled under (issue #360);
    /// `0` when no overlay was stored at publish time.
    pub overlay_revision: u64,
}

/// A Connection's stored OpenAPI overlay document (issue #360). The JSON is
/// stored verbatim and validated by `tools/overlay.rs::validate` on the way
/// in; the store treats it as opaque bytes, like the spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOpenApiOverlay {
    pub connection_id: ConnectionId,
    pub schema_version: String,
    pub overlay_revision: u64,
    pub overlay_json: String,
    /// Compile-time source status served by overlay GET without performing
    /// credentialed upstream I/O. PR1 normally leaves this absent; later
    /// source compilers persist their canonical report object here.
    pub source_reports_json: Option<String>,
    pub updated_at: String,
}

/// One durable last-known-good value set for a dynamic OpenAPI enum source.
///
/// The row is useful only when every generation field still agrees with the
/// live source plan and Connection. `credential_generation_digest == None`
/// deliberately marks a volatile credential authority (for example an
/// environment/file alias or a provider's movable `latest` selector): those
/// rows may coordinate replicas during the process lifetime but must never be
/// adopted at boot or used after a failed refresh.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredEnumSourceValue {
    pub connection_id: ConnectionId,
    pub source_id: String,
    pub overlay_revision: u64,
    pub source_digest: String,
    pub values_revision: u64,
    pub connection_revision: u64,
    pub credential_revision: u64,
    pub credential_generation_digest: Option<String>,
    pub values: Vec<Value>,
    pub labels: Option<Vec<String>>,
    pub resolved_at: String,
}

/// Small authority record polled by replicas. It deliberately excludes the
/// potentially 256 KiB values document; full JSON is fetched only when this
/// revision is newer than the replica's cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEnumSourceRevision {
    pub connection_id: ConnectionId,
    pub source_id: String,
    pub overlay_revision: u64,
    pub source_digest: String,
    pub values_revision: u64,
    pub connection_revision: u64,
    pub credential_revision: u64,
    pub credential_generation_digest: Option<String>,
}

/// Candidate for a compare-and-set update of one enum source's durable LKG.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredEnumSourceValueWrite {
    pub connection_id: ConnectionId,
    pub source_id: String,
    pub overlay_revision: u64,
    pub source_digest: String,
    /// Durable revision observed before the upstream fetch began. This is not
    /// persisted; publication fails rather than overwriting a newer winner.
    pub expected_values_revision: u64,
    pub connection_revision: u64,
    pub credential_revision: u64,
    pub credential_generation_digest: Option<String>,
    pub values: Vec<Value>,
    pub labels: Option<Vec<String>>,
    pub resolved_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredEnumSourceValuesDocument {
    pub(crate) version: u32,
    pub(crate) values: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) labels: Option<Vec<String>>,
}

/// Versioned, bounded compile-time source status stored with an overlay.
///
/// PR 1 persists an empty snapshot. Later source resolvers populate the same
/// strict shape, so an admin GET never has to perform credentialed upstream
/// I/O and an older binary fails closed instead of hiding fields it does not
/// understand.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredOpenApiSourceReports {
    pub schema_version: String,
    pub sources: Vec<StoredOpenApiSourceReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredOpenApiSourceReport {
    pub id: String,
    pub kind: StoredOpenApiSourceKind,
    pub state: String,
    pub item_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredOpenApiSourceKind {
    Enum,
    Label,
}

impl StoredOpenApiSourceReports {
    pub fn empty() -> Self {
        Self {
            schema_version: OPENAPI_SOURCE_REPORTS_SCHEMA_VERSION.to_owned(),
            sources: Vec::new(),
        }
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl StoredOpenApiOverlay {
    pub fn etag(&self, connection_revision: u64, catalog_revision: u64) -> OverlayEtag {
        OverlayEtag::for_revisions(
            self.connection_id.as_str(),
            connection_revision,
            catalog_revision,
            self.overlay_revision,
        )
    }
}

/// The overlay half of `replace_openapi_catalog` (issue #360, D1): written
/// in the same transaction as the catalog rows, so a catalog row can never
/// name an overlay revision that is not stored.
///
/// `overlay_json: Some(_)` stores the document at `expected_overlay_revision
/// + 1`; `None` deletes the stored overlay (the catalog row then records
/// `0`). Either way `expected_overlay_revision` must equal the stored
/// revision (`0` when nothing is stored) or the whole replace fails with
/// [`ConnectionStoreError::OverlayConflict`] and nothing is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredOverlayWrite {
    /// Store a new authoring document and advance its overlay revision.
    Put {
        schema_version: String,
        overlay_json: String,
        source_reports_json: String,
        expected_overlay_revision: u64,
    },
    /// Delete the authoring document and reset the compiled revision to zero.
    Delete { expected_overlay_revision: u64 },
    /// Replace only the canonical source report snapshot. The authoring
    /// document and overlay revision remain unchanged, while the catalog and
    /// report timestamp still commit atomically.
    Reports {
        source_reports_json: String,
        expected_overlay_revision: u64,
    },
}

impl StoredOverlayWrite {
    fn expected_overlay_revision(&self) -> u64 {
        match self {
            Self::Put {
                expected_overlay_revision,
                ..
            }
            | Self::Delete {
                expected_overlay_revision,
            }
            | Self::Reports {
                expected_overlay_revision,
                ..
            } => *expected_overlay_revision,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredOpenApiInventoryCatalog {
    pub connection_id: ConnectionId,
    pub spec_revision: u64,
    pub catalog_revision: u64,
    pub observed_etag: ConnectionEtag,
    pub spec_digest: String,
    pub refreshed_at: String,
    pub entries: Vec<StoredOpenApiCatalogEntry>,
}

#[derive(Debug)]
pub enum ConnectionStoreError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Sqlite {
        path: PathBuf,
        operation: &'static str,
        source: rusqlite::Error,
    },
    Json {
        operation: &'static str,
        source: serde_json::Error,
    },
    Validation {
        problems: Vec<String>,
    },
    CorruptRecord {
        id: String,
        reason: &'static str,
    },
    UnsupportedSchema {
        version: u32,
    },
    InvalidMigrationHistory,
    LimitExceeded {
        resource: &'static str,
        maximum: usize,
    },
    NotFound {
        id: String,
    },
    Conflict {
        id: String,
        current: ConnectionEtag,
    },
    /// The overlay precondition of a catalog replace did not hold (issue
    /// #360): the stored overlay is at `current_overlay_revision`, not the
    /// revision the caller expected. The caller surfaces `412` with the
    /// current overlay ETag. Nothing was written.
    OverlayConflict {
        id: String,
        current_connection_revision: u64,
        current_catalog_revision: u64,
        current_overlay_revision: u64,
    },
    /// A dynamic-enum writer lost its per-source CAS, or the Connection /
    /// overlay generation it resolved under is no longer authoritative.
    EnumSourceConflict {
        id: String,
        source_id: String,
        current_values_revision: u64,
    },
    /// A catalog tool name is already published by another lane at the
    /// authority (cluster mode). The caller surfaces `409`.
    ToolNameConflict {
        id: String,
        tool_name: String,
        lane: String,
        owner_id: String,
    },
    DependencyConflict {
        id: String,
        count: usize,
    },
    RevisionOverflow {
        id: String,
    },
    Busy {
        resource: &'static str,
    },
    DeadlineExceeded {
        operation: &'static str,
    },
    /// The PostgreSQL authority could not be consulted or rejected the
    /// operation (cluster mode's store). Carries a stable operation label
    /// only -- no SQL text, no query values, no DSN material; the detail
    /// is logged where the failure occurs.
    Postgres {
        operation: &'static str,
    },
    /// The store could not be consulted at all: the blocking worker that
    /// runs the standalone store's synchronous body did not complete
    /// (runtime shutdown, or a panic inside it). Fail closed -- this is
    /// never a "not found" and never a success.
    Unavailable {
        operation: &'static str,
    },
    /// A create's collection precondition (the `If-Match` over the whole
    /// managed collection) no longer holds at the authority: another
    /// replica changed the collection after the caller read it. Carries
    /// the authority's current collection ETag so the response can name
    /// it, exactly as the process-local check does.
    CollectionConflict {
        current: String,
    },
}

/// The cross-replica half of a create's `If-Match` (issue #241, PR 8).
///
/// The control plane checks the collection ETag against its own runtime
/// snapshot before calling the store, which is authoritative in standalone
/// mode -- one process, one snapshot. In cluster mode two replicas can
/// each pass that local check with the same `If-Match` and both insert, so
/// the PostgreSQL store re-derives the collection ETag from the authority's
/// records inside the create transaction, under the same lock every other
/// mutation takes, and refuses the create if it moved. `compute` is the
/// control plane's own derivation (it captures the replica's legacy
/// projections, which the store does not know about), so the two checks
/// cannot disagree about what the ETag means.
pub struct CollectionCheck<'a> {
    pub expected_etag: &'a str,
    pub compute: &'a (dyn Fn(&BTreeMap<ConnectionId, StoredConnection>) -> String + Send + Sync),
}

impl fmt::Display for ConnectionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open configured connection SQLite store at {}: {source}",
                path.display()
            ),
            Self::Sqlite {
                path,
                operation,
                source,
            } => write!(
                formatter,
                "connection SQLite {operation} failed at {}: {source}",
                path.display()
            ),
            Self::Json { operation, source } => {
                write!(
                    formatter,
                    "connection {operation} serialization failed: {source}"
                )
            }
            Self::Validation { problems } => write!(
                formatter,
                "connection candidate failed validation: {}",
                problems.join("; ")
            ),
            Self::CorruptRecord { id, reason } => {
                write!(formatter, "stored connection '{id}' is invalid: {reason}")
            }
            Self::UnsupportedSchema { version } => write!(
                formatter,
                "connection SQLite schema version {version} is newer or unknown"
            ),
            Self::InvalidMigrationHistory => formatter.write_str(
                "connection SQLite migration history is not a contiguous ordered prefix",
            ),
            Self::LimitExceeded { resource, maximum } => {
                write!(formatter, "{resource} limit of {maximum} has been reached")
            }
            Self::NotFound { id } => write!(formatter, "connection '{id}' was not found"),
            Self::Conflict { id, current } => write!(
                formatter,
                "connection '{id}' changed; current ETag is {current}"
            ),
            Self::DependencyConflict { id, count } => write!(
                formatter,
                "connection '{id}' is referenced by {count} retained control-plane records"
            ),
            Self::ToolNameConflict {
                id,
                tool_name,
                lane,
                owner_id,
            } => write!(
                formatter,
                "connection '{id}' cannot publish tool '{tool_name}': it is already published by the {lane} lane ({owner_id})"
            ),
            Self::RevisionOverflow { id } => {
                write!(
                    formatter,
                    "connection '{id}' revision cannot be incremented"
                )
            }
            Self::Busy { resource } => {
                write!(formatter, "{resource} is busy")
            }
            Self::DeadlineExceeded { operation } => {
                write!(formatter, "{operation} exceeded its deadline")
            }
            Self::Postgres { operation } => {
                write!(formatter, "connection PostgreSQL {operation} failed")
            }
            Self::Unavailable { operation } => {
                write!(formatter, "{operation} could not be executed")
            }
            Self::CollectionConflict { current } => write!(
                formatter,
                "connection collection changed at the authority; current ETag is {current}"
            ),
            Self::OverlayConflict {
                id,
                current_connection_revision,
                current_catalog_revision,
                current_overlay_revision,
            } => write!(
                formatter,
                "connection '{id}' overlay changed during the mutation; current connection/catalog/overlay revisions are {current_connection_revision}/{current_catalog_revision}/{current_overlay_revision}"
            ),
            Self::EnumSourceConflict {
                id,
                source_id,
                current_values_revision,
            } => write!(
                formatter,
                "connection '{id}' enum source '{source_id}' changed during refresh; current values revision is {current_values_revision}"
            ),
        }
    }
}

impl Error for ConnectionStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl SqliteConnectionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ConnectionStoreError> {
        Self::open_with_maximum(path, MAX_CONNECTIONS)
    }

    pub fn open_with_maximum(
        path: impl AsRef<Path>,
        maximum_connections: usize,
    ) -> Result<Self, ConnectionStoreError> {
        if maximum_connections > MAX_CONNECTIONS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: MAX_CONNECTIONS,
            });
        }
        let path = path.as_ref().to_path_buf();
        let mut connection =
            Connection::open(&path).map_err(|source| ConnectionStoreError::Open {
                path: path.clone(),
                source,
            })?;
        connection
            .busy_timeout(DEFAULT_SQLITE_BUSY_TIMEOUT)
            .map_err(|source| sqlite_error(&path, "configuration", source))?;
        connection
            .execute_batch(CONFIGURE_SQL)
            .map_err(|source| sqlite_error(&path, "configuration", source))?;
        run_migrations(&mut connection, &path, MIGRATIONS)?;
        validate_persisted_state(&mut connection, &path, maximum_connections)?;

        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
            maximum_connections,
        })
    }

    pub fn maximum_connections(&self) -> usize {
        self.maximum_connections
    }

    pub(crate) fn shared_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.connection)
    }

    pub(crate) fn local_secret_count(&self) -> Result<usize, ConnectionStoreError> {
        let connection = self.connection_guard();
        count_rows(
            &connection,
            &self.path,
            "encrypted local secrets",
            "SELECT COUNT(*) FROM connection_local_secrets",
        )
    }

    pub fn add_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let now = utc_timestamp()?;
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "dependency transaction", source))?;
        let exists: bool = transaction
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM connection_dependencies
                    WHERE connection_id = ?1 AND consumer_kind = ?2 AND consumer_id = ?3
                )
                "#,
                params![id.as_str(), kind.as_str(), consumer_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency lookup", source))?;
        if exists {
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, "dependency no-op commit", source))?;
            return Ok(());
        }
        let dependency_count = count_rows(
            &transaction,
            &self.path,
            "connection dependencies",
            "SELECT COUNT(*) FROM connection_dependencies",
        )?;
        if dependency_count >= MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        transaction
            .execute(
                r#"
                INSERT INTO connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![id.as_str(), kind.as_str(), consumer_id, now],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency insert", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "dependency commit", source))?;
        Ok(())
    }

    pub fn remove_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let connection = self.connection_guard();
        connection
            .execute(
                r#"
                DELETE FROM connection_dependencies
                WHERE connection_id = ?1 AND consumer_kind = ?2 AND consumer_id = ?3
                "#,
                params![id.as_str(), kind.as_str(), consumer_id],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency delete", source))?;
        Ok(())
    }

    pub fn replace_dependencies_for_kind(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(ConnectionId, String)],
    ) -> Result<(), ConnectionStoreError> {
        if desired.len() > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        let mut unique = BTreeSet::new();
        for (connection_id, consumer_id) in desired {
            validate_dependency_id(consumer_id)?;
            if !unique.insert((connection_id.as_str(), consumer_id.as_str())) {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "connection dependency set contains duplicate consumers".to_owned()
                    ],
                });
            }
        }

        let now = utc_timestamp()?;
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| {
                sqlite_error(&self.path, "dependency replacement transaction", source)
            })?;
        transaction
            .execute(
                "DELETE FROM connection_dependencies WHERE consumer_kind = ?1",
                params![kind.as_str()],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency replacement delete", source))?;
        let retained_count = count_rows(
            &transaction,
            &self.path,
            "connection dependencies",
            "SELECT COUNT(*) FROM connection_dependencies",
        )?;
        if retained_count.saturating_add(desired.len()) > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }

        for (connection_id, consumer_id) in desired {
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM connection_records WHERE id = ?1)",
                    params![connection_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "dependency replacement owner lookup", source)
                })?;
            if !exists {
                return Err(ConnectionStoreError::NotFound {
                    id: connection_id.to_string(),
                });
            }
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![connection_id.as_str(), kind.as_str(), consumer_id, now],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "dependency replacement insert", source)
                })?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "dependency replacement commit", source))?;
        Ok(())
    }

    pub fn dependencies(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<ConnectionDependency>, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "dependency read transaction", source))?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM connection_records WHERE id = ?1)",
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency owner lookup", source))?;
        if !exists {
            return Err(ConnectionStoreError::NotFound { id: id.to_string() });
        }
        let mut statement = transaction
            .prepare(
                r#"
                SELECT consumer_kind, consumer_id
                FROM connection_dependencies
                WHERE connection_id = ?1
                ORDER BY consumer_kind ASC, consumer_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "dependency read prepare", source))?;
        let raw = statement
            .query_map(
                params![
                    id.as_str(),
                    i64::try_from(MAX_CONNECTION_DEPENDENCIES + 1).unwrap_or(i64::MAX)
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency read query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "dependency read", source))?;
        drop(statement);
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "dependency read commit", source))?;
        if raw.len() > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        raw.into_iter()
            .map(|(kind, consumer_id)| {
                let kind = ConnectionDependencyKind::parse(&kind).ok_or_else(|| {
                    ConnectionStoreError::CorruptRecord {
                        id: id.to_string(),
                        reason: "unknown dependency kind",
                    }
                })?;
                Ok(ConnectionDependency { kind, consumer_id })
            })
            .collect()
    }

    pub fn dependency_counts(&self) -> Result<BTreeMap<ConnectionId, usize>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT connection_id, COUNT(*)
                FROM connection_dependencies
                GROUP BY connection_id
                ORDER BY connection_id ASC
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "dependency counts prepare", source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|source| sqlite_error(&self.path, "dependency counts query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "dependency counts read", source))?;
        rows.into_iter()
            .map(|(id, count)| {
                let parsed = ConnectionId::parse(id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id,
                        reason: "invalid dependency owner ID",
                    }
                })?;
                let count =
                    usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
                        id: parsed.to_string(),
                        reason: "invalid dependency count",
                    })?;
                if count > MAX_CONNECTION_DEPENDENCIES {
                    return Err(ConnectionStoreError::LimitExceeded {
                        resource: "connection dependencies",
                        maximum: MAX_CONNECTION_DEPENDENCIES,
                    });
                }
                Ok((parsed, count))
            })
            .collect()
    }

    pub fn activity_times(
        &self,
    ) -> Result<BTreeMap<ConnectionId, ConnectionActivityTimes>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT id, last_test_at, last_refresh_at
                FROM connection_records
                ORDER BY id ASC
                LIMIT ?1
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "connection activity prepare", source))?;
        let rows = statement
            .query_map(
                params![i64::try_from(MAX_CONNECTIONS + 1).unwrap_or(i64::MAX)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .map_err(|source| sqlite_error(&self.path, "connection activity query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "connection activity read", source))?;
        if rows.len() > MAX_CONNECTIONS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection activity metadata",
                maximum: MAX_CONNECTIONS,
            });
        }
        rows.into_iter()
            .map(|(id, last_test_at, last_refresh_at)| {
                let parsed = ConnectionId::parse(id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id,
                        reason: "invalid activity owner ID",
                    }
                })?;
                validate_activity_timestamp(&parsed, last_test_at.as_deref())?;
                validate_activity_timestamp(&parsed, last_refresh_at.as_deref())?;
                Ok((
                    parsed,
                    ConnectionActivityTimes {
                        last_test_at,
                        last_refresh_at,
                    },
                ))
            })
            .collect()
    }

    pub fn mcp_catalogs(&self) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        let connection = self.connection_guard();
        load_mcp_catalogs(&connection, &self.path, None)
    }

    pub fn mcp_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredMcpCatalog>, ConnectionStoreError> {
        let connection = self.connection_guard();
        Ok(load_mcp_catalogs(&connection, &self.path, Some(id))?
            .into_iter()
            .next())
    }

    pub fn replace_mcp_catalog(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        entries: &[StoredMcpCatalogEntry],
        resources: &[StoredMcpResource],
        resource_templates: &[StoredMcpResourceTemplate],
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        self.replace_mcp_catalog_expecting(
            id,
            expected,
            entries,
            resources,
            resource_templates,
            None,
        )
    }

    /// [`SqliteConnectionStore::replace_mcp_catalog`] with the catalog's
    /// own compare-and-swap: `Some(revision)` requires the stored catalog
    /// revision to equal it (`0` = no catalog yet) and refuses with
    /// `Conflict` otherwise; `None` skips the check. The connection ETag
    /// does not move on a catalog replacement, so this is the only
    /// precondition that can tell two refreshes of the same prior catalog
    /// apart. Standalone mode serializes refreshes per Connection inside
    /// the process, so the check is redundant here -- it exists so both
    /// stores enforce exactly what the cluster path asks for.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_mcp_catalog_expecting(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        entries: &[StoredMcpCatalogEntry],
        resources: &[StoredMcpResource],
        resource_templates: &[StoredMcpResourceTemplate],
        expected_catalog_revision: Option<u64>,
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        let validated = validate_mcp_catalog(id, entries, resources, resource_templates)?;
        let now = utc_timestamp()?;
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "MCP catalog transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        if !supports_managed_mcp_catalog(&current.write) {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "MCP catalogs require a managed MCP streamable HTTP Connection".to_owned(),
                ],
            });
        }

        let retained_catalog_entry_count: i64 = transaction
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*)
                     FROM connection_mcp_catalog_entries
                     WHERE connection_id != ?1)
                  + (SELECT COUNT(*)
                     FROM connection_mcp_catalog_resources
                     WHERE connection_id != ?1)
                  + (SELECT COUNT(*)
                     FROM connection_mcp_catalog_resource_templates
                     WHERE connection_id != ?1)
                  + (SELECT COUNT(*) FROM connection_openapi_catalog_entries)
                "#,
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "catalog retained count", source))?;
        let retained_catalog_entries =
            usize::try_from(retained_catalog_entry_count).map_err(|_| {
                ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "invalid MCP catalog entry count",
                }
            })?;
        let candidate_count = entries
            .len()
            .saturating_add(resources.len())
            .saturating_add(resource_templates.len());
        if retained_catalog_entries.saturating_add(candidate_count) > MAX_CATALOG_ENTRIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: MAX_CATALOG_ENTRIES,
            });
        }
        let retained_catalog_bytes = mcp_catalog_bytes(
            &transaction,
            &self.path,
            Some(id),
            "MCP retained catalog byte count",
        )?;
        if retained_catalog_bytes
            .checked_add(validated.stored_bytes)
            .is_none_or(|total| total > MAX_MANAGED_MCP_CATALOG_BYTES)
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection MCP catalog bytes",
                maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
            });
        }

        let previous_revision = transaction
            .query_row(
                "SELECT catalog_revision FROM connection_mcp_catalogs WHERE connection_id = ?1",
                params![id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, "MCP catalog revision lookup", source))?
            .map(|revision| {
                u64::try_from(revision).map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "invalid MCP catalog revision",
                })
            })
            .transpose()?
            .unwrap_or_default();
        if let Some(expected_catalog_revision) = expected_catalog_revision {
            if previous_revision != expected_catalog_revision {
                return Err(ConnectionStoreError::Conflict {
                    id: id.to_string(),
                    current: current.etag(),
                });
            }
        }
        let catalog_revision = increment_revision(id, previous_revision)?;

        transaction
            .execute(
                "DELETE FROM connection_dependencies WHERE connection_id = ?1 AND consumer_kind = ?2",
                params![id.as_str(), ConnectionDependencyKind::ManagedTool.as_str()],
            )
            .map_err(|source| {
                sqlite_error(&self.path, "MCP catalog dependency replacement delete", source)
            })?;
        let retained_dependencies = count_rows(
            &transaction,
            &self.path,
            "connection dependencies",
            "SELECT COUNT(*) FROM connection_dependencies",
        )?;
        if retained_dependencies.saturating_add(entries.len()) > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }

        transaction
            .execute(
                "DELETE FROM connection_mcp_catalogs WHERE connection_id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| sqlite_error(&self.path, "MCP catalog replacement delete", source))?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_mcp_catalogs (
                    connection_id, catalog_revision, observed_etag, refreshed_at, entry_count,
                    resource_count, resource_template_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, catalog_revision)?,
                    expected.as_str(),
                    now,
                    i64::try_from(entries.len()).unwrap_or(i64::MAX),
                    i64::try_from(resources.len()).unwrap_or(i64::MAX),
                    i64::try_from(resource_templates.len()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "MCP catalog insert", source))?;

        for (ordinal, ((entry, input_schema_json), annotations_json)) in entries
            .iter()
            .zip(validated.encoded_tool_schemas.iter())
            .zip(validated.encoded_tool_annotations.iter())
            .enumerate()
        {
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_mcp_catalog_entries (
                        connection_id, remote_tool_name, title, description,
                        input_schema_json, annotations_json, ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        id.as_str(),
                        entry.remote_tool_name,
                        entry.title,
                        entry.description,
                        input_schema_json,
                        annotations_json,
                        i64::try_from(ordinal).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|source| sqlite_error(&self.path, "MCP catalog entry insert", source))?;
            let public_name = managed_tool_dependency_id(id, &entry.remote_tool_name);
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        id.as_str(),
                        ConnectionDependencyKind::ManagedTool.as_str(),
                        public_name,
                        now,
                    ],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "MCP catalog dependency insert", source)
                })?;
        }

        for (ordinal, resource) in resources.iter().enumerate() {
            let size = resource
                .size
                .map(|size| {
                    i64::try_from(size).map_err(|_| ConnectionStoreError::Validation {
                        problems: vec![format!(
                            "MCP resource {ordinal} size exceeds the durable integer range"
                        )],
                    })
                })
                .transpose()?;
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_mcp_catalog_resources (
                        connection_id, uri, name, title, description, mime_type, size, ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        id.as_str(),
                        resource.uri,
                        resource.name,
                        resource.title,
                        resource.description,
                        resource.mime_type,
                        size,
                        i64::try_from(ordinal).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "MCP catalog resource insert", source)
                })?;
        }

        for (ordinal, resource_template) in resource_templates.iter().enumerate() {
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_mcp_catalog_resource_templates (
                        connection_id, uri_template, name, title, description, mime_type, ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        id.as_str(),
                        resource_template.uri_template,
                        resource_template.name,
                        resource_template.title,
                        resource_template.description,
                        resource_template.mime_type,
                        i64::try_from(ordinal).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "MCP catalog resource template insert", source)
                })?;
        }

        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "MCP catalog transaction commit", source))?;

        Ok(StoredMcpCatalog {
            connection_id: id.clone(),
            catalog_revision,
            observed_etag: expected.clone(),
            refreshed_at: now,
            entries: entries.to_vec(),
            resources: resources.to_vec(),
            resource_templates: resource_templates.to_vec(),
        })
    }

    pub fn openapi_catalogs(&self) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        let connection = self.connection_guard();
        load_openapi_catalogs(&connection, &self.path, None)
    }

    /// Read the compiled OpenAPI catalogs and their authoring overlays from
    /// one SQLite snapshot. They are one logical resource: two independent
    /// reads could otherwise straddle a writer from another process and
    /// manufacture a revision mismatch during boot or reconciliation.
    pub fn openapi_catalogs_with_overlays(
        &self,
    ) -> Result<(Vec<StoredOpenApiCatalog>, Vec<StoredOpenApiOverlay>), ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "OpenAPI snapshot transaction", source))?;
        let catalogs = load_openapi_catalogs(&transaction, &self.path, None)?;
        let overlays = load_openapi_overlays(&transaction, &self.path, None)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "OpenAPI snapshot commit", source))?;
        Ok((catalogs, overlays))
    }

    /// Point-read counterpart of [`Self::openapi_catalogs_with_overlays`].
    /// The shared snapshot is required even when the numeric overlay
    /// revision happens to match on both sides: revision 1 may name a new
    /// document after delete/recreate, while the catalog revision is what
    /// distinguishes that generation.
    pub fn openapi_catalog_with_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<(Option<StoredOpenApiCatalog>, Option<StoredOpenApiOverlay>), ConnectionStoreError>
    {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "OpenAPI snapshot transaction", source))?;
        let catalog = load_openapi_catalogs(&transaction, &self.path, Some(id))?
            .into_iter()
            .next();
        let overlay = load_openapi_overlays(&transaction, &self.path, Some(id))?
            .into_iter()
            .next();
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "OpenAPI snapshot commit", source))?;
        Ok((catalog, overlay))
    }

    pub fn openapi_inventory_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
        let connection = self.connection_guard();
        load_openapi_inventory_catalogs(&connection, &self.path)
    }

    pub fn openapi_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiCatalog>, ConnectionStoreError> {
        let connection = self.connection_guard();
        Ok(load_openapi_catalogs(&connection, &self.path, Some(id))?
            .into_iter()
            .next())
    }

    /// The stored OpenAPI overlay document, if any (issue #360).
    pub fn openapi_overlays(&self) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
        let connection = self.connection_guard();
        load_openapi_overlays(&connection, &self.path, None)
    }

    /// The stored OpenAPI overlay document, if any (issue #360).
    pub fn openapi_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiOverlay>, ConnectionStoreError> {
        let connection = self.connection_guard();
        Ok(load_openapi_overlays(&connection, &self.path, Some(id))?
            .into_iter()
            .next())
    }

    /// Bulk-read every durable dynamic-enum LKG in one SQLite snapshot.
    pub fn enum_source_values(&self) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let values = load_enum_source_values(&connection, &self.path, None)?;
        let maximum = self
            .maximum_connections
            .saturating_mul(MAX_OPENAPI_ENUM_SOURCES);
        if values.len() > maximum {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection enum source values",
                maximum,
            });
        }
        Ok(values)
    }

    /// Read all durable dynamic-enum LKG rows for one Connection.
    pub fn enum_source_values_for_connection(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let values = load_enum_source_values(&connection, &self.path, Some(id))?;
        if values.len() > MAX_OPENAPI_ENUM_SOURCES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection enum source values",
                maximum: MAX_OPENAPI_ENUM_SOURCES,
            });
        }
        Ok(values)
    }

    /// Poll only enum-source generation metadata. The SQL limit is applied
    /// before allocation so a corrupt/oversized authority cannot force an
    /// unbounded timer-tick read.
    pub fn enum_source_revisions(
        &self,
    ) -> Result<Vec<StoredEnumSourceRevision>, ConnectionStoreError> {
        let maximum = self
            .maximum_connections
            .saturating_mul(MAX_OPENAPI_ENUM_SOURCES);
        let connection = self.connection_guard();
        load_enum_source_revisions(&connection, &self.path, maximum)
    }

    /// Fetch one full values document after a metadata poll found a change.
    pub fn enum_source_value(
        &self,
        id: &ConnectionId,
        source_id: &str,
    ) -> Result<Option<StoredEnumSourceValue>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT connection_id, source_id, overlay_revision, source_digest,
                       values_revision, connection_revision, credential_revision,
                       credential_generation_digest, values_json, resolved_at
                FROM connection_enum_source_values
                WHERE connection_id = ?1 AND source_id = ?2
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "enum source value prepare", source))?;
        statement
            .query_row(params![id.as_str(), source_id], decode_raw_enum_source_row)
            .optional()
            .map_err(|source| sqlite_error(&self.path, "enum source value read", source))?
            .map(decode_enum_source_row)
            .transpose()
    }

    /// Publish one resolved enum value set under an exact generation fence.
    ///
    /// SQLite's immediate transaction serializes the compare-and-set with an
    /// overlay mutation. The latter prunes every row for the Connection in its
    /// catalog transaction, so an old resolver can never resurrect values for
    /// a replaced source declaration.
    pub fn replace_enum_source_value(
        &self,
        write: &StoredEnumSourceValueWrite,
        expected_values_revision: u64,
    ) -> Result<StoredEnumSourceValue, ConnectionStoreError> {
        let values_json = encode_enum_source_values(write)?;
        if write.expected_values_revision != expected_values_revision {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "enum source expected values revision does not match the fetched candidate"
                        .to_owned(),
                ],
            });
        }
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "enum source value transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, &write.connection_id)?
            .ok_or_else(|| ConnectionStoreError::NotFound {
                id: write.connection_id.to_string(),
            })?
            .into_stored()?;
        let overlay_revision = transaction
            .query_row(
                "SELECT overlay_revision FROM connection_openapi_overlays WHERE connection_id = ?1",
                params![write.connection_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, "enum source overlay lookup", source))?
            .map(|revision| {
                persisted_revision(
                    &write.connection_id,
                    revision,
                    "invalid OpenAPI overlay revision",
                )
            })
            .transpose()?
            .unwrap_or_default();
        let previous = transaction
            .query_row(
                "SELECT values_revision, source_digest FROM connection_enum_source_values WHERE connection_id = ?1 AND source_id = ?2",
                params![write.connection_id.as_str(), write.source_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|source| {
                sqlite_error(&self.path, "enum source revision lookup", source)
            })?;
        let current_values_revision = previous
            .as_ref()
            .map(|(revision, _)| {
                persisted_revision(
                    &write.connection_id,
                    *revision,
                    "invalid enum source values revision",
                )
            })
            .transpose()?
            .unwrap_or_default();

        if current_values_revision != expected_values_revision
            || previous
                .as_ref()
                .is_some_and(|(_, source_digest)| source_digest != &write.source_digest)
            || overlay_revision != write.overlay_revision
            || current.revisions.connection != write.connection_revision
            || current.revisions.credential != write.credential_revision
        {
            return Err(ConnectionStoreError::EnumSourceConflict {
                id: write.connection_id.to_string(),
                source_id: write.source_id.clone(),
                current_values_revision,
            });
        }
        let values_revision = increment_revision(&write.connection_id, current_values_revision)?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_enum_source_values (
                    connection_id, source_id, overlay_revision, source_digest,
                    values_revision, connection_revision, credential_revision,
                    credential_generation_digest, values_json, resolved_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(connection_id, source_id) DO UPDATE SET
                    overlay_revision = excluded.overlay_revision,
                    source_digest = excluded.source_digest,
                    values_revision = excluded.values_revision,
                    connection_revision = excluded.connection_revision,
                    credential_revision = excluded.credential_revision,
                    credential_generation_digest = excluded.credential_generation_digest,
                    values_json = excluded.values_json,
                    resolved_at = excluded.resolved_at
                "#,
                params![
                    write.connection_id.as_str(),
                    write.source_id,
                    u64_to_i64(&write.connection_id, write.overlay_revision)?,
                    write.source_digest,
                    u64_to_i64(&write.connection_id, values_revision)?,
                    u64_to_i64(&write.connection_id, write.connection_revision)?,
                    u64_to_i64(&write.connection_id, write.credential_revision)?,
                    write.credential_generation_digest,
                    values_json,
                    write.resolved_at,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "enum source value upsert", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "enum source value commit", source))?;
        Ok(StoredEnumSourceValue {
            connection_id: write.connection_id.clone(),
            source_id: write.source_id.clone(),
            overlay_revision: write.overlay_revision,
            source_digest: write.source_digest.clone(),
            values_revision,
            connection_revision: write.connection_revision,
            credential_revision: write.credential_revision,
            credential_generation_digest: write.credential_generation_digest.clone(),
            values: write.values.clone(),
            labels: write.labels.clone(),
            resolved_at: write.resolved_at.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replace_openapi_catalog(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        self.replace_openapi_catalog_with_overlay(
            id,
            expected_connection_etag,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            spec_digest,
            entries,
            None,
            0,
            "standalone",
            &[],
        )
    }

    /// Replace the catalog and, when `overlay` is given, the overlay row in
    /// one transaction (issue #360, D1). `overlay: None` leaves the stored
    /// overlay untouched (a refresh) and records its current revision on
    /// the catalog row.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_openapi_catalog_with_overlay(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
        overlay: Option<&StoredOverlayWrite>,
        compiled_overlay_revision: u64,
        actor_user_id: &str,
        policy_protected_names: &[String],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        self.replace_openapi_catalog_with_overlay_and_enum_values(
            id,
            expected_connection_etag,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            spec_digest,
            entries,
            overlay,
            compiled_overlay_revision,
            actor_user_id,
            policy_protected_names,
            &[],
        )
    }

    /// Catalog/overlay publication including the source values resolved for
    /// that exact compile. The enum rows are committed after the overlay has
    /// pruned superseded rows and before the transaction becomes visible.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_openapi_catalog_with_overlay_and_enum_values(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
        overlay: Option<&StoredOverlayWrite>,
        compiled_overlay_revision: u64,
        actor_user_id: &str,
        policy_protected_names: &[String],
        enum_values: &[StoredEnumSourceValueWrite],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        // Standalone SQLite serializes overlay adoption with local policy
        // swaps before this call. PostgreSQL additionally rechecks these
        // names against its authoritative policy under a shared advisory
        // transaction lock.
        let _ = policy_protected_names;
        validate_openapi_spec(spec, spec_digest)?;
        if let Some(overlay) = overlay {
            validate_openapi_overlay_write(overlay)?;
        }
        let encoded_entries = validate_openapi_catalog_entries(entries)?;
        let normalized_entries = encoded_entries
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let now = utc_timestamp()?;
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "OpenAPI catalog transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;

        let previous = transaction
            .query_row(
                r#"
                SELECT spec_revision, catalog_revision, spec_digest, overlay_revision
                FROM connection_openapi_catalogs
                WHERE connection_id = ?1
                "#,
                params![id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, "OpenAPI revision lookup", source))?;
        let (
            previous_spec_revision,
            previous_catalog_revision,
            previous_digest,
            previous_overlay_revision,
        ) = if let Some((spec_revision, catalog_revision, digest, overlay_revision)) = previous {
            (
                persisted_revision(id, spec_revision, "invalid OpenAPI spec revision")?,
                persisted_revision(id, catalog_revision, "invalid OpenAPI catalog revision")?,
                Some(digest),
                revision_from_i64(id, overlay_revision, true)?,
            )
        } else {
            (0, 0, None, 0)
        };
        if let Err(error) = ensure_etag(id, expected_connection_etag, &current) {
            return if overlay.is_some() {
                Err(ConnectionStoreError::OverlayConflict {
                    id: id.to_string(),
                    current_connection_revision: current.revisions.connection,
                    current_catalog_revision: previous_catalog_revision,
                    current_overlay_revision: previous_overlay_revision,
                })
            } else {
                Err(error)
            };
        }
        if !supports_managed_openapi_catalog(&current.write) {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "OpenAPI catalogs require a managed HTTP API OpenAPI Connection".to_owned(),
                ],
            });
        }
        if expected_spec_revision != previous_spec_revision
            || expected_catalog_revision != previous_catalog_revision
        {
            return if overlay.is_some() {
                Err(ConnectionStoreError::OverlayConflict {
                    id: id.to_string(),
                    current_connection_revision: current.revisions.connection,
                    current_catalog_revision: previous_catalog_revision,
                    current_overlay_revision: previous_overlay_revision,
                })
            } else {
                Err(ConnectionStoreError::Conflict {
                    id: id.to_string(),
                    current: current.etag(),
                })
            };
        }

        let retained_catalog_entry_count: i64 = transaction
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM connection_mcp_catalog_entries)
                  + (SELECT COUNT(*) FROM connection_mcp_catalog_resources)
                  + (SELECT COUNT(*) FROM connection_mcp_catalog_resource_templates)
                  + (SELECT COUNT(*)
                     FROM connection_openapi_catalog_entries
                     WHERE connection_id != ?1)
                "#,
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "catalog retained count", source))?;
        let retained_catalog_entries =
            usize::try_from(retained_catalog_entry_count).map_err(|_| {
                ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "invalid catalog entry count",
                }
            })?;
        if retained_catalog_entries.saturating_add(entries.len()) > MAX_CATALOG_ENTRIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: MAX_CATALOG_ENTRIES,
            });
        }
        let retained_definition_bytes = openapi_definition_bytes(
            &transaction,
            &self.path,
            Some(id),
            "OpenAPI retained definition byte count",
        )?;
        let candidate_definition_bytes = encoded_entries.iter().fold(0_usize, |total, entry| {
            total.saturating_add(entry.definition_json.len())
        });
        if retained_definition_bytes
            .checked_add(candidate_definition_bytes)
            .is_none_or(|total| total > MAX_MANAGED_OPENAPI_CATALOG_BYTES)
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection OpenAPI catalog definition bytes",
                maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            });
        }

        let spec_revision = if previous_digest.as_deref() == Some(spec_digest) {
            previous_spec_revision
        } else {
            increment_revision(id, previous_spec_revision)?
        };
        let catalog_revision = increment_revision(id, previous_catalog_revision)?;

        transaction
            .execute(
                "DELETE FROM connection_dependencies WHERE connection_id = ?1 AND consumer_kind = ?2",
                params![
                    id.as_str(),
                    ConnectionDependencyKind::ManagedTool.as_str()
                ],
            )
            .map_err(|source| {
                sqlite_error(
                    &self.path,
                    "OpenAPI catalog dependency replacement delete",
                    source,
                )
            })?;
        let retained_dependencies = count_rows(
            &transaction,
            &self.path,
            "connection dependencies",
            "SELECT COUNT(*) FROM connection_dependencies",
        )?;
        if retained_dependencies.saturating_add(entries.len()) > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }

        transaction
            .execute(
                "DELETE FROM connection_openapi_catalogs WHERE connection_id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| {
                sqlite_error(&self.path, "OpenAPI catalog replacement delete", source)
            })?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_openapi_catalogs (
                    connection_id, spec_revision, catalog_revision, observed_etag,
                    spec_digest, spec, refreshed_at, entry_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, spec_revision)?,
                    u64_to_i64(id, catalog_revision)?,
                    expected_connection_etag.as_str(),
                    spec_digest,
                    spec,
                    now,
                    i64::try_from(entries.len()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "OpenAPI catalog insert", source))?;

        for (ordinal, encoded) in encoded_entries.iter().enumerate() {
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_openapi_catalog_entries (
                        connection_id, tool_name, operation_id,
                        selected_scheme_names_json, definition_json, ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        id.as_str(),
                        encoded.entry.tool_name,
                        encoded.entry.operation_id,
                        encoded.selected_scheme_names_json,
                        encoded.definition_json,
                        i64::try_from(ordinal).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "OpenAPI catalog entry insert", source)
                })?;
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        id.as_str(),
                        ConnectionDependencyKind::ManagedTool.as_str(),
                        encoded.entry.tool_name,
                        now,
                    ],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "OpenAPI catalog dependency insert", source)
                })?;
        }

        // The overlay row is written AFTER the catalog rows and inside the
        // same transaction: a failure here (a stale overlay precondition
        // included) rolls the catalog back with it, so there is no window
        // in which the catalog names an overlay revision that is not
        // stored. `openapi_overlay_is_written_in_the_catalog_transaction`
        // pins this ordering.
        let overlay_revision = write_openapi_overlay(
            &transaction,
            &self.path,
            id,
            overlay,
            compiled_overlay_revision,
            current.revisions.connection,
            previous_catalog_revision,
            actor_user_id,
            &now,
        )?;
        write_catalog_enum_source_values(
            &transaction,
            &self.path,
            id,
            &current,
            overlay_revision,
            enum_values,
        )?;
        transaction
            .execute(
                "UPDATE connection_openapi_catalogs SET overlay_revision = ?1 WHERE connection_id = ?2",
                params![u64_to_i64(id, overlay_revision)?, id.as_str()],
            )
            .map_err(|source| {
                sqlite_error(&self.path, "OpenAPI catalog overlay revision update", source)
            })?;

        transaction.commit().map_err(|source| {
            sqlite_error(&self.path, "OpenAPI catalog transaction commit", source)
        })?;

        Ok(StoredOpenApiCatalog {
            connection_id: id.clone(),
            spec_revision,
            catalog_revision,
            observed_etag: expected_connection_etag.clone(),
            spec_digest: spec_digest.to_owned(),
            spec: spec.to_owned(),
            refreshed_at: now,
            entries: normalized_entries,
            overlay_revision,
        })
    }

    pub fn append_status(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        self.append_status_with_connection(&mut connection, id, expected, update, None)
            .map(|(status, _)| status)
    }

    pub(crate) fn append_status_before(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
        deadline: Instant,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        remaining_before(deadline, "connection status persistence")?;
        let mut connection = self.try_connection_guard()?;
        refresh_status_busy_timeout(&connection, &self.path, Some(deadline))?;

        let result = self.append_status_with_connection(
            &mut connection,
            id,
            expected,
            update,
            Some(deadline),
        );
        if let Err(source) = connection.busy_timeout(DEFAULT_SQLITE_BUSY_TIMEOUT) {
            tracing::error!(
                path = %self.path.display(),
                error = %source,
                "failed to restore the connection-store SQLite busy timeout after a bounded status append"
            );
        }
        result
    }

    fn append_status_with_connection(
        &self,
        connection: &mut Connection,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
        deadline: Option<Instant>,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        if update
            .catalog_entry_count
            .is_some_and(|count| count > MAX_CATALOG_ENTRIES)
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: MAX_CATALOG_ENTRIES,
            });
        }
        let observed_at = utc_timestamp()?;
        refresh_status_busy_timeout(connection, &self.path, deadline)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| {
                status_sqlite_error(&self.path, "status transaction", source, deadline)
            })?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        let status_revision = increment_revision(id, current.revisions.status)?;
        let latency_ms = optional_u64_to_i64(update.latency_ms, "latency_ms")?;
        let catalog_age_secs = optional_u64_to_i64(update.catalog_age_secs, "catalog_age_secs")?;
        let catalog_entry_count = update
            .catalog_entry_count
            .map(|value| {
                i64::try_from(value).map_err(|_| ConnectionStoreError::LimitExceeded {
                    resource: "connection catalog entries",
                    maximum: MAX_CATALOG_ENTRIES,
                })
            })
            .transpose()?;
        let ambiguous_failure = matches!(
            update.reason,
            ConnectionStatusReason::RequestFailed
                | ConnectionStatusReason::EgressDenied
                | ConnectionStatusReason::SecretUnavailable
                | ConnectionStatusReason::InvalidResponse
                | ConnectionStatusReason::UpstreamMethodNotFound
                | ConnectionStatusReason::UpstreamError
                | ConnectionStatusReason::UpstreamTransportFailure
        );
        let last_test_at = (update.reason == ConnectionStatusReason::TestSucceeded
            || (ambiguous_failure && update.catalog_entry_count.is_none()))
        .then_some(observed_at.as_str());
        let last_refresh_at = (matches!(
            update.reason,
            ConnectionStatusReason::CatalogRefreshed | ConnectionStatusReason::CatalogStale
        ) || (ambiguous_failure && update.catalog_entry_count.is_some()))
        .then_some(observed_at.as_str());
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_status_history (
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at,
                    latency_ms, catalog_age_secs, catalog_entry_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, status_revision)?,
                    u64_to_i64(id, current.revisions.connection)?,
                    u64_to_i64(id, current.revisions.credential)?,
                    u64_to_i64(id, current.revisions.tls)?,
                    u64_to_i64(id, current.revisions.discovery)?,
                    state_as_str(update.state),
                    reason_as_str(update.reason),
                    observed_at,
                    latency_ms,
                    catalog_age_secs,
                    catalog_entry_count,
                ],
            )
            .map_err(|source| status_sqlite_error(&self.path, "status insert", source, deadline))?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_current_status (
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at,
                    latency_ms, catalog_age_secs, catalog_entry_count
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
                )
                ON CONFLICT(connection_id) DO UPDATE SET
                    status_revision = excluded.status_revision,
                    observed_connection_revision = excluded.observed_connection_revision,
                    observed_credential_revision = excluded.observed_credential_revision,
                    observed_tls_revision = excluded.observed_tls_revision,
                    observed_discovery_revision = excluded.observed_discovery_revision,
                    state = excluded.state,
                    reason = excluded.reason,
                    observed_at = excluded.observed_at,
                    latency_ms = excluded.latency_ms,
                    catalog_age_secs = excluded.catalog_age_secs,
                    catalog_entry_count = excluded.catalog_entry_count
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, status_revision)?,
                    u64_to_i64(id, current.revisions.connection)?,
                    u64_to_i64(id, current.revisions.credential)?,
                    u64_to_i64(id, current.revisions.tls)?,
                    u64_to_i64(id, current.revisions.discovery)?,
                    state_as_str(update.state),
                    reason_as_str(update.reason),
                    observed_at,
                    latency_ms,
                    catalog_age_secs,
                    catalog_entry_count,
                ],
            )
            .map_err(|source| {
                status_sqlite_error(&self.path, "current status upsert", source, deadline)
            })?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        let current_status_count = count_rows(
            &transaction,
            &self.path,
            "current connection statuses",
            "SELECT COUNT(*) FROM connection_current_status",
        )?;
        let retained_history = MAX_STATUS_HISTORY_ROWS
            .checked_sub(current_status_count)
            .ok_or(ConnectionStoreError::LimitExceeded {
                resource: "safe connection status rows",
                maximum: MAX_STATUS_HISTORY_ROWS,
            })?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        transaction
            .execute(
                r#"
                UPDATE connection_records
                SET status_revision = ?1,
                    last_test_at = COALESCE(?2, last_test_at),
                    last_refresh_at = COALESCE(?3, last_refresh_at)
                WHERE id = ?4
                "#,
                params![
                    u64_to_i64(id, status_revision)?,
                    last_test_at,
                    last_refresh_at,
                    id.as_str(),
                ],
            )
            .map_err(|source| {
                status_sqlite_error(&self.path, "status revision update", source, deadline)
            })?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        transaction
            .execute(
                r#"
                DELETE FROM connection_status_history
                WHERE sequence IN (
                    SELECT sequence
                    FROM connection_status_history
                    ORDER BY sequence DESC
                    LIMIT -1 OFFSET ?1
                )
                "#,
                params![i64::try_from(retained_history).unwrap_or(i64::MAX)],
            )
            .map_err(|source| {
                status_sqlite_error(&self.path, "status history pruning", source, deadline)
            })?;
        refresh_status_busy_timeout(&transaction, &self.path, deadline)?;
        transaction.commit().map_err(|source| {
            status_sqlite_error(&self.path, "status transaction commit", source, deadline)
        })?;

        let status = SafeConnectionStatus {
            state: update.state,
            reason: update.reason,
            observed_at: Some(observed_at),
            latency_ms: update.latency_ms,
            catalog_age_secs: update.catalog_age_secs,
            catalog_entry_count: update.catalog_entry_count,
        };
        let mut updated = current;
        updated.revisions.status = status_revision;
        Ok((status, updated))
    }

    pub fn latest_status(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<SafeConnectionStatus>, ConnectionStoreError> {
        let connection = self.connection_guard();
        connection
            .query_row(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count
                FROM connection_current_status
                WHERE connection_id = ?1
                "#,
                params![id.as_str()],
                raw_status_from_row,
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, "status query", source))?
            .map(|raw| raw.into_safe_status(id))
            .transpose()
    }

    /// The latest safe status of each listed Connection in one pass under
    /// one lock. The collection listing and the capability inventory both
    /// need every status; asking per Connection costs a lock (here) or a
    /// pool checkout and a round trip (PostgreSQL) each.
    pub fn latest_statuses(
        &self,
        ids: &[ConnectionId],
    ) -> Result<BTreeMap<ConnectionId, SafeConnectionStatus>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count
                FROM connection_current_status
                WHERE connection_id = ?1
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "status prepare", source))?;
        let mut statuses = BTreeMap::new();
        for id in ids {
            let raw = statement
                .query_row(params![id.as_str()], raw_status_from_row)
                .optional()
                .map_err(|source| sqlite_error(&self.path, "status query", source))?;
            if let Some(raw) = raw {
                statuses.insert(id.clone(), raw.into_safe_status(id)?);
            }
        }
        Ok(statuses)
    }

    pub fn status_history(
        &self,
        id: &ConnectionId,
        limit: usize,
    ) -> Result<Vec<SafeConnectionStatus>, ConnectionStoreError> {
        let limit = limit.min(MAX_STATUS_HISTORY_ROWS);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count
                FROM connection_status_history
                WHERE connection_id = ?1
                ORDER BY status_revision DESC
                LIMIT ?2
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "status history prepare", source))?;
        let rows = statement
            .query_map(
                params![id.as_str(), i64::try_from(limit).unwrap_or(i64::MAX)],
                raw_status_from_row,
            )
            .map_err(|source| sqlite_error(&self.path, "status history query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "status history read", source))?;
        rows.into_iter()
            .map(|raw| raw.into_safe_status(id))
            .collect()
    }

    /// Both status tables, verbatim, in one transaction.
    ///
    /// The copy the standalone-to-cluster import carries across (issue
    /// #241, PR 15 step 4). The other status readers on this store serve
    /// the admin API and return the safe projection; this one returns the
    /// rows, because the cluster's tables have the same columns and its
    /// startup validation compares them against the record's revisions
    /// (pg_store.rs `validate_persisted_state`). Both tables are read on
    /// one transaction so the pair cannot be observed mid-append, and each
    /// is bounded by the budget the writer prunes them against, so a
    /// source that has overflowed it is refused rather than read.
    pub fn exported_statuses(&self) -> Result<ExportedConnectionStatuses, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "status export transaction", source))?;
        let current = exported_status_rows(
            &transaction,
            &self.path,
            r#"
            SELECT connection_id, status_revision, observed_connection_revision,
                   observed_credential_revision, observed_tls_revision,
                   observed_discovery_revision, state, reason, observed_at,
                   latency_ms, catalog_age_secs, catalog_entry_count
            FROM connection_current_status
            ORDER BY connection_id ASC
            LIMIT ?1
            "#,
        )?;
        let history = exported_status_rows(
            &transaction,
            &self.path,
            r#"
            SELECT connection_id, status_revision, observed_connection_revision,
                   observed_credential_revision, observed_tls_revision,
                   observed_discovery_revision, state, reason, observed_at,
                   latency_ms, catalog_age_secs, catalog_entry_count
            FROM connection_status_history
            ORDER BY sequence ASC
            LIMIT ?1
            "#,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "status export commit", source))?;
        Ok(ExportedConnectionStatuses { current, history })
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite connection-store lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn try_connection_guard(&self) -> Result<MutexGuard<'_, Connection>, ConnectionStoreError> {
        match self.connection.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(ConnectionStoreError::Busy {
                resource: "connection SQLite store",
            }),
            Err(TryLockError::Poisoned(poisoned)) => {
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite connection-store lock poisoned; recovering for bounded status persistence"
                );
                Ok(poisoned.into_inner())
            }
        }
    }
}

impl ConnectionStore for SqliteConnectionStore {
    fn count(&self) -> Result<usize, ConnectionStoreError> {
        let connection = self.connection_guard();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM connection_records", [], |row| {
                row.get(0)
            })
            .map_err(|source| sqlite_error(&self.path, "count", source))?;
        usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<collection>".to_owned(),
            reason: "negative or oversized record count",
        })
    }

    fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "list transaction", source))?;
        let records = load_all_records(&transaction, &self.path)?;
        for record in &records {
            validate_record_bindings(&transaction, &self.path, record)?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "list commit", source))?;
        Ok(records)
    }

    fn get(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "get transaction", source))?;
        let record = load_raw_by_id(&transaction, &self.path, id)?
            .map(RawStoredConnection::into_stored)
            .transpose()?;
        if let Some(record) = record.as_ref() {
            validate_record_bindings(&transaction, &self.path, record)?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "get commit", source))?;
        Ok(record)
    }

    fn create(&self, candidate: ConnectionWrite) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let id = ConnectionId::new_managed();
        let now = utc_timestamp()?;
        let revisions = initial_revisions(&candidate);

        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "create transaction", source))?;
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM connection_records", [], |row| {
                row.get(0)
            })
            .map_err(|source| sqlite_error(&self.path, "create count", source))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= self.maximum_connections {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: self.maximum_connections,
            });
        }
        ensure_binding_capacity(&transaction, &self.path, None, 0, binding_count(&candidate))?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_records (
                    id, schema_version, source, spec_json, connection_revision,
                    credential_revision, tls_revision, discovery_revision,
                    status_revision, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
                "#,
                params![
                    id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    u64_to_i64(&id, revisions.connection)?,
                    u64_to_i64(&id, revisions.credential)?,
                    u64_to_i64(&id, revisions.tls)?,
                    u64_to_i64(&id, revisions.discovery)?,
                    u64_to_i64(&id, revisions.status)?,
                    now,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "create insert", source))?;
        replace_bindings(&transaction, &self.path, &id, &candidate, &revisions, &now)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "create commit", source))?;

        Ok(StoredConnection {
            id,
            write: candidate,
            revisions,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let now = utc_timestamp()?;

        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "replace transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        if current.write == candidate {
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, "replace no-op commit", source))?;
            return Ok(current);
        }
        if managed_catalog_kind(&current.write) != managed_catalog_kind(&candidate) {
            let managed_tool_count: i64 = transaction
                .query_row(
                    r#"
                    SELECT COUNT(*)
                    FROM connection_dependencies
                    WHERE connection_id = ?1 AND consumer_kind = ?2
                    "#,
                    params![id.as_str(), ConnectionDependencyKind::ManagedTool.as_str()],
                    |row| row.get(0),
                )
                .map_err(|source| sqlite_error(&self.path, "managed dependency count", source))?;
            if managed_tool_count > 0 {
                return Err(ConnectionStoreError::DependencyConflict {
                    id: id.to_string(),
                    count: usize::try_from(managed_tool_count).unwrap_or(usize::MAX),
                });
            }
            transaction
                .execute(
                    "DELETE FROM connection_mcp_catalogs WHERE connection_id = ?1",
                    params![id.as_str()],
                )
                .map_err(|source| {
                    sqlite_error(&self.path, "obsolete managed MCP catalog removal", source)
                })?;
            transaction
                .execute(
                    "DELETE FROM connection_openapi_catalogs WHERE connection_id = ?1",
                    params![id.as_str()],
                )
                .map_err(|source| {
                    sqlite_error(
                        &self.path,
                        "obsolete managed OpenAPI catalog removal",
                        source,
                    )
                })?;
            for table in [
                "connection_openapi_overlays",
                "connection_enum_source_values",
            ] {
                transaction
                    .execute(
                        &format!("DELETE FROM {table} WHERE connection_id = ?1"),
                        params![id.as_str()],
                    )
                    .map_err(|source| {
                        sqlite_error(&self.path, "obsolete OpenAPI overlay removal", source)
                    })?;
            }
        }

        ensure_binding_capacity(
            &transaction,
            &self.path,
            Some(id),
            binding_count(&current.write),
            binding_count(&candidate),
        )?;
        let revisions = replacement_revisions(id, &current, &candidate)?;
        transaction
            .execute(
                r#"
                UPDATE connection_records
                SET spec_json = ?1,
                    connection_revision = ?2,
                    credential_revision = ?3,
                    tls_revision = ?4,
                    discovery_revision = ?5,
                    updated_at = ?6
                WHERE id = ?7
                "#,
                params![
                    spec_json,
                    u64_to_i64(id, revisions.connection)?,
                    u64_to_i64(id, revisions.credential)?,
                    u64_to_i64(id, revisions.tls)?,
                    u64_to_i64(id, revisions.discovery)?,
                    now,
                    id.as_str(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "replace update", source))?;
        transaction
            .execute(
                "DELETE FROM connection_current_status WHERE connection_id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| {
                sqlite_error(&self.path, "stale current status invalidation", source)
            })?;
        replace_bindings(&transaction, &self.path, id, &candidate, &revisions, &now)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "replace commit", source))?;

        Ok(StoredConnection {
            id: id.clone(),
            write: candidate,
            revisions,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
    ) -> Result<(), ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "delete transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        let dependency_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM connection_dependencies WHERE connection_id = ?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency count", source))?;
        if dependency_count > 0 {
            return Err(ConnectionStoreError::DependencyConflict {
                id: id.to_string(),
                count: usize::try_from(dependency_count).unwrap_or(usize::MAX),
            });
        }
        transaction
            .execute(
                "DELETE FROM connection_records WHERE id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| sqlite_error(&self.path, "delete", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "delete commit", source))?;
        Ok(())
    }
}

fn run_migrations(
    connection: &mut Connection,
    path: &Path,
    migrations: &[Migration],
) -> Result<(), ConnectionStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, "migration transaction", source))?;
    transaction
        .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
        .map_err(|source| sqlite_error(path, "migration table", source))?;
    let mut statement = transaction
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version ASC")
        .map_err(|source| sqlite_error(path, "migration query prepare", source))?;
    let applied = statement
        .query_map([], |row| row.get::<_, u32>(0))
        .map_err(|source| sqlite_error(path, "migration query", source))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|source| sqlite_error(path, "migration read", source))?;
    drop(statement);

    let known = migrations
        .iter()
        .map(|migration| migration.version)
        .collect::<BTreeSet<_>>();
    if let Some(version) = applied.iter().find(|version| !known.contains(version)) {
        return Err(ConnectionStoreError::UnsupportedSchema { version: *version });
    }
    if migrations
        .iter()
        .enumerate()
        .any(|(index, migration)| migration.version != u32::try_from(index + 1).unwrap_or(u32::MAX))
        || applied
            .iter()
            .copied()
            .ne(1..=u32::try_from(applied.len()).unwrap_or(u32::MAX))
    {
        return Err(ConnectionStoreError::InvalidMigrationHistory);
    }

    for migration in migrations {
        if applied.contains(&migration.version) {
            continue;
        }
        transaction
            .execute_batch(migration.sql)
            .map_err(|source| sqlite_error(path, "migration apply", source))?;
        transaction
            .execute(
                "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![migration.version, utc_timestamp()?],
            )
            .map_err(|source| sqlite_error(path, "migration record", source))?;
    }
    validate_schema(&transaction, path)?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, "migration commit", source))
}

fn validate_schema(connection: &Connection, path: &Path) -> Result<(), ConnectionStoreError> {
    for query in [
        "SELECT id, schema_version, source, spec_json, connection_revision, credential_revision, tls_revision, discovery_revision, status_revision, created_at, updated_at, last_test_at, last_refresh_at FROM connection_records LIMIT 0",
        "SELECT connection_id, purpose, header_name, secret_id, binding_version, updated_at FROM connection_credential_bindings LIMIT 0",
        "SELECT connection_id, consumer_kind, consumer_id, created_at FROM connection_dependencies LIMIT 0",
        "SELECT connection_id, status_revision, observed_connection_revision, observed_credential_revision, observed_tls_revision, observed_discovery_revision, state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count FROM connection_current_status LIMIT 0",
        "SELECT sequence, connection_id, status_revision, observed_connection_revision, observed_credential_revision, observed_tls_revision, observed_discovery_revision, state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count FROM connection_status_history LIMIT 0",
        "SELECT id, schema_version, label, purpose, secret_version, algorithm, key_id, nonce, ciphertext, created_at, rotated_at, updated_at FROM connection_local_secrets LIMIT 0",
        "SELECT connection_id, catalog_revision, observed_etag, refreshed_at, entry_count, resource_count, resource_template_count FROM connection_mcp_catalogs LIMIT 0",
        "SELECT connection_id, remote_tool_name, title, description, input_schema_json, annotations_json, ordinal FROM connection_mcp_catalog_entries LIMIT 0",
        "SELECT connection_id, uri, name, title, description, mime_type, size, ordinal FROM connection_mcp_catalog_resources LIMIT 0",
        "SELECT connection_id, uri_template, name, title, description, mime_type, ordinal FROM connection_mcp_catalog_resource_templates LIMIT 0",
        "SELECT connection_id, spec_revision, catalog_revision, observed_etag, spec_digest, spec, refreshed_at, entry_count, overlay_revision FROM connection_openapi_catalogs LIMIT 0",
        "SELECT connection_id, tool_name, operation_id, selected_scheme_names_json, definition_json, ordinal FROM connection_openapi_catalog_entries LIMIT 0",
        "SELECT connection_id, schema_version, overlay_revision, overlay_json, source_reports_json, actor_user_id, updated_at FROM connection_openapi_overlays LIMIT 0",
        "SELECT connection_id, source_id, overlay_revision, source_digest, values_revision, connection_revision, credential_revision, credential_generation_digest, values_json, resolved_at FROM connection_enum_source_values LIMIT 0",
    ] {
        connection
            .prepare(query)
            .map_err(|source| sqlite_error(path, "schema validation", source))?;
    }
    let foreign_key_error: Option<String> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .map_err(|source| sqlite_error(path, "foreign-key validation", source))?;
    if foreign_key_error.is_some() {
        return Err(ConnectionStoreError::CorruptRecord {
            id: "<schema>".to_owned(),
            reason: "foreign-key validation failed",
        });
    }
    Ok(())
}

fn validate_persisted_state(
    connection: &mut Connection,
    path: &Path,
    maximum_connections: usize,
) -> Result<(), ConnectionStoreError> {
    let transaction = connection
        .transaction()
        .map_err(|source| sqlite_error(path, "startup validation transaction", source))?;
    let connection_count = count_rows(
        &transaction,
        path,
        "managed connections",
        "SELECT COUNT(*) FROM connection_records",
    )?;
    if connection_count > maximum_connections {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "managed connections",
            maximum: maximum_connections,
        });
    }
    let binding_count = count_rows(
        &transaction,
        path,
        "connection credential bindings",
        "SELECT COUNT(*) FROM connection_credential_bindings",
    )?;
    if binding_count > MAX_CREDENTIALS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        });
    }
    let local_secret_count = count_rows(
        &transaction,
        path,
        "encrypted local secrets",
        "SELECT COUNT(*) FROM connection_local_secrets",
    )?;
    if local_secret_count > MAX_CREDENTIALS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "encrypted local secrets",
            maximum: MAX_CREDENTIALS,
        });
    }
    let dependency_count = count_rows(
        &transaction,
        path,
        "connection dependencies",
        "SELECT COUNT(*) FROM connection_dependencies",
    )?;
    if dependency_count > MAX_CONNECTION_DEPENDENCIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection dependencies",
            maximum: MAX_CONNECTION_DEPENDENCIES,
        });
    }
    let catalog_entry_count = count_rows(
        &transaction,
        path,
        "connection catalog entries",
        r#"
        SELECT
            (SELECT COUNT(*) FROM connection_mcp_catalog_entries)
          + (SELECT COUNT(*) FROM connection_mcp_catalog_resources)
          + (SELECT COUNT(*) FROM connection_mcp_catalog_resource_templates)
          + (SELECT COUNT(*) FROM connection_openapi_catalog_entries)
        "#,
    )?;
    if catalog_entry_count > MAX_CATALOG_ENTRIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection catalog entries",
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    let enum_source_value_count = count_rows(
        &transaction,
        path,
        "connection enum source values",
        "SELECT COUNT(*) FROM connection_enum_source_values",
    )?;
    let maximum_enum_source_values = maximum_connections.saturating_mul(MAX_OPENAPI_ENUM_SOURCES);
    if enum_source_value_count > maximum_enum_source_values {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection enum source values",
            maximum: maximum_enum_source_values,
        });
    }
    if openapi_definition_bytes(
        &transaction,
        path,
        None,
        "OpenAPI catalog definition byte validation",
    )? > MAX_MANAGED_OPENAPI_CATALOG_BYTES
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        });
    }
    let current_status_count = count_rows(
        &transaction,
        path,
        "current connection statuses",
        "SELECT COUNT(*) FROM connection_current_status",
    )?;
    let history_count = count_rows(
        &transaction,
        path,
        "connection status history",
        "SELECT COUNT(*) FROM connection_status_history",
    )?;
    if current_status_count
        .checked_add(history_count)
        .is_none_or(|count| count > MAX_STATUS_HISTORY_ROWS)
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: MAX_STATUS_HISTORY_ROWS,
        });
    }

    ensure_no_invalid_rows(
        &transaction,
        path,
        "current status integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_current_status AS status
        JOIN connection_records AS record ON record.id = status.connection_id
        WHERE status.status_revision != record.status_revision
           OR status.observed_connection_revision != record.connection_revision
           OR status.observed_credential_revision != record.credential_revision
           OR status.observed_tls_revision != record.tls_revision
           OR status.observed_discovery_revision != record.discovery_revision
           OR status.catalog_entry_count < 0
           OR status.catalog_entry_count > 4096
        "#,
        "current connection status is stale or invalid",
    )?;
    ensure_no_invalid_rows(
        &transaction,
        path,
        "MCP catalog integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_mcp_catalogs AS catalog
        JOIN connection_records AS record ON record.id = catalog.connection_id
        WHERE catalog.entry_count != (
                SELECT COUNT(*)
                FROM connection_mcp_catalog_entries AS entry
                WHERE entry.connection_id = catalog.connection_id
              )
           OR catalog.resource_count != (
                SELECT COUNT(*)
                FROM connection_mcp_catalog_resources AS resource
                WHERE resource.connection_id = catalog.connection_id
              )
           OR catalog.resource_template_count != (
                SELECT COUNT(*)
                FROM connection_mcp_catalog_resource_templates AS template
                WHERE template.connection_id = catalog.connection_id
              )
           OR catalog.entry_count + catalog.resource_count
                + catalog.resource_template_count > 4096
           OR catalog.catalog_revision < 1
           OR catalog.entry_count < 0
           OR catalog.entry_count > 4096
           OR catalog.resource_count < 0
           OR catalog.resource_count > 4096
           OR catalog.resource_template_count < 0
           OR catalog.resource_template_count > 4096
        "#,
        "stored MCP catalog metadata is inconsistent",
    )?;
    ensure_no_invalid_rows(
        &transaction,
        path,
        "OpenAPI catalog integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_openapi_catalogs AS catalog
        JOIN connection_records AS record ON record.id = catalog.connection_id
        WHERE catalog.entry_count != (
                SELECT COUNT(*)
                FROM connection_openapi_catalog_entries AS entry
                WHERE entry.connection_id = catalog.connection_id
              )
           OR catalog.spec_revision < 1
           OR catalog.catalog_revision < 1
           OR catalog.entry_count < 0
           OR catalog.entry_count > 4096
           OR length(CAST(catalog.spec AS BLOB)) < 1
           OR length(CAST(catalog.spec AS BLOB)) > 2097152
           OR length(catalog.spec_digest) != 64
           OR catalog.spec_digest GLOB '*[^0-9a-f]*'
        "#,
        "stored OpenAPI catalog metadata is inconsistent",
    )?;
    ensure_no_invalid_rows(
        &transaction,
        path,
        "managed catalog ownership integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_mcp_catalogs AS mcp
        JOIN connection_openapi_catalogs AS openapi
          ON openapi.connection_id = mcp.connection_id
        "#,
        "a Connection owns more than one managed catalog kind",
    )?;
    ensure_no_invalid_rows(
        &transaction,
        path,
        "status history integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_status_history AS status
        JOIN connection_records AS record ON record.id = status.connection_id
        WHERE status.status_revision > record.status_revision
           OR status.observed_connection_revision > record.connection_revision
           OR status.observed_credential_revision > record.credential_revision
           OR status.observed_tls_revision > record.tls_revision
           OR status.observed_discovery_revision > record.discovery_revision
           OR status.catalog_entry_count < 0
           OR status.catalog_entry_count > 4096
        "#,
        "connection status history contains an impossible revision or count",
    )?;

    let records = load_all_records(&transaction, path)?;
    for record in &records {
        validate_record_bindings(&transaction, path, record)?;
    }
    validate_connection_activity_rows(&transaction, path)?;
    validate_safe_status_rows(
        &transaction,
        path,
        "connection_current_status",
        "current status startup validation",
    )?;
    validate_safe_status_rows(
        &transaction,
        path,
        "connection_status_history",
        "status history startup validation",
    )?;
    let mcp_catalogs = load_mcp_catalogs(&transaction, path, None)?;
    let openapi_catalogs = load_openapi_catalogs(&transaction, path, None)?;
    let openapi_overlays = load_openapi_overlays(&transaction, path, None)?;
    let enum_source_values = load_enum_source_values(&transaction, path, None)?;
    let record_by_id = records
        .iter()
        .map(|record| (record.id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    for catalog in &mcp_catalogs {
        if record_by_id
            .get(&catalog.connection_id)
            .is_none_or(|record| !supports_managed_mcp_catalog(&record.write))
        {
            return Err(ConnectionStoreError::CorruptRecord {
                id: catalog.connection_id.to_string(),
                reason: "MCP catalog owner is not a compatible managed MCP Connection",
            });
        }
    }
    for catalog in &openapi_catalogs {
        if record_by_id
            .get(&catalog.connection_id)
            .is_none_or(|record| !supports_managed_openapi_catalog(&record.write))
        {
            return Err(ConnectionStoreError::CorruptRecord {
                id: catalog.connection_id.to_string(),
                reason: "OpenAPI catalog owner is not a compatible managed OpenAPI Connection",
            });
        }
    }
    let overlay_by_id = openapi_overlays
        .iter()
        .map(|overlay| (&overlay.connection_id, overlay))
        .collect::<BTreeMap<_, _>>();
    for catalog in &openapi_catalogs {
        match overlay_by_id.get(&catalog.connection_id) {
            Some(overlay) if overlay.overlay_revision == catalog.overlay_revision => {}
            None if catalog.overlay_revision == 0 => {}
            _ => {
                return Err(ConnectionStoreError::CorruptRecord {
                    id: catalog.connection_id.to_string(),
                    reason: "OpenAPI catalog and overlay revisions do not agree",
                });
            }
        }
    }
    if openapi_overlays.iter().any(|overlay| {
        !openapi_catalogs
            .iter()
            .any(|catalog| catalog.connection_id == overlay.connection_id)
    }) {
        return Err(ConnectionStoreError::CorruptRecord {
            id: "<openapi-overlays>".to_owned(),
            reason: "OpenAPI overlay has no durable catalog",
        });
    }
    for row in &enum_source_values {
        let Some(record) = record_by_id.get(&row.connection_id) else {
            return Err(ConnectionStoreError::CorruptRecord {
                id: row.connection_id.to_string(),
                reason: "enum source value owner is missing",
            });
        };
        let overlay_matches = overlay_by_id
            .get(&row.connection_id)
            .is_some_and(|overlay| overlay.overlay_revision == row.overlay_revision);
        if !supports_managed_openapi_catalog(&record.write)
            || !overlay_matches
            || row.connection_revision > record.revisions.connection
            || row.credential_revision > record.revisions.credential
        {
            return Err(ConnectionStoreError::CorruptRecord {
                id: row.connection_id.to_string(),
                reason: "enum source values do not match their OpenAPI overlay generation",
            });
        }
    }
    validate_managed_catalog_dependencies(&transaction, path, &mcp_catalogs, &openapi_catalogs)?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, "startup validation commit", source))
}

pub(crate) struct ValidatedMcpCatalog {
    pub(crate) encoded_tool_schemas: Vec<String>,
    pub(crate) encoded_tool_annotations: Vec<Option<String>>,
    pub(crate) stored_bytes: usize,
}

pub(crate) fn validate_mcp_catalog(
    id: &ConnectionId,
    entries: &[StoredMcpCatalogEntry],
    resources: &[StoredMcpResource],
    resource_templates: &[StoredMcpResourceTemplate],
) -> Result<ValidatedMcpCatalog, ConnectionStoreError> {
    let total_count = entries
        .len()
        .saturating_add(resources.len())
        .saturating_add(resource_templates.len());
    if total_count > MAX_CATALOG_ENTRIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog entries",
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    let (encoded_tool_schemas, encoded_tool_annotations) =
        validate_mcp_catalog_entries(id, entries)?;
    validate_mcp_resources(resources)?;
    validate_mcp_resource_templates(resource_templates)?;

    let mut encoded_bytes = entries
        .iter()
        .zip(&encoded_tool_schemas)
        .zip(&encoded_tool_annotations)
        .try_fold(0_usize, |total, ((entry, encoded), annotations)| {
            total
                .checked_add(entry.remote_tool_name.len())
                .and_then(|total| total.checked_add(entry.title.as_ref().map_or(0, String::len)))
                .and_then(|total| total.checked_add(entry.description.len()))
                .and_then(|total| total.checked_add(encoded.len()))
                .and_then(|total| total.checked_add(annotations.as_ref().map_or(0, String::len)))
        })
        .ok_or(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        })?;
    for resource in resources {
        encoded_bytes = encoded_bytes
            .checked_add(
                serde_json::to_vec(resource)
                    .map_err(|source| ConnectionStoreError::Json {
                        operation: "MCP resource metadata",
                        source,
                    })?
                    .len(),
            )
            .ok_or(ConnectionStoreError::LimitExceeded {
                resource: "connection MCP catalog bytes",
                maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
            })?;
    }
    for resource_template in resource_templates {
        encoded_bytes = encoded_bytes
            .checked_add(
                serde_json::to_vec(resource_template)
                    .map_err(|source| ConnectionStoreError::Json {
                        operation: "MCP resource template metadata",
                        source,
                    })?
                    .len(),
            )
            .ok_or(ConnectionStoreError::LimitExceeded {
                resource: "connection MCP catalog bytes",
                maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
            })?;
    }
    if encoded_bytes > MAX_MANAGED_MCP_CATALOG_BYTES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        });
    }

    Ok(ValidatedMcpCatalog {
        encoded_tool_schemas,
        encoded_tool_annotations,
        stored_bytes: encoded_bytes,
    })
}

fn validate_mcp_catalog_entries(
    id: &ConnectionId,
    entries: &[StoredMcpCatalogEntry],
) -> Result<(Vec<String>, Vec<Option<String>>), ConnectionStoreError> {
    if entries.len() > MAX_CATALOG_ENTRIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog entries",
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    let mut seen = BTreeSet::new();
    let mut encoded = Vec::with_capacity(entries.len());
    let mut encoded_annotations = Vec::with_capacity(entries.len());
    let mut problems = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let remote_name_chars = entry.remote_tool_name.chars().count();
        if remote_name_chars == 0
            || remote_name_chars > MAX_MCP_TOOL_NAME_CHARS
            || entry.remote_tool_name.contains('\0')
        {
            problems.push(format!(
                "MCP catalog entry {index} remote tool name must contain 1-{MAX_MCP_TOOL_NAME_CHARS} characters without NUL"
            ));
        }
        // Every entry also becomes a managed-tool dependency key prefixed with
        // the Connection ID, and that column is bounded in bytes while the name
        // limit above counts characters. Bound the derived key here so a
        // multi-byte name is rejected as invalid input rather than aborting the
        // whole catalog transaction on a CHECK constraint.
        if validate_dependency_id(&managed_tool_dependency_id(id, &entry.remote_tool_name)).is_err()
        {
            problems.push(format!(
                "MCP catalog entry {index} remote tool name must keep its managed tool dependency key within {MAX_DEPENDENCY_FIELD_BYTES} UTF-8 bytes"
            ));
        }
        if !seen.insert(entry.remote_tool_name.as_str()) {
            problems.push(format!(
                "MCP catalog entry {index} duplicates an earlier remote tool name"
            ));
        }
        for (field, title) in [
            ("title", entry.title.as_deref()),
            (
                "annotations.title",
                entry
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.title.as_deref()),
            ),
        ] {
            if let Some(title) = title {
                let chars = title.chars().count();
                if chars == 0
                    || chars > MAX_MCP_TOOL_TITLE_CHARS
                    || title.len() > MAX_MCP_TOOL_TITLE_BYTES
                    || title.contains('\0')
                {
                    problems.push(format!(
                        "MCP catalog entry {index} {field} must contain 1-{MAX_MCP_TOOL_TITLE_CHARS} characters and at most {MAX_MCP_TOOL_TITLE_BYTES} UTF-8 bytes without NUL"
                    ));
                }
            }
        }
        let description_chars = entry.description.chars().count();
        if description_chars == 0
            || description_chars > MAX_MCP_TOOL_DESCRIPTION_CHARS
            || entry.description.contains('\0')
        {
            problems.push(format!(
                "MCP catalog entry {index} description must contain 1-{MAX_MCP_TOOL_DESCRIPTION_CHARS} characters without NUL"
            ));
        }
        match serde_json::to_string(&entry.input_schema) {
            Ok(value) if value.len() >= 2 && value.len() <= MAX_MCP_CATALOG_ENTRY_BYTES => {
                encoded.push(value);
            }
            Ok(_) => problems.push(format!(
                "MCP catalog entry {index} input schema exceeds the bounded stored size"
            )),
            Err(error) => {
                return Err(ConnectionStoreError::Json {
                    operation: "MCP catalog input schema",
                    source: error,
                });
            }
        }
        match entry.annotations.as_ref().map(serde_json::to_string) {
            Some(Ok(value)) if value.len() <= MAX_MCP_TOOL_ANNOTATIONS_BYTES => {
                encoded_annotations.push(Some(value));
            }
            Some(Ok(_)) => {
                encoded_annotations.push(None);
                problems.push(format!(
                    "MCP catalog entry {index} annotations exceed the bounded stored size"
                ));
            }
            Some(Err(error)) => {
                return Err(ConnectionStoreError::Json {
                    operation: "MCP catalog annotations",
                    source: error,
                });
            }
            None => encoded_annotations.push(None),
        }
    }
    if problems.is_empty() {
        Ok((encoded, encoded_annotations))
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

fn validate_mcp_resources(resources: &[StoredMcpResource]) -> Result<(), ConnectionStoreError> {
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    for (index, resource) in resources.iter().enumerate() {
        validate_mcp_resource_identity(
            "resource",
            index,
            "uri",
            &resource.uri,
            MAX_MCP_RESOURCE_URI_BYTES,
            MAX_MCP_RESOURCE_URI_BYTES,
            &mut problems,
        );
        validate_mcp_resource_locator("resource", index, "URI", &resource.uri, &mut problems);
        if !seen.insert(resource.uri.as_str()) {
            problems.push(format!(
                "MCP resource {index} duplicates an earlier resource URI"
            ));
        }
        validate_mcp_resource_identity(
            "resource",
            index,
            "name",
            &resource.name,
            MAX_MCP_RESOURCE_NAME_CHARS,
            MAX_MCP_RESOURCE_NAME_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource",
            index,
            "title",
            resource.title.as_deref(),
            MAX_MCP_RESOURCE_TITLE_CHARS,
            MAX_MCP_RESOURCE_TITLE_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource",
            index,
            "description",
            resource.description.as_deref(),
            MAX_MCP_RESOURCE_DESCRIPTION_CHARS,
            MAX_MCP_RESOURCE_DESCRIPTION_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource",
            index,
            "mime type",
            resource.mime_type.as_deref(),
            MAX_MCP_RESOURCE_MIME_TYPE_BYTES,
            MAX_MCP_RESOURCE_MIME_TYPE_BYTES,
            &mut problems,
        );
        if resource.size.is_some_and(|size| size > i64::MAX as u64) {
            problems.push(format!(
                "MCP resource {index} size exceeds the durable integer range"
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

pub(crate) fn validate_mcp_resource_metadata(
    resources: &[StoredMcpResource],
    resource_templates: &[StoredMcpResourceTemplate],
) -> Result<(), ConnectionStoreError> {
    validate_mcp_resources(resources)?;
    validate_mcp_resource_templates(resource_templates)
}

fn validate_mcp_resource_templates(
    resource_templates: &[StoredMcpResourceTemplate],
) -> Result<(), ConnectionStoreError> {
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    for (index, resource_template) in resource_templates.iter().enumerate() {
        validate_mcp_resource_identity(
            "resource template",
            index,
            "URI template",
            &resource_template.uri_template,
            MAX_MCP_RESOURCE_URI_BYTES,
            MAX_MCP_RESOURCE_URI_BYTES,
            &mut problems,
        );
        validate_mcp_resource_locator(
            "resource template",
            index,
            "URI template",
            &resource_template.uri_template,
            &mut problems,
        );
        if !seen.insert(resource_template.uri_template.as_str()) {
            problems.push(format!(
                "MCP resource template {index} duplicates an earlier URI template"
            ));
        }
        validate_mcp_resource_identity(
            "resource template",
            index,
            "name",
            &resource_template.name,
            MAX_MCP_RESOURCE_NAME_CHARS,
            MAX_MCP_RESOURCE_NAME_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource template",
            index,
            "title",
            resource_template.title.as_deref(),
            MAX_MCP_RESOURCE_TITLE_CHARS,
            MAX_MCP_RESOURCE_TITLE_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource template",
            index,
            "description",
            resource_template.description.as_deref(),
            MAX_MCP_RESOURCE_DESCRIPTION_CHARS,
            MAX_MCP_RESOURCE_DESCRIPTION_BYTES,
            &mut problems,
        );
        validate_optional_mcp_metadata(
            "resource template",
            index,
            "mime type",
            resource_template.mime_type.as_deref(),
            MAX_MCP_RESOURCE_MIME_TYPE_BYTES,
            MAX_MCP_RESOURCE_MIME_TYPE_BYTES,
            &mut problems,
        );
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

fn validate_mcp_resource_locator(
    kind: &str,
    index: usize,
    field: &str,
    value: &str,
    problems: &mut Vec<String>,
) {
    if value.contains(['?', '#']) || mcp_locator_has_authority_userinfo(value) {
        problems.push(format!(
            "MCP {kind} {index} {field} must not contain query, fragment, or authority userinfo components"
        ));
    }
}

fn mcp_locator_has_authority_userinfo(value: &str) -> bool {
    let authority = if let Some(authority) = value.strip_prefix("//") {
        authority
    } else {
        let Some(scheme_end) = value.find(':') else {
            return false;
        };
        if value[..scheme_end].contains(['/', '?', '#']) {
            return false;
        }
        let Some(authority) = value[scheme_end + 1..].strip_prefix("//") else {
            return false;
        };
        authority
    };
    let authority_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    authority[..authority_end].contains('@')
}

#[allow(clippy::too_many_arguments)]
fn validate_mcp_resource_identity(
    kind: &str,
    index: usize,
    field: &str,
    value: &str,
    maximum_chars: usize,
    maximum_bytes: usize,
    problems: &mut Vec<String>,
) {
    if value.is_empty()
        || value.chars().count() > maximum_chars
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        problems.push(format!(
            "MCP {kind} {index} {field} must contain 1-{maximum_chars} characters and at most {maximum_bytes} UTF-8 bytes without control characters"
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_optional_mcp_metadata(
    kind: &str,
    index: usize,
    field: &str,
    value: Option<&str>,
    maximum_chars: usize,
    maximum_bytes: usize,
    problems: &mut Vec<String>,
) {
    if let Some(value) = value {
        validate_mcp_resource_identity(
            kind,
            index,
            field,
            value,
            maximum_chars,
            maximum_bytes,
            problems,
        );
    }
}

#[derive(Clone)]
pub(crate) struct EncodedOpenApiCatalogEntry {
    pub(crate) entry: StoredOpenApiCatalogEntry,
    pub(crate) selected_scheme_names_json: String,
    pub(crate) definition_json: String,
}

pub(crate) fn validate_openapi_spec(
    spec: &str,
    spec_digest: &str,
) -> Result<(), ConnectionStoreError> {
    let mut problems = Vec::new();
    if spec.is_empty() || spec.len() > MAX_MANAGED_SPEC_BYTES {
        problems.push(format!(
            "OpenAPI spec must contain 1-{MAX_MANAGED_SPEC_BYTES} UTF-8 bytes"
        ));
    }
    if spec_digest.len() != SHA256_HEX_CHARS
        || !spec_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        problems.push("OpenAPI spec digest must be 64 lowercase hexadecimal characters".to_owned());
    } else {
        let calculated = hex::encode(Sha256::digest(spec.as_bytes()));
        if calculated != spec_digest {
            problems.push("OpenAPI spec digest does not match the exact spec bytes".to_owned());
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

/// The store-level shape check on an overlay write (issue #360): bounded,
/// NUL-free, and JSON. Semantic validation is `tools/overlay.rs::validate`;
/// this only guarantees the row satisfies its column constraints so a
/// failure here is a `Validation` error, not a rolled-back transaction.
pub(crate) fn validate_openapi_overlay_write(
    overlay: &StoredOverlayWrite,
) -> Result<(), ConnectionStoreError> {
    let mut problems = Vec::new();
    if let StoredOverlayWrite::Put {
        schema_version,
        overlay_json,
        ..
    } = overlay
    {
        if schema_version != OPENAPI_OVERLAY_SCHEMA_VERSION {
            problems.push(format!(
                "OpenAPI overlay schema_version must be {OPENAPI_OVERLAY_SCHEMA_VERSION}"
            ));
        }
        if overlay_json.len() < 2 || overlay_json.len() > MAX_OPENAPI_OVERLAY_BYTES {
            problems.push(format!(
                "OpenAPI overlay document must contain 2-{MAX_OPENAPI_OVERLAY_BYTES} bytes"
            ));
        } else if !serde_json::from_str::<Value>(overlay_json).is_ok_and(|value| value.is_object())
        {
            problems.push("OpenAPI overlay document must be a JSON object".to_owned());
        }
    }

    let source_reports_json = match overlay {
        StoredOverlayWrite::Put {
            source_reports_json,
            ..
        }
        | StoredOverlayWrite::Reports {
            source_reports_json,
            ..
        } => Some(source_reports_json.as_str()),
        StoredOverlayWrite::Delete { .. } => None,
    };
    if let Some(source_reports_json) = source_reports_json {
        if source_reports_json.len() < 2
            || source_reports_json.len() > MAX_OPENAPI_SOURCE_REPORTS_BYTES
        {
            problems.push(format!(
                "OpenAPI source reports must contain 2-{MAX_OPENAPI_SOURCE_REPORTS_BYTES} bytes"
            ));
        } else if decode_openapi_source_reports(source_reports_json).is_err() {
            problems.push(
                "OpenAPI source reports must be a canonical supported report snapshot".to_owned(),
            );
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

/// Decode and strictly validate the safe report snapshot stored beside an
/// overlay. Unknown fields or versions are not projected as empty: callers
/// fail closed so a newer resolver cannot be silently misrepresented.
pub(crate) fn decode_openapi_source_reports(
    encoded: &str,
) -> Result<StoredOpenApiSourceReports, ()> {
    let reports = serde_json::from_str::<StoredOpenApiSourceReports>(encoded).map_err(|_| ())?;
    if reports.schema_version != OPENAPI_SOURCE_REPORTS_SCHEMA_VERSION
        || reports.sources.len() > MAX_OPENAPI_SOURCE_REPORTS
    {
        return Err(());
    }
    let mut seen = BTreeSet::new();
    for report in &reports.sources {
        if !valid_overlay_local_name(&report.id)
            || !seen.insert(report.id.as_str())
            || report.state.is_empty()
            || report.state.chars().count() > 64
            || report.state.chars().any(char::is_control)
            || report.item_count > MAX_OPENAPI_SOURCE_ITEMS
            || report
                .resolved_at
                .as_deref()
                .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
        {
            return Err(());
        }
    }
    if serde_json::to_string(&reports).map_err(|_| ())? != encoded {
        return Err(());
    }
    Ok(reports)
}

pub(crate) fn valid_overlay_local_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 64
}

fn write_catalog_enum_source_values(
    transaction: &Transaction<'_>,
    path: &Path,
    id: &ConnectionId,
    current: &StoredConnection,
    overlay_revision: u64,
    writes: &[StoredEnumSourceValueWrite],
) -> Result<(), ConnectionStoreError> {
    if writes.len() > MAX_OPENAPI_ENUM_SOURCES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection enum sources",
            maximum: MAX_OPENAPI_ENUM_SOURCES,
        });
    }
    let mut source_ids = BTreeSet::new();
    for write in writes {
        if &write.connection_id != id
            || write.overlay_revision != overlay_revision
            || write.connection_revision != current.revisions.connection
            || write.credential_revision != current.revisions.credential
            || !source_ids.insert(write.source_id.as_str())
        {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "resolved enum source values do not match the catalog generation".to_owned(),
                ],
            });
        }
        let values_json = encode_enum_source_values(write)?;
        let previous = transaction
            .query_row(
                "SELECT values_revision, source_digest FROM connection_enum_source_values WHERE connection_id = ?1 AND source_id = ?2",
                params![id.as_str(), write.source_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|source| {
                sqlite_error(path, "catalog enum source revision lookup", source)
            })?;
        if previous
            .as_ref()
            .is_some_and(|(_, source_digest)| source_digest != &write.source_digest)
        {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "resolved enum source values do not match the stored source generation"
                        .to_owned(),
                ],
            });
        }
        let current_values_revision = previous
            .map(|(revision, _)| {
                persisted_revision(id, revision, "invalid enum source values revision")
            })
            .transpose()?
            .unwrap_or_default();
        if current_values_revision != write.expected_values_revision {
            return Err(ConnectionStoreError::EnumSourceConflict {
                id: id.to_string(),
                source_id: write.source_id.clone(),
                current_values_revision,
            });
        }
        let values_revision = increment_revision(id, current_values_revision)?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_enum_source_values (
                    connection_id, source_id, overlay_revision, source_digest,
                    values_revision, connection_revision, credential_revision,
                    credential_generation_digest, values_json, resolved_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(connection_id, source_id) DO UPDATE SET
                    overlay_revision = excluded.overlay_revision,
                    source_digest = excluded.source_digest,
                    values_revision = excluded.values_revision,
                    connection_revision = excluded.connection_revision,
                    credential_revision = excluded.credential_revision,
                    credential_generation_digest = excluded.credential_generation_digest,
                    values_json = excluded.values_json,
                    resolved_at = excluded.resolved_at
                "#,
                params![
                    id.as_str(),
                    write.source_id,
                    u64_to_i64(id, write.overlay_revision)?,
                    write.source_digest,
                    u64_to_i64(id, values_revision)?,
                    u64_to_i64(id, write.connection_revision)?,
                    u64_to_i64(id, write.credential_revision)?,
                    write.credential_generation_digest,
                    values_json,
                    write.resolved_at,
                ],
            )
            .map_err(|source| sqlite_error(path, "catalog enum source upsert", source))?;
    }
    Ok(())
}

/// Read the stored overlay revision, then apply the requested write inside
/// the caller's transaction. Returns the overlay revision the catalog row
/// records: unchanged for `None`, `0` after a delete, the new revision
/// after a store.
#[allow(clippy::too_many_arguments)] // One argument per independently fenced catalog/overlay axis.
fn write_openapi_overlay(
    transaction: &Transaction<'_>,
    path: &Path,
    id: &ConnectionId,
    overlay: Option<&StoredOverlayWrite>,
    compiled_overlay_revision: u64,
    current_connection_revision: u64,
    current_catalog_revision: u64,
    actor_user_id: &str,
    now: &str,
) -> Result<u64, ConnectionStoreError> {
    let current = transaction
        .query_row(
            "SELECT overlay_revision FROM connection_openapi_overlays WHERE connection_id = ?1",
            params![id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, "OpenAPI overlay revision lookup", source))?;
    let current_revision = match current {
        Some(revision) => persisted_revision(id, revision, "invalid OpenAPI overlay revision")?,
        None => 0,
    };
    let Some(write) = overlay else {
        if compiled_overlay_revision != current_revision {
            return Err(ConnectionStoreError::OverlayConflict {
                id: id.to_string(),
                current_connection_revision,
                current_catalog_revision,
                current_overlay_revision: current_revision,
            });
        }
        return Ok(current_revision);
    };
    if write.expected_overlay_revision() != current_revision {
        return Err(ConnectionStoreError::OverlayConflict {
            id: id.to_string(),
            current_connection_revision,
            current_catalog_revision,
            current_overlay_revision: current_revision,
        });
    }
    let expected_compiled_revision = match write {
        StoredOverlayWrite::Put { .. } => increment_revision(id, current_revision)?,
        StoredOverlayWrite::Delete { .. } => 0,
        StoredOverlayWrite::Reports { .. } => current_revision,
    };
    if compiled_overlay_revision != expected_compiled_revision {
        return Err(ConnectionStoreError::Validation {
            problems: vec![
                "compiled OpenAPI overlay revision does not match the resulting overlay".to_owned(),
            ],
        });
    }
    match write {
        StoredOverlayWrite::Put {
            schema_version,
            overlay_json,
            source_reports_json,
            ..
        } => {
            transaction
                .execute(
                    "DELETE FROM connection_enum_source_values WHERE connection_id = ?1",
                    params![id.as_str()],
                )
                .map_err(|source| sqlite_error(path, "OpenAPI enum source prune", source))?;
            let next_revision = expected_compiled_revision;
            transaction
                .execute(
                    r#"
                    INSERT INTO connection_openapi_overlays (
                        connection_id, schema_version, overlay_revision, overlay_json,
                        source_reports_json, actor_user_id, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT (connection_id) DO UPDATE SET
                        schema_version = excluded.schema_version,
                        overlay_revision = excluded.overlay_revision,
                        overlay_json = excluded.overlay_json,
                        source_reports_json = excluded.source_reports_json,
                        actor_user_id = excluded.actor_user_id,
                        updated_at = excluded.updated_at
                    "#,
                    params![
                        id.as_str(),
                        schema_version,
                        u64_to_i64(id, next_revision)?,
                        overlay_json,
                        source_reports_json,
                        actor_user_id,
                        now,
                    ],
                )
                .map_err(|source| sqlite_error(path, "OpenAPI overlay upsert", source))?;
            Ok(next_revision)
        }
        StoredOverlayWrite::Delete { .. } => {
            transaction
                .execute(
                    "DELETE FROM connection_enum_source_values WHERE connection_id = ?1",
                    params![id.as_str()],
                )
                .map_err(|source| sqlite_error(path, "OpenAPI enum source prune", source))?;
            transaction
                .execute(
                    "DELETE FROM connection_openapi_overlays WHERE connection_id = ?1",
                    params![id.as_str()],
                )
                .map_err(|source| sqlite_error(path, "OpenAPI overlay delete", source))?;
            Ok(0)
        }
        StoredOverlayWrite::Reports {
            source_reports_json,
            ..
        } => {
            if current_revision == 0 {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "OpenAPI source reports cannot be stored without an overlay".to_owned()
                    ],
                });
            }
            let changed = transaction
                .execute(
                    r#"
                    UPDATE connection_openapi_overlays
                    SET source_reports_json = ?1, actor_user_id = ?2, updated_at = ?3
                    WHERE connection_id = ?4
                    "#,
                    params![source_reports_json, actor_user_id, now, id.as_str()],
                )
                .map_err(|source| sqlite_error(path, "OpenAPI source report update", source))?;
            if changed != 1 {
                return Err(ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "OpenAPI overlay disappeared during source report update",
                });
            }
            Ok(current_revision)
        }
    }
}

fn load_openapi_overlays(
    connection: &Connection,
    path: &Path,
    requested_id: Option<&ConnectionId>,
) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
    let query = if requested_id.is_some() {
        r#"
            SELECT schema_version, overlay_revision, overlay_json,
                   source_reports_json, updated_at, connection_id
            FROM connection_openapi_overlays
            WHERE connection_id = ?1
            ORDER BY connection_id
        "#
    } else {
        r#"
            SELECT schema_version, overlay_revision, overlay_json,
                   source_reports_json, updated_at, connection_id
            FROM connection_openapi_overlays
            ORDER BY connection_id
        "#
    };
    let mut statement = connection
        .prepare(query)
        .map_err(|source| sqlite_error(path, "OpenAPI overlay query prepare", source))?;
    let map_row = |row: &Row<'_>| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    };
    let rows = if let Some(id) = requested_id {
        statement.query_map(params![id.as_str()], map_row)
    } else {
        statement.query_map([], map_row)
    }
    .map_err(|source| sqlite_error(path, "OpenAPI overlay query", source))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|source| sqlite_error(path, "OpenAPI overlay read", source))?;

    rows.into_iter()
        .map(
            |(
                schema_version,
                overlay_revision,
                overlay_json,
                source_reports_json,
                updated_at,
                raw_id,
            )| {
                let id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id,
                        reason: "invalid OpenAPI overlay connection ID",
                    }
                })?;
                let overlay_revision =
                    persisted_revision(&id, overlay_revision, "invalid OpenAPI overlay revision")?;
                if overlay_revision == 0 {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: id.to_string(),
                        reason: "invalid OpenAPI overlay revision",
                    });
                }
                validate_openapi_overlay_write(&StoredOverlayWrite::Put {
                    schema_version: schema_version.clone(),
                    overlay_json: overlay_json.clone(),
                    source_reports_json: source_reports_json.clone().unwrap_or_else(|| {
                        StoredOpenApiSourceReports::empty()
                            .canonical_json()
                            .expect("the fixed empty source report snapshot serializes")
                    }),
                    expected_overlay_revision: 0,
                })
                .map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "stored OpenAPI overlay fails validation",
                })?;
                Ok(StoredOpenApiOverlay {
                    connection_id: id,
                    schema_version,
                    overlay_revision,
                    overlay_json,
                    source_reports_json,
                    updated_at,
                })
            },
        )
        .collect()
}

fn load_enum_source_revisions(
    connection: &Connection,
    path: &Path,
    maximum: usize,
) -> Result<Vec<StoredEnumSourceRevision>, ConnectionStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT connection_id, source_id, overlay_revision, source_digest,
                   values_revision, connection_revision, credential_revision,
                   credential_generation_digest
            FROM connection_enum_source_values
            ORDER BY connection_id, source_id
            LIMIT ?1
            "#,
        )
        .map_err(|source| sqlite_error(path, "enum source revisions prepare", source))?;
    let limit = i64::try_from(maximum.saturating_add(1)).unwrap_or(i64::MAX);
    let rows = statement
        .query_map(params![limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "enum source revisions query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "enum source revisions read", source))?;
    if rows.len() > maximum {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection enum source values",
            maximum,
        });
    }
    rows.into_iter()
        .map(
            |(
                raw_id,
                source_id,
                overlay_revision,
                source_digest,
                values_revision,
                connection_revision,
                credential_revision,
                credential_generation_digest,
            )| {
                let connection_id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id,
                        reason: "invalid enum source connection ID",
                    }
                })?;
                if !valid_overlay_local_name(&source_id)
                    || !valid_sha256_hex(&source_digest)
                    || credential_generation_digest
                        .as_deref()
                        .is_some_and(|digest| !valid_sha256_hex(digest))
                {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid enum source provenance",
                    });
                }
                Ok(StoredEnumSourceRevision {
                    connection_id: connection_id.clone(),
                    source_id,
                    overlay_revision: persisted_revision(
                        &connection_id,
                        overlay_revision,
                        "invalid enum source overlay revision",
                    )?,
                    source_digest,
                    values_revision: persisted_revision(
                        &connection_id,
                        values_revision,
                        "invalid enum source values revision",
                    )?,
                    connection_revision: persisted_revision(
                        &connection_id,
                        connection_revision,
                        "invalid enum source connection revision",
                    )?,
                    credential_revision: revision_from_i64(
                        &connection_id,
                        credential_revision,
                        true,
                    )?,
                    credential_generation_digest,
                })
            },
        )
        .collect()
}

fn load_enum_source_values(
    connection: &Connection,
    path: &Path,
    requested_id: Option<&ConnectionId>,
) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
    let query = if requested_id.is_some() {
        r#"
            SELECT connection_id, source_id, overlay_revision, source_digest,
                   values_revision, connection_revision, credential_revision,
                   credential_generation_digest, values_json, resolved_at
            FROM connection_enum_source_values
            WHERE connection_id = ?1
            ORDER BY connection_id, source_id
        "#
    } else {
        r#"
            SELECT connection_id, source_id, overlay_revision, source_digest,
                   values_revision, connection_revision, credential_revision,
                   credential_generation_digest, values_json, resolved_at
            FROM connection_enum_source_values
            ORDER BY connection_id, source_id
        "#
    };
    let mut statement = connection
        .prepare(query)
        .map_err(|source| sqlite_error(path, "enum source values prepare", source))?;
    let rows = if let Some(id) = requested_id {
        statement.query_map(params![id.as_str()], decode_raw_enum_source_row)
    } else {
        statement.query_map([], decode_raw_enum_source_row)
    }
    .map_err(|source| sqlite_error(path, "enum source values query", source))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|source| sqlite_error(path, "enum source values read", source))?;
    rows.into_iter().map(decode_enum_source_row).collect()
}

type RawEnumSourceRow = (
    String,
    String,
    i64,
    String,
    i64,
    i64,
    i64,
    Option<String>,
    String,
    String,
);

fn decode_raw_enum_source_row(row: &Row<'_>) -> rusqlite::Result<RawEnumSourceRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn decode_enum_source_row(
    raw: RawEnumSourceRow,
) -> Result<StoredEnumSourceValue, ConnectionStoreError> {
    let (
        raw_id,
        source_id,
        overlay_revision,
        source_digest,
        values_revision,
        connection_revision,
        credential_revision,
        credential_generation_digest,
        values_json,
        resolved_at,
    ) = raw;
    let connection_id =
        ConnectionId::parse(raw_id.clone()).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: raw_id.clone(),
            reason: "invalid enum source connection ID",
        })?;
    if !valid_overlay_local_name(&source_id) {
        return Err(ConnectionStoreError::CorruptRecord {
            id: raw_id,
            reason: "invalid enum source ID",
        });
    }
    let overlay_revision = persisted_revision(
        &connection_id,
        overlay_revision,
        "invalid enum source overlay revision",
    )?;
    let values_revision = persisted_revision(
        &connection_id,
        values_revision,
        "invalid enum source values revision",
    )?;
    let connection_revision = persisted_revision(
        &connection_id,
        connection_revision,
        "invalid enum source connection revision",
    )?;
    let credential_revision = revision_from_i64(&connection_id, credential_revision, true)?;
    if !valid_sha256_hex(&source_digest)
        || credential_generation_digest
            .as_deref()
            .is_some_and(|digest| !valid_sha256_hex(digest))
        || !valid_enum_source_timestamp(&resolved_at)
    {
        return Err(ConnectionStoreError::CorruptRecord {
            id: connection_id.to_string(),
            reason: "invalid enum source provenance",
        });
    }
    let document = decode_enum_source_values(&values_json).map_err(|_| {
        ConnectionStoreError::CorruptRecord {
            id: connection_id.to_string(),
            reason: "invalid enum source values",
        }
    })?;
    Ok(StoredEnumSourceValue {
        connection_id,
        source_id,
        overlay_revision,
        source_digest,
        values_revision,
        connection_revision,
        credential_revision,
        credential_generation_digest,
        values: document.values,
        labels: document.labels,
        resolved_at,
    })
}

pub(crate) fn encode_enum_source_values(
    write: &StoredEnumSourceValueWrite,
) -> Result<String, ConnectionStoreError> {
    let mut problems = Vec::new();
    if !valid_overlay_local_name(&write.source_id) {
        problems.push("enum source ID must be a valid overlay local name".to_owned());
    }
    if write.overlay_revision == 0 {
        problems.push("enum source overlay revision must be positive".to_owned());
    }
    if write.connection_revision == 0 {
        problems.push("enum source connection revision must be positive".to_owned());
    }
    if !valid_sha256_hex(&write.source_digest) {
        problems.push("enum source digest must be 64 lowercase hexadecimal characters".to_owned());
    }
    if write
        .credential_generation_digest
        .as_deref()
        .is_some_and(|digest| !valid_sha256_hex(digest))
    {
        problems.push(
            "enum source credential generation digest must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    if !valid_enum_source_timestamp(&write.resolved_at) {
        problems.push("enum source resolved_at must be an RFC 3339 timestamp".to_owned());
    }
    let document = StoredEnumSourceValuesDocument {
        version: OPENAPI_ENUM_SOURCE_VALUES_VERSION,
        values: write.values.clone(),
        labels: write.labels.clone(),
    };
    validate_enum_source_values_document(&document, &mut problems);
    let encoded =
        serde_json::to_string(&document).map_err(|source| ConnectionStoreError::Json {
            operation: "enum source values",
            source,
        })?;
    if encoded.len() < 2 || encoded.len() > MAX_OPENAPI_ENUM_SOURCE_VALUES_BYTES {
        problems.push(format!(
            "enum source values must contain 2-{MAX_OPENAPI_ENUM_SOURCE_VALUES_BYTES} bytes"
        ));
    }
    if problems.is_empty() {
        Ok(encoded)
    } else {
        Err(ConnectionStoreError::Validation { problems })
    }
}

pub(crate) fn decode_enum_source_values(
    encoded: &str,
) -> Result<StoredEnumSourceValuesDocument, ()> {
    if encoded.len() < 2 || encoded.len() > MAX_OPENAPI_ENUM_SOURCE_VALUES_BYTES {
        return Err(());
    }
    let document =
        serde_json::from_str::<StoredEnumSourceValuesDocument>(encoded).map_err(|_| ())?;
    let mut problems = Vec::new();
    validate_enum_source_values_document(&document, &mut problems);
    if !problems.is_empty() || serde_json::to_string(&document).map_err(|_| ())? != encoded {
        return Err(());
    }
    Ok(document)
}

/// Validate the exact canonical document that a resolver would persist. This
/// keeps the 256 KiB durable LKG limit at the fetch boundary instead of
/// allowing a successful resolve that cannot be published.
pub(crate) fn validate_enum_source_values_payload(
    values: &[Value],
    labels: Option<&[String]>,
) -> Result<(), ()> {
    let document = StoredEnumSourceValuesDocument {
        version: OPENAPI_ENUM_SOURCE_VALUES_VERSION,
        values: values.to_vec(),
        labels: labels.map(<[String]>::to_vec),
    };
    let mut problems = Vec::new();
    validate_enum_source_values_document(&document, &mut problems);
    let encoded = serde_json::to_string(&document).map_err(|_| ())?;
    if problems.is_empty()
        && encoded.len() >= 2
        && encoded.len() <= MAX_OPENAPI_ENUM_SOURCE_VALUES_BYTES
    {
        Ok(())
    } else {
        Err(())
    }
}

/// Reject line-breaking and direction/format control characters that can make
/// generated schema descriptions span lines or display different text than
/// the stored value.
pub(crate) fn enum_source_text_is_printable(value: &str) -> bool {
    value.chars().all(|character| {
        !character.is_control()
            && !matches!(
                character,
                '\u{00ad}'
                    | '\u{061c}'
                    | '\u{06dd}'
                    | '\u{070f}'
                    | '\u{08e2}'
                    | '\u{180e}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{2060}'
                    | '\u{feff}'
                    | '\u{110bd}'
                    | '\u{110cd}'
                    | '\u{e0001}'
            )
            && !matches!(
                character as u32,
                0x0600..=0x0605
                    | 0x0890..=0x0891
                    | 0x200b..=0x200f
                    | 0x202a..=0x202e
                    | 0x2061..=0x2064
                    | 0x2066..=0x206f
                    | 0xfff9..=0xfffb
                    | 0x13430..=0x13455
                    | 0x1bca0..=0x1bca3
                    | 0x1d173..=0x1d17a
                    | 0xe0020..=0xe007f
            )
    })
}

fn validate_enum_source_values_document(
    document: &StoredEnumSourceValuesDocument,
    problems: &mut Vec<String>,
) {
    if document.version != OPENAPI_ENUM_SOURCE_VALUES_VERSION {
        problems.push(format!(
            "enum source values version must be {OPENAPI_ENUM_SOURCE_VALUES_VERSION}"
        ));
    }
    if document.values.len() > usize::try_from(MAX_OPENAPI_SOURCE_ITEMS).unwrap_or(usize::MAX) {
        problems.push(format!(
            "enum source values must contain at most {MAX_OPENAPI_SOURCE_ITEMS} items"
        ));
    }
    if document
        .labels
        .as_ref()
        .is_some_and(|labels| labels.len() != document.values.len())
    {
        problems.push("enum source labels must align one-for-one with values".to_owned());
    }
    let mut seen = BTreeSet::new();
    for value in &document.values {
        let valid = match value {
            Value::String(value) => {
                !value.is_empty()
                    && value.len() <= 1_024
                    && enum_source_text_is_printable(value)
                    && !suspicious_enum_source_text(value)
            }
            Value::Bool(_) => true,
            Value::Null | Value::Number(_) | Value::Array(_) | Value::Object(_) => false,
        };
        let identity = serde_json::to_string(value).unwrap_or_default();
        if !valid || !seen.insert(identity) {
            problems
                .push("enum source values must be unique printable strings or booleans".to_owned());
            break;
        }
    }
    if document.labels.as_ref().is_some_and(|labels| {
        labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 64
                || !enum_source_text_is_printable(label)
                || suspicious_enum_source_text(label)
        })
    }) {
        problems.push(
            "enum source labels must be printable single-line strings of at most 64 bytes"
                .to_owned(),
        );
    }
}

fn suspicious_enum_source_text(value: &str) -> bool {
    let mut token = String::new();
    for character in value.chars() {
        if enum_source_token_character(character) {
            token.push(character);
        } else {
            if suspicious_enum_source_token(&token) {
                return true;
            }
            token.clear();
        }
    }
    suspicious_enum_source_token(&token)
}

fn enum_source_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '.' | '-' | '_' | ':' | '/' | '?' | '&' | '=' | '%' | '+' | '@'
        )
}

fn suspicious_enum_source_token(token: &str) -> bool {
    let token = token
        .trim_matches(|character: char| {
            matches!(character, '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']')
        })
        .to_ascii_lowercase();
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("sk_")
        || token.starts_with("pk_")
        || token.starts_with("ghp_")
        || token.starts_with("github_pat_")
        || token.starts_with("xoxb-")
        || token.starts_with("xoxp-")
        || token.contains("secret=")
        || token.contains("token=")
        || token.contains("password=")
        || token.contains("api_key=")
        || token.contains("apikey=")
        || token.contains(".internal")
        || token.contains("internal.")
        || token.ends_with(".local")
}

pub(crate) fn valid_enum_source_timestamp(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok_and(|timestamp| {
        timestamp
            .format(&Rfc3339)
            .is_ok_and(|canonical| canonical == value)
            && timestamp <= OffsetDateTime::now_utc() + time::Duration::minutes(5)
    })
}

pub(crate) fn valid_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_openapi_catalog_entries(
    entries: &[StoredOpenApiCatalogEntry],
) -> Result<Vec<EncodedOpenApiCatalogEntry>, ConnectionStoreError> {
    if entries.len() > MAX_CATALOG_ENTRIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog entries",
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    let mut seen = BTreeSet::new();
    let mut encoded = Vec::with_capacity(entries.len());
    let mut problems = Vec::new();
    let mut aggregate_definition_bytes = 0_usize;
    for (index, entry) in entries.iter().enumerate() {
        let name_chars = entry.tool_name.chars().count();
        if name_chars == 0
            || name_chars > MAX_OPENAPI_TOOL_NAME_CHARS
            || entry.tool_name.len() > MAX_OPENAPI_TOOL_NAME_CHARS
            || entry.tool_name.contains('\0')
        {
            problems.push(format!(
                "OpenAPI catalog entry {index} tool name must contain 1-{MAX_OPENAPI_TOOL_NAME_CHARS} UTF-8 bytes without NUL"
            ));
        }
        if !seen.insert(entry.tool_name.as_str()) {
            problems.push(format!(
                "OpenAPI catalog entry {index} duplicates an earlier tool name"
            ));
        }
        if entry.operation_id.as_ref().is_some_and(|operation_id| {
            let chars = operation_id.chars().count();
            chars == 0 || chars > MAX_OPENAPI_OPERATION_ID_CHARS || operation_id.contains('\0')
        }) {
            problems.push(format!(
                "OpenAPI catalog entry {index} operation ID must contain 1-{MAX_OPENAPI_OPERATION_ID_CHARS} characters without NUL when present"
            ));
        }
        if entry.selected_scheme_names.len() > MAX_OPENAPI_SECURITY_SCHEMES {
            problems.push(format!(
                "OpenAPI catalog entry {index} selects more than {MAX_OPENAPI_SECURITY_SCHEMES} security schemes"
            ));
        }
        let selected_scheme_names = entry
            .selected_scheme_names
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for scheme_name in &selected_scheme_names {
            let chars = scheme_name.chars().count();
            if chars == 0
                || chars > MAX_OPENAPI_SECURITY_SCHEME_NAME_CHARS
                || scheme_name.contains('\0')
            {
                problems.push(format!(
                    "OpenAPI catalog entry {index} security scheme names must contain 1-{MAX_OPENAPI_SECURITY_SCHEME_NAME_CHARS} characters without NUL"
                ));
            }
        }
        let selected_scheme_names_json =
            serde_json::to_string(&selected_scheme_names).map_err(|source| {
                ConnectionStoreError::Json {
                    operation: "OpenAPI selected security schemes",
                    source,
                }
            })?;
        if selected_scheme_names_json.len() > MAX_OPENAPI_SECURITY_SCHEMES_JSON_BYTES {
            problems.push(format!(
                "OpenAPI catalog entry {index} selected security schemes exceed the bounded stored size"
            ));
        }

        let definition_json = serde_json::to_string(&entry.definition).map_err(|source| {
            ConnectionStoreError::Json {
                operation: "OpenAPI catalog tool definition",
                source,
            }
        })?;
        if definition_json.len() < 2 || definition_json.len() > MAX_OPENAPI_CATALOG_ENTRY_BYTES {
            problems.push(format!(
                "OpenAPI catalog entry {index} tool definition exceeds the bounded stored size"
            ));
        }
        aggregate_definition_bytes =
            aggregate_definition_bytes.saturating_add(definition_json.len());
        match serde_json::from_value::<ToolDefinition>(entry.definition.clone()) {
            Ok(definition) if definition.name == entry.tool_name => {}
            Ok(_) => problems.push(format!(
                "OpenAPI catalog entry {index} tool name does not match its definition"
            )),
            Err(error) => problems.push(format!(
                "OpenAPI catalog entry {index} does not contain a complete ToolDefinition: {error}"
            )),
        }

        let mut normalized = entry.clone();
        normalized.selected_scheme_names = selected_scheme_names;
        encoded.push(EncodedOpenApiCatalogEntry {
            entry: normalized,
            selected_scheme_names_json,
            definition_json,
        });
    }
    if !problems.is_empty() {
        return Err(ConnectionStoreError::Validation { problems });
    }
    if aggregate_definition_bytes > MAX_MANAGED_OPENAPI_CATALOG_BYTES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        });
    }
    Ok(encoded)
}

fn load_mcp_catalogs(
    connection: &Connection,
    path: &Path,
    requested_id: Option<&ConnectionId>,
) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
    if mcp_catalog_bytes(connection, path, None, "MCP catalog byte load validation")?
        > MAX_MANAGED_MCP_CATALOG_BYTES
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        });
    }
    let query = if requested_id.is_some() {
        r#"
        SELECT connection_id, catalog_revision, observed_etag, refreshed_at, entry_count,
               resource_count, resource_template_count
        FROM connection_mcp_catalogs
        WHERE connection_id = ?1
        ORDER BY connection_id ASC
        "#
    } else {
        r#"
        SELECT connection_id, catalog_revision, observed_etag, refreshed_at, entry_count,
               resource_count, resource_template_count
        FROM connection_mcp_catalogs
        ORDER BY connection_id ASC
        "#
    };
    let mut statement = connection
        .prepare(query)
        .map_err(|source| sqlite_error(path, "MCP catalog query prepare", source))?;
    let raw = if let Some(id) = requested_id {
        statement
            .query_map(params![id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|source| sqlite_error(path, "MCP catalog query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(path, "MCP catalog read", source))?
    } else {
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|source| sqlite_error(path, "MCP catalog query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(path, "MCP catalog read", source))?
    };
    drop(statement);

    raw.into_iter()
        .map(
            |(
                raw_id,
                raw_revision,
                observed_etag,
                refreshed_at,
                raw_entry_count,
                raw_resource_count,
                raw_resource_template_count,
            )| {
                let connection_id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id.clone(),
                        reason: "invalid MCP catalog connection ID",
                    }
                })?;
                let catalog_revision = u64::try_from(raw_revision).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id.clone(),
                        reason: "invalid MCP catalog revision",
                    }
                })?;
                if catalog_revision == 0 {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: raw_id,
                        reason: "invalid MCP catalog revision",
                    });
                }
                let expected_entry_count = usize::try_from(raw_entry_count).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid MCP catalog entry count",
                    }
                })?;
                if expected_entry_count > MAX_CATALOG_ENTRIES {
                    return Err(ConnectionStoreError::LimitExceeded {
                        resource: "connection MCP catalog entries",
                        maximum: MAX_CATALOG_ENTRIES,
                    });
                }
                let expected_resource_count =
                    usize::try_from(raw_resource_count).map_err(|_| {
                        ConnectionStoreError::CorruptRecord {
                            id: connection_id.to_string(),
                            reason: "invalid MCP resource count",
                        }
                    })?;
                let expected_resource_template_count = usize::try_from(raw_resource_template_count)
                    .map_err(|_| ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid MCP resource template count",
                    })?;
                if expected_entry_count
                    .saturating_add(expected_resource_count)
                    .saturating_add(expected_resource_template_count)
                    > MAX_CATALOG_ENTRIES
                {
                    return Err(ConnectionStoreError::LimitExceeded {
                        resource: "connection MCP catalog entries",
                        maximum: MAX_CATALOG_ENTRIES,
                    });
                }

                let mut entry_statement = connection
                    .prepare(
                        r#"
                        SELECT remote_tool_name, title, description, input_schema_json,
                               annotations_json, ordinal
                        FROM connection_mcp_catalog_entries
                        WHERE connection_id = ?1
                        ORDER BY ordinal ASC
                        "#,
                    )
                    .map_err(|source| {
                        sqlite_error(path, "MCP catalog entry query prepare", source)
                    })?;
                let raw_entries = entry_statement
                    .query_map(params![connection_id.as_str()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    })
                    .map_err(|source| sqlite_error(path, "MCP catalog entry query", source))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|source| sqlite_error(path, "MCP catalog entry read", source))?;
                if raw_entries.len() != expected_entry_count {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "MCP catalog entry count mismatch",
                    });
                }
                let entries =
                    raw_entries
                        .into_iter()
                        .enumerate()
                        .map(
                            |(
                                index,
                                (
                                    remote_tool_name,
                                    title,
                                    description,
                                    input_schema_json,
                                    annotations_json,
                                    ordinal,
                                ),
                            )| {
                                if usize::try_from(ordinal).ok() != Some(index) {
                                    return Err(ConnectionStoreError::CorruptRecord {
                                        id: connection_id.to_string(),
                                        reason: "MCP catalog entry ordinals are not contiguous",
                                    });
                                }
                                let input_schema = serde_json::from_str(&input_schema_json)
                                    .map_err(|source| ConnectionStoreError::Json {
                                        operation: "stored MCP catalog input schema",
                                        source,
                                    })?;
                                let annotations = annotations_json
                                    .map(|annotations| {
                                        serde_json::from_str(&annotations).map_err(|source| {
                                            ConnectionStoreError::Json {
                                                operation: "stored MCP catalog annotations",
                                                source,
                                            }
                                        })
                                    })
                                    .transpose()?;
                                Ok(StoredMcpCatalogEntry {
                                    remote_tool_name,
                                    title,
                                    description,
                                    input_schema,
                                    annotations,
                                })
                            },
                        )
                        .collect::<Result<Vec<_>, ConnectionStoreError>>()?;

                let mut resource_statement = connection
                    .prepare(
                        r#"
                        SELECT uri, name, title, description, mime_type, size, ordinal
                        FROM connection_mcp_catalog_resources
                        WHERE connection_id = ?1
                        ORDER BY ordinal ASC
                        "#,
                    )
                    .map_err(|source| {
                        sqlite_error(path, "MCP catalog resource query prepare", source)
                    })?;
                let resources = resource_statement
                    .query_map(params![connection_id.as_str()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })
                    .map_err(|source| sqlite_error(path, "MCP catalog resource query", source))?
                    .enumerate()
                    .map(|(index, row)| {
                        let (uri, name, title, description, mime_type, raw_size, ordinal) = row
                            .map_err(|source| {
                                sqlite_error(path, "MCP catalog resource read", source)
                            })?;
                        if usize::try_from(ordinal).ok() != Some(index) {
                            return Err(ConnectionStoreError::CorruptRecord {
                                id: connection_id.to_string(),
                                reason: "MCP resource ordinals are not contiguous",
                            });
                        }
                        let size = raw_size
                            .map(|size| {
                                u64::try_from(size).map_err(|_| {
                                    ConnectionStoreError::CorruptRecord {
                                        id: connection_id.to_string(),
                                        reason: "invalid MCP resource size",
                                    }
                                })
                            })
                            .transpose()?;
                        Ok(StoredMcpResource {
                            uri,
                            name,
                            title,
                            description,
                            mime_type,
                            size,
                        })
                    })
                    .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
                if resources.len() != expected_resource_count {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "MCP resource count mismatch",
                    });
                }

                let mut resource_template_statement = connection
                    .prepare(
                        r#"
                        SELECT uri_template, name, title, description, mime_type, ordinal
                        FROM connection_mcp_catalog_resource_templates
                        WHERE connection_id = ?1
                        ORDER BY ordinal ASC
                        "#,
                    )
                    .map_err(|source| {
                        sqlite_error(path, "MCP catalog resource template query prepare", source)
                    })?;
                let resource_templates = resource_template_statement
                    .query_map(params![connection_id.as_str()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    })
                    .map_err(|source| {
                        sqlite_error(path, "MCP catalog resource template query", source)
                    })?
                    .enumerate()
                    .map(|(index, row)| {
                        let (uri_template, name, title, description, mime_type, ordinal) = row
                            .map_err(|source| {
                                sqlite_error(path, "MCP catalog resource template read", source)
                            })?;
                        if usize::try_from(ordinal).ok() != Some(index) {
                            return Err(ConnectionStoreError::CorruptRecord {
                                id: connection_id.to_string(),
                                reason: "MCP resource template ordinals are not contiguous",
                            });
                        }
                        Ok(StoredMcpResourceTemplate {
                            uri_template,
                            name,
                            title,
                            description,
                            mime_type,
                        })
                    })
                    .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
                if resource_templates.len() != expected_resource_template_count {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "MCP resource template count mismatch",
                    });
                }

                let _ = validate_mcp_catalog(
                    &connection_id,
                    &entries,
                    &resources,
                    &resource_templates,
                )?;
                Ok(StoredMcpCatalog {
                    connection_id,
                    catalog_revision,
                    observed_etag: ConnectionEtag(observed_etag),
                    refreshed_at,
                    entries,
                    resources,
                    resource_templates,
                })
            },
        )
        .collect()
}

fn load_openapi_catalogs(
    connection: &Connection,
    path: &Path,
    requested_id: Option<&ConnectionId>,
) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
    if openapi_definition_bytes(
        connection,
        path,
        None,
        "OpenAPI catalog definition byte load validation",
    )? > MAX_MANAGED_OPENAPI_CATALOG_BYTES
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        });
    }
    let query = if requested_id.is_some() {
        r#"
        SELECT connection_id, spec_revision, catalog_revision, observed_etag,
               spec_digest, spec, refreshed_at, entry_count, overlay_revision
        FROM connection_openapi_catalogs
        WHERE connection_id = ?1
        ORDER BY connection_id ASC
        "#
    } else {
        r#"
        SELECT connection_id, spec_revision, catalog_revision, observed_etag,
               spec_digest, spec, refreshed_at, entry_count, overlay_revision
        FROM connection_openapi_catalogs
        ORDER BY connection_id ASC
        "#
    };
    let mut statement = connection
        .prepare(query)
        .map_err(|source| sqlite_error(path, "OpenAPI catalog query prepare", source))?;
    let map_row = |row: &Row<'_>| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
        ))
    };
    let raw = if let Some(id) = requested_id {
        statement
            .query_map(params![id.as_str()], map_row)
            .map_err(|source| sqlite_error(path, "OpenAPI catalog query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(path, "OpenAPI catalog read", source))?
    } else {
        statement
            .query_map([], map_row)
            .map_err(|source| sqlite_error(path, "OpenAPI catalog query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(path, "OpenAPI catalog read", source))?
    };
    drop(statement);

    raw.into_iter()
        .map(
            |(
                raw_id,
                raw_spec_revision,
                raw_catalog_revision,
                observed_etag,
                spec_digest,
                spec,
                refreshed_at,
                raw_entry_count,
                raw_overlay_revision,
            )| {
                let connection_id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id.clone(),
                        reason: "invalid OpenAPI catalog connection ID",
                    }
                })?;
                let spec_revision = persisted_revision(
                    &connection_id,
                    raw_spec_revision,
                    "invalid OpenAPI spec revision",
                )?;
                let catalog_revision = persisted_revision(
                    &connection_id,
                    raw_catalog_revision,
                    "invalid OpenAPI catalog revision",
                )?;
                let overlay_revision =
                    revision_from_i64(&connection_id, raw_overlay_revision, true)?;
                validate_openapi_spec(&spec, &spec_digest).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid stored OpenAPI spec or digest",
                    }
                })?;
                let expected_entry_count = usize::try_from(raw_entry_count).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid OpenAPI catalog entry count",
                    }
                })?;
                if expected_entry_count > MAX_CATALOG_ENTRIES {
                    return Err(ConnectionStoreError::LimitExceeded {
                        resource: "connection OpenAPI catalog entries",
                        maximum: MAX_CATALOG_ENTRIES,
                    });
                }

                let entries = load_openapi_catalog_entries(
                    connection,
                    path,
                    &connection_id,
                    expected_entry_count,
                )?;
                Ok(StoredOpenApiCatalog {
                    connection_id,
                    spec_revision,
                    catalog_revision,
                    observed_etag: ConnectionEtag(observed_etag),
                    spec_digest,
                    spec,
                    refreshed_at,
                    entries,
                    overlay_revision,
                })
            },
        )
        .collect()
}

fn load_openapi_inventory_catalogs(
    connection: &Connection,
    path: &Path,
) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
    if openapi_definition_bytes(
        connection,
        path,
        None,
        "OpenAPI inventory definition byte load validation",
    )? > MAX_MANAGED_OPENAPI_CATALOG_BYTES
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        });
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT connection_id, spec_revision, catalog_revision, observed_etag,
                   spec_digest, refreshed_at, entry_count
            FROM connection_openapi_catalogs
            ORDER BY connection_id ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "OpenAPI inventory query prepare", source))?;
    let raw = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "OpenAPI inventory query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "OpenAPI inventory read", source))?;
    drop(statement);

    raw.into_iter()
        .map(
            |(
                raw_id,
                raw_spec_revision,
                raw_catalog_revision,
                observed_etag,
                spec_digest,
                refreshed_at,
                raw_entry_count,
            )| {
                let connection_id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: raw_id,
                        reason: "invalid OpenAPI catalog connection ID",
                    }
                })?;
                let spec_revision = persisted_revision(
                    &connection_id,
                    raw_spec_revision,
                    "invalid OpenAPI spec revision",
                )?;
                let catalog_revision = persisted_revision(
                    &connection_id,
                    raw_catalog_revision,
                    "invalid OpenAPI catalog revision",
                )?;
                if spec_digest.len() != SHA256_HEX_CHARS
                    || !spec_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid stored OpenAPI spec digest",
                    });
                }
                let expected_entry_count = usize::try_from(raw_entry_count).map_err(|_| {
                    ConnectionStoreError::CorruptRecord {
                        id: connection_id.to_string(),
                        reason: "invalid OpenAPI catalog entry count",
                    }
                })?;
                if expected_entry_count > MAX_CATALOG_ENTRIES {
                    return Err(ConnectionStoreError::LimitExceeded {
                        resource: "connection OpenAPI catalog entries",
                        maximum: MAX_CATALOG_ENTRIES,
                    });
                }
                let entries = load_openapi_catalog_entries(
                    connection,
                    path,
                    &connection_id,
                    expected_entry_count,
                )?;
                Ok(StoredOpenApiInventoryCatalog {
                    connection_id,
                    spec_revision,
                    catalog_revision,
                    observed_etag: ConnectionEtag(observed_etag),
                    spec_digest,
                    refreshed_at,
                    entries,
                })
            },
        )
        .collect()
}

fn load_openapi_catalog_entries(
    connection: &Connection,
    path: &Path,
    connection_id: &ConnectionId,
    expected_entry_count: usize,
) -> Result<Vec<StoredOpenApiCatalogEntry>, ConnectionStoreError> {
    let mut entry_statement = connection
        .prepare(
            r#"
            SELECT tool_name, operation_id, selected_scheme_names_json,
                   definition_json, ordinal
            FROM connection_openapi_catalog_entries
            WHERE connection_id = ?1
            ORDER BY ordinal ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "OpenAPI catalog entry query prepare", source))?;
    let raw_entries = entry_statement
        .query_map(params![connection_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "OpenAPI catalog entry query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "OpenAPI catalog entry read", source))?;
    if raw_entries.len() != expected_entry_count {
        return Err(ConnectionStoreError::CorruptRecord {
            id: connection_id.to_string(),
            reason: "OpenAPI catalog entry count mismatch",
        });
    }
    let mut entries = Vec::with_capacity(raw_entries.len());
    for (index, (tool_name, operation_id, selected_scheme_names_json, definition_json, ordinal)) in
        raw_entries.into_iter().enumerate()
    {
        if usize::try_from(ordinal).ok() != Some(index) {
            return Err(ConnectionStoreError::CorruptRecord {
                id: connection_id.to_string(),
                reason: "OpenAPI catalog entry ordinals are not contiguous",
            });
        }
        let selected_scheme_names =
            serde_json::from_str::<Vec<String>>(&selected_scheme_names_json).map_err(|source| {
                ConnectionStoreError::Json {
                    operation: "stored OpenAPI selected security schemes",
                    source,
                }
            })?;
        let definition = serde_json::from_str::<Value>(&definition_json).map_err(|source| {
            ConnectionStoreError::Json {
                operation: "stored OpenAPI catalog tool definition",
                source,
            }
        })?;
        entries.push(StoredOpenApiCatalogEntry {
            tool_name,
            operation_id,
            selected_scheme_names,
            definition,
        });
    }
    let normalized = validate_openapi_catalog_entries(&entries)?;
    if normalized
        .iter()
        .map(|entry| &entry.entry)
        .ne(entries.iter())
    {
        return Err(ConnectionStoreError::CorruptRecord {
            id: connection_id.to_string(),
            reason: "OpenAPI catalog security scheme selections are not canonical",
        });
    }
    Ok(entries)
}

fn validate_managed_catalog_dependencies(
    connection: &Connection,
    path: &Path,
    mcp_catalogs: &[StoredMcpCatalog],
    openapi_catalogs: &[StoredOpenApiCatalog],
) -> Result<(), ConnectionStoreError> {
    let mut expected = BTreeSet::new();
    for catalog in mcp_catalogs {
        for entry in &catalog.entries {
            expected.insert((
                catalog.connection_id.to_string(),
                format!(
                    "{}:{}",
                    catalog.connection_id.as_str(),
                    entry.remote_tool_name
                ),
            ));
        }
    }
    for catalog in openapi_catalogs {
        for entry in &catalog.entries {
            expected.insert((catalog.connection_id.to_string(), entry.tool_name.clone()));
        }
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT connection_id, consumer_id
            FROM connection_dependencies
            WHERE consumer_kind = 'managed_tool'
            ORDER BY connection_id ASC, consumer_id ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "managed catalog dependency validation", source))?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(path, "managed catalog dependency query", source))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|source| sqlite_error(path, "managed catalog dependency read", source))?;
    if actual != expected {
        return Err(ConnectionStoreError::CorruptRecord {
            id: "<catalog-dependencies>".to_owned(),
            reason: "managed tool dependencies do not match durable catalog entries",
        });
    }
    Ok(())
}

fn load_all_records(
    connection: &Connection,
    path: &Path,
) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT id, schema_version, source, spec_json, connection_revision,
                   credential_revision, tls_revision, discovery_revision,
                   status_revision, created_at, updated_at
            FROM connection_records
            ORDER BY id ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "list prepare", source))?;
    let rows = statement
        .query_map([], RawStoredConnection::from_row)
        .map_err(|source| sqlite_error(path, "list query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "list read", source))?;
    rows.into_iter()
        .map(RawStoredConnection::into_stored)
        .collect()
}

fn count_rows(
    connection: &Connection,
    path: &Path,
    resource: &'static str,
    query: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let count: i64 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, "persisted bound validation", source))?;
    usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: format!("<{resource}>"),
        reason: "negative or oversized persisted row count",
    })
}

fn mcp_catalog_bytes(
    connection: &Connection,
    path: &Path,
    excluded_id: Option<&ConnectionId>,
    operation: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let entry_bytes = aggregate_catalog_bytes(
        connection,
        path,
        excluded_id,
        operation,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(remote_tool_name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + length(CAST(description AS BLOB))
          + length(CAST(input_schema_json AS BLOB))
          + COALESCE(length(CAST(annotations_json AS BLOB)), 0)
        ), 0)
        FROM connection_mcp_catalog_entries
        "#,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(remote_tool_name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + length(CAST(description AS BLOB))
          + length(CAST(input_schema_json AS BLOB))
          + COALESCE(length(CAST(annotations_json AS BLOB)), 0)
        ), 0)
        FROM connection_mcp_catalog_entries
        WHERE connection_id != ?1
        "#,
    )?;
    let resource_bytes = aggregate_catalog_bytes(
        connection,
        path,
        excluded_id,
        operation,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(uri AS BLOB))
          + length(CAST(name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + COALESCE(length(CAST(description AS BLOB)), 0)
          + COALESCE(length(CAST(mime_type AS BLOB)), 0)
          + CASE WHEN size IS NULL THEN 0 ELSE 8 END
        ), 0)
        FROM connection_mcp_catalog_resources
        "#,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(uri AS BLOB))
          + length(CAST(name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + COALESCE(length(CAST(description AS BLOB)), 0)
          + COALESCE(length(CAST(mime_type AS BLOB)), 0)
          + CASE WHEN size IS NULL THEN 0 ELSE 8 END
        ), 0)
        FROM connection_mcp_catalog_resources
        WHERE connection_id != ?1
        "#,
    )?;
    let template_bytes = aggregate_catalog_bytes(
        connection,
        path,
        excluded_id,
        operation,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(uri_template AS BLOB))
          + length(CAST(name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + COALESCE(length(CAST(description AS BLOB)), 0)
          + COALESCE(length(CAST(mime_type AS BLOB)), 0)
        ), 0)
        FROM connection_mcp_catalog_resource_templates
        "#,
        r#"
        SELECT COALESCE(SUM(
            length(CAST(uri_template AS BLOB))
          + length(CAST(name AS BLOB))
          + COALESCE(length(CAST(title AS BLOB)), 0)
          + COALESCE(length(CAST(description AS BLOB)), 0)
          + COALESCE(length(CAST(mime_type AS BLOB)), 0)
        ), 0)
        FROM connection_mcp_catalog_resource_templates
        WHERE connection_id != ?1
        "#,
    )?;

    entry_bytes
        .checked_add(resource_bytes)
        .and_then(|bytes| bytes.checked_add(template_bytes))
        .ok_or(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        })
}

#[allow(clippy::too_many_arguments)]
fn aggregate_catalog_bytes(
    connection: &Connection,
    path: &Path,
    excluded_id: Option<&ConnectionId>,
    operation: &'static str,
    all_query: &'static str,
    excluding_query: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let bytes: i64 = if let Some(id) = excluded_id {
        connection.query_row(excluding_query, params![id.as_str()], |row| row.get(0))
    } else {
        connection.query_row(all_query, [], |row| row.get(0))
    }
    .map_err(|source| sqlite_error(path, operation, source))?;
    usize::try_from(bytes).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: "<mcp-catalogs>".to_owned(),
        reason: "invalid MCP catalog byte count",
    })
}

fn openapi_definition_bytes(
    connection: &Connection,
    path: &Path,
    excluded_id: Option<&ConnectionId>,
    operation: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let bytes: i64 = if let Some(id) = excluded_id {
        connection.query_row(
            r#"
            SELECT COALESCE(SUM(length(CAST(definition_json AS BLOB))), 0)
            FROM connection_openapi_catalog_entries
            WHERE connection_id != ?1
            "#,
            params![id.as_str()],
            |row| row.get(0),
        )
    } else {
        connection.query_row(
            r#"
            SELECT COALESCE(SUM(length(CAST(definition_json AS BLOB))), 0)
            FROM connection_openapi_catalog_entries
            "#,
            [],
            |row| row.get(0),
        )
    }
    .map_err(|source| sqlite_error(path, operation, source))?;
    usize::try_from(bytes).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: "<openapi-catalogs>".to_owned(),
        reason: "invalid OpenAPI catalog definition byte count",
    })
}

fn ensure_no_invalid_rows(
    connection: &Connection,
    path: &Path,
    operation: &'static str,
    query: &'static str,
    reason: &'static str,
) -> Result<(), ConnectionStoreError> {
    let count: i64 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, operation, source))?;
    if count == 0 {
        Ok(())
    } else {
        Err(ConnectionStoreError::CorruptRecord {
            id: "<status>".to_owned(),
            reason,
        })
    }
}

pub(crate) fn validate_activity_timestamp(
    id: &ConnectionId,
    value: Option<&str>,
) -> Result<(), ConnectionStoreError> {
    if value.is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err()) {
        Err(ConnectionStoreError::CorruptRecord {
            id: id.to_string(),
            reason: "invalid connection activity timestamp",
        })
    } else {
        Ok(())
    }
}

fn validate_connection_activity_rows(
    connection: &Connection,
    path: &Path,
) -> Result<(), ConnectionStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT id, last_test_at, last_refresh_at
            FROM connection_records
            WHERE last_test_at IS NOT NULL OR last_refresh_at IS NOT NULL
            ORDER BY id ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "activity timestamp validation prepare", source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "activity timestamp validation query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "activity timestamp validation read", source))?;
    for (raw_id, last_test_at, last_refresh_at) in rows {
        let id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: raw_id,
                reason: "activity row has an invalid connection ID",
            }
        })?;
        validate_activity_timestamp(&id, last_test_at.as_deref())?;
        validate_activity_timestamp(&id, last_refresh_at.as_deref())?;
    }
    Ok(())
}

fn validate_safe_status_rows(
    connection: &Connection,
    path: &Path,
    table: &'static str,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    let query = format!(
        "SELECT connection_id, state, reason, observed_at, latency_ms, \
         catalog_age_secs, catalog_entry_count FROM {table}"
    );
    let mut statement = connection
        .prepare(&query)
        .map_err(|source| sqlite_error(path, operation, source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                RawStatus {
                    state: row.get(1)?,
                    reason: row.get(2)?,
                    observed_at: row.get(3)?,
                    latency_ms: row.get(4)?,
                    catalog_age_secs: row.get(5)?,
                    catalog_entry_count: row.get(6)?,
                },
            ))
        })
        .map_err(|source| sqlite_error(path, operation, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, operation, source))?;
    for (raw_id, status) in rows {
        let id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: raw_id,
                reason: "status row has an invalid connection ID",
            }
        })?;
        status.into_safe_status(&id)?;
    }
    Ok(())
}

fn load_raw_by_id(
    connection: &Connection,
    path: &Path,
    id: &ConnectionId,
) -> Result<Option<RawStoredConnection>, ConnectionStoreError> {
    connection
        .query_row(
            r#"
            SELECT id, schema_version, source, spec_json, connection_revision,
                   credential_revision, tls_revision, discovery_revision,
                   status_revision, created_at, updated_at
            FROM connection_records
            WHERE id = ?1
            "#,
            params![id.as_str()],
            RawStoredConnection::from_row,
        )
        .optional()
        .map_err(|source| sqlite_error(path, "record query", source))
}

struct RawStoredConnection {
    id: String,
    schema_version: String,
    source: String,
    spec_json: String,
    connection_revision: i64,
    credential_revision: i64,
    tls_revision: i64,
    discovery_revision: i64,
    status_revision: i64,
    created_at: String,
    updated_at: String,
}

impl RawStoredConnection {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            schema_version: row.get(1)?,
            source: row.get(2)?,
            spec_json: row.get(3)?,
            connection_revision: row.get(4)?,
            credential_revision: row.get(5)?,
            tls_revision: row.get(6)?,
            discovery_revision: row.get(7)?,
            status_revision: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }

    fn into_stored(self) -> Result<StoredConnection, ConnectionStoreError> {
        let id = ConnectionId::parse(self.id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: self.id.clone(),
                reason: "invalid connection ID",
            }
        })?;
        if Uuid::parse_str(id.as_str()).is_err() {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "managed connection ID is not a UUID",
            });
        }
        if self.schema_version != CONNECTION_SCHEMA_VERSION {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "unsupported connection document schema version",
            });
        }
        if self.source != SOURCE_MANAGED {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "managed store row has a non-managed source",
            });
        }
        if self.spec_json.len() > MAX_MANAGED_SPEC_BYTES {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "connection document exceeds the managed specification limit",
            });
        }
        let write: ConnectionWrite = serde_json::from_str(&self.spec_json).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "connection document is not valid strict JSON",
            }
        })?;
        let write =
            write
                .validated_persisted_v0()
                .map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "connection document no longer passes validation",
                })?;
        Ok(StoredConnection {
            id: id.clone(),
            write,
            revisions: ConnectionRevisions {
                connection: revision_from_i64(&id, self.connection_revision, false)?,
                credential: revision_from_i64(&id, self.credential_revision, true)?,
                tls: revision_from_i64(&id, self.tls_revision, true)?,
                discovery: revision_from_i64(&id, self.discovery_revision, true)?,
                status: revision_from_i64(&id, self.status_revision, true)?,
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct RawStatus {
    state: String,
    reason: String,
    observed_at: String,
    latency_ms: Option<i64>,
    catalog_age_secs: Option<i64>,
    catalog_entry_count: Option<i64>,
}

impl RawStatus {
    fn into_safe_status(
        self,
        id: &ConnectionId,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        let catalog_age_secs = optional_i64_to_u64(id, self.catalog_age_secs)?.map(|age| {
            let elapsed = OffsetDateTime::parse(&self.observed_at, &Rfc3339)
                .ok()
                .map(|observed_at| (OffsetDateTime::now_utc() - observed_at).whole_seconds())
                .unwrap_or_default()
                .max(0);
            age.saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX))
        });
        Ok(SafeConnectionStatus {
            state: parse_state(&self.state).ok_or_else(|| ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "unknown safe status state",
            })?,
            reason: parse_reason(&self.reason).ok_or_else(|| {
                ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "unknown safe status reason",
                }
            })?,
            observed_at: Some(self.observed_at),
            latency_ms: optional_i64_to_u64(id, self.latency_ms)?,
            catalog_age_secs,
            catalog_entry_count: self
                .catalog_entry_count
                .map(|value| {
                    usize::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
                        id: id.to_string(),
                        reason: "invalid catalog entry count",
                    })
                })
                .transpose()?,
        })
    }
}

fn raw_status_from_row(row: &Row<'_>) -> rusqlite::Result<RawStatus> {
    Ok(RawStatus {
        state: row.get(0)?,
        reason: row.get(1)?,
        observed_at: row.get(2)?,
        latency_ms: row.get(3)?,
        catalog_age_secs: row.get(4)?,
        catalog_entry_count: row.get(5)?,
    })
}

/// Read one of the two status tables verbatim for
/// [`SqliteConnectionStore::exported_statuses`]. `query` is a literal
/// from this module and takes the row budget as its only parameter; one
/// row past the budget refuses the read, because a source that has
/// overflowed the bound the writer prunes against is one no destination
/// can accept.
fn exported_status_rows(
    transaction: &Transaction<'_>,
    path: &Path,
    query: &'static str,
) -> Result<Vec<PersistedConnectionStatus>, ConnectionStoreError> {
    let mut statement = transaction
        .prepare(query)
        .map_err(|source| sqlite_error(path, "status export prepare", source))?;
    let rows = statement
        .query_map(
            params![i64::try_from(MAX_STATUS_HISTORY_ROWS + 1).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                ))
            },
        )
        .map_err(|source| sqlite_error(path, "status export query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "status export read", source))?;
    drop(statement);
    if rows.len() > MAX_STATUS_HISTORY_ROWS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: MAX_STATUS_HISTORY_ROWS,
        });
    }
    rows.into_iter()
        .map(|raw| {
            let (
                raw_id,
                status_revision,
                observed_connection_revision,
                observed_credential_revision,
                observed_tls_revision,
                observed_discovery_revision,
                state,
                reason,
                observed_at,
                latency_ms,
                catalog_age_secs,
                catalog_entry_count,
            ) = raw;
            let id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
                ConnectionStoreError::CorruptRecord {
                    id: raw_id,
                    reason: "status row has an invalid connection ID",
                }
            })?;
            Ok(PersistedConnectionStatus {
                status_revision: persisted_revision(
                    &id,
                    status_revision,
                    "invalid status revision",
                )?,
                observed_connection_revision: revision_from_i64(
                    &id,
                    observed_connection_revision,
                    false,
                )?,
                observed_credential_revision: revision_from_i64(
                    &id,
                    observed_credential_revision,
                    true,
                )?,
                observed_tls_revision: revision_from_i64(&id, observed_tls_revision, true)?,
                observed_discovery_revision: revision_from_i64(
                    &id,
                    observed_discovery_revision,
                    true,
                )?,
                state: parse_state(&state).ok_or_else(|| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "unknown safe status state",
                })?,
                reason: parse_reason(&reason).ok_or_else(|| {
                    ConnectionStoreError::CorruptRecord {
                        id: id.to_string(),
                        reason: "unknown safe status reason",
                    }
                })?,
                observed_at,
                latency_ms: optional_i64_to_u64(&id, latency_ms)?,
                catalog_age_secs: optional_i64_to_u64(&id, catalog_age_secs)?,
                catalog_entry_count: optional_i64_to_u64(&id, catalog_entry_count)?,
                connection_id: id,
            })
        })
        .collect()
}

fn replace_bindings(
    transaction: &Transaction<'_>,
    path: &Path,
    id: &ConnectionId,
    write: &ConnectionWrite,
    revisions: &ConnectionRevisions,
    now: &str,
) -> Result<(), ConnectionStoreError> {
    transaction
        .execute(
            "DELETE FROM connection_credential_bindings WHERE connection_id = ?1",
            params![id.as_str()],
        )
        .map_err(|source| sqlite_error(path, "binding replacement", source))?;

    for binding in expected_bindings(write, revisions) {
        transaction
            .execute(
                r#"
                INSERT INTO connection_credential_bindings (
                    connection_id, purpose, header_name, secret_id, binding_version, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    id.as_str(),
                    binding.purpose,
                    binding.header_name,
                    binding.secret_id,
                    u64_to_i64(id, binding.version.max(1))?,
                    now
                ],
            )
            .map_err(|source| sqlite_error(path, "binding insert", source))?;
    }
    Ok(())
}

fn validate_record_bindings(
    connection: &Connection,
    path: &Path,
    record: &StoredConnection,
) -> Result<(), ConnectionStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT purpose, header_name, secret_id, binding_version
            FROM connection_credential_bindings
            WHERE connection_id = ?1
            ORDER BY purpose ASC, header_name ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "binding validation prepare", source))?;
    let actual = statement
        .query_map(params![record.id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "binding validation query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "binding validation read", source))?;
    let mut expected = expected_bindings(&record.write, &record.revisions)
        .into_iter()
        .map(|binding| {
            Ok((
                binding.purpose.to_owned(),
                binding.header_name.to_owned(),
                binding.secret_id.to_owned(),
                u64_to_i64(&record.id, binding.version.max(1))?,
            ))
        })
        .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
    expected.sort();
    if actual != expected {
        return Err(ConnectionStoreError::CorruptRecord {
            id: record.id.to_string(),
            reason: "credential binding rows do not match the stored connection document",
        });
    }
    Ok(())
}

/// One row of `connection_credential_bindings` as derived from the stored
/// document. `header_name` is empty for every binding except an additional
/// header, whose name is part of the row's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedBinding<'a> {
    pub(crate) purpose: &'static str,
    pub(crate) header_name: &'a str,
    pub(crate) secret_id: &'a str,
    pub(crate) version: u64,
}

pub(crate) const ADDITIONAL_HEADER_BINDING_PURPOSE: &str = "additional_header";

pub(crate) fn expected_bindings<'a>(
    write: &'a ConnectionWrite,
    revisions: &ConnectionRevisions,
) -> Vec<ExpectedBinding<'a>> {
    let binding = |purpose: &'static str, secret_id: &'a str, version: u64| ExpectedBinding {
        purpose,
        header_name: "",
        secret_id,
        version,
    };
    let mut bindings = Vec::new();
    match &write.authentication {
        ConnectionAuthentication::None => {}
        ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(secret_id),
            ..
        }
        | ConnectionAuthentication::StaticBearer {
            secret_id: Some(secret_id),
        } => bindings.push(binding(
            "http_authentication",
            secret_id.as_str(),
            revisions.credential,
        )),
        ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(secret_id),
            ..
        } => bindings.push(binding(
            "oauth_client_secret",
            secret_id.as_str(),
            revisions.credential,
        )),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        } => {}
    }
    for header in &write.additional_headers {
        if let Some(secret_id) = header.secret_id.as_deref() {
            bindings.push(ExpectedBinding {
                purpose: ADDITIONAL_HEADER_BINDING_PURPOSE,
                header_name: header.header_name.as_str(),
                secret_id,
                version: revisions.credential,
            });
        }
    }
    if let Some(secret_id) = write.tls.ca_bundle_alias.as_deref() {
        bindings.push(binding("tls_ca_bundle", secret_id, revisions.tls));
    }
    if let Some(secret_id) = write.tls.client_certificate_id.as_deref() {
        bindings.push(binding("tls_client_certificate", secret_id, revisions.tls));
    }
    if let Some(secret_id) = write.tls.client_private_key_id.as_deref() {
        bindings.push(binding("tls_client_private_key", secret_id, revisions.tls));
    }
    bindings
}

pub(crate) fn binding_count(write: &ConnectionWrite) -> usize {
    let authentication = match &write.authentication {
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        } => 0,
        ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(_), ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: Some(_) }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(_),
            ..
        } => 1,
    };
    authentication
        + write
            .additional_headers
            .iter()
            .filter(|header| header.secret_id.is_some())
            .count()
        + usize::from(write.tls.ca_bundle_alias.is_some())
        + usize::from(write.tls.client_certificate_id.is_some())
        + usize::from(write.tls.client_private_key_id.is_some())
}

pub(crate) fn supports_managed_mcp_catalog(write: &ConnectionWrite) -> bool {
    write.kind == ConnectionKind::McpStreamableHttp
        && matches!(&write.discovery, Some(DiscoveryConfig::ManagedMcp { .. }))
}

pub(crate) fn supports_managed_openapi_catalog(write: &ConnectionWrite) -> bool {
    write.kind == ConnectionKind::HttpApi
        && matches!(
            &write.discovery,
            Some(DiscoveryConfig::ManagedOpenapi { .. })
        )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagedCatalogKind {
    Mcp,
    OpenApi,
    None,
}

fn managed_catalog_kind(write: &ConnectionWrite) -> ManagedCatalogKind {
    if supports_managed_mcp_catalog(write) {
        ManagedCatalogKind::Mcp
    } else if supports_managed_openapi_catalog(write) {
        ManagedCatalogKind::OpenApi
    } else {
        ManagedCatalogKind::None
    }
}

fn ensure_binding_capacity(
    transaction: &Transaction<'_>,
    path: &Path,
    replaced_id: Option<&ConnectionId>,
    replaced_binding_count: usize,
    candidate_binding_count: usize,
) -> Result<(), ConnectionStoreError> {
    let persisted: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM connection_credential_bindings",
            [],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, "binding count", source))?;
    let persisted =
        usize::try_from(persisted).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "negative or oversized binding count",
        })?;
    if let Some(id) = replaced_id {
        let record_bindings: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM connection_credential_bindings WHERE connection_id = ?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(path, "record binding count", source))?;
        if usize::try_from(record_bindings).ok() != Some(replaced_binding_count) {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "credential binding rows do not match the stored connection document",
            });
        }
    }
    let total = persisted
        .checked_sub(replaced_binding_count)
        .and_then(|count| count.checked_add(candidate_binding_count))
        .ok_or_else(|| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "binding count is inconsistent with its connection record",
        })?;
    if total > MAX_CREDENTIALS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        });
    }
    Ok(())
}

pub(crate) fn validate_candidate(
    candidate: ConnectionWrite,
) -> Result<ConnectionWrite, ConnectionStoreError> {
    candidate
        .validated()
        .map_err(|errors| ConnectionStoreError::Validation {
            problems: errors
                .into_iter()
                .map(|error| format!("{}:{}", error.field, error.code))
                .collect(),
        })
}

pub(crate) fn initial_revisions(write: &ConnectionWrite) -> ConnectionRevisions {
    ConnectionRevisions {
        connection: 1,
        credential: u64::from(has_credential_binding(write)),
        tls: u64::from(!write.tls.is_empty()),
        discovery: u64::from(write.discovery.is_some()),
        status: 0,
    }
}

pub(crate) fn replacement_revisions(
    id: &ConnectionId,
    current: &StoredConnection,
    candidate: &ConnectionWrite,
) -> Result<ConnectionRevisions, ConnectionStoreError> {
    let credential_changed = current.write.requires_secrets_write_to_replace(candidate);
    Ok(ConnectionRevisions {
        connection: increment_revision(id, current.revisions.connection)?,
        credential: if credential_changed {
            increment_revision(id, current.revisions.credential)?
        } else {
            current.revisions.credential
        },
        tls: if current.write.tls != candidate.tls {
            increment_revision(id, current.revisions.tls)?
        } else {
            current.revisions.tls
        },
        discovery: if current.write.discovery != candidate.discovery {
            increment_revision(id, current.revisions.discovery)?
        } else {
            current.revisions.discovery
        },
        status: current.revisions.status,
    })
}

fn has_credential_binding(write: &ConnectionWrite) -> bool {
    write.configures_credential_authority()
}

fn safe_authentication_kind(authentication: &ConnectionAuthentication) -> SafeAuthenticationKind {
    match authentication {
        ConnectionAuthentication::None => SafeAuthenticationKind::None,
        ConnectionAuthentication::HeaderApiKey { .. } => SafeAuthenticationKind::HeaderApiKey,
        ConnectionAuthentication::StaticBearer { .. } => SafeAuthenticationKind::StaticBearer,
        ConnectionAuthentication::OAuth2ClientCredentials { .. } => {
            SafeAuthenticationKind::Oauth2ClientCredentials
        }
    }
}

pub(crate) fn ensure_etag(
    id: &ConnectionId,
    expected: &ConnectionEtag,
    current: &StoredConnection,
) -> Result<(), ConnectionStoreError> {
    let actual = current.etag();
    if expected == &actual {
        Ok(())
    } else {
        Err(ConnectionStoreError::Conflict {
            id: id.to_string(),
            current: actual,
        })
    }
}

/// Derives the `connection_dependencies` key recorded for one managed MCP tool.
///
/// Validation and insertion must agree on the exact string, so both go through
/// here rather than formatting it independently.
pub(crate) fn managed_tool_dependency_id(id: &ConnectionId, remote_tool_name: &str) -> String {
    format!("{}:{remote_tool_name}", id.as_str())
}

pub(crate) fn validate_dependency_id(value: &str) -> Result<(), ConnectionStoreError> {
    if value.is_empty() || value.len() > MAX_DEPENDENCY_FIELD_BYTES || value.contains('\0') {
        Err(ConnectionStoreError::Validation {
            problems: vec![format!(
                "dependency consumer_id must contain 1-{MAX_DEPENDENCY_FIELD_BYTES} bytes without NUL"
            )],
        })
    } else {
        Ok(())
    }
}

pub(crate) fn increment_revision(
    id: &ConnectionId,
    revision: u64,
) -> Result<u64, ConnectionStoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| ConnectionStoreError::RevisionOverflow { id: id.to_string() })
}

pub(crate) fn revision_from_i64(
    id: &ConnectionId,
    value: i64,
    zero_allowed: bool,
) -> Result<u64, ConnectionStoreError> {
    let value = u64::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason: "negative revision",
    })?;
    if !zero_allowed && value == 0 {
        return Err(ConnectionStoreError::CorruptRecord {
            id: id.to_string(),
            reason: "zero connection revision",
        });
    }
    Ok(value)
}

pub(crate) fn persisted_revision(
    id: &ConnectionId,
    value: i64,
    reason: &'static str,
) -> Result<u64, ConnectionStoreError> {
    let value = u64::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason,
    })?;
    if value == 0 {
        return Err(ConnectionStoreError::CorruptRecord {
            id: id.to_string(),
            reason,
        });
    }
    Ok(value)
}

pub(crate) fn u64_to_i64(id: &ConnectionId, value: u64) -> Result<i64, ConnectionStoreError> {
    i64::try_from(value).map_err(|_| ConnectionStoreError::RevisionOverflow { id: id.to_string() })
}

pub(crate) fn optional_u64_to_i64(
    value: Option<u64>,
    field: &'static str,
) -> Result<Option<i64>, ConnectionStoreError> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| ConnectionStoreError::Validation {
                problems: vec![format!("{field} is too large")],
            })
        })
        .transpose()
}

pub(crate) fn optional_i64_to_u64(
    id: &ConnectionId,
    value: Option<i64>,
) -> Result<Option<u64>, ConnectionStoreError> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "negative safe status count",
            })
        })
        .transpose()
}

pub(crate) fn state_as_str(state: ConnectionOperationalState) -> &'static str {
    match state {
        ConnectionOperationalState::Unknown => "unknown",
        ConnectionOperationalState::Configured => "configured",
        ConnectionOperationalState::Healthy => "healthy",
        ConnectionOperationalState::Degraded => "degraded",
        ConnectionOperationalState::Unavailable => "unavailable",
        ConnectionOperationalState::Disabled => "disabled",
    }
}

pub(crate) fn parse_state(value: &str) -> Option<ConnectionOperationalState> {
    match value {
        "unknown" => Some(ConnectionOperationalState::Unknown),
        "configured" => Some(ConnectionOperationalState::Configured),
        "healthy" => Some(ConnectionOperationalState::Healthy),
        "degraded" => Some(ConnectionOperationalState::Degraded),
        "unavailable" => Some(ConnectionOperationalState::Unavailable),
        "disabled" => Some(ConnectionOperationalState::Disabled),
        _ => None,
    }
}

pub(crate) fn reason_as_str(reason: ConnectionStatusReason) -> &'static str {
    match reason {
        ConnectionStatusReason::NotTested => "not_tested",
        ConnectionStatusReason::LegacyConfigured => "legacy_configured",
        ConnectionStatusReason::Disabled => "disabled",
        ConnectionStatusReason::TestSucceeded => "test_succeeded",
        ConnectionStatusReason::CatalogRefreshed => "catalog_refreshed",
        ConnectionStatusReason::RequestFailed => "request_failed",
        ConnectionStatusReason::EgressDenied => "egress_denied",
        ConnectionStatusReason::SecretUnavailable => "secret_unavailable",
        ConnectionStatusReason::InvalidResponse => "invalid_response",
        ConnectionStatusReason::UpstreamMethodNotFound => "upstream_method_not_found",
        ConnectionStatusReason::UpstreamError => "upstream_error",
        ConnectionStatusReason::UpstreamTransportFailure => "upstream_transport_failure",
        ConnectionStatusReason::CatalogStale => "catalog_stale",
    }
}

pub(crate) fn parse_reason(value: &str) -> Option<ConnectionStatusReason> {
    match value {
        "not_tested" => Some(ConnectionStatusReason::NotTested),
        "legacy_configured" => Some(ConnectionStatusReason::LegacyConfigured),
        "disabled" => Some(ConnectionStatusReason::Disabled),
        "test_succeeded" => Some(ConnectionStatusReason::TestSucceeded),
        "catalog_refreshed" => Some(ConnectionStatusReason::CatalogRefreshed),
        "request_failed" => Some(ConnectionStatusReason::RequestFailed),
        "egress_denied" => Some(ConnectionStatusReason::EgressDenied),
        "secret_unavailable" => Some(ConnectionStatusReason::SecretUnavailable),
        "invalid_response" => Some(ConnectionStatusReason::InvalidResponse),
        "upstream_method_not_found" => Some(ConnectionStatusReason::UpstreamMethodNotFound),
        "upstream_error" => Some(ConnectionStatusReason::UpstreamError),
        "upstream_transport_failure" => Some(ConnectionStatusReason::UpstreamTransportFailure),
        "catalog_stale" => Some(ConnectionStatusReason::CatalogStale),
        _ => None,
    }
}

pub(crate) fn utc_timestamp() -> Result<String, ConnectionStoreError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<clock>".to_owned(),
            reason: "failed to format UTC timestamp",
        })
}

pub(crate) fn remaining_before(
    deadline: Instant,
    operation: &'static str,
) -> Result<Duration, ConnectionStoreError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ConnectionStoreError::DeadlineExceeded { operation })
}

fn refresh_status_busy_timeout(
    connection: &Connection,
    path: &Path,
    deadline: Option<Instant>,
) -> Result<(), ConnectionStoreError> {
    if let Some(deadline) = deadline {
        let remaining = remaining_before(deadline, "connection status persistence")?;
        connection
            .busy_timeout(remaining.min(DEFAULT_SQLITE_BUSY_TIMEOUT))
            .map_err(|source| {
                status_sqlite_error(path, "status busy-timeout refresh", source, Some(deadline))
            })?;
    }
    Ok(())
}

fn status_sqlite_error(
    path: &Path,
    operation: &'static str,
    source: rusqlite::Error,
    deadline: Option<Instant>,
) -> ConnectionStoreError {
    if matches!(
        source.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    ) {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ConnectionStoreError::DeadlineExceeded {
                operation: "connection status persistence",
            };
        }
        return ConnectionStoreError::Busy {
            resource: "connection SQLite status persistence",
        };
    }
    sqlite_error(path, operation, source)
}

fn sqlite_error(
    path: &Path,
    operation: &'static str,
    source: rusqlite::Error,
) -> ConnectionStoreError {
    ConnectionStoreError::Sqlite {
        path: path.to_path_buf(),
        operation,
        source,
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
