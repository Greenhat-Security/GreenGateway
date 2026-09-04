-- Migration 13: per-Connection OpenAPI overlays are sibling documents of the
-- generated catalog. The catalog records the overlay revision it was compiled
-- from, while dynamic enum values retain enough source provenance to reject a
-- stale value set after an overlay edits or reuses a source name.

CREATE TABLE greengateway.connection_openapi_overlays (
    connection_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (
        octet_length(schema_version) BETWEEN 1 AND 32
    ),
    overlay_revision bigint NOT NULL CHECK (overlay_revision >= 1),
    -- Verbatim compact JSON. Keeping text rather than jsonb preserves the
    -- exact document the operator supplied and makes the byte limit agree
    -- with the SQLite store and Rust validation.
    overlay_json text NOT NULL CHECK (
        octet_length(overlay_json) BETWEEN 2 AND 1048576
    ),
    -- Canonical compile-time label/enum source reports are retained with the
    -- authoring document so GET and restart can report what was resolved
    -- without performing source I/O. PR 1 normally stores NULL or {}.
    source_reports_json text CHECK (
        source_reports_json IS NULL
        OR octet_length(source_reports_json) BETWEEN 2 AND 262144
    ),
    actor_user_id text,
    updated_at text NOT NULL CHECK (
        octet_length(updated_at) BETWEEN 1 AND 64
    ),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

ALTER TABLE greengateway.connection_openapi_catalogs
    ADD COLUMN overlay_revision bigint NOT NULL DEFAULT 0
        CHECK (overlay_revision >= 0);

-- Created with the base overlay migration so dynamic-enum support can land
-- without another DDL step. A value set is usable only when both its overlay
-- revision and source digest match the current compiled source declaration.
CREATE TABLE greengateway.connection_enum_source_values (
    connection_id uuid NOT NULL,
    source_id text NOT NULL CHECK (
        char_length(source_id) BETWEEN 1 AND 64
    ),
    overlay_revision bigint NOT NULL CHECK (overlay_revision >= 1),
    source_digest text NOT NULL CHECK (
        octet_length(source_digest) = 64
        AND source_digest ~ '^[0-9a-f]+$'
    ),
    values_revision bigint NOT NULL CHECK (values_revision >= 1),
    connection_revision bigint NOT NULL CHECK (connection_revision >= 0),
    credential_revision bigint NOT NULL CHECK (credential_revision >= 0),
    -- Optional keyed generation of the credential material actually used
    -- for the fetch. Connection revisions alone do not move when a local or
    -- file-backed secret alias is rotated in place.
    credential_generation_digest text CHECK (
        credential_generation_digest IS NULL
        OR (
            octet_length(credential_generation_digest) = 64
            AND credential_generation_digest ~ '^[0-9a-f]+$'
        )
    ),
    values_json text NOT NULL CHECK (
        octet_length(values_json) BETWEEN 2 AND 262144
    ),
    resolved_at text NOT NULL CHECK (
        octet_length(resolved_at) BETWEEN 1 AND 64
    ),
    PRIMARY KEY (connection_id, source_id),
    FOREIGN KEY (connection_id)
        REFERENCES greengateway.connection_records(id) ON DELETE CASCADE
);

-- Overlay replacement prunes superseded source rows by Connection/revision;
-- the primary key above remains the conflict target for atomic per-source
-- upserts within that same catalog transaction.
CREATE INDEX idx_ggw_connection_enum_source_overlay
    ON greengateway.connection_enum_source_values(connection_id, overlay_revision);
