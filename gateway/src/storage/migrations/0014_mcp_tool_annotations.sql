-- Migration 14: retain optional MCP tool display metadata and advisory client
-- hints across managed catalog refresh, restart, and replica replay. Existing
-- rows remain NULL, preserving their logical catalog representation.

ALTER TABLE greengateway.connection_mcp_catalog_entries
    ADD COLUMN title text CHECK (
        title IS NULL OR (
            char_length(title) BETWEEN 1 AND 256
            AND octet_length(title) <= 1024
        )
    );

ALTER TABLE greengateway.connection_mcp_catalog_entries
    ADD COLUMN annotations_json text CHECK (
        annotations_json IS NULL
        OR octet_length(annotations_json) BETWEEN 2 AND 2048
    );
