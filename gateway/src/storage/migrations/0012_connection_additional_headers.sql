-- Migration 12: additional secret headers on a Connection (issue #360,
-- PR A).
--
-- A Connection may now bind up to four secret-backed headers beyond its
-- primary credential -- an identity-aware proxy in front of the upstream
-- (Cloudflare Access needs two of its own) is the motivating case. Each
-- one is a row in connection_credential_bindings under the purpose
-- `additional_header`, and the binding key must therefore carry the header
-- name: `(connection_id, purpose)` can hold exactly one row per purpose,
-- which is why a second header secret could not persist before this
-- migration.
--
-- What is stored and why:
--
-- - header_name is the lowercased header the binding injects. It is '' for
--   every existing row and for every primary and TLS binding written from
--   now on (those have no header of their own; the primary credential's
--   header lives in the document), so a single-binding Connection's rows
--   read exactly as they did before: same purpose, same secret_id, same
--   binding_version, same updated_at.
-- - The primary key becomes (connection_id, purpose, header_name). The
--   existing rows all carry '' and their (connection_id, purpose) pairs
--   were unique already, so the widened key cannot collide on upgrade.
-- - The bound matches the document's own header-name limit (64 bytes) so
--   the row can never hold a name the model would have refused.
--
-- The foreign key to connection_records and its cascade are untouched.
--
-- Standalone SQLite rebuilds the table in place on open (SQLite cannot
-- change a primary key), copying every row with header_name ''.

ALTER TABLE greengateway.connection_credential_bindings
    ADD COLUMN header_name text NOT NULL DEFAULT '' CHECK (length(header_name) <= 64);

ALTER TABLE greengateway.connection_credential_bindings
    DROP CONSTRAINT connection_credential_bindings_pkey;

ALTER TABLE greengateway.connection_credential_bindings
    ADD PRIMARY KEY (connection_id, purpose, header_name);
