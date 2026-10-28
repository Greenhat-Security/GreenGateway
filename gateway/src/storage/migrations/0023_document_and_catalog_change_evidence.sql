-- Migration 23: durable policy, tools and catalog change evidence (issue
-- #425, PR 2c).
--
-- A policy or tools commit already writes an immutable document version
-- (actor subject, diff summary, ETag), advances the shared security revision
-- and appends a security_outbox row in one transaction (migrations 4 and 5).
-- A managed MCP or OpenAPI catalog replacement, including an overlay write,
-- commits its catalog rows, catalog revision and outbox row in one
-- transaction too (migrations 6 and 13). What neither kept:
--
-- - A stable identity for the change. There was no event or operation ID, so
--   a consumer had nothing to deduplicate on and an operator could name one
--   committed change only by its version.
-- - For documents, who made the change beyond a bare subject: not the issuer
--   that vouched for it, not how it authenticated, and not whether it was a
--   person at all (the tools seed and the standalone import write fixed
--   labels a principal could also carry as a subject).
-- - For catalogs, anything that outlives the next change: a replacement
--   deletes the catalog row that named its publisher, an overlay write
--   overwrites the overlay's actor, and a Connection delete cascades both.
--
-- These two tables are that evidence. Both follow migrations 16 and 18:
--
-- - One row per committed change, written in the SAME transaction as the
--   change it describes (ha-state-model.md section 2, rule 2). A change
--   whose evidence cannot be inserted rolls back and reports failure. A
--   refused change -- a stale ETag or catalog revision, a lost initialize
--   race, a tool name another lane holds, a capacity limit -- writes nothing.
-- - No foreign keys. A catalog row is deleted by every replacement and
--   cascades with its Connection, and the evidence must survive both, so it
--   can neither cascade nor restrict. Document versions are never deleted,
--   but the evidence is the record of the commit, not of the row, and keeps
--   the same rule. Nothing references the outbox: outbox maintenance must
--   never cascade into evidence.
-- - actor_user_id follows migrations 16 and 18: text, no foreign key,
--   bounded by exactly the principal subject bound authentication enforces
--   (auth/principal.rs MAX_PRINCIPAL_SUBJECT_BYTES), so no principal a
--   validator accepted is refused here.
-- - Document evidence also records the rest of the actor:
--   * actor_kind 'principal' is an authenticated caller; 'system' is a fixed
--     label written by the gateway itself ('bootstrap' for the empty tools
--     document a cluster seeds at first boot, 'import-standalone' for the
--     offline import), never a person.
--   * actor_issuer is the principal's issuer, bounded by exactly
--     MAX_PRINCIPAL_ISSUER_BYTES, NULL when the principal carries none. A
--     system actor has no issuer.
--   * actor_auth_mode is how the principal authenticated, in the audit
--     stream's vocabulary (AuthMethod::audit_mode), or 'system'.
--   Catalog writers are reached only through the admin API and carry the
--   subject alone, as the Connection store does for deletions; their issuer
--   and auth mode remain a follow-up shared with migration 16.
-- - event_id identifies this record and operation_id the logical operation
--   that produced it. The writer generates both and never regenerates them;
--   an operation records each action at most once.
-- - Documents: prior_version is the active version the commit replaced (NULL
--   for the commit that initializes the document) and new_version the
--   version it activated, the same values as its outbox row's from_version
--   and to_version; one version is activated by exactly one commit.
-- - Catalogs: prior_version is the catalog revision the change replaced
--   (NULL when the Connection had no catalog of that kind) and new_version
--   the revision it wrote, the outbox row's from_version and to_version
--   ('connection_catalog', with 0 for "none"). overlay_revision is the
--   OpenAPI overlay revision the published catalog was compiled from (0 for
--   no overlay; NULL for MCP, which has none). Catalog revisions restart
--   when a Connection leaves and re-enters a managed kind, so evidence is
--   ordered by security_revision, not by revision.
-- - security_revision is the shared revision the change took, the same value
--   as its outbox row's revision.
-- - committed_at is the database clock at transaction acceptance, never a
--   replica's wall clock.
-- - Identifiers, revisions and the actor only. No policy or tools document,
--   specification, overlay, tool definition, endpoint, secret ID or
--   credential binding is stored, so nothing here needs the secret-handling
--   rules of the tables it describes.
-- - action is a closed vocabulary using the proposed authority-event
--   operation codes (docs/schemas/authority_event.v1.schema.json). The
--   offline import's policy and tools activations are 'configuration.import'.
-- - Rows are append-only by contract: no gateway path updates or deletes
--   them. Migration 21's authority-event journal does not list these two
--   tables yet, so the dispatcher does not deliver them; journaling them is
--   a later #425 slice, and the retention rule there is that undelivered
--   evidence is never erased.

CREATE TABLE greengateway.document_change_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('principal', 'system')),
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 4096
    ),
    actor_issuer text CHECK (
        actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND 4096
    ),
    actor_auth_mode text NOT NULL CHECK (
        actor_auth_mode IN (
            'bearer_token', 'session_cookie', 'service_token',
            'client_certificate', 'system'
        )
    ),
    action text NOT NULL CHECK (
        action IN (
            'policy.publish', 'policy.rollback', 'policy.rule.create',
            'policy.rule.update', 'policy.rule.delete', 'policy.rule.reorder',
            'policy.suggestion.accept', 'tools.publish', 'configuration.import'
        )
    ),
    resource_type text NOT NULL CHECK (resource_type IN ('policy', 'tools')),
    prior_version bigint CHECK (prior_version IS NULL OR prior_version >= 1),
    new_version bigint NOT NULL CHECK (new_version >= 1),
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    committed_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((actor_kind = 'system') = (actor_auth_mode = 'system')),
    CHECK (actor_kind = 'principal' OR actor_issuer IS NULL),
    CHECK (
        action = 'configuration.import'
        OR (resource_type = 'policy' AND action LIKE 'policy.%')
        OR (resource_type = 'tools' AND action = 'tools.publish')
    ),
    CHECK (prior_version IS NULL OR new_version > prior_version),
    UNIQUE (operation_id, action),
    -- Also the reconciliation index: an ambiguous commit response is resolved
    -- by asking which commit activated a version, not by retrying it.
    UNIQUE (resource_type, new_version)
);

CREATE TABLE greengateway.catalog_change_evidence (
    event_id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    actor_user_id text NOT NULL CHECK (
        octet_length(actor_user_id) BETWEEN 1 AND 4096
    ),
    action text NOT NULL CHECK (
        action IN (
            'catalog.mcp.publish', 'catalog.openapi.publish',
            'catalog.overlay.replace', 'catalog.overlay.delete'
        )
    ),
    connection_id uuid NOT NULL,
    prior_version bigint CHECK (prior_version IS NULL OR prior_version >= 1),
    new_version bigint NOT NULL CHECK (new_version >= 1),
    overlay_revision bigint CHECK (
        overlay_revision IS NULL OR overlay_revision >= 0
    ),
    security_revision bigint NOT NULL CHECK (security_revision >= 1),
    committed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (prior_version IS NULL OR new_version > prior_version),
    CHECK ((action = 'catalog.mcp.publish') = (overlay_revision IS NULL)),
    CHECK (action <> 'catalog.overlay.replace' OR overlay_revision >= 1),
    CHECK (action <> 'catalog.overlay.delete' OR overlay_revision = 0),
    UNIQUE (operation_id, action)
);

-- Reconciliation reads one Connection's catalog evidence in commit order:
-- an ambiguous publication response is resolved by asking what committed,
-- not by publishing again.
CREATE INDEX idx_ggw_catalog_change_evidence_connection
    ON greengateway.catalog_change_evidence(connection_id, security_revision);
