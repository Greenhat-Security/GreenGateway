-- Discovery suggestions bound to what they were generated against (issue
-- #243, checklist item 19). A generation run records, with every suggestion
-- it writes or rebinds, the generator and evidence schema versions, the
-- evidence cutoff (when the run started, as the RFC 3339 text the run wrote,
-- like every other timestamp of this table), the semantic digest of the
-- suggestion's evidence, the authoritative policy ETag and semantic digest
-- the run filtered against, and the policy resource snapshot: its digest,
-- whether it was complete, and its components without the cluster security
-- revision. Freshness is computed from these on every read and never
-- stored.
--
-- Every column is nullable, with no default and no backfill: a row written
-- before this migration, or imported from a standalone deployment, has no
-- binding, reads as unbound, and is never accepted through
-- `POST .../suggestions/{id}/accept` until a generation run rebinds it.
-- A recorded binding is all or nothing; inside one, the policy semantic
-- digest (0.x documents have none) and the snapshot digest may be NULL.
--
-- The constraints are added NOT VALID, as migrations 32, 33 and 36 add
-- theirs, so no scan runs under this migration's ACCESS EXCLUSIVE lock.
-- Every existing row satisfies them, because every new column is NULL. A
-- NOT VALID CHECK is still enforced on every insert and update. The runtime
-- role's existing grants on the table cover the new columns.
ALTER TABLE greengateway.discovery_rule_suggestions
    ADD COLUMN generator_version text,
    ADD COLUMN evidence_schema_version text,
    ADD COLUMN evidence_cutoff text,
    ADD COLUMN evidence_digest text,
    ADD COLUMN binding_policy_etag text,
    ADD COLUMN binding_policy_semantic_digest text,
    ADD COLUMN binding_resource_snapshot_digest text,
    ADD COLUMN binding_resource_snapshot_complete boolean,
    ADD COLUMN binding_resource_components text;

ALTER TABLE greengateway.discovery_rule_suggestions
    ADD CONSTRAINT discovery_rule_suggestions_binding_complete_check CHECK (
        (generator_version IS NULL
            AND evidence_schema_version IS NULL
            AND evidence_cutoff IS NULL
            AND evidence_digest IS NULL
            AND binding_policy_etag IS NULL
            AND binding_policy_semantic_digest IS NULL
            AND binding_resource_snapshot_digest IS NULL
            AND binding_resource_snapshot_complete IS NULL
            AND binding_resource_components IS NULL)
        OR (generator_version IS NOT NULL
            AND evidence_schema_version IS NOT NULL
            AND evidence_cutoff IS NOT NULL
            AND evidence_digest IS NOT NULL
            AND binding_policy_etag IS NOT NULL
            AND binding_resource_snapshot_complete IS NOT NULL
            AND binding_resource_components IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_generator_version_check CHECK (
        octet_length(generator_version) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_evidence_schema_version_check CHECK (
        octet_length(evidence_schema_version) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_evidence_cutoff_check CHECK (
        octet_length(evidence_cutoff) BETWEEN 1 AND 64) NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_evidence_digest_check CHECK (
        evidence_digest ~ '^sha256:[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_binding_policy_etag_check CHECK (
        binding_policy_etag ~ '^"sha256:[0-9a-f]{64}"$') NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_binding_policy_semantic_digest_check CHECK (
        binding_policy_semantic_digest ~ '^sha256:[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_binding_resource_snapshot_digest_check CHECK (
        binding_resource_snapshot_digest ~ '^sha256:[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT discovery_rule_suggestions_binding_resource_components_check CHECK (
        octet_length(binding_resource_components) BETWEEN 2 AND 4096) NOT VALID;
