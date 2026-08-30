-- Migration 1: the cluster-mode schema epoch.
--
-- The schema and its ledger are created by the migrator's bootstrap; this
-- first migration records the schema's purpose and pins its existence in
-- the ledger, so every deployment's history starts at the same version
-- with the same checksum. Later migrations add the tables of PRs 5-13
-- (audit, control plane, authentication state, discovery, membership);
-- they must be additive-only until an explicit expand/contract release.

COMMENT ON SCHEMA greengateway IS
    'GreenGateway cluster-mode shared state (issue #241); lifecycle and rules: docs/deployment/postgres.md';
