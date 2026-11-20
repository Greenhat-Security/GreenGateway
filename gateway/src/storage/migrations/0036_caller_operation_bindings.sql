-- Caller operation IDs bound to one request (issue #425). Migration 35
-- reserved caller keys for keyed service-token revocation and keyed
-- approval preparation only. Every other keyed action stores, beside its
-- key, the binding digest of the one request the key belongs to: a SHA-256
-- over the action, the recorded actor, the target, the precondition and the
-- request with secret values removed. The two earlier actions keep a NULL
-- digest and their own replay checks.
--
-- The constraints are added NOT VALID, as migrations 32 and 33 add theirs:
-- this table grows without bound (one row per keyed prepare), and validating
-- them would scan it under this migration's ACCESS EXCLUSIVE lock and its
-- statement timeout. Every existing row satisfies all three by construction:
-- migration 35 admits only the two earlier actions, and the new column is
-- NULL. A NOT VALID CHECK is still enforced on every insert and update.
-- Nothing is backfilled.
ALTER TABLE greengateway.authority_caller_operation_ids
    DROP CONSTRAINT authority_caller_operation_ids_action_check,
    ADD COLUMN binding_digest text;

ALTER TABLE greengateway.authority_caller_operation_ids
    ADD CONSTRAINT authority_caller_operation_ids_action_check CHECK (action IN (
        'service_token.revoke', 'mutation_approval.prepare',
        'service_token.issue', 'service_token.rotate',
        'connection.create', 'connection.replace', 'connection.delete',
        'catalog.mcp.publish', 'catalog.openapi.publish',
        'catalog.overlay.replace', 'catalog.overlay.delete',
        'policy.publish', 'policy.rollback', 'policy.rule.create',
        'policy.rule.update', 'policy.rule.delete', 'policy.rule.reorder',
        'policy.suggestion.accept', 'tools.publish', 'policy_tests.publish')) NOT VALID,
    ADD CONSTRAINT authority_caller_operation_ids_binding_digest_check
        CHECK (binding_digest ~ '^[0-9a-f]{64}$') NOT VALID,
    ADD CONSTRAINT authority_caller_operation_ids_binding_check CHECK (
        binding_digest IS NOT NULL
        OR action IN ('service_token.revoke', 'mutation_approval.prepare')) NOT VALID;
