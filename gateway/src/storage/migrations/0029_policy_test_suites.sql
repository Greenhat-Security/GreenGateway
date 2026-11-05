-- Migration 29: the stored policy test suite (issue #243).
--
-- A deployment keeps one exact-version policy-tests.v1 suite beside its
-- policy, as a versioned document under the HA state model's section 2
-- transaction, exactly as migration 4 keeps the policy document and
-- migration 5 the tools document:
--
-- - policy_test_suite_versions holds the immutable versions. Each row is
--   also the history entry: the actor's subject, a diff summary of counts
--   only, the suite as the API accepted it, and its strong ETag, which is
--   the suite's ADR-0004 semantic digest in quotes. Rows are never updated
--   or deleted; replacing the suite writes a NEW version.
-- - policy_test_suite_active is the singleton active pointer. Its
--   security_revision is the shared revision the active version was
--   committed at.
-- - Every commit advances greengateway.security_revision_state, appends one
--   greengateway.security_outbox row with resource_type 'policy_tests' and
--   one greengateway.document_change_evidence row with action
--   'policy_tests.publish', in the same transaction
--   (storage/postgres_documents.rs commit_in). Two writers holding one ETag
--   produce exactly one winner; a refused commit writes nothing.
--
-- A suite is not enforced: no replica compiles, reconciles or serves
-- traffic from it, and a test run reads it from this table on each request.
-- The security revision it advances is the shared counter every replica's
-- revision gate reads; a replica behind it confirms that none of its
-- reconciled resources changed and serves on, so a suite commit costs a
-- reconcile pass and no recompilation.
--
-- The document is a policy-tests.v1 suite the gateway's parser accepted
-- (1 to 512 cases, at most 2 MiB as RFC 8785 bytes); readers re-parse it and
-- require it to reproduce document_etag, so a row edited out of band is
-- refused, never served or run. The CHECKs below are the backstop: an
-- object, of exactly that schema version, under an ETag of the policy
-- ETag's shape.
--
-- document_change_evidence (migration 23) gains the resource and its one
-- action. Its three CHECKs naming actions and resource types are replaced
-- by wider ones under the same names; every row they accepted they still
-- accept, and 'configuration.import' stays limited to the policy and tools
-- documents, the only two the offline import activates. No test suite is
-- imported: a standalone deployment's stored suite stays in its policy
-- history database.

CREATE TABLE greengateway.policy_test_suite_versions (
    version bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    diff_summary jsonb NOT NULL,
    document jsonb NOT NULL CHECK (
        jsonb_typeof(document) = 'object'
        AND COALESCE(document ->> 'schema_version' = 'policy-tests.v1', false)
    ),
    document_etag text NOT NULL CHECK (
        document_etag ~ '^"sha256:[0-9a-f]{64}"$'
    )
);

CREATE INDEX idx_ggw_policy_test_suite_versions_created_at
    ON greengateway.policy_test_suite_versions(created_at DESC);

CREATE TABLE greengateway.policy_test_suite_active (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active_version bigint NOT NULL
        REFERENCES greengateway.policy_test_suite_versions(version),
    document_etag text NOT NULL,
    security_revision bigint NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE greengateway.document_change_evidence
    DROP CONSTRAINT document_change_evidence_action_check,
    DROP CONSTRAINT document_change_evidence_resource_type_check,
    DROP CONSTRAINT document_change_evidence_check2,
    ADD CONSTRAINT document_change_evidence_action_check CHECK (
        action IN (
            'policy.publish', 'policy.rollback', 'policy.rule.create',
            'policy.rule.update', 'policy.rule.delete', 'policy.rule.reorder',
            'policy.suggestion.accept', 'tools.publish', 'configuration.import',
            'policy_tests.publish'
        )
    ),
    ADD CONSTRAINT document_change_evidence_resource_type_check CHECK (
        resource_type IN ('policy', 'tools', 'policy_tests')
    ),
    ADD CONSTRAINT document_change_evidence_check2 CHECK (
        (action = 'configuration.import' AND resource_type IN ('policy', 'tools'))
        OR (resource_type = 'policy' AND action LIKE 'policy.%')
        OR (resource_type = 'tools' AND action = 'tools.publish')
        OR (resource_type = 'policy_tests' AND action = 'policy_tests.publish')
    );
