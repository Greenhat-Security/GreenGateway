-- Migration 28: policy analysis suppressions (issue #243, slice 15).
--
-- A suppression is an operator's reviewed decision that one structural
-- analyzer finding needs no change until a stated time. It is advisory
-- review state, not authority: no replica compiles, enforces or reconciles
-- anything from this table, and a suppression changes no authorization
-- decision. An analysis marks a finding suppressed only when the finding's
-- fingerprint and code, the analyzed policy's ETag and semantic digest and
-- the resource snapshot digest all equal a row's and the row has not ended;
-- an ended or mismatched row is reported as such and hides nothing. Nothing
-- here advances the security revision or writes the outbox.
--
-- - suppression_id is "pas_" and 32 lowercase hex characters of
--   operating-system randomness.
-- - fingerprint and code name the finding: the analyzer's "sha256:"
--   fingerprint and its stable code.
-- - reason is the operator's bounded justification (1 to 512 bytes, no
--   control characters). It is shown to policy readers who may analyze and
--   never enters an audit event, a metric or an analysis report.
-- - actor_issuer and actor_subject are the creating principal's canonical
--   issuer (empty when it has none) and subject, bounded by exactly the
--   bounds authentication enforces. No email, roles or session identifiers
--   are stored.
-- - policy_etag, policy_semantic_digest and resource_snapshot_digest are
--   the binding: the policy the finding was reviewed in (its semantic digest
--   only for a document format that has one, policy v1) and the resource
--   snapshot it was reviewed against.
-- - Times are database time (ha-state-model.md section 2 rule 5). A row
--   expires at most 90 days after its creation; withdrawing it ends it at
--   once and moves revision from 1 to 2, the only change a row ever takes.
--   Writes name the revision they read (compare-and-set).
-- - At most 256 rows that have not ended may exist, counted inside the
--   inserting transaction under a transaction-scoped advisory lock, so two
--   replicas cannot both take the last slot. Ended rows stay readable until
--   a create needs their room, earliest-ended first, so the table never
--   holds more than 256 rows.

CREATE TABLE greengateway.policy_analysis_suppressions (
    suppression_id text PRIMARY KEY CHECK (suppression_id ~ '^pas_[0-9a-f]{32}$'),
    revision bigint NOT NULL CHECK (revision IN (1, 2)),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9_]{0,63}$'),
    reason text NOT NULL CHECK (
        octet_length(reason) BETWEEN 1 AND 512
        AND btrim(reason) <> ''
        AND reason !~ '[[:cntrl:]]'
    ),
    actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) <= 4096),
    actor_subject text NOT NULL CHECK (
        octet_length(actor_subject) BETWEEN 1 AND 4096
    ),
    policy_etag text NOT NULL CHECK (policy_etag ~ '^"sha256:[0-9a-f]{64}"$'),
    policy_semantic_digest text CHECK (
        policy_semantic_digest IS NULL
        OR policy_semantic_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    resource_snapshot_digest text NOT NULL CHECK (
        resource_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '90 days'),
    CHECK (
        withdrawn_at IS NULL
        OR (withdrawn_at >= created_at AND withdrawn_at < expires_at)
    ),
    CHECK ((revision = 1) = (withdrawn_at IS NULL))
);
