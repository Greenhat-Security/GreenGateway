-- Migration 21: server-side policy drafts (issue #243, slice 9).
--
-- A draft is an owner-scoped, expiring candidate policy pinned to the live
-- policy ETag it was edited from. It is a workspace, not authority: no
-- replica compiles, enforces or reconciles anything from this table, and a
-- draft becomes enforcement only when its owner publishes it, which commits
-- the candidate through the ordinary policy control-plane transaction
-- (migration 4) under the live If-Match. Nothing here advances the
-- security revision or writes the outbox.
--
-- - draft_id is "pd_" and 32 lowercase hex characters of operating-system
--   randomness. Unpredictable identifiers are defense in depth only: every
--   statement also matches the owner, so another principal's draft is
--   indistinguishable from a missing one.
-- - owner_issuer and owner_subject are the creating principal's canonical
--   issuer (empty when it has none) and subject, bounded by exactly the
--   bounds authentication enforces (auth/principal.rs
--   MAX_PRINCIPAL_ISSUER_BYTES and MAX_PRINCIPAL_SUBJECT_BYTES). No email,
--   roles or session identifiers are stored.
-- - revision starts at 1 and advances on every write; a write names the
--   revision it read (compare-and-set), so concurrent writers holding one
--   revision produce exactly one winner. The API's strong draft ETag is
--   derived from it.
-- - base_etag is the live policy ETag the candidate was edited from, and
--   candidate_etag the ETag the candidate itself would carry; both have the
--   policy ETag's exact shape. A draft whose base is no longer live is
--   refused at publication, never rebased silently. published_etag is set
--   once, by a successful publication, and freezes the draft.
-- - candidate_json is the validated policy document exactly as the gateway
--   serialized it, bounded at 1 MiB -- the same byte count the API checks
--   before writing, which a jsonb rendering would not reproduce. Readers
--   re-validate it and require it to reproduce candidate_etag.
-- - Times are database time (ha-state-model.md section 2 rule 5). A draft
--   expires 24 hours after its last write. Expired rows are refused by
--   every statement, never counted against a quota, and deleted in bounded
--   batches by later creates; the expiry index serves that prune.
-- - Quotas (8 unexpired drafts per owner, 128 per deployment) are counted
--   inside the inserting transaction under a transaction-scoped advisory
--   lock, so two replicas cannot both take the last slot. With the size
--   bound they cap the table at 128 MiB of live candidates.

CREATE TABLE greengateway.policy_drafts (
    draft_id text PRIMARY KEY CHECK (draft_id ~ '^pd_[0-9a-f]{32}$'),
    owner_issuer text NOT NULL CHECK (octet_length(owner_issuer) <= 4096),
    owner_subject text NOT NULL CHECK (
        octet_length(owner_subject) BETWEEN 1 AND 4096
    ),
    revision bigint NOT NULL CHECK (revision >= 1),
    base_etag text NOT NULL CHECK (base_etag ~ '^"sha256:[0-9a-f]{64}"$'),
    candidate_json text NOT NULL CHECK (octet_length(candidate_json) <= 1048576),
    candidate_etag text NOT NULL CHECK (
        candidate_etag ~ '^"sha256:[0-9a-f]{64}"$'
    ),
    published_etag text CHECK (
        published_etag IS NULL OR published_etag ~ '^"sha256:[0-9a-f]{64}"$'
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (expires_at > updated_at)
);

CREATE INDEX idx_ggw_policy_drafts_expires_at
    ON greengateway.policy_drafts(expires_at);
