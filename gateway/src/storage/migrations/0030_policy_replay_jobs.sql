-- Migration 30: durable historical policy replay jobs for cluster mode
-- (issue #243).
--
-- A replay job decides one window of the cluster audit stream again under a
-- candidate policy and the base it was written against. A row is one job,
-- shared by every replica: any replica serves its reads, and whichever
-- replica's worker claims it runs it. It is analysis state, not authority:
-- nothing here advances the security revision, writes the outbox or changes
-- what any replica enforces, and the job reads the audit stream only through
-- its own short read-only transactions.
--
-- - job_id is "rpl_" and 32 lowercase hex characters of operating-system
--   randomness. Every statement also matches the owner, so another
--   principal's job is indistinguishable from a missing one.
-- - owner_issuer and owner_subject are the starting principal's canonical
--   issuer (empty when it has none) and subject, bounded as authentication
--   bounds them. idempotency_key is the owner's optional key (at most 128
--   bytes), and request_digest the ADR-0004 source digest of the request
--   bytes: the same key with the same digest is the same job, a different
--   digest is a conflict. Admission serializes on a transaction-scoped
--   advisory lock, which is what keeps a key unique per owner; there is no
--   index over it, because the owner columns are wider than an index entry.
-- - actor_json, request_id and source_ip are the admitting request's audit
--   envelope, which every lifecycle event of the job carries whichever
--   replica records it. They are what the job's own policy.replay_started
--   event already holds, and they leave with the row.
-- - The pins are the active policy ETag the job was written against and its
--   document (base_json), and the candidate's source, ETag and document
--   (candidate_json, NULL when the candidate is the base itself), each the
--   validated document exactly as the gateway serialized it, at most 1 MiB.
--   A candidate read from a server-side draft names the draft and its
--   revision, and one read from the policy history names the version: which
--   document, never its content beyond candidate_json.
--   A replica that claims the job re-validates both and requires each to
--   reproduce its ETag. engine_version names the evaluator, replay-context,
--   checkpoint and result versions the job was admitted under: a replica of
--   any other engine never runs it, and marks it interrupted.
-- - The cutoff is the audit stream's high-water position when the job was
--   admitted, with the window's row count at or below it and the first and
--   last of their positions; with the window's bounds and the record bound
--   it fixes exactly which rows the job reads.
-- - state is admitting, queued, running, completed, completed_incomplete,
--   failed, cancelled or interrupted. A job is admitting until its
--   policy.replay_started event is accepted, and only then queued: no worker
--   claims an admitting job. interrupted is a job a replica took over but
--   could not continue: its pins or its checkpoint could not be rebuilt
--   under this engine, or it was taken over too often.
-- - A running job holds one lease: lease_holder (the replica's instance
--   identity), lease_fence (drawn from policy_replay_job_fence, so every
--   claim carries a larger fence than every earlier one) and
--   lease_expires_at, database time. Every write a holder makes names its
--   holder and fence; a job whose lease expired is claimed by the next worker
--   that asks, with a new fence, and the old holder's writes match nothing.
--   claims counts the claims that did not give the job back at shutdown.
-- - cursor_position is the last stream position the job has read and
--   checkpoint its whole partial aggregate after reading it (the
--   policy-replay-checkpoint.v1 document, at most 8 MiB as rendered here).
--   One statement writes both, under the fence, after every page, so a
--   takeover resumes from exactly the page after it and counts no record
--   twice. run_deadline_at is the job's run deadline, fixed at its first
--   claim and kept across takeovers.
-- - result is the policy-replay-results.v1 document of a completed job (at
--   most 2 MiB as rendered here; the gateway's own bound is far lower) and
--   result_digest its ADR-0004 semantic digest.
-- - Times are database time (ha-state-model.md section 2 rule 5).
--   finished_at, result_expires_at and expires_at are set together when a
--   job ends: its result is served until result_expires_at, the job answers
--   expired from then until expires_at, and retention deletes it after, in
--   bounded batches. A pending job has none of the three and is never
--   deleted or ended by retention; an admitting row whose replica never
--   recorded its start is, once it is older than the admission grace.
-- - Quotas (pending and unexpired jobs, per owner and per deployment) are
--   counted inside the admitting transaction under the advisory lock, so two
--   replicas cannot both take the last slot. No job is ever evicted for
--   another.

CREATE SEQUENCE greengateway.policy_replay_job_fence AS bigint;

CREATE TABLE greengateway.policy_replay_jobs (
    job_id text PRIMARY KEY CHECK (job_id ~ '^rpl_[0-9a-f]{32}$'),
    owner_issuer text NOT NULL CHECK (octet_length(owner_issuer) <= 4096),
    owner_subject text NOT NULL CHECK (
        octet_length(owner_subject) BETWEEN 1 AND 4096
    ),
    idempotency_key text CHECK (
        idempotency_key IS NULL OR octet_length(idempotency_key) BETWEEN 1 AND 128
    ),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    actor_json text NOT NULL CHECK (octet_length(actor_json) <= 65536),
    request_id text NOT NULL CHECK (octet_length(request_id) <= 4096),
    source_ip text NOT NULL CHECK (octet_length(source_ip) <= 4096),
    base_etag text NOT NULL CHECK (base_etag ~ '^"sha256:[0-9a-f]{64}"$'),
    base_json text NOT NULL CHECK (octet_length(base_json) <= 1048576),
    candidate_source text NOT NULL CHECK (
        candidate_source IN ('active', 'edits', 'inline', 'draft', 'revision')
    ),
    candidate_etag text NOT NULL CHECK (candidate_etag ~ '^"sha256:[0-9a-f]{64}"$'),
    candidate_json text CHECK (
        candidate_json IS NULL OR octet_length(candidate_json) <= 1048576
    ),
    edit_count integer NOT NULL CHECK (edit_count >= 0),
    candidate_draft_id text CHECK (
        candidate_draft_id IS NULL OR candidate_draft_id ~ '^pd_[0-9a-f]{32}$'
    ),
    candidate_draft_revision bigint CHECK (
        candidate_draft_revision IS NULL OR candidate_draft_revision >= 1
    ),
    candidate_version bigint CHECK (candidate_version IS NULL OR candidate_version >= 1),
    projections text NOT NULL CHECK (
        projections IN (
            'as_authored',
            'enforce_all_shadow',
            'as_authored,enforce_all_shadow',
            'enforce_all_shadow,as_authored'
        )
    ),
    engine_version text NOT NULL CHECK (octet_length(engine_version) BETWEEN 1 AND 512),
    window_from text NOT NULL CHECK (octet_length(window_from) BETWEEN 1 AND 64),
    window_to text NOT NULL CHECK (octet_length(window_to) BETWEEN 1 AND 64),
    from_epoch_us bigint NOT NULL,
    to_epoch_us bigint NOT NULL,
    high_water bigint NOT NULL CHECK (high_water >= 0),
    selected_records bigint NOT NULL CHECK (selected_records >= 0),
    first_position bigint,
    last_position bigint,
    max_records integer NOT NULL CHECK (max_records BETWEEN 1 AND 100000),
    state text NOT NULL CHECK (
        state IN (
            'admitting',
            'queued',
            'running',
            'completed',
            'completed_incomplete',
            'failed',
            'cancelled',
            'interrupted'
        )
    ),
    failure text CHECK (failure IS NULL OR failure ~ '^[a-z][a-z0-9_]{0,63}$'),
    cancel_requested boolean NOT NULL DEFAULT false,
    lease_holder uuid,
    lease_fence bigint,
    lease_expires_at timestamptz,
    claims integer NOT NULL DEFAULT 0 CHECK (claims >= 0),
    run_deadline_at timestamptz,
    cursor_position bigint,
    scanned_records bigint NOT NULL DEFAULT 0 CHECK (scanned_records >= 0),
    checkpoint jsonb CHECK (
        checkpoint IS NULL OR octet_length(checkpoint::text) <= 8388608
    ),
    result jsonb CHECK (result IS NULL OR octet_length(result::text) <= 2097152),
    result_digest text CHECK (
        result_digest IS NULL OR result_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    result_expires_at timestamptz,
    expires_at timestamptz,
    CHECK (to_epoch_us > from_epoch_us),
    -- The candidate is pinned as its source says: a document for every
    -- source but the base itself, and the draft or history version it was
    -- read as for those two sources only.
    CHECK ((candidate_source = 'active') = (candidate_json IS NULL)),
    CHECK ((candidate_source = 'draft') = (candidate_draft_id IS NOT NULL)),
    CHECK ((candidate_draft_id IS NULL) = (candidate_draft_revision IS NULL)),
    CHECK ((candidate_source = 'revision') = (candidate_version IS NOT NULL)),
    CHECK ((first_position IS NULL) = (last_position IS NULL)),
    CHECK (first_position IS NULL OR first_position <= last_position),
    CHECK (
        (lease_holder IS NULL) = (lease_fence IS NULL)
        AND (lease_fence IS NULL) = (lease_expires_at IS NULL)
    ),
    -- Only a running job holds a lease, and a running job always holds one.
    CHECK ((state = 'running') = (lease_holder IS NOT NULL)),
    CHECK ((cursor_position IS NULL) = (checkpoint IS NULL)),
    CHECK (checkpoint IS NULL OR state = 'running'),
    CHECK ((result IS NULL) = (result_digest IS NULL)),
    CHECK (result IS NULL OR state IN ('completed', 'completed_incomplete')),
    -- A job has ended exactly when it carries its ending times.
    CHECK (
        (state IN ('admitting', 'queued', 'running'))
        = (finished_at IS NULL AND result_expires_at IS NULL AND expires_at IS NULL)
    ),
    CHECK (
        finished_at IS NULL
        OR (result_expires_at >= finished_at AND expires_at >= result_expires_at)
    )
);

-- The claim: the oldest queued or running job.
CREATE INDEX idx_ggw_policy_replay_jobs_pending
    ON greengateway.policy_replay_jobs(created_at, job_id)
    WHERE state IN ('queued', 'running');

-- Retention: finished jobs past their retention.
CREATE INDEX idx_ggw_policy_replay_jobs_expires_at
    ON greengateway.policy_replay_jobs(expires_at)
    WHERE expires_at IS NOT NULL;
