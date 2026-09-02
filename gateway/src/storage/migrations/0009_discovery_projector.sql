-- Migration 9: durable observations and the fenced discovery projector
-- (issue #241, PR 11).
--
-- Standalone mode aggregates observed traffic on the audit writer thread
-- and flushes endpoint inventory to DISCOVERY_SQLITE_PATH, so N replicas
-- would keep N disagreeing inventories and N copies of every signal.
-- Cluster mode rejects that path. Observations already reach discovery as
-- audit events (http.request_observed), and the PostgreSQL audit store
-- ingests those idempotently by event_id onto a commit-ordered durable
-- stream; so ONE replica -- the elected projector -- reads that stream
-- after a checkpoint, runs the same in-memory aggregation the SQLite sink
-- runs, and flushes here. Every replica reads the result from these tables.
--
-- What is stored and why:
--
-- - The discovery_* tables mirror the SQLite sink's tables column for
--   column: the same names, timestamps as RFC 3339 text exactly as SQLite
--   stores them, bigint counts, and JSON as text (never jsonb: the values
--   are only ever round-tripped through serde and the reference stores
--   them as TEXT). Every text column is bounded so a row is bounded; the
--   projector refuses observations past the bounds before they reach the
--   working set, so a flush can never fail on a CHECK.
-- - discovery_detector_state holds each endpoint's serialized rolling
--   detector windows (the 20-sample recent-error window and the volume
--   baseline). The SQLite sink rebuilds these empty after a restart; the
--   projector persists them so a successor leader continues from the same
--   history and a threshold crossing is seen exactly once, on exactly one
--   leader.
-- - discovery_template_groups is the path-template learner's groups, so a
--   successor generalizes paths the way its predecessor did rather than
--   relearning and splitting the same endpoint into new templates.
-- - discovery_projector_state is the singleton the whole scheme hinges on:
--   fence is the execution-lease fence of the current leader (a claim
--   moves it only forward, so a stale leader's claim is refused); every
--   flush is one transaction that locks this row, verifies fence, applies
--   the batch, and advances checkpoint_position to the last stream
--   position the batch consumed. A crash between read and commit applies
--   nothing, and the successor resumes from the committed checkpoint; a
--   stale leader's late flush sees a newer fence and commits nothing.
--   projected_events counts observations applied, for operators.
--
-- Signals keep the SQLite UNIQUE identity (signal_type, target_kind,
-- target_key), so a threshold crossing inserts once cluster-wide and a
-- replayed flush is a no-op on it. Reviews and rule suggestions are
-- created here so the cluster read store (PR 11) and the suggestion
-- engine (PR 12) share the schema; the projector never writes them.
--
-- Audit retention (PR 13 owns the job) must never remove stream positions
-- the projector has not applied: it may trim only positions
-- <= discovery_projector_state.checkpoint_position.

CREATE TABLE greengateway.discovery_endpoint_aggregates (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    first_seen text NOT NULL CHECK (octet_length(first_seen) BETWEEN 1 AND 64),
    last_seen text NOT NULL CHECK (octet_length(last_seen) BETWEEN 1 AND 64),
    call_count bigint NOT NULL CHECK (call_count >= 0),
    schema_mismatch_count bigint NOT NULL DEFAULT 0 CHECK (schema_mismatch_count >= 0),
    latency_count bigint NOT NULL CHECK (latency_count >= 0),
    latency_p50_ms bigint NOT NULL CHECK (latency_p50_ms >= 0),
    latency_p95_ms bigint NOT NULL CHECK (latency_p95_ms >= 0),
    latency_p99_ms bigint NOT NULL CHECK (latency_p99_ms >= 0),
    -- At most LATENCY_SAMPLE_LIMIT (1024) u64 samples as a JSON array.
    latency_samples_json text NOT NULL CHECK (octet_length(latency_samples_json) BETWEEN 2 AND 32768),
    distinct_principal_count bigint NOT NULL CHECK (distinct_principal_count >= 0),
    updated_at text NOT NULL CHECK (octet_length(updated_at) BETWEEN 1 AND 64),
    PRIMARY KEY (method, endpoint_template)
);

CREATE INDEX idx_ggw_discovery_endpoint_last_seen
    ON greengateway.discovery_endpoint_aggregates(last_seen);

CREATE INDEX idx_ggw_discovery_endpoint_template
    ON greengateway.discovery_endpoint_aggregates(endpoint_template);

CREATE TABLE greengateway.discovery_endpoint_status_counts (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    status integer NOT NULL CHECK (status BETWEEN 0 AND 65535),
    count bigint NOT NULL CHECK (count >= 0),
    PRIMARY KEY (method, endpoint_template, status)
);

CREATE TABLE greengateway.discovery_endpoint_principals (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    user_id text NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
    issuer text NOT NULL DEFAULT '' CHECK (octet_length(issuer) <= 2048),
    auth_method text NOT NULL DEFAULT '' CHECK (octet_length(auth_method) <= 64),
    first_seen text NOT NULL CHECK (octet_length(first_seen) BETWEEN 1 AND 64),
    last_seen text NOT NULL CHECK (octet_length(last_seen) BETWEEN 1 AND 64),
    PRIMARY KEY (method, endpoint_template, user_id, issuer, auth_method)
);

CREATE TABLE greengateway.discovery_endpoint_routing_contexts (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    route_host text NOT NULL CHECK (octet_length(route_host) <= 1024),
    route_path_prefix text NOT NULL CHECK (octet_length(route_path_prefix) <= 2048),
    upstream_origin text NOT NULL CHECK (octet_length(upstream_origin) <= 2048),
    first_seen text NOT NULL CHECK (octet_length(first_seen) BETWEEN 1 AND 64),
    last_seen text NOT NULL CHECK (octet_length(last_seen) BETWEEN 1 AND 64),
    call_count bigint NOT NULL CHECK (call_count >= 0),
    distinct_principal_count bigint NOT NULL CHECK (distinct_principal_count >= 0),
    updated_at text NOT NULL CHECK (octet_length(updated_at) BETWEEN 1 AND 64),
    PRIMARY KEY (method, endpoint_template, route_host, route_path_prefix, upstream_origin)
);

CREATE INDEX idx_ggw_discovery_endpoint_routing_origin
    ON greengateway.discovery_endpoint_routing_contexts(upstream_origin);

CREATE TABLE greengateway.discovery_endpoint_routing_principals (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    route_host text NOT NULL CHECK (octet_length(route_host) <= 1024),
    route_path_prefix text NOT NULL CHECK (octet_length(route_path_prefix) <= 2048),
    upstream_origin text NOT NULL CHECK (octet_length(upstream_origin) <= 2048),
    user_id text NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
    issuer text NOT NULL DEFAULT '' CHECK (octet_length(issuer) <= 2048),
    auth_method text NOT NULL DEFAULT '' CHECK (octet_length(auth_method) <= 64),
    PRIMARY KEY (
        method,
        endpoint_template,
        route_host,
        route_path_prefix,
        upstream_origin,
        user_id,
        issuer,
        auth_method
    )
);

CREATE TABLE greengateway.discovery_endpoint_routing_classifications (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    first_classified_at text NOT NULL CHECK (octet_length(first_classified_at) BETWEEN 1 AND 64),
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE greengateway.discovery_endpoint_classified_signal_stats (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    call_count bigint NOT NULL CHECK (call_count >= 0),
    schema_mismatch_count bigint NOT NULL CHECK (schema_mismatch_count >= 0),
    error_count bigint NOT NULL CHECK (error_count >= 0),
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE greengateway.discovery_endpoint_classified_signal_principals (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    user_id text NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
    issuer text NOT NULL DEFAULT '' CHECK (octet_length(issuer) <= 2048),
    auth_method text NOT NULL DEFAULT '' CHECK (octet_length(auth_method) <= 64),
    PRIMARY KEY (method, endpoint_template, user_id, issuer, auth_method)
);

CREATE TABLE greengateway.discovery_payload_shape_stats (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    shape_observation_count bigint NOT NULL CHECK (shape_observation_count >= 0),
    updated_at text NOT NULL CHECK (octet_length(updated_at) BETWEEN 1 AND 64),
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE greengateway.discovery_payload_shape_samples (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    -- At most PAYLOAD_SHAPE_SAMPLE_LIMIT (128) slots per endpoint.
    sample_slot integer NOT NULL CHECK (sample_slot BETWEEN 0 AND 127),
    observed_at text NOT NULL CHECK (octet_length(observed_at) BETWEEN 1 AND 64),
    shape_hash text NOT NULL CHECK (octet_length(shape_hash) BETWEEN 1 AND 128),
    -- MAX_PAYLOAD_SHAPE_SAMPLE_BYTES: the aggregator never admits a larger shape.
    shape_json text NOT NULL CHECK (octet_length(shape_json) BETWEEN 1 AND 16384),
    PRIMARY KEY (method, endpoint_template, sample_slot)
);

CREATE INDEX idx_ggw_discovery_payload_shape_template
    ON greengateway.discovery_payload_shape_samples(endpoint_template);

CREATE TABLE greengateway.discovery_endpoint_reviews (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    reviewed_at text NOT NULL CHECK (octet_length(reviewed_at) BETWEEN 1 AND 64),
    reviewed_by text CHECK (reviewed_by IS NULL OR octet_length(reviewed_by) <= 512),
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE greengateway.discovery_signals (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 64),
    signal_type text NOT NULL CHECK (octet_length(signal_type) BETWEEN 1 AND 64),
    target_kind text NOT NULL CHECK (target_kind IN ('endpoint', 'principal_endpoint')),
    -- "{method} {endpoint_template}" or that plus the principal identity.
    target_key text NOT NULL CHECK (octet_length(target_key) BETWEEN 1 AND 16384),
    target_identity_json text NOT NULL CHECK (octet_length(target_identity_json) BETWEEN 2 AND 32768),
    explanation text NOT NULL CHECK (octet_length(explanation) BETWEEN 1 AND 32768),
    evidence_json text NOT NULL CHECK (octet_length(evidence_json) BETWEEN 2 AND 65536),
    state text NOT NULL CHECK (state IN ('open', 'acknowledged', 'dismissed')),
    created_at text NOT NULL CHECK (octet_length(created_at) BETWEEN 1 AND 64),
    updated_at text NOT NULL CHECK (octet_length(updated_at) BETWEEN 1 AND 64),
    transitioned_at text CHECK (transitioned_at IS NULL OR octet_length(transitioned_at) <= 64),
    transitioned_by text CHECK (transitioned_by IS NULL OR octet_length(transitioned_by) <= 512)
);

-- The cluster-wide signal identity: one row per threshold crossing, and the
-- projector's INSERT ... ON CONFLICT DO NOTHING infers this index.
CREATE UNIQUE INDEX idx_ggw_discovery_signals_identity
    ON greengateway.discovery_signals(signal_type, target_kind, target_key);

CREATE INDEX idx_ggw_discovery_signals_state_created
    ON greengateway.discovery_signals(state, created_at, id);

CREATE TABLE greengateway.discovery_rule_suggestions (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 64),
    suggestion_type text NOT NULL CHECK (octet_length(suggestion_type) BETWEEN 1 AND 64),
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    path_pattern text NOT NULL CHECK (octet_length(path_pattern) BETWEEN 1 AND 8192),
    principal_key text NOT NULL CHECK (octet_length(principal_key) <= 4096),
    proposed_rule_json text NOT NULL CHECK (octet_length(proposed_rule_json) BETWEEN 2 AND 65536),
    rationale text NOT NULL CHECK (octet_length(rationale) BETWEEN 1 AND 32768),
    evidence_json text NOT NULL CHECK (octet_length(evidence_json) BETWEEN 2 AND 65536),
    state text NOT NULL CHECK (state IN ('open', 'accepted', 'dismissed')),
    created_at text NOT NULL CHECK (octet_length(created_at) BETWEEN 1 AND 64),
    updated_at text NOT NULL CHECK (octet_length(updated_at) BETWEEN 1 AND 64),
    transitioned_at text CHECK (transitioned_at IS NULL OR octet_length(transitioned_at) <= 64),
    transitioned_by text CHECK (transitioned_by IS NULL OR octet_length(transitioned_by) <= 512),
    source_signal_id text CHECK (source_signal_id IS NULL OR octet_length(source_signal_id) <= 64)
);

CREATE UNIQUE INDEX idx_ggw_discovery_rule_suggestions_identity
    ON greengateway.discovery_rule_suggestions(suggestion_type, method, path_pattern, principal_key);

CREATE INDEX idx_ggw_discovery_rule_suggestions_state_created
    ON greengateway.discovery_rule_suggestions(state, created_at, id);

CREATE INDEX idx_ggw_discovery_rule_suggestions_source_signal
    ON greengateway.discovery_rule_suggestions(source_signal_id);

-- Serialized ClassifiedSignalState per endpoint (counters, distinct
-- principals, the recent-error window, the volume baseline). A state that
-- would exceed the bound is not written (its row is removed), and the
-- successor falls back to the counters in the tables above -- the SQLite
-- restart behaviour -- rather than the flush failing.
CREATE TABLE greengateway.discovery_detector_state (
    method text NOT NULL CHECK (octet_length(method) BETWEEN 1 AND 64),
    endpoint_template text NOT NULL CHECK (octet_length(endpoint_template) BETWEEN 1 AND 8192),
    state_json text NOT NULL CHECK (octet_length(state_json) BETWEEN 2 AND 65536),
    PRIMARY KEY (method, endpoint_template)
);

-- The path-template learner's groups (PathTemplateLearner::export_groups_json).
CREATE TABLE greengateway.discovery_template_groups (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    groups_json text NOT NULL CHECK (octet_length(groups_json) BETWEEN 2 AND 4194304),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE greengateway.discovery_projector_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
    checkpoint_position bigint NOT NULL DEFAULT 0 CHECK (checkpoint_position >= 0),
    projected_events bigint NOT NULL DEFAULT 0 CHECK (projected_events >= 0),
    leader_instance uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO greengateway.discovery_projector_state (singleton) VALUES (true);
