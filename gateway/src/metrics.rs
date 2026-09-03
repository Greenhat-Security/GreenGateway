pub const LOCK_POISON_RECOVERIES_TOTAL: &str = "lock_poison_recoveries_total";
pub const INBOUND_TLS_HANDSHAKES_TOTAL: &str = "inbound_tls_handshakes_total";
pub const INBOUND_TLS_HANDSHAKES_IN_FLIGHT: &str = "inbound_tls_handshakes_in_flight";
/// Inbound certificate material reloads, per listener.
///
/// Every label value is a compile-time constant. A rejected reload keeps the
/// last good chains serving, so `outcome="rejected"` is the counter that says
/// a rotation did *not* take effect and the previous certificate is still
/// being served -- the thing to alert on when a certificate's expiry is
/// approaching.
pub const INBOUND_TLS_RELOADS_TOTAL: &str = "inbound_tls_reloads_total";
/// Inbound TLS material-watcher liveness, per listener.
///
/// Every label value is a compile-time constant. The counter advances on a
/// fixed interval while the file-watching task is running; a value that stops
/// advancing means the watcher is dead and certificate reloads will silently
/// not happen -- rotation believed working is the failure this makes
/// observable. It does not cover the SIGHUP handler, which is a separate task
/// with the same uninstrumented-death exposure the `TOOLS_FILE` and
/// `POLICY_FILE` watchers have.
pub const INBOUND_TLS_WATCH_HEARTBEATS_TOTAL: &str = "inbound_tls_watch_heartbeats_total";
/// Live rate-limit buckets, per limiter.
///
/// Every label value is a compile-time constant: `read` and `write` for the
/// two global lanes, `policy` for every policy rate-limit rule (rule sets
/// change across reloads, and a per-rule label would mint and abandon time
/// series with every policy edit). A rate-limit key is never a label -- keys
/// are caller-influenced, so labelling by them would hand an attacker the
/// time-series cardinality the bucket ceiling exists to bound. A value pinned
/// at `RATE_LIMIT_MAX_BUCKETS` with evictions climbing is the signal that the
/// working set no longer fits and callers are being recycled.
pub const RATE_LIMIT_BUCKETS: &str = "rate_limit_buckets";
/// Rate-limit bucket evictions, per limiter and reason.
///
/// `reason="capacity"` means the store was full and a bucket was recycled to
/// admit a new key; `reason="ttl"` means an idle-beyond-`RATE_LIMIT_BUCKET_TTL_MS`
/// bucket was preferred for eviction. Eviction resets the evicted key's
/// allowance, so sustained `capacity` evictions are the signal that the
/// working set no longer fits and callers are being traded bursts -- raise
/// `RATE_LIMIT_MAX_BUCKETS` or investigate the key cardinality. Sustained
/// `ttl` evictions on a full store are the healthy steady state: newcomers
/// arriving, idlers naturally recycled, active callers protected.
pub const RATE_LIMIT_BUCKET_EVICTIONS_TOTAL: &str = "rate_limit_bucket_evictions_total";
/// Shared (cluster) rate-limit decisions by lane and outcome
/// (`allowed`, `denied`, `unavailable`); issue #241, PR 10.
#[cfg(feature = "postgres")]
pub const RATE_LIMIT_SHARED_DECISIONS_TOTAL: &str =
    "greengateway_rate_limit_shared_decisions_total";
/// Live members of the deployment's roster (`cluster_members` rows whose
/// heartbeat is inside `CLUSTER_MEMBER_STALE_MS`), as counted by the
/// maintenance leader on each stale sweep; issue #241, PR 13. Reported by
/// the leader only, so a replica that is not leading holds the last value
/// it set while it led (or nothing).
#[cfg(feature = "postgres")]
pub const CLUSTER_MEMBERS_LIVE: &str = "greengateway_cluster_members_live";
/// Singleton maintenance job runs by job and outcome (`success`,
/// `failure`); issue #241, PR 13. Every label value is a compile-time
/// constant: the job names are fixed, and a failure's classification goes
/// to the ledger's `last_failure_code`, not to a label.
#[cfg(feature = "postgres")]
pub const CLUSTER_MAINTENANCE_JOB_RUNS_TOTAL: &str =
    "greengateway_cluster_maintenance_job_runs_total";
/// Whether this replica currently holds the maintenance lease: `1` while
/// it leads, `0` otherwise; issue #241, PR 13. Summed across the
/// deployment it must read `1`; `0` for longer than the acquisition
/// backoff means no replica can take the lease, and `2` means the lease
/// authority is being lied to.
#[cfg(feature = "postgres")]
pub const CLUSTER_MAINTENANCE_LEADER: &str = "greengateway_cluster_maintenance_leader";
// --- HA state and cluster health (issue #241, PR 14) -------------------------
//
// Everything below answers one operator question: is this replica, and the
// deployment it belongs to, healthy enough to be sent traffic -- and if not,
// which of the state model's failure conditions is the one to fix? The
// `/readyz` reason and the cluster status view answer that for a human; these
// answer it for an alerting rule, at the point in the process that owns the
// value.
//
// **The cardinality rule, which is not negotiable here.** Every label value
// below is drawn from a *fixed enum*: a `&'static str` constant, a variant
// name, or a value the compiler can enumerate. Nothing caller-influenced --
// an instance id, a principal, a proxied route, a host, a URL, a token id, a
// query, an error string -- is ever a label, because a metric label is
// unbounded state the process keeps forever and hands to every scrape. Where
// the interesting value *is* high-cardinality (which instance, which error
// text), it goes to the roster row, the audit event, or the log, all of which
// are bounded and access-controlled; the metric keeps the classified kind.
// `the_ha_registry_never_labels_by_caller_influenced_values` walks the
// rendered registry after a synthetic run and enforces this.
//
// Names carry the `greengateway_` prefix that PRs 10 and 13 established for
// cluster metrics, so a deployment's HA series are one selectable family.

/// Whether this replica's lifecycle phase is `ready`: `1` while it is
/// serving, `0` while starting or draining. Paired with
/// [`GATEWAY_DRAINING`] so `starting` (both `0`) is distinguishable from
/// `draining` (`ready=0`, `draining=1`); the pair is the process's own
/// view, which is exactly the lifecycle half of `/readyz` and deliberately
/// says nothing about the authority-backed reasons.
pub const GATEWAY_READY: &str = "greengateway_gateway_ready";

/// Whether this replica has begun draining: `1` from the moment the
/// lifecycle cancels background work, `0` before. One-way within a boot.
pub const GATEWAY_DRAINING: &str = "greengateway_gateway_draining";

/// HTTP requests inside the observation layer right now.
///
/// The gauge is maintained by a guard, so a request that is cancelled,
/// panics, or ends in an early rejection still decrements it. A value that
/// climbs while throughput does not is the shape of a stalled upstream or
/// an exhausted pool; a value that does not fall during a drain is the
/// shape of a shutdown that will hit its deadline.
pub const INFLIGHT_REQUESTS: &str = "greengateway_inflight_requests";

/// Events waiting in the audit writer's channel, and the channel's bound.
///
/// Sampled when `/metrics` is scraped, because the queue has no periodic
/// owner: the writer thread is a blocking consumer and publishing from it
/// would sample only the moments it happens to be awake. Depth approaching
/// capacity is the precondition for [`crate::audit::AUDIT_EVENTS_DROPPED_TOTAL`]
/// beginning to count, which is the fact that matters -- audit events are
/// the record of what the gateway decided, and a dropped one is gone.
pub const AUDIT_QUEUE_DEPTH: &str = "greengateway_audit_queue_depth";

/// The audit channel's bound, so a depth can be read as a fraction of it
/// without the reader hard-coding the constant.
pub const AUDIT_QUEUE_CAPACITY: &str = "greengateway_audit_queue_capacity";

/// How long the oldest audit event the writer has not finished delivering
/// has been waiting, in seconds; `0` while the writer is idle.
///
/// Depth alone hides the worst case: a sink stuck on one event has an
/// empty queue behind it and an age that climbs without bound.
pub const AUDIT_QUEUE_OLDEST_AGE_SECONDS: &str = "greengateway_audit_queue_oldest_age_seconds";

/// Audit sink flushes by outcome (`success`, `failure`).
///
/// Both label values are compile-time constants. The failure's cause goes
/// to the log and to `audit_sqlite_flush_errors_total`'s operation label;
/// the error text is never a label.
pub const AUDIT_FLUSH_TOTAL: &str = "greengateway_audit_flush_total";

/// Execution-lease failures by classified kind (`lost`, `renew_expired`,
/// `release_failed`); issue #241, PR 14.
///
/// Every label value is a compile-time constant from
/// [`crate::tools::lease::LEASE_FAILURE_KINDS`]. The lease *scope* is not a
/// label: a scope is `tool:<name>`, so labelling by it would mint a time
/// series per tool name, and tool names are control-plane data.
pub const EXECUTION_LEASE_FAILURES_TOTAL: &str = "greengateway_execution_lease_failures_total";

/// The migration ledger's compatibility with this binary's manifest: `1`
/// when the ledger is a checksum-matching prefix covering it, `0`
/// otherwise; issue #241, PR 14. Set once at startup validation and again
/// whenever the ledger is re-read.
///
/// `0` on a serving replica is `/readyz`'s `schema_incompatible`: another
/// gateway migrated the database out from under this one.
#[cfg(feature = "postgres")]
pub const SCHEMA_COMPATIBLE: &str = "greengateway_schema_compatible";

/// How long the migrator waited for the schema advisory lock, in seconds.
///
/// A second migrator waiting behind a slow first one is the healthy case
/// and shows here as one long observation; a distribution that is long on
/// every boot means migrations are contending with something that is not
/// another migrator.
#[cfg(feature = "postgres")]
pub const MIGRATION_LOCK_WAIT_SECONDS: &str = "greengateway_migration_lock_wait_seconds";

/// Connections the database pool holds, has free, and has callers queued
/// for (deadpool's `Pool::status()`), sampled at scrape.
///
/// `available` pinned at `0` with `waiting` climbing is the pool
/// saturation that becomes `storage_unavailable` once checkouts start
/// timing out.
#[cfg(feature = "postgres")]
pub const DATABASE_POOL_SIZE: &str = "greengateway_database_pool_size";

/// See [`DATABASE_POOL_SIZE`].
#[cfg(feature = "postgres")]
pub const DATABASE_POOL_AVAILABLE: &str = "greengateway_database_pool_available";

/// See [`DATABASE_POOL_SIZE`].
#[cfg(feature = "postgres")]
pub const DATABASE_POOL_WAITING: &str = "greengateway_database_pool_waiting";

/// Pool checkouts that timed out since boot.
///
/// Counted at [`crate::storage::postgres::classify_pool_error`], the one
/// choke point every checkout failure passes through, so the count is
/// complete rather than a sample of the callers somebody remembered to
/// instrument. `Pool::status()` keeps no history, so a burst that has
/// already cleared leaves no trace in the gauges above -- this is the
/// series that remembers it.
#[cfg(feature = "postgres")]
pub const DATABASE_POOL_TIMEOUTS_TOTAL: &str = "greengateway_database_pool_timeouts_total";

/// Store operation latency by operation and classified outcome.
///
/// `operation` is one of the stores' `OPERATION_*` constants -- a fixed,
/// compile-time set naming *what was asked of the store*, never the
/// statement text, the parameters, or the rows. `error_class` is
/// `none` on success and a [`crate::storage::RepositoryErrorKind`] name
/// otherwise; SQLSTATEs and driver messages stay in the log.
#[cfg(feature = "postgres")]
pub const DATABASE_OPERATION_SECONDS: &str = "greengateway_database_operation_seconds";

/// The security revision at which every registered resource is confirmed
/// current on this replica (the compiled watermark), the authority's
/// counter as this replica last read it, and the difference.
///
/// The lag is the number the per-request gate acts on: while it is
/// non-zero the gate is reconciling, and once it stays non-zero past the
/// reconcile deadline `/readyz` refuses with
/// `security_revision_not_compiled`. Publishing all three rather than the
/// lag alone is deliberate -- a lag of 3 means something different when
/// the authority is at 4 than when it is at 4000.
#[cfg(feature = "postgres")]
pub const SECURITY_REVISION_COMPILED: &str = "greengateway_security_revision_compiled";

/// See [`SECURITY_REVISION_COMPILED`].
#[cfg(feature = "postgres")]
pub const SECURITY_REVISION_CURRENT: &str = "greengateway_security_revision_current";

/// See [`SECURITY_REVISION_COMPILED`].
#[cfg(feature = "postgres")]
pub const SECURITY_REVISION_LAG: &str = "greengateway_security_revision_lag";

/// Background security-reconcile passes that failed, by reason.
///
/// Every label value is one of
/// [`crate::middleware::rbac::SecurityRevisionCheckError::as_str`]'s three
/// classifications: the authority could not be read, the bounded deadline
/// passed with the replica still behind, or the authoritative document
/// could not be compiled by this binary. Which document, and why it did
/// not compile, goes to the log.
#[cfg(feature = "postgres")]
pub const RECONCILE_FAILURES_TOTAL: &str = "greengateway_reconcile_failures_total";

/// How long ago this replica's membership heartbeat last landed, in
/// seconds. Once it exceeds `CLUSTER_MEMBER_STALE_MS` the deployment's
/// roster has stopped counting this replica as live and `/readyz` refuses
/// with `instance_lease_invalid`, whatever the replica itself believes.
#[cfg(feature = "postgres")]
pub const CLUSTER_HEARTBEAT_AGE_SECONDS: &str = "greengateway_cluster_heartbeat_age_seconds";

/// Whether this replica is still withholding readiness on the
/// static-configuration fingerprint: `1` while it disagrees with a live
/// member, `0` once agreement is granted (which is sticky).
///
/// Summed across a deployment this is the count of replicas held at the
/// door by a rollout that changed security-relevant configuration.
#[cfg(feature = "postgres")]
pub const CLUSTER_CONFIG_MISMATCH: &str = "greengateway_cluster_config_mismatch";

/// How long this replica has held a singleton lease, in seconds, per
/// scope.
///
/// `scope` is one of the two *singleton* scopes ([`crate::tools::lease::LEASE_SCOPE_MAINTENANCE`],
/// [`crate::tools::lease::LEASE_SCOPE_DISCOVERY_PROJECTOR`]) and nothing
/// else: per-tool lease scopes are `tool:<name>`, which is control-plane
/// data and would mint a series per tool. `0` (or absent) on every replica
/// for longer than the acquisition backoff means nobody is leading.
#[cfg(feature = "postgres")]
pub const CLUSTER_LEASE_AGE_SECONDS: &str = "greengateway_cluster_lease_age_seconds";

/// How long ago each singleton maintenance job last succeeded, in
/// seconds, as the leader read it back from the fenced ledger.
///
/// `task` is one of `cluster_maintenance`'s `JOB_*` constants. Reported by
/// the leader only, from the ledger rather than from the leader's own
/// memory, so a job that has been failing across several leader terms
/// still shows its true age. Absent for a job that has never succeeded --
/// which reads correctly as "no successful run to be a certain age", and
/// is why this is not `0`.
#[cfg(feature = "postgres")]
pub const LEADER_TASK_LAST_SUCCESS_AGE_SECONDS: &str =
    "greengateway_leader_task_last_success_age_seconds";

/// The discovery projector's committed checkpoint position, and how many
/// durable stream positions sit between it and the audit stream's head.
///
/// Reported by the leading replica on each batch. A lag that grows without
/// bound means the projector is not keeping up with observation volume;
/// a checkpoint that stops advancing while the lag grows means it is
/// wedged.
#[cfg(feature = "postgres")]
pub const DISCOVERY_PROJECTOR_CHECKPOINT: &str = "greengateway_discovery_projector_checkpoint";

/// See [`DISCOVERY_PROJECTOR_CHECKPOINT`].
#[cfg(feature = "postgres")]
pub const DISCOVERY_PROJECTOR_LAG_EVENTS: &str = "greengateway_discovery_projector_lag_events";

/// Discovery projector failures by classified kind.
///
/// Every label value is a compile-time constant from
/// [`crate::discovery::projector::PROJECTOR_ERROR_KINDS`], naming the step
/// of a leader's term that failed. Neither the observation that was
/// dropped nor the store error's text is ever a label: observations carry
/// caller-controlled paths and principals, which is precisely the material
/// that must not become a time series.
#[cfg(feature = "postgres")]
pub const DISCOVERY_PROJECTOR_ERRORS_TOTAL: &str = "greengateway_discovery_projector_errors_total";

/// Durable audit-stream (SSE) connection attempts by outcome.
///
/// Every label value is a compile-time constant from
/// [`crate::AUDIT_STREAM_OUTCOMES`]: a live tail, a replay from a
/// `Last-Event-ID`, a header that was not a position, a cursor older than
/// the retained window, or an authority that could not be consulted. The
/// cursor value itself is caller-controlled and is never a label.
#[cfg(feature = "postgres")]
pub const AUDIT_STREAM_CONNECTIONS_TOTAL: &str = "greengateway_audit_stream_connections_total";

/// How many stream positions a resuming client was behind when it
/// reconnected.
///
/// The distribution an operator sizes the audit retention window against:
/// a replay backlog approaching the retained window is a client that is
/// about to start getting `410 Gone` instead of a gapless resume.
#[cfg(feature = "postgres")]
pub const AUDIT_STREAM_REPLAY_BACKLOG_EVENTS: &str =
    "greengateway_audit_stream_replay_backlog_events";

/// Durable audit-stream batches that contained a position at or below the
/// cursor already delivered.
///
/// An invariant violation, not a workload characteristic: the stream reads
/// strictly after its cursor, so this must stay at `0`. It is counted
/// rather than asserted because the alternative -- delivering a duplicate
/// frame under an `id:` the client has already seen -- silently corrupts
/// a reconnecting consumer's idea of what it has processed.
#[cfg(feature = "postgres")]
pub const AUDIT_STREAM_DUPLICATE_POSITIONS_TOTAL: &str =
    "greengateway_audit_stream_duplicate_positions_total";

/// Client-certificate outcomes, per listener.
///
/// Every label value is a compile-time constant. The identity a rejected
/// certificate carried is never a label: it is caller-controlled text, and a
/// caller who can mint certificates could otherwise mint time series.
pub const INBOUND_CLIENT_CERTIFICATES_TOTAL: &str = "inbound_client_certificates_total";
pub const EGRESS_CLIENT_CACHE_REQUESTS_TOTAL: &str = "egress_client_cache_requests_total";
pub const EGRESS_CLIENT_CACHE_EVICTIONS_TOTAL: &str = "egress_client_cache_evictions_total";
pub const EGRESS_CLIENT_CACHE_ENTRIES: &str = "egress_client_cache_entries";
pub const PROXY_ADMISSION_ACTIVE: &str = "proxy_admission_active";
pub const PROXY_ADMISSION_QUEUED: &str = "proxy_admission_queued";
pub const PROXY_ADMISSION_REJECTIONS_TOTAL: &str = "proxy_admission_rejections_total";
pub const PROXY_ENDPOINT_SELECTIONS_TOTAL: &str = "proxy_endpoint_selections_total";
pub const PROXY_UPSTREAM_ATTEMPTS_TOTAL: &str = "proxy_upstream_attempts_total";
pub const PROXY_UPSTREAM_ATTEMPT_DURATION_SECONDS: &str = "proxy_upstream_attempt_duration_seconds";
pub const PROXY_UPSTREAM_RETRIES_TOTAL: &str = "proxy_upstream_retries_total";
pub const PROXY_RETRY_BUDGET_EXHAUSTED_TOTAL: &str = "proxy_retry_budget_exhausted_total";
pub const PROXY_STREAM_TERMINATIONS_TOTAL: &str = "proxy_stream_terminations_total";
pub const PROXY_STREAM_DURATION_SECONDS: &str = "proxy_stream_duration_seconds";
pub const PROXY_STREAM_TIME_TO_HEADERS_SECONDS: &str = "proxy_stream_time_to_headers_seconds";
pub const PROXY_STREAM_TIME_TO_FIRST_BYTE_SECONDS: &str = "proxy_stream_time_to_first_byte_seconds";
pub const PROXY_STREAM_BYTES_RECEIVED: &str = "proxy_stream_bytes_received";
pub const PROXY_STREAM_BYTES_SENT: &str = "proxy_stream_bytes_sent";
pub const PROXY_WEBSOCKET_HANDSHAKES_TOTAL: &str = "proxy_websocket_handshakes_total";
pub const PROXY_WEBSOCKET_ACTIVE: &str = "proxy_websocket_active";
pub const PROXY_WEBSOCKET_FRAMES_TOTAL: &str = "proxy_websocket_frames_total";
pub const PROXY_WEBSOCKET_BYTES_TOTAL: &str = "proxy_websocket_bytes_total";
pub const PROXY_WEBSOCKET_TERMINATIONS_TOTAL: &str = "proxy_websocket_terminations_total";
pub const PROXY_WEBSOCKET_DURATION_SECONDS: &str = "proxy_websocket_duration_seconds";
pub const PROXY_GRPC_CALLS_TOTAL: &str = "proxy_grpc_calls_total";
pub const PROXY_GRPC_ACTIVE_CALLS: &str = "proxy_grpc_active_calls";
pub const PROXY_GRPC_MESSAGES_TOTAL: &str = "proxy_grpc_messages_total";
pub const PROXY_GRPC_BYTES_TOTAL: &str = "proxy_grpc_bytes_total";
pub const PROXY_GRPC_CALL_DURATION_SECONDS: &str = "proxy_grpc_call_duration_seconds";
pub const GRPC_LISTENER_CONNECTIONS_TOTAL: &str = "grpc_listener_connections_total";
pub const GRPC_LISTENER_CONNECTIONS_ACTIVE: &str = "grpc_listener_connections_active";
pub const GRPC_UPSTREAM_CONNECTIONS_TOTAL: &str = "grpc_upstream_connections_total";
pub const GRPC_UPSTREAM_CONNECTION_SLOTS: &str = "grpc_upstream_connection_slots";
pub const UPSTREAM_HEALTH_TRANSITIONS_TOTAL: &str = "upstream_health_transitions_total";
pub const UPSTREAM_CIRCUIT_TRANSITIONS_TOTAL: &str = "upstream_circuit_transitions_total";
pub const UPSTREAM_CIRCUIT_REJECTIONS_TOTAL: &str = "upstream_circuit_rejections_total";
