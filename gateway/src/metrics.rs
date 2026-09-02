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
