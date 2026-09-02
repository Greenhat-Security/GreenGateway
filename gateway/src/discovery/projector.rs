//! The cluster discovery projector (issue #241, PR 11).
//!
//! In standalone mode the SQLite aggregator sink runs on the audit writer
//! thread of the one process. In cluster mode every replica ingests its
//! `http.request_observed` events into the PostgreSQL audit store, which
//! stores them idempotently by event id on a commit-ordered durable stream;
//! ONE replica -- whichever holds the `discovery-projector` execution lease
//! -- reads that stream after the committed checkpoint, runs the same
//! in-memory aggregation (`AggregatorState`), and flushes it to PostgreSQL
//! with the checkpoint in the same transaction, under its lease fence.
//!
//! The term of one leader:
//!
//! 1. Acquire the single slot of the `discovery-projector` scope (capacity
//!    1). `Full` means another replica leads; wait with jitter and retry.
//! 2. Claim leadership in `discovery_projector_state` at the lease's fence.
//!    A newer fence already there means this lease is stale (the store
//!    reclaimed it before this replica got to claim); release and retry.
//! 3. Load the persisted rows -- after the claim, so nothing a fenced-out
//!    predecessor commits afterwards can be missed or double-applied --
//!    and rebuild the working set, detector windows and learner groups
//!    included.
//! 4. Renew the lease at a third of its TTL (the tool runtime's
//!    `renew_until_lost`); a renewal that reports the lease gone, or one
//!    that cannot be answered for half the TTL, cancels the term before
//!    the slot can be reclaimed.
//! 5. Project: read a batch after the checkpoint, apply every projectable
//!    event, flush every `flush_every` observations and at batch end. The
//!    checkpoint advances to the last position read even when nothing in
//!    the batch was projectable, so the projector never re-reads events it
//!    has already decided about. A flush the store refuses because the
//!    fence moved (`Conflict`) ends the term at once: the state is dropped
//!    and the replica goes back to step 1. Any other flush failure keeps
//!    the state and retries the same flush without re-reading the stream,
//!    so no observation is ever applied twice.
//!
//! Observations are bounded before they reach the working set (see
//! [`observation_within_bounds`]) so the tables' CHECK constraints can
//! never fail a flush and wedge the projector on one batch.

use std::{hash::BuildHasher, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    audit::AuditEventSender,
    discovery::{
        aggregator::{emit_signal_opened_events, AggregatorState, ObservedRequest},
        signals::SignalDetectorConfig,
    },
    lifecycle::GatewayLifecycle,
    storage::{
        postgres_audit::PostgresAuditEventStore,
        postgres_discovery::{FlushCheckpoint, PostgresDiscoveryStore},
        RepositoryError, RepositoryErrorKind,
    },
    tools::{
        lease::{ExecutionLeaseStore, LeaseAttempt},
        runtime::renew_until_lost,
    },
};

/// The execution-lease scope the single projector slot lives in.
pub(crate) const PROJECTOR_LEASE_SCOPE: &str = "discovery-projector";
const PROJECTOR_LEASE_INVOCATION: &str = "projector";

/// The event type the projector applies; every other event only moves the
/// checkpoint.
const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";

// The schema's bounds on the columns an observation feeds (migration 9),
// applied before an observation enters the working set. A path bounds its
// learned template at four times its length (`/1` -> `/{param}`), so the
// path bound is a quarter of the template column's.
const MAX_METHOD_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 2048;
const MAX_ENDPOINT_TEMPLATE_BYTES: usize = 8192;
const MAX_USER_ID_BYTES: usize = 512;
const MAX_ISSUER_BYTES: usize = 2048;
const MAX_AUTH_METHOD_BYTES: usize = 64;
const MAX_ROUTE_HOST_BYTES: usize = 1024;
const MAX_ROUTE_PATH_PREFIX_BYTES: usize = 2048;
const MAX_UPSTREAM_ORIGIN_BYTES: usize = 2048;
const MAX_TIMESTAMP_BYTES: usize = 64;

/// How the projector runs: the aggregation settings the SQLite sink takes,
/// plus the stream cadence.
#[derive(Clone, Debug)]
pub(crate) struct ProjectorConfig {
    pub(crate) payload_capture_enabled: bool,
    pub(crate) endpoint_limit: usize,
    pub(crate) signal_detector_config: SignalDetectorConfig,
    /// The wait when the stream is empty, a flush fails transiently, or
    /// (times four, jittered) the lease is held elsewhere.
    pub(crate) poll_interval: Duration,
    /// Stream rows read per batch.
    pub(crate) batch_size: usize,
    /// Observations applied between flushes inside one batch.
    pub(crate) flush_every: usize,
}

/// Whether an observation fits the persisted columns. One that does not is
/// dropped (counted in the log) rather than admitted: the SQLite sink has
/// no such bound, but a CHECK failure here would fail every retry of the
/// same batch.
pub(crate) fn observation_within_bounds(observation: &ObservedRequest) -> bool {
    let within = |value: &str, bound: usize| value.len() <= bound;
    let optional_within =
        |value: &Option<String>, bound: usize| value.as_deref().is_none_or(|v| v.len() <= bound);
    within(&observation.method, MAX_METHOD_BYTES)
        && within(&observation.path, MAX_PATH_BYTES)
        && within(&observation.timestamp, MAX_TIMESTAMP_BYTES)
        && optional_within(&observation.endpoint_template, MAX_ENDPOINT_TEMPLATE_BYTES)
        && observation.principal.as_ref().is_none_or(|principal| {
            within(&principal.user_id, MAX_USER_ID_BYTES)
                && within(&principal.issuer, MAX_ISSUER_BYTES)
                && within(&principal.auth_method, MAX_AUTH_METHOD_BYTES)
        })
        && optional_within(&observation.route_host, MAX_ROUTE_HOST_BYTES)
        && optional_within(&observation.route_path_prefix, MAX_ROUTE_PATH_PREFIX_BYTES)
        && optional_within(&observation.upstream_origin, MAX_UPSTREAM_ORIGIN_BYTES)
}

/// What one `project_batch` call did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchOutcome {
    /// Nothing after the checkpoint; sleep and poll again.
    Empty,
    /// A batch was read and committed through `last_position`.
    Projected {
        /// Observations applied from this batch.
        observed: usize,
        last_position: i64,
    },
    /// The store refused the flush because the fence moved: this term is
    /// over and its state must be dropped.
    Fenced,
    /// The caller's stop token fired before the batch was committed;
    /// nothing after the last committed checkpoint was written.
    Stopped,
}

/// One leader's term: the working set built after claiming the fence, the
/// committed checkpoint, and the position the working set has consumed up
/// to (ahead of the checkpoint only while a flush is outstanding).
pub(crate) struct ProjectorTerm {
    audit: Arc<PostgresAuditEventStore>,
    store: Arc<PostgresDiscoveryStore>,
    config: ProjectorConfig,
    signal_event_sender: Option<AuditEventSender>,
    fence: i64,
    state: AggregatorState,
    /// The last stream position the store has committed.
    committed: i64,
    /// The last stream position applied to `state`; equal to `committed`
    /// except between a failed flush and its retry.
    consumed: i64,
    /// Observations applied to `state` and not yet committed.
    uncommitted_observations: usize,
}

impl ProjectorTerm {
    /// Load the persisted rows and rebuild the working set for a term at
    /// `fence`, resuming from `checkpoint` (what `claim_leadership`
    /// returned). Must be called after the claim, never before.
    pub(crate) async fn begin(
        audit: Arc<PostgresAuditEventStore>,
        store: Arc<PostgresDiscoveryStore>,
        config: ProjectorConfig,
        signal_event_sender: Option<AuditEventSender>,
        fence: i64,
        checkpoint: i64,
    ) -> Result<Self, RepositoryError> {
        let rows = store.load_rows().await?;
        let state = AggregatorState::from_rows(
            rows,
            config.payload_capture_enabled,
            config.endpoint_limit,
            config.signal_detector_config,
        )
        .map_err(|error| {
            tracing::error!(error = %error, "persisted discovery state failed to parse");
            RepositoryError::new(RepositoryErrorKind::InvalidData, "discovery_load")
        })?;
        Ok(Self {
            audit,
            store,
            config,
            signal_event_sender,
            fence,
            state,
            committed: checkpoint,
            consumed: checkpoint,
            uncommitted_observations: 0,
        })
    }

    pub(crate) fn fence(&self) -> i64 {
        self.fence
    }

    /// The last stream position the store has committed for this term.
    pub(crate) fn committed_position(&self) -> i64 {
        self.committed
    }

    /// Read one batch after the consumed position, apply it, and commit it
    /// with the checkpoint. A flush left outstanding by an earlier failure
    /// is retried first, without re-reading the stream, and reported as
    /// its own `Projected` outcome; the next call reads on.
    pub(crate) async fn project_batch(
        &mut self,
        stop: &CancellationToken,
    ) -> Result<BatchOutcome, RepositoryError> {
        if self.consumed > self.committed {
            let retried = self.uncommitted_observations;
            return match self.flush(stop).await? {
                FlushOutcome::Committed => Ok(BatchOutcome::Projected {
                    observed: retried,
                    last_position: self.committed,
                }),
                FlushOutcome::Fenced => Ok(BatchOutcome::Fenced),
                FlushOutcome::Stopped => Ok(BatchOutcome::Stopped),
            };
        }

        if stop.is_cancelled() {
            return Ok(BatchOutcome::Stopped);
        }
        let events = self
            .audit
            .stream_after(self.consumed, self.config.batch_size.max(1))
            .await?;
        if events.is_empty() {
            return Ok(BatchOutcome::Empty);
        }

        let mut observed = 0_usize;
        let mut dropped = 0_usize;
        for (position, event) in events {
            self.consumed = position;
            if event.event_type == HTTP_REQUEST_OBSERVED {
                if let Some(observation) = ObservedRequest::from_event(&event) {
                    if observation_within_bounds(&observation) {
                        self.state.observe(observation);
                        observed += 1;
                        self.uncommitted_observations += 1;
                    } else {
                        dropped += 1;
                    }
                }
            }
            if self.uncommitted_observations >= self.config.flush_every.max(1) {
                match self.flush(stop).await? {
                    FlushOutcome::Committed => {}
                    FlushOutcome::Fenced => return Ok(BatchOutcome::Fenced),
                    FlushOutcome::Stopped => return Ok(BatchOutcome::Stopped),
                }
            }
        }
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "discovery projector dropped observations exceeding the persisted column bounds"
            );
        }

        match self.flush(stop).await? {
            FlushOutcome::Committed => Ok(BatchOutcome::Projected {
                observed,
                last_position: self.committed,
            }),
            FlushOutcome::Fenced => Ok(BatchOutcome::Fenced),
            FlushOutcome::Stopped => Ok(BatchOutcome::Stopped),
        }
    }

    /// Project until the stream after the checkpoint is empty. Returns the
    /// number of observations applied; `Ok(None)` means the term ended
    /// (fenced out or stopped) before catching up.
    pub(crate) async fn project_until_caught_up(
        &mut self,
        stop: &CancellationToken,
    ) -> Result<Option<usize>, RepositoryError> {
        let mut total = 0;
        loop {
            match self.project_batch(stop).await? {
                BatchOutcome::Empty => return Ok(Some(total)),
                BatchOutcome::Projected { observed, .. } => total += observed,
                BatchOutcome::Fenced | BatchOutcome::Stopped => return Ok(None),
            }
        }
    }

    /// Commit everything applied since the last commit, with the checkpoint
    /// at the consumed position. A no-op when nothing was consumed.
    async fn flush(&mut self, stop: &CancellationToken) -> Result<FlushOutcome, RepositoryError> {
        if self.consumed == self.committed {
            return Ok(FlushOutcome::Committed);
        }
        // A term that has been told to stop (lease lost, shutdown) must not
        // start a write: the fence would refuse a truly stale one, but a
        // lease reported lost may not have been reclaimed yet, and the
        // rule is to stop before the slot can be, never after.
        if stop.is_cancelled() {
            return Ok(FlushOutcome::Stopped);
        }
        let batch = self.state.pending_flush();
        let detector_states = AggregatorState::detector_states_for(&batch);
        let template_groups_json = (!batch.dirty_aggregates.is_empty()
            || !batch.deleted_keys.is_empty())
        .then(|| self.state.template_groups_json());
        let checkpoint = FlushCheckpoint {
            position: self.consumed,
            fence: self.fence,
            projected_events: i64::try_from(self.uncommitted_observations).unwrap_or(i64::MAX),
        };
        match self
            .store
            .flush(
                &batch,
                &detector_states,
                template_groups_json.as_deref(),
                checkpoint,
                self.config.payload_capture_enabled,
            )
            .await
        {
            Ok(opened) => {
                self.state.mark_flushed(&batch);
                self.committed = self.consumed;
                self.uncommitted_observations = 0;
                emit_signal_opened_events(self.signal_event_sender.as_ref(), &opened);
                Ok(FlushOutcome::Committed)
            }
            Err(error) if error.kind() == RepositoryErrorKind::Conflict => {
                tracing::warn!(
                    fence = self.fence,
                    "discovery projector fenced out; a newer leader holds the checkpoint"
                );
                Ok(FlushOutcome::Fenced)
            }
            Err(error) => Err(error),
        }
    }
}

enum FlushOutcome {
    Committed,
    Fenced,
    Stopped,
}

/// Run the projector for the life of the process: contend for the lease,
/// lead while it holds, and go back to contending when it is lost. The
/// task ends when the lifecycle's background cancellation fires.
pub(crate) fn spawn_discovery_projector(
    lifecycle: &GatewayLifecycle,
    audit: Arc<PostgresAuditEventStore>,
    store: Arc<PostgresDiscoveryStore>,
    leases: Arc<dyn ExecutionLeaseStore>,
    holder: uuid::Uuid,
    config: ProjectorConfig,
    signal_event_sender: Option<AuditEventSender>,
) {
    let shutdown = lifecycle.background_cancellation();
    let handle = tokio::spawn(async move {
        run_projector(
            shutdown,
            audit,
            store,
            leases,
            holder,
            config,
            signal_event_sender,
        )
        .await;
    });
    lifecycle.register_background_task(handle);
}

async fn run_projector(
    shutdown: CancellationToken,
    audit: Arc<PostgresAuditEventStore>,
    store: Arc<PostgresDiscoveryStore>,
    leases: Arc<dyn ExecutionLeaseStore>,
    holder: uuid::Uuid,
    config: ProjectorConfig,
    signal_event_sender: Option<AuditEventSender>,
) {
    let poll = config.poll_interval.max(Duration::from_millis(1));
    while !shutdown.is_cancelled() {
        let lease = match leases
            .try_acquire(PROJECTOR_LEASE_SCOPE, 1, PROJECTOR_LEASE_INVOCATION)
            .await
        {
            Ok(LeaseAttempt::Acquired(lease)) => lease,
            Ok(LeaseAttempt::Full) => {
                sleep_or_shutdown(&shutdown, contention_backoff(poll)).await;
                continue;
            }
            Err(error) => {
                tracing::warn!(error = %error, "discovery projector lease acquisition failed");
                sleep_or_shutdown(&shutdown, contention_backoff(poll)).await;
                continue;
            }
        };

        let checkpoint = match store.claim_leadership(lease.fence, holder).await {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                if error.kind() == RepositoryErrorKind::Conflict {
                    tracing::warn!(
                        fence = lease.fence,
                        "discovery projector lease is stale; a newer fence holds leadership"
                    );
                } else {
                    tracing::warn!(error = %error, "discovery projector leadership claim failed");
                }
                release_lease(&leases, &lease).await;
                sleep_or_shutdown(&shutdown, contention_backoff(poll)).await;
                continue;
            }
        };

        let mut term = match ProjectorTerm::begin(
            Arc::clone(&audit),
            Arc::clone(&store),
            config.clone(),
            signal_event_sender.clone(),
            lease.fence,
            checkpoint,
        )
        .await
        {
            Ok(term) => term,
            Err(error) => {
                tracing::error!(error = %error, "discovery projector could not load its state");
                release_lease(&leases, &lease).await;
                sleep_or_shutdown(&shutdown, contention_backoff(poll)).await;
                continue;
            }
        };
        tracing::info!(
            fence = lease.fence,
            checkpoint,
            "discovery projector leading"
        );

        // The term stops on the first of: the lease reported lost, or
        // shutdown. Neither cancels a flush mid-transaction; both are
        // checked before every read and every write.
        let lost = CancellationToken::new();
        let stop = lost.clone();
        let renewal = tokio::spawn(renew_until_lost(
            Arc::clone(&leases),
            lease.clone(),
            lost.clone(),
        ));
        let shutdown_watch = {
            let stop = stop.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                shutdown.cancelled().await;
                stop.cancel();
            })
        };

        loop {
            match term.project_batch(&stop).await {
                Ok(BatchOutcome::Projected { .. }) => {}
                Ok(BatchOutcome::Empty) => sleep_or_stop(&stop, poll).await,
                Ok(BatchOutcome::Fenced) | Ok(BatchOutcome::Stopped) => break,
                Err(error) => {
                    // Nothing was committed: the working set keeps what it
                    // applied and the next call retries the same flush.
                    tracing::warn!(
                        error = %error,
                        "discovery projector flush failed; retrying without re-reading"
                    );
                    sleep_or_stop(&stop, poll).await;
                }
            }
            if stop.is_cancelled() {
                break;
            }
        }

        renewal.abort();
        shutdown_watch.abort();
        drop(term);
        release_lease(&leases, &lease).await;
        tracing::info!(fence = lease.fence, "discovery projector term ended");
        if !shutdown.is_cancelled() {
            sleep_or_shutdown(&shutdown, contention_backoff(poll)).await;
        }
    }
}

async fn release_lease(
    leases: &Arc<dyn ExecutionLeaseStore>,
    lease: &crate::tools::lease::ExecutionLease,
) {
    if let Err(error) = leases.release(lease).await {
        tracing::warn!(
            error = %error,
            "discovery projector lease release failed; the slot lapses by expiry"
        );
    }
}

/// Four poll intervals plus up to one more of jitter, so replicas that
/// lost the same election do not retry in lockstep.
fn contention_backoff(poll: Duration) -> Duration {
    let jitter_steps = std::collections::hash_map::RandomState::new().hash_one(0u8) % 16;
    poll * 4 + poll.mul_f64(jitter_steps as f64 / 16.0)
}

async fn sleep_or_shutdown(shutdown: &CancellationToken, duration: Duration) {
    tokio::select! {
        () = shutdown.cancelled() => {}
        () = tokio::time::sleep(duration) => {}
    }
}

async fn sleep_or_stop(stop: &CancellationToken, duration: Duration) {
    tokio::select! {
        () = stop.cancelled() => {}
        () = tokio::time::sleep(duration) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, AuditEvent};
    use serde_json::json;

    fn observation(path: &str, user_id: &str, issuer: &str) -> ObservedRequest {
        let event = AuditEvent::new(
            HTTP_REQUEST_OBSERVED,
            "request-1",
            "203.0.113.10",
            Some(Actor {
                user_id: user_id.to_owned(),
                issuer: Some(issuer.to_owned()),
                email: None,
                roles: None,
                auth_mode: "bearer_token".to_owned(),
            }),
            json!({
                "method": "GET",
                "path": path,
                "status": 200,
                "latency_ms": 5,
                "routing_context_known": true
            }),
        );
        ObservedRequest::from_event(&event).expect("an observed event parses")
    }

    #[test]
    fn observations_past_the_column_bounds_are_refused() {
        assert!(observation_within_bounds(&observation(
            "/orders/1",
            "alice",
            "https://issuer.example/"
        )));
        let long_path = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        assert!(!observation_within_bounds(&observation(
            &long_path,
            "alice",
            "https://issuer.example/"
        )));
        let long_user = "u".repeat(MAX_USER_ID_BYTES + 1);
        assert!(!observation_within_bounds(&observation(
            "/orders/1",
            &long_user,
            "https://issuer.example/"
        )));
    }

    #[test]
    fn contention_backoff_is_at_least_four_polls_and_bounded() {
        let poll = Duration::from_millis(100);
        for _ in 0..32 {
            let backoff = contention_backoff(poll);
            assert!(backoff >= poll * 4);
            assert!(backoff < poll * 5);
        }
    }
}
