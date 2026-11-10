//! The standalone authority-event dispatcher (issue #425).
//!
//! Standalone mode has no journal and no lease: one process owns its SQLite
//! files. Each store that owns an authority -- the token database and the
//! Connections database -- is its own evidence authority, with its own
//! persisted `authority_id`, and each of its evidence tables is a *source*
//! with its own commit-ordered sequence and its own cursor in the same file
//! (`storage::standalone_authority_events`). With `AUTHORITY_EVENT_SINK` set,
//! one task delivers every source:
//!
//! 1. Read at most `batch_size` rows after the source's committed cursor.
//! 2. Project them all under the store's keyring ([`project_standalone`]).
//!    A row that cannot be projected faithfully refuses the batch, so
//!    nothing after it is offered ahead of it.
//! 3. Offer the batch to the sink.
//! 4. Only after the sink accepted, advance the cursor to the batch's last
//!    sequence with a compare-and-set in an IMMEDIATE transaction.
//!
//! Nothing here runs inside an authority transaction: a sink outage delays
//! delivery, never a change. Standalone evidence has no capacity bound and
//! no retention, so a long outage costs disk, not refused changes.
//!
//! Failures and what they cost, per source (the others keep delivering):
//!
//! - **The sink refuses or fails.** The same projected batch is offered again
//!   after an exponential backoff (0.5 s doubling to 60 s, with jitter); the
//!   cursor does not move and nothing is re-read.
//! - **The cursor advance fails after the sink accepted.** Only the advance
//!   is retried, so this process does not offer the batch twice. An advance
//!   refused because the cursor moved under it (another process on the same
//!   file) drops the batch and re-reads the cursor.
//! - **The process dies between acceptance and the advance.** The next start
//!   reads the same rows after the committed cursor and offers them again,
//!   with the same event IDs and, under the same key, byte-identical
//!   records: at least once, never exactly once.
//! - **A row cannot be projected.** The batch is refused and retried with the
//!   same backoff, so the source stalls at that row, counts `projection`
//!   failures and logs the sequence; its oldest-undelivered age keeps
//!   growing until an operator intervenes. It is never skipped.
//!
//! Metrics (the store and the failed step are the only labels): undelivered
//! rows and the oldest undelivered age per store, published after every
//! pass, and failures by store and step.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::json;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    cadence::{retry_backoff, sleep_or_stop, DispatcherConfig},
    delivery::{DeliveryRecord, ProjectionError},
    pseudonym::{resolve_keyring, PseudonymError, PseudonymKeyring},
    sink::{configured_sink, AuthorityEventSink, SinkError},
    standalone_delivery::project_standalone,
};
use crate::{
    audit,
    config::AuthorityEventSettings,
    connections::secret::SecretResolver,
    lifecycle::GatewayLifecycle,
    storage::{
        run_blocking,
        standalone_authority_events::{
            SourceBacklog, StandaloneEvidenceAuthority, StandaloneEvidenceSource, MAX_READ_BATCH,
        },
        RepositoryError, RepositoryErrorKind, StandaloneEvidenceStore,
    },
};

// The `kind` vocabulary of
// `greengateway_standalone_authority_event_delivery_failures_total`: which
// step failed, never why. The causes go to the log line.
/// The evidence rows or the cursor could not be read.
pub(crate) const FAILURE_READ: &str = "evidence_read";
/// An evidence row could not be projected faithfully; its source stalls.
pub(crate) const FAILURE_PROJECTION: &str = "projection";
/// The sink refused or failed the batch.
pub(crate) const FAILURE_SINK: &str = "sink";
/// The sink accepted but the cursor advance did not commit.
pub(crate) const FAILURE_CURSOR: &str = "cursor_advance";

/// The whole vocabulary of the `kind` label. Read by the tests; the call
/// sites pass their own constant.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const FAILURE_KINDS: [&str; 4] = [
    FAILURE_READ,
    FAILURE_PROJECTION,
    FAILURE_SINK,
    FAILURE_CURSOR,
];

/// Count one failed step of `store`'s delivery.
pub(crate) fn record_failure(store: StandaloneEvidenceStore, kind: &'static str) {
    ::metrics::counter!(
        crate::metrics::STANDALONE_AUTHORITY_EVENT_DELIVERY_FAILURES_TOTAL,
        "store" => store.as_str(),
        "kind" => kind
    )
    .increment(1);
}

/// Publish `store`'s backlog: its sources' undelivered rows summed, and the
/// oldest of their undelivered ages.
fn record_backlog(store: StandaloneEvidenceStore, backlogs: &[SourceBacklog]) {
    let now = OffsetDateTime::now_utc();
    let undelivered: i64 = backlogs.iter().map(SourceBacklog::undelivered).sum();
    let oldest = backlogs
        .iter()
        .filter_map(|backlog| backlog.oldest_undelivered_age_secs(now))
        .fold(0.0_f64, f64::max);
    ::metrics::gauge!(
        crate::metrics::STANDALONE_AUTHORITY_EVENT_UNDELIVERED,
        "store" => store.as_str()
    )
    .set(undelivered as f64);
    ::metrics::gauge!(
        crate::metrics::STANDALONE_AUTHORITY_EVENT_OLDEST_UNDELIVERED_AGE_SECONDS,
        "store" => store.as_str()
    )
    .set(oldest);
}

/// What one [`SourceLane::step`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepOutcome {
    /// Nothing after the cursor.
    Idle,
    /// A batch was accepted and the cursor committed through `through`.
    Delivered { events: usize, through: i64 },
    /// The stop token fired before anything more was offered.
    Stopped,
}

/// Why a step did not finish. The lane keeps whatever it can retry.
#[derive(Debug)]
pub(crate) enum StepError {
    Read(RepositoryError),
    Projection {
        sequence: i64,
        error: ProjectionError,
    },
    Sink(SinkError),
    Cursor(RepositoryError),
}

impl StepError {
    /// The failure-metric kind of this error.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Read(_) => FAILURE_READ,
            Self::Projection { .. } => FAILURE_PROJECTION,
            Self::Sink(_) => FAILURE_SINK,
            Self::Cursor(_) => FAILURE_CURSOR,
        }
    }
}

impl std::fmt::Display for StepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "evidence read failed: {error}"),
            Self::Projection { sequence, error } => {
                write!(formatter, "evidence sequence {sequence}: {error}")
            }
            Self::Sink(error) => write!(formatter, "{error}"),
            Self::Cursor(error) => write!(formatter, "cursor advance failed: {error}"),
        }
    }
}

/// A batch the sink has accepted whose cursor advance has not committed.
#[derive(Clone, Copy, Debug)]
struct AcceptedBatch {
    through: i64,
    events: usize,
}

/// The delivery of one evidence table: its committed cursor, and whatever
/// is in flight between reading the table and committing the cursor.
pub(crate) struct SourceLane {
    authority: Arc<dyn StandaloneEvidenceAuthority>,
    keyring: Arc<PseudonymKeyring>,
    source: StandaloneEvidenceSource,
    /// `None` once the cursor moved under this lane: re-read before the next
    /// batch.
    committed: Option<i64>,
    /// Projected records the sink has not accepted yet, and the sequence of
    /// the last one.
    pending: Vec<DeliveryRecord>,
    pending_through: i64,
    accepted: Option<AcceptedBatch>,
}

impl SourceLane {
    /// Open `source`'s cursor (creating it at 0 the first time) and begin
    /// from its committed position.
    pub(crate) async fn open(
        authority: Arc<dyn StandaloneEvidenceAuthority>,
        keyring: Arc<PseudonymKeyring>,
        source: StandaloneEvidenceSource,
    ) -> Result<Self, RepositoryError> {
        let committed = {
            let authority = Arc::clone(&authority);
            run_blocking(move || authority.open_cursor(source)).await?
        };
        Ok(Self {
            authority,
            keyring,
            source,
            committed: Some(committed),
            pending: Vec::new(),
            pending_through: committed,
            accepted: None,
        })
    }

    pub(crate) fn store(&self) -> StandaloneEvidenceStore {
        self.source.store()
    }

    /// The last sequence the cursor has committed for this lane, when known.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn committed_position(&self) -> Option<i64> {
        self.committed
    }

    /// Advance delivery by at most one batch. A batch left in flight by an
    /// earlier failure is finished first, without re-reading: an accepted
    /// batch only needs its cursor advance, a refused one is offered to the
    /// sink again.
    pub(crate) async fn step(
        &mut self,
        sink: &dyn AuthorityEventSink,
        batch_size: usize,
        stop: &CancellationToken,
    ) -> Result<StepOutcome, StepError> {
        if stop.is_cancelled() {
            return Ok(StepOutcome::Stopped);
        }
        let committed = match self.committed {
            Some(committed) => committed,
            None => self.reopen().await?,
        };
        if self.accepted.is_none() {
            if self.pending.is_empty() && !self.fill(committed, batch_size).await? {
                return Ok(StepOutcome::Idle);
            }
            if stop.is_cancelled() {
                return Ok(StepOutcome::Stopped);
            }
            self.offer(sink).await?;
        }
        self.commit(committed).await
    }

    async fn reopen(&mut self) -> Result<i64, StepError> {
        let authority = Arc::clone(&self.authority);
        let source = self.source;
        let committed = run_blocking(move || authority.open_cursor(source))
            .await
            .map_err(StepError::Read)?;
        self.committed = Some(committed);
        self.pending_through = committed;
        Ok(committed)
    }

    /// Read and project the next batch. `false` when there is none. A row
    /// that cannot be projected refuses the whole batch.
    async fn fill(&mut self, committed: i64, batch_size: usize) -> Result<bool, StepError> {
        let limit = batch_size.clamp(1, MAX_READ_BATCH);
        let authority = Arc::clone(&self.authority);
        let source = self.source;
        let rows = run_blocking(move || authority.read_after(source, committed, limit))
            .await
            .map_err(StepError::Read)?;
        let Some(last) = rows.last() else {
            return Ok(false);
        };
        let through = last.sequence;
        let mut projected = Vec::with_capacity(rows.len());
        for row in &rows {
            projected.push(project_standalone(row, &self.keyring).map_err(|error| {
                StepError::Projection {
                    sequence: row.sequence,
                    error,
                }
            })?);
        }
        self.pending = projected;
        self.pending_through = through;
        Ok(true)
    }

    /// Offer the pending batch to the sink.
    async fn offer(&mut self, sink: &dyn AuthorityEventSink) -> Result<(), StepError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        sink.deliver(&self.pending).await.map_err(StepError::Sink)?;
        self.accepted = Some(AcceptedBatch {
            through: self.pending_through,
            events: self.pending.len(),
        });
        self.pending.clear();
        Ok(())
    }

    /// Commit the cursor past an accepted batch.
    async fn commit(&mut self, committed: i64) -> Result<StepOutcome, StepError> {
        let Some(batch) = self.accepted else {
            return Ok(StepOutcome::Idle);
        };
        let events = i64::try_from(batch.events).unwrap_or(i64::MAX);
        let authority = Arc::clone(&self.authority);
        let source = self.source;
        match run_blocking(move || authority.advance(source, committed, batch.through, events))
            .await
        {
            Ok(()) => {
                self.committed = Some(batch.through);
                self.accepted = None;
                Ok(StepOutcome::Delivered {
                    events: batch.events,
                    through: batch.through,
                })
            }
            Err(error) if error.kind() == RepositoryErrorKind::Conflict => {
                // The batch was delivered; whatever moved the cursor decides
                // where delivery resumes, at worst offering rows again.
                tracing::warn!(
                    store = self.store().as_str(),
                    source = self.source.table(),
                    committed,
                    "standalone authority event cursor moved under this dispatcher; another process may share the file. Re-reading it"
                );
                self.committed = None;
                self.accepted = None;
                self.pending.clear();
                Err(StepError::Cursor(error))
            }
            Err(error) => Err(StepError::Cursor(error)),
        }
    }

    fn report(&self, error: &StepError, failures: u32) {
        record_failure(self.store(), error.kind());
        let store = self.store().as_str();
        let source = self.source.table();
        match error {
            StepError::Projection { .. } => tracing::error!(
                store,
                source,
                error = %error,
                committed = ?self.committed,
                failures,
                "standalone authority event dispatcher cannot project the next evidence row; delivery of this table is stalled there"
            ),
            _ => tracing::warn!(
                store,
                source,
                error = %error,
                committed = ?self.committed,
                failures,
                "standalone authority event delivery failed; retrying after backoff"
            ),
        }
    }

    /// Step until the table after the cursor is empty, retrying a failure
    /// after its backoff at most `MAX_TEST_RETRIES` times in a row. Returns
    /// the events delivered; `Ok(None)` means it stopped first. The tests'
    /// driver; the running dispatcher interleaves the same steps across
    /// every lane, with metrics, and never gives up.
    #[cfg(test)]
    pub(crate) async fn deliver_until_caught_up(
        &mut self,
        sink: &dyn AuthorityEventSink,
        config: DispatcherConfig,
        stop: &CancellationToken,
    ) -> Result<Option<usize>, StepError> {
        const MAX_TEST_RETRIES: u32 = 5;
        let mut delivered = 0;
        let mut failures = 0_u32;
        loop {
            match self.step(sink, config.batch_size, stop).await {
                Ok(StepOutcome::Idle) => return Ok(Some(delivered)),
                Ok(StepOutcome::Delivered { events, .. }) => {
                    failures = 0;
                    delivered += events;
                }
                Ok(StepOutcome::Stopped) => return Ok(None),
                Err(error) if failures >= MAX_TEST_RETRIES => return Err(error),
                Err(error) => {
                    failures = failures.saturating_add(1);
                    self.report(&error, failures);
                    sleep_or_stop(
                        stop,
                        retry_backoff(config.retry_base, config.retry_cap, failures),
                    )
                    .await;
                }
            }
        }
    }
}

/// One lane and when it may step again.
struct LaneState {
    lane: SourceLane,
    failures: u32,
    next_at: Instant,
}

/// Deliver every lane for the life of the process. Each lane steps when it
/// is due: at once after a delivered batch, after the poll interval when
/// idle, after its own backoff when it failed. One failing table never holds
/// another back. Every pass publishes each store's backlog.
pub(crate) async fn run_standalone_dispatcher(
    shutdown: CancellationToken,
    lanes: Vec<SourceLane>,
    sink: Arc<dyn AuthorityEventSink>,
    config: DispatcherConfig,
) {
    let poll = config.poll_interval.max(Duration::from_millis(1));
    let mut lanes: Vec<LaneState> = lanes
        .into_iter()
        .map(|lane| LaneState {
            lane,
            failures: 0,
            next_at: Instant::now(),
        })
        .collect();
    while !shutdown.is_cancelled() {
        for state in &mut lanes {
            if state.next_at > Instant::now() {
                continue;
            }
            match state
                .lane
                .step(sink.as_ref(), config.batch_size, &shutdown)
                .await
            {
                Ok(StepOutcome::Delivered { .. }) => {
                    state.failures = 0;
                    state.next_at = Instant::now();
                }
                Ok(StepOutcome::Idle) => {
                    state.failures = 0;
                    state.next_at = Instant::now() + poll;
                }
                Ok(StepOutcome::Stopped) => return,
                Err(error) => {
                    state.failures = state.failures.saturating_add(1);
                    state.lane.report(&error, state.failures);
                    state.next_at = Instant::now()
                        + retry_backoff(config.retry_base, config.retry_cap, state.failures);
                }
            }
        }
        publish_backlogs(&lanes).await;
        let wake = lanes
            .iter()
            .map(|state| state.next_at)
            .min()
            .unwrap_or_else(|| Instant::now() + poll);
        sleep_or_stop(&shutdown, wake.saturating_duration_since(Instant::now())).await;
    }
}

/// Read every lane's backlog and publish it per store. A read that fails
/// leaves that store's gauges at their last value.
async fn publish_backlogs(lanes: &[LaneState]) {
    let mut stores: Vec<(StandaloneEvidenceStore, Vec<SourceBacklog>, bool)> = Vec::new();
    for state in lanes {
        let authority = Arc::clone(&state.lane.authority);
        let source = state.lane.source;
        let backlog = run_blocking(move || authority.backlog(source)).await;
        let store = state.lane.store();
        let index = match stores.iter().position(|(known, _, _)| *known == store) {
            Some(index) => index,
            None => {
                stores.push((store, Vec::new(), true));
                stores.len() - 1
            }
        };
        match backlog {
            Ok(backlog) => stores[index].1.push(backlog),
            Err(error) => {
                stores[index].2 = false;
                tracing::debug!(
                    store = store.as_str(),
                    error = %error,
                    "standalone authority event backlog unavailable"
                );
            }
        }
    }
    for (store, backlogs, complete) in &stores {
        if *complete {
            record_backlog(*store, backlogs);
        }
    }
}

/// Why standalone delivery could not start. None carries key material, a
/// path or an identifier.
#[derive(Debug)]
pub(crate) enum StandaloneStartupError {
    /// A sink is configured without a key alias (configuration refuses this
    /// first; kept so the type cannot express an unkeyed dispatcher).
    MissingKeyAlias,
    /// A store's authority ID or one of its cursors could not be read.
    State {
        store: StandaloneEvidenceStore,
        error: RepositoryError,
    },
    Keyring(PseudonymError),
    /// The file sink's file cannot be opened for appending.
    SinkFile(std::io::ErrorKind),
}

impl std::fmt::Display for StandaloneStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKeyAlias => formatter
                .write_str("authority event delivery requires AUTHORITY_PSEUDONYM_KEY_ALIAS"),
            Self::State { store, error } => write!(
                formatter,
                "the {} store's authority event delivery state could not be read: {error}",
                store.as_str()
            ),
            Self::Keyring(error) => {
                write!(formatter, "authority event delivery cannot start: {error}")
            }
            Self::SinkFile(kind) => write!(
                formatter,
                "AUTHORITY_EVENT_FILE cannot be opened for appending ({kind:?})"
            ),
        }
    }
}

impl std::error::Error for StandaloneStartupError {}

/// What the serving path needs to start standalone delivery, assembled by
/// the app builder when a sink is configured in standalone mode.
pub(crate) struct StandaloneAuthorityEventStartup {
    /// The configured stores that own evidence: the token database and the
    /// Connections database, each when its path is set.
    pub(crate) authorities: Vec<Arc<dyn StandaloneEvidenceAuthority>>,
    /// The Connection control plane's secret resolver: the operator aliases
    /// and the network providers the builder activated.
    pub(crate) resolver: Arc<dyn SecretResolver>,
    pub(crate) settings: AuthorityEventSettings,
}

impl StandaloneAuthorityEventStartup {
    /// Prove the sink can accept, then for every store read (or write once)
    /// its authority ID, resolve the keyring under it, open its cursors and
    /// record the keyring in the audit log by key ID, and spawn the
    /// dispatcher. Nothing is spawned unless every step succeeded: a
    /// gateway configured to deliver evidence never serves without a working
    /// keyring, and there is no unkeyed mode to fall back to.
    pub(crate) async fn start(
        self,
        lifecycle: &GatewayLifecycle,
        audit_log: &audit::AuditLog,
    ) -> Result<(), StandaloneStartupError> {
        let Some(sink) = configured_sink(&self.settings.sink, self.settings.format)
            .await
            .map_err(StandaloneStartupError::SinkFile)?
        else {
            return Ok(());
        };
        let lanes = self.open_lanes(sink.kind(), audit_log).await?;
        if lanes.is_empty() {
            tracing::info!(
                sink = sink.kind(),
                "authority event sink configured, but no standalone store that owns evidence is; nothing to deliver"
            );
            return Ok(());
        }
        let shutdown = lifecycle.background_cancellation();
        let handle = tokio::spawn(run_standalone_dispatcher(
            shutdown,
            lanes,
            sink,
            DispatcherConfig::default(),
        ));
        lifecycle.register_background_task(handle);
        Ok(())
    }

    /// Every store's lanes, each under that store's own keyring.
    pub(crate) async fn open_lanes(
        &self,
        sink_kind: &'static str,
        audit_log: &audit::AuditLog,
    ) -> Result<Vec<SourceLane>, StandaloneStartupError> {
        let current = self
            .settings
            .pseudonym_key_alias
            .as_deref()
            .ok_or(StandaloneStartupError::MissingKeyAlias)?;
        let mut lanes = Vec::new();
        for authority in &self.authorities {
            let store = authority.evidence_store();
            let state = |error| StandaloneStartupError::State { store, error };
            let authority_id = {
                let authority = Arc::clone(authority);
                run_blocking(move || authority.authority_id(Uuid::new_v4()))
                    .await
                    .map_err(state)?
            };
            let keyring = Arc::new(
                resolve_keyring(
                    self.resolver.as_ref(),
                    authority_id,
                    current,
                    self.settings.previous_pseudonym_key_alias.as_deref(),
                )
                .await
                .map_err(StandaloneStartupError::Keyring)?,
            );
            for source in authority.evidence_sources() {
                lanes.push(
                    SourceLane::open(Arc::clone(authority), Arc::clone(&keyring), *source)
                        .await
                        .map_err(state)?,
                );
            }
            audit_log.emit(audit::AuditEvent::new(
                audit::event::AUTHORITY_EVENT_KEYRING_LOADED,
                "startup",
                "internal",
                None::<audit::Actor>,
                json!({
                    "authority_id": authority_id.to_string(),
                    "store": store.as_str(),
                    "current_key_id": keyring.current_key_id(),
                    "previous_key_id": keyring.previous_key_id(),
                    "sink": sink_kind,
                }),
            ));
            tracing::info!(
                authority_id = %authority_id,
                store = store.as_str(),
                current_key_id = keyring.current_key_id(),
                previous_key_id = keyring.previous_key_id().unwrap_or("-"),
                sink = sink_kind,
                "standalone authority event pseudonym keyring loaded"
            );
        }
        Ok(lanes)
    }
}

#[cfg(test)]
#[path = "standalone_tests.rs"]
mod tests;
