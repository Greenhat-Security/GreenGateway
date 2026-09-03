//! Execution leases: the cluster-wide bound on running tool invocations
//! (issue #241, PR 10).
//!
//! Standalone mode bounds concurrency with process-local semaphores. With
//! N replicas that is N times the configured global and per-tool limits,
//! so cluster mode makes each permitted concurrent invocation a *slot* in
//! a scope (`global`, or `tool:<name>`) and a running invocation the
//! holder of one slot's lease:
//!
//! - **Acquire** takes a free or expired slot with a fresh, strictly
//!   increasing fencing token. A scope with no free slot answers
//!   [`LeaseAttempt::Full`]; the runtime waits with jittered backoff inside
//!   its existing queue timeout.
//! - **Renew** extends the lease only while the holder still owns the slot
//!   at its fence. The runtime renews well inside the TTL and cancels the
//!   local work on the first failed renewal, so the work stops *before* the
//!   slot can be reclaimed by database-time expiry, never after.
//! - **Release** frees the slot at once on normal completion; a crashed
//!   holder's slot is reclaimed only after the lease expires by the
//!   database clock.
//! - **Fencing**: a stale holder's late write of shared follow-up state is
//!   refused by [`ExecutionLeaseStore::is_current`] once a successor holds
//!   the slot at a newer fence, so two holders can never both commit.
//!
//! The trait is what the runtime depends on; PostgreSQL implements it in
//! cluster mode and the in-memory store here stands in for tests of the
//! runtime's own behaviour (renewal, cancellation, release).

use std::time::Duration;

use async_trait::async_trait;

use crate::storage::RepositoryError;

/// A held slot: the scope, which slot, and the fence it was taken at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionLease {
    pub scope: String,
    pub slot: i32,
    pub fence: i64,
}

/// What an acquisition attempt found.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "postgres"), allow(dead_code))] // constructed by the PostgreSQL store and the test authority
pub enum LeaseAttempt {
    Acquired(ExecutionLease),
    /// Every slot is held by a live lease (or a race took the one that
    /// looked free); try again after a short wait.
    Full,
}

/// The lease authority the runtime consults in cluster mode.
#[async_trait]
pub trait ExecutionLeaseStore: Send + Sync {
    /// Try once to take a slot in `scope`, which has `capacity` slots.
    async fn try_acquire(
        &self,
        scope: &str,
        capacity: u32,
        invocation: &str,
    ) -> Result<LeaseAttempt, RepositoryError>;

    /// Extend the lease; `false` means it was lost (expired and possibly
    /// reclaimed), and the holder must stop its work.
    async fn renew(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError>;

    /// Free the slot if this holder still owns it at this fence.
    async fn release(&self, lease: &ExecutionLease) -> Result<(), RepositoryError>;

    /// Whether the lease is still held at this fence and unexpired: the
    /// check a fenced write of shared follow-up state makes.
    #[allow(dead_code)] // PR 11's durable observation writes are the first fenced follow-up state.
    async fn is_current(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError>;

    /// The lease's time to live on the authority's clock.
    fn ttl(&self) -> Duration;
}

/// The renewal cadence for a lease of `ttl`: a third of the TTL, so two
/// renewals can fail transiently before the lease is at risk, and never
/// less than a short floor so a tiny test TTL does not spin.
pub fn renewal_interval(ttl: Duration) -> Duration {
    (ttl / 3).max(Duration::from_millis(20))
}

/// The scope a tool's per-tool limit is leased in.
pub fn tool_scope(tool_name: &str) -> String {
    format!("tool:{tool_name}")
}

/// The scope the global limit is leased in.
pub const GLOBAL_SCOPE: &str = "global";

/// The maintenance singleton's lease scope, as a metric label.
///
/// It is spelled here rather than reused from `cluster_maintenance`'s
/// `MAINTENANCE_SCOPE` on purpose: the *lease* scope string is a database
/// value with its own compatibility rules, and a label is a published
/// interface. Keeping them separate means renaming one cannot silently
/// rewrite the other, and
/// `the_singleton_lease_scope_labels_match_their_scopes` asserts they
/// still agree.
pub(crate) const LEASE_SCOPE_MAINTENANCE: &str = "maintenance";

/// The discovery projector's lease scope, as a metric label. See
/// [`LEASE_SCOPE_MAINTENANCE`].
pub(crate) const LEASE_SCOPE_DISCOVERY_PROJECTOR: &str = "discovery_projector";

/// The whole vocabulary of `greengateway_cluster_lease_age_seconds`'s
/// `scope` label: the two *singleton* scopes and nothing else.
///
/// Per-tool leases are scoped `tool:<name>`, and a tool name is
/// control-plane data an operator adds and removes -- labelling by it
/// would mint and abandon a time series per tool. The singletons are two,
/// fixed, and the ones an operator alerts on ("nobody is leading").
///
/// Read by the registry label audit
/// (`the_ha_metric_registry_never_labels_by_a_caller_influenced_value`);
/// the two callers pass their own constant directly.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LEASE_SCOPE_LABELS: [&str; 2] =
    [LEASE_SCOPE_MAINTENANCE, LEASE_SCOPE_DISCOVERY_PROJECTOR];

/// The renewal reported the lease gone; the holder must stop its work.
pub(crate) const LEASE_FAILURE_LOST: &str = "lost";
/// The authority could not answer a renewal for half the TTL, so the
/// holder gave up before the slot could be reclaimed.
pub(crate) const LEASE_FAILURE_RENEW_EXPIRED: &str = "renew_expired";
/// A normal completion could not free its slot; it lapses by expiry
/// instead, which costs the next caller up to one TTL of the concurrency
/// this lease exists to grant.
pub(crate) const LEASE_FAILURE_RELEASE_FAILED: &str = "release_failed";

/// The whole vocabulary of `greengateway_execution_lease_failures_total`'s
/// `kind` label. Read by the registry label audit; the call sites pass
/// their own constant.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LEASE_FAILURE_KINDS: [&str; 3] = [
    LEASE_FAILURE_LOST,
    LEASE_FAILURE_RENEW_EXPIRED,
    LEASE_FAILURE_RELEASE_FAILED,
];

/// Count one lease failure by classified kind (issue #241, PR 14).
///
/// The scope is not a label (see [`LEASE_SCOPE_LABELS`]) and neither is
/// the store error: both go to the log line beside the call, which is
/// bounded and access-controlled in a way a metric label is not.
pub(crate) fn record_lease_failure(kind: &'static str) {
    ::metrics::counter!(crate::metrics::EXECUTION_LEASE_FAILURES_TOTAL, "kind" => kind)
        .increment(1);
}

/// Publish how long this replica has held a singleton lease (issue #241,
/// PR 14). `scope` must be one of [`LEASE_SCOPE_LABELS`].
///
/// Reported by the holder, so summing across a deployment gives the age of
/// the deployment's single leader; an age that resets repeatedly is a
/// leadership that keeps changing hands, which is the shape of a lease TTL
/// too short for the authority's latency.
#[cfg(feature = "postgres")] // the two singletons exist only in cluster mode
pub(crate) fn record_lease_age(scope: &'static str, age: Duration) {
    ::metrics::gauge!(crate::metrics::CLUSTER_LEASE_AGE_SECONDS, "scope" => scope)
        .set(age.as_secs_f64());
}

#[cfg(test)]
pub(crate) mod memory {
    //! An in-memory lease store with a controllable clock for runtime tests:
    //! the same acquire/renew/release/fence semantics as PostgreSQL, judged
    //! on a test-owned instant instead of database time.

    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use async_trait::async_trait;

    use super::{ExecutionLease, ExecutionLeaseStore, LeaseAttempt};
    use crate::storage::{RepositoryError, RepositoryErrorKind};

    #[derive(Clone)]
    struct Held {
        fence: i64,
        expires_at: Instant,
    }

    #[derive(Default)]
    struct State {
        slots: HashMap<(String, i32), Held>,
        next_fence: i64,
        /// When set, every call fails as an unavailable authority.
        unavailable: bool,
        /// Time offset applied to "now" so a test can expire leases.
        skew: Duration,
    }

    #[derive(Clone)]
    pub(crate) struct MemoryLeaseStore {
        state: Arc<Mutex<State>>,
        ttl: Duration,
    }

    impl MemoryLeaseStore {
        pub(crate) fn new(ttl: Duration) -> Self {
            Self {
                state: Arc::new(Mutex::new(State {
                    next_fence: 1,
                    ..State::default()
                })),
                ttl,
            }
        }

        pub(crate) fn set_unavailable(&self, unavailable: bool) {
            self.state.lock().expect("lease state").unavailable = unavailable;
        }

        /// Advance the store's clock so held leases expire.
        pub(crate) fn advance(&self, by: Duration) {
            self.state.lock().expect("lease state").skew += by;
        }

        pub(crate) fn held(&self, scope: &str) -> usize {
            let state = self.state.lock().expect("lease state");
            let now = Instant::now() + state.skew;
            state
                .slots
                .iter()
                .filter(|((held_scope, _), held)| held_scope == scope && held.expires_at > now)
                .count()
        }

        fn guard(state: &State) -> Result<(), RepositoryError> {
            if state.unavailable {
                Err(RepositoryError::new(
                    RepositoryErrorKind::Unavailable,
                    "lease_memory",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl ExecutionLeaseStore for MemoryLeaseStore {
        async fn try_acquire(
            &self,
            scope: &str,
            capacity: u32,
            _invocation: &str,
        ) -> Result<LeaseAttempt, RepositoryError> {
            let mut state = self.state.lock().expect("lease state");
            Self::guard(&state)?;
            let now = Instant::now() + state.skew;
            for slot in 0..i32::try_from(capacity).unwrap_or(i32::MAX) {
                let key = (scope.to_owned(), slot);
                let free = state
                    .slots
                    .get(&key)
                    .is_none_or(|held| held.expires_at <= now);
                if free {
                    let fence = state.next_fence;
                    state.next_fence += 1;
                    state.slots.insert(
                        key,
                        Held {
                            fence,
                            expires_at: now + self.ttl,
                        },
                    );
                    return Ok(LeaseAttempt::Acquired(ExecutionLease {
                        scope: scope.to_owned(),
                        slot,
                        fence,
                    }));
                }
            }
            Ok(LeaseAttempt::Full)
        }

        async fn renew(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError> {
            let mut state = self.state.lock().expect("lease state");
            Self::guard(&state)?;
            let now = Instant::now() + state.skew;
            let ttl = self.ttl;
            let key = (lease.scope.clone(), lease.slot);
            match state.slots.get_mut(&key) {
                Some(held) if held.fence == lease.fence && held.expires_at > now => {
                    held.expires_at = now + ttl;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        async fn release(&self, lease: &ExecutionLease) -> Result<(), RepositoryError> {
            let mut state = self.state.lock().expect("lease state");
            Self::guard(&state)?;
            let key = (lease.scope.clone(), lease.slot);
            if state
                .slots
                .get(&key)
                .is_some_and(|held| held.fence == lease.fence)
            {
                state.slots.remove(&key);
            }
            Ok(())
        }

        async fn is_current(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError> {
            let state = self.state.lock().expect("lease state");
            Self::guard(&state)?;
            let now = Instant::now() + state.skew;
            Ok(state
                .slots
                .get(&(lease.scope.clone(), lease.slot))
                .is_some_and(|held| held.fence == lease.fence && held.expires_at > now))
        }

        fn ttl(&self) -> Duration {
            self.ttl
        }
    }
}

#[cfg(test)]
mod metric_label_tests {
    use super::*;

    /// The two singleton scope *labels* are the scope strings with
    /// hyphens normalized to underscores, and nothing else.
    ///
    /// They are separate constants because a lease scope is a database
    /// value with its own compatibility rules and a metric label is a
    /// published interface; this test is what keeps "separate" from
    /// becoming "silently divergent" the next time either is renamed.
    #[test]
    fn the_singleton_lease_scope_labels_match_their_scopes() {
        #[cfg(feature = "postgres")]
        assert_eq!(
            LEASE_SCOPE_MAINTENANCE,
            crate::storage::postgres_membership::MAINTENANCE_LEASE_SCOPE.replace('-', "_"),
            "the maintenance label must name the maintenance lease scope"
        );
        #[cfg(feature = "postgres")]
        assert_eq!(
            LEASE_SCOPE_DISCOVERY_PROJECTOR,
            crate::discovery::projector::PROJECTOR_LEASE_SCOPE.replace('-', "_"),
            "the projector label must name the projector lease scope"
        );
        assert_eq!(
            LEASE_SCOPE_LABELS.len(),
            2,
            "a third singleton scope must be added to the label vocabulary too"
        );
    }

    /// A per-tool scope must never be mistaken for a singleton one: the
    /// vocabulary is the guard that keeps a tool name -- control-plane
    /// data an operator adds and removes -- out of the registry.
    #[test]
    fn a_per_tool_scope_is_not_in_the_singleton_label_vocabulary() {
        let scope = tool_scope("weather-lookup");
        assert!(
            !LEASE_SCOPE_LABELS.contains(&scope.as_str()),
            "a tool scope must never be a lease-age label: {scope}"
        );
        assert!(
            !LEASE_SCOPE_LABELS.contains(&GLOBAL_SCOPE),
            "the global tool scope is not a singleton lease"
        );
    }

    /// Every failure kind is distinct and spelled as a label may be:
    /// lowercase, underscores, nothing that needs quoting.
    #[test]
    fn every_lease_failure_kind_is_a_distinct_bare_label_value() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in LEASE_FAILURE_KINDS {
            assert!(seen.insert(kind), "duplicate lease failure kind {kind}");
            assert!(
                !kind.is_empty()
                    && kind
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "a label value must be bare lowercase text: {kind}"
            );
        }
    }
}
