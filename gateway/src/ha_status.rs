//! The readiness probe: the cluster-mode half of `/readyz` beyond the
//! fingerprint gate (issue #241, PR 14).
//!
//! `/readyz` answers one question — may this replica be sent traffic? —
//! and the HA state model's failure matrix lists the conditions under
//! which the honest answer is no. Three of them were already wired: the
//! lifecycle phase (`starting`, `draining`) and PR 13's
//! static-configuration gate (`config_fingerprint_mismatch`), plus the
//! proxy's own `required_upstream_unavailable`. This module adds the
//! four that depend on the deployment's shared authority:
//!
//! - `storage_unavailable` — the pool cannot be checked out, or the
//!   session the replica got is read-only (it reached a standby, or the
//!   primary was made read-only). A replica that cannot write cannot
//!   renew a lease, record an audit event, or take a security decision
//!   it can prove, so it must not receive traffic.
//! - `schema_incompatible` — the migration ledger no longer covers this
//!   binary's manifest. Startup validated the ledger in full (prefix
//!   *and* checksums, `storage/migrations.rs`); what can change while a
//!   replica serves is the ledger's *extent*, when another gateway
//!   migrates the database out from under it. That is the fact this
//!   probe re-reads.
//! - `instance_lease_invalid` — the membership heartbeat has not
//!   landed within the stale window, so the deployment's roster no
//!   longer counts this replica as live and the maintenance singleton
//!   may sweep its row at any moment. One failed heartbeat is not this
//!   condition; a heartbeat that has been failing longer than the
//!   window is.
//! - `security_revision_not_compiled` — the security gate has been
//!   refusing every admission for longer than the reconcile deadline,
//!   so it is failing protected traffic closed and there is no point
//!   routing more of it here.
//!
//! ## The security reason is an event, not a sample
//!
//! That last one is asked of the runtime that owns the gate rather than
//! computed here from the two watermarks, because the watermarks cannot
//! answer it in either direction. A counter read that overruns the
//! per-request budget fails every protected request while leaving both
//! watermarks exactly where the last successful read left them, so a
//! sampled comparison calls a replica healthy while it serves nothing;
//! and a deployment that commits constantly has the compiled watermark
//! behind the observed one at almost every instant while admitting every
//! request, so a sampled comparison would accumulate a healthy replica
//! into unready. `ClusterSecurityRuntime` records the outcome of every
//! admission as it happens and reports how long the failing streak has
//! run; the probe reads that. A timer the probe kept itself would also
//! start at the first probe that reached it, which is not when the gate
//! started failing — any higher-precedence reason (storage, schema, the
//! lease) would hand the replica a fresh full grace period on its way
//! out of that condition.
//!
//! ## One bounded check, cached
//!
//! Probes arrive as often as an orchestrator is configured to send
//! them, from every replica, and a probe that opens a transaction per
//! call turns a readiness check into a load source. So the authority is
//! consulted by exactly one statement — a `SELECT 1`-class read under
//! the session's `statement_timeout` — and its result is cached for
//! `READINESS_PROBE_CACHE_MS` (default 1000). The lease and revision
//! checks read process-local state and are evaluated fresh on every
//! probe; only the authority round trip is cached.
//!
//! The cache is held under an async mutex, so concurrent probes
//! collapse onto one in-flight check rather than each starting their
//! own. The check is bounded by the pool's acquire timeout and the
//! session statement timeout, so the mutex cannot be held indefinitely.
//!
//! ## Standalone mode
//!
//! None of this exists in standalone mode. There is no shared
//! authority, no membership roster, and no security revision counter,
//! so no `ReadinessProbe` is constructed and `/readyz` answers exactly
//! what it answered before this PR — byte for byte.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;

use crate::ha::ClusterReadiness;

/// The pool or the primary cannot serve this replica's writes.
pub(crate) const STORAGE_UNAVAILABLE: &str = "storage_unavailable";

/// The migration ledger is not one this binary can serve on.
pub(crate) const SCHEMA_INCOMPATIBLE: &str = "schema_incompatible";

/// The membership heartbeat has not landed within the stale window.
pub(crate) const INSTANCE_LEASE_INVALID: &str = "instance_lease_invalid";

/// The security gate has been refusing every admission for longer than
/// the reconcile deadline.
pub(crate) const SECURITY_REVISION_NOT_COMPILED: &str = "security_revision_not_compiled";

/// What one bounded authority check concluded.
///
/// Deliberately coarse: `/readyz` is a public endpoint and reports one
/// stable reason with no details, so the observation carries only what
/// the reason chain needs and never an error string, a SQLSTATE, or a
/// connection detail. The classified failure is logged at the call
/// site, where it can be audited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// A build without the `postgres` feature has no authority to observe;
// only the tests construct these there.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
pub(crate) enum AuthorityObservation {
    /// The authority answered on a writable session, and its migration
    /// ledger covers this many migrations.
    Writable { schema_version: i32 },
    /// The authority answered, but the session cannot write: a standby,
    /// or a primary put into read-only.
    ReadOnly,
    /// The authority could not be reached, checked out, or queried.
    Unavailable,
}

/// The one bounded authority check, behind a trait so the probe can be
/// driven without a database (the fault-injection seam every failure
/// matrix row is tested through).
#[async_trait]
pub(crate) trait ReadinessAuthority: Send + Sync {
    async fn observe(&self) -> AuthorityObservation;
}

/// What the security runtime tells readiness about itself, behind a
/// trait for the same reason. Implemented for `ClusterSecurityRuntime`
/// below.
pub(crate) trait SecurityRevisionHealth: Send + Sync {
    /// The highest revision at which every registered resource is
    /// confirmed current on this replica.
    fn compiled(&self) -> i64;
    /// The authority's counter as this replica last read it.
    fn observed(&self) -> i64;
    /// How long the gate has been refusing every admission, or `None`
    /// when the last attempt succeeded (and before the first, where
    /// nothing has been refused yet).
    ///
    /// The watermarks above describe how current this replica is; this
    /// describes whether protected traffic is being served, which is the
    /// question readiness is actually asking. They differ in both
    /// directions, which is why readiness reads this one.
    fn admission_failing_for(&self) -> Option<Duration>;
}

/// The probe's budgets and tolerances, all supplied by the caller so no
/// constant here has to agree with one somewhere else by accident.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadinessProbeSettings {
    /// How long one authority observation is reused
    /// (`READINESS_PROBE_CACHE_MS`). Zero means every probe consults
    /// the authority.
    pub cache_ttl: Duration,
    /// The migration-manifest range this binary serves on, exactly as
    /// the replica advertises it to the roster
    /// (`storage::migrations::schema_version_range()`).
    pub accepted_schema_versions: (i32, i32),
    /// How old the last successful membership heartbeat may be before
    /// this replica's roster row is stale (`CLUSTER_MEMBER_STALE_MS`).
    pub member_stale_window: Duration,
    /// How long the security gate may go on refusing admissions before
    /// readiness is refused: the background reconciler's deadline, so a
    /// pass that is merely slow is not called a failure.
    pub revision_reconcile_grace: Duration,
}

/// The cluster-mode readiness evaluation `/readyz` consults between the
/// fingerprint gate and the proxy's upstream check.
pub(crate) struct ReadinessProbe {
    /// PR 13's gate, which also carries this replica's membership
    /// heartbeat health (`ClusterReadiness::heartbeat_age`).
    readiness: Arc<ClusterReadiness>,
    authority: Arc<dyn ReadinessAuthority>,
    /// None when no cluster security runtime exists (a build or a
    /// deployment with no authority-backed security resources); the
    /// revision reason then never fires.
    revisions: Option<Arc<dyn SecurityRevisionHealth>>,
    settings: ReadinessProbeSettings,
    /// The last authority observation and when it was taken. An async
    /// mutex, so concurrent probes wait for the in-flight check instead
    /// of each starting one.
    cached: tokio::sync::Mutex<Option<(Instant, AuthorityObservation)>>,
}

impl ReadinessProbe {
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // built by the cluster wiring and tests
    pub(crate) fn new(
        readiness: Arc<ClusterReadiness>,
        authority: Arc<dyn ReadinessAuthority>,
        revisions: Option<Arc<dyn SecurityRevisionHealth>>,
        settings: ReadinessProbeSettings,
    ) -> Arc<Self> {
        Arc::new(Self {
            readiness,
            authority,
            revisions,
            settings,
            cached: tokio::sync::Mutex::new(None),
        })
    }

    /// Why this replica refuses readiness, or `None` when it does not.
    ///
    /// The order is the failure matrix's: storage first (nothing below
    /// it can be judged on an authority that cannot be read), then the
    /// schema, then this replica's own lease, then its security
    /// watermark. One stable coarse reason, no details.
    pub(crate) async fn blocked_reason(&self) -> Option<&'static str> {
        match self.observe_authority().await {
            AuthorityObservation::Unavailable | AuthorityObservation::ReadOnly => {
                return Some(STORAGE_UNAVAILABLE)
            }
            AuthorityObservation::Writable { schema_version } => {
                let (minimum, maximum) = self.settings.accepted_schema_versions;
                let compatible = schema_version >= minimum && schema_version <= maximum;
                // The serving-time writer of `greengateway_schema_compatible`
                // (issue #241, PR 14). Startup set it once; what can change
                // under a replica that is already serving is exactly this,
                // and the probe is the only thing that re-reads it.
                #[cfg(feature = "postgres")]
                crate::storage::migrations::record_schema_compatible(compatible);
                if !compatible {
                    return Some(SCHEMA_INCOMPATIBLE);
                }
            }
        }
        if self.readiness.heartbeat_age() >= self.settings.member_stale_window {
            return Some(INSTANCE_LEASE_INVALID);
        }
        if self.admission_failing_past_deadline() {
            return Some(SECURITY_REVISION_NOT_COMPILED);
        }
        None
    }

    /// How many migrations the authority's ledger carries, or `None`
    /// when the authority could not be read (or answered on a read-only
    /// session, where the ledger is not this replica's to judge).
    ///
    /// This is the same cached observation `blocked_reason` uses, not a
    /// second query: the cluster status view reports the number that
    /// `/readyz` decided `schema_incompatible` on, and asking for it
    /// inside the cache window costs nothing.
    pub(crate) async fn observed_schema_version(&self) -> Option<i32> {
        match self.observe_authority().await {
            AuthorityObservation::Writable { schema_version } => Some(schema_version),
            AuthorityObservation::ReadOnly | AuthorityObservation::Unavailable => None,
        }
    }

    /// The cached authority observation, refreshed when it is older
    /// than the cache TTL.
    async fn observe_authority(&self) -> AuthorityObservation {
        let mut cached = self.cached.lock().await;
        if let Some((taken_at, observation)) = *cached {
            if Instant::now().saturating_duration_since(taken_at) < self.settings.cache_ttl {
                return observation;
            }
        }
        let observation = self.authority.observe().await;
        *cached = Some((Instant::now(), observation));
        observation
    }

    /// Whether the security gate has been refusing every admission for
    /// longer than the reconcile deadline.
    ///
    /// The streak is the runtime's, measured from the first refusal
    /// after the last success and cleared by the next success, so it is
    /// neither restarted by a probe that arrives late nor extended by a
    /// higher-precedence reason that short-circuited the chain above it.
    /// A single admission clears it: a replica serving protected traffic
    /// is ready however far behind its watermark happens to be at the
    /// instant a probe looks.
    fn admission_failing_past_deadline(&self) -> bool {
        self.revisions.as_ref().is_some_and(|revisions| {
            revisions
                .admission_failing_for()
                .is_some_and(|failing_for| failing_for >= self.settings.revision_reconcile_grace)
        })
    }
}

/// The security runtime as readiness reads it. The runtime already
/// publishes both watermarks for the membership heartbeat and already
/// records what its gate decided; the probe reads those rather than
/// keeping state of its own.
#[cfg(feature = "postgres")]
impl SecurityRevisionHealth for crate::security_cluster::ClusterSecurityRuntime {
    fn compiled(&self) -> i64 {
        self.compiled_revision()
    }

    fn observed(&self) -> i64 {
        self.observed_revision()
    }

    fn admission_failing_for(&self) -> Option<Duration> {
        self.admission_failing_for()
    }
}

/// The same runtime as the cluster status view's security section: the
/// two watermarks above, plus the background reconciler's own health.
#[cfg(feature = "postgres")]
impl crate::cluster_status::SecurityStatus for crate::security_cluster::ClusterSecurityRuntime {
    fn last_reconcile_pass_age(&self) -> Option<Duration> {
        self.last_reconcile_pass_age()
    }

    fn reconcile_failures_total(&self) -> u64 {
        self.reconcile_failures_total()
    }
}

/// The production authority: one statement on the deployment's
/// PostgreSQL pool.
#[cfg(feature = "postgres")]
pub(crate) struct PostgresReadinessAuthority {
    pool: deadpool_postgres::Pool,
}

/// The one statement, and why it is the one:
///
/// - `pg_is_in_recovery()` is true on a standby, and
///   `transaction_read_only` is `on` when the session cannot write for
///   any other reason (`default_transaction_read_only`, a primary
///   flipped read-only). Together they are "this session cannot write".
/// - `count(*)` over the migration ledger is how many migrations the
///   database carries. Startup proved the ledger is a checksum-matching
///   prefix; the count is the part that can change underneath a serving
///   replica when another gateway migrates.
///
/// One round trip, no writes, no locks, and exactly one row back.
#[cfg(feature = "postgres")]
fn authority_check_statement() -> String {
    format!(
        "SELECT (pg_is_in_recovery() OR current_setting('transaction_read_only') = 'on') \
             AS read_only, \
         (SELECT count(*) FROM {ledger})::int AS schema_version",
        ledger = crate::storage::migrations::LEDGER_TABLE
    )
}

#[cfg(feature = "postgres")]
impl PostgresReadinessAuthority {
    pub(crate) fn new(pool: deadpool_postgres::Pool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

/// The `operation` label the probe's own statement is timed under, so its
/// latency sits beside the stores' in
/// `greengateway_database_operation_seconds`. A `/readyz` that has become
/// slow is a readiness check that will start timing out in an
/// orchestrator, and this is where that shows up first.
#[cfg(feature = "postgres")]
const OPERATION_READINESS_PROBE: &str = "readiness_probe";

#[cfg(feature = "postgres")]
#[async_trait]
impl ReadinessAuthority for PostgresReadinessAuthority {
    async fn observe(&self) -> AuthorityObservation {
        let started = std::time::Instant::now();
        let (observation, failure) = self.observe_once().await;
        crate::storage::postgres::observe_operation(
            OPERATION_READINESS_PROBE,
            started.elapsed(),
            // The classified kind the failure actually carried, not one
            // stamped on afterwards: a pool that is saturated reports
            // `timeout` and a database that is gone reports
            // `unavailable`, so
            // `greengateway_database_operation_seconds{operation="readiness_probe"}`
            // tells an operator which of the two `/readyz` is refusing
            // on. A successful observation carries no failure at all --
            // a read-only session answered perfectly well, it just
            // cannot be written to, and calling that a store error would
            // misreport a standby as an outage.
            failure,
        );
        observation
    }
}

#[cfg(feature = "postgres")]
impl PostgresReadinessAuthority {
    /// The observation, and the classified failure behind it when there
    /// was one — the pair the metric needs, kept out of
    /// `AuthorityObservation` so the reason chain stays as coarse as
    /// `/readyz` is allowed to be.
    async fn observe_once(
        &self,
    ) -> (
        AuthorityObservation,
        Option<crate::storage::RepositoryErrorKind>,
    ) {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(error) => {
                // Classified and logged exactly as any other pool
                // checkout failure; the probe itself reports only the
                // coarse reason, and the classified kind goes to the
                // metric so a saturated pool (`timeout`) and a database
                // that is gone (`unavailable`) are distinguishable there
                // even though `/readyz` calls both `storage_unavailable`
                // -- a replica that cannot check out a connection cannot
                // serve a protected request either way.
                let failure = crate::storage::postgres::classify_pool_error(error).kind();
                tracing::warn!(
                    kind = failure.as_str(),
                    "the readiness probe could not check out a connection; readiness is refused as storage_unavailable"
                );
                return (AuthorityObservation::Unavailable, Some(failure));
            }
        };
        let row = match client.query_one(&authority_check_statement(), &[]).await {
            Ok(row) => row,
            Err(error) => {
                let kind = crate::storage::postgres::classify_postgres_error(&error);
                // A missing ledger table or schema is not "the store is
                // down", it is "this database is not migrated for this
                // binary": report a ledger covering nothing, which no
                // accepted range contains. The statement carried the
                // read-only answer with it and failed before returning
                // either, so ask for that one on its own -- the chain's
                // order is storage before schema, and a standby whose
                // role cannot see the ledger is a storage answer.
                if matches!(
                    error.code().map(|state| state.code()),
                    Some("42P01") | Some("3F000")
                ) {
                    if self.session_is_read_only(&client).await {
                        tracing::warn!(
                            kind = kind.as_str(),
                            "the readiness probe found no migration ledger on a read-only session; readiness is refused as storage_unavailable"
                        );
                        return (AuthorityObservation::ReadOnly, None);
                    }
                    tracing::warn!(
                        kind = kind.as_str(),
                        "the readiness probe found no migration ledger; readiness is refused as schema_incompatible"
                    );
                    return (AuthorityObservation::Writable { schema_version: 0 }, None);
                }
                tracing::warn!(
                    kind = kind.as_str(),
                    "the readiness probe could not read the authority; readiness is refused as storage_unavailable"
                );
                return (AuthorityObservation::Unavailable, Some(kind));
            }
        };
        let read_only: bool = row.get("read_only");
        if read_only {
            return (AuthorityObservation::ReadOnly, None);
        }
        (
            AuthorityObservation::Writable {
                schema_version: row.get("schema_version"),
            },
            None,
        )
    }

    /// Whether this session cannot write, asked on its own. Only ever
    /// reached on the error path above, where the one-statement check
    /// could not answer it: a second round trip on a connection already
    /// in hand, in a case that is by definition not the hot one. A
    /// session that will not answer even this is not read-only as far as
    /// the probe is concerned -- the failure it is really carrying is
    /// reported by the caller.
    async fn session_is_read_only(&self, client: &deadpool_postgres::Client) -> bool {
        client
            .query_one(
                "SELECT (pg_is_in_recovery() \
                     OR current_setting('transaction_read_only') = 'on') AS read_only",
                &[],
            )
            .await
            .map(|row| row.get::<_, bool>("read_only"))
            .unwrap_or(false)
    }
}

/// Fault-injection seams: an authority and a watermark pair whose
/// answers a test sets directly, so every failure matrix row is
/// reachable without a database.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::{
        atomic::{AtomicI64, AtomicUsize, Ordering},
        Mutex,
    };

    /// An authority that answers whatever it was told to, counting how
    /// often it was actually consulted (which is how the cache is
    /// tested).
    pub(crate) struct ScriptedAuthority {
        observation: Mutex<AuthorityObservation>,
        observations: AtomicUsize,
    }

    impl ScriptedAuthority {
        pub(crate) fn new(observation: AuthorityObservation) -> Arc<Self> {
            Arc::new(Self {
                observation: Mutex::new(observation),
                observations: AtomicUsize::new(0),
            })
        }

        /// A healthy authority carrying a ledger of `schema_version`
        /// migrations.
        pub(crate) fn healthy(schema_version: i32) -> Arc<Self> {
            Self::new(AuthorityObservation::Writable { schema_version })
        }

        pub(crate) fn set(&self, observation: AuthorityObservation) {
            *self
                .observation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = observation;
        }

        pub(crate) fn observations(&self) -> usize {
            self.observations.load(Ordering::Acquire)
        }
    }

    #[async_trait]
    impl ReadinessAuthority for ScriptedAuthority {
        async fn observe(&self) -> AuthorityObservation {
            self.observations.fetch_add(1, Ordering::AcqRel);
            *self
                .observation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }

    /// A security runtime a test drives by hand: the two watermarks, and
    /// the gate's failing streak exactly as the real runtime keeps it
    /// (set on the first refusal, cleared by a success).
    pub(crate) struct ScriptedRevisions {
        compiled: AtomicI64,
        observed: AtomicI64,
        failing_since: Mutex<Option<Instant>>,
    }

    impl ScriptedRevisions {
        /// A runtime whose gate is admitting: the watermarks say what
        /// they are told to, and nothing is being refused.
        pub(crate) fn new(compiled: i64, observed: i64) -> Arc<Self> {
            Arc::new(Self {
                compiled: AtomicI64::new(compiled),
                observed: AtomicI64::new(observed),
                failing_since: Mutex::new(None),
            })
        }

        /// A runtime whose gate has been refusing every admission for
        /// `elapsed` — the fault injection for protected traffic failing
        /// closed, whatever the watermarks read.
        pub(crate) fn refusing_for(elapsed: Duration) -> Arc<Self> {
            let scripted = Self::new(0, 0);
            scripted.refuse_since(elapsed);
            scripted
        }

        pub(crate) fn set(&self, compiled: i64, observed: i64) {
            self.compiled.store(compiled, Ordering::Release);
            self.observed.store(observed, Ordering::Release);
        }

        /// The gate has been refusing for `elapsed`.
        pub(crate) fn refuse_since(&self, elapsed: Duration) {
            *self
                .failing_since
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(
                Instant::now()
                    .checked_sub(elapsed)
                    .unwrap_or_else(Instant::now),
            );
        }

        /// The gate admitted a request, which clears the streak.
        pub(crate) fn admit(&self) {
            *self
                .failing_since
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }

    impl SecurityRevisionHealth for ScriptedRevisions {
        fn compiled(&self) -> i64 {
            self.compiled.load(Ordering::Acquire)
        }

        fn observed(&self) -> i64 {
            self.observed.load(Ordering::Acquire)
        }

        fn admission_failing_for(&self) -> Option<Duration> {
            self.failing_since
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .map(|since| Instant::now().saturating_duration_since(since))
        }
    }

    /// Settings under which nothing fires on its own: a ledger of nine
    /// migrations is accepted, a heartbeat may be an hour old, and the
    /// reconciler has an hour of grace. Each test narrows exactly the
    /// one tolerance its failure matrix row is about.
    pub(crate) fn healthy_settings() -> ReadinessProbeSettings {
        ReadinessProbeSettings {
            cache_ttl: Duration::ZERO,
            accepted_schema_versions: (9, 9),
            member_stale_window: Duration::from_secs(3_600),
            revision_reconcile_grace: Duration::from_secs(3_600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{healthy_settings, ScriptedAuthority, ScriptedRevisions};
    use super::*;

    /// A gate that has agreed on the fingerprint, so the probe's own
    /// reasons are what a test is looking at.
    fn agreed_gate() -> Arc<ClusterReadiness> {
        let readiness = ClusterReadiness::new();
        readiness.record_fingerprint_agreement();
        readiness
    }

    fn probe_with(
        authority: Arc<dyn ReadinessAuthority>,
        settings: ReadinessProbeSettings,
    ) -> Arc<ReadinessProbe> {
        ReadinessProbe::new(agreed_gate(), authority, None, settings)
    }

    #[tokio::test]
    async fn a_healthy_authority_blocks_nothing() {
        let probe = probe_with(ScriptedAuthority::healthy(9), healthy_settings());
        assert_eq!(probe.blocked_reason().await, None);
    }

    /// Failure matrix row: the pool is exhausted (or the database is
    /// gone). Every checkout failure is one reason, whatever classified
    /// kind it carried.
    #[tokio::test]
    async fn an_unreachable_authority_is_storage_unavailable() {
        let probe = probe_with(
            ScriptedAuthority::new(AuthorityObservation::Unavailable),
            healthy_settings(),
        );
        assert_eq!(probe.blocked_reason().await, Some(STORAGE_UNAVAILABLE));
    }

    /// Failure matrix row: the session reached a standby, or the
    /// primary was made read-only. A replica that cannot write cannot
    /// be trusted with traffic, so it reports the same reason as one
    /// that cannot connect at all.
    #[tokio::test]
    async fn a_read_only_session_is_storage_unavailable() {
        let probe = probe_with(
            ScriptedAuthority::new(AuthorityObservation::ReadOnly),
            healthy_settings(),
        );
        assert_eq!(probe.blocked_reason().await, Some(STORAGE_UNAVAILABLE));
    }

    /// Failure matrix row: the ledger no longer matches the manifest,
    /// in either direction — behind it (not migrated yet) or ahead of
    /// it (migrated by a newer gateway).
    #[tokio::test]
    async fn a_ledger_outside_the_accepted_range_is_schema_incompatible() {
        for ledger in [0, 8, 10] {
            let probe = probe_with(ScriptedAuthority::healthy(ledger), healthy_settings());
            assert_eq!(
                probe.blocked_reason().await,
                Some(SCHEMA_INCOMPATIBLE),
                "a ledger of {ledger} migrations is not the accepted range"
            );
        }
    }

    /// Failure matrix row: the membership heartbeat cannot be written.
    /// One failed heartbeat is not the condition — a heartbeat older
    /// than the stale window is, because from that moment the roster
    /// stops counting this replica as live.
    #[tokio::test]
    async fn a_heartbeat_older_than_the_stale_window_is_an_invalid_instance_lease() {
        let gate = agreed_gate();
        let probe = ReadinessProbe::new(
            Arc::clone(&gate),
            ScriptedAuthority::healthy(9),
            None,
            ReadinessProbeSettings {
                // A zero window makes any heartbeat, however recent,
                // already stale: the fault injection for a heartbeat
                // that stopped landing.
                member_stale_window: Duration::ZERO,
                ..healthy_settings()
            },
        );
        assert_eq!(probe.blocked_reason().await, Some(INSTANCE_LEASE_INVALID));

        // A heartbeat inside the window clears it; the gate is the
        // carrier of the state, so recording a success is what a live
        // heartbeat task does.
        gate.record_heartbeat_success();
        let probe = ReadinessProbe::new(
            gate,
            ScriptedAuthority::healthy(9),
            None,
            healthy_settings(),
        );
        assert_eq!(probe.blocked_reason().await, None);
    }

    /// Failure matrix row: the security gate has been failing protected
    /// traffic closed past the reconcile deadline. Inside the deadline
    /// the replica is merely reconciling and stays ready.
    #[tokio::test]
    async fn a_gate_refusing_past_the_deadline_is_not_compiled() {
        let revisions = ScriptedRevisions::refusing_for(Duration::from_millis(10));
        let patient = ReadinessProbe::new(
            agreed_gate(),
            ScriptedAuthority::healthy(9),
            Some(revisions.clone()),
            healthy_settings(),
        );
        assert_eq!(
            patient.blocked_reason().await,
            None,
            "a refusal inside the reconcile deadline is not a readiness failure"
        );

        let impatient = ReadinessProbe::new(
            agreed_gate(),
            ScriptedAuthority::healthy(9),
            Some(revisions.clone()),
            ReadinessProbeSettings {
                revision_reconcile_grace: Duration::ZERO,
                ..healthy_settings()
            },
        );
        assert_eq!(
            impatient.blocked_reason().await,
            Some(SECURITY_REVISION_NOT_COMPILED)
        );

        // One admission clears the condition, and the streak with it.
        revisions.admit();
        assert_eq!(impatient.blocked_reason().await, None);
    }

    /// The streak is the runtime's, so a reason above this one in the
    /// chain cannot hand the replica a fresh grace period on its way
    /// out: a gate that has been failing for ten minutes behind a
    /// `storage_unavailable` answer is still failing the moment storage
    /// comes back, and readiness says so on that very probe.
    #[tokio::test]
    async fn a_higher_precedence_reason_does_not_restart_the_reconcile_grace() {
        let authority = ScriptedAuthority::new(AuthorityObservation::Unavailable);
        let probe = ReadinessProbe::new(
            agreed_gate(),
            authority.clone(),
            Some(ScriptedRevisions::refusing_for(Duration::from_secs(600))),
            ReadinessProbeSettings {
                revision_reconcile_grace: Duration::from_secs(30),
                ..healthy_settings()
            },
        );
        for _ in 0..4 {
            assert_eq!(probe.blocked_reason().await, Some(STORAGE_UNAVAILABLE));
        }

        authority.set(AuthorityObservation::Writable { schema_version: 9 });
        assert_eq!(
            probe.blocked_reason().await,
            Some(SECURITY_REVISION_NOT_COMPILED),
            "the gate has been refusing for ten minutes; storage recovering does not reset that"
        );
    }

    /// A gate can fail without either watermark moving: a counter read
    /// that overruns the per-request budget refuses the request and
    /// leaves `observed` exactly where the last successful read left it,
    /// which is `compiled`. Readiness must still refuse, because every
    /// protected request on this replica is answering `503`.
    #[tokio::test]
    async fn a_gate_failing_on_the_counter_read_is_reported_with_level_watermarks() {
        let revisions = ScriptedRevisions::new(9, 9);
        revisions.refuse_since(Duration::from_secs(60));
        let probe = ReadinessProbe::new(
            agreed_gate(),
            ScriptedAuthority::healthy(9),
            Some(revisions.clone()),
            ReadinessProbeSettings {
                revision_reconcile_grace: Duration::from_secs(30),
                ..healthy_settings()
            },
        );
        assert_eq!(
            revisions.compiled(),
            revisions.observed(),
            "the watermarks agree; only the gate knows the reads are failing"
        );
        assert_eq!(
            probe.blocked_reason().await,
            Some(SECURITY_REVISION_NOT_COMPILED)
        );
    }

    /// And the converse: a deployment that commits constantly has the
    /// compiled watermark behind the observed one at almost every
    /// instant while admitting every request. It is ready, however many
    /// probes happen to land on a behind sample, and never accumulates
    /// its way out of rotation.
    #[tokio::test]
    async fn a_replica_that_keeps_admitting_never_accumulates_into_unready() {
        let revisions = ScriptedRevisions::new(4, 5);
        let probe = ReadinessProbe::new(
            agreed_gate(),
            ScriptedAuthority::healthy(9),
            Some(revisions.clone()),
            ReadinessProbeSettings {
                revision_reconcile_grace: Duration::from_millis(1),
                ..healthy_settings()
            },
        );
        for step in 0..8 {
            revisions.set(5 + step, 6 + step);
            assert_eq!(
                probe.blocked_reason().await,
                None,
                "a replica whose gate is admitting is ready however far its watermark trails"
            );
        }

        // It becomes unready when the gate actually starts refusing, and
        // not before.
        revisions.refuse_since(Duration::from_millis(5));
        assert_eq!(
            probe.blocked_reason().await,
            Some(SECURITY_REVISION_NOT_COMPILED)
        );
    }

    /// The order the reasons are reported in is the failure matrix's,
    /// so an operator reading one `/readyz` answer sees the condition
    /// that has to be fixed first.
    #[tokio::test]
    async fn reasons_are_reported_in_the_documented_order() {
        let authority = ScriptedAuthority::new(AuthorityObservation::Unavailable);
        let probe = ReadinessProbe::new(
            agreed_gate(),
            authority.clone(),
            Some(ScriptedRevisions::refusing_for(Duration::ZERO)),
            ReadinessProbeSettings {
                member_stale_window: Duration::ZERO,
                revision_reconcile_grace: Duration::ZERO,
                ..healthy_settings()
            },
        );
        // Every condition holds at once; storage wins.
        assert_eq!(probe.blocked_reason().await, Some(STORAGE_UNAVAILABLE));
        // Storage recovers onto an unusable ledger: the schema wins.
        authority.set(AuthorityObservation::Writable { schema_version: 3 });
        assert_eq!(probe.blocked_reason().await, Some(SCHEMA_INCOMPATIBLE));
        // The ledger matches: the lease wins over the watermark.
        authority.set(AuthorityObservation::Writable { schema_version: 9 });
        assert_eq!(probe.blocked_reason().await, Some(INSTANCE_LEASE_INVALID));
    }

    /// The authority is consulted once per cache window however many
    /// probes arrive, and the in-memory conditions are still evaluated
    /// on every one of them.
    #[tokio::test]
    async fn the_authority_check_is_cached_for_the_configured_window() {
        let authority = ScriptedAuthority::healthy(9);
        let cached = ReadinessProbe::new(
            agreed_gate(),
            authority.clone(),
            None,
            ReadinessProbeSettings {
                cache_ttl: Duration::from_secs(3_600),
                ..healthy_settings()
            },
        );
        for _ in 0..8 {
            assert_eq!(cached.blocked_reason().await, None);
        }
        assert_eq!(
            authority.observations(),
            1,
            "eight probes inside the cache window must cost one authority check"
        );
        // A changed authority is not seen until the window elapses,
        // which is the trade the cache makes and the reason its default
        // is one second.
        authority.set(AuthorityObservation::Unavailable);
        assert_eq!(cached.blocked_reason().await, None);

        let uncached =
            ReadinessProbe::new(agreed_gate(), authority.clone(), None, healthy_settings());
        for _ in 0..3 {
            assert_eq!(uncached.blocked_reason().await, Some(STORAGE_UNAVAILABLE));
        }
        assert_eq!(
            authority.observations(),
            4,
            "a zero cache window consults the authority on every probe"
        );
    }
}
