//! Cluster membership: the heartbeat task and the fingerprint-agreement
//! readiness gate (issue #241, PR 13).
//!
//! In cluster mode every replica keeps one row in
//! `greengateway.cluster_members` (see `storage/postgres_membership.rs`):
//! written at boot by [`ClusterMembership::register_boot`], refreshed
//! every `CLUSTER_HEARTBEAT_MS` by the task [`ClusterMembership::spawn_heartbeat`]
//! registers with the lifecycle, stamped ready once the replica is
//! serving and agreed, and stamped draining when the lifecycle cancels
//! background work. A row whose heartbeat is older than
//! `CLUSTER_MEMBER_STALE_MS` is stale; the maintenance singleton sweeps
//! it, never this task and never a request.
//!
//! **Fingerprint agreement.** After the boot row is written, and on every
//! heartbeat until it succeeds, the replica reads the live members and
//! compares their static-configuration fingerprints with its own. Any
//! live, non-draining member with a different fingerprint is logged by
//! instance ID and keeps this replica's `/readyz` at `503`
//! (`config_fingerprint_mismatch`, [`ClusterReadiness`]). The replica does
//! not exit; agreement is granted on the first heartbeat after the last
//! disagreeing member drains or goes stale. Agreement is one-way, which is
//! what keeps a mismatched newcomer from taking the serving replicas out
//! of rotation with it -- and which means a fingerprint change completes
//! on its own only where the old replicas leave without waiting for the
//! newcomer to become ready (a `Recreate` rollout, a rolling update whose
//! `maxUnavailable` covers every old replica, or an operator draining
//! them). Under a readiness-gated rolling update (Kubernetes
//! `RollingUpdate` with `maxUnavailable: 0`, the Deployment default) the
//! newcomer is never ready while an old replica serves and the old replica
//! is never terminated while the newcomer is unready, so the rollout
//! stalls at the door until the operator rolls back or forces the old
//! replicas out: the gateway cannot tell an intended change from a
//! misconfigured replica at the moment the newcomer boots, and a stalled
//! rollout is that decision handed to the operator.
//!
//! The heartbeat also carries the replica's security-revision
//! acknowledgement (`compiled` and `observed`, from the cluster security
//! runtime), so the roster shows each replica's reconciliation lag, and the
//! capabilities this binary implements (issue #426, PR 1).
//!
//! **Operation gating.** [`ClusterMembership::admit_operation`] is the
//! write-path gate for an operation registered in
//! `storage::compatibility::OPERATION_REQUIREMENTS`: it reads the roster on
//! the database clock immediately before the write and admits the
//! operation only when every live member -- draining members included --
//! advertises what the operation requires. A refusal is logged with the
//! lacking members' instance IDs, audited as `cluster.operation_refused`,
//! and returned with a stable reason; the caller writes nothing. Unlike
//! fingerprint agreement, admission is never sticky: every write asks
//! again, because a member that lacks the capability can join at any time.
//!
//! **The durable contract fence** (issue #426, PR 3). The roster forgets:
//! a lacking member whose row went stale or was swept can come back. The
//! fence (`contract_fence`, migration 20) does not. The gate reads it
//! before every gated write and refuses (`contract_fenced`) when it
//! excludes this binary; an operation declaring `Activation::DurableFence`
//! is admitted only by raising the fence to the operation's requirement in
//! the transaction that confirms every live member already meets it. Every
//! heartbeat checks the fence in its own statement, so a replica the fence
//! excludes writes no row: at boot that fails startup, and on a running
//! replica -- one paused past the stale window while the fence was raised,
//! then resumed -- the heartbeat stops landing, readiness answers
//! `contract_fenced` for good (the fence never moves back), the refusal is
//! logged and audited as `cluster.contract_fenced` once, and the replica
//! writes nothing more to the roster, its draining stamp included.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use uuid::Uuid;

use crate::{
    audit::{self, AuditLog},
    ha::ClusterReadiness,
    lifecycle::GatewayLifecycle,
    security_cluster::ClusterSecurityRuntime,
    storage::{
        compatibility::{
            self, Activation, Backfill, BinaryContract, ContractFence, MemberAdvertisement,
            OperationAdmission, OperationRefusal, OperationRequirement, OPERATION_REQUIREMENTS,
        },
        ClusterMember, FenceDecision, FenceRaise, HeartbeatOutcome, MemberRegistration,
        MemberRevisions, PostgresMembershipStore, RepositoryError,
    },
};

/// The policy/tools document schema range this binary enforces, in
/// major versions. A cluster replica serves only a 0.x policy document
/// (`rbac/policy_document.rs`; policy v1, format 1, is standalone-only
/// until a capability lets every replica agree to read it), and the tools
/// document rides the same major; the range is advertised so a rolling
/// window can tell a document-format change apart from a schema change.
pub(crate) const DOCUMENT_VERSION_RANGE: (i32, i32) = (0, 0);

/// How long the draining stamp may take once the lifecycle cancels
/// background work: bounded, so a slow authority cannot hold shutdown.
const DRAINING_STAMP_BUDGET: Duration = Duration::from_secs(5);

/// The result of one agreement check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FingerprintAgreement {
    /// Every live, non-draining member carries this replica's fingerprint
    /// (or this replica is alone).
    Agreed,
    /// These live members carry another fingerprint.
    Disagreeing(Vec<Uuid>),
}

/// Why this replica could not register its boot row.
#[derive(Debug)]
pub(crate) enum BootRegistrationError {
    /// The row could not be written, or the first agreement check could not
    /// read the roster.
    Store(RepositoryError),
    /// The durable contract fence excludes this binary: no row was written,
    /// and none ever can be.
    ContractFenced,
}

impl std::fmt::Display for BootRegistrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::ContractFenced => formatter.write_str(
                "the deployment's durable contract fence excludes this gateway build, so it \
                 cannot join the roster; a retired build cannot return once the deployment has \
                 moved past it -- run an eligible build",
            ),
        }
    }
}

impl std::error::Error for BootRegistrationError {}

/// A raise of the durable contract fence that an admission wrote: logged,
/// and audited as `cluster.contract_fence_raised`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FenceRaised {
    before: ContractFence,
    after: ContractFence,
}

/// Who asked for a gated write: the request facts a refusal is audited
/// with, gathered the way every admin audit event gathers them
/// (`client_ip::request_id`, `client_ip::canonical_client_ip`,
/// `auth::actor_from_principal`).
#[derive(Clone, Debug)]
pub(crate) struct GatedWriteRequest {
    pub(crate) request_id: String,
    pub(crate) source_ip: String,
    pub(crate) actor: Option<audit::Actor>,
}

pub(crate) struct ClusterMembership {
    store: Arc<PostgresMembershipStore>,
    registration: MemberRegistration,
    readiness: Arc<ClusterReadiness>,
    heartbeat_interval: Duration,
    stale_window: Duration,
    /// Whether `ready_at` has been stamped; the stamp is idempotent in
    /// the store, this only saves a statement per tick.
    ready_recorded: AtomicBool,
    /// The classified kind of the last failed store call, carried on the
    /// next heartbeat as `last_error_code` and cleared by a success.
    last_error_code: Mutex<Option<&'static str>>,
}

impl ClusterMembership {
    pub(crate) fn new(
        store: PostgresMembershipStore,
        registration: MemberRegistration,
        heartbeat_interval: Duration,
        stale_window: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(store),
            registration,
            readiness: ClusterReadiness::new(),
            heartbeat_interval,
            stale_window,
            ready_recorded: AtomicBool::new(false),
            last_error_code: Mutex::new(None),
        })
    }

    /// The gate `/readyz` consults.
    pub(crate) fn readiness(&self) -> Arc<ClusterReadiness> {
        Arc::clone(&self.readiness)
    }

    /// The roster and ledger store, shared with the maintenance runner
    /// (`cluster_maintenance.rs`), which sweeps stale rows and writes the
    /// fenced job ledger through it.
    pub(crate) fn store(&self) -> Arc<PostgresMembershipStore> {
        Arc::clone(&self.store)
    }

    /// Write the boot row and run the first agreement check. A row that
    /// cannot be written is a startup failure (the database was just
    /// proven reachable), and so is a durable contract fence that excludes
    /// this binary: startup checked the fence before it read any authority
    /// state, so this is a raise that landed in between, and the boot row
    /// is where it is caught for good. A disagreement is not a failure --
    /// it is logged and the replica boots unready.
    pub(crate) async fn register_boot(
        &self,
    ) -> Result<FingerprintAgreement, BootRegistrationError> {
        let outcome = self
            .store
            .heartbeat(&self.registration, MemberRevisions::default(), None)
            .await
            .map_err(BootRegistrationError::Store)?;
        if outcome == HeartbeatOutcome::Fenced {
            self.readiness.record_contract_fenced();
            tracing::error!(
                "cluster mode: the durable contract fence excludes this gateway build; the boot row was not written and startup is refused"
            );
            return Err(BootRegistrationError::ContractFenced);
        }
        let agreement = self.check_fingerprint_agreement().await;
        // From the boot row on, so a replica that never gets past the
        // fingerprint door still has a series saying so rather than no
        // series at all -- "held at the door" and "not scraped" must not
        // look the same.
        self.publish_membership_gauges();
        agreement.map_err(BootRegistrationError::Store)
    }

    /// Compare the live roster with this replica's fingerprint, granting
    /// (sticky) agreement when nobody live disagrees. Already-agreed
    /// replicas answer without a read.
    pub(crate) async fn check_fingerprint_agreement(
        &self,
    ) -> Result<FingerprintAgreement, RepositoryError> {
        if self.readiness.fingerprint_agreed() {
            return Ok(FingerprintAgreement::Agreed);
        }
        let members = self.store.members(self.stale_window).await?;
        let disagreeing = fingerprint_disagreements(
            &members,
            self.store.instance_id(),
            &self.registration.fingerprint,
        );
        if disagreeing.is_empty() {
            self.readiness.record_fingerprint_agreement();
            tracing::info!(
                live_members = members.iter().filter(|member| member.live).count(),
                "cluster mode: every live member agrees on the static-configuration fingerprint; readiness is no longer gated on it"
            );
            return Ok(FingerprintAgreement::Agreed);
        }
        for member in &members {
            if disagreeing.contains(&member.instance_id) {
                tracing::warn!(
                    member_instance_id = %member.instance_id,
                    member_fingerprint = %member.fingerprint,
                    member_binary_version = %member.binary_version,
                    own_fingerprint = %self.registration.fingerprint,
                    "cluster mode: a live member runs a different static configuration; this replica refuses readiness (config_fingerprint_mismatch) until the members agree"
                );
            }
        }
        Ok(FingerprintAgreement::Disagreeing(disagreeing))
    }

    /// The write-path gate for a registered operation (issue #426, PR 1).
    /// Call it immediately before the operation's write and write nothing
    /// unless it admits; answer a refusal with its reason. Only an
    /// operation in `OPERATION_REQUIREMENTS` can be admitted, so an ad hoc
    /// requirement cannot bypass the registry's review. The policy commit
    /// paths call it for a document with role descriptions (PR 2). An
    /// operation declaring a durable fence is admitted only by raising the
    /// contract fence first (PR 3), which outlives a write that then fails:
    /// the fence records that the operation was activated, not that it
    /// wrote.
    pub(crate) async fn admit_operation(
        &self,
        requirement: &OperationRequirement,
        audit: &AuditLog,
        request: &GatedWriteRequest,
    ) -> Result<OperationAdmission, OperationRefusal> {
        self.admit_registered(requirement, OPERATION_REQUIREMENTS, audit, request)
            .await
    }

    /// [`Self::admit_operation`] against an explicit registry, so the
    /// contract tests can register a fixture operation without shipping
    /// one.
    pub(crate) async fn admit_registered(
        &self,
        requirement: &OperationRequirement,
        registry: &[OperationRequirement],
        audit: &AuditLog,
        request: &GatedWriteRequest,
    ) -> Result<OperationAdmission, OperationRefusal> {
        let outcome = self.evaluate_operation(requirement, registry).await;
        match &outcome {
            Ok((admission, raised)) => {
                if let Some(raised) = raised {
                    record_fence_raised(requirement, raised, admission, audit, request);
                }
                tracing::debug!(
                    operation = requirement.operation,
                    capability = requirement.capability.as_str(),
                    live_members = admission.live_members,
                    "cluster mode: every live member advertises what the operation requires; admitted"
                )
            }
            Err(refusal) => record_operation_refusal(requirement, refusal, audit, request),
        }
        outcome.map(|(admission, _)| admission)
    }

    async fn evaluate_operation(
        &self,
        requirement: &OperationRequirement,
        registry: &[OperationRequirement],
    ) -> Result<(OperationAdmission, Option<FenceRaised>), OperationRefusal> {
        if !registry.contains(requirement) {
            return Err(OperationRefusal::NotSupportedByThisBinary);
        }
        match requirement.activation {
            Activation::LiveMembers => self
                .evaluate_on_live_members(requirement)
                .await
                .map(|admission| (admission, None)),
            Activation::DurableFence => self.admit_by_raising_the_fence(requirement).await,
        }
    }

    /// An operation whose lacking members fail closed: the fence, the
    /// backfill and the roster are read, unlocked, immediately before the
    /// write.
    async fn evaluate_on_live_members(
        &self,
        requirement: &OperationRequirement,
    ) -> Result<OperationAdmission, OperationRefusal> {
        let fence = match self.store.contract_fence().await {
            Ok(fence) => fence,
            Err(error) => {
                self.note_failure(&error);
                tracing::warn!(
                    error = %error,
                    operation = requirement.operation,
                    "the durable contract fence could not be read for an operation gate; the operation is refused"
                );
                return Err(OperationRefusal::ActivationFenceUnavailable);
            }
        };
        let backfill = match requirement.backfill {
            Backfill::NotRequired => None,
            Backfill::Required { name } => match self.store.backfill_state(name).await {
                Ok(state) => Some(state),
                Err(error) => {
                    self.note_failure(&error);
                    tracing::warn!(
                        error = %error,
                        operation = requirement.operation,
                        backfill = name,
                        "the backfill ledger could not be read for an operation gate; the operation is refused"
                    );
                    None
                }
            },
        };
        let members = match self.store.members(self.stale_window).await {
            Ok(members) => members,
            Err(error) => {
                self.note_failure(&error);
                tracing::warn!(
                    error = %error,
                    operation = requirement.operation,
                    "cluster membership could not be read for an operation gate; the operation is refused"
                );
                return Err(OperationRefusal::RosterUnavailable);
            }
        };
        let advertisements: Vec<MemberAdvertisement> =
            members.iter().map(MemberAdvertisement::from).collect();
        compatibility::evaluate(
            requirement,
            &BinaryContract::shipped(),
            self.store.instance_id(),
            &advertisements,
            &fence,
            backfill,
        )
    }

    /// An operation whose lacking members would misread its data: admitted
    /// only by raising the durable contract fence to its requirement, in
    /// the one transaction that reads the ledger, the backfill and the
    /// roster under the fence's row lock and confirms every live member
    /// already meets the raised fence. A member that returns afterwards is
    /// refused at its heartbeat; a raise refused here writes nothing.
    async fn admit_by_raising_the_fence(
        &self,
        requirement: &OperationRequirement,
    ) -> Result<(OperationAdmission, Option<FenceRaised>), OperationRefusal> {
        let backfill = match requirement.backfill {
            Backfill::NotRequired => None,
            Backfill::Required { name } => Some(name),
        };
        let own_instance = self.store.instance_id();
        let raised = self
            .store
            .raise_contract_fence(
                self.stale_window,
                backfill,
                requirement.operation,
                |decision: FenceDecision<'_>| {
                    if crate::storage::migrations::validate_runtime_ledger(decision.ledger)
                        != Ok(crate::storage::migrations::SchemaStatus::Current)
                    {
                        return Err(OperationRefusal::SchemaNotServed);
                    }
                    let advertisements: Vec<MemberAdvertisement> = decision
                        .members
                        .iter()
                        .map(MemberAdvertisement::from)
                        .collect();
                    let admission = compatibility::evaluate(
                        requirement,
                        &BinaryContract::shipped(),
                        own_instance,
                        &advertisements,
                        decision.fence,
                        decision.backfill,
                    )?;
                    let target = compatibility::fence_target(decision.fence, requirement)?;
                    Ok((admission, target))
                },
            )
            .await;
        match raised {
            Ok(FenceRaise::Raised {
                decided,
                before,
                after,
            }) => Ok((decided, Some(FenceRaised { before, after }))),
            Ok(FenceRaise::Unchanged { decided }) => Ok((decided, None)),
            Ok(FenceRaise::Refused(refusal)) => Err(refusal),
            Ok(FenceRaise::MigrationInProgress) => Err(OperationRefusal::MigrationInProgress),
            Err(error) => {
                self.note_failure(&error);
                tracing::warn!(
                    error = %error,
                    operation = requirement.operation,
                    "the durable contract fence could not be raised for an operation gate; the operation is refused"
                );
                Err(OperationRefusal::ActivationFenceUnavailable)
            }
        }
    }

    /// The heartbeat task: every interval, refresh the row with the
    /// runtime's revisions, re-check agreement while it is withheld, and
    /// stamp readiness once the lifecycle is serving and the gate is
    /// open. On cancellation (draining or shutdown) the row is stamped
    /// draining under a bounded budget. Failures are logged, classified,
    /// and carried on the next heartbeat; the task never exits on one. A
    /// heartbeat the durable contract fence refuses is not a failure to
    /// retry: it is recorded once, on `audit` too, and from then on the
    /// task writes nothing.
    pub(crate) fn spawn_heartbeat(
        self: &Arc<Self>,
        lifecycle: &GatewayLifecycle,
        revisions: Option<Arc<ClusterSecurityRuntime>>,
        audit: AuditLog,
    ) {
        let membership = Arc::clone(self);
        let lifecycle_for_task = lifecycle.clone();
        let cancellation = lifecycle.background_cancellation();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(membership.heartbeat_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires at once; the boot row is already
            // written, so skip it rather than double-write.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = cancellation.cancelled() => {
                        membership.stamp_draining().await;
                        return;
                    }
                }
                membership
                    .tick(&lifecycle_for_task, revisions.as_deref(), &audit)
                    .await;
            }
        });
        lifecycle.register_background_task(handle);
    }

    async fn tick(
        &self,
        lifecycle: &GatewayLifecycle,
        revisions: Option<&ClusterSecurityRuntime>,
        audit: &AuditLog,
    ) {
        self.tick_once(lifecycle, revisions, audit).await;
        // Published after every tick, however it ended. The failure paths
        // are the ones that matter: a heartbeat that cannot be written is
        // precisely when the age has to keep climbing in the series an
        // operator is watching, and an early return that skipped the
        // publication would freeze it at its last healthy value.
        self.publish_membership_gauges();
    }

    pub(crate) async fn tick_once(
        &self,
        lifecycle: &GatewayLifecycle,
        revisions: Option<&ClusterSecurityRuntime>,
        audit: &AuditLog,
    ) {
        // Fenced is final: the fence never moves back, so a replica it
        // excludes writes nothing more to the roster and asks nothing more
        // of the authority on this task's behalf.
        if self.readiness.contract_fenced() {
            return;
        }
        let revisions = revisions
            .map(|runtime| MemberRevisions {
                compiled: runtime.compiled_revision(),
                observed: runtime.observed_revision(),
            })
            .unwrap_or_default();
        let carried_error = *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self
            .store
            .heartbeat(&self.registration, revisions, carried_error)
            .await
        {
            Ok(HeartbeatOutcome::Written) => self.note_success(),
            Ok(HeartbeatOutcome::Fenced) => {
                self.record_fenced_at_rejoin(audit).await;
                return;
            }
            Err(error) => {
                self.note_failure(&error);
                tracing::warn!(error = %error, "cluster member heartbeat failed; retrying on the next interval");
                return;
            }
        }
        if !self.readiness.fingerprint_agreed() {
            if let Err(error) = self.check_fingerprint_agreement().await {
                self.note_failure(&error);
                tracing::warn!(error = %error, "cluster membership could not be read for the fingerprint check; readiness stays withheld");
                return;
            }
        }
        if self.readiness.fingerprint_agreed()
            && lifecycle.accepting_work()
            && !self.ready_recorded.load(Ordering::Acquire)
        {
            match self.store.mark_ready().await {
                Ok(()) => self.ready_recorded.store(true, Ordering::Release),
                Err(error) => {
                    self.note_failure(&error);
                    tracing::warn!(error = %error, "cluster member ready stamp failed; retrying on the next interval");
                }
            }
        }
    }

    /// The heartbeat found the durable contract fence excluding this
    /// running replica: it was paused or partitioned past the stale window
    /// while a raise moved the deployment past this build. Readiness is
    /// refused for good, and the refusal is logged and audited once, with
    /// the fence's numbers when it can be read.
    async fn record_fenced_at_rejoin(&self, audit: &AuditLog) {
        if !self.readiness.record_contract_fenced() {
            return;
        }
        let exclusion = match self.store.contract_fence().await {
            // The same decision the heartbeat statement made, over the
            // registration it sent.
            Ok(fence) => fence.exclusion(
                self.registration.schema_version.1,
                &self.registration.capabilities,
            ),
            Err(error) => {
                self.note_failure(&error);
                None
            }
        };
        tracing::error!(
            fence_generation = exclusion.map(|exclusion| exclusion.generation),
            minimum_schema = exclusion.map(|exclusion| exclusion.minimum_schema),
            missing_capabilities = exclusion.map(|exclusion| exclusion.missing_capabilities),
            "cluster mode: the durable contract fence excludes this running gateway build; its heartbeat is no longer written and readiness is refused for good (contract_fenced) -- replace this replica with an eligible build"
        );
        audit.emit(audit::AuditEvent::new(
            audit::event::CLUSTER_CONTRACT_FENCED,
            "cluster-membership",
            "internal",
            None,
            serde_json::json!({
                "outcome": "refused",
                "reason": crate::ha::ClusterReadiness::CONTRACT_FENCED,
                "at": "heartbeat",
                "schema_max": self.registration.schema_version.1,
                "fence_generation": exclusion.map(|exclusion| exclusion.generation),
                "minimum_schema": exclusion.map(|exclusion| exclusion.minimum_schema),
                "missing_capabilities": exclusion.map(|exclusion| exclusion.missing_capabilities),
            }),
        ));
    }

    async fn stamp_draining(&self) {
        // A replica the fence excludes has no row to stamp, and writing one
        // would make it look live, and lacking, to every gate for a stale
        // window.
        if self.readiness.contract_fenced() {
            return;
        }
        match tokio::time::timeout(DRAINING_STAMP_BUDGET, self.store.mark_draining()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "cluster member draining stamp failed; the row goes stale instead")
            }
            Err(_) => {
                tracing::warn!(
                    "cluster member draining stamp timed out; the row goes stale instead"
                )
            }
        }
    }

    fn note_success(&self) {
        *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        // The readiness probe (issue #241, PR 14) refuses readiness once
        // this replica's row has not been refreshed inside the stale
        // window, which is the moment the roster stops counting it live.
        self.readiness.record_heartbeat_success();
    }

    fn note_failure(&self, error: &RepositoryError) {
        *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.kind().as_str());
    }

    /// Publish this replica's two membership facts as gauges (issue #241,
    /// PR 14): how old its roster row is, and whether it is still held at
    /// the fingerprint door.
    ///
    /// Neither carries a label. The instance the age belongs to is *this*
    /// process, which the scrape target already identifies; putting the
    /// instance id in a label would mint a series per boot, and a replica
    /// set that rolls weekly would accumulate them forever.
    pub(crate) fn publish_membership_gauges(&self) {
        record_membership_gauges(
            self.readiness.heartbeat_age(),
            self.readiness.fingerprint_agreed(),
        );
    }
}

/// Make a refusal observable: one warning per lacking member (by instance
/// ID, as the fingerprint check names a disagreeing one), one warning for
/// the decision, and one `cluster.operation_refused` audit event carrying
/// names, codes and counts only.
fn record_operation_refusal(
    requirement: &OperationRequirement,
    refusal: &OperationRefusal,
    audit: &AuditLog,
    request: &GatedWriteRequest,
) {
    if let OperationRefusal::MembersLackRequirement { lacking, .. } = refusal {
        for member in lacking {
            tracing::warn!(
                member_instance_id = %member,
                operation = requirement.operation,
                capability = requirement.capability.as_str(),
                "cluster mode: a live member does not advertise what a gated operation requires"
            );
        }
    }
    tracing::warn!(
        operation = requirement.operation,
        capability = requirement.capability.as_str(),
        reason = refusal.reason(),
        error = %refusal,
        "cluster mode: refused a gated operation; nothing was written"
    );
    audit.emit(audit::AuditEvent::new(
        audit::event::CLUSTER_OPERATION_REFUSED,
        request.request_id.clone(),
        request.source_ip.clone(),
        request.actor.clone(),
        refusal.audit_payload(requirement),
    ));
}

/// Make a fence raise observable: one warning naming both fences, and one
/// `cluster.contract_fence_raised` audit event with the operation that
/// raised it, the numbers before and after, and the live member count.
fn record_fence_raised(
    requirement: &OperationRequirement,
    raised: &FenceRaised,
    admission: &OperationAdmission,
    audit: &AuditLog,
    request: &GatedWriteRequest,
) {
    tracing::warn!(
        operation = requirement.operation,
        capability = requirement.capability.as_str(),
        previous_generation = raised.before.generation,
        fence_generation = raised.after.generation,
        minimum_schema = raised.after.minimum_schema,
        live_members = admission.live_members,
        "cluster mode: raised the durable contract fence; a gateway build without this capability can no longer start or rejoin this deployment"
    );
    audit.emit(audit::AuditEvent::new(
        audit::event::CLUSTER_CONTRACT_FENCE_RAISED,
        request.request_id.clone(),
        request.source_ip.clone(),
        request.actor.clone(),
        serde_json::json!({
            "operation": requirement.operation,
            "capability": requirement.capability.as_str(),
            "outcome": "raised",
            "previous_generation": raised.before.generation,
            "fence_generation": raised.after.generation,
            "previous_minimum_schema": raised.before.minimum_schema,
            "minimum_schema": raised.after.minimum_schema,
            "live_members": admission.live_members,
        }),
    ));
}

/// The emission itself, split from the task that owns the values so the
/// registry label audit can drive it (`metrics.rs`) without a database.
pub(crate) fn record_membership_gauges(heartbeat_age: Duration, fingerprint_agreed: bool) {
    ::metrics::gauge!(crate::metrics::CLUSTER_HEARTBEAT_AGE_SECONDS)
        .set(heartbeat_age.as_secs_f64());
    ::metrics::gauge!(crate::metrics::CLUSTER_CONFIG_MISMATCH).set(if fingerprint_agreed {
        0.0
    } else {
        1.0
    });
}

/// The live, non-draining members other than `own_instance` whose
/// fingerprint differs from `own_fingerprint`. Stale rows are ignored
/// (they are somebody's past, not the deployment's present) and draining
/// rows are ignored (they are leaving, and blocking on them would make a
/// rolling change wait for its own completion).
pub(crate) fn fingerprint_disagreements(
    members: &[ClusterMember],
    own_instance: Uuid,
    own_fingerprint: &str,
) -> Vec<Uuid> {
    members
        .iter()
        .filter(|member| member.live && member.draining_at.is_none())
        .filter(|member| member.instance_id != own_instance)
        .filter(|member| member.fingerprint != own_fingerprint)
        .map(|member| member.instance_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(fingerprint: &str, live: bool, draining: bool) -> ClusterMember {
        ClusterMember {
            instance_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
            binary_version: "0.0.0".to_owned(),
            schema_version_min: 9,
            schema_version_max: 9,
            document_version_min: 0,
            document_version_max: 0,
            fingerprint: fingerprint.to_owned(),
            started_at: "2026-01-01T00:00:00.000000Z".to_owned(),
            last_heartbeat_at: "2026-01-01T00:00:00.000000Z".to_owned(),
            heartbeat_age_secs: if live { 1.0 } else { 3_600.0 },
            ready_at: None,
            draining_at: draining.then(|| "2026-01-01T00:00:01.000000Z".to_owned()),
            compiled_security_revision: 0,
            observed_security_revision: 0,
            last_error_code: None,
            capabilities: String::new(),
            live,
        }
    }

    #[test]
    fn only_live_non_draining_other_members_can_disagree() {
        let own = member("a".repeat(64).as_str(), true, false);
        let live_other = member("b".repeat(64).as_str(), true, false);
        let stale_other = member("b".repeat(64).as_str(), false, false);
        let draining_other = member("b".repeat(64).as_str(), true, true);
        let agreeing_other = member("a".repeat(64).as_str(), true, false);
        let members = vec![
            own.clone(),
            live_other.clone(),
            stale_other,
            draining_other,
            agreeing_other,
        ];
        assert_eq!(
            fingerprint_disagreements(&members, own.instance_id, &own.fingerprint),
            vec![live_other.instance_id],
            "only the live, non-draining member with another fingerprint blocks"
        );
        let members_without_live_other = vec![member("b".repeat(64).as_str(), false, false)];
        assert!(
            fingerprint_disagreements(
                &members_without_live_other,
                own.instance_id,
                &own.fingerprint
            )
            .is_empty(),
            "a stale row is history, not a disagreement"
        );
    }

    #[test]
    fn the_readiness_gate_is_closed_until_agreement_and_then_sticky() {
        let readiness = ClusterReadiness::new();
        assert_eq!(
            readiness.blocked_reason(),
            Some(ClusterReadiness::FINGERPRINT_MISMATCH)
        );
        readiness.record_fingerprint_agreement();
        assert_eq!(readiness.blocked_reason(), None);
        readiness.record_fingerprint_agreement();
        assert!(readiness.fingerprint_agreed());
    }

    /// The durable contract fence excluding this binary is final: it is
    /// reported ahead of everything else the gate knows, it survives
    /// fingerprint agreement, and only the first record of it says so.
    #[test]
    fn a_fenced_replica_is_unready_for_good() {
        let readiness = ClusterReadiness::new();
        assert!(!readiness.contract_fenced());
        assert!(
            readiness.record_contract_fenced(),
            "the transition is reported once"
        );
        assert!(!readiness.record_contract_fenced());
        assert_eq!(
            readiness.blocked_reason(),
            Some(ClusterReadiness::CONTRACT_FENCED)
        );
        readiness.record_fingerprint_agreement();
        assert_eq!(
            readiness.blocked_reason(),
            Some(ClusterReadiness::CONTRACT_FENCED),
            "agreement does not reopen a fenced replica"
        );
    }
}
