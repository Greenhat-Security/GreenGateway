//! Conditional plan, apply, history and rollback over the standalone
//! revision ledger (issue #242, PR 11; ADR-0008, "Plan, risk acknowledgment,
//! and conditional apply" and "Ledger mode").
//!
//! A client preview never authorizes anything. [`RevisionService`] owns a
//! [`RevisionLedger`] and the plans made against it, and every decision is
//! made from what it compiles itself:
//!
//! - **Plan.** [`RevisionService::create_plan`] compiles a candidate (a
//!   submitted bundle, or a prior revision's stored content for a rollback)
//!   and the ledger's head with the caller's validators, and records an
//!   owner-scoped, expiring [`Plan`]: the base revision and its strong ETag,
//!   the candidate's source and semantic digests, the redacted semantic
//!   diff, its sorted risk codes, the union of permissions the change needs
//!   and its activation class. A change no ledger revision can carry (a
//!   bootstrap, Connection or secret, cluster or unsupported change) is
//!   refused here.
//! - **Acknowledge.** A plan carrying any risk code applies only after its
//!   owner acknowledges exactly that sorted set
//!   ([`RevisionService::acknowledge`]); the acknowledgement expires after
//!   [`ACKNOWLEDGEMENT_LIFETIME`] and never outlives its plan. There is no
//!   force flag. A risk ADR-0008 makes unacknowledgeable online
//!   (`risk.admin_access_path_removed`) is refused.
//! - **Apply.** [`RevisionService::apply`] requires `If-Match` and an
//!   idempotency key. A key the ledger already holds answers with the
//!   revision it made when the request is the same and is refused when it is
//!   not, before anything else is checked, so a retry after an ambiguous
//!   outcome never applies twice. Otherwise the ETag must name the current
//!   head (`412` when it does not), the plan must be the caller's, unexpired
//!   and made against that head, and the candidate is compiled again: its
//!   digests, risk codes, permissions and activation class must still be the
//!   plan's. Then the acknowledgement, the union of permissions, and the
//!   restart rules are checked, and the ledger appends the revision with its
//!   request in one transaction that compares the head again, so of two
//!   writers on one head exactly one wins.
//! - **Restart.** A `restart`-class change applies only when the caller asks
//!   to stage it, and while a restart is pending every new revision is staged
//!   only; a staged revision moves the desired pointer and leaves the active
//!   one where it was. Only a `live`-class change applied unstaged with no
//!   restart pending moves the active pointer, and the caller must then
//!   publish that revision's runtime snapshot or stop serving.
//! - **Rollback** is a plan whose candidate is a prior revision's stored
//!   content, held to the current validators, applied as a new forward
//!   revision under the same rules. It restores configuration only: never
//!   database schema, secret material, Connections or revoked credentials,
//!   none of which a ledger holds.
//! - **History and operations.** [`RevisionService::history`] pages the
//!   ledger newest first, and [`RevisionService::operation`] reads what a
//!   request with a given idempotency key made, which is what a client reads
//!   after an ambiguous outcome instead of resending.
//!
//! Evidence shares the commit: the revision record is the change's evidence,
//! written in the same transaction as the pointer move, and it carries the
//! actor, the operation, the plan, the digest of the request, the risk codes
//! the actor acknowledged and whether the revision was staged only. A failed
//! commit leaves no revision and no evidence; a committed one cannot lose
//! its evidence. Delivering that evidence to the gateway's audit pipeline,
//! the admin routes, and the ledger startup mode that publishes a live
//! revision are later #242 slices.
//!
//! Every error is a stable, value-free code. Like the rest of this crate the
//! service reads no clock, no environment and no randomness: callers pass the
//! time and the plan ID.

#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, SystemTime},
};

use serde_json::{json, Value};

use crate::bundle::{
    read_bundle_files, sha256_pin, Bundle, BundleDiagnostic, BundledResource, FileName,
    PublishedSchemasOnly, ReadOptions, ResourceValidators,
};
use crate::canonical_json;
use crate::ledger::{
    is_idempotency_key, ActivationClass, LedgerActor, LedgerError, LedgerState, Operation, PlanId,
    Proposal, RevisionCodes, RevisionId, RevisionLedger, RevisionRequest, RevisionSummary,
    MAX_REVISION_PAGE,
};
use crate::semantic_diff::{
    compare_bundles, BundleView, ChangeClass, Comparison, Display, RiskCode, Section, SemanticDiff,
};

/// How long a plan can be acknowledged and applied (ADR-0008, "Bounds").
pub const PLAN_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// How long a risk acknowledgement lasts; never beyond its plan.
pub const ACKNOWLEDGEMENT_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Live plans one actor may hold.
pub const MAX_PLANS_PER_ACTOR: usize = 8;
/// Live plans one deployment holds.
pub const MAX_PLANS: usize = 64;

/// Required to apply or roll back any revision.
pub const ADMIN_CONFIG_WRITE: &str = "admin:config:write";
/// Also required for a change to a secret reference, a credential binding or
/// where an identity's credentials are sent (ADR-0008, after ADR-0006).
pub const ADMIN_CONFIG_SECRETS_WRITE: &str = "admin:config:secrets:write";
/// Also required for a change to the policy resource.
pub const ADMIN_POLICY_WRITE: &str = "admin:policy:write";
/// Also required for a change to the tools resource.
pub const ADMIN_TOOLS_WRITE: &str = "admin:tools:write";

/// Risk codes ADR-0008 does not let an online request acknowledge: the
/// deployment channel is the remedy.
const NOT_ACKNOWLEDGEABLE_ONLINE: &[RiskCode] = &[RiskCode::AdminAccessPathRemoved];

/// The media type a candidate's semantic digest frames its normalized form
/// under.
const CANDIDATE_MEDIA_TYPE: &str = "application/vnd.greengateway.config-candidate+json";
/// The media type an apply request's binding digest frames it under.
const REQUEST_MEDIA_TYPE: &str = "application/vnd.greengateway.config-apply-request+json";
const DIGEST_SCHEMA_VERSION: &str = "v1";

/// How a caller compiles a bundle: the validators the bundle reader runs on
/// its policy and tools documents, and the normalized JSON form of what they
/// build, which the semantic digest and the diff compare.
pub trait PlanCompiler {
    type Validators: ResourceValidators;

    fn validators(&self) -> &Self::Validators;

    /// The validated policy as its loader models it, or `None` when it has
    /// no JSON form; a plan is then refused rather than left unbound.
    fn policy_value(&self, policy: &PolicyOf<Self>) -> Option<Value>;

    /// The validated tools as a tools document of `schema_version`, or
    /// `None` when they have no JSON form.
    fn tools_value(&self, schema_version: &'static str, tools: &ToolsOf<Self>) -> Option<Value>;
}

/// What a compiler's validators build from a policy document.
pub type PolicyOf<C> = <<C as PlanCompiler>::Validators as ResourceValidators>::Policy;
/// What a compiler's validators build from a tools document.
pub type ToolsOf<C> = <<C as PlanCompiler>::Validators as ResourceValidators>::Tools;

/// Compiles with the published schemas only, comparing documents as they
/// were written: what `ggctl` can run, since it cannot link the gateway's
/// production validators. The gateway compiles with those.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublishedSchemasCompiler;

impl PlanCompiler for PublishedSchemasCompiler {
    type Validators = PublishedSchemasOnly;

    fn validators(&self) -> &PublishedSchemasOnly {
        &PublishedSchemasOnly
    }

    fn policy_value(&self, policy: &Value) -> Option<Value> {
        Some(policy.clone())
    }

    fn tools_value(&self, _: &'static str, tools: &Value) -> Option<Value> {
        Some(tools.clone())
    }
}

/// The strong ETag of a ledger whose head is `head`: its record hash,
/// quoted. Opaque to clients, who send it back byte for byte.
pub fn revision_etag(head: &RevisionSummary) -> String {
    format!("\"{}\"", head.record_hash)
}

/// What a plan proposes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanSubject {
    /// A new bundle: the files of one flat bundle directory, by name. Every
    /// file must be one the manifest references.
    Bundle(BTreeMap<FileName, Vec<u8>>),
    /// A prior revision's content, again.
    Rollback(RevisionId),
}

/// An acknowledgement of a plan's exact risk codes by its owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    /// The sorted risk codes acknowledged: always the plan's.
    pub risk_codes: Vec<String>,
    pub expires_at: SystemTime,
}

/// A server-computed plan.
///
/// The service keeps its own copy; a caller's copy is a view, and changing
/// it changes nothing an apply checks.
#[derive(Clone, Debug)]
pub struct Plan {
    pub id: PlanId,
    /// The actor that made the plan; only it can read, acknowledge or apply
    /// it.
    pub owner: LedgerActor,
    /// [`Operation::Apply`] or [`Operation::Rollback`].
    pub operation: Operation,
    /// The head the plan was made against, and its strong ETag: the `If-Match`
    /// an apply must send.
    pub base: RevisionId,
    pub base_etag: String,
    /// The candidate's source digest (its manifest, and through the pins
    /// every file) and semantic digest (its normalized, validated form).
    pub source_digest: String,
    pub semantic_digest: String,
    /// The redacted semantic diff from the base to the candidate.
    pub diff: SemanticDiff,
    /// The sorted risk codes of the diff, which an apply needs acknowledged.
    pub risk_codes: Vec<String>,
    /// The sorted names of the changed sections.
    pub changed_sections: Vec<&'static str>,
    /// The sorted union of permissions an apply needs.
    pub required_permissions: Vec<&'static str>,
    /// `None` when the candidate changes nothing.
    pub activation: Option<ActivationClass>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub acknowledgement: Option<Acknowledgement>,
}

impl Plan {
    /// Whether an apply needs an acknowledgement of [`Self::risk_codes`].
    pub fn needs_acknowledgement(&self) -> bool {
        !self.risk_codes.is_empty()
    }

    /// Whether an online request can acknowledge every risk code.
    pub fn acknowledgeable_online(&self) -> bool {
        unacknowledgeable(&self.risk_codes).is_empty()
    }
}

/// An apply, or the apply of a rollback plan.
#[derive(Clone, Debug)]
pub struct ApplyRequest {
    pub plan: PlanId,
    /// The authenticated actor applying it, who must own the plan.
    pub actor: LedgerActor,
    /// The `If-Match` value, exactly as sent.
    pub if_match: Option<String>,
    /// The `Idempotency-Key` value, exactly as sent.
    pub idempotency_key: Option<String>,
    /// The bundle again, or the rollback target: what the plan proposed.
    pub subject: PlanSubject,
    /// Stage the revision without moving the active pointer.
    pub stage_only: bool,
}

/// What an apply did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Applied {
    pub revision: RevisionSummary,
    /// The answer replays an earlier request with the same idempotency key;
    /// nothing new was written.
    pub replayed: bool,
    /// The revision is the desired one now.
    pub desired: bool,
    /// The revision is the active one now. For a revision this request
    /// appended, the caller must publish its runtime snapshot or stop
    /// serving: the ledger already says it is active.
    pub active: bool,
    /// The desired revision is not the active one: a restart activates it.
    pub restart_pending: bool,
}

impl Applied {
    fn of(revision: RevisionSummary, replayed: bool, state: &LedgerState) -> Self {
        let desired = state.desired.revision == revision.revision;
        let active = state.active.as_ref() == Some(&revision.revision);
        Self {
            revision,
            replayed,
            desired,
            active,
            restart_pending: state.restart_pending(),
        }
    }
}

/// What a request with one idempotency key made, read after an ambiguous
/// outcome. It reports an earlier request, so `replayed` is always `true`.
pub type OperationStatus = Applied;

/// Which precondition an apply lacked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Precondition {
    IfMatch,
    IdempotencyKey,
}

/// Why a plan, acknowledgement or apply did not happen. Nothing was written.
///
/// Value-free: stable codes, fixed text, the current ETag, and permission
/// and risk codes. The comment on each variant is the HTTP status ADR-0008
/// gives it.
#[derive(Clone, Debug)]
pub enum RevisionError {
    /// `428`: no `If-Match` or no idempotency key.
    PreconditionRequired(Precondition),
    /// `400`: the idempotency key is outside its grammar.
    IdempotencyKeyInvalid,
    /// `412`: `If-Match` does not name the current head, whose ETag this is.
    PreconditionFailed { current: String },
    /// `404`: the rollback target is not a revision of this ledger.
    RollbackTargetUnknown,
    /// `409`: the rollback target is the head itself.
    RollbackTargetIsHead,
    /// `422`: the candidate, or the rollback target's stored content, fails
    /// the bundle reader or the validators.
    Invalid(Vec<BundleDiagnostic>),
    /// `409`: the head's stored content no longer passes the validators, so
    /// no change can be assessed against it. Recovery is the deployment
    /// channel.
    BaseInvalid,
    /// `422`: the validated candidate has no canonical normalized form.
    NotNormalizable,
    /// `409`: the candidate changes something no ledger revision carries;
    /// the classes, sorted.
    NotApplicable(Vec<&'static str>),
    /// `422`: the candidate differs from the base in a way the diff did not
    /// classify; refused rather than recorded without a code.
    Unclassified,
    /// `429`: the actor or the deployment holds the most live plans it may.
    QuotaExceeded,
    /// `409`: a live plan already has this ID.
    PlanIdInUse,
    /// `409`: no live plan of the actor's has this ID.
    PlanUnknown,
    /// `409`: the plan no longer describes the candidate against the head:
    /// the head moved, the subject differs, or recompiling changed a digest,
    /// a risk code, a permission or the activation class.
    PlanStale,
    /// `409`: the candidate changes nothing.
    NoChange,
    /// `409`: the plan carries risk codes and no live acknowledgement of
    /// exactly them.
    AcknowledgementRequired,
    /// `422`: the acknowledged codes are not exactly the plan's.
    AcknowledgementMismatch,
    /// `409`: the plan carries no risk code to acknowledge.
    NothingToAcknowledge,
    /// `409`: the plan carries risk codes no online request may acknowledge;
    /// the codes.
    NotAcknowledgeable(Vec<&'static str>),
    /// `409`: the idempotency key already applied a different request.
    IdempotencyConflict,
    /// `403`: the actor lacks these permissions of the plan's union.
    Forbidden(Vec<&'static str>),
    /// `409`: a `restart`-class change was not asked to be staged only.
    RestartRequired,
    /// `409`: a restart is pending, so a revision can only be staged.
    RestartPending,
    /// The ledger refused or failed: `ledger.unavailable` is `503`,
    /// `ledger.corrupt` stops the service, `ledger.full` is `409`.
    Ledger(LedgerError),
}

impl RevisionError {
    /// The stable code for reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PreconditionRequired(Precondition::IfMatch) => "apply.if_match_required",
            Self::PreconditionRequired(Precondition::IdempotencyKey) => {
                "apply.idempotency_key_required"
            }
            Self::IdempotencyKeyInvalid => "apply.idempotency_key_invalid",
            Self::PreconditionFailed { .. } => "apply.precondition_failed",
            Self::RollbackTargetUnknown => "plan.rollback_target_unknown",
            Self::RollbackTargetIsHead => "plan.rollback_target_is_head",
            Self::Invalid(_) => "plan.candidate_invalid",
            Self::BaseInvalid => "plan.base_invalid",
            Self::NotNormalizable => "plan.candidate_not_normalizable",
            Self::NotApplicable(_) => "plan.change_not_applicable",
            Self::Unclassified => "plan.change_unclassified",
            Self::QuotaExceeded => "plan.quota_exceeded",
            Self::PlanIdInUse => "plan.id_in_use",
            Self::PlanUnknown => "plan.unknown",
            Self::PlanStale => "plan.stale",
            Self::NoChange => "apply.no_change",
            Self::AcknowledgementRequired => "apply.acknowledgement_required",
            Self::AcknowledgementMismatch => "plan.acknowledgement_mismatch",
            Self::NothingToAcknowledge => "plan.nothing_to_acknowledge",
            Self::NotAcknowledgeable(_) => "plan.risk_not_acknowledgeable",
            Self::IdempotencyConflict => "apply.idempotency_conflict",
            Self::Forbidden(_) => "apply.permission_denied",
            Self::RestartRequired => "apply.restart_required",
            Self::RestartPending => "apply.restart_pending",
            Self::Ledger(error) => error.code(),
        }
    }
}

impl fmt::Display for RevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::PreconditionRequired(Precondition::IfMatch) => {
                "an apply needs If-Match with the ETag of the revision its plan was made against"
            }
            Self::PreconditionRequired(Precondition::IdempotencyKey) => {
                "an apply needs an idempotency key"
            }
            Self::IdempotencyKeyInvalid => {
                "an idempotency key is 1 to 128 ASCII letters, digits, '.', '_', ':' and '-'"
            }
            Self::PreconditionFailed { current } => {
                return write!(
                    formatter,
                    "the configuration ledger head has changed; its ETag is now {current}"
                );
            }
            Self::RollbackTargetUnknown => "the rollback target is not a revision of this ledger",
            Self::RollbackTargetIsHead => "the rollback target is the current revision",
            Self::Invalid(_) => "the candidate configuration is invalid",
            Self::BaseInvalid => {
                "the current revision no longer passes validation, so no change can be planned against it"
            }
            Self::NotNormalizable => "the candidate configuration has no canonical form",
            Self::NotApplicable(classes) => {
                return write!(
                    formatter,
                    "the candidate changes what no configuration revision can apply ({})",
                    classes.join(", ")
                );
            }
            Self::Unclassified => "the candidate differs in a way the diff could not classify",
            Self::QuotaExceeded => "too many live plans",
            Self::PlanIdInUse => "a live plan already has this ID",
            Self::PlanUnknown => "no live plan of yours has this ID",
            Self::PlanStale => {
                "the plan no longer describes this candidate against the current revision; plan again"
            }
            Self::NoChange => "the candidate changes nothing",
            Self::AcknowledgementRequired => {
                "the plan's risk codes need a live acknowledgement of exactly that set"
            }
            Self::AcknowledgementMismatch => {
                "an acknowledgement must name exactly the plan's risk codes"
            }
            Self::NothingToAcknowledge => "the plan carries no risk code",
            Self::NotAcknowledgeable(codes) => {
                return write!(
                    formatter,
                    "these risk codes cannot be acknowledged online; use the deployment channel ({})",
                    codes.join(", ")
                );
            }
            Self::IdempotencyConflict => {
                "the idempotency key already applied a different request"
            }
            Self::Forbidden(missing) => {
                return write!(
                    formatter,
                    "the change needs these permissions too ({})",
                    missing.join(", ")
                );
            }
            Self::RestartRequired => {
                "the change takes effect only after a restart; ask to stage it"
            }
            Self::RestartPending => {
                "a restart is pending, so a new revision can only be staged"
            }
            Self::Ledger(error) => return write!(formatter, "{error}"),
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for RevisionError {}

impl From<LedgerError> for RevisionError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

/// A bundle compiled by a [`PlanCompiler`], with the normalized form of its
/// documents and its semantic digest.
struct Compiled<P, T> {
    bundle: Bundle<P, T>,
    policy: Option<Value>,
    tools: Option<Value>,
    semantic_digest: String,
}

enum CompileFailure {
    Invalid(Vec<BundleDiagnostic>),
    NotNormalizable,
}

impl From<CompileFailure> for RevisionError {
    fn from(failure: CompileFailure) -> Self {
        match failure {
            CompileFailure::Invalid(diagnostics) => Self::Invalid(diagnostics),
            CompileFailure::NotNormalizable => Self::NotNormalizable,
        }
    }
}

/// Everything a plan says about a candidate against a head, computed afresh
/// for a plan and again for its apply.
struct Assessment<P, T> {
    operation: Operation,
    candidate: Compiled<P, T>,
    diff: SemanticDiff,
    risk_codes: Vec<String>,
    changed_sections: Vec<&'static str>,
    required_permissions: Vec<&'static str>,
    activation: Option<ActivationClass>,
}

/// Plans, acknowledgements and conditional applies over one ledger.
///
/// Every call takes `&mut self`: a gateway holds one service behind its
/// deployment mutation lock. A second service on the same ledger, in this
/// process or another, still cannot overwrite blindly, because each append
/// compares the head inside the ledger's own transaction.
pub struct RevisionService<C: PlanCompiler> {
    ledger: RevisionLedger,
    compiler: C,
    plans: BTreeMap<PlanId, Plan>,
}

impl<C: PlanCompiler> fmt::Debug for RevisionService<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevisionService")
            .field("ledger", &self.ledger)
            .field("plans", &self.plans.len())
            .finish_non_exhaustive()
    }
}

impl<C: PlanCompiler> RevisionService<C> {
    pub fn new(ledger: RevisionLedger, compiler: C) -> Self {
        Self {
            ledger,
            compiler,
            plans: BTreeMap::new(),
        }
    }

    /// The ledger's pointer and head.
    pub fn state(&mut self) -> Result<LedgerState, RevisionError> {
        Ok(self.ledger.state()?)
    }

    /// Plans `subject` against the current head for `owner`, under the
    /// caller-drawn `id`.
    pub fn create_plan(
        &mut self,
        id: PlanId,
        owner: LedgerActor,
        subject: PlanSubject,
        now: SystemTime,
    ) -> Result<Plan, RevisionError> {
        self.expire(now);
        if self.plans.contains_key(&id) {
            return Err(RevisionError::PlanIdInUse);
        }
        let owned = self
            .plans
            .values()
            .filter(|plan| same_actor(&plan.owner, &owner))
            .count();
        if owned >= MAX_PLANS_PER_ACTOR || self.plans.len() >= MAX_PLANS {
            return Err(RevisionError::QuotaExceeded);
        }
        let state = self.ledger.state()?;
        let assessment = self.assess(subject, &state.desired)?;
        let plan = Plan {
            id: id.clone(),
            owner,
            operation: assessment.operation,
            base: state.desired.revision.clone(),
            base_etag: revision_etag(&state.desired),
            source_digest: assessment.candidate.bundle.source_digest.clone(),
            semantic_digest: assessment.candidate.semantic_digest.clone(),
            diff: assessment.diff,
            risk_codes: assessment.risk_codes,
            changed_sections: assessment.changed_sections,
            required_permissions: assessment.required_permissions,
            activation: assessment.activation,
            created_at: now,
            // A clock at the end of its range makes a plan that is already
            // expired, never one that lasts forever.
            expires_at: now.checked_add(PLAN_LIFETIME).unwrap_or(now),
            acknowledgement: None,
        };
        self.plans.insert(id, plan.clone());
        Ok(plan)
    }

    /// The live plan `id`, when `owner` made it.
    pub fn plan(&mut self, id: &PlanId, owner: &LedgerActor, now: SystemTime) -> Option<Plan> {
        self.expire(now);
        self.plans
            .get(id)
            .filter(|plan| same_actor(&plan.owner, owner))
            .cloned()
    }

    /// Records `actor`'s acknowledgement of exactly `risk_codes`, which must
    /// be the plan's risk codes in any order.
    pub fn acknowledge<S: AsRef<str>>(
        &mut self,
        id: &PlanId,
        actor: &LedgerActor,
        risk_codes: &[S],
        now: SystemTime,
    ) -> Result<Plan, RevisionError> {
        self.expire(now);
        let plan = self
            .plans
            .get_mut(id)
            .filter(|plan| same_actor(&plan.owner, actor))
            .ok_or(RevisionError::PlanUnknown)?;
        if plan.risk_codes.is_empty() {
            return Err(RevisionError::NothingToAcknowledge);
        }
        let refused = unacknowledgeable(&plan.risk_codes);
        if !refused.is_empty() {
            return Err(RevisionError::NotAcknowledgeable(refused));
        }
        let acknowledged: BTreeSet<&str> = risk_codes.iter().map(AsRef::as_ref).collect();
        let expected: BTreeSet<&str> = plan.risk_codes.iter().map(String::as_str).collect();
        if acknowledged != expected {
            return Err(RevisionError::AcknowledgementMismatch);
        }
        let expires_at = now
            .checked_add(ACKNOWLEDGEMENT_LIFETIME)
            .unwrap_or(now)
            .min(plan.expires_at);
        plan.acknowledgement = Some(Acknowledgement {
            risk_codes: plan.risk_codes.clone(),
            expires_at,
        });
        Ok(plan.clone())
    }

    /// Applies a plan, conditionally. `permitted` answers whether the actor
    /// holds one permission; the service asks it for every permission of the
    /// plan's union.
    pub fn apply(
        &mut self,
        request: ApplyRequest,
        permitted: impl Fn(&str) -> bool,
        now: SystemTime,
    ) -> Result<Applied, RevisionError> {
        let if_match = request
            .if_match
            .clone()
            .ok_or(RevisionError::PreconditionRequired(Precondition::IfMatch))?;
        let key = request
            .idempotency_key
            .clone()
            .ok_or(RevisionError::PreconditionRequired(
                Precondition::IdempotencyKey,
            ))?;
        if !is_idempotency_key(&key) {
            return Err(RevisionError::IdempotencyKeyInvalid);
        }
        let binding = request_binding(&request, &if_match)?;
        // A key already used answers before anything else is checked: the
        // head has moved on since, and the plan is gone.
        if let Some(earlier) = self.ledger.revision_for_request(&key)? {
            return self.replay(earlier, &binding);
        }

        self.expire(now);
        let plan = self
            .plans
            .get(&request.plan)
            .filter(|plan| same_actor(&plan.owner, &request.actor))
            .cloned()
            .ok_or(RevisionError::PlanUnknown)?;
        let state = self.ledger.state()?;
        let current = revision_etag(&state.desired);
        if if_match != current {
            return Err(RevisionError::PreconditionFailed { current });
        }
        if plan.base != state.desired.revision
            || plan.base_etag != if_match
            || !subject_matches(&plan.operation, &request.subject)
        {
            return Err(RevisionError::PlanStale);
        }
        let assessment = self.assess(request.subject, &state.desired)?;
        if assessment.operation != plan.operation
            || assessment.candidate.bundle.source_digest != plan.source_digest
            || assessment.candidate.semantic_digest != plan.semantic_digest
            || assessment.risk_codes != plan.risk_codes
            || assessment.required_permissions != plan.required_permissions
            || assessment.activation != plan.activation
        {
            return Err(RevisionError::PlanStale);
        }
        let activation = assessment.activation.ok_or(RevisionError::NoChange)?;
        if !assessment.risk_codes.is_empty() {
            let refused = unacknowledgeable(&assessment.risk_codes);
            if !refused.is_empty() {
                return Err(RevisionError::NotAcknowledgeable(refused));
            }
            let acknowledged = plan
                .acknowledgement
                .as_ref()
                .is_some_and(|acknowledgement| {
                    now < acknowledgement.expires_at
                        && acknowledgement.risk_codes == assessment.risk_codes
                });
            if !acknowledged {
                return Err(RevisionError::AcknowledgementRequired);
            }
        }
        let missing: Vec<&'static str> = assessment
            .required_permissions
            .iter()
            .copied()
            .filter(|permission| !permitted(permission))
            .collect();
        if !missing.is_empty() {
            return Err(RevisionError::Forbidden(missing));
        }
        if !request.stage_only {
            if activation == ActivationClass::Restart {
                return Err(RevisionError::RestartRequired);
            }
            if state.restart_pending() {
                return Err(RevisionError::RestartPending);
            }
        }

        let revision_request = RevisionRequest::new(
            plan.id.clone(),
            &key,
            &binding,
            &assessment.risk_codes,
            request.stage_only,
        )?;
        let codes = RevisionCodes::new(
            &assessment.changed_sections,
            &assessment
                .risk_codes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &assessment.required_permissions,
        )?;
        let appended = self.ledger.append(
            &plan.base,
            Proposal {
                bundle: &assessment.candidate.bundle,
                actor: request.actor,
                operation: assessment.operation,
                activation,
                codes,
                request: Some(revision_request),
                recorded_at: now,
            },
        );
        match appended {
            Ok(revision) => {
                self.plans.remove(&plan.id);
                let state = self.ledger.state()?;
                Ok(Applied::of(revision, false, &state))
            }
            // Another writer moved the head between the read above and the
            // append: the ledger compared it again and wrote nothing.
            Err(LedgerError::Stale { .. }) => {
                let state = self.ledger.state()?;
                Err(RevisionError::PreconditionFailed {
                    current: revision_etag(&state.desired),
                })
            }
            // Another writer applied this key in between.
            Err(LedgerError::IdempotencyKeyUsed { .. }) => {
                let earlier = self
                    .ledger
                    .revision_for_request(&key)?
                    .ok_or(RevisionError::IdempotencyConflict)?;
                self.replay(earlier, &binding)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Up to `limit` revisions (at most [`MAX_REVISION_PAGE`]), newest
    /// first, below sequence `before` when given.
    pub fn history(
        &mut self,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<RevisionSummary>, RevisionError> {
        Ok(self
            .ledger
            .revisions(before, limit.min(MAX_REVISION_PAGE))?)
    }

    /// What the request with idempotency key `key` made, if any revision
    /// records it: what a client reads after an ambiguous outcome instead of
    /// sending the request again.
    pub fn operation(&mut self, key: &str) -> Result<Option<OperationStatus>, RevisionError> {
        let Some(revision) = self.ledger.revision_for_request(key)? else {
            return Ok(None);
        };
        let state = self.ledger.state()?;
        Ok(Some(Applied::of(revision, true, &state)))
    }

    fn replay(
        &mut self,
        earlier: RevisionSummary,
        binding: &str,
    ) -> Result<Applied, RevisionError> {
        let same = earlier
            .request
            .as_ref()
            .is_some_and(|request| request.binding() == binding);
        if !same {
            return Err(RevisionError::IdempotencyConflict);
        }
        let state = self.ledger.state()?;
        Ok(Applied::of(earlier, true, &state))
    }

    fn expire(&mut self, now: SystemTime) {
        self.plans.retain(|_, plan| now < plan.expires_at);
    }

    /// Compiles the head and the candidate and assesses the change between
    /// them.
    fn assess(
        &mut self,
        subject: PlanSubject,
        head: &RevisionSummary,
    ) -> Result<Assessment<PolicyOf<C>, ToolsOf<C>>, RevisionError> {
        let base = self
            .ledger
            .revision(&head.revision)?
            .ok_or(RevisionError::BaseInvalid)?;
        let base = compile(&self.compiler, stored_files(base.files))
            .map_err(|_| RevisionError::BaseInvalid)?;
        let (operation, candidate) = match subject {
            PlanSubject::Bundle(files) => (Operation::Apply, compile(&self.compiler, files)?),
            PlanSubject::Rollback(target) => {
                if target == head.revision {
                    return Err(RevisionError::RollbackTargetIsHead);
                }
                let stored = self
                    .ledger
                    .revision(&target)?
                    .ok_or(RevisionError::RollbackTargetUnknown)?;
                let candidate = compile(&self.compiler, stored_files(stored.files))?;
                (Operation::Rollback { target }, candidate)
            }
        };
        let diff = diff(&base, &candidate);
        if diff.is_empty() && base.semantic_digest != candidate.semantic_digest {
            return Err(RevisionError::Unclassified);
        }
        let activation = activation_class(&diff)?;
        let risk_codes = diff
            .risks()
            .into_iter()
            .map(|risk| risk.as_str().to_owned())
            .collect();
        let changed_sections = diff
            .sections()
            .into_iter()
            .map(Section::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let required_permissions = required_permissions(&diff);
        Ok(Assessment {
            operation,
            candidate,
            diff,
            risk_codes,
            changed_sections,
            required_permissions,
            activation,
        })
    }
}

/// Whether two actors are the same identity, however each authenticated.
fn same_actor(a: &LedgerActor, b: &LedgerActor) -> bool {
    a.kind() == b.kind() && a.subject() == b.subject() && a.issuer() == b.issuer()
}

/// The codes of `risk_codes` no online request may acknowledge, sorted.
fn unacknowledgeable(risk_codes: &[String]) -> Vec<&'static str> {
    NOT_ACKNOWLEDGEABLE_ONLINE
        .iter()
        .map(|risk| risk.as_str())
        .filter(|code| risk_codes.iter().any(|risk| risk == code))
        .collect()
}

/// Whether an apply's subject is the one its plan proposed: a bundle for an
/// apply plan, the same target for a rollback plan.
fn subject_matches(operation: &Operation, subject: &PlanSubject) -> bool {
    match (operation, subject) {
        (Operation::Apply, PlanSubject::Bundle(_)) => true,
        (Operation::Rollback { target }, PlanSubject::Rollback(requested)) => target == requested,
        _ => false,
    }
}

/// The digest an idempotency key is bound to: the plan, the `If-Match`
/// value, the stage-only flag, the actor's identity (however it
/// authenticated, as plan ownership counts it), and the subject (each
/// submitted file's name and SHA-256, or the rollback target). The same
/// request again has the same digest; any other has another.
fn request_binding(request: &ApplyRequest, if_match: &str) -> Result<String, RevisionError> {
    let subject = match &request.subject {
        PlanSubject::Bundle(files) => {
            let files: serde_json::Map<String, Value> = files
                .iter()
                .map(|(name, bytes)| (name.as_str().to_owned(), json!(sha256_pin(bytes))))
                .collect();
            json!({ "bundle": files })
        }
        PlanSubject::Rollback(target) => json!({ "rollback": target.as_str() }),
    };
    let actor = &request.actor;
    let value = json!({
        "plan": request.plan.as_str(),
        "if_match": if_match,
        "stage_only": request.stage_only,
        "actor": {
            "kind": actor.kind().as_str(),
            "subject": actor.subject(),
            "issuer": actor.issuer(),
        },
        "subject": subject,
    });
    canonical_json::semantic_digest(REQUEST_MEDIA_TYPE, DIGEST_SCHEMA_VERSION, &value)
        .map_err(|_| RevisionError::NotNormalizable)
}

/// A stored revision's files, by name, as the reader takes them.
fn stored_files(files: Vec<crate::bundle::SourceFile>) -> BTreeMap<FileName, Vec<u8>> {
    files
        .into_iter()
        .map(|file| (file.name, file.bytes))
        .collect()
}

/// Reads `files` with the compiler's validators, strictly: a candidate is
/// exactly the files its manifest references.
fn compile<C: PlanCompiler>(
    compiler: &C,
    files: BTreeMap<FileName, Vec<u8>>,
) -> Result<Compiled<PolicyOf<C>, ToolsOf<C>>, CompileFailure> {
    let report = read_bundle_files(files, ReadOptions { strict: true }, compiler.validators());
    let Some(bundle) = report.bundle else {
        return Err(CompileFailure::Invalid(report.diagnostics));
    };
    let policy = match &bundle.policy {
        Some(BundledResource::Bundle { document, .. }) => Some(
            compiler
                .policy_value(document)
                .ok_or(CompileFailure::NotNormalizable)?,
        ),
        _ => None,
    };
    let tools = match &bundle.tools {
        Some(BundledResource::Bundle {
            schema_version,
            document,
            ..
        }) => Some(
            compiler
                .tools_value(schema_version, document)
                .ok_or(CompileFailure::NotNormalizable)?,
        ),
        _ => None,
    };
    let semantic_digest = semantic_digest(&bundle, policy.as_ref(), tools.as_ref())
        .ok_or(CompileFailure::NotNormalizable)?;
    Ok(Compiled {
        bundle,
        policy,
        tools,
        semantic_digest,
    })
}

/// The `GGDIGEST` semantic frame of a compiled bundle's normalized form:
/// its document version, name and profile, its deployment document, where
/// each resource comes from with its normalized document, and the
/// Connections source. Formatting, member order and anything the validators
/// normalize do not change it.
fn semantic_digest<P, T>(
    bundle: &Bundle<P, T>,
    policy: Option<&Value>,
    tools: Option<&Value>,
) -> Option<String> {
    fn resource<R>(resource: Option<&BundledResource<R>>, normalized: Option<&Value>) -> Value {
        match resource {
            None => Value::Null,
            Some(BundledResource::Server) => json!("server"),
            Some(BundledResource::Bundle { schema_version, .. }) => {
                json!({ "schema_version": schema_version, "document": normalized })
            }
        }
    }
    let deployment: Value = serde_json::from_slice(&bundle.deployment.canonical_json).ok()?;
    let value = json!({
        "api_version": bundle.api_version.as_str(),
        "name": bundle.name,
        "profile": bundle.deployment.profile.as_str(),
        "deployment": deployment,
        "policy": resource(bundle.policy.as_ref(), policy),
        "tools": resource(bundle.tools.as_ref(), tools),
        "connections_from_server": bundle.connections_from_server,
    });
    canonical_json::semantic_digest(CANDIDATE_MEDIA_TYPE, DIGEST_SCHEMA_VERSION, &value).ok()
}

/// The semantic diff from `base` to `candidate`, by their normalized
/// documents.
fn diff<P, T>(base: &Compiled<P, T>, candidate: &Compiled<P, T>) -> SemanticDiff {
    let mut comparison = Comparison::new();
    compare_bundles(
        &mut comparison,
        &BundleView::of(&base.bundle, base.policy.as_ref(), base.tools.as_ref()),
        &BundleView::of(
            &candidate.bundle,
            candidate.policy.as_ref(),
            candidate.tools.as_ref(),
        ),
    );
    comparison.finish()
}

/// The activation class of a diff: `None` when it is empty, `restart` when
/// any change is, `live` when every change is. Any other class is refused:
/// no ledger revision performs a bootstrap, Connection or secret, cluster or
/// unsupported change.
fn activation_class(diff: &SemanticDiff) -> Result<Option<ActivationClass>, RevisionError> {
    let mut refused = BTreeSet::new();
    let mut restart = false;
    for change in diff.changes() {
        match change.class() {
            ChangeClass::Live => {}
            ChangeClass::Restart => restart = true,
            other => {
                refused.insert(other.as_str());
            }
        }
    }
    if !refused.is_empty() {
        return Err(RevisionError::NotApplicable(refused.into_iter().collect()));
    }
    Ok(match (diff.is_empty(), restart) {
        (true, _) => None,
        (false, true) => Some(ActivationClass::Restart),
        (false, false) => Some(ActivationClass::Live),
    })
}

/// The union of permissions a diff needs: [`ADMIN_CONFIG_WRITE`] always,
/// [`ADMIN_POLICY_WRITE`] and [`ADMIN_TOOLS_WRITE`] for any change to those
/// resources, their source or their content (a policy's egress members
/// included, which belong to the egress section), and
/// [`ADMIN_CONFIG_SECRETS_WRITE`] for a change to a secret reference or
/// credential binding, or to identity trust, which decides where credentials
/// are sent. Sorted.
fn required_permissions(diff: &SemanticDiff) -> Vec<&'static str> {
    let mut required = BTreeSet::from([ADMIN_CONFIG_WRITE]);
    for change in diff.changes() {
        let field = change.field();
        let resource = |name: &str| {
            field
                .strip_prefix("resources.")
                .unwrap_or(field)
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.'))
        };
        if change.section() == Section::Policy || resource("policy") {
            required.insert(ADMIN_POLICY_WRITE);
        }
        if change.section() == Section::Tools || resource("tools") {
            required.insert(ADMIN_TOOLS_WRITE);
        }
        let secret = matches!(change.display(), Display::Reference)
            || change.risks().contains(&RiskCode::CredentialBindingChanged)
            || change.risks().contains(&RiskCode::AuthTrustChanged);
        if secret {
            required.insert(ADMIN_CONFIG_SECRETS_WRITE);
        }
    }
    required.into_iter().collect()
}
