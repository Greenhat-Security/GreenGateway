//! Required authority-change evidence (issue #425, PR 4).
//!
//! `AUTHORITY_EVIDENCE_DURABILITY=required` makes the gateway refuse an
//! authority change it cannot evidence instead of performing it and leaving
//! no durable record behind. What a deployment mode can evidence is what
//! `docs/authority-evidence-inventory.json` says each change's own
//! transaction records: a change is admitted only where that transaction
//! durably names who made it, beside the change. The inventory's
//! `required_mode` for every row is the contract; [`AuthorityOperation`]'s
//! table is its executable half, and a test holds the two together.
//!
//! Four places enforce it:
//!
//! - **Startup.** A configuration that enables an unsupported change on its
//!   own (`ADMIN_SESSION_MODE=standalone_memory`), or a gateway of either mode
//!   that would record evidence without a sink to deliver it, is refused by the
//!   configuration compiler (`config::authority_events`, `config::storage`).
//!   A configuration the compiler accepts is then refused by serving startup
//!   before preflight ([`startup_refusal`]): nothing records the activation
//!   of the configuration itself until issue #242, so required mode refuses
//!   to start in either deployment mode.
//! - **Requests.** Every admin endpoint that makes one of the changes below
//!   asks [`AuthorityEvidenceGate::admit`] once the caller is authorized and
//!   before anything is written, and answers a refusal `409` with reason
//!   [`REFUSAL_REASON`]: nothing has been changed.
//! - **Background activations.** A policy or tools file reload (file watcher
//!   or `SIGHUP`) asks through [`BackgroundEvidenceGate`]; a refused reload
//!   keeps the active document.
//! - **The offline import.** `gateway import-standalone` asks
//!   [`AuthorityEvidenceGate::refusal`] for its writing forms before it
//!   reads the source or opens the target, under the command's own
//!   environment; a refusal ends the command with nothing read or written.
//!
//! Each refusal of a request or a background activation is logged and
//! audited as `authority_evidence.operation_refused` with the operation's
//! inventory code, the deployment mode and what asked; the offline import,
//! which has no audit log of its own, prints its refusal and exits.
//! The gate reads configuration only: it never waits on a store, a sink or a
//! dispatcher, so no request -- an admin change or a proxied call -- waits on
//! a downstream acknowledgement because of it. Under `best_effort`, the
//! default, it admits everything, as before.

use serde_json::json;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    config::{AuthorityEvidenceDurability, Config, StateBackend},
    storage::DocumentAction,
};

/// The stable reason a refused change carries in its response, its log line
/// and its audit event.
pub(crate) const REFUSAL_REASON: &str = "authority_evidence_unsupported";

/// An authority change some deployment mode cannot evidence, named by its
/// operation code in the evidence inventory.
///
/// Only changes some deployment mode refuses are listed. An operation every
/// mode that performs it records in its own transaction never asks:
/// Connection create, replace and delete, local-secret changes and
/// re-encryption, managed catalog publication and overlay writes and
/// removals (the standalone Connections database's own evidence tables),
/// service-token issue, rotation and revocation, and JWT revocation. The
/// inventory test holds that rule too: an operation no gate asks about must
/// be `admitted` or `unavailable` wherever its row says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityOperation {
    PolicyPublish,
    PolicyRollback,
    PolicyRuleCreate,
    PolicyRuleUpdate,
    PolicyRuleDelete,
    PolicyRuleReorder,
    PolicySuggestionAccept,
    /// A watched or signalled reload of `POLICY_FILE`.
    PolicyFileReload,
    /// OpenAPI tools registered through the admin API, or a watched or
    /// signalled reload of `TOOLS_FILE`.
    ToolsPublish,
    /// The offline import (`gateway import-standalone`). Only cluster mode
    /// has one. Its policy and tools activations record evidence, but its
    /// Connections, audit, discovery and token sections commit without any,
    /// so required mode refuses its writing forms before anything is read
    /// or opened (owner ruling 7 on issue #425, 2026-11-20); the dry run
    /// writes nothing and is not asked. The document action names it too.
    ConfigurationImport,
    /// The stored policy test suite replaced or first stored (issue #243).
    PolicyTestsPublish,
    MutationApprovalPrepare,
    MutationApprovalConsume,
    MutationApprovalReview,
    MutationApprovalRevoke,
}

impl From<DocumentAction> for AuthorityOperation {
    fn from(action: DocumentAction) -> Self {
        match action {
            DocumentAction::PolicyPublish => Self::PolicyPublish,
            DocumentAction::PolicyRollback => Self::PolicyRollback,
            DocumentAction::PolicyRuleCreate => Self::PolicyRuleCreate,
            DocumentAction::PolicyRuleUpdate => Self::PolicyRuleUpdate,
            DocumentAction::PolicyRuleDelete => Self::PolicyRuleDelete,
            DocumentAction::PolicyRuleReorder => Self::PolicyRuleReorder,
            DocumentAction::PolicySuggestionAccept => Self::PolicySuggestionAccept,
            DocumentAction::ToolsPublish => Self::ToolsPublish,
            DocumentAction::ConfigurationImport => Self::ConfigurationImport,
            DocumentAction::PolicyTestsPublish => Self::PolicyTestsPublish,
        }
    }
}

/// How `AUTHORITY_EVIDENCE_DURABILITY=required` treats an operation in one
/// deployment mode, as the inventory's `required_mode` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequiredMode {
    /// The change's own transaction durably records who made it.
    Admitted,
    /// Only PostgreSQL's caller-keyed prepare persists an immutable receipt and event.
    CallerKeyRequired,
    /// The mode records no such evidence; the change is refused.
    Refused,
    /// The mode cannot perform the change at all, whatever the durability:
    /// its configuration refuses the store, or the store does not exist.
    Unavailable,
}

impl RequiredMode {
    /// The inventory's spelling.
    #[cfg_attr(not(test), allow(dead_code))] // compared with the inventory by the tests
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Refused => "refused",
            Self::CallerKeyRequired => "caller_key_required",
            Self::Unavailable => "unavailable",
        }
    }
}

impl AuthorityOperation {
    /// The operation code, exactly as the evidence inventory and the change
    /// evidence tables spell it.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::PolicyPublish => "policy.publish",
            Self::PolicyRollback => "policy.rollback",
            Self::PolicyRuleCreate => "policy.rule.create",
            Self::PolicyRuleUpdate => "policy.rule.update",
            Self::PolicyRuleDelete => "policy.rule.delete",
            Self::PolicyRuleReorder => "policy.rule.reorder",
            Self::PolicySuggestionAccept => "policy.suggestion.accept",
            Self::PolicyFileReload => "policy.file_reload",
            Self::ToolsPublish => "tools.publish",
            Self::ConfigurationImport => "configuration.import",
            Self::PolicyTestsPublish => "policy_tests.publish",
            Self::MutationApprovalConsume => "mutation_approval.consume",
            Self::MutationApprovalPrepare => "mutation_approval.prepare",
            Self::MutationApprovalReview => "mutation_approval.review",
            Self::MutationApprovalRevoke => "mutation_approval.revoke",
        }
    }

    /// What required mode does with this operation in a deployment mode.
    ///
    /// Live approvals expire in both modes. PostgreSQL retains a separate
    /// receipt and journal entry for caller-keyed preparation. It also
    /// commits the other supported changes with evidence in one
    /// PostgreSQL transaction, and has no policy file to reload. Standalone
    /// mode records none of them: the policy and tools files, their reloads
    /// and their optional history are separate steps, and the stored
    /// policy test suite's versions name only the writer's subject. (The
    /// Connections database records catalog and overlay publication in its
    /// own transaction, so those operations are not listed.) The offline
    /// import is refused in cluster mode because it records evidence for
    /// only two of its sections.
    pub(crate) const fn required_mode(self, backend: StateBackend) -> RequiredMode {
        match backend {
            StateBackend::Postgres => match self {
                Self::PolicyFileReload => RequiredMode::Unavailable,
                Self::MutationApprovalPrepare => RequiredMode::CallerKeyRequired,
                Self::MutationApprovalConsume
                | Self::MutationApprovalReview
                | Self::MutationApprovalRevoke
                | Self::ConfigurationImport => RequiredMode::Refused,
                Self::PolicyPublish
                | Self::PolicyRollback
                | Self::PolicyRuleCreate
                | Self::PolicyRuleUpdate
                | Self::PolicyRuleDelete
                | Self::PolicyRuleReorder
                | Self::PolicySuggestionAccept
                | Self::ToolsPublish
                | Self::PolicyTestsPublish => RequiredMode::Admitted,
            },
            StateBackend::Sqlite => match self {
                // `import-standalone` imports into PostgreSQL; a standalone
                // configuration is only its source.
                Self::ConfigurationImport => RequiredMode::Unavailable,
                _ => RequiredMode::Refused,
            },
        }
    }
}

/// The deployment mode's name in refusals.
const fn mode_name(backend: StateBackend) -> &'static str {
    match backend {
        StateBackend::Sqlite => "standalone",
        StateBackend::Postgres => "cluster",
    }
}

/// A change required mode refused. Nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvidenceRefusal {
    operation: AuthorityOperation,
    backend: StateBackend,
    /// `Refused` or `Unavailable`, never `Admitted`.
    mode: RequiredMode,
}

impl EvidenceRefusal {
    pub(crate) fn operation(&self) -> AuthorityOperation {
        self.operation
    }

    /// The operator-facing explanation, naming the operation and the mode
    /// and never anything from the request.
    pub(crate) fn message(&self) -> String {
        let why = match (self.mode, self.operation) {
            (RequiredMode::CallerKeyRequired, _) => {
                "requires a caller-bound preparation with qualified_v1"
            }
            (RequiredMode::Unavailable, _) => "does not perform it",
            (RequiredMode::Refused, AuthorityOperation::ConfigurationImport) => {
                "records evidence for only part of it"
            }
            (RequiredMode::Admitted | RequiredMode::Refused, _) => {
                "records no durable evidence of it"
            }
        };
        format!(
            "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: {} mode {why}; nothing was changed",
            self.operation.code(),
            mode_name(self.backend),
        )
    }
}

/// What asked for the change, for the refusal's audit event.
pub(crate) enum RefusalOrigin {
    /// An admin API request, with the caller the audit stream names.
    Request {
        request_id: String,
        source_ip: String,
        actor: Option<audit::Actor>,
    },
    /// A change no request asked for: a `file_watch` or `signal` reload.
    Background(&'static str),
}

impl RefusalOrigin {
    fn trigger(&self) -> &'static str {
        match self {
            Self::Request { .. } => "admin_api",
            Self::Background(trigger) => trigger,
        }
    }
}

/// Whether this deployment performs an authority change it cannot evidence.
/// Built once from the configuration, and as cheap to copy as the two
/// settings it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityEvidenceGate {
    format: crate::config::AuthorityEventFormat,
    durability: AuthorityEvidenceDurability,
    backend: StateBackend,
}

impl AuthorityEvidenceGate {
    pub(crate) const fn new(
        durability: AuthorityEvidenceDurability,
        backend: StateBackend,
    ) -> Self {
        Self {
            durability,
            backend,
            format: crate::config::AuthorityEventFormat::DeliveryV1,
        }
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            format: config.authority_events.format,
            ..Self::new(config.authority_events.durability, config.state_backend)
        }
    }

    /// A gate that admits every change: `best_effort` in standalone mode.
    #[cfg(test)]
    pub(crate) const fn best_effort() -> Self {
        Self::new(
            AuthorityEvidenceDurability::BestEffort,
            StateBackend::Sqlite,
        )
    }

    /// The refusal of `operation`, or `None` when this deployment performs
    /// it. Pure: records nothing.
    pub(crate) fn refusal(&self, operation: AuthorityOperation) -> Option<EvidenceRefusal> {
        match self.durability {
            AuthorityEvidenceDurability::BestEffort => None,
            AuthorityEvidenceDurability::Required => match operation.required_mode(self.backend) {
                RequiredMode::Admitted => None,
                // An operation the mode cannot perform is refused too: the
                // gate never admits what it cannot vouch for.
                mode @ (RequiredMode::Refused
                | RequiredMode::Unavailable
                | RequiredMode::CallerKeyRequired) => Some(EvidenceRefusal {
                    operation,
                    backend: self.backend,
                    mode,
                }),
            },
        }
    }

    pub(crate) fn has_prepare_receipts(&self) -> bool {
        AuthorityOperation::MutationApprovalPrepare.required_mode(self.backend)
            == RequiredMode::CallerKeyRequired
    }

    pub(crate) fn supports_keyed_prepare(&self) -> bool {
        self.has_prepare_receipts()
            && self.format == crate::config::AuthorityEventFormat::QualifiedV1
    }

    /// Admits `operation`, or records its refusal -- one warning and one
    /// `authority_evidence.operation_refused` audit event -- and returns it.
    pub(crate) fn admit(
        &self,
        operation: AuthorityOperation,
        audit: &AuditLog,
        origin: RefusalOrigin,
    ) -> Result<(), EvidenceRefusal> {
        let Some(refusal) = self.refusal(operation) else {
            return Ok(());
        };
        let trigger = origin.trigger();
        tracing::warn!(
            operation = operation.code(),
            deployment_mode = mode_name(self.backend),
            trigger,
            reason = REFUSAL_REASON,
            "AUTHORITY_EVIDENCE_DURABILITY=required refused an authority change this deployment mode records no evidence of; nothing was changed"
        );
        let payload = json!({
            "operation": operation.code(),
            "deployment_mode": mode_name(self.backend),
            "trigger": trigger,
            "reason": REFUSAL_REASON,
        });
        let event = match origin {
            RefusalOrigin::Request {
                request_id,
                source_ip,
                actor,
            } => AuditEvent::new(
                audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED,
                request_id,
                source_ip,
                actor,
                payload,
            ),
            RefusalOrigin::Background(_) => AuditEvent::new(
                audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED,
                "authority-evidence",
                "internal",
                None,
                payload,
            ),
        };
        audit.emit(event);
        Err(refusal)
    }
}

/// What serving startup is about to activate. Today this is the
/// environment-compiled configuration, which has no revision identity.
/// Issue #242 adds the ledger revision and the safe manifest digest of the
/// plan or bundle.
pub(crate) struct ActivationCandidate {
    pub(crate) backend: StateBackend,
}

/// Proof that the activation of exactly this candidate is durably recorded.
///
/// Uninhabited on purpose: no value can exist until issue #242 adds a
/// constructor that reads a ledger or activation record matching this
/// candidate (same digest, same revision), inside the activation stage and
/// atomically with it. A value granted to a whole backend, or one computed
/// before a store is open, is not a proof. Because a ledger record can only
/// be read once preflight has opened a store, that change also moves the
/// decision out of [`startup_refusal`]'s place before preflight and into
/// the activation stage, keeping its rule: nothing is published or served
/// before the proof exists. The evidence inventory's checker holds the
/// `configuration_activation` row at `refused_at_startup` while this type
/// is uninhabited, so the type, the check and the row change together.
pub(crate) enum ActivationProof {}

/// The proof that `candidate`'s activation is durably recorded, if one
/// exists. None can exist yet (see [`ActivationProof`]).
pub(crate) fn activation_proof(_candidate: &ActivationCandidate) -> Option<ActivationProof> {
    None
}

/// Serving startup refused under `AUTHORITY_EVIDENCE_DURABILITY=required`
/// because nothing records the activation of the configuration it would
/// serve (owner decision 2 of issue #425, 2026-11-19). No stage ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StartupEvidenceRefusal {
    backend: StateBackend,
}

impl StartupEvidenceRefusal {
    /// The stable code the refusal carries.
    pub(crate) const fn code(&self) -> &'static str {
        "authority_evidence_activation_unevidenced"
    }

    /// The operator-facing explanation. It names the setting, the operation
    /// and the deployment mode, and nothing read from the environment.
    pub(crate) fn message(&self) -> String {
        format!(
            "{}: AUTHORITY_EVIDENCE_DURABILITY=required refuses configuration.activate: {} mode records no durable evidence of the configuration it would activate (issue #242); nothing was activated",
            self.code(),
            mode_name(self.backend),
        )
    }
}

impl std::fmt::Display for StartupEvidenceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for StartupEvidenceRefusal {}

/// Whether serving startup must stop before preflight because required
/// mode cannot evidence the configuration's activation. `best_effort`, the
/// default, never refuses. Pure: reads configuration only. Offline commands
/// do not ask: they activate nothing, and those that change authority
/// (`revoke-jwt`) record their own evidence.
pub(crate) fn startup_refusal(config: &Config) -> Option<StartupEvidenceRefusal> {
    match config.authority_events.durability {
        AuthorityEvidenceDurability::BestEffort => None,
        AuthorityEvidenceDurability::Required => {
            let candidate = ActivationCandidate {
                backend: config.state_backend,
            };
            match activation_proof(&candidate) {
                Some(proof) => match proof {},
                None => Some(StartupEvidenceRefusal {
                    backend: candidate.backend,
                }),
            }
        }
    }
}

/// A gate with the audit log its refusals go to, for the background paths
/// that have no request to answer.
#[derive(Clone)]
pub(crate) struct BackgroundEvidenceGate {
    gate: AuthorityEvidenceGate,
    audit: AuditLog,
}

impl BackgroundEvidenceGate {
    pub(crate) fn new(gate: AuthorityEvidenceGate, audit: AuditLog) -> Self {
        Self { gate, audit }
    }

    /// Whether `operation`, started by `trigger`, may proceed. A refusal is
    /// recorded before this returns.
    pub(crate) fn admits(&self, operation: AuthorityOperation, trigger: &'static str) -> bool {
        self.gate
            .admit(operation, &self.audit, RefusalOrigin::Background(trigger))
            .is_ok()
    }
}

#[cfg(test)]
#[path = "required_tests.rs"]
mod tests;
