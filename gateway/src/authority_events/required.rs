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
//! Three places enforce it:
//!
//! - **Startup.** A configuration that enables an unsupported change on its
//!   own (`ADMIN_SESSION_MODE=standalone_memory`), or a cluster replica that
//!   would journal evidence without a sink to deliver it, is refused by the
//!   configuration compiler (`config::authority_events`, `config::storage`).
//! - **Requests.** Every admin endpoint that makes one of the changes below
//!   asks [`AuthorityEvidenceGate::admit`] once the caller is authorized and
//!   before anything is written, and answers a refusal `409` with reason
//!   [`REFUSAL_REASON`]: nothing has been changed.
//! - **Background activations.** A policy or tools file reload (file watcher
//!   or `SIGHUP`) asks through [`BackgroundEvidenceGate`]; a refused reload
//!   keeps the active document.
//!
//! Each refusal is logged and audited as `authority_evidence.operation_refused`
//! with the operation's inventory code, the deployment mode and what asked.
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
/// re-encryption (the standalone Connections database's own evidence
/// tables), service-token issue, rotation and revocation, and JWT
/// revocation. The inventory test holds that rule too: an operation no gate
/// asks about must be `admitted` or `unavailable` wherever its row says.
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
    CatalogMcpPublish,
    CatalogOpenapiPublish,
    CatalogOverlayReplace,
    CatalogOverlayDelete,
    /// The offline import's activation of a policy or tools document. Only
    /// cluster mode has one, and it records it; it is listed so that every
    /// document action names an operation.
    ConfigurationImport,
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
        }
    }
}

/// How `AUTHORITY_EVIDENCE_DURABILITY=required` treats an operation in one
/// deployment mode, as the inventory's `required_mode` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequiredMode {
    /// The change's own transaction durably records who made it.
    Admitted,
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
            Self::CatalogMcpPublish => "catalog.mcp.publish",
            Self::CatalogOpenapiPublish => "catalog.openapi.publish",
            Self::CatalogOverlayReplace => "catalog.overlay.replace",
            Self::CatalogOverlayDelete => "catalog.overlay.delete",
            Self::ConfigurationImport => "configuration.import",
        }
    }

    /// What required mode does with this operation in a deployment mode.
    ///
    /// Cluster mode commits every change here with its evidence row in one
    /// PostgreSQL transaction, and has no policy file to reload. Standalone
    /// mode records none of them: the policy and tools files, their reloads
    /// and their optional history are separate steps, and the Connections
    /// database keeps the current catalog and overlay but no evidence of who
    /// published them.
    pub(crate) const fn required_mode(self, backend: StateBackend) -> RequiredMode {
        match backend {
            StateBackend::Postgres => match self {
                Self::PolicyFileReload => RequiredMode::Unavailable,
                Self::PolicyPublish
                | Self::PolicyRollback
                | Self::PolicyRuleCreate
                | Self::PolicyRuleUpdate
                | Self::PolicyRuleDelete
                | Self::PolicyRuleReorder
                | Self::PolicySuggestionAccept
                | Self::ToolsPublish
                | Self::CatalogMcpPublish
                | Self::CatalogOpenapiPublish
                | Self::CatalogOverlayReplace
                | Self::CatalogOverlayDelete
                | Self::ConfigurationImport => RequiredMode::Admitted,
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
        let why = match self.mode {
            RequiredMode::Unavailable => "does not perform it",
            RequiredMode::Admitted | RequiredMode::Refused => "records no durable evidence of it",
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
        }
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self::new(config.authority_events.durability, config.state_backend)
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
                mode @ (RequiredMode::Refused | RequiredMode::Unavailable) => {
                    Some(EvidenceRefusal {
                        operation,
                        backend: self.backend,
                        mode,
                    })
                }
            },
        }
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
