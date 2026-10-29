//! What a policy or tools document commit's durable evidence says about it
//! (issue #425, PR 2c): the closed action vocabulary of migration 23's
//! `document_change_evidence` and, in cluster mode, the actor it records.
//!
//! The rows are written by the transaction they describe
//! (`postgres_documents::commit_in`), and only there. This module defines what
//! a caller hands that transaction, so the vocabulary exists once and the
//! handler that knows which operation it performed names it explicitly rather
//! than having it inferred from a diff summary.

/// The operation a policy or tools document commit performed, in the proposed
/// authority-event vocabulary (`docs/schemas/authority_event.v1.schema.json`).
/// Each code is exactly one of the values migration 23's `action` CHECK
/// accepts.
///
/// Standalone policy writes pass one too. They record no evidence row: their
/// file and optional SQLite history are separate steps until the #242
/// revision ledger lands, so the action only names the operation
/// `AUTHORITY_EVIDENCE_DURABILITY=required` refuses (issue #425, PR 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
pub enum DocumentAction {
    /// The whole policy document replaced (`PUT /admin/policy`).
    PolicyPublish,
    /// An earlier policy version republished as a new version.
    PolicyRollback,
    PolicyRuleCreate,
    PolicyRuleUpdate,
    PolicyRuleDelete,
    PolicyRuleReorder,
    /// A discovery rule suggestion accepted: the rule it proposes, committed
    /// in the suggestion's own transaction.
    PolicySuggestionAccept,
    /// A tools document published: OpenAPI tools registered into the local
    /// lane, or the empty document a cluster seeds at first boot.
    ToolsPublish,
    /// The offline standalone import's activation of a policy or tools
    /// document (`import-standalone`).
    ConfigurationImport,
}

#[cfg(feature = "postgres")]
impl DocumentAction {
    /// The stored `action` code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::PolicyPublish => "policy.publish",
            Self::PolicyRollback => "policy.rollback",
            Self::PolicyRuleCreate => "policy.rule.create",
            Self::PolicyRuleUpdate => "policy.rule.update",
            Self::PolicyRuleDelete => "policy.rule.delete",
            Self::PolicyRuleReorder => "policy.rule.reorder",
            Self::PolicySuggestionAccept => "policy.suggestion.accept",
            Self::ToolsPublish => "tools.publish",
            Self::ConfigurationImport => "configuration.import",
        }
    }

    /// Whether this action can describe a commit of the document whose
    /// outbox `resource_type` is `resource_type`. Migration 23 enforces the
    /// same pairing; checking it first turns a caller's mistake into a
    /// refusal before any transaction opens.
    pub(crate) fn applies_to(self, resource_type: &str) -> bool {
        match self {
            Self::PolicyPublish
            | Self::PolicyRollback
            | Self::PolicyRuleCreate
            | Self::PolicyRuleUpdate
            | Self::PolicyRuleDelete
            | Self::PolicyRuleReorder
            | Self::PolicySuggestionAccept => resource_type == "policy",
            Self::ToolsPublish => resource_type == "tools",
            Self::ConfigurationImport => matches!(resource_type, "policy" | "tools"),
        }
    }
}

/// Who made an authority change, as its evidence records it.
#[cfg(feature = "postgres")]
#[derive(Clone, Copy, Debug)]
pub enum ChangeActor<'a> {
    /// An authenticated caller: its subject, the issuer that vouched for it
    /// and how it authenticated, exactly as the principal carries them.
    Principal {
        subject: &'a str,
        issuer: Option<&'a str>,
        auth_method: &'a crate::auth::AuthMethod,
    },
    /// The gateway itself, under a fixed label naming the code path
    /// (`bootstrap`, `import-standalone`). Never a person, and never a value
    /// a request can choose.
    System { label: &'static str },
}

#[cfg(feature = "postgres")]
impl<'a> ChangeActor<'a> {
    /// The authenticated principal behind an admin request.
    pub fn principal(principal: &'a crate::auth::Principal) -> Self {
        Self::Principal {
            subject: &principal.user_id,
            // An empty issuer names no issuer, so it is recorded as none
            // rather than as a zero-length value the column refuses.
            issuer: principal
                .issuer
                .as_deref()
                .filter(|issuer| !issuer.is_empty()),
            auth_method: &principal.auth_method,
        }
    }

    /// A bearer-token principal with no issuer, for tests that need an
    /// attributable actor and nothing more.
    #[cfg(test)]
    pub(crate) fn test_principal(subject: &'a str) -> Self {
        Self::Principal {
            subject,
            issuer: None,
            auth_method: &crate::auth::AuthMethod::Bearer,
        }
    }

    /// The stored `actor_kind`.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Principal { .. } => "principal",
            Self::System { .. } => "system",
        }
    }

    /// The stored `actor_user_id`: the principal's subject, or the system
    /// label. It is also what the document version row's own
    /// `actor_user_id` has always recorded.
    pub(crate) fn user_id(&self) -> &'a str {
        match self {
            Self::Principal { subject, .. } => subject,
            Self::System { label } => label,
        }
    }

    /// The stored `actor_issuer`.
    pub(crate) fn issuer(&self) -> Option<&'a str> {
        match self {
            Self::Principal { issuer, .. } => *issuer,
            Self::System { .. } => None,
        }
    }

    /// The stored `actor_auth_mode`: the audit stream's vocabulary for a
    /// principal, `system` for the gateway.
    pub(crate) fn auth_mode(&self) -> &'static str {
        match self {
            Self::Principal { auth_method, .. } => auth_method.audit_mode(),
            Self::System { .. } => "system",
        }
    }
}

/// What a document commit records about itself beyond the document: the
/// operation and the actor. Its event and operation IDs are minted by the
/// transaction that writes the row, once.
#[cfg(feature = "postgres")]
#[derive(Clone, Copy, Debug)]
pub struct DocumentChange<'a> {
    pub action: DocumentAction,
    pub actor: ChangeActor<'a>,
}

#[cfg(feature = "postgres")]
impl<'a> DocumentChange<'a> {
    /// An authenticated principal's change.
    pub fn by_principal(action: DocumentAction, principal: &'a crate::auth::Principal) -> Self {
        Self {
            action,
            actor: ChangeActor::principal(principal),
        }
    }

    /// A test principal publishing a policy document.
    #[cfg(test)]
    pub(crate) fn test_policy(subject: &'a str) -> Self {
        Self {
            action: DocumentAction::PolicyPublish,
            actor: ChangeActor::test_principal(subject),
        }
    }

    /// A test principal publishing a tools document.
    #[cfg(test)]
    pub(crate) fn test_tools(subject: &'a str) -> Self {
        Self {
            action: DocumentAction::ToolsPublish,
            actor: ChangeActor::test_principal(subject),
        }
    }
}
