//! What a policy, tools or policy test suite document commit's durable
//! evidence says about it (issue #425, PR 2c): the closed action vocabulary of
//! `document_change_evidence` (migration 23, widened by migration 29) and, in
//! cluster mode, the actor it records.
//!
//! The rows are written by the transaction they describe
//! (`postgres_documents::commit_in`), and only there. This module defines what
//! a caller hands that transaction, so the vocabulary exists once and the
//! handler that knows which operation it performed names it explicitly rather
//! than having it inferred from a diff summary. The actor is the one every
//! other authority-evidence writer records, `auth::change_actor::ChangeActor`:
//! since migration 32 a document row names a service token by its own kind and
//! a principal's issuer in canonical form, as migration 24's tables do.

/// The operation a policy or tools document commit performed, in the proposed
/// authority-event vocabulary (`docs/schemas/authority_event.v1.schema.json`).
/// Each code is exactly one of the values the `action` CHECK accepts
/// (migration 23's, replaced by migration 29's).
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
    /// The stored policy test suite replaced or first stored
    /// (`PUT /admin/policy/tests`, issue #243).
    PolicyTestsPublish,
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
            Self::PolicyTestsPublish => "policy_tests.publish",
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
            Self::PolicyTestsPublish => resource_type == "policy_tests",
        }
    }
}

/// What a document commit records about itself beyond the document: the
/// operation and the actor. Its event and operation IDs are minted by the
/// transaction that writes the row, once.
#[cfg(feature = "postgres")]
#[derive(Clone, Debug)]
pub struct DocumentChange {
    pub action: DocumentAction,
    /// Who made the change, recorded whole: its subject, canonical issuer,
    /// kind and auth mode.
    pub actor: crate::auth::change_actor::ChangeActor,
}

#[cfg(feature = "postgres")]
impl DocumentChange {
    /// An authenticated principal's change. A service-token caller is
    /// recorded as kind `service_token`, and an issuer in the canonical form
    /// audit and policy use (`ChangeActor::from_principal`).
    pub fn by_principal(action: DocumentAction, principal: &crate::auth::Principal) -> Self {
        Self {
            action,
            actor: crate::auth::change_actor::ChangeActor::from_principal(principal),
        }
    }

    /// The gateway's own change, under a fixed label naming the code path
    /// (`bootstrap` for the first-boot tools seed, `import-standalone` for the
    /// offline import). Never a person, and never a value a request can
    /// choose.
    pub fn system(action: DocumentAction, label: &'static str) -> Self {
        Self {
            action,
            actor: crate::auth::change_actor::ChangeActor::system(label),
        }
    }

    /// A test principal publishing a policy document.
    #[cfg(test)]
    pub(crate) fn test_policy(subject: &str) -> Self {
        Self {
            action: DocumentAction::PolicyPublish,
            actor: crate::auth::change_actor::ChangeActor::for_test(subject),
        }
    }

    /// A test principal publishing a tools document.
    #[cfg(test)]
    pub(crate) fn test_tools(subject: &str) -> Self {
        Self {
            action: DocumentAction::ToolsPublish,
            actor: crate::auth::change_actor::ChangeActor::for_test(subject),
        }
    }
}
