//! Operation requirements and member capability advertisements (issue
//! #426, PR 1).
//!
//! `migrations.rs` decides whether this binary may serve a schema at all:
//! migration history integrity first, then the explicit read/write
//! contract. Neither decides whether one particular *write* is safe while
//! other replicas share the database. A replica that serves the schema can
//! still be unable to interpret, or to enforce, data that a newer replica
//! writes through an operation the older one has never heard of. This
//! module is that third decision, made per operation:
//!
//! - **Capabilities** are a closed vocabulary ([`Capability`]). A binary
//!   advertises the capabilities it implements on its own roster row
//!   (`cluster_members.capabilities`, migration 17), rendered by
//!   [`advertisement`]. A reader recognizes only names compiled into it
//!   ([`RecognizedCapabilities`]): a name it does not know -- a newer
//!   gateway's, or one written by hand -- is counted and grants nothing,
//!   and a value outside the column's bounds grants nothing at all.
//! - **Operation requirements** ([`OperationRequirement`]) name, for one
//!   write operation, the lowest schema version whose objects it writes,
//!   the document format major it writes (if any), the capability every
//!   live member must advertise, the backfill it depends on, and the
//!   activation fence it needs.
//! - **The gate** ([`evaluate`]) admits an operation only when this binary
//!   satisfies the requirement itself and every live roster member --
//!   draining members included, because they still answer what was routed
//!   to them -- advertises the capability, recognizes the schema, and reads
//!   the document format. Anything else is a refusal with a stable reason
//!   ([`OperationRefusal`]); there is no best-effort write.
//!
//! What the gate is not: a durable fence. Liveness is judged on the
//! database clock against `CLUSTER_MEMBER_STALE_MS`, so a member that lacks
//! a capability can be stopped, swept, and started again after an operation
//! was admitted. An operation whose data such a member would *misread*,
//! rather than refuse, declares [`Activation::DurableFence`] and is refused
//! outright until the contract-fencing slice of #426 provides that fence.
//! Likewise there is no backfill state yet, so an operation that needs a
//! completed backfill ([`Backfill::Required`]) is refused. Schema presence
//! alone never enables an operation.
//!
//! The registry ([`OPERATION_REQUIREMENTS`]) holds one operation (issue
//! #426, PR 2): committing a policy document in which a role carries a
//! `description` ([`POLICY_ROLE_DESCRIPTIONS`]). A gateway built before the
//! field refuses such a document outright -- the role's fields are closed --
//! so the write waits until every live member advertises
//! [`Capability::PolicyRoleDescriptions`], and a member that lacks it and
//! returns later fails closed on the document rather than misreading it.
//! The approved-extension list in `migrations.rs` stays empty: the operation
//! changes no schema, and no schema overlap has been qualified. Every other
//! operation this binary performs belongs to the schema-18 contract, which
//! every schema-18 member shares.

use std::collections::BTreeSet;

/// The most capability names one roster row may carry. Migration 17's
/// check constraint enforces the same bound.
pub(crate) const MAX_ADVERTISED_CAPABILITIES: usize = 32;

/// The longest capability name, in bytes. Names are lowercase ASCII
/// letters, digits and underscores, starting with a letter.
pub(crate) const MAX_CAPABILITY_NAME_BYTES: usize = 64;

/// The longest advertisement a reader will consider: every name at its
/// longest, plus the separators between them.
const MAX_ADVERTISEMENT_BYTES: usize =
    MAX_ADVERTISED_CAPABILITIES * MAX_CAPABILITY_NAME_BYTES + MAX_ADVERTISED_CAPABILITIES - 1;

/// Separates names in the roster column.
const SEPARATOR: char = ',';

/// One capability a member can advertise. Closed: a binary advertises only
/// these, and recognizes only these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Capability {
    /// The member advertises its capabilities on its own roster row and
    /// holds a registered operation at the gate until every live member
    /// advertises what the operation requires (schema 17). A member
    /// without it predates the protocol and can be shown to support
    /// nothing.
    OperationRequirements,
    /// The member reads, validates and serves a policy document whose roles
    /// carry a `description` (issue #426, PR 2). A member without it refuses
    /// such a document, so [`POLICY_ROLE_DESCRIPTIONS`] waits for it.
    PolicyRoleDescriptions,
}

impl Capability {
    /// Every capability, in name order.
    pub(crate) const KNOWN: [Self; 2] = [Self::OperationRequirements, Self::PolicyRoleDescriptions];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OperationRequirements => "operation_requirements",
            Self::PolicyRoleDescriptions => "policy_role_descriptions",
        }
    }

    fn recognize(name: &str) -> Option<Self> {
        Self::KNOWN
            .into_iter()
            .find(|capability| capability.as_str() == name)
    }
}

/// What this binary advertises: every capability it implements.
pub(crate) const BINARY_CAPABILITIES: &[Capability] = &[
    Capability::OperationRequirements,
    Capability::PolicyRoleDescriptions,
];

/// The roster column's value for a capability set: the names sorted,
/// deduplicated and comma-separated. `None` when the set is larger than
/// the column admits, which the heartbeat refuses rather than truncates.
pub(crate) fn advertisement(capabilities: &[Capability]) -> Option<String> {
    let set: BTreeSet<Capability> = capabilities.iter().copied().collect();
    if set.len() > MAX_ADVERTISED_CAPABILITIES {
        return None;
    }
    let names: Vec<&str> = set.iter().map(|capability| capability.as_str()).collect();
    Some(names.join(","))
}

/// A roster row's advertisement as this binary understands it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecognizedCapabilities {
    known: BTreeSet<Capability>,
    unrecognized: usize,
}

impl RecognizedCapabilities {
    /// Read a raw `capabilities` value. Known names are kept; anything
    /// else is counted and grants nothing. A value larger than the column
    /// admits is recognized as nothing: its bound is part of the contract,
    /// and a row that breaks it cannot be trusted for any of its names.
    pub(crate) fn parse(raw: &str) -> Self {
        if raw.is_empty() {
            return Self::default();
        }
        let count = raw.split(SEPARATOR).count();
        if count > MAX_ADVERTISED_CAPABILITIES || raw.len() > MAX_ADVERTISEMENT_BYTES {
            return Self {
                known: BTreeSet::new(),
                unrecognized: count,
            };
        }
        let mut recognized = Self::default();
        for name in raw.split(SEPARATOR) {
            match Capability::recognize(name) {
                Some(capability) => {
                    recognized.known.insert(capability);
                }
                None => recognized.unrecognized += 1,
            }
        }
        recognized
    }

    /// Whether the row advertises `capability`. Only the gate asks, so a
    /// build without cluster mode has no caller outside the tests.
    #[cfg(any(test, feature = "postgres"))]
    pub(crate) fn contains(&self, capability: Capability) -> bool {
        self.known.contains(&capability)
    }

    /// The recognized names, in name order. Only compiled-in names can
    /// appear here, so the list is safe to show on any surface.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.known
            .iter()
            .map(|capability| capability.as_str())
            .collect()
    }

    /// How many advertised names this binary did not recognize.
    pub(crate) fn unrecognized(&self) -> usize {
        self.unrecognized
    }
}

// --- operation requirements and the gate (cluster mode only) -----------------

#[cfg(feature = "postgres")]
pub(crate) use gate::{
    evaluate, BinaryContract, MemberAdvertisement, OperationAdmission, OperationRefusal,
    OperationRequirement, OPERATION_REQUIREMENTS, POLICY_ROLE_DESCRIPTIONS,
};
// Named by registry entries and their tests.
#[cfg(all(feature = "postgres", test))]
pub(crate) use gate::{Activation, Backfill};

#[cfg(feature = "postgres")]
mod gate {
    use std::fmt;

    use uuid::Uuid;

    use super::{Capability, RecognizedCapabilities};

    /// Whether an operation depends on a backfill having completed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // `Required` is constructed only by tests: no shipped operation needs a backfill.
    pub(crate) enum Backfill {
        /// The operation reads nothing a backfill must first produce.
        NotRequired,
        /// The operation needs the named backfill completed and verified.
        /// No backfill state exists in this release, so the operation is
        /// refused.
        Required { name: &'static str },
    }

    /// What keeps a member that lacks the capability from serving the
    /// operation's data later.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // `DurableFence` is constructed only by tests: no shipped operation needs one.
    pub(crate) enum Activation {
        /// Live-roster agreement is enough: a lacking member that returns
        /// after the operation wrote refuses the data (fails closed)
        /// rather than misreading it.
        LiveMembers,
        /// A lacking member that returned would misread the data, so the
        /// operation needs a durable activation fence. None exists in this
        /// release, so the operation is refused.
        DurableFence,
    }

    /// What one write operation needs from every replica that shares the
    /// database.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct OperationRequirement {
        /// A stable name for logs, audit and the error: lowercase
        /// dot-separated words.
        pub(crate) operation: &'static str,
        /// The lowest schema version whose objects the operation writes.
        /// Every live member must advertise a serving range reaching it.
        pub(crate) minimum_schema: i32,
        /// The document format major the operation writes, when it writes a
        /// policy or tools document. Every live member's advertised
        /// document range must include it.
        pub(crate) document_format: Option<i32>,
        /// The capability every live member must advertise.
        pub(crate) capability: Capability,
        pub(crate) backfill: Backfill,
        pub(crate) activation: Activation,
    }

    /// Committing a policy document in which any role carries a
    /// `description`.
    ///
    /// A gateway that predates the field cannot parse the document at all:
    /// `RoleEntry` refuses unknown fields. A running one stops compiling the
    /// active revision and holds readiness at
    /// `security_revision_not_compiled`, serving nothing under the policy it
    /// had; a starting one refuses to boot. That is failing closed, never a
    /// misreading, so live-roster agreement is enough
    /// ([`Activation::LiveMembers`]) and no durable fence is needed. The
    /// field lives inside the policy document, so the operation adds no
    /// schema object and no migration, and the document format stays
    /// major 0. `minimum_schema` is 17 because that is the first schema
    /// whose members advertise capabilities at all; the policy tables it
    /// writes are older. Every member that shares this binary's schema-18
    /// contract meets it, so among those the capability alone decides.
    pub(crate) const POLICY_ROLE_DESCRIPTIONS: OperationRequirement = OperationRequirement {
        operation: "policy.role_descriptions",
        minimum_schema: 17,
        document_format: Some(0),
        capability: Capability::PolicyRoleDescriptions,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Every operation this binary gates. An operation added later
    /// registers here, advertises a new capability, and calls the gate
    /// before its write.
    pub(crate) const OPERATION_REQUIREMENTS: &[OperationRequirement] = &[POLICY_ROLE_DESCRIPTIONS];

    /// What this binary serves and advertises: the left-hand side of every
    /// requirement.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct BinaryContract {
        pub(crate) schema: (i32, i32),
        pub(crate) document: (i32, i32),
        pub(crate) capabilities: &'static [Capability],
    }

    impl BinaryContract {
        /// The contract this build ships.
        pub(crate) fn shipped() -> Self {
            Self {
                schema: crate::storage::migrations::schema_version_range(),
                document: crate::cluster_membership::DOCUMENT_VERSION_RANGE,
                capabilities: super::BINARY_CAPABILITIES,
            }
        }
    }

    /// One roster row, as far as the gate is concerned.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct MemberAdvertisement {
        pub(crate) instance_id: Uuid,
        /// Heartbeat within the stale window on the database clock.
        pub(crate) live: bool,
        pub(crate) schema_version: (i32, i32),
        pub(crate) document_version: (i32, i32),
        pub(crate) capabilities: RecognizedCapabilities,
    }

    impl From<&crate::storage::ClusterMember> for MemberAdvertisement {
        fn from(member: &crate::storage::ClusterMember) -> Self {
            Self {
                instance_id: member.instance_id,
                live: member.live,
                schema_version: (member.schema_version_min, member.schema_version_max),
                document_version: (member.document_version_min, member.document_version_max),
                capabilities: RecognizedCapabilities::parse(&member.capabilities),
            }
        }
    }

    impl MemberAdvertisement {
        fn lacks(&self, requirement: &OperationRequirement) -> bool {
            !self.capabilities.contains(requirement.capability)
                || self.schema_version.1 < requirement.minimum_schema
                || requirement.document_format.is_some_and(|major| {
                    major < self.document_version.0 || major > self.document_version.1
                })
        }
    }

    /// An admitted operation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct OperationAdmission {
        /// The live members that advertised the requirement, this replica
        /// included.
        pub(crate) live_members: usize,
    }

    /// Why the gate refused an operation. Nothing was written.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum OperationRefusal {
        /// The requirement is not one this binary can admit: it is not in
        /// the shipped registry, or it names a capability this binary does
        /// not advertise, a minimum schema its serving range does not
        /// reach, or a document format it does not read.
        NotSupportedByThisBinary,
        /// The operation needs a durable activation fence, which this
        /// release does not implement.
        ActivationFenceUnavailable,
        /// The operation needs a backfill this release cannot verify.
        BackfillUnverified { backfill: &'static str },
        /// The roster could not be read.
        RosterUnavailable,
        /// This replica's own row is missing from the live roster, so the
        /// read cannot be shown to describe the deployment.
        RosterMissingThisReplica,
        /// Live members do not advertise what the operation requires.
        MembersLackRequirement { lacking: Vec<Uuid>, live: usize },
    }

    impl OperationRefusal {
        /// A stable, closed reason code for logs, audit and responses.
        pub(crate) fn reason(&self) -> &'static str {
            match self {
                Self::NotSupportedByThisBinary => "operation_not_supported",
                Self::ActivationFenceUnavailable => "activation_fence_unavailable",
                Self::BackfillUnverified { .. } => "backfill_unverified",
                Self::RosterUnavailable => "roster_unavailable",
                Self::RosterMissingThisReplica => "roster_missing_this_replica",
                Self::MembersLackRequirement { .. } => "capability_not_advertised",
            }
        }

        /// The audit payload a caller records with the
        /// `cluster.operation_refused` event: the operation, the
        /// requirement and the reason, plus member counts. Names and codes
        /// only; no member identifiers, which the warning log carries.
        pub(crate) fn audit_payload(
            &self,
            requirement: &OperationRequirement,
        ) -> serde_json::Value {
            let (lacking, live) = match self {
                Self::MembersLackRequirement { lacking, live } => {
                    (Some(lacking.len()), Some(*live))
                }
                _ => (None, None),
            };
            serde_json::json!({
                "operation": requirement.operation,
                "capability": requirement.capability.as_str(),
                "minimum_schema": requirement.minimum_schema,
                "document_format": requirement.document_format,
                "outcome": "refused",
                "reason": self.reason(),
                "lacking_members": lacking,
                "live_members": live,
            })
        }
    }

    impl fmt::Display for OperationRefusal {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::NotSupportedByThisBinary => formatter.write_str(
                    "this gateway build does not itself support the operation's requirement; \
                     nothing was written",
                ),
                Self::ActivationFenceUnavailable => formatter.write_str(
                    "the operation needs a durable activation fence, which this release does not \
                     provide; nothing was written",
                ),
                Self::BackfillUnverified { backfill } => write!(
                    formatter,
                    "the operation needs the '{backfill}' backfill to be complete and verified, \
                     which this release cannot establish; nothing was written"
                ),
                Self::RosterUnavailable => formatter.write_str(
                    "the cluster roster could not be read, so no live member can be shown to \
                     support the operation; nothing was written — retry once the database answers",
                ),
                Self::RosterMissingThisReplica => formatter.write_str(
                    "this replica's own roster row is missing or stale, so the roster cannot be \
                     shown to describe the deployment; nothing was written — retry after its next \
                     heartbeat",
                ),
                Self::MembersLackRequirement { lacking, live } => write!(
                    formatter,
                    "{} of {live} live cluster member(s) do not advertise what the operation \
                     requires; nothing was written — finish the rollout, or wait for departed \
                     members to go stale",
                    lacking.len()
                ),
            }
        }
    }

    impl std::error::Error for OperationRefusal {}

    /// The gate: admit `requirement` only if this binary meets it and every
    /// live member of `members` advertises it. `own_instance` must be among
    /// the live members.
    ///
    /// Pure, so every refusal is unit-tested without a database; the
    /// caller reads the roster immediately before the write.
    pub(crate) fn evaluate(
        requirement: &OperationRequirement,
        binary: &BinaryContract,
        own_instance: Uuid,
        members: &[MemberAdvertisement],
    ) -> Result<OperationAdmission, OperationRefusal> {
        let supported_here = binary.capabilities.contains(&requirement.capability)
            && binary.schema.0 >= requirement.minimum_schema
            && requirement
                .document_format
                .is_none_or(|major| major >= binary.document.0 && major <= binary.document.1);
        if !supported_here {
            return Err(OperationRefusal::NotSupportedByThisBinary);
        }
        if requirement.activation == Activation::DurableFence {
            return Err(OperationRefusal::ActivationFenceUnavailable);
        }
        if let Backfill::Required { name } = requirement.backfill {
            return Err(OperationRefusal::BackfillUnverified { backfill: name });
        }
        let live: Vec<&MemberAdvertisement> = members.iter().filter(|member| member.live).collect();
        if !live.iter().any(|member| member.instance_id == own_instance) {
            return Err(OperationRefusal::RosterMissingThisReplica);
        }
        let lacking: Vec<Uuid> = live
            .iter()
            .filter(|member| member.lacks(requirement))
            .map(|member| member.instance_id)
            .collect();
        if !lacking.is_empty() {
            return Err(OperationRefusal::MembersLackRequirement {
                lacking,
                live: live.len(),
            });
        }
        Ok(OperationAdmission {
            live_members: live.len(),
        })
    }
}

#[cfg(test)]
#[path = "compatibility_tests.rs"]
mod tests;
