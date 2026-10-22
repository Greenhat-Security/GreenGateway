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
//! The roster alone is not a durable fence. Liveness is judged on the
//! database clock against `CLUSTER_MEMBER_STALE_MS`, so a member that lacks
//! a capability can be stopped, swept, and started again after an operation
//! was admitted, and a member paused past the window comes back with its
//! next heartbeat. A stale row disappearing is not proof that the member
//! retired. Two durable records outlive the roster (migration 20, issue
//! #426 PR 3):
//!
//! - **The contract fence** ([`ContractFence`]): one forward-only row naming
//!   the lowest schema a member's serving range must reach and the
//!   capabilities it must implement. A gateway the fence excludes refuses
//!   to start, writes no heartbeat (so it cannot rejoin the roster), and
//!   admits nothing. An operation whose data a lacking member would
//!   *misread*, rather than refuse, declares [`Activation::DurableFence`]:
//!   admitting it raises the fence to the operation's requirement in the
//!   same transaction that confirms every live member already meets it
//!   (`PostgresMembershipStore::raise_contract_fence`), so a lacking member
//!   that returns afterwards is refused at the door instead of misreading.
//! - **The backfill ledger** ([`BackfillState`]): an operation that needs a
//!   backfill ([`Backfill::Required`]) is admitted only once the named
//!   backfill is recorded verified. Missing, running (including
//!   interrupted) and failed backfills all refuse.
//!
//! Schema presence alone never enables an operation.
//!
//! The registry ([`OPERATION_REQUIREMENTS`]) holds two operations. The
//! first (issue #426, PR 2) is committing a policy document in which a role
//! carries a `description` ([`POLICY_ROLE_DESCRIPTIONS`]). A gateway built
//! before the field refuses such a document outright -- the role's fields
//! are closed -- so the write waits until every live member advertises
//! [`Capability::PolicyRoleDescriptions`], and a member that lacks it and
//! returns later fails closed on the document rather than misreading it.
//! The second (issue #443) is storing a managed OpenAPI catalog whose
//! specification is a Swagger 2.0 document
//! ([`OPENAPI_SWAGGER2_CATALOGS`]), which a gateway built before Swagger 2.0
//! import cannot generate from; it waits for
//! [`Capability::OpenApiSwagger2Catalogs`] the same way. The
//! approved-extension list in `migrations.rs` stays empty: neither operation
//! changes the schema, and no schema overlap has been qualified. Every other
//! operation this binary performs belongs to the schema-21 contract, which
//! every schema-21 member shares. No shipped operation declares a durable
//! fence or a backfill, so in this release nothing raises the fence and
//! the backfill ledger is empty; both are checked everywhere they apply.

use std::collections::BTreeSet;

/// The most capability names one roster row may carry. Migration 17's
/// check constraint enforces the same bound, and migration 20's enforces it
/// on the contract fence.
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
    /// The member generates, refreshes and replays a managed OpenAPI
    /// catalog whose specification is a Swagger 2.0 document (issue #443).
    /// A member without it cannot generate from one, so
    /// [`OPENAPI_SWAGGER2_CATALOGS`] waits for it.
    OpenApiSwagger2Catalogs,
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
    pub(crate) const KNOWN: [Self; 3] = [
        Self::OpenApiSwagger2Catalogs,
        Self::OperationRequirements,
        Self::PolicyRoleDescriptions,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OpenApiSwagger2Catalogs => "openapi_swagger2_catalogs",
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
    Capability::OpenApiSwagger2Catalogs,
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
    evaluate, fence_target, Activation, Backfill, BackfillState, BinaryContract, ContractFence,
    FenceExclusion, FenceTarget, MemberAdvertisement, OperationAdmission, OperationRefusal,
    OperationRequirement, OPENAPI_SWAGGER2_CATALOGS, OPERATION_REQUIREMENTS,
    POLICY_ROLE_DESCRIPTIONS,
};

#[cfg(feature = "postgres")]
mod gate {
    use std::{collections::BTreeSet, fmt};

    use uuid::Uuid;

    use super::{advertisement, Capability, RecognizedCapabilities};

    /// Whether an operation depends on a backfill having completed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // `Required` is constructed only by tests: no shipped operation needs a backfill.
    pub(crate) enum Backfill {
        /// The operation reads nothing a backfill must first produce.
        NotRequired,
        /// The operation needs the named backfill recorded verified in the
        /// backfill ledger (`schema_backfills`, migration 20).
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
        /// A lacking member that returned would misread the data, so
        /// admitting the operation raises the durable contract fence to its
        /// requirement first, in the transaction that confirms every live
        /// member already meets it. From then on a gateway that lacks the
        /// capability cannot start, rejoin, or admit anything.
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
    /// ([`Activation::LiveMembers`]) and the durable fence is not raised.
    /// The field lives inside the policy document, so the operation adds no
    /// schema object and no migration, and the document format stays
    /// major 0. `minimum_schema` is 17 because that is the first schema
    /// whose members advertise capabilities at all; the policy tables it
    /// writes are older. Every member that shares this binary's schema-21
    /// contract meets it, so among those the capability alone decides.
    pub(crate) const POLICY_ROLE_DESCRIPTIONS: OperationRequirement = OperationRequirement {
        operation: "policy.role_descriptions",
        minimum_schema: 17,
        document_format: Some(0),
        capability: Capability::PolicyRoleDescriptions,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Storing a managed OpenAPI catalog whose specification is a Swagger
    /// 2.0 document (issue #443): registering one, refreshing to one, or
    /// writing an overlay over one.
    ///
    /// The stored specification is the submitted document, and every
    /// replica regenerates from it to refresh the catalog and to rebuild an
    /// overlay's source plan. A gateway built before Swagger 2.0 import
    /// cannot generate from it: it keeps serving the tool definitions
    /// already stored, which it reads exactly as published, but its refresh
    /// fails with `catalog_stale`, and with an overlay present its startup
    /// fails and its connection reconciliation holds the security revision
    /// check unavailable, so it serves nothing new. That is failing closed,
    /// never a misreading, so live-roster agreement is enough
    /// ([`Activation::LiveMembers`]). Deleting an overlay is not gated: it
    /// removes what makes an older member fail. The specification is not a
    /// policy or tools document, so no document format is required, and
    /// `minimum_schema` is 17 for the same reason as
    /// [`POLICY_ROLE_DESCRIPTIONS`]: the catalog tables are older.
    pub(crate) const OPENAPI_SWAGGER2_CATALOGS: OperationRequirement = OperationRequirement {
        operation: "connections.openapi_swagger2_catalog",
        minimum_schema: 17,
        document_format: None,
        capability: Capability::OpenApiSwagger2Catalogs,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Every operation this binary gates. An operation added later
    /// registers here, advertises a new capability, and calls the gate
    /// before its write.
    pub(crate) const OPERATION_REQUIREMENTS: &[OperationRequirement] =
        &[POLICY_ROLE_DESCRIPTIONS, OPENAPI_SWAGGER2_CATALOGS];

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

        /// Why `fence` excludes this binary, or `None` when it admits it.
        pub(crate) fn fenced_by(&self, fence: &ContractFence) -> Option<FenceExclusion> {
            fence.exclusion(self.schema.1, self.capabilities)
        }
    }

    /// The durable contract fence (`contract_fence`, migration 20) as this
    /// binary read it: one forward-only row every gateway sharing the
    /// database checks at startup, on every heartbeat, and before every
    /// gated write.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct ContractFence {
        /// How many times the fence has been raised; `0` until the first
        /// raise.
        pub(crate) generation: i64,
        /// The lowest schema version a gateway's serving range must reach.
        pub(crate) minimum_schema: i32,
        /// The capability names a gateway must implement, exactly as
        /// stored. Only [`ContractFence::exclusion`] decides what they
        /// demand.
        pub(crate) capabilities: String,
    }

    impl ContractFence {
        /// The fence migration 20 seeds: never raised, demanding nothing.
        #[cfg(test)]
        pub(crate) fn open() -> Self {
            Self {
                generation: 0,
                minimum_schema: 0,
                capabilities: String::new(),
            }
        }

        /// Why this fence excludes a gateway that serves up to `schema_max`
        /// and implements `implemented`, or `None` when it admits it.
        ///
        /// A fenced name the reader does not recognize is one it cannot show
        /// it implements -- a newer gateway raised the fence for something
        /// this build has never heard of -- so it excludes, and so does a
        /// value outside the column's bounds. The heartbeat statement makes
        /// the same decision in SQL (`postgres_membership.rs`): the fenced
        /// names must be a subset of the names this build advertises.
        pub(crate) fn exclusion(
            &self,
            schema_max: i32,
            implemented: &[Capability],
        ) -> Option<FenceExclusion> {
            let required = RecognizedCapabilities::parse(&self.capabilities);
            let missing_capabilities = required.unrecognized()
                + required
                    .known
                    .iter()
                    .filter(|capability| !implemented.contains(capability))
                    .count();
            (missing_capabilities > 0 || schema_max < self.minimum_schema).then_some(
                FenceExclusion {
                    generation: self.generation,
                    minimum_schema: self.minimum_schema,
                    schema_max,
                    missing_capabilities,
                },
            )
        }
    }

    /// Why the contract fence excludes a gateway. Counts and versions only:
    /// the fenced names this build does not recognize are not echoed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct FenceExclusion {
        pub(crate) generation: i64,
        pub(crate) minimum_schema: i32,
        /// The highest schema the excluded gateway serves.
        pub(crate) schema_max: i32,
        /// Fenced capability names the excluded gateway does not implement,
        /// unrecognized ones included.
        pub(crate) missing_capabilities: usize,
    }

    impl fmt::Display for FenceExclusion {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "the deployment's contract fence (generation {}) requires a serving range reaching \
                 schema {} and {} fenced capability name(s) this build does not implement; this \
                 build serves up to schema {}",
                self.generation, self.minimum_schema, self.missing_capabilities, self.schema_max
            )
        }
    }

    /// Where admitting a durable-fence operation leaves the fence.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct FenceTarget {
        pub(crate) minimum_schema: i32,
        /// The canonical advertisement of the raised capability set.
        pub(crate) capabilities: String,
    }

    /// The fence after admitting `requirement` over `current`: the higher of
    /// the two minimum schemas and the union of the two capability sets, so
    /// a raise never lowers anything. `Ok(None)` when `current` already
    /// demands all of it, so a repeat admission writes nothing.
    ///
    /// Called only once the gate has established that `current` admits this
    /// binary, so every fenced name is one this build recognizes. A fence
    /// that still carries a name it does not, or a union the column cannot
    /// hold, is refused rather than rewritten without it.
    pub(crate) fn fence_target(
        current: &ContractFence,
        requirement: &OperationRequirement,
    ) -> Result<Option<FenceTarget>, OperationRefusal> {
        let recognized = RecognizedCapabilities::parse(&current.capabilities);
        if recognized.unrecognized() > 0 {
            return Err(OperationRefusal::NotSupportedByThisBinary);
        }
        let mut capabilities: BTreeSet<Capability> = recognized.known;
        let added = capabilities.insert(requirement.capability);
        let minimum_schema = current.minimum_schema.max(requirement.minimum_schema);
        if !added && minimum_schema == current.minimum_schema {
            return Ok(None);
        }
        let set: Vec<Capability> = capabilities.into_iter().collect();
        let capabilities = advertisement(&set).ok_or(OperationRefusal::NotSupportedByThisBinary)?;
        Ok(Some(FenceTarget {
            minimum_schema,
            capabilities,
        }))
    }

    /// One named backfill's state in the backfill ledger
    /// (`schema_backfills`, migration 20).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum BackfillState {
        /// No row: the backfill has not started against this database.
        Missing,
        /// Started and not finished: still running, or interrupted.
        Running,
        /// Finished, and its own verification found nothing left to
        /// backfill. The only state that admits an operation.
        Verified,
        /// Finished without verifying.
        Failed,
    }

    impl BackfillState {
        /// The ledger's `state` column, or `None` for no row. A value the
        /// column's check constraint does not admit is not a state.
        pub(crate) fn from_column(state: Option<&str>) -> Option<Self> {
            match state {
                None => Some(Self::Missing),
                Some("running") => Some(Self::Running),
                Some("verified") => Some(Self::Verified),
                Some("failed") => Some(Self::Failed),
                Some(_) => None,
            }
        }

        pub(crate) fn as_str(self) -> &'static str {
            match self {
                Self::Missing => "missing",
                Self::Running => "running",
                Self::Verified => "verified",
                Self::Failed => "failed",
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

        /// Whether the member's advertisement falls short of the fence. A
        /// member the fence excludes cannot heartbeat once it was raised,
        /// so a live one is a row from before the raise; it is a lacking
        /// member like any other, never evidence that the fence is met.
        fn falls_short_of(&self, fence: &ContractFence) -> bool {
            let required = RecognizedCapabilities::parse(&fence.capabilities);
            required.unrecognized() > 0
                || self.schema_version.1 < fence.minimum_schema
                || required
                    .known
                    .iter()
                    .any(|capability| !self.capabilities.contains(*capability))
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
        /// The durable contract fence could not be read or raised: the
        /// database did not answer, or a lock wait or statement ran out of
        /// its bound.
        ActivationFenceUnavailable,
        /// The durable contract fence excludes this binary.
        ContractFenced(FenceExclusion),
        /// A migrator holds the schema lock, so the fence is not raised
        /// while the schema may be changing.
        MigrationInProgress,
        /// The schema ledger read under the fence lock is not one this
        /// binary serves.
        SchemaNotServed,
        /// The operation needs a backfill the ledger does not record as
        /// verified. `state` is `None` when the ledger could not be read.
        BackfillUnverified {
            backfill: &'static str,
            state: Option<BackfillState>,
        },
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
                Self::ContractFenced(_) => "contract_fenced",
                Self::MigrationInProgress => "migration_in_progress",
                Self::SchemaNotServed => "schema_incompatible",
                Self::BackfillUnverified { .. } => "backfill_unverified",
                Self::RosterUnavailable => "roster_unavailable",
                Self::RosterMissingThisReplica => "roster_missing_this_replica",
                Self::MembersLackRequirement { .. } => "capability_not_advertised",
            }
        }

        /// The audit payload a caller records with the
        /// `cluster.operation_refused` event: the operation, the
        /// requirement and the reason, plus member counts, the backfill's
        /// state and the fence's generation where they decided it. Names,
        /// codes and counts only; no member identifiers, which the warning
        /// log carries.
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
            let backfill_state = match self {
                Self::BackfillUnverified { state, .. } => {
                    Some(state.map_or("unreadable", BackfillState::as_str))
                }
                _ => None,
            };
            let fence_generation = match self {
                Self::ContractFenced(exclusion) => Some(exclusion.generation),
                _ => None,
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
                "backfill_state": backfill_state,
                "fence_generation": fence_generation,
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
                    "the durable contract fence could not be read or raised, so the operation \
                     cannot be shown safe for every member that may return; nothing was written \
                     — retry once the database answers",
                ),
                Self::ContractFenced(exclusion) => write!(
                    formatter,
                    "this gateway build is excluded by the durable contract fence: {exclusion}; \
                     nothing was written — a retired build cannot return once the deployment has \
                     moved past it, so replace this replica with an eligible build"
                ),
                Self::MigrationInProgress => formatter.write_str(
                    "a schema migration holds the migration lock, so the contract fence is not \
                     raised while the schema may be changing; nothing was written — retry once \
                     the migration has finished",
                ),
                Self::SchemaNotServed => formatter.write_str(
                    "the schema ledger read under the contract fence is not one this gateway \
                     build serves; nothing was written — the database was migrated by another \
                     build",
                ),
                Self::BackfillUnverified { backfill, state } => write!(
                    formatter,
                    "the operation needs the '{backfill}' backfill recorded verified, and the \
                     backfill ledger {}; nothing was written",
                    match state {
                        None => "could not be read",
                        Some(BackfillState::Missing) => "has no record of it",
                        Some(BackfillState::Running) => {
                            "records it as still running or interrupted"
                        }
                        Some(BackfillState::Failed) => "records it as failed",
                        Some(BackfillState::Verified) => "records it as verified",
                    }
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

    /// The gate: admit `requirement` only if this binary meets it, the
    /// durable contract fence admits this binary, the backfill it names (if
    /// any) is recorded verified, and every live member of `members`
    /// advertises it and meets the fence. `own_instance` must be among the
    /// live members.
    ///
    /// Pure, so every refusal is unit-tested without a database; the
    /// caller reads the fence, the backfill and the roster immediately
    /// before the write. For an [`Activation::DurableFence`] operation the
    /// caller reads them under the fence's row lock and raises the fence to
    /// [`fence_target`] in the same transaction (`ClusterMembership`); an
    /// admission here alone never raises anything.
    pub(crate) fn evaluate(
        requirement: &OperationRequirement,
        binary: &BinaryContract,
        own_instance: Uuid,
        members: &[MemberAdvertisement],
        fence: &ContractFence,
        backfill: Option<BackfillState>,
    ) -> Result<OperationAdmission, OperationRefusal> {
        let supported_here = binary.capabilities.contains(&requirement.capability)
            && binary.schema.0 >= requirement.minimum_schema
            && requirement
                .document_format
                .is_none_or(|major| major >= binary.document.0 && major <= binary.document.1);
        if !supported_here {
            return Err(OperationRefusal::NotSupportedByThisBinary);
        }
        if let Some(exclusion) = binary.fenced_by(fence) {
            return Err(OperationRefusal::ContractFenced(exclusion));
        }
        if let Backfill::Required { name } = requirement.backfill {
            if backfill != Some(BackfillState::Verified) {
                return Err(OperationRefusal::BackfillUnverified {
                    backfill: name,
                    state: backfill,
                });
            }
        }
        let live: Vec<&MemberAdvertisement> = members.iter().filter(|member| member.live).collect();
        if !live.iter().any(|member| member.instance_id == own_instance) {
            return Err(OperationRefusal::RosterMissingThisReplica);
        }
        let lacking: Vec<Uuid> = live
            .iter()
            .filter(|member| member.lacks(requirement) || member.falls_short_of(fence))
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
