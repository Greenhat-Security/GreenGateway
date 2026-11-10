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
//! The registry ([`OPERATION_REQUIREMENTS`]) holds six operations. The
//! first (issue #426, PR 2) is committing a policy document in which a role
//! carries a `description` ([`POLICY_ROLE_DESCRIPTIONS`]). A gateway built
//! before the field refuses such a document outright -- the role's fields
//! are closed -- so the write waits until every live member advertises
//! [`Capability::PolicyRoleDescriptions`], and a member that lacks it and
//! returns later fails closed on the document rather than misreading it.
//! The second and third (issue #443) are storing a managed OpenAPI catalog
//! whose specification is a Swagger 2.0 document
//! ([`OPENAPI_SWAGGER2_CATALOGS`]) or a Google Discovery document
//! ([`OPENAPI_DISCOVERY_CATALOGS`]), which a gateway built before that
//! format's import cannot generate from; each waits for its own capability
//! ([`Capability::OpenApiSwagger2Catalogs`],
//! [`Capability::OpenApiDiscoveryCatalogs`]) the same way. The fourth (issue
//! #441) is recording a delegated-token purge for every replica
//! ([`DELEGATED_TOKEN_PURGES`]), which a gateway built before the record
//! would not apply; it waits for [`Capability::DelegatedTokenPurges`]. The
//! fifth (issue #243) is committing a policy v1 document, document format 1
//! ([`POLICY_DOCUMENT_V1`]): a gateway that does not serve format 1 in
//! cluster mode refuses the whole document, so the write waits until every
//! live member advertises [`Capability::PolicyDocumentV1`] and reads format
//! 1, and a member that lacks it and returns later fails closed on the
//! document rather than misreading it. The sixth (issue #243) is committing
//! a policy v1 document whose rules carry `conditions`
//! ([`POLICY_RULE_CONDITIONS`]): a gateway that serves format 1 but not
//! rule conditions refuses the whole document, so the write also waits
//! until every live member advertises [`Capability::PolicyRuleConditions`].
//! The seventh (issue #243) is committing one whose conditions contain a
//! `tool_argument` leaf ([`POLICY_TOOL_ARGUMENT_CONDITIONS`]): a gateway
//! that enforces the other conditions but not that leaf refuses the whole
//! document, so the write also waits until every live member advertises
//! [`Capability::PolicyToolArgumentConditions`]. Storing Discovery tools
//! with repeated query mappings also needs [`OPENAPI_REPEATED_QUERY`].
//! Enrolling a managed HTTP mutation raises a durable fence. A returning
//! replica must support the approval requirement before it may serve traffic.

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
    /// The member applies every delegated-token purge recorded at the
    /// authority before it serves another protected request (issue #441). A
    /// member without it ignores the record and keeps serving the purged
    /// principal's cached tokens, so [`DELEGATED_TOKEN_PURGES`] waits for it.
    DelegatedTokenPurges,
    /// Verifies and atomically consumes approvals before dispatching enrolled managed tools.
    ManagedHttpMutationV1,
    /// The member generates, refreshes and replays a managed OpenAPI
    /// catalog whose specification is a Google Discovery document (issue
    /// #443). A member without it cannot generate from one, so
    /// [`OPENAPI_DISCOVERY_CATALOGS`] waits for it.
    OpenApiDiscoveryCatalogs,
    /// The member can read stored repeated query mappings and emit one
    /// form-encoded key per scalar item.
    OpenApiRepeatedQuery,
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
    /// The member reads, validates and serves a policy v1 document
    /// (`"schema_version": "1.0.0"`, document format 1) from the cluster
    /// authority, and advertises document formats `0..=1` (issue #243). A
    /// member without it refuses such a document, so [`POLICY_DOCUMENT_V1`]
    /// waits for it.
    PolicyDocumentV1,
    /// The member reads, validates and serves a policy document whose roles
    /// carry a `description` (issue #426, PR 2). A member without it refuses
    /// such a document, so [`POLICY_ROLE_DESCRIPTIONS`] waits for it.
    PolicyRoleDescriptions,
    /// The member reads, validates and enforces a policy v1 document whose
    /// direct rules carry `conditions` over the organization, the verified
    /// scopes and allowlisted claims, the source network, headers, query
    /// parameters and time windows (issue #243). A member without it
    /// refuses such a document, so [`POLICY_RULE_CONDITIONS`] waits for it.
    PolicyRuleConditions,
    /// The member reads, validates and enforces a policy v1 document whose
    /// rule conditions contain a `tool_argument` leaf, deciding it on tool
    /// invocation admission after the call's arguments are validated (issue
    /// #243). A member without it refuses such a document, so
    /// [`POLICY_TOOL_ARGUMENT_CONDITIONS`] waits for it.
    PolicyToolArgumentConditions,
}

impl Capability {
    /// Every capability, in name order.
    pub(crate) const KNOWN: [Self; 10] = [
        Self::DelegatedTokenPurges,
        Self::ManagedHttpMutationV1,
        Self::OpenApiDiscoveryCatalogs,
        Self::OpenApiRepeatedQuery,
        Self::OpenApiSwagger2Catalogs,
        Self::OperationRequirements,
        Self::PolicyDocumentV1,
        Self::PolicyRoleDescriptions,
        Self::PolicyRuleConditions,
        Self::PolicyToolArgumentConditions,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DelegatedTokenPurges => "delegated_token_purges",
            Self::ManagedHttpMutationV1 => "managed_http_mutation_v1",
            Self::OpenApiDiscoveryCatalogs => "openapi_discovery_catalogs",
            Self::OpenApiRepeatedQuery => "openapi_repeated_query",
            Self::OpenApiSwagger2Catalogs => "openapi_swagger2_catalogs",
            Self::OperationRequirements => "operation_requirements",
            Self::PolicyDocumentV1 => "policy_document_v1",
            Self::PolicyRoleDescriptions => "policy_role_descriptions",
            Self::PolicyRuleConditions => "policy_rule_conditions",
            Self::PolicyToolArgumentConditions => "policy_tool_argument_conditions",
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
    Capability::DelegatedTokenPurges,
    Capability::ManagedHttpMutationV1,
    Capability::OpenApiDiscoveryCatalogs,
    Capability::OpenApiRepeatedQuery,
    Capability::OpenApiSwagger2Catalogs,
    Capability::OperationRequirements,
    Capability::PolicyDocumentV1,
    Capability::PolicyRoleDescriptions,
    Capability::PolicyRuleConditions,
    Capability::PolicyToolArgumentConditions,
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
    evaluate, evaluate_without_own_row, fence_target, Activation, Backfill, BackfillState,
    BinaryContract, ContractFence, FenceExclusion, FenceTarget, MemberAdvertisement,
    OperationAdmission, OperationRefusal, OperationRequirement, DELEGATED_TOKEN_PURGES,
    MANAGED_HTTP_MUTATION_V1, OPENAPI_DISCOVERY_CATALOGS, OPENAPI_REPEATED_QUERY,
    OPENAPI_SWAGGER2_CATALOGS, OPERATION_REQUIREMENTS, POLICY_DOCUMENT_V1,
    POLICY_ROLE_DESCRIPTIONS, POLICY_RULE_CONDITIONS, POLICY_TOOL_ARGUMENT_CONDITIONS,
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
    /// writes are older. Every member that shares this binary's schema-25
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

    /// Storing a managed OpenAPI catalog whose specification is a Google
    /// Discovery document (issue #443): registering one, refreshing to one,
    /// or writing an overlay over one.
    ///
    /// The same reasoning as [`OPENAPI_SWAGGER2_CATALOGS`], with its own
    /// capability: a gateway built with Swagger 2.0 import but before
    /// Discovery import advertises `openapi_swagger2_catalogs` and still
    /// cannot generate from a Discovery document. It fails closed the same
    /// way (refresh `catalog_stale`, and with an overlay a failed startup or
    /// held reconciliation), so live-roster agreement is enough.
    pub(crate) const OPENAPI_DISCOVERY_CATALOGS: OperationRequirement = OperationRequirement {
        operation: "connections.openapi_discovery_catalog",
        minimum_schema: 17,
        document_format: None,
        capability: Capability::OpenApiDiscoveryCatalogs,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Older members refuse the new field in a persisted query mapping.
    /// Wait for live readers before writing such a catalog.
    pub(crate) const OPENAPI_REPEATED_QUERY: OperationRequirement = OperationRequirement {
        operation: "connections.openapi_repeated_query",
        minimum_schema: 17,
        document_format: None,
        capability: Capability::OpenApiRepeatedQuery,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Recording a delegated-token purge at the authority for every replica
    /// to apply (issue #441): an operator's purge, or one a revoked
    /// credential started.
    ///
    /// The record is a `security_outbox` row every replica of this build
    /// applies before it serves again. A gateway built before it does not
    /// read the row: it keeps serving the purged principal's cached tokens,
    /// for at most the 900 seconds a delegated token is cached, and it
    /// refuses an operator's purge with `409` itself. So the record waits
    /// until every live member advertises [`Capability::DelegatedTokenPurges`].
    /// Live-roster agreement is the activation, not the durable fence: a
    /// lacking member that starts after the record starts with an empty
    /// cache, and the one it misses -- one paused past the stale window when
    /// the purge was admitted, resumed within 900 seconds -- is bounded by
    /// that cache lifetime, while raising the fence would make one purge
    /// forbid every earlier binary from rejoining the deployment. The row
    /// lives in a table schema 6 created, so `minimum_schema` is 17 for the
    /// same reason as [`POLICY_ROLE_DESCRIPTIONS`]; no document format.
    pub(crate) const DELEGATED_TOKEN_PURGES: OperationRequirement = OperationRequirement {
        operation: "connections.delegated_token_purge",
        minimum_schema: 17,
        document_format: None,
        capability: Capability::DelegatedTokenPurges,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Committing a policy v1 document (`"schema_version": "1.0.0"`,
    /// document format 1; issue #243): through the policy API's writes, a
    /// discovery suggestion's acceptance, or the standalone import.
    ///
    /// Every gateway that can share a database with this one refuses a v1
    /// document it does not serve; none reads it as anything else. A build
    /// before policy v1 refuses every `schema_version` that does not start
    /// with `0.`, as every release has since the first policy schema. A
    /// build with policy v1 but before this operation advertises document
    /// formats `0..=0` and refuses a stored v1 document as invalid data
    /// (`postgres_policy`). Either way a running replica stops compiling
    /// the active revision and holds readiness at
    /// `security_revision_not_compiled`, serving nothing under the policy it
    /// had, and a starting one refuses to boot. That is failing closed,
    /// never a misreading, so live-roster agreement is enough
    /// ([`Activation::LiveMembers`]). Raising the durable fence instead would
    /// make the first v1 commit forbid every earlier build from rejoining
    /// the deployment for good, even after a rollback to a 0.x revision had
    /// removed the only thing it could not read. A lacking member also
    /// fails the document-format half of the requirement on its own: its
    /// advertised document range stops at 0. The document lives in the
    /// policy tables, so the operation adds no schema object, and
    /// `minimum_schema` is 17 for the same reason as
    /// [`POLICY_ROLE_DESCRIPTIONS`].
    pub(crate) const POLICY_DOCUMENT_V1: OperationRequirement = OperationRequirement {
        operation: "policy.document_v1",
        minimum_schema: 17,
        document_format: Some(1),
        capability: Capability::PolicyDocumentV1,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Committing a policy v1 document in which any direct rule carries
    /// `conditions` (issue #243): through the same writes as
    /// [`POLICY_DOCUMENT_V1`], which such a commit also asks first.
    ///
    /// A gateway that serves format 1 but predates enforced rule conditions
    /// validates them and refuses the whole document
    /// (`typed_matchers_not_enforced`); none reads it without its
    /// conditions. A running replica of that build stops compiling the
    /// active revision and holds readiness at
    /// `security_revision_not_compiled`, and a starting one refuses to boot.
    /// That is failing closed, never a misreading, so live-roster agreement
    /// is enough ([`Activation::LiveMembers`]), for the same reason as
    /// [`POLICY_DOCUMENT_V1`]: raising the durable fence would forbid every
    /// earlier build from rejoining even after a document without
    /// conditions is active again. A document whose conditions contain a
    /// `tool_argument` leaf is also [`POLICY_TOOL_ARGUMENT_CONDITIONS`],
    /// which a build that enforces only the other leaves refuses. The
    /// document lives in the policy tables, so no schema object is added, and
    /// `minimum_schema` is 17 for the same reason as
    /// [`POLICY_ROLE_DESCRIPTIONS`].
    pub(crate) const POLICY_RULE_CONDITIONS: OperationRequirement = OperationRequirement {
        operation: "policy.rule_conditions",
        minimum_schema: 17,
        document_format: Some(1),
        capability: Capability::PolicyRuleConditions,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Committing a policy v1 document whose rule conditions contain a
    /// `tool_argument` leaf anywhere (issue #243): through the same writes
    /// as [`POLICY_RULE_CONDITIONS`], which such a commit also asks first.
    ///
    /// A gateway that enforces the other condition leaves but predates
    /// tool-argument conditions validates the leaf and refuses the whole
    /// document (`typed_matchers_not_enforced`); none reads it without the
    /// leaf. Like [`POLICY_RULE_CONDITIONS`] that fails closed, never a
    /// misreading, so live-roster agreement is enough
    /// ([`Activation::LiveMembers`]) and the durable fence is not raised.
    /// The document lives in the policy tables, so no schema object is
    /// added, and `minimum_schema` is 17 for the same reason as
    /// [`POLICY_ROLE_DESCRIPTIONS`].
    pub(crate) const POLICY_TOOL_ARGUMENT_CONDITIONS: OperationRequirement = OperationRequirement {
        operation: "policy.tool_argument_conditions",
        minimum_schema: 17,
        document_format: Some(1),
        capability: Capability::PolicyToolArgumentConditions,
        backfill: Backfill::NotRequired,
        activation: Activation::LiveMembers,
    };

    /// Opting into per-mutation approval changes what may send on a Connection.
    /// Returning replicas must understand that requirement even after every
    /// enrolled Connection has since been removed.
    pub(crate) const MANAGED_HTTP_MUTATION_V1: OperationRequirement = OperationRequirement {
        operation: "connections.managed_http_mutation_v1",
        minimum_schema: 34,
        document_format: None,
        capability: Capability::ManagedHttpMutationV1,
        backfill: Backfill::NotRequired,
        activation: Activation::DurableFence,
    };

    /// Every operation this binary gates. An operation added later
    /// registers here, advertises a new capability, and calls the gate
    /// before its write.
    pub(crate) const OPERATION_REQUIREMENTS: &[OperationRequirement] = &[
        POLICY_ROLE_DESCRIPTIONS,
        OPENAPI_SWAGGER2_CATALOGS,
        OPENAPI_DISCOVERY_CATALOGS,
        OPENAPI_REPEATED_QUERY,
        DELEGATED_TOKEN_PURGES,
        POLICY_DOCUMENT_V1,
        POLICY_RULE_CONDITIONS,
        POLICY_TOOL_ARGUMENT_CONDITIONS,
        MANAGED_HTTP_MUTATION_V1,
    ];

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
        judge(
            requirement,
            binary,
            Some(own_instance),
            members,
            fence,
            backfill,
        )
    }

    /// [`evaluate`] for a one-shot command that writes to the deployment
    /// without a roster row of its own: the standalone import (`gateway
    /// import-standalone`), which runs beside `gateway migrate up` rather
    /// than as a replica. Every check is the same except the one that needs
    /// this process on the roster. A roster with no live member admits,
    /// because no member can be shown to lack anything, and a member that
    /// starts afterwards is the one [`Activation::LiveMembers`] already
    /// accounts for: it fails closed on the data. The admission's
    /// `live_members` counts the live members, which may be none.
    pub(crate) fn evaluate_without_own_row(
        requirement: &OperationRequirement,
        binary: &BinaryContract,
        members: &[MemberAdvertisement],
        fence: &ContractFence,
        backfill: Option<BackfillState>,
    ) -> Result<OperationAdmission, OperationRefusal> {
        judge(requirement, binary, None, members, fence, backfill)
    }

    /// The decision both gates share; `own_instance` is `None` only for a
    /// one-shot command.
    fn judge(
        requirement: &OperationRequirement,
        binary: &BinaryContract,
        own_instance: Option<Uuid>,
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
        if let Some(own_instance) = own_instance {
            if !live.iter().any(|member| member.instance_id == own_instance) {
                return Err(OperationRefusal::RosterMissingThisReplica);
            }
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
