//! Canonical policy evidence packages (issue #243, slice 20).
//!
//! An evidence package is a reproducible aggregate report about one policy
//! publication: one version of the policy history. The admin endpoint
//! (`admin_policy_evidence`) reads that version and the one before it from
//! the history authority, revalidates it with this build, decides the test
//! suite and synthetic cases it was given through the shared evaluator, and
//! binds a finished replay job of the caller's; this module turns what those
//! steps established into the package, and parses the request that names
//! them.
//!
//! - [`request`] parses the strict, exact-version `policy-evidence-request.v1`
//!   request. Its suite and cases go through the test-suite and simulation
//!   parsers, so a case means here exactly what it means to a test run or a
//!   simulation.
//! - [`package`] assembles the `policy-evidence.v1` package: a manifest and a
//!   report whose ADR-0004 semantic digest the manifest names, serialized as
//!   RFC 8785 (JCS) bytes.
//!
//! ## What a package is, and is not
//!
//! The report is deterministic: the same publication, suite, cases and replay
//! job, judged by the same build under the same deployment checks, produce a
//! byte-identical report and report digest. Only the envelope's
//! `generated_at` differs between two exports, and it is outside the digest.
//!
//! A package is aggregate-only under [`REDACTION_PROFILE`]: digests, ETags,
//! versions, stable codes, counts, case and element identifiers. It carries no
//! policy content, no fixture value, no audit record, no actor identity and no
//! request detail, and it embeds nothing that would let it be replayed without
//! the authorities it was read from.
//!
//! It is unsigned. Signing is a later slice that needs protected signer keys
//! (#240) and offline verification (#242); until then the report says so in
//! its own `trust` member, and every package carries [`TRUST_STATEMENT`].
//! Nothing here claims that a policy is safe, that its history or audit
//! sources were complete, or compliance with any framework.

pub(crate) mod package;
pub(crate) mod request;
#[cfg(test)]
mod tests;

/// The only request schema this module implements.
pub(crate) const REQUEST_SCHEMA_VERSION: &str = "policy-evidence-request.v1";
/// The media type the request digest is framed with.
pub(crate) const REQUEST_MEDIA_TYPE: &str =
    "application/vnd.greengateway.policy-evidence-request+json";
/// The schema of the package: its envelope and manifest.
pub(crate) const PACKAGE_SCHEMA_VERSION: &str = "policy-evidence.v1";
/// The media type a package is served as.
pub(crate) const PACKAGE_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-evidence+json";
/// The schema of the report a package's manifest digests.
pub(crate) const REPORT_SCHEMA_VERSION: &str = "policy-evidence-report.v1";
/// The media type the report digest is framed with.
pub(crate) const REPORT_MEDIA_TYPE: &str =
    "application/vnd.greengateway.policy-evidence-report+json";
/// What a report may contain: aggregate results, digests, identifiers and
/// stable codes, never a value from a policy, fixture, record or actor.
pub(crate) const REDACTION_PROFILE: &str = "policy-evidence-aggregate.v1";
/// The largest package served, in bytes. A package over it is refused whole,
/// never cut short.
pub(crate) const MAX_PACKAGE_BYTES: usize = 4 * 1024 * 1024;
/// The most revalidation diagnostics a report lists; past it the report says
/// so and is incomplete.
pub(crate) const MAX_EVIDENCE_DIAGNOSTICS: usize = 100;

/// The fixed statement every report carries about what it does not prove.
pub(crate) const TRUST_STATEMENT: &str = "This package is unsigned. It reports what this \
gateway's policy history recorded about one publication and what this gateway build \
recomputed from it, under the stated versions and bounds. It does not prove that the policy \
is safe, that the history or audit sources it was read from were complete or untampered, or \
compliance with any framework.";

/// Every limitation code a report can carry. A report with none is
/// `complete`; any one makes it `incomplete`, and an incomplete report never
/// satisfies an evidence-complete gate. The assembler states them as
/// literals; the tests hold it and `docs/policy-evidence.md` to this list.
#[cfg(test)]
pub(crate) const LIMITATION_CODES: &[&str] = &[
    // The publication's document format has no normative normalization, so
    // it is bound by its ETag alone.
    "policy_semantic_digest_unavailable",
    // No earlier version is in the history, so what the publication replaced
    // is unknown and a simulation has no base to compare with.
    "predecessor_not_in_history",
    // The history version before the publication is not the base the
    // publication recorded it was made against.
    "predecessor_differs_from_recorded_base",
    // Revalidation reported a diagnostic that blocks complete evidence.
    "validation_blocks_evidence",
    // Revalidation reported more diagnostics than a report lists.
    "validation_diagnostics_truncated",
    "tests_not_included",
    // The test run reported an undecided or refused case.
    "tests_incomplete",
    "simulation_not_included",
    // The predecessor no longer compiles under this build, so the simulation
    // could not compare with it.
    "simulation_base_not_evaluable",
    "replay_not_included",
    // The replay job's result is incomplete: truncated, past its deadline,
    // over a changed source, or with no replayable record.
    "replay_incomplete",
    // The replay job compared the publication with some policy other than
    // its predecessor, so its impact is not the publication's own.
    "replay_base_not_predecessor",
];
