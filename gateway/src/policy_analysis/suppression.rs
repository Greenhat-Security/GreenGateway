//! Which findings a suppression applies to (issue #243, slice 15).
//!
//! A suppression is a record an operator wrote after reviewing one finding:
//! its fingerprint and code, the policy it was found in (ETag and, for a
//! document format that has one, semantic digest), the resource snapshot it
//! was judged against, and an expiry. [`apply`] marks a finding `suppressed`
//! only when all five match the analysis and the record has not ended. A
//! record that names the finding but no longer binds -- the policy or the
//! resources moved, or its time ran out -- never hides it; the finding is
//! reported with that record's state instead, so a reviewer sees why it is
//! back. There is no wildcard: nothing suppresses a code, a section or every
//! finding at once.
//!
//! This is a pure function of the findings, the records and the binding. The
//! store judged `ended` on its own clock when the records were read.

use std::collections::BTreeMap;

use super::{AnalysisError, Finding};

/// One stored suppression, as the analysis reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Suppression {
    pub(crate) id: String,
    pub(crate) fingerprint: String,
    pub(crate) code: String,
    pub(crate) policy_etag: String,
    pub(crate) policy_semantic_digest: Option<String>,
    pub(crate) resource_snapshot_digest: String,
    /// Unix seconds on the store's clock; orders records naming one finding.
    pub(crate) created_at: i64,
    /// Withdrawn, or past its expiry, when the store read it.
    pub(crate) ended: bool,
}

/// What the suppressions were read as.
#[derive(Clone, Debug)]
pub(crate) enum SuppressionRead {
    Available(Vec<Suppression>),
    /// No store is configured, or it could not be read. Nothing is
    /// suppressed, and the report says the records were not consulted, so
    /// a count of zero is never mistaken for none existing.
    Unavailable,
}

/// The analyzed document and resources a suppression must name to apply.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SuppressionBinding<'a> {
    pub(crate) policy_etag: &'a str,
    pub(crate) policy_semantic_digest: Option<&'a str>,
    /// `None` when the resource snapshot is incomplete: no suppression
    /// binds to resources the analysis could not read.
    pub(crate) resource_snapshot_digest: Option<&'a str>,
}

/// A finding's suppression state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SuppressionState {
    /// A record names this finding and this binding and has not ended.
    Suppressed,
    /// Every record naming this finding has ended.
    Expired,
    /// A record naming this finding has not ended but binds another policy
    /// or other resources.
    Mismatched,
}

impl SuppressionState {
    pub(crate) const ALL: [Self; 3] = [Self::Suppressed, Self::Expired, Self::Mismatched];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Suppressed => "suppressed",
            Self::Expired => "suppression_expired",
            Self::Mismatched => "suppression_mismatched",
        }
    }
}

/// Which part of a binding a mismatched record names differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BindingPart {
    Policy,
    ResourceSnapshot,
}

impl BindingPart {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::ResourceSnapshot => "resource_snapshot",
        }
    }
}

/// The record that decided a finding's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedSuppression {
    pub(crate) state: SuppressionState,
    pub(crate) suppression_id: String,
    /// For a mismatched record, what it binds differently. Empty otherwise.
    pub(crate) mismatched: Vec<BindingPart>,
}

/// The suppression state of every finding of one analysis.
#[derive(Clone, Debug)]
pub(crate) struct SuppressionOutcome {
    /// Whether the records were read at all.
    pub(crate) available: bool,
    /// How many records were read, ended and unmatched ones included.
    pub(crate) records: usize,
    /// One entry per finding, in finding order.
    pub(crate) applied: Vec<Option<AppliedSuppression>>,
}

impl SuppressionOutcome {
    /// Findings in each state, every state listed.
    pub(crate) fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = SuppressionState::ALL
            .iter()
            .map(|state| (state.as_str(), 0))
            .collect();
        for applied in self.applied.iter().flatten() {
            *counts.entry(applied.state.as_str()).or_default() += 1;
        }
        counts
    }

    /// The outcome of an analysis that read no records, for `findings`.
    pub(crate) fn unavailable(findings: usize) -> Self {
        Self {
            available: false,
            records: 0,
            applied: vec![None; findings],
        }
    }
}

fn mismatched_parts(record: &Suppression, binding: &SuppressionBinding<'_>) -> Vec<BindingPart> {
    let mut parts = Vec::new();
    if record.policy_etag != binding.policy_etag
        || record.policy_semantic_digest.as_deref() != binding.policy_semantic_digest
    {
        parts.push(BindingPart::Policy);
    }
    if binding.resource_snapshot_digest != Some(record.resource_snapshot_digest.as_str()) {
        parts.push(BindingPart::ResourceSnapshot);
    }
    parts
}

/// The state of each finding. A record applies only to the finding whose
/// fingerprint and code it names, and suppresses it only when it binds this
/// analysis exactly and has not ended. When several records name a finding,
/// one that suppresses it wins; otherwise an unended mismatched record is
/// reported before an ended one, because it is the decision a reviewer most
/// recently meant to hold; among records in one state the latest created is
/// named.
pub(crate) fn apply(
    findings: &[Finding],
    read: &SuppressionRead,
    binding: &SuppressionBinding<'_>,
) -> Result<SuppressionOutcome, AnalysisError> {
    let SuppressionRead::Available(records) = read else {
        return Ok(SuppressionOutcome::unavailable(findings.len()));
    };
    let mut applied = Vec::with_capacity(findings.len());
    for finding in findings {
        let fingerprint = finding.fingerprint()?;
        let code = finding.code.as_str();
        let mut best: Option<(SuppressionState, i64, &str, Vec<BindingPart>)> = None;
        for record in records
            .iter()
            .filter(|record| record.fingerprint == fingerprint && record.code == code)
        {
            let parts = mismatched_parts(record, binding);
            let state = if record.ended {
                SuppressionState::Expired
            } else if parts.is_empty() {
                SuppressionState::Suppressed
            } else {
                SuppressionState::Mismatched
            };
            let rank = |state: SuppressionState| match state {
                SuppressionState::Suppressed => 0,
                SuppressionState::Mismatched => 1,
                SuppressionState::Expired => 2,
            };
            let better = match &best {
                None => true,
                Some((held, created_at, id, _)) => {
                    (
                        rank(state),
                        std::cmp::Reverse(record.created_at),
                        record.id.as_str(),
                    ) < (rank(*held), std::cmp::Reverse(*created_at), *id)
                }
            };
            if better {
                let parts = if state == SuppressionState::Mismatched {
                    parts
                } else {
                    Vec::new()
                };
                best = Some((state, record.created_at, record.id.as_str(), parts));
            }
        }
        applied.push(best.map(|(state, _, id, mismatched)| AppliedSuppression {
            state,
            suppression_id: id.to_owned(),
            mismatched,
        }));
    }
    Ok(SuppressionOutcome {
        available: true,
        records: records.len(),
        applied,
    })
}
