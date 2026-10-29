//! The `policy-simulation.v1` request: strict members, exact version
//! dispatch, and structured, value-free diagnostics.
//!
//! ```json
//! {
//!   "schema_version": "policy-simulation.v1",
//!   "base_etag": "\"sha256:...\"",
//!   "candidate": { "source": "edits", "edits": [ ... ] },
//!   "trace": "matched",
//!   "projections": ["as_authored", "enforce_all_shadow"],
//!   "cases": [ ... ]
//! }
//! ```
//!
//! `base_etag` is required: every simulation is pinned to the active policy
//! it was written against, and is refused when that is no longer the one
//! live, so a position in an edit or a comparison with the base always means
//! what the author read. `candidate.source` is `active` (the base itself),
//! `edits` (position-aware edits over the base) or `inline` (a complete
//! policy document, read-only). Cases are `policy-tests.v1` cases without
//! `expect`, parsed by the same functions.

use serde::Deserialize;
use serde_json::{value::RawValue, Value};

use super::{
    edits::{parse_edits, PolicyEdit},
    Projection, TraceLevel, SIMULATION_MEDIA_TYPE, SIMULATION_SCHEMA_VERSION,
};
use crate::{
    canonical_json,
    policy_testing::suite::{
        bounded_string, check_members, object, parse_case_list, parse_synthetic_case, required,
        Diagnostics, SyntheticCase, MAX_DESCRIPTION_BYTES,
    },
};

/// Most cases one simulation may declare. Each case is evaluated once per
/// projection for the candidate and once more for the base when the two
/// differ, so this bounds a run at four times as many evaluator calls.
pub(crate) const MAX_SIMULATION_CASES: usize = 256;
/// Longest `base_etag` accepted, in bytes; far beyond the policy ETag's own
/// length, so a longer value cannot name any policy.
pub(crate) const MAX_BASE_ETAG_BYTES: usize = 256;

/// Where the candidate comes from.
pub(crate) enum CandidateSource {
    /// The pinned base, unchanged.
    Active,
    /// Position-aware edits over the pinned base.
    Edits(Vec<PolicyEdit>),
    /// A complete policy document submitted with the request, never
    /// stored: the exact bytes of `/candidate/policy`, so it is read by the
    /// parser a policy write reads its body with, not from a `Value` that
    /// has already settled repeated members and number spellings.
    Inline(Box<RawValue>),
}

impl CandidateSource {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Edits(_) => "edits",
            Self::Inline(_) => "inline",
        }
    }
}

/// An accepted request. Only [`parse_request`] builds one.
///
/// It does not derive `Debug`: cases hold fixture values and an inline
/// candidate holds a policy, and neither belongs in a log line.
pub(crate) struct SimulationRequest {
    /// The ADR-0004 source digest of the exact request bytes.
    pub(crate) digest: String,
    pub(crate) base_etag: String,
    pub(crate) candidate: CandidateSource,
    pub(crate) trace: TraceLevel,
    pub(crate) projections: Vec<Projection>,
    pub(crate) cases: Vec<SyntheticCase>,
}

/// Parse and validate a request body already read as `value` from `bytes`,
/// or say every reason it is refused.
pub(crate) fn parse_request(bytes: &[u8], value: &Value) -> Result<SimulationRequest, Diagnostics> {
    let mut diagnostics = Diagnostics::new();
    let Some(root) = object(value, "", &mut diagnostics) else {
        return Err(diagnostics);
    };
    check_members(
        root,
        "",
        &[
            "schema_version",
            "description",
            "base_etag",
            "candidate",
            "trace",
            "projections",
            "cases",
        ],
        &mut diagnostics,
    );
    match root.get("schema_version") {
        None => diagnostics.push(
            "missing_field",
            "/schema_version",
            "schema_version is required",
        ),
        Some(Value::String(version)) if version == SIMULATION_SCHEMA_VERSION => {}
        Some(_) => {
            // Refuse before reading anything else: a different version may
            // give the same members a different meaning.
            diagnostics.push(
                "unsupported_schema_version",
                "/schema_version",
                format!("schema_version must be exactly \"{SIMULATION_SCHEMA_VERSION}\""),
            );
            return Err(diagnostics);
        }
    }
    if let Some(description) = root.get("description") {
        bounded_string(
            description,
            "/description",
            MAX_DESCRIPTION_BYTES,
            &mut diagnostics,
        );
    }
    let base_etag = required(root, "base_etag", "", &mut diagnostics).and_then(|value| {
        bounded_string(value, "/base_etag", MAX_BASE_ETAG_BYTES, &mut diagnostics)
    });
    let candidate = required(root, "candidate", "", &mut diagnostics)
        .and_then(|value| parse_candidate(bytes, value, &mut diagnostics));
    let trace = match root.get("trace") {
        None => Some(TraceLevel::Terminal),
        Some(value) => {
            let trace = match value.as_str() {
                Some("terminal") => Some(TraceLevel::Terminal),
                Some("matched") => Some(TraceLevel::Matched),
                Some("full") => Some(TraceLevel::Full),
                _ => None,
            };
            if trace.is_none() {
                diagnostics.push(
                    "invalid_value",
                    "/trace",
                    "trace must be \"terminal\", \"matched\" or \"full\"",
                );
            }
            trace
        }
    };
    let projections = match root.get("projections") {
        None => Some(vec![Projection::AsAuthored]),
        Some(value) => parse_projections(value, &mut diagnostics),
    };
    let cases = parse_case_list(
        root.get("cases"),
        "/cases",
        MAX_SIMULATION_CASES,
        ("empty_simulation", "a simulation needs at least one case"),
        parse_synthetic_case,
        |case| &case.id,
        &mut diagnostics,
    );
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    match (base_etag, candidate, trace, projections) {
        (Some(base_etag), Some(candidate), Some(trace), Some(projections)) => {
            Ok(SimulationRequest {
                digest: canonical_json::source_digest(
                    SIMULATION_MEDIA_TYPE,
                    SIMULATION_SCHEMA_VERSION,
                    bytes,
                ),
                base_etag,
                candidate,
                trace,
                projections,
                cases,
            })
        }
        // Every arm that yields `None` above records why; refused rather
        // than defaulted if one ever does not.
        _ => {
            diagnostics.push(
                "invalid_request",
                "",
                "the simulation request is incomplete",
            );
            Err(diagnostics)
        }
    }
}

/// The request bytes' `/candidate/policy` member, unread.
#[derive(Deserialize)]
struct InlineCandidateBytes<'a> {
    #[serde(borrow)]
    candidate: InlinePolicyBytes<'a>,
}

#[derive(Deserialize)]
struct InlinePolicyBytes<'a> {
    #[serde(borrow)]
    policy: &'a RawValue,
}

/// Parse the top-level `candidate` member of a request read as `value` from
/// `bytes`. Historical replay takes the same three sources, with the same
/// members, so it parses them here, and an inline candidate keeps its exact
/// bytes for either.
pub(crate) fn parse_candidate(
    bytes: &[u8],
    value: &Value,
    diagnostics: &mut Diagnostics,
) -> Option<CandidateSource> {
    let map = object(value, "/candidate", diagnostics)?;
    let source = required(map, "source", "/candidate", diagnostics)?;
    match source.as_str() {
        Some("active") => {
            check_members(map, "/candidate", &["source"], diagnostics);
            Some(CandidateSource::Active)
        }
        Some("edits") => {
            check_members(map, "/candidate", &["source", "edits"], diagnostics);
            let before = diagnostics.diagnostics.len();
            let edits = parse_edits(map.get("edits"), "/candidate/edits", diagnostics);
            (diagnostics.diagnostics.len() == before).then_some(CandidateSource::Edits(edits))
        }
        Some("inline") => {
            check_members(map, "/candidate", &["source", "policy"], diagnostics);
            match required(map, "policy", "/candidate", diagnostics)? {
                // `value` was read from `bytes`, so the member is there; the
                // `Value` only says it is an object.
                Value::Object(_) => match serde_json::from_slice::<InlineCandidateBytes<'_>>(bytes)
                {
                    Ok(inline) => Some(CandidateSource::Inline(inline.candidate.policy.to_owned())),
                    Err(_) => {
                        diagnostics.push(
                            "invalid_request",
                            "/candidate/policy",
                            "the candidate policy could not be read from the request",
                        );
                        None
                    }
                },
                _ => {
                    diagnostics.push(
                        "invalid_type",
                        "/candidate/policy",
                        "policy must be a complete policy document",
                    );
                    None
                }
            }
        }
        _ => {
            diagnostics.push(
                "invalid_value",
                "/candidate/source",
                "source must be \"active\", \"edits\" or \"inline\"",
            );
            None
        }
    }
}

/// The `projections` member: one or both projections, each named once.
/// Historical replay takes the same member with the same meaning.
pub(crate) fn parse_projections(
    value: &Value,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<Projection>> {
    let Value::Array(items) = value else {
        diagnostics.push(
            "invalid_type",
            "/projections",
            "projections must be an array",
        );
        return None;
    };
    if items.is_empty() {
        diagnostics.push(
            "invalid_value",
            "/projections",
            "name at least one projection",
        );
        return None;
    }
    let mut projections = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let pointer = format!("/projections/{index}");
        let projection = match item.as_str() {
            Some("as_authored") => Projection::AsAuthored,
            Some("enforce_all_shadow") => Projection::EnforceAllShadow,
            _ => {
                diagnostics.push(
                    "invalid_value",
                    &pointer,
                    "a projection is \"as_authored\" or \"enforce_all_shadow\"",
                );
                return None;
            }
        };
        if projections.contains(&projection) {
            diagnostics.push(
                "duplicate_projection",
                &pointer,
                "each projection may be named once",
            );
            return None;
        }
        projections.push(projection);
    }
    Some(projections)
}
