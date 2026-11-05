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
//! `edits` (position-aware edits over the base), `inline` (a complete
//! policy document, read-only), `draft` (a server-side draft the caller
//! owns, as it is at the draft ETag the request names) or `revision` (a
//! version of the policy history). Cases are `policy-tests.v1` cases without
//! `expect`, parsed by the same functions.

use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use serde_json::{value::RawValue, Map, Value};

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
/// length, so a longer value cannot name any policy. A draft candidate's
/// `draft_etag` has the same bound, for the same reason.
pub(crate) const MAX_BASE_ETAG_BYTES: usize = 256;
/// Longest `draft_id` accepted, in bytes; beyond a draft identifier's own
/// length, so a longer value cannot name any draft.
pub(crate) const MAX_DRAFT_ID_BYTES: usize = 64;
/// The largest history version a `revision` candidate may name: the largest
/// integer an I-JSON number carries exactly.
pub(crate) const MAX_HISTORY_VERSION: i64 = 9_007_199_254_740_991;

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
    /// A server-side draft the caller owns, as it is at the strong draft
    /// ETag the request names. It is read through the drafts store and
    /// never written: not rebased, not touched, not extended.
    Draft {
        draft_id: String,
        draft_etag: String,
    },
    /// A version of the policy history, read from the history authority and
    /// validated again under this build.
    Revision { version: i64 },
}

impl CandidateSource {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Edits(_) => "edits",
            Self::Inline(_) => "inline",
            Self::Draft { .. } => "draft",
            Self::Revision { .. } => "revision",
        }
    }
}

/// The stored document a `draft` or `revision` candidate was read as, for
/// results and audit records: identifiers only, never content. A candidate
/// the request carried itself has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StoredCandidate {
    /// A server-side draft, at the revision the request's draft ETag named.
    Draft { draft_id: String, revision: i64 },
    /// A version of the policy history.
    Revision { version: i64 },
}

impl StoredCandidate {
    /// The identifying members, each name prefixed with `prefix`: `draft_id`
    /// and `draft_revision` for a draft, `version` for a history version.
    pub(crate) fn members(&self, prefix: &str) -> Vec<(String, Value)> {
        match self {
            Self::Draft { draft_id, revision } => vec![
                (format!("{prefix}draft_id"), Value::from(draft_id.as_str())),
                (format!("{prefix}draft_revision"), Value::from(*revision)),
            ],
            Self::Revision { version } => {
                vec![(format!("{prefix}version"), Value::from(*version))]
            }
        }
    }

    /// Add [`Self::members`] to `view`.
    pub(crate) fn describe(&self, prefix: &str, view: &mut Map<String, Value>) {
        view.extend(self.members(prefix));
    }
}

/// The unprefixed members, so a binding can flatten its stored candidate
/// into itself.
impl Serialize for StoredCandidate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let members = self.members("");
        let mut map = serializer.serialize_map(Some(members.len()))?;
        for (name, value) in &members {
            map.serialize_entry(name, value)?;
        }
        map.end()
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
        Some(value) => parse_projections(value, "/projections", &mut diagnostics),
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
/// `bytes`. Historical replay and policy analysis take the same sources, with
/// the same members, and a policy test run the stored ones, so they parse
/// them here, and an inline candidate keeps its exact bytes for each.
///
/// A `draft` or `revision` candidate is only named here; what it names is
/// read, owner-scoped and validated, when the request is served.
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
        Some("draft") => {
            check_members(
                map,
                "/candidate",
                &["source", "draft_id", "draft_etag"],
                diagnostics,
            );
            let draft_id = required(map, "draft_id", "/candidate", diagnostics).and_then(|value| {
                bounded_string(
                    value,
                    "/candidate/draft_id",
                    MAX_DRAFT_ID_BYTES,
                    diagnostics,
                )
            });
            let draft_etag =
                required(map, "draft_etag", "/candidate", diagnostics).and_then(|value| {
                    bounded_string(
                        value,
                        "/candidate/draft_etag",
                        MAX_BASE_ETAG_BYTES,
                        diagnostics,
                    )
                });
            Some(CandidateSource::Draft {
                draft_id: draft_id?,
                draft_etag: draft_etag?,
            })
        }
        Some("revision") => {
            check_members(map, "/candidate", &["source", "version"], diagnostics);
            let version = required(map, "version", "/candidate", diagnostics)?;
            match version.as_i64() {
                Some(version) if (1..=MAX_HISTORY_VERSION).contains(&version) => {
                    Some(CandidateSource::Revision { version })
                }
                _ => {
                    diagnostics.push(
                        "invalid_value",
                        "/candidate/version",
                        "version must be a positive integer naming a policy history version",
                    );
                    None
                }
            }
        }
        _ => {
            diagnostics.push(
                "invalid_value",
                "/candidate/source",
                "source must be \"active\", \"edits\", \"inline\", \"draft\" or \"revision\"",
            );
            None
        }
    }
}

/// The `projections` member at `pointer`: one or both projections, each
/// named once. Historical replay and policy evidence take the same member
/// with the same meaning.
pub(crate) fn parse_projections(
    value: &Value,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<Projection>> {
    let Value::Array(items) = value else {
        diagnostics.push("invalid_type", pointer, "projections must be an array");
        return None;
    };
    if items.is_empty() {
        diagnostics.push("invalid_value", pointer, "name at least one projection");
        return None;
    }
    let mut projections = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_pointer = format!("{pointer}/{index}");
        let projection = match item.as_str() {
            Some("as_authored") => Projection::AsAuthored,
            Some("enforce_all_shadow") => Projection::EnforceAllShadow,
            _ => {
                diagnostics.push(
                    "invalid_value",
                    &item_pointer,
                    "a projection is \"as_authored\" or \"enforce_all_shadow\"",
                );
                return None;
            }
        };
        if projections.contains(&projection) {
            diagnostics.push(
                "duplicate_projection",
                &item_pointer,
                "each projection may be named once",
            );
            return None;
        }
        projections.push(projection);
    }
    Some(projections)
}
