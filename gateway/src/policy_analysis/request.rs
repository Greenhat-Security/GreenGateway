//! The `policy-analysis.v1` request: strict members, exact version dispatch,
//! and structured, value-free diagnostics.
//!
//! ```json
//! {
//!   "schema_version": "policy-analysis.v1",
//!   "base_etag": "\"sha256:...\"",
//!   "candidate": { "source": "active" },
//!   "format": "sarif"
//! }
//! ```
//!
//! `base_etag` is required, exactly as for a simulation: an analysis is
//! pinned to the active policy it was written against, so every position a
//! finding or a patch names means what its author read. `candidate` takes the
//! simulation's three sources, parsed by the simulation's own parser.

use serde_json::Value;

use super::{ANALYSIS_MEDIA_TYPE, ANALYSIS_SCHEMA_VERSION};
use crate::{
    canonical_json,
    policy_simulation::request::{parse_candidate, CandidateSource, MAX_BASE_ETAG_BYTES},
    policy_testing::suite::{
        bounded_string, check_members, object, required, Diagnostics, MAX_DESCRIPTION_BYTES,
    },
};

/// Which rendering the caller asked for. JSON is authoritative; SARIF is
/// derived from it and carries no more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisFormat {
    Json,
    Sarif,
}

impl AnalysisFormat {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sarif => "sarif",
        }
    }
}

/// An accepted request. Only [`parse_request`] builds one.
///
/// It does not derive `Debug`: an inline candidate holds a policy, which
/// does not belong in a log line.
pub(crate) struct AnalysisRequest {
    /// The ADR-0004 source digest of the exact request bytes.
    pub(crate) digest: String,
    pub(crate) base_etag: String,
    pub(crate) candidate: CandidateSource,
    pub(crate) format: AnalysisFormat,
}

/// Parse and validate a request body already read as `value` from `bytes`,
/// or say every reason it is refused.
pub(crate) fn parse_request(bytes: &[u8], value: &Value) -> Result<AnalysisRequest, Diagnostics> {
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
            "format",
        ],
        &mut diagnostics,
    );
    match root.get("schema_version") {
        None => diagnostics.push(
            "missing_field",
            "/schema_version",
            "schema_version is required",
        ),
        Some(Value::String(version)) if version == ANALYSIS_SCHEMA_VERSION => {}
        Some(_) => {
            // Refuse before reading anything else: a different version may
            // give the same members a different meaning.
            diagnostics.push(
                "unsupported_schema_version",
                "/schema_version",
                format!("schema_version must be exactly \"{ANALYSIS_SCHEMA_VERSION}\""),
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
    let format = match root.get("format") {
        None => Some(AnalysisFormat::Json),
        Some(value) => {
            let format = match value.as_str() {
                Some("json") => Some(AnalysisFormat::Json),
                Some("sarif") => Some(AnalysisFormat::Sarif),
                _ => None,
            };
            if format.is_none() {
                diagnostics.push(
                    "invalid_value",
                    "/format",
                    "format must be \"json\" or \"sarif\"",
                );
            }
            format
        }
    };
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    match (base_etag, candidate, format) {
        (Some(base_etag), Some(candidate), Some(format)) => Ok(AnalysisRequest {
            digest: canonical_json::source_digest(
                ANALYSIS_MEDIA_TYPE,
                ANALYSIS_SCHEMA_VERSION,
                bytes,
            ),
            base_etag,
            candidate,
            format,
        }),
        // Every arm that yields `None` above records why; refused rather
        // than defaulted if one ever does not.
        _ => {
            diagnostics.push("invalid_request", "", "the analysis request is incomplete");
            Err(diagnostics)
        }
    }
}
