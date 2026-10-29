//! The `policy-evidence-request.v1` request: strict members, exact version
//! dispatch, and structured, value-free diagnostics.
//!
//! ```json
//! {
//!   "schema_version": "policy-evidence-request.v1",
//!   "publication": { "version": 12, "etag": "\"sha256:...\"" },
//!   "suite": { "schema_version": "policy-tests.v1", "cases": [ ... ] },
//!   "simulation": {
//!     "trace": "terminal",
//!     "projections": ["as_authored"],
//!     "cases": [ ... ]
//!   },
//!   "replay_job_id": "rpl_..."
//! }
//! ```
//!
//! `publication.version` names the policy history version the package is
//! about; the optional `publication.etag` pins the document the caller
//! reviewed. `suite` is a complete `policy-tests.v1` suite, parsed by the
//! test-suite parser; `simulation` holds `policy-simulation.v1` cases and
//! projections, parsed by the functions a simulation parses them with, at a
//! `terminal` or `matched` trace level. `replay_job_id` names a finished
//! replay job of the caller's. Every section but `publication` is optional,
//! and a report says which it lacks.

use serde_json::Value;

use super::{REQUEST_MEDIA_TYPE, REQUEST_SCHEMA_VERSION};
use crate::{
    canonical_json,
    policy_simulation::{
        request::{parse_projections, MAX_BASE_ETAG_BYTES, MAX_SIMULATION_CASES},
        Projection, TraceLevel,
    },
    policy_testing::suite::{
        bounded_string, check_members, object, parse_case_list, parse_suite, parse_synthetic_case,
        required, Diagnostics, Suite, SyntheticCase,
    },
};

/// The largest history version a request may name: the I-JSON safe integer
/// range, which every version a history assigns stays far below.
const MAX_PUBLICATION_VERSION: u64 = (1 << 53) - 1;
/// Longest `replay_job_id` accepted, in bytes; beyond any job id the replay
/// registry assigns.
pub(crate) const MAX_REPLAY_JOB_ID_BYTES: usize = 64;

/// Which publication a package is about.
pub(crate) struct PublicationSelector {
    pub(crate) version: i64,
    /// The policy ETag the caller reviewed, when it pinned one.
    pub(crate) etag: Option<String>,
}

/// The synthetic cases a package's simulation section decides.
///
/// It does not derive `Debug`: cases hold fixture values.
pub(crate) struct SimulationSelection {
    pub(crate) trace: TraceLevel,
    pub(crate) projections: Vec<Projection>,
    pub(crate) cases: Vec<SyntheticCase>,
}

/// An accepted request. Only [`parse_request`] builds one.
///
/// It does not derive `Debug`: the suite and the cases hold fixture values,
/// and neither belongs in a log line.
pub(crate) struct EvidenceRequest {
    /// The ADR-0004 semantic digest of the request, so two requests that
    /// differ only in whitespace or member order name one set of inputs.
    pub(crate) digest: String,
    pub(crate) publication: PublicationSelector,
    pub(crate) suite: Option<Suite>,
    pub(crate) simulation: Option<SimulationSelection>,
    pub(crate) replay_job_id: Option<String>,
}

impl EvidenceRequest {
    /// Whether the request asks for synthetic evaluation: a suite or cases.
    pub(crate) fn evaluates_synthetic_cases(&self) -> bool {
        self.suite.is_some() || self.simulation.is_some()
    }
}

/// Parse and validate a request body already read as `value`, or say every
/// reason it is refused.
///
/// The caller has already refused a body with a repeated member name: the
/// digest is over `value`, which would otherwise have settled the repeat
/// silently.
pub(crate) fn parse_request(value: &Value) -> Result<EvidenceRequest, Diagnostics> {
    let mut diagnostics = Diagnostics::new();
    let Some(root) = object(value, "", &mut diagnostics) else {
        return Err(diagnostics);
    };
    check_members(
        root,
        "",
        &[
            "schema_version",
            "publication",
            "suite",
            "simulation",
            "replay_job_id",
        ],
        &mut diagnostics,
    );
    match root.get("schema_version") {
        None => diagnostics.push(
            "missing_field",
            "/schema_version",
            "schema_version is required",
        ),
        Some(Value::String(version)) if version == REQUEST_SCHEMA_VERSION => {}
        Some(_) => {
            // Refuse before reading anything else: a different version may
            // give the same members a different meaning.
            diagnostics.push(
                "unsupported_schema_version",
                "/schema_version",
                format!("schema_version must be exactly \"{REQUEST_SCHEMA_VERSION}\""),
            );
            return Err(diagnostics);
        }
    }
    let publication = required(root, "publication", "", &mut diagnostics)
        .and_then(|value| parse_publication(value, &mut diagnostics));
    let suite = root
        .get("suite")
        .and_then(|value| parse_embedded_suite(value, &mut diagnostics));
    let simulation = root
        .get("simulation")
        .and_then(|value| parse_simulation(value, &mut diagnostics));
    let replay_job_id = root.get("replay_job_id").and_then(|value| {
        bounded_string(
            value,
            "/replay_job_id",
            MAX_REPLAY_JOB_ID_BYTES,
            &mut diagnostics,
        )
    });
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let Some(publication) = publication else {
        // Every path that yields `None` above records why; refused rather
        // than defaulted if one ever does not.
        diagnostics.push("invalid_request", "", "the evidence request is incomplete");
        return Err(diagnostics);
    };
    let digest =
        match canonical_json::semantic_digest(REQUEST_MEDIA_TYPE, REQUEST_SCHEMA_VERSION, value) {
            Ok(digest) => digest,
            // Unreachable for an accepted request, whose numbers are all
            // bounded; refused rather than digested some other way.
            Err(_) => {
                diagnostics.push(
                    "unsupported_number",
                    "",
                    "every number in a request must be within the I-JSON safe range",
                );
                return Err(diagnostics);
            }
        };
    Ok(EvidenceRequest {
        digest,
        publication,
        suite,
        simulation,
        replay_job_id,
    })
}

fn parse_publication(value: &Value, diagnostics: &mut Diagnostics) -> Option<PublicationSelector> {
    let map = object(value, "/publication", diagnostics)?;
    check_members(map, "/publication", &["version", "etag"], diagnostics);
    let version = required(map, "version", "/publication", diagnostics).and_then(|value| {
        let version = value
            .as_u64()
            .filter(|version| (1..=MAX_PUBLICATION_VERSION).contains(version))
            .and_then(|version| i64::try_from(version).ok());
        if version.is_none() {
            diagnostics.push(
                "invalid_value",
                "/publication/version",
                format!("version must be an integer from 1 to {MAX_PUBLICATION_VERSION}"),
            );
        }
        version
    });
    let etag = match map.get("etag") {
        None => None,
        Some(value) => Some(bounded_string(
            value,
            "/publication/etag",
            MAX_BASE_ETAG_BYTES,
            diagnostics,
        )?),
    };
    Some(PublicationSelector {
        version: version?,
        etag,
    })
}

/// The suite member, parsed by the test-suite parser, with every diagnostic
/// located in the request rather than in the suite.
fn parse_embedded_suite(value: &Value, diagnostics: &mut Diagnostics) -> Option<Suite> {
    match parse_suite(value) {
        Ok(suite) => Some(suite),
        Err(refused) => {
            for diagnostic in refused.diagnostics {
                diagnostics.push(
                    diagnostic.code,
                    &format!("/suite{}", diagnostic.pointer),
                    diagnostic.message,
                );
            }
            if refused.truncated {
                diagnostics.truncated = true;
            }
            None
        }
    }
}

fn parse_simulation(value: &Value, diagnostics: &mut Diagnostics) -> Option<SimulationSelection> {
    let map = object(value, "/simulation", diagnostics)?;
    check_members(
        map,
        "/simulation",
        &["trace", "projections", "cases"],
        diagnostics,
    );
    let trace = match map.get("trace") {
        None => Some(TraceLevel::Terminal),
        Some(value) => {
            let trace = match value.as_str() {
                Some("terminal") => Some(TraceLevel::Terminal),
                Some("matched") => Some(TraceLevel::Matched),
                _ => None,
            };
            if trace.is_none() {
                diagnostics.push(
                    "invalid_value",
                    "/simulation/trace",
                    "trace must be \"terminal\" or \"matched\"; a full trace is not part of an evidence package",
                );
            }
            trace
        }
    };
    let projections = match map.get("projections") {
        None => Some(vec![Projection::AsAuthored]),
        Some(value) => parse_projections(value, "/simulation/projections", diagnostics),
    };
    let cases = parse_case_list(
        map.get("cases"),
        "/simulation/cases",
        MAX_SIMULATION_CASES,
        ("empty_simulation", "a simulation needs at least one case"),
        parse_synthetic_case,
        |case| &case.id,
        diagnostics,
    );
    Some(SimulationSelection {
        trace: trace?,
        projections: projections?,
        cases,
    })
}
