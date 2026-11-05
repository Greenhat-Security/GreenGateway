//! The configuration a synthetic case may be decided by besides the policy,
//! and the two lanes that read it (issue #243, slice 12): isolated rate
//! sequences and egress cases.
//!
//! Both stay on the far side of the line ADR-0004 draws around live state.
//!
//! - A rate sequence runs against an [`IsolatedBucket`] built for it alone
//!   from the selected lane's configured rate and burst: a policy override's
//!   own limits, or the global lane's configured ones when no override
//!   governs. It starts empty, takes each step at a virtual instant the case
//!   states, and is dropped with the sequence. No production bucket, bucket
//!   store, shared PostgreSQL rate state, gauge or metric is read or changed,
//!   so a sequence says what a key with no history would meet, never what any
//!   live caller has left.
//! - An egress case is decided by the static egress lane
//!   ([`CompiledEgressPolicy`]) the egress client decides every destination
//!   by. Its only resolution input is the case's own, explicitly hypothetical
//!   address list. Without one the answer for a destination the static checks
//!   admit is indeterminate, `missing_resolution_evidence`: nothing is ever
//!   resolved to fill the gap, and there is no fallback.
//!
//! Either input can be unavailable to a run -- an evidence package judges a
//! historical publication, which this process's configuration does not
//! describe -- and a case that needs a missing one is incomplete with a stable
//! code, never decided some other way.

use std::{sync::Arc, time::Duration};

use http::Method;

use super::suite::{EgressCase, RateSequence, StepOutcome};
use crate::{
    middleware::rate_limit::{GlobalRateLanes, IsolatedBucket, Lane, LaneLimit},
    policy_eval::{
        egress::{
            CompiledEgressPolicy, EgressDenial, EgressEvaluation, EgressEvaluationContext,
            EgressLimitation, EgressOutcome, ResolutionFact, EGRESS_CONTEXT_VERSION,
        },
        EvaluationError, RateLaneOutcome,
    },
};

/// The stable limitation of a sequence whose lane is a global one when the
/// global lanes' configuration is not available to the run.
pub(crate) const MISSING_RATE_LANE_CONFIGURATION: &str = "missing_rate_lane_configuration";
/// The stable limitation of an egress case in a run with no egress controls
/// to decide by.
pub(crate) const MISSING_EGRESS_CONTROLS: &str = "missing_egress_controls";

/// What a synthetic run may read besides the policy. Configuration only:
/// nothing here holds or reaches a bucket, permit, resolver or connection.
#[derive(Clone, Default)]
pub(crate) struct SyntheticResources {
    /// The global rate lanes' configured limits, for a sequence no override
    /// governs.
    pub(crate) global_rate_lanes: Option<GlobalRateLanes>,
    /// The static egress lane egress cases are decided by.
    pub(crate) egress: Option<Arc<CompiledEgressPolicy>>,
}

impl SyntheticResources {
    /// No configuration at all: every egress case and every sequence on a
    /// global lane is incomplete.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// The identity of what this run decides by, for its report.
    pub(crate) fn binding(&self) -> ResourceBinding {
        ResourceBinding {
            egress_controls_digest: self.egress.as_ref().map(|egress| {
                format!(
                    "sha256:{}",
                    hex::encode(egress.snapshot().controls_digest())
                )
            }),
            global_rate_lanes: if self.global_rate_lanes.is_some() {
                "configured"
            } else {
                "unavailable"
            },
        }
    }
}

/// What a report says about the configuration its synthetic cases were
/// decided by: the egress controls by digest, never a host, port or range.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ResourceBinding {
    /// `sha256:<hex>` of the egress controls, or `null` when the run had
    /// none and every egress case is incomplete.
    pub(crate) egress_controls_digest: Option<String>,
    /// `configured` or `unavailable`.
    pub(crate) global_rate_lanes: &'static str,
}

/// The lane a sequence ran against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SequenceLane {
    /// The selected policy override, whose buckets are keyed by principal.
    PolicyOverride,
    /// A global lane, whose buckets are keyed by client IP.
    Global(Lane),
}

impl SequenceLane {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PolicyOverride => "policy_override",
            Self::Global(Lane::Read) => "global_read",
            Self::Global(Lane::Write) => "global_write",
        }
    }

    /// The class of key the live lane buckets a request by. A sequence is
    /// always one key's history.
    pub(crate) fn key_class(self) -> &'static str {
        match self {
            Self::PolicyOverride => "principal",
            Self::Global(_) => "client_ip",
        }
    }
}

/// The outcome of one isolated sequence.
pub(crate) enum SequenceRun {
    /// Every step ran, in order, against a fresh bucket for `lane`.
    Ran {
        lane: SequenceLane,
        limit: LaneLimit,
        steps: Vec<StepOutcome>,
    },
    /// The selection did not decide a lane, so there was none to run on.
    Undecided,
    /// No override governs and the run has no global lane configuration.
    LaneConfigurationUnavailable,
}

/// Run `sequence` against a fresh bucket for the lane `selection` chose.
///
/// The bucket is built here, used here and dropped here. A request with
/// `method` is charged in the global lane the live limiter would charge it
/// in; an override's own limits are policy data and need no configuration.
pub(crate) fn run_sequence(
    selection: RateLaneOutcome,
    method: &Method,
    sequence: &RateSequence,
    resources: &SyntheticResources,
) -> SequenceRun {
    let (lane, limit) = match selection {
        RateLaneOutcome::Override { limit, .. } => (
            SequenceLane::PolicyOverride,
            LaneLimit {
                requests_per_second: limit.requests_per_second(),
                burst: limit.burst(),
            },
        ),
        RateLaneOutcome::NoOverride => match &resources.global_rate_lanes {
            Some(lanes) => {
                let (lane, limit) = lanes.for_method(method);
                (SequenceLane::Global(lane), limit)
            }
            None => return SequenceRun::LaneConfigurationUnavailable,
        },
        RateLaneOutcome::Indeterminate(_) => return SequenceRun::Undecided,
    };
    let mut bucket = IsolatedBucket::new(limit);
    let steps = sequence
        .at_ms
        .iter()
        .map(|at| {
            if bucket.check_at(Duration::from_millis(*at)) {
                StepOutcome::Allowed
            } else {
                StepOutcome::Limited
            }
        })
        .collect();
    SequenceRun::Ran { lane, limit, steps }
}

/// An egress case's answer.
pub(crate) enum EgressAnswer {
    /// The static egress lane decided, or found it could not.
    Decided(EgressEvaluation),
    /// The run has no egress controls to decide by.
    ControlsUnavailable,
}

/// Decide `case` through the static egress lane.
///
/// The hypothetical addresses, when the case has them, are the lane's
/// resolution facts; with none the lane is asked without any, exactly as the
/// live adapter first asks. The lane refuses a destination its static checks
/// refuse whatever the facts are, so such a case is decided either way.
pub(crate) fn evaluate_egress(
    case: &EgressCase,
    resources: &SyntheticResources,
) -> Result<EgressAnswer, EvaluationError> {
    let Some(policy) = resources.egress.as_deref() else {
        return Ok(EgressAnswer::ControlsUnavailable);
    };
    let resolution = match &case.hypothetical_addresses {
        None => ResolutionFact::Missing,
        Some(addresses) => ResolutionFact::Resolved(addresses),
    };
    policy
        .evaluate(&EgressEvaluationContext {
            version: EGRESS_CONTEXT_VERSION,
            snapshot: policy.snapshot(),
            destination: &case.destination,
            resolution,
        })
        .map(EgressAnswer::Decided)
}

/// The egress lane's stable reason code: `allowed`, each refusal by the
/// name the lane serializes it with, or `incomplete`.
pub(crate) fn egress_reason(outcome: EgressOutcome) -> &'static str {
    match outcome {
        EgressOutcome::Allow { .. } => "allowed",
        EgressOutcome::Deny(denial) => match denial {
            EgressDenial::MissingHost => "missing_host",
            EgressDenial::Userinfo => "userinfo",
            EgressDenial::Fragment => "fragment",
            EgressDenial::SchemeNotAllowed => "scheme_not_allowed",
            EgressDenial::HostNotAllowed => "host_not_allowed",
            EgressDenial::MissingPort => "missing_port",
            EgressDenial::PortNotAllowed => "port_not_allowed",
            EgressDenial::EmptyResolution => "empty_resolution",
            EgressDenial::UnexpectedResolvedPort => "unexpected_resolved_port",
            EgressDenial::NonGlobalAddress { .. } => "non_global_address",
        },
        EgressOutcome::Indeterminate(_) => "incomplete",
    }
}

/// The stable limitation of an indeterminate egress answer.
///
/// The lane calls it `missing_resolution_fact`. A synthetic case can only
/// lack it one way -- it supplied no hypothetical address list -- so the
/// result names what the case is missing: resolution evidence.
pub(crate) fn egress_limitation_code(limitation: EgressLimitation) -> &'static str {
    match limitation {
        EgressLimitation::MissingResolution => "missing_resolution_evidence",
    }
}

/// The limitation of an egress answer, when it has one.
pub(crate) fn egress_limitation(evaluation: &EgressEvaluation) -> Option<&'static str> {
    match evaluation.outcome() {
        EgressOutcome::Indeterminate(limitation) => Some(egress_limitation_code(limitation)),
        EgressOutcome::Allow { .. } | EgressOutcome::Deny(_) => None,
    }
}

/// The resources the synthetic-case tests decide by: two global lanes with
/// small bursts, and egress controls admitting one exact host, one pattern
/// and port 443 only, with non-global addresses refused.
#[cfg(test)]
pub(crate) fn test_resources() -> SyntheticResources {
    use crate::policy_eval::egress::EgressControls;
    SyntheticResources {
        global_rate_lanes: Some(GlobalRateLanes::new(
            LaneLimit {
                requests_per_second: 1.0,
                burst: 2,
            },
            LaneLimit {
                requests_per_second: 0.5,
                burst: 1,
            },
        )),
        egress: Some(Arc::new(CompiledEgressPolicy::new(EgressControls {
            allowed_hosts: ["api.example.test".to_owned()].into_iter().collect(),
            allowed_host_globs: vec!["*.svc.example.test".to_owned()],
            allowed_ports: [443].into_iter().collect(),
            deny_private_ips: true,
            nat64_prefixes: Vec::new(),
            private_ip_allow_cidrs: Vec::new(),
        }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal the lane can give has the code it serializes with, and
    /// each code is one an egress expectation may name.
    #[test]
    fn egress_reasons_are_the_lane_s_own_names_and_all_expectable() {
        let denials = [
            EgressDenial::MissingHost,
            EgressDenial::Userinfo,
            EgressDenial::Fragment,
            EgressDenial::SchemeNotAllowed,
            EgressDenial::HostNotAllowed,
            EgressDenial::MissingPort,
            EgressDenial::PortNotAllowed,
            EgressDenial::EmptyResolution,
            EgressDenial::UnexpectedResolvedPort,
            EgressDenial::NonGlobalAddress { index: 0 },
        ];
        let mut codes = vec![egress_reason(EgressOutcome::Allow { pinned: 0 })];
        for denial in denials {
            let code = egress_reason(EgressOutcome::Deny(denial));
            let serialized = serde_json::to_value(denial).expect("a denial serializes");
            let name = match &serialized {
                serde_json::Value::String(name) => name.clone(),
                serde_json::Value::Object(map) => map.keys().next().cloned().unwrap_or_default(),
                other => panic!("unexpected serialization {other}"),
            };
            assert_eq!(code, name, "{denial:?}");
            codes.push(code);
        }
        assert_eq!(codes, super::super::suite::EGRESS_REASONS);
        assert_eq!(
            egress_reason(EgressOutcome::Indeterminate(
                EgressLimitation::MissingResolution
            )),
            "incomplete"
        );
        assert!(super::super::suite::parse_egress_reason("incomplete").is_none());
        assert_eq!(
            egress_limitation_code(EgressLimitation::MissingResolution),
            "missing_resolution_evidence"
        );
    }

    /// A sequence runs on the selected override's own limits, on the global
    /// lane its method is charged in when none governs, and not at all
    /// without a lane or the configuration to build one.
    #[test]
    fn a_sequence_runs_on_the_selected_lane_only() {
        let resources = test_resources();
        let sequence = RateSequence {
            at_ms: vec![0, 0, 0, 1000],
        };
        let steps = |run: SequenceRun| match run {
            SequenceRun::Ran { lane, steps, .. } => Some((lane.as_str(), lane.key_class(), steps)),
            _ => None,
        };
        use StepOutcome::{Allowed, Limited};
        // GET is charged in `read`: burst 2, one token a second.
        assert_eq!(
            steps(run_sequence(
                RateLaneOutcome::NoOverride,
                &Method::GET,
                &sequence,
                &resources
            )),
            Some((
                "global_read",
                "client_ip",
                vec![Allowed, Allowed, Limited, Allowed]
            ))
        );
        // POST in `write`: burst 1, a token every two seconds.
        assert_eq!(
            steps(run_sequence(
                RateLaneOutcome::NoOverride,
                &Method::POST,
                &sequence,
                &resources
            )),
            Some((
                "global_write",
                "client_ip",
                vec![Allowed, Limited, Limited, Limited]
            ))
        );
        assert!(matches!(
            run_sequence(
                RateLaneOutcome::NoOverride,
                &Method::GET,
                &sequence,
                &SyntheticResources::none()
            ),
            SequenceRun::LaneConfigurationUnavailable
        ));
        assert!(matches!(
            run_sequence(
                RateLaneOutcome::Indeterminate(
                    crate::policy_eval::Limitation::MissingPrincipalFact
                ),
                &Method::GET,
                &sequence,
                &resources
            ),
            SequenceRun::Undecided
        ));
    }
}
