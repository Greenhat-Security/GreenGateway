//! The static egress lane (#422 PR 3b): whether the effective egress controls
//! admit an outbound destination, decided over the destination URL and, when the
//! caller supplies them, trusted resolution facts.
//!
//! The lane resolves nothing. Its live adapter in `crate::egress` asks first with
//! no resolution facts, and only an answer that asks for them sends the adapter
//! to its resolver. A destination the static checks refuse is refused whatever
//! the resolution facts are, so a denied destination is never looked up. That is
//! stated here, in the order the lane decides, rather than left to the order an
//! adapter happens to call things in: a denial never waits for a fact the lane
//! did not need.
//!
//! The answers it reads are trusted in a narrow sense. The lane cannot know
//! whether an address set is what a resolver returned, or how fresh it is; it
//! decides over the set it is given, in the order given, and pins the first
//! answer, as the pre-cutover checks did. The DNS lookup itself, redirect
//! refusal, the transport that connects to the pinned address, TLS, gRPC
//! transport controls and request and response bounds stay in `crate::egress`,
//! and `NOT_EVALUATED` names them.
//!
//! The predicates are shared rather than copied. Host patterns, the non-global
//! address registry with its NAT64 handling, and policy CIDR membership are the
//! functions the egress module has always used, so pattern and address semantics
//! cannot drift between this lane and the module that applies it. What moved
//! here is the decision: which check runs, in which order, and what it refuses.

use std::{collections::HashSet, fmt, net::SocketAddr};

use ipnet::IpNet;
use serde::Serialize;
use url::Url;

use super::{framed_digest, EvaluationError, LogicalDecision, PolicyEffect, MAX_TRACE_BYTES};
use crate::egress::{host_glob_matches, ip_matches_policy_cidr, is_non_global_ip};

pub(crate) const EGRESS_CONTEXT_VERSION: u16 = 1;
pub(crate) const EGRESS_SEMANTICS_VERSION: &str = "gg-static-egress-v1";
const EGRESS_DOMAIN: &str = "static_egress_v1";
/// Frame kind for the digest over the controls a compiled lane decides by.
const EGRESS_CONTROLS_DIGEST_KIND: &str = "gg.egress-controls.v1";

/// The effective static egress controls, as `EgressConfig` holds them.
///
/// Exact hosts come from `EGRESS_ALLOWED_HOSTS` and auto-seeded infrastructure
/// endpoints, already lowercased by the configuration loader; host patterns,
/// ports and private-address CIDRs from the policy `egress` section; the
/// non-global switch and NAT64 prefixes from the environment. Nothing is
/// normalized here: an entry the pre-cutover check could never match, such as an
/// upper-case exact host built by hand, still never matches.
#[derive(Clone)]
pub(crate) struct EgressControls {
    pub(crate) allowed_hosts: HashSet<String>,
    pub(crate) allowed_host_globs: Vec<String>,
    pub(crate) allowed_ports: HashSet<u16>,
    pub(crate) deny_private_ips: bool,
    pub(crate) nat64_prefixes: Vec<IpNet>,
    pub(crate) private_ip_allow_cidrs: Vec<IpNet>,
}

/// The compiled static egress lane: its controls and the snapshot that names
/// them. Immutable once built; an egress client builds one with each
/// configuration and decides every destination by it.
pub(crate) struct CompiledEgressPolicy {
    controls: EgressControls,
    snapshot: EgressSnapshot,
}

impl fmt::Debug for CompiledEgressPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledEgressPolicy")
            .finish_non_exhaustive()
    }
}

/// What a result is bound to: the digest of the exact controls that decided it,
/// and the lane's context and semantics versions.
///
/// This is its own resource, not the HTTP policy's `ResourceSnapshot`. The
/// controls are only partly policy: the exact hosts, the non-global switch and
/// the NAT64 prefixes come from configuration, so the policy digest does not
/// identify them, and borrowing it would bind a result to the wrong thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EgressSnapshot {
    controls_digest: [u8; 32],
    context_version: u16,
    semantics_version: &'static str,
}

/// What a destination URL says, normalized once.
///
/// The live adapter builds this from the URL it will request and reads the host
/// and port back from it for resolution, so the name the resolver is asked for is
/// the name the controls admitted, normalized by one function.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EgressDestination {
    scheme: String,
    host: Option<String>,
    port: Option<u16>,
    userinfo: bool,
    fragment: bool,
}

impl fmt::Debug for EgressDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressDestination")
            .finish_non_exhaustive()
    }
}

impl EgressDestination {
    pub(crate) fn from_url(url: &Url) -> Self {
        Self::from_parts(
            url.scheme().to_owned(),
            url.host_str().map(str::to_ascii_lowercase),
            url.port_or_known_default(),
            !url.username().is_empty() || url.password().is_some(),
            url.fragment().is_some(),
        )
    }

    /// The same facts, from a caller that holds them rather than a URL: policy
    /// replay (#243) reads them out of a recorded context. Whether the URL had
    /// userinfo or a fragment is a flag; their values are never facts.
    pub(crate) fn from_parts(
        scheme: String,
        host: Option<String>,
        port: Option<u16>,
        userinfo: bool,
        fragment: bool,
    ) -> Self {
        Self {
            scheme,
            host,
            port,
            userinfo,
            fragment,
        }
    }

    /// The lowercased host, when the URL has one.
    pub(crate) fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The explicit port, or the scheme's default.
    pub(crate) fn port(&self) -> Option<u16> {
        self.port
    }
}

/// The resolution facts a question carries.
#[derive(Clone, Copy)]
pub(crate) enum ResolutionFact<'a> {
    /// None were supplied. The static checks still decide; a destination they
    /// admit is indeterminate, because the addresses can still refuse it.
    Missing,
    /// The complete answer set, in resolver order: what a resolver returned, or
    /// the one address an earlier check under these same controls pinned.
    Resolved(&'a [SocketAddr]),
}

#[derive(Clone, Copy)]
pub(crate) struct EgressEvaluationContext<'a> {
    pub(crate) version: u16,
    pub(crate) snapshot: EgressSnapshot,
    pub(crate) destination: &'a EgressDestination,
    pub(crate) resolution: ResolutionFact<'a>,
}

impl fmt::Debug for EgressEvaluationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressEvaluationContext")
            .finish_non_exhaustive()
    }
}

impl EgressEvaluationContext<'_> {
    /// Only the adapter-controlled facts are checked. The lane imposes no bound
    /// of its own on a URL or an answer set: the pre-cutover checks had none,
    /// and a bound found here would refuse destinations the gateway reaches
    /// today, at decision time, as an internal error.
    fn validate(&self, expected: EgressSnapshot) -> Result<(), EvaluationError> {
        if self.version != EGRESS_CONTEXT_VERSION {
            return Err(EvaluationError::UnsupportedContextVersion);
        }
        if self.snapshot != expected {
            return Err(EvaluationError::SnapshotMismatch);
        }
        Ok(())
    }

    fn binding(&self) -> Result<EgressBinding, EvaluationError> {
        let destination = self.destination;
        // Every fact binds the result, the resolution facts included: the same
        // destination with another answer set is another question.
        let resolution = match self.resolution {
            ResolutionFact::Missing => ("missing", None),
            ResolutionFact::Resolved(answers) => ("resolved", Some(answers)),
        };
        let bytes = serde_json::to_vec(&(
            EGRESS_SEMANTICS_VERSION,
            self.version,
            &destination.scheme,
            &destination.host,
            destination.port,
            destination.userinfo,
            destination.fragment,
            resolution,
        ))
        .map_err(|_| EvaluationError::TraceEncoding)?;
        Ok(EgressBinding {
            snapshot: self.snapshot,
            context_digest: framed_digest(
                "gg.egress-context",
                "application/json",
                EGRESS_SEMANTICS_VERSION,
                &bytes,
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct EgressBinding {
    snapshot: EgressSnapshot,
    context_digest: [u8; 32],
}

/// Why a destination was refused, in the order the lane checks. The first
/// failing check decides, so two failures report the earlier one, as the
/// pre-cutover checks did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EgressDenial {
    MissingHost,
    Userinfo,
    Fragment,
    SchemeNotAllowed,
    HostNotAllowed,
    MissingPort,
    PortNotAllowed,
    EmptyResolution,
    UnexpectedResolvedPort,
    /// The first answer in the set that is non-global and outside every policy
    /// CIDR. An ordinal into the supplied answers, never the address itself.
    NonGlobalAddress {
        index: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum EgressLimitation {
    /// The static checks admitted the destination and no resolution facts were
    /// supplied. The only fact this lane can be missing.
    #[serde(rename = "missing_resolution_fact")]
    MissingResolution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EgressOutcome {
    /// Every check passed. `pinned` indexes the supplied answer set: the
    /// address the transport must connect to.
    Allow {
        pinned: usize,
    },
    Deny(EgressDenial),
    Indeterminate(EgressLimitation),
}

const NOT_EVALUATED: &[&str] = &[
    "authentication",
    "http_policy",
    "tools",
    "rate_selection",
    "mutable_capacity",
    "dns",
    "redirects",
    "tls",
    "transport",
    "request_bounds",
    "response_bounds",
    "upstream_execution",
    "live_revision_freshness",
    "gateway_build_identity",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EgressEvaluation {
    binding: EgressBinding,
    domain: &'static str,
    semantics_version: &'static str,
    context_version: u16,
    not_evaluated: &'static [&'static str],
    logical: LogicalDecision,
    effect: PolicyEffect,
    outcome: EgressOutcome,
    /// Complete for the named static egress domain only. An allow is no promise
    /// that a connection is made or that a request succeeds.
    complete: bool,
}

impl EgressEvaluation {
    /// The lane's answer. The live adapter matches on this, and on nothing
    /// narrower, so a variant added here is a decision it must make.
    pub(crate) fn outcome(&self) -> EgressOutcome {
        self.outcome
    }

    /// Fixed-schema JSON trace: bounded enums, ordinals and digests only. No
    /// host, scheme, port or address escapes.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "offline trace reuse remains outside the live egress adapter"
        )
    )]
    pub(crate) fn canonical_trace_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        let bytes = serde_json::to_vec(self).map_err(|_| EvaluationError::TraceEncoding)?;
        if bytes.len() > MAX_TRACE_BYTES {
            return Err(EvaluationError::TraceTooLarge);
        }
        Ok(bytes)
    }

    /// Whether this result answers `context`. An indeterminate result never
    /// does: it is the absence of an answer, and the facts may since have
    /// arrived.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "offline trace reuse remains outside the live egress adapter"
        )
    )]
    pub(crate) fn reusable_for(&self, context: &EgressEvaluationContext<'_>) -> bool {
        self.complete
            && context.validate(self.binding.snapshot).is_ok()
            && context
                .binding()
                .is_ok_and(|binding| binding == self.binding)
    }
}

impl EgressSnapshot {
    /// The digest of the exact controls this snapshot names, for a policy
    /// resource snapshot that binds the effective egress controls by identity
    /// without carrying a host, port or range itself.
    pub(crate) fn controls_digest(&self) -> [u8; 32] {
        self.controls_digest
    }
}

impl CompiledEgressPolicy {
    pub(crate) fn new(controls: EgressControls) -> Self {
        let snapshot = EgressSnapshot {
            controls_digest: controls_digest(&controls),
            context_version: EGRESS_CONTEXT_VERSION,
            semantics_version: EGRESS_SEMANTICS_VERSION,
        };
        Self { controls, snapshot }
    }

    pub(crate) fn snapshot(&self) -> EgressSnapshot {
        self.snapshot
    }

    pub(crate) fn evaluate(
        &self,
        context: &EgressEvaluationContext<'_>,
    ) -> Result<EgressEvaluation, EvaluationError> {
        context.validate(self.snapshot)?;
        let binding = context.binding()?;
        // The static checks decide first, and a refusal is final whatever the
        // resolution facts are. That is what lets the adapter ask without them
        // and resolve nothing for a destination it is about to refuse.
        let outcome = match self.admit_destination(context.destination) {
            Err(denial) => EgressOutcome::Deny(denial),
            Ok(port) => match context.resolution {
                ResolutionFact::Missing => {
                    EgressOutcome::Indeterminate(EgressLimitation::MissingResolution)
                }
                ResolutionFact::Resolved(answers) => self.check_answers(port, answers),
            },
        };
        let (logical, effect, complete) = match outcome {
            EgressOutcome::Allow { .. } => (LogicalDecision::Allow, PolicyEffect::Allow, true),
            EgressOutcome::Deny(_) => (LogicalDecision::Deny, PolicyEffect::Block, true),
            EgressOutcome::Indeterminate(_) => {
                (LogicalDecision::Indeterminate, PolicyEffect::Block, false)
            }
        };
        Ok(EgressEvaluation {
            binding,
            domain: EGRESS_DOMAIN,
            semantics_version: EGRESS_SEMANTICS_VERSION,
            context_version: EGRESS_CONTEXT_VERSION,
            not_evaluated: NOT_EVALUATED,
            logical,
            effect,
            outcome,
            complete,
        })
    }

    /// The checks a destination must pass before any of its names is
    /// resolved, in the pre-cutover order: the URL's shape, its scheme, the host
    /// allowlist, then the port allowlist. Returns the admitted port.
    ///
    /// A host is admitted by an exact entry or by a pattern. The exact set is
    /// compared as it is held, and the patterns through `host_glob_matches`,
    /// which folds case and keeps label boundaries. An empty port list admits
    /// every port; a non-empty one admits only its own.
    fn admit_destination(&self, destination: &EgressDestination) -> Result<u16, EgressDenial> {
        let Some(host) = destination.host.as_deref() else {
            return Err(EgressDenial::MissingHost);
        };
        if destination.userinfo {
            return Err(EgressDenial::Userinfo);
        }
        if destination.fragment {
            return Err(EgressDenial::Fragment);
        }
        if !matches!(destination.scheme.as_str(), "http" | "https") {
            return Err(EgressDenial::SchemeNotAllowed);
        }
        let host_allowed = self.controls.allowed_hosts.contains(host)
            || self
                .controls
                .allowed_host_globs
                .iter()
                .any(|pattern| host_glob_matches(pattern, host));
        if !host_allowed {
            return Err(EgressDenial::HostNotAllowed);
        }
        let Some(port) = destination.port else {
            return Err(EgressDenial::MissingPort);
        };
        if !self.controls.allowed_ports.is_empty() && !self.controls.allowed_ports.contains(&port) {
            return Err(EgressDenial::PortNotAllowed);
        }
        Ok(port)
    }

    /// The checks over the trusted resolution facts.
    ///
    /// Every answer is judged, not only the one that will be pinned: a set
    /// that mixes a public address with a private one is refused, because the
    /// transport is not the only thing that could reach the other address. The
    /// first answer is pinned, in resolver order.
    fn check_answers(&self, port: u16, answers: &[SocketAddr]) -> EgressOutcome {
        if answers.is_empty() {
            return EgressOutcome::Deny(EgressDenial::EmptyResolution);
        }
        if answers.iter().any(|answer| answer.port() != port) {
            return EgressOutcome::Deny(EgressDenial::UnexpectedResolvedPort);
        }
        if self.controls.deny_private_ips {
            if let Some(index) = answers.iter().position(|answer| {
                is_non_global_ip(answer.ip(), &self.controls.nat64_prefixes)
                    && !ip_matches_policy_cidr(answer.ip(), &self.controls.private_ip_allow_cidrs)
            }) {
                return EgressOutcome::Deny(EgressDenial::NonGlobalAddress { index });
            }
        }
        EgressOutcome::Allow { pinned: 0 }
    }
}

/// Digest over the controls, with every collection sorted: the order hosts,
/// patterns, prefixes or CIDRs were listed in changes no decision, so it must
/// not change the identity either.
fn controls_digest(controls: &EgressControls) -> [u8; 32] {
    let mut hosts: Vec<&str> = controls.allowed_hosts.iter().map(String::as_str).collect();
    hosts.sort_unstable();
    let mut globs: Vec<&str> = controls
        .allowed_host_globs
        .iter()
        .map(String::as_str)
        .collect();
    globs.sort_unstable();
    let mut ports: Vec<u16> = controls.allowed_ports.iter().copied().collect();
    ports.sort_unstable();
    let mut nat64_prefixes: Vec<String> = controls
        .nat64_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    nat64_prefixes.sort_unstable();
    let mut cidrs: Vec<String> = controls
        .private_ip_allow_cidrs
        .iter()
        .map(ToString::to_string)
        .collect();
    cidrs.sort_unstable();
    // Strings, integers and a boolean always encode. The marker keeps the
    // digest defined, and unique to the failure, rather than shared.
    let payload = serde_json::to_vec(&(
        hosts,
        globs,
        ports,
        controls.deny_private_ips,
        nat64_prefixes,
        cidrs,
    ))
    .unwrap_or_else(|error| format!("unserializable\0{error}").into_bytes());
    framed_digest(
        EGRESS_CONTROLS_DIGEST_KIND,
        "application/json",
        EGRESS_SEMANTICS_VERSION,
        &payload,
    )
}

#[cfg(test)]
mod tests;
