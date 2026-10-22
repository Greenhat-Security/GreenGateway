//! Outbound requests' bounds, compiled in pure stages (issue #433, PR 2).
//!
//! One block, [`EgressInputs`]: the host allowlist, the timeouts and body
//! bounds, the NAT64 prefixes and whether private addresses are refused.
//! Every input is checked on its own; none relates to another. Nothing here
//! resolves an allowed host or builds a client: a host that does not resolve
//! is accepted exactly as the legacy parser accepts it, and the egress
//! boundary decides each destination when a request is made.

use std::env::VarError;

use ipnet::IpNet;

use super::{
    parse_comma_separated_hostnames, parse_nat64_prefixes, parse_var,
    stage::{Checked, Findings, Provenance, RawInput},
    validate_positive_timeout_ms, DEFAULT_EGRESS_CONNECT_TIMEOUT_MS,
    DEFAULT_EGRESS_DENY_PRIVATE_IPS, DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES,
    DEFAULT_EGRESS_MAX_RESPONSE_BYTES, DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
    DEFAULT_EGRESS_TIMEOUT_MS, EGRESS_ALLOWED_HOSTS, EGRESS_CONNECT_TIMEOUT_MS,
    EGRESS_DENY_PRIVATE_IPS, EGRESS_MAX_REQUEST_BODY_BYTES, EGRESS_MAX_RESPONSE_BYTES,
    EGRESS_NAT64_PREFIXES, EGRESS_RESPONSE_IDLE_TIMEOUT_MS, EGRESS_TIMEOUT_MS,
};

/// The egress block's inputs, as the reader returned them.
pub(super) struct EgressInputs {
    allowed_hosts: RawInput,
    timeout_ms: RawInput,
    response_idle_timeout_ms: RawInput,
    connect_timeout_ms: RawInput,
    max_response_bytes: RawInput,
    max_request_body_bytes: RawInput,
    nat64_prefixes: RawInput,
    deny_private_ips: RawInput,
}

impl EgressInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            allowed_hosts: RawInput::new(EGRESS_ALLOWED_HOSTS, get_var(EGRESS_ALLOWED_HOSTS)),
            timeout_ms: RawInput::new(EGRESS_TIMEOUT_MS, get_var(EGRESS_TIMEOUT_MS)),
            response_idle_timeout_ms: RawInput::new(
                EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
                get_var(EGRESS_RESPONSE_IDLE_TIMEOUT_MS),
            ),
            connect_timeout_ms: RawInput::new(
                EGRESS_CONNECT_TIMEOUT_MS,
                get_var(EGRESS_CONNECT_TIMEOUT_MS),
            ),
            max_response_bytes: RawInput::new(
                EGRESS_MAX_RESPONSE_BYTES,
                get_var(EGRESS_MAX_RESPONSE_BYTES),
            ),
            max_request_body_bytes: RawInput::new(
                EGRESS_MAX_REQUEST_BODY_BYTES,
                get_var(EGRESS_MAX_REQUEST_BODY_BYTES),
            ),
            nat64_prefixes: RawInput::new(EGRESS_NAT64_PREFIXES, get_var(EGRESS_NAT64_PREFIXES)),
            deny_private_ips: RawInput::new(
                EGRESS_DENY_PRIVATE_IPS,
                get_var(EGRESS_DENY_PRIVATE_IPS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.allowed_hosts,
            &self.timeout_ms,
            &self.response_idle_timeout_ms,
            &self.connect_timeout_ms,
            &self.max_response_bytes,
            &self.max_request_body_bytes,
            &self.nat64_prefixes,
            &self.deny_private_ips,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The validated egress settings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EgressPlan {
    pub(crate) egress_allowed_hosts: Vec<String>,
    pub(crate) egress_timeout_ms: u64,
    pub(crate) egress_response_idle_timeout_ms: u64,
    pub(crate) egress_connect_timeout_ms: u64,
    pub(crate) egress_max_response_bytes: usize,
    pub(crate) egress_max_request_body_bytes: usize,
    pub(crate) egress_nat64_prefixes: Vec<IpNet>,
    pub(crate) egress_deny_private_ips: bool,
    /// Where each of the block's inputs came from, in the order they are read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// Parses the egress block. Every input here is checked on its own.
pub(super) fn compile(inputs: EgressInputs) -> Checked<EgressPlan> {
    let mut findings = Findings::default();
    let provenance = inputs.provenance();

    let egress_allowed_hosts = findings.input(EGRESS_ALLOWED_HOSTS, |problems| {
        parse_comma_separated_hostnames(
            EGRESS_ALLOWED_HOSTS,
            inputs.allowed_hosts.value(),
            problems,
        )
    });
    let egress_timeout_ms = timeout_ms(
        EGRESS_TIMEOUT_MS,
        &inputs.timeout_ms,
        DEFAULT_EGRESS_TIMEOUT_MS,
        &mut findings,
    );
    let egress_response_idle_timeout_ms = timeout_ms(
        EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
        &inputs.response_idle_timeout_ms,
        DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
        &mut findings,
    );
    let egress_connect_timeout_ms = timeout_ms(
        EGRESS_CONNECT_TIMEOUT_MS,
        &inputs.connect_timeout_ms,
        DEFAULT_EGRESS_CONNECT_TIMEOUT_MS,
        &mut findings,
    );
    let egress_max_response_bytes = findings.input(EGRESS_MAX_RESPONSE_BYTES, |problems| {
        parse_var(
            EGRESS_MAX_RESPONSE_BYTES,
            inputs.max_response_bytes.value(),
            DEFAULT_EGRESS_MAX_RESPONSE_BYTES,
            "byte size",
            problems,
        )
    });
    let egress_max_request_body_bytes = findings.input(EGRESS_MAX_REQUEST_BODY_BYTES, |problems| {
        parse_var(
            EGRESS_MAX_REQUEST_BODY_BYTES,
            inputs.max_request_body_bytes.value(),
            DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES,
            "byte size",
            problems,
        )
    });
    let egress_nat64_prefixes = findings.input(EGRESS_NAT64_PREFIXES, |problems| {
        parse_nat64_prefixes(
            EGRESS_NAT64_PREFIXES,
            inputs.nat64_prefixes.value(),
            problems,
        )
    });
    let egress_deny_private_ips = findings.input(EGRESS_DENY_PRIVATE_IPS, |problems| {
        parse_var(
            EGRESS_DENY_PRIVATE_IPS,
            inputs.deny_private_ips.value(),
            DEFAULT_EGRESS_DENY_PRIVATE_IPS,
            "boolean",
            problems,
        )
    });

    Checked::new(
        EgressPlan {
            egress_allowed_hosts,
            egress_timeout_ms,
            egress_response_idle_timeout_ms,
            egress_connect_timeout_ms,
            egress_max_response_bytes,
            egress_max_request_body_bytes,
            egress_nat64_prefixes,
            egress_deny_private_ips,
            provenance,
        },
        findings,
    )
}

/// A positive millisecond timeout with a default.
fn timeout_ms(
    setting: &'static str,
    input: &RawInput,
    default: u64,
    findings: &mut Findings,
) -> u64 {
    findings.input(setting, |problems| {
        let timeout_ms = parse_var(
            setting,
            input.value(),
            default,
            "millisecond duration",
            problems,
        );
        validate_positive_timeout_ms(setting, timeout_ms, default, problems)
    })
}
