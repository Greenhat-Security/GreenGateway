//! The proxy in front of the gateway and the proxying it does, compiled in
//! pure stages (issue #433, PR 2).
//!
//! Two blocks, each requested where the legacy parser requested it:
//!
//! 1. proxy trust ([`TrustedProxyInputs`]): whether forwarding headers are
//!    believed, and from which networks;
//! 2. upstream routing ([`RoutingInputs`]): the single upstream or the route
//!    table, the MCP upstream servers and the global upstream timeouts. Its
//!    rules need the identity plan, because a route that delegates the
//!    gateway's cookie session must agree with the authentication and CSRF
//!    settings, and they need to know whether a policy file is configured,
//!    because a host-bound route is authorized by host.
//!
//! The route documents are validated here exactly as before, by the same
//! helpers. Nothing here connects to an upstream, resolves its host or opens
//! a CA bundle or client identity file: those paths are carried for
//! activation to load.

use std::{env::VarError, fmt};

use ipnet::IpNet;

use super::{
    cookie_session_identity_header,
    diagnostic::ConfigRule,
    identity::IdentityPlan,
    parse_comma_separated_cidrs, parse_mcp_upstream_servers, parse_optional_upstream_url,
    parse_optional_var, parse_upstream_routes, parse_var,
    stage::{Checked, Findings, Provenance, RawInput},
    validate_optional_positive_timeout_ms, AuthMode, McpUpstreamServerConfig, UpstreamRouteConfig,
    AUTH_COOKIE_NAME, AUTH_ENABLED, AUTH_EXEMPT_PATHS, AUTH_MODE, CSRF_COOKIE_NAME, CSRF_ENABLED,
    CSRF_EXEMPT_PATHS, CSRF_HEADER_NAME, MCP_UPSTREAM_SERVERS, POLICY_FILE, TRUSTED_PROXY_CIDRS,
    TRUST_PROXY_HEADERS, UPSTREAM_CONNECT_TIMEOUT_MS, UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
    UPSTREAM_ROUTES, UPSTREAM_TIMEOUT_MS, UPSTREAM_URL,
};

/// Proxy trust's inputs, as the reader returned them.
pub(super) struct TrustedProxyInputs {
    headers: RawInput,
    networks: RawInput,
}

impl TrustedProxyInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            headers: RawInput::new(TRUST_PROXY_HEADERS, get_var(TRUST_PROXY_HEADERS)),
            networks: RawInput::new(TRUSTED_PROXY_CIDRS, get_var(TRUSTED_PROXY_CIDRS)),
        }
    }
}

/// Proxy trust, validated.
pub(super) struct TrustedProxy {
    headers: bool,
    networks: Vec<IpNet>,
    provenance: Vec<Provenance>,
}

/// Parses proxy trust, then checks its rule: believing forwarding headers
/// needs at least one network to believe them from.
pub(super) fn compile_trusted_proxy(inputs: TrustedProxyInputs) -> Checked<TrustedProxy> {
    let mut findings = Findings::default();
    let headers = findings.input(TRUST_PROXY_HEADERS, |problems| {
        parse_var(
            TRUST_PROXY_HEADERS,
            inputs.headers.value(),
            false,
            "boolean",
            problems,
        )
    });
    let networks = findings.input(TRUSTED_PROXY_CIDRS, |problems| {
        parse_comma_separated_cidrs(TRUSTED_PROXY_CIDRS, inputs.networks.value(), problems)
    });

    if headers && networks.is_empty() {
        findings.refuse(
            TRUSTED_PROXY_CIDRS,
            ConfigRule::TrustedProxyNetworksRequired,
            format!(
                "{TRUSTED_PROXY_CIDRS} must contain at least one CIDR when {TRUST_PROXY_HEADERS}=true"
            ),
        );
    }

    Checked::new(
        TrustedProxy {
            headers,
            networks,
            provenance: vec![inputs.headers.provenance(), inputs.networks.provenance()],
        },
        findings,
    )
}

/// Upstream routing's inputs, as the reader returned them.
pub(super) struct RoutingInputs {
    upstream_url: RawInput,
    upstream_routes: RawInput,
    mcp_upstream_servers: RawInput,
    upstream_timeout_ms: RawInput,
    upstream_response_idle_timeout_ms: RawInput,
    upstream_connect_timeout_ms: RawInput,
}

impl RoutingInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            upstream_url: RawInput::new(UPSTREAM_URL, get_var(UPSTREAM_URL)),
            upstream_routes: RawInput::new(UPSTREAM_ROUTES, get_var(UPSTREAM_ROUTES)),
            mcp_upstream_servers: RawInput::new(
                MCP_UPSTREAM_SERVERS,
                get_var(MCP_UPSTREAM_SERVERS),
            ),
            upstream_timeout_ms: RawInput::new(UPSTREAM_TIMEOUT_MS, get_var(UPSTREAM_TIMEOUT_MS)),
            upstream_response_idle_timeout_ms: RawInput::new(
                UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
                get_var(UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS),
            ),
            upstream_connect_timeout_ms: RawInput::new(
                UPSTREAM_CONNECT_TIMEOUT_MS,
                get_var(UPSTREAM_CONNECT_TIMEOUT_MS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.upstream_url,
            &self.upstream_routes,
            &self.mcp_upstream_servers,
            &self.upstream_timeout_ms,
            &self.upstream_response_idle_timeout_ms,
            &self.upstream_connect_timeout_ms,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The validated proxy settings.
#[derive(Clone, PartialEq)]
pub(crate) struct ProxyPlan {
    pub(crate) trust_proxy_headers: bool,
    pub(crate) trusted_proxy_cidrs: Vec<IpNet>,
    pub(crate) upstream_url: Option<String>,
    pub(crate) upstream_routes: Vec<UpstreamRouteConfig>,
    pub(crate) mcp_upstream_servers: Vec<McpUpstreamServerConfig>,
    pub(crate) upstream_timeout_ms: Option<u64>,
    pub(crate) upstream_response_idle_timeout_ms: Option<u64>,
    pub(crate) upstream_connect_timeout_ms: Option<u64>,
    /// Where each of the two blocks' inputs came from, in the order they are
    /// read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// Prints the plan's shape, not its destinations.
///
/// A route document can carry static request header values, which may be
/// credentials, and client identity locators, and an upstream URL can carry
/// query parameters. The routes' and servers' own `Debug` would print all of
/// them, so the plan prints how many there are instead.
impl fmt::Debug for ProxyPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyPlan")
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .field("upstream_url_set", &self.upstream_url.is_some())
            .field("upstream_route_count", &self.upstream_routes.len())
            .field(
                "mcp_upstream_server_count",
                &self.mcp_upstream_servers.len(),
            )
            .field("upstream_timeout_ms", &self.upstream_timeout_ms)
            .field(
                "upstream_response_idle_timeout_ms",
                &self.upstream_response_idle_timeout_ms,
            )
            .field(
                "upstream_connect_timeout_ms",
                &self.upstream_connect_timeout_ms,
            )
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Upstream routing, each input parsed on its own.
struct ParsedRouting {
    upstream_url: Option<String>,
    upstream_routes: Vec<UpstreamRouteConfig>,
    mcp_upstream_servers: Vec<McpUpstreamServerConfig>,
    upstream_timeout_ms: Option<u64>,
    upstream_response_idle_timeout_ms: Option<u64>,
    upstream_connect_timeout_ms: Option<u64>,
}

/// Parses upstream routing, then checks the rules between it, the identity
/// plan and the policy file, and builds the proxy plan.
pub(super) fn compile(
    inputs: RoutingInputs,
    trusted: TrustedProxy,
    identity: &IdentityPlan,
    policy_file_configured: bool,
) -> Checked<ProxyPlan> {
    let mut findings = Findings::default();
    let mut provenance = trusted.provenance;
    provenance.extend(inputs.provenance());

    let parsed = parse_routing(&inputs, &mut findings);
    validate_cookie_session_delegation(&parsed.upstream_routes, identity, &mut findings);
    if parsed.upstream_url.is_some() && !parsed.upstream_routes.is_empty() {
        findings.refuse(
            MCP_UPSTREAM_SERVERS,
            ConfigRule::UpstreamRoutingSourcesExclusive,
            format!(
                "{UPSTREAM_URL} and {UPSTREAM_ROUTES} are mutually exclusive; set one proxy routing source"
            ),
        );
    }
    if !policy_file_configured
        && parsed
            .upstream_routes
            .iter()
            .any(|route| route.host.is_some())
    {
        findings.refuse(
            MCP_UPSTREAM_SERVERS,
            ConfigRule::HostRoutesRequirePolicy,
            format!(
                "{UPSTREAM_ROUTES} entries with host require {POLICY_FILE} so RBAC can bind authorization to the selected request host"
            ),
        );
    }

    let ParsedRouting {
        upstream_url,
        upstream_routes,
        mcp_upstream_servers,
        upstream_timeout_ms,
        upstream_response_idle_timeout_ms,
        upstream_connect_timeout_ms,
    } = parsed;
    Checked::new(
        ProxyPlan {
            trust_proxy_headers: trusted.headers,
            trusted_proxy_cidrs: trusted.networks,
            upstream_url,
            upstream_routes,
            mcp_upstream_servers,
            upstream_timeout_ms,
            upstream_response_idle_timeout_ms,
            upstream_connect_timeout_ms,
            provenance,
        },
        findings,
    )
}

fn parse_routing(inputs: &RoutingInputs, findings: &mut Findings) -> ParsedRouting {
    let upstream_url = findings.input(UPSTREAM_URL, |problems| {
        parse_optional_upstream_url(UPSTREAM_URL, inputs.upstream_url.value(), problems)
    });
    let upstream_routes = findings.input(UPSTREAM_ROUTES, |problems| {
        parse_upstream_routes(UPSTREAM_ROUTES, inputs.upstream_routes.value(), problems)
    });
    let mcp_upstream_servers = findings.input(MCP_UPSTREAM_SERVERS, |problems| {
        parse_mcp_upstream_servers(
            MCP_UPSTREAM_SERVERS,
            inputs.mcp_upstream_servers.value(),
            problems,
        )
    });
    let upstream_timeout_ms =
        optional_timeout_ms(UPSTREAM_TIMEOUT_MS, &inputs.upstream_timeout_ms, findings);
    let upstream_response_idle_timeout_ms = optional_timeout_ms(
        UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
        &inputs.upstream_response_idle_timeout_ms,
        findings,
    );
    let upstream_connect_timeout_ms = optional_timeout_ms(
        UPSTREAM_CONNECT_TIMEOUT_MS,
        &inputs.upstream_connect_timeout_ms,
        findings,
    );

    ParsedRouting {
        upstream_url,
        upstream_routes,
        mcp_upstream_servers,
        upstream_timeout_ms,
        upstream_response_idle_timeout_ms,
        upstream_connect_timeout_ms,
    }
}

/// A global upstream timeout override: unset leaves each route's own, and
/// zero is refused.
fn optional_timeout_ms(
    setting: &'static str,
    input: &RawInput,
    findings: &mut Findings,
) -> Option<u64> {
    findings.input(setting, |problems| {
        let timeout_ms =
            parse_optional_var(setting, input.value(), "millisecond duration", problems);
        validate_optional_positive_timeout_ms(setting, timeout_ms, problems)
    })
}

/// A route that delegates the gateway's validated cookie session upstream
/// relies on that session being authenticated and CSRF-protected here, on the
/// session and CSRF cookies being distinct, and on no exemption reaching the
/// routes it delegates.
fn validate_cookie_session_delegation(
    upstream_routes: &[UpstreamRouteConfig],
    identity: &IdentityPlan,
    findings: &mut Findings,
) {
    let auth_cookie_name = &identity.auth_cookie_name;
    let csrf_cookie_name = &identity.csrf_cookie_name;
    let csrf_header_name = &identity.csrf_header_name;
    for (index, route) in upstream_routes.iter().enumerate() {
        if let Some(name) = &route.upstream_csrf_cookie_name {
            let name_base = name
                .strip_prefix("__Secure-")
                .or_else(|| name.strip_prefix("__Host-"))
                .unwrap_or(name);
            let auth_base = auth_cookie_name
                .strip_prefix("__Secure-")
                .or_else(|| auth_cookie_name.strip_prefix("__Host-"))
                .unwrap_or(auth_cookie_name);
            if !route.forward_cookie_session
                || !crate::middleware::auth::safe_cookie_token(name)
                || name_base == auth_base
            {
                findings.refuse(
                    UPSTREAM_ROUTES,
                    ConfigRule::CookieSessionDelegation,
                    format!("{UPSTREAM_ROUTES}[{index}].upstream_csrf_cookie_name requires cookie-session delegation and a safe non-identity cookie name"),
                );
            }
        }
        if !route.forward_cookie_session {
            continue;
        }
        let route_name = format!("{UPSTREAM_ROUTES}[{index}].forward_cookie_session");
        if !identity.auth_enabled
            || identity.auth_mode != AuthMode::Required
            || !identity.csrf_enabled
        {
            findings.refuse(
                UPSTREAM_ROUTES,
                ConfigRule::CookieSessionDelegation,
                format!(
                    "{route_name} requires {AUTH_ENABLED}=true, {AUTH_MODE}=required and {CSRF_ENABLED}=true"
                ),
            );
        }
        let auth_cookie_base = auth_cookie_name
            .strip_prefix("__Secure-")
            .or_else(|| auth_cookie_name.strip_prefix("__Host-"))
            .unwrap_or(auth_cookie_name);
        let csrf_cookie_base = csrf_cookie_name
            .strip_prefix("__Secure-")
            .or_else(|| csrf_cookie_name.strip_prefix("__Host-"))
            .unwrap_or(csrf_cookie_name);
        if auth_cookie_base == csrf_cookie_base {
            findings.refuse(
                UPSTREAM_ROUTES,
                ConfigRule::CookieSessionDelegation,
                format!("{route_name} requires distinct {AUTH_COOKIE_NAME} and {CSRF_COOKIE_NAME}"),
            );
        }
        if cookie_session_identity_header(csrf_header_name) {
            findings.refuse(
                UPSTREAM_ROUTES,
                ConfigRule::CookieSessionDelegation,
                format!(
                    "{route_name} requires {CSRF_HEADER_NAME} not to name a credential or identity header"
                ),
            );
        }
        if route.add_request_headers.contains_key(csrf_header_name)
            || route.strip_request_headers.contains(csrf_header_name)
        {
            findings.refuse(
                UPSTREAM_ROUTES,
                ConfigRule::CookieSessionDelegation,
                format!("{route_name} must not add or strip the configured {CSRF_HEADER_NAME}"),
            );
        }
        if let Some(prefix) = route.path_prefix.as_deref() {
            if identity.auth_exempt_paths.iter().any(|exempt| {
                crate::path_match::exempt_path_matches(prefix, exempt)
                    || crate::path_match::path_prefix_matches(exempt, prefix)
            }) {
                findings.refuse(
                    UPSTREAM_ROUTES,
                    ConfigRule::CookieSessionDelegation,
                    format!("{route_name} must not overlap {AUTH_EXEMPT_PATHS}"),
                );
            }
            // CSRF exemptions match exact paths; an exempt descendant is enough
            // to leave a delegated mutation without the gateway's outer check.
            if identity
                .csrf_exempt_paths
                .iter()
                .any(|exempt| crate::path_match::path_prefix_matches(exempt, prefix))
            {
                findings.refuse(
                    UPSTREAM_ROUTES,
                    ConfigRule::CookieSessionDelegation,
                    format!("{route_name} must not overlap {CSRF_EXEMPT_PATHS}"),
                );
            }
        }
    }
}
