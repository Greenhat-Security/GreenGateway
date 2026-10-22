//! Frozen pre-cutover static egress checks from 198ab93, only for differential
//! tests: `checked_destination`, `rebind_checked_destination` and
//! `revalidated_destination`, with the URL, host, port and address checks and
//! the resolver step they composed. Never compiled into the serving binary; do
//! not update its decision semantics.
//!
//! It reads the same client's configuration and resolver that the live adapter
//! compiles its evaluator from, so the two are compared on one installed
//! instance rather than on two copies that agree by construction. The pure
//! predicates the checks called -- `host_glob_matches`, `is_non_global_ip`,
//! `ip_matches_policy_cidr` and `checked_port` -- are shared with the live
//! lane, which still calls them; what is frozen here is the composition.

use super::*;

impl EgressClient {
    pub(crate) async fn legacy_checked_destination(
        &self,
        url: &str,
    ) -> Result<CheckedEgressDestination, EgressError> {
        let parsed = self.legacy_checked_url(url)?;
        let host = legacy_checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        legacy_checked_policy_port(port, &self.config.allowed_ports)?;
        let pinned_addr = self.legacy_resolve_and_check(&host, port).await?;

        Ok(CheckedEgressDestination {
            scheme: parsed.scheme().to_owned(),
            host,
            pinned_addr,
            config_generation: self.config_generation,
            policy_generation: self.policy_generation,
        })
    }

    pub(crate) fn legacy_rebind_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
    ) -> Result<CheckedEgressDestination, EgressError> {
        if destination.policy_generation != self.policy_generation {
            return Err(EgressError::InvalidPolicy(
                "checked destination belongs to a different egress policy".to_owned(),
            ));
        }

        let parsed = self.legacy_checked_url(url)?;
        let host = legacy_checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        legacy_checked_policy_port(port, &self.config.allowed_ports)?;
        if destination.scheme != parsed.scheme()
            || destination.host != host
            || destination.pinned_addr.port() != port
        {
            return Err(EgressError::InvalidPolicy(
                "checked destination does not match the request authority".to_owned(),
            ));
        }
        legacy_checked_socket_addr(
            &host,
            &[destination.pinned_addr],
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )?;

        Ok(CheckedEgressDestination {
            scheme: destination.scheme.clone(),
            host: destination.host.clone(),
            pinned_addr: destination.pinned_addr,
            config_generation: self.config_generation,
            policy_generation: self.policy_generation,
        })
    }

    pub(crate) fn legacy_revalidated_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
    ) -> Result<(Url, String, u16), EgressError> {
        if destination.config_generation != self.config_generation {
            return Err(EgressError::InvalidPolicy(
                "checked destination belongs to a different egress configuration".to_owned(),
            ));
        }
        let parsed = self.legacy_checked_url(url)?;
        let host = legacy_checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        legacy_checked_policy_port(port, &self.config.allowed_ports)?;
        if destination.scheme != parsed.scheme()
            || destination.host != host
            || destination.pinned_addr.port() != port
        {
            return Err(EgressError::InvalidPolicy(
                "checked destination does not match the request authority".to_owned(),
            ));
        }
        legacy_checked_socket_addr(
            &host,
            &[destination.pinned_addr],
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )?;

        Ok((parsed, host, port))
    }

    pub(crate) fn legacy_checked_url(&self, url: &str) -> Result<Url, EgressError> {
        let parsed = Url::parse(url).map_err(|err| EgressError::InvalidUrl(err.to_string()))?;

        if parsed.host_str().is_none() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL without host"
            );
            return Err(EgressError::InvalidUrl("missing host".to_owned()));
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL containing userinfo"
            );
            return Err(EgressError::InvalidUrl(
                "URL userinfo is not allowed".to_owned(),
            ));
        }
        if parsed.fragment().is_some() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL containing a fragment"
            );
            return Err(EgressError::InvalidUrl(
                "URL fragments are not allowed".to_owned(),
            ));
        }

        match parsed.scheme() {
            "http" | "https" => Ok(parsed),
            scheme => {
                tracing::warn!(
                    error_category = "scheme_not_allowed",
                    "egress blocked URL scheme"
                );
                Err(EgressError::SchemeNotAllowed(scheme.to_owned()))
            }
        }
    }

    async fn legacy_resolve_and_check(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, EgressError> {
        let resolved = self
            .resolver
            .resolve(host, port)
            .await
            .map_err(|err| EgressError::DnsResolutionFailed(format!("{host}:{port}: {err}")))?;

        if resolved.is_empty() {
            return Err(EgressError::DnsResolutionFailed(format!("{host}:{port}")));
        }
        if resolved.iter().any(|address| address.port() != port) {
            return Err(EgressError::DnsResolutionFailed(format!(
                "{host}:{port}: resolver returned an unexpected port"
            )));
        }

        legacy_checked_socket_addr(
            host,
            &resolved,
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )
    }
}

fn legacy_checked_host(
    url: &Url,
    allowed_hosts: &HashSet<String>,
    allowed_host_globs: &[String],
) -> Result<String, EgressError> {
    let host = url
        .host_str()
        .ok_or_else(|| EgressError::InvalidUrl("missing host".to_owned()))?
        .to_ascii_lowercase();

    // IPv6 literal URL hosts may enter the allowlist through auto-seeded
    // infrastructure endpoints. They still fail closed today because the
    // resolver is given the bracketed form, so IPv6 literal JWKS and endpoint
    // URLs remain unsupported for now.
    if allowed_hosts.contains(&host)
        || allowed_host_globs
            .iter()
            .any(|pattern| host_glob_matches(pattern, &host))
    {
        Ok(host)
    } else {
        tracing::warn!(
            error_category = "host_not_allowed",
            "egress blocked non-allowlisted host"
        );
        Err(EgressError::HostNotAllowed(host))
    }
}

fn legacy_checked_policy_port(port: u16, allowed_ports: &HashSet<u16>) -> Result<(), EgressError> {
    if allowed_ports.is_empty() || allowed_ports.contains(&port) {
        Ok(())
    } else {
        tracing::warn!(
            error_category = "port_not_allowed",
            "egress blocked non-allowlisted port"
        );
        Err(EgressError::PortNotAllowed(port))
    }
}

fn legacy_checked_socket_addr(
    host: &str,
    resolved: &[SocketAddr],
    deny_private_ips: bool,
    nat64_prefixes: &[IpNet],
    private_ip_allow_cidrs: &[IpNet],
) -> Result<SocketAddr, EgressError> {
    if resolved.is_empty() {
        return Err(EgressError::DnsResolutionFailed(host.to_owned()));
    }

    if deny_private_ips {
        if let Some(blocked) = resolved.iter().map(SocketAddr::ip).find(|ip| {
            is_non_global_ip(*ip, nat64_prefixes)
                && !ip_matches_policy_cidr(*ip, private_ip_allow_cidrs)
        }) {
            tracing::warn!(
                error_category = "non_global_ip_blocked",
                "egress blocked non-global resolved address outside policy CIDRs"
            );
            return Err(EgressError::NonGlobalIpBlocked(blocked));
        }
    }

    Ok(resolved[0])
}
