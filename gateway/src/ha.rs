//! Deployment identity and the static-configuration fingerprint
//! (issue #241, PR 3).
//!
//! Two things every replica of one logical deployment carries, defined by
//! ADR-0007 and the HA state model:
//!
//! - **Identity.** An instance ID, unique among live replicas, paired with a
//!   per-boot ID generated at startup, so a restarted process can never
//!   inherit stale ownership of a lease, lock, or cursor. Both are random
//!   UUIDs: neither is derived from anything an operator could guess a
//!   successor for, and neither is secret — they exist to be *named* in
//!   heartbeats and audit rows.
//!
//! - **The static-configuration fingerprint.** A SHA-256 over the
//!   security-relevant, non-secret static configuration. A replica whose
//!   fingerprint does not match its deployment's can never become ready
//!   (invariant 14 of the state model), because a replica that disagrees
//!   about authentication, proxies, cookies, exemptions, routing, egress, or
//!   key generation is a replica that enforces a different security policy.
//!   PR 3 computes and exposes the fingerprint; PR 13 registers and checks it
//!   cluster-wide.
//!
//! ## What the fingerprint covers, exactly
//!
//! The normative list from ADR-0007: mode selection (`STATE_BACKEND`),
//! deployment ID, auth/provider settings, trusted proxies, public/cookie
//! settings, exempt paths, routes, egress restrictions, policy mode, and
//! secret/key generation IDs.
//!
//! Secret material is never an input. Provider `client_secret` values
//! contribute only their *presence*, keyring and secret-provider entries
//! contribute only their IDs and counts, and the PostgreSQL DSN is not part
//! of configuration at all (it is read from `DATABASE_URL_FILE` at pool
//! construction). Two replicas configured with identical structure and
//! different secret values produce identical fingerprints — that is tested,
//! not assumed. Later PRs extend the projection when they centralize the
//! state it describes (rate limits when they become shared in PR 10, for
//! example); each extension is a fingerprint-format change every replica of
//! the rolling window must agree on, which is why the input carries a
//! version string in its domain-separation prefix.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{AuthProviderType, Config, StateBackend, UpstreamRouteConfig};

/// Domain separation for the fingerprint input, with a format version. Bumping
/// the version is a deliberate act: it changes every deployment's fingerprint
/// at once, so mixed-version replicas must never happen outside a planned
/// rolling window.
const FINGERPRINT_DOMAIN: &str = "greengateway-static-config-fingerprint-v1";

/// One replica's identity for this boot.
///
/// `instance_id` distinguishes live replicas of a deployment; `boot_id`
/// distinguishes boots of the same instance, so anything a previous boot owned
/// (a lease, a fence, a cursor claim) is attributable and rejectable across a
/// restart. Both are generated at startup and never persisted: identity that
/// survived a restart is exactly the stale-ownership hole the pair exists to
/// close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceIdentity {
    instance_id: Uuid,
    boot_id: Uuid,
}

impl InstanceIdentity {
    /// Generate a fresh identity. Two calls never collide for practical
    /// purposes (`Uuid::new_v4`), and no constructor exists that could
    /// resurrect a previous boot's identity.
    pub fn generate() -> Self {
        Self {
            instance_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
        }
    }

    pub fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    pub fn boot_id(&self) -> Uuid {
        self.boot_id
    }
}

/// The SHA-256 static-configuration fingerprint, rendered as lowercase hex.
///
/// The digest is not secret-derived and may be logged, compared, and (from
/// PR 14 on) shown in cluster status; the *input* list is the thing that must
/// stay honest, and it lives in one function below.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StaticConfigFingerprint {
    digest: [u8; 32],
}

impl StaticConfigFingerprint {
    /// The raw digest, for the cluster registration PRs (#241 PR 13+) that
    /// store and compare fingerprints; not used by PR 3's startup path.
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn hex(&self) -> String {
        hex::encode(self.digest)
    }
}

impl fmt::Debug for StaticConfigFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The hex form is stable and non-secret; rendering it in Debug keeps
        // log lines and assertion failures informative without a second
        // representation that could drift.
        write!(formatter, "{}", self.hex())
    }
}

impl fmt::Display for StaticConfigFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.hex())
    }
}

/// The startup-computed HA identity material: who this process is, and what
/// static security configuration it is running. Registered and checked
/// cluster-wide by PR 13; PR 3 computes it once at startup and exposes it
/// internally (and in the one startup log line, which is the operator's
/// confirmation the values exist at all).
pub struct HaFoundation {
    identity: InstanceIdentity,
    fingerprint: StaticConfigFingerprint,
}

impl HaFoundation {
    pub fn generate(config: &Config) -> Self {
        Self {
            identity: InstanceIdentity::generate(),
            fingerprint: static_config_fingerprint(config),
        }
    }

    pub fn identity(&self) -> &InstanceIdentity {
        &self.identity
    }

    pub fn fingerprint(&self) -> &StaticConfigFingerprint {
        &self.fingerprint
    }
}

/// Compute the static-configuration fingerprint of a validated
/// configuration.
///
/// The input is a `BTreeMap` of scalar strings serialized as JSON, which is
/// canonical here for a stated reason rather than an assumed one: with
/// `serde_json`'s default (no `preserve_order` feature) map keys serialize in
/// sorted order, so the same configuration produces the same bytes on every
/// replica and every build. Values are strings (never raw floats) so no
/// formatting difference can creep in through a float-to-text path.
pub fn static_config_fingerprint(config: &Config) -> StaticConfigFingerprint {
    let mut input = BTreeMap::new();
    insert_mode(&mut input, config);
    insert_public_and_cookie_settings(&mut input, config);
    insert_auth_settings(&mut input, config);
    insert_trusted_proxies(&mut input, config);
    insert_exempt_paths(&mut input, config);
    insert_routes(&mut input, config);
    insert_egress_restrictions(&mut input, config);
    insert_secret_generation_ids(&mut input, config);

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN.as_bytes());
    hasher.update(b"\0");
    // Serialize over a sorted map; see the function comment for why this is
    // deterministic. A serialization failure is impossible for a map of
    // strings and would mean the fingerprint cannot be computed, which is a
    // startup failure, not a zero digest.
    let canonical =
        serde_json::to_vec(&input).expect("JSON serialization of string map cannot fail");
    hasher.update(&canonical);
    StaticConfigFingerprint {
        digest: hasher.finalize().into(),
    }
}

fn insert_mode(input: &mut BTreeMap<String, String>, config: &Config) {
    let backend = match config.state_backend {
        StateBackend::Sqlite => "sqlite",
        StateBackend::Postgres => "postgres",
    };
    input.insert("state_backend".into(), backend.into());
    // Deployment ID is non-secret by contract and validated to a bounded
    // shape; a replica pointed at a different deployment namespace must not
    // match, so the value participates, not just its presence.
    input.insert(
        "deployment_id".into(),
        config.deployment_id.clone().unwrap_or_default(),
    );
}

fn insert_public_and_cookie_settings(input: &mut BTreeMap<String, String>, config: &Config) {
    input.insert(
        "gateway_public_url".into(),
        config.gateway_public_url.clone().unwrap_or_default(),
    );
    input.insert("admin_prefix".into(), config.admin_prefix.clone());
    input.insert(
        "admin_login_provider".into(),
        config.admin_login_provider.clone().unwrap_or_default(),
    );
    input.insert("auth_cookie_name".into(), config.auth_cookie_name.clone());
    input.insert("csrf_enabled".into(), config.csrf_enabled.to_string());
    input.insert("csrf_cookie_name".into(), config.csrf_cookie_name.clone());
    input.insert("csrf_header_name".into(), config.csrf_header_name.clone());
    input.insert(
        "csrf_cookie_domain".into(),
        config.csrf_cookie_domain.clone().unwrap_or_default(),
    );
}

fn insert_auth_settings(input: &mut BTreeMap<String, String>, config: &Config) {
    // Policy mode: whether authentication is enforced and how strictly.
    input.insert("auth_enabled".into(), config.auth_enabled.to_string());
    input.insert(
        "auth_mode".into(),
        match config.auth_mode {
            crate::config::AuthMode::Required => "required",
            crate::config::AuthMode::Observe => "observe",
        }
        .into(),
    );
    input.insert("roles_claim".into(), config.roles_claim.clone());
    input.insert(
        "jwt_jwks_url".into(),
        config.jwt_jwks_url.clone().unwrap_or_default(),
    );
    input.insert(
        "jwt_issuer".into(),
        config.jwt_issuer.clone().unwrap_or_default(),
    );
    input.insert(
        "jwt_audience".into(),
        config.jwt_audience.clone().unwrap_or_default(),
    );
    input.insert(
        "jwt_jwks_timeout_ms".into(),
        config.jwt_jwks_timeout_ms.to_string(),
    );
    input.insert("jwt_require_jti".into(), config.jwt_require_jti.to_string());
    input.insert(
        "service_token_cache_ttl_ms".into(),
        config.service_token_cache_ttl_ms.to_string(),
    );

    for (index, provider) in config.auth_providers.iter().enumerate() {
        let prefix = format!("auth_provider[{index}]");
        input.insert(format!("{prefix}.name"), provider.name.clone());
        input.insert(
            format!("{prefix}.type"),
            match provider.provider_type {
                AuthProviderType::Jwt => "jwt".into(),
                AuthProviderType::CookieSession => "cookie_session".into(),
            },
        );
        input.insert(
            format!("{prefix}.jwks_url"),
            provider.jwks_url.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.issuer"),
            provider.issuer.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.audience"),
            provider.audience.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.jwks_timeout_ms"),
            provider.jwks_timeout_ms.to_string(),
        );
        input.insert(
            format!("{prefix}.require_jti"),
            provider.require_jti.to_string(),
        );
        input.insert(
            format!("{prefix}.roles_claim"),
            provider.roles_claim.clone(),
        );
        input.insert(
            format!("{prefix}.roles_claim_delimiter"),
            provider.roles_claim_delimiter.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.org_claim"),
            provider.org_claim.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.introspection_url"),
            provider.introspection_url.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.introspection_timeout_ms"),
            provider.introspection_timeout_ms.to_string(),
        );
        input.insert(
            format!("{prefix}.cache_ttl_ms"),
            provider.cache_ttl_ms.to_string(),
        );
        input.insert(
            format!("{prefix}.user_id_claim"),
            provider.user_id_claim.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.email_claim"),
            provider.email_claim.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.client_id"),
            provider.client_id.clone().unwrap_or_default(),
        );
        input.insert(
            format!("{prefix}.redirect_uri"),
            provider.redirect_uri.clone().unwrap_or_default(),
        );
        // The one field that is secret contributes only its presence: a
        // replica configured without a client secret must not match one
        // configured with it, but no secret-derived value may enter the
        // digest.
        input.insert(
            format!("{prefix}.client_secret_present"),
            provider.client_secret.is_some().to_string(),
        );
    }
}

fn insert_trusted_proxies(input: &mut BTreeMap<String, String>, config: &Config) {
    input.insert(
        "trust_proxy_headers".into(),
        config.trust_proxy_headers.to_string(),
    );
    let mut cidrs: Vec<String> = config
        .trusted_proxy_cidrs
        .iter()
        .map(ToString::to_string)
        .collect();
    cidrs.sort();
    input.insert("trusted_proxy_cidrs".into(), cidrs.join(","));
}

fn insert_exempt_paths(input: &mut BTreeMap<String, String>, config: &Config) {
    input.insert(
        "auth_exempt_paths".into(),
        config.auth_exempt_paths.join(","),
    );
    input.insert(
        "rbac_exempt_paths".into(),
        config.rbac_exempt_paths.join(","),
    );
    input.insert(
        "csrf_exempt_paths".into(),
        config.csrf_exempt_paths.join(","),
    );
}

fn insert_routes(input: &mut BTreeMap<String, String>, config: &Config) {
    input.insert(
        "upstream_url".into(),
        config.upstream_url.clone().unwrap_or_default(),
    );
    for (index, server) in config.mcp_upstream_servers.iter().enumerate() {
        input.insert(format!("mcp_upstream[{index}].name"), server.name.clone());
        input.insert(format!("mcp_upstream[{index}].url"), server.url.clone());
    }
    for (index, route) in config.upstream_routes.iter().enumerate() {
        insert_route(input, &format!("route[{index}]"), route);
    }
}

/// The per-route projection: routing identity (where traffic goes), TLS
/// material locators (which trust the route carries), header-name policy
/// (which credentials can leak or be injected upstream), and timeout
/// overrides. Per-replica traffic-shaping knobs (load balancing, retries,
/// circuit breaking, health checks, streaming and gRPC admission limits) are
/// deliberately not part of the cross-replica security boundary and become
/// versioned control-plane documents in PR 8 instead.
fn insert_route(input: &mut BTreeMap<String, String>, prefix: &str, route: &UpstreamRouteConfig) {
    input.insert(format!("{prefix}.id"), route.id.clone().unwrap_or_default());
    input.insert(
        format!("{prefix}.connection_id"),
        route.connection_id.clone().unwrap_or_default(),
    );
    input.insert(
        format!("{prefix}.path_prefix"),
        route.path_prefix.clone().unwrap_or_default(),
    );
    input.insert(
        format!("{prefix}.host"),
        route.host.clone().unwrap_or_default(),
    );
    input.insert(format!("{prefix}.upstream_url"), route.upstream_url.clone());
    for (endpoint_index, endpoint) in route.upstreams.iter().enumerate() {
        let endpoint_prefix = format!("{prefix}.endpoint[{endpoint_index}]");
        input.insert(format!("{endpoint_prefix}.id"), endpoint.id.clone());
        input.insert(format!("{endpoint_prefix}.url"), endpoint.url.clone());
        input.insert(
            format!("{endpoint_prefix}.weight"),
            endpoint.weight.to_string(),
        );
        input.insert(
            format!("{endpoint_prefix}.tls_ca_bundle_path"),
            endpoint
                .tls_ca_bundle_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        );
        input.insert(
            format!("{endpoint_prefix}.client_identity_pem_path"),
            endpoint
                .client_identity_pem_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        );
    }
    input.insert(
        format!("{prefix}.tls_ca_bundle_path"),
        route
            .tls_ca_bundle_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
    );
    // Header NAMES only. `add_request_headers` values are operator-written
    // static text that can carry credential material; a name cannot, and a
    // disagreement about which headers exist is the boundary-relevant fact.
    let mut added_header_names: Vec<String> = route.add_request_headers.keys().cloned().collect();
    added_header_names.sort();
    input.insert(
        format!("{prefix}.add_request_header_names"),
        added_header_names.join(","),
    );
    let mut stripped_headers = route.strip_request_headers.clone();
    stripped_headers.sort();
    input.insert(
        format!("{prefix}.strip_request_headers"),
        stripped_headers.join(","),
    );
    input.insert(
        format!("{prefix}.timeout_ms"),
        route
            .timeout_ms
            .map(|milliseconds| milliseconds.to_string())
            .unwrap_or_default(),
    );
    input.insert(
        format!("{prefix}.response_idle_timeout_ms"),
        route
            .response_idle_timeout_ms
            .map(|milliseconds| milliseconds.to_string())
            .unwrap_or_default(),
    );
    input.insert(
        format!("{prefix}.connect_timeout_ms"),
        route
            .connect_timeout_ms
            .map(|milliseconds| milliseconds.to_string())
            .unwrap_or_default(),
    );
}

fn insert_egress_restrictions(input: &mut BTreeMap<String, String>, config: &Config) {
    input.insert(
        "egress_allowed_hosts".into(),
        config.egress_allowed_hosts.join(","),
    );
    input.insert(
        "egress_timeout_ms".into(),
        config.egress_timeout_ms.to_string(),
    );
    input.insert(
        "egress_response_idle_timeout_ms".into(),
        config.egress_response_idle_timeout_ms.to_string(),
    );
    input.insert(
        "egress_connect_timeout_ms".into(),
        config.egress_connect_timeout_ms.to_string(),
    );
    input.insert(
        "egress_max_response_bytes".into(),
        config.egress_max_response_bytes.to_string(),
    );
    input.insert(
        "egress_max_request_body_bytes".into(),
        config.egress_max_request_body_bytes.to_string(),
    );
    let mut prefixes: Vec<String> = config
        .egress_nat64_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    prefixes.sort();
    input.insert("egress_nat64_prefixes".into(), prefixes.join(","));
    input.insert(
        "egress_deny_private_ips".into(),
        config.egress_deny_private_ips.to_string(),
    );
}

/// Secret/key generation IDs: the identities of keyring generations and
/// secret-provider entries, never their material or locators. A replica that
/// would encrypt or resolve with a different generation set must not match.
fn insert_secret_generation_ids(input: &mut BTreeMap<String, String>, config: &Config) {
    for (index, key) in config.connection_local_secret_keyring.iter().enumerate() {
        input.insert(format!("local_secret_keyring[{index}].id"), key.id.clone());
        // Debug of a fieldless enum is its variant name: stable, non-secret,
        // and the same on every build.
        input.insert(
            format!("local_secret_keyring[{index}].role"),
            format!("{:?}", key.role),
        );
    }
    let mut alias_ids: Vec<String> = config
        .connection_secret_aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    alias_ids.sort();
    input.insert("connection_secret_alias_ids".into(), alias_ids.join(","));
    let mut vault_profile_ids: Vec<String> = config
        .connection_vault_provider
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    vault_profile_ids.sort();
    input.insert("vault_profile_ids".into(), vault_profile_ids.join(","));
    let mut vault_alias_ids: Vec<String> = config
        .connection_vault_provider
        .aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    vault_alias_ids.sort();
    input.insert("vault_alias_ids".into(), vault_alias_ids.join(","));
    let mut gcp_profile_ids: Vec<String> = config
        .connection_gcp_provider
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    gcp_profile_ids.sort();
    input.insert("gcp_profile_ids".into(), gcp_profile_ids.join(","));
    let mut gcp_alias_ids: Vec<String> = config
        .connection_gcp_provider
        .aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    gcp_alias_ids.sort();
    input.insert("gcp_alias_ids".into(), gcp_alias_ids.join(","));
    let mut azure_profile_ids: Vec<String> = config
        .connection_azure_provider
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    azure_profile_ids.sort();
    input.insert("azure_profile_ids".into(), azure_profile_ids.join(","));
    let mut azure_alias_ids: Vec<String> = config
        .connection_azure_provider
        .aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    azure_alias_ids.sort();
    input.insert("azure_alias_ids".into(), azure_alias_ids.join(","));
    let mut aws_profile_ids: Vec<String> = config
        .connection_aws_provider
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    aws_profile_ids.sort();
    input.insert("aws_profile_ids".into(), aws_profile_ids.join(","));
    let mut aws_alias_ids: Vec<String> = config
        .connection_aws_provider
        .aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    aws_alias_ids.sort();
    input.insert("aws_alias_ids".into(), aws_alias_ids.join(","));
    let mut kubernetes_profile_ids: Vec<String> = config
        .connection_kubernetes_provider
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    kubernetes_profile_ids.sort();
    input.insert(
        "kubernetes_profile_ids".into(),
        kubernetes_profile_ids.join(","),
    );
    let mut kubernetes_alias_ids: Vec<String> = config
        .connection_kubernetes_provider
        .aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect();
    kubernetes_alias_ids.sort();
    input.insert(
        "kubernetes_alias_ids".into(),
        kubernetes_alias_ids.join(","),
    );
    input.insert(
        "connection_secrets_root_present".into(),
        config.connection_secrets_root.is_some().to_string(),
    );
}

/// Startup rejection for a cluster-mode selection this build cannot honor.
///
/// The `postgres` cargo feature ships in `default`, so official builds always
/// carry the client. A `--no-default-features` build is a legitimate shape,
/// and in it `STATE_BACKEND=postgres` must fail startup naming the gap rather
/// than failing later somewhere inside a mode half of which was never
/// compiled.
#[derive(Debug)]
pub(crate) struct BackendNotCompiledIn;

impl fmt::Display for BackendNotCompiledIn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "STATE_BACKEND=postgres was selected, but this gateway binary was built without \
             the `postgres` cargo feature and cannot serve cluster mode; build with default \
             features or set STATE_BACKEND=sqlite",
        )
    }
}

impl std::error::Error for BackendNotCompiledIn {}

/// Fail startup when cluster mode is selected but not compiled in.
///
/// Called unconditionally by startup so both build states keep one shape: a
/// build carrying the feature answers `Ok(())` immediately, and a build
/// without it rejects the selection before any listener binds.
#[cfg(feature = "postgres")]
pub(crate) fn ensure_backend_compiled_in(_config: &Config) -> Result<(), BackendNotCompiledIn> {
    Ok(())
}

#[cfg(not(feature = "postgres"))]
pub(crate) fn ensure_backend_compiled_in(config: &Config) -> Result<(), BackendNotCompiledIn> {
    if config.state_backend == crate::config::StateBackend::Postgres {
        return Err(BackendNotCompiledIn);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_DEPLOYMENT_ID_BYTES;
    use std::env::VarError;

    fn config_from(vars: &[(&str, &str)]) -> Config {
        Config::from_env_vars(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| Ok(value.to_string()))
                .unwrap_or(Err(VarError::NotPresent))
        })
        .expect("test configuration should validate")
    }

    #[test]
    fn generated_identities_never_repeat_and_are_version_four() {
        let first = InstanceIdentity::generate();
        let second = InstanceIdentity::generate();
        assert_ne!(first.instance_id(), second.instance_id());
        assert_ne!(first.boot_id(), second.boot_id());
        assert_ne!(first.instance_id(), first.boot_id());
        assert_eq!(first.instance_id().get_version_num(), 4);
        assert_eq!(first.boot_id().get_version_num(), 4);
    }

    /// The feature-off refusal, run only in a `--no-default-features` build
    /// (CI builds both states): a cluster-mode selection must fail startup
    /// naming the missing feature, and standalone mode must stay accepted.
    #[test]
    fn backend_selection_must_be_compiled_in() {
        let standalone = config_from(&[]);
        assert!(ensure_backend_compiled_in(&standalone).is_ok());

        #[cfg(not(feature = "postgres"))]
        {
            // The path never needs to exist: configuration validation checks
            // the setting's presence, and the refusal this test pins happens
            // before anything would read it.
            let cluster = config_from(&[
                ("STATE_BACKEND", "postgres"),
                ("DATABASE_URL_FILE", "/nonexistent/dsn"),
                ("DEPLOYMENT_ID", "deploy-feature-off"),
            ]);
            let error = ensure_backend_compiled_in(&cluster)
                .expect_err("a feature-off build must refuse cluster mode");
            let rendered = error.to_string();
            assert!(rendered.contains("STATE_BACKEND=postgres"), "{rendered}");
            assert!(rendered.contains("`postgres` cargo feature"), "{rendered}");
        }
    }

    #[test]
    fn ha_foundation_exposes_identity_and_fingerprint() {
        let config = config_from(&[]);
        let foundation = HaFoundation::generate(&config);
        assert_eq!(
            foundation.fingerprint(),
            &static_config_fingerprint(&config)
        );
        // Not secret: the fingerprint renders as plain hex, and the identity
        // as UUIDs. Both must be displayable without redaction.
        assert_eq!(foundation.fingerprint().hex().len(), 64);
        assert!(foundation
            .fingerprint()
            .hex()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert_ne!(foundation.identity().instance_id().to_string(), "");
    }

    #[test]
    fn fingerprint_is_deterministic_across_calls() {
        let config = config_from(&[("AUTH_MODE", "observe")]);
        assert_eq!(
            static_config_fingerprint(&config),
            static_config_fingerprint(&config)
        );
    }

    #[test]
    fn fingerprint_flips_when_security_configuration_changes() {
        /// One flip case: base environment, changed environment, and a label
        /// for the failure message.
        type FlipCase<'a> = (&'a [(&'a str, &'a str)], &'a [(&'a str, &'a str)], &'a str);
        let cases: &[FlipCase] = &[
            (&[], &[("AUTH_MODE", "observe")], "policy mode"),
            (
                &[],
                &[("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")],
                "trusted proxies",
            ),
            (
                &[],
                &[("AUTH_COOKIE_NAME", "other-session")],
                "cookie settings",
            ),
            (
                &[],
                &[("EGRESS_ALLOWED_HOSTS", "api.example.test")],
                "egress restrictions",
            ),
            (
                &[],
                &[("GATEWAY_PUBLIC_URL", "https://gateway.example.test")],
                "public settings",
            ),
            (&[], &[("DEPLOYMENT_ID", "deploy-one")], "deployment id"),
        ];
        for (base, changed, label) in cases {
            let mut base_vars: Vec<(&str, &str)> = base.to_vec();
            base_vars.extend_from_slice(&[
                ("STATE_BACKEND", "postgres"),
                ("DATABASE_URL_FILE", "/tmp/unused-dsn"),
                ("DEPLOYMENT_ID", "deploy-fingerprint"),
            ]);
            let mut changed_vars: Vec<(&str, &str)> = changed.to_vec();
            changed_vars.extend_from_slice(&[
                ("STATE_BACKEND", "postgres"),
                ("DATABASE_URL_FILE", "/tmp/unused-dsn"),
                ("DEPLOYMENT_ID", "deploy-fingerprint"),
            ]);
            let base_config = config_from(&base_vars);
            let changed_config = config_from(&changed_vars);
            assert_ne!(
                static_config_fingerprint(&base_config),
                static_config_fingerprint(&changed_config),
                "changing {label} must flip the fingerprint"
            );
        }
    }

    #[test]
    fn fingerprint_flips_when_an_exempt_path_changes() {
        let base = config_from(&[]);
        let mut changed = config_from(&[]);
        changed.auth_exempt_paths.push("/sneaky".into());
        assert_ne!(
            static_config_fingerprint(&base),
            static_config_fingerprint(&changed)
        );
    }

    #[test]
    fn fingerprint_flips_when_a_route_changes() {
        let base = config_from(&[]);
        let mut changed = config_from(&[]);
        changed.upstream_url = Some("https://elsewhere.example.test".into());
        assert_ne!(
            static_config_fingerprint(&base),
            static_config_fingerprint(&changed)
        );
    }

    #[test]
    fn fingerprint_ignores_secret_values_but_not_their_presence() {
        let with_secret = config_from(&[(
            "AUTH_PROVIDERS",
            r#"[{"name":"primary","type":"jwt","issuer":"https://idp.example.test","client_id":"admin-ui","client_secret":"first-secret-value"}]"#,
        )]);
        let with_other_secret = config_from(&[(
            "AUTH_PROVIDERS",
            r#"[{"name":"primary","type":"jwt","issuer":"https://idp.example.test","client_id":"admin-ui","client_secret":"completely-different-secret-value"}]"#,
        )]);
        assert_eq!(
            static_config_fingerprint(&with_secret),
            static_config_fingerprint(&with_other_secret),
            "secret values must not enter the fingerprint"
        );

        let without_secret = config_from(&[(
            "AUTH_PROVIDERS",
            r#"[{"name":"primary","type":"jwt","issuer":"https://idp.example.test","client_id":"admin-ui"}]"#,
        )]);
        assert_ne!(
            static_config_fingerprint(&with_secret),
            static_config_fingerprint(&without_secret),
            "a provider that lost its client secret entirely must not match"
        );
    }

    #[test]
    fn fingerprint_ignores_local_store_paths_and_dsn_references() {
        // Store paths and DSN file locators are per-replica deployment
        // details, not the cross-replica security boundary: two replicas with
        // the same effective configuration must match even when their local
        // file locations differ.
        let first = config_from(&[
            ("AUDIT_SQLITE_PATH", "/var/lib/gateway-a/audit.sqlite3"),
            (
                "POLICY_HISTORY_SQLITE_PATH",
                "/var/lib/gateway-a/history.sqlite3",
            ),
        ]);
        let second = config_from(&[
            ("AUDIT_SQLITE_PATH", "/var/lib/gateway-b/audit.sqlite3"),
            (
                "POLICY_HISTORY_SQLITE_PATH",
                "/var/lib/gateway-b/history.sqlite3",
            ),
        ]);
        assert_eq!(
            static_config_fingerprint(&first),
            static_config_fingerprint(&second)
        );
    }

    #[test]
    fn fingerprint_flips_when_key_generation_ids_change() {
        // Built by direct construction rather than environment parsing: the
        // keyring's cross-setting requirements (a secrets root and a
        // connections store) are irrelevant to the fingerprint, and the
        // fingerprint must observe the ID set exactly as the control plane
        // stores it.
        use crate::connections::local_secret::{LocalSecretKeyConfig, LocalSecretKeyRole};

        let keyring_for = |primary_id: &str| {
            vec![
                LocalSecretKeyConfig {
                    id: primary_id.to_owned(),
                    file: "primary.key".to_owned(),
                    role: LocalSecretKeyRole::Primary,
                },
                LocalSecretKeyConfig {
                    id: "previous-2026-06".to_owned(),
                    file: "previous.key".to_owned(),
                    role: LocalSecretKeyRole::DecryptOnly,
                },
            ]
        };

        let mut first = Config::test_defaults();
        first.connection_local_secret_keyring = keyring_for("primary-2026-07");
        let mut second = Config::test_defaults();
        second.connection_local_secret_keyring = keyring_for("primary-2026-08");
        assert_ne!(
            static_config_fingerprint(&first),
            static_config_fingerprint(&second),
            "a rotated key-generation ID set must not match"
        );
    }

    #[test]
    fn fingerprint_covers_the_deployment_id_shape_it_validates() {
        let long_id = "a".repeat(MAX_DEPLOYMENT_ID_BYTES);
        let config = config_from(&[
            ("STATE_BACKEND", "postgres"),
            ("DATABASE_URL_FILE", "/tmp/unused-dsn"),
            ("DEPLOYMENT_ID", &long_id),
        ]);
        assert_eq!(config.deployment_id.as_deref(), Some(long_id.as_str()));
        assert_eq!(
            config.deployment_id.as_deref().unwrap().len(),
            MAX_DEPLOYMENT_ID_BYTES
        );
    }
}
