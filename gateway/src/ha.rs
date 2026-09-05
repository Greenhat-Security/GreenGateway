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
//! settings, exempt paths, routes, egress restrictions, rate limits, policy mode, and
//! secret/key generation IDs.
//!
//! Secret material is never an input. Provider `client_secret` values
//! contribute only their *presence*, keyring and secret-provider entries
//! contribute only their IDs and counts, and the PostgreSQL DSN is not part
//! of configuration at all (it is read from `DATABASE_URL_FILE` at pool
//! construction). Two replicas configured with identical structure and
//! different secret values produce identical fingerprints — that is tested,
//! not assumed. The rate-limit projection includes both global lanes,
//! bucket bounds, and the sorted key-generation IDs and roles. Each
//! extension is a fingerprint-format change every replica of
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
const FINGERPRINT_DOMAIN: &str = "greengateway-static-config-fingerprint-v2";

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

/// The cluster-wide readiness gate a replica's `/readyz` consults in
/// addition to its own lifecycle phase (issue #241, PR 13).
///
/// A replica starts *not agreed*: until it has read the deployment's live
/// membership and found every live, non-draining member carrying its own
/// fingerprint, it answers `503` with reason `config_fingerprint_mismatch`
/// (HA state model invariant 14). Agreement is sticky. Once a replica has
/// been admitted it keeps serving even if a later, mismatched replica
/// boots: the gate is on *joining*, so a bad rollout is held at the door
/// rather than allowed to take the already-serving replicas out of
/// rotation with it. The replica does not exit while disagreeing, so a
/// rolling change can finish and the gate re-evaluates on every
/// heartbeat.
///
/// Standalone mode has no membership and never constructs one; a `None`
/// gate in the app state is "always agreed".
///
/// From PR 14 the gate is also where the heartbeat's own health is
/// carried: the readiness probe (`ha_status.rs`) needs to know when this
/// replica's roster row last landed, and the heartbeat task already owns
/// the gate. Nothing else about the roster is kept here — the probe asks
/// the authority for the rest.
#[derive(Debug)]
pub struct ClusterReadiness {
    fingerprint_agreed: std::sync::atomic::AtomicBool,
    /// When the membership heartbeat last wrote this replica's row.
    /// Seeded at construction, which is a truthful starting point: the
    /// boot row is written before the heartbeat task starts, and a boot
    /// row that cannot be written fails startup.
    last_heartbeat_success: std::sync::Mutex<std::time::Instant>,
}

impl Default for ClusterReadiness {
    fn default() -> Self {
        Self {
            fingerprint_agreed: std::sync::atomic::AtomicBool::new(false),
            last_heartbeat_success: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }
}

impl ClusterReadiness {
    /// The readiness reason a mismatched replica reports.
    pub const FINGERPRINT_MISMATCH: &'static str = "config_fingerprint_mismatch";

    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // constructed by the cluster wiring only
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    pub fn fingerprint_agreed(&self) -> bool {
        self.fingerprint_agreed
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Record that every live member agrees with this replica. One-way.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // called by the membership heartbeat only
    pub fn record_fingerprint_agreement(&self) {
        self.fingerprint_agreed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Why this gate refuses readiness, or `None` when it does not.
    pub fn blocked_reason(&self) -> Option<&'static str> {
        (!self.fingerprint_agreed()).then_some(Self::FINGERPRINT_MISMATCH)
    }

    /// Record that the membership heartbeat wrote this replica's roster
    /// row (issue #241, PR 14). Called by the heartbeat task on every
    /// successful write; a failed write records nothing, so the age
    /// below simply keeps growing until one lands.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // called by the membership heartbeat only
    pub fn record_heartbeat_success(&self) {
        *self
            .last_heartbeat_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = std::time::Instant::now();
    }

    /// How long ago the membership heartbeat last landed. The readiness
    /// probe compares this with the stale window: once it exceeds the
    /// window the deployment's roster has stopped counting this replica
    /// as live, whatever the replica itself believes.
    pub fn heartbeat_age(&self) -> std::time::Duration {
        let last = *self
            .last_heartbeat_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::time::Instant::now().saturating_duration_since(last)
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
    insert_inbound_client_certificate_authentication(&mut input, config);
    insert_trusted_proxies(&mut input, config);
    insert_exempt_paths(&mut input, config);
    insert_routes(&mut input, config);
    insert_egress_restrictions(&mut input, config);
    insert_rate_limit_settings(&mut input, config);
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

fn insert_rate_limit_settings(input: &mut BTreeMap<String, String>, config: &Config) {
    // Rates are validated finite and non-negative at startup. IEEE-754 bits
    // preserve every effective value without depending on float formatting;
    // positive and negative zero have identical limiter semantics.
    let rate_bits = |rate: f64| {
        let rate = if rate == 0.0 { 0.0 } else { rate };
        format!("{:016x}", rate.to_bits())
    };
    for (name, value) in [
        ("rate_limit_read_rps", rate_bits(config.rate_limit_read_rps)),
        (
            "rate_limit_read_burst",
            config.rate_limit_read_burst.to_string(),
        ),
        (
            "rate_limit_write_rps",
            rate_bits(config.rate_limit_write_rps),
        ),
        (
            "rate_limit_write_burst",
            config.rate_limit_write_burst.to_string(),
        ),
        (
            "rate_limit_max_buckets",
            config.rate_limit_max_buckets.to_string(),
        ),
        (
            "rate_limit_bucket_ttl_ms",
            config.rate_limit_bucket_ttl_ms.to_string(),
        ),
    ] {
        input.insert(name.into(), value);
    }

    // Order and file locations are deployment details. The generation set
    // and primary/decrypt-only roles determine which bucket namespace is
    // used, so partial rotations must not report agreement. Never read key
    // files or include secret-derived values in this public fingerprint.
    let mut generations: Vec<_> = config.rate_limit_keyring.iter().collect();
    generations.sort_by(|a, b| a.id.cmp(&b.id));
    input.insert(
        "rate_limit_keyring.count".into(),
        generations.len().to_string(),
    );
    for (index, key) in generations.into_iter().enumerate() {
        input.insert(format!("rate_limit_keyring[{index}].id"), key.id.clone());
        let role = match key.role {
            crate::connections::local_secret::LocalSecretKeyRole::Primary => "primary",
            crate::connections::local_secret::LocalSecretKeyRole::DecryptOnly => "decrypt_only",
        };
        input.insert(format!("rate_limit_keyring[{index}].role"), role.into());
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
    // Cluster mode's pending-login store is shared, so its limits must be
    // one set across replicas.
    input.insert(
        "admin_login_pending_ttl_secs".into(),
        config.admin_login_pending_ttl_secs.to_string(),
    );
    input.insert(
        "admin_login_pending_max_entries".into(),
        config.admin_login_pending_max_entries.to_string(),
    );
    input.insert(
        "admin_login_pending_max_per_ip".into(),
        config.admin_login_pending_max_per_ip.to_string(),
    );
    input.insert("auth_cookie_name".into(), config.auth_cookie_name.clone());
    input.insert("csrf_enabled".into(), config.csrf_enabled.to_string());
    input.insert("csrf_cookie_name".into(), config.csrf_cookie_name.clone());
    input.insert("csrf_header_name".into(), config.csrf_header_name.clone());
    input.insert(
        "csrf_cookie_domain".into(),
        config.csrf_cookie_domain.clone().unwrap_or_default(),
    );
    let mut cors_origins = config.cors_allow_origins.clone();
    cors_origins.sort();
    input.insert("cors_allow_origins".into(), cors_origins.join(","));
    let mut allowed_content_types = config.validation_allowed_content_types.clone();
    allowed_content_types.sort();
    input.insert(
        "validation_allowed_content_types".into(),
        allowed_content_types.join(","),
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
    input.insert(
        "jwt_jwks_max_key_age_secs".into(),
        config.jwt_jwks_max_key_age_secs.to_string(),
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
            format!("{prefix}.jwks_max_key_age_secs"),
            provider.jwks_max_key_age_secs.to_string(),
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

/// Inbound client-certificate authentication, per listener: which callers
/// authenticate with a certificate at all, against which trust anchors, with
/// which revocation list and identity extraction. A replica requiring client
/// certificates and one that requests none enforce different authentication
/// policies and must never match. The settings carry public locators and
/// enum shapes only -- no certificate material.
fn insert_inbound_client_certificate_authentication(
    input: &mut BTreeMap<String, String>,
    config: &Config,
) {
    let mut insert_listener =
        |label: &'static str, settings: &Option<crate::config::InboundClientAuthConfig>| {
            let Some(settings) = settings else {
                input.insert(format!("{label}.client_cert_mode"), "off".into());
                return;
            };
            input.insert(
                format!("{label}.client_cert_mode"),
                settings.mode_setting.into(),
            );
            input.insert(
                format!("{label}.client_cert_requirement"),
                format!("{:?}", settings.requirement),
            );
            input.insert(
                format!("{label}.client_cert_ca_file"),
                settings.ca_file.clone(),
            );
            input.insert(
                format!("{label}.client_cert_crl_file"),
                settings.crl_file.clone().unwrap_or_default(),
            );
            input.insert(
                format!("{label}.client_cert_identity_source"),
                format!("{:?}", settings.identity_source),
            );
        };
    insert_listener("data_listener", &config.client_cert_auth);
    insert_listener("admin_listener", &config.admin_client_cert_auth);
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
    for (index, key) in config.admin_login_keyring.iter().enumerate() {
        input.insert(format!("admin_login_keyring[{index}].id"), key.id.clone());
        input.insert(
            format!("admin_login_keyring[{index}].role"),
            format!("{:?}", key.role),
        );
    }
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
        // Postgres mode requires the rate-limit keyring (PR 10); a test that
        // selects the mode without setting one gets the static default so
        // the fingerprint tests keep exercising what they are about.
        let postgres = vars
            .iter()
            .any(|(key, value)| *key == "STATE_BACKEND" && *value == "postgres");
        Config::from_env_vars(|name| {
            if let Some((_, value)) = vars.iter().find(|(key, _)| *key == name) {
                return Ok(value.to_string());
            }
            if postgres {
                match name {
                    "CONNECTION_SECRETS_ROOT" => return Ok("/run/secrets/greengateway".to_owned()),
                    "RATE_LIMIT_KEYRING" => {
                        return Ok(
                            r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#
                                .to_owned(),
                        )
                    }
                    _ => {}
                }
            }
            Err(VarError::NotPresent)
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
    fn fingerprint_covers_every_static_rate_limit_setting() {
        let base = config_from(&[]);
        for (name, value) in [
            ("RATE_LIMIT_READ_RPS", "1.25"),
            ("RATE_LIMIT_READ_BURST", "7"),
            ("RATE_LIMIT_WRITE_RPS", "2.5"),
            ("RATE_LIMIT_WRITE_BURST", "9"),
            ("RATE_LIMIT_MAX_BUCKETS", "1234"),
            ("RATE_LIMIT_BUCKET_TTL_MS", "2345"),
        ] {
            let changed = config_from(&[(name, value)]);
            assert_ne!(
                static_config_fingerprint(&base),
                static_config_fingerprint(&changed),
                "{name} must participate in agreement"
            );
        }
        let mut adjacent = base.clone();
        adjacent.rate_limit_read_rps = f64::from_bits(base.rate_limit_read_rps.to_bits() + 1);
        assert_ne!(
            static_config_fingerprint(&base),
            static_config_fingerprint(&adjacent),
            "distinct finite rates must not be rounded into agreement"
        );
    }

    #[test]
    fn fingerprint_normalizes_equivalent_rate_representations() {
        for (first, second) in [("0", "-0"), ("100", "1e2"), ("1.250", "1.25")] {
            let first = config_from(&[
                ("RATE_LIMIT_READ_RPS", first),
                ("RATE_LIMIT_WRITE_RPS", first),
            ]);
            let second = config_from(&[
                ("RATE_LIMIT_READ_RPS", second),
                ("RATE_LIMIT_WRITE_RPS", second),
            ]);
            assert_eq!(
                static_config_fingerprint(&first),
                static_config_fingerprint(&second)
            );
        }
    }

    #[test]
    fn fingerprint_covers_rate_limit_generations_and_roles_but_not_order_or_paths() {
        use crate::connections::local_secret::{LocalSecretKeyConfig, LocalSecretKeyRole};
        let mut base = Config::test_defaults();
        base.rate_limit_keyring = vec![
            LocalSecretKeyConfig {
                id: "generation-a".into(),
                file: "replica-a/primary.key".into(),
                role: LocalSecretKeyRole::Primary,
            },
            LocalSecretKeyConfig {
                id: "generation-b".into(),
                file: "replica-a/previous.key".into(),
                role: LocalSecretKeyRole::DecryptOnly,
            },
        ];
        let fingerprint = static_config_fingerprint(&base);
        let mut reordered = base.clone();
        reordered.rate_limit_keyring.reverse();
        for key in &mut reordered.rate_limit_keyring {
            key.file = format!("replica-b/{}.key", key.id);
        }
        assert_eq!(fingerprint, static_config_fingerprint(&reordered));

        let mut renamed = base.clone();
        renamed.rate_limit_keyring[0].id = "generation-c".into();
        let mut predecessor_changed = base.clone();
        predecessor_changed.rate_limit_keyring[1].id = "generation-d".into();
        let mut promoted = base.clone();
        promoted.rate_limit_keyring[0].role = LocalSecretKeyRole::DecryptOnly;
        promoted.rate_limit_keyring[1].role = LocalSecretKeyRole::Primary;
        let mut removed = base.clone();
        removed.rate_limit_keyring.pop();
        let mut added = base.clone();
        added.rate_limit_keyring.push(LocalSecretKeyConfig {
            id: "generation-e".into(),
            file: "extra.key".into(),
            role: LocalSecretKeyRole::DecryptOnly,
        });
        for changed in [renamed, predecessor_changed, promoted, removed, added] {
            assert_ne!(
                fingerprint,
                static_config_fingerprint(&changed),
                "generation membership and roles must participate in agreement"
            );
        }
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

    /// Client-certificate authentication is an authentication policy: two
    /// replicas, one requiring certificates and one not, must never match.
    /// Added after an adversarial review found these settings missing from
    /// the input list.
    #[test]
    fn fingerprint_flips_when_client_certificate_authentication_changes() {
        for mode in ["required", "optional"] {
            let base = config_from(&[]);
            let with_client_certs = config_from(&[
                ("CLIENT_CERT_MODE", mode),
                ("CLIENT_CERT_CA_FILE", "/run/tls/client-ca.crt"),
                ("CLIENT_CERT_IDENTITY_SOURCE", "spiffe"),
                // A mode requires a TLS listener to serve on; give it one
                // with inert placeholder paths the config validator accepts.
                ("TLS_CERT_FILE", "cert.pem"),
                ("TLS_KEY_FILE", "key.pem"),
            ]);
            assert_ne!(
                static_config_fingerprint(&base),
                static_config_fingerprint(&with_client_certs),
                "a listener requiring client certificates must not match one that does not"
            );
        }
    }

    /// CORS origins and the validated content-type allowlist are boundary
    /// policies a replica pair must agree on; they were missing from the
    /// input list until the same review.
    #[test]
    fn fingerprint_flips_when_boundary_policies_change() {
        let base = config_from(&[]);
        let with_cors = config_from(&[("CORS_ALLOW_ORIGINS", "https://app.example.test")]);
        assert_ne!(
            static_config_fingerprint(&base),
            static_config_fingerprint(&with_cors),
            "different CORS origins must not match"
        );

        let with_content_types = config_from(&[(
            "VALIDATION_ALLOWED_CONTENT_TYPES",
            "application/json,text/plain",
        )]);
        assert_ne!(
            static_config_fingerprint(&base),
            static_config_fingerprint(&with_content_types),
            "different content-type validation must not match"
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
