//! The gateway's runtime configuration (issue #433).
//!
//! The configuration compiler lives in `gateway_config::compiler` (issue
//! #242), where `ggctl` links it too. This module re-exports it at the paths
//! the gateway has always named its settings by, and keeps what only the
//! gateway does with a compiled plan: the process-environment reader,
//! [`Config`] and its conversion from a plan, which startup and the one-shot
//! commands build from.

use std::{
    env::{self, VarError},
    net::SocketAddr,
    path::PathBuf,
};

use gateway_config::compiler::{
    connections::ConnectionsPlan,
    egress::EgressPlan,
    identity::IdentityPlan,
    listeners::{ListenerPlan, TlsMaterial},
    proxy::ProxyPlan,
    runtime::RuntimePlan,
    storage::StoragePlan,
};
use ipnet::IpNet;

use crate::{
    connections::{
        aws_secret::AwsProviderConfig,
        azure_secret::AzureProviderConfig,
        gcp_secret::GcpProviderConfig,
        kubernetes_secret::KubernetesProviderConfig,
        local_secret::LocalSecretKeyConfig,
        secret::{OperatorSecretAliasConfig, SecretRootConfig},
        vault_secret::VaultProviderConfig,
    },
    discovery::{signals::SignalDetectorConfig, suggestions::RuleSuggestionConfig},
    inbound_tls::TlsMinVersion,
};

mod bundle;
#[cfg(test)]
mod environment_reads;
#[cfg(test)]
mod fingerprint_tests;
mod revisions;
mod semantic_diff;

/// The configuration compiler, its settings, defaults and bounds, and the
/// setting types it parses, at the paths the gateway names them by. Serving
/// startup calls `compile` directly and builds from the plan it returns
/// (`bootstrap::start_serving`); the one-shot commands reach it through
/// [`Config::from_env`].
pub use gateway_config::compiler::*;

/// The process environment as the configuration compiler reads it. Serving
/// startup and [`Config::from_env`] both read their configuration inputs
/// through this one reader.
pub(crate) fn process_environment(name: &str) -> Result<String, VarError> {
    env::var(name)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub admin_listen_addr: Option<SocketAddr>,
    /// Address of the opt-in gRPC listener.
    ///
    /// Unset means no HTTP/2 server is ever constructed. A third listener
    /// rather than a mode on the data listener, because `axum::serve` offers no
    /// way to configure the HTTP/2 builder it constructs internally -- so the
    /// bounds #257 requires would be unreachable -- and because with
    /// `ADMIN_LISTEN_ADDR` unset the admin API shares the data listener's
    /// socket, which would put h2c on the admin surface by default.
    pub grpc_listen_addr: Option<SocketAddr>,
    pub grpc_max_concurrent_streams: u32,
    pub grpc_max_metadata_bytes: u32,
    /// Certificate chains for the data listener, or `None` for plaintext.
    ///
    /// Each entry is one mounted certificate file; more than one turns on SNI
    /// selection, with the first entry the default for a client that names no
    /// recognisable server. Splitting happens in `Config::from_env`, so the
    /// count here always equals `tls_key_files`'s count.
    pub tls_cert_files: Option<Vec<String>>,
    /// Private keys for the data listener, positionally paired with
    /// [`Config::tls_cert_files`].
    pub tls_key_files: Option<Vec<String>>,
    /// Certificate chains for the admin listener, or `None` for plaintext.
    ///
    /// Independent of the data listener's chains on purpose: one chain per
    /// listener was the whole of #327, and this list is what makes SNI
    /// selection per-listener rather than process-wide.
    pub admin_tls_cert_files: Option<Vec<String>>,
    /// Private keys for the admin listener, positionally paired with
    /// [`Config::admin_tls_cert_files`].
    pub admin_tls_key_files: Option<Vec<String>>,
    pub tls_min_version: TlsMinVersion,
    pub tls_handshake_timeout_ms: u64,
    pub tls_max_concurrent_handshakes: usize,
    /// Inbound client-certificate authentication for the data listener, or
    /// `None` to request no certificate at all.
    ///
    /// Composed during parsing rather than stored as loose fields, so that
    /// "client certificates are on" and "there is a CA to verify them against"
    /// cannot disagree. A mode that could not be satisfied is a startup
    /// failure, never a `Some` with a hole in it.
    pub client_cert_auth: Option<InboundClientAuthConfig>,
    /// The same for the admin listener, configured independently.
    pub admin_client_cert_auth: Option<InboundClientAuthConfig>,
    pub admin_prefix: String,
    pub admin_login_provider: Option<String>,
    pub admin_session: Option<crate::auth::admin_session::AdminSessionConfig>,
    pub admin_login_pending_ttl_secs: u64,
    pub admin_login_pending_max_entries: usize,
    pub admin_login_pending_max_per_ip: usize,
    /// Cluster mode's keyring for sealing pending admin logins (issue #241,
    /// PR 9): the same key-file shape as the connections keyring, with files
    /// beneath `CONNECTION_SECRETS_ROOT`. Required in postgres mode when an
    /// admin login provider is set; rejected in standalone mode.
    pub admin_login_keyring: Vec<LocalSecretKeyConfig>,
    /// Keys the shared rate limiter's bucket digests are HMAC'd under in
    /// cluster mode (issue #241, PR 10): the same key-file shape as the
    /// connections keyring, with files beneath `CONNECTION_SECRETS_ROOT`.
    /// Required in postgres mode; rejected in standalone mode.
    pub rate_limit_keyring: Vec<LocalSecretKeyConfig>,
    pub gateway_public_url: Option<String>,
    pub audit_log_file: Option<String>,
    pub audit_sqlite_path: Option<String>,
    pub audit_sqlite_retention_days: Option<u32>,
    pub audit_successful_probes_metrics_only: bool,
    pub shutdown_drain_delay_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub audit_drain_timeout_ms: u64,
    /// Whether a request-path security decision must be durably recorded
    /// before the gateway acts on it (issue #425). See [`AuditDurability`].
    pub audit_durability: AuditDurability,
    /// How long a request may wait for its decision record to commit under
    /// [`AuditDurability::Required`] before it is refused.
    pub audit_durability_timeout_ms: u64,
    pub discovery_sqlite_path: Option<String>,
    pub discovery_endpoint_limit: usize,
    /// Cluster mode only (issue #241, PR 11): the discovery projector's
    /// leadership lease TTL, stream poll interval, and batch size. Parsed and
    /// validated in both modes so one pass reports every problem; standalone
    /// mode rejects them when set, since it never runs a projector.
    pub discovery_projector_lease_ttl_ms: u64,
    pub discovery_projector_poll_ms: u64,
    pub discovery_projector_batch: usize,
    pub principal_sqlite_path: Option<String>,
    pub connections_sqlite_path: Option<String>,
    pub connection_local_secret_keyring: Vec<LocalSecretKeyConfig>,
    pub connection_secret_aliases: Vec<OperatorSecretAliasConfig>,
    pub connection_vault_provider: VaultProviderConfig,
    pub connection_gcp_provider: GcpProviderConfig,
    pub connection_azure_provider: AzureProviderConfig,
    pub connection_aws_provider: AwsProviderConfig,
    pub connection_kubernetes_provider: KubernetesProviderConfig,
    pub connection_secrets_root: Option<SecretRootConfig>,
    pub payload_capture_enabled: bool,
    pub payload_capture_sample_rate: f64,
    pub schema_mismatch_signal_threshold: u64,
    pub error_rate_spike_signal_threshold: f64,
    pub principal_new_to_endpoint_signal_threshold: u64,
    pub volume_outlier_signal_threshold: f64,
    pub rule_suggestion_baseline_window_hours: u64,
    pub openapi_spec_path: Option<PathBuf>,
    pub policy_file: Option<String>,
    pub tools_file: Option<String>,
    pub policy_history_sqlite_path: Option<String>,
    pub cors_allow_origins: Vec<String>,
    pub max_body_size: usize,
    /// Longest request path admitted, in bytes; `414` beyond it. Bounded above
    /// by the policy kernel's own path bound (`request_bounds`), which is why
    /// the maximum is not an operator choice.
    pub max_request_path_bytes: usize,
    pub rate_limit_read_rps: f64,
    pub rate_limit_read_burst: u32,
    pub rate_limit_write_rps: f64,
    pub rate_limit_write_burst: u32,
    /// The hard ceiling on distinct tracked rate-limit keys, per limiter (the
    /// read lane, the write lane, and each policy rate-limit rule).
    ///
    /// One bucket is a fixed handful of bytes keyed by a 64-bit hash, so the
    /// ceiling bounds memory regardless of how long an attacker's identities
    /// are. Beyond the ceiling, second-chance eviction recycles idle buckets
    /// first; an evicted key's next request starts a fresh burst.
    pub rate_limit_max_buckets: usize,
    /// How long a bucket may sit idle before it is eviction-preferred, in
    /// milliseconds.
    pub rate_limit_bucket_ttl_ms: u64,
    pub trust_proxy_headers: bool,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub rbac_exempt_paths: Vec<String>,
    pub validation_allowed_content_types: Vec<String>,
    pub auth_enabled: bool,
    pub auth_mode: AuthMode,
    pub auth_cookie_name: String,
    pub auth_exempt_paths: Vec<String>,
    pub auth_providers: Vec<AuthProviderConfig>,
    pub jwt_jwks_url: Option<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_jwks_timeout_ms: u64,
    pub jwt_jwks_max_key_age_secs: u64,
    pub jwt_require_jti: bool,
    pub roles_claim: String,
    pub service_token_sqlite_path: Option<String>,
    pub service_token_cache_ttl_ms: u64,
    pub tool_runtime_queue_depth: usize,
    pub tool_runtime_global_concurrency: usize,
    pub tool_runtime_queue_timeout_ms: u64,
    pub tool_lease_ttl_ms: u64,
    /// Cluster membership heartbeat interval (issue #241, PR 13); cluster
    /// mode only, rejected in standalone mode.
    pub cluster_heartbeat_ms: u64,
    /// How old a member's heartbeat may be before the row is stale and
    /// the maintenance singleton sweeps it; cluster mode only.
    pub cluster_member_stale_ms: u64,
    /// How often the maintenance leader runs one bounded pass of the
    /// singleton jobs; cluster mode only.
    pub cluster_maintenance_interval_ms: u64,
    /// The maintenance lease's TTL on the database clock (renewed at a
    /// third of it); cluster mode only.
    pub cluster_maintenance_lease_ttl_ms: u64,
    /// How long `/readyz` reuses one authority observation (issue #241,
    /// PR 14); cluster mode only, rejected in standalone mode.
    pub readiness_probe_cache_ms: u64,
    /// Whether the cluster status API may report this replica's own
    /// hostname (issue #241, PR 14). Default `false`: everything else on
    /// that surface is a number, a UUID, or a value recognized against a
    /// fixed shape, so a hostname is the one piece of deployment topology
    /// an operator has to ask for. Honoured in both modes, because both
    /// serve `GET /v1{ADMIN_PREFIX}/cluster`.
    pub cluster_status_expose_hostnames: bool,
    /// PostgreSQL audit retention in days, pruned by the maintenance
    /// singleton; `None` (or `0`) keeps everything. Cluster mode only.
    pub audit_postgres_retention_days: Option<u32>,
    /// Authority-event delivery (issue #425, PR 3): the dispatcher's sink,
    /// the pseudonym key aliases, the journal's capacity and retention.
    /// Cluster mode only; every field is refused in standalone mode.
    pub authority_events: AuthorityEventSettings,
    pub tool_runtime_default_timeout_ms: u64,
    pub csrf_enabled: bool,
    pub csrf_cookie_name: String,
    pub csrf_header_name: String,
    pub csrf_cookie_domain: Option<String>,
    pub csrf_exempt_paths: Vec<String>,
    pub upstream_url: Option<String>,
    pub upstream_routes: Vec<UpstreamRouteConfig>,
    pub mcp_upstream_servers: Vec<McpUpstreamServerConfig>,
    pub upstream_timeout_ms: Option<u64>,
    pub upstream_response_idle_timeout_ms: Option<u64>,
    pub upstream_connect_timeout_ms: Option<u64>,
    pub egress_allowed_hosts: Vec<String>,
    pub egress_timeout_ms: u64,
    pub egress_response_idle_timeout_ms: u64,
    pub egress_connect_timeout_ms: u64,
    pub egress_max_response_bytes: usize,
    pub egress_max_request_body_bytes: usize,
    pub egress_nat64_prefixes: Vec<IpNet>,
    pub egress_deny_private_ips: bool,
    /// Which store owns shared mutable state (issue #241). `Sqlite` is the
    /// default standalone mode and behaves exactly as this configuration always
    /// has; `Postgres` selects the experimental cluster mode, whose
    /// requirements are validated here and whose pool is built at startup.
    ///
    /// Part of the security-relevant static-configuration fingerprint a
    /// cluster-mode replica must match to become ready: a replica that
    /// disagrees with its deployment about where authority lives must never
    /// serve (ADR-0007).
    pub state_backend: StateBackend,
    /// Stable, non-secret identifier scoping every authoritative row, lock, and
    /// lease of one logical deployment. Required (and validated) in
    /// PostgreSQL mode; unused in standalone mode.
    pub deployment_id: Option<String>,
    /// PostgreSQL connection and pool settings. Contains no secret material:
    /// the connection string itself is read from `DATABASE_URL_FILE` at pool
    /// construction and never enters this structure, so the derived `Debug` of
    /// `Config` cannot render a DSN, database user, host, or name.
    pub database: DatabaseSettings,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_vars(process_environment)
    }

    #[cfg(test)]
    pub(crate) fn test_defaults() -> Self {
        Self::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("the default test configuration should validate")
    }

    // pub(crate) so sibling modules' tests can build configurations from
    // environment maps without going through process environment mutation;
    // production reaches it only through `from_env`. Serving startup calls
    // `compile` itself, which is this function without the conversion.
    //
    // The configuration compiler (issue #433) reads every input block where
    // the legacy parser read it, parses and validates each block from those
    // values alone, and reports every problem in the order the legacy parser
    // reported them. A `Config` is built only from a plan no stage refused.
    pub(crate) fn from_env_vars(
        get_var: impl FnMut(&str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        compile(get_var).map(into_config)
    }

    pub fn signal_detector_config(&self) -> SignalDetectorConfig {
        SignalDetectorConfig {
            schema_mismatch_threshold: self.schema_mismatch_signal_threshold,
            error_rate_spike_threshold: self.error_rate_spike_signal_threshold,
            principal_new_to_endpoint_threshold: self.principal_new_to_endpoint_signal_threshold,
            volume_outlier_threshold: self.volume_outlier_signal_threshold,
        }
    }

    #[allow(dead_code)]
    pub fn rule_suggestion_config(&self) -> RuleSuggestionConfig {
        RuleSuggestionConfig {
            baseline_window_hours: self.rule_suggestion_baseline_window_hours,
        }
    }

    /// The bucket idle TTL as a duration, for the rate limiter's stores.
    /// The cluster-mode execution lease TTL (issue #241, PR 10).
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn tool_lease_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.tool_lease_ttl_ms)
    }

    /// The cluster-mode discovery projector's leadership lease TTL.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Read by cluster startup.
    pub fn discovery_projector_lease_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.discovery_projector_lease_ttl_ms)
    }

    /// How long the cluster-mode discovery projector waits on an empty
    /// audit stream before reading again.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Read by cluster startup.
    pub fn discovery_projector_poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.discovery_projector_poll_ms)
    }

    /// The cluster membership heartbeat interval (issue #241, PR 13).
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn cluster_heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cluster_heartbeat_ms)
    }

    /// How old a member's heartbeat may be before its row is stale.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn cluster_member_stale_window(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cluster_member_stale_ms)
    }

    /// How long `/readyz` reuses one authority observation (issue #241,
    /// PR 14).
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn readiness_probe_cache(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.readiness_probe_cache_ms)
    }

    /// How often the maintenance leader runs one pass (issue #241, PR 13).
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn cluster_maintenance_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cluster_maintenance_interval_ms)
    }

    /// The maintenance lease TTL on the database clock.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn cluster_maintenance_lease_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cluster_maintenance_lease_ttl_ms)
    }

    /// The PostgreSQL audit retention window, or `None` to keep everything.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // read by the cluster wiring only
    pub fn audit_postgres_retention(&self) -> Option<std::time::Duration> {
        self.audit_postgres_retention_days
            .filter(|days| *days > 0)
            .map(|days| std::time::Duration::from_secs(u64::from(days) * 86_400))
    }

    pub(crate) fn rate_limit_bucket_idle_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.rate_limit_bucket_ttl_ms)
    }

    /// Inbound TLS for the data listener, or `None` to leave it plaintext.
    pub(crate) fn data_inbound_tls(&self) -> Option<InboundTlsSettings<'_>> {
        Some(InboundTlsSettings {
            certificate_setting: TLS_CERT_FILE,
            certificate_files: self.tls_cert_files.as_deref()?,
            private_key_setting: TLS_KEY_FILE,
            private_key_files: self.tls_key_files.as_deref()?,
            min_version_setting: TLS_MIN_VERSION,
            min_version: self.tls_min_version,
            client_auth: self
                .client_cert_auth
                .as_ref()
                .map(InboundClientAuthConfig::settings),
        })
    }

    /// Inbound TLS for the admin listener, or `None` to leave it plaintext.
    ///
    /// Independent of [`Config::data_inbound_tls`] on purpose: the two
    /// listeners are frequently reached over different networks, and an
    /// operator who terminates TLS for one has not thereby said anything about
    /// the other.
    pub(crate) fn admin_inbound_tls(&self) -> Option<InboundTlsSettings<'_>> {
        Some(InboundTlsSettings {
            certificate_setting: ADMIN_TLS_CERT_FILE,
            certificate_files: self.admin_tls_cert_files.as_deref()?,
            private_key_setting: ADMIN_TLS_KEY_FILE,
            private_key_files: self.admin_tls_key_files.as_deref()?,
            min_version_setting: TLS_MIN_VERSION,
            min_version: self.tls_min_version,
            client_auth: self
                .admin_client_cert_auth
                .as_ref()
                .map(InboundClientAuthConfig::settings),
        })
    }

    /// Whether any listener authenticates callers by client certificate.
    ///
    /// The auth chain is process-wide while the listeners are configured
    /// independently, so the validator is wired in when *either* listener asks
    /// for certificates. A certificate identity can only exist on a connection
    /// whose listener requested one, so this cannot make certificate auth
    /// reachable on a listener that did not.
    pub(crate) fn client_certificate_auth_enabled(&self) -> bool {
        self.client_cert_auth.is_some() || self.admin_client_cert_auth.is_some()
    }
}

/// One listener's inbound TLS material, paired with the setting names that
/// produced it.
///
/// The names travel with the values so a load failure can tell an operator
/// which variable to fix without the loader having to know whether it is
/// serving the data or the admin listener. The two lists are positionally
/// paired and equal in length -- an invariant `Config::from_env` enforces
/// before this type is ever built, which is why the loader may zip them
/// without a runtime count check.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InboundTlsSettings<'a> {
    pub(crate) certificate_setting: &'static str,
    pub(crate) certificate_files: &'a [String],
    pub(crate) private_key_setting: &'static str,
    pub(crate) private_key_files: &'a [String],
    pub(crate) min_version_setting: &'static str,
    pub(crate) min_version: TlsMinVersion,
    /// Client-certificate authentication for this listener, or `None` to
    /// request no certificate.
    pub(crate) client_auth: Option<InboundClientAuthSettings<'a>>,
}

/// The `Config` a compiled plan describes: the same values, with the
/// locators handed over as the paths startup opens. Serving startup converts
/// the plan once, before its first stage that does I/O.
///
/// Every domain plan is destructured field by field, so a setting the
/// compiler adds does not build until it is carried here.
pub(crate) fn into_config(plan: ConfigPlan) -> Config {
    let ConfigPlan {
        listeners,
        identity,
        proxy,
        storage,
        connections,
        egress,
        runtime,
    } = plan;
    let ListenerPlan {
        listen_addr,
        admin_listen_addr,
        grpc_listen_addr,
        grpc_max_concurrent_streams,
        grpc_max_metadata_bytes,
        data_tls,
        admin_tls,
        tls_min_version,
        tls_handshake_timeout_ms,
        tls_max_concurrent_handshakes,
        client_cert_auth,
        admin_client_cert_auth,
        provenance: _,
    } = listeners;
    let (tls_cert_files, tls_key_files) = data_tls.map(TlsMaterial::into_files).unzip();
    let (admin_tls_cert_files, admin_tls_key_files) =
        admin_tls.map(TlsMaterial::into_files).unzip();
    let IdentityPlan {
        admin_prefix,
        admin_login_provider,
        admin_session,
        admin_login_pending_ttl_secs,
        admin_login_pending_max_entries,
        admin_login_pending_max_per_ip,
        gateway_public_url,
        rbac_exempt_paths,
        auth_enabled,
        auth_mode,
        auth_cookie_name,
        auth_exempt_paths,
        auth_providers,
        jwt_jwks_url,
        jwt_issuer,
        jwt_audience,
        jwt_jwks_timeout_ms,
        jwt_jwks_max_key_age_secs,
        jwt_require_jti,
        roles_claim,
        service_token_sqlite_path,
        service_token_cache_ttl_ms,
        csrf_enabled,
        csrf_cookie_name,
        csrf_header_name,
        csrf_cookie_domain,
        csrf_exempt_paths,
        provenance: _,
    } = identity;
    let ProxyPlan {
        trust_proxy_headers,
        trusted_proxy_cidrs,
        upstream_url,
        upstream_routes,
        mcp_upstream_servers,
        upstream_timeout_ms,
        upstream_response_idle_timeout_ms,
        upstream_connect_timeout_ms,
        provenance: _,
    } = proxy;
    let StoragePlan {
        audit_log_file,
        audit_sqlite_path,
        audit_sqlite_retention_days,
        audit_successful_probes_metrics_only,
        discovery_sqlite_path,
        discovery_endpoint_limit,
        discovery_projector_lease_ttl_ms,
        discovery_projector_poll_ms,
        discovery_projector_batch,
        principal_sqlite_path,
        openapi_spec_path,
        policy_file,
        tools_file,
        policy_history_sqlite_path,
        tool_lease_ttl_ms,
        cluster_heartbeat_ms,
        cluster_member_stale_ms,
        cluster_maintenance_interval_ms,
        cluster_maintenance_lease_ttl_ms,
        readiness_probe_cache_ms,
        cluster_status_expose_hostnames,
        audit_postgres_retention_days,
        state_backend,
        deployment_id,
        database,
        authority_events,
        provenance: _,
    } = storage;
    let ConnectionsPlan {
        connections_sqlite_path,
        connection_secrets_root,
        connection_secret_aliases,
        connection_local_secret_keyring,
        admin_login_keyring,
        rate_limit_keyring,
        connection_vault_provider,
        connection_gcp_provider,
        connection_azure_provider,
        connection_aws_provider,
        connection_kubernetes_provider,
        provenance: _,
    } = connections;
    let EgressPlan {
        egress_allowed_hosts,
        egress_timeout_ms,
        egress_response_idle_timeout_ms,
        egress_connect_timeout_ms,
        egress_max_response_bytes,
        egress_max_request_body_bytes,
        egress_nat64_prefixes,
        egress_deny_private_ips,
        provenance: _,
    } = egress;
    let RuntimePlan {
        shutdown_drain_delay_ms,
        shutdown_timeout_ms,
        audit_drain_timeout_ms,
        audit_durability,
        audit_durability_timeout_ms,
        payload_capture_enabled,
        payload_capture_sample_rate,
        schema_mismatch_signal_threshold,
        error_rate_spike_signal_threshold,
        principal_new_to_endpoint_signal_threshold,
        volume_outlier_signal_threshold,
        rule_suggestion_baseline_window_hours,
        cors_allow_origins,
        max_body_size,
        max_request_path_bytes,
        rate_limit_read_rps,
        rate_limit_read_burst,
        rate_limit_write_rps,
        rate_limit_write_burst,
        rate_limit_max_buckets,
        rate_limit_bucket_ttl_ms,
        validation_allowed_content_types,
        tool_runtime_queue_depth,
        tool_runtime_global_concurrency,
        tool_runtime_queue_timeout_ms,
        tool_runtime_default_timeout_ms,
        provenance: _,
    } = runtime;

    Config {
        listen_addr,
        admin_listen_addr,
        grpc_listen_addr,
        grpc_max_concurrent_streams,
        grpc_max_metadata_bytes,
        tls_cert_files,
        tls_key_files,
        admin_tls_cert_files,
        admin_tls_key_files,
        tls_min_version,
        tls_handshake_timeout_ms,
        tls_max_concurrent_handshakes,
        client_cert_auth,
        admin_client_cert_auth,
        admin_prefix,
        admin_login_provider,
        admin_session,
        admin_login_pending_ttl_secs,
        admin_login_pending_max_entries,
        admin_login_pending_max_per_ip,
        admin_login_keyring,
        rate_limit_keyring,
        gateway_public_url,
        audit_log_file,
        audit_sqlite_path,
        audit_sqlite_retention_days,
        audit_successful_probes_metrics_only,
        shutdown_drain_delay_ms,
        shutdown_timeout_ms,
        audit_drain_timeout_ms,
        audit_durability,
        audit_durability_timeout_ms,
        discovery_sqlite_path,
        discovery_endpoint_limit,
        discovery_projector_lease_ttl_ms,
        discovery_projector_poll_ms,
        discovery_projector_batch,
        principal_sqlite_path,
        connections_sqlite_path,
        connection_local_secret_keyring,
        connection_vault_provider,
        connection_gcp_provider,
        connection_azure_provider,
        connection_aws_provider,
        connection_kubernetes_provider,
        connection_secret_aliases,
        connection_secrets_root,
        payload_capture_enabled,
        payload_capture_sample_rate,
        schema_mismatch_signal_threshold,
        error_rate_spike_signal_threshold,
        principal_new_to_endpoint_signal_threshold,
        volume_outlier_signal_threshold,
        rule_suggestion_baseline_window_hours,
        openapi_spec_path,
        policy_file,
        tools_file,
        policy_history_sqlite_path,
        cors_allow_origins,
        max_body_size,
        max_request_path_bytes,
        rate_limit_read_rps,
        rate_limit_read_burst,
        rate_limit_write_rps,
        rate_limit_write_burst,
        rate_limit_max_buckets,
        rate_limit_bucket_ttl_ms,
        trust_proxy_headers,
        trusted_proxy_cidrs,
        rbac_exempt_paths,
        validation_allowed_content_types,
        auth_enabled,
        auth_mode,
        auth_cookie_name,
        auth_exempt_paths,
        auth_providers,
        jwt_jwks_url,
        jwt_issuer,
        jwt_audience,
        jwt_jwks_timeout_ms,
        jwt_jwks_max_key_age_secs,
        jwt_require_jti,
        roles_claim,
        service_token_sqlite_path,
        service_token_cache_ttl_ms,
        tool_runtime_queue_depth,
        tool_runtime_global_concurrency,
        tool_runtime_queue_timeout_ms,
        tool_lease_ttl_ms,
        cluster_heartbeat_ms,
        cluster_member_stale_ms,
        cluster_maintenance_interval_ms,
        cluster_maintenance_lease_ttl_ms,
        readiness_probe_cache_ms,
        cluster_status_expose_hostnames,
        audit_postgres_retention_days,
        authority_events,
        tool_runtime_default_timeout_ms,
        csrf_enabled,
        csrf_cookie_name,
        csrf_header_name,
        csrf_cookie_domain,
        csrf_exempt_paths,
        upstream_url,
        upstream_routes,
        mcp_upstream_servers,
        upstream_timeout_ms,
        upstream_response_idle_timeout_ms,
        upstream_connect_timeout_ms,
        egress_allowed_hosts,
        egress_timeout_ms,
        egress_response_idle_timeout_ms,
        egress_connect_timeout_ms,
        egress_max_response_bytes,
        egress_max_request_body_bytes,
        egress_nat64_prefixes,
        egress_deny_private_ips,
        state_backend,
        deployment_id,
        database: database.into_settings(),
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
