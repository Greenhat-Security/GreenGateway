use std::{
    collections::{HashMap, HashSet},
    env::{self, VarError},
    error::Error,
    fmt,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::LazyLock,
};

use http::{header, HeaderName, HeaderValue};
use ipnet::IpNet;
use serde::Deserialize;

use crate::{
    auth::principal::{canonical_issuer, provider_issuer, PROVIDER_ISSUER_PREFIX},
    auth::ClientCertIdentitySource,
    connections::{
        aws_secret::{
            validate_aws_provider_config, AwsProviderConfig, MAX_AWS_PROVIDER_CONFIG_BYTES,
        },
        azure_secret::{
            validate_azure_provider_config, AzureProviderConfig, MAX_AZURE_PROVIDER_CONFIG_BYTES,
        },
        gcp_secret::{
            validate_gcp_provider_config, GcpProviderConfig, MAX_GCP_PROVIDER_CONFIG_BYTES,
        },
        kubernetes_secret::{
            validate_kubernetes_provider_config, KubernetesProviderConfig,
            MAX_KUBERNETES_PROVIDER_CONFIG_BYTES,
        },
        local_secret::{
            validate_local_secret_keyring_config, LocalSecretKeyConfig,
            MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES,
        },
        secret::{
            validate_operator_secret_alias_config, OperatorSecretAliasConfig, SecretRootConfig,
            MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES,
        },
        vault_secret::{
            validate_vault_provider_config, VaultProviderConfig, MAX_VAULT_PROVIDER_CONFIG_BYTES,
        },
    },
    discovery::{
        signals::{
            SignalDetectorConfig, DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        },
        suggestions::{
            RuleSuggestionConfig, DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        },
    },
    inbound_tls::{ClientCertMode, ClientCertRequirement, TlsMinVersion},
    upstream_route,
};

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
static DEFAULT_LISTEN_SOCKET_ADDR: LazyLock<SocketAddr> = LazyLock::new(|| {
    DEFAULT_LISTEN_ADDR
        .parse()
        .expect("default listen address should be valid")
});
static WELL_KNOWN_NAT64_PREFIX: LazyLock<IpNet> = LazyLock::new(|| {
    "64:ff9b::/96"
        .parse()
        .expect("well-known NAT64 prefix should be valid")
});
const DEFAULT_MAX_BODY_SIZE: usize = 1_048_576;
const DEFAULT_RATE_LIMIT_READ_RPS: f64 = 50.0;
const DEFAULT_RATE_LIMIT_READ_BURST: u32 = 100;
const DEFAULT_RATE_LIMIT_WRITE_RPS: f64 = 10.0;
const DEFAULT_RATE_LIMIT_WRITE_BURST: u32 = 20;
pub const DEFAULT_RATE_LIMIT_MAX_BUCKETS: usize = 65_536;
pub const DEFAULT_RATE_LIMIT_BUCKET_TTL_MS: u64 = 600_000;
const DEFAULT_VALIDATION_ALLOWED_CONTENT_TYPES: &[&str] = &["application/json"];
const DEFAULT_AUTH_ENABLED: bool = true;
pub const DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE: f64 = 0.10;
pub const DEFAULT_DISCOVERY_ENDPOINT_LIMIT: usize = 10_000;
pub const DEFAULT_SHUTDOWN_DRAIN_DELAY_MS: u64 = 1_000;
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_AUDIT_DRAIN_TIMEOUT_MS: u64 = 5_000;
const MAX_SHUTDOWN_DRAIN_DELAY_MS: u64 = 30_000;
const MAX_SHUTDOWN_TIMEOUT_MS: u64 = 300_000;
const MAX_AUDIT_DRAIN_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_AUTH_MODE: AuthMode = AuthMode::Required;
const DEFAULT_AUTH_COOKIE_NAME: &str = "session";
pub const DEFAULT_ADMIN_PREFIX: &str = "/admin";
pub const DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS: u64 = 300;
pub const DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES: usize = 1_024;
pub const DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP: usize = 16;
const DEFAULT_EXEMPT_PROBE_PATHS: &[&str] = &[
    "/health",
    "/livez",
    "/startupz",
    "/readyz",
    "/version",
    "/metrics",
];
const DEFAULT_JWT_JWKS_TIMEOUT_MS: u64 = 2000;
/// Five minutes: the longest a cached signing key is trusted before it must
/// be re-fetched (issue #241, PR 9). Matches what the validator hard-coded
/// before it became an operator setting.
pub const DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS: u64 = 300;
const DEFAULT_ROLES_CLAIM: &str = "roles";
pub const DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS: u64 = 2000;
pub const DEFAULT_COOKIE_SESSION_CACHE_TTL_MS: u64 = DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS;
pub const DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS: u64 = 5_000;
pub const DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH: usize = 1_024;
pub const DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY: usize = 64;
pub const DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS: u64 = 1_000;
/// How long a cluster-mode execution lease lives on the database clock
/// before an unrenewed slot is reclaimable (issue #241, PR 10). Renewed at
/// a third of this, so the floor keeps renewal from becoming a busy loop.
pub const DEFAULT_TOOL_LEASE_TTL_MS: u64 = 15_000;
pub const MIN_TOOL_LEASE_TTL_MS: u64 = 1_000;
pub const DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// TLS 1.2 rather than 1.3, because raising a floor is an operator decision
/// with a compatibility cost attached, and a default that silently refuses a
/// working client on upgrade is the kind of change this project would rather
/// make explicit. `docs/configuration.md` recommends `1.3` where clients allow.
pub const DEFAULT_TLS_MIN_VERSION: TlsMinVersion = TlsMinVersion::Tls12;
/// Long enough for a hand-rolled client on a slow link, short enough that a
/// client which never sends a ClientHello cannot hold an admission slot for a
/// meaningful fraction of a minute. It also sets how long a saturated listener
/// keeps refusing, since that is when the oldest slot comes back.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// The ceiling on TLS handshakes running at once, applied per listener.
///
/// Handshakes are the expensive, attacker-triggerable half of accepting a
/// connection, so this is what stops a flood of half-open connections from
/// becoming unbounded work. It does not bound accepts: a listener at the
/// ceiling keeps accepting and closes what it cannot admit, because a stalled
/// accept is worse than a refused connection. Sized well above any plausible
/// legitimate burst so that reaching it is a signal rather than a routine
/// event.
pub const DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES: usize = 256;
const DEFAULT_CSRF_ENABLED: bool = true;
const DEFAULT_CSRF_COOKIE_NAME: &str = "csrf_token";
const DEFAULT_CSRF_HEADER_NAME: &str = "x-csrf-token";
const DEFAULT_CSRF_EXEMPT_PATHS: &[&str] = &[
    "/health",
    "/livez",
    "/startupz",
    "/readyz",
    "/version",
    "/metrics",
];
const DEFAULT_EGRESS_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_EGRESS_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_EGRESS_MAX_RESPONSE_BYTES: usize = 5_242_880;
const DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const DEFAULT_EGRESS_DENY_PRIVATE_IPS: bool = true;
// Shared-state backend selection and PostgreSQL foundation settings
// (issue #241, PR 3). Defaults keep standalone mode exactly as it was: SQLite
// and process-local stores, with no database configured.
pub const DEFAULT_DATABASE_POOL_MAX: usize = 10;
pub const MAX_DATABASE_POOL_MAX: usize = 256;
pub const DEFAULT_DATABASE_CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_DATABASE_LOCK_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_DATABASE_STARTUP_RETRY_LIMIT: u64 = 5;
pub const MAX_DATABASE_STARTUP_RETRY_LIMIT: u64 = 300;
// Migration settings (issue #241, PR 4). The statement timeout for
// migrations is its own bound, deliberately wider than a request-path
// statement's: real DDL takes longer than a lookup, and it is still finite.
pub const DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS: u64 = 60_000;
pub const MAX_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS: u64 = 600_000;

/// Default ceiling on concurrently open HTTP/2 streams per gRPC connection.
///
/// Half of hyper's own default of 200. One accepted TCP connection becomes this
/// many concurrent in-flight calls, so it is the single most load-bearing
/// inbound bound the gateway has, and it exists at all only because the gRPC
/// listener is served by `hyper::server::conn::http2::Builder` directly --
/// `axum::serve` exposes no builder and would run on hyper's default with no
/// way to change it.
pub const DEFAULT_GRPC_MAX_CONCURRENT_STREAMS: u32 = 100;
pub const MAX_GRPC_MAX_CONCURRENT_STREAMS: u32 = 10_000;
/// Default ceiling on the decoded size of one request's metadata.
///
/// Matches hyper's own `max_header_list_size` default. Raised by deployments
/// whose callers carry large bearer tokens in metadata.
pub const DEFAULT_GRPC_MAX_METADATA_BYTES: u32 = 16_384;
pub const MIN_GRPC_MAX_METADATA_BYTES: u32 = 1_024;
pub const MAX_GRPC_MAX_METADATA_BYTES: u32 = 1_048_576;
const ADMIN_LISTEN_ADDR: &str = "ADMIN_LISTEN_ADDR";
const GRPC_LISTEN_ADDR: &str = "GRPC_LISTEN_ADDR";
const GRPC_MAX_CONCURRENT_STREAMS: &str = "GRPC_MAX_CONCURRENT_STREAMS";
const GRPC_MAX_METADATA_BYTES: &str = "GRPC_MAX_METADATA_BYTES";
const ADMIN_LOGIN_PROVIDER: &str = "ADMIN_LOGIN_PROVIDER";
const ADMIN_LOGIN_PENDING_TTL_SECS: &str = "ADMIN_LOGIN_PENDING_TTL_SECS";
const ADMIN_LOGIN_PENDING_MAX_ENTRIES: &str = "ADMIN_LOGIN_PENDING_MAX_ENTRIES";
const ADMIN_LOGIN_PENDING_MAX_PER_IP: &str = "ADMIN_LOGIN_PENDING_MAX_PER_IP";
const ADMIN_PREFIX: &str = "ADMIN_PREFIX";
const ADMIN_CLIENT_CERT_CA_FILE: &str = "ADMIN_CLIENT_CERT_CA_FILE";
const ADMIN_CLIENT_CERT_CRL_FILE: &str = "ADMIN_CLIENT_CERT_CRL_FILE";
const ADMIN_CLIENT_CERT_MODE: &str = "ADMIN_CLIENT_CERT_MODE";
const ADMIN_TLS_CERT_FILE: &str = "ADMIN_TLS_CERT_FILE";
const ADMIN_TLS_KEY_FILE: &str = "ADMIN_TLS_KEY_FILE";
const AUDIT_LOG_FILE: &str = "AUDIT_LOG_FILE";
const AUDIT_SQLITE_PATH: &str = "AUDIT_SQLITE_PATH";
const AUDIT_SQLITE_RETENTION_DAYS: &str = "AUDIT_SQLITE_RETENTION_DAYS";
const AUDIT_DRAIN_TIMEOUT_MS: &str = "AUDIT_DRAIN_TIMEOUT_MS";
const AUTH_COOKIE_NAME: &str = "AUTH_COOKIE_NAME";
const AUTH_ENABLED: &str = "AUTH_ENABLED";
const AUTH_EXEMPT_PATHS: &str = "AUTH_EXEMPT_PATHS";
const AUTH_MODE: &str = "AUTH_MODE";
const AUTH_PROVIDERS: &str = "AUTH_PROVIDERS";
const CORS_ALLOW_ORIGINS: &str = "CORS_ALLOW_ORIGINS";
const CSRF_COOKIE_DOMAIN: &str = "CSRF_COOKIE_DOMAIN";
const CSRF_COOKIE_NAME: &str = "CSRF_COOKIE_NAME";
const CSRF_ENABLED: &str = "CSRF_ENABLED";
const CSRF_EXEMPT_PATHS: &str = "CSRF_EXEMPT_PATHS";
const CSRF_HEADER_NAME: &str = "CSRF_HEADER_NAME";
const CONNECTIONS_SQLITE_PATH: &str = "CONNECTIONS_SQLITE_PATH";
const CONNECTION_AZURE_PROVIDER: &str = "CONNECTION_AZURE_PROVIDER";
const CONNECTION_GCP_PROVIDER: &str = "CONNECTION_GCP_PROVIDER";
const CONNECTION_AWS_PROVIDER: &str = "CONNECTION_AWS_PROVIDER";
const CONNECTION_KUBERNETES_PROVIDER: &str = "CONNECTION_KUBERNETES_PROVIDER";
const CONNECTION_LOCAL_SECRET_KEYRING: &str = "CONNECTION_LOCAL_SECRET_KEYRING";
const ADMIN_LOGIN_KEYRING: &str = "ADMIN_LOGIN_KEYRING";
const RATE_LIMIT_KEYRING: &str = "RATE_LIMIT_KEYRING";
const CONNECTION_SECRET_ALIASES: &str = "CONNECTION_SECRET_ALIASES";
const CONNECTION_VAULT_PROVIDER: &str = "CONNECTION_VAULT_PROVIDER";
const CONNECTION_SECRETS_ROOT: &str = "CONNECTION_SECRETS_ROOT";
const DATABASE_ACQUIRE_TIMEOUT_MS: &str = "DATABASE_ACQUIRE_TIMEOUT_MS";
const DATABASE_AUTO_MIGRATE: &str = "DATABASE_AUTO_MIGRATE";
const DATABASE_CONNECT_TIMEOUT_MS: &str = "DATABASE_CONNECT_TIMEOUT_MS";
const DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS: &str = "DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS";
const DATABASE_LOCK_TIMEOUT_MS: &str = "DATABASE_LOCK_TIMEOUT_MS";
const DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS: &str = "DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS";
const DATABASE_POOL_MAX: &str = "DATABASE_POOL_MAX";
const DATABASE_STARTUP_RETRY_LIMIT: &str = "DATABASE_STARTUP_RETRY_LIMIT";
const DATABASE_STATEMENT_TIMEOUT_MS: &str = "DATABASE_STATEMENT_TIMEOUT_MS";
const DATABASE_TLS_CA_FILE: &str = "DATABASE_TLS_CA_FILE";
const DATABASE_TLS_MODE: &str = "DATABASE_TLS_MODE";
const DATABASE_URL_FILE: &str = "DATABASE_URL_FILE";
const DEPLOYMENT_ID: &str = "DEPLOYMENT_ID";
const STATE_BACKEND: &str = "STATE_BACKEND";
const DISCOVERY_SQLITE_PATH: &str = "DISCOVERY_SQLITE_PATH";
const DISCOVERY_ENDPOINT_LIMIT: &str = "DISCOVERY_ENDPOINT_LIMIT";
const ERROR_RATE_SPIKE_SIGNAL_THRESHOLD: &str = "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD";
const EGRESS_ALLOWED_HOSTS: &str = "EGRESS_ALLOWED_HOSTS";
const EGRESS_CONNECT_TIMEOUT_MS: &str = "EGRESS_CONNECT_TIMEOUT_MS";
const EGRESS_DENY_PRIVATE_IPS: &str = "EGRESS_DENY_PRIVATE_IPS";
const EGRESS_MAX_REQUEST_BODY_BYTES: &str = "EGRESS_MAX_REQUEST_BODY_BYTES";
const EGRESS_MAX_RESPONSE_BYTES: &str = "EGRESS_MAX_RESPONSE_BYTES";
const EGRESS_NAT64_PREFIXES: &str = "EGRESS_NAT64_PREFIXES";
const EGRESS_RESPONSE_IDLE_TIMEOUT_MS: &str = "EGRESS_RESPONSE_IDLE_TIMEOUT_MS";
const EGRESS_TIMEOUT_MS: &str = "EGRESS_TIMEOUT_MS";
const GATEWAY_PUBLIC_URL: &str = "GATEWAY_PUBLIC_URL";
const JWT_AUDIENCE: &str = "JWT_AUDIENCE";
const JWT_ISSUER: &str = "JWT_ISSUER";
const JWT_JWKS_TIMEOUT_MS: &str = "JWT_JWKS_TIMEOUT_MS";
const JWT_JWKS_MAX_KEY_AGE_SECS: &str = "JWT_JWKS_MAX_KEY_AGE_SECS";
const JWT_JWKS_URL: &str = "JWT_JWKS_URL";
const JWT_REQUIRE_JTI: &str = "JWT_REQUIRE_JTI";
const MAX_BODY_SIZE: &str = "MAX_BODY_SIZE";
const MCP_UPSTREAM_SERVERS: &str = "MCP_UPSTREAM_SERVERS";
const OPENAPI_SPEC_PATH: &str = "OPENAPI_SPEC_PATH";
const PAYLOAD_CAPTURE_ENABLED: &str = "PAYLOAD_CAPTURE_ENABLED";
const PAYLOAD_CAPTURE_SAMPLE_RATE: &str = "PAYLOAD_CAPTURE_SAMPLE_RATE";
const POLICY_FILE: &str = "POLICY_FILE";
const POLICY_HISTORY_SQLITE_PATH: &str = "POLICY_HISTORY_SQLITE_PATH";
const PRINCIPAL_SQLITE_PATH: &str = "PRINCIPAL_SQLITE_PATH";
const PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD: &str =
    "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD";
const RBAC_EXEMPT_PATHS: &str = "RBAC_EXEMPT_PATHS";
const RULE_SUGGESTION_BASELINE_WINDOW_HOURS: &str = "RULE_SUGGESTION_BASELINE_WINDOW_HOURS";
const RATE_LIMIT_READ_RPS: &str = "RATE_LIMIT_READ_RPS";
const RATE_LIMIT_READ_BURST: &str = "RATE_LIMIT_READ_BURST";
const RATE_LIMIT_WRITE_RPS: &str = "RATE_LIMIT_WRITE_RPS";
const RATE_LIMIT_WRITE_BURST: &str = "RATE_LIMIT_WRITE_BURST";
const RATE_LIMIT_MAX_BUCKETS: &str = "RATE_LIMIT_MAX_BUCKETS";
const RATE_LIMIT_BUCKET_TTL_MS: &str = "RATE_LIMIT_BUCKET_TTL_MS";
const ROLES_CLAIM: &str = "ROLES_CLAIM";
const SERVICE_TOKEN_CACHE_TTL_MS: &str = "SERVICE_TOKEN_CACHE_TTL_MS";
const SERVICE_TOKEN_SQLITE_PATH: &str = "SERVICE_TOKEN_SQLITE_PATH";
const SCHEMA_MISMATCH_SIGNAL_THRESHOLD: &str = "SCHEMA_MISMATCH_SIGNAL_THRESHOLD";
const SHUTDOWN_DRAIN_DELAY_MS: &str = "SHUTDOWN_DRAIN_DELAY_MS";
const SHUTDOWN_TIMEOUT_MS: &str = "SHUTDOWN_TIMEOUT_MS";
const TOOL_RUNTIME_DEFAULT_TIMEOUT_MS: &str = "TOOL_RUNTIME_DEFAULT_TIMEOUT_MS";
const TOOL_RUNTIME_GLOBAL_CONCURRENCY: &str = "TOOL_RUNTIME_GLOBAL_CONCURRENCY";
const TOOL_RUNTIME_QUEUE_DEPTH: &str = "TOOL_RUNTIME_QUEUE_DEPTH";
const TOOL_RUNTIME_QUEUE_TIMEOUT_MS: &str = "TOOL_RUNTIME_QUEUE_TIMEOUT_MS";
const TOOL_LEASE_TTL_MS: &str = "TOOL_LEASE_TTL_MS";
const TOOLS_FILE: &str = "TOOLS_FILE";
const CLIENT_CERT_CA_FILE: &str = "CLIENT_CERT_CA_FILE";
const CLIENT_CERT_CRL_FILE: &str = "CLIENT_CERT_CRL_FILE";
const CLIENT_CERT_IDENTITY_SOURCE: &str = "CLIENT_CERT_IDENTITY_SOURCE";
const CLIENT_CERT_MODE: &str = "CLIENT_CERT_MODE";
const TLS_CERT_FILE: &str = "TLS_CERT_FILE";
const TLS_HANDSHAKE_TIMEOUT_MS: &str = "TLS_HANDSHAKE_TIMEOUT_MS";
const TLS_KEY_FILE: &str = "TLS_KEY_FILE";
const TLS_MAX_CONCURRENT_HANDSHAKES: &str = "TLS_MAX_CONCURRENT_HANDSHAKES";
const TLS_MIN_VERSION: &str = "TLS_MIN_VERSION";
const TRUST_PROXY_HEADERS: &str = "TRUST_PROXY_HEADERS";
const TRUSTED_PROXY_CIDRS: &str = "TRUSTED_PROXY_CIDRS";
const UPSTREAM_CONNECT_TIMEOUT_MS: &str = "UPSTREAM_CONNECT_TIMEOUT_MS";
const UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS: &str = "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS";
const UPSTREAM_ROUTES: &str = "UPSTREAM_ROUTES";
const UPSTREAM_TIMEOUT_MS: &str = "UPSTREAM_TIMEOUT_MS";
const UPSTREAM_URL: &str = "UPSTREAM_URL";
const VALIDATION_ALLOWED_CONTENT_TYPES: &str = "VALIDATION_ALLOWED_CONTENT_TYPES";
const VOLUME_OUTLIER_SIGNAL_THRESHOLD: &str = "VOLUME_OUTLIER_SIGNAL_THRESHOLD";
const REQUEST_ID_HEADER: &str = "x-request-id";

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
    pub shutdown_drain_delay_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub audit_drain_timeout_ms: u64,
    pub discovery_sqlite_path: Option<String>,
    pub discovery_endpoint_limit: usize,
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

/// Which store owns shared mutable state (issue #241, ADR-0007).
///
/// Mode is a startup-time, statically-validated setting and is deliberately
/// not hot-swappable: it is part of the static-configuration fingerprint, so a
/// replica that disagrees with its deployment about where authority lives can
/// never become ready.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StateBackend {
    /// One gateway process with local files, local SQLite, and process-local
    /// enforcement. The default, and today's behavior unchanged.
    #[default]
    Sqlite,
    /// Two or more replicas behind a load balancer with one PostgreSQL primary
    /// as the single authority for shared mutable state. Experimental and not
    /// a supported HA configuration until the #241 release gate lands; the
    /// foundation this mode needs (backend selection, redacted configuration,
    /// identity, verified-TLS pool, fingerprint) is what PR 3 introduces.
    Postgres,
}

impl FromStr for StateBackend {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            _ => Err("expected 'sqlite' or 'postgres'"),
        }
    }
}

/// TLS policy for PostgreSQL connections (issue #241 PR 3).
///
/// The default requires TLS with certificate and hostname verification. The
/// one exception is named for what it is: `loopback-dev` skips TLS entirely and
/// is refused for any database target that is not loopback or a Unix socket,
/// so the exception cannot quietly become a production plaintext connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DatabaseTlsMode {
    /// TLS is required: the handshake must succeed and the server certificate
    /// is verified (chain and hostname) against the platform trust store plus
    /// the optional `DATABASE_TLS_CA_FILE` bundle. A server that will not
    /// speak TLS fails the connection rather than falling back.
    #[default]
    Verify,
    /// Documented development exception: no TLS, and only when the database
    /// target is a loopback address, the name `localhost`, or a Unix socket.
    /// Selecting this mode with any other target fails startup naming the
    /// setting.
    LoopbackDev,
}

impl FromStr for DatabaseTlsMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "verify" => Ok(Self::Verify),
            "loopback-dev" => Ok(Self::LoopbackDev),
            _ => Err("expected 'verify' or 'loopback-dev'"),
        }
    }
}

/// PostgreSQL pool and timeout settings (issue #241 PR 3).
///
/// Every field is operator-configurable with a validated bound, because an
/// unbounded statement, lock wait, or idle-in-transaction session is exactly
/// the resource-exhaustion shape the blocking budgets in
/// `docs/architecture/ha-state-model.md` forbid. No field carries secret
/// material: the DSN lives in `DATABASE_URL_FILE` and is read at pool
/// construction, never here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseSettings {
    /// Per-replica pool ceiling. The documented connection math is
    /// `replicas x DATABASE_POOL_MAX + migrator/leader headroom` against the
    /// server's `max_connections`.
    pub pool_max: usize,
    /// Bound on establishing one new connection.
    pub connect_timeout_ms: u64,
    /// Bound on checking a connection out of the pool.
    pub acquire_timeout_ms: u64,
    /// Server-side `statement_timeout` applied to every pooled session.
    pub statement_timeout_ms: u64,
    /// Server-side `idle_in_transaction_session_timeout` applied to every
    /// pooled session.
    pub idle_in_transaction_timeout_ms: u64,
    /// Server-side `lock_timeout` applied to every pooled session.
    pub lock_timeout_ms: u64,
    /// Bounded startup policy: retries after the first connect attempt before
    /// startup fails (see `docs/configuration.md`).
    pub startup_retry_limit: u64,
    /// Development-only auto-migration: when true, a serving process in
    /// cluster mode applies pending migrations at startup, exactly as
    /// `gateway migrate up` would. Production pods validate only -- the
    /// default -- with migrations owned by a separate job and DDL role.
    pub auto_migrate: bool,
    /// Bound, in milliseconds, on each statement and lock wait inside a
    /// migration transaction. Applied with `SET LOCAL`, so it never leaks
    /// into pooled sessions.
    pub migration_statement_timeout_ms: u64,
    /// TLS policy; see [`DatabaseTlsMode`].
    pub tls_mode: DatabaseTlsMode,
    /// Optional PEM bundle of extra trust anchors for server-certificate
    /// verification, layered on top of the platform trust store exactly as
    /// egress TLS layers a configured CA. Public material.
    pub tls_ca_file: Option<String>,
    /// Path to the file containing the PostgreSQL connection string. The file
    /// is read at pool construction through a bounded, permission-checked
    /// reader and its contents never enter configuration, logs, or errors.
    pub url_file: Option<String>,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            pool_max: DEFAULT_DATABASE_POOL_MAX,
            connect_timeout_ms: DEFAULT_DATABASE_CONNECT_TIMEOUT_MS,
            acquire_timeout_ms: DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS,
            statement_timeout_ms: DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS,
            idle_in_transaction_timeout_ms: DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
            lock_timeout_ms: DEFAULT_DATABASE_LOCK_TIMEOUT_MS,
            startup_retry_limit: DEFAULT_DATABASE_STARTUP_RETRY_LIMIT,
            auto_migrate: false,
            migration_statement_timeout_ms: DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
            tls_mode: DatabaseTlsMode::default(),
            tls_ca_file: None,
            url_file: None,
        }
    }
}

/// The longest `DEPLOYMENT_ID` accepted: long enough for any real name, short
/// enough that identifiers built from it stay bounded in database keys,
/// lock namespaces, and notifications.
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 64;

/// Validate `DEPLOYMENT_ID` in the modes where it is read.
///
/// The ID is non-secret and appears in logs and status by design, which is
/// exactly why its shape is pinned: a deployment identifier that can carry
/// arbitrary bytes would turn every place it is rendered into a place an
/// operator's terminal or log pipeline could be attacked from, and one that
/// can be empty or unbounded would break the "stable, unique, named" contract
/// every row, lock, and lease relies on.
fn validate_deployment_id(
    name: &str,
    value: Option<String>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = value?;
    let bytes = value.as_bytes();
    let valid_shape = (1..=MAX_DEPLOYMENT_ID_BYTES).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid_shape {
        Some(value)
    } else {
        problems.push(format!(
            "{name} must be 1 to {MAX_DEPLOYMENT_ID_BYTES} bytes of ASCII letters, digits, '.', '_', or '-', starting and ending with a letter or digit"
        ));
        None
    }
}

/// Reject authoritative writable local stores when PostgreSQL is selected.
///
/// In cluster mode PostgreSQL is the single authority (ADR-0007): a local
/// `POLICY_FILE`, `TOOLS_FILE`, or `*_SQLITE_PATH` next to it is not a harmless
/// leftover but a second authority a replica could fall back to, which is the
/// stale-allow shape the whole mode exists to prevent. Files may return later
/// as explicit import/bootstrap inputs; until that workflow exists, any such
/// setting fails startup naming itself.
fn reject_local_authority_in_postgres_mode(
    state_backend: StateBackend,
    deployment_id: Option<&str>,
    database_url_file: Option<&str>,
    local_authority_settings: &[(&str, bool)],
    problems: &mut Vec<String>,
) {
    if state_backend != StateBackend::Postgres {
        return;
    }

    if deployment_id.is_none() {
        problems.push(format!(
            "{DEPLOYMENT_ID} is required when {STATE_BACKEND}=postgres; it scopes every authoritative row, lock, lease, and notification of the deployment and is non-secret"
        ));
    }
    if database_url_file.is_none() {
        problems.push(format!(
            "{DATABASE_URL_FILE} is required when {STATE_BACKEND}=postgres; the PostgreSQL connection string is supplied as a secret file, never as a raw environment variable"
        ));
    }
    for (setting, set) in local_authority_settings {
        if *set {
            problems.push(format!(
                "{setting} is set while {STATE_BACKEND}=postgres; in cluster mode PostgreSQL is the single authority and local stores are rejected (import/bootstrap workflows arrive in a later #241 PR) — unset {setting}"
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpUpstreamServerConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub response_idle_timeout_ms: Option<u64>,
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRouteConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub upstream_url: String,
    #[serde(default)]
    pub upstreams: Vec<UpstreamEndpointConfig>,
    #[serde(default)]
    pub load_balancing: UpstreamLoadBalancingConfig,
    #[serde(default)]
    pub request_body: UpstreamRequestBodyConfig,
    #[serde(default)]
    pub sse: Option<UpstreamSseConfig>,
    #[serde(default)]
    pub websocket: Option<UpstreamWebSocketConfig>,
    #[serde(default)]
    pub grpc: Option<UpstreamGrpcConfig>,
    #[serde(default)]
    pub limits: UpstreamPoolLimitsConfig,
    #[serde(default)]
    pub health_check: Option<UpstreamHealthCheckConfig>,
    #[serde(default)]
    pub retry: Option<UpstreamRetryConfig>,
    #[serde(default)]
    pub circuit_breaker: Option<UpstreamCircuitBreakerConfig>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub response_idle_timeout_ms: Option<u64>,
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub add_request_headers: HashMap<String, String>,
    #[serde(default)]
    pub strip_request_headers: Vec<String>,
    #[serde(default)]
    pub tls_ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub openapi_spec_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamEndpointConfig {
    pub id: String,
    pub url: String,
    #[serde(default = "default_upstream_weight")]
    pub weight: u16,
    #[serde(default)]
    pub tls_ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub client_identity_pem_path: Option<PathBuf>,
}

fn default_upstream_weight() -> u16 {
    1
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamLoadBalancingStrategy {
    #[default]
    WeightedRoundRobin,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamLoadBalancingConfig {
    #[serde(default)]
    pub strategy: UpstreamLoadBalancingStrategy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRequestBodyMode {
    #[default]
    Buffered,
    Stream,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRequestBodyConfig {
    #[serde(default)]
    pub mode: UpstreamRequestBodyMode,
}

pub const DEFAULT_UPSTREAM_SSE_MAX_DURATION_MS: u64 = 3_600_000;
pub const MAX_UPSTREAM_SSE_MAX_DURATION_MS: u64 = 604_800_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSseConfig {
    #[serde(default = "default_upstream_sse_max_duration_ms")]
    pub max_duration_ms: u64,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
}

fn default_upstream_sse_max_duration_ms() -> u64 {
    DEFAULT_UPSTREAM_SSE_MAX_DURATION_MS
}

pub const DEFAULT_WEBSOCKET_MAX_CONNECTIONS: usize = 64;
pub const MAX_WEBSOCKET_MAX_CONNECTIONS: usize = 100_000;
pub const DEFAULT_WEBSOCKET_QUEUE_DEPTH: usize = 16;
pub const MAX_WEBSOCKET_QUEUE_DEPTH: usize = 10_000;
pub const DEFAULT_WEBSOCKET_QUEUE_TIMEOUT_MS: u64 = 100;
pub const DEFAULT_WEBSOCKET_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub const MIN_WEBSOCKET_HANDSHAKE_TIMEOUT_MS: u64 = 100;
pub const MAX_WEBSOCKET_HANDSHAKE_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_WEBSOCKET_IDLE_TIMEOUT_MS: u64 = 300_000;
pub const MIN_WEBSOCKET_IDLE_TIMEOUT_MS: u64 = 1_000;
pub const MAX_WEBSOCKET_IDLE_TIMEOUT_MS: u64 = 3_600_000;
pub const DEFAULT_WEBSOCKET_MAX_DURATION_MS: u64 = 3_600_000;
pub const DEFAULT_WEBSOCKET_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MIN_WEBSOCKET_MAX_FRAME_BYTES: usize = 1024;
pub const MAX_WEBSOCKET_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_WEBSOCKET_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WEBSOCKET_MAX_MESSAGE_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_WEBSOCKET_MAX_WRITE_BUFFER_BYTES: usize = 256 * 1024;
pub const MAX_WEBSOCKET_MAX_WRITE_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WEBSOCKET_ORIGINS: usize = 32;
pub const MAX_WEBSOCKET_ORIGIN_BYTES: usize = 256;
pub const MAX_WEBSOCKET_SUBPROTOCOLS: usize = 32;
pub const MAX_WEBSOCKET_SUBPROTOCOL_BYTES: usize = 128;

pub const DEFAULT_GRPC_MAX_CONCURRENT_CALLS: usize = 256;
pub const MAX_GRPC_MAX_CONCURRENT_CALLS: usize = 100_000;
pub const DEFAULT_GRPC_QUEUE_DEPTH: usize = 64;
pub const MAX_GRPC_QUEUE_DEPTH: usize = 10_000;
pub const DEFAULT_GRPC_QUEUE_TIMEOUT_MS: u64 = 100;
pub const DEFAULT_GRPC_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GRPC_CONNECT_TIMEOUT_MS: u64 = 100;
pub const MAX_GRPC_CONNECT_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_GRPC_IDLE_TIMEOUT_MS: u64 = 300_000;
pub const MIN_GRPC_IDLE_TIMEOUT_MS: u64 = 1_000;
pub const MAX_GRPC_IDLE_TIMEOUT_MS: u64 = 3_600_000;
pub const DEFAULT_GRPC_MAX_DURATION_MS: u64 = 3_600_000;
pub const MAX_GRPC_MAX_DURATION_MS: u64 = 604_800_000;
pub const DEFAULT_GRPC_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MIN_GRPC_MAX_MESSAGE_BYTES: usize = 1_024;
pub const MAX_GRPC_MAX_MESSAGE_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_GRPC_MAX_STREAM_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_GRPC_MAX_METADATA_ENTRIES: usize = 64;
pub const MAX_GRPC_MAX_METADATA_ENTRIES: usize = 1_024;

/// Opt-in, per-route transparent gRPC proxying.
///
/// Absent means the route carries no gRPC policy, and the gRPC listener refuses
/// every call that matches it. Being absent is therefore a denial rather than a
/// fallback: a route that has not been given gRPC limits has no limits to
/// enforce, and a proxy with no limits is exactly what #257 forbids.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamGrpcConfig {
    /// Concurrent CALLS, not connections.
    ///
    /// The WebSocket transport counts connections because each carries one
    /// conversation. gRPC multiplexes many streams over one connection, so
    /// counting connections here would bound nothing at all.
    #[serde(default = "default_grpc_max_concurrent_calls")]
    pub max_concurrent_calls: usize,
    /// Defaults to `max_concurrent_calls`, i.e. no separate per-endpoint cap.
    #[serde(default)]
    pub max_concurrent_calls_per_endpoint: Option<usize>,
    #[serde(default = "default_grpc_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_grpc_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
    /// Budget for establishing an upstream connection and acquiring stream
    /// capacity on an existing one.
    #[serde(default = "default_grpc_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Zero disables. Measured on the upstream-to-client direction, which is
    /// the one a stalled server shows up in.
    #[serde(default = "default_grpc_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Ceiling on one call's total duration, and the cap applied to a client's
    /// `grpc-timeout`. Zero disables the ceiling.
    #[serde(default = "default_grpc_max_duration_ms")]
    pub max_duration_ms: u64,
    /// Largest single encoded gRPC message, in either direction.
    #[serde(default = "default_grpc_max_message_bytes")]
    pub max_message_bytes: usize,
    /// Ceiling on total bytes in one direction of one call. Zero disables.
    #[serde(default = "default_grpc_max_stream_bytes")]
    pub max_request_bytes: u64,
    #[serde(default = "default_grpc_max_stream_bytes")]
    pub max_response_bytes: u64,
    /// Ceiling on the NUMBER of metadata entries, in headers and in trailers
    /// independently. The listener bounds their total size; this bounds their
    /// count, which is the half a byte budget does not constrain.
    #[serde(default = "default_grpc_max_metadata_entries")]
    pub max_metadata_entries: usize,
}

fn default_grpc_max_concurrent_calls() -> usize {
    DEFAULT_GRPC_MAX_CONCURRENT_CALLS
}

fn default_grpc_queue_depth() -> usize {
    DEFAULT_GRPC_QUEUE_DEPTH
}

fn default_grpc_queue_timeout_ms() -> u64 {
    DEFAULT_GRPC_QUEUE_TIMEOUT_MS
}

fn default_grpc_connect_timeout_ms() -> u64 {
    DEFAULT_GRPC_CONNECT_TIMEOUT_MS
}

fn default_grpc_idle_timeout_ms() -> u64 {
    DEFAULT_GRPC_IDLE_TIMEOUT_MS
}

fn default_grpc_max_duration_ms() -> u64 {
    DEFAULT_GRPC_MAX_DURATION_MS
}

fn default_grpc_max_message_bytes() -> usize {
    DEFAULT_GRPC_MAX_MESSAGE_BYTES
}

fn default_grpc_max_stream_bytes() -> u64 {
    DEFAULT_GRPC_MAX_STREAM_BYTES
}

fn default_grpc_max_metadata_entries() -> usize {
    DEFAULT_GRPC_MAX_METADATA_ENTRIES
}

/// Opt-in, per-route WebSocket proxying.
///
/// Absent means the route keeps today's behavior: an `Upgrade` request is
/// forwarded as an ordinary HTTP request with hop-by-hop headers stripped.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamWebSocketConfig {
    #[serde(default = "default_websocket_max_connections")]
    pub max_connections: usize,
    /// Defaults to `max_connections`, i.e. no separate per-endpoint cap.
    #[serde(default)]
    pub max_connections_per_endpoint: Option<usize>,
    #[serde(default = "default_websocket_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_websocket_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
    #[serde(default = "default_websocket_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// Zero disables the idle timeout, matching the SSE convention.
    #[serde(default = "default_websocket_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Zero disables the ceiling on total connection duration.
    #[serde(default = "default_websocket_max_duration_ms")]
    pub max_duration_ms: u64,
    #[serde(default = "default_websocket_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_websocket_max_message_bytes")]
    pub max_message_bytes: usize,
    #[serde(default = "default_websocket_max_write_buffer_bytes")]
    pub max_write_buffer_bytes: usize,
    /// Exact origin serializations. An empty list denies every request that
    /// carries an `Origin`, because a browser-originated upgrade must be
    /// explicitly allowed rather than allowed by omission.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Reject an upgrade that carries no `Origin` at all.
    #[serde(default)]
    pub require_origin: bool,
    /// Subprotocols this route may negotiate. An empty list denies any client
    /// that offers one; the upstream may never select one the client did not
    /// offer and policy does not allow.
    #[serde(default)]
    pub allowed_subprotocols: Vec<String>,
}

fn default_websocket_max_connections() -> usize {
    DEFAULT_WEBSOCKET_MAX_CONNECTIONS
}

fn default_websocket_queue_depth() -> usize {
    DEFAULT_WEBSOCKET_QUEUE_DEPTH
}

fn default_websocket_queue_timeout_ms() -> u64 {
    DEFAULT_WEBSOCKET_QUEUE_TIMEOUT_MS
}

fn default_websocket_handshake_timeout_ms() -> u64 {
    DEFAULT_WEBSOCKET_HANDSHAKE_TIMEOUT_MS
}

fn default_websocket_idle_timeout_ms() -> u64 {
    DEFAULT_WEBSOCKET_IDLE_TIMEOUT_MS
}

fn default_websocket_max_duration_ms() -> u64 {
    DEFAULT_WEBSOCKET_MAX_DURATION_MS
}

fn default_websocket_max_frame_bytes() -> usize {
    DEFAULT_WEBSOCKET_MAX_FRAME_BYTES
}

fn default_websocket_max_message_bytes() -> usize {
    DEFAULT_WEBSOCKET_MAX_MESSAGE_BYTES
}

fn default_websocket_max_write_buffer_bytes() -> usize {
    DEFAULT_WEBSOCKET_MAX_WRITE_BUFFER_BYTES
}

/// Whether a string is a valid RFC 7230 token, the grammar RFC 6455 uses for a
/// subprotocol name.
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Normalizes an allowed origin to the RFC 6454 serialization the request's
/// `Origin` header is compared against, or returns `None` when it is not a
/// usable origin.
///
/// Scheme and host are lowercased; a default port is dropped so that
/// `https://app.example:443` and `https://app.example` do not silently fail to
/// match each other. Anything carrying a path, query, fragment, or credentials
/// is rejected rather than truncated, since an operator who wrote one is not
/// describing an origin and should be told so.
pub fn normalized_websocket_origin(value: &str) -> Option<String> {
    if value == "null" {
        return Some(value.to_owned());
    }
    let parsed = url::Url::parse(value).ok()?;
    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    let default_port = if scheme == "https" { 443 } else { 80 };
    Some(match parsed.port() {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

pub const DEFAULT_UPSTREAM_RETRY_MAX_ATTEMPTS: u8 = 1;
pub const MAX_UPSTREAM_RETRY_ATTEMPTS: u8 = 5;
const MAX_UPSTREAM_RETRY_STATUSES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRetryConfig {
    #[serde(default = "default_upstream_retry_max_attempts")]
    pub max_attempts: u8,
    #[serde(default = "default_upstream_retry_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_upstream_retry_statuses")]
    pub statuses: Vec<u16>,
}

pub const DEFAULT_UPSTREAM_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
pub const DEFAULT_UPSTREAM_CIRCUIT_OPEN_MS: u64 = 30_000;
pub const DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX_REQUESTS: u32 = 1;
pub const DEFAULT_UPSTREAM_CIRCUIT_RECOVERY_THRESHOLD: u32 = 2;
const MAX_UPSTREAM_CIRCUIT_THRESHOLD: u32 = 1_000;
const MIN_UPSTREAM_CIRCUIT_OPEN_MS: u64 = 10;
const MAX_UPSTREAM_CIRCUIT_OPEN_MS: u64 = 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamCircuitBreakerConfig {
    #[serde(default = "default_upstream_circuit_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_upstream_circuit_open_ms")]
    pub open_ms: u64,
    #[serde(default = "default_upstream_circuit_half_open_max_requests")]
    pub half_open_max_requests: u32,
    #[serde(default = "default_upstream_circuit_recovery_threshold")]
    pub recovery_threshold: u32,
}

fn default_upstream_circuit_failure_threshold() -> u32 {
    DEFAULT_UPSTREAM_CIRCUIT_FAILURE_THRESHOLD
}

fn default_upstream_circuit_open_ms() -> u64 {
    DEFAULT_UPSTREAM_CIRCUIT_OPEN_MS
}

fn default_upstream_circuit_half_open_max_requests() -> u32 {
    DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX_REQUESTS
}

fn default_upstream_circuit_recovery_threshold() -> u32 {
    DEFAULT_UPSTREAM_CIRCUIT_RECOVERY_THRESHOLD
}

fn default_upstream_retry_max_attempts() -> u8 {
    DEFAULT_UPSTREAM_RETRY_MAX_ATTEMPTS
}

fn default_upstream_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_upstream_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}

pub const DEFAULT_UPSTREAM_MAX_IN_FLIGHT: usize = 128;
pub const DEFAULT_UPSTREAM_QUEUE_DEPTH: usize = 256;
pub const DEFAULT_UPSTREAM_QUEUE_TIMEOUT_MS: u64 = 100;
const MIN_UPSTREAM_HEALTH_INTERVAL_MS: u64 = 100;
const MAX_UPSTREAM_HEALTH_INTERVAL_MS: u64 = 3_600_000;
const MIN_UPSTREAM_HEALTH_TIMEOUT_MS: u64 = 10;
const MAX_UPSTREAM_HEALTH_TIMEOUT_MS: u64 = 60_000;
const MAX_UPSTREAM_HEALTH_THRESHOLD: u32 = 1_000;
const MAX_UPSTREAM_HEALTH_STATUSES: usize = 32;
const MAX_UPSTREAM_HEALTH_PATH_LEN: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPoolLimitsConfig {
    #[serde(default = "default_upstream_max_in_flight")]
    pub max_in_flight: usize,
    #[serde(default = "default_upstream_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_upstream_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
}

impl Default for UpstreamPoolLimitsConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_UPSTREAM_MAX_IN_FLIGHT,
            queue_depth: DEFAULT_UPSTREAM_QUEUE_DEPTH,
            queue_timeout_ms: DEFAULT_UPSTREAM_QUEUE_TIMEOUT_MS,
        }
    }
}

fn default_upstream_max_in_flight() -> usize {
    DEFAULT_UPSTREAM_MAX_IN_FLIGHT
}

fn default_upstream_queue_depth() -> usize {
    DEFAULT_UPSTREAM_QUEUE_DEPTH
}

fn default_upstream_queue_timeout_ms() -> u64 {
    DEFAULT_UPSTREAM_QUEUE_TIMEOUT_MS
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamHealthCheckConfig {
    #[serde(default = "default_health_method")]
    pub method: String,
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_expected_statuses")]
    pub expected_statuses: Vec<u16>,
    #[serde(default = "default_passive_failure_statuses")]
    pub passive_failure_statuses: Vec<u16>,
    #[serde(default)]
    pub required_for_readiness: bool,
    #[serde(default = "default_minimum_healthy")]
    pub minimum_healthy: usize,
}

fn default_health_method() -> String {
    "GET".to_owned()
}

fn default_health_path() -> String {
    "/".to_owned()
}

fn default_health_interval_ms() -> u64 {
    10_000
}

fn default_health_timeout_ms() -> u64 {
    1_000
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_expected_statuses() -> Vec<u16> {
    vec![200, 204]
}

fn default_passive_failure_statuses() -> Vec<u16> {
    vec![500, 502, 503, 504]
}

fn default_minimum_healthy() -> usize {
    1
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthProviderConfig {
    pub name: String,
    pub provider_type: AuthProviderType,
    pub jwks_url: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub jwks_timeout_ms: u64,
    pub jwks_max_key_age_secs: u64,
    pub require_jti: bool,
    pub roles_claim: String,
    pub roles_claim_delimiter: Option<String>,
    pub org_claim: Option<String>,
    pub introspection_url: Option<String>,
    pub introspection_timeout_ms: u64,
    pub cache_ttl_ms: u64,
    pub user_id_claim: Option<String>,
    pub email_claim: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
}

impl fmt::Debug for AuthProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let client_secret = self.client_secret.as_ref().map(|_| "<redacted>");

        formatter
            .debug_struct("AuthProviderConfig")
            .field("name", &self.name)
            .field("provider_type", &self.provider_type)
            .field("jwks_url", &self.jwks_url)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_timeout_ms", &self.jwks_timeout_ms)
            .field("require_jti", &self.require_jti)
            .field("roles_claim", &self.roles_claim)
            .field("roles_claim_delimiter", &self.roles_claim_delimiter)
            .field("org_claim", &self.org_claim)
            .field("introspection_url", &self.introspection_url)
            .field("introspection_timeout_ms", &self.introspection_timeout_ms)
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .field("user_id_claim", &self.user_id_claim)
            .field("email_claim", &self.email_claim)
            .field("client_id", &self.client_id)
            .field("client_secret", &client_secret)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProviderType {
    Jwt,
    CookieSession,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthProviderConfig {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    #[serde(default)]
    jwks_url: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    jwks_timeout_ms: Option<u64>,
    #[serde(default)]
    jwks_max_key_age_secs: Option<u64>,
    #[serde(default)]
    require_jti: bool,
    #[serde(default)]
    roles_claim: Option<String>,
    #[serde(default)]
    roles_claim_delimiter: Option<String>,
    #[serde(default)]
    org_claim: Option<String>,
    #[serde(default)]
    introspection_url: Option<String>,
    #[serde(default)]
    introspection_timeout_ms: Option<u64>,
    #[serde(default)]
    cache_ttl_ms: Option<u64>,
    #[serde(default)]
    user_id_claim: Option<String>,
    #[serde(default)]
    email_claim: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}

impl fmt::Debug for RawAuthProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let client_secret = self.client_secret.as_ref().map(|_| "<redacted>");

        formatter
            .debug_struct("RawAuthProviderConfig")
            .field("name", &self.name)
            .field("provider_type", &self.provider_type)
            .field("jwks_url", &self.jwks_url)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_timeout_ms", &self.jwks_timeout_ms)
            .field("require_jti", &self.require_jti)
            .field("roles_claim", &self.roles_claim)
            .field("roles_claim_delimiter", &self.roles_claim_delimiter)
            .field("org_claim", &self.org_claim)
            .field("introspection_url", &self.introspection_url)
            .field("introspection_timeout_ms", &self.introspection_timeout_ms)
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .field("user_id_claim", &self.user_id_claim)
            .field("email_claim", &self.email_claim)
            .field("client_id", &self.client_id)
            .field("client_secret", &client_secret)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Required,
    Observe,
}

impl FromStr for AuthMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "required" => Ok(Self::Required),
            "observe" => Ok(Self::Observe),
            _ => Err("expected `required` or `observe`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    problems: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_vars(|name| env::var(name))
    }

    #[cfg(test)]
    pub(crate) fn test_defaults() -> Self {
        Self::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("the default test configuration should validate")
    }

    // pub(crate) so sibling modules' tests can build configurations from
    // environment maps without going through process environment mutation;
    // production reaches it only through `from_env`.
    pub(crate) fn from_env_vars(
        mut get_var: impl FnMut(&str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        let mut problems = Vec::new();
        const LISTEN_ADDR: &str = "LISTEN_ADDR";

        let listener_problem_count = problems.len();
        let listen_addr = parse_var(
            LISTEN_ADDR,
            get_var(LISTEN_ADDR),
            *DEFAULT_LISTEN_SOCKET_ADDR,
            "socket address",
            &mut problems,
        );
        let admin_listen_addr = parse_optional_socket_addr(
            ADMIN_LISTEN_ADDR,
            get_var(ADMIN_LISTEN_ADDR),
            &mut problems,
        );
        if problems.len() == listener_problem_count && admin_listen_addr == Some(listen_addr) {
            problems.push(format!(
                "{ADMIN_LISTEN_ADDR} must not be the same address as {LISTEN_ADDR} (both resolved to {listen_addr}); choose a different port for the admin listener or leave {ADMIN_LISTEN_ADDR} unset"
            ));
        }
        let grpc_listen_addr =
            parse_optional_socket_addr(GRPC_LISTEN_ADDR, get_var(GRPC_LISTEN_ADDR), &mut problems);
        // Sharing a socket with either existing listener is refused rather than
        // resolved. The gRPC listener speaks HTTP/2 and nothing else, and the
        // other two refuse an HTTP/2 preface outright, so a collision is not a
        // preference to reconcile -- one of the two listeners would simply
        // never answer.
        if problems.len() == listener_problem_count && grpc_listen_addr.is_some() {
            if grpc_listen_addr == Some(listen_addr) {
                problems.push(format!(
                    "{GRPC_LISTEN_ADDR} must not be the same address as {LISTEN_ADDR} (both resolved to {listen_addr}); the gRPC listener serves HTTP/2 and the data listener refuses it"
                ));
            }
            if admin_listen_addr.is_some() && grpc_listen_addr == admin_listen_addr {
                problems.push(format!(
                    "{GRPC_LISTEN_ADDR} must not be the same address as {ADMIN_LISTEN_ADDR}; the gRPC listener serves HTTP/2 and the admin listener refuses it"
                ));
            }
        }
        let grpc_max_concurrent_streams = validate_range_u32(
            GRPC_MAX_CONCURRENT_STREAMS,
            parse_var(
                GRPC_MAX_CONCURRENT_STREAMS,
                get_var(GRPC_MAX_CONCURRENT_STREAMS),
                DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
                "stream count",
                &mut problems,
            ),
            1,
            MAX_GRPC_MAX_CONCURRENT_STREAMS,
            DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            &mut problems,
        );
        let grpc_max_metadata_bytes = validate_range_u32(
            GRPC_MAX_METADATA_BYTES,
            parse_var(
                GRPC_MAX_METADATA_BYTES,
                get_var(GRPC_MAX_METADATA_BYTES),
                DEFAULT_GRPC_MAX_METADATA_BYTES,
                "byte count",
                &mut problems,
            ),
            MIN_GRPC_MAX_METADATA_BYTES,
            MAX_GRPC_MAX_METADATA_BYTES,
            DEFAULT_GRPC_MAX_METADATA_BYTES,
            &mut problems,
        );
        let tls_cert_files =
            parse_material_file_list(TLS_CERT_FILE, get_var(TLS_CERT_FILE), &mut problems);
        let tls_key_files =
            parse_material_file_list(TLS_KEY_FILE, get_var(TLS_KEY_FILE), &mut problems);
        let admin_tls_cert_files = parse_material_file_list(
            ADMIN_TLS_CERT_FILE,
            get_var(ADMIN_TLS_CERT_FILE),
            &mut problems,
        );
        let admin_tls_key_files = parse_material_file_list(
            ADMIN_TLS_KEY_FILE,
            get_var(ADMIN_TLS_KEY_FILE),
            &mut problems,
        );
        // Half a pair is the shape that quietly serves plaintext on a listener
        // an operator believes is protected, so it is a startup failure rather
        // than a warning or an implicit "TLS off".
        require_inbound_tls_pair(
            TLS_CERT_FILE,
            tls_cert_files.as_deref(),
            TLS_KEY_FILE,
            tls_key_files.as_deref(),
            &mut problems,
        );
        require_inbound_tls_pair(
            ADMIN_TLS_CERT_FILE,
            admin_tls_cert_files.as_deref(),
            ADMIN_TLS_KEY_FILE,
            admin_tls_key_files.as_deref(),
            &mut problems,
        );
        // Admin TLS only has a listener to terminate on when the admin surface
        // has its own listener. Accepting the settings without one would leave
        // the admin surface on the data listener's scheme while its own
        // settings say otherwise.
        if admin_listen_addr.is_none()
            && (admin_tls_cert_files.is_some() || admin_tls_key_files.is_some())
        {
            problems.push(format!(
                "{ADMIN_TLS_CERT_FILE} and {ADMIN_TLS_KEY_FILE} require {ADMIN_LISTEN_ADDR} to be set; without a separate admin listener there is nothing for them to terminate"
            ));
        }
        let tls_min_version = parse_var(
            TLS_MIN_VERSION,
            get_var(TLS_MIN_VERSION),
            DEFAULT_TLS_MIN_VERSION,
            "TLS version",
            &mut problems,
        );
        let tls_handshake_timeout_ms = validate_positive_timeout_ms(
            TLS_HANDSHAKE_TIMEOUT_MS,
            parse_var(
                TLS_HANDSHAKE_TIMEOUT_MS,
                get_var(TLS_HANDSHAKE_TIMEOUT_MS),
                DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            &mut problems,
        );
        let tls_max_concurrent_handshakes = validate_positive_usize(
            TLS_MAX_CONCURRENT_HANDSHAKES,
            parse_var(
                TLS_MAX_CONCURRENT_HANDSHAKES,
                get_var(TLS_MAX_CONCURRENT_HANDSHAKES),
                DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
                "handshake count",
                &mut problems,
            ),
            DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            &mut problems,
        );
        // Client-certificate authentication, per listener.
        //
        // Parsed after the certificate/key pair because it depends on it: a
        // listener that terminates no TLS cannot ask for a client certificate,
        // and a mode that says otherwise is a configuration an operator would
        // reasonably read as "mutual TLS is on".
        let client_cert_identity_source = parse_optional_string(
            CLIENT_CERT_IDENTITY_SOURCE,
            get_var(CLIENT_CERT_IDENTITY_SOURCE),
            &mut problems,
        )
        .and_then(|value| match value.parse::<ClientCertIdentitySource>() {
            Ok(source) => Some(source),
            Err(expected) => {
                problems.push(format!(
                    "{CLIENT_CERT_IDENTITY_SOURCE} must name a supported identity source, got '{value}': {expected}"
                ));
                None
            }
        });
        let client_cert_mode = parse_var(
            CLIENT_CERT_MODE,
            get_var(CLIENT_CERT_MODE),
            ClientCertMode::Off,
            "client certificate mode",
            &mut problems,
        );
        let admin_client_cert_mode = parse_var(
            ADMIN_CLIENT_CERT_MODE,
            get_var(ADMIN_CLIENT_CERT_MODE),
            ClientCertMode::Off,
            "client certificate mode",
            &mut problems,
        );
        let client_cert_auth = compose_inbound_client_auth(
            RawInboundClientAuth {
                mode_setting: CLIENT_CERT_MODE,
                mode: client_cert_mode,
                ca_setting: CLIENT_CERT_CA_FILE,
                ca_file: parse_optional_string(
                    CLIENT_CERT_CA_FILE,
                    get_var(CLIENT_CERT_CA_FILE),
                    &mut problems,
                ),
                crl_setting: CLIENT_CERT_CRL_FILE,
                crl_file: parse_optional_string(
                    CLIENT_CERT_CRL_FILE,
                    get_var(CLIENT_CERT_CRL_FILE),
                    &mut problems,
                ),
                identity_source: client_cert_identity_source,
                tls_certificate_setting: TLS_CERT_FILE,
                tls_configured: tls_cert_files.is_some(),
            },
            &mut problems,
        );
        let admin_client_cert_auth = compose_inbound_client_auth(
            RawInboundClientAuth {
                mode_setting: ADMIN_CLIENT_CERT_MODE,
                mode: admin_client_cert_mode,
                ca_setting: ADMIN_CLIENT_CERT_CA_FILE,
                ca_file: parse_optional_string(
                    ADMIN_CLIENT_CERT_CA_FILE,
                    get_var(ADMIN_CLIENT_CERT_CA_FILE),
                    &mut problems,
                ),
                crl_setting: ADMIN_CLIENT_CERT_CRL_FILE,
                crl_file: parse_optional_string(
                    ADMIN_CLIENT_CERT_CRL_FILE,
                    get_var(ADMIN_CLIENT_CERT_CRL_FILE),
                    &mut problems,
                ),
                identity_source: client_cert_identity_source,
                tls_certificate_setting: ADMIN_TLS_CERT_FILE,
                tls_configured: admin_tls_cert_files.is_some(),
            },
            &mut problems,
        );
        // An identity source with nothing to apply it to is a setting that
        // reads as "client certificates are configured" and does nothing. Say
        // so rather than ignoring it.
        if client_cert_identity_source.is_some()
            && client_cert_mode == ClientCertMode::Off
            && admin_client_cert_mode == ClientCertMode::Off
        {
            problems.push(format!(
                "{CLIENT_CERT_IDENTITY_SOURCE} is set while {CLIENT_CERT_MODE} and {ADMIN_CLIENT_CERT_MODE} are both off; set one of them to `optional` or `required`, or unset the identity source"
            ));
        }
        let admin_prefix = parse_admin_prefix(
            ADMIN_PREFIX,
            get_var(ADMIN_PREFIX),
            DEFAULT_ADMIN_PREFIX,
            &mut problems,
        );
        let admin_login_provider = parse_optional_string(
            ADMIN_LOGIN_PROVIDER,
            get_var(ADMIN_LOGIN_PROVIDER),
            &mut problems,
        );
        let admin_login_pending_ttl_secs = validate_positive_u64(
            ADMIN_LOGIN_PENDING_TTL_SECS,
            parse_var(
                ADMIN_LOGIN_PENDING_TTL_SECS,
                get_var(ADMIN_LOGIN_PENDING_TTL_SECS),
                DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
                "second duration",
                &mut problems,
            ),
            DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            &mut problems,
        );
        let admin_login_pending_max_entries = validate_positive_usize(
            ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            parse_var(
                ADMIN_LOGIN_PENDING_MAX_ENTRIES,
                get_var(ADMIN_LOGIN_PENDING_MAX_ENTRIES),
                DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
                "entry count",
                &mut problems,
            ),
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            &mut problems,
        );
        let admin_login_pending_max_per_ip = validate_positive_usize(
            ADMIN_LOGIN_PENDING_MAX_PER_IP,
            parse_var(
                ADMIN_LOGIN_PENDING_MAX_PER_IP,
                get_var(ADMIN_LOGIN_PENDING_MAX_PER_IP),
                DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
                "entry count",
                &mut problems,
            ),
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            &mut problems,
        );
        let gateway_public_url = parse_optional_gateway_public_url(
            GATEWAY_PUBLIC_URL,
            get_var(GATEWAY_PUBLIC_URL),
            &mut problems,
        );
        let audit_log_file =
            parse_optional_string(AUDIT_LOG_FILE, get_var(AUDIT_LOG_FILE), &mut problems);
        let audit_sqlite_path =
            parse_optional_string(AUDIT_SQLITE_PATH, get_var(AUDIT_SQLITE_PATH), &mut problems);
        let audit_sqlite_retention_days = normalize_audit_sqlite_retention_days(
            AUDIT_SQLITE_RETENTION_DAYS,
            parse_optional_var(
                AUDIT_SQLITE_RETENTION_DAYS,
                get_var(AUDIT_SQLITE_RETENTION_DAYS),
                "day count",
                &mut problems,
            ),
            &mut problems,
        );
        let shutdown_drain_delay_ms = validate_maximum_u64(
            SHUTDOWN_DRAIN_DELAY_MS,
            parse_var(
                SHUTDOWN_DRAIN_DELAY_MS,
                get_var(SHUTDOWN_DRAIN_DELAY_MS),
                DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
                "millisecond duration",
                &mut problems,
            ),
            MAX_SHUTDOWN_DRAIN_DELAY_MS,
            DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            &mut problems,
        );
        let shutdown_timeout_ms = validate_positive_bounded_u64(
            SHUTDOWN_TIMEOUT_MS,
            parse_var(
                SHUTDOWN_TIMEOUT_MS,
                get_var(SHUTDOWN_TIMEOUT_MS),
                DEFAULT_SHUTDOWN_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            MAX_SHUTDOWN_TIMEOUT_MS,
            DEFAULT_SHUTDOWN_TIMEOUT_MS,
            &mut problems,
        );
        let audit_drain_timeout_ms = validate_positive_bounded_u64(
            AUDIT_DRAIN_TIMEOUT_MS,
            parse_var(
                AUDIT_DRAIN_TIMEOUT_MS,
                get_var(AUDIT_DRAIN_TIMEOUT_MS),
                DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            MAX_AUDIT_DRAIN_TIMEOUT_MS,
            DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            &mut problems,
        );
        let discovery_sqlite_path = parse_optional_string(
            DISCOVERY_SQLITE_PATH,
            get_var(DISCOVERY_SQLITE_PATH),
            &mut problems,
        );
        let discovery_endpoint_limit = validate_positive_usize(
            DISCOVERY_ENDPOINT_LIMIT,
            parse_var(
                DISCOVERY_ENDPOINT_LIMIT,
                get_var(DISCOVERY_ENDPOINT_LIMIT),
                DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                "positive integer",
                &mut problems,
            ),
            DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            &mut problems,
        );
        let principal_sqlite_path = parse_optional_string(
            PRINCIPAL_SQLITE_PATH,
            get_var(PRINCIPAL_SQLITE_PATH),
            &mut problems,
        );
        let connections_sqlite_path = parse_optional_string(
            CONNECTIONS_SQLITE_PATH,
            get_var(CONNECTIONS_SQLITE_PATH),
            &mut problems,
        );
        let connection_secrets_root = parse_optional_secret_root(
            CONNECTION_SECRETS_ROOT,
            get_var(CONNECTION_SECRETS_ROOT),
            &mut problems,
        );
        let connection_secret_aliases = parse_operator_secret_aliases(
            CONNECTION_SECRET_ALIASES,
            get_var(CONNECTION_SECRET_ALIASES),
            &mut problems,
        );
        if let Err(error) = validate_operator_secret_alias_config(
            &connection_secret_aliases,
            connection_secrets_root.is_some(),
        ) {
            problems.push(format!("{CONNECTION_SECRET_ALIASES}: {error}"));
        }
        let connection_local_secret_keyring = parse_local_secret_keyring(
            CONNECTION_LOCAL_SECRET_KEYRING,
            get_var(CONNECTION_LOCAL_SECRET_KEYRING),
            &mut problems,
        );
        if let Err(error) = validate_local_secret_keyring_config(
            &connection_local_secret_keyring,
            connection_secrets_root.is_some(),
            connections_sqlite_path.is_some(),
        ) {
            problems.push(format!("{CONNECTION_LOCAL_SECRET_KEYRING}: {error}"));
        }
        let admin_login_keyring = parse_local_secret_keyring(
            ADMIN_LOGIN_KEYRING,
            get_var(ADMIN_LOGIN_KEYRING),
            &mut problems,
        );
        // The login keyring seals rows in PostgreSQL, so it needs the
        // secrets root for its key files but no local store.
        if let Err(error) = validate_local_secret_keyring_config(
            &admin_login_keyring,
            connection_secrets_root.is_some(),
            true,
        ) {
            problems.push(format!("{ADMIN_LOGIN_KEYRING}: {error}"));
        }
        let rate_limit_keyring = parse_local_secret_keyring(
            RATE_LIMIT_KEYRING,
            get_var(RATE_LIMIT_KEYRING),
            &mut problems,
        );
        // The rate-limit keyring signs bucket keys stored in PostgreSQL, so
        // it needs the secrets root for its key files but no local store.
        if let Err(error) = validate_local_secret_keyring_config(
            &rate_limit_keyring,
            connection_secrets_root.is_some(),
            true,
        ) {
            problems.push(format!("{RATE_LIMIT_KEYRING}: {error}"));
        }
        let connection_vault_provider = parse_vault_provider_config(
            CONNECTION_VAULT_PROVIDER,
            get_var(CONNECTION_VAULT_PROVIDER),
            &mut problems,
        );
        // Vault aliases share one namespace with the operator aliases, so a
        // duplicate id must fail closed at startup rather than let resolution
        // order decide which provider answers.
        let reserved_alias_ids = connection_secret_aliases
            .iter()
            .map(|alias| alias.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if let Err(error) =
            validate_vault_provider_config(&connection_vault_provider, &reserved_alias_ids)
        {
            problems.push(format!("{CONNECTION_VAULT_PROVIDER}: {error}"));
        }
        let connection_gcp_provider = parse_gcp_provider_config(
            CONNECTION_GCP_PROVIDER,
            get_var(CONNECTION_GCP_PROVIDER),
            &mut problems,
        );
        // Google Cloud aliases share the same namespace; duplicates across the
        // operator aliases fail closed at startup here, and duplicates across
        // other network providers fail closed in the connection control plane.
        if let Err(error) =
            validate_gcp_provider_config(&connection_gcp_provider, &reserved_alias_ids)
        {
            problems.push(format!("{CONNECTION_GCP_PROVIDER}: {error}"));
        }
        let connection_azure_provider = parse_azure_provider_config(
            CONNECTION_AZURE_PROVIDER,
            get_var(CONNECTION_AZURE_PROVIDER),
            &mut problems,
        );
        // Azure aliases share the same namespace as the operator aliases. IDs
        // claimed by other network providers are additionally rejected by the
        // control plane's cross-provider collision guard.
        if let Err(error) =
            validate_azure_provider_config(&connection_azure_provider, &reserved_alias_ids)
        {
            problems.push(format!("{CONNECTION_AZURE_PROVIDER}: {error}"));
        }
        let connection_aws_provider = parse_aws_provider_config(
            CONNECTION_AWS_PROVIDER,
            get_var(CONNECTION_AWS_PROVIDER),
            &mut problems,
        );
        // AWS aliases share the same namespace; duplicates against operator
        // aliases fail closed here, and duplicates against other network
        // providers fail closed in the control plane's collision guard.
        if let Err(error) =
            validate_aws_provider_config(&connection_aws_provider, &reserved_alias_ids)
        {
            problems.push(format!("{CONNECTION_AWS_PROVIDER}: {error}"));
        }
        let connection_kubernetes_provider = parse_kubernetes_provider_config(
            CONNECTION_KUBERNETES_PROVIDER,
            get_var(CONNECTION_KUBERNETES_PROVIDER),
            &mut problems,
        );
        // Kubernetes aliases share the same namespace as the operator aliases;
        // duplicates against the other network providers are rejected by the
        // control plane's network-alias collision guard.
        if let Err(error) = validate_kubernetes_provider_config(
            &connection_kubernetes_provider,
            &reserved_alias_ids,
        ) {
            problems.push(format!("{CONNECTION_KUBERNETES_PROVIDER}: {error}"));
        }
        let payload_capture_enabled = parse_var(
            PAYLOAD_CAPTURE_ENABLED,
            get_var(PAYLOAD_CAPTURE_ENABLED),
            false,
            "boolean",
            &mut problems,
        );
        let payload_capture_sample_rate = validate_payload_capture_sample_rate(
            PAYLOAD_CAPTURE_SAMPLE_RATE,
            parse_var(
                PAYLOAD_CAPTURE_SAMPLE_RATE,
                get_var(PAYLOAD_CAPTURE_SAMPLE_RATE),
                DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
                "sample rate",
                &mut problems,
            ),
            DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            &mut problems,
        );
        if payload_capture_enabled && discovery_sqlite_path.is_none() {
            problems.push(format!(
                "{PAYLOAD_CAPTURE_ENABLED}=true requires {DISCOVERY_SQLITE_PATH} to be set so captured request shapes have an explicit SQLite storage destination"
            ));
        }
        let schema_mismatch_signal_threshold = validate_positive_u64(
            SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            parse_var(
                SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                get_var(SCHEMA_MISMATCH_SIGNAL_THRESHOLD),
                DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
                "positive integer",
                &mut problems,
            ),
            DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            &mut problems,
        );
        let error_rate_spike_signal_threshold = validate_signal_ratio_threshold(
            ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            parse_var(
                ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                get_var(ERROR_RATE_SPIKE_SIGNAL_THRESHOLD),
                DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
                "ratio threshold",
                &mut problems,
            ),
            DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            &mut problems,
        );
        let principal_new_to_endpoint_signal_threshold = validate_positive_u64(
            PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            parse_var(
                PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                get_var(PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD),
                DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
                "positive integer",
                &mut problems,
            ),
            DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            &mut problems,
        );
        let volume_outlier_signal_threshold = validate_signal_multiple_threshold(
            VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            parse_var(
                VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                get_var(VOLUME_OUTLIER_SIGNAL_THRESHOLD),
                DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
                "multiple threshold",
                &mut problems,
            ),
            DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            &mut problems,
        );
        let rule_suggestion_baseline_window_hours = validate_rule_suggestion_baseline_window_hours(
            RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            parse_var(
                RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                get_var(RULE_SUGGESTION_BASELINE_WINDOW_HOURS),
                DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
                "hour count",
                &mut problems,
            ),
            DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            &mut problems,
        );
        let openapi_spec_path =
            parse_optional_path(OPENAPI_SPEC_PATH, get_var(OPENAPI_SPEC_PATH), &mut problems);
        let policy_file = parse_optional_string(POLICY_FILE, get_var(POLICY_FILE), &mut problems);
        let tools_file = parse_optional_string(TOOLS_FILE, get_var(TOOLS_FILE), &mut problems);
        let policy_history_sqlite_path = parse_optional_string(
            POLICY_HISTORY_SQLITE_PATH,
            get_var(POLICY_HISTORY_SQLITE_PATH),
            &mut problems,
        );
        let cors_allow_origins = validate_cors_allow_origins(
            CORS_ALLOW_ORIGINS,
            parse_comma_separated_header_values(
                CORS_ALLOW_ORIGINS,
                get_var(CORS_ALLOW_ORIGINS),
                &[],
                &mut problems,
            ),
            &mut problems,
        );
        let max_body_size = parse_var(
            MAX_BODY_SIZE,
            get_var(MAX_BODY_SIZE),
            DEFAULT_MAX_BODY_SIZE,
            "byte size",
            &mut problems,
        );
        let rate_limit_read_rps = validate_finite_non_negative(
            RATE_LIMIT_READ_RPS,
            parse_var(
                RATE_LIMIT_READ_RPS,
                get_var(RATE_LIMIT_READ_RPS),
                DEFAULT_RATE_LIMIT_READ_RPS,
                "requests-per-second number",
                &mut problems,
            ),
            DEFAULT_RATE_LIMIT_READ_RPS,
            &mut problems,
        );
        let rate_limit_read_burst = parse_var(
            RATE_LIMIT_READ_BURST,
            get_var(RATE_LIMIT_READ_BURST),
            DEFAULT_RATE_LIMIT_READ_BURST,
            "request burst size",
            &mut problems,
        );
        let rate_limit_write_rps = validate_finite_non_negative(
            RATE_LIMIT_WRITE_RPS,
            parse_var(
                RATE_LIMIT_WRITE_RPS,
                get_var(RATE_LIMIT_WRITE_RPS),
                DEFAULT_RATE_LIMIT_WRITE_RPS,
                "requests-per-second number",
                &mut problems,
            ),
            DEFAULT_RATE_LIMIT_WRITE_RPS,
            &mut problems,
        );
        let rate_limit_write_burst = parse_var(
            RATE_LIMIT_WRITE_BURST,
            get_var(RATE_LIMIT_WRITE_BURST),
            DEFAULT_RATE_LIMIT_WRITE_BURST,
            "request burst size",
            &mut problems,
        );
        let rate_limit_max_buckets = validate_positive_usize(
            RATE_LIMIT_MAX_BUCKETS,
            parse_var(
                RATE_LIMIT_MAX_BUCKETS,
                get_var(RATE_LIMIT_MAX_BUCKETS),
                DEFAULT_RATE_LIMIT_MAX_BUCKETS,
                "bucket count",
                &mut problems,
            ),
            DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            &mut problems,
        );
        let rate_limit_bucket_ttl_ms = validate_positive_timeout_ms(
            RATE_LIMIT_BUCKET_TTL_MS,
            parse_var(
                RATE_LIMIT_BUCKET_TTL_MS,
                get_var(RATE_LIMIT_BUCKET_TTL_MS),
                DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            &mut problems,
        );
        let trust_proxy_headers = parse_var(
            TRUST_PROXY_HEADERS,
            get_var(TRUST_PROXY_HEADERS),
            false,
            "boolean",
            &mut problems,
        );
        let trusted_proxy_cidrs = parse_comma_separated_cidrs(
            TRUSTED_PROXY_CIDRS,
            get_var(TRUSTED_PROXY_CIDRS),
            &mut problems,
        );
        if trust_proxy_headers && trusted_proxy_cidrs.is_empty() {
            problems.push(format!(
                "{TRUSTED_PROXY_CIDRS} must contain at least one CIDR when {TRUST_PROXY_HEADERS}=true"
            ));
        }
        let mut rbac_exempt_paths = parse_comma_separated_paths(
            RBAC_EXEMPT_PATHS,
            get_var(RBAC_EXEMPT_PATHS),
            &default_admin_exempt_paths(&admin_prefix, admin_login_provider.is_some()),
            &mut problems,
        );
        append_admin_login_exempt_paths(
            &mut rbac_exempt_paths,
            &admin_prefix,
            admin_login_provider.is_some(),
        );
        let validation_allowed_content_types = parse_comma_separated_header_values(
            VALIDATION_ALLOWED_CONTENT_TYPES,
            get_var(VALIDATION_ALLOWED_CONTENT_TYPES),
            DEFAULT_VALIDATION_ALLOWED_CONTENT_TYPES,
            &mut problems,
        );
        let auth_enabled = parse_var(
            AUTH_ENABLED,
            get_var(AUTH_ENABLED),
            DEFAULT_AUTH_ENABLED,
            "boolean",
            &mut problems,
        );
        let auth_mode = parse_var(
            AUTH_MODE,
            get_var(AUTH_MODE),
            DEFAULT_AUTH_MODE,
            "auth mode",
            &mut problems,
        );
        let auth_cookie_name = parse_cookie_name(
            AUTH_COOKIE_NAME,
            get_var(AUTH_COOKIE_NAME),
            DEFAULT_AUTH_COOKIE_NAME,
            &mut problems,
        );
        let mut auth_exempt_paths = parse_comma_separated_paths(
            AUTH_EXEMPT_PATHS,
            get_var(AUTH_EXEMPT_PATHS),
            &default_admin_exempt_paths(&admin_prefix, admin_login_provider.is_some()),
            &mut problems,
        );
        append_admin_login_exempt_paths(
            &mut auth_exempt_paths,
            &admin_prefix,
            admin_login_provider.is_some(),
        );
        let jwt_jwks_url =
            parse_optional_string(JWT_JWKS_URL, get_var(JWT_JWKS_URL), &mut problems);
        let jwt_issuer = parse_optional_string(JWT_ISSUER, get_var(JWT_ISSUER), &mut problems);
        let jwt_audience =
            parse_optional_string(JWT_AUDIENCE, get_var(JWT_AUDIENCE), &mut problems);
        let jwt_jwks_timeout_ms = parse_var(
            JWT_JWKS_TIMEOUT_MS,
            get_var(JWT_JWKS_TIMEOUT_MS),
            DEFAULT_JWT_JWKS_TIMEOUT_MS,
            "millisecond duration",
            &mut problems,
        );
        let jwt_jwks_max_key_age_secs = validate_jwks_max_key_age(
            JWT_JWKS_MAX_KEY_AGE_SECS,
            parse_var(
                JWT_JWKS_MAX_KEY_AGE_SECS,
                get_var(JWT_JWKS_MAX_KEY_AGE_SECS),
                DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS,
                "second duration",
                &mut problems,
            ),
            &mut problems,
        );
        let jwt_require_jti = parse_var(
            JWT_REQUIRE_JTI,
            get_var(JWT_REQUIRE_JTI),
            false,
            "boolean",
            &mut problems,
        );
        let roles_claim = parse_non_empty_string(
            ROLES_CLAIM,
            get_var(ROLES_CLAIM),
            DEFAULT_ROLES_CLAIM,
            &mut problems,
        );
        let service_token_sqlite_path = parse_optional_string(
            SERVICE_TOKEN_SQLITE_PATH,
            get_var(SERVICE_TOKEN_SQLITE_PATH),
            &mut problems,
        );
        let service_token_cache_ttl_ms = validate_positive_u64(
            SERVICE_TOKEN_CACHE_TTL_MS,
            parse_var(
                SERVICE_TOKEN_CACHE_TTL_MS,
                get_var(SERVICE_TOKEN_CACHE_TTL_MS),
                DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            &mut problems,
        );
        let tool_runtime_queue_depth = validate_positive_usize(
            TOOL_RUNTIME_QUEUE_DEPTH,
            parse_var(
                TOOL_RUNTIME_QUEUE_DEPTH,
                get_var(TOOL_RUNTIME_QUEUE_DEPTH),
                DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
                "positive integer",
                &mut problems,
            ),
            DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            &mut problems,
        );
        let tool_runtime_global_concurrency = validate_positive_usize(
            TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            parse_var(
                TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                get_var(TOOL_RUNTIME_GLOBAL_CONCURRENCY),
                DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
                "positive integer",
                &mut problems,
            ),
            DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            &mut problems,
        );
        let tool_runtime_queue_timeout_ms = validate_positive_u64(
            TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            parse_var(
                TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
                get_var(TOOL_RUNTIME_QUEUE_TIMEOUT_MS),
                DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            &mut problems,
        );
        let tool_lease_ttl_ms = validate_positive_u64(
            TOOL_LEASE_TTL_MS,
            parse_var(
                TOOL_LEASE_TTL_MS,
                get_var(TOOL_LEASE_TTL_MS),
                DEFAULT_TOOL_LEASE_TTL_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_TOOL_LEASE_TTL_MS,
            &mut problems,
        );
        let tool_lease_ttl_ms = if tool_lease_ttl_ms < MIN_TOOL_LEASE_TTL_MS {
            problems.push(format!(
                "{TOOL_LEASE_TTL_MS} must be at least {MIN_TOOL_LEASE_TTL_MS} milliseconds (a lease is renewed at a third of its TTL), got '{tool_lease_ttl_ms}'"
            ));
            DEFAULT_TOOL_LEASE_TTL_MS
        } else {
            tool_lease_ttl_ms
        };
        let tool_runtime_default_timeout_ms = validate_positive_u64(
            TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
            parse_var(
                TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                get_var(TOOL_RUNTIME_DEFAULT_TIMEOUT_MS),
                DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
            &mut problems,
        );
        let auth_providers =
            parse_auth_providers(AUTH_PROVIDERS, get_var(AUTH_PROVIDERS), &mut problems)
                .unwrap_or_else(|| {
                    legacy_auth_providers(
                        jwt_jwks_url.as_deref(),
                        jwt_issuer.as_deref(),
                        jwt_audience.as_deref(),
                        jwt_jwks_timeout_ms,
                        jwt_jwks_max_key_age_secs,
                        jwt_require_jti,
                        &roles_claim,
                    )
                });
        validate_admin_login_provider(
            admin_login_provider.as_deref(),
            &auth_providers,
            &mut problems,
        );
        let csrf_enabled = parse_var(
            CSRF_ENABLED,
            get_var(CSRF_ENABLED),
            DEFAULT_CSRF_ENABLED,
            "boolean",
            &mut problems,
        );
        let csrf_cookie_name = parse_cookie_name(
            CSRF_COOKIE_NAME,
            get_var(CSRF_COOKIE_NAME),
            DEFAULT_CSRF_COOKIE_NAME,
            &mut problems,
        );
        let csrf_header_name = parse_header_name_string(
            CSRF_HEADER_NAME,
            get_var(CSRF_HEADER_NAME),
            DEFAULT_CSRF_HEADER_NAME,
            &mut problems,
        );
        let csrf_cookie_domain = parse_optional_cookie_domain(
            CSRF_COOKIE_DOMAIN,
            get_var(CSRF_COOKIE_DOMAIN),
            &mut problems,
        );
        let csrf_exempt_paths = parse_comma_separated_paths(
            CSRF_EXEMPT_PATHS,
            get_var(CSRF_EXEMPT_PATHS),
            &default_paths(DEFAULT_CSRF_EXEMPT_PATHS),
            &mut problems,
        );
        let upstream_url =
            parse_optional_upstream_url(UPSTREAM_URL, get_var(UPSTREAM_URL), &mut problems);
        let upstream_routes =
            parse_upstream_routes(UPSTREAM_ROUTES, get_var(UPSTREAM_ROUTES), &mut problems);
        let mcp_upstream_servers = parse_mcp_upstream_servers(
            MCP_UPSTREAM_SERVERS,
            get_var(MCP_UPSTREAM_SERVERS),
            &mut problems,
        );
        if upstream_url.is_some() && !upstream_routes.is_empty() {
            problems.push(format!(
                "{UPSTREAM_URL} and {UPSTREAM_ROUTES} are mutually exclusive; set one proxy routing source"
            ));
        }
        if policy_file.is_none() && upstream_routes.iter().any(|route| route.host.is_some()) {
            problems.push(format!(
                "{UPSTREAM_ROUTES} entries with host require {POLICY_FILE} so RBAC can bind authorization to the selected request host"
            ));
        }
        let upstream_timeout_ms = validate_optional_positive_timeout_ms(
            UPSTREAM_TIMEOUT_MS,
            parse_optional_var(
                UPSTREAM_TIMEOUT_MS,
                get_var(UPSTREAM_TIMEOUT_MS),
                "millisecond duration",
                &mut problems,
            ),
            &mut problems,
        );
        let upstream_response_idle_timeout_ms = validate_optional_positive_timeout_ms(
            UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
            parse_optional_var(
                UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
                get_var(UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS),
                "millisecond duration",
                &mut problems,
            ),
            &mut problems,
        );
        let upstream_connect_timeout_ms = validate_optional_positive_timeout_ms(
            UPSTREAM_CONNECT_TIMEOUT_MS,
            parse_optional_var(
                UPSTREAM_CONNECT_TIMEOUT_MS,
                get_var(UPSTREAM_CONNECT_TIMEOUT_MS),
                "millisecond duration",
                &mut problems,
            ),
            &mut problems,
        );
        let egress_allowed_hosts = parse_comma_separated_hostnames(
            EGRESS_ALLOWED_HOSTS,
            get_var(EGRESS_ALLOWED_HOSTS),
            &mut problems,
        );
        let egress_timeout_ms = validate_positive_timeout_ms(
            EGRESS_TIMEOUT_MS,
            parse_var(
                EGRESS_TIMEOUT_MS,
                get_var(EGRESS_TIMEOUT_MS),
                DEFAULT_EGRESS_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_EGRESS_TIMEOUT_MS,
            &mut problems,
        );
        let egress_response_idle_timeout_ms = validate_positive_timeout_ms(
            EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
            parse_var(
                EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
                get_var(EGRESS_RESPONSE_IDLE_TIMEOUT_MS),
                DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
            &mut problems,
        );
        let egress_connect_timeout_ms = validate_positive_timeout_ms(
            EGRESS_CONNECT_TIMEOUT_MS,
            parse_var(
                EGRESS_CONNECT_TIMEOUT_MS,
                get_var(EGRESS_CONNECT_TIMEOUT_MS),
                DEFAULT_EGRESS_CONNECT_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_EGRESS_CONNECT_TIMEOUT_MS,
            &mut problems,
        );
        let egress_max_response_bytes = parse_var(
            EGRESS_MAX_RESPONSE_BYTES,
            get_var(EGRESS_MAX_RESPONSE_BYTES),
            DEFAULT_EGRESS_MAX_RESPONSE_BYTES,
            "byte size",
            &mut problems,
        );
        let egress_max_request_body_bytes = parse_var(
            EGRESS_MAX_REQUEST_BODY_BYTES,
            get_var(EGRESS_MAX_REQUEST_BODY_BYTES),
            DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES,
            "byte size",
            &mut problems,
        );
        let egress_nat64_prefixes = parse_nat64_prefixes(
            EGRESS_NAT64_PREFIXES,
            get_var(EGRESS_NAT64_PREFIXES),
            &mut problems,
        );
        let egress_deny_private_ips = parse_var(
            EGRESS_DENY_PRIVATE_IPS,
            get_var(EGRESS_DENY_PRIVATE_IPS),
            DEFAULT_EGRESS_DENY_PRIVATE_IPS,
            "boolean",
            &mut problems,
        );

        // Shared-state backend and PostgreSQL foundation (issue #241, PR 3).
        //
        // Everything here is validated in both modes, but nothing activates
        // outside `STATE_BACKEND=postgres`: standalone mode must remain
        // byte-for-byte unchanged. The mode's own requirements (deployment ID,
        // secret-file DSN, rejection of writable local authorities) are checked
        // below so the operator sees every problem in one pass.
        let state_backend = parse_var(
            STATE_BACKEND,
            get_var(STATE_BACKEND),
            StateBackend::Sqlite,
            "state backend",
            &mut problems,
        );
        let deployment_id = validate_deployment_id(
            DEPLOYMENT_ID,
            parse_optional_string(DEPLOYMENT_ID, get_var(DEPLOYMENT_ID), &mut problems),
            &mut problems,
        );
        let database_url_file =
            parse_optional_string(DATABASE_URL_FILE, get_var(DATABASE_URL_FILE), &mut problems);
        let database_tls_mode = parse_var(
            DATABASE_TLS_MODE,
            get_var(DATABASE_TLS_MODE),
            DatabaseTlsMode::Verify,
            "database TLS mode",
            &mut problems,
        );
        let database_tls_ca_file = parse_optional_string(
            DATABASE_TLS_CA_FILE,
            get_var(DATABASE_TLS_CA_FILE),
            &mut problems,
        );
        let database_pool_max = validate_positive_bounded_u64(
            DATABASE_POOL_MAX,
            parse_var(
                DATABASE_POOL_MAX,
                get_var(DATABASE_POOL_MAX),
                DEFAULT_DATABASE_POOL_MAX as u64,
                "connection count",
                &mut problems,
            ),
            MAX_DATABASE_POOL_MAX as u64,
            DEFAULT_DATABASE_POOL_MAX as u64,
            &mut problems,
        ) as usize;
        let database_connect_timeout_ms = validate_positive_timeout_ms(
            DATABASE_CONNECT_TIMEOUT_MS,
            parse_var(
                DATABASE_CONNECT_TIMEOUT_MS,
                get_var(DATABASE_CONNECT_TIMEOUT_MS),
                DEFAULT_DATABASE_CONNECT_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_DATABASE_CONNECT_TIMEOUT_MS,
            &mut problems,
        );
        let database_acquire_timeout_ms = validate_positive_timeout_ms(
            DATABASE_ACQUIRE_TIMEOUT_MS,
            parse_var(
                DATABASE_ACQUIRE_TIMEOUT_MS,
                get_var(DATABASE_ACQUIRE_TIMEOUT_MS),
                DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS,
            &mut problems,
        );
        let database_statement_timeout_ms = validate_positive_timeout_ms(
            DATABASE_STATEMENT_TIMEOUT_MS,
            parse_var(
                DATABASE_STATEMENT_TIMEOUT_MS,
                get_var(DATABASE_STATEMENT_TIMEOUT_MS),
                DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS,
            &mut problems,
        );
        let database_idle_in_transaction_timeout_ms = validate_positive_timeout_ms(
            DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
            parse_var(
                DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
                get_var(DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS),
                DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
            &mut problems,
        );
        let database_lock_timeout_ms = validate_positive_timeout_ms(
            DATABASE_LOCK_TIMEOUT_MS,
            parse_var(
                DATABASE_LOCK_TIMEOUT_MS,
                get_var(DATABASE_LOCK_TIMEOUT_MS),
                DEFAULT_DATABASE_LOCK_TIMEOUT_MS,
                "millisecond duration",
                &mut problems,
            ),
            DEFAULT_DATABASE_LOCK_TIMEOUT_MS,
            &mut problems,
        );
        let database_startup_retry_limit = validate_maximum_u64(
            DATABASE_STARTUP_RETRY_LIMIT,
            parse_var(
                DATABASE_STARTUP_RETRY_LIMIT,
                get_var(DATABASE_STARTUP_RETRY_LIMIT),
                DEFAULT_DATABASE_STARTUP_RETRY_LIMIT,
                "retry count",
                &mut problems,
            ),
            MAX_DATABASE_STARTUP_RETRY_LIMIT,
            DEFAULT_DATABASE_STARTUP_RETRY_LIMIT,
            &mut problems,
        );
        let database_auto_migrate = parse_var(
            DATABASE_AUTO_MIGRATE,
            get_var(DATABASE_AUTO_MIGRATE),
            false,
            "boolean",
            &mut problems,
        );
        let database_migration_statement_timeout_ms = validate_maximum_u64(
            DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
            validate_positive_timeout_ms(
                DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                parse_var(
                    DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                    get_var(DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS),
                    DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                    "millisecond duration",
                    &mut problems,
                ),
                DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                &mut problems,
            ),
            MAX_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
            DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
            &mut problems,
        );
        let database = DatabaseSettings {
            pool_max: database_pool_max,
            connect_timeout_ms: database_connect_timeout_ms,
            acquire_timeout_ms: database_acquire_timeout_ms,
            statement_timeout_ms: database_statement_timeout_ms,
            idle_in_transaction_timeout_ms: database_idle_in_transaction_timeout_ms,
            lock_timeout_ms: database_lock_timeout_ms,
            startup_retry_limit: database_startup_retry_limit,
            auto_migrate: database_auto_migrate,
            migration_statement_timeout_ms: database_migration_statement_timeout_ms,
            tls_mode: database_tls_mode,
            tls_ca_file: database_tls_ca_file.clone(),
            url_file: database_url_file.clone(),
        };
        // Postgres-mode requirements, checked after every input is parsed so
        // one pass reports every problem.
        reject_local_authority_in_postgres_mode(
            state_backend,
            deployment_id.as_deref(),
            database_url_file.as_deref(),
            &[
                (POLICY_FILE, policy_file.is_some()),
                (TOOLS_FILE, tools_file.is_some()),
                (AUDIT_SQLITE_PATH, audit_sqlite_path.is_some()),
                (DISCOVERY_SQLITE_PATH, discovery_sqlite_path.is_some()),
                (PRINCIPAL_SQLITE_PATH, principal_sqlite_path.is_some()),
                (CONNECTIONS_SQLITE_PATH, connections_sqlite_path.is_some()),
                // The local secret keyring encrypts material stored in the
                // connections SQLite database, which cluster mode does not
                // have: migration 0006 deliberately omits the
                // `connection_local_secrets` table, and a cluster deployment
                // binds credentials through an external secret provider
                // instead. Naming the setting is better than failing later
                // inside the provider with "a managed store is required".
                (
                    CONNECTION_LOCAL_SECRET_KEYRING,
                    !connection_local_secret_keyring.is_empty(),
                ),
                (
                    POLICY_HISTORY_SQLITE_PATH,
                    policy_history_sqlite_path.is_some(),
                ),
                (
                    SERVICE_TOKEN_SQLITE_PATH,
                    service_token_sqlite_path.is_some(),
                ),
            ],
            &mut problems,
        );
        // PostgreSQL material configured while standalone mode is selected is
        // the inverse gap: material a mode that will never read it invites an
        // operator to believe a database is configured when none is consulted.
        // The same rule the client-certificate settings apply to a CA bundle
        // configured against an off mode, and a deployment ID names a cluster
        // namespace that does not exist in standalone mode.
        match state_backend {
            StateBackend::Postgres => {
                if admin_login_provider.is_some() && admin_login_keyring.is_empty() {
                    problems.push(format!(
                        "{ADMIN_LOGIN_KEYRING} is required when {STATE_BACKEND}=postgres and {ADMIN_LOGIN_PROVIDER} is set; pending admin logins are sealed in the database under it"
                    ));
                }
                if rate_limit_keyring.is_empty() {
                    problems.push(format!(
                        "{RATE_LIMIT_KEYRING} is required when {STATE_BACKEND}=postgres; shared rate-limit buckets are keyed by an HMAC under it"
                    ));
                }
            }
            StateBackend::Sqlite => {
                if !admin_login_keyring.is_empty() {
                    problems.push(format!(
                        "{ADMIN_LOGIN_KEYRING} is set while {STATE_BACKEND} is sqlite; standalone mode keeps pending admin logins in memory and never reads it"
                    ));
                }
                if !rate_limit_keyring.is_empty() {
                    problems.push(format!(
                        "{RATE_LIMIT_KEYRING} is set while {STATE_BACKEND} is sqlite; standalone mode keeps rate-limit buckets in memory and never reads it"
                    ));
                }
            }
        }
        if state_backend == StateBackend::Sqlite {
            if database_url_file.is_some() {
                problems.push(format!(
                    "{DATABASE_URL_FILE} is set while {STATE_BACKEND} is sqlite; set {STATE_BACKEND}=postgres to use PostgreSQL, or unset {DATABASE_URL_FILE}"
                ));
            }
            if database_tls_ca_file.is_some() {
                problems.push(format!(
                    "{DATABASE_TLS_CA_FILE} is set while {STATE_BACKEND} is sqlite; set {STATE_BACKEND}=postgres to use PostgreSQL, or unset {DATABASE_TLS_CA_FILE}"
                ));
            }
            if deployment_id.is_some() {
                problems.push(format!(
                    "{DEPLOYMENT_ID} is set while {STATE_BACKEND} is sqlite; a deployment ID scopes a cluster-mode deployment and standalone mode never reads it — set {STATE_BACKEND}=postgres or unset {DEPLOYMENT_ID}"
                ));
            }
            if database_auto_migrate {
                problems.push(format!(
                    "{DATABASE_AUTO_MIGRATE}=true while {STATE_BACKEND} is sqlite; there is no schema to migrate in standalone mode — set {STATE_BACKEND}=postgres or unset {DATABASE_AUTO_MIGRATE}"
                ));
            }
        }

        if problems.is_empty() {
            Ok(Self {
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
                admin_login_pending_ttl_secs,
                admin_login_pending_max_entries,
                admin_login_pending_max_per_ip,
                admin_login_keyring,
                rate_limit_keyring,
                gateway_public_url,
                audit_log_file,
                audit_sqlite_path,
                audit_sqlite_retention_days,
                shutdown_drain_delay_ms,
                shutdown_timeout_ms,
                audit_drain_timeout_ms,
                discovery_sqlite_path,
                discovery_endpoint_limit,
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
                database,
            })
        } else {
            Err(ConfigError { problems })
        }
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

/// One listener's resolved client-certificate authentication, paired with the
/// setting names that produced it.
///
/// Only constructible through [`compose_inbound_client_auth`], which is what
/// makes the invariant real rather than documented: a listener that asks for a
/// client certificate always has a CA bundle to verify it against and an
/// identity source to read it with, because a configuration missing either
/// fails startup instead of reaching this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InboundClientAuthSettings<'a> {
    pub(crate) mode_setting: &'static str,
    pub(crate) requirement: ClientCertRequirement,
    pub(crate) ca_setting: &'static str,
    pub(crate) ca_file: &'a str,
    pub(crate) crl_setting: &'static str,
    pub(crate) crl_file: Option<&'a str>,
    pub(crate) identity_source: ClientCertIdentitySource,
}

/// The parsed, validated client-certificate settings for one listener.
///
/// See [`Config::client_cert_auth`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundClientAuthConfig {
    pub mode_setting: &'static str,
    pub requirement: ClientCertRequirement,
    pub ca_setting: &'static str,
    pub ca_file: String,
    pub crl_setting: &'static str,
    pub crl_file: Option<String>,
    pub identity_source: ClientCertIdentitySource,
}

impl InboundClientAuthConfig {
    fn settings(&self) -> InboundClientAuthSettings<'_> {
        InboundClientAuthSettings {
            mode_setting: self.mode_setting,
            requirement: self.requirement,
            ca_setting: self.ca_setting,
            ca_file: &self.ca_file,
            crl_setting: self.crl_setting,
            crl_file: self.crl_file.as_deref(),
            identity_source: self.identity_source,
        }
    }
}

/// The raw, still-unchecked client-certificate inputs for one listener.
struct RawInboundClientAuth {
    mode_setting: &'static str,
    mode: ClientCertMode,
    ca_setting: &'static str,
    ca_file: Option<String>,
    crl_setting: &'static str,
    crl_file: Option<String>,
    identity_source: Option<ClientCertIdentitySource>,
    tls_certificate_setting: &'static str,
    tls_configured: bool,
}

/// Turns one listener's client-certificate settings into a configuration, or
/// into the reasons it is not one.
///
/// Every failure path returns `None` *and* records a problem, so a
/// half-configured listener aborts startup rather than silently accepting
/// anonymous connections on a listener an operator believes requires
/// certificates.
fn compose_inbound_client_auth(
    raw: RawInboundClientAuth,
    problems: &mut Vec<String>,
) -> Option<InboundClientAuthConfig> {
    let RawInboundClientAuth {
        mode_setting,
        mode,
        ca_setting,
        ca_file,
        crl_setting,
        crl_file,
        identity_source,
        tls_certificate_setting,
        tls_configured,
    } = raw;

    let Some(requirement) = mode.requirement() else {
        // Material configured against a mode that will never read it is the
        // shape that makes an operator believe mutual TLS is on.
        for (setting, value) in [(ca_setting, &ca_file), (crl_setting, &crl_file)] {
            if value.is_some() {
                problems.push(format!(
                    "{setting} is set while {mode_setting} is `off`; set {mode_setting} to `optional` or `required`, or unset {setting}"
                ));
            }
        }
        return None;
    };

    let mut usable = true;
    if !tls_configured {
        problems.push(format!(
            "{mode_setting} requires {tls_certificate_setting}; a listener that terminates no TLS never sees a client certificate"
        ));
        usable = false;
    }
    // Fail closed on the trust anchors. Falling back to the platform trust
    // store here would mean any certificate any public CA has ever issued
    // authenticates, which is never what configuring client certificates
    // means.
    let Some(ca_file) = ca_file else {
        problems.push(format!(
            "{mode_setting} requires {ca_setting}; client certificates are verified only against an explicitly configured CA bundle, never the platform trust store"
        ));
        return None;
    };
    let Some(identity_source) = identity_source else {
        problems.push(format!(
            "{mode_setting} requires CLIENT_CERT_IDENTITY_SOURCE; the certificate field that carries a caller's identity is a deployment decision the gateway will not guess"
        ));
        return None;
    };
    if !usable {
        return None;
    }

    Some(InboundClientAuthConfig {
        mode_setting,
        requirement,
        ca_setting,
        ca_file,
        crl_setting,
        crl_file,
        identity_source,
    })
}

fn require_inbound_tls_pair(
    certificate_setting: &str,
    certificate_files: Option<&[String]>,
    private_key_setting: &str,
    private_key_files: Option<&[String]>,
    problems: &mut Vec<String>,
) {
    match (certificate_files, private_key_files) {
        (Some(_), None) => problems.push(format!(
            "{certificate_setting} is set without {private_key_setting}; set both to terminate TLS on this listener, or neither to serve it in plaintext"
        )),
        (None, Some(_)) => problems.push(format!(
            "{private_key_setting} is set without {certificate_setting}; set both to terminate TLS on this listener, or neither to serve it in plaintext"
        )),
        (Some(certificates), Some(keys)) if certificates.len() != keys.len() => {
            problems.push(format!(
                "{certificate_setting} lists {} certificate file(s) but {private_key_setting} lists {} key file(s); the two lists are paired by position, so they must name one key per certificate chain",
                certificates.len(),
                keys.len()
            ));
        }
        (Some(_), Some(_)) | (None, None) => {}
    }
}

/// Splits one of the inbound TLS material settings into its file list.
///
/// The value grammar is one or more comma-separated paths: a single path is the
/// #327 shape unchanged, and additional entries turn on SNI selection in
/// position order. An empty entry is a startup failure rather than something to
/// skip, because a skipped entry would silently shift every later pairing by
/// one and hand one chain another chain's key.
fn parse_material_file_list(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<Vec<String>> {
    let value = parse_optional_string(name, value, problems)?;
    let files = value
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if files.iter().any(String::is_empty) {
        problems.push(format!(
            "{name} must be a comma-separated list of file paths with no empty entry; an empty entry would shift every later certificate/key pairing by one"
        ));
        return None;
    }
    Some(files)
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration is invalid:")?;
        for problem in &self.problems {
            write!(f, "\n- {problem}")?;
        }
        Ok(())
    }
}

impl Error for ConfigError {}

fn validate_finite_non_negative(
    name: &str,
    value: f64,
    default: f64,
    problems: &mut Vec<String>,
) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        problems.push(format!(
            "{name} must be a finite non-negative requests-per-second value, got '{value}'"
        ));
        default
    }
}

fn validate_payload_capture_sample_rate(
    name: &str,
    value: f64,
    default: f64,
    problems: &mut Vec<String>,
) -> f64 {
    if value.is_finite() && (0.0..1.0).contains(&value) {
        value
    } else {
        problems.push(format!(
            "{name} must be a finite number greater than or equal to 0.0 and less than 1.0, got '{value}'"
        ));
        default
    }
}

/// The JWKS maximum key age must be positive and at most a day: zero would
/// distrust every fetch instantly, and more than a day would honour a
/// withdrawn signing key for longer than any rotation window.
fn validate_jwks_max_key_age(name: &str, value: u64, problems: &mut Vec<String>) -> u64 {
    if (crate::auth::jwt::MIN_JWKS_KEY_AGE_SECS_LIMIT
        ..=crate::auth::jwt::MAX_JWKS_KEY_AGE_SECS_LIMIT)
        .contains(&value)
    {
        value
    } else {
        problems.push(format!(
            "{name} must be between {} and {} seconds, got '{value}'",
            crate::auth::jwt::MIN_JWKS_KEY_AGE_SECS_LIMIT,
            crate::auth::jwt::MAX_JWKS_KEY_AGE_SECS_LIMIT
        ));
        DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS
    }
}

#[cfg(test)]
mod jwks_key_age_bound_tests {
    use super::{validate_jwks_max_key_age, DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS};

    /// A key age below the demand-refresh throttle is rejected: a set that
    /// went stale sooner could not refresh on demand, and every request
    /// would fail closed against a reachable issuer until the throttle
    /// window passed.
    #[test]
    fn a_key_age_below_the_demand_floor_is_rejected() {
        let mut problems = Vec::new();
        let value = validate_jwks_max_key_age("JWT_JWKS_MAX_KEY_AGE_SECS", 5, &mut problems);
        assert_eq!(value, DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("between 10 and 86400"),
            "the problem names the floor: {}",
            problems[0]
        );

        let mut problems = Vec::new();
        assert_eq!(
            validate_jwks_max_key_age("JWT_JWKS_MAX_KEY_AGE_SECS", 10, &mut problems),
            10,
            "the floor itself is accepted"
        );
        assert!(problems.is_empty(), "{problems:?}");
    }
}

fn validate_positive_u64(name: &str, value: u64, default: u64, problems: &mut Vec<String>) -> u64 {
    if value > 0 {
        value
    } else {
        problems.push(format!("{name} must be greater than 0, got '{value}'"));
        default
    }
}

/// Shared rejection message for a zero millisecond timeout.
///
/// A refused value aborts startup, and that message is often the operator's
/// only diagnostic, so it names the setting, the accepted range, and the reason.
fn zero_timeout_problem(name: &str, value: u64) -> String {
    format!(
        "{name} must be greater than 0, got '{value}'; a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout"
    )
}

/// Reject a zero millisecond timeout for a global setting with a default.
///
/// The per-route equivalents (`UPSTREAM_ROUTES[i].timeout_ms` and friends)
/// already reject `0` through `validate_optional_positive_duration`; this gives
/// the global settings that override them the same answer instead of booting
/// clean into a permanent timeout.
/// Clamps an inclusive numeric range, reporting rather than silently accepting.
fn validate_range_u32(
    name: &str,
    value: u32,
    minimum: u32,
    maximum: u32,
    default: u32,
    problems: &mut Vec<String>,
) -> u32 {
    if (minimum..=maximum).contains(&value) {
        value
    } else {
        problems.push(format!(
            "{name} must be between {minimum} and {maximum}, got {value}"
        ));
        default
    }
}

fn validate_positive_timeout_ms(
    name: &str,
    value: u64,
    default: u64,
    problems: &mut Vec<String>,
) -> u64 {
    if value > 0 {
        value
    } else {
        problems.push(zero_timeout_problem(name, value));
        default
    }
}

/// Reject a zero millisecond timeout for an optional global override.
fn validate_optional_positive_timeout_ms(
    name: &str,
    value: Option<u64>,
    problems: &mut Vec<String>,
) -> Option<u64> {
    match value {
        Some(0) => {
            problems.push(zero_timeout_problem(name, 0));
            None
        }
        other => other,
    }
}

/// The widest audit retention window that is a real setting rather than a typo.
///
/// A hundred years. Beyond this the window reaches past the earliest instant
/// `time` can represent, and the prune cutoff cannot be computed at all. No
/// working deployment is rejected by this bound: a value above it already took
/// the audit flusher thread down sixty seconds after startup, so any
/// configuration it refuses is one that was already failing.
pub const MAX_AUDIT_SQLITE_RETENTION_DAYS: u32 = 36_500;

/// Fold `AUDIT_SQLITE_RETENTION_DAYS=0` into the same "no pruning" state an
/// empty value produces.
///
/// Read literally, a zero-day window means "retain nothing": the prune cutoff
/// becomes the current instant, so the next prune tick deletes every audit row
/// the database holds, silently and on a 60-second repeat. No operator
/// configures a SQLite audit store in order to keep nothing in it; `0` is
/// written to mean "no retention limit", which is what leaving the variable
/// empty already does. Reinterpreting is also the safe upgrade: rejecting `0`
/// would abort the boot of a deployment that is running with the value today.
fn normalize_audit_sqlite_retention_days(
    name: &str,
    value: Option<u32>,
    problems: &mut Vec<String>,
) -> Option<u32> {
    if let Some(days) = value {
        if days > MAX_AUDIT_SQLITE_RETENTION_DAYS {
            problems.push(format!(
                "{name} must be at most {MAX_AUDIT_SQLITE_RETENTION_DAYS}, got '{days}'"
            ));
            return None;
        }
    }
    match value {
        Some(0) => {
            tracing::warn!(
                setting = name,
                "audit SQLite retention of 0 days is treated as disabled pruning; set a positive day count to prune, or leave the variable empty"
            );
            None
        }
        other => other,
    }
}

fn validate_maximum_u64(
    name: &str,
    value: u64,
    maximum: u64,
    default: u64,
    problems: &mut Vec<String>,
) -> u64 {
    if value <= maximum {
        value
    } else {
        problems.push(format!("{name} must be at most {maximum}, got '{value}'"));
        default
    }
}

fn validate_positive_bounded_u64(
    name: &str,
    value: u64,
    maximum: u64,
    default: u64,
    problems: &mut Vec<String>,
) -> u64 {
    if (1..=maximum).contains(&value) {
        value
    } else {
        problems.push(format!(
            "{name} must be between 1 and {maximum}, got '{value}'"
        ));
        default
    }
}

fn validate_positive_usize(
    name: &str,
    value: usize,
    default: usize,
    problems: &mut Vec<String>,
) -> usize {
    if value > 0 {
        value
    } else {
        problems.push(format!("{name} must be greater than 0, got '{value}'"));
        default
    }
}

fn validate_signal_ratio_threshold(
    name: &str,
    value: f64,
    default: f64,
    problems: &mut Vec<String>,
) -> f64 {
    if value.is_finite() && value > 0.0 && value <= 1.0 {
        value
    } else {
        problems.push(format!(
            "{name} must be a finite number greater than 0.0 and less than or equal to 1.0, got '{value}'"
        ));
        default
    }
}

fn validate_signal_multiple_threshold(
    name: &str,
    value: f64,
    default: f64,
    problems: &mut Vec<String>,
) -> f64 {
    if value.is_finite() && value > 1.0 {
        value
    } else {
        problems.push(format!(
            "{name} must be a finite number greater than 1.0, got '{value}'"
        ));
        default
    }
}

fn validate_rule_suggestion_baseline_window_hours(
    name: &str,
    value: u64,
    default: u64,
    problems: &mut Vec<String>,
) -> u64 {
    if (1..=MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS).contains(&value) {
        value
    } else {
        problems.push(format!(
            "{name} must be between 1 and {MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS}, got '{value}'"
        ));
        default
    }
}

fn parse_var<T>(
    name: &str,
    value: Result<String, VarError>,
    default: T,
    expected: &str,
    problems: &mut Vec<String>,
) -> T
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return default,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return default;
        }
    };

    match value.parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid {expected}, got '{value}': {err}"
            ));
            default
        }
    }
}

fn parse_optional_string(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return None;
        }
    };

    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn parse_auth_providers(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<Vec<AuthProviderConfig>> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Some(Vec::new());
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let providers = match serde_json::from_str::<Vec<RawAuthProviderConfig>>(value) {
        Ok(providers) => providers,
        Err(err) => {
            problems.push(format!(
                "{name} must be a JSON array of auth provider objects with name, type, and provider-specific fields: jwt uses jwks_url or issuer; cookie_session uses introspection_url and user_id_claim: {err}"
            ));
            return Some(Vec::new());
        }
    };

    Some(validate_auth_providers(name, providers, problems))
}

fn validate_auth_providers(
    name: &str,
    providers: Vec<RawAuthProviderConfig>,
    problems: &mut Vec<String>,
) -> Vec<AuthProviderConfig> {
    let jwt_provider_indices = providers
        .iter()
        .enumerate()
        .filter_map(|(index, provider)| (provider.provider_type.trim() == "jwt").then_some(index))
        .collect::<Vec<_>>();
    let mut validated = Vec::with_capacity(providers.len());
    let mut seen_names = HashMap::<String, usize>::new();

    for (index, provider) in providers.into_iter().enumerate() {
        let provider_name = format!("{name}[{index}]");
        let normalized_name = provider.name.trim().to_owned();
        if normalized_name.is_empty() {
            problems.push(format!("{provider_name}.name must be a non-empty string"));
        } else if let Some(previous_index) = seen_names.insert(normalized_name.clone(), index) {
            problems.push(format!(
                "{provider_name}.name duplicates {name}[{previous_index}].name"
            ));
        }

        let provider_type = match provider.provider_type.trim() {
            "jwt" => AuthProviderType::Jwt,
            "cookie_session" => AuthProviderType::CookieSession,
            value => {
                problems.push(format!(
                    "{provider_name}.type must be 'jwt' or 'cookie_session', got '{value}'"
                ));
                AuthProviderType::Jwt
            }
        };
        let roles_claim = normalize_auth_provider_roles_claim(
            &format!("{provider_name}.roles_claim"),
            provider.roles_claim,
            problems,
        );
        let roles_claim_delimiter =
            normalize_auth_provider_roles_claim_delimiter(provider.roles_claim_delimiter);
        let org_claim = normalize_optional_config_string(provider.org_claim);

        let mut jwks_url = None;
        let mut issuer = None;
        let mut audience = None;
        let mut jwks_timeout_ms = DEFAULT_JWT_JWKS_TIMEOUT_MS;
        let mut jwks_max_key_age_secs = DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS;
        let mut require_jti = false;
        let mut introspection_url = None;
        let mut introspection_timeout_ms = DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS;
        let mut cache_ttl_ms = DEFAULT_COOKIE_SESSION_CACHE_TTL_MS;
        let mut user_id_claim = None;
        let mut email_claim = None;
        let client_id = normalize_optional_config_string(provider.client_id);
        let client_secret = normalize_optional_config_string(provider.client_secret);
        let redirect_uri = normalize_optional_config_string(provider.redirect_uri);

        match provider_type {
            AuthProviderType::Jwt => {
                jwks_url = normalize_optional_config_string(provider.jwks_url);
                issuer = match provider.issuer.as_deref() {
                    Some(raw_issuer) => match canonical_issuer(raw_issuer) {
                        Some(canonical_issuer) => Some(canonical_issuer),
                        None => {
                            problems.push(format!(
                                "{provider_name}.issuer must be non-empty after trimming whitespace and trailing slashes"
                            ));
                            None
                        }
                    },
                    None => None,
                };
                if issuer
                    .as_deref()
                    .is_some_and(|issuer| issuer.starts_with(PROVIDER_ISSUER_PREFIX))
                {
                    problems.push(format!(
                        "{provider_name}.issuer must not use reserved prefix '{PROVIDER_ISSUER_PREFIX}'"
                    ));
                }
                audience = normalize_optional_config_string(provider.audience);
                jwks_timeout_ms = provider
                    .jwks_timeout_ms
                    .unwrap_or(DEFAULT_JWT_JWKS_TIMEOUT_MS);
                jwks_max_key_age_secs = validate_jwks_max_key_age(
                    &format!("{provider_name}.jwks_max_key_age_secs"),
                    provider
                        .jwks_max_key_age_secs
                        .unwrap_or(DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS),
                    problems,
                );
                require_jti = provider.require_jti;
                if jwks_url.is_none() && issuer.is_none() {
                    problems.push(format!(
                        "{provider_name} must set jwks_url or issuer for jwt providers"
                    ));
                }
            }
            AuthProviderType::CookieSession => {
                introspection_url = normalize_optional_config_string(provider.introspection_url);
                if introspection_url.is_none() {
                    problems.push(format!("{provider_name} must set introspection_url"));
                }
                introspection_timeout_ms = validate_auth_provider_positive_u64(
                    &format!("{provider_name}.introspection_timeout_ms"),
                    provider.introspection_timeout_ms,
                    DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                    problems,
                );
                cache_ttl_ms = validate_auth_provider_positive_u64(
                    &format!("{provider_name}.cache_ttl_ms"),
                    provider.cache_ttl_ms,
                    DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                    problems,
                );
                user_id_claim = normalize_required_auth_provider_string(
                    &format!("{provider_name}.user_id_claim"),
                    provider.user_id_claim,
                    problems,
                );
                email_claim = normalize_optional_config_string(provider.email_claim);
            }
        }

        validated.push(AuthProviderConfig {
            name: normalized_name,
            provider_type,
            jwks_url,
            issuer,
            audience,
            jwks_timeout_ms,
            jwks_max_key_age_secs,
            require_jti,
            roles_claim,
            roles_claim_delimiter,
            org_claim,
            introspection_url,
            introspection_timeout_ms,
            cache_ttl_ms,
            user_id_claim,
            email_claim,
            client_id,
            client_secret,
            redirect_uri,
        });
    }

    if jwt_provider_indices.len() > 1 {
        for index in jwt_provider_indices {
            if validated[index].issuer.is_none() {
                problems.push(format!(
                    "{name}[{index}].issuer must be explicitly configured when more than one JWT provider is configured"
                ));
            }
        }
    }

    let mut seen_effective_issuers = HashMap::<String, usize>::new();
    for (index, provider) in validated.iter().enumerate() {
        let effective_issuer = provider
            .issuer
            .clone()
            .unwrap_or_else(|| provider_issuer(&provider.name));
        if let Some(previous_index) = seen_effective_issuers.insert(effective_issuer.clone(), index)
        {
            if validated[previous_index].name == provider.name {
                continue;
            }
            problems.push(format!(
                "{name}[{index}] effective issuer '{effective_issuer}' duplicates {name}[{previous_index}]"
            ));
        }
    }

    validated
}

fn validate_admin_login_provider(
    admin_login_provider: Option<&str>,
    providers: &[AuthProviderConfig],
    problems: &mut Vec<String>,
) {
    let Some(provider_name) = admin_login_provider else {
        return;
    };

    let Some(provider) = providers
        .iter()
        .find(|provider| provider.name == provider_name)
    else {
        problems.push(format!(
            "{ADMIN_LOGIN_PROVIDER} references unknown auth provider '{provider_name}'"
        ));
        return;
    };

    if provider.provider_type != AuthProviderType::Jwt {
        problems.push(format!(
            "{ADMIN_LOGIN_PROVIDER} references provider '{provider_name}' which must be type 'jwt'"
        ));
    }
    for (field_name, value) in [
        ("client_id", &provider.client_id),
        ("client_secret", &provider.client_secret),
        ("redirect_uri", &provider.redirect_uri),
    ] {
        if value.as_deref().is_none_or(str::is_empty) {
            problems.push(format!(
                "{ADMIN_LOGIN_PROVIDER} provider '{provider_name}' must set {field_name}"
            ));
        }
    }
    if provider.issuer.as_deref().is_none_or(str::is_empty) {
        problems.push(format!(
            "{ADMIN_LOGIN_PROVIDER} provider '{provider_name}' must set issuer for OIDC discovery"
        ));
    }
}

fn normalize_optional_config_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalize_auth_provider_roles_claim(
    name: &str,
    value: Option<String>,
    problems: &mut Vec<String>,
) -> String {
    match value.map(|value| value.trim().to_owned()) {
        Some(value) if value.is_empty() => {
            problems.push(format!("{name} must be a non-empty string"));
            DEFAULT_ROLES_CLAIM.to_owned()
        }
        Some(value) => value,
        None => DEFAULT_ROLES_CLAIM.to_owned(),
    }
}

fn normalize_auth_provider_roles_claim_delimiter(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn normalize_required_auth_provider_string(
    name: &str,
    value: Option<String>,
    problems: &mut Vec<String>,
) -> Option<String> {
    match value.map(|value| value.trim().to_owned()) {
        Some(value) if value.is_empty() => {
            problems.push(format!("{name} must be a non-empty string"));
            None
        }
        Some(value) => Some(value),
        None => {
            problems.push(format!("{name} must be a non-empty string"));
            None
        }
    }
}

fn validate_auth_provider_positive_u64(
    name: &str,
    value: Option<u64>,
    default: u64,
    problems: &mut Vec<String>,
) -> u64 {
    match value {
        Some(0) => {
            problems.push(format!("{name} must be greater than 0"));
            default
        }
        Some(value) => value,
        None => default,
    }
}

fn legacy_auth_providers(
    jwt_jwks_url: Option<&str>,
    jwt_issuer: Option<&str>,
    jwt_audience: Option<&str>,
    jwt_jwks_timeout_ms: u64,
    jwt_jwks_max_key_age_secs: u64,
    jwt_require_jti: bool,
    roles_claim: &str,
) -> Vec<AuthProviderConfig> {
    let Some(jwks_url) = jwt_jwks_url else {
        return Vec::new();
    };

    vec![AuthProviderConfig {
        name: "legacy".to_owned(),
        provider_type: AuthProviderType::Jwt,
        jwks_url: Some(jwks_url.to_owned()),
        issuer: jwt_issuer.map(str::to_owned),
        audience: jwt_audience.map(str::to_owned),
        jwks_timeout_ms: jwt_jwks_timeout_ms,
        jwks_max_key_age_secs: jwt_jwks_max_key_age_secs,
        require_jti: jwt_require_jti,
        roles_claim: roles_claim.to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }]
}

fn parse_optional_path(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<PathBuf> {
    parse_optional_string(name, value, problems).map(PathBuf::from)
}

fn parse_optional_var<T>(
    name: &str,
    value: Result<String, VarError>,
    expected: &str,
    problems: &mut Vec<String>,
) -> Option<T>
where
    T: Default + FromStr,
    T::Err: fmt::Display,
{
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return None;
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let problem_count = problems.len();
    let parsed = parse_var(name, Ok(value.to_owned()), T::default(), expected, problems);

    if problems.len() == problem_count {
        Some(parsed)
    } else {
        None
    }
}

fn parse_optional_socket_addr(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<SocketAddr> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return None;
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    match value.parse() {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid socket address, got '{value}': {err}"
            ));
            None
        }
    }
}

fn parse_non_empty_string(
    name: &str,
    value: Result<String, VarError>,
    default: &str,
    problems: &mut Vec<String>,
) -> String {
    let parsed = parse_var(name, value, default.to_owned(), "string", problems);
    let parsed = parsed.trim();

    if parsed.is_empty() {
        problems.push(format!("{name} must be a non-empty string"));
        default.to_owned()
    } else {
        parsed.to_owned()
    }
}

fn parse_admin_prefix(
    name: &str,
    value: Result<String, VarError>,
    default: &str,
    problems: &mut Vec<String>,
) -> String {
    let parsed = parse_var(name, value, default.to_owned(), "URI path prefix", problems);
    let parsed = parsed.trim();

    if is_valid_admin_prefix(parsed) {
        parsed.to_owned()
    } else {
        problems.push(format!(
            "{name} must be a non-root URI path prefix starting with '/' and containing only path segments made of ASCII letters, digits, '.', '-', '_', or '~', got '{parsed}'"
        ));
        default.to_owned()
    }
}

fn parse_comma_separated_header_values(
    name: &str,
    value: Result<String, VarError>,
    default: &[&str],
    problems: &mut Vec<String>,
) -> Vec<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => {
            return default.iter().map(|value| (*value).to_owned()).collect()
        }
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return default.iter().map(|value| (*value).to_owned()).collect();
        }
    };

    let mut values = Vec::new();

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        match entry.parse::<HeaderValue>() {
            Ok(_) => values.push(entry.to_owned()),
            Err(err) => problems.push(format!(
                "{name} entries must be valid HTTP header values, got '{entry}': {err}"
            )),
        }
    }

    values
}

/// Rejects a wildcard CORS origin at startup instead of letting it reach the
/// router.
///
/// `*` is a valid HTTP header value, so it survives entry validation and then
/// panics inside `tower-http`, which refuses a wildcard in an origin list. It
/// could not have worked in any case: the gateway answers with
/// `Access-Control-Allow-Credentials: true`, and browsers reject a credentialed
/// response whose allowed origin is `*`.
fn validate_cors_allow_origins(
    name: &str,
    origins: Vec<String>,
    problems: &mut Vec<String>,
) -> Vec<String> {
    let mut validated = Vec::with_capacity(origins.len());

    for origin in origins {
        if origin == "*" {
            problems.push(format!(
                "{name} entries must be exact origins; wildcard origin '{origin}' is not allowed with credentialed CORS"
            ));
            continue;
        }
        validated.push(origin);
    }

    validated
}

fn parse_comma_separated_hostnames(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Vec::new();
        }
    };

    let mut values = Vec::new();

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let entry = entry.to_ascii_lowercase();

        if is_valid_hostname_without_port(&entry) {
            values.push(entry);
        } else {
            problems.push(format!(
                "{name} entries must be hostnames without ports, got '{entry}'"
            ));
        }
    }

    values
}

fn parse_comma_separated_cidrs(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<IpNet> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Vec::new();
        }
    };

    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| match entry.parse::<IpNet>() {
            Ok(cidr) if cidr.prefix_len() == 0 => {
                problems.push(format!(
                    "{name} entries must identify bounded proxy networks; catch-all CIDR '{entry}' is not allowed"
                ));
                None
            }
            Ok(cidr) => Some(cidr),
            Err(err) => {
                problems.push(format!(
                    "{name} entries must be valid CIDRs, got '{entry}': {err}"
                ));
                None
            }
        })
        .collect()
}

fn parse_nat64_prefixes(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<IpNet> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Vec::new();
        }
    };

    let mut prefixes = Vec::<IpNet>::new();

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let prefix = match entry.parse::<IpNet>() {
            Ok(IpNet::V6(prefix)) if matches!(prefix.prefix_len(), 32 | 40 | 48 | 56 | 64 | 96) => {
                IpNet::V6(prefix)
            }
            Ok(IpNet::V6(prefix)) => {
                problems.push(format!(
                    "{name} entries must use an RFC 6052 prefix length of 32, 40, 48, 56, 64, or 96, got '/{}' in '{entry}'",
                    prefix.prefix_len()
                ));
                continue;
            }
            Ok(IpNet::V4(_)) => {
                problems.push(format!(
                    "{name} entries must be IPv6 CIDR prefixes, got '{entry}'"
                ));
                continue;
            }
            Err(err) => {
                problems.push(format!(
                    "{name} entries must be valid IPv6 CIDR prefixes, got '{entry}': {err}"
                ));
                continue;
            }
        };

        let IpNet::V6(ipv6_prefix) = &prefix else {
            unreachable!("IPv4 NAT64 prefixes are rejected above");
        };
        if ipv6_prefix.network().octets()[8] != 0 {
            problems.push(format!(
                "{name} entries must use a zero RFC 6052 u octet, got '{entry}'"
            ));
            continue;
        }

        if WELL_KNOWN_NAT64_PREFIX.contains(&prefix.network())
            || prefix.contains(&WELL_KNOWN_NAT64_PREFIX.network())
        {
            problems.push(format!(
                "{name} entries must not overlap the built-in well-known NAT64 prefix 64:ff9b::/96, got '{prefix}'"
            ));
            continue;
        }

        if let Some(existing) = prefixes.iter().find(|existing| {
            existing.contains(&prefix.network()) || prefix.contains(&existing.network())
        }) {
            problems.push(format!(
                "{name} entries must not overlap, got '{prefix}' and '{existing}'"
            ));
            continue;
        }

        prefixes.push(prefix);
    }

    prefixes
}

fn parse_cookie_name(
    name: &str,
    value: Result<String, VarError>,
    default: &str,
    problems: &mut Vec<String>,
) -> String {
    let parsed = parse_var(name, value, default.to_owned(), "cookie name", problems);

    if is_valid_cookie_name(&parsed) {
        parsed
    } else {
        problems.push(format!(
            "{name} must be a non-empty RFC 6265 cookie name, got '{parsed}'"
        ));
        default.to_owned()
    }
}

fn parse_header_name_string(
    name: &str,
    value: Result<String, VarError>,
    default: &str,
    problems: &mut Vec<String>,
) -> String {
    let parsed = parse_var(
        name,
        value,
        default.to_owned(),
        "HTTP header name",
        problems,
    );

    match HeaderName::from_bytes(parsed.as_bytes()) {
        Ok(header_name) => header_name.as_str().to_owned(),
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid HTTP header name, got '{parsed}': {err}"
            ));
            default.to_owned()
        }
    }
}

fn parse_optional_cookie_domain(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return None;
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if is_valid_cookie_domain(value) {
        Some(value.to_owned())
    } else {
        problems.push(format!(
            "{name} must be a valid cookie Domain attribute, got '{value}'"
        ));
        None
    }
}

fn parse_optional_upstream_url(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return None;
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    validate_upstream_url(name, value, problems)
}

fn parse_optional_gateway_public_url(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = parse_optional_upstream_url(name, value, problems)?;
    let parsed = url::Url::parse(&value).expect("gateway public URL should have been validated");

    if parsed.fragment().is_some() {
        problems.push(format!(
            "{name} must not include a URL fragment, got '{value}'"
        ));
        None
    } else if parsed.scheme() == "http" && !url_host_is_loopback(&parsed) {
        problems.push(format!(
            "{name} must use https unless the host is loopback, got '{value}'"
        ));
        None
    } else {
        Some(value)
    }
}

fn url_host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped_ip| mapped_ip.is_loopback())
        }
        None => false,
    }
}

fn parse_operator_secret_aliases(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<OperatorSecretAliasConfig> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return Vec::new();
        }
    };
    if value.len() > MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES} bytes"
        ));
        return Vec::new();
    }
    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        problems.push(format!(
            "{name} must be a JSON array of operator alias objects with id, label, and a typed environment/file source (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        Vec::new()
    })
}

fn parse_vault_provider_config(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> VaultProviderConfig {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return VaultProviderConfig::default(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return VaultProviderConfig::default();
        }
    };
    if value.len() > MAX_VAULT_PROVIDER_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_VAULT_PROVIDER_CONFIG_BYTES} bytes"
        ));
        return VaultProviderConfig::default();
    }
    let value = value.trim();
    if value.is_empty() {
        return VaultProviderConfig::default();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        // Position only. serde echoes the offending scalar in its message, and
        // this string reaches stderr at startup, so interpolating the error
        // would print operator secret locators into container logs.
        problems.push(format!(
            "{name} must be a JSON object with profiles and aliases arrays (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        VaultProviderConfig::default()
    })
}

fn parse_gcp_provider_config(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> GcpProviderConfig {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return GcpProviderConfig::default(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return GcpProviderConfig::default();
        }
    };
    if value.len() > MAX_GCP_PROVIDER_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_GCP_PROVIDER_CONFIG_BYTES} bytes"
        ));
        return GcpProviderConfig::default();
    }
    let value = value.trim();
    if value.is_empty() {
        return GcpProviderConfig::default();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        // Position only. serde echoes the offending scalar in its message, and
        // this string reaches stderr at startup, so interpolating the error
        // would print operator secret locators into container logs.
        problems.push(format!(
            "{name} must be a JSON object with profiles and aliases arrays (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        GcpProviderConfig::default()
    })
}

fn parse_azure_provider_config(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> AzureProviderConfig {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return AzureProviderConfig::default(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return AzureProviderConfig::default();
        }
    };
    if value.len() > MAX_AZURE_PROVIDER_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_AZURE_PROVIDER_CONFIG_BYTES} bytes"
        ));
        return AzureProviderConfig::default();
    }
    let value = value.trim();
    if value.is_empty() {
        return AzureProviderConfig::default();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        // Position only. serde echoes the offending scalar in its message, and
        // this string reaches stderr at startup, so interpolating the error
        // would print operator secret locators into container logs.
        problems.push(format!(
            "{name} must be a JSON object with profiles and aliases arrays (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        AzureProviderConfig::default()
    })
}

fn parse_aws_provider_config(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> AwsProviderConfig {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return AwsProviderConfig::default(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return AwsProviderConfig::default();
        }
    };
    if value.len() > MAX_AWS_PROVIDER_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_AWS_PROVIDER_CONFIG_BYTES} bytes"
        ));
        return AwsProviderConfig::default();
    }
    let value = value.trim();
    if value.is_empty() {
        return AwsProviderConfig::default();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        // Position only. serde echoes the offending scalar in its message, and
        // this string reaches stderr at startup, so interpolating the error
        // would print operator secret locators into container logs.
        problems.push(format!(
            "{name} must be a JSON object with profiles and aliases arrays (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        AwsProviderConfig::default()
    })
}

fn parse_kubernetes_provider_config(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> KubernetesProviderConfig {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return KubernetesProviderConfig::default(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return KubernetesProviderConfig::default();
        }
    };
    if value.len() > MAX_KUBERNETES_PROVIDER_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_KUBERNETES_PROVIDER_CONFIG_BYTES} bytes"
        ));
        return KubernetesProviderConfig::default();
    }
    let value = value.trim();
    if value.is_empty() {
        return KubernetesProviderConfig::default();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        // Position only. serde echoes the offending scalar in its message, and
        // this string reaches stderr at startup, so interpolating the error
        // would print operator secret locators into container logs.
        problems.push(format!(
            "{name} must be a JSON object with profiles and aliases arrays (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        KubernetesProviderConfig::default()
    })
}

fn parse_local_secret_keyring(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<LocalSecretKeyConfig> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            return Vec::new();
        }
    };
    if value.len() > MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES {
        problems.push(format!(
            "{name} must contain at most {MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES} bytes"
        ));
        return Vec::new();
    }
    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }
    serde_json::from_str(value).unwrap_or_else(|error| {
        problems.push(format!(
            "{name} must be a JSON array of local key objects with id, file, and role (invalid shape at line {} column {})",
            error.line(),
            error.column()
        ));
        Vec::new()
    })
}

fn parse_optional_secret_root(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Option<SecretRootConfig> {
    match value {
        Ok(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| SecretRootConfig::new(PathBuf::from(value)))
        }
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => {
            problems.push(format!("{name} must be valid Unicode"));
            None
        }
    }
}

fn parse_upstream_routes(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<UpstreamRouteConfig> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Vec::new();
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }

    let routes = match serde_json::from_str::<Vec<UpstreamRouteConfig>>(value) {
        Ok(routes) => routes,
        Err(err) => {
            problems.push(format!(
                "{name} must be a JSON array of route objects with optional path_prefix/host and exactly one of upstream_url or upstreams: {err}"
            ));
            return Vec::new();
        }
    };

    validate_upstream_routes(name, routes, problems)
}

fn parse_mcp_upstream_servers(
    name: &str,
    value: Result<String, VarError>,
    problems: &mut Vec<String>,
) -> Vec<McpUpstreamServerConfig> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return Vec::new(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return Vec::new();
        }
    };

    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }

    let servers = match serde_json::from_str::<Vec<McpUpstreamServerConfig>>(value) {
        Ok(servers) => servers,
        Err(err) => {
            problems.push(format!(
                "{name} must be a JSON array of MCP upstream server objects with required name and url fields plus optional timeout_ms, response_idle_timeout_ms, and connect_timeout_ms: {err}"
            ));
            return Vec::new();
        }
    };

    validate_mcp_upstream_servers(name, servers, problems)
}

fn validate_mcp_upstream_servers(
    name: &str,
    servers: Vec<McpUpstreamServerConfig>,
    problems: &mut Vec<String>,
) -> Vec<McpUpstreamServerConfig> {
    let mut validated = Vec::with_capacity(servers.len());
    let mut seen_names = HashMap::<String, usize>::new();

    for (index, server) in servers.into_iter().enumerate() {
        let server_name = format!("{name}[{index}]");
        let normalized_name = server.name.trim().to_owned();

        if normalized_name.is_empty() {
            problems.push(format!("{server_name}.name must be non-empty"));
        } else if let Some(previous_index) = seen_names.insert(normalized_name.clone(), index) {
            problems.push(format!(
                "{server_name}.name duplicates {name}[{previous_index}].name"
            ));
        }

        let url = validate_upstream_url(&format!("{server_name}.url"), &server.url, problems)
            .unwrap_or_else(|| server.url.trim().to_owned());
        validate_optional_positive_duration(
            &format!("{server_name}.timeout_ms"),
            server.timeout_ms,
            problems,
        );
        validate_optional_positive_duration(
            &format!("{server_name}.response_idle_timeout_ms"),
            server.response_idle_timeout_ms,
            problems,
        );
        validate_optional_positive_duration(
            &format!("{server_name}.connect_timeout_ms"),
            server.connect_timeout_ms,
            problems,
        );

        validated.push(McpUpstreamServerConfig {
            name: normalized_name,
            url,
            timeout_ms: server.timeout_ms,
            response_idle_timeout_ms: server.response_idle_timeout_ms,
            connect_timeout_ms: server.connect_timeout_ms,
        });
    }

    validated
}

fn validate_optional_positive_duration(name: &str, value: Option<u64>, problems: &mut Vec<String>) {
    if matches!(value, Some(0)) {
        problems.push(format!("{name} must be greater than 0"));
    }
}

fn validate_upstream_routes(
    name: &str,
    routes: Vec<UpstreamRouteConfig>,
    problems: &mut Vec<String>,
) -> Vec<UpstreamRouteConfig> {
    const MAX_UPSTREAM_ROUTES: usize = 128;
    const MAX_ENDPOINTS_PER_ROUTE: usize = 32;
    const MAX_ENDPOINT_WEIGHT: u16 = 1_000;
    const MAX_IN_FLIGHT: usize = 4_096;
    const MAX_QUEUE_DEPTH: usize = 16_384;
    const MAX_QUEUE_TIMEOUT_MS: u64 = 60_000;

    if routes.len() > MAX_UPSTREAM_ROUTES {
        problems.push(format!(
            "{name} must contain at most {MAX_UPSTREAM_ROUTES} routes"
        ));
    }
    let mut validated = Vec::with_capacity(routes.len());
    let mut seen_matchers = HashMap::<(Option<String>, Option<String>), usize>::new();
    let mut seen_ids = HashMap::<String, usize>::new();

    for (index, mut route) in routes.into_iter().enumerate() {
        let route_name = format!("{name}[{index}]");
        let id = route
            .id
            .and_then(|id| normalize_stable_id(&format!("{route_name}.id"), &id, problems));
        if let Some(id) = id.as_ref() {
            if let Some(previous_index) = seen_ids.insert(id.clone(), index) {
                problems.push(format!(
                    "{route_name}.id duplicates {name}[{previous_index}].id"
                ));
            }
        }
        let path_prefix = normalize_route_path_prefix(
            &format!("{route_name}.path_prefix"),
            route.path_prefix,
            problems,
        );
        let host = normalize_route_host(&format!("{route_name}.host"), route.host, problems);
        let connection_id = route.connection_id.and_then(|connection_id| {
            normalize_connection_id(
                &format!("{route_name}.connection_id"),
                &connection_id,
                problems,
            )
        });
        let has_connection = connection_id.is_some();
        let has_legacy_url = !route.upstream_url.trim().is_empty();
        let has_pool = !route.upstreams.is_empty();
        if usize::from(has_connection) + usize::from(has_legacy_url) + usize::from(has_pool) != 1 {
            problems.push(format!(
                "{route_name} must set exactly one of connection_id, upstream_url, or a non-empty upstreams pool"
            ));
        }
        if (has_pool || has_connection) && id.is_none() {
            problems.push(format!(
                "{route_name}.id is required when upstreams or connection_id is configured"
            ));
        }
        if route.upstreams.len() > MAX_ENDPOINTS_PER_ROUTE {
            problems.push(format!(
                "{route_name}.upstreams must contain at most {MAX_ENDPOINTS_PER_ROUTE} endpoints"
            ));
        }

        let upstream_url = if has_legacy_url {
            validate_upstream_url(
                &format!("{route_name}.upstream_url"),
                &route.upstream_url,
                problems,
            )
            .unwrap_or_else(|| route.upstream_url.trim().to_owned())
        } else {
            String::new()
        };
        let mut seen_endpoint_ids = HashMap::<String, usize>::new();
        let upstreams = route
            .upstreams
            .into_iter()
            .enumerate()
            .map(|(endpoint_index, endpoint)| {
                let endpoint_name = format!("{route_name}.upstreams[{endpoint_index}]");
                let endpoint_id =
                    normalize_stable_id(&format!("{endpoint_name}.id"), &endpoint.id, problems)
                        .unwrap_or_else(|| endpoint.id.trim().to_owned());
                if let Some(previous_index) =
                    seen_endpoint_ids.insert(endpoint_id.clone(), endpoint_index)
                {
                    problems.push(format!(
                        "{endpoint_name}.id duplicates {route_name}.upstreams[{previous_index}].id"
                    ));
                }
                let url = validate_pool_endpoint_url(
                    &format!("{endpoint_name}.url"),
                    &endpoint.url,
                    problems,
                )
                .unwrap_or_else(|| endpoint.url.trim().to_owned());
                if endpoint.weight == 0 || endpoint.weight > MAX_ENDPOINT_WEIGHT {
                    problems.push(format!(
                        "{endpoint_name}.weight must be between 1 and {MAX_ENDPOINT_WEIGHT}"
                    ));
                }
                let tls_ca_bundle_path = normalize_route_tls_material_path(
                    &format!("{endpoint_name}.tls_ca_bundle_path"),
                    endpoint.tls_ca_bundle_path,
                    problems,
                );
                let client_identity_pem_path = normalize_client_identity_pem_path(
                    &format!("{endpoint_name}.client_identity_pem_path"),
                    endpoint.client_identity_pem_path,
                    problems,
                );
                if client_identity_pem_path.is_some()
                    && url::Url::parse(&url).is_ok_and(|url| url.scheme() != "https")
                {
                    problems.push(format!(
                        "{endpoint_name}.client_identity_pem_path requires an https endpoint URL"
                    ));
                }
                UpstreamEndpointConfig {
                    id: endpoint_id,
                    url,
                    weight: endpoint.weight,
                    tls_ca_bundle_path,
                    client_identity_pem_path,
                }
            })
            .collect::<Vec<_>>();
        let add_request_headers = normalize_route_add_request_headers(
            &format!("{route_name}.add_request_headers"),
            route.add_request_headers,
            problems,
        );
        let strip_request_headers = normalize_route_strip_request_headers(
            &format!("{route_name}.strip_request_headers"),
            route.strip_request_headers,
            &add_request_headers,
            problems,
        );
        let tls_ca_bundle_path = normalize_route_tls_material_path(
            &format!("{route_name}.tls_ca_bundle_path"),
            route.tls_ca_bundle_path,
            problems,
        );
        if has_pool && tls_ca_bundle_path.is_some() {
            problems.push(format!(
                "{route_name}.tls_ca_bundle_path must be configured per endpoint when upstreams is used"
            ));
        }
        if has_connection && tls_ca_bundle_path.is_some() {
            problems.push(format!(
                "{route_name}.tls_ca_bundle_path must not be configured with connection_id; Connection TLS is managed separately"
            ));
        }
        let openapi_spec_path = normalize_route_openapi_spec_path(
            &format!("{route_name}.openapi_spec_path"),
            route.openapi_spec_path,
            problems,
        );

        if path_prefix.is_none() && host.is_none() {
            problems.push(format!(
                "{route_name} must set at least one of path_prefix or host"
            ));
        }
        if host.is_none() && path_prefix.as_deref() == Some("/") {
            problems.push(format!(
                "{route_name}.path_prefix must not be '/' without host because it matches every request; use {UPSTREAM_URL} for the legacy catch-all proxy or add a host"
            ));
        }

        let matcher_key = (host.clone(), path_prefix.clone());
        if matcher_key.0.is_some() || matcher_key.1.is_some() {
            if let Some(previous_index) = seen_matchers.insert(matcher_key, index) {
                problems.push(format!(
                    "{route_name} duplicates {name}[{previous_index}] with the same host and path_prefix matcher"
                ));
            }
        }

        if route.limits.max_in_flight == 0 || route.limits.max_in_flight > MAX_IN_FLIGHT {
            problems.push(format!(
                "{route_name}.limits.max_in_flight must be between 1 and {MAX_IN_FLIGHT}"
            ));
        }
        if route.limits.queue_depth > MAX_QUEUE_DEPTH {
            problems.push(format!(
                "{route_name}.limits.queue_depth must be at most {MAX_QUEUE_DEPTH}"
            ));
        }
        if route.limits.queue_timeout_ms == 0
            || route.limits.queue_timeout_ms > MAX_QUEUE_TIMEOUT_MS
        {
            problems.push(format!(
                "{route_name}.limits.queue_timeout_ms must be between 1 and {MAX_QUEUE_TIMEOUT_MS}"
            ));
        }
        validate_optional_positive_duration(
            &format!("{route_name}.timeout_ms"),
            route.timeout_ms,
            problems,
        );
        validate_optional_positive_duration(
            &format!("{route_name}.response_idle_timeout_ms"),
            route.response_idle_timeout_ms,
            problems,
        );
        validate_optional_positive_duration(
            &format!("{route_name}.connect_timeout_ms"),
            route.connect_timeout_ms,
            problems,
        );
        if has_connection
            && (route.timeout_ms.is_some()
                || route.response_idle_timeout_ms.is_some()
                || route.connect_timeout_ms.is_some())
        {
            problems.push(format!(
                "{route_name} must not configure route timeout overrides with connection_id; use the stored Connection timeouts"
            ));
        }
        if let Some(sse) = route.sse.as_ref() {
            if sse.max_duration_ms > MAX_UPSTREAM_SSE_MAX_DURATION_MS {
                problems.push(format!(
                    "{route_name}.sse.max_duration_ms must be 0 (unlimited) or at most {MAX_UPSTREAM_SSE_MAX_DURATION_MS}"
                ));
            }
        }
        if let Some(health) = route.health_check.as_ref() {
            if has_connection {
                problems.push(format!(
                    "{route_name}.health_check is not supported with connection_id; use the stored Connection test profile"
                ));
            }
            if !matches!(health.method.as_str(), "GET" | "HEAD") {
                problems.push(format!(
                    "{route_name}.health_check.method must be GET or HEAD"
                ));
            }
            let valid_path = health.path.starts_with('/')
                && health.path.len() <= MAX_UPSTREAM_HEALTH_PATH_LEN
                && !health.path.contains('?')
                && !health.path.contains('#')
                && !crate::path_match::is_unsafe_request_path(&health.path);
            if !valid_path {
                problems.push(format!(
                    "{route_name}.health_check.path must be a safe absolute path of at most {MAX_UPSTREAM_HEALTH_PATH_LEN} bytes without query or fragment"
                ));
            }
            if !(MIN_UPSTREAM_HEALTH_INTERVAL_MS..=MAX_UPSTREAM_HEALTH_INTERVAL_MS)
                .contains(&health.interval_ms)
            {
                problems.push(format!(
                    "{route_name}.health_check.interval_ms must be between {MIN_UPSTREAM_HEALTH_INTERVAL_MS} and {MAX_UPSTREAM_HEALTH_INTERVAL_MS}"
                ));
            }
            if !(MIN_UPSTREAM_HEALTH_TIMEOUT_MS..=MAX_UPSTREAM_HEALTH_TIMEOUT_MS)
                .contains(&health.timeout_ms)
                || health.timeout_ms > health.interval_ms
            {
                problems.push(format!(
                    "{route_name}.health_check.timeout_ms must be between {MIN_UPSTREAM_HEALTH_TIMEOUT_MS} and {MAX_UPSTREAM_HEALTH_TIMEOUT_MS} and no greater than interval_ms"
                ));
            }
            if health.jitter_ms >= health.interval_ms {
                problems.push(format!(
                    "{route_name}.health_check.jitter_ms must be less than interval_ms"
                ));
            }
            if !(1..=MAX_UPSTREAM_HEALTH_THRESHOLD).contains(&health.healthy_threshold)
                || !(1..=MAX_UPSTREAM_HEALTH_THRESHOLD).contains(&health.unhealthy_threshold)
            {
                problems.push(format!(
                    "{route_name}.health_check thresholds must be between 1 and {MAX_UPSTREAM_HEALTH_THRESHOLD}"
                ));
            }
            if health.expected_statuses.is_empty()
                || health.expected_statuses.len() > MAX_UPSTREAM_HEALTH_STATUSES
                || health
                    .expected_statuses
                    .iter()
                    .any(|status| !(100..=599).contains(status))
                || health
                    .expected_statuses
                    .iter()
                    .collect::<HashSet<_>>()
                    .len()
                    != health.expected_statuses.len()
            {
                problems.push(format!(
                    "{route_name}.health_check.expected_statuses must contain 1-{MAX_UPSTREAM_HEALTH_STATUSES} unique HTTP statuses from 100 through 599"
                ));
            }
            if health.passive_failure_statuses.len() > MAX_UPSTREAM_HEALTH_STATUSES
                || health
                    .passive_failure_statuses
                    .iter()
                    .any(|status| !(500..=599).contains(status))
                || health
                    .passive_failure_statuses
                    .iter()
                    .collect::<HashSet<_>>()
                    .len()
                    != health.passive_failure_statuses.len()
            {
                problems.push(format!(
                    "{route_name}.health_check.passive_failure_statuses must contain at most {MAX_UPSTREAM_HEALTH_STATUSES} unique HTTP statuses from 500 through 599"
                ));
            }
            let endpoint_count = upstreams.len().max(1);
            if health.minimum_healthy == 0 || health.minimum_healthy > endpoint_count {
                problems.push(format!(
                    "{route_name}.health_check.minimum_healthy must be between 1 and {endpoint_count}"
                ));
            }
        }
        if let Some(retry) = route.retry.as_mut() {
            if has_connection {
                problems.push(format!(
                    "{route_name}.retry is not supported with connection_id in this static-authentication phase"
                ));
            }
            retry.methods = retry
                .methods
                .iter()
                .map(|method| method.trim().to_ascii_uppercase())
                .collect();
            if !(1..=MAX_UPSTREAM_RETRY_ATTEMPTS).contains(&retry.max_attempts) {
                problems.push(format!(
                    "{route_name}.retry.max_attempts must be between 1 and {MAX_UPSTREAM_RETRY_ATTEMPTS}"
                ));
            }
            if retry.methods.is_empty()
                || retry
                    .methods
                    .iter()
                    .any(|method| !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"))
                || retry.methods.iter().collect::<HashSet<_>>().len() != retry.methods.len()
            {
                problems.push(format!(
                    "{route_name}.retry.methods must contain unique replay-safe methods from GET, HEAD, and OPTIONS"
                ));
            }
            if retry.statuses.is_empty()
                || retry.statuses.len() > MAX_UPSTREAM_RETRY_STATUSES
                || retry
                    .statuses
                    .iter()
                    .any(|status| !(500..=599).contains(status))
                || retry.statuses.iter().collect::<HashSet<_>>().len() != retry.statuses.len()
            {
                problems.push(format!(
                    "{route_name}.retry.statuses must contain 1-{MAX_UPSTREAM_RETRY_STATUSES} unique HTTP statuses from 500 through 599"
                ));
            }
            if has_legacy_url {
                problems.push(format!(
                    "{route_name}.retry requires an upstreams pool and cannot be used with upstream_url"
                ));
            }
            if retry.max_attempts > 1 && route.request_body.mode == UpstreamRequestBodyMode::Stream
            {
                problems.push(format!(
                    "{route_name}.retry.max_attempts greater than 1 requires request_body.mode buffered"
                ));
            }
        }
        if let Some(circuit) = route.circuit_breaker.as_ref() {
            if has_connection {
                problems.push(format!(
                    "{route_name}.circuit_breaker is not supported with connection_id in this static-authentication phase"
                ));
            }
            if !(1..=MAX_UPSTREAM_CIRCUIT_THRESHOLD).contains(&circuit.failure_threshold) {
                problems.push(format!(
                    "{route_name}.circuit_breaker.failure_threshold must be between 1 and {MAX_UPSTREAM_CIRCUIT_THRESHOLD}"
                ));
            }
            if !(MIN_UPSTREAM_CIRCUIT_OPEN_MS..=MAX_UPSTREAM_CIRCUIT_OPEN_MS)
                .contains(&circuit.open_ms)
            {
                problems.push(format!(
                    "{route_name}.circuit_breaker.open_ms must be between {MIN_UPSTREAM_CIRCUIT_OPEN_MS} and {MAX_UPSTREAM_CIRCUIT_OPEN_MS}"
                ));
            }
            if circuit.half_open_max_requests == 0
                || usize::try_from(circuit.half_open_max_requests)
                    .map_or(true, |maximum| maximum > route.limits.max_in_flight)
            {
                problems.push(format!(
                    "{route_name}.circuit_breaker.half_open_max_requests must be between 1 and limits.max_in_flight"
                ));
            }
            if !(1..=MAX_UPSTREAM_CIRCUIT_THRESHOLD).contains(&circuit.recovery_threshold) {
                problems.push(format!(
                    "{route_name}.circuit_breaker.recovery_threshold must be between 1 and {MAX_UPSTREAM_CIRCUIT_THRESHOLD}"
                ));
            }
            if has_legacy_url {
                problems.push(format!(
                    "{route_name}.circuit_breaker requires an upstreams pool and cannot be used with upstream_url"
                ));
            }
        }

        let websocket = route.websocket.map(|mut websocket| {
            if !(1..=MAX_WEBSOCKET_MAX_CONNECTIONS).contains(&websocket.max_connections) {
                problems.push(format!(
                    "{route_name}.websocket.max_connections must be between 1 and {MAX_WEBSOCKET_MAX_CONNECTIONS}"
                ));
            }
            if let Some(per_endpoint) = websocket.max_connections_per_endpoint {
                if !(1..=websocket.max_connections).contains(&per_endpoint) {
                    problems.push(format!(
                        "{route_name}.websocket.max_connections_per_endpoint must be between 1 and websocket.max_connections"
                    ));
                }
            }
            if websocket.queue_depth > MAX_WEBSOCKET_QUEUE_DEPTH {
                problems.push(format!(
                    "{route_name}.websocket.queue_depth must be at most {MAX_WEBSOCKET_QUEUE_DEPTH}"
                ));
            }
            if !(MIN_WEBSOCKET_HANDSHAKE_TIMEOUT_MS..=MAX_WEBSOCKET_HANDSHAKE_TIMEOUT_MS)
                .contains(&websocket.handshake_timeout_ms)
            {
                problems.push(format!(
                    "{route_name}.websocket.handshake_timeout_ms must be between {MIN_WEBSOCKET_HANDSHAKE_TIMEOUT_MS} and {MAX_WEBSOCKET_HANDSHAKE_TIMEOUT_MS}"
                ));
            }
            if websocket.idle_timeout_ms != 0
                && !(MIN_WEBSOCKET_IDLE_TIMEOUT_MS..=MAX_WEBSOCKET_IDLE_TIMEOUT_MS)
                    .contains(&websocket.idle_timeout_ms)
            {
                problems.push(format!(
                    "{route_name}.websocket.idle_timeout_ms must be 0 to disable, or between {MIN_WEBSOCKET_IDLE_TIMEOUT_MS} and {MAX_WEBSOCKET_IDLE_TIMEOUT_MS}"
                ));
            }
            if websocket.max_duration_ms != 0
                && websocket.max_duration_ms > MAX_UPSTREAM_SSE_MAX_DURATION_MS
            {
                problems.push(format!(
                    "{route_name}.websocket.max_duration_ms must be 0 to disable, or at most {MAX_UPSTREAM_SSE_MAX_DURATION_MS}"
                ));
            }
            if !(MIN_WEBSOCKET_MAX_FRAME_BYTES..=MAX_WEBSOCKET_MAX_FRAME_BYTES)
                .contains(&websocket.max_frame_bytes)
            {
                problems.push(format!(
                    "{route_name}.websocket.max_frame_bytes must be between {MIN_WEBSOCKET_MAX_FRAME_BYTES} and {MAX_WEBSOCKET_MAX_FRAME_BYTES}"
                ));
            }
            // A message is assembled from frames, so a message cap below the
            // frame cap could never be satisfied by a single legal frame.
            if websocket.max_message_bytes < websocket.max_frame_bytes
                || websocket.max_message_bytes > MAX_WEBSOCKET_MAX_MESSAGE_BYTES
            {
                problems.push(format!(
                    "{route_name}.websocket.max_message_bytes must be at least websocket.max_frame_bytes and at most {MAX_WEBSOCKET_MAX_MESSAGE_BYTES}"
                ));
            }
            if !(1..=MAX_WEBSOCKET_MAX_WRITE_BUFFER_BYTES)
                .contains(&websocket.max_write_buffer_bytes)
            {
                problems.push(format!(
                    "{route_name}.websocket.max_write_buffer_bytes must be between 1 and {MAX_WEBSOCKET_MAX_WRITE_BUFFER_BYTES}"
                ));
            }
            if websocket.allowed_origins.len() > MAX_WEBSOCKET_ORIGINS {
                problems.push(format!(
                    "{route_name}.websocket.allowed_origins must contain at most {MAX_WEBSOCKET_ORIGINS} entries"
                ));
            }
            let mut origins = Vec::with_capacity(websocket.allowed_origins.len());
            for origin in &websocket.allowed_origins {
                if origin.len() > MAX_WEBSOCKET_ORIGIN_BYTES {
                    problems.push(format!(
                        "{route_name}.websocket.allowed_origins entries must be at most {MAX_WEBSOCKET_ORIGIN_BYTES} bytes"
                    ));
                    continue;
                }
                match normalized_websocket_origin(origin) {
                    Some(normalized) => {
                        if !origins.contains(&normalized) {
                            origins.push(normalized);
                        }
                    }
                    None => problems.push(format!(
                        "{route_name}.websocket.allowed_origins entries must be an http or https origin with no path, query, fragment, or credentials"
                    )),
                }
            }
            websocket.allowed_origins = origins;

            if websocket.allowed_subprotocols.len() > MAX_WEBSOCKET_SUBPROTOCOLS {
                problems.push(format!(
                    "{route_name}.websocket.allowed_subprotocols must contain at most {MAX_WEBSOCKET_SUBPROTOCOLS} entries"
                ));
            }
            let mut subprotocols = Vec::with_capacity(websocket.allowed_subprotocols.len());
            for subprotocol in &websocket.allowed_subprotocols {
                if subprotocol.len() > MAX_WEBSOCKET_SUBPROTOCOL_BYTES {
                    problems.push(format!(
                        "{route_name}.websocket.allowed_subprotocols entries must be at most {MAX_WEBSOCKET_SUBPROTOCOL_BYTES} bytes"
                    ));
                    continue;
                }
                if !is_http_token(subprotocol) {
                    problems.push(format!(
                        "{route_name}.websocket.allowed_subprotocols entries must be a valid HTTP token"
                    ));
                    continue;
                }
                if !subprotocols.contains(subprotocol) {
                    subprotocols.push(subprotocol.clone());
                }
            }
            websocket.allowed_subprotocols = subprotocols;

            if has_legacy_url {
                problems.push(format!(
                    "{route_name}.websocket requires an upstreams pool and cannot be used with upstream_url"
                ));
            }
            // A Connection-bound route injects a managed credential per request.
            // Doing that once for a connection that then lives for an hour is a
            // different security question, deferred rather than assumed safe.
            if connection_id.is_some() {
                problems.push(format!(
                    "{route_name}.websocket cannot be combined with connection_id"
                ));
            }
            websocket
        });

        let grpc = route.grpc.inspect(|grpc| {
            if !(1..=MAX_GRPC_MAX_CONCURRENT_CALLS).contains(&grpc.max_concurrent_calls) {
                problems.push(format!(
                    "{route_name}.grpc.max_concurrent_calls must be between 1 and {MAX_GRPC_MAX_CONCURRENT_CALLS}"
                ));
            }
            if let Some(per_endpoint) = grpc.max_concurrent_calls_per_endpoint {
                if !(1..=grpc.max_concurrent_calls).contains(&per_endpoint) {
                    problems.push(format!(
                        "{route_name}.grpc.max_concurrent_calls_per_endpoint must be between 1 and grpc.max_concurrent_calls"
                    ));
                }
            }
            if grpc.queue_depth > MAX_GRPC_QUEUE_DEPTH {
                problems.push(format!(
                    "{route_name}.grpc.queue_depth must be at most {MAX_GRPC_QUEUE_DEPTH}"
                ));
            }
            if !(MIN_GRPC_CONNECT_TIMEOUT_MS..=MAX_GRPC_CONNECT_TIMEOUT_MS)
                .contains(&grpc.connect_timeout_ms)
            {
                problems.push(format!(
                    "{route_name}.grpc.connect_timeout_ms must be between {MIN_GRPC_CONNECT_TIMEOUT_MS} and {MAX_GRPC_CONNECT_TIMEOUT_MS}"
                ));
            }
            if grpc.idle_timeout_ms != 0
                && !(MIN_GRPC_IDLE_TIMEOUT_MS..=MAX_GRPC_IDLE_TIMEOUT_MS)
                    .contains(&grpc.idle_timeout_ms)
            {
                problems.push(format!(
                    "{route_name}.grpc.idle_timeout_ms must be 0 to disable, or between {MIN_GRPC_IDLE_TIMEOUT_MS} and {MAX_GRPC_IDLE_TIMEOUT_MS}"
                ));
            }
            if grpc.max_duration_ms != 0 && grpc.max_duration_ms > MAX_GRPC_MAX_DURATION_MS {
                problems.push(format!(
                    "{route_name}.grpc.max_duration_ms must be 0 to disable, or at most {MAX_GRPC_MAX_DURATION_MS}"
                ));
            }
            if !(MIN_GRPC_MAX_MESSAGE_BYTES..=MAX_GRPC_MAX_MESSAGE_BYTES)
                .contains(&grpc.max_message_bytes)
            {
                problems.push(format!(
                    "{route_name}.grpc.max_message_bytes must be between {MIN_GRPC_MAX_MESSAGE_BYTES} and {MAX_GRPC_MAX_MESSAGE_BYTES}"
                ));
            }
            // A per-direction budget below one legal message could never carry
            // a call the route explicitly permits.
            for (name, value) in [
                ("max_request_bytes", grpc.max_request_bytes),
                ("max_response_bytes", grpc.max_response_bytes),
            ] {
                if value != 0
                    && value < u64::try_from(grpc.max_message_bytes).unwrap_or(u64::MAX)
                {
                    problems.push(format!(
                        "{route_name}.grpc.{name} must be 0 to disable, or at least grpc.max_message_bytes"
                    ));
                }
            }
            if !(1..=MAX_GRPC_MAX_METADATA_ENTRIES).contains(&grpc.max_metadata_entries) {
                problems.push(format!(
                    "{route_name}.grpc.max_metadata_entries must be between 1 and {MAX_GRPC_MAX_METADATA_ENTRIES}"
                ));
            }
            if has_legacy_url {
                problems.push(format!(
                    "{route_name}.grpc requires an upstreams pool and cannot be used with upstream_url"
                ));
            }
            // Same reasoning the WebSocket transport records: a Connection-bound
            // route injects a managed credential per request, and doing that
            // once for a stream that then lives for an hour is a different
            // security question, deferred rather than assumed safe.
            if connection_id.is_some() {
                problems.push(format!(
                    "{route_name}.grpc cannot be combined with connection_id"
                ));
            }
        });

        validated.push(UpstreamRouteConfig {
            id,
            connection_id,
            path_prefix,
            host,
            upstream_url,
            upstreams,
            load_balancing: route.load_balancing,
            request_body: route.request_body,
            sse: route.sse,
            websocket,
            grpc,
            limits: route.limits,
            health_check: route.health_check,
            retry: route.retry,
            circuit_breaker: route.circuit_breaker,
            timeout_ms: route.timeout_ms,
            response_idle_timeout_ms: route.response_idle_timeout_ms,
            connect_timeout_ms: route.connect_timeout_ms,
            add_request_headers,
            strip_request_headers,
            tls_ca_bundle_path,
            openapi_spec_path,
        });
    }

    validated
}

fn normalize_stable_id(name: &str, value: &str, problems: &mut Vec<String>) -> Option<String> {
    let value = value.trim();
    if upstream_route::is_valid_stable_route_id(value) {
        Some(value.to_owned())
    } else {
        problems.push(format!(
            "{name} must be 1-{} ASCII letters, digits, '.', '_', or '-', and must start with a letter or digit",
            upstream_route::STABLE_ROUTE_ID_MAX_LEN
        ));
        None
    }
}

fn normalize_connection_id(name: &str, value: &str, problems: &mut Vec<String>) -> Option<String> {
    let value = value.trim();
    match crate::connections::model::ConnectionId::parse(value.to_owned()) {
        Ok(id) => Some(id.to_string()),
        Err(_) => {
            problems.push(format!("{name} must be a stable URL-safe Connection ID"));
            None
        }
    }
}

fn validate_pool_endpoint_url(
    name: &str,
    value: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    let normalized = validate_upstream_url(name, value, problems)?;
    let parsed = url::Url::parse(&normalized).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        problems.push(format!(
            "{name} must not contain userinfo, query, or fragment components"
        ));
        return None;
    }
    if parsed.path() != "/" {
        problems.push(format!("{name} must be an origin URL without a base path"));
        return None;
    }
    Some(normalized)
}

fn normalize_route_add_request_headers(
    name: &str,
    headers: HashMap<String, String>,
    problems: &mut Vec<String>,
) -> HashMap<String, String> {
    let mut normalized = HashMap::with_capacity(headers.len());

    for (raw_name, value) in headers {
        let header_name =
            match normalize_route_header_name(&format!("{name}.{raw_name}"), &raw_name, problems) {
                Some(header_name) => header_name,
                None => continue,
            };

        if is_unconditionally_stripped_request_header(&header_name) {
            problems.push(format!(
                "{name}.{raw_name} must not configure hop-by-hop or gateway-managed header '{}'",
                header_name.as_str()
            ));
            continue;
        }
        if header_name.as_str() == REQUEST_ID_HEADER {
            problems.push(format!(
                "{name}.{raw_name} must not configure {REQUEST_ID_HEADER}; the gateway owns this header and removes it before dispatching upstream"
            ));
            continue;
        }
        if let Err(err) = HeaderValue::from_str(&value) {
            problems.push(format!(
                "{name}.{raw_name} must be a valid HTTP header value: {err}"
            ));
            continue;
        }

        if normalized
            .insert(header_name.as_str().to_owned(), value)
            .is_some()
        {
            problems.push(format!(
                "{name} contains duplicate header '{}' after normalization",
                header_name.as_str()
            ));
        }
    }

    normalized
}

fn normalize_route_strip_request_headers(
    name: &str,
    headers: Vec<String>,
    add_request_headers: &HashMap<String, String>,
    problems: &mut Vec<String>,
) -> Vec<String> {
    let mut normalized = Vec::with_capacity(headers.len());
    let mut seen = HashSet::new();

    for raw_name in headers {
        let header_name = match normalize_route_header_name(name, &raw_name, problems) {
            Some(header_name) => header_name,
            None => continue,
        };

        if header_name.as_str() == REQUEST_ID_HEADER {
            problems.push(format!(
                "{name} must not include {REQUEST_ID_HEADER}; the gateway owns this header and removes it before dispatching upstream"
            ));
            continue;
        }
        if add_request_headers.contains_key(header_name.as_str()) {
            problems.push(format!(
                "{name} must not include '{}' because the same route also adds it",
                header_name.as_str()
            ));
            continue;
        }

        if seen.insert(header_name.clone()) {
            normalized.push(header_name.as_str().to_owned());
        }
    }

    normalized
}

fn normalize_route_header_name(
    name: &str,
    value: &str,
    problems: &mut Vec<String>,
) -> Option<HeaderName> {
    let value = value.trim();
    if value.is_empty() {
        problems.push(format!("{name} must be a non-empty HTTP header name"));
        return None;
    }

    match HeaderName::from_bytes(value.as_bytes()) {
        Ok(header_name) => Some(header_name),
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid HTTP header name, got '{value}': {err}"
            ));
            None
        }
    }
}

fn normalize_route_tls_material_path(
    name: &str,
    value: Option<PathBuf>,
    problems: &mut Vec<String>,
) -> Option<PathBuf> {
    let value = value?;
    if value.as_os_str().is_empty() {
        problems.push(format!("{name} must be a non-empty filesystem path"));
        None
    } else {
        Some(value)
    }
}

fn normalize_client_identity_pem_path(
    name: &str,
    value: Option<PathBuf>,
    problems: &mut Vec<String>,
) -> Option<PathBuf> {
    let value = value?;
    if value.as_os_str().is_empty() {
        problems.push(format!("{name} must be a non-empty filesystem path"));
        return None;
    }

    let rendered = value.to_string_lossy();
    if rendered.contains('\n') || rendered.contains('\r') || rendered.contains("-----BEGIN") {
        problems.push(format!(
            "{name} must reference a mounted PEM file and must not contain inline PEM material"
        ));
        return None;
    }

    Some(value)
}

fn normalize_route_openapi_spec_path(
    name: &str,
    value: Option<PathBuf>,
    problems: &mut Vec<String>,
) -> Option<PathBuf> {
    let value = value?;
    if value.as_os_str().is_empty() {
        problems.push(format!("{name} must be a non-empty filesystem path"));
        None
    } else {
        Some(value)
    }
}

fn is_unconditionally_stripped_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || name == header::HOST
        || name == header::CONTENT_LENGTH
}

fn normalize_route_path_prefix(
    name: &str,
    value: Option<String>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = value?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if is_valid_exempt_path(value) {
        Some(value.to_owned())
    } else {
        problems.push(format!(
            "{name} must be a URI path prefix starting with '/', got '{value}'"
        ));
        None
    }
}

fn normalize_route_host(
    name: &str,
    value: Option<String>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let value = value?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let host = value.to_ascii_lowercase();
    if is_valid_hostname_without_port(&host) {
        Some(host)
    } else {
        problems.push(format!(
            "{name} must be a hostname without a port, got '{value}'"
        ));
        None
    }
}

fn validate_upstream_url(name: &str, value: &str, problems: &mut Vec<String>) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        problems.push(format!("{name} must be a non-empty http or https URL"));
        return None;
    }

    let parsed = match url::Url::parse(value) {
        Ok(parsed) => parsed,
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid http or https URL, got '{value}': {err}"
            ));
            return None;
        }
    };

    if parsed.host_str().is_none() {
        problems.push(format!(
            "{name} must be a valid http or https URL with a host, got '{value}'"
        ));
        return None;
    }

    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        problems.push(format!(
            "{name} must not contain URL userinfo or a fragment"
        ));
        return None;
    }

    match parsed.scheme() {
        "http" | "https" => Some(value.to_owned()),
        scheme => {
            problems.push(format!(
                "{name} must use http or https, got scheme '{scheme}'"
            ));
            None
        }
    }
}

fn parse_comma_separated_paths(
    name: &str,
    value: Result<String, VarError>,
    default: &[String],
    problems: &mut Vec<String>,
) -> Vec<String> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => return default.to_owned(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            return default.to_owned();
        }
    };

    let mut values = Vec::new();

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        if is_valid_exempt_path(entry) {
            values.push(entry.to_owned());
        } else {
            problems.push(format!(
                "{name} entries must be URI paths starting with '/', got '{entry}'"
            ));
        }
    }

    values
}

fn default_admin_exempt_paths(admin_prefix: &str, admin_login_enabled: bool) -> Vec<String> {
    let mut paths = default_paths(DEFAULT_EXEMPT_PROBE_PATHS);
    paths.push(admin_prefix.to_owned());
    if admin_login_enabled {
        paths.extend(admin_login_exempt_paths(admin_prefix));
    }
    paths
}

fn admin_login_exempt_paths(admin_prefix: &str) -> [String; 2] {
    [
        format!("/v1{admin_prefix}/auth/login"),
        format!("/v1{admin_prefix}/auth/callback"),
    ]
}

fn append_admin_login_exempt_paths(paths: &mut Vec<String>, admin_prefix: &str, enabled: bool) {
    if !enabled {
        return;
    }

    for path in admin_login_exempt_paths(admin_prefix) {
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
    }
}

fn default_paths(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|value| (*value).to_owned()).collect()
}

fn is_valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_cookie_domain(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn is_valid_exempt_path(value: &str) -> bool {
    value.starts_with('/')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn is_valid_admin_prefix(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && !value.ends_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && segment.bytes().all(is_valid_admin_path_byte))
}

fn is_valid_admin_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~')
}

fn is_valid_hostname_without_port(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains(':')
        && value.split('.').all(is_valid_hostname_label)
}

fn is_valid_hostname_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_listen_addr_parses() {
        let config = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.listen_addr,
            "127.0.0.1:9090"
                .parse::<SocketAddr>()
                .expect("test address should parse")
        );
        assert_eq!(
            config.admin_listen_addr,
            Some(
                "127.0.0.1:9091"
                    .parse::<SocketAddr>()
                    .expect("test admin address should parse")
            )
        );
        assert_eq!(config.admin_prefix, DEFAULT_ADMIN_PREFIX);
        assert_eq!(
            config.admin_login_pending_ttl_secs,
            DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS
        );
        assert_eq!(
            config.admin_login_pending_max_entries,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES
        );
        assert_eq!(
            config.admin_login_pending_max_per_ip,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP
        );
        assert_eq!(config.gateway_public_url, None);
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
        assert_eq!(config.discovery_sqlite_path, None);
        assert_eq!(config.principal_sqlite_path, None);
        assert_eq!(config.policy_file, None);
        assert_eq!(config.tools_file, None);
        assert_eq!(config.policy_history_sqlite_path, None);
        assert!(config.cors_allow_origins.is_empty());
        assert_eq!(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert_eq!(config.rate_limit_read_rps, DEFAULT_RATE_LIMIT_READ_RPS);
        assert_eq!(config.rate_limit_read_burst, DEFAULT_RATE_LIMIT_READ_BURST);
        assert_eq!(config.rate_limit_write_rps, DEFAULT_RATE_LIMIT_WRITE_RPS);
        assert_eq!(
            config.rate_limit_write_burst,
            DEFAULT_RATE_LIMIT_WRITE_BURST
        );
        assert!(!config.trust_proxy_headers);
        assert!(config.trusted_proxy_cidrs.is_empty());
        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert_eq!(
            config.validation_allowed_content_types,
            vec!["application/json".to_owned()]
        );
        assert!(config.auth_enabled);
        assert_eq!(config.auth_mode, AuthMode::Required);
        assert_eq!(config.auth_cookie_name, "session");
        assert_eq!(
            config.auth_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert_eq!(config.jwt_jwks_url, None);
        assert_eq!(config.jwt_issuer, None);
        assert_eq!(config.jwt_audience, None);
        assert_eq!(config.jwt_jwks_timeout_ms, DEFAULT_JWT_JWKS_TIMEOUT_MS);
        assert!(!config.jwt_require_jti);
        assert_eq!(config.roles_claim, "roles");
        assert_eq!(config.service_token_sqlite_path, None);
        assert_eq!(
            config.service_token_cache_ttl_ms,
            DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS
        );
        assert_eq!(
            config.tool_runtime_queue_depth,
            DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH
        );
        assert_eq!(
            config.tool_runtime_global_concurrency,
            DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY
        );
        assert_eq!(
            config.tool_runtime_queue_timeout_ms,
            DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS
        );
        assert_eq!(
            config.tool_runtime_default_timeout_ms,
            DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS
        );
        assert!(config.csrf_enabled);
        assert_eq!(config.csrf_cookie_name, "csrf_token");
        assert_eq!(config.csrf_header_name, "x-csrf-token");
        assert_eq!(config.csrf_cookie_domain, None);
        assert_eq!(
            config.csrf_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ]
        );
        assert_eq!(config.upstream_url, None);
        assert!(config.upstream_routes.is_empty());
        assert_eq!(config.upstream_timeout_ms, None);
        assert_eq!(config.upstream_response_idle_timeout_ms, None);
        assert_eq!(config.upstream_connect_timeout_ms, None);
        assert!(config.egress_allowed_hosts.is_empty());
        assert!(config.egress_nat64_prefixes.is_empty());
        assert_eq!(config.egress_timeout_ms, DEFAULT_EGRESS_TIMEOUT_MS);
        assert_eq!(
            config.egress_response_idle_timeout_ms,
            DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS
        );
        assert_eq!(
            config.egress_connect_timeout_ms,
            DEFAULT_EGRESS_CONNECT_TIMEOUT_MS
        );
        assert_eq!(
            config.egress_max_response_bytes,
            DEFAULT_EGRESS_MAX_RESPONSE_BYTES
        );
        assert_eq!(
            config.egress_max_request_body_bytes,
            DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES
        );
        assert!(config.egress_deny_private_ips);
    }

    #[test]
    fn admin_listen_addr_must_differ_from_listen_addr() {
        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" | "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject duplicate listener addresses");

        let message = error.to_string();
        assert!(message.contains("configuration is invalid:"));
        assert!(message.contains("ADMIN_LISTEN_ADDR must not be the same address as LISTEN_ADDR"));
        assert!(message.contains("both resolved to 127.0.0.1:9090"));
        assert!(message.contains("choose a different port for the admin listener"));
        assert_eq!(error.problems.len(), 1);

        let split_config = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should allow different listener addresses");
        assert_eq!(
            split_config.admin_listen_addr,
            Some(
                "127.0.0.1:9091"
                    .parse::<SocketAddr>()
                    .expect("test admin address should parse")
            )
        );

        let unified_config = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should allow ADMIN_LISTEN_ADDR to be unset");
        assert_eq!(unified_config.admin_listen_addr, None);
    }

    #[test]
    fn inbound_tls_is_off_by_default() {
        let config = Config::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("an unconfigured gateway should validate");

        assert_eq!(config.tls_cert_files, None);
        assert_eq!(config.tls_key_files, None);
        assert_eq!(config.admin_tls_cert_files, None);
        assert_eq!(config.admin_tls_key_files, None);
        assert!(config.data_inbound_tls().is_none());
        assert!(config.admin_inbound_tls().is_none());
        assert_eq!(config.tls_min_version, DEFAULT_TLS_MIN_VERSION);
        assert_eq!(
            config.tls_handshake_timeout_ms,
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS
        );
        assert_eq!(
            config.tls_max_concurrent_handshakes,
            DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES
        );
    }

    /// Half a pair is the shape that silently serves plaintext on a listener an
    /// operator believes is protected.
    #[test]
    fn half_configured_inbound_tls_is_rejected_on_both_listeners() {
        let certificate_only = Config::from_env_vars(|name| match name {
            "TLS_CERT_FILE" => Ok("/run/tls/tls.crt".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a certificate without a key must not start");
        assert!(
            certificate_only
                .to_string()
                .contains("TLS_CERT_FILE is set without TLS_KEY_FILE"),
            "{certificate_only}"
        );

        let key_only = Config::from_env_vars(|name| match name {
            "TLS_KEY_FILE" => Ok("/run/tls/tls.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a key without a certificate must not start");
        assert!(
            key_only
                .to_string()
                .contains("TLS_KEY_FILE is set without TLS_CERT_FILE"),
            "{key_only}"
        );

        let admin_certificate_only = Config::from_env_vars(|name| match name {
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            "ADMIN_TLS_CERT_FILE" => Ok("/run/tls/admin.crt".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("an admin certificate without a key must not start");
        assert!(
            admin_certificate_only
                .to_string()
                .contains("ADMIN_TLS_CERT_FILE is set without ADMIN_TLS_KEY_FILE"),
            "{admin_certificate_only}"
        );
    }

    // --- client-certificate authentication ---------------------------------

    /// The two lists are paired by position, so a count mismatch is a
    /// configuration that would hand one chain another chain's key -- or
    /// silently drop the tail -- and neither is acceptable.
    #[test]
    fn mismatched_inbound_tls_lists_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "TLS_CERT_FILE" => Ok("/run/tls/a.crt,/run/tls/b.crt,/run/tls/c.crt".to_owned()),
            "TLS_KEY_FILE" => Ok("/run/tls/a.key,/run/tls/b.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("three certificates and two keys must not start");
        assert!(
            error
                .to_string()
                .contains("TLS_CERT_FILE lists 3 certificate file(s) but TLS_KEY_FILE lists 2"),
            "{error}"
        );
    }

    /// An empty entry would shift every later pairing by one, so it is refused
    /// rather than skipped.
    #[test]
    fn an_empty_entry_in_an_inbound_tls_list_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "TLS_CERT_FILE" => Ok("/run/tls/a.crt,,/run/tls/b.crt".to_owned()),
            "TLS_KEY_FILE" => Ok("/run/tls/a.key,/run/tls/b.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("an empty list entry must not start");
        assert!(
            error.to_string().contains(
                "TLS_CERT_FILE must be a comma-separated list of file paths with no empty entry"
            ),
            "{error}"
        );
    }

    /// A multi-path list parses in order, with each entry trimmed, and reaches
    /// the listener settings in that order -- the order is the default.
    #[test]
    fn an_inbound_tls_list_parses_in_order_with_entries_trimmed() {
        let config = Config::from_env_vars(|name| match name {
            "TLS_CERT_FILE" => Ok(" /run/tls/a.crt , /run/tls/b.crt ".to_owned()),
            "TLS_KEY_FILE" => Ok("/run/tls/a.key,/run/tls/b.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("a well-formed list should validate");
        let settings = config
            .data_inbound_tls()
            .expect("listed material should reach the listener settings");
        assert_eq!(
            settings.certificate_files,
            ["/run/tls/a.crt".to_owned(), "/run/tls/b.crt".to_owned()].as_slice()
        );
        assert_eq!(
            settings.private_key_files,
            ["/run/tls/a.key".to_owned(), "/run/tls/b.key".to_owned()].as_slice()
        );
    }

    /// The TLS settings a listener needs before client certificates mean
    /// anything, so a client-cert test is not also asserting about the pair.
    fn with_data_tls(name: &str) -> Option<Result<String, VarError>> {
        match name {
            "TLS_CERT_FILE" => Some(Ok("/run/tls/tls.crt".to_owned())),
            "TLS_KEY_FILE" => Some(Ok("/run/tls/tls.key".to_owned())),
            _ => None,
        }
    }

    #[test]
    fn client_certificate_auth_is_off_by_default() {
        let config = Config::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("an unconfigured gateway should validate");

        assert_eq!(config.client_cert_auth, None);
        assert_eq!(config.admin_client_cert_auth, None);
        assert!(!config.client_certificate_auth_enabled());

        let tls_only =
            Config::from_env_vars(|name| with_data_tls(name).unwrap_or(Err(VarError::NotPresent)))
                .expect("terminating TLS should validate");

        assert_eq!(
            tls_only.client_cert_auth, None,
            "terminating TLS must not by itself start requesting client certificates"
        );
        assert!(tls_only
            .data_inbound_tls()
            .expect("data TLS is configured")
            .client_auth
            .is_none());
    }

    /// Fail closed on the trust anchors.
    ///
    /// Falling back to the platform trust store would mean every certificate
    /// every public CA has ever issued authenticates, so a mode with no bundle
    /// is a startup failure rather than a default.
    #[test]
    fn requesting_client_certificates_without_a_ca_bundle_fails_startup() {
        let error = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_MODE" => Ok("required".to_owned()),
            "CLIENT_CERT_IDENTITY_SOURCE" => Ok("spiffe".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect_err("client certificates with no CA bundle must not start");

        assert!(
            error
                .to_string()
                .contains("CLIENT_CERT_MODE requires CLIENT_CERT_CA_FILE"),
            "{error}"
        );
        assert!(
            error.to_string().contains("never the platform trust store"),
            "the error must say why, not just what: {error}"
        );
    }

    #[test]
    fn requesting_client_certificates_without_an_identity_source_fails_startup() {
        let error = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_MODE" => Ok("optional".to_owned()),
            "CLIENT_CERT_CA_FILE" => Ok("/run/tls/client-ca.crt".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect_err("client certificates with no identity source must not start");

        assert!(
            error
                .to_string()
                .contains("CLIENT_CERT_MODE requires CLIENT_CERT_IDENTITY_SOURCE"),
            "{error}"
        );
    }

    /// A listener that terminates no TLS never sees a certificate, so a mode
    /// set on one is a configuration an operator would read as mutual TLS.
    #[test]
    fn requesting_client_certificates_on_a_plaintext_listener_fails_startup() {
        let error = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_MODE" => Ok("required".to_owned()),
            "CLIENT_CERT_CA_FILE" => Ok("/run/tls/client-ca.crt".to_owned()),
            "CLIENT_CERT_IDENTITY_SOURCE" => Ok("spiffe".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("client certificates on a plaintext listener must not start");

        assert!(
            error
                .to_string()
                .contains("CLIENT_CERT_MODE requires TLS_CERT_FILE"),
            "{error}"
        );
    }

    /// Material configured against a mode that will never read it.
    #[test]
    fn client_certificate_material_without_a_mode_fails_startup() {
        for (setting, value) in [
            ("CLIENT_CERT_CA_FILE", "/run/tls/client-ca.crt"),
            ("CLIENT_CERT_CRL_FILE", "/run/tls/client.crl"),
        ] {
            let error = Config::from_env_vars(|name| {
                if name == setting {
                    return Ok(value.to_owned());
                }
                with_data_tls(name).unwrap_or(Err(VarError::NotPresent))
            })
            .expect_err("material with no mode must not start");

            assert!(
                error
                    .to_string()
                    .contains(&format!("{setting} is set while CLIENT_CERT_MODE is `off`")),
                "{error}"
            );
        }
    }

    #[test]
    fn an_identity_source_with_no_listener_asking_for_certificates_fails_startup() {
        let error = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_IDENTITY_SOURCE" => Ok("dns".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect_err("an identity source with nothing to apply it to must not start");

        assert!(
            error.to_string().contains(
                "CLIENT_CERT_IDENTITY_SOURCE is set while CLIENT_CERT_MODE and ADMIN_CLIENT_CERT_MODE are both off"
            ),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_client_certificate_mode_or_identity_source_fails_startup() {
        let bad_mode = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_MODE" => Ok("yes".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect_err("an unrecognised mode must not start");
        assert!(
            bad_mode
                .to_string()
                .contains("expected `off`, `optional`, or `required`"),
            "{bad_mode}"
        );

        let bad_source = Config::from_env_vars(|name| match name {
            "CLIENT_CERT_MODE" => Ok("required".to_owned()),
            "CLIENT_CERT_CA_FILE" => Ok("/run/tls/client-ca.crt".to_owned()),
            "CLIENT_CERT_IDENTITY_SOURCE" => Ok("subject-dn".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect_err("an unsupported identity source must not start");
        assert!(
            bad_source
                .to_string()
                .contains("expected `spiffe`, `uri`, or `dns`"),
            "the subject DN is not an available identity source: {bad_source}"
        );
    }

    /// The two listeners are configured independently, and a fully configured
    /// one reaches the loader with every part present.
    #[test]
    fn the_two_listeners_request_client_certificates_independently() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            "ADMIN_TLS_CERT_FILE" => Ok("/run/tls/admin.crt".to_owned()),
            "ADMIN_TLS_KEY_FILE" => Ok("/run/tls/admin.key".to_owned()),
            "ADMIN_CLIENT_CERT_MODE" => Ok("required".to_owned()),
            "ADMIN_CLIENT_CERT_CA_FILE" => Ok("/run/tls/admin-client-ca.crt".to_owned()),
            "ADMIN_CLIENT_CERT_CRL_FILE" => Ok("/run/tls/admin-client.crl".to_owned()),
            "CLIENT_CERT_IDENTITY_SOURCE" => Ok("spiffe".to_owned()),
            other => with_data_tls(other).unwrap_or(Err(VarError::NotPresent)),
        })
        .expect("an admin-only client-certificate deployment should validate");

        assert!(
            config.client_cert_auth.is_none(),
            "the data listener asked for nothing and must get nothing"
        );
        let admin = config
            .admin_client_cert_auth
            .as_ref()
            .expect("the admin listener asked for client certificates");
        assert_eq!(admin.requirement, ClientCertRequirement::Required);
        assert_eq!(admin.ca_file, "/run/tls/admin-client-ca.crt");
        assert_eq!(admin.crl_file.as_deref(), Some("/run/tls/admin-client.crl"));
        assert_eq!(admin.identity_source, ClientCertIdentitySource::Spiffe);
        assert!(config.client_certificate_auth_enabled());

        let settings = config
            .admin_inbound_tls()
            .expect("admin TLS is configured")
            .client_auth
            .expect("admin client auth is configured");
        assert_eq!(settings.requirement, ClientCertRequirement::Required);
        assert!(config
            .data_inbound_tls()
            .expect("data TLS is configured")
            .client_auth
            .is_none());
    }

    /// Accepting admin TLS settings with no admin listener would leave the
    /// admin surface on the data listener's scheme while its own settings claim
    /// otherwise.
    #[test]
    fn admin_inbound_tls_requires_an_admin_listener() {
        let error = Config::from_env_vars(|name| match name {
            "ADMIN_TLS_CERT_FILE" => Ok("/run/tls/admin.crt".to_owned()),
            "ADMIN_TLS_KEY_FILE" => Ok("/run/tls/admin.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("admin TLS without an admin listener must not start");

        assert!(
            error.to_string().contains(
                "ADMIN_TLS_CERT_FILE and ADMIN_TLS_KEY_FILE require ADMIN_LISTEN_ADDR to be set"
            ),
            "{error}"
        );

        let configured = Config::from_env_vars(|name| match name {
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            "ADMIN_TLS_CERT_FILE" => Ok("/run/tls/admin.crt".to_owned()),
            "ADMIN_TLS_KEY_FILE" => Ok("/run/tls/admin.key".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("admin TLS with an admin listener should validate");
        let settings = configured
            .admin_inbound_tls()
            .expect("admin TLS settings should resolve");
        assert_eq!(
            settings.certificate_files,
            ["/run/tls/admin.crt".to_owned()].as_slice()
        );
        assert_eq!(
            settings.private_key_files,
            ["/run/tls/admin.key".to_owned()].as_slice()
        );
        assert!(
            configured.data_inbound_tls().is_none(),
            "admin TLS must not imply data TLS; the two listeners are configured independently"
        );
    }

    #[test]
    fn tls_min_version_accepts_only_the_two_versions_rustls_negotiates() {
        for (value, expected) in [("1.2", TlsMinVersion::Tls12), ("1.3", TlsMinVersion::Tls13)] {
            let config = Config::from_env_vars(|name| match name {
                "TLS_MIN_VERSION" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect("a supported TLS version should validate");
            assert_eq!(config.tls_min_version, expected);
        }

        let error = Config::from_env_vars(|name| match name {
            "TLS_MIN_VERSION" => Ok("1.1".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("an unsupported TLS version must not start");
        assert!(
            error
                .to_string()
                .contains("TLS_MIN_VERSION must be a valid TLS version, got '1.1'"),
            "{error}"
        );
    }

    #[test]
    fn the_handshake_bound_and_deadline_must_both_be_positive() {
        let error = Config::from_env_vars(|name| match name {
            "TLS_HANDSHAKE_TIMEOUT_MS" => Ok("0".to_owned()),
            "TLS_MAX_CONCURRENT_HANDSHAKES" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a zero handshake bound leaves no way to accept a connection");

        let message = error.to_string();
        assert!(message.contains("TLS_HANDSHAKE_TIMEOUT_MS"), "{message}");
        assert!(
            message.contains("TLS_MAX_CONCURRENT_HANDSHAKES must be greater than 0"),
            "{message}"
        );
    }

    #[test]
    fn invalid_listen_addr_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("not-a-socket".to_owned()),
            "ADMIN_LISTEN_ADDR" => Ok("also-not-a-socket".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid socket addresses");

        let message = error.to_string();
        assert!(message.contains("configuration is invalid:"));
        assert!(message.contains("LISTEN_ADDR must be a valid socket address"));
        assert!(message.contains("not-a-socket"));
        assert!(message.contains("ADMIN_LISTEN_ADDR must be a valid socket address"));
        assert!(message.contains("also-not-a-socket"));
        assert_eq!(error.problems.len(), 2);
    }

    #[test]
    fn missing_listen_addr_uses_default() {
        let config =
            Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");

        assert_eq!(
            config.listen_addr,
            DEFAULT_LISTEN_ADDR
                .parse::<SocketAddr>()
                .expect("default address should parse")
        );
        assert_eq!(config.admin_listen_addr, None);
        assert_eq!(config.admin_prefix, DEFAULT_ADMIN_PREFIX);
        assert_eq!(
            config.admin_login_pending_ttl_secs,
            DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS
        );
        assert_eq!(
            config.admin_login_pending_max_entries,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES
        );
        assert_eq!(
            config.admin_login_pending_max_per_ip,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP
        );
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
        assert_eq!(config.discovery_sqlite_path, None);
        assert_eq!(config.principal_sqlite_path, None);
        assert!(!config.payload_capture_enabled);
        assert_eq!(
            config.payload_capture_sample_rate,
            DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE
        );
        assert_eq!(
            config.signal_detector_config(),
            SignalDetectorConfig::default()
        );
        assert_eq!(
            config.rule_suggestion_config(),
            RuleSuggestionConfig::default()
        );
        assert_eq!(config.policy_file, None);
        assert_eq!(config.tools_file, None);
        assert_eq!(config.policy_history_sqlite_path, None);
        assert!(config.cors_allow_origins.is_empty());
        assert_eq!(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert_eq!(config.rate_limit_read_rps, DEFAULT_RATE_LIMIT_READ_RPS);
        assert_eq!(config.rate_limit_read_burst, DEFAULT_RATE_LIMIT_READ_BURST);
        assert_eq!(config.rate_limit_write_rps, DEFAULT_RATE_LIMIT_WRITE_RPS);
        assert_eq!(
            config.rate_limit_write_burst,
            DEFAULT_RATE_LIMIT_WRITE_BURST
        );
        assert!(!config.trust_proxy_headers);
        assert!(config.trusted_proxy_cidrs.is_empty());
        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert_eq!(
            config.validation_allowed_content_types,
            vec!["application/json".to_owned()]
        );
        assert!(config.auth_enabled);
        assert_eq!(config.auth_mode, AuthMode::Required);
        assert_eq!(config.auth_cookie_name, "session");
        assert_eq!(
            config.auth_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert_eq!(config.jwt_jwks_url, None);
        assert_eq!(config.jwt_issuer, None);
        assert_eq!(config.jwt_audience, None);
        assert_eq!(config.jwt_jwks_timeout_ms, DEFAULT_JWT_JWKS_TIMEOUT_MS);
        assert!(!config.jwt_require_jti);
        assert_eq!(config.roles_claim, "roles");
        assert_eq!(config.service_token_sqlite_path, None);
        assert_eq!(
            config.service_token_cache_ttl_ms,
            DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS
        );
        assert_eq!(
            config.tool_runtime_queue_depth,
            DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH
        );
        assert_eq!(
            config.tool_runtime_global_concurrency,
            DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY
        );
        assert_eq!(
            config.tool_runtime_queue_timeout_ms,
            DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS
        );
        assert_eq!(
            config.tool_runtime_default_timeout_ms,
            DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS
        );
        assert!(config.csrf_enabled);
        assert_eq!(config.csrf_cookie_name, "csrf_token");
        assert_eq!(config.csrf_header_name, "x-csrf-token");
        assert_eq!(config.csrf_cookie_domain, None);
        assert_eq!(
            config.csrf_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ]
        );
        assert_eq!(config.upstream_url, None);
        assert_eq!(config.upstream_timeout_ms, None);
        assert_eq!(config.upstream_response_idle_timeout_ms, None);
        assert_eq!(config.upstream_connect_timeout_ms, None);
        assert!(config.egress_allowed_hosts.is_empty());
        assert_eq!(config.egress_timeout_ms, DEFAULT_EGRESS_TIMEOUT_MS);
        assert_eq!(
            config.egress_response_idle_timeout_ms,
            DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS
        );
        assert_eq!(
            config.egress_connect_timeout_ms,
            DEFAULT_EGRESS_CONNECT_TIMEOUT_MS
        );
        assert_eq!(
            config.egress_max_response_bytes,
            DEFAULT_EGRESS_MAX_RESPONSE_BYTES
        );
        assert_eq!(
            config.egress_max_request_body_bytes,
            DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES
        );
        assert!(config.egress_deny_private_ips);
    }

    #[test]
    fn empty_admin_listen_addr_is_unset() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LISTEN_ADDR" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.admin_listen_addr, None);
    }

    #[test]
    fn cors_allow_origins_parses_comma_separated_list() {
        let config = Config::from_env_vars(|name| match name {
            "CORS_ALLOW_ORIGINS" => Ok(
                " http://localhost:3000,https://app.example.test,, https://admin.example.test "
                    .to_owned(),
            ),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.cors_allow_origins,
            vec![
                "http://localhost:3000".to_owned(),
                "https://app.example.test".to_owned(),
                "https://admin.example.test".to_owned(),
            ]
        );
    }

    #[test]
    fn audit_log_file_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_LOG_FILE" => Ok("  /var/log/greengateway/audit.jsonl  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.audit_log_file,
            Some("/var/log/greengateway/audit.jsonl".to_owned())
        );
    }

    #[test]
    fn empty_audit_log_file_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_LOG_FILE" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.audit_log_file, None);
    }

    #[test]
    fn admin_prefix_parses_optional_path_prefix() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_PREFIX" => Ok("  /ops/admin  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.admin_prefix, "/ops/admin");
        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/ops/admin".to_owned(),
            ]
        );
        assert_eq!(
            config.auth_exempt_paths,
            vec![
                "/health".to_owned(),
                "/livez".to_owned(),
                "/startupz".to_owned(),
                "/readyz".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/ops/admin".to_owned(),
            ]
        );
    }

    #[test]
    fn custom_admin_prefix_default_exempts_track_prefix() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_PREFIX" => Ok("/ops".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        let expected = vec![
            "/health".to_owned(),
            "/livez".to_owned(),
            "/startupz".to_owned(),
            "/readyz".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/ops".to_owned(),
        ];
        assert_eq!(config.auth_exempt_paths, expected);
        assert_eq!(config.rbac_exempt_paths, expected);
    }

    #[test]
    fn invalid_admin_prefix_values_are_rejected() {
        for value in [
            "",
            "   ",
            "admin",
            "/",
            "/admin/",
            "/admin//ops",
            "/admin/{id}",
        ] {
            let error = Config::from_env_vars(|name| match name {
                "ADMIN_PREFIX" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("config should reject invalid admin prefix");

            let message = error.to_string();
            assert!(
                message.contains("ADMIN_PREFIX must be a non-root URI path prefix"),
                "{message}"
            );
            assert_eq!(error.problems.len(), 1);
        }
    }

    #[test]
    fn audit_sqlite_config_parses_optional_path_and_retention() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_PATH" => Ok("  /var/lib/greengateway/audit.sqlite  ".to_owned()),
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("30".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.audit_sqlite_path,
            Some("/var/lib/greengateway/audit.sqlite".to_owned())
        );
        assert_eq!(config.audit_sqlite_retention_days, Some(30));
    }

    #[test]
    fn empty_audit_sqlite_path_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.audit_sqlite_path, None);
    }

    #[test]
    fn audit_sqlite_retention_without_path_is_allowed() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("7".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, Some(7));
    }

    #[test]
    fn zero_audit_sqlite_retention_disables_pruning_without_aborting_startup() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_PATH" => Ok("/var/lib/greengateway/audit.sqlite".to_owned()),
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("zero retention must not newly abort startup for an existing deployment");

        assert_eq!(
            config.audit_sqlite_retention_days, None,
            "0 must mean disabled pruning, not a prune cutoff at the current instant"
        );
    }

    #[test]
    fn audit_sqlite_retention_beyond_the_representable_range_is_rejected_at_startup() {
        let error = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_PATH" => Ok("/var/lib/greengateway/audit.sqlite".to_owned()),
            // Comfortably past year -9999 once subtracted from now, which is
            // where computing the prune cutoff stops being possible at all.
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("4000000000".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a retention window that cannot be represented must fail startup");

        assert!(
            error
                .to_string()
                .contains("AUDIT_SQLITE_RETENTION_DAYS must be at most 36500"),
            "the failure must name the setting and its bound: {error}"
        );
    }

    #[test]
    fn the_widest_supported_audit_retention_window_still_starts() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_PATH" => Ok("/var/lib/greengateway/audit.sqlite".to_owned()),
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("36500".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("the documented maximum must remain a usable setting");

        assert_eq!(config.audit_sqlite_retention_days, Some(36_500));
    }

    #[test]
    fn empty_audit_sqlite_retention_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.audit_sqlite_retention_days, None);
    }

    #[test]
    fn invalid_audit_sqlite_retention_is_collected_with_other_problems() {
        let error = Config::from_env_vars(|name| match name {
            "AUDIT_SQLITE_RETENTION_DAYS" => Ok("forever".to_owned()),
            "MAX_BODY_SIZE" => Ok("large".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid SQLite retention");

        let message = error.to_string();
        assert!(message.contains("AUDIT_SQLITE_RETENTION_DAYS must be a valid day count"));
        assert!(message.contains("MAX_BODY_SIZE must be a valid byte size"));
        assert_eq!(error.problems.len(), 2);
    }

    #[test]
    fn zero_global_upstream_and_egress_timeouts_are_rejected_like_route_timeouts() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_TIMEOUT_MS"
            | "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS"
            | "UPSTREAM_CONNECT_TIMEOUT_MS"
            | "EGRESS_TIMEOUT_MS"
            | "EGRESS_RESPONSE_IDLE_TIMEOUT_MS"
            | "EGRESS_CONNECT_TIMEOUT_MS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("zero global timeouts must be rejected the way route timeouts are");

        let message = error.to_string();
        for name in [
            "UPSTREAM_TIMEOUT_MS",
            "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS",
            "UPSTREAM_CONNECT_TIMEOUT_MS",
            "EGRESS_TIMEOUT_MS",
            "EGRESS_RESPONSE_IDLE_TIMEOUT_MS",
            "EGRESS_CONNECT_TIMEOUT_MS",
        ] {
            assert!(
                message.contains(&format!("{name} must be greater than 0, got '0'")),
                "{name} should be rejected with its name and accepted range: {message}"
            );
        }
        assert!(
            message.contains("fails as a timeout"),
            "the rejection should explain why zero is refused: {message}"
        );
        assert_eq!(error.problems.len(), 6);
    }

    #[test]
    fn positive_global_upstream_and_egress_timeouts_are_still_accepted() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_TIMEOUT_MS" => Ok("1".to_owned()),
            "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS" => Ok("2".to_owned()),
            "UPSTREAM_CONNECT_TIMEOUT_MS" => Ok("3".to_owned()),
            "EGRESS_TIMEOUT_MS" => Ok("4".to_owned()),
            "EGRESS_RESPONSE_IDLE_TIMEOUT_MS" => Ok("5".to_owned()),
            "EGRESS_CONNECT_TIMEOUT_MS" => Ok("6".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("positive timeouts should still parse");

        assert_eq!(config.upstream_timeout_ms, Some(1));
        assert_eq!(config.upstream_response_idle_timeout_ms, Some(2));
        assert_eq!(config.upstream_connect_timeout_ms, Some(3));
        assert_eq!(config.egress_timeout_ms, 4);
        assert_eq!(config.egress_response_idle_timeout_ms, 5);
        assert_eq!(config.egress_connect_timeout_ms, 6);
    }

    #[test]
    fn explicit_exempt_paths_keep_the_admin_login_pair_while_admin_login_is_enabled() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PROVIDER" => Ok("primary".to_owned()),
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "issuer": "https://issuer.example.test",
                        "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                        "client_id": "admin-ui",
                        "client_secret": "secret-value",
                        "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
                    }
                ]"#
            .to_owned()),
            "AUTH_EXEMPT_PATHS" | "RBAC_EXEMPT_PATHS" => {
                Ok("/health,/livez,/startupz,/readyz,/version,/metrics".to_owned())
            }
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        // The admin OIDC login and callback routes must stay anonymous or the
        // authorization-code flow cannot complete, so they are appended even to
        // an explicit list. docs/configuration.md and .env.example disclose
        // this exception to the "setting the variable replaces the default"
        // rule; the pairing is asserted in gateway/tests/env_example.rs.
        for paths in [&config.auth_exempt_paths, &config.rbac_exempt_paths] {
            assert!(
                paths.contains(&"/v1/admin/auth/login".to_owned()),
                "{paths:?}"
            );
            assert!(
                paths.contains(&"/v1/admin/auth/callback".to_owned()),
                "{paths:?}"
            );
            assert!(!paths.contains(&"/admin".to_owned()), "{paths:?}");
        }
    }

    #[test]
    fn discovery_sqlite_path_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "DISCOVERY_SQLITE_PATH" => Ok("  /var/lib/greengateway/discovery.sqlite  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.discovery_sqlite_path,
            Some("/var/lib/greengateway/discovery.sqlite".to_owned())
        );
    }

    #[test]
    fn empty_discovery_sqlite_path_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "DISCOVERY_SQLITE_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.discovery_sqlite_path, None);
    }

    #[test]
    fn discovery_endpoint_limit_parses() {
        let config = Config::from_env_vars(|name| match name {
            "DISCOVERY_ENDPOINT_LIMIT" => Ok("2500".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("discovery endpoint limit should parse");

        assert_eq!(config.discovery_endpoint_limit, 2_500);
    }

    #[test]
    fn zero_discovery_endpoint_limit_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "DISCOVERY_ENDPOINT_LIMIT" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("zero discovery endpoint limit should be rejected");

        assert!(error
            .to_string()
            .contains("DISCOVERY_ENDPOINT_LIMIT must be greater than 0, got '0'"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn principal_sqlite_path_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "PRINCIPAL_SQLITE_PATH" => Ok("  /var/lib/greengateway/principals.sqlite  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.principal_sqlite_path,
            Some("/var/lib/greengateway/principals.sqlite".to_owned())
        );
    }

    #[test]
    fn empty_principal_sqlite_path_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "PRINCIPAL_SQLITE_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.principal_sqlite_path, None);
    }

    #[test]
    fn jwks_max_key_age_is_bounded_and_defaults_to_five_minutes() {
        let defaulted = Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("defaults");
        assert_eq!(defaulted.jwt_jwks_max_key_age_secs, 300);

        for rejected in ["0", "86401", "-5", "soon"] {
            let error = Config::from_env_vars(|name| match name {
                "JWT_JWKS_MAX_KEY_AGE_SECS" => Ok(rejected.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("out-of-range or unparseable key age must fail startup");
            assert!(
                error.to_string().contains("JWT_JWKS_MAX_KEY_AGE_SECS"),
                "the problem names the setting: {error}"
            );
        }

        let providers = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{"name":"idp","type":"jwt","jwks_url":"https://idp.example/jwks","jwks_max_key_age_secs":42}]"#.to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("provider config should parse");
        assert_eq!(providers.auth_providers[0].jwks_max_key_age_secs, 42);
    }

    #[test]
    fn connections_sqlite_path_is_explicit_and_optional() {
        let configured = Config::from_env_vars(|name| match name {
            "CONNECTIONS_SQLITE_PATH" => {
                Ok("  /var/lib/greengateway/connections.sqlite  ".to_owned())
            }
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");
        assert_eq!(
            configured.connections_sqlite_path,
            Some("/var/lib/greengateway/connections.sqlite".to_owned())
        );

        let unset = Config::from_env_vars(|name| match name {
            "CONNECTIONS_SQLITE_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("empty path should parse");
        assert_eq!(unset.connections_sqlite_path, None);
    }

    #[test]
    fn operator_secret_aliases_parse_without_exposing_locators_in_debug() {
        let environment_locator = "GGW_BILLING_SECRET_CANARY";
        let file_locator = "partner-private-key.pem";
        let root_locator = "/var/run/greengateway-secret-root-canary";
        let aliases = format!(
            r#"[
                {{"id":"billing-token","label":"Billing token","source":{{"type":"environment","key":"{environment_locator}"}}}},
                {{"id":"partner-key","label":"Partner key","source":{{"type":"file","key":"{file_locator}"}}}}
            ]"#
        );
        let config = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(aliases.clone()),
            "CONNECTION_SECRETS_ROOT" => Ok(root_locator.to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("operator aliases should parse");

        assert_eq!(config.connection_secret_aliases.len(), 2);
        assert_eq!(
            config.connection_secret_aliases[0].source,
            crate::connections::secret::OperatorSecretAliasSource::Environment {
                key: environment_locator.to_owned()
            }
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains(environment_locator));
        assert!(!debug.contains(file_locator));
        assert!(!debug.contains(root_locator));
        assert!(debug.contains("<redacted-locator>"));
    }

    #[test]
    fn operator_file_alias_requires_root_and_errors_redact_locator() {
        let locator_canary = "../host-secret-locator-canary";
        let aliases = format!(
            r#"[{{"id":"billing-token","label":"Billing token","source":{{"type":"file","key":"{locator_canary}"}}}}]"#
        );
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(aliases.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("file alias without a root must fail");
        let message = error.to_string();

        assert!(message.contains("requires CONNECTION_SECRETS_ROOT"));
        assert!(!message.contains(locator_canary));

        let invalid_with_root = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(aliases.clone()),
            "CONNECTION_SECRETS_ROOT" => Ok("/safe/root".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("traversal file key must fail");
        let message = invalid_with_root.to_string();
        assert!(message.contains("invalid file key"));
        assert!(!message.contains(locator_canary));
    }

    #[test]
    fn malformed_operator_alias_json_does_not_echo_input() {
        let locator_canary = "ENVIRONMENT_LOCATOR_CANARY";
        let raw = format!(
            r#"[{{"id":"billing","label":"Billing","source":{{"type":"environment","key":"{locator_canary}"}},"unexpected":true}}]"#
        );
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(raw.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("unknown fields must fail");
        let message = error.to_string();

        assert!(message.contains("invalid shape at line"));
        assert!(!message.contains(locator_canary));
    }

    #[test]
    fn operator_alias_json_is_bounded_before_parsing() {
        let raw = "x".repeat(MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES + 1);
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(raw.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("oversized alias JSON must fail before parsing");

        assert!(error.to_string().contains(&format!(
            "CONNECTION_SECRET_ALIASES must contain at most {MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES} bytes"
        )));
    }

    #[test]
    fn operator_alias_json_bound_includes_surrounding_whitespace() {
        let raw = format!(
            "{}[]{}",
            " ".repeat(MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES),
            " "
        );
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRET_ALIASES" => Ok(raw.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("oversized whitespace around valid JSON must fail before trimming");

        assert!(error.to_string().contains(&format!(
            "CONNECTION_SECRET_ALIASES must contain at most {MAX_OPERATOR_SECRET_ALIAS_CONFIG_BYTES} bytes"
        )));
    }

    #[test]
    fn local_secret_keyring_parses_and_redacts_key_ids_and_locators() {
        let primary_id = "primary-key-id-canary";
        let file_locator = "primary-key-file-canary";
        let root_locator = "/var/run/local-secret-root-canary";
        let database_locator = "/var/lib/local-secret-database-canary.sqlite";
        let keyring =
            format!(r#"[{{"id":"{primary_id}","file":"{file_locator}","role":"primary"}}]"#);
        let config = Config::from_env_vars(|name| match name {
            "CONNECTION_LOCAL_SECRET_KEYRING" => Ok(keyring.clone()),
            "CONNECTION_SECRETS_ROOT" => Ok(root_locator.to_owned()),
            "CONNECTIONS_SQLITE_PATH" => Ok(database_locator.to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("local keyring should parse");

        assert_eq!(config.connection_local_secret_keyring.len(), 1);
        assert_eq!(
            config.connection_local_secret_keyring[0].role,
            crate::connections::local_secret::LocalSecretKeyRole::Primary
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains(primary_id));
        assert!(!debug.contains(file_locator));
        assert!(!debug.contains(root_locator));
        assert!(debug.contains("<redacted-key-id>"));
        assert!(debug.contains("<redacted-locator>"));
    }

    #[test]
    fn local_secret_keyring_requires_store_root_and_exactly_one_primary() {
        let primary = r#"[{"id":"primary","file":"primary.key","role":"primary"}]"#.to_owned();
        let without_dependencies = Config::from_env_vars(|name| match name {
            "CONNECTION_LOCAL_SECRET_KEYRING" => Ok(primary.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("local keyring without store/root must fail");
        let message = without_dependencies.to_string();
        assert!(message.contains("requires CONNECTION_SECRETS_ROOT"));
        assert!(!message.contains("primary.key"));

        let no_primary = r#"[{"id":"old","file":"old.key","role":"decrypt_only"}]"#.to_owned();
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_LOCAL_SECRET_KEYRING" => Ok(no_primary.clone()),
            "CONNECTION_SECRETS_ROOT" => Ok("/safe/root".to_owned()),
            "CONNECTIONS_SQLITE_PATH" => Ok("/safe/connections.sqlite".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("keyring without primary must fail");
        assert!(error.to_string().contains("exactly one primary key"));

        let multiple = r#"[
            {"id":"one","file":"one.key","role":"primary"},
            {"id":"two","file":"two.key","role":"primary"}
        ]"#
        .to_owned();
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_LOCAL_SECRET_KEYRING" => Ok(multiple.clone()),
            "CONNECTION_SECRETS_ROOT" => Ok("/safe/root".to_owned()),
            "CONNECTIONS_SQLITE_PATH" => Ok("/safe/connections.sqlite".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("multiple primary keys must fail");
        assert!(error
            .to_string()
            .contains("must contain only one primary key"));
    }

    #[test]
    fn local_secret_keyring_json_is_bounded_before_trimming_or_parsing() {
        let raw = format!(
            "{}[]{}",
            " ".repeat(MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES),
            " "
        );
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_LOCAL_SECRET_KEYRING" => Ok(raw.clone()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("oversized keyring JSON must fail before trimming");
        assert!(error.to_string().contains(&format!(
            "CONNECTION_LOCAL_SECRET_KEYRING must contain at most {MAX_LOCAL_SECRET_KEYRING_CONFIG_BYTES} bytes"
        )));
    }

    #[test]
    fn payload_capture_config_parses_explicit_opt_in() {
        let config = Config::from_env_vars(|name| match name {
            "DISCOVERY_SQLITE_PATH" => Ok("  /var/lib/greengateway/discovery.sqlite  ".to_owned()),
            "PAYLOAD_CAPTURE_ENABLED" => Ok("true".to_owned()),
            "PAYLOAD_CAPTURE_SAMPLE_RATE" => Ok("0.25".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("payload capture config should parse");

        assert!(config.payload_capture_enabled);
        assert_eq!(config.payload_capture_sample_rate, 0.25);
    }

    #[test]
    fn payload_capture_enabled_requires_discovery_sqlite_path() {
        let error = Config::from_env_vars(|name| match name {
            "PAYLOAD_CAPTURE_ENABLED" => Ok("true".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("payload capture should fail closed without discovery storage");

        let message = error.to_string();
        assert!(message
            .contains("PAYLOAD_CAPTURE_ENABLED=true requires DISCOVERY_SQLITE_PATH to be set"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn invalid_payload_capture_sample_rate_is_rejected() {
        for value in ["1.0", "-0.01", "NaN", "inf"] {
            let error = Config::from_env_vars(|name| match name {
                "DISCOVERY_SQLITE_PATH" => Ok("/tmp/greengateway-discovery.sqlite".to_owned()),
                "PAYLOAD_CAPTURE_ENABLED" => Ok("true".to_owned()),
                "PAYLOAD_CAPTURE_SAMPLE_RATE" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("invalid sample rate should be rejected");

            let message = error.to_string();
            assert!(
                message.contains(
                    "PAYLOAD_CAPTURE_SAMPLE_RATE must be a finite number greater than or equal to 0.0 and less than 1.0"
                ),
                "{message}"
            );
            assert_eq!(error.problems.len(), 1);
        }
    }

    #[test]
    fn discovery_signal_thresholds_parse_from_env() {
        let config = Config::from_env_vars(|name| match name {
            "SCHEMA_MISMATCH_SIGNAL_THRESHOLD" => Ok("7".to_owned()),
            "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD" => Ok("0.25".to_owned()),
            "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD" => Ok("3".to_owned()),
            "VOLUME_OUTLIER_SIGNAL_THRESHOLD" => Ok("4.5".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("discovery signal thresholds should parse");

        assert_eq!(
            config.signal_detector_config(),
            SignalDetectorConfig {
                schema_mismatch_threshold: 7,
                error_rate_spike_threshold: 0.25,
                principal_new_to_endpoint_threshold: 3,
                volume_outlier_threshold: 4.5,
            }
        );
    }

    #[test]
    fn invalid_discovery_signal_thresholds_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "SCHEMA_MISMATCH_SIGNAL_THRESHOLD" => Ok("0".to_owned()),
            "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD" => Ok("1.25".to_owned()),
            "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD" => Ok("0".to_owned()),
            "VOLUME_OUTLIER_SIGNAL_THRESHOLD" => Ok("1.0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("invalid discovery signal thresholds should be rejected");

        let message = error.to_string();
        assert!(message.contains("SCHEMA_MISMATCH_SIGNAL_THRESHOLD must be greater than 0"));
        assert!(message.contains(
            "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD must be a finite number greater than 0.0 and less than or equal to 1.0"
        ));
        assert!(
            message.contains("PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD must be greater than 0")
        );
        assert!(message
            .contains("VOLUME_OUTLIER_SIGNAL_THRESHOLD must be a finite number greater than 1.0"));
        assert_eq!(error.problems.len(), 4);
    }

    #[test]
    fn rule_suggestion_config_parses_from_env() {
        let config = Config::from_env_vars(|name| match name {
            "RULE_SUGGESTION_BASELINE_WINDOW_HOURS" => Ok("72".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("rule suggestion config should parse");

        assert_eq!(
            config.rule_suggestion_config(),
            RuleSuggestionConfig {
                baseline_window_hours: 72,
            }
        );
    }

    #[test]
    fn invalid_rule_suggestion_baseline_window_is_rejected() {
        for value in ["0", "876001"] {
            let error = Config::from_env_vars(|name| match name {
                "RULE_SUGGESTION_BASELINE_WINDOW_HOURS" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("invalid rule suggestion window should be rejected");

            let message = error.to_string();
            assert!(
                message
                    .contains("RULE_SUGGESTION_BASELINE_WINDOW_HOURS must be between 1 and 876000"),
                "{message}"
            );
            assert_eq!(error.problems.len(), 1);
        }
    }

    #[test]
    fn openapi_spec_path_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "OPENAPI_SPEC_PATH" => Ok("  /etc/greengateway/openapi.yaml  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.openapi_spec_path,
            Some(PathBuf::from("/etc/greengateway/openapi.yaml"))
        );
    }

    #[test]
    fn empty_openapi_spec_path_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "OPENAPI_SPEC_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.openapi_spec_path, None);
    }

    #[test]
    fn policy_file_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "POLICY_FILE" => Ok("  /etc/greengateway/policy.json  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.policy_file,
            Some("/etc/greengateway/policy.json".to_owned())
        );
    }

    #[test]
    fn empty_policy_file_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "POLICY_FILE" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.policy_file, None);
    }

    #[test]
    fn tools_file_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "TOOLS_FILE" => Ok("  /etc/greengateway/tools.json  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.tools_file,
            Some("/etc/greengateway/tools.json".to_owned())
        );
    }

    #[test]
    fn empty_tools_file_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "TOOLS_FILE" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.tools_file, None);
    }

    #[test]
    fn policy_history_sqlite_path_parses_optional_path() {
        let config = Config::from_env_vars(|name| match name {
            "POLICY_HISTORY_SQLITE_PATH" => {
                Ok("  /var/lib/greengateway/policy-history.sqlite  ".to_owned())
            }
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.policy_history_sqlite_path,
            Some("/var/lib/greengateway/policy-history.sqlite".to_owned())
        );
    }

    #[test]
    fn empty_policy_history_sqlite_path_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "POLICY_HISTORY_SQLITE_PATH" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.policy_history_sqlite_path, None);
    }

    #[test]
    fn max_body_size_parses() {
        let config = Config::from_env_vars(|name| match name {
            "MAX_BODY_SIZE" => Ok("2097152".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.max_body_size, 2_097_152);
    }

    #[test]
    fn rate_limit_config_parses() {
        let config = Config::from_env_vars(|name| match name {
            "RATE_LIMIT_READ_RPS" => Ok("25.5".to_owned()),
            "RATE_LIMIT_READ_BURST" => Ok("50".to_owned()),
            "RATE_LIMIT_WRITE_RPS" => Ok("5.25".to_owned()),
            "RATE_LIMIT_WRITE_BURST" => Ok("10".to_owned()),
            "RATE_LIMIT_MAX_BUCKETS" => Ok("4096".to_owned()),
            "RATE_LIMIT_BUCKET_TTL_MS" => Ok("120000".to_owned()),
            "TRUST_PROXY_HEADERS" => Ok("true".to_owned()),
            "TRUSTED_PROXY_CIDRS" => Ok("10.0.0.0/8, 2001:db8::/32".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.rate_limit_read_rps, 25.5);
        assert_eq!(config.rate_limit_read_burst, 50);
        assert_eq!(config.rate_limit_write_rps, 5.25);
        assert_eq!(config.rate_limit_write_burst, 10);
        assert_eq!(config.rate_limit_max_buckets, 4096);
        assert_eq!(config.rate_limit_bucket_ttl_ms, 120_000);
        assert!(config.trust_proxy_headers);
        assert_eq!(
            config.trusted_proxy_cidrs,
            vec![
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "2001:db8::/32".parse::<IpNet>().unwrap()
            ]
        );
    }

    /// The bucket ceiling and TTL are what bound the limiter's memory, so a
    /// value that bounds nothing is refused rather than defaulted to.
    #[test]
    fn rate_limit_bucket_bounds_are_validated() {
        let zero_buckets = Config::from_env_vars(|name| match name {
            "RATE_LIMIT_MAX_BUCKETS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a zero bucket ceiling must not start");
        assert!(
            zero_buckets
                .to_string()
                .contains("RATE_LIMIT_MAX_BUCKETS must be greater than 0"),
            "{zero_buckets}"
        );

        let zero_ttl = Config::from_env_vars(|name| match name {
            "RATE_LIMIT_BUCKET_TTL_MS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a zero bucket TTL must not start");
        assert!(
            zero_ttl
                .to_string()
                .contains("RATE_LIMIT_BUCKET_TTL_MS must be greater than 0"),
            "{zero_ttl}"
        );
    }

    #[test]
    fn rate_limit_bucket_defaults_apply() {
        let config = Config::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("an unconfigured gateway should validate");

        assert_eq!(
            config.rate_limit_max_buckets,
            DEFAULT_RATE_LIMIT_MAX_BUCKETS
        );
        assert_eq!(
            config.rate_limit_bucket_ttl_ms,
            DEFAULT_RATE_LIMIT_BUCKET_TTL_MS
        );
    }

    #[test]
    fn shutdown_config_defaults_and_explicit_values_parse() {
        let defaults =
            Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");
        assert_eq!(
            defaults.shutdown_drain_delay_ms,
            DEFAULT_SHUTDOWN_DRAIN_DELAY_MS
        );
        assert_eq!(defaults.shutdown_timeout_ms, DEFAULT_SHUTDOWN_TIMEOUT_MS);
        assert_eq!(
            defaults.audit_drain_timeout_ms,
            DEFAULT_AUDIT_DRAIN_TIMEOUT_MS
        );

        let configured = Config::from_env_vars(|name| match name {
            "SHUTDOWN_DRAIN_DELAY_MS" => Ok("0".to_owned()),
            "SHUTDOWN_TIMEOUT_MS" => Ok("45000".to_owned()),
            "AUDIT_DRAIN_TIMEOUT_MS" => Ok("7500".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("shutdown configuration should parse");
        assert_eq!(configured.shutdown_drain_delay_ms, 0);
        assert_eq!(configured.shutdown_timeout_ms, 45_000);
        assert_eq!(configured.audit_drain_timeout_ms, 7_500);
    }

    #[test]
    fn invalid_shutdown_config_is_rejected_with_all_problems() {
        let error = Config::from_env_vars(|name| match name {
            "SHUTDOWN_DRAIN_DELAY_MS" => Ok("30001".to_owned()),
            "SHUTDOWN_TIMEOUT_MS" => Ok("0".to_owned()),
            "AUDIT_DRAIN_TIMEOUT_MS" => Ok("not-a-duration".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("invalid shutdown configuration must fail startup");

        let message = error.to_string();
        assert!(message.contains("SHUTDOWN_DRAIN_DELAY_MS must be at most 30000"));
        assert!(message.contains("SHUTDOWN_TIMEOUT_MS must be between 1 and 300000"));
        assert!(message.contains("AUDIT_DRAIN_TIMEOUT_MS must be a valid millisecond duration"));
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn trusted_proxy_headers_require_at_least_one_cidr() {
        let error = Config::from_env_vars(|name| match name {
            "TRUST_PROXY_HEADERS" => Ok("true".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("trusted proxy headers without a peer boundary must fail closed");

        assert!(error.to_string().contains(
            "TRUSTED_PROXY_CIDRS must contain at least one CIDR when TRUST_PROXY_HEADERS=true"
        ));
    }

    #[test]
    fn invalid_trusted_proxy_cidrs_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "TRUST_PROXY_HEADERS" => Ok("true".to_owned()),
            "TRUSTED_PROXY_CIDRS" => Ok("10.0.0.0/8, 192.0.2.0/99".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("invalid trusted proxy CIDRs must fail startup");

        assert!(error
            .to_string()
            .contains("TRUSTED_PROXY_CIDRS entries must be valid CIDRs"));
    }

    #[test]
    fn dormant_trusted_proxy_cidrs_are_still_validated() {
        let error = Config::from_env_vars(|name| match name {
            "TRUST_PROXY_HEADERS" => Ok("false".to_owned()),
            "TRUSTED_PROXY_CIDRS" => Ok("not-a-cidr".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("dormant trusted proxy CIDRs must still be valid configuration");

        assert!(error
            .to_string()
            .contains("TRUSTED_PROXY_CIDRS entries must be valid CIDRs"));
    }

    #[test]
    fn catch_all_trusted_proxy_cidrs_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "TRUST_PROXY_HEADERS" => Ok("true".to_owned()),
            "TRUSTED_PROXY_CIDRS" => Ok("0.0.0.0/0, ::/0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("catch-all trusted proxy CIDRs must fail startup");

        assert_eq!(
            error
                .problems
                .iter()
                .filter(|problem| problem.contains("catch-all CIDR"))
                .count(),
            2
        );
    }

    #[test]
    fn invalid_rate_limit_values_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "RATE_LIMIT_READ_RPS" => Ok("NaN".to_owned()),
            "RATE_LIMIT_READ_BURST" => Ok("not-a-burst".to_owned()),
            "RATE_LIMIT_WRITE_RPS" => Ok("-1".to_owned()),
            "TRUST_PROXY_HEADERS" => Ok("maybe".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid rate-limit settings");

        let message = error.to_string();
        assert!(message.contains("RATE_LIMIT_READ_RPS must be a finite non-negative"));
        assert!(message.contains("RATE_LIMIT_READ_BURST must be a valid request burst size"));
        assert!(message.contains("RATE_LIMIT_WRITE_RPS must be a finite non-negative"));
        assert!(message.contains("TRUST_PROXY_HEADERS must be a valid boolean"));
        assert_eq!(error.problems.len(), 4);
    }

    #[test]
    fn invalid_max_body_size_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "MAX_BODY_SIZE" => Ok("not-a-size".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid body sizes");

        let message = error.to_string();
        assert!(message.contains("MAX_BODY_SIZE must be a valid byte size"));
        assert!(message.contains("not-a-size"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn validation_allowed_content_types_defaults_to_json() {
        let config =
            Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");

        assert_eq!(
            config.validation_allowed_content_types,
            vec!["application/json".to_owned()]
        );
    }

    #[test]
    fn validation_allowed_content_types_parses_comma_separated_list() {
        let config = Config::from_env_vars(|name| match name {
            "VALIDATION_ALLOWED_CONTENT_TYPES" => {
                Ok(" application/json,multipart/form-data,, application/x-ndjson ".to_owned())
            }
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.validation_allowed_content_types,
            vec![
                "application/json".to_owned(),
                "multipart/form-data".to_owned(),
                "application/x-ndjson".to_owned(),
            ]
        );
    }

    #[test]
    fn invalid_validation_allowed_content_type_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "VALIDATION_ALLOWED_CONTENT_TYPES" => Ok("application/json,bad\nvalue".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid content type header values");

        let message = error.to_string();
        assert!(message
            .contains("VALIDATION_ALLOWED_CONTENT_TYPES entries must be valid HTTP header values"));
        assert!(message.contains("bad\nvalue"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn auth_config_parses() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_ENABLED" => Ok("false".to_owned()),
            "AUTH_MODE" => Ok("observe".to_owned()),
            "AUTH_COOKIE_NAME" => Ok("gateway_session".to_owned()),
            "AUTH_EXEMPT_PATHS" => Ok(" /health, /ready ,, /metrics ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert!(!config.auth_enabled);
        assert_eq!(config.auth_mode, AuthMode::Observe);
        assert_eq!(config.auth_cookie_name, "gateway_session");
        assert_eq!(
            config.auth_exempt_paths,
            vec![
                "/health".to_owned(),
                "/ready".to_owned(),
                "/metrics".to_owned(),
            ]
        );
    }

    #[test]
    fn auth_mode_parses_required_and_defaults_to_required() {
        let explicit = Config::from_env_vars(|name| match name {
            "AUTH_MODE" => Ok("required".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");
        assert_eq!(explicit.auth_mode, AuthMode::Required);

        let defaulted =
            Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");
        assert_eq!(defaulted.auth_mode, AuthMode::Required);
    }

    #[test]
    fn rbac_exempt_paths_parse_comma_separated_list() {
        let config = Config::from_env_vars(|name| match name {
            "RBAC_EXEMPT_PATHS" => Ok(" /health, /ready ,, /metrics ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/ready".to_owned(),
                "/metrics".to_owned()
            ]
        );
    }

    #[test]
    fn invalid_rbac_exempt_paths_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "RBAC_EXEMPT_PATHS" => Ok("/health,admin".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid RBAC exempt paths");

        let message = error.to_string();
        assert!(message.contains("RBAC_EXEMPT_PATHS entries must be URI paths"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn invalid_auth_config_values_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_ENABLED" => Ok("maybe".to_owned()),
            "AUTH_MODE" => Ok("optional".to_owned()),
            "AUTH_COOKIE_NAME" => Ok("session token".to_owned()),
            "AUTH_EXEMPT_PATHS" => Ok("/health,admin".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid auth settings");

        let message = error.to_string();
        assert!(message.contains("AUTH_ENABLED must be a valid boolean"));
        assert!(message.contains("AUTH_MODE must be a valid auth mode"));
        assert!(message.contains("expected `required` or `observe`"));
        assert!(message.contains("AUTH_COOKIE_NAME must be a non-empty RFC 6265 cookie name"));
        assert!(message.contains("AUTH_EXEMPT_PATHS entries must be URI paths"));
        assert_eq!(error.problems.len(), 4);
    }

    #[test]
    fn jwt_config_parses() {
        let config = Config::from_env_vars(|name| match name {
            "JWT_JWKS_URL" => {
                Ok("  https://issuer.example.test/.well-known/jwks.json  ".to_owned())
            }
            "JWT_ISSUER" => Ok("  https://issuer.example.test/  ".to_owned()),
            "JWT_AUDIENCE" => Ok("  greengateway  ".to_owned()),
            "JWT_JWKS_TIMEOUT_MS" => Ok("5000".to_owned()),
            "JWT_REQUIRE_JTI" => Ok("true".to_owned()),
            "ROLES_CLAIM" => Ok(" groups ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.jwt_jwks_url,
            Some("https://issuer.example.test/.well-known/jwks.json".to_owned())
        );
        assert_eq!(
            config.jwt_issuer,
            Some("https://issuer.example.test/".to_owned())
        );
        assert_eq!(config.jwt_audience, Some("greengateway".to_owned()));
        assert_eq!(config.jwt_jwks_timeout_ms, 5000);
        assert!(config.jwt_require_jti);
        assert_eq!(config.roles_claim, "groups");
    }

    #[test]
    fn gateway_public_url_parses_optional_https_url() {
        let config = Config::from_env_vars(|name| match name {
            "GATEWAY_PUBLIC_URL" => Ok("  https://gateway.example.test/base/  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.gateway_public_url,
            Some("https://gateway.example.test/base/".to_owned())
        );
    }

    #[test]
    fn invalid_gateway_public_url_values_are_rejected() {
        for (value, expected) in [
            (
                "not a url",
                "GATEWAY_PUBLIC_URL must be a valid http or https URL",
            ),
            (
                "mailto:ops@example.test",
                "GATEWAY_PUBLIC_URL must be a valid http or https URL with a host",
            ),
            (
                "ftp://gateway.example.test",
                "GATEWAY_PUBLIC_URL must use http or https",
            ),
        ] {
            let error = Config::from_env_vars(|name| match name {
                "GATEWAY_PUBLIC_URL" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("config should reject invalid public URL");

            let message = error.to_string();
            assert!(message.contains(expected), "{message}");
            assert_eq!(error.problems.len(), 1);
        }
    }

    #[test]
    fn gateway_public_url_rejects_fragment() {
        let error = Config::from_env_vars(|name| match name {
            "GATEWAY_PUBLIC_URL" => Ok("https://gateway.example.test/#metadata".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject public URL fragments");

        let message = error.to_string();
        assert!(
            message.contains("GATEWAY_PUBLIC_URL must not contain URL userinfo or a fragment"),
            "{message}"
        );
        assert!(!message.contains("https://gateway.example.test/#metadata"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn gateway_public_url_allows_http_loopback_for_local_development() {
        for value in [
            "http://localhost:8080/base",
            "http://127.0.0.1:8080/base",
            "http://[::1]:8080/base",
        ] {
            let config = Config::from_env_vars(|name| match name {
                "GATEWAY_PUBLIC_URL" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect("loopback HTTP public URL should parse");

            assert_eq!(config.gateway_public_url, Some(value.to_owned()));
        }
    }

    #[test]
    fn gateway_public_url_allows_http_ipv4_mapped_ipv6_loopback_for_local_development() {
        let value = "http://[::ffff:127.0.0.1]:8080/base";
        let config = Config::from_env_vars(|name| match name {
            "GATEWAY_PUBLIC_URL" => Ok(value.to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("IPv4-mapped IPv6 loopback HTTP public URL should parse");

        assert_eq!(config.gateway_public_url, Some(value.to_owned()));
    }

    #[test]
    fn gateway_public_url_rejects_http_non_loopback_hosts() {
        let error = Config::from_env_vars(|name| match name {
            "GATEWAY_PUBLIC_URL" => Ok("http://gateway.example.test/base".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("non-loopback HTTP public URL should be rejected");

        let message = error.to_string();
        assert!(
            message.contains("GATEWAY_PUBLIC_URL must use https unless the host is loopback"),
            "{message}"
        );
        assert!(message.contains("http://gateway.example.test/base"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn auth_providers_parse_ordered_jwt_list() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": " primary ",
                        "type": "jwt",
                        "jwks_url": " https://primary.example.test/.well-known/jwks.json ",
                        "issuer": " https://primary.example.test/ ",
                        "audience": " greengateway ",
                        "jwks_timeout_ms": 7000,
                        "require_jti": true,
                        "roles_claim": " groups ",
                        "roles_claim_delimiter": " ",
                        "org_claim": " tenant.id "
                    },
                    {
                        "name": "secondary",
                        "type": "jwt",
                        "jwks_url": "https://secondary.example.test/.well-known/jwks.json",
                        "issuer": "https://secondary.example.test/"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.auth_providers,
            vec![
                AuthProviderConfig {
                    name: "primary".to_owned(),
                    provider_type: AuthProviderType::Jwt,
                    jwks_url: Some("https://primary.example.test/.well-known/jwks.json".to_owned(),),
                    issuer: Some("https://primary.example.test".to_owned()),
                    audience: Some("greengateway".to_owned()),
                    jwks_timeout_ms: 7000,
                    jwks_max_key_age_secs: 300,
                    require_jti: true,
                    roles_claim: "groups".to_owned(),
                    roles_claim_delimiter: Some(" ".to_owned()),
                    org_claim: Some("tenant.id".to_owned()),
                    introspection_url: None,
                    introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                    cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                    user_id_claim: None,
                    email_claim: None,
                    client_id: None,
                    client_secret: None,
                    redirect_uri: None,
                },
                AuthProviderConfig {
                    name: "secondary".to_owned(),
                    provider_type: AuthProviderType::Jwt,
                    jwks_url: Some(
                        "https://secondary.example.test/.well-known/jwks.json".to_owned(),
                    ),
                    issuer: Some("https://secondary.example.test".to_owned()),
                    audience: None,
                    jwks_timeout_ms: DEFAULT_JWT_JWKS_TIMEOUT_MS,
                    jwks_max_key_age_secs: 300,
                    require_jti: false,
                    roles_claim: DEFAULT_ROLES_CLAIM.to_owned(),
                    roles_claim_delimiter: None,
                    org_claim: None,
                    introspection_url: None,
                    introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                    cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                    user_id_claim: None,
                    email_claim: None,
                    client_id: None,
                    client_secret: None,
                    redirect_uri: None,
                },
            ]
        );
    }

    #[test]
    fn auth_providers_reject_multiple_jwt_providers_with_missing_issuers() {
        for (providers, missing_issuer_indices) in [
            (
                r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "jwks_url": "https://shared.example.test/jwks.json",
                        "issuer": "https://primary.example.test/"
                    },
                    {
                        "name": "secondary",
                        "type": "jwt",
                        "jwks_url": "https://shared.example.test/jwks.json"
                    }
                ]"#,
                &[1][..],
            ),
            (
                r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "jwks_url": "https://shared.example.test/jwks.json"
                    },
                    {
                        "name": "secondary",
                        "type": "jwt",
                        "jwks_url": "https://shared.example.test/jwks.json"
                    }
                ]"#,
                &[0, 1][..],
            ),
        ] {
            let error = Config::from_env_vars(|name| match name {
                AUTH_PROVIDERS => Ok(providers.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("multiple JWT providers must each configure an issuer");

            let message = error.to_string();
            for index in missing_issuer_indices {
                assert!(message.contains(&format!(
                    "AUTH_PROVIDERS[{index}].issuer must be explicitly configured when more than one JWT provider is configured"
                )));
            }
            assert_eq!(error.problems.len(), missing_issuer_indices.len());
        }
    }

    #[test]
    fn auth_providers_accept_single_issuerless_jwt_provider() {
        let config = Config::from_env_vars(|name| match name {
            AUTH_PROVIDERS => Ok(r#"[{
                    "name": "legacy",
                    "type": "jwt",
                    "jwks_url": "https://legacy.example.test/jwks.json"
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("a single issuerless JWT provider should remain supported");

        assert_eq!(config.auth_providers.len(), 1);
        assert_eq!(
            config.auth_providers[0].provider_type,
            AuthProviderType::Jwt
        );
        assert_eq!(config.auth_providers[0].issuer, None);
    }

    #[test]
    fn auth_providers_accept_issuerless_jwt_with_cookie_session_provider() {
        let config = Config::from_env_vars(|name| match name {
            AUTH_PROVIDERS => Ok(r#"[
                    {
                        "name": "legacy",
                        "type": "jwt",
                        "jwks_url": "https://legacy.example.test/jwks.json"
                    },
                    {
                        "name": "app-session",
                        "type": "cookie_session",
                        "introspection_url": "https://app.example.test/session/introspect",
                        "user_id_claim": "sub"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("cookie-session providers should not trigger the multi-JWT issuer requirement");

        assert_eq!(config.auth_providers.len(), 2);
        assert_eq!(
            config.auth_providers[0].provider_type,
            AuthProviderType::Jwt
        );
        assert_eq!(config.auth_providers[0].issuer, None);
        assert_eq!(
            config.auth_providers[1].provider_type,
            AuthProviderType::CookieSession
        );
    }

    #[test]
    fn admin_login_provider_parses_oidc_client_settings() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PROVIDER" => Ok("primary".to_owned()),
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "issuer": " https://issuer.example.test/ ",
                        "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                        "client_id": " admin-ui ",
                        "client_secret": " secret-value ",
                        "redirect_uri": " https://gateway.example.test/v1/admin/auth/callback "
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("admin login provider should parse");

        assert_eq!(config.admin_login_provider.as_deref(), Some("primary"));
        assert_eq!(
            config.auth_providers[0].client_id.as_deref(),
            Some("admin-ui")
        );
        assert_eq!(
            config.auth_providers[0].client_secret.as_deref(),
            Some("secret-value")
        );
        assert_eq!(
            config.auth_providers[0].redirect_uri.as_deref(),
            Some("https://gateway.example.test/v1/admin/auth/callback")
        );
    }

    #[test]
    fn admin_login_pending_limits_parse() {
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PENDING_TTL_SECS" => Ok("45".to_owned()),
            "ADMIN_LOGIN_PENDING_MAX_ENTRIES" => Ok("64".to_owned()),
            "ADMIN_LOGIN_PENDING_MAX_PER_IP" => Ok("3".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("admin login pending-state limits should parse");

        assert_eq!(config.admin_login_pending_ttl_secs, 45);
        assert_eq!(config.admin_login_pending_max_entries, 64);
        assert_eq!(config.admin_login_pending_max_per_ip, 3);
    }

    #[test]
    fn admin_login_pending_limits_must_be_positive() {
        let error = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PENDING_TTL_SECS"
            | "ADMIN_LOGIN_PENDING_MAX_ENTRIES"
            | "ADMIN_LOGIN_PENDING_MAX_PER_IP" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("admin login pending-state limits should reject zero");

        let message = error.to_string();
        assert!(message.contains("ADMIN_LOGIN_PENDING_TTL_SECS must be greater than 0"));
        assert!(message.contains("ADMIN_LOGIN_PENDING_MAX_ENTRIES must be greater than 0"));
        assert!(message.contains("ADMIN_LOGIN_PENDING_MAX_PER_IP must be greater than 0"));
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn auth_provider_config_debug_redacts_client_secret() {
        let secret = "auth-provider-secret-value";
        let config = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PROVIDER" => Ok("primary".to_owned()),
            "AUTH_PROVIDERS" => Ok(format!(
                r#"[
                    {{
                        "name": "primary",
                        "type": "jwt",
                        "issuer": "https://issuer.example.test/",
                        "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                        "client_id": "admin-ui",
                        "client_secret": "{secret}",
                        "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
                    }}
                ]"#
            )),
            _ => Err(VarError::NotPresent),
        })
        .expect("admin login provider should parse");

        let output = format!("{:?}", config.auth_providers[0]);

        assert!(!output.contains(secret));
        assert!(output.contains("<redacted>"));
        assert!(output.contains("client_secret"));
    }

    #[test]
    fn raw_auth_provider_config_debug_redacts_client_secret() {
        let secret = "raw-auth-provider-secret-value";
        let raw_with_secret: RawAuthProviderConfig = serde_json::from_str(&format!(
            r#"{{
                "name": "primary",
                "type": "jwt",
                "issuer": "https://issuer.example.test/",
                "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                "client_id": "admin-ui",
                "client_secret": "{secret}",
                "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
            }}"#
        ))
        .expect("raw auth provider should parse");

        let output = format!("{:?}", raw_with_secret);

        assert!(!output.contains(secret));
        assert!(output.contains("<redacted>"));
        assert!(output.contains("client_secret"));

        let raw_without_secret: RawAuthProviderConfig = serde_json::from_str(
            r#"{
                "name": "primary",
                "type": "jwt",
                "issuer": "https://issuer.example.test/",
                "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                "client_id": "admin-ui",
                "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
            }"#,
        )
        .expect("raw auth provider without secret should parse");

        let output_without_secret = format!("{:?}", raw_without_secret);

        assert!(output_without_secret.contains("client_secret: None"));
    }

    #[test]
    fn admin_login_provider_collects_static_validation_problems() {
        let error = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PROVIDER" => Ok("session-provider".to_owned()),
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "session-provider",
                        "type": "cookie_session",
                        "introspection_url": "https://session.example.test/introspect",
                        "user_id_claim": "sub"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("admin login provider should reject non-OIDC client config");

        let message = error.to_string();
        assert!(message.contains(
            "ADMIN_LOGIN_PROVIDER references provider 'session-provider' which must be type 'jwt'"
        ));
        assert!(
            message.contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set client_id")
        );
        assert!(message
            .contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set client_secret"));
        assert!(message
            .contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set redirect_uri"));
        assert!(message.contains(
            "ADMIN_LOGIN_PROVIDER provider 'session-provider' must set issuer for OIDC discovery"
        ));
        assert_eq!(error.problems.len(), 5);
    }

    #[test]
    fn admin_login_provider_must_reference_existing_provider() {
        let error = Config::from_env_vars(|name| match name {
            "ADMIN_LOGIN_PROVIDER" => Ok("missing".to_owned()),
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "issuer": "https://issuer.example.test/",
                        "client_id": "admin-ui",
                        "client_secret": "secret-value",
                        "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("admin login provider should require a known provider name");

        assert!(error
            .to_string()
            .contains("ADMIN_LOGIN_PROVIDER references unknown auth provider 'missing'"));
    }

    #[test]
    fn auth_providers_treat_empty_optional_claim_mapping_fields_as_unset() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "primary",
                    "type": "jwt",
                    "jwks_url": "https://primary.example.test/.well-known/jwks.json",
                    "roles_claim_delimiter": "",
                    "org_claim": "   "
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.auth_providers,
            vec![AuthProviderConfig {
                name: "primary".to_owned(),
                provider_type: AuthProviderType::Jwt,
                jwks_url: Some("https://primary.example.test/.well-known/jwks.json".to_owned()),
                issuer: None,
                audience: None,
                jwks_timeout_ms: DEFAULT_JWT_JWKS_TIMEOUT_MS,
                jwks_max_key_age_secs: 300,
                require_jti: false,
                roles_claim: DEFAULT_ROLES_CLAIM.to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
                introspection_url: None,
                introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                user_id_claim: None,
                email_claim: None,
                client_id: None,
                client_secret: None,
                redirect_uri: None,
            }]
        );
    }

    #[test]
    fn auth_providers_parse_cookie_session_provider() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "app-session",
                    "type": "cookie_session",
                    "introspection_url": " https://app.example.test/session/introspect ",
                    "introspection_timeout_ms": 1500,
                    "cache_ttl_ms": 750,
                    "user_id_claim": " account.id ",
                    "email_claim": " account.email ",
                    "org_claim": " account.tenant.id ",
                    "roles_claim": " account.scope ",
                    "roles_claim_delimiter": " "
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("cookie-session provider should parse");

        assert_eq!(
            config.auth_providers,
            vec![AuthProviderConfig {
                name: "app-session".to_owned(),
                provider_type: AuthProviderType::CookieSession,
                jwks_url: None,
                issuer: None,
                audience: None,
                jwks_timeout_ms: DEFAULT_JWT_JWKS_TIMEOUT_MS,
                jwks_max_key_age_secs: 300,
                require_jti: false,
                roles_claim: "account.scope".to_owned(),
                roles_claim_delimiter: Some(" ".to_owned()),
                org_claim: Some("account.tenant.id".to_owned()),
                introspection_url: Some("https://app.example.test/session/introspect".to_owned()),
                introspection_timeout_ms: 1500,
                cache_ttl_ms: 750,
                user_id_claim: Some("account.id".to_owned()),
                email_claim: Some("account.email".to_owned()),
                client_id: None,
                client_secret: None,
                redirect_uri: None,
            }]
        );
    }

    #[test]
    fn auth_providers_reject_cookie_session_provider_without_required_fields() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "app-session",
                    "type": "cookie_session",
                    "cache_ttl_ms": 0,
                    "user_id_claim": "   "
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("cookie-session provider should require introspection URL and user id claim");

        let message = error.to_string();
        assert!(message.contains("AUTH_PROVIDERS[0] must set introspection_url"));
        assert!(message.contains("AUTH_PROVIDERS[0].user_id_claim must be a non-empty string"));
        assert!(message.contains("AUTH_PROVIDERS[0].cache_ttl_ms must be greater than 0"));
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn auth_provider_doc_examples_parse_as_configured_providers() {
        let examples = auth_provider_doc_examples();
        let found_labels = examples
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>();
        let mut expected = HashMap::from([
            (
                "keycloak-realm",
                vec![jwt_doc_provider(
                    "keycloak",
                    "https://keycloak.example.com/realms/acme",
                    Some("greengateway-api"),
                    "realm_access.roles",
                    None,
                    None,
                )],
            ),
            (
                "keycloak-client-roles",
                vec![jwt_doc_provider(
                    "keycloak-client-roles",
                    "https://keycloak.example.com/realms/acme",
                    Some("greengateway-api"),
                    "resource_access.greengateway-api.roles",
                    None,
                    None,
                )],
            ),
            (
                "keycloak-scope",
                vec![jwt_doc_provider(
                    "keycloak-scope",
                    "https://keycloak.example.com/realms/acme",
                    Some("greengateway-api"),
                    "scope",
                    Some(" "),
                    None,
                )],
            ),
            (
                "auth0-namespaced-roles",
                vec![jwt_doc_provider(
                    "auth0",
                    "https://your-tenant.us.auth0.com/",
                    Some("https://api.example.com"),
                    "https://greengateway.example.com/roles",
                    None,
                    Some("org_id"),
                )],
            ),
            (
                "entra-app-roles",
                vec![jwt_doc_provider(
                    "entra-app-roles",
                    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                    Some("api://22222222-2222-2222-2222-222222222222"),
                    "roles",
                    None,
                    Some("tid"),
                )],
            ),
            (
                "entra-groups",
                vec![jwt_doc_provider(
                    "entra-groups",
                    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                    Some("api://22222222-2222-2222-2222-222222222222"),
                    "groups",
                    None,
                    Some("tid"),
                )],
            ),
            (
                "okta-groups",
                vec![jwt_doc_provider(
                    "okta",
                    "https://your-org.okta.com/oauth2/default",
                    Some("api://greengateway"),
                    "groups",
                    None,
                    None,
                )],
            ),
        ]);

        assert_eq!(
            examples.len(),
            expected.len(),
            "unexpected doc example set: {found_labels:?}"
        );

        for (label, json) in examples {
            let expected_providers = expected
                .remove(label.as_str())
                .unwrap_or_else(|| panic!("unexpected AUTH_PROVIDERS doc example: {label}"));
            let config = Config::from_env_vars(|name| match name {
                AUTH_PROVIDERS => Ok(json.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .unwrap_or_else(|err| panic!("{label} AUTH_PROVIDERS example should parse: {err}"));

            assert_eq!(
                config.auth_providers, expected_providers,
                "{label} AUTH_PROVIDERS example parsed to an unexpected provider config"
            );
        }

        assert!(
            expected.is_empty(),
            "missing AUTH_PROVIDERS doc examples: {:?}",
            expected.keys().collect::<Vec<_>>()
        );
    }

    fn auth_provider_doc_examples() -> Vec<(String, &'static str)> {
        [
            ("keycloak", include_str!("../../docs/auth/keycloak.md")),
            ("auth0", include_str!("../../docs/auth/auth0.md")),
            ("entra-id", include_str!("../../docs/auth/entra-id.md")),
            ("okta", include_str!("../../docs/auth/okta.md")),
        ]
        .into_iter()
        .flat_map(|(doc_name, markdown)| extract_auth_provider_doc_examples(doc_name, markdown))
        .collect()
    }

    fn extract_auth_provider_doc_examples(
        doc_name: &str,
        markdown: &'static str,
    ) -> Vec<(String, &'static str)> {
        const MARKER_PREFIX: &str = "<!-- auth-providers-example:";
        const MARKER_SUFFIX: &str = "-->";
        const JSON_FENCE: &str = "```json";
        const FENCE: &str = "```";

        let mut examples = Vec::new();
        let mut remaining = markdown;

        while let Some(marker_start) = remaining.find(MARKER_PREFIX) {
            let after_prefix = &remaining[marker_start + MARKER_PREFIX.len()..];
            let marker_end = after_prefix
                .find(MARKER_SUFFIX)
                .unwrap_or_else(|| panic!("{doc_name} auth provider example marker is unclosed"));
            let label = after_prefix[..marker_end].trim().to_owned();
            let after_marker = &after_prefix[marker_end + MARKER_SUFFIX.len()..];
            let fence_start = after_marker.find(JSON_FENCE).unwrap_or_else(|| {
                panic!("{doc_name} auth provider example {label} is missing a json code fence")
            });
            let after_fence = &after_marker[fence_start + JSON_FENCE.len()..];
            let json_start = after_fence
                .strip_prefix("\r\n")
                .or_else(|| after_fence.strip_prefix('\n'))
                .unwrap_or(after_fence);
            let fence_end = json_start.find(FENCE).unwrap_or_else(|| {
                panic!("{doc_name} auth provider example {label} json fence is unclosed")
            });
            let json = &json_start[..fence_end];

            examples.push((label, json));
            remaining = &json_start[fence_end + FENCE.len()..];
        }

        examples
    }

    fn jwt_doc_provider(
        name: &str,
        issuer: &str,
        audience: Option<&str>,
        roles_claim: &str,
        roles_claim_delimiter: Option<&str>,
        org_claim: Option<&str>,
    ) -> AuthProviderConfig {
        AuthProviderConfig {
            name: name.to_owned(),
            provider_type: AuthProviderType::Jwt,
            jwks_url: None,
            issuer: canonical_issuer(issuer),
            audience: audience.map(str::to_owned),
            jwks_timeout_ms: DEFAULT_JWT_JWKS_TIMEOUT_MS,
            jwks_max_key_age_secs: 300,
            require_jti: false,
            roles_claim: roles_claim.to_owned(),
            roles_claim_delimiter: roles_claim_delimiter.map(str::to_owned),
            org_claim: org_claim.map(str::to_owned),
            introspection_url: None,
            introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }
    }

    #[test]
    fn auth_providers_accept_issuer_only_jwt_provider_for_oidc_discovery() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "oidc",
                    "type": "jwt",
                    "issuer": " https://issuer.example.test/ ",
                    "audience": " greengateway "
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("issuer-only JWT provider should parse");

        assert_eq!(
            config.auth_providers,
            vec![AuthProviderConfig {
                name: "oidc".to_owned(),
                provider_type: AuthProviderType::Jwt,
                jwks_url: None,
                issuer: Some("https://issuer.example.test".to_owned()),
                audience: Some("greengateway".to_owned()),
                jwks_timeout_ms: DEFAULT_JWT_JWKS_TIMEOUT_MS,
                jwks_max_key_age_secs: 300,
                require_jti: false,
                roles_claim: DEFAULT_ROLES_CLAIM.to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
                introspection_url: None,
                introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                user_id_claim: None,
                email_claim: None,
                client_id: None,
                client_secret: None,
                redirect_uri: None,
            }]
        );
    }

    #[test]
    fn auth_providers_reject_explicit_issuer_that_canonicalizes_to_empty() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "invalid-issuer",
                    "type": "jwt",
                    "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                    "issuer": " / "
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("an explicitly configured empty canonical issuer should fail validation");

        assert!(error.to_string().contains(
            "AUTH_PROVIDERS[0].issuer must be non-empty after trimming whitespace and trailing slashes"
        ));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn auth_providers_reject_jwt_provider_without_jwks_url_or_issuer() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[{
                    "name": "missing-keys",
                    "type": "jwt"
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("JWT provider should require jwks_url or issuer");

        let message = error.to_string();
        assert!(message.contains("AUTH_PROVIDERS[0] must set jwks_url or issuer"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn auth_providers_reject_reserved_and_duplicate_effective_issuers() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "fallback",
                        "type": "cookie_session",
                        "introspection_url": "https://fallback.example.test/introspect",
                        "user_id_claim": "sub"
                    },
                    {
                        "name": "reserved",
                        "type": "jwt",
                        "issuer": "provider:fallback"
                    },
                    {
                        "name": "issuer-a",
                        "type": "jwt",
                        "issuer": "https://issuer.example.test/"
                    },
                    {
                        "name": "issuer-b",
                        "type": "jwt",
                        "issuer": "https://issuer.example.test"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject colliding effective issuer boundaries");

        let message = error.to_string();
        assert!(
            message.contains("AUTH_PROVIDERS[1].issuer must not use reserved prefix 'provider:'")
        );
        assert!(message.contains(
            "AUTH_PROVIDERS[1] effective issuer 'provider:fallback' duplicates AUTH_PROVIDERS[0]"
        ));
        assert!(message.contains(
            "AUTH_PROVIDERS[3] effective issuer 'https://issuer.example.test' duplicates AUTH_PROVIDERS[2]"
        ));
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn malformed_auth_providers_json_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok("not-json".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject malformed AUTH_PROVIDERS JSON");

        let message = error.to_string();
        assert!(message.contains("AUTH_PROVIDERS must be a JSON array of auth provider objects"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn duplicate_auth_provider_names_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "primary",
                        "type": "jwt",
                        "jwks_url": "https://primary.example.test/.well-known/jwks.json",
                        "issuer": "https://primary.example.test/"
                    },
                    {
                        "name": " primary ",
                        "type": "jwt",
                        "jwks_url": "https://secondary.example.test/.well-known/jwks.json",
                        "issuer": "https://secondary.example.test/"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject duplicate auth provider names");

        let message = error.to_string();
        assert!(message.contains("AUTH_PROVIDERS[1].name duplicates AUTH_PROVIDERS[0].name"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn unrecognized_auth_provider_type_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "primary",
                        "type": "saml",
                        "jwks_url": "https://primary.example.test/.well-known/jwks.json"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject unrecognized auth provider types");

        let message = error.to_string();
        assert!(message.contains("AUTH_PROVIDERS[0].type must be 'jwt' or 'cookie_session'"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn legacy_jwt_settings_create_implicit_auth_provider_when_auth_providers_unset() {
        let config = Config::from_env_vars(|name| match name {
            "JWT_JWKS_URL" => Ok("https://legacy.example.test/.well-known/jwks.json".to_owned()),
            "JWT_ISSUER" => Ok("https://legacy.example.test/".to_owned()),
            "JWT_AUDIENCE" => Ok("greengateway".to_owned()),
            "JWT_JWKS_TIMEOUT_MS" => Ok("6000".to_owned()),
            "JWT_REQUIRE_JTI" => Ok("true".to_owned()),
            "ROLES_CLAIM" => Ok("groups".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("legacy JWT config should parse");

        assert_eq!(
            config.auth_providers,
            vec![AuthProviderConfig {
                name: "legacy".to_owned(),
                provider_type: AuthProviderType::Jwt,
                jwks_url: Some("https://legacy.example.test/.well-known/jwks.json".to_owned()),
                issuer: Some("https://legacy.example.test/".to_owned()),
                audience: Some("greengateway".to_owned()),
                jwks_timeout_ms: 6000,
                jwks_max_key_age_secs: 300,
                require_jti: true,
                roles_claim: "groups".to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
                introspection_url: None,
                introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                user_id_claim: None,
                email_claim: None,
                client_id: None,
                client_secret: None,
                redirect_uri: None,
            }]
        );
    }

    #[test]
    fn auth_providers_take_precedence_over_legacy_jwt_settings() {
        let config = Config::from_env_vars(|name| match name {
            "AUTH_PROVIDERS" => Ok(r#"[
                    {
                        "name": "declared",
                        "type": "jwt",
                        "jwks_url": "https://declared.example.test/.well-known/jwks.json",
                        "issuer": "https://declared.example.test/",
                        "audience": "declared-audience",
                        "jwks_timeout_ms": 8000,
                        "require_jti": false,
                        "roles_claim": "declared_roles"
                    }
                ]"#
            .to_owned()),
            "JWT_JWKS_URL" => Ok("https://legacy.example.test/.well-known/jwks.json".to_owned()),
            "JWT_ISSUER" => Ok("https://legacy.example.test/".to_owned()),
            "JWT_AUDIENCE" => Ok("legacy-audience".to_owned()),
            "JWT_JWKS_TIMEOUT_MS" => Ok("6000".to_owned()),
            "JWT_REQUIRE_JTI" => Ok("true".to_owned()),
            "ROLES_CLAIM" => Ok("legacy_roles".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.auth_providers,
            vec![AuthProviderConfig {
                name: "declared".to_owned(),
                provider_type: AuthProviderType::Jwt,
                jwks_url: Some("https://declared.example.test/.well-known/jwks.json".to_owned()),
                issuer: Some("https://declared.example.test".to_owned()),
                audience: Some("declared-audience".to_owned()),
                jwks_timeout_ms: 8000,
                jwks_max_key_age_secs: 300,
                require_jti: false,
                roles_claim: "declared_roles".to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
                introspection_url: None,
                introspection_timeout_ms: DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
                cache_ttl_ms: DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
                user_id_claim: None,
                email_claim: None,
                client_id: None,
                client_secret: None,
                redirect_uri: None,
            }]
        );
    }

    #[test]
    fn invalid_jwt_config_values_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "JWT_JWKS_TIMEOUT_MS" => Ok("slow".to_owned()),
            "JWT_REQUIRE_JTI" => Ok("sometimes".to_owned()),
            "ROLES_CLAIM" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid JWT settings");

        let message = error.to_string();
        assert!(message.contains("JWT_JWKS_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(message.contains("JWT_REQUIRE_JTI must be a valid boolean"));
        assert!(message.contains("ROLES_CLAIM must be a non-empty string"));
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn csrf_config_parses() {
        let config = Config::from_env_vars(|name| match name {
            "CSRF_ENABLED" => Ok("false".to_owned()),
            "CSRF_COOKIE_NAME" => Ok("custom_csrf".to_owned()),
            "CSRF_HEADER_NAME" => Ok("X-Custom-CSRF".to_owned()),
            "CSRF_COOKIE_DOMAIN" => Ok(".example.test".to_owned()),
            "CSRF_EXEMPT_PATHS" => Ok(" /health, /ready ,, /metrics ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert!(!config.csrf_enabled);
        assert_eq!(config.csrf_cookie_name, "custom_csrf");
        assert_eq!(config.csrf_header_name, "x-custom-csrf");
        assert_eq!(config.csrf_cookie_domain, Some(".example.test".to_owned()));
        assert_eq!(
            config.csrf_exempt_paths,
            vec![
                "/health".to_owned(),
                "/ready".to_owned(),
                "/metrics".to_owned()
            ]
        );
    }

    #[test]
    fn invalid_csrf_config_values_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "CSRF_ENABLED" => Ok("maybe".to_owned()),
            "CSRF_COOKIE_NAME" => Ok("csrf token".to_owned()),
            "CSRF_HEADER_NAME" => Ok("bad header".to_owned()),
            "CSRF_COOKIE_DOMAIN" => Ok("bad;domain".to_owned()),
            "CSRF_EXEMPT_PATHS" => Ok("/health,admin".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid CSRF settings");

        let message = error.to_string();
        assert!(message.contains("CSRF_ENABLED must be a valid boolean"));
        assert!(message.contains("CSRF_COOKIE_NAME must be a non-empty RFC 6265 cookie name"));
        assert!(message.contains("CSRF_HEADER_NAME must be a valid HTTP header name"));
        assert!(message.contains("CSRF_COOKIE_DOMAIN must be a valid cookie Domain attribute"));
        assert!(message.contains("CSRF_EXEMPT_PATHS entries must be URI paths"));
        assert_eq!(error.problems.len(), 5);
    }

    #[test]
    fn service_token_config_parses_and_validates() {
        let config = Config::from_env_vars(|name| match name {
            "SERVICE_TOKEN_SQLITE_PATH" => Ok(" data/service-tokens.sqlite ".to_owned()),
            "SERVICE_TOKEN_CACHE_TTL_MS" => Ok("7500".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.service_token_sqlite_path,
            Some("data/service-tokens.sqlite".to_owned())
        );
        assert_eq!(config.service_token_cache_ttl_ms, 7500);

        let error = Config::from_env_vars(|name| match name {
            "SERVICE_TOKEN_CACHE_TTL_MS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject zero service-token TTL");
        assert!(error
            .to_string()
            .contains("SERVICE_TOKEN_CACHE_TTL_MS must be greater than 0"));
    }

    #[test]
    fn tool_runtime_config_parses_and_validates() {
        let config = Config::from_env_vars(|name| match name {
            "TOOL_RUNTIME_QUEUE_DEPTH" => Ok("64".to_owned()),
            "TOOL_RUNTIME_GLOBAL_CONCURRENCY" => Ok("16".to_owned()),
            "TOOL_RUNTIME_QUEUE_TIMEOUT_MS" => Ok("250".to_owned()),
            "TOOL_RUNTIME_DEFAULT_TIMEOUT_MS" => Ok("15000".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.tool_runtime_queue_depth, 64);
        assert_eq!(config.tool_runtime_global_concurrency, 16);
        assert_eq!(config.tool_runtime_queue_timeout_ms, 250);
        assert_eq!(config.tool_runtime_default_timeout_ms, 15_000);

        let error = Config::from_env_vars(|name| match name {
            "TOOL_RUNTIME_QUEUE_DEPTH" => Ok("0".to_owned()),
            "TOOL_RUNTIME_GLOBAL_CONCURRENCY" => Ok("0".to_owned()),
            "TOOL_RUNTIME_QUEUE_TIMEOUT_MS" => Ok("0".to_owned()),
            "TOOL_RUNTIME_DEFAULT_TIMEOUT_MS" => Ok("0".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject zero tool runtime settings");
        let message = error.to_string();
        assert!(message.contains("TOOL_RUNTIME_QUEUE_DEPTH must be greater than 0"));
        assert!(message.contains("TOOL_RUNTIME_GLOBAL_CONCURRENCY must be greater than 0"));
        assert!(message.contains("TOOL_RUNTIME_QUEUE_TIMEOUT_MS must be greater than 0"));
        assert!(message.contains("TOOL_RUNTIME_DEFAULT_TIMEOUT_MS must be greater than 0"));
        assert_eq!(error.problems.len(), 4);
    }

    #[test]
    fn egress_config_parses() {
        let config = Config::from_env_vars(|name| match name {
            "EGRESS_ALLOWED_HOSTS" => {
                Ok(" API.EXAMPLE.TEST,upstream.example.test,,auth.example.test ".to_owned())
            }
            "EGRESS_TIMEOUT_MS" => Ok("15000".to_owned()),
            "EGRESS_RESPONSE_IDLE_TIMEOUT_MS" => Ok("4000".to_owned()),
            "EGRESS_CONNECT_TIMEOUT_MS" => Ok("3000".to_owned()),
            "EGRESS_MAX_RESPONSE_BYTES" => Ok("2097152".to_owned()),
            "EGRESS_MAX_REQUEST_BODY_BYTES" => Ok("65536".to_owned()),
            "EGRESS_NAT64_PREFIXES" => Ok(" 2001:db8:122:344::/64,64:ff9b:1::/48 ".to_owned()),
            "EGRESS_DENY_PRIVATE_IPS" => Ok("false".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.egress_allowed_hosts,
            vec![
                "api.example.test".to_owned(),
                "upstream.example.test".to_owned(),
                "auth.example.test".to_owned(),
            ]
        );
        assert_eq!(config.egress_timeout_ms, 15_000);
        assert_eq!(config.egress_response_idle_timeout_ms, 4_000);
        assert_eq!(config.egress_connect_timeout_ms, 3_000);
        assert_eq!(config.egress_max_response_bytes, 2_097_152);
        assert_eq!(config.egress_max_request_body_bytes, 65_536);
        assert_eq!(
            config.egress_nat64_prefixes,
            vec![
                "2001:db8:122:344::/64"
                    .parse::<IpNet>()
                    .expect("test prefix should parse"),
                "64:ff9b:1::/48"
                    .parse::<IpNet>()
                    .expect("test prefix should parse"),
            ]
        );
        assert!(!config.egress_deny_private_ips);
    }

    #[test]
    fn invalid_nat64_prefixes_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "EGRESS_NAT64_PREFIXES" => Ok(
                "10.0.0.0/8,2001:db8::/72,not-a-cidr,2001:db8:1::/48,2001:db8:1:1::/64".to_owned(),
            ),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid NAT64 prefixes");

        let message = error.to_string();
        assert!(message.contains("EGRESS_NAT64_PREFIXES entries must be IPv6 CIDR prefixes"));
        assert!(message.contains("RFC 6052 prefix length"));
        assert!(message.contains("valid IPv6 CIDR prefixes"));
        assert!(message.contains("entries must not overlap"));
        assert_eq!(error.problems.len(), 4);
    }

    #[test]
    fn malformed_or_well_known_overlapping_nat64_prefixes_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "EGRESS_NAT64_PREFIXES" => Ok("2001:db8:122:344:100::/96,64:ff9b::/64".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject structurally invalid NAT64 prefixes");

        let message = error.to_string();
        assert!(message.contains("must use a zero RFC 6052 u octet"));
        assert!(
            message.contains("must not overlap the built-in well-known NAT64 prefix 64:ff9b::/96")
        );
        assert_eq!(error.problems.len(), 2);
    }

    #[test]
    fn upstream_url_parses_optional_http_origin() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_URL" => Ok("  https://upstream.example.test:8443/base/path  ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.upstream_url,
            Some("https://upstream.example.test:8443/base/path".to_owned())
        );
    }

    #[test]
    fn upstream_url_rejects_userinfo_and_fragments_without_echoing_credentials() {
        for value in [
            "https://operator:credential-canary@upstream.example.test/base",
            "https://upstream.example.test/base/path#fragment",
        ] {
            let error = Config::from_env_vars(|name| match name {
                "UPSTREAM_URL" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("shared upstream URL validation should reject unsafe components");
            let message = error.to_string();
            assert!(message.contains("must not contain URL userinfo or a fragment"));
            assert!(!message.contains("credential-canary"));
        }
    }

    #[test]
    fn upstream_routes_parse_json_array_and_normalize_matchers() {
        let config = Config::from_env_vars(|name| match name {
            "POLICY_FILE" => Ok("policy.json".to_owned()),
            "UPSTREAM_ROUTES" => Ok(r#"[
                    {
                        "path_prefix": " /api ",
                        "host": " API.EXAMPLE.TEST ",
                        "upstream_url": " https://api-upstream.example.test/base ",
                        "timeout_ms": 1500,
                        "response_idle_timeout_ms": 400,
                        "connect_timeout_ms": 300,
                        "add_request_headers": {
                            " X-Route-Header ": "route-value"
                        },
                        "strip_request_headers": [" X-Client-Secret "],
                        "tls_ca_bundle_path": "certs/internal-ca.pem",
                        "openapi_spec_path": "specs/api.yaml"
                    },
                    {
                        "path_prefix": "/assets",
                        "upstream_url": "http://assets.example.test"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.upstream_url, None);
        assert_eq!(
            config.upstream_routes,
            vec![
                UpstreamRouteConfig {
                    id: None,
                    connection_id: None,
                    path_prefix: Some("/api".to_owned()),
                    host: Some("api.example.test".to_owned()),
                    upstream_url: "https://api-upstream.example.test/base".to_owned(),
                    upstreams: Vec::new(),
                    load_balancing: UpstreamLoadBalancingConfig::default(),
                    request_body: UpstreamRequestBodyConfig::default(),
                    sse: None,
                    websocket: None,
                    grpc: None,
                    limits: UpstreamPoolLimitsConfig::default(),
                    health_check: None,
                    retry: None,
                    circuit_breaker: None,
                    timeout_ms: Some(1500),
                    response_idle_timeout_ms: Some(400),
                    connect_timeout_ms: Some(300),
                    add_request_headers: HashMap::from([(
                        "x-route-header".to_owned(),
                        "route-value".to_owned(),
                    )]),
                    strip_request_headers: vec!["x-client-secret".to_owned()],
                    tls_ca_bundle_path: Some(PathBuf::from("certs/internal-ca.pem")),
                    openapi_spec_path: Some(PathBuf::from("specs/api.yaml")),
                },
                UpstreamRouteConfig {
                    id: None,
                    connection_id: None,
                    path_prefix: Some("/assets".to_owned()),
                    host: None,
                    upstream_url: "http://assets.example.test".to_owned(),
                    upstreams: Vec::new(),
                    load_balancing: UpstreamLoadBalancingConfig::default(),
                    request_body: UpstreamRequestBodyConfig::default(),
                    sse: None,
                    websocket: None,
                    grpc: None,
                    limits: UpstreamPoolLimitsConfig::default(),
                    health_check: None,
                    retry: None,
                    circuit_breaker: None,
                    timeout_ms: None,
                    response_idle_timeout_ms: None,
                    connect_timeout_ms: None,
                    add_request_headers: HashMap::new(),
                    strip_request_headers: Vec::new(),
                    tls_ca_bundle_path: None,
                    openapi_spec_path: None,
                },
            ]
        );
    }

    #[test]
    fn connection_bound_upstream_route_parses_without_a_legacy_destination() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id": "billing-route",
                    "path_prefix": "/billing",
                    "connection_id": " billing-api ",
                    "add_request_headers": {
                        "x-route-label": "billing"
                    }
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("connection-bound route should parse");

        let route = &config.upstream_routes[0];
        assert_eq!(route.id.as_deref(), Some("billing-route"));
        assert_eq!(route.connection_id.as_deref(), Some("billing-api"));
        assert!(route.upstream_url.is_empty());
        assert!(route.upstreams.is_empty());
        assert_eq!(
            route.add_request_headers.get("x-route-label"),
            Some(&"billing".to_owned())
        );
    }

    /// The gRPC listener must not share a socket with either existing one.
    ///
    /// Not a preference to reconcile: this listener speaks HTTP/2 and nothing
    /// else, and the other two refuse an HTTP/2 preface, so a shared address
    /// would leave one of them permanently unable to answer.
    #[test]
    fn grpc_listen_addr_must_differ_from_the_other_listeners() {
        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" | "GRPC_LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a gRPC listener sharing the data address must fail startup");
        assert!(
            error
                .to_string()
                .contains("GRPC_LISTEN_ADDR must not be the same address as LISTEN_ADDR"),
            "{error}"
        );

        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            "ADMIN_LISTEN_ADDR" | "GRPC_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a gRPC listener sharing the admin address must fail startup");
        assert!(
            error
                .to_string()
                .contains("GRPC_LISTEN_ADDR must not be the same address as ADMIN_LISTEN_ADDR"),
            "{error}"
        );

        // The control: three distinct addresses are accepted, so the two
        // refusals above are about the collision and not about the setting.
        let config = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            "ADMIN_LISTEN_ADDR" => Ok("127.0.0.1:9091".to_owned()),
            "GRPC_LISTEN_ADDR" => Ok("127.0.0.1:9092".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("three distinct listener addresses should validate");
        assert_eq!(
            config.grpc_listen_addr,
            Some(
                "127.0.0.1:9092"
                    .parse()
                    .expect("test gRPC address should parse")
            )
        );
    }

    #[test]
    fn grpc_listener_bounds_are_range_checked_and_default_when_unset() {
        let config = Config::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("an unset gRPC listener should validate");
        assert_eq!(config.grpc_listen_addr, None);
        assert_eq!(
            config.grpc_max_concurrent_streams,
            DEFAULT_GRPC_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(
            config.grpc_max_metadata_bytes,
            DEFAULT_GRPC_MAX_METADATA_BYTES
        );

        let error = Config::from_env_vars(|name| match name {
            "GRPC_MAX_CONCURRENT_STREAMS" => Ok("0".to_owned()),
            "GRPC_MAX_METADATA_BYTES" => Ok("16".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("out-of-range gRPC bounds must fail startup");
        let message = error.to_string();
        for expected in [
            "GRPC_MAX_CONCURRENT_STREAMS must be between 1 and",
            "GRPC_MAX_METADATA_BYTES must be between 1024 and",
        ] {
            assert!(message.contains(expected), "{message}");
        }
    }

    /// A route's gRPC policy is validated as a whole, and every problem is
    /// reported at once rather than one per startup attempt.
    #[test]
    fn grpc_routes_reject_incoherent_bounds_and_unusable_placement() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "id":"bounds",
                    "path_prefix":"/bounds",
                    "upstreams":[{"id":"a","url":"https://a.example.test"}],
                    "grpc":{
                        "max_concurrent_calls":4,
                        "max_concurrent_calls_per_endpoint":9,
                        "connect_timeout_ms":1,
                        "idle_timeout_ms":10,
                        "max_message_bytes":1048576,
                        "max_response_bytes":1024,
                        "max_metadata_entries":0
                    }
                },
                {
                    "id":"legacy",
                    "path_prefix":"/legacy",
                    "upstream_url":"https://legacy.example.test",
                    "grpc":{}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("incoherent gRPC settings must fail startup");
        let message = error.to_string();

        for expected in [
            // A per-endpoint cap above the route cap can never bind.
            "[0].grpc.max_concurrent_calls_per_endpoint must be between 1 and grpc.max_concurrent_calls",
            "[0].grpc.connect_timeout_ms must be between",
            "[0].grpc.idle_timeout_ms must be 0 to disable",
            // A direction budget below one legal message could carry nothing.
            "[0].grpc.max_response_bytes must be 0 to disable, or at least grpc.max_message_bytes",
            "[0].grpc.max_metadata_entries must be between 1 and",
            "[1].grpc requires an upstreams pool and cannot be used with upstream_url",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    /// A route with no `grpc` block is not a gRPC route, and defaults fill in
    /// for a block that is present but empty.
    #[test]
    fn grpc_route_policy_is_absent_by_default_and_defaults_when_empty() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "id":"plain",
                    "path_prefix":"/plain",
                    "upstreams":[{"id":"a","url":"https://a.example.test"}]
                },
                {
                    "id":"grpc",
                    "path_prefix":"/grpc",
                    "upstreams":[{"id":"b","url":"https://b.example.test"}],
                    "grpc":{}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("routes should parse");

        assert!(
            config.upstream_routes[0].grpc.is_none(),
            "a route without a grpc block must not become a gRPC route"
        );
        let grpc = config.upstream_routes[1]
            .grpc
            .as_ref()
            .expect("an empty grpc block still opts the route in");
        assert_eq!(grpc.max_concurrent_calls, DEFAULT_GRPC_MAX_CONCURRENT_CALLS);
        assert_eq!(grpc.max_message_bytes, DEFAULT_GRPC_MAX_MESSAGE_BYTES);
        assert_eq!(grpc.max_metadata_entries, DEFAULT_GRPC_MAX_METADATA_ENTRIES);
        assert_eq!(grpc.max_concurrent_calls_per_endpoint, None);
    }

    #[test]
    fn websocket_routes_reject_incoherent_bounds_and_unusable_policy() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "id":"bounds",
                    "path_prefix":"/bounds",
                    "upstreams":[{"id":"a","url":"https://a.example.test"}],
                    "websocket":{
                        "max_connections":4,
                        "max_connections_per_endpoint":9,
                        "handshake_timeout_ms":1,
                        "idle_timeout_ms":10,
                        "max_frame_bytes":1048576,
                        "max_message_bytes":1024
                    }
                },
                {
                    "id":"policy",
                    "path_prefix":"/policy",
                    "upstreams":[{"id":"b","url":"https://b.example.test"}],
                    "websocket":{
                        "allowed_origins":["https://ok.example.test/path","ftp://nope.example.test"],
                        "allowed_subprotocols":["bad protocol"]
                    }
                },
                {
                    "id":"legacy",
                    "path_prefix":"/legacy",
                    "upstream_url":"https://legacy.example.test",
                    "websocket":{}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("incoherent websocket settings must fail startup");
        let message = error.to_string();

        for expected in [
            // A per-endpoint cap above the route cap can never bind.
            "[0].websocket.max_connections_per_endpoint must be between 1 and websocket.max_connections",
            "[0].websocket.handshake_timeout_ms must be between",
            "[0].websocket.idle_timeout_ms must be 0 to disable",
            // A message cap below the frame cap could not be met by one legal frame.
            "[0].websocket.max_message_bytes must be at least websocket.max_frame_bytes",
            "[1].websocket.allowed_origins entries must be an http or https origin",
            "[1].websocket.allowed_subprotocols entries must be a valid HTTP token",
            "[2].websocket requires an upstreams pool and cannot be used with upstream_url",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn websocket_origins_normalize_to_one_comparable_serialization() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                "id":"origins",
                "path_prefix":"/origins",
                "upstreams":[{"id":"a","url":"https://a.example.test"}],
                "websocket":{
                    "allowed_origins":[
                        "https://App.Example.Test:443",
                        "https://app.example.test",
                        "http://Other.Example.Test:8080"
                    ],
                    "allowed_subprotocols":["chat","chat","echo"]
                }
            }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("valid websocket route should parse");
        let websocket = config.upstream_routes[0]
            .websocket
            .as_ref()
            .expect("websocket config should be present");

        // Case and a default port must not decide whether an origin matches, and
        // the same origin written two ways collapses to one entry.
        assert_eq!(
            websocket.allowed_origins,
            vec![
                "https://app.example.test".to_owned(),
                "http://other.example.test:8080".to_owned(),
            ]
        );
        assert_eq!(
            websocket.allowed_subprotocols,
            vec!["chat".to_owned(), "echo".to_owned()]
        );
    }

    #[test]
    fn a_route_without_websocket_configuration_keeps_ordinary_forwarding() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                "id":"plain",
                "path_prefix":"/plain",
                "upstreams":[{"id":"a","url":"https://a.example.test"}]
            }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("plain route should parse");
        assert!(
            config.upstream_routes[0].websocket.is_none(),
            "websocket proxying must stay opt-in"
        );
    }

    #[test]
    fn connection_bound_route_rejects_ambiguous_or_unsupported_transport_settings() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "path_prefix":"/missing-id",
                    "connection_id":"billing-api"
                },
                {
                    "id":"ambiguous",
                    "path_prefix":"/ambiguous",
                    "connection_id":"billing-api",
                    "upstream_url":"https://legacy.example.test"
                },
                {
                    "id":"unsupported",
                    "path_prefix":"/unsupported",
                    "connection_id":"billing-api",
                    "tls_ca_bundle_path":"/run/secrets/ca.pem",
                    "timeout_ms":1000,
                    "health_check":{},
                    "retry":{"max_attempts":1},
                    "circuit_breaker":{}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("unsafe connection route settings must fail startup");
        let message = error.to_string();

        for expected in [
            "[0].id is required when upstreams or connection_id is configured",
            "[1] must set exactly one of connection_id, upstream_url, or a non-empty upstreams pool",
            "[2].tls_ca_bundle_path must not be configured with connection_id",
            "[2] must not configure route timeout overrides with connection_id",
            "[2].health_check is not supported with connection_id",
            "[2].retry is not supported with connection_id",
            "[2].circuit_breaker is not supported with connection_id",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn checked_in_upstream_pool_example_parses_without_inline_secrets() {
        let example = include_str!("../../docs/examples/upstream-pool.json");
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(example.to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("checked-in upstream pool example should parse");

        assert_eq!(config.upstream_routes.len(), 1);
        assert_eq!(config.upstream_routes[0].id.as_deref(), Some("payments"));
        assert_eq!(config.upstream_routes[0].upstreams.len(), 2);
        assert!(config.upstream_routes[0]
            .upstreams
            .iter()
            .all(|endpoint| endpoint.url.contains(".example.test")));
        assert!(!example.contains("BEGIN CERTIFICATE"));
        assert!(!example.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn upstream_pool_configuration_parses_with_stable_ids_and_bounds() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id": "payments",
                    "path_prefix": "/payments",
                    "upstreams": [
                        {"id":"payments-a","url":"https://a.example.test","weight":3},
                        {
                            "id":"payments-b",
                            "url":"https://b.example.test",
                            "weight":1,
                            "tls_ca_bundle_path":"/run/secrets/payments-ca.pem",
                            "client_identity_pem_path":"/run/secrets/payments-client.pem"
                        }
                    ],
                    "load_balancing":{"strategy":"weighted_round_robin"},
                    "request_body":{"mode":"stream"},
                    "limits":{"max_in_flight":8,"queue_depth":4,"queue_timeout_ms":25},
                    "health_check":{
                        "method":"HEAD",
                        "path":"/ready",
                        "interval_ms":5000,
                        "jitter_ms":500,
                        "timeout_ms":750,
                        "healthy_threshold":3,
                        "unhealthy_threshold":4,
                        "expected_statuses":[200,204],
                        "passive_failure_statuses":[500,502,503,504],
                        "required_for_readiness":true,
                        "minimum_healthy":2
                    }
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("pool config should parse");

        let route = &config.upstream_routes[0];
        assert_eq!(route.id.as_deref(), Some("payments"));
        assert!(route.upstream_url.is_empty());
        assert_eq!(route.upstreams.len(), 2);
        assert_eq!(route.upstreams[0].id, "payments-a");
        assert_eq!(route.upstreams[0].weight, 3);
        assert_eq!(
            route.upstreams[1].tls_ca_bundle_path.as_deref(),
            Some(std::path::Path::new("/run/secrets/payments-ca.pem"))
        );
        assert_eq!(
            route.upstreams[1].client_identity_pem_path.as_deref(),
            Some(std::path::Path::new("/run/secrets/payments-client.pem"))
        );
        assert_eq!(route.request_body.mode, UpstreamRequestBodyMode::Stream);
        assert_eq!(route.limits.max_in_flight, 8);
        assert_eq!(route.limits.queue_depth, 4);
        assert_eq!(route.limits.queue_timeout_ms, 25);
        let health = route
            .health_check
            .as_ref()
            .expect("health check should parse");
        assert_eq!(health.method, "HEAD");
        assert_eq!(health.path, "/ready");
        assert_eq!(health.interval_ms, 5_000);
        assert_eq!(health.jitter_ms, 500);
        assert_eq!(health.timeout_ms, 750);
        assert_eq!(health.healthy_threshold, 3);
        assert_eq!(health.unhealthy_threshold, 4);
        assert_eq!(health.expected_statuses, vec![200, 204]);
        assert_eq!(health.passive_failure_statuses, vec![500, 502, 503, 504]);
        assert!(health.required_for_readiness);
        assert_eq!(health.minimum_healthy, 2);
    }

    #[test]
    fn upstream_client_identity_requires_a_non_empty_mounted_path() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[{
                        "id":"payments-a",
                        "url":"https://a.example.test",
                        "client_identity_pem_path":""
                    }]
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("an empty client identity path should fail startup");

        assert!(error.to_string().contains(
            "UPSTREAM_ROUTES[0].upstreams[0].client_identity_pem_path must be a non-empty filesystem path"
        ));
    }

    #[test]
    fn upstream_client_identity_rejects_http_and_inline_private_key_fields() {
        let inline_secret = "TOP_SECRET_INLINE_PRIVATE_KEY";
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(format!(
                r#"[{{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[{{
                        "id":"payments-a",
                        "url":"http://a.example.test",
                        "client_identity_pem_path":"/run/secrets/client.pem",
                        "client_identity_pem":"{inline_secret}"
                    }}]
                }}]"#
            )),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("inline identity material and mTLS on HTTP must fail startup");
        let message = error.to_string();

        assert!(message.contains("unknown field `client_identity_pem`"));
        assert!(!message.contains(inline_secret));

        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(format!(
                r#"[{{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[{{
                        "id":"payments-a",
                        "url":"https://a.example.test",
                        "client_identity_pem_path":"-----BEGIN PRIVATE KEY-----\n{inline_secret}"
                    }}]
                }}]"#
            )),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("inline identity material in the path field must fail startup");
        let message = error.to_string();
        assert!(message.contains(
            "client_identity_pem_path must reference a mounted PEM file and must not contain inline PEM material"
        ));
        assert!(!message.contains(inline_secret));

        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[{
                        "id":"payments-a",
                        "url":"http://a.example.test",
                        "client_identity_pem_path":"/run/secrets/client.pem"
                    }]
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("client identities must require TLS");
        assert!(error.to_string().contains(
            "UPSTREAM_ROUTES[0].upstreams[0].client_identity_pem_path requires an https endpoint URL"
        ));
    }

    #[test]
    fn upstream_sse_configuration_is_explicit_and_bounded() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "path_prefix":"/events",
                    "upstream_url":"https://events.example.test",
                    "sse":{"max_duration_ms":7200000,"max_response_bytes":0}
                },
                {
                    "path_prefix":"/bounded-events",
                    "upstream_url":"https://bounded.example.test",
                    "sse":{"max_response_bytes":1048576}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("SSE configuration should parse");

        let unlimited = config.upstream_routes[0]
            .sse
            .as_ref()
            .expect("SSE mode should be explicit");
        assert_eq!(unlimited.max_duration_ms, 7_200_000);
        assert_eq!(unlimited.max_response_bytes, Some(0));
        let bounded = config.upstream_routes[1]
            .sse
            .as_ref()
            .expect("bounded SSE mode");
        assert_eq!(
            bounded.max_duration_ms,
            DEFAULT_UPSTREAM_SSE_MAX_DURATION_MS
        );
        assert_eq!(bounded.max_response_bytes, Some(1_048_576));
    }

    #[test]
    fn upstream_sse_duration_above_hard_bound_fails_startup() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(format!(
                r#"[{{
                    "path_prefix":"/events",
                    "upstream_url":"https://events.example.test",
                    "sse":{{"max_duration_ms":{}}}
                }}]"#,
                MAX_UPSTREAM_SSE_MAX_DURATION_MS + 1
            )),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("excessive SSE duration should fail startup");

        assert!(error
            .to_string()
            .contains("UPSTREAM_ROUTES[0].sse.max_duration_ms must be 0 (unlimited) or at most"));
    }

    #[test]
    fn invalid_health_configuration_aggregates_conservative_bound_errors() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[
                        {"id":"a","url":"https://a.example.test"},
                        {"id":"b","url":"https://b.example.test"}
                    ],
                    "health_check":{
                        "method":"POST",
                        "path":"/ready?token=secret",
                        "interval_ms":99,
                        "jitter_ms":100,
                        "timeout_ms":0,
                        "healthy_threshold":0,
                        "unhealthy_threshold":1001,
                        "expected_statuses":[200,200,700],
                        "passive_failure_statuses":[404,500,500],
                        "minimum_healthy":3
                    }
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("unsafe health configuration should fail startup");
        let message = error.to_string();

        for expected in [
            ".health_check.method must be GET or HEAD",
            ".health_check.path must be a safe absolute path",
            ".health_check.interval_ms must be between 100 and 3600000",
            ".health_check.timeout_ms must be between 10 and 60000",
            ".health_check.jitter_ms must be less than interval_ms",
            ".health_check thresholds must be between 1 and 1000",
            ".health_check.expected_statuses must contain 1-32 unique HTTP statuses",
            ".health_check.passive_failure_statuses must contain at most 32 unique HTTP statuses",
            ".health_check.minimum_healthy must be between 1 and 2",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn upstream_retry_configuration_parses_and_normalizes_safe_methods() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[
                        {"id":"a","url":"https://a.example.test"},
                        {"id":"b","url":"https://b.example.test"}
                    ],
                    "retry":{
                        "max_attempts":3,
                        "methods":["get","HEAD"," options "],
                        "statuses":[500,502,503,504]
                    }
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("safe retry configuration should parse");

        let retry = config.upstream_routes[0]
            .retry
            .as_ref()
            .expect("retry configuration");
        assert_eq!(retry.max_attempts, 3);
        assert_eq!(retry.methods, ["GET", "HEAD", "OPTIONS"]);
        assert_eq!(retry.statuses, [500, 502, 503, 504]);
    }

    #[test]
    fn invalid_retry_configuration_fails_closed_with_aggregated_errors() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[
                        {"id":"a","url":"https://a.example.test"},
                        {"id":"b","url":"https://b.example.test"}
                    ],
                    "request_body":{"mode":"stream"},
                    "retry":{
                        "max_attempts":6,
                        "methods":["GET","get","POST"],
                        "statuses":[499,500,500]
                    }
                },
                {
                    "path_prefix":"/legacy",
                    "upstream_url":"https://legacy.example.test",
                    "retry":{"max_attempts":2}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("unsafe retry configuration should fail startup");
        let message = error.to_string();

        for expected in [
            ".retry.max_attempts must be between 1 and 5",
            ".retry.methods must contain unique replay-safe methods",
            ".retry.statuses must contain 1-32 unique HTTP statuses",
            ".retry.max_attempts greater than 1 requires request_body.mode buffered",
            ".retry requires an upstreams pool and cannot be used with upstream_url",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn upstream_circuit_breaker_configuration_parses_with_bounded_defaults() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[{
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[
                        {"id":"a","url":"https://a.example.test"},
                        {"id":"b","url":"https://b.example.test"}
                    ],
                    "circuit_breaker":{}
                }]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("bounded circuit-breaker defaults should parse");

        let circuit = config.upstream_routes[0]
            .circuit_breaker
            .as_ref()
            .expect("circuit-breaker configuration");
        assert_eq!(circuit.failure_threshold, 5);
        assert_eq!(circuit.open_ms, 30_000);
        assert_eq!(circuit.half_open_max_requests, 1);
        assert_eq!(circuit.recovery_threshold, 2);
    }

    #[test]
    fn invalid_circuit_breaker_configuration_fails_closed_with_aggregated_errors() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                {
                    "id":"payments",
                    "path_prefix":"/payments",
                    "upstreams":[
                        {"id":"a","url":"https://a.example.test"},
                        {"id":"b","url":"https://b.example.test"}
                    ],
                    "limits":{"max_in_flight":1},
                    "circuit_breaker":{
                        "failure_threshold":0,
                        "open_ms":0,
                        "half_open_max_requests":2,
                        "recovery_threshold":1001
                    }
                },
                {
                    "path_prefix":"/legacy",
                    "upstream_url":"https://legacy.example.test",
                    "circuit_breaker":{}
                }
            ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("unsafe circuit-breaker configuration should fail startup");
        let message = error.to_string();

        for expected in [
            ".circuit_breaker.failure_threshold must be between 1 and 1000",
            ".circuit_breaker.open_ms must be between 10 and 3600000",
            ".circuit_breaker.half_open_max_requests must be between 1 and limits.max_in_flight",
            ".circuit_breaker.recovery_threshold must be between 1 and 1000",
            ".circuit_breaker requires an upstreams pool and cannot be used with upstream_url",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn invalid_pool_configuration_aggregates_identity_and_bound_errors() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(
                r#"[
                    {
                        "id":"bad id",
                        "path_prefix":"/a",
                        "upstream_url":"https://legacy.example.test",
                        "upstreams":[
                            {"id":"same","url":"https://user@a.example.test/path?secret=x","weight":0},
                            {"id":"same","url":"https://b.example.test","weight":1001}
                        ],
                        "limits":{"max_in_flight":0,"queue_depth":20000,"queue_timeout_ms":0}
                    },
                    {
                        "id":"bad id",
                        "path_prefix":"/a",
                        "upstreams":[]
                    }
                ]"#
                    .to_owned(),
            ),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("invalid pool config should fail startup");
        let message = error.to_string();

        for expected in [
            ".id must be 1-64 ASCII",
            "must set exactly one of connection_id, upstream_url, or a non-empty upstreams pool",
            ".id duplicates",
            "must not contain URL userinfo or a fragment",
            ".weight must be between 1 and 1000",
            ".limits.max_in_flight must be between 1 and 4096",
            ".limits.queue_depth must be at most 16384",
            ".limits.queue_timeout_ms must be between 1 and 60000",
            "duplicates UPSTREAM_ROUTES[0] with the same host and path_prefix matcher",
        ] {
            assert!(
                message.contains(expected),
                "aggregated validation should contain '{expected}': {message}"
            );
        }
    }

    #[test]
    fn host_qualified_upstream_routes_require_policy_file() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(
                r#"[{"host":"app.example.test","upstream_url":"https://app.internal.example"}]"#
                    .to_owned(),
            ),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("host-qualified routes should require an RBAC policy");

        assert!(error.to_string().contains(
            "UPSTREAM_ROUTES entries with host require POLICY_FILE so RBAC can bind authorization to the selected request host"
        ));
    }

    #[test]
    fn mcp_upstream_servers_parse_json_array_and_validate_names() {
        let config = Config::from_env_vars(|name| match name {
            "MCP_UPSTREAM_SERVERS" => Ok(r#"[
                    {
                        "name": " tools ",
                        "url": " http://mcp-tools.example.test/mcp ",
                        "timeout_ms": 1500,
                        "response_idle_timeout_ms": 400,
                        "connect_timeout_ms": 300
                    },
                    {
                        "name": "reports",
                        "url": "https://reports.example.test/mcp"
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse MCP upstream servers");

        assert_eq!(
            config.mcp_upstream_servers,
            vec![
                McpUpstreamServerConfig {
                    name: "tools".to_owned(),
                    url: "http://mcp-tools.example.test/mcp".to_owned(),
                    timeout_ms: Some(1500),
                    response_idle_timeout_ms: Some(400),
                    connect_timeout_ms: Some(300),
                },
                McpUpstreamServerConfig {
                    name: "reports".to_owned(),
                    url: "https://reports.example.test/mcp".to_owned(),
                    timeout_ms: None,
                    response_idle_timeout_ms: None,
                    connect_timeout_ms: None,
                },
            ]
        );
    }

    #[test]
    fn invalid_mcp_upstream_servers_are_rejected_with_clear_errors() {
        let error = Config::from_env_vars(|name| match name {
            "MCP_UPSTREAM_SERVERS" => Ok(r#"[
                    {"name":"","url":"https://empty-name.example.test/mcp"},
                    {"name":"dup","url":"ftp://bad-scheme.example.test/mcp"},
                    {"name":"dup","url":"https://duplicate.example.test/mcp"},
                    {"name":"bad-timeout","url":"https://timeout.example.test/mcp","timeout_ms":0}
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid MCP upstream servers");

        let message = error.to_string();
        assert!(message.contains("MCP_UPSTREAM_SERVERS[0].name must be non-empty"));
        assert!(message.contains("MCP_UPSTREAM_SERVERS[1].url must use http or https"));
        assert!(message
            .contains("MCP_UPSTREAM_SERVERS[2].name duplicates MCP_UPSTREAM_SERVERS[1].name"));
        assert!(message.contains("MCP_UPSTREAM_SERVERS[3].timeout_ms must be greater than 0"));
    }

    #[test]
    fn invalid_upstream_route_openapi_spec_path_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                    {
                        "path_prefix": "/api",
                        "upstream_url": "https://api.example.test",
                        "openapi_spec_path": ""
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid route OpenAPI spec path");

        let message = error.to_string();
        assert!(message
            .contains("UPSTREAM_ROUTES[0].openapi_spec_path must be a non-empty filesystem path"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn empty_upstream_routes_are_absent() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("empty UPSTREAM_ROUTES should parse as no route table");
        assert!(config.upstream_routes.is_empty());

        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok("[]".to_owned()),
            "UPSTREAM_URL" => Ok("https://legacy.example.test".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("empty UPSTREAM_ROUTES should not conflict with UPSTREAM_URL");
        assert!(config.upstream_routes.is_empty());
        assert_eq!(
            config.upstream_url,
            Some("https://legacy.example.test".to_owned())
        );
    }

    #[test]
    fn upstream_url_and_non_empty_upstream_routes_are_mutually_exclusive() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_URL" => Ok("https://legacy.example.test".to_owned()),
            "UPSTREAM_ROUTES" => Ok(
                r#"[{"path_prefix":"/api","upstream_url":"https://api.example.test"}]"#.to_owned(),
            ),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject ambiguous upstream routing config");

        let message = error.to_string();
        assert!(message.contains("UPSTREAM_URL and UPSTREAM_ROUTES are mutually exclusive"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn invalid_upstream_routes_are_rejected_with_clear_errors() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                    {"path_prefix":"api","upstream_url":"ftp://api.example.test"},
                    {"path_prefix":"/","upstream_url":"https://catchall.example.test"},
                    {"host":"api.example.test:443","upstream_url":"https://api.example.test"},
                    {"upstream_url":"https://missing-matcher.example.test"},
                    {"path_prefix":"/dup","upstream_url":"https://first.example.test"},
                    {"path_prefix":"/dup","upstream_url":"https://second.example.test"}
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid upstream routes");

        let message = error.to_string();
        assert!(message.contains(
            "UPSTREAM_ROUTES[0].path_prefix must be a URI path prefix starting with '/'"
        ));
        assert!(message.contains("UPSTREAM_ROUTES[0].upstream_url must use http or https"));
        assert!(message.contains("UPSTREAM_ROUTES[1].path_prefix must not be '/' without host"));
        assert!(message.contains("UPSTREAM_ROUTES[2].host must be a hostname without a port"));
        assert!(message.contains("UPSTREAM_ROUTES[3] must set at least one of path_prefix or host"));
        assert!(message.contains(
            "UPSTREAM_ROUTES[5] duplicates UPSTREAM_ROUTES[4] with the same host and path_prefix matcher"
        ));
        assert_eq!(error.problems.len(), 8);
    }

    #[test]
    fn invalid_upstream_route_header_settings_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_ROUTES" => Ok(r#"[
                    {
                        "path_prefix": "/api",
                        "upstream_url": "https://api.example.test",
                        "add_request_headers": {
                            "connection": "close",
                            "x-request-id": "not-operator-owned",
                            "bad header": "value",
                            "x-bad-value": "line\r\nbreak",
                            "x-shared": "added"
                        },
                        "strip_request_headers": [
                            "x-request-id",
                            "bad strip header",
                            "x-shared"
                        ]
                    }
                ]"#
            .to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject unsafe route header settings");

        let message = error.to_string();
        assert!(message.contains(
            "UPSTREAM_ROUTES[0].add_request_headers.connection must not configure hop-by-hop"
        ));
        assert!(message.contains(
            "UPSTREAM_ROUTES[0].add_request_headers.x-request-id must not configure x-request-id"
        ));
        assert!(message.contains(
            "UPSTREAM_ROUTES[0].add_request_headers.bad header must be a valid HTTP header name"
        ));
        assert!(message.contains(
            "UPSTREAM_ROUTES[0].add_request_headers.x-bad-value must be a valid HTTP header value"
        ));
        assert!(message
            .contains("UPSTREAM_ROUTES[0].strip_request_headers must not include x-request-id"));
        assert!(message
            .contains("UPSTREAM_ROUTES[0].strip_request_headers must be a valid HTTP header name"));
        assert!(message
            .contains("UPSTREAM_ROUTES[0].strip_request_headers must not include 'x-shared'"));
    }

    #[test]
    fn upstream_timeout_overrides_parse_as_optional_values() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_TIMEOUT_MS" => Ok("1500".to_owned()),
            "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS" => Ok("400".to_owned()),
            "UPSTREAM_CONNECT_TIMEOUT_MS" => Ok("300".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.upstream_timeout_ms, Some(1500));
        assert_eq!(config.upstream_response_idle_timeout_ms, Some(400));
        assert_eq!(config.upstream_connect_timeout_ms, Some(300));
    }

    #[test]
    fn empty_upstream_url_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_URL" => Ok("   ".to_owned()),
            "UPSTREAM_TIMEOUT_MS" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.upstream_url, None);
        assert_eq!(config.upstream_timeout_ms, None);
    }

    #[test]
    fn invalid_upstream_url_values_are_rejected() {
        for (value, expected) in [
            (
                "not a url",
                "UPSTREAM_URL must be a valid http or https URL",
            ),
            (
                "mailto:ops@example.test",
                "UPSTREAM_URL must be a valid http or https URL with a host",
            ),
            (
                "ftp://upstream.example.test",
                "UPSTREAM_URL must use http or https",
            ),
        ] {
            let error = Config::from_env_vars(|name| match name {
                "UPSTREAM_URL" => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("config should reject invalid upstream URL");

            let message = error.to_string();
            assert!(message.contains(expected), "{message}");
            assert_eq!(error.problems.len(), 1);
        }
    }

    #[test]
    fn invalid_upstream_timeout_overrides_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "UPSTREAM_TIMEOUT_MS" => Ok("slow".to_owned()),
            "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS" => Ok("idle".to_owned()),
            "UPSTREAM_CONNECT_TIMEOUT_MS" => Ok("slower".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid upstream timeout settings");

        let message = error.to_string();
        assert!(message.contains("UPSTREAM_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(message
            .contains("UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(
            message.contains("UPSTREAM_CONNECT_TIMEOUT_MS must be a valid millisecond duration")
        );
        assert_eq!(error.problems.len(), 3);
    }

    #[test]
    fn invalid_egress_config_values_are_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "EGRESS_ALLOWED_HOSTS" => Ok("api.example.test:443,bad_host".to_owned()),
            "EGRESS_TIMEOUT_MS" => Ok("slow".to_owned()),
            "EGRESS_RESPONSE_IDLE_TIMEOUT_MS" => Ok("idle".to_owned()),
            "EGRESS_CONNECT_TIMEOUT_MS" => Ok("slower".to_owned()),
            "EGRESS_MAX_RESPONSE_BYTES" => Ok("large".to_owned()),
            "EGRESS_MAX_REQUEST_BODY_BYTES" => Ok("larger".to_owned()),
            "EGRESS_DENY_PRIVATE_IPS" => Ok("sometimes".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid egress settings");

        let message = error.to_string();
        assert!(message.contains("EGRESS_ALLOWED_HOSTS entries must be hostnames without ports"));
        assert!(message.contains("EGRESS_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(message
            .contains("EGRESS_RESPONSE_IDLE_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(message.contains("EGRESS_CONNECT_TIMEOUT_MS must be a valid millisecond duration"));
        assert!(message.contains("EGRESS_MAX_RESPONSE_BYTES must be a valid byte size"));
        assert!(message.contains("EGRESS_MAX_REQUEST_BODY_BYTES must be a valid byte size"));
        assert!(message.contains("EGRESS_DENY_PRIVATE_IPS must be a valid boolean"));
        assert_eq!(error.problems.len(), 8);
    }

    #[test]
    fn invalid_cors_allow_origin_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "CORS_ALLOW_ORIGINS" => Ok("https://app.example.test,bad\norigin".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid origin header values");

        let message = error.to_string();
        assert!(message.contains("CORS_ALLOW_ORIGINS entries must be valid HTTP header values"));
        assert!(message.contains("bad\norigin"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn wildcard_cors_allow_origin_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "CORS_ALLOW_ORIGINS" => Ok("https://app.example.test,*".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject a wildcard origin");

        let message = error.to_string();
        assert!(message.contains("CORS_ALLOW_ORIGINS entries must be exact origins"));
        assert!(message.contains("wildcard origin '*' is not allowed with credentialed CORS"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn parse_var_records_independent_problems() {
        let mut problems = Vec::new();

        let listen_addr = parse_var(
            "PRIMARY_LISTEN_ADDR",
            Ok("not-a-socket".to_owned()),
            "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("test default address should parse"),
            "socket address",
            &mut problems,
        );
        let enabled = parse_var(
            "FEATURE_ENABLED",
            Ok("maybe".to_owned()),
            false,
            "boolean",
            &mut problems,
        );

        assert_eq!(
            listen_addr,
            "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("test default address should parse")
        );
        assert!(!enabled);
        assert_eq!(problems.len(), 2);
        assert!(problems.iter().any(|problem| problem
            == "PRIMARY_LISTEN_ADDR must be a valid socket address, got 'not-a-socket': invalid socket address syntax"));
        assert!(problems.iter().any(|problem| problem
            == "FEATURE_ENABLED must be a valid boolean, got 'maybe': provided string was not `true` or `false`"));
    }

    // --- shared-state backend selection (issue #241, PR 3) -------------------

    #[test]
    fn state_backend_defaults_to_sqlite() {
        let config = Config::from_env_vars(|_| Err(VarError::NotPresent))
            .expect("an unconfigured gateway is standalone");
        assert_eq!(config.state_backend, StateBackend::Sqlite);
        assert_eq!(config.deployment_id, None);
        assert_eq!(config.database.url_file, None);
        assert_eq!(config.database.tls_mode, DatabaseTlsMode::Verify);
    }

    fn postgres_mode_vars<'a>(
        extra: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&str) -> Result<String, VarError> + 'a {
        move |name| {
            let base = [
                ("STATE_BACKEND", "postgres"),
                ("DEPLOYMENT_ID", "deploy-prod-eu"),
                (
                    "DATABASE_URL_FILE",
                    "/run/secrets/greengateway/database-url",
                ),
                // PR 10: cluster mode keys its shared rate-limit buckets
                // under a keyring whose files live beneath the secrets root.
                ("CONNECTION_SECRETS_ROOT", "/run/secrets/greengateway"),
                (
                    "RATE_LIMIT_KEYRING",
                    r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#,
                ),
            ];
            // Extra entries come first so a test can override a base value.
            for (key, value) in extra.iter().chain(base.iter()) {
                if name == *key {
                    return Ok((*value).to_owned());
                }
            }
            Err(VarError::NotPresent)
        }
    }

    #[test]
    fn a_valid_postgres_mode_configuration_parses() {
        let config = Config::from_env_vars(postgres_mode_vars(&[]))
            .expect("a complete postgres-mode configuration should validate");
        assert_eq!(config.state_backend, StateBackend::Postgres);
        assert_eq!(config.deployment_id.as_deref(), Some("deploy-prod-eu"));
        assert_eq!(
            config.database.url_file.as_deref(),
            Some("/run/secrets/greengateway/database-url")
        );
        assert!(!config.database.auto_migrate);
        assert_eq!(
            config.database.migration_statement_timeout_ms,
            DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS
        );
        assert_eq!(config.database.pool_max, DEFAULT_DATABASE_POOL_MAX);
        assert_eq!(
            config.database.connect_timeout_ms,
            DEFAULT_DATABASE_CONNECT_TIMEOUT_MS
        );
        assert_eq!(
            config.database.acquire_timeout_ms,
            DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS
        );
        assert_eq!(
            config.database.statement_timeout_ms,
            DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS
        );
        assert_eq!(
            config.database.idle_in_transaction_timeout_ms,
            DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS
        );
        assert_eq!(
            config.database.lock_timeout_ms,
            DEFAULT_DATABASE_LOCK_TIMEOUT_MS
        );
        assert_eq!(
            config.database.startup_retry_limit,
            DEFAULT_DATABASE_STARTUP_RETRY_LIMIT
        );
    }

    #[test]
    fn postgres_mode_requires_a_rate_limit_keyring() {
        let error = Config::from_env_vars(|name| match name {
            "STATE_BACKEND" => Ok("postgres".to_owned()),
            "DEPLOYMENT_ID" => Ok("deploy-prod-eu".to_owned()),
            "DATABASE_URL_FILE" => Ok("/run/secrets/greengateway/database-url".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("postgres mode without a rate-limit keyring must not start");
        assert!(
            error
                .to_string()
                .contains("RATE_LIMIT_KEYRING is required when STATE_BACKEND=postgres"),
            "{}",
            error
        );
    }

    #[test]
    fn standalone_mode_refuses_a_rate_limit_keyring() {
        let error = Config::from_env_vars(|name| match name {
            "CONNECTION_SECRETS_ROOT" => Ok("/run/secrets/greengateway".to_owned()),
            "RATE_LIMIT_KEYRING" => {
                Ok(r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#.to_owned())
            }
            _ => Err(VarError::NotPresent),
        })
        .expect_err("a rate-limit keyring in standalone mode must not start");
        assert!(
            error
                .to_string()
                .contains("RATE_LIMIT_KEYRING is set while STATE_BACKEND is sqlite"),
            "{}",
            error
        );
    }

    #[test]
    fn the_lease_ttl_has_a_floor_and_a_default() {
        let config = Config::from_env_vars(postgres_mode_vars(&[])).expect("postgres mode config");
        assert_eq!(config.tool_lease_ttl_ms, DEFAULT_TOOL_LEASE_TTL_MS);
        let error = Config::from_env_vars(postgres_mode_vars(&[("TOOL_LEASE_TTL_MS", "500")]))
            .expect_err("a lease TTL below the floor must not start");
        assert!(
            error
                .to_string()
                .contains("TOOL_LEASE_TTL_MS must be at least 1000 milliseconds"),
            "{}",
            error
        );
        let config = Config::from_env_vars(postgres_mode_vars(&[("TOOL_LEASE_TTL_MS", "4000")]))
            .expect("a lease TTL above the floor is accepted");
        assert_eq!(config.tool_lease_ttl(), std::time::Duration::from_secs(4));
    }

    #[test]
    fn postgres_mode_requires_a_deployment_id() {
        let error = Config::from_env_vars(|name| match name {
            "STATE_BACKEND" => Ok("postgres".to_owned()),
            "DATABASE_URL_FILE" => Ok("/run/secrets/greengateway/database-url".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("postgres mode without a deployment ID must not start");
        assert!(
            error.to_string().contains("DEPLOYMENT_ID is required"),
            "{}",
            error
        );
    }

    #[test]
    fn postgres_mode_requires_a_dsn_secret_file() {
        let error = Config::from_env_vars(|name| match name {
            "STATE_BACKEND" => Ok("postgres".to_owned()),
            "DEPLOYMENT_ID" => Ok("deploy-prod-eu".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("postgres mode without a DSN file must not start");
        assert!(
            error.to_string().contains("DATABASE_URL_FILE is required"),
            "{}",
            error
        );
    }

    /// Cluster mode rejects every authoritative writable local store, naming
    /// each: a second authority next to PostgreSQL is the stale-allow shape
    /// the mode exists to prevent, not a leftover.
    #[test]
    fn postgres_mode_rejects_writable_local_authority_settings() {
        for (setting, value) in [
            ("POLICY_FILE", "/etc/greengateway/policy.json"),
            ("TOOLS_FILE", "/etc/greengateway/tools.json"),
            ("AUDIT_SQLITE_PATH", "/var/lib/greengateway/audit.sqlite3"),
            (
                "DISCOVERY_SQLITE_PATH",
                "/var/lib/greengateway/discovery.sqlite3",
            ),
            (
                "PRINCIPAL_SQLITE_PATH",
                "/var/lib/greengateway/principals.sqlite3",
            ),
            (
                "CONNECTIONS_SQLITE_PATH",
                "/var/lib/greengateway/connections.sqlite3",
            ),
            (
                "POLICY_HISTORY_SQLITE_PATH",
                "/var/lib/greengateway/history.sqlite3",
            ),
            (
                "SERVICE_TOKEN_SQLITE_PATH",
                "/var/lib/greengateway/tokens.sqlite3",
            ),
        ] {
            let error = Config::from_env_vars(postgres_mode_vars(&[(setting, value)]))
                .expect_err("a writable local authority must be rejected in cluster mode");
            let message = error.to_string();
            assert!(
                message.contains(setting),
                "the rejection must name {setting}: {message}"
            );
            assert!(
                message.contains("STATE_BACKEND=postgres"),
                "the rejection must name the mode: {message}"
            );
        }
    }

    /// The inverse gap: PostgreSQL material while standalone mode is selected
    /// invites an operator to believe a database is in use when nothing reads
    /// it.
    #[test]
    fn sqlite_mode_rejects_postgres_material() {
        for (setting, value) in [
            (
                "DATABASE_URL_FILE",
                "/run/secrets/greengateway/database-url",
            ),
            (
                "DATABASE_TLS_CA_FILE",
                "/run/secrets/greengateway/postgres-ca.pem",
            ),
            ("DEPLOYMENT_ID", "deploy-prod-eu"),
            ("DATABASE_AUTO_MIGRATE", "true"),
        ] {
            let error = Config::from_env_vars(|name| match name {
                "STATE_BACKEND" => Ok("sqlite".to_owned()),
                other if other == setting => Ok(value.to_owned()),
                _ => Err(VarError::NotPresent),
            })
            .expect_err("postgres material with sqlite mode must be rejected");
            let message = error.to_string();
            assert!(
                message.contains(setting),
                "the rejection must name {setting}: {message}"
            );
            assert!(
                message.contains("STATE_BACKEND is sqlite"),
                "the rejection must name the mode: {message}"
            );
        }
    }

    #[test]
    fn state_backend_and_database_tls_mode_reject_unknown_values() {
        for (setting, value) in [
            ("STATE_BACKEND", "mysql"),
            ("STATE_BACKEND", "POSTGRES"),
            ("DATABASE_TLS_MODE", "prefer"),
            ("DATABASE_TLS_MODE", "verify-full"),
        ] {
            let mut vars: Vec<(&str, &str)> = vec![(setting, value)];
            if setting != "DATABASE_TLS_MODE" {
                vars.push(("DEPLOYMENT_ID", "deploy-prod-eu"));
                vars.push((
                    "DATABASE_URL_FILE",
                    "/run/secrets/greengateway/database-url",
                ));
            }
            let error = Config::from_env_vars(|name| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| Ok(value.to_string()))
                    .unwrap_or(Err(VarError::NotPresent))
            })
            .expect_err("an unknown enum value must be rejected");
            assert!(
                error.to_string().contains(setting),
                "the rejection must name {setting}: {error}"
            );
        }
    }

    #[test]
    fn deployment_id_shape_is_enforced() {
        // An empty value parses as unset, which in postgres mode is the
        // "DEPLOYMENT_ID is required" failure pinned by its own test above;
        // this test covers the malformed-but-present shapes.
        for bad in [
            "-leading-dash",
            "trailing-dash-",
            "has spaces",
            "has/slash",
            &"a".repeat(MAX_DEPLOYMENT_ID_BYTES + 1),
        ] {
            let error = Config::from_env_vars(postgres_mode_vars(&[("DEPLOYMENT_ID", bad)]))
                .expect_err("a malformed deployment ID must be rejected");
            let message = error.to_string();
            assert!(
                message.contains("DEPLOYMENT_ID must be 1 to 64 bytes"),
                "{message}"
            );
        }

        let config =
            Config::from_env_vars(postgres_mode_vars(&[("DEPLOYMENT_ID", "Deploy.1_prod-eu")]))
                .expect("a correctly-shaped deployment ID should validate");
        assert_eq!(config.deployment_id.as_deref(), Some("Deploy.1_prod-eu"));
    }

    #[test]
    fn database_bounds_are_enforced() {
        for (setting, value, expected_fragment) in [
            ("DATABASE_POOL_MAX", "0", "must be between 1 and"),
            (
                "DATABASE_POOL_MAX",
                &(MAX_DATABASE_POOL_MAX + 1).to_string(),
                "must be between 1 and",
            ),
            ("DATABASE_CONNECT_TIMEOUT_MS", "0", "must be greater than 0"),
            ("DATABASE_ACQUIRE_TIMEOUT_MS", "0", "must be greater than 0"),
            (
                "DATABASE_STATEMENT_TIMEOUT_MS",
                "0",
                "must be greater than 0",
            ),
            (
                "DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS",
                "0",
                "must be greater than 0",
            ),
            ("DATABASE_LOCK_TIMEOUT_MS", "0", "must be greater than 0"),
            (
                "DATABASE_STARTUP_RETRY_LIMIT",
                &(MAX_DATABASE_STARTUP_RETRY_LIMIT + 1).to_string(),
                "must be at most",
            ),
        ] {
            let error = Config::from_env_vars(postgres_mode_vars(&[(setting, value)]))
                .expect_err("out-of-bounds database settings must be rejected");
            let message = error.to_string();
            assert!(
                message.contains(setting) && message.contains(expected_fragment),
                "expected {setting} rejection containing {expected_fragment:?}: {message}"
            );
        }

        let config = Config::from_env_vars(postgres_mode_vars(&[
            ("DATABASE_POOL_MAX", "2"),
            ("DATABASE_STATEMENT_TIMEOUT_MS", "60000"),
            ("DATABASE_STARTUP_RETRY_LIMIT", "0"),
            ("DATABASE_AUTO_MIGRATE", "true"),
            ("DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS", "120000"),
        ]))
        .expect("in-bounds overrides should validate");
        assert_eq!(config.database.pool_max, 2);
        assert_eq!(config.database.statement_timeout_ms, 60_000);
        assert_eq!(config.database.startup_retry_limit, 0);
        assert!(config.database.auto_migrate);
        assert_eq!(config.database.migration_statement_timeout_ms, 120_000);
    }

    #[test]
    fn migration_settings_bounds_are_enforced() {
        for (setting, value, expected_fragment) in [
            (
                "DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS",
                "0",
                "must be greater than 0",
            ),
            (
                "DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS",
                &(MAX_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS + 1).to_string(),
                "must be at most",
            ),
            ("DATABASE_AUTO_MIGRATE", "maybe", "must be a valid boolean"),
        ] {
            let error = Config::from_env_vars(postgres_mode_vars(&[(setting, value)]))
                .expect_err("out-of-bounds migration settings must be rejected");
            let message = error.to_string();
            assert!(
                message.contains(setting) && message.contains(expected_fragment),
                "expected {setting} rejection containing {expected_fragment:?}: {message}"
            );
        }
    }

    /// The privacy contract of the HA state model: the DSN, database user,
    /// host, and name never appear in `Debug`. `Config` holds the locator of
    /// the DSN file, never its contents, and this pins that no future field
    /// quietly starts carrying connection material.
    #[test]
    fn config_debug_renders_no_dsn_material() {
        let config = Config::from_env_vars(postgres_mode_vars(&[(
            "DATABASE_TLS_CA_FILE",
            "/run/secrets/greengateway/postgres-ca.pem",
        )]))
        .expect("a full cluster-mode configuration should validate");

        let rendered = format!("{config:?}");
        for fragment in ["postgres://", "postgresql://", "canary-password", ":5432/"] {
            assert!(
                !rendered.contains(fragment),
                "Config Debug must not carry DSN material ({fragment}): {rendered}"
            );
        }
    }
}
