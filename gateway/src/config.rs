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
use serde::Deserialize;

use crate::discovery::{
    signals::{
        SignalDetectorConfig, DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
        DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
        DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
    },
    suggestions::{
        RuleSuggestionConfig, DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
    },
};

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
static DEFAULT_LISTEN_SOCKET_ADDR: LazyLock<SocketAddr> = LazyLock::new(|| {
    DEFAULT_LISTEN_ADDR
        .parse()
        .expect("default listen address should be valid")
});
const DEFAULT_MAX_BODY_SIZE: usize = 1_048_576;
const DEFAULT_RATE_LIMIT_READ_RPS: f64 = 50.0;
const DEFAULT_RATE_LIMIT_READ_BURST: u32 = 100;
const DEFAULT_RATE_LIMIT_WRITE_RPS: f64 = 10.0;
const DEFAULT_RATE_LIMIT_WRITE_BURST: u32 = 20;
const DEFAULT_VALIDATION_ALLOWED_CONTENT_TYPES: &[&str] = &["application/json"];
const DEFAULT_AUTH_ENABLED: bool = true;
pub const DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE: f64 = 0.10;
const DEFAULT_AUTH_MODE: AuthMode = AuthMode::Required;
const DEFAULT_AUTH_COOKIE_NAME: &str = "session";
pub const DEFAULT_ADMIN_PREFIX: &str = "/admin";
const DEFAULT_EXEMPT_PROBE_PATHS: &[&str] = &["/health", "/version", "/metrics"];
const DEFAULT_JWT_JWKS_TIMEOUT_MS: u64 = 2000;
const DEFAULT_ROLES_CLAIM: &str = "roles";
const DEFAULT_CSRF_ENABLED: bool = true;
const DEFAULT_CSRF_COOKIE_NAME: &str = "csrf_token";
const DEFAULT_CSRF_HEADER_NAME: &str = "x-csrf-token";
const DEFAULT_CSRF_EXEMPT_PATHS: &[&str] = &["/health", "/version", "/metrics"];
const DEFAULT_EGRESS_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_EGRESS_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_EGRESS_MAX_RESPONSE_BYTES: usize = 5_242_880;
const DEFAULT_EGRESS_MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const DEFAULT_EGRESS_DENY_PRIVATE_IPS: bool = true;
const ADMIN_LISTEN_ADDR: &str = "ADMIN_LISTEN_ADDR";
const ADMIN_PREFIX: &str = "ADMIN_PREFIX";
const AUDIT_LOG_FILE: &str = "AUDIT_LOG_FILE";
const AUDIT_SQLITE_PATH: &str = "AUDIT_SQLITE_PATH";
const AUDIT_SQLITE_RETENTION_DAYS: &str = "AUDIT_SQLITE_RETENTION_DAYS";
const AUTH_COOKIE_NAME: &str = "AUTH_COOKIE_NAME";
const AUTH_ENABLED: &str = "AUTH_ENABLED";
const AUTH_EXEMPT_PATHS: &str = "AUTH_EXEMPT_PATHS";
const AUTH_MODE: &str = "AUTH_MODE";
const CORS_ALLOW_ORIGINS: &str = "CORS_ALLOW_ORIGINS";
const CSRF_COOKIE_DOMAIN: &str = "CSRF_COOKIE_DOMAIN";
const CSRF_COOKIE_NAME: &str = "CSRF_COOKIE_NAME";
const CSRF_ENABLED: &str = "CSRF_ENABLED";
const CSRF_EXEMPT_PATHS: &str = "CSRF_EXEMPT_PATHS";
const CSRF_HEADER_NAME: &str = "CSRF_HEADER_NAME";
const DISCOVERY_SQLITE_PATH: &str = "DISCOVERY_SQLITE_PATH";
const ERROR_RATE_SPIKE_SIGNAL_THRESHOLD: &str = "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD";
const EGRESS_ALLOWED_HOSTS: &str = "EGRESS_ALLOWED_HOSTS";
const EGRESS_CONNECT_TIMEOUT_MS: &str = "EGRESS_CONNECT_TIMEOUT_MS";
const EGRESS_DENY_PRIVATE_IPS: &str = "EGRESS_DENY_PRIVATE_IPS";
const EGRESS_MAX_REQUEST_BODY_BYTES: &str = "EGRESS_MAX_REQUEST_BODY_BYTES";
const EGRESS_MAX_RESPONSE_BYTES: &str = "EGRESS_MAX_RESPONSE_BYTES";
const EGRESS_RESPONSE_IDLE_TIMEOUT_MS: &str = "EGRESS_RESPONSE_IDLE_TIMEOUT_MS";
const EGRESS_TIMEOUT_MS: &str = "EGRESS_TIMEOUT_MS";
const JWT_AUDIENCE: &str = "JWT_AUDIENCE";
const JWT_ISSUER: &str = "JWT_ISSUER";
const JWT_JWKS_TIMEOUT_MS: &str = "JWT_JWKS_TIMEOUT_MS";
const JWT_JWKS_URL: &str = "JWT_JWKS_URL";
const JWT_REQUIRE_JTI: &str = "JWT_REQUIRE_JTI";
const MAX_BODY_SIZE: &str = "MAX_BODY_SIZE";
const OPENAPI_SPEC_PATH: &str = "OPENAPI_SPEC_PATH";
const PAYLOAD_CAPTURE_ENABLED: &str = "PAYLOAD_CAPTURE_ENABLED";
const PAYLOAD_CAPTURE_SAMPLE_RATE: &str = "PAYLOAD_CAPTURE_SAMPLE_RATE";
const POLICY_FILE: &str = "POLICY_FILE";
const PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD: &str =
    "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD";
const RBAC_EXEMPT_PATHS: &str = "RBAC_EXEMPT_PATHS";
const RULE_SUGGESTION_BASELINE_WINDOW_HOURS: &str = "RULE_SUGGESTION_BASELINE_WINDOW_HOURS";
const RATE_LIMIT_READ_RPS: &str = "RATE_LIMIT_READ_RPS";
const RATE_LIMIT_READ_BURST: &str = "RATE_LIMIT_READ_BURST";
const RATE_LIMIT_WRITE_RPS: &str = "RATE_LIMIT_WRITE_RPS";
const RATE_LIMIT_WRITE_BURST: &str = "RATE_LIMIT_WRITE_BURST";
const ROLES_CLAIM: &str = "ROLES_CLAIM";
const SCHEMA_MISMATCH_SIGNAL_THRESHOLD: &str = "SCHEMA_MISMATCH_SIGNAL_THRESHOLD";
const TRUST_PROXY_HEADERS: &str = "TRUST_PROXY_HEADERS";
const SESSION_COOKIE_NAME: &str = "SESSION_COOKIE_NAME";
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
    pub admin_prefix: String,
    pub audit_log_file: Option<String>,
    pub audit_sqlite_path: Option<String>,
    pub audit_sqlite_retention_days: Option<u32>,
    pub discovery_sqlite_path: Option<String>,
    pub payload_capture_enabled: bool,
    pub payload_capture_sample_rate: f64,
    pub schema_mismatch_signal_threshold: u64,
    pub error_rate_spike_signal_threshold: f64,
    pub principal_new_to_endpoint_signal_threshold: u64,
    pub volume_outlier_signal_threshold: f64,
    pub rule_suggestion_baseline_window_hours: u64,
    pub openapi_spec_path: Option<PathBuf>,
    pub policy_file: Option<String>,
    pub cors_allow_origins: Vec<String>,
    pub max_body_size: usize,
    pub rate_limit_read_rps: f64,
    pub rate_limit_read_burst: u32,
    pub rate_limit_write_rps: f64,
    pub rate_limit_write_burst: u32,
    pub trust_proxy_headers: bool,
    pub rbac_exempt_paths: Vec<String>,
    pub session_cookie_name: String,
    pub validation_allowed_content_types: Vec<String>,
    pub auth_enabled: bool,
    pub auth_mode: AuthMode,
    pub auth_cookie_name: String,
    pub auth_exempt_paths: Vec<String>,
    pub jwt_jwks_url: Option<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_jwks_timeout_ms: u64,
    pub jwt_require_jti: bool,
    pub roles_claim: String,
    pub csrf_enabled: bool,
    pub csrf_cookie_name: String,
    pub csrf_header_name: String,
    pub csrf_cookie_domain: Option<String>,
    pub csrf_exempt_paths: Vec<String>,
    pub upstream_url: Option<String>,
    pub upstream_routes: Vec<UpstreamRouteConfig>,
    pub upstream_timeout_ms: Option<u64>,
    pub upstream_response_idle_timeout_ms: Option<u64>,
    pub upstream_connect_timeout_ms: Option<u64>,
    pub egress_allowed_hosts: Vec<String>,
    pub egress_timeout_ms: u64,
    pub egress_response_idle_timeout_ms: u64,
    pub egress_connect_timeout_ms: u64,
    pub egress_max_response_bytes: usize,
    pub egress_max_request_body_bytes: usize,
    pub egress_deny_private_ips: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRouteConfig {
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    pub upstream_url: String,
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

    fn from_env_vars(
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
        let admin_prefix = parse_admin_prefix(
            ADMIN_PREFIX,
            get_var(ADMIN_PREFIX),
            DEFAULT_ADMIN_PREFIX,
            &mut problems,
        );
        let audit_log_file =
            parse_optional_string(AUDIT_LOG_FILE, get_var(AUDIT_LOG_FILE), &mut problems);
        let audit_sqlite_path =
            parse_optional_string(AUDIT_SQLITE_PATH, get_var(AUDIT_SQLITE_PATH), &mut problems);
        let audit_sqlite_retention_days = parse_optional_var(
            AUDIT_SQLITE_RETENTION_DAYS,
            get_var(AUDIT_SQLITE_RETENTION_DAYS),
            "day count",
            &mut problems,
        );
        let discovery_sqlite_path = parse_optional_string(
            DISCOVERY_SQLITE_PATH,
            get_var(DISCOVERY_SQLITE_PATH),
            &mut problems,
        );
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
        let cors_allow_origins = parse_comma_separated_header_values(
            CORS_ALLOW_ORIGINS,
            get_var(CORS_ALLOW_ORIGINS),
            &[],
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
        let trust_proxy_headers = parse_var(
            TRUST_PROXY_HEADERS,
            get_var(TRUST_PROXY_HEADERS),
            false,
            "boolean",
            &mut problems,
        );
        let rbac_exempt_paths = parse_comma_separated_paths(
            RBAC_EXEMPT_PATHS,
            get_var(RBAC_EXEMPT_PATHS),
            &default_admin_exempt_paths(&admin_prefix),
            &mut problems,
        );
        let session_cookie_name = parse_var(
            SESSION_COOKIE_NAME,
            get_var(SESSION_COOKIE_NAME),
            String::new(),
            "string",
            &mut problems,
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
        let auth_exempt_paths = parse_comma_separated_paths(
            AUTH_EXEMPT_PATHS,
            get_var(AUTH_EXEMPT_PATHS),
            &default_admin_exempt_paths(&admin_prefix),
            &mut problems,
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
        if upstream_url.is_some() && !upstream_routes.is_empty() {
            problems.push(format!(
                "{UPSTREAM_URL} and {UPSTREAM_ROUTES} are mutually exclusive; set one proxy routing source"
            ));
        }
        let upstream_timeout_ms = parse_optional_var(
            UPSTREAM_TIMEOUT_MS,
            get_var(UPSTREAM_TIMEOUT_MS),
            "millisecond duration",
            &mut problems,
        );
        let upstream_response_idle_timeout_ms = parse_optional_var(
            UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
            get_var(UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS),
            "millisecond duration",
            &mut problems,
        );
        let upstream_connect_timeout_ms = parse_optional_var(
            UPSTREAM_CONNECT_TIMEOUT_MS,
            get_var(UPSTREAM_CONNECT_TIMEOUT_MS),
            "millisecond duration",
            &mut problems,
        );
        let egress_allowed_hosts = parse_comma_separated_hostnames(
            EGRESS_ALLOWED_HOSTS,
            get_var(EGRESS_ALLOWED_HOSTS),
            &mut problems,
        );
        let egress_timeout_ms = parse_var(
            EGRESS_TIMEOUT_MS,
            get_var(EGRESS_TIMEOUT_MS),
            DEFAULT_EGRESS_TIMEOUT_MS,
            "millisecond duration",
            &mut problems,
        );
        let egress_response_idle_timeout_ms = parse_var(
            EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
            get_var(EGRESS_RESPONSE_IDLE_TIMEOUT_MS),
            DEFAULT_EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
            "millisecond duration",
            &mut problems,
        );
        let egress_connect_timeout_ms = parse_var(
            EGRESS_CONNECT_TIMEOUT_MS,
            get_var(EGRESS_CONNECT_TIMEOUT_MS),
            DEFAULT_EGRESS_CONNECT_TIMEOUT_MS,
            "millisecond duration",
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
        let egress_deny_private_ips = parse_var(
            EGRESS_DENY_PRIVATE_IPS,
            get_var(EGRESS_DENY_PRIVATE_IPS),
            DEFAULT_EGRESS_DENY_PRIVATE_IPS,
            "boolean",
            &mut problems,
        );

        if problems.is_empty() {
            Ok(Self {
                listen_addr,
                admin_listen_addr,
                admin_prefix,
                audit_log_file,
                audit_sqlite_path,
                audit_sqlite_retention_days,
                discovery_sqlite_path,
                payload_capture_enabled,
                payload_capture_sample_rate,
                schema_mismatch_signal_threshold,
                error_rate_spike_signal_threshold,
                principal_new_to_endpoint_signal_threshold,
                volume_outlier_signal_threshold,
                rule_suggestion_baseline_window_hours,
                openapi_spec_path,
                policy_file,
                cors_allow_origins,
                max_body_size,
                rate_limit_read_rps,
                rate_limit_read_burst,
                rate_limit_write_rps,
                rate_limit_write_burst,
                trust_proxy_headers,
                rbac_exempt_paths,
                session_cookie_name,
                validation_allowed_content_types,
                auth_enabled,
                auth_mode,
                auth_cookie_name,
                auth_exempt_paths,
                jwt_jwks_url,
                jwt_issuer,
                jwt_audience,
                jwt_jwks_timeout_ms,
                jwt_require_jti,
                roles_claim,
                csrf_enabled,
                csrf_cookie_name,
                csrf_header_name,
                csrf_cookie_domain,
                csrf_exempt_paths,
                upstream_url,
                upstream_routes,
                upstream_timeout_ms,
                upstream_response_idle_timeout_ms,
                upstream_connect_timeout_ms,
                egress_allowed_hosts,
                egress_timeout_ms,
                egress_response_idle_timeout_ms,
                egress_connect_timeout_ms,
                egress_max_response_bytes,
                egress_max_request_body_bytes,
                egress_deny_private_ips,
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

fn validate_positive_u64(name: &str, value: u64, default: u64, problems: &mut Vec<String>) -> u64 {
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
                "{name} must be a JSON array of route objects with optional path_prefix, optional host, required upstream_url, and optional per-route settings: {err}"
            ));
            return Vec::new();
        }
    };

    validate_upstream_routes(name, routes, problems)
}

fn validate_upstream_routes(
    name: &str,
    routes: Vec<UpstreamRouteConfig>,
    problems: &mut Vec<String>,
) -> Vec<UpstreamRouteConfig> {
    let mut validated = Vec::with_capacity(routes.len());
    let mut seen_matchers = HashMap::<(Option<String>, Option<String>), usize>::new();

    for (index, route) in routes.into_iter().enumerate() {
        let route_name = format!("{name}[{index}]");
        let path_prefix = normalize_route_path_prefix(
            &format!("{route_name}.path_prefix"),
            route.path_prefix,
            problems,
        );
        let host = normalize_route_host(&format!("{route_name}.host"), route.host, problems);
        let upstream_url = validate_upstream_url(
            &format!("{route_name}.upstream_url"),
            &route.upstream_url,
            problems,
        )
        .unwrap_or_else(|| route.upstream_url.trim().to_owned());
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
        let tls_ca_bundle_path = normalize_route_tls_ca_bundle_path(
            &format!("{route_name}.tls_ca_bundle_path"),
            route.tls_ca_bundle_path,
            problems,
        );
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

        validated.push(UpstreamRouteConfig {
            path_prefix,
            host,
            upstream_url,
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
                "{name}.{raw_name} must not configure {REQUEST_ID_HEADER}; the gateway owns request-id propagation"
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
                "{name} must not include {REQUEST_ID_HEADER}; the gateway owns request-id propagation"
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

fn normalize_route_tls_ca_bundle_path(
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

fn default_admin_exempt_paths(admin_prefix: &str) -> Vec<String> {
    let mut paths = default_paths(DEFAULT_EXEMPT_PROBE_PATHS);
    paths.push(admin_prefix.to_owned());
    paths
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
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
        assert_eq!(config.discovery_sqlite_path, None);
        assert_eq!(config.policy_file, None);
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
        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert!(config.session_cookie_name.is_empty());
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
        assert!(config.csrf_enabled);
        assert_eq!(config.csrf_cookie_name, "csrf_token");
        assert_eq!(config.csrf_header_name, "x-csrf-token");
        assert_eq!(config.csrf_cookie_domain, None);
        assert_eq!(
            config.csrf_exempt_paths,
            vec![
                "/health".to_owned(),
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
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
        assert_eq!(config.discovery_sqlite_path, None);
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
        assert_eq!(
            config.rbac_exempt_paths,
            vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ]
        );
        assert!(config.session_cookie_name.is_empty());
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
        assert!(config.csrf_enabled);
        assert_eq!(config.csrf_cookie_name, "csrf_token");
        assert_eq!(config.csrf_header_name, "x-csrf-token");
        assert_eq!(config.csrf_cookie_domain, None);
        assert_eq!(
            config.csrf_exempt_paths,
            vec![
                "/health".to_owned(),
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
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/ops/admin".to_owned(),
            ]
        );
        assert_eq!(
            config.auth_exempt_paths,
            vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/ops/admin".to_owned(),
            ]
        );
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
            "TRUST_PROXY_HEADERS" => Ok("true".to_owned()),
            "SESSION_COOKIE_NAME" => Ok("gateway_session".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.rate_limit_read_rps, 25.5);
        assert_eq!(config.rate_limit_read_burst, 50);
        assert_eq!(config.rate_limit_write_rps, 5.25);
        assert_eq!(config.rate_limit_write_burst, 10);
        assert!(config.trust_proxy_headers);
        assert_eq!(config.session_cookie_name, "gateway_session");
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
        assert!(!config.egress_deny_private_ips);
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
    fn upstream_routes_parse_json_array_and_normalize_matchers() {
        let config = Config::from_env_vars(|name| match name {
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
                    path_prefix: Some("/api".to_owned()),
                    host: Some("api.example.test".to_owned()),
                    upstream_url: "https://api-upstream.example.test/base".to_owned(),
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
                    path_prefix: Some("/assets".to_owned()),
                    host: None,
                    upstream_url: "http://assets.example.test".to_owned(),
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
}
