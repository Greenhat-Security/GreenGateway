use std::{
    env::{self, VarError},
    error::Error,
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::LazyLock,
};

use http::{HeaderName, HeaderValue};

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
const DEFAULT_AUTH_COOKIE_NAME: &str = "session";
const DEFAULT_AUTH_EXEMPT_PATHS: &[&str] = &["/health", "/version", "/metrics", "/admin"];
const DEFAULT_RBAC_EXEMPT_PATHS: &[&str] = &["/health", "/version", "/metrics", "/admin"];
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
const AUDIT_LOG_FILE: &str = "AUDIT_LOG_FILE";
const AUDIT_SQLITE_PATH: &str = "AUDIT_SQLITE_PATH";
const AUDIT_SQLITE_RETENTION_DAYS: &str = "AUDIT_SQLITE_RETENTION_DAYS";
const AUTH_COOKIE_NAME: &str = "AUTH_COOKIE_NAME";
const AUTH_ENABLED: &str = "AUTH_ENABLED";
const AUTH_EXEMPT_PATHS: &str = "AUTH_EXEMPT_PATHS";
const CORS_ALLOW_ORIGINS: &str = "CORS_ALLOW_ORIGINS";
const CSRF_COOKIE_DOMAIN: &str = "CSRF_COOKIE_DOMAIN";
const CSRF_COOKIE_NAME: &str = "CSRF_COOKIE_NAME";
const CSRF_ENABLED: &str = "CSRF_ENABLED";
const CSRF_EXEMPT_PATHS: &str = "CSRF_EXEMPT_PATHS";
const CSRF_HEADER_NAME: &str = "CSRF_HEADER_NAME";
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
const POLICY_FILE: &str = "POLICY_FILE";
const RBAC_EXEMPT_PATHS: &str = "RBAC_EXEMPT_PATHS";
const RATE_LIMIT_READ_RPS: &str = "RATE_LIMIT_READ_RPS";
const RATE_LIMIT_READ_BURST: &str = "RATE_LIMIT_READ_BURST";
const RATE_LIMIT_WRITE_RPS: &str = "RATE_LIMIT_WRITE_RPS";
const RATE_LIMIT_WRITE_BURST: &str = "RATE_LIMIT_WRITE_BURST";
const ROLES_CLAIM: &str = "ROLES_CLAIM";
const TRUST_PROXY_HEADERS: &str = "TRUST_PROXY_HEADERS";
const SESSION_COOKIE_NAME: &str = "SESSION_COOKIE_NAME";
const UPSTREAM_URL: &str = "UPSTREAM_URL";
const VALIDATION_ALLOWED_CONTENT_TYPES: &str = "VALIDATION_ALLOWED_CONTENT_TYPES";

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub audit_log_file: Option<String>,
    pub audit_sqlite_path: Option<String>,
    pub audit_sqlite_retention_days: Option<u32>,
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
    pub egress_allowed_hosts: Vec<String>,
    pub egress_timeout_ms: u64,
    pub egress_response_idle_timeout_ms: u64,
    pub egress_connect_timeout_ms: u64,
    pub egress_max_response_bytes: usize,
    pub egress_max_request_body_bytes: usize,
    pub egress_deny_private_ips: bool,
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

        let listen_addr = parse_var(
            LISTEN_ADDR,
            get_var(LISTEN_ADDR),
            *DEFAULT_LISTEN_SOCKET_ADDR,
            "socket address",
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
            DEFAULT_RBAC_EXEMPT_PATHS,
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
        let auth_cookie_name = parse_cookie_name(
            AUTH_COOKIE_NAME,
            get_var(AUTH_COOKIE_NAME),
            DEFAULT_AUTH_COOKIE_NAME,
            &mut problems,
        );
        let auth_exempt_paths = parse_comma_separated_paths(
            AUTH_EXEMPT_PATHS,
            get_var(AUTH_EXEMPT_PATHS),
            DEFAULT_AUTH_EXEMPT_PATHS,
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
            DEFAULT_CSRF_EXEMPT_PATHS,
            &mut problems,
        );
        let upstream_url =
            parse_optional_upstream_url(UPSTREAM_URL, get_var(UPSTREAM_URL), &mut problems);
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
                audit_log_file,
                audit_sqlite_path,
                audit_sqlite_retention_days,
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
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.listen_addr,
            "127.0.0.1:9090"
                .parse::<SocketAddr>()
                .expect("test address should parse")
        );
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
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
    fn invalid_listen_addr_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("not-a-socket".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid socket addresses");

        let message = error.to_string();
        assert!(message.contains("configuration is invalid:"));
        assert!(message.contains("LISTEN_ADDR must be a valid socket address"));
        assert!(message.contains("not-a-socket"));
        assert_eq!(error.problems.len(), 1);
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
        assert_eq!(config.audit_log_file, None);
        assert_eq!(config.audit_sqlite_path, None);
        assert_eq!(config.audit_sqlite_retention_days, None);
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
            "AUTH_COOKIE_NAME" => Ok("gateway_session".to_owned()),
            "AUTH_EXEMPT_PATHS" => Ok(" /health, /ready ,, /metrics ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert!(!config.auth_enabled);
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
            "AUTH_COOKIE_NAME" => Ok("session token".to_owned()),
            "AUTH_EXEMPT_PATHS" => Ok("/health,admin".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid auth settings");

        let message = error.to_string();
        assert!(message.contains("AUTH_ENABLED must be a valid boolean"));
        assert!(message.contains("AUTH_COOKIE_NAME must be a non-empty RFC 6265 cookie name"));
        assert!(message.contains("AUTH_EXEMPT_PATHS entries must be URI paths"));
        assert_eq!(error.problems.len(), 3);
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
    fn empty_upstream_url_is_none() {
        let config = Config::from_env_vars(|name| match name {
            "UPSTREAM_URL" => Ok("   ".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(config.upstream_url, None);
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
