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
const DEFAULT_CSRF_ENABLED: bool = true;
const DEFAULT_CSRF_COOKIE_NAME: &str = "csrf_token";
const DEFAULT_CSRF_HEADER_NAME: &str = "x-csrf-token";
const DEFAULT_CSRF_EXEMPT_PATHS: &[&str] = &["/health", "/version", "/metrics"];
const AUDIT_LOG_FILE: &str = "AUDIT_LOG_FILE";
const CORS_ALLOW_ORIGINS: &str = "CORS_ALLOW_ORIGINS";
const CSRF_COOKIE_DOMAIN: &str = "CSRF_COOKIE_DOMAIN";
const CSRF_COOKIE_NAME: &str = "CSRF_COOKIE_NAME";
const CSRF_ENABLED: &str = "CSRF_ENABLED";
const CSRF_EXEMPT_PATHS: &str = "CSRF_EXEMPT_PATHS";
const CSRF_HEADER_NAME: &str = "CSRF_HEADER_NAME";
const MAX_BODY_SIZE: &str = "MAX_BODY_SIZE";
const RATE_LIMIT_READ_RPS: &str = "RATE_LIMIT_READ_RPS";
const RATE_LIMIT_READ_BURST: &str = "RATE_LIMIT_READ_BURST";
const RATE_LIMIT_WRITE_RPS: &str = "RATE_LIMIT_WRITE_RPS";
const RATE_LIMIT_WRITE_BURST: &str = "RATE_LIMIT_WRITE_BURST";
const TRUST_PROXY_HEADERS: &str = "TRUST_PROXY_HEADERS";
const SESSION_COOKIE_NAME: &str = "SESSION_COOKIE_NAME";
const VALIDATION_ALLOWED_CONTENT_TYPES: &str = "VALIDATION_ALLOWED_CONTENT_TYPES";

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub audit_log_file: Option<String>,
    pub cors_allow_origins: Vec<String>,
    pub max_body_size: usize,
    pub rate_limit_read_rps: f64,
    pub rate_limit_read_burst: u32,
    pub rate_limit_write_rps: f64,
    pub rate_limit_write_burst: u32,
    pub trust_proxy_headers: bool,
    pub session_cookie_name: String,
    pub validation_allowed_content_types: Vec<String>,
    pub csrf_enabled: bool,
    pub csrf_cookie_name: String,
    pub csrf_header_name: String,
    pub csrf_cookie_domain: Option<String>,
    pub csrf_exempt_paths: Vec<String>,
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

        if problems.is_empty() {
            Ok(Self {
                listen_addr,
                audit_log_file,
                cors_allow_origins,
                max_body_size,
                rate_limit_read_rps,
                rate_limit_read_burst,
                rate_limit_write_rps,
                rate_limit_write_burst,
                trust_proxy_headers,
                session_cookie_name,
                validation_allowed_content_types,
                csrf_enabled,
                csrf_cookie_name,
                csrf_header_name,
                csrf_cookie_domain,
                csrf_exempt_paths,
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
        assert!(config.session_cookie_name.is_empty());
        assert_eq!(
            config.validation_allowed_content_types,
            vec!["application/json".to_owned()]
        );
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
        assert!(config.session_cookie_name.is_empty());
        assert_eq!(
            config.validation_allowed_content_types,
            vec!["application/json".to_owned()]
        );
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
