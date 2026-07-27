use std::{fmt, str::FromStr};

use http::HeaderName;
use percent_encoding::percent_decode_str;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use url::Url;
use uuid::Uuid;

pub const CONNECTION_SCHEMA_VERSION: &str = "0.1.0";
pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_CREDENTIALS: usize = 512;
pub const MAX_MANAGED_SPEC_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CATALOG_ENTRIES: usize = 4_096;
pub const MAX_STATUS_HISTORY_ROWS: usize = 4_096;
pub const MAX_CONCURRENT_REFRESHES: usize = 4;
pub const MAX_CONNECTION_ID_BYTES: usize = 128;
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;
pub const MAX_DESCRIPTION_CHARS: usize = 1_024;
pub const MAX_URL_BYTES: usize = 2_048;
pub const MAX_PATH_BYTES: usize = 1_024;
pub const MAX_SECRET_ID_BYTES: usize = 128;
pub const MAX_HEADER_NAME_BYTES: usize = 64;
pub const MAX_CLIENT_ID_BYTES: usize = 256;
pub const MAX_SCOPE_CHARS: usize = 128;
pub const MAX_SCOPES: usize = 16;
pub const MAX_AUDIENCE_RESOURCE_BYTES: usize = 512;
pub const MAX_EXPECTED_STATUSES: usize = 16;
pub const MIN_TIMEOUT_MS: u64 = 1;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_RESPONSE_IDLE_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(String);

impl ConnectionId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ConnectionValidationError> {
        let value = value.into();
        if is_valid_stable_id(&value, MAX_CONNECTION_ID_BYTES) {
            Ok(Self(value))
        } else {
            Err(ConnectionValidationError::new(
                "id",
                "invalid_stable_id",
                format!(
                    "must be 1-{MAX_CONNECTION_ID_BYTES} URL-safe ASCII characters, start with an ASCII letter or digit, and contain only letters, digits, '.', '_', or '-'"
                ),
            ))
        }
    }

    pub fn new_managed() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConnectionId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ConnectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ConnectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    HttpApi,
    McpStreamableHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionManagementSource {
    Managed,
    LegacyDefaultHttp,
    LegacyRoute,
    LegacyMcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionWrite {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub enabled: bool,
    pub kind: ConnectionKind,
    pub endpoint: ConnectionEndpoint,
    pub authentication: ConnectionAuthentication,
    #[serde(default, skip_serializing_if = "TlsProfile::is_empty")]
    pub tls: TlsProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<ConnectionTimeouts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_profile: Option<ConnectionTestProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionEndpoint {
    pub base_url: String,
    pub base_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionAuthentication {
    None,
    HeaderApiKey {
        header_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_id: Option<String>,
    },
    StaticBearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_id: Option<String>,
    },
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials {
        client_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret_id: Option<String>,
        token_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        client_auth_method: OAuthClientAuthMethod,
    },
}

impl ConnectionAuthentication {
    pub fn requires_confidential_transport(&self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthClientAuthMethod {
    ClientSecretBasic,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_private_key_id: Option<String>,
}

impl TlsProfile {
    pub fn is_empty(&self) -> bool {
        self.ca_bundle_alias.is_none()
            && self.client_certificate_id.is_none()
            && self.client_private_key_id.is_none()
    }

    pub fn has_client_identity(&self) -> bool {
        self.client_certificate_id.is_some() || self.client_private_key_id.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTimeouts {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub response_idle_timeout_ms: u64,
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        Self {
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            response_idle_timeout_ms: DEFAULT_RESPONSE_IDLE_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoveryConfig {
    ManagedOpenapi {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        use_connection_authentication: bool,
    },
    ManagedMcp {
        use_connection_authentication: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTestProfile {
    pub method: String,
    pub path: String,
    pub expected_statuses: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionValidationError {
    pub field: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl ConnectionValidationError {
    fn new(field: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConnectionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl ConnectionWrite {
    /// Validate and normalize a complete candidate before it can be persisted.
    pub fn validated(mut self) -> Result<Self, Vec<ConnectionValidationError>> {
        let mut errors = Vec::new();

        validate_bounded_text(
            "display_name",
            &self.display_name,
            MAX_DISPLAY_NAME_CHARS,
            false,
            &mut errors,
        );
        if let Some(description) = &self.description {
            validate_bounded_text(
                "description",
                description,
                MAX_DESCRIPTION_CHARS,
                true,
                &mut errors,
            );
        }

        match normalize_base_url(&self.endpoint.base_url) {
            Ok(base_url) => self.endpoint.base_url = base_url,
            Err(error) => errors.push(error),
        }
        match normalize_origin_relative_path("endpoint.base_path", &self.endpoint.base_path) {
            Ok(base_path) => self.endpoint.base_path = base_path,
            Err(error) => errors.push(error),
        }

        validate_authentication(&mut self.authentication, self.enabled, &mut errors);
        validate_tls(&self.tls, self.enabled, &mut errors);
        validate_timeouts(self.timeouts.as_ref(), &mut errors);
        validate_discovery(self.kind, self.discovery.as_mut(), &mut errors);
        validate_test_profile(self.test_profile.as_mut(), &mut errors);

        let requires_tls =
            self.authentication.requires_confidential_transport() || !self.tls.is_empty();
        if requires_tls && !self.endpoint.base_url.starts_with("https://") {
            errors.push(ConnectionValidationError::new(
                "endpoint.base_url",
                "https_required",
                "credentialed connections and TLS profiles must use HTTPS",
            ));
        }

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }

    pub fn configures_credential_authority(&self) -> bool {
        !matches!(self.authentication, ConnectionAuthentication::None) || !self.tls.is_empty()
    }

    pub fn requires_secrets_write_to_create(&self) -> bool {
        self.configures_credential_authority()
    }

    pub fn requires_secrets_write_to_replace(&self, candidate: &Self) -> bool {
        self.authentication != candidate.authentication
            || self.tls != candidate.tls
            || ((self.configures_credential_authority()
                || candidate.configures_credential_authority())
                && self.endpoint != candidate.endpoint)
            || (discovery_uses_authentication(self.discovery.as_ref())
                || discovery_uses_authentication(candidate.discovery.as_ref()))
                && self.discovery != candidate.discovery
    }

    pub fn requires_secrets_write_to_delete(&self) -> bool {
        self.configures_credential_authority()
    }

    pub fn unresolved_enabled_binding_fields(
        &self,
        mut binding_is_configured: impl FnMut(&str) -> bool,
    ) -> Vec<&'static str> {
        if !self.enabled {
            return Vec::new();
        }
        let mut unresolved = Vec::new();
        match &self.authentication {
            ConnectionAuthentication::None => {}
            ConnectionAuthentication::HeaderApiKey {
                secret_id: Some(secret_id),
                ..
            }
            | ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret_id),
            } => {
                if !binding_is_configured(secret_id) {
                    unresolved.push("authentication.secret_id");
                }
            }
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: Some(secret_id),
                ..
            } => {
                if !binding_is_configured(secret_id) {
                    unresolved.push("authentication.client_secret_id");
                }
            }
            ConnectionAuthentication::HeaderApiKey {
                secret_id: None, ..
            }
            | ConnectionAuthentication::StaticBearer { secret_id: None }
            | ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: None,
                ..
            } => {}
        }
        for (field, binding) in [
            ("tls.ca_bundle_alias", self.tls.ca_bundle_alias.as_deref()),
            (
                "tls.client_certificate_id",
                self.tls.client_certificate_id.as_deref(),
            ),
            (
                "tls.client_private_key_id",
                self.tls.client_private_key_id.as_deref(),
            ),
        ] {
            if let Some(binding) = binding {
                if !binding_is_configured(binding) {
                    unresolved.push(field);
                }
            }
        }
        unresolved
    }
}

pub fn is_valid_connection_id(value: &str) -> bool {
    is_valid_stable_id(value, MAX_CONNECTION_ID_BYTES)
}

fn validate_authentication(
    authentication: &mut ConnectionAuthentication,
    enabled: bool,
    errors: &mut Vec<ConnectionValidationError>,
) {
    match authentication {
        ConnectionAuthentication::None => {}
        ConnectionAuthentication::HeaderApiKey {
            header_name,
            secret_id,
        } => {
            validate_optional_secret_id(
                "authentication.secret_id",
                secret_id.as_deref(),
                enabled,
                errors,
            );
            if header_name.is_empty()
                || header_name.len() > MAX_HEADER_NAME_BYTES
                || HeaderName::from_str(header_name).is_err()
                || is_reserved_credential_header(header_name)
            {
                errors.push(ConnectionValidationError::new(
                    "authentication.header_name",
                    "invalid_header_name",
                    "must be a valid non-reserved HTTP header name of at most 64 bytes",
                ));
            } else {
                *header_name = header_name.to_ascii_lowercase();
            }
        }
        ConnectionAuthentication::StaticBearer { secret_id } => {
            validate_optional_secret_id(
                "authentication.secret_id",
                secret_id.as_deref(),
                enabled,
                errors,
            );
        }
        ConnectionAuthentication::OAuth2ClientCredentials {
            client_id,
            client_secret_id,
            token_url,
            scopes,
            audience,
            resource,
            ..
        } => {
            validate_bounded_bytes(
                "authentication.client_id",
                client_id,
                MAX_CLIENT_ID_BYTES,
                false,
                errors,
            );
            validate_optional_secret_id(
                "authentication.client_secret_id",
                client_secret_id.as_deref(),
                enabled,
                errors,
            );
            match normalize_token_url(token_url) {
                Ok(normalized) => *token_url = normalized,
                Err(error) => errors.push(error),
            }
            if scopes.len() > MAX_SCOPES {
                errors.push(ConnectionValidationError::new(
                    "authentication.scopes",
                    "too_many",
                    format!("must contain at most {MAX_SCOPES} entries"),
                ));
            }
            let mut seen_scopes = std::collections::BTreeSet::new();
            for scope in scopes.iter() {
                validate_bounded_text(
                    "authentication.scopes",
                    scope,
                    MAX_SCOPE_CHARS,
                    false,
                    errors,
                );
                if scope.chars().any(char::is_whitespace) {
                    errors.push(ConnectionValidationError::new(
                        "authentication.scopes",
                        "invalid_scope",
                        "scope entries must not contain whitespace",
                    ));
                }
                if !seen_scopes.insert(scope.as_str()) {
                    errors.push(ConnectionValidationError::new(
                        "authentication.scopes",
                        "duplicate_scope",
                        "scope entries must be unique",
                    ));
                }
            }
            scopes.sort();
            scopes.dedup();
            validate_optional_bounded_bytes(
                "authentication.audience",
                audience.as_deref(),
                MAX_AUDIENCE_RESOURCE_BYTES,
                errors,
            );
            validate_optional_bounded_bytes(
                "authentication.resource",
                resource.as_deref(),
                MAX_AUDIENCE_RESOURCE_BYTES,
                errors,
            );
        }
    }
}

fn validate_tls(tls: &TlsProfile, enabled: bool, errors: &mut Vec<ConnectionValidationError>) {
    if enabled && tls.client_certificate_id.is_some() != tls.client_private_key_id.is_some() {
        errors.push(ConnectionValidationError::new(
            "tls",
            "incomplete_client_identity",
            "client_certificate_id and client_private_key_id must be configured together",
        ));
    }
    for (field, value) in [
        ("tls.ca_bundle_alias", tls.ca_bundle_alias.as_deref()),
        (
            "tls.client_certificate_id",
            tls.client_certificate_id.as_deref(),
        ),
        (
            "tls.client_private_key_id",
            tls.client_private_key_id.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_secret_id(field, value, errors);
        }
    }
}

fn validate_timeouts(
    timeouts: Option<&ConnectionTimeouts>,
    errors: &mut Vec<ConnectionValidationError>,
) {
    let Some(timeouts) = timeouts else {
        return;
    };
    for (field, value) in [
        ("timeouts.connect_timeout_ms", timeouts.connect_timeout_ms),
        ("timeouts.request_timeout_ms", timeouts.request_timeout_ms),
        (
            "timeouts.response_idle_timeout_ms",
            timeouts.response_idle_timeout_ms,
        ),
    ] {
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&value) {
            errors.push(ConnectionValidationError::new(
                field,
                "out_of_range",
                format!("must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}"),
            ));
        }
    }
}

fn validate_discovery(
    kind: ConnectionKind,
    discovery: Option<&mut DiscoveryConfig>,
    errors: &mut Vec<ConnectionValidationError>,
) {
    let Some(discovery) = discovery else {
        return;
    };
    match discovery {
        DiscoveryConfig::ManagedOpenapi { path, .. } => {
            if kind != ConnectionKind::HttpApi {
                errors.push(ConnectionValidationError::new(
                    "discovery.type",
                    "kind_mismatch",
                    "managed_openapi discovery requires kind http_api",
                ));
            }
            if let Some(path) = path {
                match normalize_origin_relative_path("discovery.path", path) {
                    Ok(normalized) => *path = normalized,
                    Err(error) => errors.push(error),
                }
            }
        }
        DiscoveryConfig::ManagedMcp { .. } => {
            if kind != ConnectionKind::McpStreamableHttp {
                errors.push(ConnectionValidationError::new(
                    "discovery.type",
                    "kind_mismatch",
                    "managed_mcp discovery requires kind mcp_streamable_http",
                ));
            }
        }
    }
}

fn discovery_uses_authentication(discovery: Option<&DiscoveryConfig>) -> bool {
    match discovery {
        Some(DiscoveryConfig::ManagedOpenapi {
            use_connection_authentication,
            ..
        })
        | Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication,
        }) => *use_connection_authentication,
        None => false,
    }
}

fn validate_test_profile(
    profile: Option<&mut ConnectionTestProfile>,
    errors: &mut Vec<ConnectionValidationError>,
) {
    let Some(profile) = profile else {
        return;
    };
    if !matches!(profile.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        errors.push(ConnectionValidationError::new(
            "test_profile.method",
            "unsafe_method",
            "must be GET, HEAD, or OPTIONS",
        ));
    }
    match normalize_origin_relative_path("test_profile.path", &profile.path) {
        Ok(path) => profile.path = path,
        Err(error) => errors.push(error),
    }
    let unique_statuses = profile
        .expected_statuses
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if profile.expected_statuses.is_empty()
        || profile.expected_statuses.len() > MAX_EXPECTED_STATUSES
        || profile
            .expected_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
        || unique_statuses.len() != profile.expected_statuses.len()
    {
        errors.push(ConnectionValidationError::new(
            "test_profile.expected_statuses",
            "invalid_statuses",
            format!("must contain 1-{MAX_EXPECTED_STATUSES} HTTP status codes between 100 and 599"),
        ));
    }
}

fn normalize_base_url(value: &str) -> Result<String, ConnectionValidationError> {
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        return Err(ConnectionValidationError::new(
            "endpoint.base_url",
            "invalid_length",
            format!("must contain 1-{MAX_URL_BYTES} bytes"),
        ));
    }
    let parsed = parse_http_url("endpoint.base_url", value)?;
    if !matches!(raw_url_path(value), Some("" | "/"))
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConnectionValidationError::new(
            "endpoint.base_url",
            "not_an_origin",
            "must be an HTTP(S) origin without a path, query, or fragment",
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}

fn normalize_token_url(value: &str) -> Result<String, ConnectionValidationError> {
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        return Err(ConnectionValidationError::new(
            "authentication.token_url",
            "invalid_length",
            format!("must contain 1-{MAX_URL_BYTES} bytes"),
        ));
    }
    let parsed = parse_http_url("authentication.token_url", value)?;
    if parsed.scheme() != "https" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ConnectionValidationError::new(
            "authentication.token_url",
            "invalid_token_url",
            "must be an HTTPS URL without userinfo, query, or fragment",
        ));
    }
    let raw_path = raw_url_path(value).unwrap_or_default();
    normalize_origin_relative_path(
        "authentication.token_url",
        if raw_path.is_empty() { "/" } else { raw_path },
    )?;
    Ok(parsed.to_string())
}

fn parse_http_url(field: &'static str, value: &str) -> Result<Url, ConnectionValidationError> {
    let parsed = Url::parse(value).map_err(|_| {
        ConnectionValidationError::new(field, "invalid_url", "must be a valid absolute HTTP(S) URL")
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ConnectionValidationError::new(
            field,
            "invalid_authority",
            "must use HTTP(S), include a host, and contain no userinfo",
        ));
    }
    Ok(parsed)
}

fn raw_url_path(value: &str) -> Option<&str> {
    let scheme_end = value.find("://")? + 3;
    let after_scheme = value.get(scheme_end..)?;
    let path_start = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let suffix = after_scheme.get(path_start..)?;
    if !suffix.starts_with('/') {
        return Some("");
    }
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    suffix.get(..path_end)
}

pub(crate) fn normalize_origin_relative_path(
    field: &'static str,
    value: &str,
) -> Result<String, ConnectionValidationError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains("//")
        || value.contains(['?', '#', '\\'])
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || has_invalid_percent_escape(value)
    {
        return Err(ConnectionValidationError::new(
            field,
            "invalid_origin_relative_path",
            format!(
                "must be an origin-relative path of 1-{MAX_PATH_BYTES} bytes without authority, query, fragment, or backslash forms"
            ),
        ));
    }

    for segment in value.split('/') {
        let decoded = percent_decode_str(segment).decode_utf8().map_err(|_| {
            ConnectionValidationError::new(
                field,
                "invalid_percent_encoding",
                "must contain valid UTF-8 percent encoding",
            )
        })?;
        if matches!(decoded.as_ref(), "." | "..")
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.contains('\0')
        {
            return Err(ConnectionValidationError::new(
                field,
                "path_confusion",
                "must not contain dot segments or encoded path separators",
            ));
        }
    }

    if value.len() > 1 {
        Ok(value.trim_end_matches('/').to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn has_invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn validate_secret_id(
    field: &'static str,
    value: &str,
    errors: &mut Vec<ConnectionValidationError>,
) {
    if !is_valid_stable_id(value, MAX_SECRET_ID_BYTES) {
        errors.push(ConnectionValidationError::new(
            field,
            "invalid_secret_id",
            format!(
                "must be an opaque URL-safe ID of 1-{MAX_SECRET_ID_BYTES} bytes and must not be an environment or file locator"
            ),
        ));
    }
}

fn validate_optional_secret_id(
    field: &'static str,
    value: Option<&str>,
    required: bool,
    errors: &mut Vec<ConnectionValidationError>,
) {
    match value {
        Some(value) => validate_secret_id(field, value, errors),
        None if required => errors.push(ConnectionValidationError::new(
            field,
            "missing_binding",
            "must be configured before the connection can be enabled",
        )),
        None => {}
    }
}

fn is_valid_stable_id(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= maximum
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_reserved_credential_header(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    matches!(
        value.as_str(),
        "authorization"
            | "cookie"
            | "host"
            | "content-length"
            | "content-type"
            | "connection"
            | "expect"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-request-id"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-real-ip"
            | "x-csrf-token"
            | "forwarded"
            | "via"
    ) || value.starts_with("x-forwarded-")
        || value.starts_with("x-greengateway-")
        || value.starts_with("sec-")
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum_chars: usize,
    allow_empty: bool,
    errors: &mut Vec<ConnectionValidationError>,
) {
    let length = value.chars().count();
    if (!allow_empty && length == 0) || length > maximum_chars || value.contains('\0') {
        errors.push(ConnectionValidationError::new(
            field,
            "invalid_length",
            format!("must contain at most {maximum_chars} characters"),
        ));
    }
}

fn validate_bounded_bytes(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
    errors: &mut Vec<ConnectionValidationError>,
) {
    if (!allow_empty && value.is_empty()) || value.len() > maximum_bytes || value.contains('\0') {
        errors.push(ConnectionValidationError::new(
            field,
            "invalid_length",
            format!("must contain at most {maximum_bytes} bytes"),
        ));
    }
}

fn validate_optional_bounded_bytes(
    field: &'static str,
    value: Option<&str>,
    maximum_bytes: usize,
    errors: &mut Vec<ConnectionValidationError>,
) {
    if let Some(value) = value {
        validate_bounded_bytes(field, value, maximum_bytes, false, errors);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    const CONNECTION_SCHEMA_JSON: &str =
        include_str!("../../../docs/schemas/connection.v0.schema.json");

    fn connection_schema_validator() -> jsonschema::Validator {
        let schema: Value =
            serde_json::from_str(CONNECTION_SCHEMA_JSON).expect("schema should be valid JSON");
        jsonschema::validator_for(&schema).expect("schema should compile")
    }

    fn example() -> Value {
        json!({
            "display_name": "Billing API",
            "enabled": false,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "oauth2_client_credentials",
                "client_id": "greengateway",
                "client_secret_id": "billing-client-secret",
                "token_url": "https://idp.example.test/oauth/token",
                "scopes": ["billing.read"],
                "client_auth_method": "client_secret_basic"
            },
            "tls": {
                "ca_bundle_alias": "billing-ca",
                "client_certificate_id": "billing-client-cert",
                "client_private_key_id": "billing-client-key"
            },
            "discovery": {
                "type": "managed_openapi",
                "use_connection_authentication": true
            },
            "test_profile": {
                "method": "HEAD",
                "path": "/ready",
                "expected_statuses": [200, 204]
            }
        })
    }

    #[test]
    fn issue_example_matches_schema_and_rust_model() {
        connection_schema_validator()
            .validate(&example())
            .expect("issue example should match published schema");

        let candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("issue example should deserialize");
        let validated = candidate
            .validated()
            .expect("issue example should validate");
        assert_eq!(validated.endpoint.base_url, "https://billing.example.test");
    }

    #[test]
    fn model_rejects_unknown_fields() {
        let mut candidate = example();
        candidate["inline_secret"] = json!("must-not-be-accepted");

        let error = serde_json::from_value::<ConnectionWrite>(candidate)
            .expect_err("unknown fields must fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn credentialed_http_and_authority_changing_paths_fail() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        candidate.endpoint.base_url = "http://billing.example.test".to_owned();
        candidate.endpoint.base_path = "//attacker.example.test".to_owned();

        let errors = candidate.validated().expect_err("candidate must fail");
        assert!(errors.iter().any(|error| error.code == "https_required"));
        assert!(errors
            .iter()
            .any(|error| error.code == "invalid_origin_relative_path"));
    }

    #[test]
    fn base_url_is_an_origin_and_default_port_is_normalized() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        candidate.endpoint.base_url = "https://BILLING.example.test:443/".to_owned();

        let validated = candidate.validated().expect("origin should validate");
        assert_eq!(validated.endpoint.base_url, "https://billing.example.test");
    }

    #[test]
    fn url_parser_normalization_cannot_hide_dot_segment_paths() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        candidate.endpoint.base_url = "https://billing.example.test/%2e%2e".to_owned();
        if let ConnectionAuthentication::OAuth2ClientCredentials { token_url, .. } =
            &mut candidate.authentication
        {
            *token_url = "https://idp.example.test/oauth/%2e%2e/token".to_owned();
        }

        let errors = candidate.validated().expect_err("candidate must fail");
        assert!(errors
            .iter()
            .any(|error| error.field == "endpoint.base_url"));
        assert!(errors
            .iter()
            .any(|error| error.field == "authentication.token_url"));
    }

    #[test]
    fn paths_reject_dot_segments_encoded_separators_query_and_fragment() {
        for path in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2F/admin",
            "/v1?next=//attacker",
            "/v1#fragment",
            "/v1\\admin",
            "/v1/%zz",
            "/v1/has space",
        ] {
            assert!(
                normalize_origin_relative_path("path", path).is_err(),
                "{path} must fail"
            );
        }
    }

    #[test]
    fn secret_ids_are_opaque_and_tls_identity_is_paired() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        candidate.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some("env://BILLING_TOKEN".to_owned()),
        };
        candidate.tls.client_private_key_id = None;
        candidate.enabled = true;

        let errors = candidate.validated().expect_err("candidate must fail");
        assert!(errors.iter().any(|error| error.code == "invalid_secret_id"));
        assert!(errors
            .iter()
            .any(|error| error.code == "incomplete_client_identity"));
    }

    #[test]
    fn auth_header_and_scope_constraints_fail_closed() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        candidate.authentication = ConnectionAuthentication::HeaderApiKey {
            header_name: "X-Forwarded-Credential".to_owned(),
            secret_id: Some("billing-api-key".to_owned()),
        };
        let errors = candidate
            .validated()
            .expect_err("reserved header must fail");
        assert!(errors
            .iter()
            .any(|error| error.code == "invalid_header_name"));

        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        if let ConnectionAuthentication::OAuth2ClientCredentials { scopes, .. } =
            &mut candidate.authentication
        {
            scopes.push("billing.read".to_owned());
        }
        let errors = candidate
            .validated()
            .expect_err("duplicate scope must fail");
        assert!(errors.iter().any(|error| error.code == "duplicate_scope"));
    }

    #[test]
    fn connection_ids_are_url_safe_and_managed_ids_are_uuid_backed() {
        let managed = ConnectionId::new_managed();
        assert!(Uuid::parse_str(managed.as_str()).is_ok());
        assert!(ConnectionId::parse("legacy-default-http").is_ok());
        assert!(ConnectionId::parse("../secret").is_err());
        assert!(ConnectionId::parse("mcp/server").is_err());
    }

    #[test]
    fn incomplete_bindings_are_allowed_only_while_disabled() {
        let mut disabled: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        disabled.authentication = ConnectionAuthentication::StaticBearer { secret_id: None };
        disabled.tls.client_private_key_id = None;
        disabled.enabled = false;
        disabled
            .clone()
            .validated()
            .expect("disabled draft may retain incomplete bindings");

        disabled.enabled = true;
        let errors = disabled
            .validated()
            .expect_err("enabled connection must have complete bindings");
        assert!(errors.iter().any(|error| error.code == "missing_binding"));
        assert!(errors
            .iter()
            .any(|error| error.code == "incomplete_client_identity"));

        let mut disabled_json = example();
        disabled_json["authentication"] = json!({
            "type": "static_bearer"
        });
        disabled_json["tls"] = json!({
            "client_certificate_id": "billing-client-cert"
        });
        disabled_json["enabled"] = json!(false);
        let validator = connection_schema_validator();
        validator
            .validate(&disabled_json)
            .expect("schema must allow incomplete disabled draft bindings");

        disabled_json["enabled"] = json!(true);
        assert!(
            validator.validate(&disabled_json).is_err(),
            "schema must reject incomplete enabled bindings"
        );
    }

    #[test]
    fn test_profile_case_and_duplicate_statuses_match_schema_rules() {
        let mut candidate: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        let profile = candidate
            .test_profile
            .as_mut()
            .expect("example should include a test profile");
        profile.method = "head".to_owned();
        profile.expected_statuses = vec![200, 200];

        let errors = candidate.validated().expect_err("profile must fail");
        assert!(errors
            .iter()
            .any(|error| error.field == "test_profile.method"));
        assert!(errors
            .iter()
            .any(|error| error.field == "test_profile.expected_statuses"));
    }

    #[test]
    fn secrets_permission_tracks_credential_use_authority_not_plain_metadata() {
        let mut plain: ConnectionWrite =
            serde_json::from_value(example()).expect("example should deserialize");
        plain.authentication = ConnectionAuthentication::None;
        plain.tls = TlsProfile::default();
        plain.discovery = None;

        assert!(!plain.requires_secrets_write_to_create());
        assert!(!plain.requires_secrets_write_to_delete());

        let mut presentation = plain.clone();
        presentation.display_name = "Renamed billing API".to_owned();
        presentation.description = Some("non-sensitive operator note".to_owned());
        presentation.timeouts = Some(ConnectionTimeouts::default());
        assert!(!plain.requires_secrets_write_to_replace(&presentation));

        let mut plain_redirect = plain.clone();
        plain_redirect.endpoint.base_url = "https://replacement.example.test".to_owned();
        assert!(!plain.requires_secrets_write_to_replace(&plain_redirect));

        let mut credentialed = plain.clone();
        credentialed.enabled = true;
        credentialed.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some("billing-token".to_owned()),
        };
        assert!(credentialed.requires_secrets_write_to_create());
        assert!(plain.requires_secrets_write_to_replace(&credentialed));
        assert!(credentialed.requires_secrets_write_to_delete());
        assert_eq!(
            credentialed.unresolved_enabled_binding_fields(|id| id == "billing-token"),
            Vec::<&'static str>::new()
        );
        assert_eq!(
            credentialed.unresolved_enabled_binding_fields(|_| false),
            vec!["authentication.secret_id"]
        );
        let mut disabled_credentialed = credentialed.clone();
        disabled_credentialed.enabled = false;
        assert!(disabled_credentialed
            .unresolved_enabled_binding_fields(|_| false)
            .is_empty());

        let mut credential_redirect = credentialed.clone();
        credential_redirect.endpoint.base_url = "https://replacement.example.test".to_owned();
        assert!(credentialed.requires_secrets_write_to_replace(&credential_redirect));

        let mut credentialed_discovery = credentialed.clone();
        credentialed_discovery.discovery = Some(DiscoveryConfig::ManagedOpenapi {
            path: Some("/openapi.json".to_owned()),
            use_connection_authentication: true,
        });
        assert!(credentialed.requires_secrets_write_to_replace(&credentialed_discovery));

        let mut tls = plain.clone();
        tls.tls.ca_bundle_alias = Some("billing-ca".to_owned());
        assert!(plain.requires_secrets_write_to_replace(&tls));
    }
}
