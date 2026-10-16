//! Golden parity for `Config::from_env_vars` (issue #433, PR 1).
//!
//! The configuration compiler issue #433 extracts must keep the legacy
//! environment's semantics, so these fixtures pin what the parser does today,
//! including where that is surprising, rather than what a reading of it
//! suggests. Expected values are written out instead of taken from the
//! `DEFAULT_*` constants, because a fixture that moved with a changed constant
//! would not notice the change, and variable names are spelled out for the
//! same reason. A fixture that has to change records a behaviour change; that
//! belongs to a pull request that says so, not to one that moves code.

use std::collections::BTreeSet;

use super::diagnostic::{ConfigDiagnostic, ConfigDiagnosticCode};
use super::*;

/// What a fixture environment holds for `name`: exactly the listed value, or
/// unset when the fixture does not list it.
fn fixture_value(fixture: &[(&str, &str)], name: &str) -> Result<String, VarError> {
    fixture
        .iter()
        .find(|(variable, _)| *variable == name)
        .map(|(_, value)| (*value).to_owned())
        .ok_or(VarError::NotPresent)
}

/// Parses a fixture environment: each listed variable has exactly the listed
/// value, and every other variable is unset.
fn parse_fixture(fixture: &[(&str, &str)]) -> Result<Config, ConfigError> {
    Config::from_env_vars(|name| fixture_value(fixture, name))
}

fn accepted(fixture: &[(&str, &str)]) -> Config {
    match parse_fixture(fixture) {
        Ok(config) => config,
        Err(error) => panic!("the fixture should be accepted: {fixture:?}\n{error}"),
    }
}

fn refused(fixture: &[(&str, &str)]) -> ConfigError {
    match parse_fixture(fixture) {
        Ok(_) => panic!("the fixture should be refused: {fixture:?}"),
        Err(error) => error,
    }
}

fn socket(value: &str) -> SocketAddr {
    value.parse().expect("fixture socket addresses are valid")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// The probe paths every exemption list starts from, then `extra`.
fn with_probes(extra: &[&str]) -> Vec<String> {
    let mut paths = strings(&[
        "/health",
        "/livez",
        "/startupz",
        "/readyz",
        "/version",
        "/metrics",
    ]);
    paths.extend(strings(extra));
    paths
}

/// The diagnostic `from_env_vars` reports for a problem about `variable`.
fn expected_diagnostic(variable: &'static str, code: ConfigDiagnosticCode) -> ConfigDiagnostic {
    let message = match code {
        ConfigDiagnosticCode::Unset => format!("{variable} is not set"),
        ConfigDiagnosticCode::Empty => format!("{variable} is set but empty"),
        ConfigDiagnosticCode::NotUnicode => format!("{variable} is not valid Unicode"),
        ConfigDiagnosticCode::Refused => format!("{variable} is set to a value that was refused"),
        ConfigDiagnosticCode::Unattributed => panic!("an expected diagnostic names its variable"),
    };
    ConfigDiagnostic {
        variable: Some(variable),
        code,
        message,
    }
}

/// An identity provider the admin login accepts, under the `/operations`
/// admin prefix.
fn admin_login_provider_document() -> &'static str {
    r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/operations/auth/callback"}]"#
}

/// A complete cluster-mode configuration.
fn postgres_fixture() -> Vec<(&'static str, &'static str)> {
    vec![
        ("STATE_BACKEND", "postgres"),
        ("DEPLOYMENT_ID", "deploy-prod-eu"),
        (
            "DATABASE_URL_FILE",
            "/run/secrets/greengateway/database-url",
        ),
        ("CONNECTION_SECRETS_ROOT", "/run/secrets/greengateway"),
        (
            "RATE_LIMIT_KEYRING",
            r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#,
        ),
    ]
}

#[test]
fn an_empty_environment_parses_to_the_legacy_defaults() {
    let config = accepted(&[]);

    // Listeners and inbound TLS.
    assert_eq!(config.listen_addr, socket("0.0.0.0:8080"));
    assert_eq!(config.admin_listen_addr, None);
    assert_eq!(config.grpc_listen_addr, None);
    assert_eq!(config.grpc_max_concurrent_streams, 100);
    assert_eq!(config.grpc_max_metadata_bytes, 16_384);
    assert_eq!(config.tls_cert_files, None);
    assert_eq!(config.tls_key_files, None);
    assert_eq!(config.admin_tls_cert_files, None);
    assert_eq!(config.admin_tls_key_files, None);
    assert_eq!(config.tls_min_version, TlsMinVersion::Tls12);
    assert_eq!(config.tls_handshake_timeout_ms, 10_000);
    assert_eq!(config.tls_max_concurrent_handshakes, 256);
    assert_eq!(config.client_cert_auth, None);
    assert_eq!(config.admin_client_cert_auth, None);

    // The admin surface and the public origin.
    assert_eq!(config.admin_prefix, "/admin");
    assert_eq!(config.admin_login_provider, None);
    assert_eq!(config.admin_session, None);
    assert_eq!(config.admin_login_pending_ttl_secs, 300);
    assert_eq!(config.admin_login_pending_max_entries, 1_024);
    assert_eq!(config.admin_login_pending_max_per_ip, 16);
    assert_eq!(config.gateway_public_url, None);
    assert!(config.cors_allow_origins.is_empty());

    // Authentication and CSRF.
    assert!(config.auth_enabled);
    assert_eq!(config.auth_mode, AuthMode::Required);
    assert_eq!(config.auth_cookie_name, "session");
    assert_eq!(config.auth_exempt_paths, with_probes(&["/admin"]));
    assert_eq!(config.rbac_exempt_paths, with_probes(&["/admin"]));
    assert!(config.auth_providers.is_empty());
    assert_eq!(config.jwt_jwks_url, None);
    assert_eq!(config.jwt_jwks_timeout_ms, 2_000);
    assert_eq!(config.jwt_jwks_max_key_age_secs, 300);
    assert!(!config.jwt_require_jti);
    assert_eq!(config.roles_claim, "roles");
    assert_eq!(config.service_token_cache_ttl_ms, 5_000);
    assert!(config.csrf_enabled);
    assert_eq!(config.csrf_cookie_name, "csrf_token");
    assert_eq!(config.csrf_header_name, "x-csrf-token");
    assert_eq!(config.csrf_cookie_domain, None);
    assert_eq!(config.csrf_exempt_paths, with_probes(&[]));

    // Request bounds and proxy trust.
    assert_eq!(config.max_body_size, 1_048_576);
    assert_eq!(config.max_request_path_bytes, 8_192);
    assert_eq!(config.rate_limit_read_rps, 50.0);
    assert_eq!(config.rate_limit_read_burst, 100);
    assert_eq!(config.rate_limit_write_rps, 10.0);
    assert_eq!(config.rate_limit_write_burst, 20);
    assert_eq!(config.rate_limit_max_buckets, 65_536);
    assert_eq!(config.rate_limit_bucket_ttl_ms, 600_000);
    assert!(!config.trust_proxy_headers);
    assert!(config.trusted_proxy_cidrs.is_empty());
    assert_eq!(
        config.validation_allowed_content_types,
        strings(&["application/json"])
    );

    // Storage: standalone, with every local store off until it is named.
    assert_eq!(config.state_backend, StateBackend::Sqlite);
    assert_eq!(config.deployment_id, None);
    for (setting, value) in [
        ("AUDIT_LOG_FILE", &config.audit_log_file),
        ("AUDIT_SQLITE_PATH", &config.audit_sqlite_path),
        ("DISCOVERY_SQLITE_PATH", &config.discovery_sqlite_path),
        ("PRINCIPAL_SQLITE_PATH", &config.principal_sqlite_path),
        ("CONNECTIONS_SQLITE_PATH", &config.connections_sqlite_path),
        ("POLICY_FILE", &config.policy_file),
        ("TOOLS_FILE", &config.tools_file),
        (
            "POLICY_HISTORY_SQLITE_PATH",
            &config.policy_history_sqlite_path,
        ),
        (
            "SERVICE_TOKEN_SQLITE_PATH",
            &config.service_token_sqlite_path,
        ),
    ] {
        assert!(value.is_none(), "{setting} defaults to unset");
    }
    assert_eq!(config.audit_sqlite_retention_days, None);
    assert_eq!(config.audit_postgres_retention_days, None);
    assert_eq!(
        config.database,
        DatabaseSettings {
            pool_max: 10,
            connect_timeout_ms: 5_000,
            acquire_timeout_ms: 5_000,
            statement_timeout_ms: 15_000,
            idle_in_transaction_timeout_ms: 30_000,
            lock_timeout_ms: 5_000,
            startup_retry_limit: 5,
            auto_migrate: false,
            migration_statement_timeout_ms: 60_000,
            tls_mode: DatabaseTlsMode::Verify,
            tls_ca_file: None,
            url_file: None,
        }
    );

    // Upstream routing and egress: nothing is routed, private addresses are
    // denied, and every bound is finite.
    assert_eq!(config.upstream_url, None);
    assert!(config.upstream_routes.is_empty());
    assert!(config.mcp_upstream_servers.is_empty());
    assert_eq!(config.upstream_timeout_ms, None);
    assert_eq!(config.upstream_response_idle_timeout_ms, None);
    assert_eq!(config.upstream_connect_timeout_ms, None);
    assert!(config.egress_allowed_hosts.is_empty());
    assert_eq!(config.egress_timeout_ms, 30_000);
    assert_eq!(config.egress_response_idle_timeout_ms, 30_000);
    assert_eq!(config.egress_connect_timeout_ms, 10_000);
    assert_eq!(config.egress_max_response_bytes, 5_242_880);
    assert_eq!(config.egress_max_request_body_bytes, 1_048_576);
    assert!(config.egress_nat64_prefixes.is_empty());
    assert!(config.egress_deny_private_ips);
}

/// Variables for which an empty or whitespace-only value is exactly the same
/// as leaving them unset.
const BLANK_IS_UNSET: &[&str] = &[
    "ADMIN_LISTEN_ADDR",
    "GRPC_LISTEN_ADDR",
    "TLS_CERT_FILE",
    "TLS_KEY_FILE",
    "ADMIN_TLS_CERT_FILE",
    "ADMIN_TLS_KEY_FILE",
    "CLIENT_CERT_IDENTITY_SOURCE",
    "CLIENT_CERT_CA_FILE",
    "CLIENT_CERT_CRL_FILE",
    "ADMIN_CLIENT_CERT_CA_FILE",
    "ADMIN_CLIENT_CERT_CRL_FILE",
    "ADMIN_LOGIN_PROVIDER",
    "ADMIN_SESSION_MODE",
    "ADMIN_SESSION_TTL_SECS",
    "ADMIN_SESSION_MAX_ENTRIES",
    "GATEWAY_PUBLIC_URL",
    "AUDIT_LOG_FILE",
    "AUDIT_SQLITE_PATH",
    "AUDIT_SQLITE_RETENTION_DAYS",
    "DISCOVERY_SQLITE_PATH",
    "DISCOVERY_PROJECTOR_LEASE_TTL_MS",
    "DISCOVERY_PROJECTOR_POLL_MS",
    "DISCOVERY_PROJECTOR_BATCH",
    "PRINCIPAL_SQLITE_PATH",
    "CONNECTIONS_SQLITE_PATH",
    "CONNECTION_SECRETS_ROOT",
    "CONNECTION_SECRET_ALIASES",
    "CONNECTION_LOCAL_SECRET_KEYRING",
    "ADMIN_LOGIN_KEYRING",
    "RATE_LIMIT_KEYRING",
    "CONNECTION_VAULT_PROVIDER",
    "CONNECTION_GCP_PROVIDER",
    "CONNECTION_AZURE_PROVIDER",
    "CONNECTION_AWS_PROVIDER",
    "CONNECTION_KUBERNETES_PROVIDER",
    "OPENAPI_SPEC_PATH",
    "POLICY_FILE",
    "TOOLS_FILE",
    "POLICY_HISTORY_SQLITE_PATH",
    "CORS_ALLOW_ORIGINS",
    "TRUSTED_PROXY_CIDRS",
    "JWT_JWKS_URL",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "SERVICE_TOKEN_SQLITE_PATH",
    "CLUSTER_HEARTBEAT_MS",
    "CLUSTER_MEMBER_STALE_MS",
    "CLUSTER_MAINTENANCE_INTERVAL_MS",
    "CLUSTER_MAINTENANCE_LEASE_TTL_MS",
    "READINESS_PROBE_CACHE_MS",
    "CLUSTER_STATUS_EXPOSE_HOSTNAMES",
    "AUDIT_POSTGRES_RETENTION_DAYS",
    "AUTH_PROVIDERS",
    "CSRF_COOKIE_DOMAIN",
    "UPSTREAM_URL",
    "UPSTREAM_ROUTES",
    "MCP_UPSTREAM_SERVERS",
    "UPSTREAM_TIMEOUT_MS",
    "UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS",
    "UPSTREAM_CONNECT_TIMEOUT_MS",
    "EGRESS_ALLOWED_HOSTS",
    "EGRESS_NAT64_PREFIXES",
    "DEPLOYMENT_ID",
    "DATABASE_URL_FILE",
    "DATABASE_TLS_CA_FILE",
];

/// Variables for which an empty value is a value, and one the parser refuses:
/// it is parsed as it stands, without falling back to the default.
const BLANK_IS_REFUSED: &[&str] = &[
    "LISTEN_ADDR",
    "GRPC_MAX_CONCURRENT_STREAMS",
    "GRPC_MAX_METADATA_BYTES",
    "TLS_MIN_VERSION",
    "TLS_HANDSHAKE_TIMEOUT_MS",
    "TLS_MAX_CONCURRENT_HANDSHAKES",
    "CLIENT_CERT_MODE",
    "ADMIN_CLIENT_CERT_MODE",
    "ADMIN_PREFIX",
    "ADMIN_LOGIN_PENDING_TTL_SECS",
    "ADMIN_LOGIN_PENDING_MAX_ENTRIES",
    "ADMIN_LOGIN_PENDING_MAX_PER_IP",
    "AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY",
    "SHUTDOWN_DRAIN_DELAY_MS",
    "SHUTDOWN_TIMEOUT_MS",
    "AUDIT_DRAIN_TIMEOUT_MS",
    "DISCOVERY_ENDPOINT_LIMIT",
    "PAYLOAD_CAPTURE_ENABLED",
    "PAYLOAD_CAPTURE_SAMPLE_RATE",
    "SCHEMA_MISMATCH_SIGNAL_THRESHOLD",
    "ERROR_RATE_SPIKE_SIGNAL_THRESHOLD",
    "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD",
    "VOLUME_OUTLIER_SIGNAL_THRESHOLD",
    "RULE_SUGGESTION_BASELINE_WINDOW_HOURS",
    "MAX_BODY_SIZE",
    "MAX_REQUEST_PATH_BYTES",
    "RATE_LIMIT_READ_RPS",
    "RATE_LIMIT_READ_BURST",
    "RATE_LIMIT_WRITE_RPS",
    "RATE_LIMIT_WRITE_BURST",
    "RATE_LIMIT_MAX_BUCKETS",
    "RATE_LIMIT_BUCKET_TTL_MS",
    "TRUST_PROXY_HEADERS",
    "AUTH_ENABLED",
    "AUTH_MODE",
    "AUTH_COOKIE_NAME",
    "JWT_JWKS_TIMEOUT_MS",
    "JWT_JWKS_MAX_KEY_AGE_SECS",
    "JWT_REQUIRE_JTI",
    "ROLES_CLAIM",
    "SERVICE_TOKEN_CACHE_TTL_MS",
    "TOOL_RUNTIME_QUEUE_DEPTH",
    "TOOL_RUNTIME_GLOBAL_CONCURRENCY",
    "TOOL_RUNTIME_QUEUE_TIMEOUT_MS",
    "TOOL_LEASE_TTL_MS",
    "TOOL_RUNTIME_DEFAULT_TIMEOUT_MS",
    "CSRF_ENABLED",
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "EGRESS_TIMEOUT_MS",
    "EGRESS_RESPONSE_IDLE_TIMEOUT_MS",
    "EGRESS_CONNECT_TIMEOUT_MS",
    "EGRESS_MAX_RESPONSE_BYTES",
    "EGRESS_MAX_REQUEST_BODY_BYTES",
    "EGRESS_DENY_PRIVATE_IPS",
    "STATE_BACKEND",
    "DATABASE_TLS_MODE",
    "DATABASE_POOL_MAX",
    "DATABASE_CONNECT_TIMEOUT_MS",
    "DATABASE_ACQUIRE_TIMEOUT_MS",
    "DATABASE_STATEMENT_TIMEOUT_MS",
    "DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS",
    "DATABASE_LOCK_TIMEOUT_MS",
    "DATABASE_STARTUP_RETRY_LIMIT",
    "DATABASE_AUTO_MIGRATE",
    "DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS",
];

/// Variables for which an empty value replaces a non-empty default list with
/// an empty one.
const BLANK_CLEARS_THE_DEFAULT: &[&str] = &[
    "RBAC_EXEMPT_PATHS",
    "VALIDATION_ALLOWED_CONTENT_TYPES",
    "AUTH_EXEMPT_PATHS",
    "CSRF_EXEMPT_PATHS",
];

fn list_with_a_default<'a>(config: &'a Config, name: &str) -> &'a [String] {
    match name {
        "RBAC_EXEMPT_PATHS" => config.rbac_exempt_paths.as_slice(),
        "VALIDATION_ALLOWED_CONTENT_TYPES" => config.validation_allowed_content_types.as_slice(),
        "AUTH_EXEMPT_PATHS" => config.auth_exempt_paths.as_slice(),
        "CSRF_EXEMPT_PATHS" => config.csrf_exempt_paths.as_slice(),
        _ => panic!("{name} is not a list setting with a default"),
    }
}

/// Absent and empty are different inputs, and the parser has three answers
/// to an empty one. Every input is classified, so a new variable has to say
/// which answer it gives.
#[test]
fn every_input_treats_a_blank_value_by_one_of_three_legacy_rules() {
    let mut classified: Vec<&str> = BLANK_IS_UNSET
        .iter()
        .chain(BLANK_IS_REFUSED)
        .chain(BLANK_CLEARS_THE_DEFAULT)
        .copied()
        .collect();
    classified.sort_unstable();
    let mut inputs = inventory::CONFIG_INPUTS.to_vec();
    inputs.sort_unstable();
    assert_eq!(classified, inputs, "every input is classified exactly once");

    let defaults = accepted(&[]);
    for blank in ["", " \t "] {
        for &name in BLANK_IS_UNSET {
            assert_eq!(accepted(&[(name, blank)]), defaults, "{name}={blank:?}");
        }
        for &name in BLANK_IS_REFUSED {
            let error = refused(&[(name, blank)]);
            assert_eq!(error.problems.len(), 1, "{name}={blank:?}: {error}");
            assert!(
                error.problems[0].starts_with(&format!("{name} ")),
                "{name}={blank:?}: {error}"
            );
            assert_eq!(
                error.diagnostics(),
                [ConfigDiagnostic {
                    variable: Some(name),
                    code: ConfigDiagnosticCode::Empty,
                    message: format!("{name} is set but empty"),
                }],
                "{name}={blank:?}"
            );
        }
        for &name in BLANK_CLEARS_THE_DEFAULT {
            assert!(!list_with_a_default(&defaults, name).is_empty(), "{name}");
            let config = accepted(&[(name, blank)]);
            assert!(
                list_with_a_default(&config, name).is_empty(),
                "{name}={blank:?}"
            );
        }
    }
}

#[test]
fn some_settings_are_trimmed_and_others_are_parsed_exactly_as_given() {
    let config = accepted(&[
        ("ADMIN_LISTEN_ADDR", " 127.0.0.1:9091 "),
        ("ADMIN_PREFIX", " /ops "),
        ("STATE_BACKEND", " sqlite "),
        ("TLS_MIN_VERSION", " 1.3 "),
        ("UPSTREAM_TIMEOUT_MS", " 5000 "),
        ("AUDIT_LOG_FILE", " /var/log/greengateway/audit.jsonl "),
    ]);
    assert_eq!(config.admin_listen_addr, Some(socket("127.0.0.1:9091")));
    assert_eq!(config.admin_prefix, "/ops");
    assert_eq!(config.state_backend, StateBackend::Sqlite);
    assert_eq!(config.tls_min_version, TlsMinVersion::Tls13);
    assert_eq!(config.upstream_timeout_ms, Some(5_000));
    assert_eq!(
        config.audit_log_file.as_deref(),
        Some("/var/log/greengateway/audit.jsonl")
    );

    for (name, value, problem) in [
        (
            "LISTEN_ADDR",
            " 127.0.0.1:9090",
            "LISTEN_ADDR must be a valid socket address, got ' 127.0.0.1:9090': invalid socket address syntax",
        ),
        (
            "LISTEN_ADDR",
            "",
            "LISTEN_ADDR must be a valid socket address, got '': invalid socket address syntax",
        ),
        (
            "AUTH_ENABLED",
            " true",
            "AUTH_ENABLED must be a valid boolean, got ' true': provided string was not `true` or `false`",
        ),
        (
            "AUTH_MODE",
            "observe ",
            "AUTH_MODE must be a valid auth mode, got 'observe ': expected `required` or `observe`",
        ),
        (
            "JWT_JWKS_TIMEOUT_MS",
            " 5000",
            "JWT_JWKS_TIMEOUT_MS must be a valid millisecond duration, got ' 5000': invalid digit found in string",
        ),
        (
            "JWT_JWKS_TIMEOUT_MS",
            "",
            "JWT_JWKS_TIMEOUT_MS must be a valid millisecond duration, got '': cannot parse integer from empty string",
        ),
    ] {
        assert_eq!(
            refused(&[(name, value)]).problems,
            [problem],
            "{name}={value:?}"
        );
    }
}

#[test]
fn auth_providers_take_precedence_over_the_legacy_jwt_settings() {
    let legacy = [
        (
            "JWT_JWKS_URL",
            "https://issuer.example.test/.well-known/jwks.json",
        ),
        ("JWT_ISSUER", "https://issuer.example.test/"),
        ("JWT_AUDIENCE", "gateway"),
        ("ROLES_CLAIM", "groups"),
    ];

    // Alone, the legacy settings become one provider named `legacy`, with the
    // issuer exactly as written: unlike AUTH_PROVIDERS, it is not
    // canonicalized.
    let config = accepted(&legacy);
    assert_eq!(config.auth_providers.len(), 1);
    let provider = &config.auth_providers[0];
    assert_eq!(provider.name, "legacy");
    assert_eq!(provider.provider_type, AuthProviderType::Jwt);
    assert_eq!(
        provider.jwks_url.as_deref(),
        Some("https://issuer.example.test/.well-known/jwks.json")
    );
    assert_eq!(
        provider.issuer.as_deref(),
        Some("https://issuer.example.test/")
    );
    assert_eq!(provider.audience.as_deref(), Some("gateway"));
    assert_eq!(provider.roles_claim, "groups");
    assert_eq!(provider.jwks_timeout_ms, 2_000);
    assert_eq!(provider.jwks_max_key_age_secs, 300);
    assert!(!provider.require_jti);

    // A blank AUTH_PROVIDERS is unset, so the legacy provider stays.
    let mut blank = legacy.to_vec();
    blank.push(("AUTH_PROVIDERS", "  "));
    assert_eq!(accepted(&blank).auth_providers, config.auth_providers);

    // A non-empty AUTH_PROVIDERS replaces the legacy provider entirely:
    // ROLES_CLAIM no longer applies and the issuer is canonicalized. The
    // legacy settings are still parsed, and still validated, but unused.
    let mut both = legacy.to_vec();
    both.push((
        "AUTH_PROVIDERS",
        r#"[{"name":"corp","type":"jwt","issuer":"https://corp.example.test/"}]"#,
    ));
    let config = accepted(&both);
    assert_eq!(config.auth_providers.len(), 1);
    let provider = &config.auth_providers[0];
    assert_eq!(provider.name, "corp");
    assert_eq!(
        provider.issuer.as_deref(),
        Some("https://corp.example.test")
    );
    assert_eq!(provider.jwks_url, None);
    assert_eq!(provider.roles_claim, "roles");
    assert_eq!(config.roles_claim, "groups");
    assert_eq!(
        config.jwt_jwks_url.as_deref(),
        Some("https://issuer.example.test/.well-known/jwks.json")
    );

    // Without a JWKS URL the legacy settings make no provider at all.
    assert!(accepted(&[("JWT_ISSUER", "https://issuer.example.test")])
        .auth_providers
        .is_empty());

    // An AUTH_PROVIDERS that does not parse is refused; it does not fall back
    // to the legacy provider.
    let mut broken = legacy.to_vec();
    broken.push(("AUTH_PROVIDERS", "{}"));
    let error = refused(&broken);
    assert_eq!(error.problems.len(), 1, "{error}");
    assert!(
        error.problems[0]
            .starts_with("AUTH_PROVIDERS must be a JSON array of auth provider objects"),
        "{error}"
    );
}

#[test]
fn exempt_path_defaults_follow_a_custom_admin_prefix_and_explicit_lists_replace_them() {
    let config = accepted(&[("ADMIN_PREFIX", "/ops/gateway")]);
    assert_eq!(config.admin_prefix, "/ops/gateway");
    assert_eq!(config.auth_exempt_paths, with_probes(&["/ops/gateway"]));
    assert_eq!(config.rbac_exempt_paths, with_probes(&["/ops/gateway"]));
    // CSRF exemptions do not follow the admin prefix.
    assert_eq!(config.csrf_exempt_paths, with_probes(&[]));

    // An explicit list replaces its own default and leaves the others alone.
    let config = accepted(&[
        ("ADMIN_PREFIX", "/ops/gateway"),
        ("AUTH_EXEMPT_PATHS", "/status, /ping"),
    ]);
    assert_eq!(config.auth_exempt_paths, strings(&["/status", "/ping"]));
    assert_eq!(config.rbac_exempt_paths, with_probes(&["/ops/gateway"]));
}

#[test]
fn admin_login_and_the_standalone_session_add_their_routes_under_a_custom_prefix() {
    let login = [
        ("AUTH_PROVIDERS", admin_login_provider_document()),
        ("ADMIN_LOGIN_PROVIDER", "primary"),
        ("ADMIN_PREFIX", "/operations"),
    ];

    // The login pair joins the defaults, and an explicit list as well.
    let config = accepted(&login);
    let expected = with_probes(&[
        "/operations",
        "/v1/operations/auth/login",
        "/v1/operations/auth/callback",
    ]);
    assert_eq!(config.auth_exempt_paths, expected);
    assert_eq!(config.rbac_exempt_paths, expected);
    let mut explicit = login.to_vec();
    explicit.push(("AUTH_EXEMPT_PATHS", "/status"));
    assert_eq!(
        accepted(&explicit).auth_exempt_paths,
        strings(&[
            "/status",
            "/v1/operations/auth/login",
            "/v1/operations/auth/callback",
        ])
    );

    // The standalone session adds logout and config, for authentication and
    // authorization alike, and never exempts anything from CSRF.
    let mut session = login.to_vec();
    session.push(("ADMIN_SESSION_MODE", "standalone_memory"));
    let config = accepted(&session);
    let expected = with_probes(&[
        "/operations",
        "/v1/operations/auth/login",
        "/v1/operations/auth/callback",
        "/v1/operations/auth/logout",
        "/v1/operations/auth/config",
    ]);
    assert_eq!(config.auth_exempt_paths, expected);
    assert_eq!(config.rbac_exempt_paths, expected);
    assert_eq!(config.csrf_exempt_paths, with_probes(&[]));
    assert_eq!(
        config.admin_session,
        Some(crate::auth::admin_session::AdminSessionConfig {
            ttl: std::time::Duration::from_secs(3_600),
            max_entries: 1_024,
        })
    );
}

#[test]
fn split_listeners_parse_independently_and_a_shared_address_is_refused() {
    let config = accepted(&[
        ("LISTEN_ADDR", "0.0.0.0:8080"),
        ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
        ("GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
        ("ADMIN_TLS_KEY_FILE", "/run/tls/admin.key"),
    ]);
    assert_eq!(config.listen_addr, socket("0.0.0.0:8080"));
    assert_eq!(config.admin_listen_addr, Some(socket("127.0.0.1:9091")));
    assert_eq!(config.grpc_listen_addr, Some(socket("0.0.0.0:50051")));
    assert_eq!(config.tls_cert_files, None);
    assert_eq!(
        config.admin_tls_cert_files,
        Some(strings(&["/run/tls/admin.crt"]))
    );
    assert_eq!(
        config.admin_tls_key_files,
        Some(strings(&["/run/tls/admin.key"]))
    );
    assert!(config.data_inbound_tls().is_none());
    assert!(config.admin_inbound_tls().is_some());

    for (fixture, problem) in [
        (
            &[
                ("LISTEN_ADDR", "127.0.0.1:9090"),
                ("ADMIN_LISTEN_ADDR", "127.0.0.1:9090"),
            ][..],
            "ADMIN_LISTEN_ADDR must not be the same address as LISTEN_ADDR (both resolved to 127.0.0.1:9090); choose a different port for the admin listener or leave ADMIN_LISTEN_ADDR unset",
        ),
        // The default data listener counts.
        (
            &[("ADMIN_LISTEN_ADDR", "0.0.0.0:8080")][..],
            "ADMIN_LISTEN_ADDR must not be the same address as LISTEN_ADDR (both resolved to 0.0.0.0:8080); choose a different port for the admin listener or leave ADMIN_LISTEN_ADDR unset",
        ),
        (
            &[
                ("LISTEN_ADDR", "127.0.0.1:9090"),
                ("GRPC_LISTEN_ADDR", "127.0.0.1:9090"),
            ][..],
            "GRPC_LISTEN_ADDR must not be the same address as LISTEN_ADDR (both resolved to 127.0.0.1:9090); the gRPC listener serves HTTP/2 and the data listener refuses it",
        ),
        (
            &[
                ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
                ("GRPC_LISTEN_ADDR", "127.0.0.1:9091"),
            ][..],
            "GRPC_LISTEN_ADDR must not be the same address as ADMIN_LISTEN_ADDR; the gRPC listener serves HTTP/2 and the admin listener refuses it",
        ),
        // Once one collision is found the gRPC checks are skipped, so three
        // listeners on one address report only the first.
        (
            &[
                ("LISTEN_ADDR", "127.0.0.1:9090"),
                ("ADMIN_LISTEN_ADDR", "127.0.0.1:9090"),
                ("GRPC_LISTEN_ADDR", "127.0.0.1:9090"),
            ][..],
            "ADMIN_LISTEN_ADDR must not be the same address as LISTEN_ADDR (both resolved to 127.0.0.1:9090); choose a different port for the admin listener or leave ADMIN_LISTEN_ADDR unset",
        ),
        (
            &[
                ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
                ("ADMIN_TLS_KEY_FILE", "/run/tls/admin.key"),
            ][..],
            "ADMIN_TLS_CERT_FILE and ADMIN_TLS_KEY_FILE require ADMIN_LISTEN_ADDR to be set; without a separate admin listener there is nothing for them to terminate",
        ),
    ] {
        assert_eq!(refused(fixture).problems, [problem], "{fixture:?}");
    }
}

#[test]
fn the_public_origin_cors_and_csrf_settings_keep_their_legacy_shapes() {
    // GATEWAY_PUBLIC_URL must use https unless its host is loopback, and is
    // kept exactly as written.
    for url in [
        "https://gateway.example.test/",
        "https://gateway.example.test/base",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ] {
        assert_eq!(
            accepted(&[("GATEWAY_PUBLIC_URL", url)])
                .gateway_public_url
                .as_deref(),
            Some(url)
        );
    }
    for (url, problem) in [
        (
            "http://gateway.example.test",
            "GATEWAY_PUBLIC_URL must use https unless the host is loopback, got 'http://gateway.example.test'",
        ),
        // The shared URL check refuses a fragment first, so the public URL's
        // own fragment message is never reached.
        (
            "https://gateway.example.test/#top",
            "GATEWAY_PUBLIC_URL must not contain URL userinfo or a fragment",
        ),
        (
            "https://operator@gateway.example.test",
            "GATEWAY_PUBLIC_URL must not contain URL userinfo or a fragment",
        ),
        (
            "ftp://gateway.example.test",
            "GATEWAY_PUBLIC_URL must use http or https, got scheme 'ftp'",
        ),
    ] {
        assert_eq!(
            refused(&[("GATEWAY_PUBLIC_URL", url)]).problems,
            [problem],
            "{url}"
        );
    }

    // CORS origins are trimmed and kept as written; a wildcard is refused.
    let config = accepted(&[(
        "CORS_ALLOW_ORIGINS",
        " https://app.example.test , https://admin.example.test ,",
    )]);
    assert_eq!(
        config.cors_allow_origins,
        strings(&["https://app.example.test", "https://admin.example.test"])
    );
    assert_eq!(
        refused(&[("CORS_ALLOW_ORIGINS", "*")]).problems,
        ["CORS_ALLOW_ORIGINS entries must be exact origins; wildcard origin '*' is not allowed with credentialed CORS"]
    );

    // The CSRF header name is lower-cased; cookie names are kept exactly.
    let config = accepted(&[
        ("CSRF_HEADER_NAME", "X-CSRF-Token"),
        ("CSRF_COOKIE_NAME", "__Host-csrf"),
        ("CSRF_COOKIE_DOMAIN", " .example.test "),
        ("AUTH_COOKIE_NAME", "__Host-session"),
    ]);
    assert_eq!(config.csrf_header_name, "x-csrf-token");
    assert_eq!(config.csrf_cookie_name, "__Host-csrf");
    assert_eq!(config.auth_cookie_name, "__Host-session");
    assert_eq!(config.csrf_cookie_domain.as_deref(), Some(".example.test"));
    assert_eq!(
        refused(&[("CSRF_COOKIE_DOMAIN", "example.test:443")]).problems,
        ["CSRF_COOKIE_DOMAIN must be a valid cookie Domain attribute, got 'example.test:443'"]
    );

    // Authentication and CSRF can each be turned off or observed ...
    let config = accepted(&[
        ("AUTH_ENABLED", "false"),
        ("AUTH_MODE", "observe"),
        ("CSRF_ENABLED", "false"),
    ]);
    assert!(!config.auth_enabled);
    assert_eq!(config.auth_mode, AuthMode::Observe);
    assert!(!config.csrf_enabled);
    // ... but the standalone admin session refuses to run without them.
    assert_eq!(
        refused(&[("ADMIN_SESSION_MODE", "standalone_memory")]).problems,
        ["ADMIN_SESSION_MODE=standalone_memory requires ADMIN_LOGIN_PROVIDER, AUTH_ENABLED=true, AUTH_MODE=required and CSRF_ENABLED=true"]
    );
}

#[test]
fn invalid_combinations_are_refused_with_their_legacy_messages() {
    for (fixture, problems) in [
        (
            &[("TLS_CERT_FILE", "/run/tls/tls.crt")][..],
            &["TLS_CERT_FILE is set without TLS_KEY_FILE; set both to terminate TLS on this listener, or neither to serve it in plaintext"][..],
        ),
        (
            &[("PAYLOAD_CAPTURE_ENABLED", "true")][..],
            &["PAYLOAD_CAPTURE_ENABLED=true requires DISCOVERY_SQLITE_PATH to be set so captured request shapes have an explicit SQLite storage destination"][..],
        ),
        (
            &[("CLIENT_CERT_MODE", "required")][..],
            &[
                "CLIENT_CERT_MODE requires TLS_CERT_FILE; a listener that terminates no TLS never sees a client certificate",
                "CLIENT_CERT_MODE requires CLIENT_CERT_CA_FILE; client certificates are verified only against an explicitly configured CA bundle, never the platform trust store",
            ][..],
        ),
        (
            &[("CLIENT_CERT_CA_FILE", "/run/tls/clients.pem")][..],
            &["CLIENT_CERT_CA_FILE is set while CLIENT_CERT_MODE is `off`; set CLIENT_CERT_MODE to `optional` or `required`, or unset CLIENT_CERT_CA_FILE"][..],
        ),
        (
            &[("ADMIN_SESSION_TTL_SECS", "600")][..],
            &["ADMIN_SESSION_TTL_SECS and ADMIN_SESSION_MAX_ENTRIES require ADMIN_SESSION_MODE=standalone_memory"][..],
        ),
    ] {
        assert_eq!(refused(fixture).problems, problems, "{fixture:?}");
    }
}

#[test]
fn every_problem_is_reported_in_one_pass_in_the_order_the_settings_are_read() {
    let error = refused(&[
        ("LISTEN_ADDR", "not-a-socket"),
        ("TRUST_PROXY_HEADERS", "true"),
        ("AUTH_ENABLED", "maybe"),
        ("UPSTREAM_URL", "https://legacy.example.test"),
        (
            "UPSTREAM_ROUTES",
            r#"[{"path_prefix":"/api","upstream_url":"https://api.example.test"}]"#,
        ),
        ("EGRESS_TIMEOUT_MS", "0"),
    ]);
    assert_eq!(
        error.problems,
        [
            "LISTEN_ADDR must be a valid socket address, got 'not-a-socket': invalid socket address syntax",
            "TRUSTED_PROXY_CIDRS must contain at least one CIDR when TRUST_PROXY_HEADERS=true",
            "AUTH_ENABLED must be a valid boolean, got 'maybe': provided string was not `true` or `false`",
            "UPSTREAM_URL and UPSTREAM_ROUTES are mutually exclusive; set one proxy routing source",
            "EGRESS_TIMEOUT_MS must be greater than 0, got '0'; a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout",
        ]
    );
    assert_eq!(
        error.to_string(),
        format!(
            "configuration is invalid:\n- {}",
            error.problems.join("\n- ")
        )
    );
    assert_eq!(
        error.diagnostics(),
        [
            expected_diagnostic("LISTEN_ADDR", ConfigDiagnosticCode::Refused),
            expected_diagnostic("TRUSTED_PROXY_CIDRS", ConfigDiagnosticCode::Unset),
            expected_diagnostic("AUTH_ENABLED", ConfigDiagnosticCode::Refused),
            expected_diagnostic("UPSTREAM_URL", ConfigDiagnosticCode::Refused),
            expected_diagnostic("EGRESS_TIMEOUT_MS", ConfigDiagnosticCode::Refused),
        ]
    );
}

#[test]
fn storage_modes_keep_their_requirements_and_refuse_each_others_material() {
    let config = accepted(&postgres_fixture());
    assert_eq!(config.state_backend, StateBackend::Postgres);
    assert_eq!(config.deployment_id.as_deref(), Some("deploy-prod-eu"));
    assert_eq!(
        config.database.url_file.as_deref(),
        Some("/run/secrets/greengateway/database-url")
    );
    assert_eq!(config.database.tls_mode, DatabaseTlsMode::Verify);
    assert_eq!(config.rate_limit_keyring.len(), 1);
    assert_eq!(config.cluster_heartbeat_ms, 5_000);
    assert_eq!(config.cluster_member_stale_ms, 30_000);
    assert_eq!(config.cluster_maintenance_interval_ms, 60_000);
    assert_eq!(config.cluster_maintenance_lease_ttl_ms, 15_000);
    assert_eq!(config.readiness_probe_cache_ms, 1_000);
    assert_eq!(config.discovery_projector_lease_ttl_ms, 15_000);
    assert_eq!(config.discovery_projector_poll_ms, 250);
    assert_eq!(config.discovery_projector_batch, 500);

    // PostgreSQL alone names everything it is missing, in one pass.
    let error = refused(&[("STATE_BACKEND", "postgres")]);
    assert_eq!(
        error.problems,
        [
            "DEPLOYMENT_ID is required when STATE_BACKEND=postgres; it scopes every authoritative row, lock, lease, and notification of the deployment and is non-secret",
            "DATABASE_URL_FILE is required when STATE_BACKEND=postgres; the PostgreSQL connection string is supplied as a secret file, never as a raw environment variable",
            "RATE_LIMIT_KEYRING is required when STATE_BACKEND=postgres; shared rate-limit buckets are keyed by an HMAC under it",
        ]
    );
    assert_eq!(
        error.diagnostics(),
        [
            expected_diagnostic("DEPLOYMENT_ID", ConfigDiagnosticCode::Unset),
            expected_diagnostic("DATABASE_URL_FILE", ConfigDiagnosticCode::Unset),
            expected_diagnostic("RATE_LIMIT_KEYRING", ConfigDiagnosticCode::Unset),
        ]
    );

    // A local store beside PostgreSQL would be a second authority.
    let mut fixture = postgres_fixture();
    fixture.extend([
        ("POLICY_FILE", "/etc/greengateway/policy.json"),
        ("AUDIT_SQLITE_PATH", "/var/lib/greengateway/audit.sqlite"),
    ]);
    assert_eq!(
        refused(&fixture).problems,
        [
            "POLICY_FILE is set while STATE_BACKEND=postgres; in cluster mode PostgreSQL is the single authority and local stores are rejected (import/bootstrap workflows arrive in a later #241 PR) \u{2014} unset POLICY_FILE",
            "AUDIT_SQLITE_PATH is set while STATE_BACKEND=postgres; in cluster mode PostgreSQL is the single authority and local stores are rejected (import/bootstrap workflows arrive in a later #241 PR) \u{2014} unset AUDIT_SQLITE_PATH",
        ]
    );

    // Cluster material in standalone mode is material nothing reads.
    assert_eq!(
        refused(&[
            ("CLUSTER_HEARTBEAT_MS", "5000"),
            ("DATABASE_URL_FILE", "/run/secrets/greengateway/database-url"),
            ("DEPLOYMENT_ID", "deploy-prod-eu"),
        ])
        .problems,
        [
            "CLUSTER_HEARTBEAT_MS is set while STATE_BACKEND is sqlite; standalone mode has no cluster membership and never reads it",
            "DATABASE_URL_FILE is set while STATE_BACKEND is sqlite; set STATE_BACKEND=postgres to use PostgreSQL, or unset DATABASE_URL_FILE",
            "DEPLOYMENT_ID is set while STATE_BACKEND is sqlite; a deployment ID scopes a cluster-mode deployment and standalone mode never reads it \u{2014} set STATE_BACKEND=postgres or unset DEPLOYMENT_ID",
        ]
    );

    // Standalone stores are taken as written, trimmed, and a retention of
    // zero days means no pruning, the same as none.
    let config = accepted(&[
        ("AUDIT_SQLITE_PATH", " /var/lib/greengateway/audit.sqlite "),
        ("AUDIT_SQLITE_RETENTION_DAYS", "30"),
    ]);
    assert_eq!(
        config.audit_sqlite_path.as_deref(),
        Some("/var/lib/greengateway/audit.sqlite")
    );
    assert_eq!(config.audit_sqlite_retention_days, Some(30));
    assert_eq!(
        accepted(&[("AUDIT_SQLITE_RETENTION_DAYS", "0")]).audit_sqlite_retention_days,
        None
    );
}

#[test]
fn egress_settings_normalize_hosts_and_refuse_ambiguous_values() {
    let config = accepted(&[
        (
            "EGRESS_ALLOWED_HOSTS",
            " API.Example.Test ,hooks.example.test,,",
        ),
        ("EGRESS_DENY_PRIVATE_IPS", "false"),
        ("EGRESS_NAT64_PREFIXES", "64:ff9b:1::/48"),
    ]);
    assert_eq!(
        config.egress_allowed_hosts,
        strings(&["api.example.test", "hooks.example.test"])
    );
    assert!(!config.egress_deny_private_ips);
    assert_eq!(
        config.egress_nat64_prefixes,
        ["64:ff9b:1::/48"
            .parse::<IpNet>()
            .expect("the fixture prefix is valid")]
    );

    for (name, value, problem) in [
        (
            "EGRESS_ALLOWED_HOSTS",
            "api.example.test:443",
            "EGRESS_ALLOWED_HOSTS entries must be hostnames without ports, got 'api.example.test:443'",
        ),
        (
            "EGRESS_NAT64_PREFIXES",
            "64:ff9b::/96",
            "EGRESS_NAT64_PREFIXES entries must not overlap the built-in well-known NAT64 prefix 64:ff9b::/96, got '64:ff9b::/96'",
        ),
        (
            "EGRESS_NAT64_PREFIXES",
            "192.0.2.0/24",
            "EGRESS_NAT64_PREFIXES entries must be IPv6 CIDR prefixes, got '192.0.2.0/24'",
        ),
        (
            "EGRESS_TIMEOUT_MS",
            "0",
            "EGRESS_TIMEOUT_MS must be greater than 0, got '0'; a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout",
        ),
    ] {
        assert_eq!(
            refused(&[(name, value)]).problems,
            [problem],
            "{name}={value:?}"
        );
    }
}

/// A refused environment can skip a read that only a valid value reaches, so
/// the inventory tests' recordings -- every variable unset, and every
/// variable set to a probe most settings refuse -- are repeated here for
/// configurations the parser accepts. Each one requests every inventoried
/// variable and nothing else.
#[test]
fn accepted_configurations_request_every_inventoried_variable_and_nothing_else() {
    let cluster = postgres_fixture();
    let standalone_session = [
        ("AUTH_PROVIDERS", admin_login_provider_document()),
        ("ADMIN_LOGIN_PROVIDER", "primary"),
        ("ADMIN_PREFIX", "/operations"),
        ("ADMIN_SESSION_MODE", "standalone_memory"),
    ];
    let split_listeners = [
        ("LISTEN_ADDR", "0.0.0.0:8080"),
        ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
        ("GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
        ("ADMIN_TLS_KEY_FILE", "/run/tls/admin.key"),
    ];

    let inventoried: BTreeSet<&str> = inventory::CONFIG_INPUTS.iter().copied().collect();
    for fixture in [&cluster[..], &standalone_session[..], &split_listeners[..]] {
        let mut requested = BTreeSet::new();
        let parsed = Config::from_env_vars(|name| {
            requested.insert(name.to_owned());
            fixture_value(fixture, name)
        });
        if let Err(error) = parsed {
            panic!("the fixture should be accepted: {fixture:?}\n{error}");
        }
        let requested: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        assert_eq!(requested, inventoried, "{fixture:?}");
    }
}

#[test]
fn diagnostics_follow_the_problems_one_for_one_and_describe_the_input() {
    let error = refused(&[
        ("STATE_BACKEND", "postgres"),
        ("LISTEN_ADDR", ""),
        ("AUTH_ENABLED", "maybe"),
    ]);
    // The operator-facing report is unchanged by the diagnostics beside it.
    assert_eq!(
        error.problems,
        [
            "LISTEN_ADDR must be a valid socket address, got '': invalid socket address syntax",
            "AUTH_ENABLED must be a valid boolean, got 'maybe': provided string was not `true` or `false`",
            "DEPLOYMENT_ID is required when STATE_BACKEND=postgres; it scopes every authoritative row, lock, lease, and notification of the deployment and is non-secret",
            "DATABASE_URL_FILE is required when STATE_BACKEND=postgres; the PostgreSQL connection string is supplied as a secret file, never as a raw environment variable",
            "RATE_LIMIT_KEYRING is required when STATE_BACKEND=postgres; shared rate-limit buckets are keyed by an HMAC under it",
        ]
    );
    assert_eq!(
        error.diagnostics(),
        [
            ConfigDiagnostic {
                variable: Some("LISTEN_ADDR"),
                code: ConfigDiagnosticCode::Empty,
                message: "LISTEN_ADDR is set but empty".to_owned(),
            },
            ConfigDiagnostic {
                variable: Some("AUTH_ENABLED"),
                code: ConfigDiagnosticCode::Refused,
                message: "AUTH_ENABLED is set to a value that was refused".to_owned(),
            },
            ConfigDiagnostic {
                variable: Some("DEPLOYMENT_ID"),
                code: ConfigDiagnosticCode::Unset,
                message: "DEPLOYMENT_ID is not set".to_owned(),
            },
            ConfigDiagnostic {
                variable: Some("DATABASE_URL_FILE"),
                code: ConfigDiagnosticCode::Unset,
                message: "DATABASE_URL_FILE is not set".to_owned(),
            },
            ConfigDiagnostic {
                variable: Some("RATE_LIMIT_KEYRING"),
                code: ConfigDiagnosticCode::Unset,
                message: "RATE_LIMIT_KEYRING is not set".to_owned(),
            },
        ]
    );
}

/// A problem is attributed to the setting it begins with. The paired
/// admin-session message begins with `ADMIN_SESSION_TTL_SECS` whichever of
/// the two is set, so setting only the other is reported against a variable
/// that is not set.
#[test]
fn a_problem_is_attributed_to_the_setting_it_begins_with() {
    let error = refused(&[("ADMIN_SESSION_MAX_ENTRIES", "10")]);
    assert_eq!(
        error.problems,
        ["ADMIN_SESSION_TTL_SECS and ADMIN_SESSION_MAX_ENTRIES require ADMIN_SESSION_MODE=standalone_memory"]
    );
    assert_eq!(
        error.diagnostics(),
        [expected_diagnostic(
            "ADMIN_SESSION_TTL_SECS",
            ConfigDiagnosticCode::Unset
        )]
    );
}

#[cfg(unix)]
fn non_unicode_value() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;

    std::ffi::OsString::from_vec(vec![b'f', 0x80])
}

#[cfg(windows)]
fn non_unicode_value() -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;

    // An unpaired surrogate: storable, but not Unicode text.
    std::ffi::OsString::from_wide(&[u16::from(b'f'), 0xD800])
}

#[test]
fn a_value_that_is_not_unicode_is_reported_without_its_bytes() {
    for name in ["LISTEN_ADDR", "CONNECTION_SECRET_ALIASES"] {
        let error = Config::from_env_vars(|requested| {
            if requested == name {
                Err(VarError::NotUnicode(non_unicode_value()))
            } else {
                Err(VarError::NotPresent)
            }
        })
        .expect_err("a value that is not Unicode is refused");
        assert_eq!(error.problems.len(), 1, "{error}");
        assert!(
            error.problems[0].starts_with(&format!("{name} must be valid Unicode")),
            "{error}"
        );
        assert_eq!(
            error.diagnostics(),
            [expected_diagnostic(name, ConfigDiagnosticCode::NotUnicode)]
        );
    }
}

/// Every canary below contains this, in lower case.
const CANARY_MARKER: &str = "zqcanary";

/// The diagnostics pair one for one with the problems, every one names an
/// inventoried variable, and none of them carries any part of a canary.
fn assert_diagnostics_are_value_free(error: &ConfigError) {
    assert_eq!(error.diagnostics().len(), error.problems.len());
    let rendered = format!("{:?}", error.diagnostics()).to_ascii_lowercase();
    assert!(
        !rendered.contains(CANARY_MARKER),
        "a diagnostic carries a value: {rendered}"
    );
    for diagnostic in error.diagnostics() {
        assert!(
            diagnostic.variable.is_some(),
            "every problem begins with an inventoried setting: {diagnostic:?}"
        );
    }
}

#[test]
fn no_diagnostic_carries_a_value_even_when_every_input_holds_a_canary() {
    let canaries: Vec<(&str, String)> = inventory::CONFIG_INPUTS
        .iter()
        .enumerate()
        .map(|(index, name)| (*name, format!("{CANARY_MARKER}-{index}-value")))
        .collect();
    let error = Config::from_env_vars(|name| {
        canaries
            .iter()
            .find(|(input, _)| *input == name)
            .map(|(_, canary)| canary.clone())
            .ok_or(VarError::NotPresent)
    })
    .expect_err("a canary in every input is refused");

    // The canaries reached the parser: the operator-facing report quotes some
    // of them, which is what makes their absence from the diagnostics mean
    // something.
    assert!(
        error
            .problems
            .iter()
            .any(|problem| problem.contains(CANARY_MARKER)),
        "{error}"
    );
    assert_diagnostics_are_value_free(&error);
}

#[test]
fn no_diagnostic_carries_a_secret_or_locator_from_a_structured_input() {
    // Each fixture is paired with the start of the problem it exists to
    // provoke, so it is evidence about that rule rather than about whichever
    // refusal it happens to reach.
    for (fixture, refusal) in [
        // A client secret beside a provider type the report quotes back.
        (
            &[(
                "AUTH_PROVIDERS",
                r#"[{"name":"corp","type":"zqcanary","client_secret":"zqcanary"}]"#,
            )][..],
            "AUTH_PROVIDERS[0].type must be 'jwt' or 'cookie_session'",
        ),
        // An environment locator inside an alias the parser refuses.
        (
            &[(
                "CONNECTION_SECRET_ALIASES",
                r#"[{"id":"billing","label":"Billing","source":{"type":"environment","key":"zqcanary"},"unexpected":true}]"#,
            )][..],
            "CONNECTION_SECRET_ALIASES must be a JSON array of operator alias objects",
        ),
        // Key-file and root locators for a keyring standalone mode refuses.
        (
            &[
                ("CONNECTION_SECRETS_ROOT", "/run/secrets/zqcanary"),
                (
                    "RATE_LIMIT_KEYRING",
                    r#"[{"id":"rl-primary","file":"zqcanary","role":"primary"}]"#,
                ),
            ][..],
            "RATE_LIMIT_KEYRING is set while STATE_BACKEND is sqlite",
        ),
        (
            &[
                ("CONNECTION_SECRETS_ROOT", "/run/secrets/zqcanary"),
                (
                    "CONNECTION_LOCAL_SECRET_KEYRING",
                    r#"[{"id":"primary","file":"zqcanary","role":"primary"}]"#,
                ),
            ][..],
            "CONNECTION_LOCAL_SECRET_KEYRING: local secret keyring requires CONNECTIONS_SQLITE_PATH",
        ),
        // The database connection string's locator, in the wrong mode.
        (
            &[("DATABASE_URL_FILE", "/run/secrets/zqcanary")][..],
            "DATABASE_URL_FILE is set while STATE_BACKEND is sqlite",
        ),
        // A private key's locator without its certificate.
        (
            &[("TLS_KEY_FILE", "/run/tls/zqcanary.key")][..],
            "TLS_KEY_FILE is set without TLS_CERT_FILE",
        ),
        // A provider document that does not parse.
        (
            &[("CONNECTION_VAULT_PROVIDER", r#"{"profiles":["zqcanary""#)][..],
            "CONNECTION_VAULT_PROVIDER must be a JSON object with profiles and aliases arrays",
        ),
        // A static header value on a route the parser refuses.
        (
            &[(
                "UPSTREAM_ROUTES",
                r#"[{"upstream_url":"https://api.example.test","add_request_headers":{"x-route-label":"zqcanary"}}]"#,
            )][..],
            "UPSTREAM_ROUTES[0] must set at least one of path_prefix or host",
        ),
    ] {
        let error = refused(fixture);
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.starts_with(refusal)),
            "{fixture:?} was not refused with {refusal:?}:\n{error}"
        );
        assert_diagnostics_are_value_free(&error);
    }

    // The report itself does quote a refused provider type, which is what
    // the diagnostics exist to avoid.
    let error = refused(&[(
        "AUTH_PROVIDERS",
        r#"[{"name":"corp","type":"zqcanary","client_secret":"zqcanary"}]"#,
    )]);
    assert!(
        error
            .problems
            .iter()
            .any(|problem| problem.contains(CANARY_MARKER)),
        "{error}"
    );
}
