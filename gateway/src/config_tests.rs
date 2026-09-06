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
    let config = Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");

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
        "CONNECTIONS_SQLITE_PATH" => Ok("  /var/lib/greengateway/connections.sqlite  ".to_owned()),
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
    let keyring = format!(r#"[{{"id":"{primary_id}","file":"{file_locator}","role":"primary"}}]"#);
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
    assert!(
        message.contains("PAYLOAD_CAPTURE_ENABLED=true requires DISCOVERY_SQLITE_PATH to be set")
    );
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
    assert!(message.contains("PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD must be greater than 0"));
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
            message.contains("RULE_SUGGESTION_BASELINE_WINDOW_HOURS must be between 1 and 876000"),
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
    let config = Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");

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
        "JWT_JWKS_URL" => Ok("  https://issuer.example.test/.well-known/jwks.json  ".to_owned()),
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
                jwks_url: Some("https://secondary.example.test/.well-known/jwks.json".to_owned(),),
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
    assert!(message.contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set client_id"));
    assert!(
        message.contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set client_secret")
    );
    assert!(
        message.contains("ADMIN_LOGIN_PROVIDER provider 'session-provider' must set redirect_uri")
    );
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
    assert!(message.contains("AUTH_PROVIDERS[1].issuer must not use reserved prefix 'provider:'"));
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
        "EGRESS_NAT64_PREFIXES" => {
            Ok("10.0.0.0/8,2001:db8::/72,not-a-cidr,2001:db8:1::/48,2001:db8:1:1::/64".to_owned())
        }
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
    assert!(message.contains("must not overlap the built-in well-known NAT64 prefix 64:ff9b::/96"));
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
    assert!(
        message.contains("MCP_UPSTREAM_SERVERS[2].name duplicates MCP_UPSTREAM_SERVERS[1].name")
    );
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
        "UPSTREAM_ROUTES" => {
            Ok(r#"[{"path_prefix":"/api","upstream_url":"https://api.example.test"}]"#.to_owned())
        }
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
    assert!(message
        .contains("UPSTREAM_ROUTES[0].path_prefix must be a URI path prefix starting with '/'"));
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
    assert!(
        message.contains("UPSTREAM_ROUTES[0].strip_request_headers must not include x-request-id")
    );
    assert!(message
        .contains("UPSTREAM_ROUTES[0].strip_request_headers must be a valid HTTP header name"));
    assert!(
        message.contains("UPSTREAM_ROUTES[0].strip_request_headers must not include 'x-shared'")
    );
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
    assert!(
        message.contains("UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS must be a valid millisecond duration")
    );
    assert!(message.contains("UPSTREAM_CONNECT_TIMEOUT_MS must be a valid millisecond duration"));
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
    assert!(
        message.contains("EGRESS_RESPONSE_IDLE_TIMEOUT_MS must be a valid millisecond duration")
    );
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
fn cluster_membership_settings_have_defaults_floors_and_standalone_rejection() {
    let config = Config::from_env_vars(postgres_mode_vars(&[])).expect("postgres mode config");
    assert_eq!(config.cluster_heartbeat_ms, DEFAULT_CLUSTER_HEARTBEAT_MS);
    assert_eq!(
        config.cluster_member_stale_ms,
        DEFAULT_CLUSTER_MEMBER_STALE_MS
    );
    assert_eq!(
        config.cluster_heartbeat_interval(),
        std::time::Duration::from_millis(DEFAULT_CLUSTER_HEARTBEAT_MS)
    );

    let config = Config::from_env_vars(postgres_mode_vars(&[
        ("CLUSTER_HEARTBEAT_MS", "2000"),
        ("CLUSTER_MEMBER_STALE_MS", "6000"),
    ]))
    .expect("a stale window of three heartbeats is accepted");
    assert_eq!(config.cluster_heartbeat_ms, 2_000);
    assert_eq!(config.cluster_member_stale_ms, 6_000);

    let error = Config::from_env_vars(postgres_mode_vars(&[("CLUSTER_HEARTBEAT_MS", "500")]))
        .expect_err("a heartbeat below the floor must not start");
    assert!(
        error
            .to_string()
            .contains("CLUSTER_HEARTBEAT_MS must be at least 1000 milliseconds"),
        "{error}"
    );
    let error = Config::from_env_vars(postgres_mode_vars(&[
        ("CLUSTER_HEARTBEAT_MS", "5000"),
        ("CLUSTER_MEMBER_STALE_MS", "10000"),
    ]))
    .expect_err("a stale window under three heartbeats must not start");
    assert!(
            error
                .to_string()
                .contains("CLUSTER_MEMBER_STALE_MS must be at least 3 x CLUSTER_HEARTBEAT_MS (15000 milliseconds)"),
            "{error}"
        );
    let error = Config::from_env_vars(postgres_mode_vars(&[("CLUSTER_MEMBER_STALE_MS", "0")]))
        .expect_err("a zero stale window must not start");
    assert!(
        error
            .to_string()
            .contains("CLUSTER_MEMBER_STALE_MS must be greater than 0"),
        "{error}"
    );

    for name in ["CLUSTER_HEARTBEAT_MS", "CLUSTER_MEMBER_STALE_MS"] {
        let error = Config::from_env_vars(|key| {
            if key == name {
                Ok("30000".to_owned())
            } else {
                Err(VarError::NotPresent)
            }
        })
        .expect_err("a cluster membership setting in standalone mode must not start");
        assert!(
            error
                .to_string()
                .contains(&format!("{name} is set while STATE_BACKEND is sqlite")),
            "{error}"
        );
    }
}

/// A blank cluster-only variable is absence, in both modes: a loader
/// that exports `KEY=` (docker compose `env_file`, systemd
/// `EnvironmentFile`) must not turn `.env.example`'s blank lines into
/// a standalone-mode refusal, and blank means the default in postgres
/// mode too.
#[test]
fn blank_cluster_only_variables_are_unset_in_both_modes() {
    let names = [
        "CLUSTER_HEARTBEAT_MS",
        "CLUSTER_MEMBER_STALE_MS",
        "CLUSTER_MAINTENANCE_INTERVAL_MS",
        "CLUSTER_MAINTENANCE_LEASE_TTL_MS",
        "AUDIT_POSTGRES_RETENTION_DAYS",
        "READINESS_PROBE_CACHE_MS",
    ];
    for name in names {
        for blank in ["", "  "] {
            let config = Config::from_env_vars(|key| {
                if key == name {
                    Ok(blank.to_owned())
                } else {
                    Err(VarError::NotPresent)
                }
            })
            .unwrap_or_else(|error| panic!("a blank {name} must boot in standalone mode: {error}"));
            assert_eq!(config.state_backend, StateBackend::Sqlite);
            let config = Config::from_env_vars(postgres_mode_vars(&[(name, blank)]))
                .unwrap_or_else(|error| {
                    panic!("a blank {name} must boot in postgres mode: {error}")
                });
            assert_eq!(config.cluster_heartbeat_ms, DEFAULT_CLUSTER_HEARTBEAT_MS);
            assert_eq!(
                config.cluster_member_stale_ms,
                DEFAULT_CLUSTER_MEMBER_STALE_MS
            );
            assert_eq!(
                config.cluster_maintenance_interval_ms,
                DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS
            );
            assert_eq!(
                config.cluster_maintenance_lease_ttl_ms,
                DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS
            );
            assert_eq!(config.audit_postgres_retention_days, None);
        }
    }
}

/// `.env.example` boots as shipped: every assignment in it, taken
/// verbatim under the file's own `STATE_BACKEND=sqlite` default, is a
/// valid standalone configuration -- the cluster-only lines included.
#[test]
fn the_env_example_boots_verbatim_in_standalone_mode() {
    let example = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.env.example"))
        .expect(".env.example is readable");
    let vars: std::collections::BTreeMap<String, String> = example
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty() && !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.to_owned()))
        .collect();
    for name in [
        "CLUSTER_HEARTBEAT_MS",
        "CLUSTER_MEMBER_STALE_MS",
        "CLUSTER_MAINTENANCE_INTERVAL_MS",
        "CLUSTER_MAINTENANCE_LEASE_TTL_MS",
        "AUDIT_POSTGRES_RETENTION_DAYS",
        "READINESS_PROBE_CACHE_MS",
    ] {
        assert_eq!(
            vars.get(name).map(String::as_str),
            Some(""),
            "{name} ships blank: a value would refuse the file's own sqlite default"
        );
    }
    let config = Config::from_env_vars(|key| vars.get(key).cloned().ok_or(VarError::NotPresent))
        .unwrap_or_else(|error| {
            panic!("a verbatim copy of .env.example must boot in standalone mode: {error}")
        });
    assert_eq!(config.state_backend, StateBackend::Sqlite);
    assert_eq!(config.cluster_heartbeat_ms, DEFAULT_CLUSTER_HEARTBEAT_MS);
    assert_eq!(config.audit_postgres_retention_days, None);
}

#[test]
fn cluster_maintenance_settings_have_defaults_floors_and_standalone_rejection() {
    let config = Config::from_env_vars(postgres_mode_vars(&[])).expect("postgres mode config");
    assert_eq!(
        config.cluster_maintenance_interval_ms,
        DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS
    );
    assert_eq!(
        config.cluster_maintenance_lease_ttl_ms,
        DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS
    );
    assert_eq!(config.audit_postgres_retention_days, None);
    assert_eq!(config.audit_postgres_retention(), None);
    assert_eq!(
        config.cluster_maintenance_interval(),
        std::time::Duration::from_millis(DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS)
    );
    assert_eq!(
        config.cluster_maintenance_lease_ttl(),
        std::time::Duration::from_millis(DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS)
    );

    let config = Config::from_env_vars(postgres_mode_vars(&[
        ("CLUSTER_MAINTENANCE_INTERVAL_MS", "30000"),
        ("CLUSTER_MAINTENANCE_LEASE_TTL_MS", "6000"),
        ("AUDIT_POSTGRES_RETENTION_DAYS", "90"),
    ]))
    .expect("explicit maintenance settings are accepted");
    assert_eq!(config.cluster_maintenance_interval_ms, 30_000);
    assert_eq!(config.cluster_maintenance_lease_ttl_ms, 6_000);
    assert_eq!(config.audit_postgres_retention_days, Some(90));
    assert_eq!(
        config.audit_postgres_retention(),
        Some(std::time::Duration::from_secs(90 * 86_400))
    );

    let config = Config::from_env_vars(postgres_mode_vars(&[(
        "AUDIT_POSTGRES_RETENTION_DAYS",
        "0",
    )]))
    .expect("zero retention disables pruning without aborting startup");
    assert_eq!(config.audit_postgres_retention_days, None);

    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "CLUSTER_MAINTENANCE_INTERVAL_MS",
        "500",
    )]))
    .expect_err("an interval below the floor must not start");
    assert!(
        error
            .to_string()
            .contains("CLUSTER_MAINTENANCE_INTERVAL_MS must be at least 1000 milliseconds"),
        "{error}"
    );
    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "CLUSTER_MAINTENANCE_LEASE_TTL_MS",
        "999",
    )]))
    .expect_err("a lease TTL below the floor must not start");
    assert!(
        error
            .to_string()
            .contains("CLUSTER_MAINTENANCE_LEASE_TTL_MS must be at least 1000 milliseconds"),
        "{error}"
    );
    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "AUDIT_POSTGRES_RETENTION_DAYS",
        "40000",
    )]))
    .expect_err("a retention beyond the representable range must not start");
    assert!(
        error
            .to_string()
            .contains("AUDIT_POSTGRES_RETENTION_DAYS must be at most 36500"),
        "{error}"
    );
    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "AUDIT_POSTGRES_RETENTION_DAYS",
        "forever",
    )]))
    .expect_err("a non-numeric retention must not start");
    assert!(
        error
            .to_string()
            .contains("AUDIT_POSTGRES_RETENTION_DAYS must be a valid day count"),
        "{error}"
    );

    for name in [
        "CLUSTER_MAINTENANCE_INTERVAL_MS",
        "CLUSTER_MAINTENANCE_LEASE_TTL_MS",
        "AUDIT_POSTGRES_RETENTION_DAYS",
    ] {
        let error = Config::from_env_vars(|key| {
            if key == name {
                Ok("30000".to_owned())
            } else {
                Err(VarError::NotPresent)
            }
        })
        .expect_err("a maintenance setting in standalone mode must not start");
        assert!(
            error
                .to_string()
                .contains(&format!("{name} is set while STATE_BACKEND is sqlite")),
            "{error}"
        );
    }
}

/// The readiness probe's cache window (issue #241, PR 14): a default
/// of one second, `0` accepted as "consult the authority on every
/// probe", a ceiling so a readiness answer cannot outlive the probe
/// interval that asked for it, and standalone mode refusing it
/// outright because it consults no shared authority.
#[test]
fn the_readiness_probe_cache_has_a_default_a_ceiling_and_a_standalone_rejection() {
    let config = Config::from_env_vars(postgres_mode_vars(&[])).expect("postgres mode config");
    assert_eq!(
        config.readiness_probe_cache_ms,
        DEFAULT_READINESS_PROBE_CACHE_MS
    );
    assert_eq!(
        config.readiness_probe_cache(),
        std::time::Duration::from_millis(DEFAULT_READINESS_PROBE_CACHE_MS)
    );

    let config = Config::from_env_vars(postgres_mode_vars(&[("READINESS_PROBE_CACHE_MS", "0")]))
        .expect("a zero cache window is a supported setting, not a rejection");
    assert_eq!(config.readiness_probe_cache(), std::time::Duration::ZERO);

    let error = Config::from_env_vars(postgres_mode_vars(&[("READINESS_PROBE_CACHE_MS", "60001")]))
        .expect_err("a cache window past the ceiling must not start");
    assert!(
        error.to_string().contains(&format!(
            "READINESS_PROBE_CACHE_MS must be at most {MAX_READINESS_PROBE_CACHE_MS} milliseconds"
        )),
        "{error}"
    );

    let error = Config::from_env_vars(|key| {
        if key == "READINESS_PROBE_CACHE_MS" {
            Ok("2000".to_owned())
        } else {
            Err(VarError::NotPresent)
        }
    })
    .expect_err("the probe cache in standalone mode must not start");
    assert!(
        error
            .to_string()
            .contains("READINESS_PROBE_CACHE_MS is set while STATE_BACKEND is sqlite"),
        "{error}"
    );
}

/// The hostname opt-in (issue #241, PR 14): off by default, honoured
/// in *both* modes -- unlike the probe's cache window, which is
/// cluster-only -- because standalone serves the same cluster status
/// endpoint and has the same hostname to report. Blank is unset, so
/// `.env.example`'s own line boots.
#[test]
fn the_hostname_opt_in_defaults_off_and_is_honoured_in_both_modes() {
    for vars in [
        postgres_mode_vars(&[]),
        postgres_mode_vars(&[("CLUSTER_STATUS_EXPOSE_HOSTNAMES", "")]),
        postgres_mode_vars(&[("CLUSTER_STATUS_EXPOSE_HOSTNAMES", "  ")]),
    ] {
        let config = Config::from_env_vars(vars).expect("postgres mode config");
        assert!(!config.cluster_status_expose_hostnames);
    }

    let config = Config::from_env_vars(postgres_mode_vars(&[(
        "CLUSTER_STATUS_EXPOSE_HOSTNAMES",
        "true",
    )]))
    .expect("the opt-in is a supported cluster-mode setting");
    assert!(config.cluster_status_expose_hostnames);

    // Standalone accepts it rather than refusing it, because
    // standalone serves `GET /v1{ADMIN_PREFIX}/cluster` too.
    let config = Config::from_env_vars(|key| {
        if key == "CLUSTER_STATUS_EXPOSE_HOSTNAMES" {
            Ok("true".to_owned())
        } else {
            Err(VarError::NotPresent)
        }
    })
    .expect("the opt-in is honoured in standalone mode, not refused");
    assert_eq!(config.state_backend, StateBackend::Sqlite);
    assert!(config.cluster_status_expose_hostnames);

    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "CLUSTER_STATUS_EXPOSE_HOSTNAMES",
        "yes",
    )]))
    .expect_err("a non-boolean must not start");
    assert!(
        error
            .to_string()
            .contains("CLUSTER_STATUS_EXPOSE_HOSTNAMES"),
        "{error}"
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

// --- discovery projector cadence (issue #241, PR 11) ---------------------

#[test]
fn the_discovery_projector_settings_have_defaults_and_accessors() {
    let config = Config::from_env_vars(postgres_mode_vars(&[])).expect("postgres mode config");
    assert_eq!(
        config.discovery_projector_lease_ttl_ms,
        DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS
    );
    assert_eq!(
        config.discovery_projector_poll_ms,
        DEFAULT_DISCOVERY_PROJECTOR_POLL_MS
    );
    assert_eq!(
        config.discovery_projector_batch,
        DEFAULT_DISCOVERY_PROJECTOR_BATCH
    );
    let config = Config::from_env_vars(postgres_mode_vars(&[
        ("DISCOVERY_PROJECTOR_LEASE_TTL_MS", "4000"),
        ("DISCOVERY_PROJECTOR_POLL_MS", "50"),
        ("DISCOVERY_PROJECTOR_BATCH", "5000"),
    ]))
    .expect("values at and above the floors are accepted");
    assert_eq!(
        config.discovery_projector_lease_ttl(),
        std::time::Duration::from_secs(4)
    );
    assert_eq!(
        config.discovery_projector_poll_interval(),
        std::time::Duration::from_millis(50)
    );
    assert_eq!(config.discovery_projector_batch, 5_000);
}

#[test]
fn the_discovery_projector_settings_are_bounded() {
    for (setting, value, expected) in [
        (
            "DISCOVERY_PROJECTOR_LEASE_TTL_MS",
            "999",
            "DISCOVERY_PROJECTOR_LEASE_TTL_MS must be at least 1000 milliseconds",
        ),
        (
            "DISCOVERY_PROJECTOR_POLL_MS",
            "49",
            "DISCOVERY_PROJECTOR_POLL_MS must be at least 50 milliseconds",
        ),
        (
            "DISCOVERY_PROJECTOR_BATCH",
            "0",
            "DISCOVERY_PROJECTOR_BATCH must be between 1 and 5000, got '0'",
        ),
        (
            "DISCOVERY_PROJECTOR_BATCH",
            "5001",
            "DISCOVERY_PROJECTOR_BATCH must be between 1 and 5000, got '5001'",
        ),
        (
            "DISCOVERY_PROJECTOR_POLL_MS",
            "soon",
            "DISCOVERY_PROJECTOR_POLL_MS must be a valid millisecond duration, got 'soon'",
        ),
    ] {
        let error = Config::from_env_vars(postgres_mode_vars(&[(setting, value)]))
            .expect_err("an out-of-range projector setting must not start");
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "expected {expected:?} in: {message}"
        );
        assert_eq!(error.problems.len(), 1, "{message}");
    }
}

/// Standalone mode never starts a projector, so its settings are
/// material nothing reads and are rejected by name, like the keyrings.
#[test]
fn standalone_mode_refuses_the_discovery_projector_settings() {
    for (setting, value) in [
        ("DISCOVERY_PROJECTOR_LEASE_TTL_MS", "15000"),
        ("DISCOVERY_PROJECTOR_POLL_MS", "250"),
        ("DISCOVERY_PROJECTOR_BATCH", "500"),
        // Rejected for being set, not for its value: an invalid value in
        // the wrong mode reports both problems.
        ("DISCOVERY_PROJECTOR_BATCH", "0"),
    ] {
        let error = Config::from_env_vars(|name| {
            if name == setting {
                Ok(value.to_owned())
            } else {
                Err(VarError::NotPresent)
            }
        })
        .expect_err("a projector setting in standalone mode must not start");
        let message = error.to_string();
        assert!(
            message.contains(&format!("{setting} is set while STATE_BACKEND is sqlite")),
            "the rejection must name {setting} and the mode: {message}"
        );
    }
    // Empty is unset, exactly as the keyrings and paths treat it, so a
    // copied .env.example with the variables left blank still starts.
    Config::from_env_vars(|name| match name {
        "DISCOVERY_PROJECTOR_LEASE_TTL_MS"
        | "DISCOVERY_PROJECTOR_POLL_MS"
        | "DISCOVERY_PROJECTOR_BATCH" => Ok(String::new()),
        _ => Err(VarError::NotPresent),
    })
    .expect("blank projector settings are unset");
}

/// The discovery SQLite file is the standalone aggregator's store;
/// cluster mode's discovery is the projector's PostgreSQL tables, so the
/// path is refused like every other local authority.
#[test]
fn postgres_mode_refuses_the_discovery_sqlite_path() {
    let error = Config::from_env_vars(postgres_mode_vars(&[(
        "DISCOVERY_SQLITE_PATH",
        "/var/lib/greengateway/discovery.sqlite3",
    )]))
    .expect_err("a discovery SQLite path in cluster mode must not start");
    let message = error.to_string();
    assert!(
        message.contains("DISCOVERY_SQLITE_PATH is set while STATE_BACKEND=postgres"),
        "{message}"
    );
    assert!(message.contains("unset DISCOVERY_SQLITE_PATH"), "{message}");
}

/// Payload-shape capture has a destination in cluster mode -- the
/// projector's tables -- so it no longer demands the SQLite path that
/// cluster mode rejects.
#[test]
fn postgres_mode_allows_payload_capture_without_a_discovery_sqlite_path() {
    let config = Config::from_env_vars(postgres_mode_vars(&[("PAYLOAD_CAPTURE_ENABLED", "true")]))
        .expect("payload capture in cluster mode needs no local file");
    assert!(config.payload_capture_enabled);
    assert_eq!(config.discovery_sqlite_path, None);

    let error = Config::from_env_vars(|name| match name {
        "PAYLOAD_CAPTURE_ENABLED" => Ok("true".to_owned()),
        _ => Err(VarError::NotPresent),
    })
    .expect_err("standalone payload capture still needs the SQLite path");
    assert!(error
        .to_string()
        .contains("PAYLOAD_CAPTURE_ENABLED=true requires DISCOVERY_SQLITE_PATH to be set"));
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
