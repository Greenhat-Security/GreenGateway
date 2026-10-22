//! The configuration compiler's extracted stages, run on their own (issue
//! #433, PR 2).
//!
//! The parity tests hold `Config::from_env_vars` to its legacy behaviour.
//! These hold the stages it is now built from: that each block asks for its
//! inputs once, in the inventory's order; that the stages, run alone against
//! values, report what the parser reports for those inputs and produce the
//! values it builds its `Config` from; that provenance names a source and
//! never a value; that no plan prints a secret or a secret locator; and that
//! nothing a stage does opens a file or reaches the network.

use std::{collections::BTreeSet, env::VarError, fs, path::Path, time::Duration};

use super::{
    diagnostic::{ConfigDiagnosticCode, ConfigRule, Rules},
    identity::{
        self, AdminSurfaceInputs, AuthenticationInputs, IdentityPlan, ProviderAndCsrfInputs,
        RbacExemptionInputs,
    },
    inventory,
    listeners::{self, ListenerInputs, ListenerPlan},
    proxy::{self, ProxyPlan, RoutingInputs, TrustedProxyInputs},
    stage::{Provenance, SecretLocator, Source},
    Config,
};
use crate::auth::admin_session::AdminSessionStorage;

fn fixture_value(fixture: &[(&str, &str)], name: &str) -> Result<String, VarError> {
    fixture
        .iter()
        .find(|(variable, _)| *variable == name)
        .map(|(_, value)| (*value).to_owned())
        .ok_or(VarError::NotPresent)
}

/// What the extracted stages make of a fixture when they run alone, in the
/// order `from_env_vars` runs them and with nothing between them.
struct Staged {
    listeners: ListenerPlan,
    identity: IdentityPlan,
    proxy: ProxyPlan,
    problems: Vec<String>,
    rules: Rules,
}

impl Staged {
    fn rules(&self) -> Vec<Option<ConfigRule>> {
        (0..self.problems.len())
            .map(|index| self.rules.rule(index))
            .collect()
    }

    fn provenance(&self) -> Vec<Provenance> {
        let mut provenance = self.listeners.provenance.clone();
        provenance.extend_from_slice(&self.identity.provenance);
        provenance.extend_from_slice(&self.proxy.provenance);
        provenance
    }

    fn source_of(&self, setting: &str) -> Source {
        self.provenance()
            .into_iter()
            .find(|provenance| provenance.setting == setting)
            .unwrap_or_else(|| panic!("{setting} has no provenance"))
            .source
    }
}

fn staged(fixture: &[(&str, &str)]) -> Staged {
    let read = |name: &str| fixture_value(fixture, name);
    let policy_file_configured = fixture_value(fixture, "POLICY_FILE").is_ok();
    let mut problems = Vec::new();
    let mut rules = Rules::default();

    let listeners =
        listeners::compile(ListenerInputs::read(read)).report(&mut problems, &mut rules);
    let surface = identity::compile_admin_surface(AdminSurfaceInputs::read(read))
        .report(&mut problems, &mut rules);
    let trusted = proxy::compile_trusted_proxy(TrustedProxyInputs::read(read))
        .report(&mut problems, &mut rules);
    let rbac = identity::compile_rbac_exemptions(RbacExemptionInputs::read(read), &surface)
        .report(&mut problems, &mut rules);
    let authentication =
        identity::compile_authentication(AuthenticationInputs::read(read), &surface)
            .report(&mut problems, &mut rules);
    let identity = identity::compile(
        ProviderAndCsrfInputs::read(read),
        surface,
        rbac,
        authentication,
    )
    .report(&mut problems, &mut rules);
    let proxy = proxy::compile(
        RoutingInputs::read(read),
        trusted,
        &identity,
        policy_file_configured,
    )
    .report(&mut problems, &mut rules);

    Staged {
        listeners,
        identity,
        proxy,
        problems,
        rules,
    }
}

/// Every input the extracted stages read, block by block, in the order they
/// read them.
fn extracted_blocks() -> Vec<Vec<String>> {
    fn recorded(
        read: impl FnOnce(&mut dyn FnMut(&str) -> Result<String, VarError>),
    ) -> Vec<String> {
        let mut names = Vec::new();
        read(&mut |name: &str| {
            names.push(name.to_owned());
            Err(VarError::NotPresent)
        });
        names
    }

    vec![
        recorded(|get| {
            ListenerInputs::read(get);
        }),
        recorded(|get| {
            AdminSurfaceInputs::read(get);
        }),
        recorded(|get| {
            TrustedProxyInputs::read(get);
        }),
        recorded(|get| {
            RbacExemptionInputs::read(get);
        }),
        recorded(|get| {
            AuthenticationInputs::read(get);
        }),
        recorded(|get| {
            ProviderAndCsrfInputs::read(get);
        }),
        recorded(|get| {
            RoutingInputs::read(get);
        }),
    ]
}

/// Every input an extracted stage reads.
pub(super) fn extracted_inputs() -> BTreeSet<String> {
    extracted_blocks().into_iter().flatten().collect()
}

/// An identity provider the admin login accepts, under the `/operations`
/// admin prefix.
const ADMIN_LOGIN_PROVIDER_DOCUMENT: &str = r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/operations/auth/callback"}]"#;

/// A route that delegates the gateway's cookie session upstream.
const COOKIE_SESSION_ROUTE: &str = r#"[{"id":"pm-session","path_prefix":"/api/exponential","upstream_url":"https://pm-backend.example.test","forward_cookie_session":true}]"#;

#[test]
fn each_block_requests_its_inputs_once_and_in_the_inventory_order() {
    let mut seen = BTreeSet::new();
    for block in extracted_blocks() {
        assert!(!block.is_empty());
        let first = inventory::position(&block[0]);
        for (offset, name) in block.iter().enumerate() {
            assert!(seen.insert(name.clone()), "{name} is read twice");
            assert_eq!(
                inventory::CONFIG_INPUTS.get(first + offset).copied(),
                Some(name.as_str()),
                "a block reads a run of the inventory, in its order: {block:?}"
            );
        }
    }
}

#[test]
fn each_plan_records_the_provenance_of_its_blocks_inputs_in_read_order() {
    fn settings(provenance: &[Provenance]) -> Vec<String> {
        provenance
            .iter()
            .map(|provenance| provenance.setting.to_owned())
            .collect()
    }

    let staged = staged(&[]);
    let blocks = extracted_blocks();
    let [listeners, admin_surface, trusted_proxy, rbac, authentication, providers_and_csrf, routing] =
        <[Vec<String>; 7]>::try_from(blocks).expect("seven extracted blocks");
    assert_eq!(settings(&staged.listeners.provenance), listeners);
    assert_eq!(
        settings(&staged.identity.provenance),
        [admin_surface, rbac, authentication, providers_and_csrf].concat()
    );
    assert_eq!(
        settings(&staged.proxy.provenance),
        [trusted_proxy, routing].concat()
    );

    // An empty environment takes every default.
    for provenance in staged.provenance() {
        assert_eq!(provenance.source, Source::Default, "{}", provenance.setting);
    }
}

/// For fixtures that set only extracted inputs, the stages run alone report
/// exactly what `from_env_vars` reports, and an accepted configuration is
/// built from exactly the stages' values.
#[test]
fn the_stages_alone_report_and_build_what_from_env_vars_does() {
    let fixtures: &[&[(&str, &str)]] = &[
        &[],
        &[
            ("LISTEN_ADDR", "0.0.0.0:8080"),
            ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
            ("GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            ("TLS_CERT_FILE", "/run/tls/data.crt,/run/tls/sni.crt"),
            ("TLS_KEY_FILE", "/run/tls/data.key,/run/tls/sni.key"),
            ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
            ("ADMIN_TLS_KEY_FILE", "/run/tls/admin.key"),
            ("CLIENT_CERT_MODE", "required"),
            ("CLIENT_CERT_CA_FILE", "/run/tls/clients.pem"),
            ("CLIENT_CERT_IDENTITY_SOURCE", "spiffe"),
            ("ADMIN_CLIENT_CERT_MODE", "optional"),
            ("ADMIN_CLIENT_CERT_CA_FILE", "/run/tls/admins.pem"),
            ("ADMIN_CLIENT_CERT_CRL_FILE", "/run/tls/admins.crl"),
            ("TLS_MIN_VERSION", "1.3"),
        ],
        &[
            ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
            ("ADMIN_LOGIN_PROVIDER", "primary"),
            ("ADMIN_PREFIX", "/operations"),
            ("ADMIN_SESSION_MODE", "standalone_memory"),
            ("ADMIN_SESSION_IDLE_TIMEOUT_SECS", "900"),
            ("GATEWAY_PUBLIC_URL", "https://management.example.test"),
            ("CSRF_HEADER_NAME", "X-CSRF-Token"),
            ("CSRF_COOKIE_DOMAIN", ".example.test"),
        ],
        &[
            (
                "JWT_JWKS_URL",
                "https://issuer.example.test/.well-known/jwks.json",
            ),
            ("JWT_ISSUER", "https://issuer.example.test/"),
            ("JWT_AUDIENCE", "gateway"),
            ("ROLES_CLAIM", "groups"),
            ("AUTH_EXEMPT_PATHS", ""),
            ("TRUST_PROXY_HEADERS", "true"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.0.2.0/24"),
            ("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE),
            (
                "MCP_UPSTREAM_SERVERS",
                r#"[{"name":"docs","url":"https://mcp.example.test/mcp"}]"#,
            ),
            ("UPSTREAM_TIMEOUT_MS", "5000"),
        ],
        // Refused, with problems from every extracted domain.
        &[
            ("LISTEN_ADDR", "127.0.0.1:9090"),
            ("ADMIN_LISTEN_ADDR", "127.0.0.1:9090"),
            ("GRPC_MAX_CONCURRENT_STREAMS", "0"),
            ("TLS_KEY_FILE", "/run/tls/data.key"),
            ("CLIENT_CERT_IDENTITY_SOURCE", "dns"),
            ("ADMIN_SESSION_TTL_SECS", "600"),
            ("ADMIN_LOGIN_PENDING_TTL_SECS", "0"),
            ("ADMIN_LOGIN_PROVIDER", "missing"),
            ("TRUST_PROXY_HEADERS", "true"),
            ("AUTH_ENABLED", "false"),
            ("CSRF_ENABLED", "maybe"),
            ("UPSTREAM_URL", "https://legacy.example.test"),
            ("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE),
            ("MCP_UPSTREAM_SERVERS", "{}"),
            ("UPSTREAM_CONNECT_TIMEOUT_MS", "0"),
        ],
    ];

    for fixture in fixtures {
        let staged = staged(fixture);
        match Config::from_env_vars(|name| fixture_value(fixture, name)) {
            Ok(config) => {
                assert!(
                    staged.problems.is_empty(),
                    "{fixture:?}: {:?}",
                    staged.problems
                );
                assert_config_is_built_from(&config, &staged);
            }
            Err(error) => {
                assert!(!staged.problems.is_empty(), "{fixture:?}");
                assert_eq!(error.problems(), staged.problems, "{fixture:?}");
                let rules: Vec<Option<ConfigRule>> = error
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| diagnostic.rule)
                    .collect();
                assert_eq!(rules, staged.rules(), "{fixture:?}");
            }
        }
    }
}

fn assert_config_is_built_from(config: &Config, staged: &Staged) {
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
    } = staged.listeners.clone();
    assert_eq!(config.listen_addr, listen_addr);
    assert_eq!(config.admin_listen_addr, admin_listen_addr);
    assert_eq!(config.grpc_listen_addr, grpc_listen_addr);
    assert_eq!(
        config.grpc_max_concurrent_streams,
        grpc_max_concurrent_streams
    );
    assert_eq!(config.grpc_max_metadata_bytes, grpc_max_metadata_bytes);
    let (tls_cert_files, tls_key_files) = data_tls.map(listeners::TlsMaterial::into_files).unzip();
    assert_eq!(config.tls_cert_files, tls_cert_files);
    assert_eq!(config.tls_key_files, tls_key_files);
    let (admin_tls_cert_files, admin_tls_key_files) =
        admin_tls.map(listeners::TlsMaterial::into_files).unzip();
    assert_eq!(config.admin_tls_cert_files, admin_tls_cert_files);
    assert_eq!(config.admin_tls_key_files, admin_tls_key_files);
    assert_eq!(config.tls_min_version, tls_min_version);
    assert_eq!(config.tls_handshake_timeout_ms, tls_handshake_timeout_ms);
    assert_eq!(
        config.tls_max_concurrent_handshakes,
        tls_max_concurrent_handshakes
    );
    assert_eq!(config.client_cert_auth, client_cert_auth);
    assert_eq!(config.admin_client_cert_auth, admin_client_cert_auth);

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
    } = staged.identity.clone();
    assert_eq!(config.admin_prefix, admin_prefix);
    assert_eq!(config.admin_login_provider, admin_login_provider);
    assert_eq!(config.admin_session, admin_session);
    assert_eq!(
        config.admin_login_pending_ttl_secs,
        admin_login_pending_ttl_secs
    );
    assert_eq!(
        config.admin_login_pending_max_entries,
        admin_login_pending_max_entries
    );
    assert_eq!(
        config.admin_login_pending_max_per_ip,
        admin_login_pending_max_per_ip
    );
    assert_eq!(config.gateway_public_url, gateway_public_url);
    assert_eq!(config.rbac_exempt_paths, rbac_exempt_paths);
    assert_eq!(config.auth_enabled, auth_enabled);
    assert_eq!(config.auth_mode, auth_mode);
    assert_eq!(config.auth_cookie_name, auth_cookie_name);
    assert_eq!(config.auth_exempt_paths, auth_exempt_paths);
    assert_eq!(config.auth_providers, auth_providers);
    assert_eq!(config.jwt_jwks_url, jwt_jwks_url);
    assert_eq!(config.jwt_issuer, jwt_issuer);
    assert_eq!(config.jwt_audience, jwt_audience);
    assert_eq!(config.jwt_jwks_timeout_ms, jwt_jwks_timeout_ms);
    assert_eq!(config.jwt_jwks_max_key_age_secs, jwt_jwks_max_key_age_secs);
    assert_eq!(config.jwt_require_jti, jwt_require_jti);
    assert_eq!(config.roles_claim, roles_claim);
    assert_eq!(config.service_token_sqlite_path, service_token_sqlite_path);
    assert_eq!(
        config.service_token_cache_ttl_ms,
        service_token_cache_ttl_ms
    );
    assert_eq!(config.csrf_enabled, csrf_enabled);
    assert_eq!(config.csrf_cookie_name, csrf_cookie_name);
    assert_eq!(config.csrf_header_name, csrf_header_name);
    assert_eq!(config.csrf_cookie_domain, csrf_cookie_domain);
    assert_eq!(config.csrf_exempt_paths, csrf_exempt_paths);

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
    } = staged.proxy.clone();
    assert_eq!(config.trust_proxy_headers, trust_proxy_headers);
    assert_eq!(config.trusted_proxy_cidrs, trusted_proxy_cidrs);
    assert_eq!(config.upstream_url, upstream_url);
    assert_eq!(config.upstream_routes, upstream_routes);
    assert_eq!(config.mcp_upstream_servers, mcp_upstream_servers);
    assert_eq!(config.upstream_timeout_ms, upstream_timeout_ms);
    assert_eq!(
        config.upstream_response_idle_timeout_ms,
        upstream_response_idle_timeout_ms
    );
    assert_eq!(
        config.upstream_connect_timeout_ms,
        upstream_connect_timeout_ms
    );
}

/// The identity stage accepts either session store on its own terms. Whether
/// the state backend can host the store is a storage rule, which the legacy
/// parser still checks once the storage settings are read.
#[test]
fn a_session_stores_backend_is_left_to_the_storage_rules() {
    let fixture = [
        ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
        ("ADMIN_LOGIN_PROVIDER", "primary"),
        ("ADMIN_PREFIX", "/operations"),
        ("ADMIN_SESSION_MODE", "cluster_postgres"),
        ("ADMIN_SESSION_IDLE_TIMEOUT_SECS", "900"),
    ];
    let staged = staged(&fixture);
    assert!(staged.problems.is_empty(), "{:?}", staged.problems);
    let session = staged
        .identity
        .admin_session
        .as_ref()
        .expect("a session store is enabled");
    assert_eq!(session.storage, AdminSessionStorage::ClusterPostgres);
    assert_eq!(session.ttl, Duration::from_secs(3_600));
    assert_eq!(session.idle_timeout, Duration::from_secs(900));
    for route in ["logout", "config"] {
        let path = format!("/v1/operations/auth/{route}");
        assert!(staged.identity.auth_exempt_paths.contains(&path), "{path}");
        assert!(staged.identity.rbac_exempt_paths.contains(&path), "{path}");
    }

    let error = Config::from_env_vars(|name| fixture_value(&fixture, name))
        .expect_err("standalone mode has no PostgreSQL session store");
    assert_eq!(
        error.problems(),
        ["ADMIN_SESSION_MODE=cluster_postgres requires STATE_BACKEND=postgres; standalone mode keeps admin sessions in process memory (standalone_memory)"]
    );
    assert_eq!(error.diagnostics()[0].rule, None);
}

#[test]
fn provenance_says_where_a_value_came_from_and_never_what_it_is() {
    let staged = staged(&[
        ("LISTEN_ADDR", "127.0.0.1:9090"),
        ("ADMIN_LISTEN_ADDR", "  "),
        ("TLS_CERT_FILE", "/run/tls/zqcanary.crt"),
        ("TLS_KEY_FILE", "/run/tls/zqcanary.key"),
        ("ADMIN_PREFIX", "/zqcanary"),
        ("AUTH_EXEMPT_PATHS", ""),
        ("CSRF_EXEMPT_PATHS", " "),
        ("UPSTREAM_URL", "https://zqcanary.example.test"),
    ]);
    assert!(staged.problems.is_empty(), "{:?}", staged.problems);

    for (setting, source) in [
        ("LISTEN_ADDR", Source::Environment),
        // Blank is unset for an optional address ...
        ("ADMIN_LISTEN_ADDR", Source::Default),
        ("TLS_CERT_FILE", Source::Environment),
        ("TLS_KEY_FILE", Source::Environment),
        ("ADMIN_PREFIX", Source::Environment),
        // ... and a value for a list that replaces its default.
        ("AUTH_EXEMPT_PATHS", Source::Environment),
        ("CSRF_EXEMPT_PATHS", Source::Environment),
        ("RBAC_EXEMPT_PATHS", Source::Default),
        ("UPSTREAM_URL", Source::Environment),
        ("UPSTREAM_ROUTES", Source::Default),
        ("AUTH_PROVIDERS", Source::Default),
    ] {
        assert_eq!(staged.source_of(setting), source, "{setting}");
    }
    let rendered = format!("{:?}", staged.provenance()).to_ascii_lowercase();
    assert!(!rendered.contains("zqcanary"), "{rendered}");
}

/// A blank value's provenance agrees with what the parser does with it:
/// where blank is accepted and changes nothing it is the default, and where
/// it changes the configuration it came from the environment.
#[test]
fn a_blank_input_is_attributed_by_what_the_parser_does_with_it() {
    let defaults = Config::from_env_vars(|_| Err(VarError::NotPresent))
        .expect("an empty environment is accepted");
    for name in extracted_inputs() {
        let fixture = [(name.as_str(), " ")];
        let Ok(config) = Config::from_env_vars(|requested| fixture_value(&fixture, requested))
        else {
            // A refused blank builds no plan, so it has no provenance to
            // report.
            continue;
        };
        let expected = if config == defaults {
            Source::Default
        } else {
            Source::Environment
        };
        assert_eq!(staged(&fixture).source_of(&name), expected, "{name}");
    }
}

#[test]
fn no_plan_prints_a_secret_or_a_secret_locator() {
    let staged = staged(&[
        ("TLS_CERT_FILE", "/run/tls/data.crt"),
        ("TLS_KEY_FILE", "/run/secrets/zqcanary-data.key"),
        ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
        ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
        ("ADMIN_TLS_KEY_FILE", "/run/secrets/zqcanary-admin.key"),
        (
            "AUTH_PROVIDERS",
            r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"zqcanary","redirect_uri":"https://management.example.test/v1/admin/auth/callback"}]"#,
        ),
        (
            "UPSTREAM_ROUTES",
            r#"[{"id":"billing","path_prefix":"/billing","upstreams":[{"id":"primary","url":"https://billing.example.test","client_identity_pem_path":"/run/secrets/zqcanary-client.pem"}],"add_request_headers":{"x-route-label":"zqcanary"}}]"#,
        ),
        (
            "MCP_UPSTREAM_SERVERS",
            r#"[{"name":"docs","url":"https://mcp.example.test/mcp?label=zqcanary"}]"#,
        ),
    ]);
    assert!(staged.problems.is_empty(), "{:?}", staged.problems);

    // The values reached the plans ...
    let data_tls = staged
        .listeners
        .data_tls
        .clone()
        .expect("data TLS is paired");
    assert_eq!(data_tls.into_files().1, ["/run/secrets/zqcanary-data.key"]);
    assert_eq!(
        staged.identity.auth_providers[0].client_secret.as_deref(),
        Some("zqcanary")
    );
    assert_eq!(
        staged.proxy.upstream_routes[0]
            .add_request_headers
            .get("x-route-label")
            .map(String::as_str),
        Some("zqcanary")
    );

    // ... and none of them is printed.
    for rendered in [
        format!("{:?}", staged.listeners),
        format!("{:?}", staged.identity),
        format!("{:?}", staged.proxy),
    ] {
        assert!(!rendered.contains("zqcanary"), "{rendered}");
    }
}

/// The stages carry locators and destinations without touching them: files
/// that do not exist and hosts that cannot resolve are accepted, because
/// opening and connecting are activation's work.
#[test]
fn the_stages_carry_locators_and_destinations_without_touching_them() {
    let missing = Path::new("greengateway-433-stage-tests-absent");
    assert!(!missing.exists(), "{} should not exist", missing.display());
    let path = |file: &str| missing.join(file).to_string_lossy().into_owned();
    let (certificate, key, clients, revoked) = (
        path("data.crt"),
        path("data.key"),
        path("clients.pem"),
        path("clients.crl"),
    );
    let staged = staged(&[
        ("TLS_CERT_FILE", &certificate),
        ("TLS_KEY_FILE", &key),
        ("CLIENT_CERT_MODE", "required"),
        ("CLIENT_CERT_CA_FILE", &clients),
        ("CLIENT_CERT_CRL_FILE", &revoked),
        ("CLIENT_CERT_IDENTITY_SOURCE", "dns"),
        // `.invalid` never resolves (RFC 6761).
        (
            "AUTH_PROVIDERS",
            r#"[{"name":"corp","type":"jwt","issuer":"https://issuer.invalid","jwks_url":"https://issuer.invalid/jwks.json"}]"#,
        ),
        ("UPSTREAM_URL", "https://upstream.invalid"),
    ]);
    assert!(staged.problems.is_empty(), "{:?}", staged.problems);
    assert!(!missing.exists());

    let data_tls = staged.listeners.data_tls.expect("data TLS is paired");
    assert_eq!(data_tls.certificate_files, [certificate]);
    assert_eq!(data_tls.private_key_files, [SecretLocator::new(key)]);
    let client_cert_auth = staged
        .listeners
        .client_cert_auth
        .expect("client certificates are required");
    assert_eq!(client_cert_auth.ca_file, clients);
    assert_eq!(client_cert_auth.crl_file, Some(revoked));
    assert_eq!(
        staged.identity.auth_providers[0].jwks_url.as_deref(),
        Some("https://issuer.invalid/jwks.json")
    );
    assert_eq!(
        staged.proxy.upstream_url.as_deref(),
        Some("https://upstream.invalid")
    );
}

/// The configuration modules' code names no file, network, process or store
/// API, and logs only the one warning the inventory documents.
///
/// A scan of the source text outside comments, so it holds what these files
/// call directly; it does not follow a call into another module. The ones the
/// extracted stages reach -- path matching, cookie-token and issuer
/// canonicalization, route and Connection ID shapes, header-name parsing --
/// are functions of their arguments alone.
///
/// The outbound HTTP client is not listed: `scripts/check-egress-only.sh`
/// already refuses it by name anywhere but `gateway/src/egress.rs`, these
/// files included.
#[test]
fn the_configuration_modules_name_no_input_or_output_api() {
    const FORBIDDEN: &[&str] = &[
        "std::fs",
        "fs::",
        "File::",
        "OpenOptions",
        "tokio",
        "hyper",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "lookup_host",
        "to_socket_addrs",
        "std::process",
        "Command::",
        "rusqlite",
        "tokio_postgres",
        "deadpool",
        "sqlx",
    ];
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, logging) in [
        // The audit-retention warning for a `0`-day window.
        ("src/config.rs", 1),
        ("src/config/diagnostic.rs", 0),
        ("src/config/identity.rs", 0),
        ("src/config/listeners.rs", 0),
        ("src/config/proxy.rs", 0),
        ("src/config/stage.rs", 0),
    ] {
        let source = fs::read_to_string(crate_root.join(file))
            .unwrap_or_else(|error| panic!("failed to read {file}: {error}"));
        let code: Vec<&str> = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        for forbidden in FORBIDDEN {
            assert!(
                !code.iter().any(|line| line.contains(forbidden)),
                "{file} names `{forbidden}`; compiling the configuration must not do I/O"
            );
        }
        assert_eq!(
            code.iter()
                .map(|line| line.matches("tracing::").count())
                .sum::<usize>(),
            logging,
            "{file} logs a different number of times than the inventory documents"
        );
    }
}

/// One fixture per rule, and the diagnostic each produces.
fn rule_fixture(rule: ConfigRule) -> (&'static [(&'static str, &'static str)], &'static str) {
    match rule {
        ConfigRule::Value => (&[("LISTEN_ADDR", "not-a-socket")], "LISTEN_ADDR"),
        ConfigRule::AdminListenerCollision => (
            &[("ADMIN_LISTEN_ADDR", "0.0.0.0:8080")],
            "ADMIN_LISTEN_ADDR",
        ),
        ConfigRule::GrpcListenerCollision => {
            (&[("GRPC_LISTEN_ADDR", "0.0.0.0:8080")], "GRPC_LISTEN_ADDR")
        }
        ConfigRule::TlsMaterialUnpaired => {
            (&[("TLS_CERT_FILE", "/run/tls/data.crt")], "TLS_CERT_FILE")
        }
        ConfigRule::AdminTlsWithoutAdminListener => (
            &[
                ("ADMIN_TLS_CERT_FILE", "/run/tls/admin.crt"),
                ("ADMIN_TLS_KEY_FILE", "/run/tls/admin.key"),
            ],
            "ADMIN_TLS_CERT_FILE",
        ),
        ConfigRule::ClientCertificateAuth => (
            &[("CLIENT_CERT_CA_FILE", "/run/tls/clients.pem")],
            "CLIENT_CERT_CA_FILE",
        ),
        ConfigRule::ClientCertIdentitySourceUnused => (
            &[("CLIENT_CERT_IDENTITY_SOURCE", "spiffe")],
            "CLIENT_CERT_IDENTITY_SOURCE",
        ),
        ConfigRule::AdminSessionSettingsWithoutMode => (
            &[("ADMIN_SESSION_MAX_ENTRIES", "10")],
            "ADMIN_SESSION_TTL_SECS",
        ),
        ConfigRule::AdminSessionIdleTimeoutBounds => (
            &[
                ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
                ("ADMIN_LOGIN_PROVIDER", "primary"),
                ("ADMIN_PREFIX", "/operations"),
                ("ADMIN_SESSION_MODE", "standalone_memory"),
                ("ADMIN_SESSION_IDLE_TIMEOUT_SECS", "7200"),
            ],
            "ADMIN_SESSION_IDLE_TIMEOUT_SECS",
        ),
        ConfigRule::AdminLoginProviderUnusable => (
            &[("ADMIN_LOGIN_PROVIDER", "missing")],
            "ADMIN_LOGIN_PROVIDER",
        ),
        ConfigRule::AdminSessionRequirements => (
            &[("ADMIN_SESSION_MODE", "standalone_memory")],
            "ADMIN_SESSION_MODE",
        ),
        ConfigRule::AdminSessionCsrfExemption => (
            &[
                ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
                ("ADMIN_LOGIN_PROVIDER", "primary"),
                ("ADMIN_PREFIX", "/operations"),
                ("ADMIN_SESSION_MODE", "standalone_memory"),
                ("CSRF_EXEMPT_PATHS", "/v1/operations/policy"),
            ],
            "CSRF_EXEMPT_PATHS",
        ),
        ConfigRule::TrustedProxyNetworksRequired => {
            (&[("TRUST_PROXY_HEADERS", "true")], "TRUSTED_PROXY_CIDRS")
        }
        ConfigRule::CookieSessionDelegation => (
            &[
                ("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE),
                ("AUTH_ENABLED", "false"),
            ],
            "UPSTREAM_ROUTES",
        ),
        ConfigRule::UpstreamRoutingSourcesExclusive => (
            &[
                ("UPSTREAM_URL", "https://legacy.example.test"),
                (
                    "UPSTREAM_ROUTES",
                    r#"[{"path_prefix":"/api","upstream_url":"https://api.example.test"}]"#,
                ),
            ],
            "UPSTREAM_URL",
        ),
        ConfigRule::HostRoutesRequirePolicy => (
            &[(
                "UPSTREAM_ROUTES",
                r#"[{"host":"api.example.test","upstream_url":"https://api.example.test"}]"#,
            )],
            "UPSTREAM_ROUTES",
        ),
    }
}

const EVERY_RULE: [ConfigRule; 16] = [
    ConfigRule::Value,
    ConfigRule::AdminListenerCollision,
    ConfigRule::GrpcListenerCollision,
    ConfigRule::TlsMaterialUnpaired,
    ConfigRule::AdminTlsWithoutAdminListener,
    ConfigRule::ClientCertificateAuth,
    ConfigRule::ClientCertIdentitySourceUnused,
    ConfigRule::AdminSessionSettingsWithoutMode,
    ConfigRule::AdminSessionIdleTimeoutBounds,
    ConfigRule::AdminLoginProviderUnusable,
    ConfigRule::AdminSessionRequirements,
    ConfigRule::AdminSessionCsrfExemption,
    ConfigRule::TrustedProxyNetworksRequired,
    ConfigRule::CookieSessionDelegation,
    ConfigRule::UpstreamRoutingSourcesExclusive,
    ConfigRule::HostRoutesRequirePolicy,
];

/// Every rule is reachable, and a refusal under it is reported as a
/// diagnostic naming the rule, the variable its problem begins with and how
/// that variable was set -- and nothing else.
#[test]
fn every_rule_is_reported_by_name_in_the_diagnostics() {
    for rule in EVERY_RULE {
        let (fixture, variable) = rule_fixture(rule);
        let error = Config::from_env_vars(|name| fixture_value(fixture, name))
            .expect_err("each rule fixture is refused");
        assert_eq!(error.diagnostics().len(), 1, "{rule:?}: {error}");
        let diagnostic = &error.diagnostics()[0];
        assert_eq!(diagnostic.rule, Some(rule), "{rule:?}: {error}");
        assert_eq!(diagnostic.variable, Some(variable), "{rule:?}: {error}");
        let code = if fixture_value(fixture, variable).is_ok() {
            ConfigDiagnosticCode::Refused
        } else {
            ConfigDiagnosticCode::Unset
        };
        assert_eq!(diagnostic.code, code, "{rule:?}: {error}");
    }
}
