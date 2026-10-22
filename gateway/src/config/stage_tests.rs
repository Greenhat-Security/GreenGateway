//! The configuration compiler's stages, run on their own (issue #433, PR 2).
//!
//! The parity tests hold `Config::from_env_vars` to its legacy behaviour.
//! These hold the stages it is now built from: that each block asks for its
//! inputs once and together the blocks read the inventory in order; that
//! `from_env_vars` is exactly the compiled plan; that provenance names a
//! source and never a value; that no plan prints a secret or a secret
//! locator; and that nothing a stage does opens a file or reaches the
//! network.

use std::{env::VarError, fs, path::Path, time::Duration};

use super::{
    connections::ConnectionInputs,
    diagnostic::{ConfigDiagnosticCode, ConfigRule, Report},
    egress::EgressInputs,
    identity::{
        AdminSurfaceInputs, AuthenticationInputs, ProviderAndCsrfInputs, RbacExemptionInputs,
    },
    inventory,
    listeners::ListenerInputs,
    plan::{self, ConfigPlan},
    proxy::{RoutingInputs, TrustedProxyInputs},
    runtime::{
        ContentTypeInputs, RequestBoundInputs, ShutdownInputs, SignalInputs, ToolRuntimeInputs,
        ToolTimeoutInputs,
    },
    stage::{Provenance, SecretLocator, Source},
    storage::{
        AuditStoreInputs, ClusterInputs, DiscoveryStoreInputs, DocumentInputs, StateBackendInputs,
    },
    Config, ConfigError, StateBackend,
};
use crate::{
    auth::admin_session::AdminSessionStorage, connections::secret::OperatorSecretAliasSource,
};

fn fixture_value(fixture: &[(&str, &str)], name: &str) -> Result<String, VarError> {
    fixture
        .iter()
        .find(|(variable, _)| *variable == name)
        .map(|(_, value)| (*value).to_owned())
        .ok_or(VarError::NotPresent)
}

/// What the stages make of a fixture: the plan, built even when it is
/// refused, and the report.
fn compiled(fixture: &[(&str, &str)]) -> (ConfigPlan, Report) {
    plan::compile_blocks(|name| fixture_value(fixture, name))
}

fn source_of(plan: &ConfigPlan, setting: &str) -> Source {
    plan.provenance()
        .into_iter()
        .find(|provenance| provenance.setting == setting)
        .unwrap_or_else(|| panic!("{setting} has no provenance"))
        .source
}

/// The plan each block's inputs belong to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Domain {
    Listeners,
    Identity,
    Proxy,
    Storage,
    Connections,
    Egress,
    Runtime,
}

/// Every block, in the order `compile_blocks` reads them, with the inputs it
/// reads, in the order it reads them.
fn blocks() -> Vec<(Domain, Vec<String>)> {
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
        (
            Domain::Listeners,
            recorded(|get| {
                ListenerInputs::read(get);
            }),
        ),
        (
            Domain::Identity,
            recorded(|get| {
                AdminSurfaceInputs::read(get);
            }),
        ),
        (
            Domain::Storage,
            recorded(|get| {
                AuditStoreInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                ShutdownInputs::read(get);
            }),
        ),
        (
            Domain::Storage,
            recorded(|get| {
                DiscoveryStoreInputs::read(get);
            }),
        ),
        (
            Domain::Connections,
            recorded(|get| {
                ConnectionInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                SignalInputs::read(get);
            }),
        ),
        (
            Domain::Storage,
            recorded(|get| {
                DocumentInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                RequestBoundInputs::read(get);
            }),
        ),
        (
            Domain::Proxy,
            recorded(|get| {
                TrustedProxyInputs::read(get);
            }),
        ),
        (
            Domain::Identity,
            recorded(|get| {
                RbacExemptionInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                ContentTypeInputs::read(get);
            }),
        ),
        (
            Domain::Identity,
            recorded(|get| {
                AuthenticationInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                ToolRuntimeInputs::read(get);
            }),
        ),
        (
            Domain::Storage,
            recorded(|get| {
                ClusterInputs::read(get);
            }),
        ),
        (
            Domain::Runtime,
            recorded(|get| {
                ToolTimeoutInputs::read(get);
            }),
        ),
        (
            Domain::Identity,
            recorded(|get| {
                ProviderAndCsrfInputs::read(get);
            }),
        ),
        (
            Domain::Proxy,
            recorded(|get| {
                RoutingInputs::read(get);
            }),
        ),
        (
            Domain::Egress,
            recorded(|get| {
                EgressInputs::read(get);
            }),
        ),
        (
            Domain::Storage,
            recorded(|get| {
                StateBackendInputs::read(get);
            }),
        ),
    ]
}

/// An identity provider the admin login accepts, under the `/operations`
/// admin prefix.
const ADMIN_LOGIN_PROVIDER_DOCUMENT: &str = r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/operations/auth/callback"}]"#;

/// A route that delegates the gateway's cookie session upstream.
const COOKIE_SESSION_ROUTE: &str = r#"[{"id":"pm-session","path_prefix":"/api/exponential","upstream_url":"https://pm-backend.example.test","forward_cookie_session":true}]"#;

/// An operator secret alias read from an environment variable.
const ENVIRONMENT_ALIAS: &str =
    r#"[{"id":"billing","label":"Billing","source":{"type":"environment","key":"BILLING_TOKEN"}}]"#;

/// An operator secret alias read from a file beneath the secrets root.
const FILE_ALIAS: &str =
    r#"[{"id":"billing","label":"Billing","source":{"type":"file","key":"billing-file"}}]"#;

/// A keyring of one primary key.
const KEYRING: &str = r#"[{"id":"primary","file":"local-key","role":"primary"}]"#;

/// A Google Cloud secret provider whose one alias is `billing`.
const GCP_BILLING_PROVIDER: &str = r#"{"profiles":[{"id":"primary","audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider","token_root":"/var/run/secrets/tokens","token_file":"gcp-token"}],"aliases":[{"id":"billing","label":"Billing","profile":"primary","project":"billing-project","secret":"billing-credential"}]}"#;

/// A complete cluster-mode configuration.
const POSTGRES: [(&str, &str); 5] = [
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
];

#[test]
fn each_block_requests_its_inputs_once_and_the_blocks_read_the_inventory_in_order() {
    let blocks = blocks();
    for (domain, names) in &blocks {
        assert!(!names.is_empty(), "{domain:?}");
    }
    let read: Vec<String> = blocks.into_iter().flat_map(|(_, names)| names).collect();
    assert_eq!(
        read,
        inventory::CONFIG_INPUTS,
        "the blocks, in the order they are read, read every inventoried input once and in order"
    );
}

#[test]
fn each_plan_records_the_provenance_of_its_blocks_inputs_in_read_order() {
    fn settings(provenance: &[Provenance]) -> Vec<String> {
        provenance
            .iter()
            .map(|provenance| provenance.setting.to_owned())
            .collect()
    }
    fn read_by(domain: Domain) -> Vec<String> {
        blocks()
            .into_iter()
            .filter(|(owner, _)| *owner == domain)
            .flat_map(|(_, names)| names)
            .collect()
    }

    let (plan, report) = compiled(&[]);
    assert!(report.is_empty(), "{:?}", report.problems());
    for (domain, provenance) in [
        (Domain::Listeners, &plan.listeners.provenance),
        (Domain::Identity, &plan.identity.provenance),
        (Domain::Proxy, &plan.proxy.provenance),
        (Domain::Storage, &plan.storage.provenance),
        (Domain::Connections, &plan.connections.provenance),
        (Domain::Egress, &plan.egress.provenance),
        (Domain::Runtime, &plan.runtime.provenance),
    ] {
        assert_eq!(settings(provenance), read_by(domain), "{domain:?}");
    }

    // Together they describe every input exactly once, and an empty
    // environment takes every default.
    assert_eq!(settings(&plan.provenance()), inventory::CONFIG_INPUTS);
    for provenance in plan.provenance() {
        assert_eq!(provenance.source, Source::Default, "{}", provenance.setting);
    }
}

/// `from_env_vars` is the compiled plan: an accepted configuration is exactly
/// the plan's `Config`, and a refused one reports exactly the stages'
/// problems, each with its rule.
#[test]
fn from_env_vars_builds_the_compiled_plan_and_reports_its_problems() {
    let postgres_session: Vec<(&str, &str)> = POSTGRES
        .into_iter()
        .chain([
            ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
            ("ADMIN_LOGIN_PROVIDER", "primary"),
            ("ADMIN_PREFIX", "/operations"),
            ("ADMIN_SESSION_MODE", "cluster_postgres"),
            ("ADMIN_LOGIN_KEYRING", KEYRING),
            ("CLUSTER_HEARTBEAT_MS", "2000"),
            ("READINESS_PROBE_CACHE_MS", "2500"),
            ("AUDIT_POSTGRES_RETENTION_DAYS", "90"),
            ("DATABASE_POOL_MAX", "32"),
            ("DATABASE_TLS_CA_FILE", "/run/tls/database-ca.pem"),
        ])
        .collect();
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
            ("TLS_MIN_VERSION", "1.3"),
        ],
        &[
            ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
            ("ADMIN_LOGIN_PROVIDER", "primary"),
            ("ADMIN_PREFIX", "/operations"),
            ("ADMIN_SESSION_MODE", "standalone_memory"),
            ("GATEWAY_PUBLIC_URL", "https://management.example.test"),
            ("TRUST_PROXY_HEADERS", "true"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.0.2.0/24"),
            ("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE),
            ("UPSTREAM_TIMEOUT_MS", "5000"),
        ],
        // Standalone stores, Connections and egress.
        &[
            ("AUDIT_LOG_FILE", "/var/log/greengateway/audit.jsonl"),
            ("AUDIT_SQLITE_PATH", "/var/lib/greengateway/audit.sqlite"),
            ("AUDIT_SQLITE_RETENTION_DAYS", "30"),
            (
                "DISCOVERY_SQLITE_PATH",
                "/var/lib/greengateway/discovery.sqlite",
            ),
            ("PAYLOAD_CAPTURE_ENABLED", "true"),
            ("PAYLOAD_CAPTURE_SAMPLE_RATE", "0.25"),
            ("POLICY_FILE", "/etc/greengateway/policy.json"),
            ("TOOLS_FILE", "/etc/greengateway/tools.json"),
            (
                "CONNECTIONS_SQLITE_PATH",
                "/var/lib/greengateway/connections.sqlite",
            ),
            ("CONNECTION_SECRETS_ROOT", "/run/secrets/greengateway"),
            ("CONNECTION_SECRET_ALIASES", FILE_ALIAS),
            ("CONNECTION_LOCAL_SECRET_KEYRING", KEYRING),
            ("RATE_LIMIT_READ_RPS", "12.5"),
            ("VALIDATION_ALLOWED_CONTENT_TYPES", ""),
            ("TOOL_RUNTIME_DEFAULT_TIMEOUT_MS", "45000"),
            (
                "EGRESS_ALLOWED_HOSTS",
                "API.Example.Test, hooks.example.test",
            ),
            ("EGRESS_NAT64_PREFIXES", "64:ff9b:1::/48"),
            ("EGRESS_DENY_PRIVATE_IPS", "false"),
        ],
        &POSTGRES,
        &postgres_session,
        // Refused, with problems from every domain.
        &[
            ("LISTEN_ADDR", "127.0.0.1:9090"),
            ("ADMIN_LISTEN_ADDR", "127.0.0.1:9090"),
            ("ADMIN_SESSION_TTL_SECS", "600"),
            ("AUDIT_SQLITE_RETENTION_DAYS", "36501"),
            ("SHUTDOWN_TIMEOUT_MS", "0"),
            ("DISCOVERY_PROJECTOR_POLL_MS", "10"),
            ("CONNECTION_SECRET_ALIASES", FILE_ALIAS),
            ("PAYLOAD_CAPTURE_ENABLED", "true"),
            ("CORS_ALLOW_ORIGINS", "*"),
            ("TRUST_PROXY_HEADERS", "true"),
            ("TOOL_LEASE_TTL_MS", "10"),
            ("CLUSTER_MEMBER_STALE_MS", "1000"),
            ("UPSTREAM_URL", "https://legacy.example.test"),
            ("UPSTREAM_ROUTES", COOKIE_SESSION_ROUTE),
            ("EGRESS_NAT64_PREFIXES", "192.0.2.0/24"),
            ("DATABASE_AUTO_MIGRATE", "true"),
        ],
        &[
            ("STATE_BACKEND", "postgres"),
            ("ADMIN_SESSION_MODE", "standalone_memory"),
            ("ADMIN_LOGIN_PROVIDER", "primary"),
            ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
            ("ADMIN_PREFIX", "/operations"),
            (
                "POLICY_HISTORY_SQLITE_PATH",
                "/var/lib/greengateway/history.sqlite",
            ),
            (
                "SERVICE_TOKEN_SQLITE_PATH",
                "/var/lib/greengateway/tokens.sqlite",
            ),
            ("CONNECTION_LOCAL_SECRET_KEYRING", KEYRING),
            ("DEPLOYMENT_ID", "-not-a-deployment"),
        ],
    ];

    for fixture in fixtures {
        let (plan, report) = compiled(fixture);
        match Config::from_env_vars(|name| fixture_value(fixture, name)) {
            Ok(config) => {
                assert!(report.is_empty(), "{fixture:?}: {:?}", report.problems());
                assert_eq!(config, plan.into_config(), "{fixture:?}");
            }
            Err(error) => {
                assert!(!report.is_empty(), "{fixture:?}");
                assert_eq!(error.problems(), report.problems(), "{fixture:?}");
                let rules: Vec<ConfigRule> = error
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| diagnostic.rule)
                    .collect();
                assert_eq!(rules, report.rules(), "{fixture:?}");
            }
        }
    }
}

/// The identity stage accepts either session store on its own terms. Whether
/// the state backend can host the store is a storage rule, checked once the
/// backend is read.
#[test]
fn the_storage_stage_pairs_the_admin_session_store_with_the_state_backend() {
    let fixture = [
        ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
        ("ADMIN_LOGIN_PROVIDER", "primary"),
        ("ADMIN_PREFIX", "/operations"),
        ("ADMIN_SESSION_MODE", "cluster_postgres"),
        ("ADMIN_SESSION_IDLE_TIMEOUT_SECS", "900"),
    ];
    let (plan, report) = compiled(&fixture);
    let session = plan
        .identity
        .admin_session
        .as_ref()
        .expect("the identity stage enables the session store");
    assert_eq!(session.storage, AdminSessionStorage::ClusterPostgres);
    assert_eq!(session.ttl, Duration::from_secs(3_600));
    assert_eq!(session.idle_timeout, Duration::from_secs(900));
    for route in ["logout", "config"] {
        let path = format!("/v1/operations/auth/{route}");
        assert!(plan.identity.auth_exempt_paths.contains(&path), "{path}");
        assert!(plan.identity.rbac_exempt_paths.contains(&path), "{path}");
    }
    assert_eq!(plan.storage.state_backend, StateBackend::Sqlite);
    assert_eq!(
        report.problems(),
        ["ADMIN_SESSION_MODE=cluster_postgres requires STATE_BACKEND=postgres; standalone mode keeps admin sessions in process memory (standalone_memory)"]
    );
    assert_eq!(report.rules(), [ConfigRule::AdminSessionStoreBackend]);

    // In cluster mode, with its login keyring, the same store is accepted.
    let cluster: Vec<(&str, &str)> = POSTGRES
        .into_iter()
        .chain(fixture)
        .chain([("ADMIN_LOGIN_KEYRING", KEYRING)])
        .collect();
    let (plan, report) = compiled(&cluster);
    assert!(report.is_empty(), "{:?}", report.problems());
    assert_eq!(plan.storage.state_backend, StateBackend::Postgres);
    assert_eq!(plan.connections.admin_login_keyring.len(), 1);
}

#[test]
fn provenance_says_where_a_value_came_from_and_never_what_it_is() {
    let fixture: Vec<(&str, &str)> = POSTGRES
        .into_iter()
        .chain([
            ("LISTEN_ADDR", "127.0.0.1:9090"),
            ("ADMIN_LISTEN_ADDR", "  "),
            ("TLS_CERT_FILE", "/run/tls/zqcanary.crt"),
            ("TLS_KEY_FILE", "/run/tls/zqcanary.key"),
            ("ADMIN_PREFIX", "/zqcanary"),
            ("AUTH_EXEMPT_PATHS", ""),
            ("CSRF_EXEMPT_PATHS", " "),
            ("VALIDATION_ALLOWED_CONTENT_TYPES", ""),
            ("UPSTREAM_URL", "https://zqcanary.example.test"),
            ("CLUSTER_HEARTBEAT_MS", " "),
            ("CLUSTER_MEMBER_STALE_MS", "60000"),
            ("EGRESS_ALLOWED_HOSTS", "zqcanary.example.test"),
            ("CORS_ALLOW_ORIGINS", "https://zqcanary.example.test"),
            ("DATABASE_URL_FILE", "/run/secrets/zqcanary-database-url"),
        ])
        .collect();
    let (plan, report) = compiled(&fixture);
    assert!(report.is_empty(), "{:?}", report.problems());

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
        ("VALIDATION_ALLOWED_CONTENT_TYPES", Source::Environment),
        ("RBAC_EXEMPT_PATHS", Source::Default),
        ("UPSTREAM_URL", Source::Environment),
        ("UPSTREAM_ROUTES", Source::Default),
        ("AUTH_PROVIDERS", Source::Default),
        // A blank cluster-only setting is absent.
        ("CLUSTER_HEARTBEAT_MS", Source::Default),
        ("CLUSTER_MEMBER_STALE_MS", Source::Environment),
        ("STATE_BACKEND", Source::Environment),
        ("DATABASE_URL_FILE", Source::Environment),
        ("DATABASE_POOL_MAX", Source::Default),
        ("CONNECTION_SECRETS_ROOT", Source::Environment),
        ("CONNECTION_SECRET_ALIASES", Source::Default),
        ("EGRESS_ALLOWED_HOSTS", Source::Environment),
        ("EGRESS_TIMEOUT_MS", Source::Default),
        ("CORS_ALLOW_ORIGINS", Source::Environment),
        ("TOOL_RUNTIME_DEFAULT_TIMEOUT_MS", Source::Default),
    ] {
        assert_eq!(source_of(&plan, setting), source, "{setting}");
    }
    let rendered = format!("{:?}", plan.provenance()).to_ascii_lowercase();
    assert!(!rendered.contains("zqcanary"), "{rendered}");
}

/// A blank value's provenance agrees with what the parser does with it:
/// where blank is accepted and changes nothing it is the default, and where
/// it changes the configuration it came from the environment.
#[test]
fn a_blank_input_is_attributed_by_what_the_parser_does_with_it() {
    let defaults = Config::from_env_vars(|_| Err(VarError::NotPresent))
        .expect("an empty environment is accepted");
    for name in inventory::CONFIG_INPUTS {
        let fixture = [(*name, " ")];
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
        let (plan, _) = compiled(&fixture);
        assert_eq!(source_of(&plan, name), expected, "{name}");
    }
}

/// A standalone configuration whose every secret value and secret locator
/// carries the canary `zqcanary`.
const CANARY_STANDALONE: &[(&str, &str)] = &[
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
    (
        "CONNECTIONS_SQLITE_PATH",
        "/var/lib/greengateway/connections.sqlite",
    ),
    ("CONNECTION_SECRETS_ROOT", "/run/secrets/zqcanary"),
    (
        "CONNECTION_SECRET_ALIASES",
        r#"[{"id":"billing","label":"Billing","source":{"type":"environment","key":"ZQCANARY_TOKEN"}},{"id":"ledger","label":"Ledger","source":{"type":"file","key":"zqcanary-ledger"}}]"#,
    ),
    (
        "CONNECTION_LOCAL_SECRET_KEYRING",
        r#"[{"id":"zqcanary-local","file":"zqcanary-local-key","role":"primary"}]"#,
    ),
    (
        "CONNECTION_GCP_PROVIDER",
        r#"{"profiles":[{"id":"primary","audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider","token_root":"/run/secrets/zqcanary-tokens","token_file":"zqcanary-token"}],"aliases":[{"id":"gcp-ledger","label":"Ledger","profile":"primary","project":"zqcanary-project","secret":"zqcanary-secret"}]}"#,
    ),
];

/// The same for cluster mode: the database URL file, the secrets root and
/// the keyrings.
const CANARY_CLUSTER: &[(&str, &str)] = &[
    ("STATE_BACKEND", "postgres"),
    ("DEPLOYMENT_ID", "deploy-prod-eu"),
    ("DATABASE_URL_FILE", "/run/secrets/zqcanary-database-url"),
    ("CONNECTION_SECRETS_ROOT", "/run/secrets/zqcanary"),
    (
        "RATE_LIMIT_KEYRING",
        r#"[{"id":"zqcanary-rate","file":"zqcanary-rate-key","role":"primary"}]"#,
    ),
    (
        "ADMIN_LOGIN_KEYRING",
        r#"[{"id":"zqcanary-login","file":"zqcanary-login-key","role":"primary"}]"#,
    ),
];

#[test]
fn no_plan_prints_a_secret_or_a_secret_locator() {
    let (standalone, report) = compiled(CANARY_STANDALONE);
    assert!(report.is_empty(), "{:?}", report.problems());
    let (cluster, report) = compiled(CANARY_CLUSTER);
    assert!(report.is_empty(), "{:?}", report.problems());

    // The values reached the plans ...
    let data_tls = standalone
        .listeners
        .data_tls
        .clone()
        .expect("data TLS is paired");
    assert_eq!(data_tls.into_files().1, ["/run/secrets/zqcanary-data.key"]);
    assert_eq!(
        standalone.identity.auth_providers[0]
            .client_secret
            .as_deref(),
        Some("zqcanary")
    );
    assert_eq!(
        standalone.proxy.upstream_routes[0]
            .add_request_headers
            .get("x-route-label")
            .map(String::as_str),
        Some("zqcanary")
    );
    let root = standalone
        .connections
        .connection_secrets_root
        .as_ref()
        .expect("a secrets root is configured");
    assert_eq!(root.as_path(), Path::new("/run/secrets/zqcanary"));
    assert!(matches!(
        &standalone.connections.connection_secret_aliases[0].source,
        OperatorSecretAliasSource::Environment { key } if key == "ZQCANARY_TOKEN"
    ));
    assert_eq!(
        standalone.connections.connection_local_secret_keyring[0].file,
        "zqcanary-local-key"
    );
    assert_eq!(
        standalone.connections.connection_gcp_provider.profiles[0].token_root,
        "/run/secrets/zqcanary-tokens"
    );
    assert_eq!(
        cluster.storage.database.url_file,
        Some(SecretLocator::new(
            "/run/secrets/zqcanary-database-url".to_owned()
        ))
    );
    assert_eq!(
        cluster.connections.rate_limit_keyring[0].file,
        "zqcanary-rate-key"
    );

    // ... and none of them is printed, by any plan or by the whole.
    for plan in [&standalone, &cluster] {
        for rendered in [
            format!("{:?}", plan.listeners),
            format!("{:?}", plan.identity),
            format!("{:?}", plan.proxy),
            format!("{:?}", plan.storage),
            format!("{:?}", plan.connections),
            format!("{:?}", plan.egress),
            format!("{:?}", plan.runtime),
            format!("{:?}", plan.provenance()),
            format!("{plan:?}"),
        ] {
            let rendered = rendered.to_ascii_lowercase();
            assert!(!rendered.contains("zqcanary"), "{rendered}");
        }
    }
}

/// A refusal reports no secret and no locator it was not about, and its
/// diagnostics report none at all.
///
/// `Display` -- the report startup prints, and so `problems` -- is the
/// operator-facing form and quotes the value a problem is about: the gateway
/// is reporting its own environment back to the operator who set it. So the
/// first half refuses an unrelated setting and holds every rendering of the
/// refusal free of the secrets and locators the same configuration carries.
/// The second half refuses the secret inputs themselves and holds the
/// value-free diagnostics to their word.
#[test]
fn a_refusal_reports_no_secret_or_locator() {
    let render = |error: &ConfigError| {
        [
            error.to_string(),
            format!("{error:?}"),
            format!("{:?}", error.diagnostics()),
        ]
        .map(|rendered| rendered.to_ascii_lowercase())
    };
    for canaries in [CANARY_STANDALONE, CANARY_CLUSTER] {
        let fixture = [canaries, &[("LISTEN_ADDR", "not an address")][..]].concat();
        let error = Config::from_env_vars(|name| fixture_value(&fixture, name))
            .expect_err("the listen address is refused");
        assert_eq!(error.problems().len(), 1, "{error}");
        for rendered in render(&error) {
            assert!(!rendered.contains("zqcanary"), "{rendered}");
        }
    }

    for refused in [
        // A private key without its certificate.
        &[("TLS_KEY_FILE", "/run/secrets/zqcanary-data.key")][..],
        // Cluster material in standalone mode.
        &[("DATABASE_URL_FILE", "/run/secrets/zqcanary-database-url")][..],
        // A keyring with no store for it to encrypt, and no secrets root.
        &[(
            "CONNECTION_LOCAL_SECRET_KEYRING",
            r#"[{"id":"primary","file":"zqcanary-local-key","role":"primary"}]"#,
        )][..],
        // A provider with a client secret and no issuer to discover.
        &[(
            "AUTH_PROVIDERS",
            r#"[{"name":"primary","type":"jwt","client_secret":"zqcanary"}]"#,
        )][..],
        // A file alias with no secrets root to read it beneath.
        &[
            (
                "CONNECTIONS_SQLITE_PATH",
                "/var/lib/greengateway/connections.sqlite",
            ),
            (
                "CONNECTION_SECRET_ALIASES",
                r#"[{"id":"billing","label":"Billing","source":{"type":"file","key":"zqcanary-ledger"}}]"#,
            ),
        ][..],
    ] {
        let error = Config::from_env_vars(|name| fixture_value(refused, name))
            .expect_err("the secret input is refused");
        assert!(!error.diagnostics().is_empty());
        let diagnostics = format!("{:?}", error.diagnostics()).to_ascii_lowercase();
        assert!(!diagnostics.contains("zqcanary"), "{diagnostics}");
    }
}

/// The static-configuration fingerprint -- the one digest of the
/// configuration, written to the membership roster and served by the
/// cluster status API -- is the same whatever the secrets are and wherever
/// they are kept, while the plans it is computed from do differ in them.
///
/// A route's upstream TLS material locators are deliberately part of it
/// (`ha::insert_route`: they decide which trust the route carries), so they
/// are held fixed here.
#[test]
fn the_fingerprint_is_the_same_whatever_the_secrets_and_their_locators_are() {
    let configuration = |tag: &str| -> Vec<(&'static str, String)> {
        vec![
            ("STATE_BACKEND", "postgres".to_owned()),
            ("DEPLOYMENT_ID", "deploy-prod-eu".to_owned()),
            ("DATABASE_URL_FILE", format!("/run/{tag}/database-url")),
            ("CONNECTION_SECRETS_ROOT", format!("/run/{tag}")),
            (
                "RATE_LIMIT_KEYRING",
                format!(r#"[{{"id":"rate","file":"{tag}-rate-key","role":"primary"}}]"#),
            ),
            (
                "ADMIN_LOGIN_KEYRING",
                format!(r#"[{{"id":"login","file":"{tag}-login-key","role":"primary"}}]"#),
            ),
            ("TLS_CERT_FILE", "/run/tls/data.crt".to_owned()),
            ("TLS_KEY_FILE", format!("/run/{tag}/data.key")),
            (
                "AUTH_PROVIDERS",
                format!(
                    r#"[{{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"{tag}-client-secret"}}]"#
                ),
            ),
            (
                "UPSTREAM_ROUTES",
                format!(
                    r#"[{{"id":"billing","path_prefix":"/billing","upstream_url":"https://billing.example.test","add_request_headers":{{"x-route-key":"{tag}-header-value"}}}}]"#
                ),
            ),
            (
                "CONNECTION_SECRET_ALIASES",
                format!(
                    r#"[{{"id":"billing","label":"Billing","source":{{"type":"environment","key":"{}_TOKEN"}}}}]"#,
                    tag.to_ascii_uppercase()
                ),
            ),
            (
                "CONNECTION_GCP_PROVIDER",
                format!(
                    r#"{{"profiles":[{{"id":"primary","audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider","token_root":"/run/{tag}-tokens","token_file":"{tag}-token"}}],"aliases":[{{"id":"gcp-ledger","label":"Ledger","profile":"primary","project":"{tag}-project","secret":"{tag}-secret"}}]}}"#
                ),
            ),
        ]
    };
    let compile = |tag: &str| {
        let fixture = configuration(tag);
        let fixture: Vec<(&str, &str)> = fixture
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let (plan, report) = compiled(&fixture);
        assert!(report.is_empty(), "{tag}: {:?}", report.problems());
        plan
    };
    let (first, second) = (compile("zqcanary"), compile("relocated"));
    assert_ne!(first, second, "the plans differ in their secrets");

    let (first, second) = (first.into_config(), second.into_config());
    let fingerprint = crate::ha::static_config_fingerprint(&first);
    assert_eq!(fingerprint, crate::ha::static_config_fingerprint(&second));
    let rendered = format!("{fingerprint} {fingerprint:?}").to_ascii_lowercase();
    assert!(!rendered.contains("zqcanary"), "{rendered}");
}

/// The stages carry locators and destinations without touching them: files
/// and directories that do not exist and hosts that cannot resolve are
/// accepted, because opening and connecting are activation's work.
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
    let (policy, tools, openapi, audit, connections, secrets) = (
        path("policy.json"),
        path("tools.json"),
        path("openapi.json"),
        path("audit.sqlite"),
        path("connections.sqlite"),
        path("secrets"),
    );
    let (plan, report) = compiled(&[
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
        ("POLICY_FILE", &policy),
        ("TOOLS_FILE", &tools),
        ("OPENAPI_SPEC_PATH", &openapi),
        ("AUDIT_SQLITE_PATH", &audit),
        ("CONNECTIONS_SQLITE_PATH", &connections),
        ("CONNECTION_SECRETS_ROOT", &secrets),
        ("CONNECTION_SECRET_ALIASES", FILE_ALIAS),
        ("CONNECTION_LOCAL_SECRET_KEYRING", KEYRING),
        ("EGRESS_ALLOWED_HOSTS", "egress.invalid"),
    ]);
    assert!(report.is_empty(), "{:?}", report.problems());
    assert!(!missing.exists());

    let data_tls = plan.listeners.data_tls.expect("data TLS is paired");
    assert_eq!(data_tls.certificate_files, [certificate]);
    assert_eq!(data_tls.private_key_files, [SecretLocator::new(key)]);
    let client_cert_auth = plan
        .listeners
        .client_cert_auth
        .expect("client certificates are required");
    assert_eq!(client_cert_auth.ca_file, clients);
    assert_eq!(client_cert_auth.crl_file, Some(revoked));
    assert_eq!(
        plan.identity.auth_providers[0].jwks_url.as_deref(),
        Some("https://issuer.invalid/jwks.json")
    );
    assert_eq!(
        plan.proxy.upstream_url.as_deref(),
        Some("https://upstream.invalid")
    );
    assert_eq!(plan.storage.policy_file, Some(policy));
    assert_eq!(plan.storage.tools_file, Some(tools));
    assert_eq!(
        plan.storage.openapi_spec_path.as_deref(),
        Some(Path::new(&openapi))
    );
    assert_eq!(plan.storage.audit_sqlite_path, Some(audit));
    assert_eq!(plan.connections.connections_sqlite_path, Some(connections));
    assert_eq!(
        plan.connections
            .connection_secrets_root
            .as_ref()
            .map(|root| root.as_path()),
        Some(Path::new(&secrets))
    );
    assert_eq!(plan.egress.egress_allowed_hosts, ["egress.invalid"]);

    // Cluster mode's database URL file and CA bundle, and its keyrings'
    // root, are carried the same way.
    let (database_url, database_ca) = (path("database-url"), path("database-ca.pem"));
    let (plan, report) = compiled(&[
        ("STATE_BACKEND", "postgres"),
        ("DEPLOYMENT_ID", "deploy-prod-eu"),
        ("DATABASE_URL_FILE", &database_url),
        ("DATABASE_TLS_CA_FILE", &database_ca),
        ("CONNECTION_SECRETS_ROOT", &secrets),
        ("RATE_LIMIT_KEYRING", KEYRING),
    ]);
    assert!(report.is_empty(), "{:?}", report.problems());
    assert!(!missing.exists());
    assert_eq!(
        plan.storage.database.url_file,
        Some(SecretLocator::new(database_url))
    );
    assert_eq!(plan.storage.database.tls_ca_file, Some(database_ca));
}

/// The configuration modules' code names no file, network, process or store
/// API, and logs only the one warning the inventory documents.
///
/// A scan of the source text outside comments, so it holds what these files
/// call directly; it does not follow a call into another module. The ones the
/// stages reach -- path matching, cookie-token and issuer canonicalization,
/// route and Connection ID shapes, header-name parsing, and the Connections
/// validators that check alias, keyring and provider documents -- are
/// functions of their arguments alone.
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
        "canonicalize",
    ];
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, logging) in [
        // The audit-retention warning for a `0`-day window.
        ("src/config.rs", 1),
        ("src/config/authority_events.rs", 0),
        ("src/config/connections.rs", 0),
        ("src/config/diagnostic.rs", 0),
        ("src/config/egress.rs", 0),
        ("src/config/identity.rs", 0),
        ("src/config/listeners.rs", 0),
        ("src/config/plan.rs", 0),
        ("src/config/proxy.rs", 0),
        ("src/config/runtime.rs", 0),
        ("src/config/stage.rs", 0),
        ("src/config/storage.rs", 0),
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

/// One fixture per rule, and the variable its one diagnostic names.
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
        ConfigRule::SecretsRootRequired => (
            &[("CONNECTION_SECRET_ALIASES", FILE_ALIAS)],
            "CONNECTION_SECRET_ALIASES",
        ),
        ConfigRule::LocalKeyringRequiresConnectionsStore => (
            &[
                ("CONNECTION_SECRETS_ROOT", "/run/secrets/greengateway"),
                ("CONNECTION_LOCAL_SECRET_KEYRING", KEYRING),
            ],
            "CONNECTION_LOCAL_SECRET_KEYRING",
        ),
        ConfigRule::SecretAliasIdReserved => (
            &[
                ("CONNECTION_SECRET_ALIASES", ENVIRONMENT_ALIAS),
                ("CONNECTION_GCP_PROVIDER", GCP_BILLING_PROVIDER),
            ],
            "CONNECTION_GCP_PROVIDER",
        ),
        ConfigRule::ClusterMemberStaleWindow => (
            &[
                POSTGRES[0],
                POSTGRES[1],
                POSTGRES[2],
                POSTGRES[3],
                POSTGRES[4],
                ("CLUSTER_MEMBER_STALE_MS", "10000"),
            ],
            "CLUSTER_MEMBER_STALE_MS",
        ),
        // Every requirement but the deployment ID is met.
        ConfigRule::ClusterModeRequirements => (
            &[POSTGRES[0], POSTGRES[2], POSTGRES[3], POSTGRES[4]],
            "DEPLOYMENT_ID",
        ),
        ConfigRule::LocalAuthorityInClusterMode => (
            &[
                POSTGRES[0],
                POSTGRES[1],
                POSTGRES[2],
                POSTGRES[3],
                POSTGRES[4],
                ("POLICY_FILE", "/etc/greengateway/policy.json"),
            ],
            "POLICY_FILE",
        ),
        ConfigRule::AdminSessionStoreBackend => (
            &[
                ("AUTH_PROVIDERS", ADMIN_LOGIN_PROVIDER_DOCUMENT),
                ("ADMIN_LOGIN_PROVIDER", "primary"),
                ("ADMIN_PREFIX", "/operations"),
                ("ADMIN_SESSION_MODE", "cluster_postgres"),
            ],
            "ADMIN_SESSION_MODE",
        ),
        ConfigRule::ClusterSettingInStandaloneMode => {
            (&[("CLUSTER_HEARTBEAT_MS", "5000")], "CLUSTER_HEARTBEAT_MS")
        }
        ConfigRule::PayloadCaptureDestination => (
            &[("PAYLOAD_CAPTURE_ENABLED", "true")],
            "PAYLOAD_CAPTURE_ENABLED",
        ),
        // A sink with no pseudonym key to key its references under.
        ConfigRule::AuthorityEventDelivery => (
            &[
                POSTGRES[0],
                POSTGRES[1],
                POSTGRES[2],
                POSTGRES[3],
                POSTGRES[4],
                ("AUTHORITY_EVENT_SINK", "log"),
            ],
            "AUTHORITY_PSEUDONYM_KEY_ALIAS",
        ),
    }
}

const EVERY_RULE: [ConfigRule; 26] = [
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
    ConfigRule::SecretsRootRequired,
    ConfigRule::LocalKeyringRequiresConnectionsStore,
    ConfigRule::SecretAliasIdReserved,
    ConfigRule::ClusterMemberStaleWindow,
    ConfigRule::ClusterModeRequirements,
    ConfigRule::LocalAuthorityInClusterMode,
    ConfigRule::AdminSessionStoreBackend,
    ConfigRule::ClusterSettingInStandaloneMode,
    ConfigRule::PayloadCaptureDestination,
    ConfigRule::AuthorityEventDelivery,
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
        assert_eq!(diagnostic.rule, rule, "{rule:?}: {error}");
        assert_eq!(diagnostic.variable, Some(variable), "{rule:?}: {error}");
        let code = if fixture_value(fixture, variable).is_ok() {
            ConfigDiagnosticCode::Refused
        } else {
            ConfigDiagnosticCode::Unset
        };
        assert_eq!(diagnostic.code, code, "{rule:?}: {error}");
    }
}
