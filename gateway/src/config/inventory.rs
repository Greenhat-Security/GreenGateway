//! The gateway's environment inputs, and how far this module can vouch for
//! them (issue #433, PR 1).
//!
//! [`CONFIG_INPUTS`] is the complete list of variables `Config::from_env_vars`
//! asks its reader for, in the order it first asks. It is the input boundary
//! the configuration compiler of issue #433 starts from, and the tests below
//! hold it to the parser exactly: they run `from_env_vars` against a reader
//! that records every name requested, so a variable added to the parser and
//! not to this list fails them, and so does a variable left here after the
//! parser stops reading it.
//!
//! Apart from the lookups, the parser has one side effect: a retention of `0`
//! days for either audit store is accepted as "no pruning" and logged as a
//! warning. It logs nothing else, opens no file and calls no store, secret
//! provider or network, which a source scan in the stage tests holds the
//! configuration modules to. Every input is read in a block, and the parse and
//! validate stages are given that block's values rather than a reader; see
//! `stage` and `plan`.
//!
//! Every variable is requested exactly once, and none conditionally.
//! `DISCOVERY_PROJECTOR_LEASE_TTL_MS`, `DISCOVERY_PROJECTOR_POLL_MS` and
//! `DISCOVERY_PROJECTOR_BATCH` used to be requested twice, once to learn
//! whether they were set and once to parse them; the check and the parse now
//! share the one value requested. `ADMIN_SESSION_IDLE_TIMEOUT_SECS` and
//! `ADMIN_SESSION_MAX_ENTRIES` used to be skipped when `ADMIN_SESSION_MODE`
//! enabled no session store and `ADMIN_SESSION_TTL_SECS` was set, because the
//! check that read them short-circuited. The admin surface's inputs are now
//! requested together, before any of them is parsed, and that check reads
//! what was requested.
//!
//! The gateway's own source also reads the environment outside the parser.
//! The test-only `ENVIRONMENT_READS` table lists every file under
//! `gateway/src` that calls a `std::env` variable reader, what it reads and
//! how many times; its test scans the source so the table cannot fall
//! behind. That scan is the edge of what this module holds complete: it sees
//! the reads written in `gateway/src`, and nothing a dependency does.
//!
//! Dependencies read the environment too, and one of those reads decides
//! trust: on Linux, `SSL_CERT_FILE` and `SSL_CERT_DIR` choose the platform
//! trust anchors of the egress and PostgreSQL TLS verifiers. The test-only
//! `DEPENDENCY_READS` table records the reads found by reading the sources of
//! the dependencies the gateway calls into. It is a record, not a scan: a
//! dependency update can add a read without failing anything, and the
//! variables the Rust runtime reads for itself (`RUST_BACKTRACE`,
//! `RUST_MIN_STACK`) or that code compiled from C reads (the C library's
//! resolver, the bundled SQLite) are not listed at all.

use super::authority_events::{
    AUTHORITY_EVENT_FILE, AUTHORITY_EVENT_JOURNAL_CAPACITY, AUTHORITY_EVENT_RETENTION_HOURS,
    AUTHORITY_EVENT_SINK, AUTHORITY_EVIDENCE_DURABILITY, AUTHORITY_PSEUDONYM_KEY_ALIAS,
    AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
};
use super::{
    ADMIN_CLIENT_CERT_CA_FILE, ADMIN_CLIENT_CERT_CRL_FILE, ADMIN_CLIENT_CERT_MODE,
    ADMIN_LISTEN_ADDR, ADMIN_LOGIN_KEYRING, ADMIN_LOGIN_PENDING_MAX_ENTRIES,
    ADMIN_LOGIN_PENDING_MAX_PER_IP, ADMIN_LOGIN_PENDING_TTL_SECS, ADMIN_LOGIN_PROVIDER,
    ADMIN_PREFIX, ADMIN_SESSION_IDLE_TIMEOUT_SECS, ADMIN_SESSION_MAX_ENTRIES, ADMIN_SESSION_MODE,
    ADMIN_SESSION_TTL_SECS, ADMIN_TLS_CERT_FILE, ADMIN_TLS_KEY_FILE, AUDIT_DRAIN_TIMEOUT_MS,
    AUDIT_DURABILITY, AUDIT_DURABILITY_TIMEOUT_MS, AUDIT_LOG_FILE, AUDIT_POSTGRES_RETENTION_DAYS,
    AUDIT_SQLITE_PATH, AUDIT_SQLITE_RETENTION_DAYS, AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
    AUTH_COOKIE_NAME, AUTH_ENABLED, AUTH_EXEMPT_PATHS, AUTH_MODE, AUTH_PROVIDERS,
    CLIENT_CERT_CA_FILE, CLIENT_CERT_CRL_FILE, CLIENT_CERT_IDENTITY_SOURCE, CLIENT_CERT_MODE,
    CLUSTER_HEARTBEAT_MS, CLUSTER_MAINTENANCE_INTERVAL_MS, CLUSTER_MAINTENANCE_LEASE_TTL_MS,
    CLUSTER_MEMBER_STALE_MS, CLUSTER_STATUS_EXPOSE_HOSTNAMES, CONNECTIONS_SQLITE_PATH,
    CONNECTION_AWS_PROVIDER, CONNECTION_AZURE_PROVIDER, CONNECTION_GCP_PROVIDER,
    CONNECTION_KUBERNETES_PROVIDER, CONNECTION_LOCAL_SECRET_KEYRING, CONNECTION_SECRETS_ROOT,
    CONNECTION_SECRET_ALIASES, CONNECTION_VAULT_PROVIDER, CORS_ALLOW_ORIGINS, CSRF_COOKIE_DOMAIN,
    CSRF_COOKIE_NAME, CSRF_ENABLED, CSRF_EXEMPT_PATHS, CSRF_HEADER_NAME,
    DATABASE_ACQUIRE_TIMEOUT_MS, DATABASE_AUTO_MIGRATE, DATABASE_CONNECT_TIMEOUT_MS,
    DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS, DATABASE_LOCK_TIMEOUT_MS,
    DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, DATABASE_POOL_MAX, DATABASE_STARTUP_RETRY_LIMIT,
    DATABASE_STATEMENT_TIMEOUT_MS, DATABASE_TLS_CA_FILE, DATABASE_TLS_MODE, DATABASE_URL_FILE,
    DEPLOYMENT_ID, DISCOVERY_ENDPOINT_LIMIT, DISCOVERY_PROJECTOR_BATCH,
    DISCOVERY_PROJECTOR_LEASE_TTL_MS, DISCOVERY_PROJECTOR_POLL_MS, DISCOVERY_SQLITE_PATH,
    EGRESS_ALLOWED_HOSTS, EGRESS_CONNECT_TIMEOUT_MS, EGRESS_DENY_PRIVATE_IPS,
    EGRESS_MAX_REQUEST_BODY_BYTES, EGRESS_MAX_RESPONSE_BYTES, EGRESS_NAT64_PREFIXES,
    EGRESS_RESPONSE_IDLE_TIMEOUT_MS, EGRESS_TIMEOUT_MS, ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
    GATEWAY_PUBLIC_URL, GRPC_LISTEN_ADDR, GRPC_MAX_CONCURRENT_STREAMS, GRPC_MAX_METADATA_BYTES,
    JWT_AUDIENCE, JWT_ISSUER, JWT_JWKS_MAX_KEY_AGE_SECS, JWT_JWKS_TIMEOUT_MS, JWT_JWKS_URL,
    JWT_REQUIRE_JTI, LISTEN_ADDR, MAX_BODY_SIZE, MAX_REQUEST_PATH_BYTES, MCP_UPSTREAM_SERVERS,
    OPENAPI_SPEC_PATH, PAYLOAD_CAPTURE_ENABLED, PAYLOAD_CAPTURE_SAMPLE_RATE, POLICY_FILE,
    POLICY_HISTORY_SQLITE_PATH, PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD, PRINCIPAL_SQLITE_PATH,
    RATE_LIMIT_BUCKET_TTL_MS, RATE_LIMIT_KEYRING, RATE_LIMIT_MAX_BUCKETS, RATE_LIMIT_READ_BURST,
    RATE_LIMIT_READ_RPS, RATE_LIMIT_WRITE_BURST, RATE_LIMIT_WRITE_RPS, RBAC_EXEMPT_PATHS,
    READINESS_PROBE_CACHE_MS, ROLES_CLAIM, RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
    SCHEMA_MISMATCH_SIGNAL_THRESHOLD, SERVICE_TOKEN_CACHE_TTL_MS, SERVICE_TOKEN_SQLITE_PATH,
    SHUTDOWN_DRAIN_DELAY_MS, SHUTDOWN_TIMEOUT_MS, STATE_BACKEND, TLS_CERT_FILE,
    TLS_HANDSHAKE_TIMEOUT_MS, TLS_KEY_FILE, TLS_MAX_CONCURRENT_HANDSHAKES, TLS_MIN_VERSION,
    TOOLS_FILE, TOOL_LEASE_TTL_MS, TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
    TOOL_RUNTIME_GLOBAL_CONCURRENCY, TOOL_RUNTIME_QUEUE_DEPTH, TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    TRUSTED_PROXY_CIDRS, TRUST_PROXY_HEADERS, UPSTREAM_CONNECT_TIMEOUT_MS,
    UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS, UPSTREAM_ROUTES, UPSTREAM_TIMEOUT_MS, UPSTREAM_URL,
    VALIDATION_ALLOWED_CONTENT_TYPES, VOLUME_OUTLIER_SIGNAL_THRESHOLD,
};

/// Every variable `Config::from_env_vars` requests, in the order it first
/// requests each one.
///
/// Grouped as the parser reads them, which is not always by domain: the
/// keyrings sit with the Connections settings because they share
/// `CONNECTION_SECRETS_ROOT`, and the cluster settings sit with the tool
/// runtime because they are parsed next to the execution lease.
pub(crate) const CONFIG_INPUTS: &[&str] = &[
    // Listeners, inbound TLS and client certificates.
    LISTEN_ADDR,
    ADMIN_LISTEN_ADDR,
    GRPC_LISTEN_ADDR,
    GRPC_MAX_CONCURRENT_STREAMS,
    GRPC_MAX_METADATA_BYTES,
    TLS_CERT_FILE,
    TLS_KEY_FILE,
    ADMIN_TLS_CERT_FILE,
    ADMIN_TLS_KEY_FILE,
    TLS_MIN_VERSION,
    TLS_HANDSHAKE_TIMEOUT_MS,
    TLS_MAX_CONCURRENT_HANDSHAKES,
    CLIENT_CERT_IDENTITY_SOURCE,
    CLIENT_CERT_MODE,
    ADMIN_CLIENT_CERT_MODE,
    CLIENT_CERT_CA_FILE,
    CLIENT_CERT_CRL_FILE,
    ADMIN_CLIENT_CERT_CA_FILE,
    ADMIN_CLIENT_CERT_CRL_FILE,
    // The admin surface, its login and the public origin.
    ADMIN_PREFIX,
    ADMIN_LOGIN_PROVIDER,
    ADMIN_SESSION_MODE,
    ADMIN_SESSION_TTL_SECS,
    ADMIN_SESSION_IDLE_TIMEOUT_SECS,
    ADMIN_SESSION_MAX_ENTRIES,
    ADMIN_LOGIN_PENDING_TTL_SECS,
    ADMIN_LOGIN_PENDING_MAX_ENTRIES,
    ADMIN_LOGIN_PENDING_MAX_PER_IP,
    GATEWAY_PUBLIC_URL,
    // Audit and shutdown.
    AUDIT_LOG_FILE,
    AUDIT_SQLITE_PATH,
    AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
    AUDIT_SQLITE_RETENTION_DAYS,
    SHUTDOWN_DRAIN_DELAY_MS,
    SHUTDOWN_TIMEOUT_MS,
    AUDIT_DRAIN_TIMEOUT_MS,
    AUDIT_DURABILITY,
    AUDIT_DURABILITY_TIMEOUT_MS,
    // Discovery storage, the cluster projector and the principal directory.
    DISCOVERY_SQLITE_PATH,
    DISCOVERY_ENDPOINT_LIMIT,
    DISCOVERY_PROJECTOR_LEASE_TTL_MS,
    DISCOVERY_PROJECTOR_POLL_MS,
    DISCOVERY_PROJECTOR_BATCH,
    PRINCIPAL_SQLITE_PATH,
    // Connections, secret providers and keyrings.
    CONNECTIONS_SQLITE_PATH,
    CONNECTION_SECRETS_ROOT,
    CONNECTION_SECRET_ALIASES,
    CONNECTION_LOCAL_SECRET_KEYRING,
    ADMIN_LOGIN_KEYRING,
    RATE_LIMIT_KEYRING,
    CONNECTION_VAULT_PROVIDER,
    CONNECTION_GCP_PROVIDER,
    CONNECTION_AZURE_PROVIDER,
    CONNECTION_AWS_PROVIDER,
    CONNECTION_KUBERNETES_PROVIDER,
    // Payload capture and discovery signals.
    PAYLOAD_CAPTURE_ENABLED,
    PAYLOAD_CAPTURE_SAMPLE_RATE,
    SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
    ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
    PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
    VOLUME_OUTLIER_SIGNAL_THRESHOLD,
    RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
    // Documents and their local stores.
    OPENAPI_SPEC_PATH,
    POLICY_FILE,
    TOOLS_FILE,
    POLICY_HISTORY_SQLITE_PATH,
    // Request bounds, rate limits and proxy trust.
    CORS_ALLOW_ORIGINS,
    MAX_BODY_SIZE,
    MAX_REQUEST_PATH_BYTES,
    RATE_LIMIT_READ_RPS,
    RATE_LIMIT_READ_BURST,
    RATE_LIMIT_WRITE_RPS,
    RATE_LIMIT_WRITE_BURST,
    RATE_LIMIT_MAX_BUCKETS,
    RATE_LIMIT_BUCKET_TTL_MS,
    TRUST_PROXY_HEADERS,
    TRUSTED_PROXY_CIDRS,
    RBAC_EXEMPT_PATHS,
    VALIDATION_ALLOWED_CONTENT_TYPES,
    // Authentication and the legacy single JWT provider.
    AUTH_ENABLED,
    AUTH_MODE,
    AUTH_COOKIE_NAME,
    AUTH_EXEMPT_PATHS,
    JWT_JWKS_URL,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_JWKS_TIMEOUT_MS,
    JWT_JWKS_MAX_KEY_AGE_SECS,
    JWT_REQUIRE_JTI,
    ROLES_CLAIM,
    SERVICE_TOKEN_SQLITE_PATH,
    SERVICE_TOKEN_CACHE_TTL_MS,
    // The tool runtime and cluster coordination.
    TOOL_RUNTIME_QUEUE_DEPTH,
    TOOL_RUNTIME_GLOBAL_CONCURRENCY,
    TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    TOOL_LEASE_TTL_MS,
    CLUSTER_HEARTBEAT_MS,
    CLUSTER_MEMBER_STALE_MS,
    CLUSTER_MAINTENANCE_INTERVAL_MS,
    CLUSTER_MAINTENANCE_LEASE_TTL_MS,
    READINESS_PROBE_CACHE_MS,
    CLUSTER_STATUS_EXPOSE_HOSTNAMES,
    AUDIT_POSTGRES_RETENTION_DAYS,
    TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
    // Auth providers and CSRF.
    AUTH_PROVIDERS,
    CSRF_ENABLED,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRF_COOKIE_DOMAIN,
    CSRF_EXEMPT_PATHS,
    // Upstream routing.
    UPSTREAM_URL,
    UPSTREAM_ROUTES,
    MCP_UPSTREAM_SERVERS,
    UPSTREAM_TIMEOUT_MS,
    UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
    UPSTREAM_CONNECT_TIMEOUT_MS,
    // Egress.
    EGRESS_ALLOWED_HOSTS,
    EGRESS_TIMEOUT_MS,
    EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
    EGRESS_CONNECT_TIMEOUT_MS,
    EGRESS_MAX_RESPONSE_BYTES,
    EGRESS_MAX_REQUEST_BODY_BYTES,
    EGRESS_NAT64_PREFIXES,
    EGRESS_DENY_PRIVATE_IPS,
    // The shared-state backend and PostgreSQL.
    STATE_BACKEND,
    DEPLOYMENT_ID,
    DATABASE_URL_FILE,
    DATABASE_TLS_MODE,
    DATABASE_TLS_CA_FILE,
    DATABASE_POOL_MAX,
    DATABASE_CONNECT_TIMEOUT_MS,
    DATABASE_ACQUIRE_TIMEOUT_MS,
    DATABASE_STATEMENT_TIMEOUT_MS,
    DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    DATABASE_LOCK_TIMEOUT_MS,
    DATABASE_STARTUP_RETRY_LIMIT,
    DATABASE_AUTO_MIGRATE,
    DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
    // Required authority evidence, and authority-event delivery (cluster
    // mode only).
    AUTHORITY_EVIDENCE_DURABILITY,
    AUTHORITY_EVENT_SINK,
    AUTHORITY_EVENT_FILE,
    AUTHORITY_PSEUDONYM_KEY_ALIAS,
    AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
    AUTHORITY_EVENT_JOURNAL_CAPACITY,
    AUTHORITY_EVENT_RETENTION_HOURS,
];

/// The inventory's own spelling of `name`, or `None` when `from_env_vars`
/// never requests it.
pub(crate) fn config_input(name: &str) -> Option<&'static str> {
    CONFIG_INPUTS.iter().copied().find(|input| *input == name)
}

/// Where `name` comes in the order `from_env_vars` first requests its
/// inputs. A name it never requests sorts after all of them, so a problem
/// placed after one is still reported, last, rather than dropped.
pub(super) fn position(name: &str) -> usize {
    CONFIG_INPUTS
        .iter()
        .position(|input| *input == name)
        .unwrap_or(CONFIG_INPUTS.len())
}

/// Who an environment read serves.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadPurpose {
    /// The running gateway reads it.
    Gateway,
    /// Only test code reads it, to find harness resources such as a
    /// disposable database. A deployment never sets it.
    TestHarness,
}

/// Which variables an environment read names.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum ReadNames {
    /// [`CONFIG_INPUTS`], through `Config::from_env`.
    ConfigInputs,
    /// Exactly these, written in the source.
    Fixed(&'static [&'static str]),
    /// Whatever the operator names in this configuration input. Operator
    /// secret aliases of the `environment` kind name the variable holding the
    /// secret, and it is read when a Connection credential is resolved.
    ///
    /// The name is any well-formed variable name, so an alias can name a
    /// configuration input, or a variable a dependency reads, and that
    /// variable then has a second reader. Nothing here refuses that yet; the
    /// configuration compiler is where the rule belongs.
    NamedBy(&'static str),
}

/// One source file that reads the process environment.
#[cfg(test)]
struct EnvironmentRead {
    /// Relative to the crate root, with forward slashes.
    file: &'static str,
    names: ReadNames,
    purpose: ReadPurpose,
    /// How many times the file names a `std::env` variable reader, so a read
    /// added to a file that already has one changes the table too.
    reads: usize,
}

/// Every file under `gateway/src` that calls a `std::env` variable reader.
///
/// Within the gateway's own source, `Config::from_env` is the parser's only
/// window onto the process, and the other reads written for the running
/// gateway are the two rows below it. This is all the scan below can see: a
/// read inside a dependency, the standard library included, is in no file
/// here and is recorded in [`DEPENDENCY_READS`] instead. The test-harness
/// reads are kept here too, because a disposable-database locator is still an
/// environment input, and listing it is what lets the scan hold this table to
/// the source.
#[cfg(test)]
const ENVIRONMENT_READS: &[EnvironmentRead] = &[
    EnvironmentRead {
        file: "src/config.rs",
        names: ReadNames::ConfigInputs,
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    // This replica's hostname for the cluster status API, read once at
    // startup and only when `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`.
    EnvironmentRead {
        file: "src/admin_identity.rs",
        names: ReadNames::Fixed(&["HOSTNAME", "COMPUTERNAME"]),
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/connections/secret.rs",
        names: ReadNames::NamedBy(CONNECTION_SECRET_ALIASES),
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/admin_observability_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 2,
    },
    EnvironmentRead {
        file: "src/admin_policy_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/admin_tools_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/connections/pg_store_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/import/tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/contract_tests.rs",
        names: ReadNames::Fixed(&[
            "GATEWAY_TEST_POSTGRES_URL_FILE",
            "GATEWAY_TEST_POSTGRES_BENCHMARK_ROWS",
        ]),
        purpose: ReadPurpose::TestHarness,
        reads: 2,
    },
    EnvironmentRead {
        file: "src/storage/migrations.rs",
        names: ReadNames::Fixed(&[
            "GATEWAY_TEST_POSTGRES_URL_FILE",
            "GATEWAY_TEST_POSTGRES_NODDL_URL_FILE",
        ]),
        purpose: ReadPurpose::TestHarness,
        reads: 2,
    },
    EnvironmentRead {
        file: "src/storage/postgres.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/postgres_session.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
];

/// One environment read made inside a dependency the gateway calls into.
#[cfg(test)]
struct DependencyRead {
    /// The package whose source calls the `std::env` reader, as `Cargo.lock`
    /// names it, or `std` for the standard library.
    reader: &'static str,
    names: &'static [&'static str],
    /// The gateway calls that reach the read: each source file, relative to
    /// the crate root, and the call as that file spells it.
    reached_from: &'static [(&'static str, &'static str)],
}

/// The environment reads found inside dependencies, by reading their sources
/// at the versions `Cargo.lock` pins.
///
/// Nothing scans for these, so the table records what was found rather than
/// promising nothing else is read; the module documentation says what it
/// leaves out. Its test holds each row to the gateway call that reaches it
/// and to the lock file, so a row whose call or package goes away fails
/// instead of lingering.
#[cfg(test)]
const DEPENDENCY_READS: &[DependencyRead] = &[
    // The platform trust anchors of the egress and PostgreSQL TLS verifiers,
    // read each time one is built. On Linux, `rustls-platform-verifier`
    // loads them through `rustls_native_certs::load_native_certs`, and
    // either variable, when set, replaces the system's certificate
    // locations; a configured CA bundle is still added on top. Other
    // platforms ask the operating system instead and read neither.
    DependencyRead {
        reader: "rustls-native-certs",
        names: &["SSL_CERT_FILE", "SSL_CERT_DIR"],
        reached_from: &[
            (
                "src/egress/tls.rs",
                "rustls_platform_verifier::Verifier::new",
            ),
            (
                "src/storage/postgres.rs",
                "rustls_platform_verifier::Verifier::new",
            ),
        ],
    },
    // The worker thread count of the runtime `main` starts. A value that is
    // not a positive integer panics before the gateway runs.
    DependencyRead {
        reader: "tokio",
        names: &["TOKIO_WORKER_THREADS"],
        reached_from: &[("src/main.rs", "#[tokio::main]")],
    },
    // Whether log lines carry ANSI colour codes: any non-empty value turns
    // them off.
    DependencyRead {
        reader: "tracing-subscriber",
        names: &["NO_COLOR"],
        reached_from: &[("src/bootstrap.rs", "tracing_subscriber::fmt::layer()")],
    },
    // On Unix, where `gateway import-standalone` stages its private copies of
    // the source databases; the import names it when that fails.
    DependencyRead {
        reader: "std",
        names: &["TMPDIR"],
        reached_from: &[("src/import/source.rs", "std::env::temp_dir()")],
    },
];

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        env::VarError,
        fs,
        path::Path,
    };

    use super::*;
    use crate::config::Config;

    /// Every name `from_env_vars` asks `environment` for, in order, repeats
    /// included.
    fn requested_names(environment: impl Fn(&str) -> Result<String, VarError>) -> Vec<String> {
        let mut requested = Vec::new();
        let _ = Config::from_env_vars(|name| {
            requested.push(name.to_owned());
            environment(name)
        });
        requested
    }

    #[test]
    fn the_inventory_is_exactly_what_from_env_vars_requests() {
        let requested = requested_names(|_| Err(VarError::NotPresent));

        let inventory: BTreeSet<&str> = CONFIG_INPUTS.iter().copied().collect();
        assert_eq!(
            inventory.len(),
            CONFIG_INPUTS.len(),
            "the inventory lists a variable twice"
        );
        let requested_set: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let unlisted: Vec<&str> = requested_set.difference(&inventory).copied().collect();
        let unread: Vec<&str> = inventory.difference(&requested_set).copied().collect();
        assert!(
            unlisted.is_empty() && unread.is_empty(),
            "from_env_vars requests {unlisted:?}, which the inventory does not list, \
             and never requests {unread:?}, which it does"
        );

        let mut first_requests: Vec<&str> = Vec::new();
        for name in &requested {
            if !first_requests.contains(&name.as_str()) {
                first_requests.push(name);
            }
        }
        assert_eq!(
            first_requests, CONFIG_INPUTS,
            "the inventory lists the variables in the order from_env_vars first requests them"
        );

        assert_eq!(
            requested.len(),
            CONFIG_INPUTS.len(),
            "from_env_vars requests every variable exactly once, as the module documentation says"
        );
    }

    /// With every variable set, nothing outside the inventory is requested
    /// and nothing in it is skipped.
    ///
    /// The probe is a value most settings refuse, so a read that only a valid
    /// value reaches is not exercised here; the parity tests record the reads
    /// of configurations the parser accepts.
    #[test]
    fn setting_every_variable_at_once_requests_nothing_outside_the_inventory() {
        let requested = requested_names(|_| Ok("inventory-probe".to_owned()));

        let inventory: BTreeSet<&str> = CONFIG_INPUTS.iter().copied().collect();
        let requested: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let unlisted: Vec<&str> = requested.difference(&inventory).copied().collect();
        assert!(
            unlisted.is_empty(),
            "unlisted variables requested: {unlisted:?}"
        );
        let skipped: Vec<&str> = inventory.difference(&requested).copied().collect();
        assert!(skipped.is_empty(), "skipped variables: {skipped:?}");
    }

    #[test]
    fn every_name_the_parser_reads_is_found_by_its_own_spelling() {
        for name in CONFIG_INPUTS {
            assert_eq!(config_input(name), Some(*name));
        }
        assert_eq!(config_input("listen_addr"), None);
        assert_eq!(config_input("HOSTNAME"), None);
    }

    /// The environment reads table matches the source: the files that name a
    /// `std::env` variable reader are exactly the files it lists, each one
    /// names a reader as many times as its row says, and each listed name is
    /// one the file spells out.
    ///
    /// The keys are mostly built at runtime, so the scan cannot read the name
    /// a call asks for. The count is what catches a read added to a file that
    /// already has one; the row's names are then for its reviewer to update.
    #[test]
    fn the_environment_reads_table_lists_every_file_that_reads_the_environment() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = BTreeMap::new();
        collect_environment_readers(crate_root, &crate_root.join("src"), &mut found);

        let listed: BTreeMap<String, usize> = ENVIRONMENT_READS
            .iter()
            .map(|read| (read.file.to_owned(), read.reads))
            .collect();
        assert_eq!(
            listed.len(),
            ENVIRONMENT_READS.len(),
            "the table lists a file twice"
        );
        let unlisted: Vec<&String> = found
            .keys()
            .filter(|file| !listed.contains_key(*file))
            .collect();
        let stale: Vec<&String> = listed
            .keys()
            .filter(|file| !found.contains_key(*file))
            .collect();
        assert!(
            unlisted.is_empty() && stale.is_empty(),
            "{unlisted:?} read the environment without an entry in ENVIRONMENT_READS, \
             and {stale:?} are listed but no longer read it"
        );
        assert_eq!(
            found, listed,
            "a file names a std::env variable reader a different number of times than its \
             ENVIRONMENT_READS row records; review the reads and update the row"
        );

        for read in ENVIRONMENT_READS {
            let source = fs::read_to_string(crate_root.join(read.file))
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", read.file));
            match read.names {
                ReadNames::ConfigInputs => assert_eq!(read.file, "src/config.rs"),
                ReadNames::NamedBy(input) => {
                    assert_eq!(read.purpose, ReadPurpose::Gateway, "{}", read.file);
                    assert_eq!(config_input(input), Some(input), "{}", read.file);
                }
                ReadNames::Fixed(names) => {
                    for name in names {
                        assert!(
                            source.contains(&format!("\"{name}\"")),
                            "{} does not spell out {name}",
                            read.file
                        );
                        // No fixed read takes a configuration input, so the
                        // parser is the only reader written for one, and a
                        // harness locator is never one. An operator alias can
                        // still name one; see `ReadNames::NamedBy`.
                        assert_eq!(config_input(name), None, "{name} in {}", read.file);
                        assert_eq!(
                            name.starts_with("GATEWAY_TEST_"),
                            read.purpose == ReadPurpose::TestHarness,
                            "{name} in {}",
                            read.file
                        );
                    }
                }
            }
        }
    }

    /// Each dependency read is still reached the way its row says, from a
    /// package the lock file still has, and names a variable no other row
    /// accounts for.
    #[test]
    fn every_dependency_read_is_still_reached_from_the_gateway() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lock = fs::read_to_string(crate_root.join("../Cargo.lock"))
            .unwrap_or_else(|error| panic!("failed to read Cargo.lock: {error}"));
        let locked: BTreeSet<&str> = lock
            .lines()
            .filter_map(|line| line.strip_prefix("name = \""))
            .filter_map(|line| line.strip_suffix('"'))
            .collect();
        let fixed: BTreeSet<&str> = ENVIRONMENT_READS
            .iter()
            .filter_map(|read| match read.names {
                ReadNames::Fixed(names) => Some(names.iter().copied()),
                ReadNames::ConfigInputs | ReadNames::NamedBy(_) => None,
            })
            .flatten()
            .collect();

        let mut seen = BTreeSet::new();
        for read in DEPENDENCY_READS {
            assert!(
                read.reader == "std" || locked.contains(read.reader),
                "{} is no longer in Cargo.lock",
                read.reader
            );
            assert!(!read.reached_from.is_empty(), "{}", read.reader);
            for (file, call) in read.reached_from {
                let source = fs::read_to_string(crate_root.join(file))
                    .unwrap_or_else(|error| panic!("failed to read {file}: {error}"));
                assert!(
                    source.contains(call),
                    "{file} no longer calls {call}, which is how the gateway reaches {}",
                    read.reader
                );
            }
            for name in read.names {
                assert!(seen.insert(*name), "{name} is listed twice");
                assert_eq!(config_input(name), None, "{name} in {}", read.reader);
                assert!(!fixed.contains(name), "{name} in {}", read.reader);
                assert!(
                    !name.starts_with("GATEWAY_TEST_"),
                    "{name} in {}",
                    read.reader
                );
            }
        }
    }

    /// Every `.rs` file under `directory` that names a `std::env` variable
    /// reader, relative to the crate root, with how many times it does.
    fn collect_environment_readers(
        crate_root: &Path,
        directory: &Path,
        found: &mut BTreeMap<String, usize>,
    ) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
                .path();
            if path.is_dir() {
                collect_environment_readers(crate_root, &path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
                let relative = path
                    .strip_prefix(crate_root)
                    .expect("source files live under the crate root")
                    .to_string_lossy()
                    .replace('\\', "/");
                assert!(
                    !imports_an_environment_reader(&source),
                    "{relative} imports a std::env variable reader by name; call it by its \
                     env:: path so the environment reads scan can count it"
                );
                let reads = environment_reader_uses(&source);
                if reads > 0 {
                    found.insert(relative, reads);
                }
            }
        }
    }

    /// The `std::env` functions that read variables.
    const ENVIRONMENT_READERS: [&str; 4] = ["var", "var_os", "vars", "vars_os"];

    /// The length of the identifier `text` starts with.
    fn identifier_length(text: &str) -> usize {
        text.find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(text.len())
    }

    /// How many times the source names one of the `std::env` functions that
    /// read variables by its `env::` path, as a call or as a function value.
    /// A name in backticks is documentation, not a use. The reader names are
    /// matched after the path rather than written out with it, so this file
    /// does not count as a reader itself -- here or in the walk of
    /// `tests/env_example.rs`, which looks for the same calls.
    fn environment_reader_uses(source: &str) -> usize {
        source
            .match_indices("env::")
            .filter(|(index, path)| {
                let rest = &source[index + path.len()..];
                let (name, after) = rest.split_at(identifier_length(rest));
                ENVIRONMENT_READERS.contains(&name) && !after.starts_with('`')
            })
            .count()
    }

    /// Whether a `use` declaration in the source brings a variable reader
    /// into scope under its bare name, or all of `std::env` with a glob,
    /// where its calls would no longer carry the `env::` path the count above
    /// looks for. rustfmt starts every declaration on its own line, after at
    /// most a visibility.
    fn imports_an_environment_reader(source: &str) -> bool {
        source.match_indices("use ").any(|(index, _)| {
            let line_start = source[..index].rfind('\n').map_or(0, |newline| newline + 1);
            let qualifier = source[line_start..index].trim();
            let is_declaration = qualifier.is_empty()
                || qualifier == "pub"
                || (qualifier.starts_with("pub(") && qualifier.ends_with(')'));
            if !is_declaration {
                return false;
            }
            let declaration = &source[index..];
            let declaration = &declaration[..declaration.find(';').unwrap_or(declaration.len())];
            declaration.match_indices("env::").any(|(at, path)| {
                let rest = &declaration[at + path.len()..];
                if let Some(list) = rest.strip_prefix('{') {
                    let list = &list[..list.find('}').unwrap_or(list.len())];
                    return list.split(',').any(|item| {
                        let item = item.trim();
                        ENVIRONMENT_READERS.contains(&&item[..identifier_length(item)])
                    });
                }
                rest.starts_with('*')
                    || ENVIRONMENT_READERS.contains(&&rest[..identifier_length(rest)])
            })
        })
    }

    /// The scan's own fixtures are written with `ENV::` and rewritten before
    /// use, so the text of this file never names a reader.
    fn fixture_source(text: &str) -> String {
        text.replace("ENV::", "env::")
    }

    #[test]
    fn the_scan_counts_every_use_of_a_reader_and_refuses_an_imported_one() {
        let uses = fixture_source(
            "let a = std::ENV::var(key);\n\
             let b = ENV::var_os (key);\n\
             let c = ENV::vars();\n\
             let d = names.map(ENV::var);\n\
             // `ENV::var` in documentation, and ENV::VarError, are not uses.\n",
        );
        assert_eq!(environment_reader_uses(&uses), 4);
        assert!(!imports_an_environment_reader(&uses));
        assert!(!imports_an_environment_reader(&fixture_source(
            "use std::ENV::{self, VarError};"
        )));

        for import in [
            "use std::ENV::var;",
            "    use std::ENV::var_os as read;",
            "use std::{ENV::vars, fs};",
            "use std::ENV::{self, var};",
            "use std::ENV::{\n    VarError,\n    var_os,\n};",
            "pub(crate) use std::ENV::*;",
        ] {
            let import = fixture_source(import);
            assert!(imports_an_environment_reader(&import), "{import}");
        }
    }
}
