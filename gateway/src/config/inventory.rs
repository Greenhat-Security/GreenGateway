//! Every environment input the gateway reads (issue #433, PR 1).
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
//! warning. By inspection it logs nothing else, opens no file and calls no
//! store, secret provider or network; the compiler's pure stages are where
//! that becomes a tested guarantee. Three variables are requested twice --
//! `DISCOVERY_PROJECTOR_LEASE_TTL_MS`, `DISCOVERY_PROJECTOR_POLL_MS` and
//! `DISCOVERY_PROJECTOR_BATCH`, once to learn whether they were set and once
//! to parse them -- and one is requested conditionally:
//! `ADMIN_SESSION_MAX_ENTRIES` is not requested at all when
//! `ADMIN_SESSION_MODE` is anything but `standalone_memory` and
//! `ADMIN_SESSION_TTL_SECS` is set, because the check that reads it
//! short-circuits.
//!
//! The gateway also reads the environment outside the parser. The test-only
//! `ENVIRONMENT_READS` table lists every source file that does, and what it
//! reads; its test scans `gateway/src` so the table cannot fall behind.

use super::{
    ADMIN_CLIENT_CERT_CA_FILE, ADMIN_CLIENT_CERT_CRL_FILE, ADMIN_CLIENT_CERT_MODE,
    ADMIN_LISTEN_ADDR, ADMIN_LOGIN_KEYRING, ADMIN_LOGIN_PENDING_MAX_ENTRIES,
    ADMIN_LOGIN_PENDING_MAX_PER_IP, ADMIN_LOGIN_PENDING_TTL_SECS, ADMIN_LOGIN_PROVIDER,
    ADMIN_PREFIX, ADMIN_SESSION_MAX_ENTRIES, ADMIN_SESSION_MODE, ADMIN_SESSION_TTL_SECS,
    ADMIN_TLS_CERT_FILE, ADMIN_TLS_KEY_FILE, AUDIT_DRAIN_TIMEOUT_MS, AUDIT_LOG_FILE,
    AUDIT_POSTGRES_RETENTION_DAYS, AUDIT_SQLITE_PATH, AUDIT_SQLITE_RETENTION_DAYS,
    AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY, AUTH_COOKIE_NAME, AUTH_ENABLED, AUTH_EXEMPT_PATHS,
    AUTH_MODE, AUTH_PROVIDERS, CLIENT_CERT_CA_FILE, CLIENT_CERT_CRL_FILE,
    CLIENT_CERT_IDENTITY_SOURCE, CLIENT_CERT_MODE, CLUSTER_HEARTBEAT_MS,
    CLUSTER_MAINTENANCE_INTERVAL_MS, CLUSTER_MAINTENANCE_LEASE_TTL_MS, CLUSTER_MEMBER_STALE_MS,
    CLUSTER_STATUS_EXPOSE_HOSTNAMES, CONNECTIONS_SQLITE_PATH, CONNECTION_AWS_PROVIDER,
    CONNECTION_AZURE_PROVIDER, CONNECTION_GCP_PROVIDER, CONNECTION_KUBERNETES_PROVIDER,
    CONNECTION_LOCAL_SECRET_KEYRING, CONNECTION_SECRETS_ROOT, CONNECTION_SECRET_ALIASES,
    CONNECTION_VAULT_PROVIDER, CORS_ALLOW_ORIGINS, CSRF_COOKIE_DOMAIN, CSRF_COOKIE_NAME,
    CSRF_ENABLED, CSRF_EXEMPT_PATHS, CSRF_HEADER_NAME, DATABASE_ACQUIRE_TIMEOUT_MS,
    DATABASE_AUTO_MIGRATE, DATABASE_CONNECT_TIMEOUT_MS, DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    DATABASE_LOCK_TIMEOUT_MS, DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, DATABASE_POOL_MAX,
    DATABASE_STARTUP_RETRY_LIMIT, DATABASE_STATEMENT_TIMEOUT_MS, DATABASE_TLS_CA_FILE,
    DATABASE_TLS_MODE, DATABASE_URL_FILE, DEPLOYMENT_ID, DISCOVERY_ENDPOINT_LIMIT,
    DISCOVERY_PROJECTOR_BATCH, DISCOVERY_PROJECTOR_LEASE_TTL_MS, DISCOVERY_PROJECTOR_POLL_MS,
    DISCOVERY_SQLITE_PATH, EGRESS_ALLOWED_HOSTS, EGRESS_CONNECT_TIMEOUT_MS,
    EGRESS_DENY_PRIVATE_IPS, EGRESS_MAX_REQUEST_BODY_BYTES, EGRESS_MAX_RESPONSE_BYTES,
    EGRESS_NAT64_PREFIXES, EGRESS_RESPONSE_IDLE_TIMEOUT_MS, EGRESS_TIMEOUT_MS,
    ERROR_RATE_SPIKE_SIGNAL_THRESHOLD, GATEWAY_PUBLIC_URL, GRPC_LISTEN_ADDR,
    GRPC_MAX_CONCURRENT_STREAMS, GRPC_MAX_METADATA_BYTES, JWT_AUDIENCE, JWT_ISSUER,
    JWT_JWKS_MAX_KEY_AGE_SECS, JWT_JWKS_TIMEOUT_MS, JWT_JWKS_URL, JWT_REQUIRE_JTI, LISTEN_ADDR,
    MAX_BODY_SIZE, MAX_REQUEST_PATH_BYTES, MCP_UPSTREAM_SERVERS, OPENAPI_SPEC_PATH,
    PAYLOAD_CAPTURE_ENABLED, PAYLOAD_CAPTURE_SAMPLE_RATE, POLICY_FILE, POLICY_HISTORY_SQLITE_PATH,
    PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD, PRINCIPAL_SQLITE_PATH, RATE_LIMIT_BUCKET_TTL_MS,
    RATE_LIMIT_KEYRING, RATE_LIMIT_MAX_BUCKETS, RATE_LIMIT_READ_BURST, RATE_LIMIT_READ_RPS,
    RATE_LIMIT_WRITE_BURST, RATE_LIMIT_WRITE_RPS, RBAC_EXEMPT_PATHS, READINESS_PROBE_CACHE_MS,
    ROLES_CLAIM, RULE_SUGGESTION_BASELINE_WINDOW_HOURS, SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
    SERVICE_TOKEN_CACHE_TTL_MS, SERVICE_TOKEN_SQLITE_PATH, SHUTDOWN_DRAIN_DELAY_MS,
    SHUTDOWN_TIMEOUT_MS, STATE_BACKEND, TLS_CERT_FILE, TLS_HANDSHAKE_TIMEOUT_MS, TLS_KEY_FILE,
    TLS_MAX_CONCURRENT_HANDSHAKES, TLS_MIN_VERSION, TOOLS_FILE, TOOL_LEASE_TTL_MS,
    TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, TOOL_RUNTIME_GLOBAL_CONCURRENCY, TOOL_RUNTIME_QUEUE_DEPTH,
    TOOL_RUNTIME_QUEUE_TIMEOUT_MS, TRUSTED_PROXY_CIDRS, TRUST_PROXY_HEADERS,
    UPSTREAM_CONNECT_TIMEOUT_MS, UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS, UPSTREAM_ROUTES,
    UPSTREAM_TIMEOUT_MS, UPSTREAM_URL, VALIDATION_ALLOWED_CONTENT_TYPES,
    VOLUME_OUTLIER_SIGNAL_THRESHOLD,
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
];

/// The inventory's own spelling of `name`, or `None` when `from_env_vars`
/// never requests it.
pub(crate) fn config_input(name: &str) -> Option<&'static str> {
    CONFIG_INPUTS.iter().copied().find(|input| *input == name)
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
    NamedBy(&'static str),
}

/// One source file that reads the process environment.
#[cfg(test)]
struct EnvironmentRead {
    /// Relative to the crate root, with forward slashes.
    file: &'static str,
    names: ReadNames,
    purpose: ReadPurpose,
}

/// Every file under `gateway/src` that reads the process environment.
///
/// `Config::from_env` is the parser's only window onto the process; the
/// other gateway reads are the two below it. The test-harness reads are kept
/// here too, because a disposable-database locator is still an environment
/// input, and listing it is what lets the scan below hold this table to the
/// source.
#[cfg(test)]
const ENVIRONMENT_READS: &[EnvironmentRead] = &[
    EnvironmentRead {
        file: "src/config.rs",
        names: ReadNames::ConfigInputs,
        purpose: ReadPurpose::Gateway,
    },
    // This replica's hostname for the cluster status API, read once at
    // startup and only when `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`.
    EnvironmentRead {
        file: "src/admin_identity.rs",
        names: ReadNames::Fixed(&["HOSTNAME", "COMPUTERNAME"]),
        purpose: ReadPurpose::Gateway,
    },
    EnvironmentRead {
        file: "src/connections/secret.rs",
        names: ReadNames::NamedBy(CONNECTION_SECRET_ALIASES),
        purpose: ReadPurpose::Gateway,
    },
    EnvironmentRead {
        file: "src/app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/connections/pg_store_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/import/tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/storage/contract_tests.rs",
        names: ReadNames::Fixed(&[
            "GATEWAY_TEST_POSTGRES_URL_FILE",
            "GATEWAY_TEST_POSTGRES_BENCHMARK_ROWS",
        ]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/storage/migrations.rs",
        names: ReadNames::Fixed(&[
            "GATEWAY_TEST_POSTGRES_URL_FILE",
            "GATEWAY_TEST_POSTGRES_NODDL_URL_FILE",
        ]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/storage/postgres.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
    },
    EnvironmentRead {
        file: "src/storage/postgres_session.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
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

        let mut counts = BTreeMap::<&str, usize>::new();
        for name in &requested {
            *counts.entry(name.as_str()).or_default() += 1;
        }
        let repeated: Vec<(&str, usize)> =
            counts.into_iter().filter(|(_, count)| *count > 1).collect();
        assert_eq!(
            repeated,
            [
                (DISCOVERY_PROJECTOR_BATCH, 2),
                (DISCOVERY_PROJECTOR_LEASE_TTL_MS, 2),
                (DISCOVERY_PROJECTOR_POLL_MS, 2),
            ],
            "the module documentation names every variable requested more than once"
        );
    }

    /// With every variable set, nothing outside the inventory is requested,
    /// and the one conditional read is the one the module documentation
    /// names.
    #[test]
    fn no_environment_makes_from_env_vars_request_a_name_outside_the_inventory() {
        let requested = requested_names(|_| Ok("inventory-probe".to_owned()));

        let inventory: BTreeSet<&str> = CONFIG_INPUTS.iter().copied().collect();
        let requested: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let unlisted: Vec<&str> = requested.difference(&inventory).copied().collect();
        assert!(
            unlisted.is_empty(),
            "unlisted variables requested: {unlisted:?}"
        );
        let skipped: Vec<&str> = inventory.difference(&requested).copied().collect();
        assert_eq!(skipped, [ADMIN_SESSION_MAX_ENTRIES]);
    }

    #[test]
    fn every_name_the_parser_reads_is_found_by_its_own_spelling() {
        for name in CONFIG_INPUTS {
            assert_eq!(config_input(name), Some(*name));
        }
        assert_eq!(config_input("listen_addr"), None);
        assert_eq!(config_input("HOSTNAME"), None);
    }

    /// The environment reads table matches the source: the files that call a
    /// `std::env` variable reader are exactly the files it lists, and each
    /// listed name is one the file spells out.
    #[test]
    fn the_environment_reads_table_lists_every_file_that_reads_the_environment() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = BTreeSet::new();
        collect_environment_readers(crate_root, &crate_root.join("src"), &mut found);

        let listed: BTreeSet<String> = ENVIRONMENT_READS
            .iter()
            .map(|read| read.file.to_owned())
            .collect();
        assert_eq!(
            listed.len(),
            ENVIRONMENT_READS.len(),
            "the table lists a file twice"
        );
        let unlisted: Vec<&String> = found.difference(&listed).collect();
        let stale: Vec<&String> = listed.difference(&found).collect();
        assert!(
            unlisted.is_empty() && stale.is_empty(),
            "{unlisted:?} read the environment without an entry in ENVIRONMENT_READS, \
             and {stale:?} are listed but no longer read it"
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
                        // A configuration input has exactly one reader, the
                        // parser, and a harness locator is never one.
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

    fn collect_environment_readers(
        crate_root: &Path,
        directory: &Path,
        found: &mut BTreeSet<String>,
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
                if calls_an_environment_reader(&source) {
                    let relative = path
                        .strip_prefix(crate_root)
                        .expect("source files live under the crate root");
                    found.insert(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }

    /// Whether the source calls one of the `std::env` functions that read
    /// variables. The reader names are matched after the `env::` path rather
    /// than written out with their call parenthesis, so this file does not
    /// count as a reader itself -- here or in the walk of
    /// `tests/env_example.rs`, which looks for the same calls.
    fn calls_an_environment_reader(source: &str) -> bool {
        source.match_indices("env::").any(|(index, path)| {
            let rest = &source[index + path.len()..];
            let name_end = rest
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(rest.len());
            matches!(&rest[..name_end], "var" | "var_os" | "vars" | "vars_os")
                && rest[name_end..].trim_start().starts_with('(')
        })
    }
}
