//! The configuration compiler's inputs (issue #433, PR 1).
//!
//! [`CONFIG_INPUTS`] is the complete list of variables [`super::compile`]
//! asks its reader for, in the order it first asks. It is the compiler's
//! input boundary, and the tests below hold it to the compiler exactly: they
//! run `compile` against a reader that records every name requested, so a
//! variable added to a stage and not to this list fails them, and so does a
//! variable left here after its stage stops reading it.
//!
//! Apart from the lookups, the compiler has one side effect: a retention of
//! `0` days for either audit store is accepted as "no pruning" and logged as
//! a warning. It logs nothing else, opens no file and calls no store, secret
//! provider or network, which a source scan in the stage tests holds the
//! compiler's modules to. Every input is read in a block, and the parse and
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
//! What else reads the environment of a running gateway -- its own other
//! reads and those its dependencies make -- is the gateway's to list, in
//! `gateway/src/config/environment_reads.rs`.

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
    POLICY_HISTORY_SQLITE_PATH, POLICY_TESTS_REQUIRED, PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
    PRINCIPAL_SQLITE_PATH, RATE_LIMIT_BUCKET_TTL_MS, RATE_LIMIT_KEYRING, RATE_LIMIT_MAX_BUCKETS,
    RATE_LIMIT_READ_BURST, RATE_LIMIT_READ_RPS, RATE_LIMIT_WRITE_BURST, RATE_LIMIT_WRITE_RPS,
    RBAC_EXEMPT_PATHS, READINESS_PROBE_CACHE_MS, ROLES_CLAIM,
    RULE_SUGGESTION_BASELINE_WINDOW_HOURS, SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
    SERVICE_TOKEN_CACHE_TTL_MS, SERVICE_TOKEN_SQLITE_PATH, SHUTDOWN_DRAIN_DELAY_MS,
    SHUTDOWN_TIMEOUT_MS, STATE_BACKEND, TLS_CERT_FILE, TLS_HANDSHAKE_TIMEOUT_MS, TLS_KEY_FILE,
    TLS_MAX_CONCURRENT_HANDSHAKES, TLS_MIN_VERSION, TOOLS_FILE, TOOL_LEASE_TTL_MS,
    TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, TOOL_RUNTIME_GLOBAL_CONCURRENCY, TOOL_RUNTIME_QUEUE_DEPTH,
    TOOL_RUNTIME_QUEUE_TIMEOUT_MS, TRUSTED_PROXY_CIDRS, TRUST_PROXY_HEADERS,
    UPSTREAM_CONNECT_TIMEOUT_MS, UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS, UPSTREAM_ROUTES,
    UPSTREAM_TIMEOUT_MS, UPSTREAM_URL, VALIDATION_ALLOWED_CONTENT_TYPES,
    VOLUME_OUTLIER_SIGNAL_THRESHOLD,
};

/// Every variable [`super::compile`] requests, in the order it first
/// requests each one.
///
/// Grouped as the parser reads them, which is not always by domain: the
/// keyrings sit with the Connections settings because they share
/// `CONNECTION_SECRETS_ROOT`, and the cluster settings sit with the tool
/// runtime because they are parsed next to the execution lease.
pub const CONFIG_INPUTS: &[&str] = &[
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
    POLICY_TESTS_REQUIRED,
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

/// The inventory's own spelling of `name`, or `None` when the compiler
/// never requests it.
pub fn config_input(name: &str) -> Option<&'static str> {
    CONFIG_INPUTS.iter().copied().find(|input| *input == name)
}

/// Where `name` comes in the order the compiler first requests its
/// inputs. A name it never requests sorts after all of them, so a problem
/// placed after one is still reported, last, rather than dropped.
pub(super) fn position(name: &str) -> usize {
    CONFIG_INPUTS
        .iter()
        .position(|input| *input == name)
        .unwrap_or(CONFIG_INPUTS.len())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, env::VarError};

    use super::*;

    /// Every name `compile` asks `environment` for, in order, repeats
    /// included.
    fn requested_names(environment: impl Fn(&str) -> Result<String, VarError>) -> Vec<String> {
        let mut requested = Vec::new();
        let _ = super::super::compile(|name| {
            requested.push(name.to_owned());
            environment(name)
        });
        requested
    }

    #[test]
    fn the_inventory_is_exactly_what_the_compiler_requests() {
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
            "the compiler requests {unlisted:?}, which the inventory does not list, \
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
            "the inventory lists the variables in the order the compiler first requests them"
        );

        assert_eq!(
            requested.len(),
            CONFIG_INPUTS.len(),
            "the compiler requests every variable exactly once, as the module documentation says"
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
}
