//! The semantic diff of two compiled configurations (issue #242, PR 9).
//!
//! `gateway_config::semantic_diff` is the engine: the risk codes, the change
//! classes and the redaction rules. This module feeds it what this crate
//! compiles, so the diff compares exactly what the gateway would run:
//!
//! - [`plans`] compares two compiled environment configurations, setting by
//!   setting, each identified by its environment variable name. Every
//!   setting is compared as the compiler normalized it, so spelling,
//!   whitespace and list order never register. Each domain plan is
//!   destructured field by field, so a setting added to a plan does not
//!   compile until it is named here and is an unused binding, which CI's
//!   warnings-as-errors builds refuse, until it is compared; a test holds the
//!   compared names to the inventory's `CONFIG_INPUTS`.
//! - [`bundles`] compares two bundles the shared bundle reader accepted
//!   with the gateway's production validators, with their policy and tools
//!   documents in the form those validators produced. (`ggctl diff` compares
//!   bundles read with the published schemas only, as they were written.)
//!
//! Every environment setting is read at startup, so every change is a
//! `restart` change, except a change of state backend or deployment, which is
//! a #241 `cluster_operation` (`gateway import-standalone` and its
//! procedure). In cluster mode, a restart change to a setting in ADR-0007's
//! static-configuration fingerprint also needs ADR-0007's coordinated
//! procedure; this diff does not single those out yet.
//!
//! Nothing here reads a file, the environment or the network; values are
//! compared in memory and only the closed-vocabulary ones are shown.
#![allow(dead_code)] // Server plans (#242 PR 11) are the readers; until then the tests are.

use std::collections::{BTreeMap, BTreeSet};

use gateway_config::{
    bundle::{Bundle, BundledResource},
    semantic_diff::{
        compare_bundles, BundleView, ChangeClass, ChangeKind, Comparison, Display, Field, Impact,
        Redaction, RiskCode, Rule, Section, SemanticDiff,
    },
};
use serde_json::{json, Value};

use super::{
    authority_events::{AuthorityEventSettings, AuthorityEventSinkSetting},
    connections::ConnectionsPlan,
    egress::EgressPlan,
    identity::IdentityPlan,
    listeners::{ListenerPlan, TlsMaterial},
    plan::ConfigPlan,
    proxy::ProxyPlan,
    runtime::RuntimePlan,
    storage::{DatabasePlan, StoragePlan},
    AuditDurability, AuthMode, AuthProviderConfig, DatabaseTlsMode, InboundClientAuthConfig,
    McpUpstreamServerConfig, StateBackend, UpstreamRouteConfig,
};
use crate::{
    inbound_tls::ClientCertRequirement, rbac::policy::Policy, tools::definitions::ToolDefinition,
};

/// Compares two compiled environment configurations.
pub(crate) fn plans(base: &ConfigPlan, candidate: &ConfigPlan) -> SemanticDiff {
    // Every domain is bound by name, so a domain added to the plan does not
    // compile until it is compared.
    let ConfigPlan {
        listeners,
        identity,
        proxy,
        storage,
        connections,
        egress,
        runtime,
    } = base;
    let mut comparison = Comparison::new();
    compare_listeners(&mut comparison, listeners, &candidate.listeners);
    compare_identity(&mut comparison, identity, &candidate.identity);
    compare_proxy(
        &mut comparison,
        proxy,
        &candidate.proxy,
        (egress, &candidate.egress),
    );
    compare_storage(&mut comparison, storage, &candidate.storage);
    compare_connections(&mut comparison, connections, &candidate.connections);
    compare_egress(&mut comparison, egress, &candidate.egress);
    compare_runtime(&mut comparison, runtime, &candidate.runtime);
    comparison.finish()
}

/// A bundle the shared reader accepted with the production validators.
type ProductionBundle = Bundle<Policy, Vec<ToolDefinition>>;

/// Compares two bundles the shared reader accepted with the gateway's
/// production validators, by the documents those validators built.
pub(crate) fn bundles(base: &ProductionBundle, candidate: &ProductionBundle) -> SemanticDiff {
    let (base_policy, base_tools) = (policy_value(base), tools_value(base));
    let (candidate_policy, candidate_tools) = (policy_value(candidate), tools_value(candidate));
    let mut comparison = Comparison::new();
    compare_bundles(
        &mut comparison,
        &BundleView::of(base, base_policy.as_ref(), base_tools.as_ref()),
        &BundleView::of(
            candidate,
            candidate_policy.as_ref(),
            candidate_tools.as_ref(),
        ),
    );
    comparison.finish()
}

/// The validated policy as its loader models it, with every default filled
/// in. `None` when it cannot be serialized, which the engine reports as an
/// `unknown` change whenever the pins differ.
fn policy_value(bundle: &ProductionBundle) -> Option<Value> {
    match &bundle.policy {
        Some(BundledResource::Bundle { document, .. }) => serde_json::to_value(document).ok(),
        _ => None,
    }
}

/// The validated tool definitions, as a tools document.
fn tools_value(bundle: &ProductionBundle) -> Option<Value> {
    match &bundle.tools {
        Some(BundledResource::Bundle {
            schema_version,
            document,
            ..
        }) => {
            let tools = serde_json::to_value(document).ok()?;
            Some(json!({"schema_version": schema_version, "tools": tools}))
        }
        _ => None,
    }
}

// --- Fields -----------------------------------------------------------------

const fn setting(id: &'static str, section: Section, risk: RiskCode, rule: Rule) -> Field {
    Field {
        id,
        section,
        class: ChangeClass::Restart,
        risk,
        rule,
    }
}

/// A setting with no security effect in either direction.
const fn neutral(id: &'static str, section: Section) -> Field {
    setting(id, section, RiskCode::UnknownImpact, Rule::Neutral)
}

/// A bound where raising it loosens.
const fn limit(id: &'static str, section: Section) -> Field {
    setting(id, section, RiskCode::LimitsLoosened, Rule::HigherIsLooser)
}

/// A secret, secret reference or secret locator.
const fn credential(id: &'static str, section: Section) -> Field {
    setting(
        id,
        section,
        RiskCode::CredentialBindingChanged,
        Rule::AnyChange,
    )
}

/// The client-certificate modes from the strictest to the loosest.
const CLIENT_CERT_MODES: &[&str] = &["required", "optional", "off"];

// Listeners and inbound TLS.
static LISTEN_ADDR: Field = setting(
    "LISTEN_ADDR",
    Section::Listeners,
    RiskCode::ListenerExposed,
    Rule::Unclassified,
);
static ADMIN_LISTEN_ADDR: Field = setting(
    "ADMIN_LISTEN_ADDR",
    Section::Listeners,
    RiskCode::ListenerExposed,
    Rule::Unclassified,
);
static GRPC_LISTEN_ADDR: Field = setting(
    "GRPC_LISTEN_ADDR",
    Section::Listeners,
    RiskCode::ListenerExposed,
    Rule::Unclassified,
);
static GRPC_MAX_CONCURRENT_STREAMS: Field = limit("GRPC_MAX_CONCURRENT_STREAMS", Section::Limits);
static GRPC_MAX_METADATA_BYTES: Field = limit("GRPC_MAX_METADATA_BYTES", Section::Limits);
static TLS_CERT_FILE: Field = setting(
    "TLS_CERT_FILE",
    Section::Tls,
    RiskCode::PlaintextTransport,
    Rule::AbsenceIsLooser,
);
static TLS_KEY_FILE: Field = credential("TLS_KEY_FILE", Section::Tls);
static ADMIN_TLS_CERT_FILE: Field = setting(
    "ADMIN_TLS_CERT_FILE",
    Section::Tls,
    RiskCode::PlaintextTransport,
    Rule::AbsenceIsLooser,
);
static ADMIN_TLS_KEY_FILE: Field = credential("ADMIN_TLS_KEY_FILE", Section::Tls);
static TLS_MIN_VERSION: Field = setting(
    "TLS_MIN_VERSION",
    Section::Tls,
    RiskCode::TlsWeakened,
    Rule::Ranked(&["1.3", "1.2"]),
);
static TLS_HANDSHAKE_TIMEOUT_MS: Field = limit("TLS_HANDSHAKE_TIMEOUT_MS", Section::Tls);
static TLS_MAX_CONCURRENT_HANDSHAKES: Field = limit("TLS_MAX_CONCURRENT_HANDSHAKES", Section::Tls);
static CLIENT_CERT_MODE: Field = setting(
    "CLIENT_CERT_MODE",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::Ranked(CLIENT_CERT_MODES),
);
static ADMIN_CLIENT_CERT_MODE: Field = setting(
    "ADMIN_CLIENT_CERT_MODE",
    Section::Admin,
    RiskCode::AuthTrustChanged,
    Rule::Ranked(CLIENT_CERT_MODES),
);
static CLIENT_CERT_CA_FILE: Field = setting(
    "CLIENT_CERT_CA_FILE",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static CLIENT_CERT_CRL_FILE: Field = setting(
    "CLIENT_CERT_CRL_FILE",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AbsenceIsLooser,
);
static ADMIN_CLIENT_CERT_CA_FILE: Field = setting(
    "ADMIN_CLIENT_CERT_CA_FILE",
    Section::Admin,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static ADMIN_CLIENT_CERT_CRL_FILE: Field = setting(
    "ADMIN_CLIENT_CERT_CRL_FILE",
    Section::Admin,
    RiskCode::AuthTrustChanged,
    Rule::AbsenceIsLooser,
);
static CLIENT_CERT_IDENTITY_SOURCE: Field = setting(
    "CLIENT_CERT_IDENTITY_SOURCE",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);

// The admin surface and the public origin.
static ADMIN_PREFIX: Field = neutral("ADMIN_PREFIX", Section::Admin);
static ADMIN_LOGIN_PROVIDER: Field = setting(
    "ADMIN_LOGIN_PROVIDER",
    Section::Admin,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static ADMIN_SESSION_MODE: Field = setting(
    "ADMIN_SESSION_MODE",
    Section::Admin,
    RiskCode::CookieOrCsrfWeakened,
    Rule::PresenceIsLooser,
);
static ADMIN_SESSION_TTL_SECS: Field = setting(
    "ADMIN_SESSION_TTL_SECS",
    Section::Admin,
    RiskCode::CookieOrCsrfWeakened,
    Rule::HigherIsLooser,
);
static ADMIN_SESSION_IDLE_TIMEOUT_SECS: Field = setting(
    "ADMIN_SESSION_IDLE_TIMEOUT_SECS",
    Section::Admin,
    RiskCode::CookieOrCsrfWeakened,
    Rule::HigherIsLooser,
);
static ADMIN_SESSION_MAX_ENTRIES: Field = limit("ADMIN_SESSION_MAX_ENTRIES", Section::Admin);
static ADMIN_LOGIN_PENDING_TTL_SECS: Field = limit("ADMIN_LOGIN_PENDING_TTL_SECS", Section::Admin);
static ADMIN_LOGIN_PENDING_MAX_ENTRIES: Field =
    limit("ADMIN_LOGIN_PENDING_MAX_ENTRIES", Section::Admin);
static ADMIN_LOGIN_PENDING_MAX_PER_IP: Field =
    limit("ADMIN_LOGIN_PENDING_MAX_PER_IP", Section::Admin);
static GATEWAY_PUBLIC_URL: Field = setting(
    "GATEWAY_PUBLIC_URL",
    Section::BrowserSecurity,
    RiskCode::PublicOriginChanged,
    Rule::AnyChange,
);

// Authentication.
static RBAC_EXEMPT_PATHS: Field = setting(
    "RBAC_EXEMPT_PATHS",
    Section::Authentication,
    RiskCode::ExemptionsBroadened,
    Rule::GrowthIsLooser,
);
static AUTH_ENABLED: Field = setting(
    "AUTH_ENABLED",
    Section::Authentication,
    RiskCode::AuthDisabled,
    Rule::LooserWhen(false),
);
static AUTH_MODE: Field = setting(
    "AUTH_MODE",
    Section::Authentication,
    RiskCode::AuthObserveOnly,
    Rule::Ranked(&["required", "observe"]),
);
static AUTH_COOKIE_NAME: Field = neutral("AUTH_COOKIE_NAME", Section::BrowserSecurity);
static AUTH_EXEMPT_PATHS: Field = setting(
    "AUTH_EXEMPT_PATHS",
    Section::Authentication,
    RiskCode::ExemptionsBroadened,
    Rule::GrowthIsLooser,
);
static AUTH_PROVIDERS: Field = setting(
    "AUTH_PROVIDERS",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static JWT_JWKS_URL: Field = setting(
    "JWT_JWKS_URL",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static JWT_ISSUER: Field = setting(
    "JWT_ISSUER",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static JWT_AUDIENCE: Field = setting(
    "JWT_AUDIENCE",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static JWT_JWKS_TIMEOUT_MS: Field = limit("JWT_JWKS_TIMEOUT_MS", Section::Authentication);
static JWT_JWKS_MAX_KEY_AGE_SECS: Field = setting(
    "JWT_JWKS_MAX_KEY_AGE_SECS",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::HigherIsLooser,
);
static JWT_REQUIRE_JTI: Field = setting(
    "JWT_REQUIRE_JTI",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::LooserWhen(false),
);
static ROLES_CLAIM: Field = setting(
    "ROLES_CLAIM",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static SERVICE_TOKEN_SQLITE_PATH: Field = setting(
    "SERVICE_TOKEN_SQLITE_PATH",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::AnyChange,
);
static SERVICE_TOKEN_CACHE_TTL_MS: Field = setting(
    "SERVICE_TOKEN_CACHE_TTL_MS",
    Section::Authentication,
    RiskCode::AuthTrustChanged,
    Rule::HigherIsLooser,
);

// Browser security.
static CSRF_ENABLED: Field = setting(
    "CSRF_ENABLED",
    Section::BrowserSecurity,
    RiskCode::CookieOrCsrfWeakened,
    Rule::LooserWhen(false),
);
static CSRF_COOKIE_NAME: Field = neutral("CSRF_COOKIE_NAME", Section::BrowserSecurity);
static CSRF_HEADER_NAME: Field = neutral("CSRF_HEADER_NAME", Section::BrowserSecurity);
static CSRF_COOKIE_DOMAIN: Field = setting(
    "CSRF_COOKIE_DOMAIN",
    Section::BrowserSecurity,
    RiskCode::CookieOrCsrfWeakened,
    Rule::AnyChange,
);
static CSRF_EXEMPT_PATHS: Field = setting(
    "CSRF_EXEMPT_PATHS",
    Section::BrowserSecurity,
    RiskCode::ExemptionsBroadened,
    Rule::GrowthIsLooser,
);
static CORS_ALLOW_ORIGINS: Field = setting(
    "CORS_ALLOW_ORIGINS",
    Section::BrowserSecurity,
    RiskCode::CorsBroadened,
    Rule::GrowthIsLooser,
);

// Proxy trust and routing.
static TRUST_PROXY_HEADERS: Field = setting(
    "TRUST_PROXY_HEADERS",
    Section::ProxyTrust,
    RiskCode::TrustedProxiesChanged,
    Rule::LooserWhen(true),
);
static TRUSTED_PROXY_CIDRS: Field = setting(
    "TRUSTED_PROXY_CIDRS",
    Section::ProxyTrust,
    RiskCode::TrustedProxiesChanged,
    Rule::GrowthIsLooser,
);
static UPSTREAM_URL: Field = setting(
    "UPSTREAM_URL",
    Section::Routing,
    RiskCode::RoutingChanged,
    Rule::AnyChange,
);
static UPSTREAM_ROUTES: Field = setting(
    "UPSTREAM_ROUTES",
    Section::Routing,
    RiskCode::RoutingChanged,
    Rule::AnyChange,
);
static MCP_UPSTREAM_SERVERS: Field = setting(
    "MCP_UPSTREAM_SERVERS",
    Section::Routing,
    RiskCode::RoutingChanged,
    Rule::AnyChange,
);
static UPSTREAM_TIMEOUT_MS: Field = limit("UPSTREAM_TIMEOUT_MS", Section::Routing);
static UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS: Field =
    limit("UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS", Section::Routing);
static UPSTREAM_CONNECT_TIMEOUT_MS: Field = limit("UPSTREAM_CONNECT_TIMEOUT_MS", Section::Routing);

// Egress.
static EGRESS_ALLOWED_HOSTS: Field = setting(
    "EGRESS_ALLOWED_HOSTS",
    Section::Egress,
    RiskCode::EgressBroadened,
    Rule::GrowthIsLooser,
);
static EGRESS_TIMEOUT_MS: Field = limit("EGRESS_TIMEOUT_MS", Section::Egress);
static EGRESS_RESPONSE_IDLE_TIMEOUT_MS: Field =
    limit("EGRESS_RESPONSE_IDLE_TIMEOUT_MS", Section::Egress);
static EGRESS_CONNECT_TIMEOUT_MS: Field = limit("EGRESS_CONNECT_TIMEOUT_MS", Section::Egress);
static EGRESS_MAX_RESPONSE_BYTES: Field = limit("EGRESS_MAX_RESPONSE_BYTES", Section::Egress);
static EGRESS_MAX_REQUEST_BODY_BYTES: Field =
    limit("EGRESS_MAX_REQUEST_BODY_BYTES", Section::Egress);
// A network-specific prefix decodes the IPv4 address embedded in matching
// IPv6 destinations before the private-address check. Whether that admits or
// refuses more destinations depends on the prefix, so no direction is safe.
static EGRESS_NAT64_PREFIXES: Field = setting(
    "EGRESS_NAT64_PREFIXES",
    Section::Egress,
    RiskCode::PrivateEgressAllowed,
    Rule::Unclassified,
);
static EGRESS_DENY_PRIVATE_IPS: Field = setting(
    "EGRESS_DENY_PRIVATE_IPS",
    Section::Egress,
    RiskCode::PrivateEgressAllowed,
    Rule::LooserWhen(false),
);

// Request bounds and rate limits.
static MAX_BODY_SIZE: Field = limit("MAX_BODY_SIZE", Section::Limits);
static MAX_REQUEST_PATH_BYTES: Field = limit("MAX_REQUEST_PATH_BYTES", Section::Limits);
static RATE_LIMIT_READ_RPS: Field = limit("RATE_LIMIT_READ_RPS", Section::Limits);
static RATE_LIMIT_READ_BURST: Field = limit("RATE_LIMIT_READ_BURST", Section::Limits);
static RATE_LIMIT_WRITE_RPS: Field = limit("RATE_LIMIT_WRITE_RPS", Section::Limits);
static RATE_LIMIT_WRITE_BURST: Field = limit("RATE_LIMIT_WRITE_BURST", Section::Limits);
// Under cardinality pressure the limiter recycles a bucket, forgetting the
// tokens it spent: fewer buckets, or buckets preferred for recycling sooner,
// let a caller with many identities reset its own limits sooner.
static RATE_LIMIT_MAX_BUCKETS: Field = setting(
    "RATE_LIMIT_MAX_BUCKETS",
    Section::Limits,
    RiskCode::LimitsLoosened,
    Rule::LowerIsLooser,
);
static RATE_LIMIT_BUCKET_TTL_MS: Field = setting(
    "RATE_LIMIT_BUCKET_TTL_MS",
    Section::Limits,
    RiskCode::LimitsLoosened,
    Rule::LowerIsLooser,
);
static VALIDATION_ALLOWED_CONTENT_TYPES: Field = setting(
    "VALIDATION_ALLOWED_CONTENT_TYPES",
    Section::Limits,
    RiskCode::LimitsLoosened,
    Rule::GrowthIsLooser,
);
static TOOL_RUNTIME_QUEUE_DEPTH: Field = limit("TOOL_RUNTIME_QUEUE_DEPTH", Section::Limits);
static TOOL_RUNTIME_GLOBAL_CONCURRENCY: Field =
    limit("TOOL_RUNTIME_GLOBAL_CONCURRENCY", Section::Limits);
static TOOL_RUNTIME_QUEUE_TIMEOUT_MS: Field =
    limit("TOOL_RUNTIME_QUEUE_TIMEOUT_MS", Section::Limits);
static TOOL_RUNTIME_DEFAULT_TIMEOUT_MS: Field =
    limit("TOOL_RUNTIME_DEFAULT_TIMEOUT_MS", Section::Limits);

// Audit, shutdown and authority events.
static AUDIT_LOG_FILE: Field = setting(
    "AUDIT_LOG_FILE",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::AbsenceIsLooser,
);
static AUDIT_SQLITE_PATH: Field = setting(
    "AUDIT_SQLITE_PATH",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::AbsenceIsLooser,
);
static AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY: Field = setting(
    "AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LooserWhen(true),
);
static AUDIT_SQLITE_RETENTION_DAYS: Field = setting(
    "AUDIT_SQLITE_RETENTION_DAYS",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);
static AUDIT_POSTGRES_RETENTION_DAYS: Field = setting(
    "AUDIT_POSTGRES_RETENTION_DAYS",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);
static AUDIT_DRAIN_TIMEOUT_MS: Field = setting(
    "AUDIT_DRAIN_TIMEOUT_MS",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);
static AUDIT_DURABILITY: Field = setting(
    "AUDIT_DURABILITY",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::Ranked(&["required", "best_effort"]),
);
static AUDIT_DURABILITY_TIMEOUT_MS: Field = limit("AUDIT_DURABILITY_TIMEOUT_MS", Section::Audit);
static SHUTDOWN_DRAIN_DELAY_MS: Field = neutral("SHUTDOWN_DRAIN_DELAY_MS", Section::Lifecycle);
static SHUTDOWN_TIMEOUT_MS: Field = neutral("SHUTDOWN_TIMEOUT_MS", Section::Lifecycle);
static AUTHORITY_EVENT_SINK: Field = setting(
    "AUTHORITY_EVENT_SINK",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::Ranked(&["file", "log", "none"]),
);
static AUTHORITY_EVENT_FILE: Field = neutral("AUTHORITY_EVENT_FILE", Section::Audit);
static AUTHORITY_PSEUDONYM_KEY_ALIAS: Field =
    credential("AUTHORITY_PSEUDONYM_KEY_ALIAS", Section::Audit);
static AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS: Field =
    credential("AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS", Section::Audit);
static AUTHORITY_EVENT_JOURNAL_CAPACITY: Field = setting(
    "AUTHORITY_EVENT_JOURNAL_CAPACITY",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);
static AUTHORITY_EVENT_RETENTION_HOURS: Field = setting(
    "AUTHORITY_EVENT_RETENTION_HOURS",
    Section::Audit,
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);

// Observability.
static PAYLOAD_CAPTURE_ENABLED: Field = setting(
    "PAYLOAD_CAPTURE_ENABLED",
    Section::Observability,
    RiskCode::DataExposureIncreased,
    Rule::LooserWhen(true),
);
static PAYLOAD_CAPTURE_SAMPLE_RATE: Field = setting(
    "PAYLOAD_CAPTURE_SAMPLE_RATE",
    Section::Observability,
    RiskCode::DataExposureIncreased,
    Rule::HigherIsLooser,
);
static SCHEMA_MISMATCH_SIGNAL_THRESHOLD: Field =
    neutral("SCHEMA_MISMATCH_SIGNAL_THRESHOLD", Section::Observability);
static ERROR_RATE_SPIKE_SIGNAL_THRESHOLD: Field =
    neutral("ERROR_RATE_SPIKE_SIGNAL_THRESHOLD", Section::Observability);
static PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD: Field = neutral(
    "PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD",
    Section::Observability,
);
static VOLUME_OUTLIER_SIGNAL_THRESHOLD: Field =
    neutral("VOLUME_OUTLIER_SIGNAL_THRESHOLD", Section::Observability);
static RULE_SUGGESTION_BASELINE_WINDOW_HOURS: Field = neutral(
    "RULE_SUGGESTION_BASELINE_WINDOW_HOURS",
    Section::Observability,
);
static CLUSTER_STATUS_EXPOSE_HOSTNAMES: Field = setting(
    "CLUSTER_STATUS_EXPOSE_HOSTNAMES",
    Section::Observability,
    RiskCode::DataExposureIncreased,
    Rule::LooserWhen(true),
);

// Stores, documents and cluster coordination.
static DISCOVERY_SQLITE_PATH: Field = setting(
    "DISCOVERY_SQLITE_PATH",
    Section::Storage,
    RiskCode::StorageChanged,
    Rule::AnyChange,
);
static DISCOVERY_ENDPOINT_LIMIT: Field = limit("DISCOVERY_ENDPOINT_LIMIT", Section::Storage);
static DISCOVERY_PROJECTOR_LEASE_TTL_MS: Field =
    neutral("DISCOVERY_PROJECTOR_LEASE_TTL_MS", Section::Cluster);
static DISCOVERY_PROJECTOR_POLL_MS: Field =
    neutral("DISCOVERY_PROJECTOR_POLL_MS", Section::Cluster);
static DISCOVERY_PROJECTOR_BATCH: Field = neutral("DISCOVERY_PROJECTOR_BATCH", Section::Cluster);
static PRINCIPAL_SQLITE_PATH: Field = setting(
    "PRINCIPAL_SQLITE_PATH",
    Section::Storage,
    RiskCode::StorageChanged,
    Rule::AnyChange,
);
static OPENAPI_SPEC_PATH: Field = setting(
    "OPENAPI_SPEC_PATH",
    Section::Tools,
    RiskCode::ToolSurfaceBroadened,
    Rule::PresenceIsLooser,
);
// Without a policy file no policy is enforced at all; another file is
// another policy, which this diff cannot see.
static POLICY_FILE: Field = setting(
    "POLICY_FILE",
    Section::Policy,
    RiskCode::PolicyDefaultAllow,
    Rule::AbsenceIsLooser,
);
static TOOLS_FILE: Field = setting(
    "TOOLS_FILE",
    Section::Tools,
    RiskCode::ToolSurfaceBroadened,
    Rule::PresenceIsLooser,
);
static POLICY_HISTORY_SQLITE_PATH: Field = setting(
    "POLICY_HISTORY_SQLITE_PATH",
    Section::Storage,
    RiskCode::StorageChanged,
    Rule::AnyChange,
);
static TOOL_LEASE_TTL_MS: Field = neutral("TOOL_LEASE_TTL_MS", Section::Cluster);
static CLUSTER_HEARTBEAT_MS: Field = neutral("CLUSTER_HEARTBEAT_MS", Section::Cluster);
static CLUSTER_MEMBER_STALE_MS: Field = neutral("CLUSTER_MEMBER_STALE_MS", Section::Cluster);
static CLUSTER_MAINTENANCE_INTERVAL_MS: Field =
    neutral("CLUSTER_MAINTENANCE_INTERVAL_MS", Section::Cluster);
static CLUSTER_MAINTENANCE_LEASE_TTL_MS: Field =
    neutral("CLUSTER_MAINTENANCE_LEASE_TTL_MS", Section::Cluster);
static READINESS_PROBE_CACHE_MS: Field = neutral("READINESS_PROBE_CACHE_MS", Section::Cluster);
static STATE_BACKEND: Field = Field {
    id: "STATE_BACKEND",
    section: Section::Storage,
    class: ChangeClass::ClusterOperation,
    risk: RiskCode::StorageChanged,
    rule: Rule::AnyChange,
};
static DEPLOYMENT_ID: Field = Field {
    id: "DEPLOYMENT_ID",
    section: Section::Cluster,
    class: ChangeClass::ClusterOperation,
    risk: RiskCode::StorageChanged,
    rule: Rule::AnyChange,
};

// PostgreSQL.
static DATABASE_URL_FILE: Field = credential("DATABASE_URL_FILE", Section::Storage);
static DATABASE_TLS_MODE: Field = setting(
    "DATABASE_TLS_MODE",
    Section::Storage,
    RiskCode::PlaintextTransport,
    Rule::Ranked(&["verify", "loopback-dev"]),
);
static DATABASE_TLS_CA_FILE: Field = setting(
    "DATABASE_TLS_CA_FILE",
    Section::Storage,
    RiskCode::StorageChanged,
    Rule::AnyChange,
);
static DATABASE_POOL_MAX: Field = neutral("DATABASE_POOL_MAX", Section::Storage);
static DATABASE_CONNECT_TIMEOUT_MS: Field = limit("DATABASE_CONNECT_TIMEOUT_MS", Section::Storage);
static DATABASE_ACQUIRE_TIMEOUT_MS: Field = limit("DATABASE_ACQUIRE_TIMEOUT_MS", Section::Storage);
static DATABASE_STATEMENT_TIMEOUT_MS: Field =
    limit("DATABASE_STATEMENT_TIMEOUT_MS", Section::Storage);
static DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS: Field =
    limit("DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS", Section::Storage);
static DATABASE_LOCK_TIMEOUT_MS: Field = limit("DATABASE_LOCK_TIMEOUT_MS", Section::Storage);
static DATABASE_STARTUP_RETRY_LIMIT: Field =
    neutral("DATABASE_STARTUP_RETRY_LIMIT", Section::Storage);
static DATABASE_AUTO_MIGRATE: Field = setting(
    "DATABASE_AUTO_MIGRATE",
    Section::Storage,
    RiskCode::StorageChanged,
    Rule::LooserWhen(true),
);
static DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS: Field =
    limit("DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS", Section::Storage);

// Connections, secret providers and keyrings.
static CONNECTIONS_SQLITE_PATH: Field = setting(
    "CONNECTIONS_SQLITE_PATH",
    Section::Connections,
    RiskCode::StorageChanged,
    Rule::AnyChange,
);
static CONNECTION_SECRETS_ROOT: Field = credential("CONNECTION_SECRETS_ROOT", Section::Connections);
static CONNECTION_SECRET_ALIASES: Field =
    credential("CONNECTION_SECRET_ALIASES", Section::Connections);
static CONNECTION_LOCAL_SECRET_KEYRING: Field =
    credential("CONNECTION_LOCAL_SECRET_KEYRING", Section::Connections);
static ADMIN_LOGIN_KEYRING: Field = credential("ADMIN_LOGIN_KEYRING", Section::Admin);
static RATE_LIMIT_KEYRING: Field = credential("RATE_LIMIT_KEYRING", Section::Limits);
static CONNECTION_VAULT_PROVIDER: Field =
    credential("CONNECTION_VAULT_PROVIDER", Section::Connections);
static CONNECTION_GCP_PROVIDER: Field = credential("CONNECTION_GCP_PROVIDER", Section::Connections);
static CONNECTION_AZURE_PROVIDER: Field =
    credential("CONNECTION_AZURE_PROVIDER", Section::Connections);
static CONNECTION_AWS_PROVIDER: Field = credential("CONNECTION_AWS_PROVIDER", Section::Connections);
static CONNECTION_KUBERNETES_PROVIDER: Field =
    credential("CONNECTION_KUBERNETES_PROVIDER", Section::Connections);

/// Every setting [`plans`] compares; a test holds it to `CONFIG_INPUTS`.
pub(crate) static SETTINGS: &[&Field] = &[
    &LISTEN_ADDR,
    &ADMIN_LISTEN_ADDR,
    &GRPC_LISTEN_ADDR,
    &GRPC_MAX_CONCURRENT_STREAMS,
    &GRPC_MAX_METADATA_BYTES,
    &TLS_CERT_FILE,
    &TLS_KEY_FILE,
    &ADMIN_TLS_CERT_FILE,
    &ADMIN_TLS_KEY_FILE,
    &TLS_MIN_VERSION,
    &TLS_HANDSHAKE_TIMEOUT_MS,
    &TLS_MAX_CONCURRENT_HANDSHAKES,
    &CLIENT_CERT_IDENTITY_SOURCE,
    &CLIENT_CERT_MODE,
    &ADMIN_CLIENT_CERT_MODE,
    &CLIENT_CERT_CA_FILE,
    &CLIENT_CERT_CRL_FILE,
    &ADMIN_CLIENT_CERT_CA_FILE,
    &ADMIN_CLIENT_CERT_CRL_FILE,
    &ADMIN_PREFIX,
    &ADMIN_LOGIN_PROVIDER,
    &ADMIN_SESSION_MODE,
    &ADMIN_SESSION_TTL_SECS,
    &ADMIN_SESSION_IDLE_TIMEOUT_SECS,
    &ADMIN_SESSION_MAX_ENTRIES,
    &ADMIN_LOGIN_PENDING_TTL_SECS,
    &ADMIN_LOGIN_PENDING_MAX_ENTRIES,
    &ADMIN_LOGIN_PENDING_MAX_PER_IP,
    &GATEWAY_PUBLIC_URL,
    &AUDIT_LOG_FILE,
    &AUDIT_SQLITE_PATH,
    &AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
    &AUDIT_SQLITE_RETENTION_DAYS,
    &SHUTDOWN_DRAIN_DELAY_MS,
    &SHUTDOWN_TIMEOUT_MS,
    &AUDIT_DRAIN_TIMEOUT_MS,
    &AUDIT_DURABILITY,
    &AUDIT_DURABILITY_TIMEOUT_MS,
    &DISCOVERY_SQLITE_PATH,
    &DISCOVERY_ENDPOINT_LIMIT,
    &DISCOVERY_PROJECTOR_LEASE_TTL_MS,
    &DISCOVERY_PROJECTOR_POLL_MS,
    &DISCOVERY_PROJECTOR_BATCH,
    &PRINCIPAL_SQLITE_PATH,
    &CONNECTIONS_SQLITE_PATH,
    &CONNECTION_SECRETS_ROOT,
    &CONNECTION_SECRET_ALIASES,
    &CONNECTION_LOCAL_SECRET_KEYRING,
    &ADMIN_LOGIN_KEYRING,
    &RATE_LIMIT_KEYRING,
    &CONNECTION_VAULT_PROVIDER,
    &CONNECTION_GCP_PROVIDER,
    &CONNECTION_AZURE_PROVIDER,
    &CONNECTION_AWS_PROVIDER,
    &CONNECTION_KUBERNETES_PROVIDER,
    &PAYLOAD_CAPTURE_ENABLED,
    &PAYLOAD_CAPTURE_SAMPLE_RATE,
    &SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
    &ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
    &PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
    &VOLUME_OUTLIER_SIGNAL_THRESHOLD,
    &RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
    &OPENAPI_SPEC_PATH,
    &POLICY_FILE,
    &TOOLS_FILE,
    &POLICY_HISTORY_SQLITE_PATH,
    &CORS_ALLOW_ORIGINS,
    &MAX_BODY_SIZE,
    &MAX_REQUEST_PATH_BYTES,
    &RATE_LIMIT_READ_RPS,
    &RATE_LIMIT_READ_BURST,
    &RATE_LIMIT_WRITE_RPS,
    &RATE_LIMIT_WRITE_BURST,
    &RATE_LIMIT_MAX_BUCKETS,
    &RATE_LIMIT_BUCKET_TTL_MS,
    &TRUST_PROXY_HEADERS,
    &TRUSTED_PROXY_CIDRS,
    &RBAC_EXEMPT_PATHS,
    &VALIDATION_ALLOWED_CONTENT_TYPES,
    &AUTH_ENABLED,
    &AUTH_MODE,
    &AUTH_COOKIE_NAME,
    &AUTH_EXEMPT_PATHS,
    &JWT_JWKS_URL,
    &JWT_ISSUER,
    &JWT_AUDIENCE,
    &JWT_JWKS_TIMEOUT_MS,
    &JWT_JWKS_MAX_KEY_AGE_SECS,
    &JWT_REQUIRE_JTI,
    &ROLES_CLAIM,
    &SERVICE_TOKEN_SQLITE_PATH,
    &SERVICE_TOKEN_CACHE_TTL_MS,
    &TOOL_RUNTIME_QUEUE_DEPTH,
    &TOOL_RUNTIME_GLOBAL_CONCURRENCY,
    &TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    &TOOL_LEASE_TTL_MS,
    &CLUSTER_HEARTBEAT_MS,
    &CLUSTER_MEMBER_STALE_MS,
    &CLUSTER_MAINTENANCE_INTERVAL_MS,
    &CLUSTER_MAINTENANCE_LEASE_TTL_MS,
    &READINESS_PROBE_CACHE_MS,
    &CLUSTER_STATUS_EXPOSE_HOSTNAMES,
    &AUDIT_POSTGRES_RETENTION_DAYS,
    &TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
    &AUTH_PROVIDERS,
    &CSRF_ENABLED,
    &CSRF_COOKIE_NAME,
    &CSRF_HEADER_NAME,
    &CSRF_COOKIE_DOMAIN,
    &CSRF_EXEMPT_PATHS,
    &UPSTREAM_URL,
    &UPSTREAM_ROUTES,
    &MCP_UPSTREAM_SERVERS,
    &UPSTREAM_TIMEOUT_MS,
    &UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
    &UPSTREAM_CONNECT_TIMEOUT_MS,
    &EGRESS_ALLOWED_HOSTS,
    &EGRESS_TIMEOUT_MS,
    &EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
    &EGRESS_CONNECT_TIMEOUT_MS,
    &EGRESS_MAX_RESPONSE_BYTES,
    &EGRESS_MAX_REQUEST_BODY_BYTES,
    &EGRESS_NAT64_PREFIXES,
    &EGRESS_DENY_PRIVATE_IPS,
    &STATE_BACKEND,
    &DEPLOYMENT_ID,
    &DATABASE_URL_FILE,
    &DATABASE_TLS_MODE,
    &DATABASE_TLS_CA_FILE,
    &DATABASE_POOL_MAX,
    &DATABASE_CONNECT_TIMEOUT_MS,
    &DATABASE_ACQUIRE_TIMEOUT_MS,
    &DATABASE_STATEMENT_TIMEOUT_MS,
    &DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    &DATABASE_LOCK_TIMEOUT_MS,
    &DATABASE_STARTUP_RETRY_LIMIT,
    &DATABASE_AUTO_MIGRATE,
    &DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
    &AUTHORITY_EVENT_SINK,
    &AUTHORITY_EVENT_FILE,
    &AUTHORITY_PSEUDONYM_KEY_ALIAS,
    &AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
    &AUTHORITY_EVENT_JOURNAL_CAPACITY,
    &AUTHORITY_EVENT_RETENTION_HOURS,
];

// --- Domains ----------------------------------------------------------------
//
// Each function binds every field of the base plan by name and compares it
// with the candidate's: a field added to a plan does not compile until it is
// named here, and is an unused binding, which CI's warnings-as-errors builds
// refuse, until it is compared. Provenance says where a
// value came from, not what it is, so it is not compared.

fn compare_listeners(c: &mut Comparison, base: &ListenerPlan, candidate: &ListenerPlan) {
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
    } = base;
    // The data listener always exists; the gRPC listener is opened only
    // when configured; without its own listener the admin surface is served
    // on the data listener, so moving it to or from one is `unknown`.
    if *listen_addr != candidate.listen_addr {
        let (before, after) = (listen_addr.ip(), candidate.listen_addr.ip());
        listener(
            c,
            &LISTEN_ADDR,
            Some(Reach::of(before.is_loopback(), before.is_unspecified())),
            Some(Reach::of(after.is_loopback(), after.is_unspecified())),
            before == after,
        );
    }
    for (field, before, after, shared) in [
        (
            &ADMIN_LISTEN_ADDR,
            admin_listen_addr,
            &candidate.admin_listen_addr,
            true,
        ),
        (
            &GRPC_LISTEN_ADDR,
            grpc_listen_addr,
            &candidate.grpc_listen_addr,
            false,
        ),
    ] {
        if before == after {
            continue;
        }
        let same_ip = matches!((before, after), (Some(b), Some(a)) if b.ip() == a.ip());
        if shared && before.is_some() != after.is_some() {
            c.record(
                field,
                ChangeKind::of(before.as_ref(), after.as_ref()),
                &[Impact::Unknown],
                Display::Withheld,
                None,
            );
        } else {
            let before = before.map(|address| {
                Reach::of(address.ip().is_loopback(), address.ip().is_unspecified())
            });
            let after = after.map(|address| {
                Reach::of(address.ip().is_loopback(), address.ip().is_unspecified())
            });
            listener(c, field, before, after, same_ip);
        }
    }
    c.count(
        &GRPC_MAX_CONCURRENT_STREAMS,
        Some(u64::from(*grpc_max_concurrent_streams)),
        Some(u64::from(candidate.grpc_max_concurrent_streams)),
    );
    c.count(
        &GRPC_MAX_METADATA_BYTES,
        Some(u64::from(*grpc_max_metadata_bytes)),
        Some(u64::from(candidate.grpc_max_metadata_bytes)),
    );
    tls(
        c,
        (&TLS_CERT_FILE, &TLS_KEY_FILE),
        data_tls.as_ref(),
        candidate.data_tls.as_ref(),
    );
    tls(
        c,
        (&ADMIN_TLS_CERT_FILE, &ADMIN_TLS_KEY_FILE),
        admin_tls.as_ref(),
        candidate.admin_tls.as_ref(),
    );
    c.word(
        &TLS_MIN_VERSION,
        tls_min_version.as_str(),
        candidate.tls_min_version.as_str(),
    );
    c.count(
        &TLS_HANDSHAKE_TIMEOUT_MS,
        Some(*tls_handshake_timeout_ms),
        Some(candidate.tls_handshake_timeout_ms),
    );
    c.count(
        &TLS_MAX_CONCURRENT_HANDSHAKES,
        Some(*tls_max_concurrent_handshakes as u64),
        Some(candidate.tls_max_concurrent_handshakes as u64),
    );
    client_certificates(
        c,
        (
            &CLIENT_CERT_MODE,
            &CLIENT_CERT_CA_FILE,
            &CLIENT_CERT_CRL_FILE,
        ),
        client_cert_auth.as_ref(),
        candidate.client_cert_auth.as_ref(),
    );
    client_certificates(
        c,
        (
            &ADMIN_CLIENT_CERT_MODE,
            &ADMIN_CLIENT_CERT_CA_FILE,
            &ADMIN_CLIENT_CERT_CRL_FILE,
        ),
        admin_client_cert_auth.as_ref(),
        candidate.admin_client_cert_auth.as_ref(),
    );
    // One identity source serves both listeners; it means nothing while
    // neither asks for certificates.
    let source = |data: &Option<InboundClientAuthConfig>,
                  admin: &Option<InboundClientAuthConfig>| {
        data.as_ref()
            .or(admin.as_ref())
            .map(|auth| auth.identity_source.as_str())
    };
    if let (Some(before), Some(after)) = (
        source(client_cert_auth, admin_client_cert_auth),
        source(
            &candidate.client_cert_auth,
            &candidate.admin_client_cert_auth,
        ),
    ) {
        c.word(&CLIENT_CERT_IDENTITY_SOURCE, before, after);
    }
}

/// How far a listener reaches.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Reach {
    Loopback,
    /// One address beyond loopback.
    Address,
    /// Every address of the host.
    Everywhere,
}

impl Reach {
    fn of(loopback: bool, unspecified: bool) -> Self {
        if loopback {
            Self::Loopback
        } else if unspecified {
            Self::Everywhere
        } else {
            Self::Address
        }
    }
}

/// A listener that is opened, closed or moved: reaching further loosens,
/// a loopback listener opened adds no exposure, and a move between two
/// addresses of the same reach is `unknown` unless only the port changed.
fn listener(
    c: &mut Comparison,
    field: &'static Field,
    base: Option<Reach>,
    candidate: Option<Reach>,
    same_ip: bool,
) {
    let impact = match (base, candidate) {
        (None, None) => return,
        (None, Some(Reach::Loopback)) => Impact::Neutral,
        (None, Some(_)) => Impact::Loosened(RiskCode::ListenerExposed),
        (Some(_), None) => Impact::Tightened,
        (Some(before), Some(after)) if after > before => {
            Impact::Loosened(RiskCode::ListenerExposed)
        }
        (Some(before), Some(after)) if after < before => Impact::Tightened,
        (Some(reach), Some(_)) if same_ip || reach != Reach::Address => Impact::Neutral,
        (Some(_), Some(_)) => Impact::Unknown,
    };
    c.record(
        field,
        ChangeKind::of(base, candidate),
        &[impact],
        Display::Withheld,
        None,
    );
}

/// A listener's TLS material: removing it serves plaintext, a changed
/// certificate path is neutral, and the private key is a credential.
fn tls(
    c: &mut Comparison,
    (certificate, key): (&'static Field, &'static Field),
    base: Option<&TlsMaterial>,
    candidate: Option<&TlsMaterial>,
) {
    c.value(
        certificate,
        base.map(|tls| &tls.certificate_files),
        candidate.map(|tls| &tls.certificate_files),
    );
    c.secret(
        key,
        base.map(|tls| &tls.private_key_files),
        candidate.map(|tls| &tls.private_key_files),
    );
}

fn client_certificates(
    c: &mut Comparison,
    (mode, ca, crl): (&'static Field, &'static Field, &'static Field),
    base: Option<&InboundClientAuthConfig>,
    candidate: Option<&InboundClientAuthConfig>,
) {
    let word = |auth: Option<&InboundClientAuthConfig>| match auth.map(|auth| auth.requirement) {
        None => "off",
        Some(ClientCertRequirement::Optional) => "optional",
        Some(ClientCertRequirement::Required) => "required",
    };
    c.word(mode, word(base), word(candidate));
    c.value(
        ca,
        base.map(|auth| &auth.ca_file),
        candidate.map(|auth| &auth.ca_file),
    );
    c.value(
        crl,
        base.and_then(|auth| auth.crl_file.as_ref()),
        candidate.and_then(|auth| auth.crl_file.as_ref()),
    );
}

fn compare_identity(c: &mut Comparison, base: &IdentityPlan, candidate: &IdentityPlan) {
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
    } = base;
    c.value(
        &ADMIN_PREFIX,
        Some(admin_prefix),
        Some(&candidate.admin_prefix),
    );
    c.value(
        &ADMIN_LOGIN_PROVIDER,
        admin_login_provider.as_ref(),
        candidate.admin_login_provider.as_ref(),
    );
    // Turning admin sessions on adds a cookie-authenticated admin path;
    // moving them to another store is `unknown`. Their lifetimes are
    // compared only while both sides have them.
    let mode = |plan: &IdentityPlan| plan.admin_session.as_ref().map(|s| s.storage.as_str());
    match (mode(base), mode(candidate)) {
        (Some(before), Some(after)) if before != after => c.record(
            &ADMIN_SESSION_MODE,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        ),
        (before, after) => c.value(&ADMIN_SESSION_MODE, before, after),
    }
    if let (Some(before), Some(after)) = (admin_session, &candidate.admin_session) {
        c.count(
            &ADMIN_SESSION_TTL_SECS,
            Some(before.ttl.as_secs()),
            Some(after.ttl.as_secs()),
        );
        c.count(
            &ADMIN_SESSION_IDLE_TIMEOUT_SECS,
            Some(before.idle_timeout.as_secs()),
            Some(after.idle_timeout.as_secs()),
        );
        c.count(
            &ADMIN_SESSION_MAX_ENTRIES,
            Some(before.max_entries as u64),
            Some(after.max_entries as u64),
        );
    }
    c.count(
        &ADMIN_LOGIN_PENDING_TTL_SECS,
        Some(*admin_login_pending_ttl_secs),
        Some(candidate.admin_login_pending_ttl_secs),
    );
    c.count(
        &ADMIN_LOGIN_PENDING_MAX_ENTRIES,
        Some(*admin_login_pending_max_entries as u64),
        Some(candidate.admin_login_pending_max_entries as u64),
    );
    c.count(
        &ADMIN_LOGIN_PENDING_MAX_PER_IP,
        Some(*admin_login_pending_max_per_ip as u64),
        Some(candidate.admin_login_pending_max_per_ip as u64),
    );
    c.value(
        &GATEWAY_PUBLIC_URL,
        gateway_public_url.as_ref(),
        candidate.gateway_public_url.as_ref(),
    );
    c.set(
        &RBAC_EXEMPT_PATHS,
        rbac_exempt_paths,
        &candidate.rbac_exempt_paths,
    );
    c.flag(&AUTH_ENABLED, *auth_enabled, candidate.auth_enabled);
    c.word(
        &AUTH_MODE,
        auth_mode_word(auth_mode),
        auth_mode_word(&candidate.auth_mode),
    );
    c.value(
        &AUTH_COOKIE_NAME,
        Some(auth_cookie_name),
        Some(&candidate.auth_cookie_name),
    );
    c.set(
        &AUTH_EXEMPT_PATHS,
        auth_exempt_paths,
        &candidate.auth_exempt_paths,
    );
    // Providers are keyed by their unique names. A provider carries its
    // client secret, so the collection is reported as a reference. Removing
    // one trusts fewer issuers; adding or changing one is a trust change.
    let (before, after) = (
        providers_by_name(auth_providers),
        providers_by_name(&candidate.auth_providers),
    );
    if before.len() == auth_providers.len() && after.len() == candidate.auth_providers.len() {
        c.entries(
            &AUTH_PROVIDERS,
            Redaction::Reference,
            &before,
            &after,
            |before, after| match (before, after) {
                (Some(_), None) => vec![Impact::Tightened],
                _ => vec![Impact::Loosened(RiskCode::AuthTrustChanged)],
            },
        );
    } else {
        c.secret(
            &AUTH_PROVIDERS,
            Some(auth_providers),
            Some(&candidate.auth_providers),
        );
    }
    c.value(
        &JWT_JWKS_URL,
        jwt_jwks_url.as_ref(),
        candidate.jwt_jwks_url.as_ref(),
    );
    c.value(
        &JWT_ISSUER,
        jwt_issuer.as_ref(),
        candidate.jwt_issuer.as_ref(),
    );
    c.value(
        &JWT_AUDIENCE,
        jwt_audience.as_ref(),
        candidate.jwt_audience.as_ref(),
    );
    c.count(
        &JWT_JWKS_TIMEOUT_MS,
        Some(*jwt_jwks_timeout_ms),
        Some(candidate.jwt_jwks_timeout_ms),
    );
    c.count(
        &JWT_JWKS_MAX_KEY_AGE_SECS,
        Some(*jwt_jwks_max_key_age_secs),
        Some(candidate.jwt_jwks_max_key_age_secs),
    );
    c.flag(
        &JWT_REQUIRE_JTI,
        *jwt_require_jti,
        candidate.jwt_require_jti,
    );
    c.value(
        &ROLES_CLAIM,
        Some(roles_claim),
        Some(&candidate.roles_claim),
    );
    c.value(
        &SERVICE_TOKEN_SQLITE_PATH,
        service_token_sqlite_path.as_ref(),
        candidate.service_token_sqlite_path.as_ref(),
    );
    c.count(
        &SERVICE_TOKEN_CACHE_TTL_MS,
        Some(*service_token_cache_ttl_ms),
        Some(candidate.service_token_cache_ttl_ms),
    );
    c.flag(&CSRF_ENABLED, *csrf_enabled, candidate.csrf_enabled);
    c.value(
        &CSRF_COOKIE_NAME,
        Some(csrf_cookie_name),
        Some(&candidate.csrf_cookie_name),
    );
    c.value(
        &CSRF_HEADER_NAME,
        Some(csrf_header_name),
        Some(&candidate.csrf_header_name),
    );
    c.value(
        &CSRF_COOKIE_DOMAIN,
        csrf_cookie_domain.as_ref(),
        candidate.csrf_cookie_domain.as_ref(),
    );
    c.set(
        &CSRF_EXEMPT_PATHS,
        csrf_exempt_paths,
        &candidate.csrf_exempt_paths,
    );
}

fn providers_by_name(providers: &[AuthProviderConfig]) -> BTreeMap<&str, &AuthProviderConfig> {
    providers
        .iter()
        .map(|provider| (provider.name.as_str(), provider))
        .collect()
}

fn auth_mode_word(mode: &AuthMode) -> &'static str {
    match mode {
        AuthMode::Required => "required",
        AuthMode::Observe => "observe",
    }
}

fn compare_proxy(
    c: &mut Comparison,
    base: &ProxyPlan,
    candidate: &ProxyPlan,
    (base_egress, candidate_egress): (&EgressPlan, &EgressPlan),
) {
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
    } = base;
    c.flag(
        &TRUST_PROXY_HEADERS,
        *trust_proxy_headers,
        candidate.trust_proxy_headers,
    );
    c.set(
        &TRUSTED_PROXY_CIDRS,
        trusted_proxy_cidrs,
        &candidate.trusted_proxy_cidrs,
    );
    if upstream_url != &candidate.upstream_url {
        let plaintext = |url: &Option<String>| url.as_deref().is_some_and(is_plaintext);
        let mut impacts = vec![Impact::Loosened(RiskCode::RoutingChanged)];
        if plaintext(&candidate.upstream_url) && !plaintext(upstream_url) {
            impacts.push(Impact::Loosened(RiskCode::PlaintextTransport));
        }
        c.record(
            &UPSTREAM_URL,
            ChangeKind::of(upstream_url.as_ref(), candidate.upstream_url.as_ref()),
            &impacts,
            Display::Withheld,
            None,
        );
    }
    routes(c, upstream_routes, &candidate.upstream_routes);
    if mcp_upstream_servers != &candidate.mcp_upstream_servers {
        let plaintext = |servers: &[McpUpstreamServerConfig]| {
            servers
                .iter()
                .filter(|server| is_plaintext(&server.url))
                .count()
        };
        let mut impacts = vec![Impact::Loosened(RiskCode::RoutingChanged)];
        if plaintext(&candidate.mcp_upstream_servers) > plaintext(mcp_upstream_servers) {
            impacts.push(Impact::Loosened(RiskCode::PlaintextTransport));
        }
        c.assessed_sequence(
            &MCP_UPSTREAM_SERVERS,
            mcp_upstream_servers,
            &candidate.mcp_upstream_servers,
            &impacts,
        );
    }
    // An unset upstream timeout inherits the egress one, so it is compared
    // as the timeout that applies.
    for (field, before, after, inherited) in [
        (
            &UPSTREAM_TIMEOUT_MS,
            upstream_timeout_ms,
            &candidate.upstream_timeout_ms,
            (
                base_egress.egress_timeout_ms,
                candidate_egress.egress_timeout_ms,
            ),
        ),
        (
            &UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS,
            upstream_response_idle_timeout_ms,
            &candidate.upstream_response_idle_timeout_ms,
            (
                base_egress.egress_response_idle_timeout_ms,
                candidate_egress.egress_response_idle_timeout_ms,
            ),
        ),
        (
            &UPSTREAM_CONNECT_TIMEOUT_MS,
            upstream_connect_timeout_ms,
            &candidate.upstream_connect_timeout_ms,
            (
                base_egress.egress_connect_timeout_ms,
                candidate_egress.egress_connect_timeout_ms,
            ),
        ),
    ] {
        c.count(
            field,
            Some(before.unwrap_or(inherited.0)),
            Some(after.unwrap_or(inherited.1)),
        );
    }
}

/// The route table, in order. Any change reroutes; a route that gains a
/// plaintext upstream, forwards the session cookie upstream, or binds a
/// different Connection says so as well.
fn routes(c: &mut Comparison, base: &[UpstreamRouteConfig], candidate: &[UpstreamRouteConfig]) {
    if base == candidate {
        return;
    }
    let plaintext = |routes: &[UpstreamRouteConfig]| {
        routes
            .iter()
            .map(|route| {
                usize::from(is_plaintext(&route.upstream_url))
                    + route
                        .upstreams
                        .iter()
                        .filter(|endpoint| is_plaintext(&endpoint.url))
                        .count()
            })
            .sum::<usize>()
    };
    let forwarding = |routes: &[UpstreamRouteConfig]| {
        routes
            .iter()
            .filter(|route| route.forward_cookie_session)
            .count()
    };
    let mut impacts = vec![Impact::Loosened(RiskCode::RoutingChanged)];
    if plaintext(candidate) > plaintext(base) {
        impacts.push(Impact::Loosened(RiskCode::PlaintextTransport));
    }
    if forwarding(candidate) > forwarding(base) {
        impacts.push(Impact::Loosened(RiskCode::DataExposureIncreased));
    }
    if route_connections(candidate) != route_connections(base) {
        impacts.push(Impact::Loosened(RiskCode::CredentialBindingChanged));
    }
    c.assessed_sequence(&UPSTREAM_ROUTES, base, candidate, &impacts);
}

fn route_connections(routes: &[UpstreamRouteConfig]) -> BTreeSet<&str> {
    routes
        .iter()
        .filter_map(|route| route.connection_id.as_deref())
        .collect()
}

/// `http://`, in any case: a connection that does not use TLS.
fn is_plaintext(url: &str) -> bool {
    url.get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
}

fn compare_storage(c: &mut Comparison, base: &StoragePlan, candidate: &StoragePlan) {
    let StoragePlan {
        audit_log_file,
        audit_sqlite_path,
        audit_sqlite_retention_days,
        audit_successful_probes_metrics_only,
        discovery_sqlite_path,
        discovery_endpoint_limit,
        discovery_projector_lease_ttl_ms,
        discovery_projector_poll_ms,
        discovery_projector_batch,
        principal_sqlite_path,
        openapi_spec_path,
        policy_file,
        tools_file,
        policy_history_sqlite_path,
        tool_lease_ttl_ms,
        cluster_heartbeat_ms,
        cluster_member_stale_ms,
        cluster_maintenance_interval_ms,
        cluster_maintenance_lease_ttl_ms,
        readiness_probe_cache_ms,
        cluster_status_expose_hostnames,
        audit_postgres_retention_days,
        state_backend,
        deployment_id,
        database,
        authority_events,
        provenance: _,
    } = base;
    c.value(
        &AUDIT_LOG_FILE,
        audit_log_file.as_ref(),
        candidate.audit_log_file.as_ref(),
    );
    c.value(
        &AUDIT_SQLITE_PATH,
        audit_sqlite_path.as_ref(),
        candidate.audit_sqlite_path.as_ref(),
    );
    // No retention keeps every record.
    c.count(
        &AUDIT_SQLITE_RETENTION_DAYS,
        audit_sqlite_retention_days.map(u64::from),
        candidate.audit_sqlite_retention_days.map(u64::from),
    );
    c.count(
        &AUDIT_POSTGRES_RETENTION_DAYS,
        audit_postgres_retention_days.map(u64::from),
        candidate.audit_postgres_retention_days.map(u64::from),
    );
    c.flag(
        &AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
        *audit_successful_probes_metrics_only,
        candidate.audit_successful_probes_metrics_only,
    );
    for (field, before, after) in [
        (
            &DISCOVERY_SQLITE_PATH,
            discovery_sqlite_path,
            &candidate.discovery_sqlite_path,
        ),
        (
            &PRINCIPAL_SQLITE_PATH,
            principal_sqlite_path,
            &candidate.principal_sqlite_path,
        ),
        (
            &POLICY_HISTORY_SQLITE_PATH,
            policy_history_sqlite_path,
            &candidate.policy_history_sqlite_path,
        ),
        (&TOOLS_FILE, tools_file, &candidate.tools_file),
    ] {
        c.value(field, before.as_ref(), after.as_ref());
    }
    c.count(
        &DISCOVERY_ENDPOINT_LIMIT,
        Some(*discovery_endpoint_limit as u64),
        Some(candidate.discovery_endpoint_limit as u64),
    );
    for (field, before, after) in [
        (
            &DISCOVERY_PROJECTOR_LEASE_TTL_MS,
            *discovery_projector_lease_ttl_ms,
            candidate.discovery_projector_lease_ttl_ms,
        ),
        (
            &DISCOVERY_PROJECTOR_POLL_MS,
            *discovery_projector_poll_ms,
            candidate.discovery_projector_poll_ms,
        ),
        (
            &DISCOVERY_PROJECTOR_BATCH,
            *discovery_projector_batch as u64,
            candidate.discovery_projector_batch as u64,
        ),
        (
            &TOOL_LEASE_TTL_MS,
            *tool_lease_ttl_ms,
            candidate.tool_lease_ttl_ms,
        ),
        (
            &CLUSTER_HEARTBEAT_MS,
            *cluster_heartbeat_ms,
            candidate.cluster_heartbeat_ms,
        ),
        (
            &CLUSTER_MEMBER_STALE_MS,
            *cluster_member_stale_ms,
            candidate.cluster_member_stale_ms,
        ),
        (
            &CLUSTER_MAINTENANCE_INTERVAL_MS,
            *cluster_maintenance_interval_ms,
            candidate.cluster_maintenance_interval_ms,
        ),
        (
            &CLUSTER_MAINTENANCE_LEASE_TTL_MS,
            *cluster_maintenance_lease_ttl_ms,
            candidate.cluster_maintenance_lease_ttl_ms,
        ),
        (
            &READINESS_PROBE_CACHE_MS,
            *readiness_probe_cache_ms,
            candidate.readiness_probe_cache_ms,
        ),
    ] {
        c.count(field, Some(before), Some(after));
    }
    c.value(
        &OPENAPI_SPEC_PATH,
        openapi_spec_path.as_ref(),
        candidate.openapi_spec_path.as_ref(),
    );
    // Another policy file is another policy, which this diff cannot see.
    match (policy_file, &candidate.policy_file) {
        (Some(before), Some(after)) if before != after => c.record(
            &POLICY_FILE,
            ChangeKind::Modified,
            &[Impact::Unknown],
            Display::Withheld,
            None,
        ),
        (before, after) => c.value(&POLICY_FILE, before.as_ref(), after.as_ref()),
    }
    c.flag(
        &CLUSTER_STATUS_EXPOSE_HOSTNAMES,
        *cluster_status_expose_hostnames,
        candidate.cluster_status_expose_hostnames,
    );
    c.word(
        &STATE_BACKEND,
        state_backend_word(state_backend),
        state_backend_word(&candidate.state_backend),
    );
    c.value(
        &DEPLOYMENT_ID,
        deployment_id.as_ref(),
        candidate.deployment_id.as_ref(),
    );
    compare_database(c, database, &candidate.database);
    compare_authority_events(c, authority_events, &candidate.authority_events);
}

fn state_backend_word(backend: &StateBackend) -> &'static str {
    match backend {
        StateBackend::Sqlite => "sqlite",
        StateBackend::Postgres => "postgres",
    }
}

fn compare_database(c: &mut Comparison, base: &DatabasePlan, candidate: &DatabasePlan) {
    let DatabasePlan {
        pool_max,
        connect_timeout_ms,
        acquire_timeout_ms,
        statement_timeout_ms,
        idle_in_transaction_timeout_ms,
        lock_timeout_ms,
        startup_retry_limit,
        auto_migrate,
        migration_statement_timeout_ms,
        tls_mode,
        tls_ca_file,
        url_file,
    } = base;
    for (field, before, after) in [
        (
            &DATABASE_POOL_MAX,
            *pool_max as u64,
            candidate.pool_max as u64,
        ),
        (
            &DATABASE_CONNECT_TIMEOUT_MS,
            *connect_timeout_ms,
            candidate.connect_timeout_ms,
        ),
        (
            &DATABASE_ACQUIRE_TIMEOUT_MS,
            *acquire_timeout_ms,
            candidate.acquire_timeout_ms,
        ),
        (
            &DATABASE_STATEMENT_TIMEOUT_MS,
            *statement_timeout_ms,
            candidate.statement_timeout_ms,
        ),
        (
            &DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
            *idle_in_transaction_timeout_ms,
            candidate.idle_in_transaction_timeout_ms,
        ),
        (
            &DATABASE_LOCK_TIMEOUT_MS,
            *lock_timeout_ms,
            candidate.lock_timeout_ms,
        ),
        (
            &DATABASE_STARTUP_RETRY_LIMIT,
            *startup_retry_limit,
            candidate.startup_retry_limit,
        ),
        (
            &DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
            *migration_statement_timeout_ms,
            candidate.migration_statement_timeout_ms,
        ),
    ] {
        c.count(field, Some(before), Some(after));
    }
    c.flag(
        &DATABASE_AUTO_MIGRATE,
        *auto_migrate,
        candidate.auto_migrate,
    );
    let tls_word = |mode: &DatabaseTlsMode| match mode {
        DatabaseTlsMode::Verify => "verify",
        DatabaseTlsMode::LoopbackDev => "loopback-dev",
    };
    c.word(
        &DATABASE_TLS_MODE,
        tls_word(tls_mode),
        tls_word(&candidate.tls_mode),
    );
    c.value(
        &DATABASE_TLS_CA_FILE,
        tls_ca_file.as_ref(),
        candidate.tls_ca_file.as_ref(),
    );
    c.secret(
        &DATABASE_URL_FILE,
        url_file.as_ref(),
        candidate.url_file.as_ref(),
    );
}

fn compare_authority_events(
    c: &mut Comparison,
    base: &AuthorityEventSettings,
    candidate: &AuthorityEventSettings,
) {
    let AuthorityEventSettings {
        sink,
        pseudonym_key_alias,
        previous_pseudonym_key_alias,
        journal_capacity,
        retention_hours,
    } = base;
    c.word(&AUTHORITY_EVENT_SINK, sink.kind(), candidate.sink.kind());
    c.value(
        &AUTHORITY_EVENT_FILE,
        event_file(sink),
        event_file(&candidate.sink),
    );
    c.secret(
        &AUTHORITY_PSEUDONYM_KEY_ALIAS,
        pseudonym_key_alias.as_ref(),
        candidate.pseudonym_key_alias.as_ref(),
    );
    c.secret(
        &AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS,
        previous_pseudonym_key_alias.as_ref(),
        candidate.previous_pseudonym_key_alias.as_ref(),
    );
    c.count(
        &AUTHORITY_EVENT_JOURNAL_CAPACITY,
        Some(*journal_capacity),
        Some(candidate.journal_capacity),
    );
    c.count(
        &AUTHORITY_EVENT_RETENTION_HOURS,
        Some(*retention_hours),
        Some(candidate.retention_hours),
    );
}

fn event_file(sink: &AuthorityEventSinkSetting) -> Option<&String> {
    match sink {
        AuthorityEventSinkSetting::File(path) => Some(path),
        _ => None,
    }
}

fn compare_connections(c: &mut Comparison, base: &ConnectionsPlan, candidate: &ConnectionsPlan) {
    let ConnectionsPlan {
        connections_sqlite_path,
        connection_secrets_root,
        connection_secret_aliases,
        connection_local_secret_keyring,
        admin_login_keyring,
        rate_limit_keyring,
        connection_vault_provider,
        connection_gcp_provider,
        connection_azure_provider,
        connection_aws_provider,
        connection_kubernetes_provider,
        provenance: _,
    } = base;
    c.value(
        &CONNECTIONS_SQLITE_PATH,
        connections_sqlite_path.as_ref(),
        candidate.connections_sqlite_path.as_ref(),
    );
    c.secret(
        &CONNECTION_SECRETS_ROOT,
        connection_secrets_root.as_ref(),
        candidate.connection_secrets_root.as_ref(),
    );
    c.secret(
        &CONNECTION_SECRET_ALIASES,
        Some(connection_secret_aliases),
        Some(&candidate.connection_secret_aliases),
    );
    for (field, before, after) in [
        (
            &CONNECTION_LOCAL_SECRET_KEYRING,
            connection_local_secret_keyring,
            &candidate.connection_local_secret_keyring,
        ),
        (
            &ADMIN_LOGIN_KEYRING,
            admin_login_keyring,
            &candidate.admin_login_keyring,
        ),
        (
            &RATE_LIMIT_KEYRING,
            rate_limit_keyring,
            &candidate.rate_limit_keyring,
        ),
    ] {
        c.secret(field, Some(before), Some(after));
    }
    c.secret(
        &CONNECTION_VAULT_PROVIDER,
        Some(connection_vault_provider),
        Some(&candidate.connection_vault_provider),
    );
    c.secret(
        &CONNECTION_GCP_PROVIDER,
        Some(connection_gcp_provider),
        Some(&candidate.connection_gcp_provider),
    );
    c.secret(
        &CONNECTION_AZURE_PROVIDER,
        Some(connection_azure_provider),
        Some(&candidate.connection_azure_provider),
    );
    c.secret(
        &CONNECTION_AWS_PROVIDER,
        Some(connection_aws_provider),
        Some(&candidate.connection_aws_provider),
    );
    c.secret(
        &CONNECTION_KUBERNETES_PROVIDER,
        Some(connection_kubernetes_provider),
        Some(&candidate.connection_kubernetes_provider),
    );
}

fn compare_egress(c: &mut Comparison, base: &EgressPlan, candidate: &EgressPlan) {
    let EgressPlan {
        egress_allowed_hosts,
        egress_timeout_ms,
        egress_response_idle_timeout_ms,
        egress_connect_timeout_ms,
        egress_max_response_bytes,
        egress_max_request_body_bytes,
        egress_nat64_prefixes,
        egress_deny_private_ips,
        provenance: _,
    } = base;
    // Host names match case-insensitively.
    let hosts = |hosts: &[String]| {
        hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    c.set(
        &EGRESS_ALLOWED_HOSTS,
        hosts(egress_allowed_hosts),
        hosts(&candidate.egress_allowed_hosts),
    );
    for (field, before, after) in [
        (
            &EGRESS_TIMEOUT_MS,
            *egress_timeout_ms,
            candidate.egress_timeout_ms,
        ),
        (
            &EGRESS_RESPONSE_IDLE_TIMEOUT_MS,
            *egress_response_idle_timeout_ms,
            candidate.egress_response_idle_timeout_ms,
        ),
        (
            &EGRESS_CONNECT_TIMEOUT_MS,
            *egress_connect_timeout_ms,
            candidate.egress_connect_timeout_ms,
        ),
        (
            &EGRESS_MAX_RESPONSE_BYTES,
            *egress_max_response_bytes as u64,
            candidate.egress_max_response_bytes as u64,
        ),
        (
            &EGRESS_MAX_REQUEST_BODY_BYTES,
            *egress_max_request_body_bytes as u64,
            candidate.egress_max_request_body_bytes as u64,
        ),
    ] {
        c.count(field, Some(before), Some(after));
    }
    c.set(
        &EGRESS_NAT64_PREFIXES,
        egress_nat64_prefixes,
        &candidate.egress_nat64_prefixes,
    );
    c.flag(
        &EGRESS_DENY_PRIVATE_IPS,
        *egress_deny_private_ips,
        candidate.egress_deny_private_ips,
    );
}

fn compare_runtime(c: &mut Comparison, base: &RuntimePlan, candidate: &RuntimePlan) {
    let RuntimePlan {
        shutdown_drain_delay_ms,
        shutdown_timeout_ms,
        audit_drain_timeout_ms,
        audit_durability,
        audit_durability_timeout_ms,
        payload_capture_enabled,
        payload_capture_sample_rate,
        schema_mismatch_signal_threshold,
        error_rate_spike_signal_threshold,
        principal_new_to_endpoint_signal_threshold,
        volume_outlier_signal_threshold,
        rule_suggestion_baseline_window_hours,
        cors_allow_origins,
        max_body_size,
        max_request_path_bytes,
        rate_limit_read_rps,
        rate_limit_read_burst,
        rate_limit_write_rps,
        rate_limit_write_burst,
        rate_limit_max_buckets,
        rate_limit_bucket_ttl_ms,
        validation_allowed_content_types,
        tool_runtime_queue_depth,
        tool_runtime_global_concurrency,
        tool_runtime_queue_timeout_ms,
        tool_runtime_default_timeout_ms,
        provenance: _,
    } = base;
    for (field, before, after) in [
        (
            &SHUTDOWN_DRAIN_DELAY_MS,
            *shutdown_drain_delay_ms,
            candidate.shutdown_drain_delay_ms,
        ),
        (
            &SHUTDOWN_TIMEOUT_MS,
            *shutdown_timeout_ms,
            candidate.shutdown_timeout_ms,
        ),
        (
            &AUDIT_DRAIN_TIMEOUT_MS,
            *audit_drain_timeout_ms,
            candidate.audit_drain_timeout_ms,
        ),
        (
            &AUDIT_DURABILITY_TIMEOUT_MS,
            *audit_durability_timeout_ms,
            candidate.audit_durability_timeout_ms,
        ),
        (
            &SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            *schema_mismatch_signal_threshold,
            candidate.schema_mismatch_signal_threshold,
        ),
        (
            &PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            *principal_new_to_endpoint_signal_threshold,
            candidate.principal_new_to_endpoint_signal_threshold,
        ),
        (
            &RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            *rule_suggestion_baseline_window_hours,
            candidate.rule_suggestion_baseline_window_hours,
        ),
        (
            &MAX_BODY_SIZE,
            *max_body_size as u64,
            candidate.max_body_size as u64,
        ),
        (
            &MAX_REQUEST_PATH_BYTES,
            *max_request_path_bytes as u64,
            candidate.max_request_path_bytes as u64,
        ),
        (
            &RATE_LIMIT_READ_BURST,
            u64::from(*rate_limit_read_burst),
            u64::from(candidate.rate_limit_read_burst),
        ),
        (
            &RATE_LIMIT_WRITE_BURST,
            u64::from(*rate_limit_write_burst),
            u64::from(candidate.rate_limit_write_burst),
        ),
        (
            &RATE_LIMIT_MAX_BUCKETS,
            *rate_limit_max_buckets as u64,
            candidate.rate_limit_max_buckets as u64,
        ),
        (
            &RATE_LIMIT_BUCKET_TTL_MS,
            *rate_limit_bucket_ttl_ms,
            candidate.rate_limit_bucket_ttl_ms,
        ),
        (
            &TOOL_RUNTIME_QUEUE_DEPTH,
            *tool_runtime_queue_depth as u64,
            candidate.tool_runtime_queue_depth as u64,
        ),
        (
            &TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            *tool_runtime_global_concurrency as u64,
            candidate.tool_runtime_global_concurrency as u64,
        ),
        (
            &TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            *tool_runtime_queue_timeout_ms,
            candidate.tool_runtime_queue_timeout_ms,
        ),
        (
            &TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
            *tool_runtime_default_timeout_ms,
            candidate.tool_runtime_default_timeout_ms,
        ),
    ] {
        c.count(field, Some(before), Some(after));
    }
    let durability = |durability: &AuditDurability| match durability {
        AuditDurability::Required => "required",
        AuditDurability::BestEffort => "best_effort",
    };
    c.word(
        &AUDIT_DURABILITY,
        durability(audit_durability),
        durability(&candidate.audit_durability),
    );
    c.flag(
        &PAYLOAD_CAPTURE_ENABLED,
        *payload_capture_enabled,
        candidate.payload_capture_enabled,
    );
    for (field, before, after) in [
        (
            &PAYLOAD_CAPTURE_SAMPLE_RATE,
            *payload_capture_sample_rate,
            candidate.payload_capture_sample_rate,
        ),
        (
            &ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            *error_rate_spike_signal_threshold,
            candidate.error_rate_spike_signal_threshold,
        ),
        (
            &VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            *volume_outlier_signal_threshold,
            candidate.volume_outlier_signal_threshold,
        ),
        (
            &RATE_LIMIT_READ_RPS,
            *rate_limit_read_rps,
            candidate.rate_limit_read_rps,
        ),
        (
            &RATE_LIMIT_WRITE_RPS,
            *rate_limit_write_rps,
            candidate.rate_limit_write_rps,
        ),
    ] {
        c.rate(field, before, after);
    }
    c.set(
        &CORS_ALLOW_ORIGINS,
        cors_allow_origins,
        &candidate.cors_allow_origins,
    );
    c.set(
        &VALIDATION_ALLOWED_CONTENT_TYPES,
        validation_allowed_content_types,
        &candidate.validation_allowed_content_types,
    );
}

#[cfg(test)]
mod tests;
