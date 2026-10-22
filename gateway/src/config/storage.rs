//! Where the gateway keeps its state -- the local stores and documents, the
//! cluster's coordination settings, the state backend and PostgreSQL --
//! compiled in pure stages (issue #433, PR 2).
//!
//! `Config::from_env_vars` reads these in five blocks with other domains'
//! settings between them, and each block is requested where the legacy parser
//! requested it, so the read order does not move:
//!
//! 1. the audit sinks and SQLite retention ([`AuditStoreInputs`]);
//! 2. the discovery store, the cluster's discovery projector and the
//!    principal directory ([`DiscoveryStoreInputs`]);
//! 3. the policy, tools and OpenAPI documents and the policy history store
//!    ([`DocumentInputs`]);
//! 4. the execution lease, cluster membership, maintenance, readiness and
//!    PostgreSQL audit retention ([`ClusterInputs`]);
//! 5. the state backend and PostgreSQL ([`StateBackendInputs`]), after which
//!    [`compile`] checks the rules that pair every store and every
//!    cluster-only setting with the backend that reads it, and returns the
//!    [`StoragePlan`].
//!
//! Those rules also need what other domains configured: the Connections
//! store, keyrings and local keyring (`connections`), the admin session store,
//! the admin login and the service-token store (`identity`), and payload
//! capture (`runtime`). They are checked last because the backend is read
//! last, which is also where the legacy parser checked them.
//!
//! Nothing here opens a store, reads the database URL file or connects to
//! PostgreSQL. The URL file comes out as a [`SecretLocator`]; a path that does
//! not exist is accepted here exactly as the legacy parser accepts it. The one
//! thing a stage here does besides return values is the warning a retention
//! of `0` days has always logged, which it still logs through the same helper
//! when that input is parsed.

use std::{env::VarError, path::PathBuf};

use super::{
    blank_as_unset,
    connections::ConnectionsPlan,
    diagnostic::ConfigRule,
    identity::IdentityPlan,
    normalize_audit_retention_days, parse_optional_path, parse_optional_string, parse_optional_var,
    parse_var,
    runtime::RuntimePlan,
    stage::{Checked, Findings, Provenance, RawInput, SecretLocator},
    validate_deployment_id, validate_maximum_u64, validate_minimum_u64,
    validate_positive_bounded_u64, validate_positive_timeout_ms, validate_positive_u64,
    validate_positive_usize, DatabaseSettings, DatabaseTlsMode, StateBackend, ADMIN_LOGIN_KEYRING,
    ADMIN_LOGIN_PROVIDER, ADMIN_SESSION_MODE, AUDIT_LOG_FILE, AUDIT_POSTGRES_RETENTION_DAYS,
    AUDIT_SQLITE_PATH, AUDIT_SQLITE_RETENTION_DAYS, AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
    CLUSTER_HEARTBEAT_MS, CLUSTER_MAINTENANCE_INTERVAL_MS, CLUSTER_MAINTENANCE_LEASE_TTL_MS,
    CLUSTER_MEMBER_STALE_MS, CLUSTER_STATUS_EXPOSE_HOSTNAMES, CONNECTIONS_SQLITE_PATH,
    CONNECTION_LOCAL_SECRET_KEYRING, DATABASE_ACQUIRE_TIMEOUT_MS, DATABASE_AUTO_MIGRATE,
    DATABASE_CONNECT_TIMEOUT_MS, DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS, DATABASE_LOCK_TIMEOUT_MS,
    DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, DATABASE_POOL_MAX, DATABASE_STARTUP_RETRY_LIMIT,
    DATABASE_STATEMENT_TIMEOUT_MS, DATABASE_TLS_CA_FILE, DATABASE_TLS_MODE, DATABASE_URL_FILE,
    DEFAULT_CLUSTER_HEARTBEAT_MS, DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
    DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS, DEFAULT_CLUSTER_MEMBER_STALE_MS,
    DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS, DEFAULT_DATABASE_CONNECT_TIMEOUT_MS,
    DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS, DEFAULT_DATABASE_LOCK_TIMEOUT_MS,
    DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, DEFAULT_DATABASE_POOL_MAX,
    DEFAULT_DATABASE_STARTUP_RETRY_LIMIT, DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS,
    DEFAULT_DISCOVERY_ENDPOINT_LIMIT, DEFAULT_DISCOVERY_PROJECTOR_BATCH,
    DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS, DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
    DEFAULT_READINESS_PROBE_CACHE_MS, DEFAULT_TOOL_LEASE_TTL_MS, DEPLOYMENT_ID,
    DISCOVERY_ENDPOINT_LIMIT, DISCOVERY_PROJECTOR_BATCH, DISCOVERY_PROJECTOR_LEASE_TTL_MS,
    DISCOVERY_PROJECTOR_POLL_MS, DISCOVERY_SQLITE_PATH,
    MAX_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, MAX_DATABASE_POOL_MAX,
    MAX_DATABASE_STARTUP_RETRY_LIMIT, MAX_DISCOVERY_PROJECTOR_BATCH, MAX_READINESS_PROBE_CACHE_MS,
    MIN_CLUSTER_HEARTBEAT_MS, MIN_CLUSTER_MAINTENANCE_INTERVAL_MS,
    MIN_CLUSTER_MAINTENANCE_LEASE_TTL_MS, MIN_CLUSTER_STALE_HEARTBEATS,
    MIN_DISCOVERY_PROJECTOR_LEASE_TTL_MS, MIN_DISCOVERY_PROJECTOR_POLL_MS, MIN_TOOL_LEASE_TTL_MS,
    OPENAPI_SPEC_PATH, PAYLOAD_CAPTURE_ENABLED, POLICY_FILE, POLICY_HISTORY_SQLITE_PATH,
    PRINCIPAL_SQLITE_PATH, RATE_LIMIT_KEYRING, READINESS_PROBE_CACHE_MS, SERVICE_TOKEN_SQLITE_PATH,
    STATE_BACKEND, TOOLS_FILE, TOOL_LEASE_TTL_MS,
};
use crate::auth::admin_session::AdminSessionStorage;

/// The audit sinks' inputs, as the reader returned them.
pub(super) struct AuditStoreInputs {
    log_file: RawInput,
    sqlite_path: RawInput,
    successful_probes_metrics_only: RawInput,
    sqlite_retention_days: RawInput,
}

impl AuditStoreInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            log_file: RawInput::new(AUDIT_LOG_FILE, get_var(AUDIT_LOG_FILE)),
            sqlite_path: RawInput::new(AUDIT_SQLITE_PATH, get_var(AUDIT_SQLITE_PATH)),
            successful_probes_metrics_only: RawInput::new(
                AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
                get_var(AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY),
            ),
            sqlite_retention_days: RawInput::new(
                AUDIT_SQLITE_RETENTION_DAYS,
                get_var(AUDIT_SQLITE_RETENTION_DAYS),
            ),
        }
    }
}

/// The audit sinks, parsed.
pub(super) struct AuditStores {
    audit_log_file: Option<String>,
    audit_sqlite_path: Option<String>,
    audit_successful_probes_metrics_only: bool,
    audit_sqlite_retention_days: Option<u32>,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_audit_stores(inputs: AuditStoreInputs) -> Checked<AuditStores> {
    let mut findings = Findings::default();
    let audit_log_file = findings.input(AUDIT_LOG_FILE, |problems| {
        parse_optional_string(AUDIT_LOG_FILE, inputs.log_file.value(), problems)
    });
    let audit_sqlite_path = findings.input(AUDIT_SQLITE_PATH, |problems| {
        parse_optional_string(AUDIT_SQLITE_PATH, inputs.sqlite_path.value(), problems)
    });
    let audit_successful_probes_metrics_only =
        findings.input(AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY, |problems| {
            parse_var(
                AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY,
                inputs.successful_probes_metrics_only.value(),
                false,
                "boolean",
                problems,
            )
        });
    let audit_sqlite_retention_days = findings.input(AUDIT_SQLITE_RETENTION_DAYS, |problems| {
        let days = parse_optional_var(
            AUDIT_SQLITE_RETENTION_DAYS,
            inputs.sqlite_retention_days.value(),
            "day count",
            problems,
        );
        normalize_audit_retention_days(AUDIT_SQLITE_RETENTION_DAYS, "SQLite", days, problems)
    });
    Checked::new(
        AuditStores {
            audit_log_file,
            audit_sqlite_path,
            audit_successful_probes_metrics_only,
            audit_sqlite_retention_days,
            provenance: vec![
                inputs.log_file.provenance(),
                inputs.sqlite_path.provenance(),
                inputs.successful_probes_metrics_only.provenance(),
                inputs.sqlite_retention_days.provenance(),
            ],
        },
        findings,
    )
}

/// The discovery store's, the discovery projector's and the principal
/// directory's inputs, as the reader returned them.
pub(super) struct DiscoveryStoreInputs {
    sqlite_path: RawInput,
    endpoint_limit: RawInput,
    projector_lease_ttl_ms: RawInput,
    projector_poll_ms: RawInput,
    projector_batch: RawInput,
    principal_sqlite_path: RawInput,
}

impl DiscoveryStoreInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            sqlite_path: RawInput::new(DISCOVERY_SQLITE_PATH, get_var(DISCOVERY_SQLITE_PATH)),
            endpoint_limit: RawInput::new(
                DISCOVERY_ENDPOINT_LIMIT,
                get_var(DISCOVERY_ENDPOINT_LIMIT),
            ),
            projector_lease_ttl_ms: RawInput::new(
                DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                get_var(DISCOVERY_PROJECTOR_LEASE_TTL_MS),
            ),
            projector_poll_ms: RawInput::new(
                DISCOVERY_PROJECTOR_POLL_MS,
                get_var(DISCOVERY_PROJECTOR_POLL_MS),
            ),
            projector_batch: RawInput::new(
                DISCOVERY_PROJECTOR_BATCH,
                get_var(DISCOVERY_PROJECTOR_BATCH),
            ),
            principal_sqlite_path: RawInput::new(
                PRINCIPAL_SQLITE_PATH,
                get_var(PRINCIPAL_SQLITE_PATH),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.sqlite_path,
            &self.endpoint_limit,
            &self.projector_lease_ttl_ms,
            &self.projector_poll_ms,
            &self.projector_batch,
            &self.principal_sqlite_path,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The discovery store, the projector and the principal directory, parsed.
pub(super) struct DiscoveryStores {
    discovery_sqlite_path: Option<String>,
    discovery_endpoint_limit: usize,
    discovery_projector_lease_ttl_ms: u64,
    discovery_projector_poll_ms: u64,
    discovery_projector_batch: usize,
    principal_sqlite_path: Option<String>,
    /// Whether each projector setting was set, even to a value that was
    /// refused: standalone mode refuses all three.
    projector_settings_set: [(&'static str, bool); 3],
    provenance: Vec<Provenance>,
}

/// Parses the discovery block. The cluster-mode projector's cadence is
/// parsed in both modes so one pass reports every problem.
pub(super) fn compile_discovery_stores(inputs: DiscoveryStoreInputs) -> Checked<DiscoveryStores> {
    let mut findings = Findings::default();
    let discovery_sqlite_path = findings.input(DISCOVERY_SQLITE_PATH, |problems| {
        parse_optional_string(DISCOVERY_SQLITE_PATH, inputs.sqlite_path.value(), problems)
    });
    let discovery_endpoint_limit = findings.input(DISCOVERY_ENDPOINT_LIMIT, |problems| {
        let limit = parse_var(
            DISCOVERY_ENDPOINT_LIMIT,
            inputs.endpoint_limit.value(),
            DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            "positive integer",
            problems,
        );
        validate_positive_usize(
            DISCOVERY_ENDPOINT_LIMIT,
            limit,
            DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            problems,
        )
    });
    let discovery_projector_lease_ttl_ms =
        findings.input(DISCOVERY_PROJECTOR_LEASE_TTL_MS, |problems| {
            let ttl_ms = parse_optional_var(
                DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                inputs.projector_lease_ttl_ms.value(),
                "millisecond duration",
                problems,
            )
            .unwrap_or(DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS);
            validate_minimum_u64(
                DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                ttl_ms,
                MIN_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                "milliseconds (the lease is renewed at a third of its TTL)",
                DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                problems,
            )
        });
    let discovery_projector_poll_ms = findings.input(DISCOVERY_PROJECTOR_POLL_MS, |problems| {
        let poll_ms = parse_optional_var(
            DISCOVERY_PROJECTOR_POLL_MS,
            inputs.projector_poll_ms.value(),
            "millisecond duration",
            problems,
        )
        .unwrap_or(DEFAULT_DISCOVERY_PROJECTOR_POLL_MS);
        validate_minimum_u64(
            DISCOVERY_PROJECTOR_POLL_MS,
            poll_ms,
            MIN_DISCOVERY_PROJECTOR_POLL_MS,
            "milliseconds (an idle projector polls the audit stream this often)",
            DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
            problems,
        )
    });
    let discovery_projector_batch = findings.input(DISCOVERY_PROJECTOR_BATCH, |problems| {
        let batch = parse_optional_var::<u64>(
            DISCOVERY_PROJECTOR_BATCH,
            inputs.projector_batch.value(),
            "positive integer",
            problems,
        )
        .unwrap_or(DEFAULT_DISCOVERY_PROJECTOR_BATCH as u64);
        validate_positive_bounded_u64(
            DISCOVERY_PROJECTOR_BATCH,
            batch,
            MAX_DISCOVERY_PROJECTOR_BATCH as u64,
            DEFAULT_DISCOVERY_PROJECTOR_BATCH as u64,
            problems,
        ) as usize
    });
    let principal_sqlite_path = findings.input(PRINCIPAL_SQLITE_PATH, |problems| {
        parse_optional_string(
            PRINCIPAL_SQLITE_PATH,
            inputs.principal_sqlite_path.value(),
            problems,
        )
    });
    Checked::new(
        DiscoveryStores {
            discovery_sqlite_path,
            discovery_endpoint_limit,
            discovery_projector_lease_ttl_ms,
            discovery_projector_poll_ms,
            discovery_projector_batch,
            principal_sqlite_path,
            // A blank value is unset (the shape `.env.example` ships), and a
            // value that is not Unicode was still set.
            projector_settings_set: [
                (
                    DISCOVERY_PROJECTOR_LEASE_TTL_MS,
                    inputs.projector_lease_ttl_ms.is_set(),
                ),
                (
                    DISCOVERY_PROJECTOR_POLL_MS,
                    inputs.projector_poll_ms.is_set(),
                ),
                (DISCOVERY_PROJECTOR_BATCH, inputs.projector_batch.is_set()),
            ],
            provenance: inputs.provenance(),
        },
        findings,
    )
}

/// The documents' and the policy history store's inputs, as the reader
/// returned them.
pub(super) struct DocumentInputs {
    openapi_spec_path: RawInput,
    policy_file: RawInput,
    tools_file: RawInput,
    policy_history_sqlite_path: RawInput,
}

impl DocumentInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            openapi_spec_path: RawInput::new(OPENAPI_SPEC_PATH, get_var(OPENAPI_SPEC_PATH)),
            policy_file: RawInput::new(POLICY_FILE, get_var(POLICY_FILE)),
            tools_file: RawInput::new(TOOLS_FILE, get_var(TOOLS_FILE)),
            policy_history_sqlite_path: RawInput::new(
                POLICY_HISTORY_SQLITE_PATH,
                get_var(POLICY_HISTORY_SQLITE_PATH),
            ),
        }
    }
}

/// The documents and the policy history store, parsed.
pub(super) struct Documents {
    openapi_spec_path: Option<PathBuf>,
    policy_file: Option<String>,
    tools_file: Option<String>,
    policy_history_sqlite_path: Option<String>,
    provenance: Vec<Provenance>,
}

impl Documents {
    /// Whether a policy file is configured, for the upstream routing rule
    /// that host-bound routes need one.
    pub(super) fn policy_file_configured(&self) -> bool {
        self.policy_file.is_some()
    }
}

pub(super) fn compile_documents(inputs: DocumentInputs) -> Checked<Documents> {
    let mut findings = Findings::default();
    let openapi_spec_path = findings.input(OPENAPI_SPEC_PATH, |problems| {
        parse_optional_path(
            OPENAPI_SPEC_PATH,
            inputs.openapi_spec_path.value(),
            problems,
        )
    });
    let policy_file = findings.input(POLICY_FILE, |problems| {
        parse_optional_string(POLICY_FILE, inputs.policy_file.value(), problems)
    });
    let tools_file = findings.input(TOOLS_FILE, |problems| {
        parse_optional_string(TOOLS_FILE, inputs.tools_file.value(), problems)
    });
    let policy_history_sqlite_path = findings.input(POLICY_HISTORY_SQLITE_PATH, |problems| {
        parse_optional_string(
            POLICY_HISTORY_SQLITE_PATH,
            inputs.policy_history_sqlite_path.value(),
            problems,
        )
    });
    Checked::new(
        Documents {
            openapi_spec_path,
            policy_file,
            tools_file,
            policy_history_sqlite_path,
            provenance: vec![
                inputs.openapi_spec_path.provenance(),
                inputs.policy_file.provenance(),
                inputs.tools_file.provenance(),
                inputs.policy_history_sqlite_path.provenance(),
            ],
        },
        findings,
    )
}

/// The execution lease's and the cluster coordination settings' inputs, as
/// the reader returned them.
pub(super) struct ClusterInputs {
    tool_lease_ttl_ms: RawInput,
    heartbeat_ms: RawInput,
    member_stale_ms: RawInput,
    maintenance_interval_ms: RawInput,
    maintenance_lease_ttl_ms: RawInput,
    readiness_probe_cache_ms: RawInput,
    status_expose_hostnames: RawInput,
    audit_postgres_retention_days: RawInput,
}

impl ClusterInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            tool_lease_ttl_ms: RawInput::new(TOOL_LEASE_TTL_MS, get_var(TOOL_LEASE_TTL_MS)),
            heartbeat_ms: RawInput::new(CLUSTER_HEARTBEAT_MS, get_var(CLUSTER_HEARTBEAT_MS)),
            member_stale_ms: RawInput::new(
                CLUSTER_MEMBER_STALE_MS,
                get_var(CLUSTER_MEMBER_STALE_MS),
            ),
            maintenance_interval_ms: RawInput::new(
                CLUSTER_MAINTENANCE_INTERVAL_MS,
                get_var(CLUSTER_MAINTENANCE_INTERVAL_MS),
            ),
            maintenance_lease_ttl_ms: RawInput::new(
                CLUSTER_MAINTENANCE_LEASE_TTL_MS,
                get_var(CLUSTER_MAINTENANCE_LEASE_TTL_MS),
            ),
            readiness_probe_cache_ms: RawInput::new(
                READINESS_PROBE_CACHE_MS,
                get_var(READINESS_PROBE_CACHE_MS),
            ),
            status_expose_hostnames: RawInput::new(
                CLUSTER_STATUS_EXPOSE_HOSTNAMES,
                get_var(CLUSTER_STATUS_EXPOSE_HOSTNAMES),
            ),
            audit_postgres_retention_days: RawInput::new(
                AUDIT_POSTGRES_RETENTION_DAYS,
                get_var(AUDIT_POSTGRES_RETENTION_DAYS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.tool_lease_ttl_ms,
            &self.heartbeat_ms,
            &self.member_stale_ms,
            &self.maintenance_interval_ms,
            &self.maintenance_lease_ttl_ms,
            &self.readiness_probe_cache_ms,
            &self.status_expose_hostnames,
            &self.audit_postgres_retention_days,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The execution lease and the cluster coordination settings, parsed.
pub(super) struct Cluster {
    tool_lease_ttl_ms: u64,
    cluster_heartbeat_ms: u64,
    cluster_member_stale_ms: u64,
    cluster_maintenance_interval_ms: u64,
    cluster_maintenance_lease_ttl_ms: u64,
    readiness_probe_cache_ms: u64,
    cluster_status_expose_hostnames: bool,
    audit_postgres_retention_days: Option<u32>,
    /// Whether each cluster-only setting was set to a value, for standalone
    /// mode to refuse. A value that is not Unicode is refused by its parse
    /// and is not also reported as set, unlike the projector's settings.
    heartbeat_set: bool,
    member_stale_set: bool,
    maintenance_interval_set: bool,
    maintenance_lease_ttl_set: bool,
    readiness_probe_cache_set: bool,
    audit_postgres_retention_set: bool,
    provenance: Vec<Provenance>,
}

/// Parses the cluster block, then checks its rule: a member's heartbeat may
/// be missed a few times before the member is stale.
///
/// Cluster membership, maintenance and readiness exist only in postgres mode,
/// and `.env.example` ships every cluster-only variable blank under its
/// `STATE_BACKEND=sqlite` default, so a blank value is absence and a verbatim
/// copy boots. Whether the status API reports this replica's hostname is not
/// cluster-only: standalone serves the same endpoint.
pub(super) fn compile_cluster(inputs: ClusterInputs) -> Checked<Cluster> {
    let mut findings = Findings::default();
    let provenance = inputs.provenance();

    let tool_lease_ttl_ms = findings.input(TOOL_LEASE_TTL_MS, |problems| {
        let ttl_ms = parse_var(
            TOOL_LEASE_TTL_MS,
            inputs.tool_lease_ttl_ms.value(),
            DEFAULT_TOOL_LEASE_TTL_MS,
            "millisecond duration",
            problems,
        );
        let ttl_ms =
            validate_positive_u64(TOOL_LEASE_TTL_MS, ttl_ms, DEFAULT_TOOL_LEASE_TTL_MS, problems);
        if ttl_ms < MIN_TOOL_LEASE_TTL_MS {
            problems.push(format!(
                "{TOOL_LEASE_TTL_MS} must be at least {MIN_TOOL_LEASE_TTL_MS} milliseconds (a lease is renewed at a third of its TTL), got '{ttl_ms}'"
            ));
            DEFAULT_TOOL_LEASE_TTL_MS
        } else {
            ttl_ms
        }
    });
    let heartbeat_raw = blank_as_unset(inputs.heartbeat_ms.value());
    let heartbeat_set = heartbeat_raw.is_ok();
    let cluster_heartbeat_ms = findings.input(CLUSTER_HEARTBEAT_MS, |problems| {
        let heartbeat_ms = parse_var(
            CLUSTER_HEARTBEAT_MS,
            heartbeat_raw,
            DEFAULT_CLUSTER_HEARTBEAT_MS,
            "millisecond duration",
            problems,
        );
        let heartbeat_ms = validate_positive_u64(
            CLUSTER_HEARTBEAT_MS,
            heartbeat_ms,
            DEFAULT_CLUSTER_HEARTBEAT_MS,
            problems,
        );
        if heartbeat_ms < MIN_CLUSTER_HEARTBEAT_MS {
            problems.push(format!(
                "{CLUSTER_HEARTBEAT_MS} must be at least {MIN_CLUSTER_HEARTBEAT_MS} milliseconds, got '{heartbeat_ms}'"
            ));
            DEFAULT_CLUSTER_HEARTBEAT_MS
        } else {
            heartbeat_ms
        }
    });
    let member_stale_raw = blank_as_unset(inputs.member_stale_ms.value());
    let member_stale_set = member_stale_raw.is_ok();
    let member_stale_ms = findings.input(CLUSTER_MEMBER_STALE_MS, |problems| {
        let stale_ms = parse_var(
            CLUSTER_MEMBER_STALE_MS,
            member_stale_raw,
            DEFAULT_CLUSTER_MEMBER_STALE_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_u64(
            CLUSTER_MEMBER_STALE_MS,
            stale_ms,
            DEFAULT_CLUSTER_MEMBER_STALE_MS,
            problems,
        )
    });
    // Against the heartbeat as parsed, its default included when it was
    // refused, which is the interval the replica would heartbeat at.
    let minimum_stale_ms = cluster_heartbeat_ms.saturating_mul(MIN_CLUSTER_STALE_HEARTBEATS);
    let cluster_member_stale_ms = if member_stale_ms < minimum_stale_ms {
        findings.refuse(
            CLUSTER_MEMBER_STALE_MS,
            ConfigRule::ClusterMemberStaleWindow,
            format!(
                "{CLUSTER_MEMBER_STALE_MS} must be at least {MIN_CLUSTER_STALE_HEARTBEATS} x {CLUSTER_HEARTBEAT_MS} ({minimum_stale_ms} milliseconds) so one slow heartbeat never makes a live replica look stale, got '{member_stale_ms}'"
            ),
        );
        minimum_stale_ms.max(DEFAULT_CLUSTER_MEMBER_STALE_MS)
    } else {
        member_stale_ms
    };
    let maintenance_interval_raw = blank_as_unset(inputs.maintenance_interval_ms.value());
    let maintenance_interval_set = maintenance_interval_raw.is_ok();
    let cluster_maintenance_interval_ms =
        findings.input(CLUSTER_MAINTENANCE_INTERVAL_MS, |problems| {
            let interval_ms = parse_var(
                CLUSTER_MAINTENANCE_INTERVAL_MS,
                maintenance_interval_raw,
                DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
                "millisecond duration",
                problems,
            );
            let interval_ms = validate_positive_u64(
                CLUSTER_MAINTENANCE_INTERVAL_MS,
                interval_ms,
                DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
                problems,
            );
            if interval_ms < MIN_CLUSTER_MAINTENANCE_INTERVAL_MS {
                problems.push(format!(
                    "{CLUSTER_MAINTENANCE_INTERVAL_MS} must be at least {MIN_CLUSTER_MAINTENANCE_INTERVAL_MS} milliseconds, got '{interval_ms}'"
                ));
                DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS
            } else {
                interval_ms
            }
        });
    let maintenance_lease_ttl_raw = blank_as_unset(inputs.maintenance_lease_ttl_ms.value());
    let maintenance_lease_ttl_set = maintenance_lease_ttl_raw.is_ok();
    let cluster_maintenance_lease_ttl_ms =
        findings.input(CLUSTER_MAINTENANCE_LEASE_TTL_MS, |problems| {
            let ttl_ms = parse_var(
                CLUSTER_MAINTENANCE_LEASE_TTL_MS,
                maintenance_lease_ttl_raw,
                DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
                "millisecond duration",
                problems,
            );
            let ttl_ms = validate_positive_u64(
                CLUSTER_MAINTENANCE_LEASE_TTL_MS,
                ttl_ms,
                DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
                problems,
            );
            if ttl_ms < MIN_CLUSTER_MAINTENANCE_LEASE_TTL_MS {
                problems.push(format!(
                    "{CLUSTER_MAINTENANCE_LEASE_TTL_MS} must be at least {MIN_CLUSTER_MAINTENANCE_LEASE_TTL_MS} milliseconds (the lease is renewed at a third of its TTL), got '{ttl_ms}'"
                ));
                DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS
            } else {
                ttl_ms
            }
        });
    // The readiness probe's cache window. Standalone `/readyz` consults no
    // authority, so a value there would configure a check that never runs.
    let readiness_probe_cache_raw = blank_as_unset(inputs.readiness_probe_cache_ms.value());
    let readiness_probe_cache_set = readiness_probe_cache_raw.is_ok();
    let readiness_probe_cache_ms = findings.input(READINESS_PROBE_CACHE_MS, |problems| {
        let cache_ms = parse_var(
            READINESS_PROBE_CACHE_MS,
            readiness_probe_cache_raw,
            DEFAULT_READINESS_PROBE_CACHE_MS,
            "millisecond duration",
            problems,
        );
        if cache_ms > MAX_READINESS_PROBE_CACHE_MS {
            problems.push(format!(
                "{READINESS_PROBE_CACHE_MS} must be at most {MAX_READINESS_PROBE_CACHE_MS} milliseconds so a readiness answer is never older than the probe interval that asked for it, got '{cache_ms}'"
            ));
            DEFAULT_READINESS_PROBE_CACHE_MS
        } else {
            cache_ms
        }
    });
    let cluster_status_expose_hostnames =
        findings.input(CLUSTER_STATUS_EXPOSE_HOSTNAMES, |problems| {
            parse_var(
                CLUSTER_STATUS_EXPOSE_HOSTNAMES,
                blank_as_unset(inputs.status_expose_hostnames.value()),
                false,
                "boolean",
                problems,
            )
        });
    let audit_postgres_retention_raw = blank_as_unset(inputs.audit_postgres_retention_days.value());
    let audit_postgres_retention_set = audit_postgres_retention_raw.is_ok();
    let audit_postgres_retention_days = findings.input(AUDIT_POSTGRES_RETENTION_DAYS, |problems| {
        let days = parse_optional_var(
            AUDIT_POSTGRES_RETENTION_DAYS,
            audit_postgres_retention_raw,
            "day count",
            problems,
        );
        normalize_audit_retention_days(AUDIT_POSTGRES_RETENTION_DAYS, "PostgreSQL", days, problems)
    });

    Checked::new(
        Cluster {
            tool_lease_ttl_ms,
            cluster_heartbeat_ms,
            cluster_member_stale_ms,
            cluster_maintenance_interval_ms,
            cluster_maintenance_lease_ttl_ms,
            readiness_probe_cache_ms,
            cluster_status_expose_hostnames,
            audit_postgres_retention_days,
            heartbeat_set,
            member_stale_set,
            maintenance_interval_set,
            maintenance_lease_ttl_set,
            readiness_probe_cache_set,
            audit_postgres_retention_set,
            provenance,
        },
        findings,
    )
}

/// The state backend's and PostgreSQL's inputs, as the reader returned them.
pub(super) struct StateBackendInputs {
    state_backend: RawInput,
    deployment_id: RawInput,
    database_url_file: RawInput,
    database_tls_mode: RawInput,
    database_tls_ca_file: RawInput,
    database_pool_max: RawInput,
    database_connect_timeout_ms: RawInput,
    database_acquire_timeout_ms: RawInput,
    database_statement_timeout_ms: RawInput,
    database_idle_in_transaction_timeout_ms: RawInput,
    database_lock_timeout_ms: RawInput,
    database_startup_retry_limit: RawInput,
    database_auto_migrate: RawInput,
    database_migration_statement_timeout_ms: RawInput,
}

impl StateBackendInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            state_backend: RawInput::new(STATE_BACKEND, get_var(STATE_BACKEND)),
            deployment_id: RawInput::new(DEPLOYMENT_ID, get_var(DEPLOYMENT_ID)),
            database_url_file: RawInput::new(DATABASE_URL_FILE, get_var(DATABASE_URL_FILE)),
            database_tls_mode: RawInput::new(DATABASE_TLS_MODE, get_var(DATABASE_TLS_MODE)),
            database_tls_ca_file: RawInput::new(
                DATABASE_TLS_CA_FILE,
                get_var(DATABASE_TLS_CA_FILE),
            ),
            database_pool_max: RawInput::new(DATABASE_POOL_MAX, get_var(DATABASE_POOL_MAX)),
            database_connect_timeout_ms: RawInput::new(
                DATABASE_CONNECT_TIMEOUT_MS,
                get_var(DATABASE_CONNECT_TIMEOUT_MS),
            ),
            database_acquire_timeout_ms: RawInput::new(
                DATABASE_ACQUIRE_TIMEOUT_MS,
                get_var(DATABASE_ACQUIRE_TIMEOUT_MS),
            ),
            database_statement_timeout_ms: RawInput::new(
                DATABASE_STATEMENT_TIMEOUT_MS,
                get_var(DATABASE_STATEMENT_TIMEOUT_MS),
            ),
            database_idle_in_transaction_timeout_ms: RawInput::new(
                DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
                get_var(DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS),
            ),
            database_lock_timeout_ms: RawInput::new(
                DATABASE_LOCK_TIMEOUT_MS,
                get_var(DATABASE_LOCK_TIMEOUT_MS),
            ),
            database_startup_retry_limit: RawInput::new(
                DATABASE_STARTUP_RETRY_LIMIT,
                get_var(DATABASE_STARTUP_RETRY_LIMIT),
            ),
            database_auto_migrate: RawInput::new(
                DATABASE_AUTO_MIGRATE,
                get_var(DATABASE_AUTO_MIGRATE),
            ),
            database_migration_statement_timeout_ms: RawInput::new(
                DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                get_var(DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.state_backend,
            &self.deployment_id,
            &self.database_url_file,
            &self.database_tls_mode,
            &self.database_tls_ca_file,
            &self.database_pool_max,
            &self.database_connect_timeout_ms,
            &self.database_acquire_timeout_ms,
            &self.database_statement_timeout_ms,
            &self.database_idle_in_transaction_timeout_ms,
            &self.database_lock_timeout_ms,
            &self.database_startup_retry_limit,
            &self.database_auto_migrate,
            &self.database_migration_statement_timeout_ms,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The storage blocks read before the state backend.
pub(super) struct StorageBlocks {
    pub(super) audit: AuditStores,
    pub(super) discovery: DiscoveryStores,
    pub(super) documents: Documents,
    pub(super) cluster: Cluster,
}

/// PostgreSQL's pool, timeout and TLS settings, validated.
///
/// The same settings as [`DatabaseSettings`], except that the file holding
/// the connection string is a [`SecretLocator`]: the string carries the
/// database credentials, so the plan never prints where it is kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DatabasePlan {
    pub(crate) pool_max: usize,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) acquire_timeout_ms: u64,
    pub(crate) statement_timeout_ms: u64,
    pub(crate) idle_in_transaction_timeout_ms: u64,
    pub(crate) lock_timeout_ms: u64,
    pub(crate) startup_retry_limit: u64,
    pub(crate) auto_migrate: bool,
    pub(crate) migration_statement_timeout_ms: u64,
    pub(crate) tls_mode: DatabaseTlsMode,
    pub(crate) tls_ca_file: Option<String>,
    pub(crate) url_file: Option<SecretLocator>,
}

impl DatabasePlan {
    /// The legacy `Config` field.
    pub(super) fn into_settings(self) -> DatabaseSettings {
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
        } = self;
        DatabaseSettings {
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
            url_file: url_file.map(SecretLocator::into_locator),
        }
    }
}

/// The validated storage settings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoragePlan {
    pub(crate) audit_log_file: Option<String>,
    pub(crate) audit_sqlite_path: Option<String>,
    pub(crate) audit_sqlite_retention_days: Option<u32>,
    pub(crate) audit_successful_probes_metrics_only: bool,
    pub(crate) discovery_sqlite_path: Option<String>,
    pub(crate) discovery_endpoint_limit: usize,
    pub(crate) discovery_projector_lease_ttl_ms: u64,
    pub(crate) discovery_projector_poll_ms: u64,
    pub(crate) discovery_projector_batch: usize,
    pub(crate) principal_sqlite_path: Option<String>,
    pub(crate) openapi_spec_path: Option<PathBuf>,
    pub(crate) policy_file: Option<String>,
    pub(crate) tools_file: Option<String>,
    pub(crate) policy_history_sqlite_path: Option<String>,
    pub(crate) tool_lease_ttl_ms: u64,
    pub(crate) cluster_heartbeat_ms: u64,
    pub(crate) cluster_member_stale_ms: u64,
    pub(crate) cluster_maintenance_interval_ms: u64,
    pub(crate) cluster_maintenance_lease_ttl_ms: u64,
    pub(crate) readiness_probe_cache_ms: u64,
    pub(crate) cluster_status_expose_hostnames: bool,
    pub(crate) audit_postgres_retention_days: Option<u32>,
    pub(crate) state_backend: StateBackend,
    pub(crate) deployment_id: Option<String>,
    pub(crate) database: DatabasePlan,
    /// Where each of the five blocks' inputs came from, in the order they are
    /// read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// The state backend and PostgreSQL, each input parsed on its own.
struct ParsedStateBackend {
    state_backend: StateBackend,
    deployment_id: Option<String>,
    database: DatabasePlan,
}

/// Parses the state backend block, then checks the rules between the backend
/// and everything that depends on it, and builds the plan.
///
/// Everything is validated in both modes, but nothing activates outside
/// `STATE_BACKEND=postgres`: standalone mode must remain byte-for-byte
/// unchanged. Each mode's requirements, and the refusal of the other mode's
/// material, are checked after every input is parsed, so the operator sees
/// every problem in one pass.
pub(super) fn compile(
    inputs: StateBackendInputs,
    blocks: StorageBlocks,
    identity: &IdentityPlan,
    connections: &ConnectionsPlan,
    runtime: &RuntimePlan,
) -> Checked<StoragePlan> {
    let mut findings = Findings::default();
    let parsed = parse_state_backend(&inputs, &mut findings);
    let StorageBlocks {
        audit,
        discovery,
        documents,
        cluster,
    } = blocks;
    let backend = parsed.state_backend;

    // Every rule below is reported once the last PostgreSQL input is read.
    let after = DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS;
    if backend == StateBackend::Postgres {
        reject_local_authority_in_postgres_mode(
            parsed.deployment_id.as_deref(),
            parsed.database.url_file.is_some(),
            &[
                (POLICY_FILE, documents.policy_file.is_some()),
                (TOOLS_FILE, documents.tools_file.is_some()),
                (AUDIT_SQLITE_PATH, audit.audit_sqlite_path.is_some()),
                (
                    DISCOVERY_SQLITE_PATH,
                    discovery.discovery_sqlite_path.is_some(),
                ),
                (
                    PRINCIPAL_SQLITE_PATH,
                    discovery.principal_sqlite_path.is_some(),
                ),
                (
                    CONNECTIONS_SQLITE_PATH,
                    connections.connections_sqlite_path.is_some(),
                ),
                // The local secret keyring encrypts material stored in the
                // connections SQLite database, which cluster mode does not
                // have: migration 0006 deliberately omits the
                // `connection_local_secrets` table, and a cluster deployment
                // binds credentials through an external secret provider
                // instead. Naming the setting is better than failing later
                // inside the provider with "a managed store is required".
                (
                    CONNECTION_LOCAL_SECRET_KEYRING,
                    !connections.connection_local_secret_keyring.is_empty(),
                ),
                (
                    POLICY_HISTORY_SQLITE_PATH,
                    documents.policy_history_sqlite_path.is_some(),
                ),
                (
                    SERVICE_TOKEN_SQLITE_PATH,
                    identity.service_token_sqlite_path.is_some(),
                ),
            ],
            &mut findings,
        );
    }

    // PostgreSQL material configured while standalone mode is selected is
    // the inverse gap: material a mode that will never read it invites an
    // operator to believe a database is configured when none is consulted.
    // The same rule the client-certificate settings apply to a CA bundle
    // configured against an off mode, and a deployment ID names a cluster
    // namespace that does not exist in standalone mode.
    let session_storage = identity
        .admin_session
        .as_ref()
        .map(|session| session.storage);
    match backend {
        StateBackend::Postgres => {
            if session_storage == Some(AdminSessionStorage::StandaloneMemory) {
                findings.refuse(
                    after,
                    ConfigRule::AdminSessionStoreBackend,
                    format!("{ADMIN_SESSION_MODE}=standalone_memory is unsupported with {STATE_BACKEND}=postgres; no process-local HA fallback is provided"),
                );
            }
            if identity.admin_login_provider.is_some() && connections.admin_login_keyring.is_empty()
            {
                findings.refuse(
                    after,
                    ConfigRule::ClusterModeRequirements,
                    format!(
                        "{ADMIN_LOGIN_KEYRING} is required when {STATE_BACKEND}=postgres and {ADMIN_LOGIN_PROVIDER} is set; pending admin logins are sealed in the database under it"
                    ),
                );
            }
            if connections.rate_limit_keyring.is_empty() {
                findings.refuse(
                    after,
                    ConfigRule::ClusterModeRequirements,
                    format!(
                        "{RATE_LIMIT_KEYRING} is required when {STATE_BACKEND}=postgres; shared rate-limit buckets are keyed by an HMAC under it"
                    ),
                );
            }
        }
        StateBackend::Sqlite => {
            if session_storage == Some(AdminSessionStorage::ClusterPostgres) {
                findings.refuse(
                    after,
                    ConfigRule::AdminSessionStoreBackend,
                    format!(
                        "{ADMIN_SESSION_MODE}=cluster_postgres requires {STATE_BACKEND}=postgres; standalone mode keeps admin sessions in process memory (standalone_memory)"
                    ),
                );
            }
            if !connections.admin_login_keyring.is_empty() {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{ADMIN_LOGIN_KEYRING} is set while {STATE_BACKEND} is sqlite; standalone mode keeps pending admin logins in memory and never reads it"
                    ),
                );
            }
            if !connections.rate_limit_keyring.is_empty() {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{RATE_LIMIT_KEYRING} is set while {STATE_BACKEND} is sqlite; standalone mode keeps rate-limit buckets in memory and never reads it"
                    ),
                );
            }
            // The discovery projector is cluster mode's replacement for the
            // SQLite aggregator sink; standalone mode never starts one, so
            // its cadence settings are material nothing reads.
            for (setting, set) in discovery.projector_settings_set {
                if set {
                    findings.refuse(
                        after,
                        ConfigRule::ClusterSettingInStandaloneMode,
                        format!(
                            "{setting} is set while {STATE_BACKEND} is sqlite; the discovery projector runs only in cluster mode and standalone mode never reads it — set {STATE_BACKEND}=postgres or unset {setting}"
                        ),
                    );
                }
            }
            if cluster.heartbeat_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{CLUSTER_HEARTBEAT_MS} is set while {STATE_BACKEND} is sqlite; standalone mode has no cluster membership and never reads it"
                    ),
                );
            }
            if cluster.member_stale_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{CLUSTER_MEMBER_STALE_MS} is set while {STATE_BACKEND} is sqlite; standalone mode has no cluster membership and never reads it"
                    ),
                );
            }
            if cluster.maintenance_interval_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{CLUSTER_MAINTENANCE_INTERVAL_MS} is set while {STATE_BACKEND} is sqlite; standalone mode has no maintenance singleton and never reads it"
                    ),
                );
            }
            if cluster.maintenance_lease_ttl_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{CLUSTER_MAINTENANCE_LEASE_TTL_MS} is set while {STATE_BACKEND} is sqlite; standalone mode has no maintenance singleton and never reads it"
                    ),
                );
            }
            if cluster.audit_postgres_retention_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{AUDIT_POSTGRES_RETENTION_DAYS} is set while {STATE_BACKEND} is sqlite; standalone mode has no PostgreSQL audit store and never reads it (use {AUDIT_SQLITE_RETENTION_DAYS})"
                    ),
                );
            }
            if cluster.readiness_probe_cache_set {
                findings.refuse(
                    after,
                    ConfigRule::ClusterSettingInStandaloneMode,
                    format!(
                        "{READINESS_PROBE_CACHE_MS} is set while {STATE_BACKEND} is sqlite; standalone readiness consults no shared authority and never reads it"
                    ),
                );
            }
        }
    }

    // Payload-shape capture needs a destination. Standalone mode's is the
    // discovery SQLite database; cluster mode's is the projector's PostgreSQL
    // tables, which every cluster replica has.
    if runtime.payload_capture_enabled
        && discovery.discovery_sqlite_path.is_none()
        && backend == StateBackend::Sqlite
    {
        findings.refuse(
            after,
            ConfigRule::PayloadCaptureDestination,
            format!(
                "{PAYLOAD_CAPTURE_ENABLED}=true requires {DISCOVERY_SQLITE_PATH} to be set so captured request shapes have an explicit SQLite storage destination"
            ),
        );
    }
    if backend == StateBackend::Sqlite {
        if parsed.database.url_file.is_some() {
            findings.refuse(
                after,
                ConfigRule::ClusterSettingInStandaloneMode,
                format!(
                    "{DATABASE_URL_FILE} is set while {STATE_BACKEND} is sqlite; set {STATE_BACKEND}=postgres to use PostgreSQL, or unset {DATABASE_URL_FILE}"
                ),
            );
        }
        if parsed.database.tls_ca_file.is_some() {
            findings.refuse(
                after,
                ConfigRule::ClusterSettingInStandaloneMode,
                format!(
                    "{DATABASE_TLS_CA_FILE} is set while {STATE_BACKEND} is sqlite; set {STATE_BACKEND}=postgres to use PostgreSQL, or unset {DATABASE_TLS_CA_FILE}"
                ),
            );
        }
        if parsed.deployment_id.is_some() {
            findings.refuse(
                after,
                ConfigRule::ClusterSettingInStandaloneMode,
                format!(
                    "{DEPLOYMENT_ID} is set while {STATE_BACKEND} is sqlite; a deployment ID scopes a cluster-mode deployment and standalone mode never reads it — set {STATE_BACKEND}=postgres or unset {DEPLOYMENT_ID}"
                ),
            );
        }
        if parsed.database.auto_migrate {
            findings.refuse(
                after,
                ConfigRule::ClusterSettingInStandaloneMode,
                format!(
                    "{DATABASE_AUTO_MIGRATE}=true while {STATE_BACKEND} is sqlite; there is no schema to migrate in standalone mode — set {STATE_BACKEND}=postgres or unset {DATABASE_AUTO_MIGRATE}"
                ),
            );
        }
    }

    let provenance = [
        audit.provenance,
        discovery.provenance,
        documents.provenance,
        cluster.provenance,
        inputs.provenance(),
    ]
    .concat();
    let ParsedStateBackend {
        state_backend,
        deployment_id,
        database,
    } = parsed;
    Checked::new(
        StoragePlan {
            audit_log_file: audit.audit_log_file,
            audit_sqlite_path: audit.audit_sqlite_path,
            audit_sqlite_retention_days: audit.audit_sqlite_retention_days,
            audit_successful_probes_metrics_only: audit.audit_successful_probes_metrics_only,
            discovery_sqlite_path: discovery.discovery_sqlite_path,
            discovery_endpoint_limit: discovery.discovery_endpoint_limit,
            discovery_projector_lease_ttl_ms: discovery.discovery_projector_lease_ttl_ms,
            discovery_projector_poll_ms: discovery.discovery_projector_poll_ms,
            discovery_projector_batch: discovery.discovery_projector_batch,
            principal_sqlite_path: discovery.principal_sqlite_path,
            openapi_spec_path: documents.openapi_spec_path,
            policy_file: documents.policy_file,
            tools_file: documents.tools_file,
            policy_history_sqlite_path: documents.policy_history_sqlite_path,
            tool_lease_ttl_ms: cluster.tool_lease_ttl_ms,
            cluster_heartbeat_ms: cluster.cluster_heartbeat_ms,
            cluster_member_stale_ms: cluster.cluster_member_stale_ms,
            cluster_maintenance_interval_ms: cluster.cluster_maintenance_interval_ms,
            cluster_maintenance_lease_ttl_ms: cluster.cluster_maintenance_lease_ttl_ms,
            readiness_probe_cache_ms: cluster.readiness_probe_cache_ms,
            cluster_status_expose_hostnames: cluster.cluster_status_expose_hostnames,
            audit_postgres_retention_days: cluster.audit_postgres_retention_days,
            state_backend,
            deployment_id,
            database,
            provenance,
        },
        findings,
    )
}

fn parse_state_backend(inputs: &StateBackendInputs, findings: &mut Findings) -> ParsedStateBackend {
    let state_backend = findings.input(STATE_BACKEND, |problems| {
        parse_var(
            STATE_BACKEND,
            inputs.state_backend.value(),
            StateBackend::Sqlite,
            "state backend",
            problems,
        )
    });
    let deployment_id = findings.input(DEPLOYMENT_ID, |problems| {
        let deployment_id =
            parse_optional_string(DEPLOYMENT_ID, inputs.deployment_id.value(), problems);
        validate_deployment_id(DEPLOYMENT_ID, deployment_id, problems)
    });
    let url_file = findings.input(DATABASE_URL_FILE, |problems| {
        parse_optional_string(
            DATABASE_URL_FILE,
            inputs.database_url_file.value(),
            problems,
        )
    });
    let tls_mode = findings.input(DATABASE_TLS_MODE, |problems| {
        parse_var(
            DATABASE_TLS_MODE,
            inputs.database_tls_mode.value(),
            DatabaseTlsMode::Verify,
            "database TLS mode",
            problems,
        )
    });
    let tls_ca_file = findings.input(DATABASE_TLS_CA_FILE, |problems| {
        parse_optional_string(
            DATABASE_TLS_CA_FILE,
            inputs.database_tls_ca_file.value(),
            problems,
        )
    });
    let pool_max = findings.input(DATABASE_POOL_MAX, |problems| {
        let pool_max = parse_var(
            DATABASE_POOL_MAX,
            inputs.database_pool_max.value(),
            DEFAULT_DATABASE_POOL_MAX as u64,
            "connection count",
            problems,
        );
        validate_positive_bounded_u64(
            DATABASE_POOL_MAX,
            pool_max,
            MAX_DATABASE_POOL_MAX as u64,
            DEFAULT_DATABASE_POOL_MAX as u64,
            problems,
        ) as usize
    });
    let connect_timeout_ms = timeout_ms(
        DATABASE_CONNECT_TIMEOUT_MS,
        &inputs.database_connect_timeout_ms,
        DEFAULT_DATABASE_CONNECT_TIMEOUT_MS,
        findings,
    );
    let acquire_timeout_ms = timeout_ms(
        DATABASE_ACQUIRE_TIMEOUT_MS,
        &inputs.database_acquire_timeout_ms,
        DEFAULT_DATABASE_ACQUIRE_TIMEOUT_MS,
        findings,
    );
    let statement_timeout_ms = timeout_ms(
        DATABASE_STATEMENT_TIMEOUT_MS,
        &inputs.database_statement_timeout_ms,
        DEFAULT_DATABASE_STATEMENT_TIMEOUT_MS,
        findings,
    );
    let idle_in_transaction_timeout_ms = timeout_ms(
        DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
        &inputs.database_idle_in_transaction_timeout_ms,
        DEFAULT_DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
        findings,
    );
    let lock_timeout_ms = timeout_ms(
        DATABASE_LOCK_TIMEOUT_MS,
        &inputs.database_lock_timeout_ms,
        DEFAULT_DATABASE_LOCK_TIMEOUT_MS,
        findings,
    );
    let startup_retry_limit = findings.input(DATABASE_STARTUP_RETRY_LIMIT, |problems| {
        let limit = parse_var(
            DATABASE_STARTUP_RETRY_LIMIT,
            inputs.database_startup_retry_limit.value(),
            DEFAULT_DATABASE_STARTUP_RETRY_LIMIT,
            "retry count",
            problems,
        );
        validate_maximum_u64(
            DATABASE_STARTUP_RETRY_LIMIT,
            limit,
            MAX_DATABASE_STARTUP_RETRY_LIMIT,
            DEFAULT_DATABASE_STARTUP_RETRY_LIMIT,
            problems,
        )
    });
    let auto_migrate = findings.input(DATABASE_AUTO_MIGRATE, |problems| {
        parse_var(
            DATABASE_AUTO_MIGRATE,
            inputs.database_auto_migrate.value(),
            false,
            "boolean",
            problems,
        )
    });
    let migration_statement_timeout_ms =
        findings.input(DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS, |problems| {
            let timeout_ms = parse_var(
                DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                inputs.database_migration_statement_timeout_ms.value(),
                DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                "millisecond duration",
                problems,
            );
            let timeout_ms = validate_positive_timeout_ms(
                DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                timeout_ms,
                DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                problems,
            );
            validate_maximum_u64(
                DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                timeout_ms,
                MAX_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                DEFAULT_DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS,
                problems,
            )
        });

    ParsedStateBackend {
        state_backend,
        deployment_id,
        database: DatabasePlan {
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
            url_file: url_file.map(SecretLocator::new),
        },
    }
}

/// A positive millisecond timeout with a default.
fn timeout_ms(
    setting: &'static str,
    input: &RawInput,
    default: u64,
    findings: &mut Findings,
) -> u64 {
    findings.input(setting, |problems| {
        let timeout_ms = parse_var(
            setting,
            input.value(),
            default,
            "millisecond duration",
            problems,
        );
        validate_positive_timeout_ms(setting, timeout_ms, default, problems)
    })
}

/// Rejects authoritative writable local stores when PostgreSQL is selected,
/// and names what cluster mode cannot run without.
///
/// In cluster mode PostgreSQL is the single authority (ADR-0007): a local
/// `POLICY_FILE`, `TOOLS_FILE`, or `*_SQLITE_PATH` next to it is not a harmless
/// leftover but a second authority a replica could fall back to, which is the
/// stale-allow shape the whole mode exists to prevent. Files may return later
/// as explicit import/bootstrap inputs; until that workflow exists, any such
/// setting fails startup naming itself.
fn reject_local_authority_in_postgres_mode(
    deployment_id: Option<&str>,
    database_url_file_configured: bool,
    local_authority_settings: &[(&str, bool)],
    findings: &mut Findings,
) {
    let after = DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS;
    if deployment_id.is_none() {
        findings.refuse(
            after,
            ConfigRule::ClusterModeRequirements,
            format!(
                "{DEPLOYMENT_ID} is required when {STATE_BACKEND}=postgres; it scopes every authoritative row, lock, lease, and notification of the deployment and is non-secret"
            ),
        );
    }
    if !database_url_file_configured {
        findings.refuse(
            after,
            ConfigRule::ClusterModeRequirements,
            format!(
                "{DATABASE_URL_FILE} is required when {STATE_BACKEND}=postgres; the PostgreSQL connection string is supplied as a secret file, never as a raw environment variable"
            ),
        );
    }
    for (setting, set) in local_authority_settings {
        if *set {
            findings.refuse(
                after,
                ConfigRule::LocalAuthorityInClusterMode,
                format!(
                    "{setting} is set while {STATE_BACKEND}=postgres; in cluster mode PostgreSQL is the single authority and local stores are rejected (import/bootstrap workflows arrive in a later #241 PR) — unset {setting}"
                ),
            );
        }
    }
}
