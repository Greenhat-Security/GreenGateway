//! The validated configuration plan, and the compiler that builds it from
//! the environment (issue #433, PR 2).
//!
//! [`compile`] requests every block of inputs in the inventory's order, runs
//! each block's pure stage on the values it read, and collects every problem
//! in one [`Report`], in the order the legacy parser has always reported
//! them. It returns a [`ConfigPlan`] only when no stage found anything. The
//! plan holds every domain's validated settings and the provenance of every
//! input, and carries secret material only as locators: TLS private keys and
//! the database URL file as `SecretLocator`s, and the Connections aliases,
//! keyrings and providers in types that print them redacted. Nothing here or
//! in the stages opens a file, resolves a name or reaches a store, a provider
//! or the network; preflight and activation stay with startup, which runs
//! them as stages of their own after this compiler has returned
//! (`bootstrap::start_serving`, #433 PR 3).
//!
//! `Config::from_env_vars` is this compiler followed by
//! [`ConfigPlan::into_config`], which is why its behaviour has not changed.

use std::env::VarError;

use super::{
    authority_events::AuthorityEventInputs,
    connections::{self, ConnectionInputs, ConnectionsPlan},
    diagnostic::{Lookups, Report},
    egress::{self, EgressInputs, EgressPlan},
    identity::{
        self, AdminSurfaceInputs, AuthenticationInputs, IdentityPlan, ProviderAndCsrfInputs,
        RbacExemptionInputs,
    },
    listeners::{self, ListenerInputs, ListenerPlan, TlsMaterial},
    proxy::{self, ProxyPlan, RoutingInputs, TrustedProxyInputs},
    runtime::{
        self, ContentTypeInputs, RequestBoundInputs, RuntimeBlocks, RuntimePlan, ShutdownInputs,
        SignalInputs, ToolRuntimeInputs, ToolTimeoutInputs,
    },
    storage::{
        self, AuditStoreInputs, ClusterInputs, DiscoveryStoreInputs, DocumentInputs,
        StateBackendInputs, StorageBlocks, StoragePlan,
    },
    Config, ConfigError,
};
#[cfg(test)]
use super::{inventory, stage::Provenance};

/// Every domain's validated settings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConfigPlan {
    pub(crate) listeners: ListenerPlan,
    pub(crate) identity: IdentityPlan,
    pub(crate) proxy: ProxyPlan,
    pub(crate) storage: StoragePlan,
    pub(crate) connections: ConnectionsPlan,
    pub(crate) egress: EgressPlan,
    pub(crate) runtime: RuntimePlan,
}

/// Compiles the configuration a reader describes into a validated plan, or
/// into every problem it has, each with its value-free diagnostic.
pub(crate) fn compile(
    mut get_var: impl FnMut(&str) -> Result<String, VarError>,
) -> Result<ConfigPlan, ConfigError> {
    // How each lookup came back -- unset, empty, not Unicode, or set, never
    // the value -- is remembered so a refusal can also be reported as
    // value-free diagnostics. Every lookup still reaches the caller's reader
    // exactly as before, in the same order.
    let mut lookups = Lookups::default();
    let (plan, report) = compile_blocks(|name: &str| {
        let value = get_var(name);
        lookups.record(name, &value);
        value
    });
    if report.is_empty() {
        Ok(plan)
    } else {
        let (problems, diagnostics) = report.into_problems_and_diagnostics(&lookups);
        Err(ConfigError {
            problems,
            diagnostics,
        })
    }
}

/// Reads and compiles every block, where the legacy parser read it.
///
/// The plan is always built, with defaults where an input was refused, so
/// that every later block still checks its own inputs and one pass reports
/// every problem. It is a validated plan only when the report is empty.
pub(super) fn compile_blocks(
    mut get_var: impl FnMut(&str) -> Result<String, VarError>,
) -> (ConfigPlan, Report) {
    let mut report = Report::default();

    let listeners = listeners::compile(ListenerInputs::read(&mut get_var)).report(&mut report);
    let admin_surface =
        identity::compile_admin_surface(AdminSurfaceInputs::read(&mut get_var)).report(&mut report);
    let audit =
        storage::compile_audit_stores(AuditStoreInputs::read(&mut get_var)).report(&mut report);
    let shutdown =
        runtime::compile_shutdown(ShutdownInputs::read(&mut get_var)).report(&mut report);
    let discovery = storage::compile_discovery_stores(DiscoveryStoreInputs::read(&mut get_var))
        .report(&mut report);
    let connections =
        connections::compile(ConnectionInputs::read(&mut get_var)).report(&mut report);
    let signals = runtime::compile_signals(SignalInputs::read(&mut get_var)).report(&mut report);
    let documents =
        storage::compile_documents(DocumentInputs::read(&mut get_var)).report(&mut report);
    let request_bounds =
        runtime::compile_request_bounds(RequestBoundInputs::read(&mut get_var)).report(&mut report);
    let trusted_proxy =
        proxy::compile_trusted_proxy(TrustedProxyInputs::read(&mut get_var)).report(&mut report);
    let rbac_exemptions =
        identity::compile_rbac_exemptions(RbacExemptionInputs::read(&mut get_var), &admin_surface)
            .report(&mut report);
    let content_types =
        runtime::compile_content_types(ContentTypeInputs::read(&mut get_var)).report(&mut report);
    let authentication =
        identity::compile_authentication(AuthenticationInputs::read(&mut get_var), &admin_surface)
            .report(&mut report);
    let tool_runtime =
        runtime::compile_tool_runtime(ToolRuntimeInputs::read(&mut get_var)).report(&mut report);
    let cluster = storage::compile_cluster(ClusterInputs::read(&mut get_var)).report(&mut report);
    let runtime = runtime::compile(
        ToolTimeoutInputs::read(&mut get_var),
        RuntimeBlocks {
            shutdown,
            signals,
            request_bounds,
            content_types,
            tool_runtime,
        },
    )
    .report(&mut report);
    let identity = identity::compile(
        ProviderAndCsrfInputs::read(&mut get_var),
        admin_surface,
        rbac_exemptions,
        authentication,
    )
    .report(&mut report);
    let proxy = proxy::compile(
        RoutingInputs::read(&mut get_var),
        trusted_proxy,
        &identity,
        documents.policy_file_configured(),
    )
    .report(&mut report);
    let egress = egress::compile(EgressInputs::read(&mut get_var)).report(&mut report);
    let storage = storage::compile(
        StateBackendInputs::read(&mut get_var),
        AuthorityEventInputs::read(&mut get_var),
        StorageBlocks {
            audit,
            discovery,
            documents,
            cluster,
        },
        &identity,
        &connections,
        &runtime,
    )
    .report(&mut report);

    (
        ConfigPlan {
            listeners,
            identity,
            proxy,
            storage,
            connections,
            egress,
            runtime,
        },
        report,
    )
}

impl ConfigPlan {
    /// The legacy `Config` the plan describes: the same values, with the
    /// locators handed over as the paths startup opens. Serving startup
    /// converts the plan once, before its first stage that does I/O.
    pub(crate) fn into_config(self) -> Config {
        let ConfigPlan {
            listeners,
            identity,
            proxy,
            storage,
            connections,
            egress,
            runtime,
        } = self;
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
        } = listeners;
        let (tls_cert_files, tls_key_files) = data_tls.map(TlsMaterial::into_files).unzip();
        let (admin_tls_cert_files, admin_tls_key_files) =
            admin_tls.map(TlsMaterial::into_files).unzip();
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
        } = identity;
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
        } = proxy;
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
        } = storage;
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
        } = connections;
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
        } = egress;
        let RuntimePlan {
            shutdown_drain_delay_ms,
            shutdown_timeout_ms,
            audit_drain_timeout_ms,
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
        } = runtime;

        Config {
            listen_addr,
            admin_listen_addr,
            grpc_listen_addr,
            grpc_max_concurrent_streams,
            grpc_max_metadata_bytes,
            tls_cert_files,
            tls_key_files,
            admin_tls_cert_files,
            admin_tls_key_files,
            tls_min_version,
            tls_handshake_timeout_ms,
            tls_max_concurrent_handshakes,
            client_cert_auth,
            admin_client_cert_auth,
            admin_prefix,
            admin_login_provider,
            admin_session,
            admin_login_pending_ttl_secs,
            admin_login_pending_max_entries,
            admin_login_pending_max_per_ip,
            admin_login_keyring,
            rate_limit_keyring,
            gateway_public_url,
            audit_log_file,
            audit_sqlite_path,
            audit_sqlite_retention_days,
            audit_successful_probes_metrics_only,
            shutdown_drain_delay_ms,
            shutdown_timeout_ms,
            audit_drain_timeout_ms,
            discovery_sqlite_path,
            discovery_endpoint_limit,
            discovery_projector_lease_ttl_ms,
            discovery_projector_poll_ms,
            discovery_projector_batch,
            principal_sqlite_path,
            connections_sqlite_path,
            connection_local_secret_keyring,
            connection_vault_provider,
            connection_gcp_provider,
            connection_azure_provider,
            connection_aws_provider,
            connection_kubernetes_provider,
            connection_secret_aliases,
            connection_secrets_root,
            payload_capture_enabled,
            payload_capture_sample_rate,
            schema_mismatch_signal_threshold,
            error_rate_spike_signal_threshold,
            principal_new_to_endpoint_signal_threshold,
            volume_outlier_signal_threshold,
            rule_suggestion_baseline_window_hours,
            openapi_spec_path,
            policy_file,
            tools_file,
            policy_history_sqlite_path,
            cors_allow_origins,
            max_body_size,
            max_request_path_bytes,
            rate_limit_read_rps,
            rate_limit_read_burst,
            rate_limit_write_rps,
            rate_limit_write_burst,
            rate_limit_max_buckets,
            rate_limit_bucket_ttl_ms,
            trust_proxy_headers,
            trusted_proxy_cidrs,
            rbac_exempt_paths,
            validation_allowed_content_types,
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
            tool_runtime_queue_depth,
            tool_runtime_global_concurrency,
            tool_runtime_queue_timeout_ms,
            tool_lease_ttl_ms,
            cluster_heartbeat_ms,
            cluster_member_stale_ms,
            cluster_maintenance_interval_ms,
            cluster_maintenance_lease_ttl_ms,
            readiness_probe_cache_ms,
            cluster_status_expose_hostnames,
            audit_postgres_retention_days,
            authority_events,
            tool_runtime_default_timeout_ms,
            csrf_enabled,
            csrf_cookie_name,
            csrf_header_name,
            csrf_cookie_domain,
            csrf_exempt_paths,
            upstream_url,
            upstream_routes,
            mcp_upstream_servers,
            upstream_timeout_ms,
            upstream_response_idle_timeout_ms,
            upstream_connect_timeout_ms,
            egress_allowed_hosts,
            egress_timeout_ms,
            egress_response_idle_timeout_ms,
            egress_connect_timeout_ms,
            egress_max_response_bytes,
            egress_max_request_body_bytes,
            egress_nat64_prefixes,
            egress_deny_private_ips,
            state_backend,
            deployment_id,
            database: database.into_settings(),
        }
    }

    /// Where every input came from, in the order the inputs are read.
    #[cfg(test)]
    pub(super) fn provenance(&self) -> Vec<Provenance> {
        let mut provenance = [
            self.listeners.provenance.as_slice(),
            &self.identity.provenance,
            &self.proxy.provenance,
            &self.storage.provenance,
            &self.connections.provenance,
            &self.egress.provenance,
            &self.runtime.provenance,
        ]
        .concat();
        provenance.sort_by_key(|provenance| inventory::position(provenance.setting));
        provenance
    }
}
