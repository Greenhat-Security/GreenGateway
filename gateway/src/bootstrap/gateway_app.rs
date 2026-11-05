//! Activation's gateway build: every store, client, background task and
//! admin state the configuration and preflight's seeds call for, and the
//! routers that serve them, in the order startup has always built them.
use super::*;

#[cfg(test)]
pub(crate) fn app(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
) -> Result<Router, Box<dyn std::error::Error>> {
    app_with_process_started_at(
        config,
        metrics_handle,
        audit_log,
        audit_event_sender,
        Instant::now(),
    )
}

#[cfg(test)]
pub(crate) fn app_with_process_started_at(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
    process_started_at: Instant,
) -> Result<Router, Box<dyn std::error::Error>> {
    match gateway_app_with_process_started_at(
        config,
        metrics_handle,
        audit_log,
        audit_event_sender,
        process_started_at,
    )?
    .http
    {
        GatewayApp::Unified(router) => Ok(router),
        GatewayApp::Split { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "app_with_process_started_at requires ADMIN_LISTEN_ADDR to be unset",
        )
        .into()),
    }
}

#[cfg(test)]
pub(crate) fn gateway_app_with_process_started_at(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
    process_started_at: Instant,
) -> Result<GatewayApps, Box<dyn std::error::Error>> {
    gateway_app_with_process_started_at_and_overrides(
        config,
        metrics_handle,
        audit_log,
        audit_event_sender,
        process_started_at,
        GatewayAppBuildOverrides::default(),
    )
}

pub(crate) fn gateway_app_with_process_started_at_and_overrides(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
    process_started_at: Instant,
    build_overrides: GatewayAppBuildOverrides,
) -> Result<GatewayApps, Box<dyn std::error::Error>> {
    let lifecycle = build_overrides.lifecycle.clone().unwrap_or_default();
    let split_admin_listener = config.admin_listen_addr.is_some();
    let csrf_config = middleware::csrf::CsrfConfig::from_config(&config);
    // Required authority evidence (issue #425, PR 4): every admin change and
    // file reload this deployment mode records no evidence of asks this gate.
    // What the configuration enables on its own was refused before this ran.
    let authority_evidence =
        authority_events::required::AuthorityEvidenceGate::from_config(&config);
    if config.authority_events.durability == config::AuthorityEvidenceDurability::Required {
        tracing::info!(
            state_backend = ?config.state_backend,
            "AUTHORITY_EVIDENCE_DURABILITY=required: authority changes this deployment mode records no evidence of are refused, and reported as authority_evidence.operation_refused"
        );
    }
    let audit_query_store = config
        .audit_sqlite_path
        .as_deref()
        .map(storage::SqliteAuditEventStore::open)
        .transpose()?
        .map(Arc::new);
    let audit_event_store: Option<Arc<dyn storage::AuditEventStore>> = audit_query_store
        .as_ref()
        .map(|store| store.clone() as Arc<dyn storage::AuditEventStore>);
    #[cfg(feature = "postgres")]
    let audit_event_store = build_overrides
        .pg_audit
        .as_ref()
        .map(|store| store.clone() as Arc<dyn storage::AuditEventStore>)
        .or(audit_event_store);
    let schema_coverage = discovery::openapi::SchemaCoverage::from_config(&config)?;
    let discovery_query_store = config
        .discovery_sqlite_path
        .as_deref()
        .map(discovery::query::DiscoveryQueryStore::open)
        .transpose()?
        .map(Arc::new);
    // The admin surfaces read through the backend-neutral trait: standalone
    // mode's implementation is the SQLite store opened above, cluster mode's
    // the PostgreSQL read store over the projector's tables (issue #241,
    // PR 11). `DISCOVERY_SQLITE_PATH` is rejected in postgres mode
    // (config.rs), so the two are never both present.
    #[cfg(feature = "postgres")]
    let cluster_discovery_read_store: Option<DiscoveryReadHandle> =
        build_overrides.pg_discovery.as_ref().map(|seed| {
            Arc::new(
                storage::postgres_discovery_read::PostgresDiscoveryReadStore::new(
                    seed.pool.clone(),
                ),
            ) as DiscoveryReadHandle
        });
    #[cfg(not(feature = "postgres"))]
    let cluster_discovery_read_store: Option<DiscoveryReadHandle> = None;
    let discovery_read_store: Option<DiscoveryReadHandle> =
        cluster_discovery_read_store.clone().or_else(|| {
            discovery_query_store
                .clone()
                .map(|store| store as DiscoveryReadHandle)
        });
    // Cluster mode's schema-conformance check reads a snapshot a background
    // task refreshes from the read store, so the request path never waits
    // on PostgreSQL; standalone mode keeps its SQLite store behind the TTL
    // cache.
    #[cfg(feature = "postgres")]
    let cluster_conformance_cache = build_overrides
        .pg_discovery
        .as_ref()
        .map(|_| Arc::new(middleware::observation::ClusterConformanceCache::new()));
    #[cfg(feature = "postgres")]
    let schema_conformance_state = match cluster_conformance_cache.as_ref() {
        Some(cache) => middleware::observation::SchemaConformanceState::from_config_cluster(
            &config,
            schema_coverage.clone(),
            Some(cache.clone()),
        ),
        None => middleware::observation::SchemaConformanceState::from_config(
            &config,
            schema_coverage.clone(),
            discovery_query_store.clone(),
        ),
    };
    #[cfg(not(feature = "postgres"))]
    let schema_conformance_state = middleware::observation::SchemaConformanceState::from_config(
        &config,
        schema_coverage.clone(),
        discovery_query_store.clone(),
    );
    #[cfg(feature = "postgres")]
    if let Some(seed) = build_overrides.pg_discovery.as_ref() {
        if let (Some(cache), Some(read_store)) = (
            cluster_conformance_cache.clone(),
            cluster_discovery_read_store.clone(),
        ) {
            middleware::observation::spawn_cluster_conformance_refresher(
                &lifecycle,
                cache,
                read_store,
                middleware::observation::CLUSTER_CONFORMANCE_REFRESH_INTERVAL,
            );
        }
        // The projector's leadership lease is a slot of the PR 10 lease
        // store on the same pool, with its own TTL: leadership of a
        // long-running job and admission of one tool invocation have
        // different failover needs.
        let projector_leases = Arc::new(storage::PostgresExecutionLeaseStore::new(
            seed.pool.clone(),
            &seed.deployment_id,
            seed.instance_id,
            config.discovery_projector_lease_ttl(),
        )) as Arc<dyn tools::lease::ExecutionLeaseStore>;
        discovery::projector::spawn_discovery_projector(
            &lifecycle,
            seed.audit.clone(),
            Arc::new(storage::postgres_discovery::PostgresDiscoveryStore::new(
                seed.pool.clone(),
            )),
            projector_leases,
            seed.instance_id,
            discovery::projector::ProjectorConfig {
                payload_capture_enabled: config.payload_capture_enabled,
                endpoint_limit: config.discovery_endpoint_limit,
                signal_detector_config: config.signal_detector_config(),
                poll_interval: config.discovery_projector_poll_interval(),
                batch_size: config.discovery_projector_batch,
                flush_every: discovery::aggregator::AGGREGATOR_BATCH_SIZE,
            },
            Some(audit_event_sender.clone()),
        );
    }
    // Cluster mode serves Connections from the authority; standalone mode
    // opens the local file. `CONNECTIONS_SQLITE_PATH` is rejected outright
    // in postgres mode (config.rs), so the two are never both present.
    #[cfg(feature = "postgres")]
    let connection_control_plane = {
        let cluster = build_overrides.pg_connections.as_ref().map(|seed| {
            connections::control_plane::ClusterConnectionStoreSeed {
                store: connections::managed_store::ManagedConnectionStore::Postgres {
                    store: seed.store.clone(),
                    boot: seed.boot.clone(),
                },
                records: seed.records.clone(),
            }
        });
        connections::control_plane::ConnectionControlPlane::from_config_with_cluster_seed(
            &config, cluster,
        )?
    };
    #[cfg(not(feature = "postgres"))]
    let connection_control_plane =
        connections::control_plane::ConnectionControlPlane::from_config(&config)?;
    let configured_suggestion_routes = suggestion_proxy_routes(&config);
    // The suggestion engine: cluster mode generates from the PostgreSQL
    // read store, audit store, and lifecycle store on the discovery seed's
    // pool (issue #241, PR 12); standalone mode from the SQLite files.
    // `DISCOVERY_SQLITE_PATH` is rejected in postgres mode, so the two arms
    // are exclusive.
    #[cfg(feature = "postgres")]
    let cluster_suggestion_engine = build_overrides.pg_discovery.as_ref().map(|seed| {
        discovery::suggestions::SuggestionEngineHandle::Cluster(Arc::new(
            discovery::cluster_suggestions::ClusterRuleSuggestionEngine::new(
                Arc::new(
                    storage::postgres_discovery_read::PostgresDiscoveryReadStore::new(
                        seed.pool.clone(),
                    ),
                ),
                seed.audit.clone(),
                storage::postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore::new(
                    seed.pool.clone(),
                ),
                config.rule_suggestion_config(),
            )
            .with_configured_proxy_routes(configured_suggestion_routes.clone()),
        ))
    });
    #[cfg(not(feature = "postgres"))]
    let cluster_suggestion_engine: Option<discovery::suggestions::SuggestionEngineHandle> = None;
    let rule_suggestion_engine = match cluster_suggestion_engine {
        Some(engine) => Some(engine),
        None => config
            .discovery_sqlite_path
            .as_deref()
            .map(|path| {
                discovery::suggestions::RuleSuggestionEngine::open(
                    path,
                    config.audit_sqlite_path.as_deref(),
                    config.rule_suggestion_config(),
                )
                .map(|engine| engine.with_configured_proxy_routes(configured_suggestion_routes))
            })
            .transpose()?
            .map(|engine| {
                discovery::suggestions::SuggestionEngineHandle::Standalone(Arc::new(engine))
            }),
    };
    // Cluster mode: the immutable `policy_documents` rows ARE the history
    // (written transactionally inside every commit), so the PostgreSQL
    // store satisfies the same contract the SQLite history does.
    #[cfg(feature = "postgres")]
    let policy_history_store: Option<Arc<dyn storage::PolicyHistory>> =
        match build_overrides.pg_policy.as_ref() {
            Some(seed) => Some(seed.store.clone()),
            None => policy_history_sqlite_path(&config)
                .map(rbac::PolicyHistoryStore::open)
                .transpose()?
                .map(|store| Arc::new(store) as Arc<dyn storage::PolicyHistory>),
        };
    #[cfg(not(feature = "postgres"))]
    let policy_history_store: Option<Arc<dyn storage::PolicyHistory>> =
        policy_history_sqlite_path(&config)
            .map(rbac::PolicyHistoryStore::open)
            .transpose()?
            .map(|store| Arc::new(store) as Arc<dyn storage::PolicyHistory>);
    // Policy drafts (issue #243, slice 9) live beside the history they will
    // join once published: migration 22's table in cluster mode, and a
    // `policy_drafts` table in the same SQLite database as `policy_versions`
    // in standalone mode. A database that cannot be opened fails startup,
    // exactly as the history store does.
    #[cfg(feature = "postgres")]
    let policy_draft_store: Option<Arc<dyn storage::PolicyDraftStore>> =
        match build_overrides.pg_policy.as_ref() {
            Some(seed) => Some(Arc::new(seed.store.draft_store())),
            None => policy_history_sqlite_path(&config)
                .map(storage::SqlitePolicyDraftStore::open)
                .transpose()?
                .map(|store| Arc::new(store) as Arc<dyn storage::PolicyDraftStore>),
        };
    #[cfg(not(feature = "postgres"))]
    let policy_draft_store: Option<Arc<dyn storage::PolicyDraftStore>> =
        policy_history_sqlite_path(&config)
            .map(storage::SqlitePolicyDraftStore::open)
            .transpose()?
            .map(|store| Arc::new(store) as Arc<dyn storage::PolicyDraftStore>);
    // The stored policy test suite (issue #243) lives beside the policy
    // history the same way: migration 29's tables in cluster mode, and a
    // `policy_test_suite_versions` table in the history database standalone.
    // A database that cannot be opened fails startup.
    #[cfg(feature = "postgres")]
    let policy_test_suite_store: Option<Arc<dyn storage::PolicyTestSuiteStore>> =
        match build_overrides.pg_policy.as_ref() {
            Some(seed) => Some(Arc::new(seed.store.test_suite_store())),
            None => policy_history_sqlite_path(&config)
                .map(storage::SqlitePolicyTestSuiteStore::open)
                .transpose()?
                .map(|store| Arc::new(store) as Arc<dyn storage::PolicyTestSuiteStore>),
        };
    #[cfg(not(feature = "postgres"))]
    let policy_test_suite_store: Option<Arc<dyn storage::PolicyTestSuiteStore>> =
        policy_history_sqlite_path(&config)
            .map(storage::SqlitePolicyTestSuiteStore::open)
            .transpose()?
            .map(|store| Arc::new(store) as Arc<dyn storage::PolicyTestSuiteStore>);

    // Analyzer finding suppressions (issue #243, slice 15) live where drafts
    // do: migration 31's table in cluster mode, and a
    // `policy_analysis_suppressions` table in the policy history database in
    // standalone mode. A database that cannot be opened fails startup.
    #[cfg(feature = "postgres")]
    let analysis_suppression_store: Option<Arc<dyn storage::AnalysisSuppressionStore>> =
        match build_overrides.pg_policy.as_ref() {
            Some(seed) => Some(Arc::new(seed.store.analysis_suppression_store())),
            None => policy_history_sqlite_path(&config)
                .map(storage::SqliteAnalysisSuppressionStore::open)
                .transpose()?
                .map(|store| Arc::new(store) as Arc<dyn storage::AnalysisSuppressionStore>),
        };
    #[cfg(not(feature = "postgres"))]
    let analysis_suppression_store: Option<Arc<dyn storage::AnalysisSuppressionStore>> =
        policy_history_sqlite_path(&config)
            .map(storage::SqliteAnalysisSuppressionStore::open)
            .transpose()?
            .map(|store| Arc::new(store) as Arc<dyn storage::AnalysisSuppressionStore>);
    let observation_state =
        middleware::observation::ObservationState::from_config(&config, audit_log.clone())
            .with_conformance(schema_conformance_state);
    // Cluster mode replaces the file with the authority's active document
    // (already parsed and ETag-verified by `active()`); the proxy-route
    // cross-check runs here, where the config is at hand, and a document
    // that fails it fails startup -- a replica must never serve under a
    // policy it cannot fully enforce.
    #[cfg(feature = "postgres")]
    let loaded_policy = match build_overrides.pg_policy.as_ref() {
        Some(seed) => {
            if let Err(err) = middleware::rbac::validate_policy_proxy_dispatch_config(
                &seed.active.policy,
                &config,
            ) {
                return Err(
                    Box::new(ClusterPolicyStartupError::InvalidDocument(err.to_string()))
                        as Box<dyn std::error::Error>,
                );
            }
            Some(seed.active.policy.clone())
        }
        None => rbac::Policy::from_config(&config)?,
    };
    #[cfg(not(feature = "postgres"))]
    let loaded_policy = rbac::Policy::from_config(&config)?;
    if let Some(policy) = loaded_policy.as_ref() {
        middleware::rbac::validate_policy_proxy_dispatch_config(policy, &config)?;
    }
    let tool_runtime_config = match loaded_policy.as_ref() {
        Some(policy) => {
            tools::runtime::ToolRuntimeConfig::from_env_defaults(&config).with_policy_tools(policy)
        }
        None => tools::runtime::ToolRuntimeConfig::from_env_defaults(&config),
    };
    // The policy stage's overrides arrive when the RBAC state is built below
    // and attaches it with the snapshot it installed: there are none without
    // a policy, and the stage selects with no other copy of one.
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config(&config);
    // Cluster mode: every locally-allowed request is also decided at the
    // shared store, so one configured burst permits that many requests
    // across the cluster (issue #241, PR 10).
    #[cfg(feature = "postgres")]
    let rate_limit_state = match build_overrides.pg_limits.as_ref() {
        Some(seed) => {
            rate_limit_state.with_shared_store(Arc::new(storage::PostgresRateLimitStore::new(
                seed.pool.clone(),
                &seed.deployment_id,
                seed.keyring.clone(),
                config.rate_limit_max_buckets,
            )))
        }
        None => rate_limit_state,
    };
    let mut egress_config = match loaded_policy.as_ref() {
        Some(policy) => {
            egress::EgressConfig::from_config_and_policy(&config, Some(&policy.egress))?
        }
        None => egress::EgressConfig::from_config(&config),
    };
    #[cfg(test)]
    if let Some(path) = build_overrides.egress_tls_ca_bundle_path.as_ref() {
        egress_config.apply_tls_ca_bundle_path(path.clone())?;
    }
    let discovery_egress_client = Arc::new(egress_client_for_build(
        egress_config.clone(),
        &build_overrides,
    )?);
    let discovered_oidc = discover_oidc_from_config(&config, discovery_egress_client)?;
    auto_seed_discovered_oidc_hosts(&mut egress_config, &discovered_oidc);
    let egress_allowed_hosts_count = egress_config.allowed_host_rule_count();
    let proxy_egress_config = {
        let mut proxy_egress_config = egress_config.clone();
        proxy_egress_config.apply_upstream_timeout_overrides(&config);
        proxy_egress_config
    };
    let egress_client = Arc::new(egress_client_for_build(
        egress_config.clone(),
        &build_overrides,
    )?);
    connection_control_plane.activate_network_secret_providers(&egress_client)?;
    // Cluster mode with an authority-event sink: everything the dispatcher's
    // startup needs, finished by `run()` once it can await the keyring. The
    // control plane's resolver is the one that knows the operator aliases
    // and the network providers just activated.
    #[cfg(feature = "postgres")]
    let authority_event_startup =
        authority_event_startup(&config, &build_overrides, &connection_control_plane);
    let connection_http_runtime = connections::http::ConnectionHttpRuntime::new(
        connection_control_plane.clone(),
        egress_config,
        Arc::clone(&egress_client),
    )
    .with_audit(audit_log.clone());
    // Cluster mode: a delegated-token purge is recorded for every replica,
    // through the operation gate, before it is reported done (issue #441).
    // Wired before the runtime is cloned into anything that purges.
    #[cfg(feature = "postgres")]
    let connection_http_runtime = match build_overrides.pg_delegated_token_purges.as_ref() {
        Some(seed) => connection_http_runtime.with_delegated_token_purge_ledger(
            security_cluster::delegated_tokens::ClusterDelegatedTokenPurgeLedger::new(
                Arc::clone(&seed.store),
                build_overrides.pg_membership.clone(),
                audit_log.clone(),
            ),
            &seed.deployment_id,
        ),
        None => connection_http_runtime,
    };
    // Set once this replica also applies the purges the others record;
    // only then may it offer the principal purge in cluster mode.
    #[cfg(feature = "postgres")]
    let mut delegated_token_purges_applied = false;
    #[cfg(not(feature = "postgres"))]
    let delegated_token_purges_applied = false;
    let proxy_egress_client = Arc::new(egress_client_for_build(
        proxy_egress_config.clone(),
        &build_overrides,
    )?);
    let proxy_state = ProxyState::from_config_with_connections_and_lifecycle(
        &config,
        &proxy_egress_config,
        proxy_egress_client,
        Some(connection_http_runtime.clone()),
        audit_log.clone(),
        lifecycle.clone(),
    )?;
    #[cfg(test)]
    let proxy_state = match build_overrides.request_selection_count.as_ref() {
        Some(counter) => {
            proxy_state.map(|state| state.with_request_selection_counter(Arc::clone(counter)))
        }
        None => proxy_state,
    };
    #[cfg(test)]
    let proxy_state = if build_overrides.stream_proxy_request_bodies {
        proxy_state.map(ProxyState::with_streaming_request_bodies)
    } else {
        proxy_state
    };
    let proxy_classifier = proxy_state.as_ref().map(ProxyState::classifier);
    #[cfg(test)]
    let spawn_proxy_health_checks = !build_overrides.disable_proxy_health_checks;
    #[cfg(not(test))]
    let spawn_proxy_health_checks = true;
    if spawn_proxy_health_checks {
        if let Some(proxy) = proxy_state.as_ref() {
            proxy.spawn_upstream_health_checks();
        }
    }
    let routes = GatewayRoutes::from_config(&config);
    warn_on_mcp_exempt_prefix_overlaps(&routes, &config);
    warn_on_unowned_exempt_paths(&routes, &config);
    let sqlite_token_store = config
        .service_token_sqlite_path
        .as_deref()
        .map(auth::SqliteTokenStore::open)
        .transpose()?;
    // Standalone mode with an authority-event sink: the stores that own
    // evidence, delivered by `run()` once it can await the keyring.
    let standalone_authority_events = standalone_authority_event_startup(
        &config,
        sqlite_token_store.as_ref(),
        &connection_control_plane,
    );
    let service_token_store: Option<Arc<dyn storage::ServiceTokenStore>> =
        sqlite_token_store.map(|store| Arc::new(store) as Arc<dyn storage::ServiceTokenStore>);
    // Cluster mode serves tokens from the authority; SERVICE_TOKEN_SQLITE_PATH
    // is rejected there (config.rs), so the two never coexist.
    #[cfg(feature = "postgres")]
    let service_token_store = match build_overrides.pg_service_tokens.as_ref() {
        Some(seed) => Some(seed.store.clone() as Arc<dyn storage::ServiceTokenStore>),
        None => service_token_store,
    };
    let service_token_validator = service_token_store.as_ref().map(|store| {
        let validator = auth::ServiceTokenValidator::new(
            Arc::clone(store),
            Duration::from_millis(config.service_token_cache_ttl_ms),
        );
        // In cluster mode the cache is only trusted at the revision the
        // authority reports for the request at hand: a revoke on any
        // replica moves it, so the next request here re-verifies.
        #[cfg(feature = "postgres")]
        let validator = match build_overrides.pg_service_tokens.as_ref() {
            Some(seed) => validator.with_revision_source(Arc::new(seed.store.revision_source())),
            None => validator,
        };
        Arc::new(validator)
    });
    // Cluster mode: every JWT provider's validator consults the shared
    // denylist, keyed by that provider's principal issuer under this
    // deployment's ID.
    #[cfg(feature = "postgres")]
    let jwt_revocation_factory = build_overrides.pg_service_tokens.as_ref().map(|seed| {
        let pool = seed.pool.clone();
        let deployment_id = seed.deployment_id.clone();
        move |issuer: &str| {
            Arc::new(storage::PostgresJwtRevocationStore::new(
                pool.clone(),
                &deployment_id,
                issuer,
            )) as Arc<dyn auth::RevocationStore>
        }
    });
    #[cfg(feature = "postgres")]
    let jwt_revocation: Option<JwtRevocationStoreFactory<'_>> = jwt_revocation_factory
        .as_ref()
        .map(|factory| factory as JwtRevocationStoreFactory<'_>);
    #[cfg(not(feature = "postgres"))]
    let jwt_revocation: Option<JwtRevocationStoreFactory<'_>> = None;
    // A JWT refused because its `jti` is on the shared denylist purges the
    // principal's delegated tokens on this replica (issue #441).
    let revoked_credentials =
        Arc::new(connection_http_runtime.clone()) as Arc<dyn auth::RevokedCredentialObserver>;
    let validator = auth_validator_from_config(
        &config,
        Arc::clone(&egress_client),
        service_token_validator.clone(),
        &discovered_oidc.jwks_urls,
        jwt_revocation,
        Some(Arc::clone(&revoked_credentials)),
        Some(&lifecycle),
    )?;
    #[cfg(feature = "postgres")]
    let pending_login_backend: Option<Arc<dyn auth::oidc_login::PendingLoginBackend>> =
        build_overrides.pg_pending_logins.as_ref().map(|seed| {
            Arc::new(storage::PostgresPendingLoginStore::new(
                seed.pool.clone(),
                &seed.deployment_id,
                seed.keyring.clone(),
                auth::PendingLoginLimits {
                    ttl: Duration::from_secs(config.admin_login_pending_ttl_secs),
                    max_entries: config.admin_login_pending_max_entries,
                    max_per_ip: config.admin_login_pending_max_per_ip,
                },
            )) as Arc<dyn auth::oidc_login::PendingLoginBackend>
        });
    #[cfg(not(feature = "postgres"))]
    let pending_login_backend: Option<Arc<dyn auth::oidc_login::PendingLoginBackend>> = None;
    #[cfg(test)]
    let pending_login_backend = build_overrides
        .pending_login_backend
        .clone()
        .or(pending_login_backend);
    let admin_auth_state = admin_auth_state_from_config(
        &config,
        audit_log.clone(),
        &discovered_oidc,
        Arc::clone(&egress_client),
        pending_login_backend,
        Some(&lifecycle),
    )?;
    let admin_auth_state = if let Some(mut state) = admin_auth_state {
        if let Some(session_config) = config.admin_session.clone() {
            // Each store is valid in exactly one state backend; there is no
            // process-local fallback for cluster mode and no shared store in
            // standalone mode.
            let backend = match session_config.storage {
                auth::admin_session::AdminSessionStorage::StandaloneMemory => {
                    config::StateBackend::Sqlite
                }
                auth::admin_session::AdminSessionStorage::ClusterPostgres => {
                    config::StateBackend::Postgres
                }
            };
            if config.state_backend != backend
                || !config.auth_enabled
                || config.auth_mode != config::AuthMode::Required
                || !config.csrf_enabled
            {
                return Err(auth::AuthError::Upstream(
                    "admin sessions require their state backend's store, required authentication and CSRF"
                        .to_owned(),
                )
                .into());
            }
            // Restrict validation to the selected login provider. In particular,
            // never submit OIDC tokens to an external cookie introspector or
            // allow a different provider in the global chain to own the identity.
            let mut authority_config = config.clone();
            authority_config.auth_providers.retain(|provider| {
                Some(provider.name.as_str()) == config.admin_login_provider.as_deref()
            });
            let authority = auth_validator_from_config(
                &authority_config,
                Arc::clone(&egress_client),
                None,
                &discovered_oidc.jwks_urls,
                jwt_revocation,
                Some(Arc::clone(&revoked_credentials)),
                Some(&lifecycle),
            )?
            .ok_or_else(|| {
                auth::AuthError::Upstream("admin session authority is not configured".to_owned())
            })?;
            #[cfg(feature = "postgres")]
            let cluster_store = build_overrides.pg_pending_logins.as_ref().map(|seed| {
                Arc::new(
                    storage::postgres_admin_sessions::PostgresAdminSessionStore::new(
                        seed.pool.clone(),
                        &seed.deployment_id,
                        seed.keyring.clone(),
                        session_config.clone(),
                    ),
                ) as Arc<dyn auth::admin_session::AdminSessionStore>
            });
            #[cfg(not(feature = "postgres"))]
            let cluster_store: Option<Arc<dyn auth::admin_session::AdminSessionStore>> = None;
            let store = admin_session_store(&session_config, cluster_store)?;
            let sessions = auth::admin_session::AdminSessions::new(
                session_config,
                authority,
                store,
                &config.admin_prefix,
                state.login.redirect_origin(),
                &config.csrf_header_name,
            )?;
            if sessions.cookie_name == config.auth_cookie_name
                || sessions.cookie_name == config.csrf_cookie_name
            {
                return Err(auth::AuthError::Upstream(
                    "admin session cookie name conflicts with another credential cookie".to_owned(),
                )
                .into());
            }
            state.sessions = Some(Arc::new(sessions));
        }
        Some(state)
    } else {
        None
    };
    let principal_directory = auth::PrincipalDirectory::from_config(&config)?;
    let rbac_status = RbacStatus {
        policy_loaded: loaded_policy.is_some(),
        policy_id: loaded_policy.as_ref().and_then(|policy| policy.id.clone()),
    };
    let rbac_state = match loaded_policy {
        Some(policy) => {
            tracing::info!(
                policy_id = policy.id.as_deref().unwrap_or("unnamed"),
                route_rules = policy.routes.len(),
                "RBAC enabled: policy file loaded"
            );
            let mut state =
                middleware::rbac::RbacState::from_policy(policy, &config, audit_log.clone())
                    .with_rate_limit_state(rate_limit_state.clone());
            // Self-capabilities require authentication, but no route permission.
            // The endpoint still checks the principal and the admin revision
            // gate still runs. This does not add an authentication exemption.
            state
                .exempt_paths
                .push(format!("{}/capabilities", routes.admin.api_prefix));
            Some(state)
        }
        None => {
            tracing::warn!("RBAC disabled: no policy file configured");
            None
        }
    };
    // Cluster mode: key the initial snapshot to the authority's revision
    // and attach the strict gate plus the background reconciler. Every
    // clone made after this point (token, status, tool, schema admin
    // states, the middleware layer) shares the gated ArcSwap.
    #[cfg(feature = "postgres")]
    let mut policy_control_plane: Option<Arc<dyn storage::PolicyControlPlane>> = None;
    #[cfg(feature = "postgres")]
    let mut cluster_security_runtime: Option<Arc<security_cluster::ClusterSecurityRuntime>> = None;
    #[cfg(feature = "postgres")]
    let rbac_state = match (build_overrides.pg_policy.as_ref(), rbac_state) {
        (Some(seed), Some(state)) => {
            state.install_initial_revision_snapshot(
                seed.active.policy.clone(),
                seed.active.security_revision,
            );
            let policy_resource =
                security_cluster::PolicyResource::new(seed.store.clone(), state.clone());
            let runtime = security_cluster::ClusterSecurityRuntime::new(
                seed.store.revision_source(),
                policy_resource,
            );
            policy_control_plane = Some(seed.store.clone());
            cluster_security_runtime = Some(runtime.clone());
            Some(
                state
                    .with_revision_gate(runtime as Arc<dyn middleware::rbac::SecurityRevisionGate>)
                    .with_connection_control_plane(connection_control_plane.clone()),
            )
        }
        (_, state) => state,
    };
    if let (Some(policy_file), Some(rbac_state)) =
        (config.policy_file.as_ref(), rbac_state.as_ref())
    {
        middleware::rbac::spawn_policy_reload_tasks_with_lifecycle(
            policy_file.clone(),
            rbac_state.clone(),
            authority_events::required::BackgroundEvidenceGate::new(
                authority_evidence,
                audit_log.clone(),
            ),
            &lifecycle,
        )?;
    }
    let tool_registry =
        tools::definitions::ToolRegistry::from_config_with_audit(&config, audit_log.clone())?;
    let connection_http_for_tools = connection_http_runtime.clone();
    tool_registry.set_definition_validator(Arc::new(move |definitions| {
        validate_connection_bound_tools(&connection_http_for_tools, definitions)
    }))?;
    let mcp_upstream_definitions =
        tools::mcp_upstream::discover_upstream_tools_blocking(&config, Arc::clone(&egress_client))?;
    tool_registry.merge_definitions(mcp_upstream_definitions)?;
    // What a candidate policy is validated against before it is published
    // (issue #243, slice 8): the live tool registry and Connection control
    // plane, the egress lane the egress client decides by, and this
    // process's configuration fingerprint. Attached before any admin state
    // takes its copy of the RBAC state.
    let rbac_state = rbac_state.map(|state| {
        state.with_policy_resources(rbac::policy_resources::PolicyResourceSources {
            tools: tool_registry.clone(),
            connections: connection_control_plane.clone(),
            egress: egress_client.static_egress_policy(),
            configuration_fingerprint: format!(
                "sha256:{}",
                ha::static_config_fingerprint(&config).hex()
            ),
            policy_route: routes.admin.policy_route.clone(),
        })
    });
    // Cluster mode: the registry's local lane belongs to the authoritative
    // tools document (not TOOLS_FILE, which cluster mode rejects). Install
    // the boot document -- validating it exactly as a file load would, and
    // failing startup on a document this binary cannot enforce -- and
    // register the document with the security runtime so every commit
    // reconciles here.
    #[cfg(feature = "postgres")]
    let mut tool_control_plane: Option<Arc<dyn storage::ToolControlPlane>> = None;
    #[cfg(feature = "postgres")]
    let mut tools_resource: Option<Arc<security_cluster::ToolsResource>> = None;
    #[cfg(feature = "postgres")]
    if let (Some(seed), Some(runtime)) = (
        build_overrides.pg_tools.as_ref(),
        cluster_security_runtime.as_ref(),
    ) {
        let definitions =
            tools::definitions::definitions_from_json_value(seed.active.document.clone(), None)
                .map_err(|error| {
                    Box::new(ClusterToolsStartupError::InvalidDocument(error.to_string()))
                        as Box<dyn std::error::Error>
                })?;
        // Authoritative content read at boot: a name a legacy lane holds is
        // refused as a collision, while a stale managed holder (the seeds
        // are read one resource at a time) is evicted and reconciled on the
        // gate's first pass.
        connection_control_plane.note_manual_tool_revision(seed.active.security_revision);
        tool_registry
            .install_local_definitions_with(
                definitions,
                tools::definitions::LaneConflicts::EvictStale,
            )
            .map_err(|error| {
                Box::new(ClusterToolsStartupError::InvalidDocument(error.to_string()))
                    as Box<dyn std::error::Error>
            })?;
        let resource = security_cluster::ToolsResource::new_with_connection_control_plane(
            seed.store.clone(),
            tool_registry.clone(),
            Some(connection_control_plane.clone()),
            seed.active.security_revision,
        );
        runtime.register_resource(resource.clone());
        tools_resource = Some(resource);
        tool_control_plane = Some(seed.store.clone());
    }
    // Cluster mode's boot seeds are read one resource at a time; a name that
    // moved between two seeds' revisions must not abort startup, because
    // the gate's first pass reconciles every resource before a request is
    // served. Standalone mode's single store is consistent by construction
    // and keeps refusing.
    #[cfg(feature = "postgres")]
    let boot_conflicts = if build_overrides.pg_connections.is_some() {
        tools::definitions::LaneConflicts::EvictStale
    } else {
        tools::definitions::LaneConflicts::Refuse
    };
    #[cfg(not(feature = "postgres"))]
    let boot_conflicts = tools::definitions::LaneConflicts::Refuse;
    let mcp_catalog_service = connections::mcp::McpConnectionCatalogService::load_with(
        connection_control_plane.clone(),
        connection_http_runtime.clone(),
        tool_registry.clone(),
        boot_conflicts,
    )?;
    let enum_source_runtime = if connection_control_plane.is_managed_store_configured() {
        let boot_rows = connection_control_plane
            .managed_store()?
            .boot_enum_source_values()?;
        Some(tools::enum_source::EnumSourceRuntime::new(
            connection_control_plane.clone(),
            connection_http_runtime.clone(),
            audit_log.clone(),
            boot_rows,
        ))
    } else {
        None
    };
    let openapi_catalog_service =
        connections::openapi::OpenApiConnectionCatalogService::load_with_enum_sources(
            connection_control_plane.clone(),
            connection_http_runtime.clone(),
            tool_registry.clone(),
            boot_conflicts,
            enum_source_runtime.clone(),
        )?
        .with_rbac_state(rbac_state.clone());
    // Cluster mode: every replica regenerates from the stored specification,
    // and one built before Swagger 2.0 import cannot, so storing a catalog
    // converted from one waits for the operation gate (issue #443).
    #[cfg(feature = "postgres")]
    let gate_converted_openapi_catalogs = build_overrides.pg_connections.is_some();
    #[cfg(not(feature = "postgres"))]
    let gate_converted_openapi_catalogs = false;
    #[cfg(test)]
    let gate_converted_openapi_catalogs =
        gate_converted_openapi_catalogs || build_overrides.gate_converted_openapi_catalogs;
    let openapi_catalog_service = if gate_converted_openapi_catalogs {
        openapi_catalog_service.with_converted_catalog_gate()
    } else {
        openapi_catalog_service
    };
    // Cluster mode: register the Connection control plane with the security
    // runtime so every committed record or catalog change reconciles here
    // before the next protected request is served, and start the task that
    // publishes the dependency rows the synchronous callers had to queue.
    #[cfg(feature = "postgres")]
    if let (Some(seed), Some(runtime)) = (
        build_overrides.pg_connections.as_ref(),
        cluster_security_runtime.as_ref(),
    ) {
        runtime.register_resource(security_cluster::ConnectionsResource::new(
            seed.store.clone(),
            connection_control_plane.clone(),
            mcp_catalog_service.clone(),
            openapi_catalog_service.clone(),
            seed.revision,
        ));
        connections::control_plane::spawn_dependency_flush_task(
            connection_control_plane.clone(),
            &lifecycle,
        );
        // Every lane is registered: wire the bundle sources so the first
        // pass publishes one consistent cut of policy, tools, and
        // Connections with its watermark, and every admitted request is
        // served from exactly that cut.
        runtime.set_bundle_sources(
            tool_registry.state_handle(),
            connection_control_plane.runtime_handle(),
        );
    }
    #[cfg(feature = "postgres")]
    if let (Some(seed), Some(runtime), Some(validator)) = (
        build_overrides.pg_service_tokens.as_ref(),
        cluster_security_runtime.as_ref(),
        service_token_validator.as_ref(),
    ) {
        runtime.register_resource(security_cluster::ServiceTokensResource::new(
            seed.store.clone(),
            validator.clone(),
            seed.revision,
        ));
    }
    // Every replica applies each recorded delegated-token purge to its own
    // cache before it serves another protected request (issue #441).
    #[cfg(feature = "postgres")]
    if let (Some(seed), Some(runtime)) = (
        build_overrides.pg_delegated_token_purges.as_ref(),
        cluster_security_runtime.as_ref(),
    ) {
        runtime.register_resource(
            security_cluster::delegated_tokens::DelegatedTokenPurgesResource::new(
                Arc::clone(&seed.store),
                connection_http_runtime.clone(),
                seed.revision,
            ),
        );
        delegated_token_purges_applied = true;
    }
    // Every resource is registered; only now may the background reconciler
    // start. A pass that ran before tools or Connections registered would
    // confirm policy alone and advance the watermark past any commit those
    // resources took during startup -- and a later gate check would return
    // early on that watermark with the late resource still stale.
    // Registration also resets the watermark, so the order is belt and
    // braces rather than a single point of failure.
    #[cfg(feature = "postgres")]
    if let Some(runtime) = cluster_security_runtime.as_ref() {
        runtime.spawn_poller(&lifecycle);
    }
    // Cluster membership (issue #241, PR 13): the heartbeat task carries
    // the security runtime's compiled/observed revisions, and the
    // readiness gate it owns is what `/readyz` consults for fingerprint
    // agreement. Standalone mode has neither.
    #[cfg(feature = "postgres")]
    let cluster_readiness: Option<Arc<ha::ClusterReadiness>> =
        build_overrides.pg_membership.as_ref().map(|membership| {
            membership.spawn_heartbeat(
                &lifecycle,
                cluster_security_runtime.clone(),
                audit_log.clone(),
            );
            membership.readiness()
        });
    #[cfg(not(feature = "postgres"))]
    let cluster_readiness: Option<Arc<ha::ClusterReadiness>> = None;
    #[cfg(test)]
    let cluster_readiness = build_overrides
        .cluster_readiness
        .clone()
        .or(cluster_readiness);
    // The readiness probe (issue #241, PR 14): the authority-backed half
    // of `/readyz`, evaluated between the fingerprint gate above and the
    // proxy's upstream check. It reads the same gate the heartbeat
    // stamps, runs its one bounded check on the deployment's pool, and
    // compares the security runtime's watermarks. Standalone mode has
    // none of the three and never builds one.
    #[cfg(feature = "postgres")]
    let readiness_probe: Option<Arc<ha_status::ReadinessProbe>> = match (
        cluster_readiness.as_ref(),
        build_overrides.pg_limits.as_ref(),
    ) {
        (Some(readiness), Some(seed)) => Some(ha_status::ReadinessProbe::new(
            Arc::clone(readiness),
            ha_status::PostgresReadinessAuthority::new(seed.pool.clone()),
            cluster_security_runtime
                .clone()
                .map(|runtime| runtime as Arc<dyn ha_status::SecurityRevisionHealth>),
            ha_status::ReadinessProbeSettings {
                cache_ttl: config.readiness_probe_cache(),
                accepted_schema_versions: storage::migrations::schema_version_range(),
                member_stale_window: config.cluster_member_stale_window(),
                // A gate refusing for longer than one background
                // reconcile pass is a stuck reconciler, not a slow one.
                revision_reconcile_grace: security_cluster::RECONCILE_BACKGROUND_DEADLINE,
            },
        )),
        _ => None,
    };
    #[cfg(not(feature = "postgres"))]
    let readiness_probe: Option<Arc<ha_status::ReadinessProbe>> = None;
    #[cfg(test)]
    let readiness_probe = build_overrides.readiness_probe.clone().or(readiness_probe);
    // The maintenance singleton (issue #241, PR 13): every cluster-mode
    // replica runs the runner, and the one holding the `maintenance` lease
    // runs the bounded housekeeping jobs under its fence. The lease store
    // here carries the maintenance TTL, not the tool lease TTL. The handle
    // is kept so the cluster status API can report whether this replica is
    // the leader (issue #241, PR 14).
    #[cfg(feature = "postgres")]
    let mut maintenance_runner: Option<Arc<cluster_maintenance::MaintenanceRunner>> = None;
    #[cfg(feature = "postgres")]
    if let (Some(membership), Some(seed)) = (
        build_overrides.pg_membership.as_ref(),
        build_overrides.pg_limits.as_ref(),
    ) {
        let jobs = cluster_maintenance::standard_jobs(cluster_maintenance::StandardJobSources {
            pool: seed.pool.clone(),
            deployment_id: seed.deployment_id.clone(),
            rate_limit_keyring: seed.keyring.clone(),
            rate_limit_max_buckets: config.rate_limit_max_buckets,
            rate_limit_idle: config.rate_limit_bucket_idle_ttl(),
            membership: membership.store(),
            stale_window: config.cluster_member_stale_window(),
            audit: build_overrides.pg_audit.clone(),
            audit_retention: config.audit_postgres_retention(),
            // The discovery projector's committed checkpoint is the
            // retention floor: nothing it has not applied is ever trimmed.
            audit_floor: Some(Arc::new(
                storage::postgres_discovery::PostgresDiscoveryStore::new(seed.pool.clone()),
            )),
            authority_event_retention: config.authority_events.retention(),
            lease_holder: seed.instance_id,
            tool_lease_ttl: config.tool_lease_ttl(),
        });
        let runner = cluster_maintenance::MaintenanceRunner::new(
            seed.pool.clone(),
            Arc::new(storage::PostgresExecutionLeaseStore::new(
                seed.pool.clone(),
                &seed.deployment_id,
                seed.instance_id,
                config.cluster_maintenance_lease_ttl(),
            )),
            membership.store(),
            jobs,
            config.cluster_maintenance_interval(),
            seed.instance_id,
        );
        runner.spawn(&lifecycle);
        maintenance_runner = Some(runner);
    }
    let mcp_catalog_runtime = connection_control_plane
        .is_managed_store_configured()
        .then(|| mcp_catalog_service.runtime());
    let openapi_catalog_runtime = connection_control_plane
        .is_managed_store_configured()
        .then(|| openapi_catalog_service.runtime());
    let mcp_proxy_definitions_provider =
        mcp_proxy_definitions_provider(&config, Arc::clone(&egress_client));
    if let Some(tools_file) = config.tools_file.as_ref() {
        tools::definitions::spawn_tool_registry_reload_tasks_with_lifecycle(
            tools_file.clone(),
            tool_registry.clone(),
            mcp_proxy_definitions_provider.clone(),
            authority_events::required::BackgroundEvidenceGate::new(
                authority_evidence,
                audit_log.clone(),
            ),
            &lifecycle,
        )?;
    }
    // Cluster mode: the global and per-tool concurrency limits are slots
    // leased from the authority, so they bound the cluster rather than each
    // replica (issue #241, PR 10).
    #[cfg(feature = "postgres")]
    let execution_leases: Option<Arc<dyn tools::lease::ExecutionLeaseStore>> =
        build_overrides.pg_limits.as_ref().map(|seed| {
            Arc::new(storage::PostgresExecutionLeaseStore::new(
                seed.pool.clone(),
                &seed.deployment_id,
                seed.instance_id,
                config.tool_lease_ttl(),
            )) as Arc<dyn tools::lease::ExecutionLeaseStore>
        });
    #[cfg(not(feature = "postgres"))]
    let execution_leases: Option<Arc<dyn tools::lease::ExecutionLeaseStore>> = None;
    let tool_runtime = tools::runtime::ToolRuntime::new_with_rbac_state_and_leases(
        tool_runtime_config,
        audit_log.clone(),
        rbac_state.clone(),
        execution_leases,
    );
    openapi_catalog_service.set_source_authorizer(Arc::new(tool_runtime.clone()));
    if let Some(enum_runtime) = enum_source_runtime.as_ref() {
        enum_runtime.spawn_refresher(&lifecycle, Arc::new(tool_runtime.clone()));
    }
    let tool_connection_runtimes = tools::executor::ToolConnectionRuntimes {
        http: Some(connection_http_runtime.clone()),
        mcp_catalog: mcp_catalog_runtime,
        openapi_catalog: openapi_catalog_runtime,
    };
    let mcp_executor = mcp::mcp_executor_from_config(
        &config,
        tool_registry.clone(),
        tool_runtime.clone(),
        Arc::clone(&egress_client),
        tool_connection_runtimes.clone(),
        audit_log.clone(),
    )?
    .map(|executor| executor.with_enum_source_runtime(enum_source_runtime.clone()));
    let tool_executor = match mcp_executor.as_ref() {
        Some(executor) => executor.clone(),
        None => tools::executor::ToolExecutor::from_config(
            &config,
            tool_registry.clone(),
            tool_runtime,
            Arc::clone(&egress_client),
            tool_connection_runtimes,
            audit_log.clone(),
        )?
        .with_enum_source_runtime(enum_source_runtime.clone()),
    };
    let client_ip_policy = client_ip::ClientIpPolicy::from_config(&config);
    let mcp_state = mcp::McpState::new(
        tool_registry.clone(),
        mcp_executor,
        client_ip_policy.clone(),
        config.max_body_size,
    );
    let protected_resource_metadata =
        auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&config);
    let status_state = StatusAdminState {
        config: config.clone(),
        rbac: rbac_status,
        rbac_state: rbac_state.clone(),
        egress_allowed_hosts_count,
        process_started_at,
        proxy: proxy_state.clone(),
        lifecycle: lifecycle.clone(),
    };
    // The cluster status API (issue #241, PR 14). Both modes serve it:
    // standalone has no authority to read, so it gets no source and
    // reports this process as the whole deployment.
    #[cfg(feature = "postgres")]
    let cluster_status_source: Option<Arc<dyn cluster_status::ClusterStatusSource>> = match (
        build_overrides.pg_membership.as_ref(),
        build_overrides.pg_limits.as_ref(),
    ) {
        (Some(membership), Some(seed)) => Some(cluster_status::PostgresClusterStatusSource::new(
            membership.store(),
            build_overrides.pg_audit.clone(),
            maintenance_runner,
            seed.pool.clone(),
            config.cluster_member_stale_window(),
        )),
        _ => None,
    };
    #[cfg(not(feature = "postgres"))]
    let cluster_status_source: Option<Arc<dyn cluster_status::ClusterStatusSource>> = None;
    #[cfg(test)]
    let cluster_status_source = build_overrides
        .cluster_status_source
        .clone()
        .or(cluster_status_source);
    #[cfg(feature = "postgres")]
    let cluster_security_status: Option<Arc<dyn cluster_status::SecurityStatus>> =
        cluster_security_runtime
            .clone()
            .map(|runtime| runtime as Arc<dyn cluster_status::SecurityStatus>);
    #[cfg(not(feature = "postgres"))]
    let cluster_security_status: Option<Arc<dyn cluster_status::SecurityStatus>> = None;
    let standalone_storage_readiness = StandaloneStorageReadiness::start(&config, &lifecycle);
    let cluster_admin_state = ClusterAdminState {
        rbac_state: rbac_state.clone(),
        // Having an authority to read *is* cluster mode here: both seeds
        // the source is built from are present exactly when
        // `STATE_BACKEND=postgres` started successfully, and startup fails
        // rather than proceeding with one of them missing.
        cluster_mode: cluster_status_source.is_some(),
        source: cluster_status_source,
        lifecycle: lifecycle.clone(),
        cluster_readiness: cluster_readiness.clone(),
        readiness_probe: readiness_probe.clone(),
        standalone_storage_readiness: standalone_storage_readiness.clone(),
        proxy: proxy_state.clone(),
        security: cluster_security_status,
        audit: audit_log.clone(),
        identity: build_overrides
            .ha_identity
            .unwrap_or_else(ha::InstanceIdentity::generate),
        fingerprint: ha::static_config_fingerprint(&config).hex(),
        hostname: config
            .cluster_status_expose_hostnames
            .then(local_hostname)
            .flatten(),
        process_started_at,
    };
    #[cfg(feature = "postgres")]
    let replay_cluster = cluster_policy_replays(
        &config,
        &build_overrides,
        policy_control_plane.is_some(),
        &lifecycle,
        cluster_readiness.clone(),
        &audit_log,
    );
    let policy_admin_state = PolicyAdminState {
        policy_file: config.policy_file.as_ref().map(PathBuf::from),
        rbac_state: rbac_state.clone(),
        history_store: policy_history_store,
        draft_store: policy_draft_store,
        test_suite_store: policy_test_suite_store,
        analysis_suppression_store,
        policy_tests_required: config.policy_tests_required,
        #[cfg(feature = "postgres")]
        control_plane: policy_control_plane,
        #[cfg(feature = "postgres")]
        membership: build_overrides.pg_membership.clone(),
        #[cfg(feature = "postgres")]
        replay_cluster,
        event_store: audit_event_store.clone(),
        query_store: audit_query_store.clone(),
        authority_evidence,
        audit: audit_log.clone(),
        client_ip_policy: client_ip_policy.clone(),
        max_body_size: config.max_body_size,
    };
    let token_admin_state = TokenAdminState {
        store: service_token_store,
        validator: service_token_validator,
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        client_ip_policy: client_ip_policy.clone(),
        max_body_size: config.max_body_size,
    };
    let capability_inventory = tools::inventory::CapabilityInventory::new(
        tool_registry.clone(),
        connection_control_plane.clone(),
    )
    .with_enum_source_runtime(enum_source_runtime);
    let connection_admin_state = ConnectionAdminState {
        control_plane: connection_control_plane.clone(),
        inventory: capability_inventory.clone(),
        mcp_catalogs: mcp_catalog_service,
        openapi_catalogs: openapi_catalog_service,
        tests: connections::test::ConnectionTestService::new(connection_http_runtime.clone()),
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        client_ip_policy: client_ip_policy.clone(),
        max_body_size: config.max_body_size,
        secret_precondition_lock: Arc::new(Mutex::new(())),
        #[cfg(feature = "postgres")]
        membership: build_overrides.pg_membership.clone(),
    };
    let tool_admin_state = ToolAdminState {
        tools_file: config.tools_file.as_ref().map(PathBuf::from),
        registry: tool_registry.clone(),
        inventory: capability_inventory,
        executor: tool_executor,
        rbac_state: rbac_state.clone(),
        authority_evidence,
        audit: audit_log.clone(),
        client_ip_policy: client_ip_policy.clone(),
        max_body_size: config.max_body_size,
        write_lock: Arc::new(Mutex::new(())),
        #[cfg(feature = "postgres")]
        tool_control_plane,
        #[cfg(feature = "postgres")]
        tools_resource,
    };
    let schema_admin_state = SchemaAdminState {
        coverage: schema_coverage,
        query_store: discovery_read_store.clone(),
        rbac_state: rbac_state.clone(),
        payload_capture_enabled: config.payload_capture_enabled,
    };

    if config.auth_enabled && validator.is_none() {
        tracing::warn!(
            "authentication is enabled but no session validator is configured; non-exempt requests will be rejected"
        );
    }

    let auth_state = if config.auth_enabled {
        Some(
            middleware::auth::AuthState::from_config(
                &config,
                validator,
                audit_log.clone(),
                principal_directory.clone(),
            )
            .with_admin_sessions(
                admin_auth_state
                    .as_ref()
                    .and_then(|state| state.sessions.clone()),
            ),
        )
    } else {
        None
    };
    let middleware_stack = MiddlewareStack {
        config: config.clone(),
        audit_log: audit_log.clone(),
        csrf_config,
        rate_limit_state,
        observation_state,
        rbac_state: rbac_state.clone(),
        auth_state,
        proxy_dispatch_state: ProxyDispatchState {
            classifier: proxy_classifier,
            routes: routes.clone(),
        },
    };
    let app_state = AppState {
        metrics_handle,
        proxy: proxy_state,
        routes: routes.clone(),
        client_ip_policy: client_ip_policy.clone(),
        admin_login_configured: admin_auth_state.is_some(),
        admin_session: admin_auth_state
            .as_ref()
            .and_then(AdminAuthState::session_capabilities),
        csrf_cookie_name: config.csrf_cookie_name.clone(),
        csrf_header_name: config.csrf_header_name.clone(),
        max_body_size: config.max_body_size,
        mcp: mcp_state,
        protected_resource_metadata,
        lifecycle,
        cluster_readiness,
        readiness_probe,
        standalone_storage_readiness,
        audit_log: audit_log.clone(),
        #[cfg(feature = "postgres")]
        database_pool: build_overrides
            .pg_limits
            .as_ref()
            .map(|seed| seed.pool.clone()),
        connections: connection_control_plane,
    };
    let audit_admin_state = AuditAdminState {
        query_store: audit_event_store,
        event_sender: audit_event_sender,
        rbac_state: rbac_state.clone(),
        stream_limits: AuditStreamLimits::SERVED,
        #[cfg(feature = "postgres")]
        pg_audit: build_overrides.pg_audit,
    };
    let signals_admin_state = SignalsAdminState {
        discovery_store: discovery_read_store.clone(),
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        client_ip_policy: client_ip_policy.clone(),
    };
    let suggestions_admin_state = SuggestionsAdminState {
        suggestion_engine: rule_suggestion_engine,
        policy: policy_admin_state.clone(),
        lifecycle_guard: Arc::default(),
    };
    // Settles a standalone acceptance a previous process left pending
    // (issue #243) without waiting for the first suggestion request.
    spawn_suggestion_acceptance_reconciler(suggestions_admin_state.clone(), &app_state.lifecycle);
    let principal_admin_state = PrincipalAdminState {
        directory: principal_directory,
        audit_query_store: audit_query_store.clone(),
        discovery_store: discovery_read_store.clone(),
        rbac_state: rbac_state.clone(),
        // Cluster mode purges by principal only where the purge is recorded
        // for the other replicas and this replica applies theirs; a build
        // without both refuses.
        delegated_tokens: (config.state_backend == config::StateBackend::Sqlite
            || delegated_token_purges_applied)
            .then(|| connection_http_runtime.clone()),
        client_ip_policy: client_ip_policy.clone(),
        max_body_size: config.max_body_size,
    };
    let traffic_admin_state = TrafficAdminState {
        discovery_store: discovery_read_store,
        audit_query_store: audit_query_store.clone(),
        rbac_state,
        audit: audit_log,
        client_ip_policy,
        max_body_size: config.max_body_size,
    };
    let admin_api_states = AdminApiStates {
        audit: audit_admin_state,
        auth: admin_auth_state,
        status: status_state,
        cluster: cluster_admin_state,
        policy: policy_admin_state,
        tokens: token_admin_state,
        connections: connection_admin_state,
        tools: tool_admin_state,
        schema: schema_admin_state,
        signals: signals_admin_state,
        suggestions: suggestions_admin_state,
        traffic: traffic_admin_state,
        principals: principal_admin_state,
        #[cfg(feature = "postgres")]
        revision_gate: cluster_security_runtime
            .map(|runtime| runtime as Arc<dyn middleware::rbac::SecurityRevisionGate>),
    };

    let grpc = grpc_app(&config, &app_state, &middleware_stack);

    let http = if split_admin_listener {
        GatewayApp::Split {
            data: apply_middleware(data_router(app_state.clone()), &middleware_stack, true),
            admin: apply_middleware(
                admin_router(&routes, app_state, admin_api_states),
                &middleware_stack,
                false,
            ),
        }
    } else {
        GatewayApp::Unified(apply_middleware(
            unified_router(&routes, app_state, admin_api_states),
            &middleware_stack,
            true,
        ))
    };

    Ok(GatewayApps {
        http,
        grpc,
        #[cfg(feature = "postgres")]
        authority_events: authority_event_startup,
        standalone_authority_events,
    })
}

/// The proxy routes the configuration declares, for the rule suggestion
/// engine to attribute observed traffic to: `UPSTREAM_URL` first, then each
/// `UPSTREAM_ROUTES` entry by its Connection, its upstream's origin or its
/// pool's logical origin.
fn suggestion_proxy_routes(
    config: &config::Config,
) -> Vec<discovery::suggestions::ConfiguredProxyRoute> {
    let mut configured_suggestion_routes = config
        .upstream_url
        .as_deref()
        .map(|upstream_url| {
            discovery::suggestions::ConfiguredProxyRoute::new(
                None,
                None,
                proxy::upstream_origin_from_url(upstream_url, "UPSTREAM_URL"),
            )
        })
        .into_iter()
        .collect::<Vec<_>>();
    configured_suggestion_routes.extend(config.upstream_routes.iter().enumerate().map(
        |(index, route)| {
            let logical_origin = if let Some(connection_id) = route.connection_id.as_deref() {
                format!("connection:{connection_id}")
            } else if route.upstreams.is_empty() {
                proxy::upstream_origin_from_url(
                    &route.upstream_url,
                    &format!("UPSTREAM_ROUTES[{index}].upstream_url"),
                )
            } else {
                proxy::logical_pool_origin(
                    route
                        .id
                        .as_deref()
                        .expect("validated upstream pool route must have an id"),
                )
            };
            discovery::suggestions::ConfiguredProxyRoute::new(
                route.host.clone(),
                route.path_prefix.clone(),
                logical_origin,
            )
        },
    ));
    configured_suggestion_routes
}

/// Warn about every `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` entry the
/// gateway does not own: such a path bypasses authentication or RBAC and can
/// be forwarded upstream.
fn warn_on_unowned_exempt_paths(routes: &GatewayRoutes, config: &config::Config) {
    for (var, paths) in [
        ("AUTH_EXEMPT_PATHS", config.auth_exempt_paths.as_slice()),
        ("RBAC_EXEMPT_PATHS", config.rbac_exempt_paths.as_slice()),
    ] {
        let unowned = routes.unowned_exempt_paths(paths);
        if !unowned.is_empty() {
            tracing::warn!(
                var,
                admin_prefix = %config.admin_prefix,
                paths = ?unowned,
                "exempt paths are not gateway-owned; these paths bypass auth/RBAC and can be forwarded upstream; confirm this is intended or align them with ADMIN_PREFIX"
            );
        }
    }
}

/// What `run()` needs to start authority-event delivery, when this is a
/// cluster replica with a sink configured. Kept out of the app builder, whose
/// unoptimized stack frame already sits close to the main thread's limit.
/// The membership's readiness gate goes with it: the dispatcher leads only
/// while the gate admits this replica, and a cluster replica always has one.
#[cfg(feature = "postgres")]
#[inline(never)]
fn authority_event_startup(
    config: &config::Config,
    build_overrides: &GatewayAppBuildOverrides,
    connection_control_plane: &connections::control_plane::ConnectionControlPlane,
) -> Option<authority_events::startup::AuthorityEventStartup> {
    if config.authority_events.sink == config::AuthorityEventSinkSetting::None {
        return None;
    }
    let store = build_overrides.pg_authority_events.as_ref()?;
    let seed = build_overrides.pg_limits.as_ref()?;
    let membership = build_overrides.pg_membership.as_ref()?;
    Some(authority_events::startup::AuthorityEventStartup {
        store: Arc::clone(store),
        resolver: connection_control_plane.secret_resolver_handle(),
        settings: config.authority_events.clone(),
        leases: Arc::new(storage::PostgresExecutionLeaseStore::new(
            seed.pool.clone(),
            &seed.deployment_id,
            seed.instance_id,
            authority_events::dispatcher::DISPATCHER_LEASE_TTL,
        )) as Arc<dyn tools::lease::ExecutionLeaseStore>,
        holder: seed.instance_id,
        readiness: membership.readiness(),
    })
}

/// What `run()` needs to start standalone authority-event delivery, when
/// this is a standalone gateway with a sink configured: every configured
/// store that owns evidence, each its own evidence authority, and the
/// resolver the keyring comes from. Kept out of the app builder for the
/// same stack-frame reason as the cluster startup.
#[inline(never)]
fn standalone_authority_event_startup(
    config: &config::Config,
    token_store: Option<&auth::SqliteTokenStore>,
    connection_control_plane: &connections::control_plane::ConnectionControlPlane,
) -> Option<authority_events::standalone::StandaloneAuthorityEventStartup> {
    if config.state_backend != config::StateBackend::Sqlite
        || config.authority_events.sink == config::AuthorityEventSinkSetting::None
    {
        return None;
    }
    let mut authorities: Vec<
        Arc<dyn storage::standalone_authority_events::StandaloneEvidenceAuthority>,
    > = Vec::new();
    if let Some(store) = token_store {
        authorities.push(Arc::new(store.clone()));
    }
    if let Ok(connections::managed_store::ManagedConnectionStore::Sqlite(store)) =
        connection_control_plane.managed_store()
    {
        authorities.push(Arc::new(store.clone()));
    }
    Some(
        authority_events::standalone::StandaloneAuthorityEventStartup {
            authorities,
            resolver: connection_control_plane.secret_resolver_handle(),
            settings: config.authority_events.clone(),
        },
    )
}

/// Cluster mode's durable replay jobs (issue #243): the job store over the
/// deployment's pool, and this replica's worker, started here so it claims
/// jobs for the life of the process and stops with the lifecycle's
/// background tasks. `None` in standalone mode. Out of line for the same
/// stack-frame reason as [`authority_event_startup`].
#[cfg(feature = "postgres")]
#[inline(never)]
fn cluster_policy_replays(
    config: &config::Config,
    build_overrides: &GatewayAppBuildOverrides,
    cluster_policy: bool,
    lifecycle: &GatewayLifecycle,
    readiness: Option<Arc<ha::ClusterReadiness>>,
    audit_log: &audit::AuditLog,
) -> Option<Arc<ClusterPolicyReplays>> {
    if !cluster_policy {
        return None;
    }
    let seed = build_overrides.pg_limits.as_ref()?;
    let replays = Arc::new(ClusterPolicyReplays::new(
        seed.pool.clone(),
        &config.database,
        seed.instance_id,
    ));
    replays.spawn_worker(lifecycle, readiness, audit_log.clone());
    Some(replays)
}

pub(crate) fn policy_history_sqlite_path(config: &config::Config) -> Option<PathBuf> {
    config
        .policy_history_sqlite_path
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| {
            config
                .policy_file
                .as_deref()
                .map(default_policy_history_sqlite_path)
        })
}

pub(crate) fn default_policy_history_sqlite_path(policy_file: &str) -> PathBuf {
    PathBuf::from(format!("{policy_file}.history.sqlite"))
}
