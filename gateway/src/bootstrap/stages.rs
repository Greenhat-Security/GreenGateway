//! Serving startup (issue #433, PR 3): the configuration compiler, then
//! preflight, activation and serving, run in order by [`start_serving`],
//! and the gateway process's implementation of those stages.
use super::*;

/// Why serving startup stopped.
#[derive(Debug)]
pub(crate) enum StartupFailure {
    /// The configuration compiler refused the environment. No stage ran.
    Configuration(config::ConfigError),
    /// Preflight, activation or serving failed.
    Stage(Box<dyn std::error::Error>),
}

/// The stages of serving startup that do I/O (issue #433, PR 3), run in
/// order by [`start_serving`] once the configuration compiler has accepted
/// the environment. Each receives the compiled configuration; none reads
/// the environment again.
///
/// * **Preflight** proves that the authority the configuration names can
///   be served from: that this build carries its backend, and in cluster
///   mode the database foundation (connected, migrated when the operator
///   allows it, schema, contract fence and deployment binding checked), the
///   control-plane documents and stores read and checked, the keyrings
///   loaded and this boot's row written to the membership roster -- the one
///   thing it publishes about this boot, and so the one thing withdrawn.
///   Its other writes are deployment-wide and the same from every replica
///   that makes them (migrations the operator allows, the empty tool
///   document a first boot seeds, the journal capacity an admitted replica
///   applies), so none says this boot might serve. It builds nothing that
///   serves.
/// * **Activation** builds the gateway from the configuration and the
///   seeds: the metrics recorder, the listeners' TLS material, the audit
///   sinks, every store, client and background task, and the routers. It
///   binds nothing.
/// * **Serving** binds the listeners and serves until shutdown. Once a
///   listener has served, shutdown is serving's own; until then, a failure
///   to bind or to announce readiness is a startup failure like the stages'
///   before it.
///
/// [`ProcessStartup`] is the gateway's; the bootstrap tests run the same
/// sequence against a recording double.
pub(crate) trait StartupStages {
    type Seeds;
    type Published;
    type Activated;

    /// Returns the seeds activation builds from. What preflight publishes
    /// outside this process goes into `published` before the step that
    /// publishes it, so it is withdrawn whichever later step fails,
    /// preflight's own included.
    async fn preflight(
        &mut self,
        config: &config::Config,
        published: &mut Option<Self::Published>,
    ) -> Result<Self::Seeds, Box<dyn std::error::Error>>;

    async fn activate(
        &mut self,
        config: config::Config,
        seeds: Self::Seeds,
    ) -> Result<Self::Activated, Box<dyn std::error::Error>>;

    /// Withdraw what preflight published, after preflight, activation or
    /// serving failed before the gateway served.
    async fn withdraw(&mut self, published: Self::Published);

    async fn serve(&mut self, activated: Self::Activated) -> Result<(), ServingFailure>;
}

/// How serving ended when it did not end in an orderly shutdown.
#[derive(Debug)]
pub(crate) enum ServingFailure {
    /// No listener served: a listener could not be bound or readiness could
    /// not be announced. Startup failed, so what preflight published is
    /// withdrawn.
    NeverServed(Box<dyn std::error::Error>),
    /// Serving ended on an error after the gateway became ready. Serving's
    /// own shutdown has already run.
    AfterServing(Box<dyn std::error::Error>),
}

impl ServingFailure {
    /// Classify an error `serve_gateway` returned by the phase it left the
    /// lifecycle in: still starting means no listener ever served.
    pub(super) fn from_lifecycle(
        error: Box<dyn std::error::Error>,
        lifecycle: &GatewayLifecycle,
    ) -> Self {
        if lifecycle.startup_complete() {
            Self::AfterServing(error)
        } else {
            Self::NeverServed(error)
        }
    }
}

/// Serving startup: the configuration compiler, then the stages.
///
/// The compiler runs first and alone. It is handed the environment reader
/// and nothing else -- no file system, resolver, client, store, provider or
/// database -- so a configuration it refuses stops startup before anything
/// has been opened, resolved or connected to, and the configuration every
/// stage receives is that one compiled result. Its effective values and the
/// order its problems are reported in are `Config::from_env`'s, and the
/// stages run the startup work in the order it has always run in, so a
/// startup that fails still fails with the same error.
///
/// Serving starts only with a gateway activation built in full. When
/// preflight or activation fails, or serving fails before any listener
/// served, what preflight published is withdrawn before the error is
/// returned, so a gateway that will not serve leaves nothing behind that
/// says it might.
pub(crate) async fn start_serving<S: StartupStages>(
    stages: &mut S,
    get_var: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> Result<(), StartupFailure> {
    let plan = config::source::compile_selected(get_var).map_err(StartupFailure::Configuration)?;
    let config = config::into_config(plan);
    // Each stage's future is boxed: an unoptimized build would otherwise
    // hold all of them inline, and the main thread's stack on Windows is
    // 1 MiB.
    let mut published = None;
    let seeds = match Box::pin(stages.preflight(&config, &mut published)).await {
        Ok(seeds) => seeds,
        Err(error) => {
            if let Some(published) = published {
                Box::pin(stages.withdraw(published)).await;
            }
            return Err(StartupFailure::Stage(error));
        }
    };
    let activated = match Box::pin(stages.activate(config, seeds)).await {
        Ok(activated) => activated,
        Err(error) => {
            if let Some(published) = published {
                Box::pin(stages.withdraw(published)).await;
            }
            return Err(StartupFailure::Stage(error));
        }
    };
    match Box::pin(stages.serve(activated)).await {
        Ok(()) => Ok(()),
        Err(ServingFailure::NeverServed(error)) => {
            if let Some(published) = published {
                Box::pin(stages.withdraw(published)).await;
            }
            Err(StartupFailure::Stage(error))
        }
        Err(ServingFailure::AfterServing(error)) => Err(StartupFailure::Stage(error)),
    }
}

/// The gateway process's startup stages.
pub(crate) struct ProcessStartup {
    pub(super) process_started_at: Instant,
}

/// What preflight proved and loaded, for activation to build from.
pub(crate) struct ProcessSeeds {
    ha_foundation: Option<ha::HaFoundation>,
    #[cfg(feature = "postgres")]
    database_foundation: Option<storage::postgres::PostgresFoundation>,
    #[cfg(feature = "postgres")]
    cluster: ClusterBootSeeds,
}

/// What preflight publishes outside the process: in cluster mode, this
/// boot's membership row. Standalone mode publishes nothing, and a build
/// without the PostgreSQL client has nothing it could publish.
#[cfg(feature = "postgres")]
pub(crate) type ProcessPublication = Arc<cluster_membership::ClusterMembership>;
#[cfg(not(feature = "postgres"))]
pub(crate) type ProcessPublication = std::convert::Infallible;

/// A gateway activation built in full: everything serving needs, and the
/// foundations it serves from, held until serving ends.
pub(crate) struct ActivatedGateway {
    apps: GatewayApps,
    listen: ListenAddresses,
    inbound_tls: inbound_tls::InboundTlsBindings,
    audit_log: audit::AuditLog,
    lifecycle: GatewayLifecycle,
    shutdown_config: ShutdownConfig,
    shutdown_budget: Duration,
    ha_foundation: Option<ha::HaFoundation>,
    #[cfg(feature = "postgres")]
    database_foundation: Option<storage::postgres::PostgresFoundation>,
}

impl StartupStages for ProcessStartup {
    type Seeds = ProcessSeeds;
    type Published = ProcessPublication;
    type Activated = ActivatedGateway;

    async fn preflight(
        &mut self,
        config: &config::Config,
        published: &mut Option<ProcessPublication>,
    ) -> Result<ProcessSeeds, Box<dyn std::error::Error>> {
        // Cluster mode's startup prerequisites, before anything binds: this
        // build must carry the PostgreSQL client at all, and a selected
        // STATE_BACKEND=postgres must prove the database answers within its
        // bounded retry budget. Standalone mode runs none of this.
        ha::ensure_backend_compiled_in(config)?;
        let ha_foundation = match config.state_backend {
            config::StateBackend::Postgres => {
                let foundation = ha::HaFoundation::generate(config);
                tracing::info!(
                    deployment_id = config.deployment_id.as_deref().unwrap_or_default(),
                    instance_id = %foundation.identity().instance_id(),
                    boot_id = %foundation.identity().boot_id(),
                    fingerprint = %foundation.fingerprint(),
                    "cluster mode: identity established; every replica of this deployment \
                     must agree on the static-configuration fingerprint to become ready"
                );
                Some(foundation)
            }
            config::StateBackend::Sqlite => None,
        };
        #[cfg(feature = "postgres")]
        let database_foundation =
            storage::postgres::PostgresFoundation::start_if_selected(config).await?;
        #[cfg(feature = "postgres")]
        let cluster = preflight_cluster_authority(
            config,
            database_foundation.as_ref(),
            ha_foundation.as_ref(),
            published,
        )
        .await?;
        #[cfg(not(feature = "postgres"))]
        let _ = published;
        Ok(ProcessSeeds {
            ha_foundation,
            #[cfg(feature = "postgres")]
            database_foundation,
            #[cfg(feature = "postgres")]
            cluster,
        })
    }

    async fn activate(
        &mut self,
        config: config::Config,
        seeds: ProcessSeeds,
    ) -> Result<ActivatedGateway, Box<dyn std::error::Error>> {
        let ProcessSeeds {
            ha_foundation,
            #[cfg(feature = "postgres")]
            database_foundation,
            #[cfg(feature = "postgres")]
            cluster,
        } = seeds;
        // Seeds every counter a single-event alert reads at zero (the
        // cluster-only ones in cluster mode), so the first event moves 0 -> 1.
        let metrics_handle =
            install_metrics_recorder(config.state_backend == config::StateBackend::Postgres)?;
        let listen = ListenAddresses::from_config(&config);
        // Loaded before any listener binds. Certificate and key problems must abort
        // startup rather than leave a listener serving plaintext that an operator
        // configured for TLS.
        let inbound_tls = inbound_tls::InboundTlsBindings::load(&config)?;
        let shutdown_config = ShutdownConfig::from_config(&config);
        let shutdown_budget = Duration::from_millis(config.shutdown_timeout_ms);
        let lifecycle = GatewayLifecycle::new();
        let overrides = GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            ha_identity: ha_foundation
                .as_ref()
                .map(|foundation| *foundation.identity()),
            #[cfg(feature = "postgres")]
            pg_audit: cluster.audit,
            #[cfg(feature = "postgres")]
            pg_policy: cluster.policy,
            #[cfg(feature = "postgres")]
            pg_tools: cluster.tools,
            #[cfg(feature = "postgres")]
            pg_connections: cluster.connections,
            #[cfg(feature = "postgres")]
            pg_service_tokens: cluster.service_tokens,
            #[cfg(feature = "postgres")]
            pg_delegated_token_purges: cluster.delegated_token_purges,
            #[cfg(feature = "postgres")]
            pg_pending_logins: cluster.pending_logins,
            #[cfg(feature = "postgres")]
            pg_limits: cluster.limits,
            #[cfg(feature = "postgres")]
            pg_discovery: cluster.discovery,
            #[cfg(feature = "postgres")]
            pg_membership: cluster.membership,
            #[cfg(feature = "postgres")]
            pg_authority_events: cluster.authority_events,
            #[cfg(test)]
            cluster_readiness: None,
            #[cfg(test)]
            readiness_probe: None,
            #[cfg(test)]
            cluster_status_source: None,
            #[cfg(test)]
            egress_resolver: None,
            #[cfg(test)]
            egress_tls_ca_bundle_path: None,
            #[cfg(test)]
            pending_login_backend: None,
            #[cfg(test)]
            request_selection_count: None,
            #[cfg(test)]
            disable_proxy_health_checks: false,
            #[cfg(test)]
            stream_proxy_request_bodies: false,
            #[cfg(test)]
            gate_converted_openapi_catalogs: false,
        };
        let built = build_activated_gateway(
            config,
            metrics_handle,
            &inbound_tls,
            &lifecycle,
            overrides,
            self.process_started_at,
        );
        let (apps, audit_log) = match built {
            Ok(built) => built,
            Err(error) => {
                // Building may already have started background work on the
                // lifecycle -- reload watchers, the membership heartbeat,
                // the projector and maintenance leaders, the reconciler.
                // None of it may outlive an activation that will not serve.
                stop_unserved_gateway(&lifecycle, shutdown_budget).await;
                return Err(error);
            }
        };
        // Authority-event delivery needs the pseudonym keyring, which may
        // sit behind a network secret provider the builder only just
        // activated, so it starts here, after the build and before any
        // listener binds. Any failure refuses startup like a build failure.
        // This runs on a replica held at the fingerprint door too, but the
        // dispatcher it spawns contends for the lease only once the
        // membership gate admits this replica.
        #[cfg(feature = "postgres")]
        let apps = {
            let mut apps = apps;
            if let Some(startup) = apps.authority_events.take() {
                if let Err(error) = Box::pin(startup.start(&lifecycle, &audit_log)).await {
                    stop_unserved_gateway(&lifecycle, shutdown_budget).await;
                    return Err(Box::new(error));
                }
            }
            apps
        };
        // Standalone delivery starts the same way, for the same reason: its
        // keyring may sit behind a network secret provider, and a gateway
        // configured to deliver evidence never serves without it.
        let apps = {
            let mut apps = apps;
            if let Some(startup) = apps.standalone_authority_events.take() {
                if let Err(error) = Box::pin(startup.start(&lifecycle, &audit_log)).await {
                    stop_unserved_gateway(&lifecycle, shutdown_budget).await;
                    return Err(Box::new(error));
                }
            }
            apps
        };
        Ok(ActivatedGateway {
            apps,
            listen,
            inbound_tls,
            audit_log,
            lifecycle,
            shutdown_config,
            shutdown_budget,
            ha_foundation,
            #[cfg(feature = "postgres")]
            database_foundation,
        })
    }

    async fn withdraw(&mut self, published: ProcessPublication) {
        #[cfg(feature = "postgres")]
        published.withdraw_unserved_boot().await;
        #[cfg(not(feature = "postgres"))]
        let _ = published;
    }

    async fn serve(&mut self, activated: ActivatedGateway) -> Result<(), ServingFailure> {
        let ActivatedGateway {
            apps,
            listen,
            inbound_tls,
            audit_log,
            lifecycle,
            shutdown_config,
            shutdown_budget,
            // Held, not used: the foundations live as long as serving does.
            ha_foundation: _ha_foundation,
            #[cfg(feature = "postgres")]
                database_foundation: _database_foundation,
        } = activated;
        let background_lifecycle = lifecycle.clone();
        let phase = lifecycle.clone();
        let served = serve_gateway(
            apps.http,
            apps.grpc,
            listen.data,
            listen.admin,
            inbound_tls,
            audit_log,
            lifecycle,
            shutdown_config,
            Box::pin(async move {
                background_lifecycle.shutdown_background_tasks().await;
            }),
        )
        .await;
        match served {
            Ok(()) => Ok(()),
            Err(error) => match ServingFailure::from_lifecycle(Box::new(error), &phase) {
                // A listener that could not be bound leaves the background
                // work activation started running, with no shutdown of
                // serving's to stop it.
                ServingFailure::NeverServed(error) => {
                    stop_unserved_gateway(&phase, shutdown_budget).await;
                    Err(ServingFailure::NeverServed(error))
                }
                after_serving => Err(after_serving),
            },
        }
    }
}

/// Stop the background work activation started for a gateway that will
/// never serve, within the shutdown budget: a task that will not stop must
/// not hold the process that is about to report the failure.
async fn stop_unserved_gateway(lifecycle: &GatewayLifecycle, budget: Duration) {
    if tokio::time::timeout(budget, lifecycle.shutdown_background_tasks())
        .await
        .is_err()
    {
        tracing::warn!(
            "background tasks started for a gateway that never served did not stop within SHUTDOWN_TIMEOUT_MS"
        );
    }
}

/// Activation's synchronous part: the audit sinks, the TLS reload watchers
/// and the gateway itself, built from the configuration and preflight's
/// seeds (in `overrides`). Everything it starts is registered with
/// `lifecycle`.
fn build_activated_gateway(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    inbound_tls: &inbound_tls::InboundTlsBindings,
    lifecycle: &GatewayLifecycle,
    overrides: GatewayAppBuildOverrides,
    process_started_at: Instant,
) -> Result<(GatewayApps, audit::AuditLog), Box<dyn std::error::Error>> {
    // Cluster mode's audit of record is the shared store (issue #11, PR 3):
    // the durable sink writes through the same store instance the SSE and
    // discovery readers were just handed, with this replica's identity on
    // every row, and its drain gets the audit drain's own budget. Standalone
    // builds the sinks exactly as before -- `from_config` is this call with
    // no store.
    #[cfg(feature = "postgres")]
    let (audit_log, audit_event_sender) = audit::AuditLog::from_config_with_durable_store(
        &config,
        overrides
            .pg_audit
            .as_ref()
            .map(|store| audit::postgres_sink::PostgresSinkConfig {
                store: Arc::clone(store),
                flush_deadline: Duration::from_millis(config.audit_drain_timeout_ms),
            }),
    )?;
    #[cfg(not(feature = "postgres"))]
    let (audit_log, audit_event_sender) = audit::AuditLog::from_config(&config)?;
    // Started once the audit log exists, so every reload outcome -- accepted
    // or rejected -- is observable from the first moment a listener serves.
    // A watcher that cannot be installed aborts startup for the same reason
    // unreadable material does: a listener whose certificate files cannot be
    // watched is a listener whose certificates quietly stop being renewable.
    inbound_tls.spawn_material_reload_tasks_with_lifecycle(audit_log.clone(), lifecycle)?;
    let apps = gateway_app_with_process_started_at_and_overrides(
        config,
        metrics_handle,
        audit_log.clone(),
        audit_event_sender,
        process_started_at,
        overrides,
    )?;
    Ok((apps, audit_log))
}
