//! bootstrap boundary extracted from the application composition root.
use super::*;

pub(super) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // `gateway migrate check|up` (issue #241, PR 4): a one-shot schema
    // command that connects, does its work, prints one line, and exits --
    // never a serving process. It is dispatched BEFORE the connection-secret
    // maintenance parser, because that parser rejects every argument list
    // that is not exactly its own shape and would swallow `migrate ...` with
    // a misleading error (an adversarial review caught exactly that). It
    // runs after the tracing subscriber below, so a failing migration's
    // classified diagnostics have somewhere to go.
    #[cfg(feature = "postgres")]
    if let Some(word) = std::env::args_os().nth(1) {
        if word == *"migrate" {
            initialize_tracing_for_one_shot_commands();
            match storage::migrations::run_if_requested(
                std::env::args_os().skip(1),
                config::Config::from_env,
            )
            .await?
            {
                Some(output) => {
                    println!("{output}");
                    let exit_code = output.exit_code();
                    if exit_code != 0 {
                        // `check` is a gate: not-current is a printed
                        // status plus a nonzero exit, not a panic.
                        std::process::exit(exit_code);
                    }
                    return Ok(());
                }
                // Unreachable: the first argument is `migrate`, which the
                // parser either executes or rejects.
                None => return Err("gateway migrate reached an unreachable parse state".into()),
            }
        }
    }
    // `gateway revoke-jwt <issuer> <jti> [expires_at]` (issue #241, PR 9):
    // the shared denylist's write path. A one-shot command like `migrate`:
    // it connects, records the withdrawal as a committed control-plane
    // mutation, prints one line, and exits. There is deliberately no admin
    // HTTP endpoint for this yet -- a permission model for revoking other
    // people's sessions is a product decision, and until it is made the
    // operator's shell is the right place for a break-glass action. The
    // jti is digested before it reaches the database and is never echoed.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"revoke-jwt")
    {
        initialize_tracing_for_one_shot_commands();
        let arguments = std::env::args_os()
            .skip(2)
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let (issuer, jti, expires_at) = match arguments.as_slice() {
            [issuer, jti] => (issuer.clone(), jti.clone(), None),
            [issuer, jti, expires_at] => (issuer.clone(), jti.clone(), Some(expires_at.clone())),
            _ => {
                return Err(
                    "usage: gateway revoke-jwt <issuer> <jti> [expires_at RFC 3339]".into(),
                );
            }
        };
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let Some(foundation) =
            storage::postgres::PostgresFoundation::start_if_selected(&config).await?
        else {
            return Err("gateway revoke-jwt requires STATE_BACKEND=postgres".into());
        };
        let deployment_id = config
            .deployment_id
            .clone()
            .ok_or("STATE_BACKEND=postgres requires DEPLOYMENT_ID")?;
        let boundary = auth::JwtValidator::issuer_boundary(&issuer)?;
        let store = storage::PostgresJwtRevocationStore::new(
            foundation.pool().clone(),
            &deployment_id,
            &boundary,
        );
        match store
            .revoke(&jti, expires_at.as_deref(), "operator:revoke-jwt")
            .await
            .map_err(|error| match error.invalid_parameter_name() {
                Some("jti") => Box::<dyn std::error::Error>::from(
                    "revoke-jwt requires a non-empty JTI (an empty one names no token)",
                ),
                Some("expires_at") => Box::<dyn std::error::Error>::from(
                    "revoke-jwt: expires_at must be an RFC 3339 instant no earlier than the validator's expiry leeway before now",
                ),
                _ => Box::<dyn std::error::Error>::from(format!("JWT revocation failed: {error}")),
            })? {
            storage::JwtRevocationOutcome::Revoked { security_revision } => {
                println!("revoked: issuer={boundary} security_revision={security_revision}");
                println!(
                    "note: replicas older than this release do not enforce JWT revocations; \
                     the withdrawal is deployment-wide once the rollout completes"
                );
            }
            storage::JwtRevocationOutcome::AlreadyRevoked => {
                println!("already revoked: issuer={boundary}");
            }
        }
        return Ok(());
    }
    // `gateway jwt-revocations-cleanup [limit]`: delete revocations whose
    // expiry has passed, at most `limit` (default 1000) per run. Idempotent
    // and bounded; the maintenance singleton (`cluster_maintenance.rs`)
    // runs the same step on every pass, so this stays for operators rather
    // than schedules. Expired rows are already ignored on the read path;
    // this only reclaims space.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"jwt-revocations-cleanup")
    {
        initialize_tracing_for_one_shot_commands();
        let limit = match std::env::args_os().nth(2) {
            None => 1_000,
            Some(raw) => raw
                .to_string_lossy()
                .parse::<usize>()
                .ok()
                .filter(|limit| (1..=100_000).contains(limit))
                .ok_or("usage: gateway jwt-revocations-cleanup [limit 1-100000]")?,
        };
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let Some(foundation) =
            storage::postgres::PostgresFoundation::start_if_selected(&config).await?
        else {
            return Err("gateway jwt-revocations-cleanup requires STATE_BACKEND=postgres".into());
        };
        let deployment_id = config
            .deployment_id
            .clone()
            .ok_or("STATE_BACKEND=postgres requires DEPLOYMENT_ID")?;
        // Cleanup is issuer-agnostic; the store's issuer is irrelevant here.
        let store = storage::PostgresJwtRevocationStore::new(
            foundation.pool().clone(),
            &deployment_id,
            "-",
        );
        let deleted = store.cleanup_expired(limit).await.map_err(|error| {
            Box::<dyn std::error::Error>::from(format!("JWT revocation cleanup failed: {error}"))
        })?;
        println!("deleted expired JWT revocations: {deleted}");
        return Ok(());
    }
    // `gateway rate-limit-buckets-cleanup [limit]`: reclaim shared rate-limit
    // buckets idle for at least RATE_LIMIT_BUCKET_TTL_MS by the database
    // clock, at most `limit` (default 1000) per run, keeping the live-bucket
    // count exact. Idempotent and bounded; the maintenance singleton
    // (`cluster_maintenance.rs`) runs the same step on every pass, so this
    // stays for operators rather than schedules. The bound on live buckets
    // is enforced on the request path regardless.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"rate-limit-buckets-cleanup")
    {
        initialize_tracing_for_one_shot_commands();
        let limit = match std::env::args_os().nth(2) {
            None => 1_000,
            Some(raw) => raw
                .to_string_lossy()
                .parse::<u32>()
                .ok()
                .filter(|limit| (1..=100_000).contains(limit))
                .ok_or("usage: gateway rate-limit-buckets-cleanup [limit 1-100000]")?,
        };
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let Some(foundation) =
            storage::postgres::PostgresFoundation::start_if_selected(&config).await?
        else {
            return Err(
                "gateway rate-limit-buckets-cleanup requires STATE_BACKEND=postgres".into(),
            );
        };
        let deployment_id = config
            .deployment_id
            .clone()
            .ok_or("STATE_BACKEND=postgres requires DEPLOYMENT_ID")?;
        let root = config
            .connection_secrets_root
            .as_ref()
            .ok_or("RATE_LIMIT_KEYRING requires CONNECTION_SECRETS_ROOT for its key files")?;
        let keyring =
            connections::local_secret::LocalSecretKeyring::load(&config.rate_limit_keyring, root)
                .map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "the rate-limit keyring could not be loaded: {error}"
                ))
            })?;
        let store = storage::PostgresRateLimitStore::new(
            foundation.pool().clone(),
            &deployment_id,
            keyring,
            config.rate_limit_max_buckets,
        );
        let idle_secs = config.rate_limit_bucket_idle_ttl().as_secs_f64();
        let removed = store
            .cleanup_idle(idle_secs, limit)
            .await
            .map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "rate-limit bucket cleanup failed: {error}"
                ))
            })?;
        let live = store.live_buckets().await.map_err(|error| {
            Box::<dyn std::error::Error>::from(format!("rate-limit bucket count failed: {error}"))
        })?;
        println!("removed idle rate-limit buckets: {removed} (live: {live})");
        return Ok(());
    }
    // `gateway cluster-members`: one line per member row of the deployment
    // (issue #241, PR 13), liveness judged on the database clock against
    // CLUSTER_MEMBER_STALE_MS. Read-only: the command is not a member and
    // writes no row of its own. The status API/UI is PR 14.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"cluster-members")
    {
        initialize_tracing_for_one_shot_commands();
        if std::env::args_os().nth(2).is_some() {
            return Err("usage: gateway cluster-members".into());
        }
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let Some(foundation) =
            storage::postgres::PostgresFoundation::start_if_selected(&config).await?
        else {
            return Err("gateway cluster-members requires STATE_BACKEND=postgres".into());
        };
        let deployment_id = config
            .deployment_id
            .clone()
            .ok_or("STATE_BACKEND=postgres requires DEPLOYMENT_ID")?;
        let store = storage::PostgresMembershipStore::new(
            foundation.pool().clone(),
            &deployment_id,
            ha::InstanceIdentity::generate(),
        );
        let stale_window = config.cluster_member_stale_window();
        let members = store.members(stale_window).await.map_err(|error| {
            Box::<dyn std::error::Error>::from(format!("cluster member listing failed: {error}"))
        })?;
        let live = members.iter().filter(|member| member.live).count();
        println!(
            "deployment={deployment_id} members={} live={live} stale_window_ms={}",
            members.len(),
            stale_window.as_millis()
        );
        for member in &members {
            let state = match (
                member.live,
                member.draining_at.is_some(),
                member.ready_at.is_some(),
            ) {
                (false, _, _) => "stale",
                (true, true, _) => "draining",
                (true, false, true) => "ready",
                (true, false, false) => "starting",
            };
            println!(
                "{state:<9} instance={} boot={} version={} schema={}..{} document={}..{} fingerprint={} started={} heartbeat={} age_secs={:.1} revisions=compiled:{}/observed:{} last_error={}",
                member.instance_id,
                member.boot_id,
                member.binary_version,
                member.schema_version_min,
                member.schema_version_max,
                member.document_version_min,
                member.document_version_max,
                member.fingerprint,
                member.started_at,
                member.last_heartbeat_at,
                member.heartbeat_age_secs,
                member.compiled_security_revision,
                member.observed_security_revision,
                member.last_error_code.as_deref().unwrap_or("-"),
            );
        }
        return Ok(());
    }
    // `gateway maintenance-run`: one bounded pass of the singleton jobs
    // (issue #241, PR 13) for an operator's cron until the in-process
    // singleton is trusted. It takes the `maintenance` lease like any
    // leader -- with CLUSTER_MAINTENANCE_LEASE_TTL_MS as its TTL, renewed
    // while the pass runs -- so a live leader's slot is reported held and
    // nothing runs, and every ledger write carries the one-shot's fence.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"maintenance-run")
    {
        initialize_tracing_for_one_shot_commands();
        if std::env::args_os().nth(2).is_some() {
            return Err("usage: gateway maintenance-run".into());
        }
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let Some(foundation) =
            storage::postgres::PostgresFoundation::start_if_selected(&config).await?
        else {
            return Err("gateway maintenance-run requires STATE_BACKEND=postgres".into());
        };
        let deployment_id = config
            .deployment_id
            .clone()
            .ok_or("STATE_BACKEND=postgres requires DEPLOYMENT_ID")?;
        let root = config
            .connection_secrets_root
            .as_ref()
            .ok_or("RATE_LIMIT_KEYRING requires CONNECTION_SECRETS_ROOT for its key files")?;
        let keyring =
            connections::local_secret::LocalSecretKeyring::load(&config.rate_limit_keyring, root)
                .map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "the rate-limit keyring could not be loaded: {error}"
                ))
            })?;
        // The one-shot is not a member: a fresh identity names its lease
        // and nothing else, and no member row is written for it.
        let identity = ha::InstanceIdentity::generate();
        let pool = foundation.pool().clone();
        let membership = Arc::new(storage::PostgresMembershipStore::new(
            pool.clone(),
            &deployment_id,
            identity,
        ));
        let jobs = cluster_maintenance::standard_jobs(cluster_maintenance::StandardJobSources {
            pool: pool.clone(),
            deployment_id: deployment_id.clone(),
            rate_limit_keyring: keyring,
            rate_limit_max_buckets: config.rate_limit_max_buckets,
            rate_limit_idle: config.rate_limit_bucket_idle_ttl(),
            membership: Arc::clone(&membership),
            stale_window: config.cluster_member_stale_window(),
            audit: Some(Arc::new(
                storage::postgres_audit::PostgresAuditEventStore::new(pool.clone(), None),
            )),
            audit_retention: config.audit_postgres_retention(),
            // The discovery projector's committed checkpoint is the
            // retention floor: nothing it has not applied is ever trimmed.
            audit_floor: Some(Arc::new(
                storage::postgres_discovery::PostgresDiscoveryStore::new(pool.clone()),
            )),
            lease_holder: identity.instance_id(),
            tool_lease_ttl: config.tool_lease_ttl(),
        });
        let runner = cluster_maintenance::MaintenanceRunner::new(
            pool.clone(),
            Arc::new(storage::PostgresExecutionLeaseStore::new(
                pool,
                &deployment_id,
                identity.instance_id(),
                config.cluster_maintenance_lease_ttl(),
            )),
            Arc::clone(&membership),
            jobs,
            config.cluster_maintenance_interval(),
            identity.instance_id(),
        );
        let outcome = runner.run_once().await.map_err(|error| {
            Box::<dyn std::error::Error>::from(format!("maintenance pass failed: {error}"))
        })?;
        match outcome {
            cluster_maintenance::OnePassOutcome::LeaseHeld => {
                return Err(
                    "a live leader holds the maintenance lease; nothing ran (retry after CLUSTER_MAINTENANCE_LEASE_TTL_MS if it is dead)"
                        .into(),
                );
            }
            cluster_maintenance::OnePassOutcome::LeaseLost { fence } => {
                return Err(format!(
                    "the maintenance lease (fence {fence}) was lost mid-pass; the pass was cancelled"
                )
                .into());
            }
            cluster_maintenance::OnePassOutcome::Ran { fence, outcome } => {
                let jobs = membership.maintenance_jobs().await.map_err(|error| {
                    Box::<dyn std::error::Error>::from(format!(
                        "maintenance ledger read failed: {error}"
                    ))
                })?;
                for record in &jobs {
                    println!(
                        "job={} fence={} started={} success={} failure={} duration_ms={}",
                        record.job,
                        record.fence,
                        record.last_started_at.as_deref().unwrap_or("-"),
                        record.last_success_at.as_deref().unwrap_or("-"),
                        record.last_failure_code.as_deref().unwrap_or("-"),
                        record
                            .last_duration_ms
                            .map_or_else(|| "-".to_owned(), |ms| ms.to_string()),
                    );
                }
                match outcome {
                    cluster_maintenance::PassOutcome::Completed { failed_jobs: 0 } => {
                        println!("maintenance pass completed: fence={fence}");
                    }
                    cluster_maintenance::PassOutcome::Completed { failed_jobs } => {
                        return Err(format!(
                            "maintenance pass completed with {failed_jobs} failing job(s): fence={fence}"
                        )
                        .into());
                    }
                    cluster_maintenance::PassOutcome::Skipped => {
                        return Err(format!(
                            "maintenance pass skipped: another session holds the maintenance advisory lock (fence={fence})"
                        )
                        .into());
                    }
                    cluster_maintenance::PassOutcome::Stale => {
                        return Err(format!(
                            "maintenance pass refused by the ledger fence: a successor holds a higher fence (fence={fence})"
                        )
                        .into());
                    }
                    cluster_maintenance::PassOutcome::ConnectionLost => {
                        return Err(format!(
                            "maintenance session lost mid-pass; the remaining jobs did not run (fence={fence})"
                        )
                        .into());
                    }
                }
            }
        }
        return Ok(());
    }
    // `gateway import-standalone --from <standalone-env-file>`: the
    // one-way, offline standalone-to-cluster import (issue #241, PR 15).
    // The process environment is the TARGET cluster configuration, like
    // every other one-shot command here; the SOURCE standalone
    // configuration is the file `--from` names, because `Config` refuses
    // to hold both at once. `--dry-run` is the default and writes
    // nothing. The report goes to stdout as JSON: counts, checksums,
    // revisions and durations, never a token, secret or DSN.
    #[cfg(feature = "postgres")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"import-standalone")
    {
        initialize_tracing_for_one_shot_commands();
        let request = import::ImportRequest::parse(std::env::args_os().skip(2))
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let config = config::Config::from_env()
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        let report = import::run(&request, &config)
            .await
            .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
        println!("{report}");
        return Ok(());
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::args_os().nth(1).is_some_and(|word| {
        word == *"revoke-jwt"
            || word == *"jwt-revocations-cleanup"
            || word == *"rate-limit-buckets-cleanup"
            || word == *"cluster-members"
            || word == *"maintenance-run"
            || word == *"import-standalone"
    }) {
        return Err(
            "this gateway binary was built without the `postgres` cargo feature and \
                    cannot run the JWT revocation, rate-limit, cluster maintenance, or \
                    standalone-import commands; build with default features"
                .into(),
        );
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == *"migrate")
    {
        return Err(
            "this gateway binary was built without the `postgres` cargo feature and \
                    cannot run `gateway migrate`; build with default features"
                .into(),
        );
    }
    // `gateway connection-secret ...`: a one-shot command that opens the
    // connections SQLite database, does its work, prints one line, and
    // exits. It runs on a blocking thread rather than on this one.
    //
    // That is not an optimization. The local-secret manager serializes
    // against connection mutations on the control plane's mutation lock,
    // which is a Tokio mutex acquired synchronously (see
    // `CoordinatedLocalSecretManager::mutation_guard`) -- and acquiring it
    // synchronously is only legal off a runtime thread. `run()` is async,
    // so calling straight into the command here panicked the process with
    // "Cannot block the current thread from within a runtime". This is the
    // same shape the admin handlers already use for the same manager.
    let maintenance_arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let maintenance = tokio::task::spawn_blocking(move || {
        connection_secret_maintenance::run_if_requested(
            maintenance_arguments,
            config::Config::from_env,
        )
    })
    .await
    .map_err(|error| -> Box<dyn std::error::Error> {
        format!("the connection-secret maintenance command did not complete: {error}").into()
    })??;
    if let Some(output) = maintenance {
        println!("{output}");
        return Ok(());
    }

    let process_started_at = Instant::now();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .with(production_tracing_filter())
        .init();

    let config = match config::Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    // Cluster mode's startup prerequisites, before anything binds: this build
    // must carry the PostgreSQL client at all, and a selected
    // STATE_BACKEND=postgres must prove the database answers within its
    // bounded retry budget. Standalone mode runs none of this.
    ha::ensure_backend_compiled_in(&config)?;
    let _ha_foundation = match config.state_backend {
        config::StateBackend::Postgres => {
            let foundation = ha::HaFoundation::generate(&config);
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
    let _database_foundation =
        storage::postgres::PostgresFoundation::start_if_selected(&config).await?;
    // The foundation bound the database to this DEPLOYMENT_ID (or refused
    // one bound elsewhere) as part of establishing itself: deployments
    // never share a database.
    // The policy control plane rides the same pool. `active()` validates
    // the document (parse) and verifies its recorded ETag; the proxy-route
    // cross-check needs the config and runs in the app builder. Serving
    // without a validated active document is not an option the mode has:
    // an uninitialized or unreadable deployment fails startup here.
    #[cfg(feature = "postgres")]
    let pg_policy_seed = match &_database_foundation {
        Some(foundation) => {
            let store = Arc::new(storage::PostgresPolicyStore::new(foundation.pool().clone()));
            match store.active().await {
                Ok(Some(active)) => Some(ClusterPolicySeed { store, active }),
                Ok(None) => {
                    return Err(Box::new(ClusterPolicyStartupError::Uninitialized)
                        as Box<dyn std::error::Error>)
                }
                Err(error) => {
                    return Err(Box::new(ClusterPolicyStartupError::Store(error))
                        as Box<dyn std::error::Error>)
                }
            }
        }
        None => None,
    };
    // The tools control plane rides the same pool. Unlike policy, an empty
    // tools document is a valid state (it is exactly what standalone mode
    // serves without TOOLS_FILE), so a first boot seeds one idempotently:
    // racing replicas produce exactly one seeded document, later boots
    // no-op. The seed loads the authoritative local lane for the builder.
    #[cfg(feature = "postgres")]
    let pg_tools_seed = match &_database_foundation {
        Some(foundation) => {
            let store = Arc::new(storage::PostgresToolStore::new(foundation.pool().clone()));
            if let Err(error) = store.seed_empty_document().await {
                return Err(Box::new(ClusterToolsStartupError::Seeding(error))
                    as Box<dyn std::error::Error>);
            }
            match ToolControlPlane::active_tools(&*store).await {
                Ok(Some(active)) => Some(ClusterToolsSeed { store, active }),
                // Unreachable after a successful seed (ours or a racing
                // replica's): the pointer exists. Defensive fail closed.
                Ok(None) => {
                    return Err(
                        Box::new(ClusterToolsStartupError::NotSeeded) as Box<dyn std::error::Error>
                    )
                }
                Err(error) => {
                    return Err(Box::new(ClusterToolsStartupError::Store(error))
                        as Box<dyn std::error::Error>)
                }
            }
        }
        None => None,
    };
    // The Connection control plane rides the same pool. Unlike policy and
    // tools there is no document to seed: an empty deployment simply has no
    // Connections, which is exactly what standalone mode serves without
    // `CONNECTIONS_SQLITE_PATH`. What this does do before serving is run
    // the integrity preflight the SQLite store runs on every `open` -- the
    // bounds, the counter agreement, the managed-tool dependency
    // invariant -- because a replica that starts on tables it cannot vouch
    // for is a replica serving unbounded state. The records and catalogs
    // are fetched here, in an async context, because the app builder that
    // needs them is synchronous.
    #[cfg(feature = "postgres")]
    let pg_connections_seed = match &_database_foundation {
        Some(foundation) => {
            // The bound covers managed records AND this replica's legacy
            // projections (static configuration, so the same on every
            // replica); the store gets the remainder, as the SQLite path
            // gives its store the remainder.
            let legacy_projection_count =
                connections::control_plane::legacy_projection_count(&config)?;
            let store = Arc::new(
                connections::pg_store::PostgresConnectionStore::new(
                    foundation.pool().clone(),
                    connections::model::MAX_CONNECTIONS.saturating_sub(legacy_projection_count),
                )
                .map_err(|error| {
                    Box::new(ClusterConnectionsStartupError::Store(error))
                        as Box<dyn std::error::Error>
                })?,
            );
            store.validate_persisted_state().await.map_err(|error| {
                Box::new(ClusterConnectionsStartupError::Corrupt(error))
                    as Box<dyn std::error::Error>
            })?;
            let to_startup_error = |error| {
                Box::new(ClusterConnectionsStartupError::Store(error)) as Box<dyn std::error::Error>
            };
            // The revision is read BEFORE the content it labels. These are
            // separate reads, and a commit can land between them; reading
            // the revision first means such a commit leaves the authority's
            // activation revision above the seed's, so the gate's first
            // pass reconciles rather than trusting the older content under
            // the newer number.
            let revision = store.state_revision().await.map_err(to_startup_error)?;
            let records = store.list().await.map_err(to_startup_error)?;
            let (openapi_catalogs, openapi_overlays) = store
                .openapi_catalogs_with_overlays()
                .await
                .map_err(to_startup_error)?;
            let openapi_inventory_catalogs = openapi_catalogs
                .iter()
                .map(
                    |catalog| connections::store::StoredOpenApiInventoryCatalog {
                        connection_id: catalog.connection_id.clone(),
                        spec_revision: catalog.spec_revision,
                        catalog_revision: catalog.catalog_revision,
                        observed_etag: catalog.observed_etag.clone(),
                        spec_digest: catalog.spec_digest.clone(),
                        refreshed_at: catalog.refreshed_at.clone(),
                        entries: catalog.entries.clone(),
                    },
                )
                .collect();
            let boot = connections::managed_store::ClusterConnectionsBoot {
                mcp_catalogs: store.mcp_catalogs().await.map_err(to_startup_error)?,
                openapi_catalogs,
                openapi_inventory_catalogs,
                openapi_overlays,
                enum_source_values: std::sync::Mutex::new(Some(
                    store.enum_source_values().await.map_err(to_startup_error)?,
                )),
            };
            Some(ClusterConnectionsSeed {
                store,
                records,
                boot: Arc::new(boot),
                revision,
            })
        }
        None => None,
    };
    // Service tokens ride the same pool (issue #241, PR 9). Nothing to
    // seed: an empty deployment has no tokens. The revision is the gate's
    // boot watermark for the resource.
    #[cfg(feature = "postgres")]
    let pg_service_tokens_seed = match &_database_foundation {
        Some(foundation) => {
            let store = Arc::new(storage::PostgresServiceTokenStore::new(
                foundation.pool().clone(),
            ));
            let revision = store.state_revision().await.map_err(|error| {
                Box::new(ClusterServiceTokenStartupError(error)) as Box<dyn std::error::Error>
            })?;
            // Postgres mode requires DEPLOYMENT_ID (config.rs); it is the
            // domain separator under which every jti digest is computed.
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the JWT revocation store",
                )
            })?;
            Some(ClusterServiceTokenSeed {
                store,
                revision,
                pool: foundation.pool().clone(),
                deployment_id,
            })
        }
        None => None,
    };
    // Pending admin logins ride the same pool when an admin login provider
    // is configured. The keyring is loaded here, from files beneath the
    // secrets root, with the connections keyring's reader.
    #[cfg(feature = "postgres")]
    let pg_pending_logins_seed = match (&_database_foundation, config.admin_login_provider.as_ref())
    {
        (Some(foundation), Some(_)) => {
            let root = config.connection_secrets_root.as_ref().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "ADMIN_LOGIN_KEYRING requires CONNECTION_SECRETS_ROOT for its key files",
                )
            })?;
            let keyring = connections::local_secret::LocalSecretKeyring::load(
                &config.admin_login_keyring,
                root,
            )
            .map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "the admin login keyring could not be loaded: {error}"
                ))
            })?;
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the pending-login store",
                )
            })?;
            Some(ClusterPendingLoginSeed {
                pool: foundation.pool().clone(),
                deployment_id,
                keyring,
            })
        }
        _ => None,
    };
    // Cluster-mode rate limiting and execution leases ride the same pool
    // (issue #241, PR 10). The rate-limit keyring is required in postgres
    // mode (config validation), loaded from files beneath the secrets root
    // with the connections keyring's reader; the replica's instance
    // identity is the lease holder.
    #[cfg(feature = "postgres")]
    let pg_limits_seed = match (&_database_foundation, &_ha_foundation) {
        (Some(foundation), Some(ha_foundation)) => {
            let root = config.connection_secrets_root.as_ref().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "RATE_LIMIT_KEYRING requires CONNECTION_SECRETS_ROOT for its key files",
                )
            })?;
            let keyring = connections::local_secret::LocalSecretKeyring::load(
                &config.rate_limit_keyring,
                root,
            )
            .map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "the rate-limit keyring could not be loaded: {error}"
                ))
            })?;
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the rate-limit and lease stores",
                )
            })?;
            Some(ClusterLimitsSeed {
                pool: foundation.pool().clone(),
                deployment_id,
                keyring,
                instance_id: ha_foundation.identity().instance_id(),
            })
        }
        _ => None,
    };
    // Cluster membership (issue #241, PR 13): register this boot in the
    // roster and run the first fingerprint-agreement check before the app
    // is built. A disagreement is logged and leaves the replica unready
    // (`/readyz` answers `config_fingerprint_mismatch`) until the members
    // agree; only a row that cannot be written aborts startup.
    #[cfg(feature = "postgres")]
    let pg_membership_seed = match (&_database_foundation, &_ha_foundation) {
        (Some(foundation), Some(ha_foundation)) => {
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the membership roster",
                )
            })?;
            let store = storage::PostgresMembershipStore::new(
                foundation.pool().clone(),
                &deployment_id,
                *ha_foundation.identity(),
            );
            let registration = storage::MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: storage::migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: ha_foundation.fingerprint().hex(),
            };
            let membership = cluster_membership::ClusterMembership::new(
                store,
                registration,
                config.cluster_heartbeat_interval(),
                config.cluster_member_stale_window(),
            );
            membership.register_boot().await.map_err(|error| {
                Box::new(ClusterMembershipStartupError(error)) as Box<dyn std::error::Error>
            })?;
            Some(membership)
        }
        _ => None,
    };
    // The durable audit store rides the foundation's pool; the SSE
    // endpoint reads committed events through it in cluster mode. Built
    // here, where both the pool and the replica identity exist, and handed
    // to the app builder; standalone mode passes None.
    #[cfg(feature = "postgres")]
    let pg_audit_store = match (&_database_foundation, &_ha_foundation) {
        (Some(foundation), Some(ha_foundation)) => Some(Arc::new(
            storage::postgres_audit::PostgresAuditEventStore::new(
                foundation.pool().clone(),
                Some(storage::postgres_audit::IngestIdentity {
                    instance_id: ha_foundation.identity().instance_id(),
                    boot_id: ha_foundation.identity().boot_id(),
                }),
            ),
        )),
        _ => None,
    };
    // Cluster-mode discovery rides the same pool and reads the durable audit
    // store above (issue #241, PR 11): one replica at a time projects the
    // stream under a fenced lease, and every replica serves the admin
    // discovery surfaces from the projected tables.
    #[cfg(feature = "postgres")]
    let pg_discovery_seed = match (&_database_foundation, &_ha_foundation, &pg_audit_store) {
        (Some(foundation), Some(ha_foundation), Some(audit)) => {
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the discovery projector",
                )
            })?;
            Some(ClusterDiscoverySeed {
                pool: foundation.pool().clone(),
                deployment_id,
                instance_id: ha_foundation.identity().instance_id(),
                audit: audit.clone(),
            })
        }
        _ => None,
    };
    let metrics_handle = install_metrics_recorder()?;
    let listen_addr = config.listen_addr;
    let admin_listen_addr = config.admin_listen_addr;
    // Loaded before any listener binds. Certificate and key problems must abort
    // startup rather than leave a listener serving plaintext that an operator
    // configured for TLS.
    let inbound_tls = inbound_tls::InboundTlsBindings::load(&config)?;
    let shutdown_config = ShutdownConfig::from_config(&config);
    let lifecycle = GatewayLifecycle::new();
    // Cluster mode's audit of record is the shared store (issue #11, PR 3):
    // the durable sink writes through the same store instance the SSE and
    // discovery readers were just handed, with this replica's identity on
    // every row, and its drain gets the audit drain's own budget. Standalone
    // builds the sinks exactly as before -- `from_config` is this call with
    // no store.
    #[cfg(feature = "postgres")]
    let (audit_log, audit_event_sender) = audit::AuditLog::from_config_with_durable_store(
        &config,
        pg_audit_store
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
    inbound_tls.spawn_material_reload_tasks_with_lifecycle(audit_log.clone(), &lifecycle)?;
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        metrics_handle,
        audit_log.clone(),
        audit_event_sender,
        process_started_at,
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            ha_identity: _ha_foundation
                .as_ref()
                .map(|foundation| *foundation.identity()),
            #[cfg(feature = "postgres")]
            pg_audit: pg_audit_store,
            #[cfg(feature = "postgres")]
            pg_policy: pg_policy_seed,
            #[cfg(feature = "postgres")]
            pg_tools: pg_tools_seed,
            #[cfg(feature = "postgres")]
            pg_connections: pg_connections_seed,
            #[cfg(feature = "postgres")]
            pg_service_tokens: pg_service_tokens_seed,
            #[cfg(feature = "postgres")]
            pg_pending_logins: pg_pending_logins_seed,
            #[cfg(feature = "postgres")]
            pg_limits: pg_limits_seed,
            #[cfg(feature = "postgres")]
            pg_discovery: pg_discovery_seed,
            #[cfg(feature = "postgres")]
            pg_membership: pg_membership_seed,
            #[cfg(test)]
            cluster_readiness: None,
            #[cfg(test)]
            readiness_probe: None,
            #[cfg(test)]
            cluster_status_source: None,
            #[cfg(test)]
            egress_resolver: None,
            #[cfg(test)]
            pending_login_backend: None,
            #[cfg(test)]
            request_selection_count: None,
            #[cfg(test)]
            disable_proxy_health_checks: false,
            #[cfg(test)]
            stream_proxy_request_bodies: false,
        },
    )?;
    let background_lifecycle = lifecycle.clone();

    serve_gateway(
        app.http,
        app.grpc,
        listen_addr,
        admin_listen_addr,
        inbound_tls,
        audit_log,
        lifecycle,
        shutdown_config,
        Box::pin(async move {
            background_lifecycle.shutdown_background_tasks().await;
        }),
    )
    .await?;

    Ok(())
}

pub(super) fn production_tracing_filter() -> Targets {
    // rmcp 2.1 emits peer metadata, raw transport errors, and session identifiers from its
    // internal tracing calls. Keep the dependency disabled globally; GreenGateway emits its own
    // bounded MCP outcome categories at the integration boundary.
    Targets::new()
        .with_default(LevelFilter::INFO)
        .with_target("rmcp", LevelFilter::OFF)
}

/// The one-shot maintenance commands (`gateway migrate ...`) run before the
/// serving startup path initializes tracing, but their classified failure
/// diagnostics are emitted through `tracing`; without a subscriber those
/// diagnostics vanish and the operator sees only the one-line error. Give
/// the command the same compact subscriber the server uses.
#[cfg(feature = "postgres")]
pub(super) fn initialize_tracing_for_one_shot_commands() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .with(production_tracing_filter())
        .init();
}

#[cfg(test)]
pub(super) fn app(
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
pub(super) fn app_with_process_started_at(
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
pub(super) fn gateway_app_with_process_started_at(
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

pub(super) fn gateway_app_with_process_started_at_and_overrides(
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
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config_and_policy(
        &config,
        loaded_policy.as_ref(),
    );
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
    let connection_http_runtime = connections::http::ConnectionHttpRuntime::new(
        connection_control_plane.clone(),
        egress_config,
        Arc::clone(&egress_client),
    )
    .with_audit(audit_log.clone());
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
    let service_token_store: Option<Arc<dyn storage::ServiceTokenStore>> = config
        .service_token_sqlite_path
        .as_deref()
        .map(auth::SqliteTokenStore::open)
        .transpose()?
        .map(|store| Arc::new(store) as Arc<dyn storage::ServiceTokenStore>);
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
    let validator = auth_validator_from_config(
        &config,
        Arc::clone(&egress_client),
        service_token_validator.clone(),
        &discovered_oidc.jwks_urls,
        jwt_revocation,
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
            membership.spawn_heartbeat(&lifecycle, cluster_security_runtime.clone());
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
    let policy_admin_state = PolicyAdminState {
        policy_file: config.policy_file.as_ref().map(PathBuf::from),
        rbac_state: rbac_state.clone(),
        history_store: policy_history_store,
        #[cfg(feature = "postgres")]
        control_plane: policy_control_plane,
        event_store: audit_event_store.clone(),
        query_store: audit_query_store.clone(),
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
    };
    let tool_admin_state = ToolAdminState {
        tools_file: config.tools_file.as_ref().map(PathBuf::from),
        registry: tool_registry.clone(),
        inventory: capability_inventory,
        executor: tool_executor,
        rbac_state: rbac_state.clone(),
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
        Some(middleware::auth::AuthState::from_config(
            &config,
            validator,
            audit_log.clone(),
            principal_directory.clone(),
        ))
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
        csrf_cookie_name: config.csrf_cookie_name.clone(),
        csrf_header_name: config.csrf_header_name.clone(),
        max_body_size: config.max_body_size,
        mcp: mcp_state,
        protected_resource_metadata,
        lifecycle,
        cluster_readiness,
        readiness_probe,
        audit_log: audit_log.clone(),
        #[cfg(feature = "postgres")]
        database_pool: build_overrides
            .pg_limits
            .as_ref()
            .map(|seed| seed.pool.clone()),
        _connections: connection_control_plane,
    };
    let audit_admin_state = AuditAdminState {
        query_store: audit_event_store,
        event_sender: audit_event_sender,
        rbac_state: rbac_state.clone(),
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
        lifecycle_guard: Arc::new(tokio::sync::Mutex::new(())),
    };
    let principal_admin_state = PrincipalAdminState {
        directory: principal_directory,
        audit_query_store: audit_query_store.clone(),
        discovery_store: discovery_read_store.clone(),
        rbac_state: rbac_state.clone(),
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

    Ok(GatewayApps { http, grpc })
}

pub(super) fn auth_validator_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
    service_token_validator: Option<Arc<auth::ServiceTokenValidator>>,
    discovered_oidc_jwks_urls: &HashMap<String, String>,
    jwt_revocation: Option<JwtRevocationStoreFactory<'_>>,
    lifecycle: Option<&GatewayLifecycle>,
) -> Result<Option<Arc<dyn auth::SessionValidator>>, auth::AuthError> {
    let client_certificate_auth = config.client_certificate_auth_enabled();
    if config.auth_providers.is_empty()
        && service_token_validator.is_none()
        && !client_certificate_auth
    {
        return Ok(None);
    }

    let mut validators = Vec::with_capacity(
        config.auth_providers.len()
            + usize::from(service_token_validator.is_some())
            + usize::from(client_certificate_auth),
    );
    if let Some(service_token_validator) = service_token_validator {
        validators.push(service_token_validator as Arc<dyn auth::SessionValidator>);
    }
    if client_certificate_auth {
        // Position in the chain is not a precedence decision. Every validator
        // is offered every credential and each rejects the kinds it does not
        // own, so the certificate validator sits first only because it is the
        // cheapest rejection: it does no work at all on a credential that is
        // not a certificate, and it never returns `AuthError::Upstream`, so it
        // cannot turn another provider's 401 into a 503.
        validators
            .push(Arc::new(auth::ClientCertificateValidator) as Arc<dyn auth::SessionValidator>);
    }
    for provider in &config.auth_providers {
        match provider.provider_type {
            config::AuthProviderType::Jwt => {
                let jwks_url = match provider.jwks_url.clone() {
                    Some(jwks_url) => jwks_url,
                    None => {
                        let issuer = provider.issuer.as_deref().ok_or_else(|| {
                            auth::AuthError::Upstream(format!(
                                "JWT auth provider '{}' is missing jwks_url and issuer",
                                provider.name
                            ))
                        })?;
                        discovered_oidc_jwks_urls
                            .get(&provider.name)
                            .cloned()
                            .ok_or_else(|| {
                                auth::AuthError::Upstream(format!(
                                    "JWT auth provider '{}' is missing discovered jwks_uri for issuer '{issuer}'",
                                    provider.name
                                ))
                            })?
                    }
                };
                let jwt_config = auth::JwtAuthConfig::from_provider_config(provider, jwks_url);
                let validator = match jwt_revocation {
                    Some(factory) => {
                        // The denylist is keyed by exactly the issuer the
                        // validator will stamp on its principals.
                        let boundary = auth::JwtValidator::provider_principal_issuer(
                            &jwt_config,
                            &provider.name,
                        )?;
                        auth::JwtValidator::new_for_provider_with_revocation(
                            jwt_config,
                            &provider.name,
                            Arc::clone(&egress_client),
                            factory(&boundary),
                        )?
                    }
                    None => auth::JwtValidator::new_for_provider(
                        jwt_config,
                        &provider.name,
                        Arc::clone(&egress_client),
                    )?,
                };
                let validator = Arc::new(validator);
                // Keys are refreshed on a schedule, not only on a kid miss,
                // so a withdrawn signing key disappears promptly.
                if let Some(lifecycle) = lifecycle {
                    validator.spawn_background_refresh(lifecycle);
                }
                validators.push(validator as Arc<dyn auth::SessionValidator>);
            }
            config::AuthProviderType::CookieSession => {
                let cookie_config = auth::CookieSessionAuthConfig::from_provider_config(provider)?;
                validators.push(Arc::new(auth::CookieSessionValidator::new_for_provider(
                    cookie_config,
                    &provider.name,
                    Arc::clone(&egress_client),
                )?) as Arc<dyn auth::SessionValidator>);
            }
        }
    }

    Ok(Some(
        Arc::new(auth::ChainValidator::new(validators)) as Arc<dyn auth::SessionValidator>
    ))
}

pub(super) fn admin_auth_state_from_config(
    config: &config::Config,
    audit: audit::AuditLog,
    discovered_oidc: &DiscoveredOidcConfig,
    egress_client: Arc<egress::EgressClient>,
    pending_login_backend: Option<Arc<dyn auth::oidc_login::PendingLoginBackend>>,
    lifecycle: Option<&GatewayLifecycle>,
) -> Result<Option<AdminAuthState>, auth::AuthError> {
    let Some(admin_login_provider) = config.admin_login_provider.as_deref() else {
        return Ok(None);
    };
    let provider = config
        .auth_providers
        .iter()
        .find(|provider| provider.name == admin_login_provider)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER references unknown auth provider '{admin_login_provider}'"
            ))
        })?;
    let endpoints = discovered_oidc
        .admin_login
        .as_ref()
        .filter(|endpoints| endpoints.provider_name == provider.name)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{}' is missing discovered OIDC login endpoints",
                provider.name
            ))
        })?;

    let login_config = auth::OidcLoginConfig {
        client_id: required_admin_login_provider_field(provider, "client_id", &provider.client_id)?,
        client_secret: required_admin_login_provider_field(
            provider,
            "client_secret",
            &provider.client_secret,
        )?,
        redirect_uri: required_admin_login_provider_field(
            provider,
            "redirect_uri",
            &provider.redirect_uri,
        )?,
        issuer: endpoints.issuer.clone(),
        jwks_url: endpoints.jwks_url.clone(),
        authorization_endpoint: endpoints.authorization_endpoint.clone(),
        token_endpoint: endpoints.token_endpoint.clone(),
        http_timeout: Duration::from_millis(provider.jwks_timeout_ms),
        jwks_max_key_age: Duration::from_secs(provider.jwks_max_key_age_secs),
    };

    let pending_limits = auth::PendingLoginLimits {
        ttl: Duration::from_secs(config.admin_login_pending_ttl_secs),
        max_entries: config.admin_login_pending_max_entries,
        max_per_ip: config.admin_login_pending_max_per_ip,
    };
    // Cluster mode consumes the login on whichever replica the callback
    // lands; standalone mode keeps the process-local store.
    let login = match pending_login_backend {
        Some(backend) => {
            auth::OidcLoginState::new_with_backend(login_config, egress_client, backend)?
        }
        None => auth::OidcLoginState::new(login_config, egress_client, pending_limits)?,
    };
    // The ID-token validator refreshes its JWKS on the same schedule as the
    // bearer validators, so a retired signing key stops being accepted at
    // the half-age refresh rather than only at the cache's maximum age.
    if let Some(lifecycle) = lifecycle {
        login.spawn_background_refresh(lifecycle);
    }

    Ok(Some(AdminAuthState {
        login,
        audit,
        admin_prefix: config.admin_prefix.clone(),
        cookie_max_age: config.admin_login_pending_ttl_secs,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(config),
    }))
}

pub(super) fn required_admin_login_provider_field(
    provider: &config::AuthProviderConfig,
    field_name: &str,
    value: &Option<String>,
) -> Result<String, auth::AuthError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "admin login provider '{}' is missing {field_name}",
                provider.name
            ))
        })
}

pub(super) fn validate_connection_bound_tools(
    runtime: &connections::http::ConnectionHttpRuntime,
    definitions: &[tools::definitions::ToolDefinition],
) -> Result<(), Vec<String>> {
    use connections::store::ConnectionDependencyKind;
    use tools::definitions::{ToolSource, ToolTarget};

    let mut problems = Vec::new();
    let mut dependencies = Vec::new();
    for definition in definitions {
        match (&definition.source, definition.target.as_ref()) {
            (ToolSource::Manual, Some(ToolTarget::Http { connection_id, .. })) => {
                if let Err(error) = runtime.validate_binding(connection_id) {
                    problems.push(format!(
                        "tool '{}' Connection target is unavailable: {}",
                        definition.name,
                        error.safe_reason()
                    ));
                    continue;
                }
                dependencies.push((connection_id.clone(), definition.name.clone()));
            }
            (
                ToolSource::OpenApi {
                    connection_id: source_connection_id,
                    catalog_revision,
                    ..
                },
                Some(ToolTarget::Http {
                    connection_id: target_connection_id,
                    ..
                })
                | Some(ToolTarget::Composite {
                    connection_id: target_connection_id,
                }),
            ) => {
                if source_connection_id != target_connection_id {
                    problems.push(format!(
                        "OpenAPI tool '{}' source and target Connection IDs do not match",
                        definition.name
                    ));
                    continue;
                }
                if catalog_revision.is_none() {
                    problems.push(format!(
                        "managed OpenAPI tool '{}' is missing its catalog revision",
                        definition.name
                    ));
                    continue;
                }
                if let Err(error) = runtime.validate_binding(target_connection_id) {
                    problems.push(format!(
                        "OpenAPI tool '{}' Connection target is unavailable: {}",
                        definition.name,
                        error.safe_reason()
                    ));
                }
            }
            (ToolSource::OpenApi { .. }, _) => {
                problems.push(format!(
                    "managed OpenAPI tool '{}' must use a Connection HTTP or composite target",
                    definition.name
                ));
            }
            (_, Some(ToolTarget::Http { .. }) | Some(ToolTarget::Composite { .. })) => {
                problems.push(format!(
                    "tool '{}' uses a Connection HTTP or composite target with an unsupported source",
                    definition.name
                ));
            }
            _ => {}
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    runtime
        .replace_dependencies(ConnectionDependencyKind::ManualTool, &dependencies)
        .map_err(|error| {
            vec![format!(
                "manual tool Connection dependencies could not be reconciled: {}",
                error.safe_reason()
            )]
        })
}

pub(super) fn mcp_proxy_definitions_provider(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Option<tools::definitions::McpProxyDefinitionsProvider> {
    let config = config.clone();
    Some(Arc::new(
        move || match tools::mcp_upstream::discover_upstream_tools_strict_blocking(
            &config,
            Arc::clone(&egress_client),
        ) {
            Ok(definitions) => Some(definitions),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "MCP upstream rediscovery failed during tool registry reload; preserving existing MCP proxy tools"
                );
                None
            }
        },
    ))
}

pub(super) fn discover_oidc_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<DiscoveredOidcConfig, auth::AuthError> {
    let mut discovered = DiscoveredOidcConfig::default();

    for provider in &config.auth_providers {
        if provider.provider_type != config::AuthProviderType::Jwt {
            continue;
        }
        let is_admin_login_provider = config
            .admin_login_provider
            .as_deref()
            .is_some_and(|name| name == provider.name);
        if provider.jwks_url.is_some() && !is_admin_login_provider {
            continue;
        }

        let issuer = provider.issuer.as_deref().ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "JWT auth provider '{}' is missing jwks_url and issuer",
                provider.name
            ))
        })?;
        if !is_admin_login_provider {
            let jwks_url = auth::oidc::discover_jwks_uri_blocking(
                issuer,
                Duration::from_millis(provider.jwks_timeout_ms),
                Arc::clone(&egress_client),
            )?;
            discovered.jwks_urls.insert(provider.name.clone(), jwks_url);
            continue;
        }

        let document = auth::oidc::discover_document_blocking(
            issuer,
            Duration::from_millis(provider.jwks_timeout_ms),
            Arc::clone(&egress_client),
        )?;
        let issuer = document
            .issuer()
            .and_then(auth::oidc::normalize_issuer)
            .ok_or_else(|| {
                auth::AuthError::Upstream("OIDC discovery response missing issuer".to_owned())
            })?;

        let jwks_url = match provider.jwks_url.clone() {
            Some(jwks_url) => jwks_url,
            None => {
                let jwks_url = document.jwks_uri().ok_or_else(|| {
                    auth::AuthError::Upstream("OIDC discovery response missing jwks_uri".to_owned())
                })?;
                discovered
                    .jwks_urls
                    .insert(provider.name.clone(), jwks_url.clone());
                jwks_url
            }
        };

        let authorization_endpoint = document.authorization_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream(
                "OIDC discovery response missing authorization_endpoint".to_owned(),
            )
        })?;
        let token_endpoint = document.token_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream("OIDC discovery response missing token_endpoint".to_owned())
        })?;
        discovered.admin_login = Some(DiscoveredAdminLoginEndpoints {
            provider_name: provider.name.clone(),
            issuer,
            jwks_url,
            authorization_endpoint,
            token_endpoint,
        });
    }

    if let Some(admin_login_provider) = config.admin_login_provider.as_deref() {
        if discovered.admin_login.is_none() {
            return Err(auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{admin_login_provider}' could not be resolved through OIDC discovery"
            )));
        }
    }

    Ok(discovered)
}

#[cfg(test)]
pub(super) fn discover_oidc_jwks_urls_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<HashMap<String, String>, auth::AuthError> {
    discover_oidc_from_config(config, egress_client).map(|discovered| discovered.jwks_urls)
}

pub(super) fn auto_seed_discovered_oidc_hosts(
    egress_config: &mut egress::EgressConfig,
    discovered_oidc: &DiscoveredOidcConfig,
) {
    let mut auto_seeded_hosts = discovered_oidc
        .jwks_urls
        .values()
        .filter_map(|jwks_url| egress_config.auto_seed_endpoint_host(jwks_url))
        .collect::<Vec<_>>();
    if let Some(admin_login) = &discovered_oidc.admin_login {
        if let Some(host) = egress_config.auto_seed_endpoint_host(&admin_login.token_endpoint) {
            auto_seeded_hosts.push(host);
        }
    }

    if !auto_seeded_hosts.is_empty() {
        tracing::debug!(
            hosts = ?auto_seeded_hosts,
            "auto-seeded egress allowlist from discovered OIDC endpoints"
        );
    }
}

pub(super) fn policy_history_sqlite_path(config: &config::Config) -> Option<PathBuf> {
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

pub(super) fn default_policy_history_sqlite_path(policy_file: &str) -> PathBuf {
    PathBuf::from(format!("{policy_file}.history.sqlite"))
}
