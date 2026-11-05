//! The one-shot operator commands the server binary runs instead of
//! serving: `healthcheck`, the cluster commands (`migrate`, `revoke-jwt`,
//! `jwt-revocations-cleanup`, `rate-limit-buckets-cleanup`,
//! `cluster-members`, `maintenance-run`, `import-standalone`) and
//! `connection-secrets ...`. Each does its work, prints its result and ends
//! the process; none starts a listener.
use super::*;

/// Run the one-shot command the process arguments name, before anything
/// serving needs is initialized. `Ok(true)` when a command ran, so the
/// process exits; `Ok(false)` when the arguments name none and startup goes
/// on to serve. A command that fails returns its error, which `main`
/// reports like any other startup error; `migrate` exits with its own
/// status when its check finds the schema not current.
pub(crate) async fn run_one_shot_command() -> Result<bool, Box<dyn std::error::Error>> {
    // Container probes must not initialize application state or require secrets.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| word == "healthcheck")
    {
        let arguments = std::env::args_os().skip(2).collect::<Vec<_>>();
        let [url] = arguments.as_slice() else {
            return Err("usage: gateway healthcheck <loopback probe URL>".into());
        };
        egress::check_local_health(url.to_str().ok_or("probe URL must be UTF-8")?).await?;
        return Ok(true);
    }
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
                    return Ok(true);
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
            .revoke(
                &jti,
                expires_at.as_deref(),
                &auth::change_actor::ChangeActor::system("operator:revoke-jwt"),
            )
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
        return Ok(true);
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
        return Ok(true);
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
        return Ok(true);
    }
    // `gateway cluster-members`: one line per member row of the deployment
    // (issue #241, PR 13), liveness judged on the database clock against
    // CLUSTER_MEMBER_STALE_MS, after a line for the durable contract fence
    // (issue #426, PR 3). Read-only: the command is not a member and writes
    // no row of its own. The status API/UI is PR 14.
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
        let fence = store.contract_fence().await.map_err(|error| {
            Box::<dyn std::error::Error>::from(format!("contract fence read failed: {error}"))
        })?;
        let live = members.iter().filter(|member| member.live).count();
        println!(
            "deployment={deployment_id} members={} live={live} stale_window_ms={}",
            members.len(),
            stale_window.as_millis()
        );
        // The durable contract fence (issue #426, PR 3), redacted like the
        // member rows below: recognized names only, plus a count of the rest.
        let fenced = storage::compatibility::RecognizedCapabilities::parse(&fence.capabilities);
        let fenced_names = fenced.names();
        println!(
            "fence generation={} minimum_schema={} capabilities={} unrecognized_capabilities={}",
            fence.generation,
            fence.minimum_schema,
            if fenced_names.is_empty() {
                "-".to_owned()
            } else {
                fenced_names.join(",")
            },
            fenced.unrecognized(),
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
            // Recognized names only, plus a count of the rest: the roster
            // column is written by other replicas, and this line prints
            // what this binary can vouch for.
            let capabilities =
                storage::compatibility::RecognizedCapabilities::parse(&member.capabilities);
            let capability_names = capabilities.names();
            println!(
                "{state:<9} instance={} boot={} version={} schema={}..{} document={}..{} fingerprint={} started={} heartbeat={} age_secs={:.1} revisions=compiled:{}/observed:{} last_error={} capabilities={} unrecognized_capabilities={}",
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
                if capability_names.is_empty() {
                    "-".to_owned()
                } else {
                    capability_names.join(",")
                },
                capabilities.unrecognized(),
            );
        }
        return Ok(true);
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
            authority_event_retention: config.authority_events.retention(),
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
        return Ok(true);
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
        return Ok(true);
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
        return Ok(true);
    }
    Ok(false)
}

/// The one-shot maintenance commands (`gateway migrate ...`) run before the
/// serving startup path initializes tracing, but their classified failure
/// diagnostics are emitted through `tracing`; without a subscriber those
/// diagnostics vanish and the operator sees only the one-line error. Give
/// the command the same compact subscriber the server uses.
#[cfg(feature = "postgres")]
pub(crate) fn initialize_tracing_for_one_shot_commands() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .with(production_tracing_filter())
        .init();
}
