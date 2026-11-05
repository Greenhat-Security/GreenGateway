//! Cluster mode's half of preflight: the boot seeds read and checked from
//! the authority the database foundation established, and this boot's
//! membership row. Only a `postgres` build has an authority to read.
use super::*;

/// Cluster mode's boot seeds, read from the authority by preflight. Every
/// one is `None` in standalone mode.
pub(crate) struct ClusterBootSeeds {
    pub(super) policy: Option<ClusterPolicySeed>,
    pub(super) tools: Option<ClusterToolsSeed>,
    pub(super) connections: Option<ClusterConnectionsSeed>,
    pub(super) service_tokens: Option<ClusterServiceTokenSeed>,
    pub(super) delegated_token_purges: Option<ClusterDelegatedTokenPurgeSeed>,
    pub(super) pending_logins: Option<ClusterPendingLoginSeed>,
    pub(super) limits: Option<ClusterLimitsSeed>,
    pub(super) membership: Option<Arc<cluster_membership::ClusterMembership>>,
    pub(super) audit: Option<Arc<storage::postgres_audit::PostgresAuditEventStore>>,
    pub(super) discovery: Option<ClusterDiscoverySeed>,
    pub(super) authority_events:
        Option<Arc<storage::postgres_authority_events::PostgresAuthorityEventStore>>,
}

/// Cluster mode's preflight against the authority the database foundation
/// established: the boot seeds, read and checked in the order startup has
/// always read them, and this boot's membership row, which goes into
/// `published` before it is written. Standalone mode, with no foundation,
/// reads and publishes nothing.
pub(super) async fn preflight_cluster_authority(
    config: &config::Config,
    database_foundation: Option<&storage::postgres::PostgresFoundation>,
    ha_foundation: Option<&ha::HaFoundation>,
    published: &mut Option<ProcessPublication>,
) -> Result<ClusterBootSeeds, Box<dyn std::error::Error>> {
    // The foundation bound the database to this DEPLOYMENT_ID (or refused
    // one bound elsewhere) as part of establishing itself: deployments
    // never share a database.
    // The policy control plane rides the same pool. `active()` validates
    // the document (parse) and verifies its recorded ETag; the proxy-route
    // cross-check needs the config and runs in the app builder. Serving
    // without a validated active document is not an option the mode has:
    // an uninitialized or unreadable deployment fails startup here.
    let policy = match database_foundation {
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
    let tools = match database_foundation {
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
    let connections = match database_foundation {
        Some(foundation) => {
            // The bound covers managed records AND this replica's legacy
            // projections (static configuration, so the same on every
            // replica); the store gets the remainder, as the SQLite path
            // gives its store the remainder.
            let legacy_projection_count =
                connections::control_plane::legacy_projection_count(config)?;
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
    let service_tokens = match database_foundation {
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
    // Delegated-token purges ride the same pool (issue #441). The revision
    // is read here, before activation builds the cache, so nothing recorded
    // at or below it can name a token the replica holds; the gate's
    // resource applies only what is recorded above it.
    let delegated_token_purges = match database_foundation {
        Some(foundation) => {
            let revisions = storage::SecurityRevisionSource::new(foundation.pool().clone());
            let revision = revisions.current().await.map_err(|error| {
                Box::<dyn std::error::Error>::from(format!(
                    "the shared security revision could not be read for the delegated-token \
                         purge record: {error}"
                ))
            })?;
            let deployment_id = config.deployment_id.clone().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "STATE_BACKEND=postgres requires DEPLOYMENT_ID for the delegated-token purge \
                     record",
                )
            })?;
            Some(ClusterDelegatedTokenPurgeSeed {
                store: Arc::new(storage::PostgresDelegatedTokenPurgeStore::new(
                    foundation.pool().clone(),
                )),
                deployment_id,
                revision,
            })
        }
        None => None,
    };
    // Pending admin logins ride the same pool when an admin login provider
    // is configured. The keyring is loaded here, from files beneath the
    // secrets root, with the connections keyring's reader.
    let pending_logins = match (database_foundation, config.admin_login_provider.as_ref()) {
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
    let limits = match (database_foundation, ha_foundation) {
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
    // The authority-event journal (issue #425, PR 3) rides the same pool.
    // Its capacity is one row the whole deployment reserves against, so it
    // is not written here: a replica applies AUTHORITY_EVENT_JOURNAL_CAPACITY
    // only when the membership below admits it (an admission write), and a
    // replica held at the fingerprint door never does, so a stale or
    // misconfigured replica booting mid-rollout cannot rewrite the capacity
    // the serving replicas enforce. A capacity that cannot be applied on
    // admission refuses startup: every authority mutation reserves it.
    let authority_events = database_foundation.map(|foundation| {
        Arc::new(
            storage::postgres_authority_events::PostgresAuthorityEventStore::new(
                foundation.pool().clone(),
            ),
        )
    });
    // Cluster membership (issue #241, PR 13): register this boot in the
    // roster and run the first fingerprint-agreement check before the app
    // is built. A disagreement is logged and leaves the replica unready
    // (`/readyz` answers `config_fingerprint_mismatch`) until the members
    // agree; only a row, or an admission write, that cannot be written
    // aborts startup.
    let membership = match (database_foundation, ha_foundation, &authority_events) {
        (Some(foundation), Some(ha_foundation), Some(journal)) => {
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
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            };
            let membership = cluster_membership::ClusterMembership::with_journal_capacity(
                store,
                registration,
                config.cluster_heartbeat_interval(),
                config.cluster_member_stale_window(),
                cluster_membership::JournalCapacity {
                    store: Arc::clone(journal),
                    capacity: config.authority_events.journal_capacity,
                },
            );
            // Published before registration, which may write the boot row
            // and then fail: from here on, a startup that fails before it
            // serves -- registration and its admission writes, activation,
            // binding a listener -- has the row withdrawn.
            *published = Some(Arc::clone(&membership));
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
    let audit = match (database_foundation, ha_foundation) {
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
    let discovery = match (database_foundation, ha_foundation, &audit) {
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
    Ok(ClusterBootSeeds {
        policy,
        tools,
        connections,
        service_tokens,
        delegated_token_purges,
        pending_logins,
        limits,
        membership,
        audit,
        discovery,
        authority_events,
    })
}
