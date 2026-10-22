//! Starting authority-event delivery on a cluster replica (issue #425, PR 3).
//!
//! The app builder is synchronous, and the pseudonym key may live behind a
//! network secret provider that only exists once the builder has activated
//! it, so the builder hands back an [`AuthorityEventStartup`] and the serving
//! path finishes it before any listener binds. Every failure here refuses
//! startup: a replica configured to deliver evidence never serves without a
//! working keyring, and there is no unkeyed mode to fall back to.

use std::{fmt, sync::Arc};

use serde_json::json;
use uuid::Uuid;

use super::{
    dispatcher::{spawn_authority_event_dispatcher, DispatcherConfig},
    pseudonym::{resolve_keyring, PseudonymError},
    sink::{AuthorityEventSink, FileSink, LogSink},
};
use crate::{
    audit,
    config::{AuthorityEventSettings, AuthorityEventSinkSetting},
    connections::secret::SecretResolver,
    lifecycle::GatewayLifecycle,
    storage::{postgres_authority_events::PostgresAuthorityEventStore, RepositoryError},
    tools::lease::ExecutionLeaseStore,
};

/// What the serving path needs to start the dispatcher, assembled by the
/// app builder when a sink is configured.
pub(crate) struct AuthorityEventStartup {
    pub(crate) store: Arc<PostgresAuthorityEventStore>,
    /// The Connection control plane's secret resolver: the operator aliases
    /// and the network providers the builder activated.
    pub(crate) resolver: Arc<dyn SecretResolver>,
    pub(crate) settings: AuthorityEventSettings,
    pub(crate) leases: Arc<dyn ExecutionLeaseStore>,
    pub(crate) holder: Uuid,
}

/// Why delivery could not start. None carries key material, a path or an
/// identifier.
#[derive(Debug)]
pub(crate) enum AuthorityEventStartupError {
    /// A sink is configured without a key alias (configuration refuses this
    /// first; kept so the type cannot express an unkeyed dispatcher).
    MissingKeyAlias,
    AuthorityId(RepositoryError),
    Keyring(PseudonymError),
    /// The file sink's file cannot be opened for appending.
    SinkFile(std::io::ErrorKind),
}

impl fmt::Display for AuthorityEventStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKeyAlias => formatter
                .write_str("authority event delivery requires AUTHORITY_PSEUDONYM_KEY_ALIAS"),
            Self::AuthorityId(error) => write!(
                formatter,
                "the authority event journal's authority ID could not be read: {error}"
            ),
            Self::Keyring(error) => {
                write!(formatter, "authority event delivery cannot start: {error}")
            }
            Self::SinkFile(kind) => write!(
                formatter,
                "AUTHORITY_EVENT_FILE cannot be opened for appending ({kind:?})"
            ),
        }
    }
}

impl std::error::Error for AuthorityEventStartupError {}

impl AuthorityEventStartup {
    /// Resolve the keyring under the persisted authority ID, prove the sink
    /// can accept, record the keyring in the audit log by key ID, and spawn
    /// the dispatcher. Nothing is spawned unless every step succeeded.
    pub(crate) async fn start(
        self,
        lifecycle: &GatewayLifecycle,
        audit_log: &audit::AuditLog,
    ) -> Result<(), AuthorityEventStartupError> {
        let sink: Arc<dyn AuthorityEventSink> = match &self.settings.sink {
            AuthorityEventSinkSetting::None => return Ok(()),
            AuthorityEventSinkSetting::Log => Arc::new(LogSink),
            AuthorityEventSinkSetting::File(path) => {
                let sink = FileSink::new(path.into());
                sink.probe()
                    .await
                    .map_err(AuthorityEventStartupError::SinkFile)?;
                Arc::new(sink)
            }
        };
        let current = self
            .settings
            .pseudonym_key_alias
            .as_deref()
            .ok_or(AuthorityEventStartupError::MissingKeyAlias)?;
        // Written once by the first replica that gets here, read back by
        // every other, so all of them derive under one authority.
        let authority_id = self
            .store
            .authority_id(Uuid::new_v4())
            .await
            .map_err(AuthorityEventStartupError::AuthorityId)?;
        let keyring = resolve_keyring(
            self.resolver.as_ref(),
            authority_id,
            current,
            self.settings.previous_pseudonym_key_alias.as_deref(),
        )
        .await
        .map_err(AuthorityEventStartupError::Keyring)?;

        audit_log.emit(audit::AuditEvent::new(
            audit::event::AUTHORITY_EVENT_KEYRING_LOADED,
            "startup",
            "internal",
            None::<audit::Actor>,
            json!({
                "authority_id": authority_id.to_string(),
                "current_key_id": keyring.current_key_id(),
                "previous_key_id": keyring.previous_key_id(),
                "sink": sink.kind(),
            }),
        ));
        tracing::info!(
            authority_id = %authority_id,
            current_key_id = keyring.current_key_id(),
            previous_key_id = keyring.previous_key_id().unwrap_or("-"),
            sink = sink.kind(),
            "authority event pseudonym keyring loaded"
        );

        spawn_authority_event_dispatcher(
            lifecycle,
            self.store,
            sink,
            Arc::new(keyring),
            self.leases,
            self.holder,
            DispatcherConfig::default(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex, time::Duration};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        authority_events::pseudonym::{test_support::generated_key_hex, KeyRole},
        connections::secret::{
            ResolvedSecret, SecretAliasMetadata, SecretPurpose, SecretResolveError,
            SecretResolveErrorKind,
        },
        storage::contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        tools::lease::memory::MemoryLeaseStore,
    };

    /// Fixed material per alias, under whatever purpose is asked for.
    struct FixedResolver(BTreeMap<String, String>);

    #[async_trait]
    impl SecretResolver for FixedResolver {
        async fn resolve(
            &self,
            alias_id: &str,
            purpose: SecretPurpose,
        ) -> Result<ResolvedSecret, SecretResolveError> {
            let material = self.0.get(alias_id).ok_or_else(|| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::UnknownAlias)
            })?;
            ResolvedSecret::new(purpose, material.as_bytes().to_vec()).map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial)
            })
        }

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            Vec::new()
        }
    }

    #[derive(Default)]
    struct CapturingSink(Mutex<Vec<audit::AuditEvent>>);

    impl audit::AuditSink for CapturingSink {
        fn emit(&self, event: &audit::AuditEvent) {
            self.0.lock().expect("capture lock").push(event.clone());
        }
    }

    async fn migrated_store(database: &TestDatabase) -> Arc<PostgresAuthorityEventStore> {
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-authority-startup".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = crate::storage::postgres::PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        crate::storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the schema should migrate");
        Arc::new(PostgresAuthorityEventStore::new(foundation.pool().clone()))
    }

    fn startup(
        store: &Arc<PostgresAuthorityEventStore>,
        resolver: FixedResolver,
        sink: AuthorityEventSinkSetting,
    ) -> AuthorityEventStartup {
        AuthorityEventStartup {
            store: Arc::clone(store),
            resolver: Arc::new(resolver),
            settings: AuthorityEventSettings {
                sink,
                pseudonym_key_alias: Some("pseudonym-current".to_owned()),
                ..AuthorityEventSettings::default()
            },
            leases: Arc::new(MemoryLeaseStore::new(Duration::from_secs(5))),
            holder: Uuid::new_v4(),
        }
    }

    /// A configured sink starts only with a key that resolves, and the load
    /// is audited by key ID, never by material. Every refusal is an error
    /// the serving path turns into a refused startup.
    #[tokio::test]
    async fn delivery_starts_only_with_a_resolvable_key_and_audits_only_its_key_id() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database).await;
        let lifecycle = GatewayLifecycle::new();
        let capture = Arc::new(CapturingSink::default());
        let audit_log = audit::AuditLog::new(Arc::clone(&capture) as Arc<dyn audit::AuditSink>);

        // An alias nothing provides refuses startup.
        assert!(matches!(
            startup(
                &store,
                FixedResolver(BTreeMap::new()),
                AuthorityEventSinkSetting::Log
            )
            .start(&lifecycle, &audit_log)
            .await,
            Err(AuthorityEventStartupError::Keyring(
                PseudonymError::KeyUnavailable {
                    role: KeyRole::Current,
                    kind: SecretResolveErrorKind::UnknownAlias,
                }
            ))
        ));
        // So does material that is not a generated key.
        let placeholder = FixedResolver(BTreeMap::from([(
            "pseudonym-current".to_owned(),
            "a".repeat(64),
        )]));
        assert!(matches!(
            startup(&store, placeholder, AuthorityEventSinkSetting::Log)
                .start(&lifecycle, &audit_log)
                .await,
            Err(AuthorityEventStartupError::Keyring(
                PseudonymError::KeyRejected { .. }
            ))
        ));
        // And a file sink whose file cannot be opened.
        let directory =
            std::env::temp_dir().join(format!("greengateway-authority-startup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let material = generated_key_hex();
        let resolver = || {
            FixedResolver(BTreeMap::from([(
                "pseudonym-current".to_owned(),
                material.clone(),
            )]))
        };
        assert!(matches!(
            startup(
                &store,
                resolver(),
                AuthorityEventSinkSetting::File(directory.display().to_string()),
            )
            .start(&lifecycle, &audit_log)
            .await,
            Err(AuthorityEventStartupError::SinkFile(_))
        ));

        startup(&store, resolver(), AuthorityEventSinkSetting::Log)
            .start(&lifecycle, &audit_log)
            .await
            .expect("a resolvable key starts delivery");
        audit_log
            .close_and_drain(Duration::from_secs(5))
            .await
            .expect("the audit log drains");
        lifecycle.shutdown_background_tasks().await;
        let _ = std::fs::remove_dir_all(directory);

        let loaded: Vec<audit::AuditEvent> = capture
            .0
            .lock()
            .expect("capture lock")
            .iter()
            .filter(|event| event.event_type == audit::event::AUTHORITY_EVENT_KEYRING_LOADED)
            .cloned()
            .collect();
        assert_eq!(loaded.len(), 1, "only the successful start is audited");
        let payload = &loaded[0].payload;
        let authority_id = store
            .authority_id(Uuid::new_v4())
            .await
            .expect("the authority ID persisted");
        assert_eq!(payload["authority_id"], authority_id.to_string());
        assert_eq!(payload["sink"], "log");
        assert_eq!(payload["previous_key_id"], serde_json::Value::Null);
        let key_id = payload["current_key_id"]
            .as_str()
            .expect("the key ID is a string");
        assert_eq!(key_id.len(), 8);
        assert!(
            !serde_json::to_string(&loaded[0])
                .expect("serializes")
                .contains(&material),
            "the audit record never carries key material"
        );
    }

    /// Without a sink there is nothing to start, and nothing is resolved.
    #[tokio::test]
    async fn no_sink_starts_nothing_and_resolves_nothing() {
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            tokio_postgres::Config::new(),
            tokio_postgres::NoTls,
        ))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("a lazy pool builds without connecting");
        let store = Arc::new(PostgresAuthorityEventStore::new(pool));
        let audit_log = audit::AuditLog::new(Arc::new(CapturingSink::default()));
        startup(
            &store,
            FixedResolver(BTreeMap::new()),
            AuthorityEventSinkSetting::None,
        )
        .start(&GatewayLifecycle::new(), &audit_log)
        .await
        .expect("no sink, no startup work");
    }
}
