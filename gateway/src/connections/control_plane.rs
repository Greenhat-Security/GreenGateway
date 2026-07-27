use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use async_trait::async_trait;

use crate::config::Config;

use super::{
    local_secret::{
        LocalSecretError, LocalSecretKeyring, LocalSecretKeyringConfigError, LocalSecretManager,
        LocalSecretProvider,
    },
    model::MAX_CONNECTIONS,
    projection::{project_legacy_connections, LegacyConnectionProjection, LegacyProjectionError},
    secret::{
        OperatorAliasResolver, ResolvedSecret, SecretAliasMetadata, SecretProviderConfigError,
        SecretPurpose, SecretResolveError, SecretResolver,
    },
    store::{ConnectionStore, ConnectionStoreError, SqliteConnectionStore},
};

#[derive(Clone)]
pub struct ConnectionControlPlane {
    managed: Option<SqliteConnectionStore>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    secret_resolver: Arc<ConnectionSecretResolver>,
    local_secret_provider: Option<Arc<LocalSecretProvider>>,
}

impl ConnectionControlPlane {
    pub fn from_config(config: &Config) -> Result<Self, ConnectionControlPlaneError> {
        let secret_resolver = Arc::new(OperatorAliasResolver::from_config(
            &config.connection_secret_aliases,
            config.connection_secrets_root.as_ref(),
        )?);
        let local_secret_keyring = if config.connection_local_secret_keyring.is_empty() {
            None
        } else {
            let root = config
                .connection_secrets_root
                .as_ref()
                .ok_or(LocalSecretKeyringConfigError::SecretsRootRequired)?;
            Some(LocalSecretKeyring::load(
                &config.connection_local_secret_keyring,
                root,
            )?)
        };
        let projection = project_legacy_connections(config)?;
        if config.connections_sqlite_path.is_some() && projection.omitted_count > 0 {
            return Err(ConnectionControlPlaneError::LimitExceeded {
                count: projection.connections.len() + projection.omitted_count,
                maximum: MAX_CONNECTIONS,
            });
        }
        if projection.omitted_count > 0 {
            tracing::warn!(
                projected_count = projection.connections.len(),
                omitted_count = projection.omitted_count,
                maximum = MAX_CONNECTIONS,
                "legacy runtime configuration exceeds the bounded Connection projection; preserving legacy runtime and omitting excess read-only projections"
            );
        }
        let omitted_legacy_projection_count = projection.omitted_count;
        let legacy = projection.connections;
        let managed = config
            .connections_sqlite_path
            .as_deref()
            .map(|path| {
                SqliteConnectionStore::open_with_maximum(
                    path,
                    MAX_CONNECTIONS.saturating_sub(legacy.len()),
                )
            })
            .transpose()?;
        let managed_count = managed
            .as_ref()
            .map(ConnectionStore::count)
            .transpose()?
            .unwrap_or_default();
        let total = managed_count.checked_add(legacy.len()).ok_or(
            ConnectionControlPlaneError::LimitExceeded {
                count: usize::MAX,
                maximum: MAX_CONNECTIONS,
            },
        )?;
        if total > MAX_CONNECTIONS {
            return Err(ConnectionControlPlaneError::LimitExceeded {
                count: total,
                maximum: MAX_CONNECTIONS,
            });
        }

        if let Some(store) = managed.as_ref() {
            let legacy_ids = legacy
                .iter()
                .map(|projection| projection.id().as_str())
                .collect::<BTreeSet<_>>();
            if let Some(collision) = store
                .list()?
                .into_iter()
                .find(|record| legacy_ids.contains(record.id.as_str()))
            {
                return Err(ConnectionControlPlaneError::IdCollision {
                    id: collision.id.to_string(),
                });
            }
        }

        let local_secret_count = managed
            .as_ref()
            .map(SqliteConnectionStore::local_secret_count)
            .transpose()?
            .unwrap_or_default();
        if local_secret_count > 0 && local_secret_keyring.is_none() {
            return Err(ConnectionControlPlaneError::LocalSecretKeyringRequired);
        }
        let local_secret_provider = if let Some(keyring) = local_secret_keyring {
            let store = managed
                .as_ref()
                .ok_or(LocalSecretKeyringConfigError::ManagedStoreRequired)?;
            let reserved_ids = config
                .connection_secret_aliases
                .iter()
                .map(|alias| alias.id.clone())
                .collect();
            Some(Arc::new(LocalSecretProvider::open(
                store,
                keyring,
                reserved_ids,
            )?))
        } else {
            None
        };
        let secret_resolver = Arc::new(ConnectionSecretResolver {
            operator: secret_resolver,
            local: local_secret_provider.clone(),
        });

        Ok(Self {
            managed,
            legacy: legacy.into(),
            omitted_legacy_projection_count,
            secret_resolver,
            local_secret_provider,
        })
    }

    pub fn managed_store(
        &self,
    ) -> Result<&SqliteConnectionStore, ManagedConnectionMutationUnavailable> {
        self.managed
            .as_ref()
            .ok_or(ManagedConnectionMutationUnavailable)
    }

    pub fn legacy(&self) -> &[LegacyConnectionProjection] {
        &self.legacy
    }

    pub fn omitted_legacy_projection_count(&self) -> usize {
        self.omitted_legacy_projection_count
    }

    pub fn is_managed_store_configured(&self) -> bool {
        self.managed.is_some()
    }

    pub fn secret_resolver(&self) -> &(dyn SecretResolver + Send + Sync) {
        self.secret_resolver.as_ref()
    }

    pub fn local_secret_manager(
        &self,
    ) -> Result<&(dyn LocalSecretManager + Send + Sync), LocalSecretMutationUnavailable> {
        self.local_secret_provider
            .as_deref()
            .map(|provider| provider as &(dyn LocalSecretManager + Send + Sync))
            .ok_or(LocalSecretMutationUnavailable)
    }
}

#[derive(Clone)]
struct ConnectionSecretResolver {
    operator: Arc<OperatorAliasResolver>,
    local: Option<Arc<LocalSecretProvider>>,
}

impl fmt::Debug for ConnectionSecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionSecretResolver")
            .field("operator_alias_count", &self.operator.aliases().len())
            .field("local_provider_enabled", &self.local.is_some())
            .finish()
    }
}

#[async_trait]
impl SecretResolver for ConnectionSecretResolver {
    async fn resolve(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        if self.operator.contains_alias(alias_id) {
            return self.operator.resolve(alias_id, purpose).await;
        }
        if let Some(local) = self.local.as_ref() {
            return local.resolve(alias_id, purpose).await;
        }
        self.operator.resolve(alias_id, purpose).await
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        let mut aliases = self.operator.aliases();
        if let Some(local) = self.local.as_ref() {
            aliases.extend(local.aliases());
        }
        aliases.sort_by(|left, right| left.id.cmp(&right.id));
        aliases
    }
}

#[derive(Debug)]
pub enum ConnectionControlPlaneError {
    Store(ConnectionStoreError),
    Projection(LegacyProjectionError),
    SecretProvider(SecretProviderConfigError),
    LocalSecretKeyring(LocalSecretKeyringConfigError),
    LocalSecret(LocalSecretError),
    LocalSecretKeyringRequired,
    LimitExceeded { count: usize, maximum: usize },
    IdCollision { id: String },
}

impl fmt::Display for ConnectionControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
            Self::SecretProvider(error) => error.fmt(formatter),
            Self::LocalSecretKeyring(error) => error.fmt(formatter),
            Self::LocalSecret(error) => error.fmt(formatter),
            Self::LocalSecretKeyringRequired => formatter.write_str(
                "encrypted local secrets exist but CONNECTION_LOCAL_SECRET_KEYRING is not configured",
            ),
            Self::LimitExceeded { count, maximum } => write!(
                formatter,
                "managed and projected connections total {count}, exceeding the maximum of {maximum}"
            ),
            Self::IdCollision { id } => write!(
                formatter,
                "managed connection ID '{id}' collides with a reserved legacy projection"
            ),
        }
    }
}

impl Error for ConnectionControlPlaneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::SecretProvider(error) => Some(error),
            Self::LocalSecretKeyring(error) => Some(error),
            Self::LocalSecret(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ConnectionStoreError> for ConnectionControlPlaneError {
    fn from(error: ConnectionStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<LegacyProjectionError> for ConnectionControlPlaneError {
    fn from(error: LegacyProjectionError) -> Self {
        Self::Projection(error)
    }
}

impl From<SecretProviderConfigError> for ConnectionControlPlaneError {
    fn from(error: SecretProviderConfigError) -> Self {
        Self::SecretProvider(error)
    }
}

impl From<LocalSecretKeyringConfigError> for ConnectionControlPlaneError {
    fn from(error: LocalSecretKeyringConfigError) -> Self {
        Self::LocalSecretKeyring(error)
    }
}

impl From<LocalSecretError> for ConnectionControlPlaneError {
    fn from(error: LocalSecretError) -> Self {
        Self::LocalSecret(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedConnectionMutationUnavailable;

impl fmt::Display for ManagedConnectionMutationUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "managed connection storage is unavailable; set CONNECTIONS_SQLITE_PATH to enable managed mutations, or use the read-only legacy projections",
        )
    }
}

impl Error for ManagedConnectionMutationUnavailable {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSecretMutationUnavailable;

impl fmt::Display for LocalSecretMutationUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "encrypted local secret mutations are unavailable; configure CONNECTIONS_SQLITE_PATH, CONNECTION_SECRETS_ROOT, and CONNECTION_LOCAL_SECRET_KEYRING",
        )
    }
}

impl Error for LocalSecretMutationUnavailable {}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        config::McpUpstreamServerConfig,
        connections::local_secret::{LocalSecretKeyConfig, LocalSecretKeyRole},
    };

    use super::*;

    fn config() -> Config {
        Config::test_defaults()
    }

    struct TemporaryLocalControlPlane {
        root: PathBuf,
        database: PathBuf,
    }

    impl TemporaryLocalControlPlane {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-control-plane-local-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary secret root should create");
            set_directory_permissions(&root, 0o700);
            let key = root.join("primary.key");
            fs::write(&key, [73u8; 32]).expect("temporary primary key should write");
            set_file_permissions(&key, 0o600);
            let database = root.join("connections.sqlite");
            Self { root, database }
        }

        fn config(&self) -> Config {
            let mut config = config();
            config.connections_sqlite_path = Some(self.database.display().to_string());
            config.connection_secrets_root = Some(
                crate::connections::secret::SecretRootConfig::new(self.root.clone()),
            );
            config.connection_local_secret_keyring = vec![LocalSecretKeyConfig {
                id: "primary-key-canary".to_owned(),
                file: "primary.key".to_owned(),
                role: LocalSecretKeyRole::Primary,
            }];
            config
        }
    }

    impl Drop for TemporaryLocalControlPlane {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-control-plane-local-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    #[test]
    fn unset_store_is_explicitly_read_only_and_creates_no_database() {
        let config = config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        assert!(!control_plane.is_managed_store_configured());
        assert!(control_plane.legacy().is_empty());
        assert_eq!(control_plane.omitted_legacy_projection_count(), 0);
        let error = match control_plane.managed_store() {
            Ok(_) => panic!("managed mutations must be unavailable"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "managed connection storage is unavailable; set CONNECTIONS_SQLITE_PATH to enable managed mutations, or use the read-only legacy projections"
        );
        assert!(matches!(
            control_plane.local_secret_manager(),
            Err(LocalSecretMutationUnavailable)
        ));
    }

    #[test]
    fn oversized_legacy_only_config_preserves_runtime_and_bounds_projection() {
        let mut config = config();
        config.mcp_upstream_servers = (0..=MAX_CONNECTIONS)
            .map(|index| McpUpstreamServerConfig {
                name: format!("server-{index}"),
                url: format!("https://mcp-{index}.example.test"),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
            })
            .collect();

        let control_plane = ConnectionControlPlane::from_config(&config)
            .expect("unset managed storage must preserve legacy startup");
        assert_eq!(control_plane.legacy().len(), MAX_CONNECTIONS);
        assert_eq!(control_plane.omitted_legacy_projection_count(), 1);
        assert!(!control_plane.is_managed_store_configured());
    }

    #[test]
    fn oversized_legacy_config_with_managed_store_fails_before_creating_database() {
        let path = std::env::temp_dir().join(format!(
            "greengateway-control-plane-overflow-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let mut config = config();
        config.connections_sqlite_path = Some(path.display().to_string());
        config.mcp_upstream_servers = (0..=MAX_CONNECTIONS)
            .map(|index| McpUpstreamServerConfig {
                name: format!("server-{index}"),
                url: format!("https://mcp-{index}.example.test"),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
            })
            .collect();

        assert!(matches!(
            ConnectionControlPlane::from_config(&config),
            Err(ConnectionControlPlaneError::LimitExceeded {
                count,
                maximum: MAX_CONNECTIONS,
            }) if count == MAX_CONNECTIONS + 1
        ));
        assert!(
            !path.exists(),
            "capacity failure must happen before store open"
        );
    }

    #[test]
    fn operator_alias_metadata_is_held_without_exposing_locators() {
        let locator_canary = "CONTROL_PLANE_SECRET_LOCATOR_CANARY";
        let mut config = config();
        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: "billing-token".to_owned(),
                label: "Billing token".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::Environment {
                    key: locator_canary.to_owned(),
                },
            }];

        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let metadata = control_plane.secret_resolver().aliases();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].id, "billing-token");
        let serialized = serde_json::to_string(&metadata).expect("metadata should serialize");
        assert!(!serialized.contains(locator_canary));
    }

    #[test]
    fn unsafe_secret_provider_startup_fails_before_database_creation() {
        let database_path = std::env::temp_dir().join(format!(
            "greengateway-control-plane-secret-order-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let missing_root = std::env::temp_dir().join(format!(
            "greengateway-control-plane-missing-root-{}",
            uuid::Uuid::new_v4()
        ));
        let mut config = config();
        config.connections_sqlite_path = Some(database_path.display().to_string());
        config.connection_secrets_root = Some(crate::connections::secret::SecretRootConfig::new(
            missing_root,
        ));
        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: "billing-token".to_owned(),
                label: "Billing token".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::File {
                    key: "billing-token".to_owned(),
                },
            }];

        assert!(matches!(
            ConnectionControlPlane::from_config(&config),
            Err(ConnectionControlPlaneError::SecretProvider(
                SecretProviderConfigError::SecretsRootUnavailable
            ))
        ));
        assert!(
            !database_path.exists(),
            "secret-provider validation must precede store creation"
        );
    }

    #[test]
    fn unavailable_local_master_key_fails_before_database_creation() {
        let temporary = TemporaryLocalControlPlane::new("missing-master-key");
        let config = temporary.config();
        fs::remove_file(temporary.root.join("primary.key"))
            .expect("test primary key should remove");

        assert!(matches!(
            ConnectionControlPlane::from_config(&config),
            Err(ConnectionControlPlaneError::LocalSecretKeyring(
                LocalSecretKeyringConfigError::KeyFileUnavailable { index: 0 }
            ))
        ));
        assert!(
            !temporary.database.exists(),
            "master-key validation must precede store creation"
        );
    }

    #[test]
    fn configured_store_is_migrated_during_control_plane_construction() {
        let path = std::env::temp_dir().join(format!(
            "greengateway-control-plane-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let mut config = config();
        config.connections_sqlite_path = Some(path.display().to_string());
        config.upstream_url = Some("https://legacy.example.test".to_owned());

        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        assert!(control_plane.is_managed_store_configured());
        assert_eq!(control_plane.legacy().len(), 1);
        assert!(path.is_file());
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should work"),
            0
        );
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .maximum_connections(),
            MAX_CONNECTIONS - 1
        );
        drop(control_plane);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn configured_local_provider_exposes_mutation_only_manager_and_combined_resolution() {
        let temporary = TemporaryLocalControlPlane::new("combined");
        let mut config = temporary.config();
        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: "operator-token".to_owned(),
                label: "Operator token".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::Environment {
                    key: "CONTROL_PLANE_OPERATOR_TOKEN".to_owned(),
                },
            }];
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let manager = control_plane
            .local_secret_manager()
            .expect("local secret manager should be enabled");
        let canary = b"control-plane-local-secret-canary";
        let created = manager
            .create(
                "Local token",
                ResolvedSecret::new(SecretPurpose::StaticBearer, canary.to_vec())
                    .expect("test secret should validate"),
            )
            .expect("local secret should create");

        let aliases = control_plane.secret_resolver().aliases();
        assert_eq!(aliases.len(), 2);
        assert!(aliases
            .iter()
            .any(|metadata| metadata.id == "operator-token"));
        assert!(aliases.iter().any(|metadata| metadata.id == created.id));
        assert_eq!(
            control_plane
                .secret_resolver()
                .resolve(&created.id, SecretPurpose::StaticBearer)
                .await
                .expect("local secret should resolve through combined resolver")
                .expose(),
            canary
        );
        let metadata_json = serde_json::to_string(&aliases).expect("metadata should serialize");
        assert!(!metadata_json.contains("primary-key-canary"));
        assert!(!metadata_json.contains("primary.key"));
        assert!(!metadata_json
            .contains(std::str::from_utf8(canary).expect("control-plane canary should be utf8")));
    }

    #[test]
    fn encrypted_rows_without_a_keyring_fail_restart_closed() {
        let temporary = TemporaryLocalControlPlane::new("missing-keyring");
        let mut config = temporary.config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        control_plane
            .local_secret_manager()
            .expect("manager should exist")
            .create(
                "Restart token",
                ResolvedSecret::new(
                    SecretPurpose::StaticBearer,
                    b"restart-local-secret-canary".to_vec(),
                )
                .expect("test secret should validate"),
            )
            .expect("local secret should create");
        drop(control_plane);

        config.connection_local_secret_keyring.clear();
        let error = match ConnectionControlPlane::from_config(&config) {
            Ok(_) => panic!("encrypted rows without a keyring must fail startup"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConnectionControlPlaneError::LocalSecretKeyringRequired
        ));
        let message = error.to_string();
        assert!(!message.contains("primary-key-canary"));
        assert!(!message.contains("primary.key"));
        assert!(!message.contains("restart-local-secret-canary"));
    }

    #[test]
    fn local_and_operator_alias_identifier_collision_fails_restart_closed() {
        let temporary = TemporaryLocalControlPlane::new("alias-collision");
        let mut config = temporary.config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let created = control_plane
            .local_secret_manager()
            .expect("manager should exist")
            .create(
                "Collision token",
                ResolvedSecret::new(
                    SecretPurpose::StaticBearer,
                    b"collision-local-secret-canary".to_vec(),
                )
                .expect("test secret should validate"),
            )
            .expect("local secret should create");
        drop(control_plane);

        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: created.id,
                label: "Colliding operator alias".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::Environment {
                    key: "COLLISION_OPERATOR_SECRET".to_owned(),
                },
            }];
        assert!(matches!(
            ConnectionControlPlane::from_config(&config),
            Err(ConnectionControlPlaneError::LocalSecret(
                LocalSecretError::IdentifierCollision
            ))
        ));
    }

    #[cfg(unix)]
    fn set_directory_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("directory permissions should set");
    }

    #[cfg(not(unix))]
    fn set_directory_permissions(_: &std::path::Path, _: u32) {}

    #[cfg(unix)]
    fn set_file_permissions(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("file permissions should set");
    }

    #[cfg(not(unix))]
    fn set_file_permissions(_: &std::path::Path, _: u32) {}
}
