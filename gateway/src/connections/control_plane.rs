use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::config::Config;

use super::{
    local_secret::{
        LocalSecretError, LocalSecretKeyring, LocalSecretKeyringConfigError, LocalSecretManager,
        LocalSecretProvider,
    },
    model::{ConnectionId, ConnectionWrite, MAX_CONNECTIONS},
    projection::{project_legacy_connections, LegacyConnectionProjection, LegacyProjectionError},
    secret::{
        OperatorAliasResolver, ResolvedSecret, SecretAliasMetadata, SecretProviderConfigError,
        SecretPurpose, SecretResolveError, SecretResolver,
    },
    store::{
        ConnectionEtag, ConnectionStore, ConnectionStoreError, SqliteConnectionStore,
        StoredConnection,
    },
};

#[derive(Clone)]
pub struct ConnectionControlPlane {
    managed: Option<SqliteConnectionStore>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    runtime: Arc<ArcSwap<ConnectionRuntimeSnapshot>>,
    mutation_lock: Arc<Mutex<()>>,
    secret_resolver: Arc<ConnectionSecretResolver>,
    local_secret_provider: Option<Arc<LocalSecretProvider>>,
}

#[derive(Clone)]
pub struct ConnectionRuntimeSnapshot {
    managed: Arc<BTreeMap<ConnectionId, StoredConnection>>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    collection_etag: Arc<str>,
}

impl fmt::Debug for ConnectionRuntimeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRuntimeSnapshot")
            .field("managed_count", &self.managed.len())
            .field("legacy_count", &self.legacy.len())
            .field(
                "omitted_legacy_projection_count",
                &self.omitted_legacy_projection_count,
            )
            .finish()
    }
}

impl ConnectionRuntimeSnapshot {
    fn new(
        managed: BTreeMap<ConnectionId, StoredConnection>,
        legacy: Arc<[LegacyConnectionProjection]>,
        omitted_legacy_projection_count: usize,
    ) -> Self {
        let collection_etag = collection_etag(&managed, &legacy, omitted_legacy_projection_count);
        Self {
            managed: Arc::new(managed),
            legacy,
            omitted_legacy_projection_count,
            collection_etag: Arc::from(collection_etag),
        }
    }

    pub fn managed(&self) -> &BTreeMap<ConnectionId, StoredConnection> {
        &self.managed
    }

    pub fn legacy(&self) -> &[LegacyConnectionProjection] {
        &self.legacy
    }

    pub fn omitted_legacy_projection_count(&self) -> usize {
        self.omitted_legacy_projection_count
    }

    pub fn collection_etag(&self) -> &str {
        &self.collection_etag
    }
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

        let managed_records = managed
            .as_ref()
            .map(ConnectionStore::list)
            .transpose()?
            .unwrap_or_default();
        if managed.is_some() {
            let legacy_ids = legacy
                .iter()
                .map(|projection| projection.id().as_str())
                .collect::<BTreeSet<_>>();
            if let Some(collision) = managed_records
                .iter()
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
        let configured_alias_ids = secret_resolver
            .aliases()
            .into_iter()
            .filter(|alias| alias.configured)
            .map(|alias| alias.id)
            .collect::<BTreeSet<_>>();
        if let Some(record) = managed_records.iter().find(|record| {
            !record
                .write
                .unresolved_enabled_binding_fields(|id| configured_alias_ids.contains(id))
                .is_empty()
        }) {
            return Err(ConnectionControlPlaneError::UnresolvableBindings {
                id: record.id.to_string(),
            });
        }
        let legacy: Arc<[LegacyConnectionProjection]> = legacy.into();
        let managed_runtime = managed_records
            .into_iter()
            .map(|record| (record.id.clone(), record))
            .collect();
        let runtime = Arc::new(ArcSwap::from_pointee(ConnectionRuntimeSnapshot::new(
            managed_runtime,
            legacy.clone(),
            omitted_legacy_projection_count,
        )));

        Ok(Self {
            managed,
            legacy,
            omitted_legacy_projection_count,
            runtime,
            mutation_lock: Arc::new(Mutex::new(())),
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

    pub fn runtime_snapshot(&self) -> Arc<ConnectionRuntimeSnapshot> {
        self.runtime.load_full()
    }

    pub fn create_managed(
        &self,
        expected_collection_etag: &str,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionMutationError> {
        let _guard = self.mutation_guard();
        let current = self.runtime.load_full();
        if current.collection_etag() != expected_collection_etag {
            return Err(ConnectionMutationError::CollectionConflict {
                current: current.collection_etag().to_owned(),
            });
        }
        self.ensure_activatable(&candidate)?;
        let created = self.managed_store()?.create(candidate)?;
        let mut managed = current.managed().clone();
        managed.insert(created.id.clone(), created.clone());
        self.publish_runtime(managed);
        Ok(created)
    }

    pub fn replace_managed(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionMutationError> {
        let _guard = self.mutation_guard();
        self.ensure_activatable(&candidate)?;
        let replaced = self.managed_store()?.replace(id, expected, candidate)?;
        let current = self.runtime.load_full();
        let mut managed = current.managed().clone();
        managed.insert(id.clone(), replaced.clone());
        self.publish_runtime(managed);
        Ok(replaced)
    }

    pub fn delete_managed(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
    ) -> Result<(), ConnectionMutationError> {
        let _guard = self.mutation_guard();
        self.managed_store()?.delete(id, expected)?;
        let current = self.runtime.load_full();
        let mut managed = current.managed().clone();
        managed.remove(id);
        self.publish_runtime(managed);
        Ok(())
    }

    fn publish_runtime(&self, managed: BTreeMap<ConnectionId, StoredConnection>) {
        self.runtime.store(Arc::new(ConnectionRuntimeSnapshot::new(
            managed,
            self.legacy.clone(),
            self.omitted_legacy_projection_count,
        )));
    }

    fn ensure_activatable(
        &self,
        candidate: &ConnectionWrite,
    ) -> Result<(), ConnectionMutationError> {
        let configured_alias_ids = self
            .secret_resolver
            .aliases()
            .into_iter()
            .filter(|alias| alias.configured)
            .map(|alias| alias.id)
            .collect::<BTreeSet<_>>();
        let fields =
            candidate.unresolved_enabled_binding_fields(|id| configured_alias_ids.contains(id));
        if fields.is_empty() {
            Ok(())
        } else {
            Err(ConnectionMutationError::UnresolvableBindings { fields })
        }
    }

    fn mutation_guard(&self) -> MutexGuard<'_, ()> {
        match self.mutation_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "Connection control-plane mutation lock poisoned; recovering fail-closed state"
                );
                poisoned.into_inner()
            }
        }
    }
}

fn collection_etag(
    managed: &BTreeMap<ConnectionId, StoredConnection>,
    legacy: &[LegacyConnectionProjection],
    omitted_legacy_projection_count: usize,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"greengateway.connections.collection.v1");
    digest.update(
        u64::try_from(omitted_legacy_projection_count)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for projection in legacy {
        digest.update(b"legacy");
        update_digest_field(&mut digest, projection.id().as_str());
    }
    for (id, record) in managed {
        digest.update(b"managed");
        update_digest_field(&mut digest, id.as_str());
        update_digest_field(&mut digest, record.etag().as_str());
    }
    format!("\"connections:sha256:{}\"", hex::encode(digest.finalize()))
}

fn update_digest_field(digest: &mut Sha256, value: &str) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

#[derive(Debug)]
pub enum ConnectionMutationError {
    Unavailable(ManagedConnectionMutationUnavailable),
    CollectionConflict { current: String },
    UnresolvableBindings { fields: Vec<&'static str> },
    Store(ConnectionStoreError),
}

impl fmt::Display for ConnectionMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => error.fmt(formatter),
            Self::CollectionConflict { current } => write!(
                formatter,
                "connection collection changed; current ETag is {current}"
            ),
            Self::UnresolvableBindings { fields } => write!(
                formatter,
                "enabled connection has unresolvable bindings in {} field(s)",
                fields.len()
            ),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl Error for ConnectionMutationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unavailable(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::CollectionConflict { .. } | Self::UnresolvableBindings { .. } => None,
        }
    }
}

impl From<ManagedConnectionMutationUnavailable> for ConnectionMutationError {
    fn from(error: ManagedConnectionMutationUnavailable) -> Self {
        Self::Unavailable(error)
    }
}

impl From<ConnectionStoreError> for ConnectionMutationError {
    fn from(error: ConnectionStoreError) -> Self {
        Self::Store(error)
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
    UnresolvableBindings { id: String },
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
            Self::UnresolvableBindings { id } => write!(
                formatter,
                "enabled managed connection '{id}' references a secret binding that is not configured"
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

    #[test]
    fn enabled_persisted_connection_with_unknown_binding_fails_restart_closed() {
        let temporary = TemporaryLocalControlPlane::new("unknown-persisted-binding");
        let config = temporary.config();
        let store = SqliteConnectionStore::open(
            config
                .connections_sqlite_path
                .as_deref()
                .expect("managed store path should be configured"),
        )
        .expect("store should open");
        let candidate = serde_json::from_value(serde_json::json!({
            "display_name": "Billing API",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "static_bearer",
                "secret_id": "unknown-token"
            }
        }))
        .expect("candidate should deserialize");
        let created = store
            .create(candidate)
            .expect("fixture should persist directly");
        drop(store);

        assert!(matches!(
            ConnectionControlPlane::from_config(&config),
            Err(ConnectionControlPlaneError::UnresolvableBindings { id })
                if id == created.id.as_str()
        ));
    }

    fn managed_candidate() -> ConnectionWrite {
        serde_json::from_value(serde_json::json!({
            "display_name": "Billing API",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "none"
            }
        }))
        .expect("managed candidate should deserialize")
    }

    #[test]
    fn successful_mutations_publish_one_atomic_runtime_snapshot() {
        let temporary = TemporaryLocalControlPlane::new("runtime-mutations");
        let control_plane = ConnectionControlPlane::from_config(&temporary.config())
            .expect("control plane should build");
        let initial = control_plane.runtime_snapshot();
        assert!(initial.managed().is_empty());

        let created = control_plane
            .create_managed(initial.collection_etag(), managed_candidate())
            .expect("create should succeed");
        let after_create = control_plane.runtime_snapshot();
        assert!(
            initial.managed().is_empty(),
            "old snapshot must remain immutable"
        );
        assert_eq!(after_create.managed().get(&created.id), Some(&created));
        assert_ne!(initial.collection_etag(), after_create.collection_etag());

        assert!(matches!(
            control_plane.create_managed(initial.collection_etag(), managed_candidate()),
            Err(ConnectionMutationError::CollectionConflict { .. })
        ));
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            1,
            "stale collection mutation must not reach storage"
        );

        let mut replacement = created.write.clone();
        replacement.display_name = "Billing API v2".to_owned();
        let replaced = control_plane
            .replace_managed(&created.id, &created.etag(), replacement)
            .expect("replace should succeed");
        let after_replace = control_plane.runtime_snapshot();
        assert_eq!(after_create.managed().get(&created.id), Some(&created));
        assert_eq!(after_replace.managed().get(&created.id), Some(&replaced));

        control_plane
            .delete_managed(&created.id, &replaced.etag())
            .expect("delete should succeed");
        let after_delete = control_plane.runtime_snapshot();
        assert!(!after_delete.managed().contains_key(&created.id));
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            0
        );
    }

    #[test]
    fn failed_mutation_preserves_runtime_and_persisted_state() {
        let temporary = TemporaryLocalControlPlane::new("runtime-failure");
        let control_plane = ConnectionControlPlane::from_config(&temporary.config())
            .expect("control plane should build");
        let before = control_plane.runtime_snapshot();
        let mut invalid = managed_candidate();
        invalid.endpoint.base_url = "https://billing.example.test?secret=forbidden".to_owned();

        assert!(matches!(
            control_plane.create_managed(before.collection_etag(), invalid),
            Err(ConnectionMutationError::Store(
                ConnectionStoreError::Validation { .. }
            ))
        ));
        let after = control_plane.runtime_snapshot();
        assert!(after.managed().is_empty());
        assert_eq!(before.collection_etag(), after.collection_etag());
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            0
        );
    }

    #[test]
    fn concurrent_creates_with_one_collection_etag_have_exactly_one_winner() {
        let temporary = TemporaryLocalControlPlane::new("runtime-one-winner");
        let control_plane = Arc::new(
            ConnectionControlPlane::from_config(&temporary.config())
                .expect("control plane should build"),
        );
        let expected = control_plane
            .runtime_snapshot()
            .collection_etag()
            .to_owned();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for index in 0..2 {
            let control_plane = Arc::clone(&control_plane);
            let barrier = Arc::clone(&barrier);
            let expected = expected.clone();
            workers.push(std::thread::spawn(move || {
                let mut candidate = managed_candidate();
                candidate.display_name = format!("Concurrent API {index}");
                barrier.wait();
                control_plane.create_managed(&expected, candidate)
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should join"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(ConnectionMutationError::CollectionConflict { .. })
                    )
                })
                .count(),
            1
        );
        assert_eq!(control_plane.runtime_snapshot().managed().len(), 1);
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            1
        );
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
