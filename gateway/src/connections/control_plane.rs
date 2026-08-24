use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError},
    time::Instant,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::Config;

use super::{
    aws_secret::{
        AwsProviderConfig, AwsProviderConfigError, AwsSecretsManagerProvider, AwsTransport,
        EgressAwsTransport,
    },
    azure_secret::{
        AzureKeyVaultSecretProvider, AzureProviderConfig, AzureProviderConfigError, AzureTransport,
        EgressAzureTransport,
    },
    gcp_secret::{
        EgressGcpTransport, GcpProviderConfig, GcpProviderConfigError, GcpSecretManagerProvider,
        GcpTransport,
    },
    local_secret::{
        LocalSecretError, LocalSecretKeyring, LocalSecretKeyringConfigError, LocalSecretManager,
        LocalSecretProvider, MasterKeyRotationProgress,
    },
    model::{
        ConnectionAuthentication, ConnectionId, ConnectionWrite, MAX_CONCURRENT_REFRESHES,
        MAX_CONNECTIONS,
    },
    projection::{project_legacy_connections, LegacyConnectionProjection, LegacyProjectionError},
    secret::{
        OperatorAliasResolver, ResolvedSecret, SecretAliasMetadata, SecretProviderConfigError,
        SecretProviderKind, SecretPurpose, SecretResolveError, SecretResolveErrorKind,
        SecretResolver,
    },
    status::SafeConnectionStatus,
    store::{
        ConnectionDependencyKind, ConnectionEtag, ConnectionStatusUpdate, ConnectionStore,
        ConnectionStoreError, SqliteConnectionStore, StoredConnection,
    },
    vault_secret::{
        EgressVaultTransport, VaultKvV2SecretProvider, VaultProviderConfig,
        VaultProviderConfigError, VaultTransport,
    },
};

#[derive(Clone)]
pub struct ConnectionControlPlane {
    managed: Option<SqliteConnectionStore>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    runtime: Arc<ArcSwap<ConnectionRuntimeSnapshot>>,
    mutation_lock: Arc<Mutex<()>>,
    catalog_lifecycle: Arc<CatalogLifecycleCoordinator>,
    secret_resolver: Arc<ConnectionSecretResolver>,
    local_secret_versions: Arc<ArcSwap<BTreeMap<String, u64>>>,
    local_secret_manager: Option<Arc<CoordinatedLocalSecretManager>>,
    vault_config: VaultProviderConfig,
    gcp_config: GcpProviderConfig,
    azure_config: AzureProviderConfig,
    aws_config: AwsProviderConfig,
}

#[derive(Clone)]
pub struct ConnectionRuntimeSnapshot {
    managed: Arc<BTreeMap<ConnectionId, StoredConnection>>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    collection_etag: Arc<str>,
}

struct CatalogLifecycleCoordinator {
    active_connections: Mutex<BTreeSet<ConnectionId>>,
    refresh_permits: Arc<Semaphore>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogLifecycleError {
    Busy,
}

impl CatalogLifecycleError {
    pub(crate) const fn safe_reason(self) -> &'static str {
        match self {
            Self::Busy => "catalog_operation_in_progress",
        }
    }
}

impl fmt::Display for CatalogLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Connection catalog operation failed: {}",
            self.safe_reason()
        )
    }
}

impl Error for CatalogLifecycleError {}

pub(crate) struct CatalogMutationGuard {
    lifecycle: Arc<CatalogLifecycleCoordinator>,
    connection_id: ConnectionId,
}

impl Drop for CatalogMutationGuard {
    fn drop(&mut self) {
        catalog_active_guard(&self.lifecycle.active_connections).remove(&self.connection_id);
    }
}

pub(crate) struct CatalogRefreshGuard {
    _mutation: CatalogMutationGuard,
    _permit: OwnedSemaphorePermit,
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
        // Aliases owned by network secret providers, which are activated after
        // the egress client exists and are validated on first use. Additional
        // network providers extend both collections here; an id claimed by two
        // network providers is rejected so one provider cannot silently shadow
        // another during resolution.
        let mut network_alias_ids: BTreeSet<String> = BTreeSet::new();
        for alias in &config.connection_vault_provider.aliases {
            if !network_alias_ids.insert(alias.id.clone()) {
                return Err(ConnectionControlPlaneError::NetworkAliasIdCollision {
                    id: alias.id.clone(),
                });
            }
        }
        for alias in &config.connection_gcp_provider.aliases {
            if !network_alias_ids.insert(alias.id.clone()) {
                return Err(ConnectionControlPlaneError::NetworkAliasIdCollision {
                    id: alias.id.clone(),
                });
            }
        }
        for alias in &config.connection_azure_provider.aliases {
            if !network_alias_ids.insert(alias.id.clone()) {
                return Err(ConnectionControlPlaneError::NetworkAliasIdCollision {
                    id: alias.id.clone(),
                });
            }
        }
        for alias in &config.connection_aws_provider.aliases {
            if !network_alias_ids.insert(alias.id.clone()) {
                return Err(ConnectionControlPlaneError::NetworkAliasIdCollision {
                    id: alias.id.clone(),
                });
            }
        }
        let mut network_alias_metadata: Vec<SecretAliasMetadata> = config
            .connection_vault_provider
            .aliases
            .iter()
            .map(|alias| SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::VaultKvV2,
                configured: true,
                purpose: None,
                version: alias.version,
                rotated_at: None,
            })
            .collect();
        network_alias_metadata.extend(config.connection_gcp_provider.aliases.iter().map(|alias| {
            SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::GcpSecretManager,
                configured: true,
                purpose: None,
                version: alias.version,
                rotated_at: None,
            }
        }));
        network_alias_metadata.extend(config.connection_azure_provider.aliases.iter().map(
            |alias| SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::AzureKeyVault,
                configured: true,
                purpose: None,
                // Key Vault versions are opaque locator-like identifiers;
                // they are never surfaced through metadata.
                version: None,
                rotated_at: None,
            },
        ));
        network_alias_metadata.extend(config.connection_aws_provider.aliases.iter().map(|alias| {
            SecretAliasMetadata {
                id: alias.id.clone(),
                label: alias.label.clone(),
                provider: SecretProviderKind::AwsSecretsManager,
                configured: true,
                purpose: None,
                version: None,
                rotated_at: None,
            }
        }));
        let local_secret_provider = if let Some(keyring) = local_secret_keyring {
            let store = managed
                .as_ref()
                .ok_or(LocalSecretKeyringConfigError::ManagedStoreRequired)?;
            let reserved_ids = config
                .connection_secret_aliases
                .iter()
                .map(|alias| alias.id.clone())
                .chain(network_alias_ids.iter().cloned())
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
            network: OnceLock::new(),
            network_alias_ids,
            network_alias_metadata,
        });
        for record in &managed_records {
            if secret_resolver
                .validate_enabled_candidate(&record.write)
                .is_err()
            {
                return Err(ConnectionControlPlaneError::UnresolvableBindings {
                    id: record.id.to_string(),
                });
            }
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
        let mutation_lock = Arc::new(Mutex::new(()));
        let catalog_lifecycle = Arc::new(CatalogLifecycleCoordinator {
            active_connections: Mutex::new(BTreeSet::new()),
            refresh_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REFRESHES)),
        });
        let local_secret_versions = Arc::new(ArcSwap::from_pointee(
            local_secret_provider
                .as_ref()
                .map(|provider| {
                    provider
                        .metadata()
                        .into_iter()
                        .filter_map(|metadata| {
                            metadata.version.map(|version| (metadata.id, version))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        ));
        let local_secret_manager = local_secret_provider.map(|provider| {
            Arc::new(CoordinatedLocalSecretManager {
                provider,
                mutation_lock: Arc::clone(&mutation_lock),
                runtime: Arc::clone(&runtime),
                secret_resolver: Arc::clone(&secret_resolver),
                local_secret_versions: Arc::clone(&local_secret_versions),
            })
        });

        Ok(Self {
            managed,
            legacy,
            omitted_legacy_projection_count,
            runtime,
            mutation_lock,
            catalog_lifecycle,
            secret_resolver,
            local_secret_versions,
            local_secret_manager,
            vault_config: config.connection_vault_provider.clone(),
            gcp_config: config.connection_gcp_provider.clone(),
            azure_config: config.connection_azure_provider.clone(),
            aws_config: config.connection_aws_provider.clone(),
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

    pub(crate) fn local_secret_version(&self, id: &str) -> Option<u64> {
        self.local_secret_versions.load().get(id).copied()
    }

    pub fn local_secret_manager(
        &self,
    ) -> Result<&(dyn LocalSecretManager + Send + Sync), LocalSecretMutationUnavailable> {
        self.local_secret_manager
            .as_deref()
            .map(|manager| manager as &(dyn LocalSecretManager + Send + Sync))
            .ok_or(LocalSecretMutationUnavailable)
    }

    pub fn secret_alias_metadata(&self) -> Vec<SecretAliasMetadata> {
        self.secret_resolver.aliases()
    }

    /// Build and install every configured network secret provider. Called once
    /// after the egress client exists; later calls are no-ops. Additional
    /// network providers add their construction block here and must extend
    /// `reserved_ids` with their own alias ids afterwards, so each successive
    /// provider rejects ids already claimed by an earlier one.
    pub fn activate_network_secret_providers(
        &self,
        egress: &Arc<crate::egress::EgressClient>,
    ) -> Result<(), ConnectionControlPlaneError> {
        if self.secret_resolver.network.get().is_some() {
            return Ok(());
        }
        let mut reserved_ids: BTreeSet<String> = self
            .secret_resolver
            .operator
            .aliases()
            .into_iter()
            .map(|a| a.id)
            .collect();
        let bootstrap: Option<Arc<dyn SecretResolver>> =
            Some(Arc::clone(&self.secret_resolver.operator) as Arc<dyn SecretResolver>);
        let mut providers: Vec<Arc<dyn SecretResolver>> = Vec::new();
        if !self.vault_config.is_empty() {
            let transport: Arc<dyn VaultTransport> =
                Arc::new(EgressVaultTransport::new(Arc::clone(egress)));
            let provider = VaultKvV2SecretProvider::from_config(
                &self.vault_config,
                &reserved_ids,
                transport,
                bootstrap.clone(),
            )?;
            providers.push(Arc::new(provider));
            reserved_ids.extend(
                self.vault_config
                    .aliases
                    .iter()
                    .map(|alias| alias.id.clone()),
            );
        }
        if !self.gcp_config.is_empty() {
            let transport: Arc<dyn GcpTransport> =
                Arc::new(EgressGcpTransport::new(Arc::clone(egress)));
            let provider =
                GcpSecretManagerProvider::from_config(&self.gcp_config, &reserved_ids, transport)?;
            providers.push(Arc::new(provider));
            reserved_ids.extend(self.gcp_config.aliases.iter().map(|alias| alias.id.clone()));
        }
        if !self.azure_config.is_empty() {
            let transport: Arc<dyn AzureTransport> =
                Arc::new(EgressAzureTransport::new(Arc::clone(egress)));
            let provider = AzureKeyVaultSecretProvider::from_config(
                &self.azure_config,
                &reserved_ids,
                transport,
                bootstrap.clone(),
            )?;
            providers.push(Arc::new(provider));
            reserved_ids.extend(
                self.azure_config
                    .aliases
                    .iter()
                    .map(|alias| alias.id.clone()),
            );
        }
        if !self.aws_config.is_empty() {
            let transport: Arc<dyn AwsTransport> =
                Arc::new(EgressAwsTransport::new(Arc::clone(egress)));
            let provider = AwsSecretsManagerProvider::from_config(
                &self.aws_config,
                &reserved_ids,
                transport,
                bootstrap.clone(),
            )?;
            providers.push(Arc::new(provider));
            reserved_ids.extend(self.aws_config.aliases.iter().map(|alias| alias.id.clone()));
        }
        self.install_network_secret_providers(providers);
        Ok(())
    }

    /// Install pre-built network providers directly. Production activation goes
    /// through [`Self::activate_network_secret_providers`]; this seam lets
    /// integration tests substitute fake providers without real transports.
    pub(crate) fn install_network_secret_providers(&self, providers: Vec<Arc<dyn SecretResolver>>) {
        let _ = self.secret_resolver.network.set(providers);
    }

    pub fn is_local_secret_manager_configured(&self) -> bool {
        self.local_secret_manager.is_some()
    }

    pub fn runtime_snapshot(&self) -> Arc<ConnectionRuntimeSnapshot> {
        self.runtime.load_full()
    }

    pub(crate) fn begin_catalog_mutation(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<CatalogMutationGuard, CatalogLifecycleError> {
        let inserted = catalog_active_guard(&self.catalog_lifecycle.active_connections)
            .insert(connection_id.clone());
        if !inserted {
            return Err(CatalogLifecycleError::Busy);
        }
        Ok(CatalogMutationGuard {
            lifecycle: Arc::clone(&self.catalog_lifecycle),
            connection_id: connection_id.clone(),
        })
    }

    pub(crate) fn begin_catalog_refresh(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<CatalogRefreshGuard, CatalogLifecycleError> {
        let mutation = self.begin_catalog_mutation(connection_id)?;
        let permit = Arc::clone(&self.catalog_lifecycle.refresh_permits)
            .try_acquire_owned()
            .map_err(|_| CatalogLifecycleError::Busy)?;
        Ok(CatalogRefreshGuard {
            _mutation: mutation,
            _permit: permit,
        })
    }

    pub fn replace_runtime_dependencies(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(ConnectionId, String)],
    ) -> Result<(), ConnectionMutationError> {
        let _guard = self.mutation_guard();
        if desired.is_empty() && self.managed.is_none() {
            return Ok(());
        }
        self.managed_store()?
            .replace_dependencies_for_kind(kind, desired)?;
        Ok(())
    }

    pub fn append_status(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionMutationError> {
        let _guard = self.mutation_guard();
        let store = self.managed_store()?;
        let status = store.append_status(id, expected, update)?;
        let updated = store
            .get(id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
        let current = self.runtime.load_full();
        let mut managed = current.managed().clone();
        managed.insert(id.clone(), updated);
        self.publish_runtime(managed);
        Ok(status)
    }

    pub fn append_status_before(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
        deadline: Instant,
    ) -> Result<SafeConnectionStatus, ConnectionMutationError> {
        let _guard = self.try_mutation_guard_before(deadline)?;
        let store = self.managed_store()?;
        let (status, updated) = store.append_status_before(id, expected, update, deadline)?;
        let current = self.runtime.load_full();
        let mut managed = current.managed().clone();
        managed.insert(id.clone(), updated);
        self.publish_runtime(managed);
        Ok(status)
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
        match self.secret_resolver.validate_enabled_candidate(candidate) {
            Ok(()) => Ok(()),
            Err(BindingActivationError::Invalid { fields }) => {
                Err(ConnectionMutationError::UnresolvableBindings { fields })
            }
            Err(BindingActivationError::Unavailable) => {
                Err(ConnectionMutationError::BindingUnavailable)
            }
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

    fn try_mutation_guard_before(
        &self,
        deadline: Instant,
    ) -> Result<MutexGuard<'_, ()>, ConnectionMutationError> {
        if Instant::now() >= deadline {
            return Err(ConnectionMutationError::DeadlineExceeded);
        }
        match self.mutation_lock.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(ConnectionMutationError::Busy),
            Err(TryLockError::Poisoned(poisoned)) => {
                tracing::error!(
                    "Connection control-plane mutation lock poisoned; recovering bounded fail-closed state"
                );
                Ok(poisoned.into_inner())
            }
        }
    }
}

fn catalog_active_guard(
    active_connections: &Mutex<BTreeSet<ConnectionId>>,
) -> MutexGuard<'_, BTreeSet<ConnectionId>> {
    match active_connections.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(
                "Connection catalog lifecycle lock poisoned; recovering bounded fail-closed state"
            );
            poisoned.into_inner()
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
    BindingUnavailable,
    Busy,
    DeadlineExceeded,
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
            Self::BindingUnavailable => {
                formatter.write_str("enabled connection binding validation is unavailable")
            }
            Self::Busy => formatter.write_str("connection control-plane mutation is busy"),
            Self::DeadlineExceeded => {
                formatter.write_str("connection control-plane mutation deadline exceeded")
            }
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl Error for ConnectionMutationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unavailable(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::CollectionConflict { .. }
            | Self::UnresolvableBindings { .. }
            | Self::BindingUnavailable
            | Self::Busy
            | Self::DeadlineExceeded => None,
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

struct ConnectionSecretResolver {
    operator: Arc<OperatorAliasResolver>,
    local: Option<Arc<LocalSecretProvider>>,
    /// Network-backed providers activated once the egress client
    /// exists. Their aliases are deferred: known from configuration at startup
    /// but resolvable only after activation, and validated on first use.
    network: OnceLock<Vec<Arc<dyn SecretResolver>>>,
    network_alias_ids: BTreeSet<String>,
    network_alias_metadata: Vec<SecretAliasMetadata>,
}

#[derive(Debug)]
enum BindingActivationError {
    Invalid { fields: Vec<&'static str> },
    Unavailable,
}

impl fmt::Debug for ConnectionSecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionSecretResolver")
            .field("operator_alias_count", &self.operator.aliases().len())
            .field("local_provider_enabled", &self.local.is_some())
            .field("network_alias_count", &self.network_alias_ids.len())
            .field("network_providers_activated", &self.network.get().is_some())
            .finish()
    }
}

impl ConnectionSecretResolver {
    fn is_deferred_alias(&self, alias_id: &str) -> bool {
        self.network_alias_ids.contains(alias_id)
    }

    fn resolve_blocking(
        &self,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, SecretResolveError> {
        if self.operator.contains_alias(alias_id) {
            return self.operator.resolve_blocking(alias_id, purpose);
        }
        if self.is_deferred_alias(alias_id) {
            return Err(SecretResolveError::new(
                alias_id,
                SecretResolveErrorKind::SourceUnavailable,
            ));
        }
        if let Some(local) = self.local.as_ref() {
            return local.resolve_blocking(alias_id, purpose);
        }
        self.operator.resolve_blocking(alias_id, purpose)
    }

    fn validate_enabled_candidate(
        &self,
        candidate: &ConnectionWrite,
    ) -> Result<(), BindingActivationError> {
        if !candidate.enabled {
            return Ok(());
        }
        let configured_alias_ids = self
            .aliases()
            .into_iter()
            .filter(|alias| alias.configured)
            .map(|alias| alias.id)
            .collect::<BTreeSet<_>>();
        let unresolved =
            candidate.unresolved_enabled_binding_fields(|id| configured_alias_ids.contains(id));
        if !unresolved.is_empty() {
            return Err(BindingActivationError::Invalid { fields: unresolved });
        }

        match &candidate.authentication {
            ConnectionAuthentication::None => {}
            ConnectionAuthentication::HeaderApiKey {
                secret_id: Some(secret_id),
                ..
            } if !self.is_deferred_alias(secret_id) => {
                self.resolve_required(
                    "authentication.secret_id",
                    secret_id,
                    SecretPurpose::HeaderApiKey,
                )?;
            }
            ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret_id),
            } if !self.is_deferred_alias(secret_id) => {
                self.resolve_required(
                    "authentication.secret_id",
                    secret_id,
                    SecretPurpose::StaticBearer,
                )?;
            }
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: Some(secret_id),
                ..
            } if !self.is_deferred_alias(secret_id) => {
                self.resolve_required(
                    "authentication.client_secret_id",
                    secret_id,
                    SecretPurpose::OAuthClientSecret,
                )?;
            }
            ConnectionAuthentication::HeaderApiKey { .. }
            | ConnectionAuthentication::StaticBearer { .. }
            | ConnectionAuthentication::OAuth2ClientCredentials { .. } => {}
        }

        let ca_bundle = candidate
            .tls
            .ca_bundle_alias
            .as_deref()
            .filter(|id| !self.is_deferred_alias(id))
            .map(|id| self.resolve_required("tls.ca_bundle_alias", id, SecretPurpose::TlsCaBundle))
            .transpose()?;
        if ca_bundle
            .as_ref()
            .is_some_and(|material| !crate::egress::tls_ca_bundle_pem_is_valid(material.expose()))
        {
            return Err(BindingActivationError::Invalid {
                fields: vec!["tls.ca_bundle_alias"],
            });
        }

        let client_certificate = candidate
            .tls
            .client_certificate_id
            .as_deref()
            .filter(|id| !self.is_deferred_alias(id))
            .map(|id| {
                self.resolve_required(
                    "tls.client_certificate_id",
                    id,
                    SecretPurpose::TlsCertificate,
                )
            })
            .transpose()?;
        let client_private_key = candidate
            .tls
            .client_private_key_id
            .as_deref()
            .filter(|id| !self.is_deferred_alias(id))
            .map(|id| {
                self.resolve_required(
                    "tls.client_private_key_id",
                    id,
                    SecretPurpose::TlsPrivateKey,
                )
            })
            .transpose()?;
        if let (Some(certificate), Some(private_key)) =
            (client_certificate.as_ref(), client_private_key.as_ref())
        {
            validate_client_identity_material(certificate.expose(), private_key.expose())?;
        }

        Ok(())
    }

    fn validate_enabled_candidate_with_rotated_secret(
        &self,
        candidate: &ConnectionWrite,
        rotated_id: &str,
        replacement: &ResolvedSecret,
    ) -> Result<(), BindingActivationError> {
        if !candidate.enabled {
            return Ok(());
        }

        let authentication_purpose = match &candidate.authentication {
            ConnectionAuthentication::HeaderApiKey {
                secret_id: Some(secret_id),
                ..
            } if secret_id == rotated_id => Some(SecretPurpose::HeaderApiKey),
            ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret_id),
            } if secret_id == rotated_id => Some(SecretPurpose::StaticBearer),
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: Some(secret_id),
                ..
            } if secret_id == rotated_id => Some(SecretPurpose::OAuthClientSecret),
            _ => None,
        };
        if authentication_purpose.is_some_and(|purpose| replacement.purpose() != purpose) {
            return Err(BindingActivationError::Invalid {
                fields: vec!["authentication"],
            });
        }

        if candidate.tls.ca_bundle_alias.as_deref() == Some(rotated_id)
            && (replacement.purpose() != SecretPurpose::TlsCaBundle
                || !crate::egress::tls_ca_bundle_pem_is_valid(replacement.expose()))
        {
            return Err(BindingActivationError::Invalid {
                fields: vec!["tls.ca_bundle_alias"],
            });
        }

        if candidate.tls.client_certificate_id.as_deref() == Some(rotated_id) {
            if replacement.purpose() != SecretPurpose::TlsCertificate {
                return Err(BindingActivationError::Invalid {
                    fields: vec!["tls.client_certificate_id"],
                });
            }
            let private_key_id =
                candidate
                    .tls
                    .client_private_key_id
                    .as_deref()
                    .ok_or_else(|| BindingActivationError::Invalid {
                        fields: vec!["tls.client_certificate_id", "tls.client_private_key_id"],
                    })?;
            if !self.is_deferred_alias(private_key_id) {
                let private_key = self.resolve_required(
                    "tls.client_private_key_id",
                    private_key_id,
                    SecretPurpose::TlsPrivateKey,
                )?;
                validate_client_identity_material(replacement.expose(), private_key.expose())?;
            }
        }

        if candidate.tls.client_private_key_id.as_deref() == Some(rotated_id) {
            if replacement.purpose() != SecretPurpose::TlsPrivateKey {
                return Err(BindingActivationError::Invalid {
                    fields: vec!["tls.client_private_key_id"],
                });
            }
            let certificate_id =
                candidate
                    .tls
                    .client_certificate_id
                    .as_deref()
                    .ok_or_else(|| BindingActivationError::Invalid {
                        fields: vec!["tls.client_certificate_id", "tls.client_private_key_id"],
                    })?;
            if !self.is_deferred_alias(certificate_id) {
                let certificate = self.resolve_required(
                    "tls.client_certificate_id",
                    certificate_id,
                    SecretPurpose::TlsCertificate,
                )?;
                validate_client_identity_material(certificate.expose(), replacement.expose())?;
            }
        }

        Ok(())
    }

    fn resolve_required(
        &self,
        field: &'static str,
        alias_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, BindingActivationError> {
        self.resolve_blocking(alias_id, purpose)
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::UnknownAlias
                | SecretResolveErrorKind::SourceDenied
                | SecretResolveErrorKind::InvalidMaterial => BindingActivationError::Invalid {
                    fields: vec![field],
                },
                SecretResolveErrorKind::ProviderBusy
                | SecretResolveErrorKind::SourceUnavailable
                | SecretResolveErrorKind::UnsafeSource
                | SecretResolveErrorKind::ProviderFailure => BindingActivationError::Unavailable,
            })
    }
}

fn validate_client_identity_material(
    certificate: &[u8],
    private_key: &[u8],
) -> Result<(), BindingActivationError> {
    let mut identity = Zeroizing::new(Vec::with_capacity(certificate.len() + private_key.len()));
    identity.extend_from_slice(certificate);
    identity.extend_from_slice(private_key);
    if crate::egress::tls_client_identity_pem_is_valid(identity.as_slice()) {
        Ok(())
    } else {
        Err(BindingActivationError::Invalid {
            fields: vec!["tls.client_certificate_id", "tls.client_private_key_id"],
        })
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
        if let Some(providers) = self.network.get() {
            for provider in providers {
                if provider.contains_alias(alias_id) {
                    return provider.resolve(alias_id, purpose).await;
                }
            }
        }
        if let Some(local) = self.local.as_ref() {
            return local.resolve(alias_id, purpose).await;
        }
        self.operator.resolve(alias_id, purpose).await
    }

    fn aliases(&self) -> Vec<SecretAliasMetadata> {
        let mut aliases = self.operator.aliases();
        if let Some(providers) = self.network.get() {
            for provider in providers {
                aliases.extend(provider.aliases());
            }
        } else {
            aliases.extend(self.network_alias_metadata.iter().cloned());
        }
        if let Some(local) = self.local.as_ref() {
            aliases.extend(local.aliases());
        }
        aliases.sort_by(|left, right| left.id.cmp(&right.id));
        aliases
    }
}

#[derive(Clone)]
struct CoordinatedLocalSecretManager {
    provider: Arc<LocalSecretProvider>,
    mutation_lock: Arc<Mutex<()>>,
    runtime: Arc<ArcSwap<ConnectionRuntimeSnapshot>>,
    secret_resolver: Arc<ConnectionSecretResolver>,
    local_secret_versions: Arc<ArcSwap<BTreeMap<String, u64>>>,
}

impl CoordinatedLocalSecretManager {
    fn mutation_guard(&self) -> MutexGuard<'_, ()> {
        match self.mutation_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "Connection/local-secret mutation lock poisoned; recovering fail-closed state"
                );
                poisoned.into_inner()
            }
        }
    }

    fn publish_version(&self, metadata: &SecretAliasMetadata) {
        let Some(version) = metadata.version else {
            return;
        };
        let mut versions = self.local_secret_versions.load_full().as_ref().clone();
        versions.insert(metadata.id.clone(), version);
        self.local_secret_versions.store(Arc::new(versions));
    }

    fn remove_version(&self, id: &str) {
        let mut versions = self.local_secret_versions.load_full().as_ref().clone();
        versions.remove(id);
        self.local_secret_versions.store(Arc::new(versions));
    }
}

impl LocalSecretManager for CoordinatedLocalSecretManager {
    fn create(
        &self,
        label: &str,
        secret: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        let _guard = self.mutation_guard();
        let metadata = self.provider.create(label, secret)?;
        self.publish_version(&metadata);
        Ok(metadata)
    }

    fn rotate(
        &self,
        id: &str,
        replacement: ResolvedSecret,
    ) -> Result<SecretAliasMetadata, LocalSecretError> {
        let _guard = self.mutation_guard();
        let snapshot = self.runtime.load_full();
        for record in snapshot.managed().values() {
            self.secret_resolver
                .validate_enabled_candidate_with_rotated_secret(&record.write, id, &replacement)
                .map_err(|error| match error {
                    BindingActivationError::Invalid { .. } => LocalSecretError::InvalidSecret,
                    BindingActivationError::Unavailable => LocalSecretError::StorageFailure,
                })?;
        }
        let metadata = self.provider.rotate(id, replacement)?;
        self.publish_version(&metadata);
        Ok(metadata)
    }

    fn delete(&self, id: &str) -> Result<(), LocalSecretError> {
        let _guard = self.mutation_guard();
        self.provider.delete(id)?;
        self.remove_version(id);
        Ok(())
    }

    fn metadata(&self) -> Vec<SecretAliasMetadata> {
        self.provider.metadata()
    }

    fn reencrypt_master_key_batch(
        &self,
        maximum_records: usize,
    ) -> Result<MasterKeyRotationProgress, LocalSecretError> {
        let _guard = self.mutation_guard();
        self.provider.reencrypt_master_key_batch(maximum_records)
    }

    fn ensure_key_unused(&self, key_id: &str) -> Result<(), LocalSecretError> {
        let _guard = self.mutation_guard();
        self.provider.ensure_key_unused(key_id)
    }
}

#[derive(Debug)]
pub enum ConnectionControlPlaneError {
    Store(ConnectionStoreError),
    Projection(LegacyProjectionError),
    SecretProvider(SecretProviderConfigError),
    VaultProvider(VaultProviderConfigError),
    GcpProvider(GcpProviderConfigError),
    AzureProvider(AzureProviderConfigError),
    AwsProvider(AwsProviderConfigError),
    LocalSecretKeyring(LocalSecretKeyringConfigError),
    LocalSecret(LocalSecretError),
    LocalSecretKeyringRequired,
    LimitExceeded { count: usize, maximum: usize },
    IdCollision { id: String },
    NetworkAliasIdCollision { id: String },
    UnresolvableBindings { id: String },
}

impl fmt::Display for ConnectionControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
            Self::SecretProvider(error) => error.fmt(formatter),
            Self::VaultProvider(error) => error.fmt(formatter),
            Self::GcpProvider(error) => error.fmt(formatter),
            Self::AzureProvider(error) => error.fmt(formatter),
            Self::AwsProvider(error) => error.fmt(formatter),
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
            Self::NetworkAliasIdCollision { id } => write!(
                formatter,
                "secret alias '{id}' is claimed by more than one network secret provider"
            ),
            Self::UnresolvableBindings { id } => write!(
                formatter,
                "enabled managed connection '{id}' references a secret or TLS binding that is not usable"
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
            Self::VaultProvider(error) => Some(error),
            Self::GcpProvider(error) => Some(error),
            Self::AzureProvider(error) => Some(error),
            Self::AwsProvider(error) => Some(error),
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

impl From<VaultProviderConfigError> for ConnectionControlPlaneError {
    fn from(error: VaultProviderConfigError) -> Self {
        Self::VaultProvider(error)
    }
}

impl From<GcpProviderConfigError> for ConnectionControlPlaneError {
    fn from(error: GcpProviderConfigError) -> Self {
        Self::GcpProvider(error)
    }
}

impl From<AzureProviderConfigError> for ConnectionControlPlaneError {
    fn from(error: AzureProviderConfigError) -> Self {
        Self::AzureProvider(error)
    }
}

impl From<AwsProviderConfigError> for ConnectionControlPlaneError {
    fn from(error: AwsProviderConfigError) -> Self {
        Self::AwsProvider(error)
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
    use std::{fs, path::PathBuf, sync::Barrier};

    use crate::{
        config::McpUpstreamServerConfig,
        connections::local_secret::{LocalSecretKeyConfig, LocalSecretKeyRole},
    };

    use super::*;

    fn config() -> Config {
        Config::test_defaults()
    }

    struct StaticNetworkProvider {
        alias_id: &'static str,
        value: &'static [u8],
    }

    #[async_trait]
    impl SecretResolver for StaticNetworkProvider {
        async fn resolve(
            &self,
            alias_id: &str,
            purpose: SecretPurpose,
        ) -> Result<ResolvedSecret, SecretResolveError> {
            if alias_id != self.alias_id {
                return Err(SecretResolveError::new(
                    alias_id,
                    SecretResolveErrorKind::UnknownAlias,
                ));
            }
            ResolvedSecret::new(purpose, self.value.to_vec()).map_err(|_| {
                SecretResolveError::new(alias_id, SecretResolveErrorKind::InvalidMaterial)
            })
        }

        fn contains_alias(&self, alias_id: &str) -> bool {
            alias_id == self.alias_id
        }

        fn aliases(&self) -> Vec<SecretAliasMetadata> {
            vec![SecretAliasMetadata {
                id: self.alias_id.to_owned(),
                label: format!("{} live", self.alias_id),
                provider: SecretProviderKind::VaultKvV2,
                configured: true,
                purpose: None,
                version: None,
                rotated_at: None,
            }]
        }
    }

    fn network_alias_metadata(alias_id: &str) -> SecretAliasMetadata {
        SecretAliasMetadata {
            id: alias_id.to_owned(),
            label: format!("{alias_id} configured"),
            provider: SecretProviderKind::VaultKvV2,
            configured: true,
            purpose: None,
            version: None,
            rotated_at: None,
        }
    }

    #[tokio::test]
    async fn network_alias_defers_before_activation_and_routes_to_owning_provider_after() {
        let operator = Arc::new(
            OperatorAliasResolver::from_config(&[], None)
                .expect("empty operator resolver should build"),
        );
        let resolver = ConnectionSecretResolver {
            operator,
            local: None,
            network: OnceLock::new(),
            network_alias_ids: ["alpha", "beta"]
                .iter()
                .map(|id| (*id).to_owned())
                .collect(),
            network_alias_metadata: vec![
                network_alias_metadata("alpha"),
                network_alias_metadata("beta"),
            ],
        };

        let blocked = resolver
            .resolve_blocking("alpha", SecretPurpose::HeaderApiKey)
            .expect_err("deferred alias must not resolve before activation");
        assert_eq!(blocked.kind(), SecretResolveErrorKind::SourceUnavailable);
        let configured = resolver.aliases();
        assert_eq!(configured.len(), 2);
        assert!(configured
            .iter()
            .all(|alias| alias.label.ends_with("configured")));

        let providers: Vec<Arc<dyn SecretResolver>> = vec![
            Arc::new(StaticNetworkProvider {
                alias_id: "alpha",
                value: b"alpha-value",
            }),
            Arc::new(StaticNetworkProvider {
                alias_id: "beta",
                value: b"beta-value",
            }),
        ];
        resolver
            .network
            .set(providers)
            .ok()
            .expect("network providers should activate once");

        let beta = resolver
            .resolve("beta", SecretPurpose::HeaderApiKey)
            .await
            .expect("activated alias should route to its owning provider");
        assert_eq!(beta.expose(), b"beta-value");
        let live = resolver.aliases();
        assert_eq!(live.len(), 2);
        assert!(live.iter().all(|alias| alias.label.ends_with("live")));

        // The synchronous validation path must keep deferring network aliases
        // even after activation: deferral keys off the configured alias set,
        // never the activated providers, so startup binding validation can
        // never fetch network secret material.
        let still_blocked = resolver
            .resolve_blocking("alpha", SecretPurpose::HeaderApiKey)
            .expect_err("network alias must stay deferred on the blocking path after activation");
        assert_eq!(
            still_blocked.kind(),
            SecretResolveErrorKind::SourceUnavailable
        );

        let unknown = resolver
            .resolve("gamma", SecretPurpose::HeaderApiKey)
            .await
            .expect_err("alias owned by no provider must fail");
        assert_eq!(unknown.kind(), SecretResolveErrorKind::UnknownAlias);
    }

    #[test]
    fn an_alias_id_claimed_by_two_network_providers_fails_closed_at_startup() {
        use crate::connections::{
            azure_secret::{AzureAuthConfig, AzureProfileConfig, AzureSecretAliasConfig},
            vault_secret::{VaultAuthConfig, VaultProfileConfig, VaultSecretAliasConfig},
        };

        let mut config = config();
        config.connection_vault_provider = VaultProviderConfig {
            profiles: vec![VaultProfileConfig {
                id: "vault-primary".to_owned(),
                address: "https://vault.internal.example".to_owned(),
                namespace: None,
                auth: VaultAuthConfig::Token {
                    secret_alias: "bootstrap-token".to_owned(),
                },
            }],
            aliases: vec![VaultSecretAliasConfig {
                id: "shared-alias".to_owned(),
                label: "Vault shared alias".to_owned(),
                profile: "vault-primary".to_owned(),
                mount: "secret".to_owned(),
                path: "billing".to_owned(),
                key: "api-key".to_owned(),
                version: None,
            }],
        };
        config.connection_azure_provider = AzureProviderConfig {
            profiles: vec![AzureProfileConfig {
                id: "azure-primary".to_owned(),
                authority_host: None,
                tenant_id: "11111111-2222-3333-4444-555566667777".to_owned(),
                client_id: "88888888-9999-aaaa-bbbb-ccccddddeeee".to_owned(),
                scope: None,
                auth: AzureAuthConfig::ClientSecret {
                    secret_alias: "bootstrap-client-secret".to_owned(),
                },
            }],
            aliases: vec![AzureSecretAliasConfig {
                id: "shared-alias".to_owned(),
                label: "Azure shared alias".to_owned(),
                profile: "azure-primary".to_owned(),
                vault: "https://myvault.vault.azure.net".to_owned(),
                name: "billing-api-key".to_owned(),
                version: None,
            }],
        };

        let error = match ConnectionControlPlane::from_config(&config) {
            Ok(_) => panic!("an alias id claimed by two network providers must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConnectionControlPlaneError::NetworkAliasIdCollision { ref id } if id == "shared-alias"
        ));
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

    fn catalog_connection_id(suffix: usize) -> ConnectionId {
        ConnectionId::parse(format!("{suffix:08}-1111-4111-8111-111111111111"))
            .expect("test catalog Connection ID should validate")
    }

    #[test]
    fn catalog_lifecycle_is_shared_by_control_plane_clones_and_recovers_after_panic() {
        let control_plane =
            ConnectionControlPlane::from_config(&config()).expect("control plane should build");
        let clone = control_plane.clone();
        let connection_id = catalog_connection_id(1);
        let mutation = control_plane
            .begin_catalog_mutation(&connection_id)
            .expect("first catalog mutation should acquire");
        assert_eq!(
            clone.begin_catalog_mutation(&connection_id).err(),
            Some(CatalogLifecycleError::Busy),
            "a clone must observe the same active Connection set"
        );
        drop(mutation);

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let clone = clone.clone();
            let connection_id = connection_id.clone();
            move || {
                let _guard = clone
                    .begin_catalog_mutation(&connection_id)
                    .expect("catalog mutation should acquire before panic");
                panic!("exercise catalog lifecycle RAII");
            }
        }));
        assert!(panic_result.is_err());
        let recovered = control_plane
            .begin_catalog_mutation(&connection_id)
            .expect("panic unwinding must release the active Connection ID");
        drop(recovered);
    }

    #[test]
    fn catalog_lifecycle_rejects_same_connection_refresh_and_mutation() {
        let control_plane =
            ConnectionControlPlane::from_config(&config()).expect("control plane should build");
        let connection_id = catalog_connection_id(1);
        let refresh = control_plane
            .begin_catalog_refresh(&connection_id)
            .expect("first catalog refresh should acquire");
        assert_eq!(
            control_plane.begin_catalog_refresh(&connection_id).err(),
            Some(CatalogLifecycleError::Busy)
        );
        assert_eq!(
            control_plane.begin_catalog_mutation(&connection_id).err(),
            Some(CatalogLifecycleError::Busy)
        );
        drop(refresh);

        let mutation = control_plane
            .begin_catalog_mutation(&connection_id)
            .expect("catalog mutation should acquire after refresh completion");
        assert_eq!(
            control_plane.begin_catalog_refresh(&connection_id).err(),
            Some(CatalogLifecycleError::Busy)
        );
        drop(mutation);
    }

    #[test]
    fn catalog_refreshes_share_four_permit_bound_and_release_permits() {
        let control_plane =
            ConnectionControlPlane::from_config(&config()).expect("control plane should build");
        let mut refreshes = (1..=MAX_CONCURRENT_REFRESHES)
            .map(|suffix| {
                control_plane
                    .begin_catalog_refresh(&catalog_connection_id(suffix))
                    .expect("each of the four distinct refreshes should acquire")
            })
            .collect::<Vec<_>>();
        let overflow_id = catalog_connection_id(MAX_CONCURRENT_REFRESHES + 1);
        assert_eq!(
            control_plane.begin_catalog_refresh(&overflow_id).err(),
            Some(CatalogLifecycleError::Busy),
            "the fifth global catalog refresh must fail safely"
        );

        refreshes.pop();
        let replacement = control_plane
            .begin_catalog_refresh(&overflow_id)
            .expect("dropping a refresh guard must release its global permit");
        drop(replacement);
        drop(refreshes);
    }

    #[test]
    fn catalog_mutations_for_different_connections_can_proceed() {
        let control_plane =
            ConnectionControlPlane::from_config(&config()).expect("control plane should build");
        let first = control_plane
            .begin_catalog_mutation(&catalog_connection_id(1))
            .expect("first Connection mutation should acquire");
        let second = control_plane
            .begin_catalog_mutation(&catalog_connection_id(2))
            .expect("different Connection mutation should proceed independently");
        drop((first, second));
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
    fn local_secret_version_snapshot_tracks_restart_rotation_and_deletion() {
        let temporary = TemporaryLocalControlPlane::new("version-snapshot");
        let config = temporary.config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let created = control_plane
            .local_secret_manager()
            .expect("local secret manager should be enabled")
            .create(
                "OAuth client secret",
                ResolvedSecret::new(
                    SecretPurpose::OAuthClientSecret,
                    b"oauth-client-secret-v1".to_vec(),
                )
                .expect("test secret should validate"),
            )
            .expect("local secret should create");
        assert_eq!(
            control_plane.local_secret_version(&created.id),
            created.version
        );

        drop(control_plane);
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should restart");
        assert_eq!(
            control_plane.local_secret_version(&created.id),
            created.version,
            "the lock-free snapshot must initialize from persisted local metadata"
        );

        let rotated = control_plane
            .local_secret_manager()
            .expect("local secret manager should be enabled")
            .rotate(
                &created.id,
                ResolvedSecret::new(
                    SecretPurpose::OAuthClientSecret,
                    b"oauth-client-secret-v2".to_vec(),
                )
                .expect("replacement secret should validate"),
            )
            .expect("local secret should rotate");
        assert_eq!(
            control_plane.local_secret_version(&created.id),
            rotated.version
        );

        control_plane
            .local_secret_manager()
            .expect("local secret manager should be enabled")
            .delete(&created.id)
            .expect("unused local secret should delete");
        assert_eq!(control_plane.local_secret_version(&created.id), None);
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

    #[test]
    fn enabled_mutation_resolves_material_and_rejects_wrong_local_purpose() {
        let temporary = TemporaryLocalControlPlane::new("binding-purpose");
        let control_plane = ConnectionControlPlane::from_config(&temporary.config())
            .expect("control plane should build");
        let secret = control_plane
            .local_secret_manager()
            .expect("local manager should exist")
            .create(
                "Header-only secret",
                ResolvedSecret::new(SecretPurpose::HeaderApiKey, b"header-canary".to_vec())
                    .expect("fixture secret should validate"),
            )
            .expect("fixture secret should create");
        let before = control_plane.runtime_snapshot();
        let mut candidate = managed_candidate();
        candidate.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some(secret.id),
        };

        assert!(matches!(
            control_plane.create_managed(before.collection_etag(), candidate),
            Err(ConnectionMutationError::UnresolvableBindings { fields })
                if fields == vec!["authentication.secret_id"]
        ));
        assert!(control_plane.runtime_snapshot().managed().is_empty());
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
    fn unavailable_operator_material_preserves_previous_persisted_and_runtime_state() {
        let temporary = TemporaryLocalControlPlane::new("binding-unavailable");
        let mut config = temporary.config();
        let alias_id = format!("missing-alias-{}", uuid::Uuid::new_v4());
        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: alias_id.clone(),
                label: "Unavailable token".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::Environment {
                    key: format!("GGW_MISSING_{}", uuid::Uuid::new_v4().simple()),
                },
            }];
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let initial = control_plane.runtime_snapshot();
        let mut unavailable_create = managed_candidate();
        unavailable_create.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some(alias_id.clone()),
        };
        assert!(matches!(
            control_plane.create_managed(initial.collection_etag(), unavailable_create),
            Err(ConnectionMutationError::BindingUnavailable)
        ));
        assert!(control_plane.runtime_snapshot().managed().is_empty());
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            0
        );
        let created = control_plane
            .create_managed(initial.collection_etag(), managed_candidate())
            .expect("plain connection should create");
        let before = control_plane.runtime_snapshot();
        let mut replacement = created.write.clone();
        replacement.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some(alias_id),
        };

        assert!(matches!(
            control_plane.replace_managed(&created.id, &created.etag(), replacement),
            Err(ConnectionMutationError::BindingUnavailable)
        ));
        let after = control_plane.runtime_snapshot();
        assert_eq!(before.collection_etag(), after.collection_etag());
        assert_eq!(after.managed().get(&created.id), Some(&created));
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .get(&created.id)
                .expect("stored connection should load")
                .expect("stored connection should remain"),
            created
        );
    }

    #[test]
    fn invalid_der_ca_is_rejected_before_persistence_and_publication() {
        let temporary = TemporaryLocalControlPlane::new("invalid-der-ca");
        let control_plane = ConnectionControlPlane::from_config(&temporary.config())
            .expect("control plane should build");
        let secret = control_plane
            .local_secret_manager()
            .expect("local manager should exist")
            .create(
                "Invalid DER CA",
                ResolvedSecret::new(
                    SecretPurpose::TlsCaBundle,
                    b"-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n".to_vec(),
                )
                .expect("bounded invalid-DER PEM fixture should validate"),
            )
            .expect("fixture secret should create");
        let before = control_plane.runtime_snapshot();
        let mut candidate = managed_candidate();
        candidate.tls.ca_bundle_alias = Some(secret.id);

        let result = control_plane.create_managed(before.collection_etag(), candidate);
        match result {
            Err(ConnectionMutationError::UnresolvableBindings { fields }) => {
                assert_eq!(fields, vec!["tls.ca_bundle_alias"]);
            }
            result => panic!("unexpected malformed TLS activation result: {result:?}"),
        }
        assert!(control_plane.runtime_snapshot().managed().is_empty());
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should load"),
            0
        );
    }

    #[tokio::test]
    async fn mixed_valid_and_invalid_ca_rotation_preserves_previous_material() {
        let temporary = TemporaryLocalControlPlane::new("mixed-ca-rotation");
        let config = temporary.config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let key = rcgen::KeyPair::generate().expect("test CA key should generate");
        let certificate = rcgen::CertificateParams::new(vec!["ca.example.test".to_owned()])
            .expect("test CA parameters should build")
            .self_signed(&key)
            .expect("test CA certificate should build");
        let valid_ca_pem = certificate.pem().into_bytes();
        let manager = control_plane
            .local_secret_manager()
            .expect("local manager should exist");
        let ca_secret = manager
            .create(
                "CA bundle",
                ResolvedSecret::new(SecretPurpose::TlsCaBundle, valid_ca_pem.clone())
                    .expect("valid CA secret should construct"),
            )
            .expect("valid CA secret should create");
        let before = control_plane.runtime_snapshot();
        let mut candidate = managed_candidate();
        candidate.tls.ca_bundle_alias = Some(ca_secret.id.clone());
        let created = control_plane
            .create_managed(before.collection_etag(), candidate)
            .expect("valid CA connection should activate");

        let mut mixed_bundle = valid_ca_pem.clone();
        mixed_bundle.extend_from_slice(
            b"\n-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n",
        );
        assert_eq!(
            manager.rotate(
                &ca_secret.id,
                ResolvedSecret::new(SecretPurpose::TlsCaBundle, mixed_bundle)
                    .expect("bounded mixed CA fixture should construct"),
            ),
            Err(LocalSecretError::InvalidSecret)
        );
        assert_eq!(
            control_plane
                .secret_resolver()
                .resolve(&ca_secret.id, SecretPurpose::TlsCaBundle)
                .await
                .expect("previous CA bundle should remain resolvable")
                .expose(),
            valid_ca_pem
        );
        assert_eq!(
            control_plane.runtime_snapshot().managed().get(&created.id),
            Some(&created)
        );
        drop(control_plane);
        ConnectionControlPlane::from_config(&config)
            .expect("rejected CA rotation must leave restartable state");
    }

    #[tokio::test]
    async fn in_use_local_tls_rotation_is_preflighted_and_preserves_previous_material() {
        let temporary = TemporaryLocalControlPlane::new("tls-rotation-preflight");
        let config = temporary.config();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let key = rcgen::KeyPair::generate().expect("test identity key should generate");
        let certificate = rcgen::CertificateParams::new(vec!["client.example.test".to_owned()])
            .expect("test identity parameters should build")
            .self_signed(&key)
            .expect("test identity certificate should build");
        let certificate_pem = certificate.pem().into_bytes();
        let private_key_pem = key.serialize_pem().into_bytes();
        let manager = control_plane
            .local_secret_manager()
            .expect("local manager should exist");
        let certificate_secret = manager
            .create(
                "Client certificate",
                ResolvedSecret::new(SecretPurpose::TlsCertificate, certificate_pem.clone())
                    .expect("certificate secret should validate"),
            )
            .expect("certificate secret should create");
        let private_key_secret = manager
            .create(
                "Client private key",
                ResolvedSecret::new(SecretPurpose::TlsPrivateKey, private_key_pem.clone())
                    .expect("private-key secret should validate"),
            )
            .expect("private-key secret should create");
        let before = control_plane.runtime_snapshot();
        let mut candidate = managed_candidate();
        candidate.tls.client_certificate_id = Some(certificate_secret.id.clone());
        candidate.tls.client_private_key_id = Some(private_key_secret.id.clone());
        let created = control_plane
            .create_managed(before.collection_etag(), candidate)
            .expect("valid mTLS connection should activate");

        assert_eq!(
            manager.rotate(
                &certificate_secret.id,
                ResolvedSecret::new(
                    SecretPurpose::TlsCertificate,
                    b"malformed-certificate-canary".to_vec(),
                )
                .expect("bounded malformed fixture should construct"),
            ),
            Err(LocalSecretError::InvalidSecret)
        );
        let mismatched_key =
            rcgen::KeyPair::generate().expect("mismatched identity key should generate");
        assert_eq!(
            manager.rotate(
                &private_key_secret.id,
                ResolvedSecret::new(
                    SecretPurpose::TlsPrivateKey,
                    mismatched_key.serialize_pem().into_bytes(),
                )
                .expect("mismatched key fixture should construct"),
            ),
            Err(LocalSecretError::InvalidSecret)
        );

        assert_eq!(
            control_plane
                .secret_resolver()
                .resolve(&certificate_secret.id, SecretPurpose::TlsCertificate,)
                .await
                .expect("previous certificate should remain resolvable")
                .expose(),
            certificate_pem
        );
        assert_eq!(
            control_plane
                .secret_resolver()
                .resolve(&private_key_secret.id, SecretPurpose::TlsPrivateKey,)
                .await
                .expect("previous private key should remain resolvable")
                .expose(),
            private_key_pem
        );
        assert_eq!(
            control_plane.runtime_snapshot().managed().get(&created.id),
            Some(&created)
        );
        drop(control_plane);
        ConnectionControlPlane::from_config(&config)
            .expect("rejected rotations must leave restartable state");
    }

    #[test]
    fn configured_but_unavailable_persisted_binding_fails_restart_closed() {
        let temporary = TemporaryLocalControlPlane::new("unavailable-persisted-binding");
        let mut config = temporary.config();
        let alias_id = format!("missing-alias-{}", uuid::Uuid::new_v4());
        config.connection_secret_aliases =
            vec![crate::connections::secret::OperatorSecretAliasConfig {
                id: alias_id.clone(),
                label: "Unavailable token".to_owned(),
                source: crate::connections::secret::OperatorSecretAliasSource::Environment {
                    key: format!("GGW_MISSING_{}", uuid::Uuid::new_v4().simple()),
                },
            }];
        let store = SqliteConnectionStore::open(
            config
                .connections_sqlite_path
                .as_deref()
                .expect("managed store path should be configured"),
        )
        .expect("store should open");
        let mut candidate = managed_candidate();
        candidate.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some(alias_id),
        };
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

    #[test]
    fn local_secret_delete_and_connection_activation_are_serialized() {
        let temporary = TemporaryLocalControlPlane::new("delete-activation-race");
        let control_plane = ConnectionControlPlane::from_config(&temporary.config())
            .expect("control plane should build");

        for iteration in 0..16 {
            let secret = control_plane
                .local_secret_manager()
                .expect("local manager should exist")
                .create(
                    &format!("Race token {iteration}"),
                    ResolvedSecret::new(
                        SecretPurpose::StaticBearer,
                        format!("race-token-{iteration}").into_bytes(),
                    )
                    .expect("fixture secret should validate"),
                )
                .expect("fixture secret should create");
            let mut candidate = managed_candidate();
            candidate.display_name = format!("Race connection {iteration}");
            candidate.authentication = ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret.id.clone()),
            };
            let expected_collection_etag = control_plane
                .runtime_snapshot()
                .collection_etag()
                .to_owned();
            let barrier = Arc::new(Barrier::new(2));
            let create_control_plane = control_plane.clone();
            let delete_control_plane = control_plane.clone();
            let create_barrier = Arc::clone(&barrier);
            let delete_barrier = Arc::clone(&barrier);
            let secret_id = secret.id.clone();

            let (create_result, delete_result) = std::thread::scope(|scope| {
                let create = scope.spawn(|| {
                    create_barrier.wait();
                    create_control_plane.create_managed(&expected_collection_etag, candidate)
                });
                let delete = scope.spawn(|| {
                    delete_barrier.wait();
                    delete_control_plane
                        .local_secret_manager()
                        .expect("local manager should exist")
                        .delete(&secret_id)
                });
                (
                    create.join().expect("create thread should not panic"),
                    delete.join().expect("delete thread should not panic"),
                )
            });

            match (create_result, delete_result) {
                (Ok(created), Err(LocalSecretError::DependencyConflict { connection_ids, .. })) => {
                    assert_eq!(connection_ids, vec![created.id.to_string()]);
                    control_plane
                        .delete_managed(&created.id, &created.etag())
                        .expect("fixture connection should delete");
                    control_plane
                        .local_secret_manager()
                        .expect("local manager should exist")
                        .delete(&secret.id)
                        .expect("fixture secret should delete after dependency removal");
                }
                (Err(ConnectionMutationError::UnresolvableBindings { .. }), Ok(())) => {
                    assert!(control_plane
                        .runtime_snapshot()
                        .managed()
                        .values()
                        .all(|record| {
                            record.write.authentication
                                != (ConnectionAuthentication::StaticBearer {
                                    secret_id: Some(secret.id.clone()),
                                })
                        }));
                }
                (create, delete) => {
                    panic!(
                        "unexpected serialized race outcome: create={create:?}, delete={delete:?}"
                    )
                }
            }
        }
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
