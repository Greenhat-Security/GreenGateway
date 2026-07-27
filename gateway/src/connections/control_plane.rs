use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use crate::config::Config;

use super::{
    model::MAX_CONNECTIONS,
    projection::{project_legacy_connections, LegacyConnectionProjection, LegacyProjectionError},
    secret::{OperatorAliasResolver, SecretProviderConfigError, SecretResolver},
    store::{ConnectionStore, ConnectionStoreError, SqliteConnectionStore},
};

#[derive(Clone)]
pub struct ConnectionControlPlane {
    managed: Option<SqliteConnectionStore>,
    legacy: Arc<[LegacyConnectionProjection]>,
    omitted_legacy_projection_count: usize,
    secret_resolver: Arc<OperatorAliasResolver>,
}

impl ConnectionControlPlane {
    pub fn from_config(config: &Config) -> Result<Self, ConnectionControlPlaneError> {
        let secret_resolver = Arc::new(OperatorAliasResolver::from_config(
            &config.connection_secret_aliases,
            config.connection_secrets_root.as_ref(),
        )?);
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

        Ok(Self {
            managed,
            legacy: legacy.into(),
            omitted_legacy_projection_count,
            secret_resolver,
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
}

#[derive(Debug)]
pub enum ConnectionControlPlaneError {
    Store(ConnectionStoreError),
    Projection(LegacyProjectionError),
    SecretProvider(SecretProviderConfigError),
    LimitExceeded { count: usize, maximum: usize },
    IdCollision { id: String },
}

impl fmt::Display for ConnectionControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
            Self::SecretProvider(error) => error.fmt(formatter),
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

#[cfg(test)]
mod tests {
    use crate::config::McpUpstreamServerConfig;

    use super::*;

    fn config() -> Config {
        Config::test_defaults()
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
}
