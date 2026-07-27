use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use crate::config::Config;

use super::{
    model::MAX_CONNECTIONS,
    projection::{project_legacy_connections, LegacyConnectionProjection, LegacyProjectionError},
    store::{ConnectionStore, ConnectionStoreError, SqliteConnectionStore},
};

#[derive(Clone)]
pub struct ConnectionControlPlane {
    managed: Option<SqliteConnectionStore>,
    legacy: Arc<[LegacyConnectionProjection]>,
}

impl ConnectionControlPlane {
    pub fn from_config(config: &Config) -> Result<Self, ConnectionControlPlaneError> {
        let legacy = project_legacy_connections(config)?;
        let managed = config
            .connections_sqlite_path
            .as_deref()
            .map(SqliteConnectionStore::open)
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

    pub fn is_managed_store_configured(&self) -> bool {
        self.managed.is_some()
    }
}

#[derive(Debug)]
pub enum ConnectionControlPlaneError {
    Store(ConnectionStoreError),
    Projection(LegacyProjectionError),
    LimitExceeded { count: usize, maximum: usize },
    IdCollision { id: String },
}

impl fmt::Display for ConnectionControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
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
    fn configured_store_is_migrated_during_control_plane_construction() {
        let path = std::env::temp_dir().join(format!(
            "greengateway-control-plane-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let mut config = config();
        config.connections_sqlite_path = Some(path.display().to_string());

        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        assert!(control_plane.is_managed_store_configured());
        assert!(path.is_file());
        assert_eq!(
            control_plane
                .managed_store()
                .expect("store should exist")
                .count()
                .expect("count should work"),
            0
        );
        drop(control_plane);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
