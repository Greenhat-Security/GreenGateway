use std::{error::Error, ffi::OsString, fmt};

use crate::{
    config::Config,
    connections::{
        control_plane::ConnectionControlPlane,
        local_secret::{LocalSecretError, MAX_MASTER_KEY_ROTATION_BATCH},
        model::MAX_SECRET_ID_BYTES,
        secret::is_valid_opaque_id,
    },
};

const INVALID_ARGUMENTS: &str = "invalid arguments; expected either no arguments, \
    `connection-secrets reencrypt --batch-size N`, or \
    `connection-secrets ensure-key-unused --key-id ID`";

pub(crate) enum MaintenanceCommand {
    Reencrypt { batch_size: usize },
    EnsureKeyUnused { key_id: String },
}

impl fmt::Debug for MaintenanceCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reencrypt { batch_size } => formatter
                .debug_struct("Reencrypt")
                .field("batch_size", batch_size)
                .finish(),
            Self::EnsureKeyUnused { .. } => formatter
                .debug_struct("EnsureKeyUnused")
                .field("key_id", &"<redacted-key-id>")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceOutput {
    Reencrypted {
        reencrypted: usize,
        remaining: usize,
    },
    KeyUnused {
        unused: bool,
    },
}

impl fmt::Display for MaintenanceOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reencrypted {
                reencrypted,
                remaining,
            } => write!(formatter, "reencrypted={reencrypted} remaining={remaining}"),
            Self::KeyUnused { unused } => write!(formatter, "unused={unused}"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaintenanceError {
    InvalidArguments,
    ConfigurationInvalid,
    ProviderUnavailable,
    InitializationFailed,
    KeyStillInUse { count: usize },
    OperationFailed,
}

impl fmt::Display for MaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str(INVALID_ARGUMENTS),
            Self::ConfigurationInvalid => {
                formatter.write_str("connection-secret maintenance configuration is invalid")
            }
            Self::ProviderUnavailable => formatter.write_str(
                "connection-secret maintenance requires configured SQLite storage and a local keyring",
            ),
            Self::InitializationFailed => {
                formatter.write_str("connection-secret maintenance initialization failed")
            }
            Self::KeyStillInUse { count } => write!(
                formatter,
                "connection-secret maintenance check failed: key_in_use_records={count}"
            ),
            Self::OperationFailed => {
                formatter.write_str("connection-secret maintenance operation failed")
            }
        }
    }
}

impl fmt::Debug for MaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for MaintenanceError {}

pub(crate) fn run_if_requested<I, F, E>(
    arguments: I,
    load_config: F,
) -> Result<Option<MaintenanceOutput>, MaintenanceError>
where
    I: IntoIterator<Item = OsString>,
    F: FnOnce() -> Result<Config, E>,
{
    let Some(command) = parse_arguments(arguments)? else {
        return Ok(None);
    };
    let config = load_config().map_err(|_| MaintenanceError::ConfigurationInvalid)?;
    execute(&config, command).map(Some)
}

fn parse_arguments<I>(arguments: I) -> Result<Option<MaintenanceCommand>, MaintenanceError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.is_empty() {
        return Ok(None);
    }
    let arguments = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| MaintenanceError::InvalidArguments)
        })
        .collect::<Result<Vec<_>, _>>()?;

    match arguments.as_slice() {
        [group, operation, option, raw_batch_size]
            if group == "connection-secrets"
                && operation == "reencrypt"
                && option == "--batch-size" =>
        {
            let batch_size = raw_batch_size
                .parse::<usize>()
                .map_err(|_| MaintenanceError::InvalidArguments)?;
            if !(1..=MAX_MASTER_KEY_ROTATION_BATCH).contains(&batch_size) {
                return Err(MaintenanceError::InvalidArguments);
            }
            Ok(Some(MaintenanceCommand::Reencrypt { batch_size }))
        }
        [group, operation, option, key_id]
            if group == "connection-secrets"
                && operation == "ensure-key-unused"
                && option == "--key-id" =>
        {
            if !is_valid_opaque_id(key_id, MAX_SECRET_ID_BYTES) {
                return Err(MaintenanceError::InvalidArguments);
            }
            Ok(Some(MaintenanceCommand::EnsureKeyUnused {
                key_id: key_id.clone(),
            }))
        }
        _ => Err(MaintenanceError::InvalidArguments),
    }
}

fn execute(
    config: &Config,
    command: MaintenanceCommand,
) -> Result<MaintenanceOutput, MaintenanceError> {
    if config.connections_sqlite_path.is_none()
        || config.connection_secrets_root.is_none()
        || config.connection_local_secret_keyring.is_empty()
    {
        return Err(MaintenanceError::ProviderUnavailable);
    }
    let control_plane = ConnectionControlPlane::from_config(config)
        .map_err(|_| MaintenanceError::InitializationFailed)?;
    let manager = control_plane
        .local_secret_manager()
        .map_err(|_| MaintenanceError::ProviderUnavailable)?;

    match command {
        MaintenanceCommand::Reencrypt { batch_size } => {
            let progress = manager
                .reencrypt_master_key_batch(batch_size)
                .map_err(map_operation_error)?;
            Ok(MaintenanceOutput::Reencrypted {
                reencrypted: progress.reencrypted,
                remaining: progress.remaining,
            })
        }
        MaintenanceCommand::EnsureKeyUnused { key_id } => {
            manager
                .ensure_key_unused(&key_id)
                .map_err(map_operation_error)?;
            Ok(MaintenanceOutput::KeyUnused { unused: true })
        }
    }
}

fn map_operation_error(error: LocalSecretError) -> MaintenanceError {
    match error {
        LocalSecretError::KeyStillInUse { count } => MaintenanceError::KeyStillInUse { count },
        _ => MaintenanceError::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
    };

    use crate::connections::{
        control_plane::ConnectionControlPlane,
        local_secret::{LocalSecretKeyConfig, LocalSecretKeyRole},
        secret::{ResolvedSecret, SecretPurpose, SecretRootConfig},
    };

    use super::*;

    const OLD_KEY_ID: &str = "historical-master";
    const NEW_KEY_ID: &str = "current-master";
    const OLD_KEY_FILE: &str = "historical.key";
    const NEW_KEY_FILE: &str = "current.key";
    const SECRET_VALUE: &[u8] = b"test-only-secret-material";

    struct TemporaryMaintenanceStore {
        root: PathBuf,
        database: PathBuf,
    }

    impl TemporaryMaintenanceStore {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-connection-secret-maintenance-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary maintenance root should create");
            set_directory_permissions(&root, 0o700);
            write_key(&root.join(OLD_KEY_FILE), 41);
            write_key(&root.join(NEW_KEY_FILE), 73);
            let database = root.join("connections.sqlite");
            Self { root, database }
        }

        fn config(&self, rotating: bool) -> Config {
            let mut config = Config::test_defaults();
            config.connections_sqlite_path = Some(self.database.display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(self.root.clone()));
            config.connection_local_secret_keyring = if rotating {
                vec![
                    LocalSecretKeyConfig {
                        id: NEW_KEY_ID.to_owned(),
                        file: NEW_KEY_FILE.to_owned(),
                        role: LocalSecretKeyRole::Primary,
                    },
                    LocalSecretKeyConfig {
                        id: OLD_KEY_ID.to_owned(),
                        file: OLD_KEY_FILE.to_owned(),
                        role: LocalSecretKeyRole::DecryptOnly,
                    },
                ]
            } else {
                vec![LocalSecretKeyConfig {
                    id: OLD_KEY_ID.to_owned(),
                    file: OLD_KEY_FILE.to_owned(),
                    role: LocalSecretKeyRole::Primary,
                }]
            };
            config
        }

        fn seed_historical_secrets(&self, count: usize) {
            let control_plane = ConnectionControlPlane::from_config(&self.config(false))
                .expect("historical control plane should initialize");
            let manager = control_plane
                .local_secret_manager()
                .expect("historical local-secret manager should exist");
            for index in 0..count {
                manager
                    .create(
                        &format!("historical secret {index}"),
                        ResolvedSecret::new(SecretPurpose::StaticBearer, SECRET_VALUE.to_vec())
                            .expect("test secret should validate"),
                    )
                    .expect("historical test secret should create");
            }
        }
    }

    impl Drop for TemporaryMaintenanceStore {
        fn drop(&mut self) {
            if self.root.starts_with(std::env::temp_dir())
                && self
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("greengateway-connection-secret-maintenance-")
                    })
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn run_command(
        config: &Config,
        values: &[&str],
    ) -> Result<MaintenanceOutput, MaintenanceError> {
        run_if_requested(arguments(values), || Ok::<_, ()>(config.clone()))?
            .ok_or(MaintenanceError::InvalidArguments)
    }

    #[test]
    fn parser_accepts_only_exact_bounded_commands() {
        assert!(parse_arguments(Vec::<OsString>::new())
            .expect("no arguments should select server startup")
            .is_none());
        assert!(matches!(
            parse_arguments(arguments(&[
                "connection-secrets",
                "reencrypt",
                "--batch-size",
                "1"
            ])),
            Ok(Some(MaintenanceCommand::Reencrypt { batch_size: 1 }))
        ));
        assert!(matches!(
            parse_arguments(arguments(&[
                "connection-secrets",
                "reencrypt",
                "--batch-size",
                "64"
            ])),
            Ok(Some(MaintenanceCommand::Reencrypt { batch_size: 64 }))
        ));
        assert!(matches!(
            parse_arguments(arguments(&[
                "connection-secrets",
                "ensure-key-unused",
                "--key-id",
                "opaque-key_1"
            ])),
            Ok(Some(MaintenanceCommand::EnsureKeyUnused { .. }))
        ));

        for invalid in [
            arguments(&["connection-secrets"]),
            arguments(&["connection-secrets", "reencrypt", "--batch-size", "0"]),
            arguments(&["connection-secrets", "reencrypt", "--batch-size", "65"]),
            arguments(&["connection-secrets", "reencrypt", "--batch-size", "-1"]),
            arguments(&[
                "connection-secrets",
                "ensure-key-unused",
                "--key-id",
                "../secret.key",
            ]),
            arguments(&[
                "connection-secrets",
                "ensure-key-unused",
                "--key-id",
                "env:MASTER_KEY",
            ]),
            arguments(&["serve"]),
        ] {
            assert_eq!(
                parse_arguments(invalid).expect_err("command must fail closed"),
                MaintenanceError::InvalidArguments
            );
        }
    }

    #[test]
    fn one_batch_per_command_is_bounded_resumable_and_reports_progress() {
        let store = TemporaryMaintenanceStore::new();
        store.seed_historical_secrets(3);
        let config = store.config(true);

        assert_eq!(
            run_command(
                &config,
                &["connection-secrets", "reencrypt", "--batch-size", "2"],
            )
            .expect("first bounded batch should succeed"),
            MaintenanceOutput::Reencrypted {
                reencrypted: 2,
                remaining: 1,
            }
        );
        assert_eq!(
            run_command(
                &config,
                &["connection-secrets", "reencrypt", "--batch-size", "2"],
            )
            .expect("second bounded batch should resume"),
            MaintenanceOutput::Reencrypted {
                reencrypted: 1,
                remaining: 0,
            }
        );
        assert_eq!(
            run_command(
                &config,
                &["connection-secrets", "reencrypt", "--batch-size", "2"],
            )
            .expect("completed rotation should be idempotent"),
            MaintenanceOutput::Reencrypted {
                reencrypted: 0,
                remaining: 0,
            }
        );
    }

    #[test]
    fn key_unused_check_fails_closed_then_succeeds_after_rotation() {
        let store = TemporaryMaintenanceStore::new();
        store.seed_historical_secrets(2);
        let config = store.config(true);

        assert_eq!(
            run_command(
                &config,
                &[
                    "connection-secrets",
                    "ensure-key-unused",
                    "--key-id",
                    OLD_KEY_ID,
                ],
            )
            .expect_err("historical key must remain blocked while rows use it"),
            MaintenanceError::KeyStillInUse { count: 2 }
        );
        run_command(
            &config,
            &["connection-secrets", "reencrypt", "--batch-size", "2"],
        )
        .expect("rotation should complete");
        assert_eq!(
            run_command(
                &config,
                &[
                    "connection-secrets",
                    "ensure-key-unused",
                    "--key-id",
                    OLD_KEY_ID,
                ],
            )
            .expect("unused historical key should pass"),
            MaintenanceOutput::KeyUnused { unused: true }
        );
    }

    #[test]
    fn output_and_errors_never_echo_sensitive_inputs_or_locators() {
        let store = TemporaryMaintenanceStore::new();
        store.seed_historical_secrets(1);
        let config = store.config(true);
        let error = execute(
            &config,
            MaintenanceCommand::EnsureKeyUnused {
                key_id: OLD_KEY_ID.to_owned(),
            },
        )
        .expect_err("in-use key should fail");
        let safe_error = format!("{error:?} {error}");
        let safe_output = execute(&config, MaintenanceCommand::Reencrypt { batch_size: 1 })
            .expect("rotation should succeed")
            .to_string();
        for forbidden in [
            OLD_KEY_ID,
            NEW_KEY_ID,
            OLD_KEY_FILE,
            NEW_KEY_FILE,
            SECRET_VALUE
                .iter()
                .copied()
                .map(char::from)
                .collect::<String>()
                .as_str(),
            store.root.to_string_lossy().as_ref(),
            store.database.to_string_lossy().as_ref(),
        ] {
            assert!(!safe_error.contains(forbidden));
            assert!(!safe_output.contains(forbidden));
        }

        let invalid = parse_arguments(arguments(&[
            "connection-secrets",
            "ensure-key-unused",
            "--key-id",
            "../do-not-echo.key",
        ]))
        .expect_err("invalid locator-like key ID should fail");
        assert!(!invalid.to_string().contains("do-not-echo"));
    }

    #[test]
    fn maintenance_selection_returns_before_listener_start_path() {
        let store = TemporaryMaintenanceStore::new();
        let config = store.config(true);
        let listener_starts = Cell::new(0usize);

        let output = run_if_requested(
            arguments(&["connection-secrets", "reencrypt", "--batch-size", "1"]),
            || Ok::<_, ()>(config),
        )
        .expect("maintenance command should run");
        if output.is_none() {
            listener_starts.set(listener_starts.get() + 1);
        }

        assert_eq!(
            output,
            Some(MaintenanceOutput::Reencrypted {
                reencrypted: 0,
                remaining: 0,
            })
        );
        assert_eq!(listener_starts.get(), 0);
    }

    #[test]
    fn provider_and_initialization_failures_are_safe_and_closed() {
        let unavailable = execute(
            &Config::test_defaults(),
            MaintenanceCommand::Reencrypt { batch_size: 1 },
        )
        .expect_err("unset provider must fail");
        assert_eq!(unavailable, MaintenanceError::ProviderUnavailable);

        let store = TemporaryMaintenanceStore::new();
        let mut invalid = store.config(true);
        invalid.connection_local_secret_keyring[0].file = "missing-sensitive-name.key".to_owned();
        let error = execute(&invalid, MaintenanceCommand::Reencrypt { batch_size: 1 })
            .expect_err("missing key file must fail initialization");
        assert_eq!(error, MaintenanceError::InitializationFailed);
        assert!(!error.to_string().contains("missing-sensitive-name"));
        assert!(!format!("{error:?}").contains(store.root.to_string_lossy().as_ref()));
    }

    fn write_key(path: &Path, byte: u8) {
        fs::write(path, [byte; 32]).expect("temporary master key should write");
        set_file_permissions(path, 0o600);
    }

    #[cfg(unix)]
    fn set_directory_permissions(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("temporary directory permissions should set");
    }

    #[cfg(not(unix))]
    fn set_directory_permissions(_: &Path, _: u32) {}

    #[cfg(unix)]
    fn set_file_permissions(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("temporary key permissions should set");
    }

    #[cfg(not(unix))]
    fn set_file_permissions(_: &Path, _: u32) {}
}
