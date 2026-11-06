//! The gateway's side of a standalone restore (issue #242; ADR-0008,
//! "Export, backup, and restore" and "Audit, status, and metrics").
//!
//! `ggctl backup restore` puts a restore marker beside the stores it puts in
//! place (`gateway_config::backup::read_restore_marker`). The first start
//! from that state directory records the restore as `config.restore_detected`
//! and removes the marker, so each restore is recorded once:
//!
//! - [`record_restore`] runs under the held state directory once the audit
//!   log is open and before anything is served. It reads the marker, records
//!   the event, waits for the audit store of record to commit it where
//!   `AUDIT_DURABILITY=required` asks for that, and only then removes the
//!   marker.
//! - The event is value-free: the restore's opaque ID, its times, the
//!   programs and document versions involved, the restored stores' fixed
//!   names and the ledger's opaque revision IDs. Never a path, an archive
//!   name or a store's content.
//! - A marker that is unsafe or invalid, an event that cannot be made
//!   durable, or a marker that cannot be removed fails the start, and the
//!   marker stays for the next one: a restore is never left unrecorded, and
//!   nothing is served from a state directory whose marker something other
//!   than a restore wrote until an operator looks.
//!
//! Nothing starts from a state directory yet: the bundle and ledger startup
//! modes (`GATEWAY_CONFIG_SOURCE`) are later #242 slices, which call this
//! from their startup. Until then only the tests do, against state
//! directories the shared library restored exactly as `ggctl` restores them.
#![cfg_attr(not(test), expect(dead_code))]

use std::fmt;

use gateway_config::{
    backup::{acknowledge_restore_marker, read_restore_marker, MarkerError, RestoreMarker},
    state_dir::{StateDirectory, StateFile},
};
use serde_json::{json, Value};

use crate::audit::{self, AuditLog};

/// The audit event of the first start from a state directory `ggctl backup
/// restore` produced (ADR-0008, "Audit, status, and metrics"). It lives here
/// rather than with the other event types until a startup mode records it.
pub(crate) const CONFIG_RESTORE_DETECTED: &str = "config.restore_detected";

/// Why a start refused a restored state directory. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoreStartError {
    /// The marker is unsafe, invalid or unreadable.
    Marker(MarkerError),
    /// The event could not be recorded durably; the marker stays.
    AuditUnavailable,
    /// The event is recorded but the marker could not be removed, so the
    /// next start would record the restore again.
    MarkerNotRemoved,
}

impl RestoreStartError {
    /// The stable code for the startup error.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Marker(error) => error.code(),
            Self::AuditUnavailable => "restore.audit_unavailable",
            Self::MarkerNotRemoved => "restore.marker_not_removed",
        }
    }
}

impl fmt::Display for RestoreStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the state directory's restore marker could not be recorded and removed: error[{}]",
            self.code()
        )
    }
}

impl std::error::Error for RestoreStartError {}

/// Records the restore the held `state_dir` carries a marker of, once, and
/// returns the marker; `None` on every start but the first after a restore.
pub(crate) async fn record_restore(
    state_dir: &StateDirectory,
    audit: &AuditLog,
) -> Result<Option<RestoreMarker>, RestoreStartError> {
    let Some(marker) = read_restore_marker(state_dir).map_err(RestoreStartError::Marker)? else {
        return Ok(None);
    };
    let receipt = audit.record(restore_detected_event(&marker));
    audit
        .confirm(receipt)
        .await
        .map_err(|_| RestoreStartError::AuditUnavailable)?;
    acknowledge_restore_marker(state_dir).map_err(|_| RestoreStartError::MarkerNotRemoved)?;
    Ok(Some(marker))
}

fn restore_detected_event(marker: &RestoreMarker) -> audit::AuditEvent {
    audit::AuditEvent::new(
        CONFIG_RESTORE_DETECTED,
        "startup",
        "internal",
        None::<audit::Actor>,
        restore_detected_payload(marker),
    )
}

fn restore_detected_payload(marker: &RestoreMarker) -> Value {
    let stores: Vec<&str> = marker.stores.iter().map(|store| store.id()).collect();
    json!({
        "restore_id": marker.restore_id,
        "restored_at_ms": marker.restored_at_ms,
        "restored_by": {
            "program": marker.restored_by_program,
            "version": marker.restored_by_version,
        },
        "replaced_existing_state": marker.replaced,
        "backup": {
            "api_version": marker.backup_api_version,
            "created_at_ms": marker.backup_created_at_ms,
            "created_by": {
                "program": marker.backup_created_by_program,
                "version": marker.backup_created_by_version,
            },
        },
        "store_count": stores.len(),
        "stores": stores,
        "connections_restored": marker.stores.contains(&StateFile::Connections),
        "ledger": marker.ledger.as_ref().map(|(desired, active)| json!({
            "desired_revision": desired.as_str(),
            "active_revision": active.as_ref().map(|active| active.as_str()),
        })),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, UNIX_EPOCH},
    };

    use gateway_config::{
        backup::{self, CreateRequest, Producer, RestoreRequest},
        bundle::{
            read_bundle, read_bundle_files, sha256_pin, FileName, ProductionValidators, ReadOptions,
        },
        ledger::{LedgerActor, RevisionLedger},
        state_dir::{StateDirectory, StateFile, RESTORE_MARKER_FILE_NAME},
    };

    use super::*;
    use crate::{
        audit::{
            query::{AuditQueryFilters, AuditQueryStore},
            sqlite_sink::{SqliteSink, SqliteSinkConfig},
            AuditEvent,
        },
        connections::store::{ConnectionStore, SqliteConnectionStore},
    };

    /// Names every temporary directory, so a path that reaches an event is
    /// caught.
    const CANARY: &str = "zqcanary";
    const PRODUCER: Producer = Producer {
        program: "ggctl",
        version: "0.1.0",
    };
    const DENY: &str = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n";
    const DEPLOYMENT: &str = "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n";

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-restore-{CANARY}-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("temporary directory should create");
            #[cfg(unix)]
            set_mode(&path, 0o700);
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("permissions should set");
    }

    fn repository_text(path: &str) -> String {
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path))
            .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
            .replace("\r\n", "\n")
    }

    fn name(text: &str) -> FileName {
        FileName::parse(text).expect("a portable file name")
    }

    /// A production bundle: the deny-by-default policy and the starter tools.
    fn bundle_files() -> BTreeMap<FileName, Vec<u8>> {
        let tools = repository_text("docs/examples/tools.starter.json");
        let manifest = format!(
            concat!(
                "apiVersion: greengateway.dev/v1alpha1\n",
                "kind: GatewayBundle\n",
                "metadata:\n",
                "  name: payments-production\n",
                "spec:\n",
                "  deployment:\n",
                "    path: deployment.yaml\n",
                "    sha256: \"{}\"\n",
                "  resources:\n",
                "    policy:\n",
                "      source: bundle\n",
                "      path: policy.json\n",
                "      schema_version: \"0.1.0\"\n",
                "      sha256: \"{}\"\n",
                "    tools:\n",
                "      source: bundle\n",
                "      path: tools.json\n",
                "      schema_version: \"0.1.0\"\n",
                "      sha256: \"{}\"\n",
                "    connections:\n",
                "      source: server\n",
            ),
            sha256_pin(DEPLOYMENT.as_bytes()),
            sha256_pin(DENY.as_bytes()),
            sha256_pin(tools.as_bytes()),
        );
        BTreeMap::from([
            (name("bundle.yaml"), manifest.into_bytes()),
            (name("deployment.yaml"), DEPLOYMENT.as_bytes().to_vec()),
            (name("policy.json"), DENY.as_bytes().to_vec()),
            (name("tools.json"), tools.into_bytes()),
        ])
    }

    /// The audit store of record at `path`, as a log that waits for it.
    fn audit_log(path: &Path) -> AuditLog {
        let sink = SqliteSink::new(SqliteSinkConfig {
            path: path.to_path_buf(),
            retention_days: None,
        })
        .expect("the audit store should open");
        AuditLog::new_required(Arc::new(sink), Duration::from_secs(10))
    }

    /// Records one event into the audit store at `path`, as a gateway that
    /// ran before the loss did.
    async fn record_an_event(path: &Path) {
        let log = audit_log(path);
        log.emit(AuditEvent::new(
            audit::event::GATEWAY_READY,
            "lifecycle",
            "internal",
            None::<audit::Actor>,
            json!({}),
        ));
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
    }

    fn events(path: &Path, event_type: &str) -> Vec<AuditEvent> {
        AuditQueryStore::open(path)
            .expect("the audit store should open for queries")
            .query(&AuditQueryFilters {
                from: None,
                to: None,
                event_type: Some(event_type.to_owned()),
                reason: None,
                actor: None,
                actor_issuer: None,
                actor_auth_mode: None,
                method: None,
                path: None,
                status: None,
                matched_rule_id: None,
                limit: 50,
                before_id: None,
            })
            .expect("the audit store should answer")
            .events
    }

    /// Backs up the stopped state directory `source` and restores the
    /// archive into a new empty directory, as `ggctl` does; returns the
    /// directory holding the archive and the restored state directory.
    fn backup_and_restore(source: &Path) -> (TempDir, TempDir) {
        let out = TempDir::new("out");
        let archive = out.join("state.ggbk");
        {
            let held = StateDirectory::acquire(source).expect("the source should lock");
            backup::create(
                &held,
                &CreateRequest {
                    output: &archive,
                    producer: PRODUCER,
                    created_at: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                },
            )
            .expect("the backup should be created");
        }
        let target = TempDir::new("target");
        backup::restore(&RestoreRequest {
            archive: &archive,
            target: &target.0,
            replace_existing: false,
            producer: PRODUCER,
            restored_at: UNIX_EPOCH + Duration::from_secs(1_800_000_060),
            nonce: [7; 16],
        })
        .expect("the backup should be restored");
        (out, target)
    }

    fn assert_value_free(event: &AuditEvent) {
        let text = serde_json::to_string(event).expect("the event serializes");
        assert!(!text.contains(CANARY), "a path reached the event: {text}");
        assert!(
            !text.contains("ggbk"),
            "an archive name reached the event: {text}"
        );
    }

    #[tokio::test]
    async fn a_restored_ledger_mode_state_directory_starts_and_records_the_restore_once() {
        // The deployment before the loss: a seeded, active ledger and an
        // audit trail.
        let source = TempDir::new("source");
        let seeded = {
            let held = StateDirectory::acquire(&source.0).expect("the source should lock");
            let bundle = read_bundle_files(
                bundle_files(),
                ReadOptions { strict: true },
                &ProductionValidators,
            )
            .bundle
            .expect("the bundle should read");
            let (mut ledger, seed) = RevisionLedger::seed(
                &held,
                &bundle,
                LedgerActor::system("ggctl-ledger-seed").expect("system"),
                UNIX_EPOCH + Duration::from_secs(1_799_999_000),
            )
            .expect("seed");
            ledger.activate(&seed.revision).expect("activate");
            seed.revision
        };
        record_an_event(&source.join(StateFile::Audit.file_name())).await;
        let (_out, target) = backup_and_restore(&source.0);

        // The next start, as ledger mode starts: the held directory, its
        // audit store, the ledger fully verified, and its desired revision
        // compiled again with the production validators.
        let held = StateDirectory::acquire(&target.0).expect("the restored directory should lock");
        let audit_path = held.file(StateFile::Audit);
        let log = audit_log(&audit_path);
        let mut ledger = RevisionLedger::open(&held).expect("the restored ledger should verify");
        let state = ledger.state().expect("the ledger's state");
        assert_eq!(state.desired.revision, seeded);
        assert_eq!(state.active.as_ref(), Some(&seeded));
        let stored = ledger
            .revision(&seeded)
            .expect("the revision should read")
            .expect("the ledger holds it");
        let files = stored
            .files
            .into_iter()
            .map(|file| (file.name, file.bytes))
            .collect();
        let compiled =
            read_bundle_files(files, ReadOptions { strict: true }, &ProductionValidators);
        assert!(compiled.bundle.is_some(), "{:?}", compiled.diagnostics);

        let marker = record_restore(&held, &log)
            .await
            .expect("the restore should be recorded")
            .expect("the restore should be detected");
        assert_eq!(marker.restore_id, format!("rst-{}", "07".repeat(16)));
        assert_eq!(marker.stores, [StateFile::Audit, StateFile::ConfigLedger]);
        assert_eq!(marker.ledger, Some((seeded.clone(), Some(seeded.clone()))));
        assert!(!marker.replaced);
        assert!(!held.path().join(RESTORE_MARKER_FILE_NAME).exists());
        // Every later start finds no marker and records nothing.
        assert_eq!(record_restore(&held, &log).await, Ok(None));
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
        drop(ledger);
        drop(held);

        let detected = events(&audit_path, CONFIG_RESTORE_DETECTED);
        assert_eq!(detected.len(), 1, "the restore is recorded once");
        let event = &detected[0];
        assert_value_free(event);
        assert!(event.actor.is_none());
        assert_eq!(
            event.payload,
            json!({
                "restore_id": marker.restore_id,
                "restored_at_ms": 1_800_000_060_000_u64,
                "restored_by": {"program": "ggctl", "version": "0.1.0"},
                "replaced_existing_state": false,
                "backup": {
                    "api_version": "greengateway.dev/v1alpha1",
                    "created_at_ms": 1_800_000_000_000_u64,
                    "created_by": {"program": "ggctl", "version": "0.1.0"},
                },
                "store_count": 2,
                "stores": ["audit", "config_ledger"],
                "connections_restored": false,
                "ledger": {
                    "desired_revision": seeded.as_str(),
                    "active_revision": seeded.as_str(),
                },
            })
        );
        // The audit trail from before the loss came back with the restore.
        assert_eq!(events(&audit_path, audit::event::GATEWAY_READY).len(), 1);
    }

    #[tokio::test]
    async fn a_restored_bundle_mode_state_directory_starts_with_its_stores_and_records_the_restore_once(
    ) {
        // Bundle mode reads its bundle from its own read-only mount and keeps
        // only stores beneath the state directory.
        let mounted = TempDir::new("bundle");
        for (file, bytes) in bundle_files() {
            fs::write(mounted.join(file.as_str()), bytes).expect("the bundle should write");
        }
        #[cfg(unix)]
        set_mode(&mounted.0, 0o755);
        let source = TempDir::new("source");
        record_an_event(&source.join(StateFile::Audit.file_name())).await;
        drop(
            SqliteConnectionStore::open(source.join(StateFile::Connections.file_name()))
                .expect("the Connections store should open"),
        );
        let (_out, target) = backup_and_restore(&source.0);

        // The next start, as bundle mode starts: the bundle compiled with
        // the production validators, the held directory, its stores opened
        // through the gateway's own migrations.
        let report = read_bundle(
            &mounted.0,
            ReadOptions { strict: true },
            &ProductionValidators,
        );
        assert!(report.bundle.is_some(), "{:?}", report.diagnostics);
        let held = StateDirectory::acquire(&target.0).expect("the restored directory should lock");
        let audit_path = held.file(StateFile::Audit);
        let log = audit_log(&audit_path);
        let connections = SqliteConnectionStore::open(held.file(StateFile::Connections))
            .expect("the restored Connections store should open");
        assert_eq!(connections.count().expect("count"), 0);

        let marker = record_restore(&held, &log)
            .await
            .expect("the restore should be recorded")
            .expect("the restore should be detected");
        assert_eq!(marker.stores, [StateFile::Audit, StateFile::Connections]);
        assert_eq!(marker.ledger, None);
        assert_eq!(record_restore(&held, &log).await, Ok(None));
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
        drop(connections);
        drop(held);

        let detected = events(&audit_path, CONFIG_RESTORE_DETECTED);
        assert_eq!(detected.len(), 1, "the restore is recorded once");
        assert_value_free(&detected[0]);
        assert_eq!(detected[0].payload["connections_restored"], true);
        assert_eq!(detected[0].payload["ledger"], Value::Null);
        assert_eq!(events(&audit_path, audit::event::GATEWAY_READY).len(), 1);
    }

    #[tokio::test]
    async fn a_restore_that_cannot_be_recorded_durably_keeps_its_marker() {
        let source = TempDir::new("source");
        record_an_event(&source.join(StateFile::Audit.file_name())).await;
        let (_out, target) = backup_and_restore(&source.0);
        let held = StateDirectory::acquire(&target.0).expect("the restored directory should lock");
        let log = audit_log(&held.file(StateFile::Audit));
        // A closed log admits nothing, so the event is never durable.
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
        assert_eq!(
            record_restore(&held, &log).await,
            Err(RestoreStartError::AuditUnavailable)
        );
        assert!(held.path().join(RESTORE_MARKER_FILE_NAME).exists());
        // The next start records it.
        let log = audit_log(&held.file(StateFile::Audit));
        assert!(record_restore(&held, &log)
            .await
            .expect("the restore should be recorded")
            .is_some());
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
    }

    #[tokio::test]
    async fn an_unsafe_or_invalid_marker_refuses_the_start_and_is_kept() {
        let state = TempDir::new("state");
        let held = StateDirectory::acquire(&state.0).expect("the directory should lock");
        let marker = held.path().join(RESTORE_MARKER_FILE_NAME);
        let log = audit_log(&held.file(StateFile::Audit));
        for invalid in [
            format!("{{\"path\": \"{CANARY}\"}}").into_bytes(),
            b"not json".to_vec(),
            vec![b' '; 64 * 1024],
        ] {
            fs::write(&marker, &invalid).expect("the marker should write");
            #[cfg(unix)]
            set_mode(&marker, 0o600);
            let refused = record_restore(&held, &log).await;
            assert_eq!(
                refused,
                Err(RestoreStartError::Marker(MarkerError::Invalid))
            );
            let refused = refused.expect_err("refused");
            assert_eq!(refused.code(), "restore.marker_invalid");
            assert!(!refused.to_string().contains(CANARY));
            assert!(marker.exists(), "a refused marker is kept");
        }
        fs::remove_file(&marker).expect("the marker should go");
        fs::create_dir(&marker).expect("a directory in the marker's place");
        assert_eq!(
            record_restore(&held, &log).await,
            Err(RestoreStartError::Marker(MarkerError::Unsafe))
        );
        log.close_and_drain(Duration::from_secs(10))
            .await
            .expect("the audit log should drain");
        assert!(events(&held.file(StateFile::Audit), CONFIG_RESTORE_DETECTED).is_empty());
    }
}
