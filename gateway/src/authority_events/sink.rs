//! Where the dispatcher delivers authority events (issue #425, PR 3).
//!
//! A sink is pluggable: the dispatcher hands it one ordered batch of
//! [`DeliveryRecord`]s and advances its durable cursor only after the sink
//! returns `Ok`. A sink that fails, or never returns, leaves the cursor where
//! it was, and the same batch is offered again: delivery is at least once,
//! and a consumer deduplicates on `(authority_id, event_id)`.
//!
//! Two reference sinks ship, neither of which opens a network connection:
//!
//! - [`LogSink`] (`AUTHORITY_EVENT_SINK=log`) writes one structured `INFO`
//!   line per record, the record's JSON in the `authority_event` field.
//!   "Accepted" means handed to the process's log writer; whatever collects
//!   the log decides whether it is kept. It is a reference for wiring a log
//!   pipeline, not a durable store.
//! - [`FileSink`] (`AUTHORITY_EVENT_SINK=file`) appends one JSON line per
//!   record to `AUTHORITY_EVENT_FILE` and calls `fsync` before it reports the
//!   batch accepted, so an accepted batch survives a crash of the host. The
//!   file is opened for every batch, so an external rotation (rename and let
//!   the gateway create a new file) loses nothing. A crash in the middle of a
//!   write can leave a partial final line; the next batch starts on a fresh
//!   line, so a consumer reading the file skips at most that one unparsable
//!   line, whose record is delivered again in full.
//!
//! Errors name a class only; neither the path nor a record reaches one.

use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use async_trait::async_trait;

use super::delivery::DeliveryRecord;

/// The tracing target the log sink writes under, so a log pipeline can route
/// authority events without parsing messages.
pub(crate) const LOG_TARGET: &str = "greengateway::authority_event";

/// The configured sink kinds: the value vocabulary of
/// `AUTHORITY_EVENT_SINK` beyond `none`.
pub(crate) const SINK_KIND_LOG: &str = "log";
pub(crate) const SINK_KIND_FILE: &str = "file";

/// Why a sink did not accept a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SinkError {
    kind: &'static str,
}

impl SinkError {
    pub(crate) const fn new(kind: &'static str) -> Self {
        Self { kind }
    }

    #[cfg_attr(not(test), allow(dead_code))] // the Display carries it everywhere else
    pub(crate) const fn kind(self) -> &'static str {
        self.kind
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authority event sink refused the batch: {}",
            self.kind
        )
    }
}

impl std::error::Error for SinkError {}

/// A destination for delivered authority events.
#[async_trait]
pub(crate) trait AuthorityEventSink: Send + Sync {
    /// A fixed, label-safe name for logs.
    fn kind(&self) -> &'static str;

    /// Accept `batch`, in order. `Ok` must mean the sink holds every record
    /// as durably as it can; the dispatcher then advances its cursor past
    /// them and never offers them again unless that advance is lost.
    async fn deliver(&self, batch: &[DeliveryRecord]) -> Result<(), SinkError>;
}

/// One structured log line per record.
pub(crate) struct LogSink;

#[async_trait]
impl AuthorityEventSink for LogSink {
    fn kind(&self) -> &'static str {
        SINK_KIND_LOG
    }

    async fn deliver(&self, batch: &[DeliveryRecord]) -> Result<(), SinkError> {
        // Serialize the whole batch first, so a record that cannot be
        // written refuses the batch before any of it is logged.
        let lines = serialize_batch(batch)?;
        for line in &lines {
            tracing::info!(target: LOG_TARGET, authority_event = %line, "authority event");
        }
        Ok(())
    }
}

/// JSON lines appended to one file, synced before acceptance.
pub(crate) struct FileSink {
    path: PathBuf,
    /// One batch at a time, so two lines never interleave.
    write: tokio::sync::Mutex<()>,
}

impl FileSink {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            write: tokio::sync::Mutex::new(()),
        }
    }

    /// Open the file for appending, creating it if missing, and write
    /// nothing: the startup check that a configured file sink can accept at
    /// all. Only the error's kind is reported, never the path.
    pub(crate) async fn probe(&self) -> Result<(), io::ErrorKind> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || open_for_append(&path).map(drop))
            .await
            .map_err(|_| io::ErrorKind::Other)?
            .map_err(|error| error.kind())
    }
}

#[async_trait]
impl AuthorityEventSink for FileSink {
    fn kind(&self) -> &'static str {
        SINK_KIND_FILE
    }

    async fn deliver(&self, batch: &[DeliveryRecord]) -> Result<(), SinkError> {
        let mut payload = String::new();
        for line in serialize_batch(batch)? {
            payload.push_str(&line);
            payload.push('\n');
        }
        let _write = self.write.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || append_synced(&path, payload.as_bytes()))
            .await
            .map_err(|_| SinkError::new("worker_unavailable"))?
            .map_err(|error| {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "authority event file sink could not append the batch"
                );
                SinkError::new("file_write")
            })
    }
}

/// Open `path` to append and to read its last byte, creating it owner-only on
/// Unix if missing.
fn open_for_append(path: &std::path::Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn serialize_batch(batch: &[DeliveryRecord]) -> Result<Vec<String>, SinkError> {
    batch
        .iter()
        .map(|record| serde_json::to_string(record).map_err(|_| SinkError::new("serialize")))
        .collect()
}

/// Append `bytes` to `path`, starting on a fresh line, and sync the data
/// before returning. The file is created owner-only on Unix.
fn append_synced(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_for_append(path)?;
    if file.metadata()?.len() > 0 {
        // Writes in append mode always land at the end; the seek only
        // positions this read of the last byte.
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    file.write_all(bytes)?;
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_events::delivery::{DeliveryActor, DeliveryResource, DeliveryRevision};

    fn record(sequence: &str) -> DeliveryRecord {
        DeliveryRecord {
            schema_version: crate::authority_events::delivery::DELIVERY_SCHEMA_VERSION.to_owned(),
            authority_id: uuid::Uuid::new_v4().to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            sequence: sequence.to_owned(),
            operation: "service_token.revoke".to_owned(),
            result: "committed".to_owned(),
            committed_at: "2026-10-21T12:34:56.123456Z".to_owned(),
            actor: DeliveryActor {
                recorded_ref: "0".repeat(64),
            },
            resource: DeliveryResource {
                kind: "service_token".to_owned(),
                reference: "1".repeat(64),
            },
            revision: DeliveryRevision {
                axis: "token".to_owned(),
                before: Some("1".to_owned()),
                after: Some("2".to_owned()),
                security: "9".to_owned(),
            },
        }
    }

    fn scratch_file() -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-authority-sink-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("scratch directory should create");
        let path = directory.join("authority-events.jsonl");
        (directory, path)
    }

    fn lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .expect("the sink file should be readable")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[tokio::test]
    async fn the_file_sink_appends_one_parsable_line_per_record_in_order() {
        let (directory, path) = scratch_file();
        let sink = FileSink::new(path.clone());
        let first = vec![record("1"), record("2")];
        let second = vec![record("3")];
        sink.deliver(&first).await.expect("first batch accepted");
        sink.deliver(&second).await.expect("second batch accepted");

        let delivered: Vec<DeliveryRecord> = lines(&path)
            .iter()
            .map(|line| serde_json::from_str(line).expect("every line is one record"))
            .collect();
        assert_eq!(
            delivered,
            first.into_iter().chain(second).collect::<Vec<_>>()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the event file is owner-only");
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    /// A crash mid-write leaves a partial last line. The next batch starts on
    /// a line of its own, so the damage is one unparsable line, never a
    /// record glued to garbage.
    #[tokio::test]
    async fn a_partial_line_left_by_a_crash_stands_alone() {
        let (directory, path) = scratch_file();
        std::fs::write(&path, b"{\"schema_version\":\"authority_ev").expect("partial write");
        let sink = FileSink::new(path.clone());
        let batch = vec![record("7")];
        sink.deliver(&batch).await.expect("batch accepted");

        let written = lines(&path);
        assert_eq!(written.len(), 2);
        assert!(serde_json::from_str::<DeliveryRecord>(&written[0]).is_err());
        assert_eq!(
            serde_json::from_str::<DeliveryRecord>(&written[1]).expect("a whole record"),
            batch[0]
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_written_refuses_the_batch() {
        let (directory, path) = scratch_file();
        // A directory where the file should be: the open fails.
        std::fs::create_dir_all(&path).expect("blocking directory");
        let sink = FileSink::new(path);
        assert!(
            sink.probe().await.is_err(),
            "the startup probe refuses it too"
        );
        assert_eq!(
            sink.deliver(&[record("1")]).await,
            Err(SinkError::new("file_write"))
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn the_startup_probe_creates_the_file_and_writes_nothing() {
        let (directory, path) = scratch_file();
        let sink = FileSink::new(path.clone());
        sink.probe().await.expect("a writable location probes");
        assert_eq!(
            std::fs::read(&path).expect("the probe created the file"),
            Vec::<u8>::new()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn the_log_sink_accepts_a_batch() {
        assert_eq!(LogSink.kind(), SINK_KIND_LOG);
        LogSink
            .deliver(&[record("1"), record("2")])
            .await
            .expect("the log sink accepts");
    }

    #[test]
    fn sink_errors_name_a_class_only() {
        let error = SinkError::new("file_write");
        assert_eq!(error.kind(), "file_write");
        assert_eq!(
            error.to_string(),
            "authority event sink refused the batch: file_write"
        );
    }
}
