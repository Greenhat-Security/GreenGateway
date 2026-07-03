use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{audit::AuditEvent, config::Config};

pub const LOCK_POISON_RECOVERIES_TOTAL: &str = "lock_poison_recoveries_total";

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent);
}

#[derive(Debug, Default)]
pub struct StdoutSink;

impl StdoutSink {
    pub fn new() -> Self {
        Self
    }
}

impl AuditSink for StdoutSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize audit event for stdout");
                return;
            }
        };

        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if let Err(err) = writeln!(handle, "{line}") {
            tracing::error!(error = %err, "failed to write audit event to stdout");
            return;
        }

        if let Err(err) = handle.flush() {
            tracing::error!(error = %err, "failed to flush audit event to stdout");
        }
    }
}

#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: Mutex::new(None),
        }
    }

    fn file_guard(&self) -> MutexGuard<'_, Option<File>> {
        match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "file_sink"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "audit file sink lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn write_locked(&self, file: &mut Option<File>, line: &str) -> io::Result<()> {
        if file.is_none() {
            *file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }

        let Some(file) = file.as_mut() else {
            return Err(io::Error::other("audit file handle was not opened"));
        };

        writeln!(file, "{line}")?;
        file.flush()
    }
}

impl AuditSink for FileSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize audit event for file sink");
                return;
            }
        };

        let mut file = self.file_guard();
        if let Err(err) = self.write_locked(&mut file, &line) {
            tracing::error!(
                path = %self.path.display(),
                error = %err,
                "failed to write audit event to file; reopening once"
            );
            *file = None;

            if let Err(err) = self.write_locked(&mut file, &line) {
                tracing::error!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to write audit event to file after reopen"
                );
            }
        }
    }
}

#[derive(Clone)]
pub struct CompositeSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl CompositeSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

impl AuditSink for CompositeSink {
    fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }
}

pub fn build_sink(audit_log_file: Option<&str>) -> Arc<dyn AuditSink> {
    let stdout: Arc<dyn AuditSink> = Arc::new(StdoutSink::new());
    let mut sinks = vec![stdout];

    if let Some(path) = audit_log_file
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        sinks.push(Arc::new(FileSink::new(path)) as Arc<dyn AuditSink>);
    }

    if sinks.len() == 1 {
        Arc::clone(&sinks[0])
    } else {
        Arc::new(CompositeSink::new(sinks))
    }
}

pub fn build_sink_from_config(config: &Config) -> Arc<dyn AuditSink> {
    build_sink(config.audit_log_file.as_deref())
}

#[allow(dead_code)] // Kept for direct sink construction in future entry points; main validates Config first.
pub fn build_sink_from_env() -> Arc<dyn AuditSink> {
    match Config::from_env() {
        Ok(config) => build_sink_from_config(&config),
        Err(err) => {
            tracing::error!(error = %err, "failed to load config for audit sink; using stdout only");
            build_sink(None)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{fs, sync::MutexGuard};

    #[derive(Clone, Default)]
    pub struct CaptureSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl CaptureSink {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn events(&self) -> Vec<AuditEvent> {
            self.events_guard().clone()
        }

        pub fn len(&self) -> usize {
            self.events_guard().len()
        }

        fn events_guard(&self) -> MutexGuard<'_, Vec<AuditEvent>> {
            match self.events.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }
    }

    impl AuditSink for CaptureSink {
        fn emit(&self, event: &AuditEvent) {
            self.events_guard().push(event.clone());
        }
    }

    #[test]
    fn capture_records_events() {
        let sink = CaptureSink::new();
        let event = test_event("audit.capture");

        sink.emit(&event);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "audit.capture");
    }

    #[test]
    fn stdout_sink_emit_does_not_panic() {
        let sink = StdoutSink::new();

        sink.emit(&test_event("audit.stdout"));
    }

    #[test]
    fn composite_fans_out_to_multiple_sinks() {
        let first = CaptureSink::new();
        let second = CaptureSink::new();
        let sink = CompositeSink::new(vec![
            Arc::new(first.clone()) as Arc<dyn AuditSink>,
            Arc::new(second.clone()) as Arc<dyn AuditSink>,
        ]);

        sink.emit(&test_event("audit.composite"));

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first.events()[0].event_type, "audit.composite");
        assert_eq!(second.events()[0].event_type, "audit.composite");
    }

    #[test]
    fn file_sink_writes_json_lines() {
        let path = std::env::temp_dir().join(format!(
            "greengateway-audit-sink-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let sink = FileSink::new(&path);

        sink.emit(&test_event("audit.file"));

        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let mut lines = contents.lines();
        let line = lines.next().expect("file should contain one audit line");
        assert!(lines.next().is_none());

        let value: Value = serde_json::from_str(line).expect("audit line should be JSON");
        assert_eq!(value["event_type"], "audit.file");

        fs::remove_file(&path)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", path.display()));
    }

    pub fn test_event(event_type: &str) -> AuditEvent {
        AuditEvent::new(
            event_type,
            "request-123",
            "203.0.113.10",
            None,
            json!({ "test": true }),
        )
    }
}
