//! `AUDIT_DURABILITY` at the process boundary (issue #425).
//!
//! The default is `required`, and a configuration that cannot honour it is
//! refused at startup rather than served in a mode that would quietly
//! downgrade to best effort -- or refuse every request. These rows run the
//! real binary with a cleared environment, so what they observe is what an
//! operator who sets nothing gets. The last two rows run it under
//! `AUTHORITY_EVIDENCE_DURABILITY=required`, which refuses to start at all
//! and refuses the offline import's writing forms.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

/// How long a gateway may take to refuse, or to start serving.
const PROCESS_BUDGET: Duration = Duration::from_secs(30);

/// The binary with a cleared environment: the GreenGateway configuration is
/// exactly what each row sets, plus the platform variables a process needs
/// to start networking and find a temporary directory.
fn gateway() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateway"));
    command
        .env_clear()
        .env("AUTH_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for key in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

/// Run a gateway that is expected to refuse startup, and return how it
/// exited. One that is still running at the budget is killed and the row
/// fails: it started when it should not have.
fn run_to_refusal(mut command: Command) -> Output {
    let mut child = command
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .spawn()
        .expect("the gateway should spawn");
    let deadline = Instant::now() + PROCESS_BUDGET;
    loop {
        if child
            .try_wait()
            .expect("the gateway status should be readable")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("the gateway output should be readable");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the gateway was still running after {PROCESS_BUDGET:?}; it should have refused to start");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn unused_loopback_address() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port should bind");
    let address = listener
        .local_addr()
        .expect("the listener should have an address");
    drop(listener);
    address.to_string()
}

/// A gateway that is killed when the row ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `GET /livez` once, answering the status line, or `None` while nothing
/// answers.
fn livez(address: &str) -> Option<String> {
    let mut stream = TcpStream::connect(address).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .map(str::to_owned)
}

fn start_serving(mut command: Command) -> (Running, String) {
    let address = unused_loopback_address();
    let child = command
        .env("LISTEN_ADDR", &address)
        .spawn()
        .expect("the gateway should spawn");
    let mut running = Running(child);
    let deadline = Instant::now() + PROCESS_BUDGET;
    loop {
        if let Some(status) = running
            .0
            .try_wait()
            .expect("the gateway status should be readable")
        {
            let mut stderr = String::new();
            if let Some(mut pipe) = running.0.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("the gateway exited with {status} instead of serving: {stderr}");
        }
        if let Some(status_line) = livez(&address) {
            assert!(
                status_line.contains(" 200 "),
                "/livez should answer 200, said {status_line}"
            );
            return (running, address);
        }
        assert!(
            Instant::now() < deadline,
            "the gateway did not serve /livez within {PROCESS_BUDGET:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn temp_audit_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "greengateway-audit-durability-{label}-{}.sqlite",
        std::process::id()
    ))
}

fn remove_sqlite(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// An operator who sets nothing gets `required`, and a standalone gateway
/// with no audit store of record does not start. The refusal names both
/// ways out; stdout and an audit log file are not stores of record.
#[test]
fn the_default_refuses_a_standalone_gateway_with_no_audit_store_of_record() {
    let output = run_to_refusal(gateway());
    assert!(
        !output.status.success(),
        "the gateway must exit unsuccessfully"
    );
    let message = stderr(&output);
    assert!(message.contains("AUDIT_DURABILITY=required"), "{message}");
    assert!(message.contains("AUDIT_SQLITE_PATH"), "{message}");
    assert!(
        message.contains("AUDIT_DURABILITY=best_effort"),
        "{message}"
    );

    let log_file = std::env::temp_dir().join(format!(
        "greengateway-audit-durability-log-{}.jsonl",
        std::process::id()
    ));
    let mut command = gateway();
    command.env("AUDIT_LOG_FILE", &log_file);
    let output = run_to_refusal(command);
    let _ = std::fs::remove_file(&log_file);
    assert!(
        !output.status.success(),
        "a JSONL file is not a store of record: {}",
        stderr(&output)
    );
}

/// Values the gateway cannot honour are configuration errors, never a
/// fallback to the default.
#[test]
fn an_unknown_mode_or_an_unbounded_timeout_is_a_configuration_error() {
    for (name, value) in [
        ("AUDIT_DURABILITY", "sometimes"),
        ("AUDIT_DURABILITY", ""),
        ("AUDIT_DURABILITY_TIMEOUT_MS", "0"),
        ("AUDIT_DURABILITY_TIMEOUT_MS", "60001"),
    ] {
        let audit_db = temp_audit_path("invalid");
        let mut command = gateway();
        command.env("AUDIT_SQLITE_PATH", &audit_db).env(name, value);
        let output = run_to_refusal(command);
        remove_sqlite(&audit_db);
        assert!(!output.status.success(), "{name}={value:?} must not start");
        let message = stderr(&output);
        assert!(
            message.contains(name),
            "the error should name {name}: {message}"
        );
    }
}

/// With the SQLite store of record the default starts and serves, and the
/// explicit opt-out starts without one.
#[test]
fn the_default_serves_over_sqlite_and_the_opt_out_serves_without_a_store() {
    let audit_db = temp_audit_path("required");
    let mut command = gateway();
    command.env("AUDIT_SQLITE_PATH", &audit_db);
    let (running, _) = start_serving(command);
    assert!(
        audit_db.exists(),
        "the store of record should have been created"
    );
    drop(running);
    remove_sqlite(&audit_db);

    let mut command = gateway();
    command.env("AUDIT_DURABILITY", "best_effort");
    let (running, _) = start_serving(command);
    drop(running);
}

/// A fresh, empty directory for one row, removed when the row ends.
struct EmptyDirectory(PathBuf);

impl EmptyDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-startup-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temporary directory should be created");
        Self(path)
    }

    fn entries(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.0)
            .expect("the temporary directory should be readable")
            .map(|entry| entry.expect("the entry should be readable").path())
            .collect()
    }
}

impl Drop for EmptyDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `AUTHORITY_EVIDENCE_DURABILITY=required` refuses to start in either
/// deployment mode, because nothing records the activation of the
/// configuration the gateway would serve (issue #425, owner decision of
/// 2026-11-19). The real binary prints the value-free refusal, exits with
/// status 1, and writes nothing: every store path, and the working
/// directory any default path would resolve against, is inside one empty
/// directory that stays empty. The cluster row names a database URL file
/// that does not exist, so the refusal can only come before preflight.
#[test]
fn required_authority_evidence_exits_before_writing_anything() {
    const MARKER: &str = "startup-refusal-marker";
    let mut modes = vec!["standalone"];
    if cfg!(feature = "postgres") {
        modes.push("cluster");
    }
    for mode in modes {
        let directory = EmptyDirectory::new(&format!("authority-evidence-{mode}"));
        let inside = |name: &str| directory.0.join(format!("{MARKER}-{name}"));
        let mut command = gateway();
        command
            .current_dir(&directory.0)
            .env("AUTHORITY_EVIDENCE_DURABILITY", "required")
            .env("AUTHORITY_EVENT_SINK", "log")
            .env("AUTHORITY_PSEUDONYM_KEY_ALIAS", format!("{MARKER}-alias"))
            .env("UPSTREAM_URL", format!("https://{MARKER}.invalid"));
        if mode == "standalone" {
            command.env("AUDIT_SQLITE_PATH", inside("audit.sqlite"));
        } else {
            command
                .env("STATE_BACKEND", "postgres")
                .env("DEPLOYMENT_ID", format!("{MARKER}-deployment"))
                .env("DATABASE_URL_FILE", inside("database-url"))
                .env("CONNECTION_SECRETS_ROOT", inside("secrets"))
                .env(
                    "RATE_LIMIT_KEYRING",
                    r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#,
                );
        }
        let output = run_to_refusal(command);
        let message = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{mode}: {message}");
        let expected = format!(
            "authority_evidence_activation_unevidenced: AUTHORITY_EVIDENCE_DURABILITY=required refuses configuration.activate: {mode} mode "
        );
        assert!(
            message.lines().any(|line| line.starts_with(&expected)),
            "{mode}: {message}"
        );
        assert!(!message.contains(MARKER), "{mode}: {message}");
        assert_eq!(directory.entries(), Vec::<PathBuf>::new(), "{mode}");
    }
}

/// `gateway import-standalone` under `AUTHORITY_EVIDENCE_DURABILITY=required`
/// at the process boundary (issue #425, owner ruling of 2026-11-20). The
/// writing forms print the gate's value-free refusal and exit with status 1
/// before reading the `--from` file or the target's DSN file, neither of
/// which exists; the dry run gets past the gate and fails on reading the
/// `--from` file. Nothing is written in either case.
#[cfg(feature = "postgres")]
#[test]
fn the_import_writes_nothing_under_required_and_its_dry_run_still_runs() {
    const MARKER: &str = "import-refusal-marker";
    let directory = EmptyDirectory::new("authority-evidence-import");
    let inside = |name: &str| directory.0.join(format!("{MARKER}-{name}"));
    let from = inside("standalone.env");
    let import = |arguments: &[&str]| {
        let mut command = gateway();
        command
            .current_dir(&directory.0)
            .arg("import-standalone")
            .arg("--from")
            .arg(&from)
            .args(arguments)
            .env("AUTHORITY_EVIDENCE_DURABILITY", "required")
            .env("AUTHORITY_EVENT_SINK", "log")
            .env("AUTHORITY_PSEUDONYM_KEY_ALIAS", format!("{MARKER}-alias"))
            .env("UPSTREAM_URL", format!("https://{MARKER}.invalid"))
            .env("STATE_BACKEND", "postgres")
            .env("DEPLOYMENT_ID", format!("{MARKER}-deployment"))
            .env("DATABASE_URL_FILE", inside("database-url"))
            .env("CONNECTION_SECRETS_ROOT", inside("secrets"))
            .env(
                "RATE_LIMIT_KEYRING",
                r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#,
            );
        run_to_refusal(command)
    };
    for arguments in [&["--apply"][..], &["--apply", "--resume"][..]] {
        let output = import(arguments);
        let message = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}: {message}");
        assert!(
            message.lines().any(|line| line
                == "Error: authority_evidence_unsupported: AUTHORITY_EVIDENCE_DURABILITY=required refuses configuration.import: cluster mode records evidence for only part of it; nothing was changed"),
            "{arguments:?}: {message}"
        );
        assert!(!message.contains(MARKER), "{arguments:?}: {message}");
    }
    for arguments in [&[][..], &["--dry-run"][..]] {
        let output = import(arguments);
        let message = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}: {message}");
        assert!(
            message.contains("Error: standalone_env_file_unreadable: "),
            "{arguments:?}: {message}"
        );
        assert!(
            !message.contains("authority_evidence_unsupported"),
            "{arguments:?}: {message}"
        );
    }
    assert_eq!(directory.entries(), Vec::<PathBuf>::new());
}
