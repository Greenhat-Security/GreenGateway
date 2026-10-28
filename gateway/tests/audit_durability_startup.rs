//! `AUDIT_DURABILITY` at the process boundary (issue #425).
//!
//! The default is `required`, and a configuration that cannot honour it is
//! refused at startup rather than served in a mode that would quietly
//! downgrade to best effort -- or refuse every request. These rows run the
//! real binary with a cleared environment, so what they observe is what an
//! operator who sets nothing gets.

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
