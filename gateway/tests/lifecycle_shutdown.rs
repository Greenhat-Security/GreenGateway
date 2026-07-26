#![cfg(unix)]

use std::{
    fs,
    io::Read,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn unused_loopback_address() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test port should bind");
    let address = listener
        .local_addr()
        .expect("test listener address should be available");
    drop(listener);
    address.to_string()
}

fn temp_audit_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "greengateway-lifecycle-{}-{nonce}.jsonl",
        std::process::id()
    ))
}

#[test]
fn sigterm_exits_cleanly_and_persists_terminal_audit_event() {
    let listen_addr = unused_loopback_address();
    let audit_path = temp_audit_path();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .env_clear()
        .env("LISTEN_ADDR", &listen_addr)
        .env("AUTH_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .env("AUDIT_LOG_FILE", &audit_path)
        .env("SHUTDOWN_DRAIN_DELAY_MS", "10")
        .env("SHUTDOWN_TIMEOUT_MS", "2000")
        .env("AUDIT_DRAIN_TIMEOUT_MS", "2000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gateway subprocess should start");

    let startup_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&listen_addr).is_ok() {
            break;
        }
        if let Some(status) = child
            .try_wait()
            .expect("gateway subprocess status should be readable")
        {
            let mut stderr = String::new();
            if let Some(mut stream) = child.stderr.take() {
                let _ = stream.read_to_string(&mut stderr);
            }
            panic!("gateway exited before accepting connections ({status}): {stderr}");
        }
        assert!(
            Instant::now() < startup_deadline,
            "gateway did not begin accepting connections before the test deadline"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let signal_status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill command should send SIGTERM");
    assert!(signal_status.success(), "SIGTERM delivery should succeed");

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let exit_status = loop {
        if let Some(status) = child
            .try_wait()
            .expect("gateway subprocess status should be readable")
        {
            break status;
        }
        assert!(
            Instant::now() < shutdown_deadline,
            "gateway did not exit before the shutdown deadline"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_string(&mut stderr);
    }
    assert!(
        exit_status.success(),
        "clean SIGTERM shutdown should exit zero: {stderr}"
    );

    let audit = fs::read_to_string(&audit_path)
        .expect("durable audit file should exist after clean shutdown");
    let event_types = audit
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("audit line should be valid JSON")
        })
        .filter_map(|event| {
            event["event_type"]
                .as_str()
                .map(std::borrow::ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert!(
        event_types
            .iter()
            .any(|event_type| event_type == "gateway.shutdown_started"),
        "SIGTERM must persist gateway.shutdown_started"
    );
    assert!(
        event_types
            .iter()
            .any(|event_type| event_type == "gateway.shutdown_completed"),
        "clean SIGTERM must persist gateway.shutdown_completed"
    );

    let _ = fs::remove_file(audit_path);
}
