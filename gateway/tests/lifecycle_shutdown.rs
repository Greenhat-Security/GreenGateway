#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{mpsc, Mutex, MutexGuard},
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

/// Serializes port allocation through child startup.
///
/// `unused_loopback_address` asks the OS for a free port and then releases it,
/// so the port is unowned between that call and the child binding it. Two of
/// these tests running concurrently can therefore be handed the SAME port. What
/// follows is worse than a bind failure: the first gateway binds it, the second
/// fails to bind and exits, and the second test's startup probe then connects
/// successfully -- to the FIRST test's gateway. It leaves the gate believing its
/// child is up. When the first test signals its gateway, the second test's real
/// request is refused, surfacing as a bare `ConnectionRefused` with nothing to
/// suggest that its child had died at startup.
///
/// Holding this across allocation and startup keeps the window closed. It is
/// released once the child owns the port, so the slow parts of these tests still
/// overlap.
static STARTUP_GUARD: Mutex<()> = Mutex::new(());

fn startup_guard() -> MutexGuard<'static, ()> {
    // A panicking test must not cascade into the others; the data is `()`.
    STARTUP_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Blocks until the child answers a request on its own listener.
///
/// Deliberately not a bare `TcpStream::connect`. A successful connect proves
/// only that something is listening on that address, which is exactly the
/// assumption that made a cross-test port collision look like a healthy start.
/// Requiring a response to a gateway-owned probe route proves the child is
/// serving, and re-checking `try_wait` on every iteration means a child that
/// died reports its stderr instead of the failure surfacing later as a refused
/// connection.
fn wait_until_serving(child: &mut Child, listen_addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
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

        if gateway_answers_probe(listen_addr) {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "gateway did not begin serving before the test deadline"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn gateway_answers_probe(listen_addr: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(listen_addr) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(
            b"GET /livez HTTP/1.1
Host: localhost
Connection: close

",
        )
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    response.starts_with(b"HTTP/1.1 200")
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
fn the_startup_gate_is_not_satisfied_by_a_listener_that_is_not_this_gateway() {
    // The precise confusion this guards against: a port collision between two
    // of these tests leaves a DIFFERENT process listening on the address, and
    // the old gate accepted that as its own child having started.
    let foreign = TcpListener::bind(("127.0.0.1", 0)).expect("test listener should bind");
    let address = foreign
        .local_addr()
        .expect("test listener address should be available")
        .to_string();

    // A bare connect succeeds against anything that is listening, which is
    // exactly why it could not tell the two apart.
    assert!(
        TcpStream::connect(&address).is_ok(),
        "a plain connect succeeds against any listener, which is the trap"
    );

    // Requiring a served response does tell them apart.
    assert!(
        !gateway_answers_probe(&address),
        "the gate must not accept a listener that never answers the probe route"
    );
}

#[test]
fn sigterm_exits_cleanly_and_persists_terminal_audit_event() {
    let startup = startup_guard();
    let listen_addr = unused_loopback_address();
    let audit_path = temp_audit_path();
    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).expect("test upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("test upstream address should be available");
    let (upstream_started_tx, upstream_started_rx) = mpsc::channel();
    let (release_upstream_tx, release_upstream_rx) = mpsc::channel();
    let upstream = thread::spawn(move || loop {
        let (mut stream, _) = upstream_listener
            .accept()
            .expect("test upstream should accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("test upstream read timeout should configure");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream
                .read(&mut buffer)
                .expect("test upstream request should read");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        if request.starts_with(b"GET /in-flight ") {
            upstream_started_tx
                .send(())
                .expect("in-flight request start should be observed");
            release_upstream_rx
                .recv()
                .expect("in-flight upstream should be released");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nupstream-drained",
                )
                .expect("test upstream response should write");
            break;
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("test upstream health response should write");
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .env_clear()
        .env("LISTEN_ADDR", &listen_addr)
        .env("AUTH_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .env("AUDIT_LOG_FILE", &audit_path)
        .env("UPSTREAM_URL", format!("http://{upstream_addr}"))
        .env("EGRESS_ALLOWED_HOSTS", "127.0.0.1")
        .env("EGRESS_DENY_PRIVATE_IPS", "false")
        .env("SHUTDOWN_DRAIN_DELAY_MS", "10")
        .env("SHUTDOWN_TIMEOUT_MS", "2000")
        .env("AUDIT_DRAIN_TIMEOUT_MS", "2000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gateway subprocess should start");

    wait_until_serving(&mut child, &listen_addr);
    // The child owns the port now, so the remaining work can overlap again.
    drop(startup);

    let request_addr = listen_addr.clone();
    let request = thread::spawn(move || {
        let mut stream =
            TcpStream::connect(request_addr).expect("in-flight gateway request should connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("gateway response timeout should configure");
        stream
            .write_all(b"GET /in-flight HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("in-flight gateway request should write");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("in-flight gateway response should read");
        response
    });
    upstream_started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("gateway should start the upstream request");

    let signal_status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill command should send SIGTERM");
    assert!(signal_status.success(), "SIGTERM delivery should succeed");
    thread::sleep(Duration::from_millis(50));
    release_upstream_tx
        .send(())
        .expect("in-flight upstream should still be draining");
    let response = request.join().expect("gateway request thread should join");
    upstream.join().expect("test upstream thread should join");
    assert!(
        String::from_utf8_lossy(&response).contains("upstream-drained"),
        "SIGTERM must allow the in-flight proxied response to complete"
    );

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

#[test]
fn sigint_ctrl_c_path_exits_cleanly_and_persists_terminal_audit_event() {
    let startup = startup_guard();
    let listen_addr = unused_loopback_address();
    let audit_path = temp_audit_path();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .env_clear()
        .env("LISTEN_ADDR", &listen_addr)
        .env("AUTH_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .env("AUDIT_LOG_FILE", &audit_path)
        .env("SHUTDOWN_DRAIN_DELAY_MS", "0")
        .env("SHUTDOWN_TIMEOUT_MS", "2000")
        .env("AUDIT_DRAIN_TIMEOUT_MS", "2000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gateway subprocess should start");

    wait_until_serving(&mut child, &listen_addr);
    // The child owns the port now, so the remaining work can overlap again.
    drop(startup);

    let signal_status = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .expect("kill command should send SIGINT");
    assert!(
        signal_status.success(),
        "SIGINT/Ctrl-C delivery should succeed"
    );

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
        "clean SIGINT/Ctrl-C shutdown should exit zero: {stderr}"
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
        "SIGINT/Ctrl-C must persist gateway.shutdown_started"
    );
    assert!(
        event_types
            .iter()
            .any(|event_type| event_type == "gateway.shutdown_completed"),
        "clean SIGINT/Ctrl-C must persist gateway.shutdown_completed"
    );

    let _ = fs::remove_file(audit_path);
}

#[test]
fn hard_shutdown_cancels_sse_before_persisted_audit_drain() {
    let startup = startup_guard();
    let listen_addr = unused_loopback_address();
    let audit_path = temp_audit_path();
    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).expect("test upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("test upstream address should be available");
    let (sse_started_tx, sse_started_rx) = mpsc::channel();
    let upstream = thread::spawn(move || loop {
        let (mut stream, _) = upstream_listener
            .accept()
            .expect("test SSE upstream should accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("test SSE upstream read timeout should configure");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream
                .read(&mut buffer)
                .expect("test SSE upstream request should read");
            if count == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        if !request.starts_with(b"GET /events ") {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("test SSE upstream health response should write");
            continue;
        }
        sse_started_tx
            .send(())
            .expect("SSE request start should be observed");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            )
            .expect("test SSE headers should write");
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("test SSE upstream close should read: {error}"),
            }
        }
        break;
    });
    let upstream_routes = format!(
        r#"[{{"path_prefix":"/events","upstream_url":"http://{upstream_addr}","sse":{{"max_duration_ms":0,"max_response_bytes":0}}}}]"#
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .env_clear()
        .env("LISTEN_ADDR", &listen_addr)
        .env("AUTH_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .env("AUDIT_LOG_FILE", &audit_path)
        .env("UPSTREAM_ROUTES", upstream_routes)
        .env("EGRESS_ALLOWED_HOSTS", "127.0.0.1")
        .env("EGRESS_DENY_PRIVATE_IPS", "false")
        .env("EGRESS_RESPONSE_IDLE_TIMEOUT_MS", "60000")
        .env("SHUTDOWN_DRAIN_DELAY_MS", "0")
        .env("SHUTDOWN_TIMEOUT_MS", "50")
        .env("AUDIT_DRAIN_TIMEOUT_MS", "2000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gateway subprocess should start");

    wait_until_serving(&mut child, &listen_addr);
    // The child owns the port now, so the remaining work can overlap again.
    drop(startup);

    let mut client = TcpStream::connect(&listen_addr).expect("SSE gateway request should connect");
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("SSE gateway response timeout should configure");
    client
        .write_all(
            b"GET /events HTTP/1.1\r\nHost: localhost\r\nx-request-id: sse-hard-shutdown\r\nConnection: keep-alive\r\n\r\n",
        )
        .expect("SSE gateway request should write");
    sse_started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("gateway should start the intended SSE upstream request");
    let mut response_headers = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !response_headers
        .windows(4)
        .any(|window| window == b"\r\n\r\n")
    {
        let count = client
            .read(&mut buffer)
            .expect("SSE gateway headers should read");
        assert!(count > 0, "gateway closed before committing SSE headers");
        response_headers.extend_from_slice(&buffer[..count]);
    }
    assert!(
        String::from_utf8_lossy(&response_headers).starts_with("HTTP/1.1 200"),
        "gateway should commit the SSE response before shutdown"
    );

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
            "gateway did not exit before the hard shutdown test deadline"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_string(&mut stderr);
    }
    assert!(
        exit_status.success(),
        "hard SSE shutdown should finish cleanup successfully: {stderr}"
    );
    drop(client);
    upstream.join().expect("test SSE upstream should join");

    let events = fs::read_to_string(&audit_path)
        .expect("durable audit file should exist after hard SSE shutdown")
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("audit line should be valid JSON")
        })
        .collect::<Vec<_>>();
    assert!(
        events.iter().any(|event| {
            event["event_type"] == "upstream.stream_terminated"
                && event["request_id"] == "sse-hard-shutdown"
                && event["payload"]["outcome"] == "shutdown"
        }),
        "forced SSE termination must be persisted before audit drain"
    );
    assert!(
        events.iter().any(|event| {
            event["event_type"] == "gateway.shutdown_forced"
                && event["payload"]["reason"] == "deadline"
        }),
        "the real listener must exercise the hard shutdown deadline"
    );

    let _ = fs::remove_file(audit_path);
}
