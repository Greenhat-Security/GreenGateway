use std::{
    fs, io,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection};
use serde_json::json;
use uuid::Uuid;

const OLD_KEY_ID: &str = "historical-master-key-canary";
const NEW_KEY_ID: &str = "current-master-key-canary";
const OLD_KEY_FILE: &str = "historical-master-canary.key";
const NEW_KEY_FILE: &str = "current-master-canary.key";
const WRONG_KEY_FILE: &str = "wrong-master-canary.key";
const SECRET_MATERIAL: &[u8] = b"issue-240-secret-material-canary";
const OLD_KEY: [u8; 32] = [b'H'; 32];
const NEW_KEY: [u8; 32] = [b'N'; 32];
const WRONG_KEY: [u8; 32] = [b'W'; 32];
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn issue_240_e2e_11_wrong_key_process_restart() {
    let fixture = ProcessFixture::new("e2e-11");
    fixture.bootstrap_store();
    let secret_ids = fixture.seed_historical_secrets(1);

    let correct_primary = fixture.old_primary_keyring();
    let correct = fixture.observe_gateway_start(Some(&correct_primary));
    assert!(
        correct.ready,
        "the real gateway must restart with the correct historical primary key: {}",
        combined_output(&correct.output)
    );
    fixture.assert_output_redacted(&correct.output, &secret_ids);

    let absent = fixture.observe_gateway_start(None);
    assert_failed_before_listening(
        &absent,
        "encrypted rows without a configured keyring must fail closed",
    );
    fixture.assert_output_redacted(&absent.output, &secret_ids);

    let correct_rotating = fixture.rotating_keyring();
    let rotating = fixture.observe_gateway_start(Some(&correct_rotating));
    assert!(
        rotating.ready,
        "the real gateway must restart with a correct primary/decrypt-only keyring: {}",
        combined_output(&rotating.output)
    );
    fixture.assert_output_redacted(&rotating.output, &secret_ids);

    let wrong_decrypt_only = fixture.wrong_decrypt_only_keyring();
    let wrong = fixture.observe_gateway_start(Some(&wrong_decrypt_only));
    assert_failed_before_listening(
        &wrong,
        "a wrong decrypt-only key must fail closed before the listener starts",
    );
    fixture.assert_output_redacted(&wrong.output, &secret_ids);
}

#[test]
fn issue_240_vm_06_local_encryption_process_recovery() {
    let fixture = ProcessFixture::new("vm-06");
    fixture.bootstrap_store();
    let secret_ids = fixture.seed_historical_secrets(3);
    let rotating_keyring = fixture.rotating_keyring();

    let still_used = fixture.run_cli(
        &rotating_keyring,
        &[
            "connection-secrets",
            "ensure-key-unused",
            "--key-id",
            OLD_KEY_ID,
        ],
    );
    assert!(
        !still_used.status.success(),
        "the historical key must not be removable while records still use it"
    );
    assert!(
        String::from_utf8_lossy(&still_used.stderr).contains("key_in_use_records=3"),
        "the failure should expose only the bounded record count: {}",
        combined_output(&still_used)
    );
    fixture.assert_output_redacted(&still_used, &secret_ids);

    let first_batch = fixture.run_cli(
        &rotating_keyring,
        &["connection-secrets", "reencrypt", "--batch-size", "2"],
    );
    assert_success_output(&first_batch, "reencrypted=2 remaining=1");
    fixture.assert_output_redacted(&first_batch, &secret_ids);
    fixture.assert_key_usage(1, 2);

    // A new process resumes from the durable state left by the first bounded
    // invocation; no in-memory continuation is involved.
    let resumed_batch = fixture.run_cli(
        &rotating_keyring,
        &["connection-secrets", "reencrypt", "--batch-size", "2"],
    );
    assert_success_output(&resumed_batch, "reencrypted=1 remaining=0");
    fixture.assert_output_redacted(&resumed_batch, &secret_ids);
    fixture.assert_key_usage(0, 3);

    let completed = fixture.run_cli(
        &rotating_keyring,
        &["connection-secrets", "reencrypt", "--batch-size", "2"],
    );
    assert_success_output(&completed, "reencrypted=0 remaining=0");
    fixture.assert_output_redacted(&completed, &secret_ids);

    let unused = fixture.run_cli(
        &rotating_keyring,
        &[
            "connection-secrets",
            "ensure-key-unused",
            "--key-id",
            OLD_KEY_ID,
        ],
    );
    assert_success_output(&unused, "unused=true");
    fixture.assert_output_redacted(&unused, &secret_ids);

    let wrong_primary_keyring = fixture.wrong_primary_keyring();
    let wrong_primary = fixture.observe_gateway_start(Some(&wrong_primary_keyring));
    assert_failed_before_listening(
        &wrong_primary,
        "a wrong current primary key must fail closed after re-encryption",
    );
    fixture.assert_output_redacted(&wrong_primary.output, &secret_ids);

    // Once the process-level unused check succeeds, the historical key can be
    // removed from the keyring and a fresh gateway process still starts.
    let current_only_keyring = fixture.new_primary_keyring();
    let current_only = fixture.observe_gateway_start(Some(&current_only_keyring));
    assert!(
        current_only.ready,
        "the gateway must restart with only the verified current key: {}",
        combined_output(&current_only.output)
    );
    fixture.assert_output_redacted(&current_only.output, &secret_ids);
    fixture.assert_plaintext_absent_from_ciphertext();
}

struct ProcessFixture {
    root: PathBuf,
    database: PathBuf,
}

impl ProcessFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-issue-240-process-{label}-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("temporary process-test root should create");
        set_directory_permissions(&root, 0o700);
        write_key(&root.join(OLD_KEY_FILE), &OLD_KEY);
        write_key(&root.join(NEW_KEY_FILE), &NEW_KEY);
        write_key(&root.join(WRONG_KEY_FILE), &WRONG_KEY);
        let database = root.join("connections-e2e11.sqlite");
        Self { root, database }
    }

    fn bootstrap_store(&self) {
        let output = self.run_cli(
            &self.old_primary_keyring(),
            &["connection-secrets", "reencrypt", "--batch-size", "1"],
        );
        assert_success_output(&output, "reencrypted=0 remaining=0");
        self.assert_output_redacted(&output, &[]);
    }

    fn seed_historical_secrets(&self, count: usize) -> Vec<String> {
        let connection =
            Connection::open(&self.database).expect("migrated Connections database should open");
        let timestamp = "2026-07-29T00:00:00Z";
        let cipher = XChaCha20Poly1305::new_from_slice(&OLD_KEY)
            .expect("fixture key length should be valid");
        let mut ids = Vec::with_capacity(count);

        for index in 0..count {
            let id = Uuid::new_v4().to_string();
            let version = 1_u64;
            let aad = canonical_aad(&id, version, "static_bearer");
            let nonce = [u8::try_from(index + 1).expect("fixture nonce index should fit"); 24];
            let ciphertext = cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: SECRET_MATERIAL,
                        aad: &aad,
                    },
                )
                .expect("fixture encryption should succeed");
            connection
                .execute(
                    r#"
                    INSERT INTO connection_local_secrets (
                        id, schema_version, label, purpose, secret_version, algorithm,
                        key_id, nonce, ciphertext, created_at, rotated_at, updated_at
                    ) VALUES (?1, 1, ?2, 'static_bearer', ?3, 'xchacha20poly1305',
                              ?4, ?5, ?6, ?7, NULL, ?7)
                    "#,
                    params![
                        id,
                        format!("process secret label canary {index}"),
                        i64::try_from(version).expect("fixture version should fit"),
                        OLD_KEY_ID,
                        nonce.as_slice(),
                        ciphertext,
                        timestamp,
                    ],
                )
                .expect("encrypted fixture row should insert");
            ids.push(id);
        }

        ids
    }

    fn old_primary_keyring(&self) -> String {
        keyring_json(&[(OLD_KEY_ID, OLD_KEY_FILE, "primary")])
    }

    fn new_primary_keyring(&self) -> String {
        keyring_json(&[(NEW_KEY_ID, NEW_KEY_FILE, "primary")])
    }

    fn rotating_keyring(&self) -> String {
        keyring_json(&[
            (NEW_KEY_ID, NEW_KEY_FILE, "primary"),
            (OLD_KEY_ID, OLD_KEY_FILE, "decrypt_only"),
        ])
    }

    fn wrong_decrypt_only_keyring(&self) -> String {
        keyring_json(&[
            (NEW_KEY_ID, NEW_KEY_FILE, "primary"),
            (OLD_KEY_ID, WRONG_KEY_FILE, "decrypt_only"),
        ])
    }

    fn wrong_primary_keyring(&self) -> String {
        keyring_json(&[
            (NEW_KEY_ID, WRONG_KEY_FILE, "primary"),
            (OLD_KEY_ID, OLD_KEY_FILE, "decrypt_only"),
        ])
    }

    fn command(&self, keyring: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gateway"));
        command
            .env_clear()
            .env("CONNECTIONS_SQLITE_PATH", &self.database)
            .env("CONNECTION_SECRETS_ROOT", &self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        preserve_platform_process_environment(&mut command);
        if let Some(keyring) = keyring {
            command.env("CONNECTION_LOCAL_SECRET_KEYRING", keyring);
        }
        command
    }

    fn run_cli(&self, keyring: &str, arguments: &[&str]) -> Output {
        let mut command = self.command(Some(keyring));
        command.args(arguments);
        run_to_completion(command, PROCESS_TIMEOUT)
    }

    fn observe_gateway_start(&self, keyring: Option<&str>) -> ObservedStart {
        let listen_addr = unused_loopback_address();
        let mut command = self.command(keyring);
        command
            .env("LISTEN_ADDR", listen_addr.to_string())
            .env("AUTH_ENABLED", "false")
            .env("CSRF_ENABLED", "false")
            .env("SHUTDOWN_DRAIN_DELAY_MS", "0")
            .env("SHUTDOWN_TIMEOUT_MS", "1000")
            .env("AUDIT_DRAIN_TIMEOUT_MS", "1000");
        let mut process = ManagedChild::spawn(command);
        let deadline = Instant::now() + PROCESS_TIMEOUT;

        loop {
            if process
                .try_wait()
                .expect("gateway subprocess status should be readable")
                .is_some()
            {
                return ObservedStart {
                    ready: false,
                    output: process.finish(),
                };
            }
            if TcpStream::connect(listen_addr).is_ok() {
                return ObservedStart {
                    ready: true,
                    output: process.terminate(),
                };
            }
            if Instant::now() >= deadline {
                let output = process.terminate();
                panic!(
                    "gateway subprocess did not start or fail before the deadline: {}",
                    combined_output(&output)
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn assert_key_usage(&self, old: usize, new: usize) {
        let connection =
            Connection::open(&self.database).expect("Connections database should reopen");
        let count_for = |key_id: &str| -> usize {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM connection_local_secrets WHERE key_id = ?1",
                    params![key_id],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| usize::try_from(count).expect("fixture count should fit"))
                .expect("fixture key usage should query")
        };
        assert_eq!(count_for(OLD_KEY_ID), old);
        assert_eq!(count_for(NEW_KEY_ID), new);
    }

    fn assert_plaintext_absent_from_ciphertext(&self) {
        let connection =
            Connection::open(&self.database).expect("Connections database should reopen");
        let mut statement = connection
            .prepare("SELECT ciphertext FROM connection_local_secrets")
            .expect("ciphertext query should prepare");
        let ciphertexts = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("ciphertext query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("ciphertext rows should decode");
        assert!(ciphertexts.iter().all(|ciphertext| {
            !ciphertext
                .windows(SECRET_MATERIAL.len())
                .any(|window| window == SECRET_MATERIAL)
        }));
    }

    fn assert_output_redacted(&self, output: &Output, secret_ids: &[String]) {
        let combined = combined_output(output);
        let root = self.root.to_string_lossy();
        let database = self.database.to_string_lossy();
        let escaped_root =
            serde_json::to_string(root.as_ref()).expect("root locator should JSON encode");
        let escaped_database =
            serde_json::to_string(database.as_ref()).expect("database locator should JSON encode");
        let secret_material = String::from_utf8_lossy(SECRET_MATERIAL);
        let old_material = String::from_utf8_lossy(&OLD_KEY);
        let new_material = String::from_utf8_lossy(&NEW_KEY);
        let wrong_material = String::from_utf8_lossy(&WRONG_KEY);
        let root_name = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture root should have a Unicode basename");

        let mut forbidden = vec![
            OLD_KEY_ID,
            NEW_KEY_ID,
            OLD_KEY_FILE,
            NEW_KEY_FILE,
            WRONG_KEY_FILE,
            "connections-e2e11.sqlite",
            "process secret label canary",
            secret_material.as_ref(),
            old_material.as_ref(),
            new_material.as_ref(),
            wrong_material.as_ref(),
            root.as_ref(),
            database.as_ref(),
            escaped_root.as_str(),
            escaped_database.as_str(),
            root_name,
        ];
        forbidden.extend(secret_ids.iter().map(String::as_str));

        for value in forbidden {
            assert!(
                !combined.contains(value),
                "gateway process output leaked forbidden fixture data `{value}`: {combined}"
            );
        }
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        let safe_parent = self.root.parent() == Some(std::env::temp_dir().as_path());
        let safe_name = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("greengateway-issue-240-process-"));
        if safe_parent && safe_name {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct ObservedStart {
    ready: bool,
    output: Output,
}

struct ManagedChild(Option<Child>);

impl ManagedChild {
    fn spawn(mut command: Command) -> Self {
        let child = command
            .spawn()
            .expect("gateway subprocess should be spawnable");
        Self(Some(child))
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.0
            .as_mut()
            .expect("managed child should exist")
            .try_wait()
    }

    fn finish(mut self) -> Output {
        self.0
            .take()
            .expect("managed child should exist")
            .wait_with_output()
            .expect("gateway subprocess output should collect")
    }

    fn terminate(mut self) -> Output {
        let mut child = self.0.take().expect("managed child should exist");
        let _ = child.kill();
        child
            .wait_with_output()
            .expect("terminated gateway subprocess output should collect")
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_to_completion(command: Command, timeout: Duration) -> Output {
    let mut process = ManagedChild::spawn(command);
    let deadline = Instant::now() + timeout;
    loop {
        if process
            .try_wait()
            .expect("gateway subprocess status should be readable")
            .is_some()
        {
            return process.finish();
        }
        if Instant::now() >= deadline {
            let output = process.terminate();
            panic!(
                "gateway subprocess did not exit before the deadline: {}",
                combined_output(&output)
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn keyring_json(entries: &[(&str, &str, &str)]) -> String {
    serde_json::to_string(
        &entries
            .iter()
            .map(|(id, file, role)| json!({"id": id, "file": file, "role": role}))
            .collect::<Vec<_>>(),
    )
    .expect("fixture keyring should serialize")
}

fn canonical_aad(id: &str, version: u64, purpose: &str) -> Vec<u8> {
    let uuid = Uuid::parse_str(id).expect("fixture secret ID should be a UUID");
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"greengateway.local-secret");
    aad.push(0);
    aad.extend_from_slice(&1_u32.to_be_bytes());
    aad.extend_from_slice(uuid.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.push(u8::try_from(purpose.len()).expect("fixture purpose length should fit"));
    aad.extend_from_slice(purpose.as_bytes());
    aad.push(u8::try_from("material".len()).expect("fixture field purpose length should fit"));
    aad.extend_from_slice(b"material");
    aad
}

fn assert_failed_before_listening(observed: &ObservedStart, context: &str) {
    assert!(!observed.ready, "{context}");
    assert!(
        !observed.output.status.success(),
        "{context}; process unexpectedly exited successfully: {}",
        combined_output(&observed.output)
    );
}

fn assert_success_output(output: &Output, expected: &str) {
    assert!(
        output.status.success(),
        "gateway maintenance command failed: {}",
        combined_output(output)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim_end(), expected);
    assert!(
        output.stderr.is_empty(),
        "successful maintenance command wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn combined_output(output: &Output) -> String {
    format!(
        "stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn unused_loopback_address() -> std::net::SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback listener should bind")
        .local_addr()
        .expect("loopback address should be available")
}

fn write_key(path: &Path, material: &[u8; 32]) {
    fs::write(path, material).expect("fixture key should write");
    set_file_permissions(path, 0o600);
}

#[cfg(windows)]
fn preserve_platform_process_environment(command: &mut Command) {
    // Winsock providers are loaded from the Windows system directory. Keep
    // only the platform locators needed to initialize networking after
    // env_clear; GreenGateway configuration remains fully controlled.
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(not(windows))]
fn preserve_platform_process_environment(_: &mut Command) {}

#[cfg(unix)]
fn set_directory_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("fixture directory permissions should set");
}

#[cfg(not(unix))]
fn set_directory_permissions(_: &Path, _: u32) {}

#[cfg(unix)]
fn set_file_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("fixture key permissions should set");
}

#[cfg(not(unix))]
fn set_file_permissions(_: &Path, _: u32) {}
