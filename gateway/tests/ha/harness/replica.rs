//! One real gateway process.
//!
//! Not an in-process router: `CARGO_BIN_EXE_gateway`, spawned with an
//! environment, holding its own PostgreSQL pool, running its own
//! membership heartbeat. Everything the cluster suites assert about
//! crash, restart, fencing and partition needs a process that can actually
//! be killed.
//!
//! **Ports.** Every replica is started with `LISTEN_ADDR=127.0.0.1:0` and
//! the port it was given is read back from its own `gateway.startup` audit
//! record (with its stdout as a fallback). The harness therefore never
//! binds a port, frees it, and hands the number to a child — the race that
//! made `tests/lifecycle_shutdown.rs` need a startup mutex, and that this
//! machine loses regularly.
//!
//! **Discovery is scoped to the boot that is running.** The audit sink
//! *appends*, and the captured output accumulates, so a restarted replica's
//! file still holds the previous boot's `gateway.startup` record. Every
//! launch therefore records how many startup records and how many bytes of
//! output preceded it, and discovery ignores both — otherwise a restart
//! would "succeed" instantly by reading the dead port back. The discovered
//! address is then confirmed by connecting to it, so no wait here can
//! return without the new listener having actually been observed.
//!
//! **Stopping.** [`Replica::stop`] is the drain path on every platform:
//! `SIGTERM` on unix, `Ctrl+Break` on Windows, where each replica is
//! spawned in its own process group so the console event can be addressed
//! at it alone. A replica that does not exit within [`STOP_BUDGET`] fails
//! the test rather than being quietly killed, because the rows that call
//! `stop` are the rows about draining.
//!
//! **Cleanup.** `Drop` kills the process and reaps it, so a panicking test
//! cannot leave a gateway holding a database connection or a port. On
//! Windows every replica is also placed in a kill-on-close job object the
//! moment it is spawned, so a test *runner* that dies (and never runs
//! `Drop`) cannot leave one behind either — the process group that makes
//! Ctrl+Break addressable also stops the console's Ctrl+C from reaching
//! the replicas, and the job is what stands in for it.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;

/// How long a replica may take to bind its listener. Generous: a cold
/// start opens a pool, validates the schema, and writes a membership row,
/// on a machine that may be running other builds.
pub const LISTEN_BUDGET: Duration = Duration::from_secs(90);
/// How long a replica may take to answer `/readyz` with `200` once it is
/// listening. Covers at least one membership heartbeat.
pub const READY_BUDGET: Duration = Duration::from_secs(90);
/// How long a replica may take to exit once [`Replica::stop`] has asked
/// it to. The harness pins `SHUTDOWN_DRAIN_DELAY_MS=0` and
/// `SHUTDOWN_TIMEOUT_MS=5000`, so a clean shutdown is seconds; the rest is
/// headroom for a machine running other builds, not for the product.
pub const STOP_BUDGET: Duration = Duration::from_secs(30);

pub struct Replica {
    /// `a`, `b`, ... — the value this replica injects as
    /// `x-ha-replica`, and the name the balancer pins on.
    pub name: String,
    binary: PathBuf,
    env: Vec<(String, String)>,
    audit_path: PathBuf,
    addr: Option<SocketAddr>,
    child: Option<Child>,
    output: Arc<Mutex<String>>,
    pumps: Vec<std::thread::JoinHandle<()>>,
    /// How many `gateway.startup` records the audit file already held when
    /// the current process was launched: everything discovery must skip.
    startup_records_before_launch: usize,
    /// How many bytes of captured output preceded the current process, for
    /// the same reason.
    output_bytes_before_launch: usize,
}

impl Replica {
    /// Spawn the process. The listener is not up yet; call
    /// [`Replica::wait_until_listening`].
    pub fn spawn(
        name: &str,
        binary: &std::path::Path,
        env: Vec<(String, String)>,
        audit_path: PathBuf,
    ) -> Self {
        let mut replica = Self {
            name: name.to_owned(),
            binary: binary.to_owned(),
            env,
            audit_path,
            addr: None,
            child: None,
            output: Arc::new(Mutex::new(String::new())),
            pumps: Vec::new(),
            startup_records_before_launch: 0,
            output_bytes_before_launch: 0,
        };
        replica.launch();
        replica
    }

    fn launch(&mut self) {
        // The previous boot's readers first: they are finished as soon as
        // the old process closed its pipes, and joining them here means the
        // byte offset taken below cannot be overtaken by a line the DEAD
        // process wrote. (On a first launch there are none.)
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
        self.startup_records_before_launch = self.startup_record_count();
        self.output_bytes_before_launch = self.captured_output().len();
        let mut command = Command::new(&self.binary);
        command.env_clear();
        // A cleared environment is the point — an ambient `AUTH_ENABLED`
        // or `DEPLOYMENT_ID` on a developer's shell must not reach the
        // replica, and neither must the locator, which would let the
        // replica reach a database the harness did not give it. The
        // platform variables below are not configuration: without them a
        // Windows child cannot initialize its socket library at all.
        for key in super::INHERITED_ENVIRONMENT {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        #[cfg(windows)]
        {
            // Its own process group, so that `stop` can address a
            // Ctrl+Break at this replica and nothing else (see
            // `send_ctrl_break`). The console's own Ctrl+C no longer
            // reaches a replica either: `Drop` takes it down when a test
            // is interrupted, and the job object below takes it down when
            // the runner itself dies and `Drop` never runs.
            use std::os::windows::process::CommandExt;
            command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the gateway binary should start");
        #[cfg(windows)]
        if let Err(error) = job::adopt(&child) {
            // A replica the job will not own is a replica this runner
            // cannot promise to clean up; kill it now rather than run a
            // test whose failure could leave it holding the database.
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "replica {} could not be assigned to the harness's job object, so a runner \
                 that died would orphan it: {error}",
                self.name
            );
        }
        if let Some(stream) = child.stdout.take() {
            self.pumps.push(pump(stream, Arc::clone(&self.output)));
        }
        if let Some(stream) = child.stderr.take() {
            self.pumps.push(pump(stream, Arc::clone(&self.output)));
        }
        self.child = Some(child);
        self.addr = None;
    }

    /// The address this replica bound, once discovered.
    pub fn addr(&self) -> SocketAddr {
        self.addr
            .unwrap_or_else(|| panic!("replica {} has not bound a listener yet", self.name))
    }

    /// The address, or `None` when the replica is stopped or has not
    /// bound one yet. Used to keep the balancer's rotation honest.
    pub fn addr_if_bound(&self) -> Option<SocketAddr> {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr())
    }

    pub fn audit_path(&self) -> &std::path::Path {
        &self.audit_path
    }

    /// Everything the process has written to stdout and stderr so far.
    /// The secret-leak suite greps this; every other suite uses it to make
    /// a failure message say why the replica did not come up.
    pub fn captured_output(&self) -> String {
        self.output
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The replica's durable audit records, parsed. Lines that are not yet
    /// complete JSON (a record being written as this reads) are skipped.
    pub fn audit_events(&self) -> Vec<Value> {
        let Ok(contents) = std::fs::read_to_string(&self.audit_path) else {
            return Vec::new();
        };
        contents
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }

    /// Everything the CURRENT process has written, with the output of any
    /// previous boot of this replica trimmed off.
    pub fn output_since_launch(&self) -> String {
        let output = self.captured_output();
        match output.get(self.output_bytes_before_launch..) {
            Some(tail) => tail.to_owned(),
            // A boundary that is not a character boundary can only mean the
            // buffer was rewritten under us; the whole of it is still a
            // correct (if noisier) answer.
            None => output,
        }
    }

    fn startup_record_count(&self) -> usize {
        self.audit_events()
            .iter()
            .filter(|event| event["event_type"] == "gateway.startup")
            .count()
    }

    /// Poll until the process reports the port it bound, then connect to it.
    ///
    /// The authority is the replica's own `gateway.startup` audit record,
    /// which carries `listen_addr` and is flushed as it is written; the
    /// startup log line is a fallback for a configuration that has no file
    /// sink. Both are read only from the current boot onwards — the audit
    /// sink appends, so a restarted replica's file still names the port the
    /// dead process had, and returning that would be a wait that observed
    /// nothing. The address is then confirmed by opening a connection to
    /// it, which is the observation the caller is really waiting for.
    ///
    /// A process that exits while we wait fails here with its own output
    /// rather than later as a refused connection.
    pub async fn wait_until_listening(&mut self, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        let addr = loop {
            self.assert_still_running("while waiting for its listener");
            if let Some(addr) = self.discover_addr() {
                break addr;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "replica {} did not bind a listener within {budget:?}\n--- output ---\n{}",
                self.name,
                self.output_since_launch()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        loop {
            self.assert_still_running("while connecting to its listener");
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                self.addr = Some(addr);
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "replica {} announced {addr} but never accepted a connection there within \
                 {budget:?}\n--- output ---\n{}",
                self.name,
                self.output_since_launch()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn discover_addr(&self) -> Option<SocketAddr> {
        let mut startup_records_seen = 0_usize;
        for event in self.audit_events() {
            if event["event_type"] != "gateway.startup" {
                continue;
            }
            startup_records_seen += 1;
            if startup_records_seen <= self.startup_records_before_launch {
                continue;
            }
            if let Some(text) = event["payload"]["listen_addr"].as_str() {
                if let Ok(addr) = text.parse() {
                    return Some(addr);
                }
            }
        }
        let output = self.output_since_launch();
        for line in output.lines() {
            if !line.contains("gateway listening") && !line.contains("data listener listening") {
                continue;
            }
            let Some(start) = line.find("listen_addr=") else {
                continue;
            };
            let rest = &line[start + "listen_addr=".len()..];
            let end = rest
                .find(|character: char| character.is_whitespace())
                .unwrap_or(rest.len());
            if let Ok(addr) = rest[..end].parse() {
                return Some(addr);
            }
        }
        None
    }

    fn assert_still_running(&mut self, context: &str) {
        let Some(child) = self.child.as_mut() else {
            panic!("replica {} is not running {context}", self.name);
        };
        if let Some(status) = child
            .try_wait()
            .expect("the gateway process status should be readable")
        {
            panic!(
                "replica {} exited ({status}) {context}\n--- output ---\n{}",
                self.name,
                self.output_since_launch()
            );
        }
    }

    /// `GET /readyz`, decoded.
    pub async fn readyz(&self) -> (u16, Value) {
        self.probe("/readyz").await
    }

    pub async fn livez(&self) -> (u16, Value) {
        self.probe("/livez").await
    }

    async fn probe(&self, path: &str) -> (u16, Value) {
        let response = super::http_client()
            .get(format!("{}{path}", self.base_url()))
            .send()
            .await
            .unwrap_or_else(|error| panic!("replica {} did not answer {path}: {error}", self.name));
        let status = response.status().as_u16();
        let body = response.bytes().await.unwrap_or_default();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// Poll `/readyz` until it answers `200`.
    ///
    /// A bounded poll on an observable condition, never a sleep: in
    /// cluster mode readiness waits on a membership heartbeat, and how
    /// many heartbeats that takes is not the test's business.
    pub async fn wait_until_ready(&mut self, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        loop {
            self.assert_still_running("while waiting for readiness");
            let (status, body) = self.readyz().await;
            if status == 200 {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "replica {} was not ready within {budget:?}; last /readyz said {body}\n--- output ---\n{}",
                self.name,
                self.captured_output()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Poll `/readyz` until it answers `503` with this reason.
    pub async fn wait_until_not_ready(&mut self, reason: &str, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        loop {
            let (status, body) = self.readyz().await;
            if status == 503 && body["reason"] == reason {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "replica {} never reported {reason} within {budget:?}; last /readyz said {body}",
                self.name
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub fn process_id(&self) -> u32 {
        self.child
            .as_ref()
            .map(Child::id)
            .unwrap_or_else(|| panic!("replica {} is not running", self.name))
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => child
                .try_wait()
                .expect("the gateway process status should be readable")
                .is_none(),
            None => false,
        }
    }

    /// Ask the replica to shut down cleanly and wait for it to exit.
    ///
    /// This is the drain path the lifecycle tests pin, on every platform:
    /// `SIGTERM` on unix, `Ctrl+Break` on Windows. The gateway's
    /// `SystemShutdownSignals` listens for both and takes the same
    /// coordinated shutdown either way — readiness false, the shutdown
    /// records, the `draining_at` stamp, exit — so a suite that is *about*
    /// draining no longer needs to say `#[cfg(unix)]` for itself. Ctrl+Break
    /// rather than Ctrl+C because it is the one console event
    /// `GenerateConsoleCtrlEvent` can address at a single child, and the
    /// child was launched in its own process group to make it addressable.
    ///
    /// A replica that has not exited [`STOP_BUDGET`] after being asked is
    /// killed **and the test fails**. A hard kill leaves no draining stamp
    /// and no terminal audit record, so a row that carried on after one
    /// would be asserting a drain that never happened — and a drain that
    /// did not happen must not read as one that did.
    pub fn stop(&mut self) {
        let Some(child) = self.child.as_ref() else {
            self.kill();
            return;
        };
        #[cfg(unix)]
        {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(child.id().to_string())
                .status();
        }
        #[cfg(windows)]
        if let Err(error) = send_ctrl_break(child.id()) {
            // ERROR_INVALID_HANDLE is what a process with no console gets:
            // the event has nothing to travel through. Say so, because the
            // fix is to run the suite from a terminal, not to change it.
            let hint = if error.raw_os_error() == Some(6) {
                " (this test process is not attached to a console, so there is nothing to \
                 deliver the event through; run the suite from a terminal)"
            } else {
                ""
            };
            panic!(
                "replica {} could not be sent Ctrl+Break, so it cannot be drained here: \
                 {error}{hint}",
                self.name
            );
        }
        #[cfg(not(any(unix, windows)))]
        {
            panic!(
                "replica {} cannot be asked to shut down on this platform: the harness has no \
                 signal to send it",
                self.name
            );
        }
        self.wait_for_exit(STOP_BUDGET, "after being asked to shut down");
    }

    /// Kill the process outright — the crash the fencing rows need: no
    /// drain, no draining stamp, no lease release.
    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        self.addr = None;
    }

    /// Reap the process, or fail the test.
    ///
    /// The failure is deliberate and loud: past `budget` the process is
    /// killed so nothing leaks, and then the test panics with the
    /// process's own output, because "still running" here means the
    /// coordinated shutdown did not finish and no row may go on to claim
    /// that it did.
    fn wait_for_exit(&mut self, budget: Duration, context: &str) {
        let deadline = std::time::Instant::now() + budget;
        while let Some(child) = self.child.as_mut() {
            match child
                .try_wait()
                .expect("the gateway process status should be readable")
            {
                Some(_) => {
                    self.child = None;
                    self.addr = None;
                    return;
                }
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.child = None;
                    self.addr = None;
                    panic!(
                        "replica {} was still running {budget:?} {context}; it has been killed, \
                         which means it never drained\n--- output ---\n{}",
                        self.name,
                        self.output_since_launch()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Freeze the process without killing it: the partition-shaped fault
    /// where a replica still holds its rows and its lease but stops making
    /// progress.
    ///
    /// Returns `false` on a platform with no such signal, and the pause
    /// tests skip rather than fail — Windows has no `SIGSTOP`, and
    /// suspending a process by thread there is not the same thing.
    #[must_use]
    pub fn pause(&self) -> bool {
        #[cfg(unix)]
        {
            let Some(child) = self.child.as_ref() else {
                return false;
            };
            return Command::new("kill")
                .arg("-STOP")
                .arg(child.id().to_string())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Undo [`Replica::pause`].
    pub fn resume(&self) -> bool {
        #[cfg(unix)]
        {
            let Some(child) = self.child.as_ref() else {
                return false;
            };
            return Command::new("kill")
                .arg("-CONT")
                .arg(child.id().to_string())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Start the process again with the same environment.
    ///
    /// It gets a fresh ephemeral port (and, by design, a fresh instance
    /// and boot ID), so a caller holding the old address must re-read
    /// [`Replica::addr`] — `Cluster::restart` does that and refreshes the
    /// balancer.
    pub async fn restart(&mut self) {
        self.relaunch();
        self.wait_until_listening(LISTEN_BUDGET).await;
    }

    /// Start the process again and return at once, without waiting for a
    /// listener.
    ///
    /// For the tests whose subject is a boot that must NOT come up — a
    /// replica started against a database it cannot reach, which has to
    /// exhaust its bounded startup retry and exit rather than retry
    /// forever. [`Replica::restart`] is the same launch plus the wait.
    pub fn relaunch(&mut self) {
        if self.is_running() {
            self.stop();
        }
        self.launch();
    }

    /// Poll until the process exits, and answer whether it did within
    /// `budget`. The process is left alone either way: a caller that wants
    /// it gone calls [`Replica::kill`].
    pub async fn wait_until_exited(&mut self, budget: Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        loop {
            if !self.is_running() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The environment this replica runs with, for a test that needs to
    /// assert what it was configured with.
    pub fn environment(&self) -> BTreeMap<String, String> {
        self.env.iter().cloned().collect()
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
    }
}

/// Deliver `CTRL_BREAK_EVENT` to the process group that `process_id` leads.
///
/// `GenerateConsoleCtrlEvent` addresses a process *group* on this console,
/// never a process, and takes `CTRL_C_EVENT` only for group `0` — every
/// process on the console, this test runner included. A child created with
/// `CREATE_NEW_PROCESS_GROUP` leads a group whose id is its own pid, so
/// `CTRL_BREAK_EVENT` addressed there reaches that replica and nothing
/// else. The gateway's lifecycle takes it as the request `SIGTERM` is.
///
/// Fails, rather than returning quietly, when this process has no console
/// to send it through: that is a harness that cannot drain, not a replica
/// that did.
#[cfg(windows)]
fn send_ctrl_break(process_id: u32) -> std::io::Result<()> {
    use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};

    // SAFETY: a kernel32 call taking two integers by value; it reads and
    // writes no memory this process owns.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process_id) };
    if sent == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The harness's kill-on-close job object: the Windows answer to "what
/// takes the gateways down when the test runner dies".
///
/// A replica is spawned with `CREATE_NEW_PROCESS_GROUP` (so that
/// [`send_ctrl_break`] can address it), and the price of that is the
/// console's own Ctrl+C no longer reaching it. `Drop` covers every exit
/// this process lives through — a panic, a failed assertion, a normal
/// return — but not a runner that is itself killed, and a gateway that
/// outlives its runner is a process holding a test database and a port
/// that nothing will ever reap. So every replica is assigned, right after
/// it is spawned, to one job object per test process whose only limit is
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The kernel closes that handle
/// when this process ends for any reason at all, and closing it
/// terminates every process still in the job.
///
/// One job per process rather than per cluster because the property
/// wanted is "nothing outlives the runner", and the runner is the
/// process. The handle is deliberately never closed by hand: its close
/// is the runner's exit.
#[cfg(windows)]
mod job {
    use std::{os::windows::io::AsRawHandle, process::Child, sync::OnceLock};

    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };

    /// The job's handle. A `HANDLE` is a raw pointer only in name — it is
    /// a kernel object index the process owns for its whole life and every
    /// thread may use — so the wrapper is `Send + Sync` for the `OnceLock`.
    struct Job(HANDLE);

    // SAFETY: see the type's documentation; the handle is an opaque
    // kernel object identifier, not memory, and the calls made with it
    // are all thread-safe by contract.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    /// Put `child` in the runner's job, creating the job on first use.
    pub fn adopt(child: &Child) -> std::io::Result<()> {
        static JOB: OnceLock<std::io::Result<Job>> = OnceLock::new();
        let job = match JOB.get_or_init(create) {
            Ok(job) => job,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("the harness's job object could not be created: {error}"),
                ))
            }
        };
        // SAFETY: both handles are valid for the duration of the call —
        // the job's for the life of the process, the child's for as long
        // as `child` is borrowed — and the call touches no memory of ours.
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) };
        if assigned == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn create() -> std::io::Result<Job> {
        // SAFETY: an anonymous job with default security; both pointer
        // arguments are documented as optional and are null here.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a zeroed `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` is the
        // "no limits" value the API documents; every field is an integer
        // or a plain struct of integers.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the pointer and length describe exactly the struct the
        // information class names, and the struct outlives the call.
        let set = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .expect("a job limit struct is smaller than 4 GiB"),
            )
        };
        if set == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Job(handle))
    }
}

fn pump(
    stream: impl Read + Send + 'static,
    sink: Arc<Mutex<String>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            let Ok(line) = line else { return };
            let mut sink = sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            sink.push_str(&line);
            sink.push('\n');
        }
    })
}
