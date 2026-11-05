use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead as _, BufReader, Read as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        mpsc::{self, Receiver},
        Arc, Barrier,
    },
    time::Duration,
};

use super::filesystem::{linux_kind, macos_kind};
use super::*;
use crate::catalog::{BundleMapping, FIELDS};
use crate::ledger::LEDGER_FILE_NAME;

/// A directory name that must never reach an error.
const CANARY: &str = "zqcanary";

// --- fixtures -------------------------------------------------------------------

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    /// A new directory, owner-only on Unix, with the canary in its name.
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-state-{CANARY}-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("temporary directory should create");
        #[cfg(unix)]
        set_mode(&path, 0o700);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn lock_file(&self) -> PathBuf {
        self.0.join(LOCK_FILE_NAME)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

fn acquire(path: &Path) -> Result<StateDirectory, StateDirError> {
    StateDirectory::acquire(path)
}

fn refusal(result: Result<StateDirectory, StateDirError>) -> StateDirError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected a refusal, the state directory was acquired"),
    }
}

fn repository_text(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate should live under the repository root");
    fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
        .replace("\r\n", "\n")
}

// --- layout -----------------------------------------------------------------------

#[test]
fn every_name_in_the_layout_is_distinct_portable_and_stable() {
    let mut names = BTreeSet::new();
    for file in StateFile::ALL {
        let name = file.file_name();
        assert!(
            name.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
                && name.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-')),
            "{name}"
        );
        assert!(name.ends_with(".sqlite3"), "{name}");
        // SQLite's companions belong to the store; no other name may be one.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            assert!(names.insert(format!("{name}{suffix}")), "{name}{suffix}");
        }
    }
    assert!(names.insert(LOCK_FILE_NAME.to_owned()));
    assert_eq!(StateFile::ConfigLedger.file_name(), LEDGER_FILE_NAME);

    // The names are a published contract: changing one strands a store.
    let pinned: Vec<_> = StateFile::ALL.iter().map(|file| file.file_name()).collect();
    assert_eq!(
        pinned,
        [
            "audit.sqlite3",
            "discovery.sqlite3",
            "principals.sqlite3",
            "connections.sqlite3",
            "service-tokens.sqlite3",
            "policy-history.sqlite3",
            "config-ledger.sqlite3",
        ]
    );
    assert_eq!(LOCK_FILE_NAME, "state.lock");
}

/// Every standalone store the field catalog replaces with a fixed file has
/// exactly one, and nothing else claims a catalog field.
#[test]
fn the_layout_covers_every_store_the_catalog_maps_to_a_fixed_file() {
    let catalog: BTreeSet<&str> = FIELDS
        .iter()
        .filter(|field| {
            field.bundle == BundleMapping::Resource && field.environment.ends_with("_SQLITE_PATH")
        })
        .map(|field| field.id)
        .collect();
    let layout: BTreeSet<&str> = StateFile::ALL
        .iter()
        .filter_map(|file| file.catalog_field())
        .collect();
    assert_eq!(layout, catalog);
    assert_eq!(
        layout.len(),
        StateFile::ALL.len() - 1,
        "only the ledger has no catalog field"
    );
    assert_eq!(StateFile::ConfigLedger.catalog_field(), None);
}

#[test]
fn the_layout_and_codes_are_documented() {
    let reference = repository_text("docs/configuration-bundles.md");
    for file in StateFile::ALL {
        assert!(
            reference.contains(&format!("`{}`", file.file_name())),
            "{} is not documented",
            file.file_name()
        );
        if let Some(field) = file.catalog_field() {
            let environment = FIELDS
                .iter()
                .find(|candidate| candidate.id == field)
                .map(|candidate| candidate.environment)
                .expect("a catalog field");
            assert!(
                reference.contains(&format!("`{environment}`")),
                "{environment} is not documented"
            );
        }
    }
    assert!(reference.contains(&format!("`{LOCK_FILE_NAME}`")));
    for code in all_errors()
        .iter()
        .map(StateDirError::code)
        .chain([NETWORK_FILESYSTEM_CODE])
    {
        assert!(
            reference.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
}

#[test]
fn a_held_directory_names_its_files_beneath_its_absolute_path() {
    let state = TempDir::new("layout");
    let held = acquire(state.path()).expect("acquire");
    assert!(held.path().is_absolute());
    assert_eq!(held.path(), state.path());
    for file in StateFile::ALL {
        assert_eq!(held.file(file), state.path().join(file.file_name()));
    }
    // Acquiring creates the lock file and nothing else.
    let names: Vec<_> = fs::read_dir(state.path())
        .expect("state directory")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(names, [LOCK_FILE_NAME]);
    // No path reaches Debug output.
    assert!(!format!("{held:?}").contains(CANARY));
}

// --- the lock -----------------------------------------------------------------

#[test]
fn a_second_handle_in_this_process_is_refused_until_every_clone_drops() {
    let state = TempDir::new("one-process");
    let first = acquire(state.path()).expect("the first handle wins");
    assert_eq!(refusal(acquire(state.path())), StateDirError::Locked);

    // A clone shares the lock: dropping the original does not release it.
    let clone = first.clone();
    drop(first);
    assert_eq!(refusal(acquire(state.path())), StateDirError::Locked);

    drop(clone);
    let again = acquire(state.path()).expect("released once every clone dropped");
    drop(again);
    acquire(state.path()).expect("released on drop each time");
}

#[test]
fn threads_racing_for_the_lock_have_exactly_one_winner() {
    const CONTENDERS: usize = 8;
    let state = TempDir::new("race");
    let start = Arc::new(Barrier::new(CONTENDERS));
    let contenders: Vec<_> = (0..CONTENDERS)
        .map(|_| {
            let path = state.path().to_path_buf();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                acquire(&path)
            })
        })
        .collect();
    // Join every thread before any handle drops, so a winner cannot release
    // the lock to a later contender.
    let results: Vec<_> = contenders
        .into_iter()
        .map(|contender| contender.join().expect("the contender should not panic"))
        .collect();
    let winners = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(winners, 1);
    for result in &results {
        if let Err(error) = result {
            assert_eq!(error, &StateDirError::Locked);
        }
    }
}

#[test]
fn the_lock_file_is_kept_and_never_truncated() {
    let state = TempDir::new("kept");
    // Whatever is in an existing lock file stays there: it is never read or
    // written.
    fs::write(state.lock_file(), b"left by an older release").expect("lock file");
    #[cfg(unix)]
    set_mode(&state.lock_file(), 0o600);
    drop(acquire(state.path()).expect("acquire"));
    assert_eq!(
        fs::read(state.lock_file()).expect("the lock file remains"),
        b"left by an older release"
    );
    acquire(state.path()).expect("the kept lock file locks again");
}

#[cfg(unix)]
#[test]
fn a_new_lock_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let state = TempDir::new("mode");
    drop(acquire(state.path()).expect("acquire"));
    let mode = fs::metadata(state.lock_file())
        .expect("lock file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}

// --- two processes ------------------------------------------------------------

/// Where the child process side of the two-process tests finds its state
/// directory. Set only on the test binary these tests spawn.
const CHILD_DIRECTORY: &str = "GREENGATEWAY_TEST_STATE_DIR_CHILD";
/// Set when the child holds what it acquired until its standard input ends.
const CHILD_HOLDS: &str = "GREENGATEWAY_TEST_STATE_DIR_CHILD_HOLDS";
const CHILD_TEST: &str = "state_dir::tests::the_child_process_side_of_the_lock_tests";
const VERDICT: &str = "state-dir-lock: ";

/// The child process side of the two-process tests: run by itself, with
/// [`CHILD_DIRECTORY`] unset, it does nothing.
#[test]
fn the_child_process_side_of_the_lock_tests() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let held = acquire(Path::new(&directory));
    let verdict = match &held {
        Ok(_) => "acquired",
        Err(error) => error.code(),
    };
    println!("{VERDICT}{verdict}");
    if std::env::var_os(CHILD_HOLDS).is_some() {
        // Hold the lock, if this process won it, until the parent closes
        // standard input.
        let mut rest = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut rest);
    }
    drop(held);
}

/// This test binary, started again as a second process contending for one
/// state directory.
struct Contender {
    child: Child,
    verdicts: Receiver<String>,
}

impl Contender {
    fn start(directory: &Path, holds: bool) -> Self {
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads", "1"])
            .env(CHILD_DIRECTORY, directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if holds {
            command.env(CHILD_HOLDS, "1");
        }
        let mut child = command.spawn().expect("the test binary should start again");
        let output = child.stdout.take().expect("piped standard output");
        // Read on a thread, to the end, so the child never blocks writing and
        // a missing verdict fails the test instead of hanging it. The harness
        // prints the test's name on the line the verdict joins, so the
        // verdict is found anywhere in a line.
        let (sender, verdicts) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if let Some((_, verdict)) = line.split_once(VERDICT) {
                    let _ = sender.send(verdict.trim_end().to_owned());
                }
            }
        });
        Self { child, verdicts }
    }

    /// What the child reported: `acquired` or the refusal's code.
    fn verdict(&mut self) -> String {
        match self.verdicts.recv_timeout(Duration::from_secs(60)) {
            Ok(verdict) => verdict,
            Err(_) => {
                let _ = self.child.kill();
                panic!("the child reported no verdict");
            }
        }
    }

    /// Lets the child exit, releasing anything it holds, and checks that its
    /// side passed.
    fn finish(mut self) {
        drop(self.child.stdin.take());
        let status = self.child.wait().expect("the child should exit");
        assert!(status.success(), "the child failed: {status}");
    }
}

#[test]
fn another_process_is_refused_while_this_one_holds_the_lock() {
    let state = TempDir::new("two-processes");
    let held = acquire(state.path()).expect("this process wins");
    let mut child = Contender::start(state.path(), false);
    assert_eq!(child.verdict(), "state_dir.locked");
    child.finish();

    drop(held);
    let mut child = Contender::start(state.path(), false);
    assert_eq!(
        child.verdict(),
        "acquired",
        "released when this process dropped it"
    );
    child.finish();
}

#[test]
fn a_lock_another_process_holds_is_refused_here_until_it_exits() {
    let state = TempDir::new("held-elsewhere");
    let mut child = Contender::start(state.path(), true);
    assert_eq!(child.verdict(), "acquired");
    assert_eq!(refusal(acquire(state.path())), StateDirError::Locked);
    child.finish();
    acquire(state.path()).expect("released when the other process exited");
}

// --- admission -----------------------------------------------------------------

#[test]
fn missing_paths_and_non_directories_are_refused() {
    let state = TempDir::new("admission");
    assert_eq!(
        refusal(acquire(&state.path().join("absent"))),
        StateDirError::Missing
    );
    assert_eq!(refusal(acquire(Path::new(""))), StateDirError::Missing);
    let file = state.path().join("file");
    fs::write(&file, b"").expect("file should write");
    assert_eq!(refusal(acquire(&file)), StateDirError::NotDirectory);
}

#[test]
fn a_lock_file_that_is_not_a_regular_file_is_refused() {
    let state = TempDir::new("lock-directory");
    fs::create_dir(state.lock_file()).expect("directory should create");
    assert_eq!(
        refusal(acquire(state.path())),
        StateDirError::UnsafeLockFile
    );
}

#[cfg(unix)]
#[test]
fn group_or_other_writable_directories_are_refused() {
    let state = TempDir::new("unix-modes");
    for mode in [0o770, 0o720, 0o702, 0o777, 0o1777] {
        set_mode(state.path(), mode);
        assert_eq!(
            refusal(acquire(state.path())),
            StateDirError::UnsafePermissions,
            "{mode:o}"
        );
    }
    // Reading and searching by others is not writing.
    set_mode(state.path(), 0o755);
    acquire(state.path()).expect("a directory only its owner can write");
}

#[cfg(unix)]
#[test]
fn group_or_other_writable_lock_files_are_refused() {
    let state = TempDir::new("unix-lock-modes");
    drop(acquire(state.path()).expect("acquire"));
    for mode in [0o620, 0o602, 0o666] {
        set_mode(&state.lock_file(), mode);
        assert_eq!(
            refusal(acquire(state.path())),
            StateDirError::UnsafeLockFile,
            "{mode:o}"
        );
    }
    set_mode(&state.lock_file(), 0o644);
    acquire(state.path()).expect("a lock file only its owner can write");
}

/// A directory the process may not write is refused before anything is
/// locked: no lock file can be created in it.
#[cfg(unix)]
#[test]
fn a_directory_this_process_cannot_write_is_refused() {
    let state = TempDir::new("unix-read-only");
    set_mode(state.path(), 0o500);
    let privileged = fs::write(state.path().join("probe"), b"").is_ok();
    if !privileged {
        assert_eq!(
            refusal(acquire(state.path())),
            StateDirError::Unavailable {
                operation: "lock file open"
            }
        );
        assert!(!state.lock_file().exists());
    }
    // Root writes whatever the mode says; then only the cleanup matters.
    set_mode(state.path(), 0o700);
}

#[cfg(unix)]
#[test]
fn a_linked_directory_or_lock_file_is_refused() {
    use std::os::unix::fs::symlink;
    let state = TempDir::new("unix-links");
    let target = state.path().join("target");
    fs::create_dir(&target).expect("target directory");
    set_mode(&target, 0o700);
    let linked = state.path().join("linked");
    symlink(&target, &linked).expect("directory symlink");
    assert_eq!(refusal(acquire(&linked)), StateDirError::Link);
    assert!(!target.join(LOCK_FILE_NAME).exists());

    // A lock file linked elsewhere, even dangling, is refused, and the
    // link's target is never created.
    let elsewhere = state.path().join("elsewhere");
    symlink(&elsewhere, target.join(LOCK_FILE_NAME)).expect("lock file symlink");
    assert_eq!(refusal(acquire(&target)), StateDirError::UnsafeLockFile);
    assert!(!elsewhere.exists());
    fs::write(&elsewhere, b"").expect("link target");
    assert_eq!(refusal(acquire(&target)), StateDirError::UnsafeLockFile);
}

#[cfg(unix)]
#[test]
fn a_fifo_in_place_of_the_lock_file_is_refused_without_blocking() {
    let state = TempDir::new("unix-fifo");
    let status = Command::new("mkfifo")
        .arg(state.lock_file())
        .status()
        .expect("mkfifo should run");
    assert!(status.success());
    let path = state.path().to_path_buf();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(acquire(&path).map(|_| ()));
    });
    let acquired = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("acquiring must not block on a FIFO");
    assert_eq!(acquired, Err(StateDirError::UnsafeLockFile));
}

#[cfg(windows)]
fn create_junction(target: &Path, junction: &Path) {
    let output = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .output()
        .expect("the Windows command processor should start");
    assert!(output.status.success(), "the junction should create");
}

#[cfg(windows)]
#[test]
fn a_junction_directory_or_lock_file_is_refused() {
    let state = TempDir::new("windows-junctions");
    let target = state.path().join("target");
    fs::create_dir(&target).expect("target directory");
    let linked = state.path().join("linked");
    create_junction(&target, &linked);
    assert_eq!(refusal(acquire(&linked)), StateDirError::Link);
    assert!(!target.join(LOCK_FILE_NAME).exists());

    let elsewhere = state.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("junction target");
    create_junction(&elsewhere, &target.join(LOCK_FILE_NAME));
    assert_eq!(refusal(acquire(&target)), StateDirError::UnsafeLockFile);
}

#[cfg(windows)]
#[test]
#[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege"]
fn windows_symbolic_links_are_refused() {
    let state = TempDir::new("windows-symlinks");
    let target = state.path().join("target");
    fs::create_dir(&target).expect("target directory");
    let linked = state.path().join("linked");
    std::os::windows::fs::symlink_dir(&target, &linked)
        .expect("Windows symbolic-link privilege is required for this ignored test");
    assert_eq!(refusal(acquire(&linked)), StateDirError::Link);

    let elsewhere = state.path().join("elsewhere");
    fs::write(&elsewhere, b"").expect("link target");
    std::os::windows::fs::symlink_file(&elsewhere, target.join(LOCK_FILE_NAME))
        .expect("Windows symbolic-link privilege is required for this ignored test");
    assert_eq!(refusal(acquire(&target)), StateDirError::UnsafeLockFile);
}

// --- errors ---------------------------------------------------------------------

fn all_errors() -> [StateDirError; 8] {
    [
        StateDirError::Missing,
        StateDirError::NotDirectory,
        StateDirError::Link,
        StateDirError::UnsafePermissions,
        StateDirError::UnsafeLockFile,
        StateDirError::Locked,
        StateDirError::LockUnsupported,
        StateDirError::Unavailable {
            operation: "lock acquisition",
        },
    ]
}

#[test]
fn errors_are_value_free_and_stable() {
    let codes: Vec<_> = all_errors().iter().map(StateDirError::code).collect();
    assert_eq!(
        codes,
        [
            "state_dir.missing",
            "state_dir.not_directory",
            "state_dir.link",
            "state_dir.unsafe_permissions",
            "state_dir.unsafe_lock_file",
            "state_dir.locked",
            "state_dir.lock_unsupported",
            "state_dir.unavailable",
        ]
    );
    for error in all_errors() {
        let shown = error.to_string();
        assert!(!shown.is_empty() && !shown.ends_with('.'), "{shown}");
    }
    // A refusal names no path, even one it was given.
    let state = TempDir::new("value-free");
    let missing = refusal(acquire(&state.path().join(CANARY)));
    assert!(!format!("{missing} {missing:?}").contains(CANARY));
}

// --- network filesystems ----------------------------------------------------------

#[test]
fn network_filesystems_are_recognised_by_magic_number_and_type_name() {
    for magic in [0x6969, 0x517B, 0xFF53_4D42, 0xFE53_4D42, 0x0102_1997] {
        assert_eq!(linux_kind(magic), FilesystemKind::Network, "{magic:#x}");
    }
    // ext4, XFS, Btrfs, tmpfs, overlayfs and FUSE.
    for magic in [
        0xEF53,
        0x5846_5342,
        0x9123_683E,
        0x0102_1994,
        0x794C_7630,
        0x6573_5546,
    ] {
        assert_eq!(linux_kind(magic), FilesystemKind::Local, "{magic:#x}");
    }
    for name in [&b"nfs"[..], b"smbfs", b"afpfs", b"webdav", b"ftp"] {
        assert_eq!(macos_kind(name), FilesystemKind::Network);
    }
    for name in [&b"apfs"[..], b"hfs", b"msdos", b"NFS", b""] {
        assert_eq!(macos_kind(name), FilesystemKind::Local);
    }

    assert_eq!(
        FilesystemKind::Network.warning_code(),
        Some("state_dir.network_filesystem")
    );
    assert_eq!(FilesystemKind::Local.warning_code(), None);
    assert_eq!(FilesystemKind::Unchecked.warning_code(), None);
}

#[cfg(windows)]
#[test]
fn windows_unc_paths_are_network_filesystems() {
    use super::filesystem::windows_kind;
    for path in [r"\\server\share\state", r"\\?\UNC\server\share\state"] {
        assert_eq!(
            windows_kind(Path::new(path)),
            FilesystemKind::Network,
            "{path}"
        );
    }
    for path in [r"\\?\C:\state", r"C:\state"] {
        assert_eq!(
            windows_kind(Path::new(path)),
            FilesystemKind::Local,
            "{path}"
        );
    }
}

/// The check runs for real where the platform has one, and a directory it
/// cannot examine is unchecked rather than an error. The runners' temporary
/// directories are local disks.
#[test]
fn the_check_examines_a_real_directory_and_never_fails() {
    let state = TempDir::new("filesystem");
    let held = acquire(state.path()).expect("acquire");
    let expected = if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        FilesystemKind::Local
    } else {
        FilesystemKind::Unchecked
    };
    assert_eq!(held.filesystem(), expected);
    assert_eq!(filesystem_kind(state.path()), expected);
    assert_eq!(
        filesystem_kind(&state.path().join("absent")),
        FilesystemKind::Unchecked
    );
}
