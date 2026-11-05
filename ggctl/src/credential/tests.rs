use std::path::PathBuf;

use super::*;

const CANARY: &str = "gg-canary.token_7f3a9c+/~==";

struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, contents: &[u8]) -> Self {
        let directory =
            std::env::temp_dir().join(format!("ggctl-credential-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let path = directory.join("token");
        std::fs::write(&path, contents).expect("temp file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only mode");
        }
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(directory) = self.0.parent() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

#[test]
fn a_piped_token_is_accepted_with_at_most_one_line_ending() {
    for input in [
        CANARY.to_owned(),
        format!("{CANARY}\n"),
        format!("{CANARY}\r\n"),
    ] {
        let token = from_stdin(false, &mut input.as_bytes()).expect("valid token");
        assert_eq!(token.expose(), CANARY);
    }
}

#[test]
fn a_terminal_is_refused_before_anything_is_read() {
    let mut reader: &[u8] = CANARY.as_bytes();
    assert_eq!(
        from_stdin(true, &mut reader).map(|_| ()),
        Err(Code::StdinIsTerminal)
    );
    assert_eq!(reader.len(), CANARY.len(), "nothing was consumed");
}

#[test]
fn anything_but_one_bearer_token_is_refused() {
    for (input, code) in [
        ("", Code::CredentialEmpty),
        ("\n", Code::CredentialEmpty),
        ("two tokens", Code::CredentialInvalid),
        ("token\n\n", Code::CredentialInvalid),
        ("token\nsecond", Code::CredentialInvalid),
        ("tab\there", Code::CredentialInvalid),
        ("=leading", Code::CredentialInvalid),
        ("pad=ding", Code::CredentialInvalid),
        ("Bearer abc", Code::CredentialInvalid),
        ("caf\u{e9}", Code::CredentialInvalid),
        ("nul\0", Code::CredentialInvalid),
        ("\r", Code::CredentialInvalid),
    ] {
        assert_eq!(
            from_stdin(false, &mut input.as_bytes()).map(|_| ()),
            Err(code),
            "{input:?}"
        );
    }
    let large = "a".repeat(MAX_TOKEN_BYTES + 1);
    assert_eq!(
        from_stdin(false, &mut large.as_bytes()).map(|_| ()),
        Err(Code::CredentialTooLarge)
    );
    let largest = "a".repeat(MAX_TOKEN_BYTES);
    assert!(from_stdin(false, &mut largest.as_bytes()).is_ok());
}

#[test]
fn debug_never_shows_the_token() {
    let token = from_stdin(false, &mut CANARY.as_bytes()).expect("valid token");
    let debug = format!("{token:?}");
    assert_eq!(debug, "Token(<redacted>)");
    assert!(!debug.contains("canary"));
}

#[test]
fn a_token_file_is_read_when_regular_bounded_and_owner_only() {
    let file = TempFile::new("valid", format!("{CANARY}\n").as_bytes());
    assert_eq!(from_file(&file.0).expect("valid file").expose(), CANARY);

    let large = TempFile::new("large", "a".repeat(MAX_TOKEN_BYTES + 1).as_bytes());
    assert_eq!(
        from_file(&large.0).map(|_| ()),
        Err(Code::CredentialTooLarge)
    );

    let directory = TempFile::new("directory", b"x");
    let parent = directory.0.parent().expect("parent").to_owned();
    assert_eq!(
        from_file(&parent).map(|_| ()),
        Err(Code::CredentialNotRegularFile)
    );

    let missing = parent.join("missing");
    assert_eq!(
        from_file(&missing).map(|_| ()),
        Err(Code::CredentialUnreadable)
    );
}

#[cfg(unix)]
#[test]
fn a_token_file_readable_by_group_or_other_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    for mode in [0o640, 0o604, 0o660, 0o644, 0o606] {
        let file = TempFile::new(&format!("mode-{mode:o}"), CANARY.as_bytes());
        std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(mode)).expect("mode");
        assert_eq!(
            from_file(&file.0).map(|_| ()),
            Err(Code::CredentialUnsafePermissions),
            "{mode:o}"
        );
    }
    let file = TempFile::new("mode-400", CANARY.as_bytes());
    std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o400)).expect("mode");
    assert!(from_file(&file.0).is_ok());
}

#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_blocking_on_open() {
    let file = TempFile::new("fifo", b"");
    std::fs::remove_file(&file.0).expect("remove placeholder");
    let status = std::process::Command::new("mkfifo")
        .arg(&file.0)
        .status()
        .expect("mkfifo should run");
    assert!(status.success());
    assert_eq!(
        from_file(&file.0).map(|_| ()),
        Err(Code::CredentialNotRegularFile)
    );
}

/// A FIFO put in place of a checked path after the path check, with no
/// writer behind it: a blocking open would wait forever, before the handle
/// check could refuse it.
#[cfg(unix)]
#[test]
fn a_fifo_swapped_in_after_the_path_check_is_opened_without_blocking_and_refused() {
    let file = TempFile::new("swapped-fifo", b"");
    std::fs::remove_file(&file.0).expect("remove placeholder");
    let status = std::process::Command::new("mkfifo")
        .arg(&file.0)
        .status()
        .expect("mkfifo should run");
    assert!(status.success());

    let path = file.0.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let opened = open_without_blocking(&path).and_then(|file| file.metadata());
        let _ = sender.send(opened.map(|metadata| {
            check_metadata(&metadata, MAX_TOKEN_BYTES, FilePermissions::OwnerOnly)
        }));
    });
    let checked = receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("opening a FIFO without a writer must not block")
        .expect("the FIFO opens");
    assert_eq!(checked, Err(FileProblem::NotRegularFile));
}

#[cfg(unix)]
#[test]
fn a_handle_to_another_file_than_the_one_checked_is_refused() {
    let first = TempFile::new("identity-first", CANARY.as_bytes());
    let second = TempFile::new("identity-second", CANARY.as_bytes());
    let metadata = |path: &Path| std::fs::metadata(path).expect("metadata");
    // Held open, so the inode cannot be freed and reused below.
    let handle = File::open(&first.0).expect("open");
    let opened = handle.metadata().expect("handle metadata");
    assert_eq!(check_same_file(&metadata(&first.0), &opened), Ok(()));
    assert_eq!(
        check_same_file(&metadata(&second.0), &opened),
        Err(FileProblem::Unreadable)
    );
    // A replacement at the same path is another file.
    std::fs::remove_file(&first.0).expect("remove");
    std::fs::write(&first.0, CANARY).expect("replacement");
    assert_eq!(
        check_same_file(&metadata(&first.0), &opened),
        Err(FileProblem::Unreadable)
    );
}

/// The account that owns what a test creates, and an account that owns none
/// of it. Root may own anything a trust anchor's path resolves through, so a
/// test run as root first gives `entries` to an unprivileged account.
#[cfg(unix)]
fn owner_and_stranger(entries: &[&Path]) -> (u32, u32) {
    const UNPRIVILEGED: u32 = 65_534;
    let owner = if running_account() == 0 {
        for entry in entries {
            std::os::unix::fs::lchown(entry, Some(UNPRIVILEGED), None).expect("chown");
        }
        UNPRIVILEGED
    } else {
        running_account()
    };
    let stranger = if owner == 1 { 2 } else { 1 };
    (owner, stranger)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

/// An entry created directly in the system temporary directory, removed on
/// drop.
#[cfg(unix)]
struct TempEntry(PathBuf);

#[cfg(unix)]
impl TempEntry {
    fn path(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ggctl-credential-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

#[cfg(unix)]
impl Drop for TempEntry {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A sticky directory such as `/tmp` stops another account replacing an
/// entry, not creating the name first: a trust anchor someone else put there
/// is theirs to rewrite, whatever its mode.
#[cfg(unix)]
#[test]
fn a_trust_anchor_another_account_owns_is_refused_even_in_a_sticky_directory() {
    let file = TempEntry::path("owned.pem");
    std::fs::write(&file.0, CANARY).expect("write");
    set_mode(&file.0, 0o644);
    let (owner, stranger) = owner_and_stranger(&[&file.0]);
    let checked = std::fs::metadata(&file.0).expect("metadata");
    assert_eq!(check_resolution(&file.0, &checked, owner), Ok(()));
    assert_eq!(
        check_resolution(&file.0, &checked, stranger),
        Err(FileProblem::UnsafePermissions)
    );
}

/// The directories above the file and the links on its path count as much
/// as the file: whoever owns one can make the path resolve elsewhere.
#[cfg(unix)]
#[test]
fn every_entry_a_trust_anchor_path_resolves_through_must_be_owned_by_root_or_the_operator() {
    use std::os::unix::fs::symlink;

    let file = TempFile::new("owned-directory", CANARY.as_bytes());
    let directory = file.0.parent().expect("parent").to_owned();
    set_mode(&directory, 0o755);
    let (owner, stranger) = owner_and_stranger(&[&directory, &file.0]);
    let checked = std::fs::metadata(&file.0).expect("metadata");
    assert_eq!(check_resolution(&file.0, &checked, owner), Ok(()));
    assert_eq!(
        check_resolution(&file.0, &checked, stranger),
        Err(FileProblem::UnsafePermissions)
    );

    // A link the stranger made is refused even though everything it leads
    // to is root's: root's own `/` stands in for a root-owned file such as a
    // test CA a package installs.
    let link = TempEntry::path("owned-link");
    symlink("/", &link.0).expect("symlink");
    let (owner, stranger) = owner_and_stranger(&[&link.0]);
    // What the link leads to, examined without following it: Linux refuses
    // root to follow a link another account owns in a sticky directory.
    let checked = std::fs::metadata("/").expect("metadata");
    assert_eq!(check_resolution(&link.0, &checked, owner), Ok(()));
    assert_eq!(
        check_resolution(&link.0, &checked, stranger),
        Err(FileProblem::UnsafePermissions)
    );
}

/// A relative link target resolves in the directory holding the link, and
/// `..` in the physical parent, so the directory checked is the directory
/// read: here the one holding `sub`, not `sub` itself.
#[cfg(unix)]
#[test]
fn a_relative_link_and_dot_dot_resolve_where_the_kernel_resolves_them() {
    use std::os::unix::fs::symlink;

    let file = TempFile::new("relative-link", CANARY.as_bytes());
    let directory = file.0.parent().expect("parent").to_owned();
    let sub = directory.join("sub");
    std::fs::create_dir(&sub).expect("sub");
    let link = sub.join("link");
    symlink("../token", &link).expect("symlink");
    let (owner, _) = owner_and_stranger(&[&directory, &file.0, &sub, &link]);
    let checked = std::fs::metadata(&file.0).expect("metadata");
    set_mode(&directory, 0o755);
    set_mode(&sub, 0o755);
    assert_eq!(check_resolution(&link, &checked, owner), Ok(()));
    assert_eq!(
        check_resolution(&sub.join("..").join("token"), &checked, owner),
        Ok(())
    );
    // No write to `sub` changes what `..` in it is.
    set_mode(&sub, 0o777);
    assert_eq!(
        check_resolution(&sub.join("..").join("token"), &checked, owner),
        Ok(())
    );
    // `sub` holds the link, so it decides where the link leads.
    assert_eq!(
        check_resolution(&link, &checked, owner),
        Err(FileProblem::UnsafePermissions)
    );
    set_mode(&sub, 0o755);
    // The file is looked up in `directory`, wherever the path came from.
    set_mode(&directory, 0o777);
    assert_eq!(
        check_resolution(&link, &checked, owner),
        Err(FileProblem::UnsafePermissions)
    );
}

#[cfg(unix)]
#[test]
fn a_trust_anchor_path_that_resolves_to_another_file_than_the_one_checked_is_refused() {
    let first = TempFile::new("resolution-first", CANARY.as_bytes());
    let second = TempFile::new("resolution-second", CANARY.as_bytes());
    for file in [&first, &second] {
        set_mode(file.0.parent().expect("parent"), 0o755);
    }
    let (owner, _) = owner_and_stranger(&[
        first.0.parent().expect("parent"),
        &first.0,
        second.0.parent().expect("parent"),
        &second.0,
    ]);
    let checked = std::fs::metadata(&second.0).expect("metadata");
    assert_eq!(
        check_resolution(&first.0, &checked, owner),
        Err(FileProblem::Unreadable)
    );
}

/// A cycle of links is refused once more links than Linux follows were
/// followed, instead of looping.
#[cfg(unix)]
#[test]
fn a_cycle_of_links_is_refused() {
    use std::os::unix::fs::symlink;

    let file = TempFile::new("link-cycle", CANARY.as_bytes());
    let directory = file.0.parent().expect("parent").to_owned();
    set_mode(&directory, 0o755);
    symlink("b", directory.join("a")).expect("symlink");
    symlink("a", directory.join("b")).expect("symlink");
    let (owner, _) = owner_and_stranger(&[
        &directory,
        &file.0,
        &directory.join("a"),
        &directory.join("b"),
    ]);
    let checked = std::fs::metadata(&file.0).expect("metadata");
    assert_eq!(
        check_resolution(&directory.join("a"), &checked, owner),
        Err(FileProblem::Unreadable)
    );
}

/// Only a trust anchor's path is walked: the manifest `pin` compares is a
/// file the bundle reader already judged, directory and owner included, so
/// it is held to its mode alone.
#[cfg(unix)]
#[test]
fn only_a_trust_anchor_path_is_judged_beyond_the_file_mode() {
    let file = TempFile::new("mode-only", CANARY.as_bytes());
    let directory = file.0.parent().expect("parent").to_owned();
    set_mode(&file.0, 0o644);
    set_mode(&directory, 0o777);
    assert_eq!(
        read_regular_file(
            &file.0,
            MAX_TOKEN_BYTES,
            FilePermissions::NotWritableByOthers
        )
        .map(|bytes| bytes.len()),
        Ok(CANARY.len())
    );
    assert_eq!(
        read_regular_file(&file.0, MAX_TOKEN_BYTES, FilePermissions::TrustAnchor).map(|_| ()),
        Err(FileProblem::UnsafePermissions)
    );
}
