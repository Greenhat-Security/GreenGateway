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
