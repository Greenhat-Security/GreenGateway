//! Bearer-token input and bounded local file reads.
//!
//! A token never arrives on the command line (the parser refuses any option
//! that would carry one). It comes from a piped standard input
//! (`--token-stdin`) or from a regular, bounded, owner-only file
//! (`--token-file`), is held in memory that is zeroed on drop, has a redacted
//! `Debug`, and is checked against the RFC 6750 bearer-token grammar so a
//! stray newline, space or control character can never reach a header.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

use zeroize::Zeroizing;

use crate::diagnostic::Code;

/// The largest token accepted (ADR-0008, "Remote client").
pub(crate) const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// A bearer token. Its value is reachable only through [`Token::expose`].
pub(crate) struct Token(Zeroizing<String>);

impl Token {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token(<redacted>)")
    }
}

/// Reads a token from standard input, which must not be a terminal: a token
/// typed there is echoed to the screen and kept in scrollback, and `ggctl`
/// cannot read one hidden without a platform terminal dependency.
pub(crate) fn from_stdin(stdin_is_terminal: bool, stdin: &mut dyn Read) -> Result<Token, Code> {
    if stdin_is_terminal {
        return Err(Code::StdinIsTerminal);
    }
    let bytes = read_bounded(stdin, MAX_TOKEN_BYTES).map_err(|problem| match problem {
        Bounded::TooLarge => Code::CredentialTooLarge,
        Bounded::Failed => Code::CredentialUnreadable,
    })?;
    token(bytes)
}

/// Reads a token from a file: a regular file (a symbolic link to one is
/// followed, as mounted secrets use them), at most [`MAX_TOKEN_BYTES`] and,
/// on Unix, neither readable nor writable by group or other.
pub(crate) fn from_file(path: &Path) -> Result<Token, Code> {
    let bytes =
        read_regular_file(path, MAX_TOKEN_BYTES, true).map_err(|problem| match problem {
            FileProblem::Unreadable => Code::CredentialUnreadable,
            FileProblem::NotRegularFile => Code::CredentialNotRegularFile,
            FileProblem::TooLarge => Code::CredentialTooLarge,
            FileProblem::UnsafePermissions => Code::CredentialUnsafePermissions,
        })?;
    token(bytes)
}

/// Accepts exactly one bearer token, optionally followed by one line ending.
fn token(mut bytes: Zeroizing<Vec<u8>>) -> Result<Token, Code> {
    let ending = if bytes.ends_with(b"\r\n") {
        2
    } else {
        usize::from(bytes.ends_with(b"\n"))
    };
    let length = bytes.len() - ending;
    bytes.truncate(length);
    if bytes.is_empty() {
        return Err(Code::CredentialEmpty);
    }
    if !is_bearer_token(&bytes) {
        return Err(Code::CredentialInvalid);
    }
    // Validated ASCII, so the conversion takes the buffer without copying it.
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Token(Zeroizing::new(text))),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(Code::CredentialInvalid)
        }
    }
}

/// RFC 6750 `b64token`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_bearer_token(bytes: &[u8]) -> bool {
    let body = bytes
        .iter()
        .position(|&byte| byte == b'=')
        .unwrap_or(bytes.len());
    body > 0
        && bytes[..body].iter().all(|&byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && bytes[body..].iter().all(|&byte| byte == b'=')
}

/// Why a local file was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileProblem {
    Unreadable,
    NotRegularFile,
    TooLarge,
    UnsafePermissions,
}

/// Reads a whole regular file of at most `maximum` bytes into memory that is
/// zeroed on drop.
///
/// The path is checked before it is opened, so a FIFO or device is refused
/// rather than blocking on `open`, and the opened handle is checked again, so
/// a path swapped between the two is refused rather than read. With
/// `owner_only`, a Unix file whose mode grants group or other any access is
/// refused; Windows has no mode bits, and the file's ACL is left to the
/// operator.
pub(crate) fn read_regular_file(
    path: &Path,
    maximum: usize,
    owner_only: bool,
) -> Result<Zeroizing<Vec<u8>>, FileProblem> {
    let before = std::fs::metadata(path).map_err(|_| FileProblem::Unreadable)?;
    check_metadata(&before, maximum, owner_only)?;
    let mut file = File::open(path).map_err(|_| FileProblem::Unreadable)?;
    let opened = file.metadata().map_err(|_| FileProblem::Unreadable)?;
    check_metadata(&opened, maximum, owner_only)?;
    read_bounded(&mut file, maximum).map_err(|problem| match problem {
        Bounded::TooLarge => FileProblem::TooLarge,
        Bounded::Failed => FileProblem::Unreadable,
    })
}

fn check_metadata(
    metadata: &std::fs::Metadata,
    maximum: usize,
    owner_only: bool,
) -> Result<(), FileProblem> {
    if !metadata.is_file() {
        return Err(FileProblem::NotRegularFile);
    }
    if !usize::try_from(metadata.len()).is_ok_and(|length| length <= maximum) {
        return Err(FileProblem::TooLarge);
    }
    if owner_only && !permissions_are_owner_only(metadata) {
        return Err(FileProblem::UnsafePermissions);
    }
    Ok(())
}

#[cfg(unix)]
fn permissions_are_owner_only(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn permissions_are_owner_only(_metadata: &std::fs::Metadata) -> bool {
    true
}

enum Bounded {
    TooLarge,
    Failed,
}

/// Reads at most `maximum` bytes, refusing more. The buffer is allocated
/// once at its final capacity so no partial copy of a secret is left behind
/// in a freed allocation.
fn read_bounded(reader: &mut dyn Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>, Bounded> {
    let limit = u64::try_from(maximum).map_or(u64::MAX, |maximum| maximum.saturating_add(1));
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum.saturating_add(1)));
    match io::Read::take(reader, limit).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() > maximum => Err(Bounded::TooLarge),
        Ok(_) => Ok(bytes),
        Err(_) => Err(Bounded::Failed),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const CANARY: &str = "gg-canary.token_7f3a9c+/~==";

    struct TempFile(PathBuf);

    impl TempFile {
        fn new(name: &str, contents: &[u8]) -> Self {
            let directory = std::env::temp_dir()
                .join(format!("ggctl-credential-{}-{name}", std::process::id()));
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
}
