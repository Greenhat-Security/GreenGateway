//! Local documents a command reads: a policy document, a test suite, a
//! simulation request or an evidence package.
//!
//! A document is read whole and once, the way a token file is: a regular
//! file (a link to one is followed), bounded, opened without blocking and
//! checked to be the file the path check examined, so a FIFO or device is
//! never read and a path swapped between the checks is refused. A document
//! grants nothing and decides where nothing is sent, so its mode is not
//! checked. Its path is an argument and is never echoed: a refusal names the
//! argument's position.

use std::path::Path;

use serde::de::IgnoredAny;

use crate::{
    credential::{read_regular_file, FilePermissions, FileProblem},
    diagnostic::{Code, Diagnostic},
};

/// The largest document a policy command sends: the gateway's own request
/// body bound for the policy routes.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;

/// Reads the document at `path`, which the argument at position `argument`
/// names; a file larger than `maximum` is refused with `too_large`.
pub(crate) fn read(
    path: &Path,
    argument: usize,
    maximum: usize,
    too_large: Code,
) -> Result<Vec<u8>, Diagnostic> {
    match read_regular_file(path, maximum, FilePermissions::Unrestricted) {
        // A document is not a secret: the bytes leave the zeroing buffer.
        Ok(mut bytes) => Ok(std::mem::take(&mut *bytes)),
        Err(problem) => Err(Diagnostic::at(
            match problem {
                FileProblem::NotRegularFile => Code::InputNotRegularFile,
                FileProblem::TooLarge => too_large,
                // `Unrestricted` refuses no mode, so this is only a file
                // that could not be examined.
                FileProblem::Unreadable | FileProblem::UnsafePermissions => Code::InputUnreadable,
            },
            argument,
        )),
    }
}

/// Reads a document that must be exactly one JSON value in UTF-8, without a
/// byte-order mark, at most [`MAX_DOCUMENT_BYTES`]. Its bytes are returned
/// unchanged: a command sends them as they are.
pub(crate) fn read_json(path: &Path, argument: usize) -> Result<Vec<u8>, Diagnostic> {
    let bytes = read(path, argument, MAX_DOCUMENT_BYTES, Code::InputTooLarge)?;
    if !is_one_json_value(&bytes) {
        return Err(Diagnostic::at(Code::InputNotJson, argument));
    }
    Ok(bytes)
}

/// Whether `bytes` are UTF-8 holding exactly one JSON value and nothing but
/// whitespace around it.
pub(crate) fn is_one_json_value(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| serde_json::from_str::<IgnoredAny>(text).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of documents, removed on drop.
    struct Documents(std::path::PathBuf);

    impl Documents {
        fn new(name: &str) -> Self {
            let directory =
                std::env::temp_dir().join(format!("ggctl-input-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&directory).expect("directory");
            Self(directory)
        }

        fn write(&self, name: &str, contents: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, contents).expect("write");
            path
        }
    }

    impl Drop for Documents {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_json_document_is_returned_byte_for_byte() {
        let documents = Documents::new("json");
        let bytes = b" {\"b\": 1.0,  \"a\": [true, null]}\n";
        let path = documents.write("suite.json", bytes);
        assert_eq!(read_json(&path, 3).expect("valid"), bytes);
    }

    #[test]
    fn only_one_json_value_in_utf8_is_a_json_document() {
        for (bytes, valid) in [
            (&b"{}"[..], true),
            (b"[1, 2]", true),
            (b"\"text\"", true),
            (b"", false),
            (b"{} {}", false),
            (b"{\"a\": 1,}", false),
            (b"\xef\xbb\xbf{}", false),
            (b"{\"a\": \"\xff\"}", false),
            (b"not json", false),
        ] {
            assert_eq!(is_one_json_value(bytes), valid, "{bytes:?}");
        }
        let documents = Documents::new("not-json");
        let path = documents.write("cases.json", b"{\"cases\": [");
        let refused = read_json(&path, 4).expect_err("not JSON");
        assert_eq!(refused.code, Code::InputNotJson);
        assert_eq!(refused.argument, Some(4));
    }

    #[test]
    fn a_document_must_be_a_bounded_regular_file() {
        let documents = Documents::new("files");
        let large = documents.write("large.json", &vec![b' '; MAX_DOCUMENT_BYTES + 1]);
        assert_eq!(
            read_json(&large, 2).map(|_| ()),
            Err(Diagnostic::at(Code::InputTooLarge, 2))
        );
        let small = documents.write("small.json", b"{}");
        assert_eq!(
            read(&small, 2, 1, Code::EvidencePackageTooLarge).map(|_| ()),
            Err(Diagnostic::at(Code::EvidencePackageTooLarge, 2))
        );
        assert_eq!(
            read_json(&documents.0, 5).map(|_| ()),
            Err(Diagnostic::at(Code::InputNotRegularFile, 5))
        );
        assert_eq!(
            read_json(&documents.0.join("missing.json"), 6).map(|_| ()),
            Err(Diagnostic::at(Code::InputUnreadable, 6))
        );
    }

    /// A document grants nothing, so a group-writable one is read like any
    /// other.
    #[cfg(unix)]
    #[test]
    fn a_document_is_read_whatever_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let documents = Documents::new("modes");
        let path = documents.write("policy.json", b"{}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("mode");
        assert_eq!(read_json(&path, 2).expect("readable"), b"{}");
    }
}
