use std::sync::atomic::{AtomicUsize, Ordering};

use gateway_config::bundle::{
    init::{scaffold, Answers},
    Profile,
};

use super::*;

/// A parent directory for destinations, removed on drop.
struct Parent {
    root: PathBuf,
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Parent {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the parent directory should create");
        Self { root }
    }

    /// Every entry name in the parent, sorted.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&self.root)
            .expect("the parent should list")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect();
        names.sort();
        names
    }
}

fn files() -> Vec<SourceFile> {
    scaffold(Profile::Production, &Answers::default())
}

fn assert_written(destination: &Path, files: &[SourceFile]) {
    for file in files {
        assert_eq!(
            fs::read(destination.join(file.name.as_str())).expect("the file is written"),
            file.bytes
        );
    }
    assert_eq!(
        fs::read_to_string(destination.join(".gitattributes")).expect("attributes"),
        GITATTRIBUTES
    );
    assert_eq!(
        fs::read_dir(destination).expect("lists").count(),
        files.len() + 1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(destination), 0o700);
        for entry in fs::read_dir(destination).expect("lists") {
            assert_eq!(mode(&entry.expect("an entry").path()), 0o600);
        }
    }
}

#[test]
fn a_new_bundle_is_written_whole_and_read_back_and_no_staging_remains() {
    let parent = Parent::new();
    let destination = parent.root.join("bundle");
    let files = files();
    let read = write_new_bundle(&destination, &files).expect("the bundle is written");
    let bundle = read.bundle.expect("it read back as a bundle");
    assert_eq!(bundle.source_files(), files);
    assert!(read.diagnostics.is_empty(), "{:?}", read.diagnostics);
    assert_written(&destination, &files);
    assert_eq!(parent.entries(), ["bundle"]);
}

#[test]
fn an_empty_destination_directory_is_replaced() {
    let parent = Parent::new();
    let destination = parent.root.join("empty");
    fs::create_dir(&destination).expect("an empty directory");
    let files = files();
    write_new_bundle(&destination, &files).expect("the bundle is written");
    assert_written(&destination, &files);
    assert_eq!(parent.entries(), ["empty"]);
}

#[test]
fn a_destination_that_holds_anything_is_refused_and_left_alone() {
    let parent = Parent::new();
    let full = parent.root.join("full");
    fs::create_dir(&full).expect("a directory");
    fs::write(full.join("keep.txt"), "keep").expect("a file");
    let file = parent.root.join("file");
    fs::write(&file, "keep").expect("a file");
    for destination in [&full, &file] {
        assert!(matches!(
            write_new_bundle(destination, &files()),
            Err(WriteError::Exists)
        ));
    }
    assert_eq!(
        fs::read_to_string(full.join("keep.txt")).expect("kept"),
        "keep"
    );
    assert_eq!(fs::read_dir(&full).expect("lists").count(), 1);
    assert_eq!(fs::read_to_string(&file).expect("kept"), "keep");
    assert_eq!(parent.entries(), ["file", "full"]);
}

#[cfg(unix)]
#[test]
fn a_link_destination_is_refused_even_to_an_empty_directory() {
    let parent = Parent::new();
    let target = parent.root.join("target");
    fs::create_dir(&target).expect("a directory");
    let link = parent.root.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("a link");
    assert!(matches!(
        write_new_bundle(&link, &files()),
        Err(WriteError::Exists)
    ));
    assert_eq!(fs::read_dir(&target).expect("lists").count(), 0);
}

#[test]
fn files_that_do_not_read_back_as_a_valid_bundle_are_never_placed() {
    let parent = Parent::new();
    let destination = parent.root.join("bundle");
    let mut files = files();
    // A deployment document whose bytes no longer match the manifest's pin.
    files[1].bytes.extend_from_slice(b"# changed\n");
    let Err(WriteError::Invalid(read)) = write_new_bundle(&destination, &files) else {
        panic!("a bundle whose pin does not match must be refused");
    };
    assert!(read.bundle.is_none());
    assert!(read
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code.as_str() == "bundle.digest_mismatch"));
    assert!(parent.entries().is_empty(), "{:?}", parent.entries());
}

#[test]
fn a_destination_without_a_name_or_a_usable_parent_is_unusable() {
    let parent = Parent::new();
    let missing = parent.root.join("missing").join("bundle");
    assert!(matches!(
        write_new_bundle(&missing, &files()),
        Err(WriteError::Unusable)
    ));
    assert!(parent.entries().is_empty());
    assert!(matches!(
        Staging::create(Path::new("..")),
        Err(WriteError::Unusable)
    ));
}

/// A manifest in the parent directory, as `replace_manifest` finds one.
fn with_manifest(parent: &Parent, bytes: &[u8]) -> PathBuf {
    let path = parent.root.join(MANIFEST_FILE_NAME);
    fs::write(&path, bytes).expect("the manifest writes");
    path
}

fn failing_rename(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::other("injected"))
}

#[test]
fn a_manifest_is_replaced_whole_and_owner_only_and_nothing_else_remains() {
    let parent = Parent::new();
    let path = with_manifest(&parent, b"old manifest\n");
    replace_manifest(&parent.root, b"old manifest\n", b"new manifest\n", rename)
        .expect("the manifest is replaced");
    assert_eq!(fs::read(&path).expect("reads"), b"new manifest\n");
    assert_eq!(parent.entries(), [MANIFEST_FILE_NAME]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_failed_rename_leaves_the_manifest_and_no_hidden_file() {
    let parent = Parent::new();
    let path = with_manifest(&parent, b"old manifest\n");
    assert_eq!(
        replace_manifest(
            &parent.root,
            b"old manifest\n",
            b"new manifest\n",
            failing_rename
        ),
        Err(ReplaceError::Unusable)
    );
    assert_eq!(fs::read(&path).expect("reads"), b"old manifest\n");
    assert_eq!(parent.entries(), [MANIFEST_FILE_NAME]);
}

#[test]
fn a_manifest_that_changed_or_went_is_not_replaced() {
    let parent = Parent::new();
    let path = with_manifest(&parent, b"edited meanwhile\n");
    assert_eq!(
        replace_manifest(&parent.root, b"old manifest\n", b"new manifest\n", rename),
        Err(ReplaceError::Changed)
    );
    assert_eq!(fs::read(&path).expect("reads"), b"edited meanwhile\n");
    assert_eq!(parent.entries(), [MANIFEST_FILE_NAME]);

    fs::remove_file(&path).expect("removes");
    assert_eq!(
        replace_manifest(&parent.root, b"old manifest\n", b"new manifest\n", rename),
        Err(ReplaceError::Changed)
    );
    assert!(parent.entries().is_empty());
    // An absent manifest is left to the reader to report.
    assert_eq!(check_manifest_entry(&parent.root), Ok(()));
}

#[test]
fn a_manifest_that_is_not_a_regular_file_is_never_replaced() {
    let parent = Parent::new();
    fs::create_dir(parent.root.join(MANIFEST_FILE_NAME)).expect("a directory");
    assert_eq!(
        check_manifest_entry(&parent.root),
        Err(ReplaceError::NotRegularFile)
    );
    assert_eq!(
        replace_manifest(&parent.root, b"", b"new manifest\n", rename),
        Err(ReplaceError::NotRegularFile)
    );
    assert_eq!(parent.entries(), [MANIFEST_FILE_NAME]);
}

#[cfg(unix)]
#[test]
fn a_linked_manifest_is_never_replaced_nor_its_target() {
    let parent = Parent::new();
    let target = parent.root.join("elsewhere.yaml");
    fs::write(&target, b"old manifest\n").expect("writes");
    std::os::unix::fs::symlink(&target, parent.root.join(MANIFEST_FILE_NAME)).expect("a link");
    assert_eq!(
        check_manifest_entry(&parent.root),
        Err(ReplaceError::NotRegularFile)
    );
    assert_eq!(
        replace_manifest(&parent.root, b"old manifest\n", b"new manifest\n", rename),
        Err(ReplaceError::NotRegularFile)
    );
    assert_eq!(fs::read(&target).expect("reads"), b"old manifest\n");
}

#[test]
fn every_error_has_its_own_code() {
    let codes = [
        WriteError::Exists.code(),
        WriteError::Unusable.code(),
        WriteError::Permissions.code(),
    ];
    assert_eq!(
        codes.map(Code::as_str),
        [
            "output.destination_exists",
            "output.destination_unusable",
            "output.permissions_unavailable"
        ]
    );
    let codes = [
        ReplaceError::NotRegularFile.code(),
        ReplaceError::Changed.code(),
        ReplaceError::Unusable.code(),
        ReplaceError::Permissions.code(),
    ];
    assert_eq!(
        codes.map(Code::as_str),
        [
            "pin.manifest_link",
            "pin.manifest_changed",
            "pin.write_failed",
            "pin.permissions_unavailable"
        ]
    );
}
