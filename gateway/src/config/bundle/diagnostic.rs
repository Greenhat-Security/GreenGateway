//! Value-free bundle diagnostics.
//!
//! A bundle diagnostic is built from a stable code, the bundle-relative name
//! of the file it is about, a JSON Pointer and a line and column. Every one of
//! those is value-free by construction rather than by redaction:
//!
//! - the message is fixed text chosen by the code;
//! - the file name is a [`FileName`], which can only hold a name that passed
//!   the portable file-name grammar;
//! - a [`Pointer`] is built from `&'static str` member names the reader
//!   itself defines, and array indices, so an unknown member is reported at
//!   its parent's pointer and its own line and column, never by its name;
//! - positions are numbers.
//!
//! So no document value, unknown member name, host path, environment value or
//! library error text can reach a diagnostic, and there is no pattern to miss.

use std::fmt;

use super::source::FileName;

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// A position in a document: 1-based line and character column.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Position {
    pub(crate) line: u32,
    pub(crate) column: u32,
}

impl Position {
    pub(crate) fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Segment {
    Member(&'static str),
    Index(usize),
}

/// An RFC 6901 JSON Pointer whose member names are the reader's own.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Pointer(Vec<Segment>);

impl Pointer {
    pub(crate) fn root() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn member(&self, name: &'static str) -> Self {
        let mut segments = self.0.clone();
        segments.push(Segment::Member(name));
        Self(segments)
    }

    pub(crate) fn index(&self, index: usize) -> Self {
        let mut segments = self.0.clone();
        segments.push(Segment::Index(index));
        Self(segments)
    }

    pub(crate) fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in &self.0 {
            match segment {
                Segment::Member(name) => {
                    formatter.write_str("/")?;
                    for character in name.chars() {
                        match character {
                            '~' => formatter.write_str("~0")?,
                            '/' => formatter.write_str("~1")?,
                            other => write!(formatter, "{other}")?,
                        }
                    }
                }
                Segment::Index(index) => write!(formatter, "/{index}")?,
            }
        }
        Ok(())
    }
}

/// Every reason a bundle can be refused or warned about.
///
/// The string form (`family.reason`) is the stable contract. A published code
/// never changes meaning; renaming or removing one needs a new report schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Code {
    // The bundle directory and its files.
    RootUnavailable,
    RootNotDirectory,
    UnsafePermissions,
    TooManyEntries,
    ManifestMissing,
    FileMissing,
    SymlinkForbidden,
    NotRegularFile,
    HardLinkForbidden,
    FileTooLarge,
    BundleTooLarge,
    ReadFailed,
    ChangedDuringRead,
    AtomicWriterInvalid,
    UnreferencedEntry,
    ByteOrderMark,
    CarriageReturn,
    NotUtf8,
    DigestMismatch,
    // Syntax shared by YAML and JSON.
    EmptyDocument,
    TooDeep,
    TooManyMembers,
    TooManyElements,
    TooManyNodes,
    StringTooLong,
    KeyTooLong,
    NumberNotInteger,
    IntegerOutOfRange,
    ForbiddenCharacter,
    // JSON.
    JsonSyntax,
    JsonDuplicateKey,
    // The YAML subset.
    YamlSyntax,
    YamlDuplicateKey,
    AliasForbidden,
    AnchorForbidden,
    TagForbidden,
    MergeKeyForbidden,
    DirectiveForbidden,
    MultipleDocuments,
    ComplexKeyForbidden,
    NonStringKey,
    KeyMustBeQuoted,
    AmbiguousScalar,
    BlockScalarForbidden,
    MultilineValueForbidden,
    UnsupportedEscape,
    TabForbidden,
    BadIndentation,
    EmptyValue,
    // Document versions.
    UnsupportedApiVersion,
    UnsupportedKind,
    // Document structure.
    UnknownMember,
    MissingMember,
    WrongType,
    InvalidValue,
    InvalidName,
    InvalidDecimal,
    // References between bundle files.
    InvalidPath,
    ReservedPath,
    DuplicatePath,
    InvalidDigest,
    SourceUnsupported,
    Unresolved,
    // Secret references.
    InlineSecretValue,
    InvalidSecretReference,
    // Referenced policy and tools documents.
    UnsupportedSchemaVersion,
    SchemaVersionMismatch,
    ResourceUnknownMember,
    ResourceInvalid,
}

impl Code {
    /// Every code, in declaration order, for the uniqueness and
    /// documentation tests.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Code] = &[
        Self::RootUnavailable,
        Self::RootNotDirectory,
        Self::UnsafePermissions,
        Self::TooManyEntries,
        Self::ManifestMissing,
        Self::FileMissing,
        Self::SymlinkForbidden,
        Self::NotRegularFile,
        Self::HardLinkForbidden,
        Self::FileTooLarge,
        Self::BundleTooLarge,
        Self::ReadFailed,
        Self::ChangedDuringRead,
        Self::AtomicWriterInvalid,
        Self::UnreferencedEntry,
        Self::ByteOrderMark,
        Self::CarriageReturn,
        Self::NotUtf8,
        Self::DigestMismatch,
        Self::EmptyDocument,
        Self::TooDeep,
        Self::TooManyMembers,
        Self::TooManyElements,
        Self::TooManyNodes,
        Self::StringTooLong,
        Self::KeyTooLong,
        Self::NumberNotInteger,
        Self::IntegerOutOfRange,
        Self::ForbiddenCharacter,
        Self::JsonSyntax,
        Self::JsonDuplicateKey,
        Self::YamlSyntax,
        Self::YamlDuplicateKey,
        Self::AliasForbidden,
        Self::AnchorForbidden,
        Self::TagForbidden,
        Self::MergeKeyForbidden,
        Self::DirectiveForbidden,
        Self::MultipleDocuments,
        Self::ComplexKeyForbidden,
        Self::NonStringKey,
        Self::KeyMustBeQuoted,
        Self::AmbiguousScalar,
        Self::BlockScalarForbidden,
        Self::MultilineValueForbidden,
        Self::UnsupportedEscape,
        Self::TabForbidden,
        Self::BadIndentation,
        Self::EmptyValue,
        Self::UnsupportedApiVersion,
        Self::UnsupportedKind,
        Self::UnknownMember,
        Self::MissingMember,
        Self::WrongType,
        Self::InvalidValue,
        Self::InvalidName,
        Self::InvalidDecimal,
        Self::InvalidPath,
        Self::ReservedPath,
        Self::DuplicatePath,
        Self::InvalidDigest,
        Self::SourceUnsupported,
        Self::Unresolved,
        Self::InlineSecretValue,
        Self::InvalidSecretReference,
        Self::UnsupportedSchemaVersion,
        Self::SchemaVersionMismatch,
        Self::ResourceUnknownMember,
        Self::ResourceInvalid,
    ];

    /// The stable code.
    pub(crate) fn as_str(self) -> &'static str {
        self.entry().0
    }

    /// Fixed text describing the code. Never a value.
    pub(crate) fn message(self) -> &'static str {
        self.entry().1
    }

    fn entry(self) -> (&'static str, &'static str) {
        match self {
            Self::RootUnavailable => (
                "bundle.root_unavailable",
                "the bundle directory cannot be opened",
            ),
            Self::RootNotDirectory => (
                "bundle.root_not_directory",
                "the bundle location is not a directory",
            ),
            Self::UnsafePermissions => (
                "bundle.unsafe_permissions",
                "a bundle directory or file is writable by group or other",
            ),
            Self::TooManyEntries => (
                "bundle.too_many_entries",
                "the bundle directory holds more entries than a bundle may",
            ),
            Self::ManifestMissing => (
                "bundle.manifest_missing",
                "the bundle has no bundle.yaml manifest",
            ),
            Self::FileMissing => (
                "bundle.file_missing",
                "a file the manifest references is not in the bundle",
            ),
            Self::SymlinkForbidden => (
                "bundle.symlink_forbidden",
                "a bundle entry is a symbolic link, junction or reparse point",
            ),
            Self::NotRegularFile => (
                "bundle.not_regular_file",
                "a bundle entry is not a regular file",
            ),
            Self::HardLinkForbidden => (
                "bundle.hard_link_forbidden",
                "a bundle file has more than one hard link",
            ),
            Self::FileTooLarge => (
                "bundle.file_too_large",
                "a bundle file is larger than its kind allows",
            ),
            Self::BundleTooLarge => (
                "bundle.bundle_too_large",
                "the files the bundle references are larger in total than a bundle may be",
            ),
            Self::ReadFailed => ("bundle.read_failed", "a bundle file could not be read"),
            Self::ChangedDuringRead => (
                "bundle.changed_during_read",
                "a bundle file changed while it was being read",
            ),
            Self::AtomicWriterInvalid => (
                "bundle.atomic_writer_invalid",
                "the bundle's ..data layout is not one resolvable generation directory",
            ),
            Self::UnreferencedEntry => (
                "bundle.unreferenced_entry",
                "the bundle directory holds an entry the manifest does not reference",
            ),
            Self::ByteOrderMark => (
                "bundle.byte_order_mark",
                "a bundle file starts with a byte-order mark",
            ),
            Self::CarriageReturn => (
                "bundle.carriage_return",
                "a bundle file contains a carriage return; bundle files use LF line endings",
            ),
            Self::NotUtf8 => ("bundle.not_utf8", "a bundle file is not valid UTF-8"),
            Self::DigestMismatch => (
                "bundle.digest_mismatch",
                "a file's SHA-256 digest differs from the digest the manifest pins",
            ),
            Self::EmptyDocument => ("syntax.empty_document", "the document is empty"),
            Self::TooDeep => (
                "syntax.too_deep",
                "the document nests more collections than allowed",
            ),
            Self::TooManyMembers => (
                "syntax.too_many_members",
                "an object has more members than allowed",
            ),
            Self::TooManyElements => (
                "syntax.too_many_elements",
                "an array has more elements than allowed",
            ),
            Self::TooManyNodes => (
                "syntax.too_many_nodes",
                "the document has more values than allowed",
            ),
            Self::StringTooLong => (
                "syntax.string_too_long",
                "a string is longer than allowed",
            ),
            Self::KeyTooLong => (
                "syntax.key_too_long",
                "an object key is longer than allowed",
            ),
            Self::NumberNotInteger => (
                "syntax.number_not_integer",
                "a number is not an integer; write fractional settings as decimal strings",
            ),
            Self::IntegerOutOfRange => (
                "syntax.integer_out_of_range",
                "an integer is outside the I-JSON safe range",
            ),
            Self::ForbiddenCharacter => (
                "syntax.forbidden_character",
                "the document contains a control, bidirectional formatting or line separator character",
            ),
            Self::JsonSyntax => ("json.syntax_error", "the document is not valid JSON"),
            Self::JsonDuplicateKey => (
                "json.duplicate_key",
                "an object names the same member twice",
            ),
            Self::YamlSyntax => (
                "yaml.syntax_error",
                "the document is not in the supported YAML subset",
            ),
            Self::YamlDuplicateKey => (
                "yaml.duplicate_key",
                "a mapping names the same key twice",
            ),
            Self::AliasForbidden => ("yaml.alias_forbidden", "YAML aliases are not allowed"),
            Self::AnchorForbidden => ("yaml.anchor_forbidden", "YAML anchors are not allowed"),
            Self::TagForbidden => ("yaml.tag_forbidden", "YAML tags are not allowed"),
            Self::MergeKeyForbidden => (
                "yaml.merge_key_forbidden",
                "YAML merge keys are not allowed",
            ),
            Self::DirectiveForbidden => (
                "yaml.directive_forbidden",
                "YAML directives are not allowed",
            ),
            Self::MultipleDocuments => (
                "yaml.multiple_documents",
                "a bundle file holds exactly one YAML document",
            ),
            Self::ComplexKeyForbidden => (
                "yaml.complex_key_forbidden",
                "explicit and collection keys are not allowed",
            ),
            Self::NonStringKey => (
                "yaml.non_string_key",
                "a key would be read as a boolean, null or number; keys are strings",
            ),
            Self::KeyMustBeQuoted => (
                "yaml.key_must_be_quoted",
                "a key outside the plain identifier form must be quoted",
            ),
            Self::AmbiguousScalar => (
                "yaml.ambiguous_scalar",
                "an unquoted value could be read as another type; quote it",
            ),
            Self::BlockScalarForbidden => (
                "yaml.block_scalar_forbidden",
                "literal and folded block scalars are not allowed",
            ),
            Self::MultilineValueForbidden => (
                "yaml.multiline_value_forbidden",
                "a scalar or flow collection must end on the line it starts",
            ),
            Self::UnsupportedEscape => (
                "yaml.unsupported_escape",
                "a double-quoted string uses an escape outside the JSON set",
            ),
            Self::TabForbidden => (
                "yaml.tab_forbidden",
                "tabs are allowed only inside quoted strings and comments",
            ),
            Self::BadIndentation => (
                "yaml.bad_indentation",
                "a line is indented inconsistently with its mapping or sequence",
            ),
            Self::EmptyValue => (
                "yaml.empty_value",
                "a key or sequence item has no value; write null explicitly",
            ),
            Self::UnsupportedApiVersion => (
                "compat.unsupported_api_version",
                "the document's apiVersion is not one this reader implements",
            ),
            Self::UnsupportedKind => (
                "compat.unsupported_kind",
                "the document's kind is not the kind expected here",
            ),
            Self::UnknownMember => (
                "schema.unknown_member",
                "an object has a member the document version does not define",
            ),
            Self::MissingMember => (
                "schema.missing_member",
                "a required member is missing",
            ),
            Self::WrongType => ("schema.wrong_type", "a value has the wrong type"),
            Self::InvalidValue => (
                "schema.invalid_value",
                "a value is not one the document version allows",
            ),
            Self::InvalidName => (
                "schema.invalid_name",
                "a name is not a lowercase DNS label of at most 63 characters",
            ),
            Self::InvalidDecimal => (
                "schema.invalid_decimal",
                "a decimal is not a string of up to 16 integer and 6 fraction digits",
            ),
            Self::InvalidPath => (
                "reference.invalid_path",
                "a referenced file name is not a portable bundle file name of the right type",
            ),
            Self::ReservedPath => (
                "reference.reserved_path",
                "a reference names the bundle.yaml manifest",
            ),
            Self::DuplicatePath => (
                "reference.duplicate_path",
                "two references name the same file",
            ),
            Self::InvalidDigest => (
                "reference.invalid_digest",
                "a pinned digest is not 64 lowercase hexadecimal digits",
            ),
            Self::SourceUnsupported => (
                "reference.source_unsupported",
                "the resource cannot be supplied by this source in this document version",
            ),
            Self::Unresolved => (
                "reference.unresolved",
                "a value is an unresolved placeholder; supply a reference or value",
            ),
            Self::InlineSecretValue => (
                "secret.inline_value",
                "a sensitive setting holds a literal value; use a secret reference",
            ),
            Self::InvalidSecretReference => (
                "secret.invalid_reference",
                "a secret reference is not a single opaque alias ID",
            ),
            Self::UnsupportedSchemaVersion => (
                "resource.unsupported_schema_version",
                "the declared resource schema_version is not one this reader implements",
            ),
            Self::SchemaVersionMismatch => (
                "resource.schema_version_mismatch",
                "the resource document's schema_version differs from the version the manifest declares",
            ),
            Self::ResourceUnknownMember => (
                "resource.unknown_member",
                "the resource document has a top-level member its validator would ignore",
            ),
            Self::ResourceInvalid => (
                "resource.invalid",
                "the resource document fails its published schema or production validator",
            ),
        }
    }
}

/// One problem with a bundle, without any value from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BundleDiagnostic {
    pub(crate) code: Code,
    pub(crate) severity: Severity,
    pub(crate) file: Option<FileName>,
    pub(crate) pointer: Pointer,
    pub(crate) position: Option<Position>,
}

impl BundleDiagnostic {
    /// An error about the bundle as a whole.
    pub(crate) fn bundle(code: Code) -> Self {
        Self {
            code,
            severity: Severity::Error,
            file: None,
            pointer: Pointer::root(),
            position: None,
        }
    }

    /// An error about one file.
    pub(crate) fn file(code: Code, file: &FileName) -> Self {
        Self {
            file: Some(file.clone()),
            ..Self::bundle(code)
        }
    }

    /// An error at a place in one file's document.
    pub(crate) fn at(
        code: Code,
        file: &FileName,
        pointer: Pointer,
        position: Option<Position>,
    ) -> Self {
        Self {
            pointer,
            position,
            ..Self::file(code, file)
        }
    }

    pub(crate) fn warning(mut self) -> Self {
        self.severity = Severity::Warning;
        self
    }

    pub(crate) fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for BundleDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            formatter.write_str(file.as_str())?;
            if let Some(position) = self.position {
                write!(formatter, ":{}:{}", position.line, position.column)?;
            }
            formatter.write_str(": ")?;
        }
        write!(
            formatter,
            "{}[{}]: {}",
            self.severity.as_str(),
            self.code.as_str(),
            self.code.message()
        )?;
        if !self.pointer.is_root() {
            write!(formatter, " (at {})", self.pointer)?;
        }
        Ok(())
    }
}
