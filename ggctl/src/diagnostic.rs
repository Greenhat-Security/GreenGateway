//! Value-free diagnostics and the stable exit codes.
//!
//! A diagnostic is a stable code plus, at most, the 1-based position of the
//! command-line argument it is about and a fixed hint. Its message, hint and
//! remediation anchor are static text chosen by the code, so no argument,
//! token, URL, path, server response or library error text can reach one:
//! an unknown option is reported by its position, never by its spelling,
//! because the spelling may be a mistyped secret.

use std::fmt;

/// The process exit codes (ADR-0008, "Exit codes"). The numbers and names
/// are a published contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Exit {
    Success,
    Failure,
    Usage,
    Invalid,
    Drift,
    Conflict,
    Unavailable,
    Integrity,
    Denied,
}

impl Exit {
    pub(crate) const ALL: [Self; 9] = [
        Self::Success,
        Self::Failure,
        Self::Usage,
        Self::Invalid,
        Self::Drift,
        Self::Conflict,
        Self::Unavailable,
        Self::Integrity,
        Self::Denied,
    ];

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::Invalid => 3,
            Self::Drift => 4,
            Self::Conflict => 5,
            Self::Unavailable => 6,
            Self::Integrity => 7,
            Self::Denied => 8,
        }
    }

    /// The stable name a report carries as its `outcome`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Usage => "usage",
            Self::Invalid => "invalid",
            Self::Drift => "drift",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
            Self::Integrity => "integrity",
            Self::Denied => "denied",
        }
    }

    pub(crate) fn meaning(self) -> &'static str {
        match self {
            Self::Success => "success; for diff --check, no drift; for doctor, no required check failed",
            Self::Failure => {
                "unexpected internal, I/O or transport failure, including a mutation whose outcome could not be determined"
            }
            Self::Usage => "usage error, including a reserved command or a refused insecure option",
            Self::Invalid => {
                "invalid, incompatible or unsupported configuration, server or document version; a failed required doctor check; a policy that does not lint clean, a policy test suite that did not pass or an incomplete replay; any warning under --warnings-as-errors"
            }
            Self::Drift => "drift found by diff --check",
            Self::Conflict => {
                "precondition conflict: missing or stale ETag, plan, draft, acknowledgment, idempotency key or lock, a replay whose base changed, an output destination that is not empty, or a manifest that changed while it was being pinned"
            }
            Self::Unavailable => "a dependency was unavailable and nothing was sent or committed; safe to retry",
            Self::Integrity => {
                "backup, archive or evidence package integrity failure, or restore verification failure"
            }
            Self::Denied => "authentication or authorization refused",
        }
    }

    /// When several errors apply, the outcome that must not be hidden wins.
    /// An outcome that may have committed (`Failure`) outranks everything,
    /// and "safe to retry" (`Unavailable`) is never reported while any other
    /// error stands, so a pipeline that retries on 6 cannot resend work
    /// another error left in doubt.
    fn precedence(self) -> u8 {
        match self {
            Self::Failure => 8,
            Self::Integrity => 7,
            Self::Denied => 6,
            Self::Conflict => 5,
            Self::Usage => 4,
            Self::Invalid => 3,
            Self::Drift => 2,
            Self::Unavailable => 1,
            Self::Success => 0,
        }
    }

    /// The exit code for a set of diagnostics: success when there is none.
    #[cfg(test)]
    pub(crate) fn of(diagnostics: &[Diagnostic]) -> Self {
        Self::worst(diagnostics.iter().map(|diagnostic| diagnostic.code.exit()))
    }

    /// The exit code that must not be hidden among `exits`: success when
    /// there is none.
    pub(crate) fn worst(exits: impl IntoIterator<Item = Self>) -> Self {
        exits
            .into_iter()
            .max_by_key(|exit| exit.precedence())
            .unwrap_or(Self::Success)
    }
}

/// Every reason `ggctl` can refuse or fail. The string form (`family.reason`)
/// is the stable contract: a published code never changes meaning, and
/// renaming or removing one needs a new report schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Code {
    // Arguments.
    MissingCommand,
    UnknownCommand,
    ReservedCommand,
    UnknownOption,
    MissingValue,
    DuplicateOption,
    UnexpectedValue,
    UnexpectedArgument,
    MissingArgument,
    InvalidValue,
    ArgumentNotUtf8,
    ConflictingOptions,
    OptionRequiresServer,
    ServerRequired,
    MissingOption,
    FormatUnsupported,
    SecretOnCommandLine,
    InsecureOptionRefused,
    CaFileRequiresHttps,
    // Bearer-token input.
    StdinIsTerminal,
    CredentialUnreadable,
    CredentialNotRegularFile,
    CredentialUnsafePermissions,
    CredentialTooLarge,
    CredentialEmpty,
    CredentialInvalid,
    // Additional trust anchors.
    CaFileUnreadable,
    CaFileNotRegularFile,
    CaFileUnsafePermissions,
    CaFileTooLarge,
    CaFileInvalid,
    // The server address and the admin API transport.
    InvalidServerUrl,
    PlaintextRefused,
    UserinfoRefused,
    QueryOrFragmentRefused,
    ConnectFailed,
    Timeout,
    TransportFailed,
    RedirectRefused,
    Unauthenticated,
    Forbidden,
    ServerUnavailable,
    UnexpectedStatus,
    ResponseTooLarge,
    UnexpectedContentType,
    // Local documents a command reads.
    InputUnreadable,
    InputNotRegularFile,
    InputTooLarge,
    InputNotJson,
    // The policy commands.
    PolicyInvalid,
    PolicyTestsNotPassed,
    PolicyReplayIncomplete,
    PolicyReplayFailed,
    PolicyReplayStale,
    PolicyWaitTimedOut,
    PolicyRequestRefused,
    PolicyNotFound,
    PolicyPreconditionFailed,
    PolicyRequestTooLarge,
    PolicyBusy,
    PolicyResponseInvalid,
    PolicyOutcomeUnknown,
    // Offline evidence verification.
    EvidenceUnsigned,
    EvidencePackageTooLarge,
    EvidenceMalformed,
    EvidenceNotCanonical,
    EvidenceUnsupportedVersion,
    EvidenceUnsupportedArtifact,
    EvidenceArtifactTypeMismatch,
    EvidenceDuplicateEntry,
    EvidenceMissingArtifact,
    EvidenceUnlistedMember,
    EvidenceSizeMismatch,
    EvidenceDigestMismatch,
    EvidenceBindingMismatch,
    EvidenceSignatureUnsupported,
    // The version handshake.
    CapabilitiesUnavailable,
    UnsupportedCapabilitiesVersion,
    CapabilitiesInvalid,
    // Published schemas.
    UnsupportedSchemaVersion,
    // Bundle validation and the offline doctor.
    WarningsAsErrors,
    RequiredCheckFailed,
    // The semantic diff.
    DriftFound,
    // Initialization.
    AnswersUnreadable,
    AnswersNotRegularFile,
    AnswersUnsafePermissions,
    AnswersTooLarge,
    // Conversion between document versions.
    UnsupportedTargetVersion,
    DowngradeRefused,
    InPlaceUnavailable,
    // Pinning.
    ManifestLink,
    ManifestChanged,
    PinWriteFailed,
    PinPermissionsUnavailable,
    ReadBackFailed,
    // The standalone state directory.
    StateDirMissing,
    StateDirNotDirectory,
    StateDirLink,
    StateDirUnsafePermissions,
    StateDirUnsafeLockFile,
    StateDirLocked,
    StateDirLockUnsupported,
    StateDirUnavailable,
    // The revision ledger and its offline commands.
    LedgerMissing,
    LedgerExists,
    LedgerUnsafeLocation,
    LedgerUnsupported,
    LedgerCorrupt,
    LedgerFull,
    LedgerRefused,
    LedgerStale,
    LedgerUnavailable,
    RollbackTargetUnknown,
    RollbackTargetIsHead,
    RollbackTargetInvalid,
    HeadInvalid,
    ChangeNotApplicable,
    ChangeUnclassified,
    NotNormalizable,
    NoChange,
    AcknowledgementRequired,
    AcknowledgementMismatch,
    NothingToAcknowledge,
    UnexpectedRefusal,
    GatewayRecompilesAtStart,
    // Standalone backups.
    BackupStdoutRefused,
    BackupOutputExists,
    BackupOutputUnusable,
    BackupPermissionsUnavailable,
    BackupNothingToBackUp,
    BackupStoreLink,
    BackupStoreNotRegularFile,
    BackupStoreUnsafePermissions,
    BackupStoreUnavailable,
    BackupStoreCorrupt,
    BackupLedgerInvalid,
    BackupLedgerShared,
    BackupArchiveUnreadable,
    BackupArchiveNotRegularFile,
    BackupArchiveTooLarge,
    BackupStagingUnavailable,
    BackupNotABackup,
    BackupPostgresUnsupported,
    BackupUnsupportedArchiveVersion,
    BackupManifestMissing,
    BackupManifestInvalid,
    BackupUnsupportedManifestVersion,
    BackupUnexpectedEntry,
    BackupEntryMissing,
    BackupArchiveDigestMismatch,
    BackupChecksumMismatch,
    BackupStoreIntegrityFailed,
    BackupStoreMismatch,
    BackupLedgerVerificationFailed,
    BackupLedgerMismatch,
    BackupSecretKeysNotIncluded,
    // Standalone restore.
    RestoreTargetNotEmpty,
    RestoreTargetNotStateDir,
    RestoreTargetMountPoint,
    RestoreTargetUnavailable,
    RestoreStagingUnavailable,
    RestorePermissionsUnavailable,
    RestoreStoreIdentityMismatch,
    RestoreTargetChanged,
    RestoreSwitchFailed,
    RestoreRollbackFailed,
    RestoreDirectoryNotFlushed,
    RestorePreviousNotRemoved,
    RestoreSecretKeysRequired,
    // This process.
    WriteFailed,
    DestinationExists,
    DestinationUnusable,
    PermissionsUnavailable,
    WrittenBundleInvalid,
    RuntimeUnavailable,
    ClientUnavailable,
}

/// The documentation families, each a section of `docs/ggctl.md`.
#[cfg(test)]
pub(crate) const FAMILIES: &[&str] = &[
    "usage",
    "credential",
    "trust",
    "remote",
    "input",
    "policy",
    "evidence",
    "compat",
    "schema",
    "validate",
    "doctor",
    "diff",
    "init",
    "convert",
    "pin",
    "state_dir",
    "ledger",
    "backup",
    "restore",
    "output",
    "internal",
];

impl Code {
    /// Every code, in declaration order, for the uniqueness and
    /// documentation tests.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::MissingCommand,
        Self::UnknownCommand,
        Self::ReservedCommand,
        Self::UnknownOption,
        Self::MissingValue,
        Self::DuplicateOption,
        Self::UnexpectedValue,
        Self::UnexpectedArgument,
        Self::MissingArgument,
        Self::InvalidValue,
        Self::ArgumentNotUtf8,
        Self::ConflictingOptions,
        Self::OptionRequiresServer,
        Self::ServerRequired,
        Self::MissingOption,
        Self::FormatUnsupported,
        Self::SecretOnCommandLine,
        Self::InsecureOptionRefused,
        Self::CaFileRequiresHttps,
        Self::StdinIsTerminal,
        Self::CredentialUnreadable,
        Self::CredentialNotRegularFile,
        Self::CredentialUnsafePermissions,
        Self::CredentialTooLarge,
        Self::CredentialEmpty,
        Self::CredentialInvalid,
        Self::CaFileUnreadable,
        Self::CaFileNotRegularFile,
        Self::CaFileUnsafePermissions,
        Self::CaFileTooLarge,
        Self::CaFileInvalid,
        Self::InvalidServerUrl,
        Self::PlaintextRefused,
        Self::UserinfoRefused,
        Self::QueryOrFragmentRefused,
        Self::ConnectFailed,
        Self::Timeout,
        Self::TransportFailed,
        Self::RedirectRefused,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::ServerUnavailable,
        Self::UnexpectedStatus,
        Self::ResponseTooLarge,
        Self::UnexpectedContentType,
        Self::InputUnreadable,
        Self::InputNotRegularFile,
        Self::InputTooLarge,
        Self::InputNotJson,
        Self::PolicyInvalid,
        Self::PolicyTestsNotPassed,
        Self::PolicyReplayIncomplete,
        Self::PolicyReplayFailed,
        Self::PolicyReplayStale,
        Self::PolicyWaitTimedOut,
        Self::PolicyRequestRefused,
        Self::PolicyNotFound,
        Self::PolicyPreconditionFailed,
        Self::PolicyRequestTooLarge,
        Self::PolicyBusy,
        Self::PolicyResponseInvalid,
        Self::PolicyOutcomeUnknown,
        Self::EvidenceUnsigned,
        Self::EvidencePackageTooLarge,
        Self::EvidenceMalformed,
        Self::EvidenceNotCanonical,
        Self::EvidenceUnsupportedVersion,
        Self::EvidenceUnsupportedArtifact,
        Self::EvidenceArtifactTypeMismatch,
        Self::EvidenceDuplicateEntry,
        Self::EvidenceMissingArtifact,
        Self::EvidenceUnlistedMember,
        Self::EvidenceSizeMismatch,
        Self::EvidenceDigestMismatch,
        Self::EvidenceBindingMismatch,
        Self::EvidenceSignatureUnsupported,
        Self::CapabilitiesUnavailable,
        Self::UnsupportedCapabilitiesVersion,
        Self::CapabilitiesInvalid,
        Self::UnsupportedSchemaVersion,
        Self::WarningsAsErrors,
        Self::RequiredCheckFailed,
        Self::DriftFound,
        Self::AnswersUnreadable,
        Self::AnswersNotRegularFile,
        Self::AnswersUnsafePermissions,
        Self::AnswersTooLarge,
        Self::UnsupportedTargetVersion,
        Self::DowngradeRefused,
        Self::InPlaceUnavailable,
        Self::ManifestLink,
        Self::ManifestChanged,
        Self::PinWriteFailed,
        Self::PinPermissionsUnavailable,
        Self::ReadBackFailed,
        Self::StateDirMissing,
        Self::StateDirNotDirectory,
        Self::StateDirLink,
        Self::StateDirUnsafePermissions,
        Self::StateDirUnsafeLockFile,
        Self::StateDirLocked,
        Self::StateDirLockUnsupported,
        Self::StateDirUnavailable,
        Self::LedgerMissing,
        Self::LedgerExists,
        Self::LedgerUnsafeLocation,
        Self::LedgerUnsupported,
        Self::LedgerCorrupt,
        Self::LedgerFull,
        Self::LedgerRefused,
        Self::LedgerStale,
        Self::LedgerUnavailable,
        Self::RollbackTargetUnknown,
        Self::RollbackTargetIsHead,
        Self::RollbackTargetInvalid,
        Self::HeadInvalid,
        Self::ChangeNotApplicable,
        Self::ChangeUnclassified,
        Self::NotNormalizable,
        Self::NoChange,
        Self::AcknowledgementRequired,
        Self::AcknowledgementMismatch,
        Self::NothingToAcknowledge,
        Self::UnexpectedRefusal,
        Self::GatewayRecompilesAtStart,
        Self::BackupStdoutRefused,
        Self::BackupOutputExists,
        Self::BackupOutputUnusable,
        Self::BackupPermissionsUnavailable,
        Self::BackupNothingToBackUp,
        Self::BackupStoreLink,
        Self::BackupStoreNotRegularFile,
        Self::BackupStoreUnsafePermissions,
        Self::BackupStoreUnavailable,
        Self::BackupStoreCorrupt,
        Self::BackupLedgerInvalid,
        Self::BackupLedgerShared,
        Self::BackupArchiveUnreadable,
        Self::BackupArchiveNotRegularFile,
        Self::BackupArchiveTooLarge,
        Self::BackupStagingUnavailable,
        Self::BackupNotABackup,
        Self::BackupPostgresUnsupported,
        Self::BackupUnsupportedArchiveVersion,
        Self::BackupManifestMissing,
        Self::BackupManifestInvalid,
        Self::BackupUnsupportedManifestVersion,
        Self::BackupUnexpectedEntry,
        Self::BackupEntryMissing,
        Self::BackupArchiveDigestMismatch,
        Self::BackupChecksumMismatch,
        Self::BackupStoreIntegrityFailed,
        Self::BackupStoreMismatch,
        Self::BackupLedgerVerificationFailed,
        Self::BackupLedgerMismatch,
        Self::BackupSecretKeysNotIncluded,
        Self::RestoreTargetNotEmpty,
        Self::RestoreTargetNotStateDir,
        Self::RestoreTargetMountPoint,
        Self::RestoreTargetUnavailable,
        Self::RestoreStagingUnavailable,
        Self::RestorePermissionsUnavailable,
        Self::RestoreStoreIdentityMismatch,
        Self::RestoreTargetChanged,
        Self::RestoreSwitchFailed,
        Self::RestoreRollbackFailed,
        Self::RestoreDirectoryNotFlushed,
        Self::RestorePreviousNotRemoved,
        Self::RestoreSecretKeysRequired,
        Self::WriteFailed,
        Self::DestinationExists,
        Self::DestinationUnusable,
        Self::PermissionsUnavailable,
        Self::WrittenBundleInvalid,
        Self::RuntimeUnavailable,
        Self::ClientUnavailable,
    ];

    /// The stable code.
    pub(crate) fn as_str(self) -> &'static str {
        self.entry().0
    }

    /// Fixed text describing the code. Never a value.
    pub(crate) fn message(self) -> &'static str {
        self.entry().1
    }

    pub(crate) fn exit(self) -> Exit {
        self.entry().2
    }

    /// The family, which is also the `docs/ggctl.md` section that explains
    /// the code and how to fix it.
    pub(crate) fn family(self) -> &'static str {
        let code = self.as_str();
        code.split_once('.').map_or(code, |(family, _)| family)
    }

    /// The remediation reference: a repository documentation anchor.
    pub(crate) fn remediation(self) -> &'static str {
        match self.family() {
            "usage" => "docs/ggctl.md#usage-diagnostics",
            "credential" => "docs/ggctl.md#credential-diagnostics",
            "trust" => "docs/ggctl.md#trust-diagnostics",
            "remote" => "docs/ggctl.md#remote-diagnostics",
            "input" => "docs/ggctl.md#input-diagnostics",
            "policy" => "docs/ggctl.md#policy-diagnostics",
            "evidence" => "docs/ggctl.md#evidence-diagnostics",
            "compat" => "docs/ggctl.md#compat-diagnostics",
            "schema" => "docs/ggctl.md#schema-diagnostics",
            "validate" => "docs/ggctl.md#validate-diagnostics",
            "doctor" => "docs/ggctl.md#doctor-diagnostics",
            "diff" => "docs/ggctl.md#diff-diagnostics",
            "init" => "docs/ggctl.md#init-diagnostics",
            "convert" => "docs/ggctl.md#convert-diagnostics",
            "pin" => "docs/ggctl.md#pin-diagnostics",
            "state_dir" => "docs/ggctl.md#state_dir-diagnostics",
            "ledger" => "docs/ggctl.md#ledger-diagnostics",
            "backup" => "docs/ggctl.md#backup-diagnostics",
            "restore" => "docs/ggctl.md#restore-diagnostics",
            "output" => "docs/ggctl.md#output-diagnostics",
            _ => "docs/ggctl.md#internal-diagnostics",
        }
    }

    fn entry(self) -> (&'static str, &'static str, Exit) {
        use Exit::{
            Conflict, Denied, Drift, Failure, Integrity, Invalid, Success, Unavailable, Usage,
        };
        match self {
            Self::MissingCommand => ("usage.missing_command", "no command was given", Usage),
            Self::UnknownCommand => ("usage.unknown_command", "the command is not one this ggctl implements", Usage),
            Self::ReservedCommand => (
                "usage.reserved_command",
                "the command name is reserved for operations that stay on the gateway binary",
                Usage,
            ),
            Self::UnknownOption => ("usage.unknown_option", "an argument is not an option this command accepts", Usage),
            Self::MissingValue => ("usage.missing_value", "an option that takes a value was given none", Usage),
            Self::DuplicateOption => ("usage.duplicate_option", "an option was given more than once", Usage),
            Self::UnexpectedValue => ("usage.unexpected_value", "an option that takes no value was given one", Usage),
            Self::UnexpectedArgument => (
                "usage.unexpected_argument",
                "the command takes no further positional argument",
                Usage,
            ),
            Self::MissingArgument => ("usage.missing_argument", "a required argument is missing", Usage),
            Self::InvalidValue => ("usage.invalid_value", "an argument's value is not one the command accepts", Usage),
            Self::ArgumentNotUtf8 => ("usage.argument_not_utf8", "an argument is not valid UTF-8", Usage),
            Self::ConflictingOptions => ("usage.conflicting_options", "two options that exclude each other were both given", Usage),
            Self::OptionRequiresServer => (
                "usage.option_requires_server",
                "a remote option was given without --server",
                Usage,
            ),
            Self::ServerRequired => (
                "usage.server_required",
                "the command asks a gateway and needs --server",
                Usage,
            ),
            Self::MissingOption => (
                "usage.missing_option",
                "an option the command, or another option given, needs was not given",
                Usage,
            ),
            Self::FormatUnsupported => (
                "usage.format_unsupported",
                "this form of the command writes an artifact and takes no --format",
                Usage,
            ),
            Self::SecretOnCommandLine => (
                "usage.secret_on_command_line",
                "ggctl never accepts a secret as a command-line argument",
                Usage,
            ),
            Self::InsecureOptionRefused => (
                "usage.insecure_option_refused",
                "ggctl has no option that disables certificate or hostname verification",
                Usage,
            ),
            Self::CaFileRequiresHttps => (
                "usage.ca_file_requires_https",
                "--ca-file applies only to an https server",
                Usage,
            ),
            Self::StdinIsTerminal => (
                "credential.stdin_is_terminal",
                "--token-stdin reads a piped token and refuses a terminal, where the token would be echoed",
                Usage,
            ),
            Self::CredentialUnreadable => ("credential.unreadable", "the token file could not be opened or read", Failure),
            Self::CredentialNotRegularFile => ("credential.not_regular_file", "the token file is not a regular file", Usage),
            Self::CredentialUnsafePermissions => (
                "credential.unsafe_permissions",
                "the token file is readable or writable by group or other",
                Usage,
            ),
            Self::CredentialTooLarge => ("credential.too_large", "the token is larger than 8 KiB", Usage),
            Self::CredentialEmpty => ("credential.empty", "the token is empty", Usage),
            Self::CredentialInvalid => (
                "credential.invalid",
                "the token is not a single RFC 6750 bearer token",
                Usage,
            ),
            Self::CaFileUnreadable => ("trust.ca_file_unreadable", "the CA file could not be opened or read", Failure),
            Self::CaFileNotRegularFile => ("trust.ca_file_not_regular_file", "the CA file is not a regular file", Usage),
            Self::CaFileUnsafePermissions => (
                "trust.ca_file_unsafe_permissions",
                "the CA file, a directory above it or a link on its path is owned by an account other than root and this one, or is writable by group or other",
                Usage,
            ),
            Self::CaFileTooLarge => ("trust.ca_file_too_large", "the CA file is larger than 1 MiB", Usage),
            Self::CaFileInvalid => (
                "trust.ca_file_invalid",
                "the CA file holds no PEM certificate that can be used as a trust anchor",
                Usage,
            ),
            Self::InvalidServerUrl => (
                "remote.invalid_server_url",
                "--server is not an admin API base of the form https://HOST[:PORT]/v1<ADMIN_PREFIX>",
                Usage,
            ),
            Self::PlaintextRefused => (
                "remote.plaintext_refused",
                "plain http is accepted only for a loopback IP literal; use https",
                Usage,
            ),
            Self::UserinfoRefused => (
                "remote.userinfo_refused",
                "--server must not carry a user name or password",
                Usage,
            ),
            Self::QueryOrFragmentRefused => (
                "remote.query_or_fragment_refused",
                "--server must not carry a query or fragment",
                Usage,
            ),
            Self::ConnectFailed => (
                "remote.connect_failed",
                "the connection or TLS handshake to the server failed before any request was sent",
                Unavailable,
            ),
            Self::Timeout => ("remote.timeout", "the request did not complete within the timeout", Failure),
            Self::TransportFailed => ("remote.transport_failed", "the request failed after the connection was established", Failure),
            Self::RedirectRefused => ("remote.redirect_refused", "the server answered with a redirect, which ggctl never follows", Failure),
            Self::Unauthenticated => ("remote.unauthenticated", "the server refused the request as unauthenticated (HTTP 401)", Denied),
            Self::Forbidden => ("remote.forbidden", "the server refused the request as unauthorized (HTTP 403)", Denied),
            Self::ServerUnavailable => (
                "remote.server_unavailable",
                "the server reported that a dependency is unavailable (HTTP 503)",
                Unavailable,
            ),
            Self::UnexpectedStatus => ("remote.unexpected_status", "the server answered with an unexpected HTTP status", Failure),
            Self::ResponseTooLarge => ("remote.response_too_large", "the server's response is larger than ggctl accepts", Failure),
            Self::UnexpectedContentType => (
                "remote.unexpected_content_type",
                "the server's response is not application/json",
                Failure,
            ),
            Self::InputUnreadable => ("input.unreadable", "a document file could not be opened or read", Failure),
            Self::InputNotRegularFile => ("input.not_regular_file", "a document file is not a regular file", Usage),
            Self::InputTooLarge => (
                "input.too_large",
                "a document file is larger than the command accepts",
                Invalid,
            ),
            Self::InputNotJson => (
                "input.not_json",
                "a document file is not exactly one JSON value in UTF-8",
                Invalid,
            ),
            Self::PolicyInvalid => (
                "policy.invalid",
                "the gateway's policy validator reported an error in the document",
                Invalid,
            ),
            Self::PolicyTestsNotPassed => (
                "policy.tests_not_passed",
                "the policy test suite did not pass: a case failed, was left undecided or was refused",
                Invalid,
            ),
            Self::PolicyReplayIncomplete => (
                "policy.replay_incomplete",
                "the replay finished with an incomplete result, which satisfies no gate",
                Invalid,
            ),
            Self::PolicyReplayFailed => (
                "policy.replay_failed",
                "the replay job ended without a result: it failed, was cancelled or expired",
                Failure,
            ),
            Self::PolicyReplayStale => (
                "policy.replay_stale",
                "the active policy changed after the replay job was pinned, so its result is not evidence about the live policy",
                Conflict,
            ),
            Self::PolicyWaitTimedOut => (
                "policy.wait_timed_out",
                "the replay job did not finish within the wait; it may still be running",
                Failure,
            ),
            Self::PolicyRequestRefused => (
                "policy.request_refused",
                "the gateway refused the request as invalid (HTTP 400 or 422); the result carries its reason and diagnostics",
                Invalid,
            ),
            Self::PolicyNotFound => (
                "policy.not_found",
                "the gateway has no such policy, draft, history version or replay job for this caller (HTTP 404)",
                Invalid,
            ),
            Self::PolicyPreconditionFailed => (
                "policy.precondition_failed",
                "a precondition the request was bound to no longer holds (HTTP 409, 410, 412 or 428); nothing was resent or rebased",
                Conflict,
            ),
            Self::PolicyRequestTooLarge => (
                "policy.request_too_large",
                "the gateway refused the request body as too large (HTTP 413)",
                Invalid,
            ),
            Self::PolicyBusy => (
                "policy.busy",
                "the gateway started nothing: it is busy with other runs, or the body did not arrive in time (HTTP 408 or 429)",
                Unavailable,
            ),
            Self::PolicyResponseInvalid => (
                "policy.response_invalid",
                "the gateway's answer is not a document of the version this ggctl reads",
                Invalid,
            ),
            Self::PolicyOutcomeUnknown => (
                "policy.outcome_unknown",
                "the replay request reached the gateway but its answer could not be read, so a job may have started",
                Failure,
            ),
            Self::EvidenceUnsigned => (
                "evidence.unsigned",
                "the package is unsigned: its integrity was checked, but nothing shows who produced it, and ggctl never reports it as trusted",
                Success,
            ),
            Self::EvidencePackageTooLarge => (
                "evidence.package_too_large",
                "the package is larger than 4 MiB, the most a gateway serves",
                Integrity,
            ),
            Self::EvidenceMalformed => (
                "evidence.malformed",
                "the package is not a policy evidence envelope: a member is missing, of the wrong type or out of order",
                Integrity,
            ),
            Self::EvidenceNotCanonical => (
                "evidence.not_canonical",
                "the package is not exactly its RFC 8785 bytes: whitespace, member order, a repeated member name or a number's spelling differs from the form a gateway serves",
                Integrity,
            ),
            Self::EvidenceUnsupportedVersion => (
                "evidence.unsupported_version",
                "the package or its report is a schema version this ggctl does not verify",
                Invalid,
            ),
            Self::EvidenceUnsupportedArtifact => (
                "evidence.unsupported_artifact",
                "the manifest names an artifact this ggctl does not verify",
                Invalid,
            ),
            Self::EvidenceArtifactTypeMismatch => (
                "evidence.artifact_type_mismatch",
                "an artifact's media type or schema version is not the one its name defines, or not the one it states itself",
                Integrity,
            ),
            Self::EvidenceDuplicateEntry => (
                "evidence.duplicate_entry",
                "the manifest names one artifact more than once",
                Integrity,
            ),
            Self::EvidenceMissingArtifact => (
                "evidence.missing_artifact",
                "the manifest names an artifact the package does not hold, or does not name the report",
                Integrity,
            ),
            Self::EvidenceUnlistedMember => (
                "evidence.unlisted_member",
                "the package holds a member its manifest does not list",
                Integrity,
            ),
            Self::EvidenceSizeMismatch => (
                "evidence.size_mismatch",
                "an artifact's size is not the one its manifest entry states",
                Integrity,
            ),
            Self::EvidenceDigestMismatch => (
                "evidence.digest_mismatch",
                "an artifact's ADR-0004 digest is not the one its manifest entry states",
                Integrity,
            ),
            Self::EvidenceBindingMismatch => (
                "evidence.binding_mismatch",
                "the report's own record of an artifact differs from the manifest's entry for it",
                Integrity,
            ),
            Self::EvidenceSignatureUnsupported => (
                "evidence.signature_unsupported",
                "the package claims a signature, which this ggctl cannot verify; it reports no package as signed or trusted",
                Invalid,
            ),
            Self::CapabilitiesUnavailable => (
                "compat.capabilities_unavailable",
                "the server does not serve the configuration capability document (HTTP 404)",
                Invalid,
            ),
            Self::UnsupportedCapabilitiesVersion => (
                "compat.unsupported_capabilities_version",
                "the server's capability document is a version this ggctl does not read",
                Invalid,
            ),
            Self::CapabilitiesInvalid => (
                "compat.capabilities_invalid",
                "the server's capability document is not a valid document of its version",
                Invalid,
            ),
            Self::UnsupportedSchemaVersion => (
                "schema.unsupported_api_version",
                "this ggctl publishes no schema for that kind at that document version",
                Invalid,
            ),
            Self::WarningsAsErrors => (
                "validate.warnings_as_errors",
                "--warnings-as-errors was given and a warning was reported",
                Invalid,
            ),
            Self::RequiredCheckFailed => (
                "doctor.required_check_failed",
                "a required doctor check failed",
                Invalid,
            ),
            Self::DriftFound => (
                "diff.drift_found",
                "--check was given and the bundles differ",
                Drift,
            ),
            Self::AnswersUnreadable => ("init.answers_unreadable", "the answers file could not be opened or read", Failure),
            Self::AnswersNotRegularFile => ("init.answers_not_regular_file", "the answers file is not a regular file", Usage),
            Self::AnswersUnsafePermissions => (
                "init.answers_unsafe_permissions",
                "the answers file, a directory above it or a link on its path is owned by an account other than root and this one, or is writable by group or other",
                Usage,
            ),
            Self::AnswersTooLarge => ("init.answers_too_large", "the answers file is larger than 64 KiB", Invalid),
            Self::UnsupportedTargetVersion => (
                "convert.unsupported_version",
                "--to is not a document version this ggctl can convert the bundle to",
                Invalid,
            ),
            Self::DowngradeRefused => (
                "convert.downgrade_refused",
                "--to is older than the bundle's document version, and ggctl never converts down",
                Invalid,
            ),
            Self::InPlaceUnavailable => (
                "convert.in_place_unavailable",
                "this ggctl cannot replace a bundle in place with a conversion that changes it; write it with --output",
                Invalid,
            ),
            Self::ManifestLink => (
                "pin.manifest_link",
                "bundle.yaml is a link or not a regular file, which ggctl pin never replaces; nothing was written",
                Invalid,
            ),
            Self::ManifestChanged => (
                "pin.manifest_changed",
                "bundle.yaml changed after ggctl pin read it; nothing was written",
                Conflict,
            ),
            Self::PinWriteFailed => (
                "pin.write_failed",
                "the new bundle.yaml could not be created, written, flushed or renamed into place; bundle.yaml was left as it was",
                Failure,
            ),
            Self::PinPermissionsUnavailable => (
                "pin.permissions_unavailable",
                "the filesystem did not keep owner-only permissions on the new bundle.yaml; bundle.yaml was left as it was",
                Failure,
            ),
            Self::ReadBackFailed => (
                "pin.read_back_failed",
                "the bundle did not read back as the files that were pinned, so a file changed while ggctl pin ran; run ggctl validate",
                Failure,
            ),
            Self::StateDirMissing => (
                "state_dir.missing",
                "nothing is at the --state-dir path",
                Invalid,
            ),
            Self::StateDirNotDirectory => (
                "state_dir.not_directory",
                "--state-dir names something other than a directory",
                Invalid,
            ),
            Self::StateDirLink => (
                "state_dir.link",
                "--state-dir names a symbolic link, junction or reparse point",
                Invalid,
            ),
            Self::StateDirUnsafePermissions => (
                "state_dir.unsafe_permissions",
                "the state directory is writable by group or other",
                Invalid,
            ),
            Self::StateDirUnsafeLockFile => (
                "state_dir.unsafe_lock_file",
                "the state directory's lock file is a link, not a regular file, or writable by group or other",
                Invalid,
            ),
            Self::StateDirLocked => (
                "state_dir.locked",
                "a gateway or another ggctl holds the state directory's lock; nothing was read or written",
                Conflict,
            ),
            Self::StateDirLockUnsupported => (
                "state_dir.lock_unsupported",
                "the state directory's filesystem cannot take an exclusive lock",
                Invalid,
            ),
            Self::StateDirUnavailable => (
                "state_dir.unavailable",
                "the state directory or its lock file could not be inspected, opened or locked",
                Failure,
            ),
            Self::LedgerMissing => (
                "ledger.missing",
                "the state directory holds no configuration ledger",
                Invalid,
            ),
            Self::LedgerExists => (
                "ledger.exists",
                "the state directory already holds a configuration ledger or a ledger's -wal, -shm or -journal file; nothing was written",
                Conflict,
            ),
            Self::LedgerUnsafeLocation => (
                "ledger.unsafe_location",
                "the state directory or the ledger file is a link, not the expected kind of entry, or writable by group or other",
                Invalid,
            ),
            Self::LedgerUnsupported => (
                "ledger.unsupported",
                "the configuration ledger uses a format or document version this ggctl does not support",
                Invalid,
            ),
            Self::LedgerCorrupt => (
                "ledger.corrupt",
                "the configuration ledger failed verification; the result names the class of corruption, and nothing was written",
                Invalid,
            ),
            Self::LedgerFull => (
                "ledger.full",
                "the configuration ledger already holds the most revisions it may; nothing was written",
                Invalid,
            ),
            Self::LedgerRefused => (
                "ledger.refused",
                "the configuration ledger refused to record the revision; nothing was written",
                Invalid,
            ),
            Self::LedgerStale => (
                "ledger.stale",
                "the configuration ledger's head changed while ggctl held its lock; nothing was written",
                Conflict,
            ),
            Self::LedgerUnavailable => (
                "ledger.unavailable",
                "the configuration ledger could not be read or written",
                Failure,
            ),
            Self::RollbackTargetUnknown => (
                "ledger.rollback_target_unknown",
                "REVISION is not a revision of this ledger; nothing was written",
                Invalid,
            ),
            Self::RollbackTargetIsHead => (
                "ledger.rollback_target_is_head",
                "REVISION is the desired revision already; nothing was written",
                Invalid,
            ),
            Self::RollbackTargetInvalid => (
                "ledger.rollback_target_invalid",
                "REVISION's stored content no longer passes the bundle reader's checks; nothing was written",
                Invalid,
            ),
            Self::HeadInvalid => (
                "ledger.head_invalid",
                "the desired revision's stored content no longer passes the bundle reader's checks, so no rollback can be assessed against it; nothing was written",
                Invalid,
            ),
            Self::ChangeNotApplicable => (
                "ledger.change_not_applicable",
                "the rollback changes what no configuration revision can carry; nothing was written",
                Invalid,
            ),
            Self::ChangeUnclassified => (
                "ledger.change_unclassified",
                "the rollback differs in a way the semantic diff could not classify; nothing was written",
                Invalid,
            ),
            Self::NotNormalizable => (
                "ledger.not_normalizable",
                "REVISION's stored content has no canonical form; nothing was written",
                Invalid,
            ),
            Self::NoChange => (
                "ledger.no_change",
                "rolling back to REVISION changes nothing; nothing was written",
                Invalid,
            ),
            Self::AcknowledgementRequired => (
                "ledger.acknowledgement_required",
                "the rollback carries risk codes, each of which must be named with --acknowledge; nothing was written",
                Invalid,
            ),
            Self::AcknowledgementMismatch => (
                "ledger.acknowledgement_mismatch",
                "--acknowledge must name exactly the rollback's risk codes; nothing was written",
                Invalid,
            ),
            Self::NothingToAcknowledge => (
                "ledger.nothing_to_acknowledge",
                "--acknowledge was given but the rollback carries no risk code; nothing was written",
                Invalid,
            ),
            Self::UnexpectedRefusal => (
                "ledger.unexpected_refusal",
                "the revision service refused the rollback for a reason an offline command does not expect; nothing was written",
                Failure,
            ),
            Self::GatewayRecompilesAtStart => (
                "ledger.gateway_recompiles_at_start",
                "a gateway starting from this ledger compiles its desired revision again, with the production policy and tools validators, and refuses to start if it does not compile",
                Success,
            ),
            Self::BackupStdoutRefused => (
                "backup.stdout_refused",
                "a backup is never written to standard output; name a new file with --output",
                Usage,
            ),
            Self::BackupOutputExists => (
                "backup.output_exists",
                "something exists at the --output path, which a backup never replaces; nothing was written",
                Conflict,
            ),
            Self::BackupOutputUnusable => (
                "backup.output_unusable",
                "the archive or its working files could not be created, written, flushed or linked into place beside --output; nothing was left at it",
                Failure,
            ),
            Self::BackupPermissionsUnavailable => (
                "backup.permissions_unavailable",
                "the filesystem did not keep the archive owner-only; nothing was left at --output",
                Failure,
            ),
            Self::BackupNothingToBackUp => (
                "backup.nothing_to_back_up",
                "the state directory holds none of the stores of the standalone layout",
                Invalid,
            ),
            Self::BackupStoreLink => (
                "backup.store_link",
                "a store's file is a symbolic link, junction or reparse point; nothing was written",
                Invalid,
            ),
            Self::BackupStoreNotRegularFile => (
                "backup.store_not_regular_file",
                "a store's name in the state directory is not a regular file; nothing was written",
                Invalid,
            ),
            Self::BackupStoreUnsafePermissions => (
                "backup.store_unsafe_permissions",
                "a store's file is writable by group or other; nothing was written",
                Invalid,
            ),
            Self::BackupStoreUnavailable => (
                "backup.store_unavailable",
                "a store could not be opened, read or snapshotted; nothing was written",
                Failure,
            ),
            Self::BackupStoreCorrupt => (
                "backup.store_corrupt",
                "a store is not a SQLite database this ggctl can back up, or fails SQLite's integrity check; nothing was written",
                Invalid,
            ),
            Self::BackupLedgerInvalid => (
                "backup.ledger_invalid",
                "the configuration revision ledger does not pass its verification; nothing was written",
                Invalid,
            ),
            Self::BackupLedgerShared => (
                "backup.ledger_shared",
                "the configuration revision ledger is the same file as another store; nothing was written",
                Invalid,
            ),
            Self::BackupArchiveUnreadable => (
                "backup.archive_unreadable",
                "the archive could not be opened or read",
                Failure,
            ),
            Self::BackupArchiveNotRegularFile => (
                "backup.archive_not_regular_file",
                "the archive is a symbolic link, junction or reparse point, or not a regular file",
                Invalid,
            ),
            Self::BackupArchiveTooLarge => (
                "backup.archive_too_large",
                "the archive is longer than any backup can be",
                Integrity,
            ),
            Self::BackupStagingUnavailable => (
                "backup.staging_unavailable",
                "the staging directory beside the archive could not be created, written or read",
                Failure,
            ),
            Self::BackupNotABackup => (
                "backup.not_a_backup",
                "the file is not a GreenGateway backup archive",
                Integrity,
            ),
            Self::BackupPostgresUnsupported => (
                "backup.postgres_unsupported",
                "the file is a PostgreSQL dump: PostgreSQL and cluster state is backed up and restored with the PostgreSQL runbooks, never with ggctl backup",
                Invalid,
            ),
            Self::BackupUnsupportedArchiveVersion => (
                "backup.unsupported_archive_version",
                "the archive is a container version this ggctl does not read",
                Integrity,
            ),
            Self::BackupManifestMissing => (
                "backup.manifest_missing",
                "the archive's first entry is not its GatewayBackup manifest",
                Integrity,
            ),
            Self::BackupManifestInvalid => (
                "backup.manifest_invalid",
                "the manifest is not a valid GatewayBackup document, or its inventory, entries and counts disagree",
                Integrity,
            ),
            Self::BackupUnsupportedManifestVersion => (
                "backup.unsupported_manifest_version",
                "the manifest is not a GatewayBackup document version this ggctl reads",
                Integrity,
            ),
            Self::BackupUnexpectedEntry => (
                "backup.unexpected_entry",
                "an entry is not the next one the manifest lists",
                Integrity,
            ),
            Self::BackupEntryMissing => (
                "backup.entry_missing",
                "the archive ends before an entry the manifest lists",
                Integrity,
            ),
            Self::BackupArchiveDigestMismatch => (
                "backup.archive_digest_mismatch",
                "the archive's end record does not hold the digest of the archive before it",
                Integrity,
            ),
            Self::BackupChecksumMismatch => (
                "backup.checksum_mismatch",
                "an entry's bytes do not match the SHA-256 the manifest records",
                Integrity,
            ),
            Self::BackupStoreIntegrityFailed => (
                "backup.store_integrity_failed",
                "an entry is not a SQLite database in rollback-journal mode that passes SQLite's integrity check",
                Integrity,
            ),
            Self::BackupStoreMismatch => (
                "backup.store_mismatch",
                "an entry's header versions, schema or table rows are not what the manifest records",
                Integrity,
            ),
            Self::BackupLedgerVerificationFailed => (
                "backup.ledger_verification_failed",
                "the archive's configuration revision ledger does not pass the ledger's verification",
                Integrity,
            ),
            Self::BackupLedgerMismatch => (
                "backup.ledger_mismatch",
                "the archive's ledger verifies but does not hold the revisions the manifest names",
                Integrity,
            ),
            Self::BackupSecretKeysNotIncluded => (
                "backup.secret_keys_not_included",
                "the backup holds the Connections store's secrets as ciphertext only; back up the key files under CONNECTION_SECRETS_ROOT separately, or they cannot be decrypted after a restore",
                Success,
            ),
            Self::RestoreTargetNotEmpty => (
                "restore.target_not_empty",
                "the state directory holds stores and --replace-existing-state was not given; it was left as it was",
                Conflict,
            ),
            Self::RestoreTargetNotStateDir => (
                "restore.target_not_state_dir",
                "the state directory holds an entry the state-directory layout does not name, or a store name that is not a regular file; it was left as it was",
                Invalid,
            ),
            Self::RestoreTargetMountPoint => (
                "restore.target_mount_point",
                "the state directory is a mount point, which a restore cannot rename within its parent; it was left as it was",
                Invalid,
            ),
            Self::RestoreTargetUnavailable => (
                "restore.target_unavailable",
                "the state directory's entries, or the directory holding it, could not be read; it was left as it was",
                Failure,
            ),
            Self::RestoreStagingUnavailable => (
                "restore.staging_unavailable",
                "the staging directory beside the state directory could not be created, written or flushed; the state directory was left as it was",
                Failure,
            ),
            Self::RestorePermissionsUnavailable => (
                "restore.permissions_unavailable",
                "the filesystem did not keep the staged stores owner-only; the state directory was left as it was",
                Failure,
            ),
            Self::RestoreStoreIdentityMismatch => (
                "restore.store_identity_mismatch",
                "an archive entry does not carry the SQLite application ID of the store it would restore; the state directory was left as it was",
                Integrity,
            ),
            Self::RestoreTargetChanged => (
                "restore.target_changed",
                "the state directory's entries changed while the restore ran; it was put back as it was",
                Conflict,
            ),
            Self::RestoreSwitchFailed => (
                "restore.switch_failed",
                "the restored directory could not be moved into the state directory's place; the state directory was left as it was",
                Failure,
            ),
            Self::RestoreRollbackFailed => (
                "restore.rollback_failed",
                "the restored directory could not take the state directory's place and the state directory could not be moved back: it is beside its name, under a hidden name with .ggrestore-previous-",
                Failure,
            ),
            Self::RestoreDirectoryNotFlushed => (
                "restore.directory_not_flushed",
                "the restore is in place, but the directory holding the state directory could not be flushed; a crash before the filesystem writes it could undo it",
                Success,
            ),
            Self::RestorePreviousNotRemoved => (
                "restore.previous_not_removed",
                "the restore is in place, but the replaced stores could not all be removed: they are beside the state directory, under a hidden name with .ggrestore-previous-; delete them",
                Success,
            ),
            Self::RestoreSecretKeysRequired => (
                "restore.secret_keys_required",
                "the restored Connections store holds its secrets as ciphertext only; put the key files under CONNECTION_SECRETS_ROOT back from their own backup before the gateway starts",
                Success,
            ),
            Self::WriteFailed => ("output.write_failed", "the output could not be written", Failure),
            Self::DestinationExists => (
                "output.destination_exists",
                "the output directory exists and is not empty, or is a link or a file; nothing was written",
                Conflict,
            ),
            Self::DestinationUnusable => (
                "output.destination_unusable",
                "the output directory could not be written; nothing was left at it",
                Failure,
            ),
            Self::PermissionsUnavailable => (
                "output.permissions_unavailable",
                "the filesystem did not keep owner-only permissions on the files written; nothing was left at the output directory",
                Failure,
            ),
            Self::WrittenBundleInvalid => (
                "output.written_bundle_invalid",
                "the files written did not read back as the same valid bundle; nothing was left at the output directory",
                Failure,
            ),
            Self::RuntimeUnavailable => ("internal.runtime_unavailable", "the asynchronous runtime could not be started", Failure),
            Self::ClientUnavailable => ("internal.client_unavailable", "the HTTP client could not be built", Failure),
        }
    }
}

/// One diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Diagnostic {
    pub(crate) code: Code,
    /// The 1-based position of the argument after `ggctl` it is about.
    pub(crate) argument: Option<usize>,
    /// Fixed guidance chosen by the caller from static text.
    pub(crate) hint: Option<&'static str>,
}

impl Diagnostic {
    pub(crate) fn new(code: Code) -> Self {
        Self {
            code,
            argument: None,
            hint: None,
        }
    }

    pub(crate) fn at(code: Code, argument: usize) -> Self {
        Self {
            argument: Some(argument),
            ..Self::new(code)
        }
    }

    pub(crate) fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }

    /// A code that leaves the exit status alone is information; every
    /// other one is an error. Warnings come only from the bundle reader.
    pub(crate) fn severity(&self) -> &'static str {
        if self.code.exit() == Exit::Success {
            "info"
        } else {
            "error"
        }
    }
}

impl From<Code> for Diagnostic {
    fn from(code: Code) -> Self {
        Self::new(code)
    }
}

/// The human form written to standard error.
impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ggctl: {}: {}: {}",
            self.severity(),
            self.code.as_str(),
            self.code.message()
        )?;
        if let Some(argument) = self.argument {
            write!(formatter, " (argument {argument})")?;
        }
        if let Some(hint) = self.hint {
            write!(formatter, "\n  hint: {hint}")?;
        }
        write!(formatter, "\n  see: {}", self.code.remediation())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn exit_codes_are_the_published_table() {
        let codes: Vec<_> = Exit::ALL.iter().map(|exit| exit.code()).collect();
        assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
        let names: BTreeSet<_> = Exit::ALL.iter().map(|exit| exit.name()).collect();
        assert_eq!(names.len(), Exit::ALL.len());
    }

    #[test]
    fn codes_are_unique_lowercase_family_reason_pairs_in_documented_families() {
        let mut seen = BTreeSet::new();
        for code in Code::ALL {
            let text = code.as_str();
            assert!(seen.insert(text), "{text} is not unique");
            let (family, reason) = text.split_once('.').expect("family.reason");
            assert!(FAMILIES.contains(&family), "{text}");
            assert!(code
                .remediation()
                .ends_with(&format!("#{family}-diagnostics")));
            for segment in [family, reason] {
                assert!(
                    segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase())
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        }),
                    "{text}"
                );
            }
            assert!(!code.message().is_empty());
        }
    }

    fn reference() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ggctl.md"))
            .expect("docs/ggctl.md should be readable")
            .replace("\r\n", "\n")
    }

    /// The text of one `### Heading` section, up to the next heading.
    fn section<'a>(document: &'a str, heading: &str) -> &'a str {
        let start = document
            .find(&format!("\n### {heading}\n"))
            .unwrap_or_else(|| panic!("docs/ggctl.md has no `### {heading}` section"));
        let body = &document[start + heading.len() + 6..];
        body.find("\n#").map_or(body, |end| &body[..end])
    }

    #[test]
    fn the_reference_documents_every_code_in_its_family_with_its_exit() {
        let document = reference();
        for family in FAMILIES {
            let mut heading = (*family).to_owned();
            heading[..1].make_ascii_uppercase();
            let section = section(&document, &format!("{heading} diagnostics"));
            let documented: Vec<_> = section
                .lines()
                .filter_map(|line| line.strip_prefix("| `"))
                .filter_map(|line| line.split_once('`'))
                .map(|(code, rest)| (code.to_owned(), rest.to_owned()))
                .collect();
            let codes: Vec<_> = Code::ALL
                .iter()
                .filter(|code| code.family() == *family)
                .collect();
            assert_eq!(
                documented
                    .iter()
                    .map(|(code, _)| code.as_str())
                    .collect::<Vec<_>>(),
                codes.iter().map(|code| code.as_str()).collect::<Vec<_>>(),
                "the {family} section must list exactly its codes, in order"
            );
            for ((_, row), code) in documented.iter().zip(codes) {
                assert!(
                    row.starts_with(&format!(" | {} | ", code.exit().code())),
                    "{}: documented exit differs",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn the_reference_documents_every_exit_code() {
        let document = reference();
        for exit in Exit::ALL {
            assert!(
                document.contains(&format!("\n| `{}` | `{}` | ", exit.code(), exit.name())),
                "{}",
                exit.name()
            );
        }
    }

    #[test]
    fn the_outcome_that_may_have_committed_is_never_hidden_and_retryable_never_masks() {
        let diagnostics = [
            Diagnostic::new(Code::ConnectFailed),
            Diagnostic::new(Code::Unauthenticated),
            Diagnostic::new(Code::Timeout),
        ];
        assert_eq!(Exit::of(&diagnostics), Exit::Failure);
        assert_eq!(Exit::of(&diagnostics[..2]), Exit::Denied);
        assert_eq!(Exit::of(&diagnostics[..1]), Exit::Unavailable);
        assert_eq!(
            Exit::of(&[
                Diagnostic::new(Code::ServerUnavailable),
                Diagnostic::new(Code::CapabilitiesInvalid)
            ]),
            Exit::Invalid
        );
        assert_eq!(Exit::of(&[]), Exit::Success);
    }

    #[test]
    fn the_human_form_names_the_position_and_never_a_value() {
        let text = Diagnostic::at(Code::UnknownOption, 3)
            .with_hint("run `ggctl help`")
            .to_string();
        assert_eq!(
            text,
            "ggctl: error: usage.unknown_option: an argument is not an option this command accepts (argument 3)\n  hint: run `ggctl help`\n  see: docs/ggctl.md#usage-diagnostics"
        );
    }
}
