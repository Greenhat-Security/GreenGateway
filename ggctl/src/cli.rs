//! The command table and the argument parser.
//!
//! One static table defines every command, argument and option. Help text
//! (`help.rs`) and shell completion (`completion.rs`) are generated from it,
//! and the parser accepts exactly what it lists, so the three cannot drift.
//! A command family (`ggctl ledger`, `ggctl backup`) is a name whose commands
//! are listed in the table under their full names (`ledger seed`,
//! `backup create`).
//!
//! Before anything else the parser refuses any argument that looks like a
//! secret-carrying or verification-disabling option, wherever it appears, so
//! a token typed as `--token=...` is refused rather than parsed, echoed or
//! reported back. Diagnostics name argument positions, never spellings.

use std::ffi::{OsStr, OsString};

use crate::{
    diagnostic::{Code, Diagnostic, Exit},
    report::Io,
};

/// What an argument or option value holds; completion uses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueKind {
    /// A local file path.
    Path,
    /// A URL.
    Url,
    /// A whole number of seconds.
    Seconds,
    /// A document version string.
    Text,
    /// One of a fixed set of words.
    Choice(&'static [&'static str]),
}

#[derive(Debug)]
pub(crate) struct OptionSpec {
    pub(crate) name: &'static str,
    /// The placeholder and kind of the option's value; `None` for a flag.
    pub(crate) value: Option<(&'static str, ValueKind)>,
    /// The option may be given more than once, and every value is kept in
    /// order. Any other option given twice is a usage error.
    pub(crate) repeatable: bool,
    pub(crate) help: &'static str,
}

#[derive(Debug)]
pub(crate) struct ArgumentSpec {
    pub(crate) name: &'static str,
    pub(crate) kind: ValueKind,
    pub(crate) required: bool,
    pub(crate) help: &'static str,
}

pub(crate) struct CommandSpec {
    pub(crate) name: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) description: &'static [&'static str],
    pub(crate) arguments: &'static [ArgumentSpec],
    pub(crate) options: &'static [OptionSpec],
    pub(crate) run: fn(&Invocation, &mut Io<'_>) -> Exit,
}

impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl CommandSpec {
    /// How many words the command's name is: two for a family's command.
    pub(crate) fn words(&self) -> usize {
        self.name.split(' ').count()
    }

    /// The family the command belongs to, if any.
    pub(crate) fn family(&self) -> Option<&'static FamilySpec> {
        let (family, _) = self.name.split_once(' ')?;
        FAMILIES.iter().find(|spec| spec.name == family)
    }
}

/// A family of commands under one name.
#[derive(Debug)]
pub(crate) struct FamilySpec {
    pub(crate) name: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) description: &'static [&'static str],
    /// The second word of each of its commands, in table order.
    pub(crate) commands: &'static [&'static str],
    /// Fixed guidance for a command line that names the family alone.
    pub(crate) hint: &'static str,
}

impl FamilySpec {
    /// The family's commands, in table order.
    pub(crate) fn members(&self) -> impl Iterator<Item = &'static CommandSpec> + '_ {
        COMMANDS.iter().filter(move |command| {
            command
                .family()
                .is_some_and(|family| family.name == self.name)
        })
    }
}

pub(crate) const FORMAT_HUMAN: &str = "human";
pub(crate) const FORMAT_JSON: &str = "json";
pub(crate) const FORMAT_SARIF: &str = "sarif";

pub(crate) const SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell"];
pub(crate) const SCHEMA_KINDS: &[&str] = &[
    gateway_config::documents::BUNDLE_KIND,
    gateway_config::documents::DEPLOYMENT_KIND,
    gateway_config::documents::INIT_ANSWERS_KIND,
    gateway_config::documents::CAPABILITIES_KIND,
    gateway_config::documents::REPORT_KIND,
    gateway_config::documents::BACKUP_KIND,
];
/// The deployment profiles, as `gateway_config::bundle::Profile` names them.
pub(crate) const PROFILES: &[&str] = &["production", "migration", "development"];
/// Every risk code, as `gateway_config::semantic_diff::RiskCode` names them.
pub(crate) const RISK_CODES: &[&str] = &[
    "risk.admin_access_path_removed",
    "risk.audit_durability_reduced",
    "risk.auth_disabled",
    "risk.auth_observe_only",
    "risk.auth_trust_changed",
    "risk.cookie_or_csrf_weakened",
    "risk.cors_broadened",
    "risk.credential_binding_changed",
    "risk.data_exposure_increased",
    "risk.egress_broadened",
    "risk.evidence_not_required",
    "risk.exemptions_broadened",
    "risk.limits_loosened",
    "risk.listener_exposed",
    "risk.plaintext_transport",
    "risk.policy_broadened",
    "risk.policy_default_allow",
    "risk.private_egress_allowed",
    "risk.profile_changed",
    "risk.public_origin_changed",
    "risk.routing_changed",
    "risk.shadow_enabled",
    "risk.storage_changed",
    "risk.tls_weakened",
    "risk.tool_surface_broadened",
    "risk.trusted_proxies_changed",
    "risk.unknown_impact",
];
#[cfg(test)]
const COMMAND_NAMES: &[&str] = &[
    "version",
    "schema",
    "init",
    "validate",
    "pin",
    "convert",
    "doctor",
    "diff",
    "ledger seed",
    "ledger verify",
    "ledger rollback",
    "backup create",
    "backup verify",
    "completion",
    "help",
];
/// What `ggctl help` describes: every command outside a family, and every
/// family.
pub(crate) const HELP_TOPICS: &[&str] = &[
    "version",
    "schema",
    "init",
    "validate",
    "pin",
    "convert",
    "doctor",
    "diff",
    "ledger",
    "backup",
    "completion",
    "help",
];
const LEDGER_COMMANDS: &[&str] = &["seed", "verify", "rollback"];
const BACKUP_COMMANDS: &[&str] = &["create", "verify"];
/// The second word of every family's commands, once each, for `ggctl help`.
const SUBCOMMANDS: &[&str] = &["seed", "verify", "rollback", "create"];

const FORMAT: OptionSpec = OptionSpec {
    name: "--format",
    value: Some(("FORMAT", ValueKind::Choice(&[FORMAT_HUMAN, FORMAT_JSON]))),
    repeatable: false,
    help: "human (default) or json: one GgctlReport document on standard output",
};
/// `validate` and `diff` also offer SARIF (ADR-0008, "Output contract"; for
/// `diff`, an addition made with the semantic diff).
const VALIDATE_FORMAT: OptionSpec = OptionSpec {
    name: "--format",
    value: Some((
        "FORMAT",
        ValueKind::Choice(&[FORMAT_HUMAN, FORMAT_JSON, FORMAT_SARIF]),
    )),
    repeatable: false,
    help: "human (default), json (one GgctlReport document) or sarif (one SARIF 2.1.0 log) on standard output",
};
const STRICT: OptionSpec = OptionSpec {
    name: "--strict",
    value: None,
    repeatable: false,
    help:
        "refuse, rather than warn about, a bundle directory entry the manifest does not reference",
};
const WARNINGS_AS_ERRORS: OptionSpec = OptionSpec {
    name: "--warnings-as-errors",
    value: None,
    repeatable: false,
    help: "exit 3 when any warning is reported",
};
const AGAINST: OptionSpec = OptionSpec {
    name: "--against",
    value: Some(("BUNDLE", ValueKind::Path)),
    repeatable: false,
    help: "the bundle directory to compare BUNDLE with (required): the change is from it to BUNDLE",
};
const CHECK: OptionSpec = OptionSpec {
    name: "--check",
    value: None,
    repeatable: false,
    help: "exit 4 when the bundles differ at all",
};
const BUNDLE: ArgumentSpec = ArgumentSpec {
    name: "BUNDLE",
    kind: ValueKind::Path,
    required: true,
    help: "the bundle directory, which holds bundle.yaml",
};
const REVISION: ArgumentSpec = ArgumentSpec {
    name: "REVISION",
    kind: ValueKind::Text,
    required: true,
    help: "the revision to roll back to: rev- and 32 lowercase hexadecimal digits, as ggctl ledger verify reports one",
};
const SERVER: OptionSpec = OptionSpec {
    name: "--server",
    value: Some(("URL", ValueKind::Url)),
    repeatable: false,
    help: "the admin API base, https://HOST[:PORT]/v1<ADMIN_PREFIX>; plain http only for a loopback IP literal",
};
const CA_FILE: OptionSpec = OptionSpec {
    name: "--ca-file",
    value: Some(("PATH", ValueKind::Path)),
    repeatable: false,
    help: "a PEM file of trust anchors added to the platform's for an https --server",
};
const TOKEN_STDIN: OptionSpec = OptionSpec {
    name: "--token-stdin",
    value: None,
    repeatable: false,
    help: "read the admin bearer token from standard input, which must be a pipe or file",
};
const TOKEN_FILE: OptionSpec = OptionSpec {
    name: "--token-file",
    value: Some(("PATH", ValueKind::Path)),
    repeatable: false,
    help: "read the admin bearer token from a regular file of at most 8 KiB, owner-only on Unix",
};
const TIMEOUT: OptionSpec = OptionSpec {
    name: "--timeout",
    value: Some(("SECONDS", ValueKind::Seconds)),
    repeatable: false,
    help: "the time allowed for each request, 1 to 300 seconds (default 30)",
};
const PROFILE: OptionSpec = OptionSpec {
    name: "--profile",
    value: Some(("PROFILE", ValueKind::Choice(PROFILES))),
    repeatable: false,
    help: "production, migration or development (required): the deployment profile the bundle declares",
};
const OUTPUT: OptionSpec = OptionSpec {
    name: "--output",
    value: Some(("DIR", ValueKind::Path)),
    repeatable: false,
    help: "the bundle directory to create: it must not exist, or must be an empty directory",
};
const ANSWERS: OptionSpec = OptionSpec {
    name: "--answers",
    value: Some(("FILE", ValueKind::Path)),
    repeatable: false,
    help: "a GatewayInitAnswers document (YAML, or JSON when FILE ends in .json) to use instead of the defaults",
};
const TO: OptionSpec = OptionSpec {
    name: "--to",
    value: Some(("VERSION", ValueKind::Text)),
    repeatable: false,
    help: "the document version to convert to (required), such as greengateway.dev/v1alpha1",
};
const IN_PLACE: OptionSpec = OptionSpec {
    name: "--in-place",
    value: None,
    repeatable: false,
    help: "convert BUNDLE where it is instead of writing --output",
};
const API_VERSION: OptionSpec = OptionSpec {
    name: "--api-version",
    value: Some(("VERSION", ValueKind::Text)),
    repeatable: false,
    help: "the document version to print (default: the newest this ggctl publishes)",
};
const STATE_DIR: OptionSpec = OptionSpec {
    name: "--state-dir",
    value: Some(("DIR", ValueKind::Path)),
    repeatable: false,
    help: "the standalone state directory (required), which ggctl holds under its exclusive lock while it runs",
};
const ACKNOWLEDGE: OptionSpec = OptionSpec {
    name: "--acknowledge",
    value: Some(("RISK_CODE", ValueKind::Choice(RISK_CODES))),
    repeatable: true,
    help: "acknowledge one risk code of the rollback; give it once for each code, since every code must be named",
};
const BACKUP_OUTPUT: OptionSpec = OptionSpec {
    name: "--output",
    value: Some(("FILE", ValueKind::Path)),
    repeatable: false,
    help:
        "the backup archive to create (required): it must not exist, and is never standard output",
};
const ARCHIVE: ArgumentSpec = ArgumentSpec {
    name: "FILE",
    kind: ValueKind::Path,
    required: true,
    help: "the backup archive, as ggctl backup create wrote it",
};

pub(crate) const FAMILIES: &[FamilySpec] = &[
    FamilySpec {
        name: "ledger",
        summary: "Seed, verify or roll back a standalone configuration revision ledger, offline",
        description: &[
            "The offline commands over the configuration revision ledger beneath a standalone \
             state directory (docs/configuration-ledger.md). Each takes the state directory's \
             exclusive lock first, so it runs only while no gateway or other ggctl holds it, and \
             exits 5 when one does. None makes a network request or reads an environment \
             variable, and none writes gateway audit events: a revision's record is its \
             evidence.",
        ],
        commands: LEDGER_COMMANDS,
        hint: "run `ggctl help ledger` for the ledger commands",
    },
    FamilySpec {
        name: "backup",
        summary: "Back up a standalone state directory, or verify a backup, offline",
        description: &[
            "The offline commands over standalone backups (docs/standalone-backup.md): one \
             archive of the stores beneath a state directory, with a GatewayBackup manifest of \
             versions, inventory, counts and checksums. A backup is sensitive recovery material, \
             not configuration. It never holds a plaintext token, a secret value or a key: the \
             Connections store keeps its secrets as ciphertext, and the key files under \
             CONNECTION_SECRETS_ROOT are a separate artifact to back up separately. None of \
             these commands makes a network request or reads an environment variable, and none \
             writes gateway audit events.",
        ],
        commands: BACKUP_COMMANDS,
        hint: "run `ggctl help backup` for the backup commands",
    },
];

pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "version",
        summary: "Print this ggctl's version and, with --server, check a gateway is compatible",
        description: &[
            "Prints the ggctl version and the document versions whose schemas it publishes.",
            "With --server it reads the gateway's configuration capability document \
             (GET <server>/config/capabilities, permission admin:config:read) and reports the \
             gateway version and whether this ggctl can work with it. It exits 3 when it \
             cannot. A configuration command refuses a server this check rejects; this \
             command still reports what it found.",
        ],
        arguments: &[],
        options: &[SERVER, CA_FILE, TOKEN_STDIN, TOKEN_FILE, TIMEOUT, FORMAT],
        run: crate::version::run,
    },
    CommandSpec {
        name: "schema",
        summary: "List the published document schemas or print one",
        description: &[
            "Without KIND, lists every document kind and version this ggctl publishes a \
             JSON Schema (Draft 2020-12) for. With KIND, writes that schema to standard \
             output exactly as published under docs/schemas.",
            "A schema is necessary but not sufficient: the gateway's reader is authoritative.",
        ],
        arguments: &[ArgumentSpec {
            name: "KIND",
            kind: ValueKind::Choice(SCHEMA_KINDS),
            required: false,
            help: "the document kind to print",
        }],
        options: &[API_VERSION, FORMAT],
        run: crate::schema::run,
    },
    CommandSpec {
        name: "init",
        summary: "Create a new configuration bundle for a deployment profile",
        description: &[
            "Writes a new greengateway.dev/v1alpha1 bundle into --output: bundle.yaml, a \
             deployment document declaring --profile and, for the standalone topology, a policy \
             that denies by default with no role and a tools document with no tools. An answers \
             document (--answers) names the bundle, chooses the cluster topology, whose policy \
             and tools stay with the server, or binds an operator role to one issuer; nothing \
             it can hold, and nothing ggctl writes, is a secret.",
            "The files are written into a new hidden directory beside --output, owner-only on \
             Unix, read back with the gateway's bundle reader, and only then renamed into \
             place, so nothing that looks like a bundle is left behind on failure. An existing \
             --output is refused unless it is an empty directory. ggctl prompts for nothing, \
             starts nothing and makes no network request. Exits 0 when the bundle was written, \
             3 for invalid answers, 5 when --output is not empty, and 1 when it could not be \
             written.",
        ],
        arguments: &[],
        options: &[PROFILE, OUTPUT, ANSWERS, FORMAT],
        run: crate::init::run,
    },
    CommandSpec {
        name: "validate",
        summary: "Validate a configuration bundle offline",
        description: &[
            "Reads the bundle in the directory BUNDLE with the gateway's own bundle reader and \
             reports every problem it finds: unsafe files and bounds, the YAML subset and strict \
             JSON, exact document versions, closed documents, references and SHA-256 pins, the \
             published policy and tools schemas, and the deployment profile's policy invariants. \
             It makes no network request, reads no environment variable and writes nothing.",
            "The gateway's production policy and tools validators are not part of ggctl and do \
             not run, and the report says so. Exits 0 for a valid bundle, 3 for an invalid one \
             (or any warning with --warnings-as-errors), and 1 when the bundle could not be read.",
        ],
        arguments: &[BUNDLE],
        options: &[STRICT, WARNINGS_AS_ERRORS, VALIDATE_FORMAT],
        run: crate::validate::run,
    },
    CommandSpec {
        name: "pin",
        summary: "Rewrite a bundle's SHA-256 pins for files that validate",
        description: &[
            "The only command that rewrites manifest digests. Reads the bundle in the directory \
             BUNDLE as validate does, with every check except the comparison of each referenced \
             file with its pin, and pins nothing unless every file passes: then each pin that \
             differs from its file's SHA-256 is replaced digit for digit, so every other byte of \
             bundle.yaml, comments and order included, is kept. A pin to replace must be its 64 \
             digits between quotes, as init writes it.",
            "The new manifest is written to a new hidden file beside bundle.yaml, owner-only on \
             Unix, flushed and renamed over it, so an interrupted write never leaves a partial \
             manifest; bundle.yaml must be a regular file, not a link, and must not change while \
             ggctl runs. The bundle is then read back with every check and its new source digest \
             reported. It makes no network request and reads no environment variable. Exits 0 \
             when pinned (or already pinned), 3 when a file is invalid or bundle.yaml is a link, \
             5 when bundle.yaml changed meanwhile, and 1 when the bundle could not be read or \
             written.",
        ],
        arguments: &[BUNDLE],
        options: &[STRICT, FORMAT],
        run: crate::pin::run,
    },
    CommandSpec {
        name: "convert",
        summary: "Convert a configuration bundle to another document version",
        description: &[
            "Reads the bundle in the directory BUNDLE as validate does and converts it to the \
             document version --to names exactly: step by step from its own version, never \
             down, so converting the result again changes nothing. --output writes the \
             converted bundle as a new directory, the way init writes one; --in-place leaves \
             BUNDLE where it is.",
            "greengateway.dev/v1alpha1 is the only document version, so a bundle is already at \
             every version ggctl can convert to: --output copies its files unchanged and \
             --in-place changes nothing. Exits 0 when converted, 3 for an invalid bundle, an \
             unknown --to or a downgrade, 5 when --output is not empty, and 1 when the bundle \
             could not be read or written.",
        ],
        arguments: &[BUNDLE],
        options: &[TO, OUTPUT, IN_PLACE, STRICT, FORMAT],
        run: crate::convert::run,
    },
    CommandSpec {
        name: "doctor",
        summary: "Diagnose a configuration bundle offline",
        description: &[
            "Runs the offline checks on the bundle in the directory BUNDLE: each stage of the \
             gateway's bundle reader as its own check, the deployment profile, and the checks \
             ggctl cannot run here. Every check has a stable ID, a severity, a status (pass, \
             warning, fail or skipped), a reason code and a duration; skipped never counts as \
             pass. It makes no network request, reads no environment variable and writes nothing.",
            "Exits 0 when no required check failed, 3 when one did, and 1 when the bundle could \
             not be read.",
        ],
        arguments: &[BUNDLE],
        options: &[FORMAT],
        run: crate::doctor::run,
    },
    CommandSpec {
        name: "diff",
        summary: "Compare two configuration bundles semantically and classify each change's risk",
        description: &[
            "Reads BUNDLE and the --against bundle with the gateway's own bundle reader, as \
             validate does, and compares what they configure rather than their text: the \
             manifest, the deployment document and the policy and tools documents, member by \
             member. Each change is reported with its change class, whether it loosens or \
             tightens a control, and stable risk codes (docs/semantic-diff.md); no value is \
             ever shown, and a secret only as a changed reference. It makes no network request, \
             reads no environment variable and writes nothing.",
            "Exits 0 when both bundles were compared, 4 with --check when they differ, 3 when \
             either bundle is invalid (they are then not compared), and 1 when one could not be \
             read. --format sarif reports each risk code of each change as a result.",
        ],
        arguments: &[BUNDLE],
        options: &[AGAINST, CHECK, STRICT, VALIDATE_FORMAT],
        run: crate::diff::run,
    },
    CommandSpec {
        name: "ledger seed",
        summary: "Create a state directory's revision ledger from a bundle",
        description: &[
            "Reads the bundle in the directory BUNDLE with the gateway's own bundle reader, \
             strictly (an entry the manifest does not reference is an error), takes the \
             exclusive lock of the state directory --state-dir names, and creates its \
             configuration revision ledger with the bundle as the first revision: desired, and \
             not active until a gateway starts from it. The ledger is built under a temporary \
             name and linked into place only once complete, so an interrupted seed leaves no \
             ledger. A state directory that already holds a ledger, or a ledger's -wal, -shm \
             or -journal file, is refused and left as it is.",
            "The gateway's production policy and tools validators are not part of ggctl and do \
             not run, and the report says so: a gateway starting from the ledger compiles the \
             revision again with them and refuses to start if it does not compile. Exits 0 when \
             seeded, 3 for an invalid bundle or an unusable state directory, 5 when the state \
             directory is locked or already holds a ledger, and 1 when the bundle or the ledger \
             could not be read or written.",
        ],
        arguments: &[BUNDLE],
        options: &[STATE_DIR, FORMAT],
        run: crate::ledger::seed,
    },
    CommandSpec {
        name: "ledger verify",
        summary: "Verify a state directory's revision ledger, read-only",
        description: &[
            "Takes the exclusive lock of the state directory --state-dir names, opens its \
             configuration revision ledger read-only and verifies all of it, as a gateway does \
             at start: the file's location and permissions, the SQLite page structure, the \
             exact schema, every record and its hash, the whole chain, every document against \
             its pin and the pointer. It reports the desired and active revisions and how many \
             revisions the ledger holds, or the class of corruption it found. Nothing in the \
             ledger is written.",
            "Exits 0 when the ledger verifies, 3 when it is corrupt, missing, unsupported or \
             unsafely placed, 5 when the state directory is locked, and 1 when the ledger could \
             not be read.",
        ],
        arguments: &[],
        options: &[STATE_DIR, FORMAT],
        run: crate::ledger::verify,
    },
    CommandSpec {
        name: "ledger rollback",
        summary: "Roll a state directory's revision ledger back to a prior revision, offline",
        description: &[
            "The offline lockout recovery path: with the gateway stopped, takes the exclusive \
             lock of the state directory --state-dir names, verifies its ledger, and plans a \
             rollback to REVISION exactly as the gateway's revision service plans one: the \
             target's stored content is compiled again and diffed against the desired \
             revision, with its risk codes. Unless every one of those codes is named with \
             --acknowledge, nothing is written and the plan is reported. There is no option \
             that acknowledges them all.",
            "Every risk code can be acknowledged offline, risk.admin_access_path_removed \
             included, which no online request can acknowledge: filesystem access to the state \
             directory is already full control of a standalone deployment. The rollback is \
             appended as a new forward revision recording ggctl-ledger as its system actor, \
             history is never rewritten, and the revision is desired and not active until a \
             gateway starts from it. The gateway's production policy and tools validators do \
             not run in ggctl, and the report says so: the gateway compiles the revision again \
             with them at start. Exits 0 when rolled back, 2 for a REVISION that is not a \
             revision ID, 3 when the ledger or the target's content is invalid or a risk code \
             is not acknowledged, 5 when the state directory is locked, and 1 when the ledger \
             could not be read or written.",
        ],
        arguments: &[REVISION],
        options: &[STATE_DIR, ACKNOWLEDGE, FORMAT],
        run: crate::ledger::rollback,
    },
    CommandSpec {
        name: "backup create",
        summary: "Back up a stopped standalone state directory into a new archive",
        description: &[
            "Takes the exclusive lock of the state directory --state-dir names, so it runs only \
             while no gateway or other ggctl holds it, and writes one archive of every store of \
             the state-directory layout it holds to the new file --output names. Each store is \
             snapshotted with SQLite's VACUUM INTO from a read-only connection, never copied \
             file by file, so whatever its write-ahead log holds is included consistently and \
             neither the store nor its log is written; two names for one file are snapshotted \
             once. The \
             configuration revision ledger must pass its full verification and every snapshot \
             SQLite's integrity check. Nothing else in the directory is read: not its lock \
             file, not a store's -wal, -shm or -journal file, not any other file.",
            "The archive is written to a new hidden file beside --output, owner-only on Unix, \
             flushed and read back with every check of ggctl backup verify, then linked to \
             --output, which must not exist and is never replaced; a failure leaves nothing at \
             --output. A backup is never written to standard output. Exits 0 when the backup \
             was written, 3 for a store that is a link, not a regular file, writable by others \
             or corrupt, a ledger that does not verify, or a state directory with no store, 5 \
             when the state directory is locked or --output exists, 7 when what was written \
             did not verify, and 1 when a store or the archive could not be read or written.",
        ],
        arguments: &[],
        options: &[STATE_DIR, BACKUP_OUTPUT, FORMAT],
        run: crate::backup::create,
    },
    CommandSpec {
        name: "backup verify",
        summary: "Verify a backup archive completely, offline",
        description: &[
            "Reads the archive FILE completely through the shared archive admission rules, into \
             a new hidden staging directory beside it, owner-only on Unix and removed \
             afterwards: every entry name, kind and size before its data is read, the \
             GatewayBackup manifest as a closed document of a version this ggctl reads, \
             exactly the entries the manifest lists in its order with each one's SHA-256, the \
             archive's own digest, and then each database: rollback-journal mode, SQLite's \
             integrity check, its header versions, schema and table rows as the manifest \
             records them, and the ledger's full verification and revisions.",
            "Exits 0 when the backup verifies, 7 when anything about it does not (truncation, \
             tampering, traversal, links, duplicate or case-colliding entries, a bomb, an \
             unsupported version or a database that fails its checks), 3 when FILE is a link or \
             not a regular file, and 1 when it or the staging directory could not be read or \
             written. A digest is integrity evidence, not authenticity.",
        ],
        arguments: &[ARCHIVE],
        options: &[FORMAT],
        run: crate::backup::verify,
    },
    CommandSpec {
        name: "completion",
        summary: "Write a shell completion script",
        description: &[
            "Writes a completion script for SHELL to standard output, generated from the \
             same command table as ggctl help. For example: \
             ggctl completion bash > /etc/bash_completion.d/ggctl",
        ],
        arguments: &[ArgumentSpec {
            name: "SHELL",
            kind: ValueKind::Choice(SHELLS),
            required: true,
            help: "bash, zsh, fish or powershell",
        }],
        options: &[],
        run: crate::completion::run,
    },
    CommandSpec {
        name: "help",
        summary: "Print help for ggctl or one command",
        description: &[
            "Prints the help for COMMAND, or the overview without one. For a command family \
             such as ledger or backup, prints the family's commands, or with SUBCOMMAND that command's help.",
        ],
        arguments: &[
            ArgumentSpec {
                name: "COMMAND",
                kind: ValueKind::Choice(HELP_TOPICS),
                required: false,
                help: "the command or command family to describe",
            },
            ArgumentSpec {
                name: "SUBCOMMAND",
                kind: ValueKind::Choice(SUBCOMMANDS),
                required: false,
                help: "a command of the COMMAND family",
            },
        ],
        options: &[],
        run: crate::help::run,
    },
];

/// Names `ggctl` keeps for operations that stay on the `gateway` binary,
/// with the fixed hint naming what to run instead (ADR-0008).
const RESERVED: &[(&str, &str)] = &[
    (
        "db",
        "database migration stays on the gateway binary: run `gateway migrate check` or \
         `gateway migrate up` where the database role and network are",
    ),
    (
        "cluster",
        "cluster operations stay on the gateway binary: run `gateway cluster-members`, \
         `gateway maintenance-run` or `gateway import-standalone`",
    ),
];

/// Option names that would carry a secret. Matched exactly, case-insensitive,
/// after the leading dashes and before any `=`.
const SECRET_OPTIONS: &[&str] = &[
    "token",
    "bearer",
    "bearer-token",
    "access-token",
    "auth-token",
    "id-token",
    "authorization",
    "password",
    "passwd",
    "secret",
    "client-secret",
    "api-key",
    "apikey",
    "credential",
    "credentials",
];

/// Option names that would disable certificate or hostname verification.
const INSECURE_OPTIONS: &[&str] = &[
    "insecure",
    "insecure-skip-tls-verify",
    "skip-tls-verify",
    "tls-skip-verify",
    "no-verify",
    "no-tls-verify",
    "k",
];

const HINT_HELP: &str =
    "run `ggctl help` for the commands and `ggctl help COMMAND` for its options";
const HINT_TOKEN: &str =
    "pipe the token to --token-stdin or name an owner-only file with --token-file";
const HINT_INSECURE: &str = "add the server's CA with --ca-file instead";

/// A parsed command line.
#[derive(Debug)]
pub(crate) enum Parsed {
    Run(Invocation),
    /// `--help`, `-h` or `help`.
    Help(HelpTopic),
    /// `--version`.
    Version,
}

/// What a help request asks about.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HelpTopic {
    Overview,
    Family(&'static FamilySpec),
    /// One command, by its table entry.
    Spec(&'static CommandSpec),
}

/// A command and its arguments, each with its 1-based position.
#[derive(Debug)]
pub(crate) struct Invocation {
    pub(crate) command: &'static CommandSpec,
    positionals: Vec<(usize, OsString)>,
    options: Vec<(&'static str, usize, Option<OsString>)>,
}

impl Invocation {
    pub(crate) fn flag(&self, name: &str) -> Option<usize> {
        self.options
            .iter()
            .find(|(option, _, _)| *option == name)
            .map(|(_, position, _)| *position)
    }

    pub(crate) fn value(&self, name: &str) -> Option<(usize, &OsStr)> {
        self.options
            .iter()
            .find(|(option, _, _)| *option == name)
            .and_then(|(_, position, value)| value.as_deref().map(|value| (*position, value)))
    }

    /// A value the parser already checked is UTF-8 (every non-path kind).
    pub(crate) fn text(&self, name: &str) -> Option<(usize, &str)> {
        self.value(name)
            .and_then(|(position, value)| value.to_str().map(|value| (position, value)))
    }

    /// Every value of a repeatable option, in command-line order. Each is
    /// UTF-8, as [`Self::text`] is.
    pub(crate) fn texts(&self, name: &str) -> Vec<(usize, &str)> {
        self.options
            .iter()
            .filter(|(option, _, _)| *option == name)
            .filter_map(|(_, position, value)| {
                value
                    .as_deref()
                    .and_then(OsStr::to_str)
                    .map(|value| (*position, value))
            })
            .collect()
    }

    pub(crate) fn positional(&self, index: usize) -> Option<(usize, &str)> {
        self.positionals
            .get(index)
            .and_then(|(position, value)| value.to_str().map(|value| (*position, value)))
    }
}

/// Parses the arguments after the program name.
pub(crate) fn parse(arguments: &[OsString]) -> Result<Parsed, Diagnostic> {
    refuse_dangerous_options(arguments)?;
    let Some(first) = arguments.first() else {
        return Err(Diagnostic::new(Code::MissingCommand).with_hint(HINT_HELP));
    };
    let word = match first.to_str() {
        Some("--help" | "-h") => return Ok(Parsed::Help(HelpTopic::Overview)),
        Some("--version") => return Ok(Parsed::Version),
        Some(word) if word.starts_with('-') => {
            return Err(Diagnostic::at(Code::UnknownOption, 1).with_hint(HINT_HELP))
        }
        Some(word) => {
            if let Some((_, hint)) = RESERVED.iter().find(|(name, _)| *name == word) {
                return Err(Diagnostic::at(Code::ReservedCommand, 1).with_hint(hint));
            }
            word
        }
        None => return Err(Diagnostic::at(Code::ArgumentNotUtf8, 1)),
    };
    let command = match FAMILIES.iter().find(|family| family.name == word) {
        Some(family) => match family_command(family, arguments)? {
            Some(command) => command,
            None => return Ok(Parsed::Help(HelpTopic::Family(family))),
        },
        // A family's command is named only by two arguments.
        None => COMMANDS
            .iter()
            .find(|command| command.family().is_none() && command.name == word)
            .ok_or(Diagnostic::at(Code::UnknownCommand, 1).with_hint(HINT_HELP))?,
    };
    let invocation = parse_command(command, arguments)?;
    if invocation.flag("--help").is_some() {
        return Ok(Parsed::Help(HelpTopic::Spec(command)));
    }
    if command.name == "help" {
        return help_topic(&invocation).map(Parsed::Help);
    }
    Ok(Parsed::Run(invocation))
}

/// The command of `family` the second argument names, or `None` for a help
/// request about the family itself.
fn family_command(
    family: &'static FamilySpec,
    arguments: &[OsString],
) -> Result<Option<&'static CommandSpec>, Diagnostic> {
    let Some(second) = arguments.get(1) else {
        return Err(Diagnostic::new(Code::MissingCommand).with_hint(family.hint));
    };
    match second.to_str() {
        Some("--help" | "-h") => Ok(None),
        Some(word) => family
            .members()
            .find(|command| member_word(family, command) == Some(word))
            .map(Some)
            .ok_or(Diagnostic::at(Code::UnknownCommand, 2).with_hint(family.hint)),
        None => Err(Diagnostic::at(Code::ArgumentNotUtf8, 2)),
    }
}

/// The second word of `command`'s name when it is a command of `family`.
fn member_word(family: &FamilySpec, command: &CommandSpec) -> Option<&'static str> {
    command
        .name
        .strip_prefix(family.name)
        .and_then(|rest| rest.strip_prefix(' '))
}

/// What `ggctl help [COMMAND [SUBCOMMAND]]` asks about. A SUBCOMMAND is
/// accepted only after a family that has it.
pub(crate) fn help_topic(invocation: &Invocation) -> Result<HelpTopic, Diagnostic> {
    let Some((position, topic)) = invocation.positional(0) else {
        return Ok(HelpTopic::Overview);
    };
    let subcommand = invocation.positional(1);
    if let Some(family) = FAMILIES.iter().find(|family| family.name == topic) {
        let Some((position, word)) = subcommand else {
            return Ok(HelpTopic::Family(family));
        };
        return family
            .members()
            .find(|command| member_word(family, command) == Some(word))
            .map(HelpTopic::Spec)
            .ok_or(Diagnostic::at(Code::InvalidValue, position));
    }
    if let Some((position, _)) = subcommand {
        return Err(Diagnostic::at(Code::UnexpectedArgument, position).with_hint(HINT_HELP));
    }
    // The parser accepted only a topic `HELP_TOPICS` lists.
    COMMANDS
        .iter()
        .find(|command| command.name == topic)
        .map(HelpTopic::Spec)
        .ok_or(Diagnostic::at(Code::InvalidValue, position))
}

fn parse_command(
    command: &'static CommandSpec,
    arguments: &[OsString],
) -> Result<Invocation, Diagnostic> {
    let mut invocation = Invocation {
        command,
        positionals: Vec::new(),
        options: Vec::new(),
    };
    let mut only_positionals = false;
    let mut index = command.words();
    while index < arguments.len() {
        let position = index + 1;
        let argument = &arguments[index];
        index += 1;
        let Some(text) = argument.to_str() else {
            // A non-UTF-8 argument can only be a path option's value, which
            // is consumed below with its option; anywhere else it is refused.
            return Err(Diagnostic::at(Code::ArgumentNotUtf8, position));
        };
        if only_positionals || text == "-" || !text.starts_with('-') {
            if invocation.positionals.len() == command.arguments.len() {
                return Err(Diagnostic::at(Code::UnexpectedArgument, position).with_hint(HINT_HELP));
            }
            invocation.positionals.push((position, argument.clone()));
            continue;
        }
        if text == "--" {
            only_positionals = true;
            continue;
        }
        if text == "--help" || text == "-h" {
            invocation.options.push(("--help", position, None));
            return Ok(invocation);
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (text, None),
        };
        let Some(option) = command.options.iter().find(|option| option.name == name) else {
            return Err(Diagnostic::at(Code::UnknownOption, position).with_hint(HINT_HELP));
        };
        if !option.repeatable && invocation.flag(option.name).is_some() {
            return Err(Diagnostic::at(Code::DuplicateOption, position));
        }
        let value = match (option.value, inline) {
            (None, None) => None,
            (None, Some(_)) => return Err(Diagnostic::at(Code::UnexpectedValue, position)),
            (Some((_, kind)), Some(value)) => {
                Some(checked_value(kind, OsStr::new(value), position)?)
            }
            (Some((_, kind)), None) => {
                let Some(value) = arguments.get(index) else {
                    return Err(Diagnostic::at(Code::MissingValue, position));
                };
                index += 1;
                Some(checked_value(kind, value, position + 1)?)
            }
        };
        invocation.options.push((option.name, position, value));
    }
    for (spec, index) in command.arguments.iter().zip(0..) {
        match invocation.positionals.get(index) {
            Some((position, value)) => {
                checked_value(spec.kind, value, *position)?;
            }
            None if spec.required => {
                return Err(Diagnostic::new(Code::MissingArgument).with_hint(HINT_HELP))
            }
            None => {}
        }
    }
    Ok(invocation)
}

/// Checks a value against its kind. Only a path may be non-UTF-8.
fn checked_value(kind: ValueKind, value: &OsStr, position: usize) -> Result<OsString, Diagnostic> {
    if value.is_empty() {
        return Err(Diagnostic::at(Code::InvalidValue, position));
    }
    if kind == ValueKind::Path {
        return Ok(value.to_owned());
    }
    let Some(text) = value.to_str() else {
        return Err(Diagnostic::at(Code::ArgumentNotUtf8, position));
    };
    if let ValueKind::Choice(choices) = kind {
        if !choices.contains(&text) {
            return Err(Diagnostic::at(Code::InvalidValue, position));
        }
    }
    Ok(value.to_owned())
}

/// Refuses a secret-carrying or verification-disabling option anywhere on
/// the command line, before any other parsing.
fn refuse_dangerous_options(arguments: &[OsString]) -> Result<(), Diagnostic> {
    for (index, argument) in arguments.iter().enumerate() {
        let text = argument.to_string_lossy();
        if text == "--" {
            break;
        }
        let Some(name) = text.strip_prefix('-') else {
            continue;
        };
        let name = name.strip_prefix('-').unwrap_or(name);
        let name = name
            .split_once('=')
            .map_or(name, |(name, _)| name)
            .to_ascii_lowercase();
        if SECRET_OPTIONS.contains(&name.as_str()) {
            return Err(Diagnostic::at(Code::SecretOnCommandLine, index + 1).with_hint(HINT_TOKEN));
        }
        if INSECURE_OPTIONS.contains(&name.as_str()) {
            return Err(
                Diagnostic::at(Code::InsecureOptionRefused, index + 1).with_hint(HINT_INSECURE)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
