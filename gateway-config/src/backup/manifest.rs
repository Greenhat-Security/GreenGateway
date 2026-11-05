//! The `GatewayBackup` manifest (`docs/schemas/gateway-backup.v1alpha1.schema.json`):
//! the first entry of every backup archive.
//!
//! A manifest is read as a closed document: an unknown or duplicate member,
//! a missing one, or a value outside its grammar refuses the whole document,
//! and so does any inconsistency between its inventory, its entries and its
//! counts. Only then is an entry compared with what the manifest says of it.

use serde::{Deserialize, Serialize};

use crate::documents::{API_VERSION_V1ALPHA1, BACKUP_KIND, BUNDLE_KIND};
use crate::ledger::RevisionId;
use crate::state_dir::StateFile;

use super::{container, BackupError};

/// The manifest's entry name: the first entry of every archive.
pub const MANIFEST_ENTRY: &str = "gateway-backup.json";
/// The largest manifest read.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The container a manifest's `archive.format` names.
pub const ARCHIVE_FORMAT: &str = "ggbk";
/// What a manifest's `source` names: the only source this build backs up.
pub const SOURCE_STANDALONE: &str = "standalone_state_directory";
/// The most tables one database entry may describe.
pub const MAX_TABLES: usize = 256;
/// The longest table name a database entry may describe.
pub const MAX_TABLE_NAME_BYTES: usize = 128;
/// I-JSON's largest exact integer: every count stays within it.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// One manifest, exactly as it is serialized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Manifest {
    pub(super) api_version: String,
    pub(super) kind: String,
    pub(super) archive: ArchiveFormatRecord,
    pub(super) source: String,
    pub(super) created_by: ProducerRecord,
    pub(super) created_at_ms: u64,
    pub(super) sqlite_version: String,
    pub(super) stores: Vec<StoreRecord>,
    pub(super) entries: Vec<EntryRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ledger: Option<LedgerRecord>,
    pub(super) counts: CountsRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ArchiveFormatRecord {
    pub(super) format: String,
    pub(super) version: u16,
}

/// The program that wrote the archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ProducerRecord {
    pub(super) program: String,
    pub(super) version: String,
}

/// One logical store of the state directory layout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct StoreRecord {
    pub(super) store: String,
    pub(super) file: String,
    pub(super) included: bool,
    /// The entry holding the store, when it is included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) entry: Option<String>,
}

/// One archive entry after the manifest: one physical database.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct EntryRecord {
    pub(super) name: String,
    pub(super) bytes: u64,
    /// 64 lowercase hexadecimal digits over the entry's exact bytes.
    pub(super) sha256: String,
    pub(super) database: DatabaseRecord,
}

/// What a database entry holds, as SQLite describes it: its header
/// versions, its size in pages, a digest of its schema and the rows of each
/// table. The store's version as the gateway knows it is its schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct DatabaseRecord {
    pub(super) application_id: i32,
    pub(super) user_version: i32,
    pub(super) page_size: u32,
    pub(super) pages: u64,
    pub(super) schema_sha256: String,
    pub(super) tables: Vec<TableRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct TableRecord {
    pub(super) name: String,
    pub(super) rows: u64,
}

/// The configuration revision ledger, as it verified when it was backed up.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct LedgerRecord {
    pub(super) revisions: u64,
    pub(super) desired: String,
    /// `null` until a gateway activated a revision.
    pub(super) active: Option<String>,
    /// The document version of the desired revision's bundle.
    pub(super) bundle_api_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct CountsRecord {
    pub(super) stores: u64,
    pub(super) included_stores: u64,
    pub(super) entries: u64,
    pub(super) bytes: u64,
    pub(super) tables: u64,
    pub(super) rows: u64,
}

impl CountsRecord {
    /// The counts `stores` and `entries` imply.
    pub(super) fn of(stores: &[StoreRecord], entries: &[EntryRecord]) -> Self {
        let sum = |value: fn(&EntryRecord) -> u64| {
            entries.iter().map(value).fold(0_u64, u64::saturating_add)
        };
        Self {
            stores: count(stores.len()),
            included_stores: count(stores.iter().filter(|store| store.included).count()),
            entries: count(entries.len()),
            bytes: sum(|entry| entry.bytes),
            tables: sum(|entry| count(entry.database.tables.len())),
            rows: sum(|entry| {
                entry
                    .database
                    .tables
                    .iter()
                    .map(|table| table.rows)
                    .fold(0_u64, u64::saturating_add)
            }),
        }
    }
}

fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

impl Manifest {
    /// The serialized manifest: compact JSON, as the archive stores it.
    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        serde_json::to_vec(self).map_err(|_| BackupError::OutputUnusable)
    }

    /// Reads and checks a manifest's bytes.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, BackupError> {
        // Read first only far enough to tell an unsupported document from an
        // invalid one: a later version may change any other member.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Header {
            api_version: Option<serde_json::Value>,
            kind: Option<serde_json::Value>,
        }
        let header: Header =
            serde_json::from_slice(bytes).map_err(|_| BackupError::ManifestInvalid)?;
        if header.api_version.as_ref().and_then(|value| value.as_str())
            != Some(API_VERSION_V1ALPHA1)
            || header.kind.as_ref().and_then(|value| value.as_str()) != Some(BACKUP_KIND)
        {
            return Err(BackupError::UnsupportedManifestVersion);
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| BackupError::ManifestInvalid)?;
        manifest.check()?;
        Ok(manifest)
    }

    /// Every rule a manifest must meet beyond its member types.
    pub(super) fn check(&self) -> Result<(), BackupError> {
        let invalid = || BackupError::ManifestInvalid;
        if self.archive.format != ARCHIVE_FORMAT
            || self.archive.version != container::FORMAT_VERSION
            || self.source != SOURCE_STANDALONE
            || !is_program(&self.created_by.program)
            || !is_version_text(&self.created_by.version, 64)
            || !is_sqlite_version(&self.sqlite_version)
            || self.created_at_ms > MAX_SAFE_INTEGER
        {
            return Err(invalid());
        }
        // The inventory names every store of the layout once, in order.
        if self.stores.len() != StateFile::ALL.len() {
            return Err(invalid());
        }
        let mut referenced = vec![false; self.entries.len()];
        for (record, store) in self.stores.iter().zip(StateFile::ALL) {
            if record.store != store.id() || record.file != store.file_name() {
                return Err(invalid());
            }
            match (&record.entry, record.included) {
                (None, false) => {}
                (Some(name), true) => {
                    let index = self
                        .entries
                        .iter()
                        .position(|entry| &entry.name == name)
                        .ok_or_else(invalid)?;
                    referenced[index] = true;
                }
                _ => return Err(invalid()),
            }
        }
        // Each entry is the file of the first store that it holds, so two
        // stores that were one file share the entry named after the first.
        for (entry, used) in self.entries.iter().zip(&referenced) {
            let first = self
                .stores
                .iter()
                .find(|record| record.entry.as_deref() == Some(entry.name.as_str()));
            if !used || first.is_none_or(|record| record.file != entry.name) {
                return Err(invalid());
            }
            entry.check()?;
        }
        let names: std::collections::BTreeSet<_> =
            self.entries.iter().map(|entry| &entry.name).collect();
        if names.len() != self.entries.len() || self.entries.is_empty() {
            return Err(invalid());
        }
        // The ledger shares its file with no other store, and is described
        // exactly when it is included.
        let ledger = self.store(StateFile::ConfigLedger);
        match (
            &self.ledger,
            ledger.and_then(|record| record.entry.as_deref()),
        ) {
            (None, None) => {}
            (Some(record), Some(entry)) => {
                let shared = self.stores.iter().filter(|other| {
                    other.store != StateFile::ConfigLedger.id()
                        && other.entry.as_deref() == Some(entry)
                });
                if shared.count() != 0 || entry != StateFile::ConfigLedger.file_name() {
                    return Err(invalid());
                }
                record.check()?;
            }
            _ => return Err(invalid()),
        }
        if self.counts != CountsRecord::of(&self.stores, &self.entries)
            || [self.counts.bytes, self.counts.rows, self.counts.tables]
                .iter()
                .any(|value| *value > MAX_SAFE_INTEGER)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// The inventory record of `store`.
    pub(super) fn store(&self, store: StateFile) -> Option<&StoreRecord> {
        self.stores.iter().find(|record| record.store == store.id())
    }

    /// The first store an entry holds.
    pub(super) fn store_of(&self, entry: &str) -> Option<StateFile> {
        StateFile::ALL.into_iter().find(|store| {
            self.store(*store)
                .and_then(|record| record.entry.as_deref())
                == Some(entry)
        })
    }
}

impl EntryRecord {
    fn check(&self) -> Result<(), BackupError> {
        let invalid = || BackupError::ManifestInvalid;
        let database = &self.database;
        if self.bytes > MAX_SAFE_INTEGER
            || database.pages > MAX_SAFE_INTEGER
            || !is_lowercase_hex_digest(&self.sha256)
            || !is_lowercase_hex_digest(&database.schema_sha256)
            || !database.page_size.is_power_of_two()
            || !(512..=65_536).contains(&database.page_size)
            || u64::from(database.page_size).checked_mul(database.pages) != Some(self.bytes)
            || database.tables.len() > MAX_TABLES
        {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        for table in &database.tables {
            // Sorted and unique, so a manifest has one spelling.
            if !is_table_name(&table.name)
                || table.rows > MAX_SAFE_INTEGER
                || previous.is_some_and(|previous| previous >= table.name.as_str())
            {
                return Err(invalid());
            }
            previous = Some(&table.name);
        }
        Ok(())
    }
}

impl LedgerRecord {
    fn check(&self) -> Result<(), BackupError> {
        let invalid = || BackupError::ManifestInvalid;
        if self.revisions == 0
            || self.revisions > MAX_SAFE_INTEGER
            || RevisionId::parse(&self.desired).is_none()
            || self
                .active
                .as_deref()
                .is_some_and(|active| RevisionId::parse(active).is_none())
            || !crate::documents::api_versions_of(BUNDLE_KIND)
                .any(|version| version == self.bundle_api_version)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// `^[a-z][a-z0-9-]{0,31}$`
fn is_program(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A version string: ASCII letters, digits, `.`, `+` and `-`, starting with
/// a digit.
fn is_version_text(text: &str, maximum: usize) -> bool {
    let bytes = text.as_bytes();
    (1..=maximum).contains(&bytes.len())
        && bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

/// `3.50.4`: two to four dot-separated numbers.
fn is_sqlite_version(text: &str) -> bool {
    let parts: Vec<_> = text.split('.').collect();
    text.len() <= 32
        && (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`, at most [`MAX_TABLE_NAME_BYTES`]: the names
/// a row count is taken from, and the only ones quoted into SQL.
pub(super) fn is_table_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=MAX_TABLE_NAME_BYTES).contains(&bytes.len())
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn is_lowercase_hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
