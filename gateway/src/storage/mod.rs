//! Async repository contracts for shared state (issue #241, PR 2).
//!
//! These traits are the storage boundary the HA sequence builds on. The
//! standalone SQLite adapters here satisfy them today; the PostgreSQL
//! implementations in later PRs must satisfy the same behavioral contracts
//! (see `docs/adr/0007-shared-state-and-ha-modes.md` and
//! `docs/architecture/ha-state-model.md`).
//!
//! Two rules govern every adapter in this module:
//!
//! - Synchronous `rusqlite` work runs on Tokio's dedicated blocking threads
//!   (`tokio::task::spawn_blocking`), never on the request executors.
//! - Errors crossing these traits are classified
//!   ([`RepositoryErrorKind`]) and carry a stable operation label only: no
//!   paths, no SQL text, no query values, no secrets. Operator-grade detail
//!   is logged where the failure first occurs, never propagated through the
//!   contract.

mod audit;
/// Versioned migrations and the schema lifecycle (issue #241, PR 4), on the
/// same `postgres` feature as the pool it runs on. A feature-off build
/// refuses the `migrate` subcommand in `main` with a clear message rather
/// than treating it as an unknown word.
#[cfg(feature = "postgres")]
pub mod migrations;
mod policy_history;
#[cfg(feature = "postgres")]
pub mod postgres;
mod principal;
mod service_token;

#[cfg(test)]
mod contract_tests;

pub use audit::{AuditEventStore, SqliteAuditEventStore};
pub use policy_history::PolicyHistory;
pub use principal::PrincipalDirectoryStore;
pub use service_token::ServiceTokenStore;

use std::fmt;

/// Classification of a repository failure. These are the only failure
/// classes the repository contracts expose; anything an adapter cannot place
/// in one of them is [`RepositoryErrorKind::Internal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RepositoryErrorKind {
    /// The backing store could not be reached or used at all.
    Unavailable,
    /// The operation could not complete within its contention budget.
    Timeout,
    /// The operation lost a race against a concurrent writer or violated a
    /// uniqueness expectation the caller can retry or surface as a conflict.
    Conflict,
    /// The request data, or data read back from the store, was not valid.
    InvalidData,
    /// The store's schema is not one this binary can use.
    #[allow(dead_code)] // Constructed by the PostgreSQL adapters' schema validation (PRs 3-4);
    // no standalone SQLite path produces it today.
    IncompatibleSchema,
    /// An unexpected failure with no more specific classification.
    Internal,
}

impl RepositoryErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Conflict => "conflict",
            Self::InvalidData => "invalid data",
            Self::IncompatibleSchema => "incompatible schema",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for RepositoryErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A classified repository failure.
///
/// The error deliberately carries only the classification, a stable
/// operation label, and — for invalid request parameters — the parameter
/// name: no paths, no SQL text, no query values, no secrets. That keeps the
/// contract safe to surface and to carry across store boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryError {
    kind: RepositoryErrorKind,
    operation: &'static str,
    parameter: Option<&'static str>,
}

impl RepositoryError {
    pub fn new(kind: RepositoryErrorKind, operation: &'static str) -> Self {
        Self {
            kind,
            operation,
            parameter: None,
        }
    }

    /// Build an `InvalidData` failure caused by a specific request parameter,
    /// so callers can keep answering "invalid query parameter" with `400`
    /// instead of a store failure with `500`.
    pub fn invalid_parameter(operation: &'static str, parameter: &'static str) -> Self {
        Self {
            kind: RepositoryErrorKind::InvalidData,
            operation,
            parameter: Some(parameter),
        }
    }

    pub fn kind(&self) -> RepositoryErrorKind {
        self.kind
    }

    #[allow(dead_code)] // Read by the admin error responses of the PostgreSQL PRs; the
                        // classified Display already carries the operation for today's callers.
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    /// The request parameter responsible for an `InvalidData` failure, when
    /// the invalid data came from the caller rather than from the store.
    pub fn invalid_parameter_name(&self) -> Option<&'static str> {
        self.parameter
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.parameter {
            Some(parameter) => write!(
                formatter,
                "{} rejected invalid request parameter {parameter}: {}",
                self.operation, self.kind
            ),
            None => write!(formatter, "{} failed: {}", self.operation, self.kind),
        }
    }
}

impl std::error::Error for RepositoryError {}

/// Run a blocking repository call on Tokio's dedicated blocking pool.
///
/// The closure maps its own detailed error into a [`RepositoryError`] before
/// returning; the detailed source is logged by the mapping helper, never
/// propagated. A panic or cancellation in the blocking task is classified as
/// [`RepositoryErrorKind::Internal`].
pub(crate) async fn run_blocking<T, F>(call: F) -> Result<T, RepositoryError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, RepositoryError> + Send + 'static,
{
    match tokio::task::spawn_blocking(call).await {
        Ok(result) => result,
        Err(join_error) => Err(RepositoryError::new(
            RepositoryErrorKind::Internal,
            join_error_operation(&join_error),
        )),
    }
}

fn join_error_operation(join_error: &tokio::task::JoinError) -> &'static str {
    // `JoinError` does not carry the closure's identity, so the operation
    // label of a failed task is logged here and reported generically below.
    tracing::error!(error = %join_error, "repository blocking task failed");
    "repository_blocking_task"
}

/// Classify a `rusqlite` failure without propagating its message: SQLite
/// error text can embed database paths, table names, and SQL fragments.
pub(crate) fn classify_rusqlite(
    operation: &'static str,
    error: &rusqlite::Error,
) -> RepositoryError {
    let kind = sqlite_error_kind(error);
    RepositoryError::new(kind, operation)
}

fn sqlite_error_kind(error: &rusqlite::Error) -> RepositoryErrorKind {
    use rusqlite::Error as SqliteError;

    match error {
        SqliteError::SqliteFailure(ffi_error, _) => {
            // Primary SQLite result codes: 5 BUSY, 6 LOCKED, 7 NOMEM,
            // 8 READONLY, 10 IOERR, 11 CORRUPT, 13 FULL, 14 CANTOPEN,
            // 19 CONSTRAINT, 26 NOTADB. Extended codes share the low byte.
            match ffi_error.extended_code & 0xff {
                5 | 6 => RepositoryErrorKind::Timeout,
                19 => RepositoryErrorKind::Conflict,
                7 | 8 | 10 | 11 | 13 | 14 | 26 => RepositoryErrorKind::Unavailable,
                _ => RepositoryErrorKind::Internal,
            }
        }
        SqliteError::InvalidParameterName(_)
        | SqliteError::InvalidColumnType(_, _, _)
        | SqliteError::FromSqlConversionFailure(_, _, _)
        | SqliteError::ToSqlConversionFailure(_) => RepositoryErrorKind::InvalidData,
        _ => RepositoryErrorKind::Internal,
    }
}

/// Log the detailed source of a classified failure and return the classified
/// form. Failures caused by an invalid request parameter are expected client
/// input and are not logged as gateway errors.
pub(crate) fn log_classified(
    operation: &'static str,
    detail: &dyn std::error::Error,
    classified: RepositoryError,
) -> RepositoryError {
    if classified.invalid_parameter_name().is_none() {
        tracing::error!(operation, error = %detail, "repository operation failed");
    }
    classified
}
