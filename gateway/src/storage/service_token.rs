//! Service-token repository contract and its standalone SQLite adapter.

use crate::auth::tokens::{
    CreateTokenRequest, CreatedToken, SqliteTokenStore, TokenListFilters, TokenPage, TokenRecord,
    TokenStore, TokenStoreError, TokenVerification,
};
use async_trait::async_trait;

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// Contract for service-token storage.
///
/// Plaintext tokens appear exactly once, in the `CreatedToken` returned by
/// `create` and `rotate`; every other surface exposes only the display
/// prefix. Verification is authoritative: it consults stored revocation and
/// expiry state rather than a cache, and updates `last_used_at` only for
/// tokens it has already re-checked. Revocation is idempotent and monotonic
/// — a revoked token never becomes valid again, and rotating a revoked token
/// is a conflict.
#[async_trait]
pub trait ServiceTokenStore: Send + Sync {
    async fn create(&self, request: CreateTokenRequest) -> Result<CreatedToken, RepositoryError>;

    async fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, RepositoryError>;

    async fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError>;

    async fn revoke(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError>;

    async fn rotate(&self, id: &str) -> Result<Option<CreatedToken>, RepositoryError>;

    async fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, RepositoryError>;

    #[allow(dead_code)] // `verify` updates `last_used_at` in the same transaction; no
                        // standalone admin endpoint touches usage independently. The method
                        // stays in the contract for the PostgreSQL store (PR 9) and is covered
                        // by the contract tests.
    async fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError>;
}

/// The standalone SQLite token store satisfies the contract by running each
/// synchronous operation on Tokio's blocking pool. The store itself, its
/// schema, and its query results are unchanged. The synchronous
/// [`TokenStore`] methods are invoked by fully-qualified syntax because the
/// trait shares its method names with this contract.
#[async_trait]
impl ServiceTokenStore for SqliteTokenStore {
    async fn create(&self, request: CreateTokenRequest) -> Result<CreatedToken, RepositoryError> {
        let store = self.clone();
        run_blocking(move || {
            TokenStore::create(&store, request)
                .map_err(|error| map_token_store_error("service_token_create", error))
        })
        .await
    }

    async fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
        let store = self.clone();
        let filters = filters.clone();
        run_blocking(move || {
            TokenStore::list(&store, &filters)
                .map_err(|error| map_token_store_error("service_token_list", error))
        })
        .await
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        run_blocking(move || {
            TokenStore::get_by_id(&store, &id)
                .map_err(|error| map_token_store_error("service_token_get", error))
        })
        .await
    }

    async fn revoke(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        run_blocking(move || {
            TokenStore::revoke(&store, &id)
                .map_err(|error| map_token_store_error("service_token_revoke", error))
        })
        .await
    }

    async fn rotate(&self, id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        run_blocking(move || {
            TokenStore::rotate(&store, &id)
                .map_err(|error| map_token_store_error("service_token_rotate", error))
        })
        .await
    }

    async fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, RepositoryError> {
        let store = self.clone();
        let plaintext_token = plaintext_token.to_owned();
        run_blocking(move || {
            TokenStore::verify(&store, &plaintext_token)
                .map_err(|error| map_token_store_error("service_token_verify", error))
        })
        .await
    }

    async fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        run_blocking(move || {
            TokenStore::touch_last_used(&store, &id)
                .map_err(|error| map_token_store_error("service_token_touch_last_used", error))
        })
        .await
    }
}

fn map_token_store_error(operation: &'static str, error: TokenStoreError) -> RepositoryError {
    let classified = match &error {
        TokenStoreError::Open { source, .. } | TokenStoreError::Sqlite { source, .. } => {
            classify_rusqlite(operation, source)
        }
        TokenStoreError::Json { .. } | TokenStoreError::TimeFormat(_) => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
        // A timestamp that failed to parse names the field it came from, which
        // is the request-reachable invalid-data case the admin API answers
        // with `400` rather than `500` (`context` is a `&'static str` field
        // name like `expires_at`, never a value). Only create parses a
        // caller-supplied timestamp; a parse failure on any other operation
        // is a read-back of stored data and stays a plain store failure.
        // Serialization and clock-formatting failures have no such field and
        // stay plain `InvalidData` as well.
        TokenStoreError::TimeParse { context, .. } if operation == "service_token_create" => {
            RepositoryError::invalid_parameter(operation, context)
        }
        TokenStoreError::TimeParse { .. } => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
        TokenStoreError::InvalidCursor { parameter } => {
            RepositoryError::invalid_parameter(operation, parameter)
        }
        TokenStoreError::Random(_) => {
            RepositoryError::new(RepositoryErrorKind::Internal, operation)
        }
        TokenStoreError::RevokedToken { .. } => {
            RepositoryError::new(RepositoryErrorKind::Conflict, operation)
        }
    };
    log_classified(operation, &error, classified)
}
