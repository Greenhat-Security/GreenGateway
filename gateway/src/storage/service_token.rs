//! Service-token repository contract and its standalone SQLite adapter.

use crate::auth::{
    change_actor::ChangeActor,
    tokens::{
        CreateTokenRequest, CreatedToken, SqliteTokenStore, TokenListFilters, TokenPage,
        TokenRecord, TokenStore, TokenStoreError, TokenVerification,
    },
};
use crate::authority_events::caller_operation::{
    CallerKeyState, CallerOperation, CallerOutcome, OperationReceipt,
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
/// â€” a revoked token never becomes valid again, and rotating a revoked token
/// is a conflict.
///
/// Create, rotate and revoke are told who is acting. Each committed change --
/// the issue of a new token included -- records that actor -- its subject,
/// canonical issuer, actor kind and auth mode ([`ChangeActor`]) -- and its
/// action as append-only change evidence in the same transaction as the
/// change itself (issue #425): if the evidence cannot be written, the change
/// rolls back and the call fails. A call that changes nothing -- a repeat
/// revoke, a rotate refused as a conflict, an unknown token -- records
/// nothing. An actor evidence cannot record exactly (an empty or oversized
/// subject, [`crate::auth::tokens::MAX_TOKEN_CHANGE_ACTOR_BYTES`], or an
/// issuer outside [`ChangeActor::is_recordable`]) is refused before anything
/// changes. The evidence never holds the plaintext, the hash, the display
/// prefix or the scopes. A token's `created_by` still names its creator; for
/// a token issued before issue evidence existed it is the only record.
///
/// Issue and rotation also take an optional caller key bound to one request
/// (issue #425, [`CallerOperation`]). Inside the change's own transaction the
/// key is looked up first: an exact retry of a committed change is answered
/// with its [`OperationReceipt`] (`CallerOutcome::Replayed`), read from the
/// evidence row, and changes nothing -- never a second token, and never a
/// plaintext; a key reserved for anything else is a `Conflict` labelled
/// [`crate::auth::tokens::CALLER_OPERATION_BINDING`], and nothing changes.
/// Otherwise the key is reserved with the change and its evidence row, whose
/// `operation_id` it becomes, and the three commit together or not at all.
/// Every committed issue, rotation and revocation records the token's
/// revision before and after it.
#[async_trait]
pub trait ServiceTokenStore: Send + Sync {
    // The admin handlers call the `_with_operation` forms; the unkeyed
    // wrappers serve the tests and any caller that binds no key.
    #[allow(dead_code)]
    async fn create(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
    ) -> Result<CreatedToken, RepositoryError> {
        match self.create_with_operation(request, actor, None).await? {
            CallerOutcome::Committed(created) => Ok(created),
            // Only a caller key is answered from a receipt.
            CallerOutcome::Replayed(_) => Err(RepositoryError::new(
                RepositoryErrorKind::Internal,
                "service_token_create",
            )),
        }
    }

    /// [`Self::create`] under an optional caller key bound to the request.
    async fn create_with_operation(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<CallerOutcome<CreatedToken>, RepositoryError>;

    /// What the store's reservation table says about `caller`'s key: the
    /// read-only pre-check a keyed handler asks before it does any work.
    /// Advisory: the change's own transaction decides again. A store that
    /// binds no caller keys refuses, so no key is ever ignored.
    async fn caller_operation_state(
        &self,
        _caller: &CallerOperation,
    ) -> Result<CallerKeyState, RepositoryError> {
        Err(RepositoryError::new(
            RepositoryErrorKind::Unavailable,
            "service_token_caller_operation",
        ))
    }

    /// The receipt of the issue or rotation `caller`'s key committed, read
    /// from its evidence row, or `None` when there is none.
    async fn caller_operation_receipt(
        &self,
        _caller: &CallerOperation,
    ) -> Result<Option<OperationReceipt>, RepositoryError> {
        Err(RepositoryError::new(
            RepositoryErrorKind::Unavailable,
            "service_token_caller_operation",
        ))
    }

    async fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, RepositoryError>;

    async fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError>;

    async fn revoke(
        &self,
        id: &str,
        actor: &ChangeActor,
    ) -> Result<Option<TokenRecord>, RepositoryError> {
        self.revoke_with_operation(id, actor, None).await
    }

    /// A supplied operation ID binds the committed revoke to its actor and
    /// token. Only an identical retry may return that operation's result.
    async fn revoke_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        operation_id: Option<uuid::Uuid>,
    ) -> Result<Option<TokenRecord>, RepositoryError>;

    #[allow(dead_code)]
    async fn rotate(
        &self,
        id: &str,
        actor: &ChangeActor,
    ) -> Result<Option<CreatedToken>, RepositoryError> {
        match self.rotate_with_operation(id, actor, None).await? {
            None => Ok(None),
            Some(CallerOutcome::Committed(created)) => Ok(Some(created)),
            Some(CallerOutcome::Replayed(_)) => Err(RepositoryError::new(
                RepositoryErrorKind::Internal,
                "service_token_rotate",
            )),
        }
    }

    /// [`Self::rotate`] under an optional caller key bound to the request.
    /// An exact retry is answered from its receipt whatever happened to the
    /// token since.
    async fn rotate_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<Option<CallerOutcome<CreatedToken>>, RepositoryError>;

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
    async fn create_with_operation(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<CallerOutcome<CreatedToken>, RepositoryError> {
        let store = self.clone();
        let actor = actor.clone();
        let caller = caller.cloned();
        run_blocking(move || {
            TokenStore::create_with_operation(&store, request, &actor, caller.as_ref())
                .map_err(|error| map_token_store_error("service_token_create", error))
        })
        .await
    }

    async fn caller_operation_state(
        &self,
        caller: &CallerOperation,
    ) -> Result<CallerKeyState, RepositoryError> {
        let store = self.clone();
        let caller = caller.clone();
        run_blocking(move || {
            store
                .caller_operation_state(&caller)
                .map_err(|error| map_token_store_error("service_token_caller_operation", error))
        })
        .await
    }

    async fn caller_operation_receipt(
        &self,
        caller: &CallerOperation,
    ) -> Result<Option<OperationReceipt>, RepositoryError> {
        let store = self.clone();
        let caller = caller.clone();
        run_blocking(move || {
            store
                .caller_operation_receipt(&caller)
                .map_err(|error| map_token_store_error("service_token_caller_operation", error))
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

    async fn revoke_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        operation_id: Option<uuid::Uuid>,
    ) -> Result<Option<TokenRecord>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        let actor = actor.clone();
        run_blocking(move || {
            TokenStore::revoke_with_operation(&store, &id, &actor, operation_id)
                .map_err(|error| map_token_store_error("service_token_revoke", error))
        })
        .await
    }

    async fn rotate_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<Option<CallerOutcome<CreatedToken>>, RepositoryError> {
        let store = self.clone();
        let id = id.to_owned();
        let actor = actor.clone();
        let caller = caller.cloned();
        run_blocking(move || {
            TokenStore::rotate_with_operation(&store, &id, &actor, caller.as_ref())
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

pub(super) fn map_token_store_error(
    operation: &'static str,
    error: TokenStoreError,
) -> RepositoryError {
    let classified = match &error {
        TokenStoreError::Open { source, .. } | TokenStoreError::Sqlite { source, .. } => {
            classify_rusqlite(operation, source)
        }
        // The contention budget ran out and nothing committed: the same
        // `Timeout` a raw lock failure always classified as, which the admin
        // API answers `503 service-token store is unavailable`.
        TokenStoreError::Busy { .. } => {
            RepositoryError::new(RepositoryErrorKind::Timeout, operation)
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
        TokenStoreError::RevokeOperationConflict => RepositoryError::new(
            RepositoryErrorKind::Conflict,
            crate::auth::tokens::REVOKE_OPERATION_BINDING,
        ),
        TokenStoreError::RevokedToken { .. } => {
            RepositoryError::new(RepositoryErrorKind::Conflict, operation)
        }
        TokenStoreError::InvalidRevokeOperationId => {
            RepositoryError::invalid_parameter(operation, "operation_id")
        }
        // A keyed issue or rotation whose key is bound to another request:
        // the one conflict the admin API answers `409 caller_operation_conflict`.
        TokenStoreError::CallerOperationConflict => RepositoryError::new(
            RepositoryErrorKind::Conflict,
            crate::auth::tokens::CALLER_OPERATION_BINDING,
        ),
        TokenStoreError::CallerOperationAction => {
            RepositoryError::new(RepositoryErrorKind::Internal, operation)
        }
        // Already classified by the reservation table. Never a conflict here:
        // on rotate that kind means exactly "the token is revoked".
        TokenStoreError::CallerOperation(error) => {
            if error.kind() == RepositoryErrorKind::Conflict {
                RepositoryError::new(RepositoryErrorKind::Internal, operation)
            } else {
                RepositoryError::new(error.kind(), operation)
            }
        }
        // Only an authenticated principal reaches a store, so an actor
        // evidence cannot record is the gateway's defect, not the caller's
        // input: refused, and not answered as a parameter error.
        TokenStoreError::InvalidChangeActor | TokenStoreError::InconsistentRevokeEvidence => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
        // The change rolled back with its evidence. Keep an availability
        // classification (busy, I/O, read-only), but never let a constraint
        // failure on the evidence row surface as `Conflict`: on rotate that
        // kind means exactly "the token is revoked".
        TokenStoreError::ChangeEvidence { source, .. } => {
            let classified = classify_rusqlite(operation, source);
            if classified.kind() == RepositoryErrorKind::Conflict {
                RepositoryError::new(RepositoryErrorKind::Internal, operation)
            } else {
                classified
            }
        }
    };
    log_classified(operation, &error, classified)
}
