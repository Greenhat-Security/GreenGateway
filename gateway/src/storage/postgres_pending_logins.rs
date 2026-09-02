//! PostgreSQL admin pending-login store (issue #241, PR 9).
//!
//! The cluster-mode backend for the admin OIDC login flow's pending state:
//! the `state` a browser is sent out with, and the PKCE verifier and nonce
//! that must be presented back with it. Standalone mode keeps the
//! process-local map, which is why standalone multi-instance deployments
//! needed sticky routing for the callback; cluster mode consumes the login
//! on whichever replica the callback lands.
//!
//! What is stored, and what is not:
//!
//! - **The `state` is never stored.** The row is looked up by
//!   `SHA-256(deployment_id || "state" || state)`. A database reader learns
//!   nothing they could present to the callback.
//! - **The PKCE verifier and the nonce are AEAD-encrypted** with
//!   XChaCha20-Poly1305 under the operator's login keyring (the same
//!   key-file discipline as the connections keyring), with the deployment
//!   ID, the row's ID, and the field's purpose bound as associated data. A
//!   row moved between deployments, between rows, or between fields fails
//!   to open. The envelope carries the key ID it was sealed under, so a
//!   `decrypt_only` predecessor key still opens rows sealed before a
//!   rotation; keep predecessors in the ring for at least one pending TTL.
//! - **The client is identified by a keyed digest**, never a raw IP: the
//!   per-client quota is enforced on `HMAC-SHA-256(primary login key,
//!   deployment_id || "client" || canonical_ip)`. A plain digest would let a
//!   database reader recover addresses by dictionary (IPv4 is enumerable
//!   and the deployment ID is not secret); the HA privacy model requires
//!   quota keys to be HMACs. Rotating the primary key changes the quota
//!   key, so a client's logins sealed before the rotation are counted
//!   separately for one pending TTL.
//! - **Consumption is one statement**: `DELETE ... WHERE state_hash = $1 AND
//!   expires_at > now() RETURNING ...`. Exactly one concurrent callback --
//!   on any replica -- gets the row; the other gets nothing. Expiry is the
//!   database clock's.
//! - **Quotas are transactional.** An insert takes a transaction-scoped
//!   advisory lock, prunes a bounded number of expired rows, counts, and
//!   inserts, so two replicas cannot both admit the login that fills the
//!   last slot.
//!
//! A store that cannot be consulted is a dependency failure. It is
//! reported as such and the handlers answer `503`; it is never laundered
//! into "unknown state".

use std::sync::Arc;

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    auth::oidc_login::{
        PendingLogin, PendingLoginBackend, PendingLoginLimits, PendingLoginStoreError,
    },
    connections::local_secret::LocalSecretKeyring,
};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_INSERT: &str = "pending_login_insert";
const OPERATION_TAKE: &str = "pending_login_take";
const OPERATION_PRUNE: &str = "pending_login_prune";
/// The bound on one singleton prune step (`prune_expired`), independent
/// of the per-admission batch.
const MAX_PRUNE_BATCH: u32 = 10_000;
/// Expired rows are judged on the statement clock, the same basis the
/// admission path uses for its TTL and quota count (see `insert`).
const PRUNE_EXPIRED_SQL: &str = r#"
    DELETE FROM greengateway.admin_pending_logins
    WHERE ctid IN (
        SELECT ctid FROM greengateway.admin_pending_logins
        WHERE expires_at <= clock_timestamp() LIMIT $1
    )
    "#;
/// The AEAD envelope's schema, bound into the associated data.
const ENVELOPE_SCHEMA_VERSION: u16 = 1;
const NONCE_BYTES: usize = 24;
/// Transaction-scoped advisory lock serializing admissions. One database is
/// one deployment, so a constant key is the whole namespace.
const ADMISSION_LOCK_KEY: i64 = 0x6767_7077_6c6f_6769;
/// Expired rows pruned per admission, so the sweep is bounded by the
/// admission rate rather than by how long the deployment has run.
const PRUNE_BATCH: i64 = 256;

const PURPOSE_VERIFIER: &str = "pkce_verifier";
const PURPOSE_NONCE: &str = "nonce";

pub struct PostgresPendingLoginStore {
    pool: deadpool_postgres::Pool,
    deployment_id: Arc<str>,
    keyring: LocalSecretKeyring,
    limits: PendingLoginLimits,
    /// Test seam: a pause after the admission lock is taken, standing in
    /// for a wait behind other admissions.
    #[cfg(test)]
    after_lock_delay: Option<std::time::Duration>,
}

impl PostgresPendingLoginStore {
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment_id: &str,
        keyring: LocalSecretKeyring,
        limits: PendingLoginLimits,
    ) -> Self {
        Self {
            pool,
            deployment_id: Arc::from(deployment_id),
            keyring,
            limits,
            #[cfg(test)]
            after_lock_delay: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_after_lock_delay_for_test(mut self, delay: std::time::Duration) -> Self {
        self.after_lock_delay = Some(delay);
        self
    }

    /// Delete up to `limit` expired rows on the statement clock: the
    /// maintenance singleton's bounded step (issue #241, PR 13). Every
    /// admission also prunes a small batch inside its own transaction, so
    /// this only matters for a deployment whose logins stopped arriving
    /// with expired rows still on disk. Returns how many rows were removed.
    #[allow(dead_code)] // the singleton runs `prune_expired_with`; this is the store-level surface for the CLI (PR 13, section 7)
    pub async fn prune_expired(&self, limit: u32) -> Result<u64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        Self::prune_expired_with(&client, limit).await
    }

    /// [`Self::prune_expired`] without a store and over a connection the
    /// caller holds: the statement needs no keyring, so the singleton can
    /// run it whether or not an admin login provider is configured on this
    /// replica, and it runs on the dedicated session that holds the
    /// maintenance advisory lock so the lock covers the statement itself.
    pub(crate) async fn prune_expired_with(
        client: &tokio_postgres::Client,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        prune_expired_statement(
            client,
            i64::from(limit.clamp(1, MAX_PRUNE_BATCH)),
            OPERATION_PRUNE,
        )
        .await
    }

    fn digest(&self, kind: &str, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.deployment_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(kind.as_bytes());
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The lookup key for a `state` (a 128-bit random value, so a plain
    /// digest cannot be inverted by enumeration). Exposed so tests can find
    /// the row they are tampering with.
    pub fn state_digest(&self, state: &str) -> String {
        self.digest("state", state)
    }

    /// The per-client quota key: an HMAC under the primary login key over
    /// the deployment ID and the canonical client address.
    fn client_key(&self, client_ip: &str) -> Result<String, RepositoryError> {
        use hmac::{Hmac, Mac};
        let key = self
            .keyring
            .key(self.keyring.primary_id())
            .ok_or_else(|| internal(OPERATION_INSERT))?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).map_err(|_| internal(OPERATION_INSERT))?;
        mac.update(self.deployment_id.as_bytes());
        mac.update(&[0u8]);
        mac.update(b"client");
        mac.update(&[0u8]);
        mac.update(client_ip.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn associated_data(&self, row_id: &uuid::Uuid, purpose: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(96);
        aad.extend_from_slice(b"greengateway.pending-login");
        aad.push(0);
        aad.extend_from_slice(&ENVELOPE_SCHEMA_VERSION.to_be_bytes());
        let deployment = self.deployment_id.as_bytes();
        aad.extend_from_slice(&(deployment.len() as u16).to_be_bytes());
        aad.extend_from_slice(deployment);
        aad.extend_from_slice(row_id.as_bytes());
        aad.push(purpose.len() as u8);
        aad.extend_from_slice(purpose.as_bytes());
        aad
    }

    fn seal(
        &self,
        row_id: &uuid::Uuid,
        purpose: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), RepositoryError> {
        let key = self
            .keyring
            .key(self.keyring.primary_id())
            .ok_or_else(|| internal(OPERATION_INSERT))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| internal(OPERATION_INSERT))?;
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| internal(OPERATION_INSERT))?;
        let aad = self.associated_data(row_id, purpose);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| internal(OPERATION_INSERT))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    fn open(
        &self,
        row_id: &uuid::Uuid,
        key_id: &str,
        purpose: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryError> {
        // A key this replica does not hold, or a tag that does not verify,
        // is a row this replica cannot vouch for: fail closed as invalid
        // data, which the handlers answer 503, never as "unknown state".
        let key = self
            .keyring
            .key(key_id)
            .ok_or_else(|| invalid_data(OPERATION_TAKE))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| internal(OPERATION_TAKE))?;
        let nonce: [u8; NONCE_BYTES] =
            nonce.try_into().map_err(|_| invalid_data(OPERATION_TAKE))?;
        let aad = self.associated_data(row_id, purpose);
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid_data(OPERATION_TAKE))
    }
}

/// The prune statement over whichever client the caller holds: the
/// admission transaction, or the singleton's dedicated session.
async fn prune_expired_statement(
    client: &tokio_postgres::Client,
    limit: i64,
    operation: &'static str,
) -> Result<u64, RepositoryError> {
    client
        .execute(PRUNE_EXPIRED_SQL, &[&limit])
        .await
        .map_err(|error| classify_query(error, operation))
}

#[async_trait]
impl PendingLoginBackend for PostgresPendingLoginStore {
    async fn insert(
        &self,
        state: &str,
        pending: PendingLogin,
    ) -> Result<bool, PendingLoginStoreError> {
        let state_hash = self.state_digest(state);
        let client_key = self
            .client_key(&pending.client_ip)
            .map_err(PendingLoginStoreError)?;
        let row_id = uuid::Uuid::new_v4();
        let (verifier_nonce, verifier_ct) = self
            .seal(&row_id, PURPOSE_VERIFIER, pending.code_verifier.as_bytes())
            .map_err(PendingLoginStoreError)?;
        let (nonce_nonce, nonce_ct) = self
            .seal(&row_id, PURPOSE_NONCE, pending.nonce.as_bytes())
            .map_err(PendingLoginStoreError)?;
        let ttl_seconds = self.limits.ttl.as_secs_f64();
        let max_per_client = i64::try_from(self.limits.max_per_ip).unwrap_or(i64::MAX);
        let max_entries = i64::try_from(self.limits.max_entries).unwrap_or(i64::MAX);

        let client = self
            .pool
            .get()
            .await
            .map_err(classify_pool_error)
            .map_err(PendingLoginStoreError)?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| PendingLoginStoreError(classify_query(error, OPERATION_INSERT)))?;
        let outcome: Result<bool, RepositoryError> = async {
            // Admissions serialize on one lock so the quota counts are
            // authoritative across replicas.
            client
                .execute("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK_KEY])
                .await
                .map_err(|error| classify_query(error, OPERATION_INSERT))?;
            #[cfg(test)]
            if let Some(delay) = self.after_lock_delay {
                tokio::time::sleep(delay).await;
            }
            // Every clock below is the statement clock, not `now()`: `now()`
            // is fixed at transaction start, before the admission lock was
            // waited for, and a TTL measured from there could already have
            // lapsed by the time the row is written -- an admitted login
            // whose callback is guaranteed to fail. Pruning and the quota
            // count use the same basis so they agree with the expiry.
            prune_expired_statement(&client, PRUNE_BATCH, OPERATION_INSERT).await?;
            let counts = client
                .query_one(
                    r#"
                    SELECT COUNT(*) FILTER (WHERE client_key = $1), COUNT(*)
                    FROM greengateway.admin_pending_logins
                    WHERE expires_at > clock_timestamp()
                    "#,
                    &[&client_key],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_INSERT))?;
            let per_client: i64 = counts
                .try_get(0)
                .map_err(|_| invalid_data(OPERATION_INSERT))?;
            let total: i64 = counts
                .try_get(1)
                .map_err(|_| invalid_data(OPERATION_INSERT))?;
            if per_client >= max_per_client || total >= max_entries {
                return Ok(false);
            }
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.admin_pending_logins (
                        id, state_hash, client_key, key_id,
                        verifier_nonce, verifier_ct, nonce_nonce, nonce_ct, expires_at
                    ) VALUES (
                        $1::text::uuid, $2, $3, $4, $5, $6, $7, $8,
                        clock_timestamp() + make_interval(secs => $9)
                    )
                    "#,
                    &[
                        &row_id.to_string(),
                        &state_hash,
                        &client_key,
                        &self.keyring.primary_id(),
                        &verifier_nonce,
                        &verifier_ct,
                        &nonce_nonce,
                        &nonce_ct,
                        &ttl_seconds,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_INSERT))?;
            Ok(true)
        }
        .await;
        match outcome {
            Ok(true) => {
                client.batch_execute("COMMIT").await.map_err(|error| {
                    PendingLoginStoreError(classify_query(error, OPERATION_INSERT))
                })?;
                Ok(true)
            }
            Ok(false) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Ok(false)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(PendingLoginStoreError(error))
            }
        }
    }

    async fn take(&self, state: &str) -> Result<Option<PendingLogin>, PendingLoginStoreError> {
        let state_hash = self.state_digest(state);
        let client = self
            .pool
            .get()
            .await
            .map_err(classify_pool_error)
            .map_err(PendingLoginStoreError)?;
        // Consumption and opening are one transaction: a replica that
        // cannot open the envelopes (a key it does not hold, a tag that
        // does not verify) rolls the delete back, so the login survives
        // for a replica that can. Two callbacks still consume exactly
        // once -- the row lock serializes them and the loser finds
        // nothing once the winner commits.
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| PendingLoginStoreError(classify_query(error, OPERATION_TAKE)))?;
        let outcome: Result<Option<PendingLogin>, RepositoryError> = async {
            let row = client
                .query_opt(
                    r#"
                    DELETE FROM greengateway.admin_pending_logins
                    WHERE state_hash = $1 AND expires_at > now()
                    RETURNING id::text, key_id, verifier_nonce, verifier_ct, nonce_nonce, nonce_ct
                    "#,
                    &[&state_hash],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_TAKE))?;
            match row {
                Some(row) => self.open_row(&row).map(Some),
                None => Ok(None),
            }
        }
        .await;
        match outcome {
            Ok(consumed) => {
                client.batch_execute("COMMIT").await.map_err(|error| {
                    PendingLoginStoreError(classify_query(error, OPERATION_TAKE))
                })?;
                Ok(consumed)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(PendingLoginStoreError(error))
            }
        }
    }
}

impl PostgresPendingLoginStore {
    /// Open a consumed row's two envelopes. Any failure is `InvalidData`:
    /// the caller rolls the consumption back.
    fn open_row(&self, row: &tokio_postgres::Row) -> Result<PendingLogin, RepositoryError> {
        let id_text: String = row.try_get(0).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let row_id = uuid::Uuid::parse_str(&id_text).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let key_id: String = row.try_get(1).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let verifier_nonce: Vec<u8> = row.try_get(2).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let verifier_ct: Vec<u8> = row.try_get(3).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let nonce_nonce: Vec<u8> = row.try_get(4).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let nonce_ct: Vec<u8> = row.try_get(5).map_err(|_| invalid_data(OPERATION_TAKE))?;
        let verifier = self.open(
            &row_id,
            &key_id,
            PURPOSE_VERIFIER,
            &verifier_nonce,
            &verifier_ct,
        )?;
        let nonce = self.open(&row_id, &key_id, PURPOSE_NONCE, &nonce_nonce, &nonce_ct)?;
        Ok(PendingLogin {
            code_verifier: String::from_utf8(verifier.to_vec())
                .map_err(|_| invalid_data(OPERATION_TAKE))?,
            nonce: String::from_utf8(nonce.to_vec()).map_err(|_| invalid_data(OPERATION_TAKE))?,
            created_at: std::time::Instant::now(),
            client_ip: String::new(),
        })
    }
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn internal(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::Internal, operation)
}
