//! PostgreSQL admin session store (issue #424, ADR-0009).
//!
//! The `ADMIN_SESSION_MODE=cluster_postgres` backend of
//! [`AdminSessionStore`]: the sessions the gateway issues after a
//! browser-bound OIDC login, and the pending cookie logins logout can still
//! cancel, shared by every replica on the PostgreSQL primary. The front end
//! (`auth::admin_session::AdminSessions`) is the same in both modes; this
//! module decides only what is stored, on which clock, and how it ends.
//!
//! What is stored, and what is not:
//!
//! - **No secret the browser holds is stored.** Rows are keyed by the
//!   front's purpose-separated digests over the deployment ID: the session
//!   cookie, the login's browser binding and the CSRF token the session is
//!   bound to. Each is a 256-bit or 122-bit random value, so a database
//!   reader learns nothing they could present.
//! - **The access token is AEAD-encrypted** with XChaCha20-Poly1305 under the
//!   operator's login keyring (the pending-login keyring), with the
//!   deployment ID, the session digest and the session ID bound as
//!   associated data. A ciphertext moved to another row or deployment fails
//!   to open. The envelope names the key it was sealed under, so a
//!   `decrypt_only` predecessor still opens it; keep predecessors for one
//!   session TTL.
//! - **Both deadlines are the database clock's.** `expires_at` is fixed at
//!   issuance. `idle_expires_at` moves on each admitted request, never past
//!   `expires_at` (a check constraint holds it there), so a session is live
//!   exactly while `idle_expires_at > clock_timestamp()`.
//! - **Every request reads the primary.** Nothing is cached, so a logout,
//!   replacement or rejection committed on one replica refuses the next
//!   request on every replica. The admit after the provider check is
//!   conditional on the row still being live: a withdrawal during
//!   validation wins.
//! - **Admissions are transactional and bounded.** Beginning a login and
//!   granting a session take one transaction-scoped advisory lock, prune a
//!   bounded batch of expired rows, count, and write, so two replicas cannot
//!   both admit the row that fills the last slot.
//! - **Each grant and each withdrawal writes one `admin_session_evidence`
//!   row in the same statement or transaction as the change** (migration
//!   19). A change whose evidence cannot be written does not happen. An
//!   expiry is recorded when the prune removes the row.
//!
//! A store that cannot be consulted, or a row this replica cannot open, is a
//! dependency failure: the front answers `503`, never "signed out".

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::{
    auth::{
        admin_session::{
            AdminSessionConfig, AdminSessionStore, GrantOutcome, SessionDigest, SessionGrant,
            StoredSession, MAX_ACCESS_TOKEN_BYTES,
        },
        principal::{MAX_PRINCIPAL_ISSUER_BYTES, MAX_PRINCIPAL_SUBJECT_BYTES},
        AuthError,
    },
    connections::local_secret::LocalSecretKeyring,
};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_BEGIN: &str = "admin_session_begin_login";
const OPERATION_GRANT: &str = "admin_session_grant";
const OPERATION_LOOKUP: &str = "admin_session_lookup";
const OPERATION_ADMIT: &str = "admin_session_admit";
const OPERATION_WITHDRAW: &str = "admin_session_withdraw";
const OPERATION_PRUNE: &str = "admin_session_prune";

const UNAVAILABLE: &str = "admin session authority is unavailable";

/// The AEAD envelope's schema, bound into the associated data.
const ENVELOPE_SCHEMA_VERSION: u16 = 1;
const NONCE_BYTES: usize = 24;
const PURPOSE_ACCESS_TOKEN: &str = "access_token";
/// Transaction-scoped advisory lock serializing session and login
/// admissions. One database is one deployment, so a constant key is the
/// whole namespace; it differs from the pending-login store's key.
const ADMISSION_LOCK_KEY: i64 = 0x6767_7761_6473_6573;
/// Expired rows pruned per admission, so the sweep is bounded by the
/// admission rate rather than by how long the deployment has run.
const PRUNE_BATCH: i64 = 256;
/// The bound on one singleton prune step, independent of the batch.
const MAX_PRUNE_BATCH: u32 = 10_000;

const REASON_LOGOUT: &str = "logout";
const REASON_REPLACED: &str = "replaced";

const LOOKUP_SQL: &str = r#"
    SELECT id::text, csrf_hash, user_id, issuer, key_id, token_nonce, token_ct
    FROM greengateway.admin_sessions
    WHERE session_hash = $1 AND idle_expires_at > clock_timestamp()
    "#;

/// The idle deadline moves from this statement's clock and never past the
/// absolute deadline. Admitting a session also releases any pending login
/// still tracking it: presenting the cookie proves its response arrived.
const ADMIT_SQL: &str = r#"
    WITH admitted AS (
        UPDATE greengateway.admin_sessions
        SET last_seen_at = clock_timestamp(),
            idle_expires_at = LEAST(expires_at, clock_timestamp() + make_interval(secs => $3))
        WHERE session_hash = $1 AND id = $2::text::uuid
          AND idle_expires_at > clock_timestamp()
        RETURNING session_hash
    ), released AS (
        DELETE FROM greengateway.admin_session_logins
        WHERE issued_session_hash IN (SELECT session_hash FROM admitted)
    )
    SELECT count(*) FROM admitted
    "#;

/// Withdraw sessions by key with one evidence row each, and release the
/// pending logins that tracked them. One statement, so the evidence exists
/// exactly when the withdrawal does.
const WITHDRAW_SQL: &str = r#"
    WITH withdrawn AS (
        DELETE FROM greengateway.admin_sessions
        WHERE session_hash = ANY($1::text[])
        RETURNING session_hash, id, user_id, issuer, expires_at
    ), released AS (
        DELETE FROM greengateway.admin_session_logins
        WHERE issued_session_hash IN (SELECT session_hash FROM withdrawn)
    )
    INSERT INTO greengateway.admin_session_evidence (
        event_id, operation_id, session_id, action, reason, user_id, issuer, expires_at
    )
    SELECT gen_random_uuid(), $2::text::uuid, id, 'admin_session.withdraw', $3,
           user_id, issuer, expires_at
    FROM withdrawn
    "#;

/// The same, for one session whose token the provider rejected or which now
/// names another identity. The ID guards against a row that is not the one
/// the request read.
const REJECT_SQL: &str = r#"
    WITH withdrawn AS (
        DELETE FROM greengateway.admin_sessions
        WHERE session_hash = $1 AND id = $2::text::uuid
        RETURNING session_hash, id, user_id, issuer, expires_at
    ), released AS (
        DELETE FROM greengateway.admin_session_logins
        WHERE issued_session_hash IN (SELECT session_hash FROM withdrawn)
    )
    INSERT INTO greengateway.admin_session_evidence (
        event_id, operation_id, session_id, action, reason, user_id, issuer, expires_at
    )
    SELECT gen_random_uuid(), $3::text::uuid, id, 'admin_session.withdraw', 'rejected',
           user_id, issuer, expires_at
    FROM withdrawn
    "#;

/// Expired sessions, oldest deadline first, judged on the statement clock.
/// Rows another transaction holds are skipped rather than waited for: that
/// transaction is withdrawing or admitting them already.
const PRUNE_SESSIONS_SQL: &str = r#"
    WITH withdrawn AS (
        DELETE FROM greengateway.admin_sessions
        WHERE session_hash IN (
            SELECT session_hash FROM greengateway.admin_sessions
            WHERE idle_expires_at <= clock_timestamp()
            ORDER BY idle_expires_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING session_hash, id, user_id, issuer, expires_at
    ), released AS (
        DELETE FROM greengateway.admin_session_logins
        WHERE issued_session_hash IN (SELECT session_hash FROM withdrawn)
    )
    INSERT INTO greengateway.admin_session_evidence (
        event_id, operation_id, session_id, action, reason, user_id, issuer, expires_at
    )
    SELECT gen_random_uuid(), $2::text::uuid, id, 'admin_session.withdraw', 'expired',
           user_id, issuer, expires_at
    FROM withdrawn
    "#;

const PRUNE_LOGINS_SQL: &str = r#"
    DELETE FROM greengateway.admin_session_logins
    WHERE binding_hash IN (
        SELECT binding_hash FROM greengateway.admin_session_logins
        WHERE expires_at <= clock_timestamp()
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )
    "#;

/// One clock reading for every timestamp of the new row, so the idle
/// deadline can never land after the absolute one.
const GRANT_SQL: &str = r#"
    WITH clock AS (SELECT clock_timestamp() AS at),
    granted AS (
        INSERT INTO greengateway.admin_sessions (
            session_hash, id, csrf_hash, user_id, issuer, key_id, token_nonce, token_ct,
            created_at, last_seen_at, expires_at, idle_expires_at
        )
        SELECT $1, $2::text::uuid, $3, $4, $5, $6, $7, $8, at, at,
               at + make_interval(secs => $9),
               LEAST(at + make_interval(secs => $9), at + make_interval(secs => $10))
        FROM clock
        RETURNING id, user_id, issuer, expires_at
    )
    INSERT INTO greengateway.admin_session_evidence (
        event_id, operation_id, session_id, action, reason, user_id, issuer, expires_at
    )
    SELECT gen_random_uuid(), $11::text::uuid, id, 'admin_session.grant', 'issued',
           user_id, issuer, expires_at
    FROM granted
    "#;

pub struct PostgresAdminSessionStore {
    pool: deadpool_postgres::Pool,
    deployment_id: Arc<str>,
    keyring: LocalSecretKeyring,
    config: AdminSessionConfig,
}

impl PostgresAdminSessionStore {
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment_id: &str,
        keyring: LocalSecretKeyring,
        config: AdminSessionConfig,
    ) -> Self {
        Self {
            pool,
            deployment_id: Arc::from(deployment_id),
            keyring,
            config,
        }
    }

    /// Withdraw up to `limit` expired sessions, each with its evidence row,
    /// and delete up to `limit` expired pending logins: the maintenance
    /// singleton's bounded step. Every admission also prunes a small batch,
    /// so this matters only for a deployment whose logins stopped. Needs no
    /// keyring, and runs on the connection the caller holds: the dedicated
    /// session that holds the maintenance advisory lock. Returns how many
    /// rows were removed.
    pub(crate) async fn prune_expired_with(
        client: &tokio_postgres::Client,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        prune_expired_statements(
            client,
            i64::from(limit.clamp(1, MAX_PRUNE_BATCH)),
            OPERATION_PRUNE,
        )
        .await
    }

    async fn client(
        &self,
        operation: &'static str,
    ) -> Result<deadpool_postgres::Object, AuthError> {
        self.pool
            .get()
            .await
            .map_err(classify_pool_error)
            .map_err(|error| unavailable(operation, &error))
    }

    fn associated_data(&self, key: &SessionDigest, session_id: &uuid::Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(128);
        aad.extend_from_slice(b"greengateway.admin-session");
        aad.push(0);
        aad.extend_from_slice(&ENVELOPE_SCHEMA_VERSION.to_be_bytes());
        let deployment = self.deployment_id.as_bytes();
        aad.extend_from_slice(&(deployment.len() as u16).to_be_bytes());
        aad.extend_from_slice(deployment);
        aad.extend_from_slice(key);
        aad.extend_from_slice(session_id.as_bytes());
        aad.push(PURPOSE_ACCESS_TOKEN.len() as u8);
        aad.extend_from_slice(PURPOSE_ACCESS_TOKEN.as_bytes());
        aad
    }

    fn seal(
        &self,
        key: &SessionDigest,
        session_id: &uuid::Uuid,
        token: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), RepositoryError> {
        let material = self
            .keyring
            .key(self.keyring.primary_id())
            .ok_or_else(|| internal(OPERATION_GRANT))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(material).map_err(|_| internal(OPERATION_GRANT))?;
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| internal(OPERATION_GRANT))?;
        let aad = self.associated_data(key, session_id);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: token.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| internal(OPERATION_GRANT))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    /// Open a looked-up row. A key this replica does not hold, or a tag that
    /// does not verify, is a row this replica cannot vouch for: invalid data,
    /// which the front answers `503`, never "signed out".
    fn open_row(
        &self,
        key: &SessionDigest,
        row: &tokio_postgres::Row,
    ) -> Result<StoredSession, RepositoryError> {
        let id_text: String = row.try_get(0).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let session_id =
            uuid::Uuid::parse_str(&id_text).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let csrf_hex: String = row.try_get(1).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let user_id: String = row.try_get(2).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let issuer: Option<String> = row.try_get(3).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let key_id: String = row.try_get(4).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let nonce: Vec<u8> = row.try_get(5).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let ciphertext: Vec<u8> = row.try_get(6).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let mut csrf = [0u8; 32];
        hex::decode_to_slice(&csrf_hex, &mut csrf).map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let material = self
            .keyring
            .key(&key_id)
            .ok_or_else(|| invalid_data(OPERATION_LOOKUP))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(material).map_err(|_| internal(OPERATION_LOOKUP))?;
        let nonce: [u8; NONCE_BYTES] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let aad = self.associated_data(key, &session_id);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        let token = String::from_utf8(plaintext.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| invalid_data(OPERATION_LOOKUP))?;
        Ok(StoredSession {
            token,
            user_id,
            issuer,
            id: session_id.to_string(),
            csrf,
        })
    }

    async fn begin_login_in(
        &self,
        client: &tokio_postgres::Client,
        binding: &str,
        ttl: Duration,
        delivered: Option<String>,
    ) -> Result<bool, RepositoryError> {
        admission_lock(client, OPERATION_BEGIN).await?;
        prune_expired_statements(client, PRUNE_BATCH, OPERATION_BEGIN).await?;
        if let Some(delivered) = delivered {
            client
                .execute(
                    "DELETE FROM greengateway.admin_session_logins \
                     WHERE issued_session_hash = $1",
                    &[&delivered],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_BEGIN))?;
        }
        let pending: i64 = client
            .query_one(
                "SELECT count(*) FROM greengateway.admin_session_logins \
                 WHERE expires_at > clock_timestamp()",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_BEGIN))?
            .try_get(0)
            .map_err(|_| invalid_data(OPERATION_BEGIN))?;
        if pending >= max_entries(&self.config) {
            return Ok(false);
        }
        client
            .execute(
                r#"
                INSERT INTO greengateway.admin_session_logins (binding_hash, expires_at)
                VALUES ($1, clock_timestamp() + make_interval(secs => $2))
                ON CONFLICT (binding_hash) DO UPDATE
                SET expires_at = EXCLUDED.expires_at, issued_session_hash = NULL,
                    created_at = now()
                "#,
                &[&binding, &ttl.as_secs_f64()],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_BEGIN))?;
        Ok(true)
    }

    async fn grant_in(
        &self,
        client: &tokio_postgres::Client,
        grant: &SessionGrant,
    ) -> Result<GrantOutcome, RepositoryError> {
        let session = &grant.session;
        if session.user_id.is_empty()
            || session.user_id.len() > MAX_PRINCIPAL_SUBJECT_BYTES
            || session
                .issuer
                .as_ref()
                .is_some_and(|issuer| issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES)
            || session.token.is_empty()
            || session.token.len() > MAX_ACCESS_TOKEN_BYTES
        {
            return Err(invalid_data(OPERATION_GRANT));
        }
        let session_id =
            uuid::Uuid::parse_str(&session.id).map_err(|_| invalid_data(OPERATION_GRANT))?;
        let key = hex::encode(grant.key);
        let binding = hex::encode(grant.binding);
        let previous = grant.previous.map(hex::encode);
        let operation_id = uuid::Uuid::new_v4().to_string();

        admission_lock(client, OPERATION_GRANT).await?;
        prune_expired_statements(client, PRUNE_BATCH, OPERATION_GRANT).await?;
        let pending = client
            .query_opt(
                "SELECT issued_session_hash IS NULL FROM greengateway.admin_session_logins \
                 WHERE binding_hash = $1 AND expires_at > clock_timestamp() FOR UPDATE",
                &[&binding],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_GRANT))?;
        let unissued = match pending {
            Some(row) => row
                .try_get::<_, bool>(0)
                .map_err(|_| invalid_data(OPERATION_GRANT))?,
            None => false,
        };
        if !unissued {
            return Ok(GrantOutcome::NoPendingLogin);
        }
        // Do not withdraw a prior session if admission would fail.
        let replaces = match &previous {
            Some(previous) => client
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM greengateway.admin_sessions \
                     WHERE session_hash = $1 AND idle_expires_at > clock_timestamp())",
                    &[previous],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_GRANT))?
                .try_get::<_, bool>(0)
                .map_err(|_| invalid_data(OPERATION_GRANT))?,
            None => false,
        };
        let live: i64 = client
            .query_one(
                "SELECT count(*) FROM greengateway.admin_sessions \
                 WHERE idle_expires_at > clock_timestamp()",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_GRANT))?
            .try_get(0)
            .map_err(|_| invalid_data(OPERATION_GRANT))?;
        if live >= max_entries(&self.config) && !replaces {
            return Ok(GrantOutcome::AtCapacity);
        }
        // Only a live session is replaced. One already past a deadline is
        // left to the prune, whose evidence says it expired.
        if let Some(previous) = previous.filter(|_| replaces) {
            client
                .execute(
                    WITHDRAW_SQL,
                    &[&vec![previous], &operation_id, &REASON_REPLACED],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_GRANT))?;
        }
        let (nonce, ciphertext) = self.seal(&grant.key, &session_id, &session.token)?;
        let granted = client
            .execute(
                GRANT_SQL,
                &[
                    &key,
                    &session.id,
                    &hex::encode(session.csrf),
                    &session.user_id,
                    &session.issuer,
                    &self.keyring.primary_id(),
                    &nonce,
                    &ciphertext,
                    &self.config.ttl.as_secs_f64(),
                    &self.config.idle_timeout.as_secs_f64(),
                    &operation_id,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_GRANT))?;
        if granted != 1 {
            return Err(internal(OPERATION_GRANT));
        }
        client
            .execute(
                "UPDATE greengateway.admin_session_logins SET issued_session_hash = $1 \
                 WHERE binding_hash = $2",
                &[&key, &binding],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_GRANT))?;
        Ok(GrantOutcome::Granted)
    }

    async fn withdraw_in(
        &self,
        client: &tokio_postgres::Client,
        key: Option<String>,
        binding: Option<String>,
    ) -> Result<(), RepositoryError> {
        let mut targets: Vec<String> = key.into_iter().collect();
        if let Some(binding) = binding {
            let cancelled = client
                .query_opt(
                    "DELETE FROM greengateway.admin_session_logins WHERE binding_hash = $1 \
                     RETURNING issued_session_hash",
                    &[&binding],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_WITHDRAW))?;
            if let Some(row) = cancelled {
                let issued: Option<String> = row
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_WITHDRAW))?;
                targets.extend(issued);
            }
        }
        if targets.is_empty() {
            return Ok(());
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        client
            .execute(WITHDRAW_SQL, &[&targets, &operation_id, &REASON_LOGOUT])
            .await
            .map_err(|error| classify_query(error, OPERATION_WITHDRAW))?;
        Ok(())
    }
}

#[async_trait]
impl AdminSessionStore for PostgresAdminSessionStore {
    fn namespace(&self) -> &str {
        &self.deployment_id
    }

    async fn begin_login(
        &self,
        binding: &SessionDigest,
        ttl: Duration,
        delivered: Option<&SessionDigest>,
    ) -> Result<bool, AuthError> {
        let binding = hex::encode(binding);
        let delivered = delivered.map(hex::encode);
        let client = self.client(OPERATION_BEGIN).await?;
        transaction(&client, OPERATION_BEGIN, |client| {
            Box::pin(self.begin_login_in(client, &binding, ttl, delivered))
        })
        .await
        .map_err(|error| unavailable(OPERATION_BEGIN, &error))
    }

    async fn grant(&self, grant: SessionGrant) -> Result<GrantOutcome, AuthError> {
        let client = self.client(OPERATION_GRANT).await?;
        transaction(&client, OPERATION_GRANT, |client| {
            Box::pin(self.grant_in(client, &grant))
        })
        .await
        .map_err(|error| unavailable(OPERATION_GRANT, &error))
    }

    async fn lookup(&self, key: &SessionDigest) -> Result<Option<StoredSession>, AuthError> {
        let client = self.client(OPERATION_LOOKUP).await?;
        let row = client
            .query_opt(LOOKUP_SQL, &[&hex::encode(key)])
            .await
            .map_err(|error| classify_query(error, OPERATION_LOOKUP))
            .map_err(|error| unavailable(OPERATION_LOOKUP, &error))?;
        match row {
            Some(row) => self
                .open_row(key, &row)
                .map(Some)
                .map_err(|error| unavailable(OPERATION_LOOKUP, &error)),
            None => Ok(None),
        }
    }

    async fn admit(&self, key: &SessionDigest, id: &str) -> Result<bool, AuthError> {
        let client = self.client(OPERATION_ADMIT).await?;
        let admitted: i64 = client
            .query_one(
                ADMIT_SQL,
                &[
                    &hex::encode(key),
                    &id,
                    &self.config.idle_timeout.as_secs_f64(),
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_ADMIT))
            .and_then(|row| row.try_get(0).map_err(|_| invalid_data(OPERATION_ADMIT)))
            .map_err(|error| unavailable(OPERATION_ADMIT, &error))?;
        Ok(admitted == 1)
    }

    async fn reject(&self, key: &SessionDigest, id: &str) -> Result<(), AuthError> {
        let client = self.client(OPERATION_WITHDRAW).await?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        client
            .execute(REJECT_SQL, &[&hex::encode(key), &id, &operation_id])
            .await
            .map_err(|error| classify_query(error, OPERATION_WITHDRAW))
            .map_err(|error| unavailable(OPERATION_WITHDRAW, &error))?;
        Ok(())
    }

    async fn withdraw(
        &self,
        key: Option<&SessionDigest>,
        binding: Option<&SessionDigest>,
    ) -> Result<(), AuthError> {
        if key.is_none() && binding.is_none() {
            return Ok(());
        }
        let key = key.map(hex::encode);
        let binding = binding.map(hex::encode);
        let client = self.client(OPERATION_WITHDRAW).await?;
        transaction(&client, OPERATION_WITHDRAW, |client| {
            Box::pin(self.withdraw_in(client, key, binding))
        })
        .await
        .map_err(|error| unavailable(OPERATION_WITHDRAW, &error))
    }
}

type StepFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

/// Run `step` inside one transaction on `client`: committed when it
/// succeeds, rolled back when it fails. A refusal the step reports as a
/// value (capacity, no pending login) changed nothing, so committing it is
/// harmless; the prune it ran first is kept.
async fn transaction<'a, T, F>(
    client: &'a tokio_postgres::Client,
    operation: &'static str,
    step: F,
) -> Result<T, RepositoryError>
where
    F: FnOnce(&'a tokio_postgres::Client) -> StepFuture<'a, T>,
{
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|error| classify_query(error, operation))?;
    match step(client).await {
        Ok(value) => {
            client
                .batch_execute("COMMIT")
                .await
                .map_err(|error| classify_query(error, operation))?;
            Ok(value)
        }
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

async fn admission_lock(
    client: &tokio_postgres::Client,
    operation: &'static str,
) -> Result<(), RepositoryError> {
    client
        .execute("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK_KEY])
        .await
        .map_err(|error| classify_query(error, operation))?;
    Ok(())
}

/// Both prune statements over whichever client the caller holds: an
/// admission transaction, or the singleton's dedicated session.
async fn prune_expired_statements(
    client: &tokio_postgres::Client,
    limit: i64,
    operation: &'static str,
) -> Result<u64, RepositoryError> {
    let operation_id = uuid::Uuid::new_v4().to_string();
    let sessions = client
        .execute(PRUNE_SESSIONS_SQL, &[&limit, &operation_id])
        .await
        .map_err(|error| classify_query(error, operation))?;
    let logins = client
        .execute(PRUNE_LOGINS_SQL, &[&limit])
        .await
        .map_err(|error| classify_query(error, operation))?;
    Ok(sessions.saturating_add(logins))
}

fn max_entries(config: &AdminSessionConfig) -> i64 {
    i64::try_from(config.max_entries).unwrap_or(i64::MAX)
}

/// A store failure, already logged where it was classified, as the front
/// sees it: the authority could not decide.
fn unavailable(operation: &'static str, error: &RepositoryError) -> AuthError {
    tracing::warn!(
        operation,
        kind = error.kind().as_str(),
        "admin session store could not be consulted"
    );
    AuthError::Upstream(UNAVAILABLE.to_owned())
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

#[cfg(test)]
#[path = "postgres_admin_sessions_tests.rs"]
mod tests;
