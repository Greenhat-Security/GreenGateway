use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    auth::{AuthMethod, Principal},
    egress::{EgressError, EgressRequestBody},
};

use super::{
    http::{ConnectionHttpError, ConnectionHttpRuntime},
    model::{ConnectionId, ConnectionKind},
    oauth::scope_connection_test_oauth_mints,
    status::{ConnectionOperationalState, ConnectionStatusReason},
    store::{ConnectionStatusUpdate, StoredConnection},
};

pub const CONNECTION_TEST_DEADLINE: Duration = Duration::from_secs(10);
const PRINCIPAL_ENTRY_LIMIT: usize = 1_024;
const CONNECTION_ENTRY_LIMIT: usize = super::model::MAX_CONNECTIONS;
const ADMISSION_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

const GLOBAL_CONCURRENCY: usize = 4;
const PRINCIPAL_CONCURRENCY: usize = 2;
const CONNECTION_CONCURRENCY: usize = 1;

const GLOBAL_BURST: f64 = 4.0;
const PRINCIPAL_BURST: f64 = 2.0;
const CONNECTION_BURST: f64 = 1.0;
const GLOBAL_REFILL_PER_SECOND: f64 = 2.0;
const PRINCIPAL_REFILL_PER_SECOND: f64 = 0.5;
const CONNECTION_REFILL_PER_SECOND: f64 = 0.2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTestStageName {
    EgressPolicy,
    SecretAvailable,
    Connected,
    TlsValid,
    Authenticated,
    ProtocolValid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTestStageOutcome {
    Success,
    Failure,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTestReason {
    HostNotAllowed,
    PortNotAllowed,
    NonGlobalIpBlocked,
    InvalidPolicy,
    DnsResolutionFailed,
    InvalidUrl,
    SchemeNotAllowed,
    RequestBodyTooLarge,
    RequestBodyReadFailed,
    UnexpectedStatus,
    ResponseTooLarge,
    ResponseIdleTimeout,
    HttpTimeout,
    HttpConnect,
    HttpRequest,
    HttpBody,
    HttpDecode,
    HttpStatus,
    HttpOther,
    InvalidTlsCaBundle,
    InvalidTlsClientIdentity,
    TlsInvalid,
    TlsUnavailable,
    AuthenticationNotSupported,
    CredentialInvalid,
    CredentialUnavailable,
    OauthTokenEgressDenied,
    OauthTokenUnavailable,
    OauthTokenRejected,
    OauthTokenInvalidResponse,
    AuthenticationFailed,
    TransportUnavailable,
    InvalidTargetPath,
    ConnectionKindMismatch,
    ConnectionChanged,
    TestProfileNotConfigured,
    ProtocolError,
    DeadlineExceeded,
    TestRateLimited,
    TestBusy,
    TestCapacityReached,
    InternalError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTestStage {
    pub name: ConnectionTestStageName,
    pub outcome: ConnectionTestStageOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ConnectionTestReason>,
}

impl ConnectionTestStage {
    pub const fn success(name: ConnectionTestStageName) -> Self {
        Self {
            name,
            outcome: ConnectionTestStageOutcome::Success,
            reason: None,
        }
    }

    pub const fn failure(name: ConnectionTestStageName, reason: ConnectionTestReason) -> Self {
        Self {
            name,
            outcome: ConnectionTestStageOutcome::Failure,
            reason: Some(reason),
        }
    }

    pub const fn not_applicable(name: ConnectionTestStageName) -> Self {
        Self {
            name,
            outcome: ConnectionTestStageOutcome::NotApplicable,
            reason: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTestResult {
    pub ok: bool,
    pub state: ConnectionOperationalState,
    pub tested_at: String,
    pub latency_ms: u64,
    pub stages: Vec<ConnectionTestStage>,
}

pub struct ConnectionTestExecution {
    pub result: ConnectionTestResult,
    pub status_reason: ConnectionStatusReason,
}

impl ConnectionTestExecution {
    pub fn status_update(&self) -> ConnectionStatusUpdate {
        ConnectionStatusUpdate {
            state: self.result.state,
            reason: self.status_reason,
            latency_ms: Some(self.result.latency_ms),
            catalog_age_secs: None,
            catalog_entry_count: None,
        }
    }
}

#[derive(Clone)]
pub struct ConnectionTestService {
    runtime: ConnectionHttpRuntime,
    admission: ConnectionTestAdmission,
}

impl fmt::Debug for ConnectionTestService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionTestService")
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct ConnectionTestAdmission {
    state: Arc<Mutex<AdmissionState>>,
    limits: AdmissionLimits,
}

impl fmt::Debug for ConnectionTestAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionTestAdmission")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct AdmissionLimits {
    principal_entries: usize,
    connection_entries: usize,
    idle_ttl: Duration,
    global_concurrency: usize,
    principal_concurrency: usize,
    connection_concurrency: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            principal_entries: PRINCIPAL_ENTRY_LIMIT,
            connection_entries: CONNECTION_ENTRY_LIMIT,
            idle_ttl: ADMISSION_IDLE_TTL,
            global_concurrency: GLOBAL_CONCURRENCY,
            principal_concurrency: PRINCIPAL_CONCURRENCY,
            connection_concurrency: CONNECTION_CONCURRENCY,
        }
    }
}

struct AdmissionState {
    global: AdmissionEntry,
    principals: HashMap<[u8; 32], AdmissionEntry>,
    connections: HashMap<ConnectionId, AdmissionEntry>,
}

struct AdmissionEntry {
    bucket: TokenBucket,
    in_flight: usize,
    last_seen: Instant,
}

struct TokenBucket {
    tokens: f64,
    burst: f64,
    refill_per_second: f64,
    updated_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionTestAdmissionError {
    RateLimited,
    Busy,
    CapacityReached,
    Unavailable,
}

impl ConnectionTestAdmissionError {
    pub const fn safe_reason(self) -> ConnectionTestReason {
        match self {
            Self::RateLimited => ConnectionTestReason::TestRateLimited,
            Self::Busy => ConnectionTestReason::TestBusy,
            Self::CapacityReached => ConnectionTestReason::TestCapacityReached,
            Self::Unavailable => ConnectionTestReason::InternalError,
        }
    }
}

pub struct ConnectionTestPermit {
    state: Weak<Mutex<AdmissionState>>,
    principal_key: [u8; 32],
    connection_id: ConnectionId,
}

impl fmt::Debug for ConnectionTestPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionTestPermit")
            .finish_non_exhaustive()
    }
}

impl Default for ConnectionTestAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTestAdmission {
    pub fn new() -> Self {
        Self::with_limits(AdmissionLimits::default())
    }

    fn with_limits(limits: AdmissionLimits) -> Self {
        let now = Instant::now();
        Self {
            state: Arc::new(Mutex::new(AdmissionState {
                global: AdmissionEntry::new(GLOBAL_BURST, GLOBAL_REFILL_PER_SECOND, now),
                principals: HashMap::new(),
                connections: HashMap::new(),
            })),
            limits,
        }
    }

    pub fn deadline(&self) -> Duration {
        CONNECTION_TEST_DEADLINE
    }

    pub fn admit(
        &self,
        principal: &Principal,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionTestPermit, ConnectionTestAdmissionError> {
        let now = Instant::now();
        let principal_key = principal_admission_key(principal);
        let mut state = self.state_guard()?;
        prune_idle_entries(&mut state, now, self.limits.idle_ttl);

        if !state.principals.contains_key(&principal_key)
            && state.principals.len() >= self.limits.principal_entries
        {
            return Err(ConnectionTestAdmissionError::CapacityReached);
        }
        if !state.connections.contains_key(connection_id)
            && state.connections.len() >= self.limits.connection_entries
        {
            return Err(ConnectionTestAdmissionError::CapacityReached);
        }

        state.principals.entry(principal_key).or_insert_with(|| {
            AdmissionEntry::new(PRINCIPAL_BURST, PRINCIPAL_REFILL_PER_SECOND, now)
        });
        state
            .connections
            .entry(connection_id.clone())
            .or_insert_with(|| {
                AdmissionEntry::new(CONNECTION_BURST, CONNECTION_REFILL_PER_SECOND, now)
            });

        state.global.refresh(now);
        let principal_entry = state
            .principals
            .get_mut(&principal_key)
            .expect("principal entry was inserted");
        principal_entry.refresh(now);
        let connection_entry = state
            .connections
            .get_mut(connection_id)
            .expect("connection entry was inserted");
        connection_entry.refresh(now);

        let principal_in_flight = state
            .principals
            .get(&principal_key)
            .map_or(0, |entry| entry.in_flight);
        let connection_in_flight = state
            .connections
            .get(connection_id)
            .map_or(0, |entry| entry.in_flight);
        if state.global.in_flight >= self.limits.global_concurrency
            || principal_in_flight >= self.limits.principal_concurrency
            || connection_in_flight >= self.limits.connection_concurrency
        {
            return Err(ConnectionTestAdmissionError::Busy);
        }

        let principal_has_token = state
            .principals
            .get(&principal_key)
            .is_some_and(AdmissionEntry::has_token);
        let connection_has_token = state
            .connections
            .get(connection_id)
            .is_some_and(AdmissionEntry::has_token);
        if !state.global.has_token() || !principal_has_token || !connection_has_token {
            return Err(ConnectionTestAdmissionError::RateLimited);
        }

        state.global.consume();
        state
            .principals
            .get_mut(&principal_key)
            .expect("principal entry was inserted")
            .consume();
        state
            .connections
            .get_mut(connection_id)
            .expect("connection entry was inserted")
            .consume();

        Ok(ConnectionTestPermit {
            state: Arc::downgrade(&self.state),
            principal_key,
            connection_id: connection_id.clone(),
        })
    }

    fn state_guard(&self) -> Result<MutexGuard<'_, AdmissionState>, ConnectionTestAdmissionError> {
        self.state
            .lock()
            .map_err(|_| ConnectionTestAdmissionError::Unavailable)
    }
}

impl ConnectionTestService {
    pub fn new(runtime: ConnectionHttpRuntime) -> Self {
        Self {
            runtime,
            admission: ConnectionTestAdmission::new(),
        }
    }

    pub fn deadline(&self) -> Duration {
        self.admission.deadline()
    }

    pub fn admit(
        &self,
        principal: &Principal,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionTestPermit, ConnectionTestAdmissionError> {
        self.admission.admit(principal, connection_id)
    }

    pub async fn execute(
        &self,
        record: &StoredConnection,
        expected_etag: &str,
    ) -> ConnectionTestExecution {
        self.execute_before(
            record,
            expected_etag,
            tokio::time::Instant::now() + self.deadline(),
        )
        .await
    }

    pub async fn execute_before(
        &self,
        record: &StoredConnection,
        expected_etag: &str,
        deadline: tokio::time::Instant,
    ) -> ConnectionTestExecution {
        scope_connection_test_oauth_mints(async {
            let started = Instant::now();
            match record.write.kind {
                ConnectionKind::HttpApi => {
                    match tokio::time::timeout_at(
                        deadline,
                        self.execute_http(record, expected_etag),
                    )
                    .await
                    {
                        Ok(execution) => execution,
                        Err(_) => deadline_execution(started),
                    }
                }
                ConnectionKind::McpStreamableHttp => {
                    self.execute_mcp(record, expected_etag, deadline).await
                }
            }
        })
        .await
    }

    async fn execute_http(
        &self,
        record: &StoredConnection,
        expected_etag: &str,
    ) -> ConnectionTestExecution {
        let started = Instant::now();
        let test_target = match self.runtime.test_target(record.id.as_str(), expected_etag) {
            Ok(Some(target)) => target,
            Ok(None) => {
                return failed_execution(
                    started,
                    ConnectionOperationalState::Unavailable,
                    ConnectionStatusReason::RequestFailed,
                    vec![ConnectionTestStage::failure(
                        ConnectionTestStageName::ProtocolValid,
                        ConnectionTestReason::ConnectionChanged,
                    )],
                );
            }
            Err(error) => {
                return failed_connection_execution(started, error);
            }
        };
        let target = test_target.target();
        let uses_authentication = target.is_credentialed();
        let uses_tls = !record.write.tls.is_empty();
        let mut stages = Vec::with_capacity(6);

        let checked = match target
            .preflight_client()
            .checked_destination(target.url())
            .await
        {
            Ok(destination) => {
                stages.push(ConnectionTestStage::success(
                    ConnectionTestStageName::EgressPolicy,
                ));
                destination
            }
            Err(error) => {
                stages.push(ConnectionTestStage::failure(
                    ConnectionTestStageName::EgressPolicy,
                    test_reason_from_egress(&error),
                ));
                return failed_execution(
                    started,
                    ConnectionOperationalState::Unavailable,
                    ConnectionStatusReason::EgressDenied,
                    stages,
                );
            }
        };

        let prepared = match self.runtime.prepare_transport(target, &checked).await {
            Ok(prepared) => prepared,
            Err(error) => {
                let (stage, state, status_reason) = connection_failure_classification(error);
                stages.push(ConnectionTestStage::failure(
                    stage,
                    test_reason_from_connection(error),
                ));
                return failed_execution(started, state, status_reason, stages);
            }
        };

        let credential = match self.runtime.resolve_credential(target).await {
            Ok(credential) => {
                stages.push(if uses_authentication || uses_tls {
                    ConnectionTestStage::success(ConnectionTestStageName::SecretAvailable)
                } else {
                    ConnectionTestStage::not_applicable(ConnectionTestStageName::SecretAvailable)
                });
                credential
            }
            Err(error) => {
                let (stage, state, status_reason) = connection_failure_classification(error);
                stages.push(ConnectionTestStage::failure(
                    stage,
                    test_reason_from_connection(error),
                ));
                return failed_execution(started, state, status_reason, stages);
            }
        };

        let mut headers = http::HeaderMap::new();
        if let Some(credential) = credential.as_ref() {
            if let Err(error) = credential.inject(&mut headers) {
                stages.push(ConnectionTestStage::failure(
                    ConnectionTestStageName::Authenticated,
                    test_reason_from_connection(error),
                ));
                return failed_execution(
                    started,
                    ConnectionOperationalState::Degraded,
                    ConnectionStatusReason::InvalidResponse,
                    stages,
                );
            }
        }

        let response = match prepared
            .client()
            .stream_request_with_body_at_checked_destination(
                prepared.destination(),
                test_target.method().clone(),
                target.url(),
                headers,
                EgressRequestBody::Empty,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                stages.push(ConnectionTestStage::failure(
                    ConnectionTestStageName::Connected,
                    test_reason_from_egress(&error),
                ));
                return failed_execution(
                    started,
                    ConnectionOperationalState::Unavailable,
                    ConnectionStatusReason::RequestFailed,
                    stages,
                );
            }
        };
        let status = response.status;
        if uses_authentication
            && matches!(
                status,
                http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN
            )
        {
            stages.push(ConnectionTestStage::success(
                ConnectionTestStageName::Connected,
            ));
            stages.push(if uses_tls {
                ConnectionTestStage::success(ConnectionTestStageName::TlsValid)
            } else {
                ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid)
            });
            if let Some(credential) = credential.as_ref() {
                credential.invalidate_after_unauthorized().await;
            }
            stages.push(ConnectionTestStage::failure(
                ConnectionTestStageName::Authenticated,
                ConnectionTestReason::AuthenticationFailed,
            ));
            return failed_execution(
                started,
                ConnectionOperationalState::Degraded,
                ConnectionStatusReason::InvalidResponse,
                stages,
            );
        }

        let mut response_body = response.body;
        while let Some(chunk) = response_body.next().await {
            if let Err(error) = chunk {
                stages.push(ConnectionTestStage::failure(
                    ConnectionTestStageName::Connected,
                    test_reason_from_egress(&error),
                ));
                return failed_execution(
                    started,
                    ConnectionOperationalState::Unavailable,
                    ConnectionStatusReason::RequestFailed,
                    stages,
                );
            }
        }

        stages.push(ConnectionTestStage::success(
            ConnectionTestStageName::Connected,
        ));
        stages.push(if uses_tls {
            ConnectionTestStage::success(ConnectionTestStageName::TlsValid)
        } else {
            ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid)
        });

        stages.push(if uses_authentication {
            ConnectionTestStage::success(ConnectionTestStageName::Authenticated)
        } else {
            ConnectionTestStage::not_applicable(ConnectionTestStageName::Authenticated)
        });

        if !test_target.expected_statuses().contains(&status.as_u16()) {
            stages.push(ConnectionTestStage::failure(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::UnexpectedStatus,
            ));
            return failed_execution(
                started,
                ConnectionOperationalState::Degraded,
                ConnectionStatusReason::InvalidResponse,
                stages,
            );
        }
        stages.push(ConnectionTestStage::success(
            ConnectionTestStageName::ProtocolValid,
        ));
        successful_execution(started, stages)
    }

    async fn execute_mcp(
        &self,
        record: &StoredConnection,
        expected_etag: &str,
        deadline: tokio::time::Instant,
    ) -> ConnectionTestExecution {
        let started = Instant::now();
        match crate::tools::mcp_upstream::probe_connection_protocol_before(
            &self.runtime,
            record.id.as_str(),
            expected_etag,
            deadline,
        )
        .await
        {
            Ok(()) => successful_execution(started, successful_mcp_stages(record)),
            Err(error) => failed_execution(
                started,
                error.operational_state(),
                error.status_reason(),
                vec![ConnectionTestStage::failure(
                    error.stage(),
                    error.safe_reason(),
                )],
            ),
        }
    }
}

fn managed_mcp_uses_authentication(record: &StoredConnection) -> bool {
    matches!(
        &record.write.discovery,
        Some(super::model::DiscoveryConfig::ManagedMcp {
            use_connection_authentication: true,
        })
    ) && record.write.sends_credentials()
}

fn successful_mcp_stages(record: &StoredConnection) -> Vec<ConnectionTestStage> {
    let uses_authentication = managed_mcp_uses_authentication(record);
    let uses_tls = !record.write.tls.is_empty();
    vec![
        ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
        if uses_authentication || uses_tls {
            ConnectionTestStage::success(ConnectionTestStageName::SecretAvailable)
        } else {
            ConnectionTestStage::not_applicable(ConnectionTestStageName::SecretAvailable)
        },
        ConnectionTestStage::success(ConnectionTestStageName::Connected),
        if uses_tls {
            ConnectionTestStage::success(ConnectionTestStageName::TlsValid)
        } else {
            ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid)
        },
        if uses_authentication {
            ConnectionTestStage::success(ConnectionTestStageName::Authenticated)
        } else {
            ConnectionTestStage::not_applicable(ConnectionTestStageName::Authenticated)
        },
        ConnectionTestStage::success(ConnectionTestStageName::ProtocolValid),
    ]
}

impl AdmissionEntry {
    fn new(burst: f64, refill_per_second: f64, now: Instant) -> Self {
        Self {
            bucket: TokenBucket {
                tokens: burst,
                burst,
                refill_per_second,
                updated_at: now,
            },
            in_flight: 0,
            last_seen: now,
        }
    }

    fn refresh(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.bucket.updated_at);
        self.bucket.tokens = (self.bucket.tokens
            + elapsed.as_secs_f64() * self.bucket.refill_per_second)
            .min(self.bucket.burst);
        self.bucket.updated_at = now;
        self.last_seen = now;
    }

    fn has_token(&self) -> bool {
        self.bucket.tokens >= 1.0
    }

    fn consume(&mut self) {
        self.bucket.tokens -= 1.0;
        self.in_flight += 1;
    }
}

impl Drop for ConnectionTestPermit {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let mut state = match state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                tracing::error!("Connection test admission lock poisoned while releasing a permit");
                poisoned.into_inner()
            }
        };
        state.global.in_flight = state.global.in_flight.saturating_sub(1);
        if let Some(entry) = state.principals.get_mut(&self.principal_key) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
        if let Some(entry) = state.connections.get_mut(&self.connection_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

fn prune_idle_entries(state: &mut AdmissionState, now: Instant, idle_ttl: Duration) {
    state.principals.retain(|_, entry| {
        entry.in_flight != 0 || now.saturating_duration_since(entry.last_seen) < idle_ttl
    });
    state.connections.retain(|_, entry| {
        entry.in_flight != 0 || now.saturating_duration_since(entry.last_seen) < idle_ttl
    });
}

fn principal_admission_key(principal: &Principal) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:connection-test-principal:v1\0");
    hash_optional_string(&mut hasher, principal.issuer.as_deref());
    hash_string(&mut hasher, &principal.user_id);
    hasher.update([match principal.auth_method {
        AuthMethod::Cookie => 1,
        AuthMethod::Bearer => 2,
        AuthMethod::ServiceToken => 3,
        AuthMethod::ClientCertificate => 4,
    }]);
    hasher.finalize().into()
}

fn successful_execution(
    started: Instant,
    stages: Vec<ConnectionTestStage>,
) -> ConnectionTestExecution {
    ConnectionTestExecution {
        result: ConnectionTestResult {
            ok: true,
            state: ConnectionOperationalState::Healthy,
            tested_at: tested_at(),
            latency_ms: elapsed_millis(started),
            stages,
        },
        status_reason: ConnectionStatusReason::TestSucceeded,
    }
}

fn failed_connection_execution(
    started: Instant,
    error: ConnectionHttpError,
) -> ConnectionTestExecution {
    let (stage, state, status_reason) = connection_failure_classification(error);
    failed_execution(
        started,
        state,
        status_reason,
        vec![ConnectionTestStage::failure(
            stage,
            test_reason_from_connection(error),
        )],
    )
}

pub(crate) fn connection_failure_classification(
    error: ConnectionHttpError,
) -> (
    ConnectionTestStageName,
    ConnectionOperationalState,
    ConnectionStatusReason,
) {
    match error {
        ConnectionHttpError::TlsInvalid | ConnectionHttpError::TlsUnavailable => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionOperationalState::Unavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::CredentialInvalid
        | ConnectionHttpError::CredentialHeaderConflict
        | ConnectionHttpError::CredentialUnavailable
        | ConnectionHttpError::UnsupportedAuthentication
        | ConnectionHttpError::OAuthTokenUnavailable
        | ConnectionHttpError::OAuthTokenRejected
        | ConnectionHttpError::OAuthTokenInvalidResponse => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionOperationalState::Unavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::OAuthTokenEgressDenied => (
            ConnectionTestStageName::EgressPolicy,
            ConnectionOperationalState::Unavailable,
            ConnectionStatusReason::EgressDenied,
        ),
        ConnectionHttpError::UpstreamAuthenticationRejected => (
            ConnectionTestStageName::Authenticated,
            ConnectionOperationalState::Degraded,
            ConnectionStatusReason::InvalidResponse,
        ),
        ConnectionHttpError::InvalidTargetPath => (
            ConnectionTestStageName::ProtocolValid,
            ConnectionOperationalState::Unavailable,
            ConnectionStatusReason::InvalidResponse,
        ),
        ConnectionHttpError::InvalidConnectionId
        | ConnectionHttpError::ConnectionNotFound
        | ConnectionHttpError::ConnectionDisabled
        | ConnectionHttpError::WrongConnectionKind
        | ConnectionHttpError::TransportUnavailable => (
            ConnectionTestStageName::Connected,
            ConnectionOperationalState::Unavailable,
            ConnectionStatusReason::RequestFailed,
        ),
    }
}

fn failed_execution(
    started: Instant,
    state: ConnectionOperationalState,
    status_reason: ConnectionStatusReason,
    stages: Vec<ConnectionTestStage>,
) -> ConnectionTestExecution {
    ConnectionTestExecution {
        result: ConnectionTestResult {
            ok: false,
            state,
            tested_at: tested_at(),
            latency_ms: elapsed_millis(started),
            stages,
        },
        status_reason,
    }
}

pub fn deadline_execution(started: Instant) -> ConnectionTestExecution {
    failed_execution(
        started,
        ConnectionOperationalState::Unavailable,
        ConnectionStatusReason::RequestFailed,
        vec![ConnectionTestStage::failure(
            ConnectionTestStageName::Connected,
            ConnectionTestReason::DeadlineExceeded,
        )],
    )
}

fn test_reason_from_connection(error: ConnectionHttpError) -> ConnectionTestReason {
    match error {
        ConnectionHttpError::InvalidConnectionId
        | ConnectionHttpError::ConnectionNotFound
        | ConnectionHttpError::ConnectionDisabled => ConnectionTestReason::ConnectionChanged,
        ConnectionHttpError::WrongConnectionKind => ConnectionTestReason::ConnectionKindMismatch,
        ConnectionHttpError::UnsupportedAuthentication => {
            ConnectionTestReason::AuthenticationNotSupported
        }
        ConnectionHttpError::TlsInvalid => ConnectionTestReason::TlsInvalid,
        ConnectionHttpError::TlsUnavailable => ConnectionTestReason::TlsUnavailable,
        ConnectionHttpError::InvalidTargetPath => ConnectionTestReason::TestProfileNotConfigured,
        ConnectionHttpError::CredentialHeaderConflict | ConnectionHttpError::CredentialInvalid => {
            ConnectionTestReason::CredentialInvalid
        }
        ConnectionHttpError::CredentialUnavailable => ConnectionTestReason::CredentialUnavailable,
        ConnectionHttpError::OAuthTokenEgressDenied => ConnectionTestReason::OauthTokenEgressDenied,
        ConnectionHttpError::OAuthTokenUnavailable => ConnectionTestReason::OauthTokenUnavailable,
        ConnectionHttpError::OAuthTokenRejected => ConnectionTestReason::OauthTokenRejected,
        ConnectionHttpError::OAuthTokenInvalidResponse => {
            ConnectionTestReason::OauthTokenInvalidResponse
        }
        ConnectionHttpError::UpstreamAuthenticationRejected => {
            ConnectionTestReason::AuthenticationFailed
        }
        ConnectionHttpError::TransportUnavailable => ConnectionTestReason::TransportUnavailable,
    }
}

fn test_reason_from_egress(error: &EgressError) -> ConnectionTestReason {
    match error.safe_category() {
        "host_not_allowed" => ConnectionTestReason::HostNotAllowed,
        "port_not_allowed" => ConnectionTestReason::PortNotAllowed,
        "non_global_ip_blocked" => ConnectionTestReason::NonGlobalIpBlocked,
        "invalid_policy" => ConnectionTestReason::InvalidPolicy,
        "dns_resolution_failed" => ConnectionTestReason::DnsResolutionFailed,
        "invalid_url" => ConnectionTestReason::InvalidUrl,
        "scheme_not_allowed" => ConnectionTestReason::SchemeNotAllowed,
        "request_body_too_large" => ConnectionTestReason::RequestBodyTooLarge,
        "request_body_read_failed" => ConnectionTestReason::RequestBodyReadFailed,
        "unexpected_status" => ConnectionTestReason::UnexpectedStatus,
        "response_too_large" => ConnectionTestReason::ResponseTooLarge,
        "response_idle_timeout" => ConnectionTestReason::ResponseIdleTimeout,
        "invalid_tls_ca_bundle" => ConnectionTestReason::InvalidTlsCaBundle,
        "invalid_tls_client_identity" => ConnectionTestReason::InvalidTlsClientIdentity,
        "http_timeout" => ConnectionTestReason::HttpTimeout,
        "http_connect" => ConnectionTestReason::HttpConnect,
        "http_request" => ConnectionTestReason::HttpRequest,
        "http_body" => ConnectionTestReason::HttpBody,
        "http_decode" => ConnectionTestReason::HttpDecode,
        "http_status" => ConnectionTestReason::HttpStatus,
        "http_other" => ConnectionTestReason::HttpOther,
        _ => ConnectionTestReason::InternalError,
    }
}

fn tested_at() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_string(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(user_id: &str) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            issuer: Some("https://issuer.example".to_owned()),
            email: None,
            org_id: None,
            roles: vec![],
            session_id: "opaque-session".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }

    fn connection(id: u128) -> ConnectionId {
        ConnectionId::parse(uuid::Uuid::from_u128(id).to_string())
            .expect("test connection ID should parse")
    }

    #[test]
    fn same_connection_is_busy_until_raii_permit_drops() {
        let admission = ConnectionTestAdmission::new();
        let principal = principal("user-1");
        let connection = connection(1);
        let permit = admission
            .admit(&principal, &connection)
            .expect("first test should be admitted");

        assert_eq!(
            admission.admit(&principal, &connection).unwrap_err(),
            ConnectionTestAdmissionError::Busy
        );
        drop(permit);
        assert_eq!(
            admission.admit(&principal, &connection).unwrap_err(),
            ConnectionTestAdmissionError::RateLimited,
            "dropping a permit releases concurrency but does not refund rate tokens"
        );
    }

    #[test]
    fn principal_and_global_concurrency_are_bounded() {
        let admission = ConnectionTestAdmission::new();
        let shared = principal("shared-user");
        let first = admission
            .admit(&shared, &connection(1))
            .expect("first principal request should be admitted");
        let second = admission
            .admit(&shared, &connection(2))
            .expect("second principal request should be admitted");
        assert_eq!(
            admission.admit(&shared, &connection(3)).unwrap_err(),
            ConnectionTestAdmissionError::Busy
        );
        drop(first);
        drop(second);

        let admission = ConnectionTestAdmission::new();
        let mut permits = Vec::new();
        for index in 0..GLOBAL_CONCURRENCY {
            permits.push(
                admission
                    .admit(
                        &principal(&format!("global-user-{index}")),
                        &connection(100 + index as u128),
                    )
                    .expect("global slot should be admitted"),
            );
        }
        assert_eq!(
            admission
                .admit(&principal("global-overflow"), &connection(999))
                .unwrap_err(),
            ConnectionTestAdmissionError::Busy
        );
    }

    #[test]
    fn unseen_principal_fails_closed_when_identity_map_is_full() {
        let admission = ConnectionTestAdmission::with_limits(AdmissionLimits {
            principal_entries: 1,
            connection_entries: 2,
            ..AdmissionLimits::default()
        });
        let permit = admission
            .admit(&principal("first-user"), &connection(1))
            .expect("first identity should be admitted");
        drop(permit);

        assert_eq!(
            admission
                .admit(&principal("second-user"), &connection(2))
                .unwrap_err(),
            ConnectionTestAdmissionError::CapacityReached
        );
    }

    #[test]
    fn principal_keys_are_identity_boundaries_and_debug_is_opaque() {
        let first = principal("user-1");
        let mut second = principal("user-1");
        second.issuer = Some("https://other-issuer.example".to_owned());
        assert_ne!(
            principal_admission_key(&first),
            principal_admission_key(&second)
        );

        let admission_debug = format!("{:?}", ConnectionTestAdmission::new());
        assert!(!admission_debug.contains("user-1"));
        assert!(!admission_debug.contains("issuer"));
    }

    #[test]
    fn result_serialization_uses_only_closed_safe_values() {
        let result = ConnectionTestResult {
            ok: false,
            state: ConnectionOperationalState::Unavailable,
            tested_at: "2026-07-27T00:00:00Z".to_owned(),
            latency_ms: 12,
            stages: vec![ConnectionTestStage::failure(
                ConnectionTestStageName::EgressPolicy,
                ConnectionTestReason::HostNotAllowed,
            )],
        };

        assert_eq!(
            serde_json::to_value(result).expect("result should serialize"),
            serde_json::json!({
                "ok": false,
                "state": "unavailable",
                "tested_at": "2026-07-27T00:00:00Z",
                "latency_ms": 12,
                "stages": [{
                    "name": "egress_policy",
                    "outcome": "failure",
                    "reason": "host_not_allowed"
                }]
            })
        );
    }

    #[test]
    fn connection_failures_preserve_operational_stage_and_status_reason() {
        for (error, expected_stage, expected_state, expected_status_reason) in [
            (
                ConnectionHttpError::OAuthTokenEgressDenied,
                ConnectionTestStageName::EgressPolicy,
                ConnectionOperationalState::Unavailable,
                ConnectionStatusReason::EgressDenied,
            ),
            (
                ConnectionHttpError::OAuthTokenRejected,
                ConnectionTestStageName::SecretAvailable,
                ConnectionOperationalState::Unavailable,
                ConnectionStatusReason::SecretUnavailable,
            ),
            (
                ConnectionHttpError::OAuthTokenInvalidResponse,
                ConnectionTestStageName::SecretAvailable,
                ConnectionOperationalState::Unavailable,
                ConnectionStatusReason::SecretUnavailable,
            ),
            (
                ConnectionHttpError::UpstreamAuthenticationRejected,
                ConnectionTestStageName::Authenticated,
                ConnectionOperationalState::Degraded,
                ConnectionStatusReason::InvalidResponse,
            ),
            (
                ConnectionHttpError::TransportUnavailable,
                ConnectionTestStageName::Connected,
                ConnectionOperationalState::Unavailable,
                ConnectionStatusReason::RequestFailed,
            ),
            (
                ConnectionHttpError::CredentialUnavailable,
                ConnectionTestStageName::SecretAvailable,
                ConnectionOperationalState::Unavailable,
                ConnectionStatusReason::SecretUnavailable,
            ),
        ] {
            assert_eq!(
                connection_failure_classification(error),
                (expected_stage, expected_state, expected_status_reason)
            );
        }
    }

    #[test]
    fn additional_header_only_managed_mcp_exercises_credential_stages() {
        let write = serde_json::from_value(serde_json::json!({
            "display_name": "Access-protected MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://mcp.example.test",
                "base_path": "/mcp"
            },
            "authentication": {"type": "none"},
            "additional_headers": [{
                "header_name": "cf-access-client-id",
                "secret_id": "access-client-id"
            }],
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": true
            }
        }))
        .expect("additional-header MCP Connection should deserialize");
        let record = StoredConnection {
            id: ConnectionId::parse("access-protected-mcp")
                .expect("test Connection ID should parse"),
            write,
            revisions: crate::connections::status::ConnectionRevisions {
                connection: 1,
                credential: 1,
                tls: 0,
                discovery: 1,
                status: 0,
            },
            created_at: "2026-09-03T00:00:00Z".to_owned(),
            updated_at: "2026-09-03T00:00:00Z".to_owned(),
        };

        assert!(managed_mcp_uses_authentication(&record));
        let stages = successful_mcp_stages(&record);
        for name in [
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestStageName::Authenticated,
        ] {
            assert_eq!(
                stages.iter().find(|stage| stage.name == name),
                Some(&ConnectionTestStage::success(name)),
                "an additional secret header must exercise the {name:?} MCP test stage"
            );
        }
    }
}
