//! Dynamic enum source resolution and last-known-good publication.
//!
//! The data plane only reads [`EnumSourceRuntime::snapshot`]. Network and
//! durable-store work is confined to explicit admin resolution and the fixed
//! refresh loop, so `tools/list` and `tools/call` can never drive upstream I/O.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak},
    time::Duration,
};

use futures_util::{stream, StreamExt};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use crate::{
    audit::{Actor, AuditEvent, AuditLog},
    connections::{
        control_plane::ConnectionControlPlane,
        http::{ConnectionHttpError, ConnectionHttpRuntime},
        model::ConnectionId,
        store::{
            enum_source_text_is_printable, validate_enum_source_values_payload,
            ConnectionStoreError, StoredConnection, StoredEnumSourceRevision,
            StoredEnumSourceValue, StoredEnumSourceValueWrite, StoredOpenApiSourceKind,
            StoredOpenApiSourceReport, StoredOpenApiSourceReports,
            OPENAPI_SOURCE_REPORTS_SCHEMA_VERSION,
        },
    },
    egress::{EgressError, EgressRequestBody},
    lifecycle::GatewayLifecycle,
};

use super::overlay::{
    EnumSourcePlan, LabelSourcePlan, OverlayError, OverlayProblem, OverlaySourcePlan,
    OverlayWarning, ResolvedEnumSource, ResolvedLabelSource, ResolvedOverlaySources, SourceLimits,
    SourceRequestPlan,
};

pub const ENUM_SOURCE_REFRESH_TICK: Duration = Duration::from_secs(15);
pub const MAX_CONCURRENT_ENUM_REFRESHES: usize = 4;
const ENUM_SOURCE_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const REFRESHED_EVENT: &str = "connection.enum_source_refreshed";
const REFRESH_FAILED_EVENT: &str = "connection.enum_source_refresh_failed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnumSourceState {
    Fresh,
    Stale,
    Missing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnumSourceSnapshot {
    pub state: EnumSourceState,
    pub values: Vec<Value>,
    pub labels: Option<Vec<String>>,
    pub values_revision: u64,
    pub resolved_at: Option<String>,
}

impl EnumSourceSnapshot {
    fn missing() -> Self {
        Self {
            state: EnumSourceState::Missing,
            values: Vec::new(),
            labels: None,
            values_revision: 0,
            resolved_at: None,
        }
    }

    pub fn item_count(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedPlan {
    pub sources: ResolvedOverlaySources,
    pub enum_values: Vec<StoredEnumSourceValueWrite>,
    pub reports: StoredOpenApiSourceReports,
    pub warnings: Vec<OverlayWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnumSourceFailureReason {
    HttpRuleDenied,
    ToolDisabled,
    EgressDenied,
    CredentialUnavailable,
    UpstreamStatus(u16),
    ResponseTooLarge,
    NotJson,
    SelectorNoItems,
    TooManyItems,
    ValueRejected,
    LabelRejected,
    SuspiciousValue,
    Timeout,
}

impl EnumSourceFailureReason {
    pub fn safe_reason(&self) -> String {
        match self {
            Self::HttpRuleDenied => "http_rule_denied".to_owned(),
            Self::ToolDisabled => "tool_disabled".to_owned(),
            Self::EgressDenied => "egress_denied".to_owned(),
            Self::CredentialUnavailable => "credential_unavailable".to_owned(),
            Self::UpstreamStatus(status) => format!("upstream_status:{status}"),
            Self::ResponseTooLarge => "response_too_large".to_owned(),
            Self::NotJson => "not_json".to_owned(),
            Self::SelectorNoItems => "selector_no_items".to_owned(),
            Self::TooManyItems => "too_many_items".to_owned(),
            Self::ValueRejected => "value_rejected".to_owned(),
            Self::LabelRejected => "label_rejected".to_owned(),
            Self::SuspiciousValue => "suspicious_value".to_owned(),
            Self::Timeout => "timeout".to_owned(),
        }
    }
}

impl fmt::Display for EnumSourceFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_reason())
    }
}

impl std::error::Error for EnumSourceFailureReason {}

/// Policy precheck supplied by the tools runtime. Implementations must use a
/// contextless dispatch and must not resolve a credential or perform I/O.
pub trait SourceAuthorizer: Send + Sync {
    fn authorize(
        &self,
        connection_id: &ConnectionId,
        source_id: &str,
        tool: Option<&str>,
        rendered_path_and_query: &str,
        audit_path_template: &str,
    ) -> Result<(), EnumSourceFailureReason>;
}

#[derive(Clone)]
pub struct EnumSourceRuntime {
    inner: Arc<EnumSourceRuntimeInner>,
}

struct EnumSourceRuntimeInner {
    control_plane: ConnectionControlPlane,
    http: ConnectionHttpRuntime,
    audit: AuditLog,
    registrations: RwLock<BTreeMap<SourceKey, RegisteredSource>>,
    cache: RwLock<BTreeMap<SourceKey, CachedSource>>,
    boot_rows: RwLock<BTreeMap<SourceKey, StoredEnumSourceValue>>,
    authority_revisions: RwLock<BTreeMap<SourceKey, u64>>,
    retry_not_before: Mutex<BTreeMap<SourceKey, Instant>>,
    flights: Mutex<BTreeMap<SourceKey, Weak<AsyncMutex<()>>>>,
    refresh_permits: Arc<Semaphore>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    connection_id: ConnectionId,
    source_id: String,
}

#[derive(Clone)]
struct RegisteredSource {
    overlay_revision: u64,
    plan: EnumSourcePlan,
}

#[derive(Clone)]
struct CachedSource {
    row: StoredEnumSourceValue,
    /// A row written/resolved by this process may be served fresh with a
    /// volatile provider generation. Durable adoption never sets this bit.
    locally_resolved_volatile: bool,
}

struct FetchedJson {
    body: Value,
    record: StoredConnection,
    credential_generation_digest: Option<String>,
}

struct FetchedEnum {
    resolved: ResolvedEnumSource,
    write: StoredEnumSourceValueWrite,
}

impl EnumSourceRuntime {
    pub fn new(
        control_plane: ConnectionControlPlane,
        http: ConnectionHttpRuntime,
        audit: AuditLog,
        boot_rows: Vec<StoredEnumSourceValue>,
    ) -> Self {
        let boot_rows = boot_rows
            .into_iter()
            .map(|row| {
                (
                    SourceKey {
                        connection_id: row.connection_id.clone(),
                        source_id: row.source_id.clone(),
                    },
                    row,
                )
            })
            .collect();
        Self {
            inner: Arc::new(EnumSourceRuntimeInner {
                control_plane,
                http,
                audit,
                registrations: RwLock::new(BTreeMap::new()),
                cache: RwLock::new(BTreeMap::new()),
                boot_rows: RwLock::new(boot_rows),
                authority_revisions: RwLock::new(BTreeMap::new()),
                retry_not_before: Mutex::new(BTreeMap::new()),
                flights: Mutex::new(BTreeMap::new()),
                refresh_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_ENUM_REFRESHES)),
            }),
        }
    }

    /// Resolve all compile-time sources. This fetches but does not publish to
    /// memory or durable storage; the caller passes `enum_values` to the
    /// catalog transaction, then calls [`Self::install_resolved_plan`].
    pub async fn resolve_plan(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
        allow_unresolved_enum_sources: bool,
        authorizer: &dyn SourceAuthorizer,
    ) -> Result<ResolvedPlan, OverlayError> {
        let authority_revisions = if plan.enum_sources.is_empty() {
            BTreeMap::new()
        } else {
            let store = self
                .inner
                .control_plane
                .managed_store()
                .map_err(|_| enum_authority_unavailable())?;
            store
                .enum_source_revisions()
                .await
                .map_err(|_| enum_authority_unavailable())?
                .into_iter()
                .filter(|row| {
                    row.connection_id == *connection_id && row.overlay_revision == overlay_revision
                })
                .map(|row| ((row.source_id, row.source_digest), row.values_revision))
                .collect::<BTreeMap<_, _>>()
        };
        let mut sources = ResolvedOverlaySources::default();
        let mut enum_values = Vec::with_capacity(plan.enum_sources.len());
        let mut reports = Vec::with_capacity(
            plan.enum_sources
                .len()
                .saturating_add(plan.label_sources.len()),
        );
        let mut warnings = Vec::new();
        let mut problems = Vec::new();

        for (source_id, source) in &plan.enum_sources {
            let flight = self.flight(connection_id, source_id);
            let _flight = flight.lock().await;
            match self
                .fetch_enum(
                    connection_id,
                    overlay_revision,
                    source,
                    authority_revisions
                        .get(&(source_id.clone(), source.source_digest.clone()))
                        .copied()
                        .unwrap_or_default(),
                    authorizer,
                )
                .await
            {
                Ok(fetched) => {
                    reports.push(source_report(
                        source_id,
                        StoredOpenApiSourceKind::Enum,
                        "fresh",
                        fetched.resolved.values.len(),
                        Some(&fetched.resolved.resolved_at),
                    ));
                    sources
                        .enum_sources
                        .insert(source_id.clone(), fetched.resolved);
                    enum_values.push(fetched.write);
                }
                Err(reason) => {
                    reports.push(source_report(
                        source_id,
                        StoredOpenApiSourceKind::Enum,
                        "missing",
                        0,
                        None,
                    ));
                    let path = format!("/enum_sources/{source_id}");
                    let message = format!(
                        "enum source '{source_id}' could not be resolved: {}",
                        reason.safe_reason()
                    );
                    if allow_unresolved_enum_sources {
                        warnings.push(OverlayWarning { path, message });
                    } else {
                        problems.push(OverlayProblem { path, message });
                    }
                }
            }
        }

        for (source_id, source) in &plan.label_sources {
            let flight = self.flight(connection_id, source_id);
            let _flight = flight.lock().await;
            match self.fetch_label(connection_id, source, authorizer).await {
                Ok(resolved) => {
                    reports.push(source_report(
                        source_id,
                        StoredOpenApiSourceKind::Label,
                        "fresh",
                        resolved.labels.len(),
                        Some(&resolved.resolved_at),
                    ));
                    sources.label_sources.insert(source_id.clone(), resolved);
                }
                Err(reason) => {
                    reports.push(source_report(
                        source_id,
                        StoredOpenApiSourceKind::Label,
                        "missing",
                        0,
                        None,
                    ));
                    problems.push(OverlayProblem {
                        path: format!("/label_sources/{source_id}"),
                        message: format!(
                            "label source '{source_id}' could not be resolved: {}",
                            reason.safe_reason()
                        ),
                    });
                }
            }
        }

        if !problems.is_empty() {
            return Err(OverlayError { problems });
        }
        Ok(ResolvedPlan {
            sources,
            enum_values,
            reports: StoredOpenApiSourceReports {
                schema_version: OPENAPI_SOURCE_REPORTS_SCHEMA_VERSION.to_owned(),
                sources: reports,
            },
            warnings,
        })
    }

    /// Atomically replace this Connection's in-process registration after the
    /// catalog transaction commits. `rows` should be the post-commit durable
    /// rows; volatile rows in this call are known to have been resolved by this
    /// process and may be served until their TTL (never stale).
    pub fn install_resolved_plan(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
        rows: &[StoredEnumSourceValue],
    ) {
        let plan_ids = plan.enum_sources.keys().cloned().collect::<BTreeSet<_>>();
        {
            let mut registrations = write_lock(&self.inner.registrations);
            registrations.retain(|key, _| key.connection_id != *connection_id);
            for (source_id, source) in &plan.enum_sources {
                registrations.insert(
                    SourceKey {
                        connection_id: connection_id.clone(),
                        source_id: source_id.clone(),
                    },
                    RegisteredSource {
                        overlay_revision,
                        plan: source.clone(),
                    },
                );
            }
        }

        let supplied = rows
            .iter()
            .filter(|row| row.connection_id == *connection_id)
            .map(|row| (row.source_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        mutex_lock(&self.inner.flights).retain(|key, _| {
            key.connection_id != *connection_id || plan_ids.contains(&key.source_id)
        });
        mutex_lock(&self.inner.retry_not_before)
            .retain(|key, _| key.connection_id != *connection_id);
        {
            let mut authority_revisions = write_lock(&self.inner.authority_revisions);
            // Values revisions restart at one when an overlay publication
            // prunes/recreates its rows. Never carry a same-ID watermark
            // across a newly installed source generation.
            authority_revisions.retain(|key, _| key.connection_id != *connection_id);
            for (source_id, source) in &plan.enum_sources {
                let key = SourceKey {
                    connection_id: connection_id.clone(),
                    source_id: source_id.clone(),
                };
                let supplied_row = supplied.get(source_id.as_str()).copied();
                let boot_row = read_lock(&self.inner.boot_rows).get(&key).cloned();
                if let Some(row) = supplied_row
                    .cloned()
                    .or(boot_row)
                    .filter(|row| row_matches_source_generation(row, overlay_revision, source))
                {
                    authority_revisions
                        .entry(key)
                        .and_modify(|revision| *revision = (*revision).max(row.values_revision))
                        .or_insert(row.values_revision);
                }
            }
        }
        let mut cache = write_lock(&self.inner.cache);
        cache.retain(|key, _| {
            key.connection_id != *connection_id || plan_ids.contains(&key.source_id)
        });
        for (source_id, source) in &plan.enum_sources {
            let key = SourceKey {
                connection_id: connection_id.clone(),
                source_id: source_id.clone(),
            };
            let supplied_row = supplied.get(source_id.as_str()).copied();
            let boot_row = read_lock(&self.inner.boot_rows).get(&key).cloned();
            let candidate = supplied_row.cloned().or(boot_row);
            match candidate {
                Some(row)
                    if self.row_matches_registration(
                        &row,
                        overlay_revision,
                        source,
                        supplied_row.is_some(),
                    ) =>
                {
                    cache.insert(
                        key,
                        CachedSource {
                            locally_resolved_volatile: supplied_row.is_some()
                                && row.credential_generation_digest.is_none(),
                            row,
                        },
                    );
                }
                _ => {
                    cache.remove(&key);
                }
            }
        }
        drop(cache);
        // Boot rows are a one-shot seed. Keeping rejected or superseded rows
        // around would retain values for deleted source declarations and
        // could let a later local reinstall reconsider an old generation.
        write_lock(&self.inner.boot_rows).retain(|key, _| key.connection_id != *connection_id);
    }

    /// Install using the boot bulk-read rows only.
    pub fn install_plan(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
    ) {
        self.install_resolved_plan(connection_id, overlay_revision, plan, &[]);
    }

    /// Re-read the authority for boot/reconciliation and install only rows
    /// backed by a stable credential generation. A durable row with a `NULL`
    /// generation may have been written by another replica (or another boot),
    /// so this path must never turn it into process-local cache state.
    pub async fn install_plan_from_store(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
    ) -> Result<(), ConnectionStoreError> {
        let rows = self
            .inner
            .control_plane
            .managed_store()
            .map_err(|_| ConnectionStoreError::Unavailable {
                operation: "enum source values read",
            })?
            .enum_source_values_for_connection(connection_id)
            .await?;
        let stable_rows = rows
            .iter()
            .filter(|row| row.credential_generation_digest.is_some())
            .cloned()
            .collect::<Vec<_>>();
        self.install_resolved_plan(connection_id, overlay_revision, plan, &stable_rows);
        self.record_authority_rows(&rows);
        Ok(())
    }

    /// Re-read an atomic publication and install stable rows plus the exact
    /// volatile values fetched by this process. The latter are compared in
    /// full (apart from the authority-assigned values revision), preventing a
    /// cross-replica `NULL` generation row from being mistaken for local work.
    pub async fn install_published_plan_from_store(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
        locally_resolved: &[StoredEnumSourceValueWrite],
    ) -> Result<(), ConnectionStoreError> {
        let rows = self
            .inner
            .control_plane
            .managed_store()
            .map_err(|_| ConnectionStoreError::Unavailable {
                operation: "enum source values read",
            })?
            .enum_source_values_for_connection(connection_id)
            .await?;
        let installable = rows
            .iter()
            .filter(|&row| {
                row.credential_generation_digest.is_some()
                    || locally_resolved
                        .iter()
                        .any(|write| enum_row_matches_write(row, write))
            })
            .cloned()
            .collect::<Vec<_>>();
        self.install_resolved_plan(connection_id, overlay_revision, plan, &installable);
        self.record_authority_rows(&rows);
        Ok(())
    }

    pub fn remove_plan(&self, connection_id: &ConnectionId) {
        write_lock(&self.inner.registrations).retain(|key, _| key.connection_id != *connection_id);
        write_lock(&self.inner.cache).retain(|key, _| key.connection_id != *connection_id);
        write_lock(&self.inner.boot_rows).retain(|key, _| key.connection_id != *connection_id);
        write_lock(&self.inner.authority_revisions)
            .retain(|key, _| key.connection_id != *connection_id);
        mutex_lock(&self.inner.retry_not_before)
            .retain(|key, _| key.connection_id != *connection_id);
        mutex_lock(&self.inner.flights).retain(|key, _| key.connection_id != *connection_id);
    }

    /// Boot rows are only eligible during the synchronous active-catalog
    /// install. Disabled, stale, or incompatible catalogs are reconciled from
    /// authority later and must not retain their full value documents.
    pub fn discard_unclaimed_boot_rows(&self) {
        write_lock(&self.inner.boot_rows).clear();
    }

    /// Pure memory read used by schema serving and validation.
    pub fn snapshot(
        &self,
        connection_id: &ConnectionId,
        source_id: &str,
        source_digest: &str,
    ) -> EnumSourceSnapshot {
        let key = SourceKey {
            connection_id: connection_id.clone(),
            source_id: source_id.to_owned(),
        };
        let registrations = read_lock(&self.inner.registrations);
        let Some(registration) = registrations.get(&key) else {
            return EnumSourceSnapshot::missing();
        };
        if registration.plan.source_digest != source_digest {
            return EnumSourceSnapshot::missing();
        }
        let cache = read_lock(&self.inner.cache);
        let Some(cached) = cache.get(&key) else {
            return EnumSourceSnapshot::missing();
        };
        let state = self.cached_state(cached, registration);
        EnumSourceSnapshot {
            state,
            values: if state != EnumSourceState::Missing {
                cached.row.values.clone()
            } else {
                Vec::new()
            },
            labels: (state != EnumSourceState::Missing)
                .then(|| cached.row.labels.clone())
                .flatten(),
            values_revision: cached.row.values_revision,
            resolved_at: Some(cached.row.resolved_at.clone()),
        }
    }

    /// One fixed scheduler pass: adopt newer authority rows, then refresh every
    /// expired/missing registration with at most four concurrent requests.
    #[cfg(test)]
    pub async fn refresh_tick(&self, authorizer: &dyn SourceAuthorizer) {
        self.adopt_from_authority().await;
        self.refresh_due(authorizer).await;
    }

    async fn adopt_from_authority(&self) {
        let Ok(store) = self.inner.control_plane.managed_store() else {
            record_adoption_failure("authority_unavailable");
            return;
        };
        let revisions = match store.enum_source_revisions().await {
            Ok(revisions) => revisions,
            Err(_) => {
                record_adoption_failure("revision_scan_failed");
                return;
            }
        };
        let changed = self.observe_authority_revisions(revisions);
        let mut rows = Vec::with_capacity(changed.len());
        for key in changed {
            match store
                .enum_source_value(&key.connection_id, &key.source_id)
                .await
            {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => {}
                Err(_) => record_adoption_failure("row_read_failed"),
            }
        }
        self.adopt_durable_rows(rows);
    }

    async fn refresh_due(&self, authorizer: &dyn SourceAuthorizer) {
        let now = Instant::now();
        let due = read_lock(&self.inner.registrations)
            .iter()
            .filter_map(|(key, registration)| {
                let cached = read_lock(&self.inner.cache).get(key).cloned();
                if cached.as_ref().is_some_and(|cached| {
                    self.cached_state(cached, registration) == EnumSourceState::Fresh
                }) || mutex_lock(&self.inner.retry_not_before)
                    .get(key)
                    .is_some_and(|retry_at| *retry_at > now)
                {
                    None
                } else {
                    Some((key.clone(), registration.clone()))
                }
            })
            .collect::<Vec<_>>();

        stream::iter(due)
            .for_each_concurrent(
                MAX_CONCURRENT_ENUM_REFRESHES,
                |(key, registration)| async move {
                    let permit = Arc::clone(&self.inner.refresh_permits)
                        .acquire_owned()
                        .await;
                    let Ok(permit) = permit else { return };
                    self.refresh_registered(key, registration, authorizer, permit)
                        .await;
                },
            )
            .await;
    }

    pub fn spawn_refresher(
        &self,
        lifecycle: &GatewayLifecycle,
        authorizer: Arc<dyn SourceAuthorizer>,
    ) {
        // Durable adoption has its own lightweight ticker. A batch of four
        // slow upstreams may keep the refresh pass busy for minutes; it must
        // not stretch the documented cross-replica convergence window.
        let adoption_cancellation = lifecycle.background_cancellation();
        let adoption_runtime = self.clone();
        let adoption_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ENUM_SOURCE_REFRESH_TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {},
                    () = adoption_cancellation.cancelled() => return,
                }
                tokio::select! {
                    () = adoption_runtime.adopt_from_authority() => {},
                    () = adoption_cancellation.cancelled() => return,
                }
            }
        });
        lifecycle.register_background_task(adoption_handle);

        let refresh_cancellation = lifecycle.background_cancellation();
        let runtime = self.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ENUM_SOURCE_REFRESH_TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {},
                    () = refresh_cancellation.cancelled() => return,
                }
                tokio::select! {
                    () = runtime.refresh_due(authorizer.as_ref()) => {},
                    () = refresh_cancellation.cancelled() => return,
                }
            }
        });
        lifecycle.register_background_task(handle);
    }

    async fn refresh_registered(
        &self,
        key: SourceKey,
        registration: RegisteredSource,
        authorizer: &dyn SourceAuthorizer,
        _permit: OwnedSemaphorePermit,
    ) {
        let flight = self.flight(&key.connection_id, &key.source_id);
        let _flight = flight.lock().await;
        let still_current = read_lock(&self.inner.registrations)
            .get(&key)
            .is_some_and(|current| {
                current.overlay_revision == registration.overlay_revision
                    && current.plan.source_digest == registration.plan.source_digest
            });
        if !still_current {
            return;
        }
        if read_lock(&self.inner.cache)
            .get(&key)
            .is_some_and(|cached| {
                self.cached_state(cached, &registration) == EnumSourceState::Fresh
            })
        {
            return;
        }
        let now = Instant::now();
        {
            let mut retry_not_before = mutex_lock(&self.inner.retry_not_before);
            if retry_not_before
                .get(&key)
                .is_some_and(|retry_at| *retry_at > now)
            {
                return;
            }
            retry_not_before.insert(
                key.clone(),
                now.checked_add(Duration::from_secs(registration.plan.cache.ttl_secs))
                    .unwrap_or(now),
            );
        }

        let started = Instant::now();
        let cached_revision = read_lock(&self.inner.cache)
            .get(&key)
            .filter(|cached| {
                cached.row.overlay_revision == registration.overlay_revision
                    && cached.row.source_digest == registration.plan.source_digest
            })
            .map_or(0, |cached| cached.row.values_revision);
        let expected_values_revision = read_lock(&self.inner.authority_revisions)
            .get(&key)
            .copied()
            .unwrap_or_default()
            .max(cached_revision);
        let outcome = self
            .fetch_enum(
                &key.connection_id,
                registration.overlay_revision,
                &registration.plan,
                expected_values_revision,
                authorizer,
            )
            .await;
        let fetched = match outcome {
            Ok(fetched) => fetched,
            Err(reason) => {
                self.emit_refresh(
                    &key.connection_id,
                    &key.source_id,
                    Err(&reason),
                    started.elapsed(),
                );
                return;
            }
        };
        match self.publish_refresh(&key, &registration, fetched).await {
            Ok(item_count) => self.emit_refresh(
                &key.connection_id,
                &key.source_id,
                Ok(item_count),
                started.elapsed(),
            ),
            Err(reason) => self.emit_refresh(
                &key.connection_id,
                &key.source_id,
                Err(&reason),
                started.elapsed(),
            ),
        }
    }

    async fn publish_refresh(
        &self,
        key: &SourceKey,
        registration: &RegisteredSource,
        fetched: FetchedEnum,
    ) -> Result<usize, EnumSourceFailureReason> {
        let store = self
            .inner
            .control_plane
            .managed_store()
            .map_err(|_| EnumSourceFailureReason::EgressDenied)?;
        let row = match store
            .replace_enum_source_value(&fetched.write, fetched.write.expected_values_revision)
            .await
        {
            Ok(row) => row,
            Err(ConnectionStoreError::EnumSourceConflict {
                current_values_revision,
                ..
            }) => {
                self.record_authority_revision(key, current_values_revision);
                if fetched.write.credential_generation_digest.is_none() {
                    let local = enum_row_from_write(&fetched.write, current_values_revision);
                    if self.row_matches_registration(
                        &local,
                        registration.overlay_revision,
                        &registration.plan,
                        true,
                    ) {
                        write_lock(&self.inner.cache).insert(
                            key.clone(),
                            CachedSource {
                                row: local,
                                locally_resolved_volatile: true,
                            },
                        );
                    }
                    // This process may serve its own fresh result, but a
                    // foreign volatile winner is never adopted and a
                    // refresh is not reported successful without a
                    // durable publication.
                    return Err(EnumSourceFailureReason::CredentialUnavailable);
                }
                let winner = store
                    .enum_source_value(&key.connection_id, &key.source_id)
                    .await
                    .map_err(|_| EnumSourceFailureReason::EgressDenied)?;
                if let Some(winner) = winner.filter(|row| {
                    self.row_matches_registration(
                        row,
                        registration.overlay_revision,
                        &registration.plan,
                        false,
                    ) && row.values_revision >= current_values_revision
                }) {
                    let count = winner.values.len();
                    write_lock(&self.inner.cache).insert(
                        key.clone(),
                        CachedSource {
                            row: winner,
                            locally_resolved_volatile: false,
                        },
                    );
                    return Ok(count);
                }
                return Err(EnumSourceFailureReason::CredentialUnavailable);
            }
            Err(_) => return Err(EnumSourceFailureReason::EgressDenied),
        };

        if !self.row_matches_registration(
            &row,
            registration.overlay_revision,
            &registration.plan,
            true,
        ) {
            return Err(EnumSourceFailureReason::CredentialUnavailable);
        }
        let count = row.values.len();
        let locally_resolved_volatile = row.credential_generation_digest.is_none();
        self.record_authority_revision(key, row.values_revision);
        write_lock(&self.inner.cache).insert(
            key.clone(),
            CachedSource {
                row,
                locally_resolved_volatile,
            },
        );
        Ok(count)
    }

    async fn fetch_enum(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &EnumSourcePlan,
        expected_values_revision: u64,
        authorizer: &dyn SourceAuthorizer,
    ) -> Result<FetchedEnum, EnumSourceFailureReason> {
        let fetched = self
            .fetch_json(
                connection_id,
                &plan.id,
                &plan.request,
                &plan.limits,
                authorizer,
            )
            .await?;
        let (values, labels) = select_enum_values(&fetched.body, plan)?;
        let resolved_at = now_rfc3339();
        let resolved = ResolvedEnumSource {
            values: values.clone(),
            labels: labels.clone(),
            resolved_at: resolved_at.clone(),
        };
        Ok(FetchedEnum {
            resolved,
            write: StoredEnumSourceValueWrite {
                connection_id: connection_id.clone(),
                source_id: plan.id.clone(),
                overlay_revision,
                source_digest: plan.source_digest.clone(),
                expected_values_revision,
                connection_revision: fetched.record.revisions.connection,
                credential_revision: fetched.record.revisions.credential,
                credential_generation_digest: fetched.credential_generation_digest,
                values,
                labels,
                resolved_at,
            },
        })
    }

    async fn fetch_label(
        &self,
        connection_id: &ConnectionId,
        plan: &LabelSourcePlan,
        authorizer: &dyn SourceAuthorizer,
    ) -> Result<ResolvedLabelSource, EnumSourceFailureReason> {
        let fetched = self
            .fetch_json(
                connection_id,
                &plan.id,
                &plan.request,
                &plan.limits,
                authorizer,
            )
            .await?;
        let selected = plan.select.items.select(&fetched.body);
        if selected.is_empty() && plan.limits.min_items > 0 {
            return Err(EnumSourceFailureReason::SelectorNoItems);
        }
        let mut labels = BTreeMap::new();
        for item in selected {
            let key = item
                .pointer(&plan.select.key)
                .and_then(Value::as_str)
                .ok_or(EnumSourceFailureReason::ValueRejected)?;
            validate_text(key, plan.limits.max_value_bytes)
                .map_err(|_| EnumSourceFailureReason::ValueRejected)?;
            let label = item
                .pointer(&plan.select.label)
                .and_then(Value::as_str)
                .ok_or(EnumSourceFailureReason::LabelRejected)?;
            validate_text(label, plan.limits.max_label_bytes)
                .map_err(|_| EnumSourceFailureReason::LabelRejected)?;
            if suspicious_source_text(key) || suspicious_source_text(label) {
                return Err(EnumSourceFailureReason::SuspiciousValue);
            }
            if !labels.contains_key(key) && labels.len() >= plan.limits.max_items {
                return Err(EnumSourceFailureReason::TooManyItems);
            }
            labels
                .entry(key.to_owned())
                .or_insert_with(|| label.to_owned());
        }
        if labels.len() < plan.limits.min_items {
            return Err(EnumSourceFailureReason::SelectorNoItems);
        }
        Ok(ResolvedLabelSource {
            labels,
            resolved_at: now_rfc3339(),
        })
    }

    async fn fetch_json(
        &self,
        connection_id: &ConnectionId,
        source_id: &str,
        request: &SourceRequestPlan,
        limits: &SourceLimits,
        authorizer: &dyn SourceAuthorizer,
    ) -> Result<FetchedJson, EnumSourceFailureReason> {
        // This call is intentionally first. It is pure and occurs before DNS,
        // TLS material, OAuth, or any other credential resolution.
        authorizer.authorize(
            connection_id,
            source_id,
            request.tool.as_deref(),
            &request.path_and_query,
            &request.path_template,
        )?;
        let operation = async {
            let record = self
                .inner
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(connection_id)
                .cloned()
                .ok_or(EnumSourceFailureReason::EgressDenied)?;
            let generation = self
                .inner
                .control_plane
                .credential_generation_digest(&record);
            let target = self
                .inner
                .http
                .target(connection_id.as_str(), &request.path_and_query)
                .map_err(connection_failure)?;
            if target.connection_etag() != record.etag().as_str() {
                return Err(EnumSourceFailureReason::CredentialUnavailable);
            }
            let destination = target
                .preflight_client()
                .checked_destination(target.url())
                .await
                .map_err(egress_failure)?;
            let prepared = self
                .inner
                .http
                .prepare_transport(&target, &destination)
                .await
                .map_err(connection_failure)?;
            let credential = self
                .inner
                .http
                .resolve_credential(&target)
                .await
                .map_err(connection_failure)?;
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
            if let Some(credential) = credential.as_ref() {
                credential
                    .inject(&mut headers)
                    .map_err(connection_failure)?;
            }
            let response = prepared
                .client()
                .stream_request_with_body_at_checked_destination(
                    prepared.destination(),
                    Method::GET,
                    target.url(),
                    headers,
                    EgressRequestBody::Empty,
                )
                .await
                .map_err(egress_failure)?;
            if !response.status.is_success() {
                if response.status == StatusCode::UNAUTHORIZED {
                    if let Some(credential) = credential
                        .as_ref()
                        .filter(|credential| credential.is_oauth())
                    {
                        credential.invalidate_after_unauthorized().await;
                    }
                }
                return Err(EnumSourceFailureReason::UpstreamStatus(
                    response.status.as_u16(),
                ));
            }
            let mut bytes = Vec::new();
            let mut body = response.body;
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(egress_failure)?;
                if bytes.len().saturating_add(chunk.len()) > limits.max_response_bytes {
                    return Err(EnumSourceFailureReason::ResponseTooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            let body =
                serde_json::from_slice(&bytes).map_err(|_| EnumSourceFailureReason::NotJson)?;
            let current = self
                .inner
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(connection_id)
                .cloned()
                .ok_or(EnumSourceFailureReason::CredentialUnavailable)?;
            if current.revisions.connection != record.revisions.connection
                || current.revisions.credential != record.revisions.credential
                || self
                    .inner
                    .control_plane
                    .credential_generation_digest(&current)
                    != generation
                || !self.inner.http.target_is_current(&target)
            {
                return Err(EnumSourceFailureReason::CredentialUnavailable);
            }
            Ok(FetchedJson {
                body,
                record,
                credential_generation_digest: generation,
            })
        };
        tokio::time::timeout(ENUM_SOURCE_FETCH_TIMEOUT, operation)
            .await
            .map_err(|_| EnumSourceFailureReason::Timeout)?
    }

    fn cached_state(
        &self,
        cached: &CachedSource,
        registration: &RegisteredSource,
    ) -> EnumSourceState {
        if !self.row_matches_registration(
            &cached.row,
            registration.overlay_revision,
            &registration.plan,
            cached.locally_resolved_volatile,
        ) {
            return EnumSourceState::Missing;
        }
        let age = timestamp_age(&cached.row.resolved_at);
        if age <= Duration::from_secs(registration.plan.cache.ttl_secs) {
            return EnumSourceState::Fresh;
        }
        if cached.row.credential_generation_digest.is_none() {
            return EnumSourceState::Missing;
        }
        let stale_deadline = registration
            .plan
            .cache
            .ttl_secs
            .saturating_add(registration.plan.cache.max_stale_secs);
        if registration.plan.cache.max_stale_secs > 0 && age <= Duration::from_secs(stale_deadline)
        {
            EnumSourceState::Stale
        } else {
            EnumSourceState::Missing
        }
    }

    fn row_matches_registration(
        &self,
        row: &StoredEnumSourceValue,
        overlay_revision: u64,
        plan: &EnumSourcePlan,
        allow_local_volatile: bool,
    ) -> bool {
        if !self.row_matches_registration_fences(row, overlay_revision, plan) {
            return false;
        }
        let snapshot = self.inner.control_plane.runtime_snapshot();
        let Some(record) = snapshot.managed().get(&row.connection_id) else {
            return false;
        };
        let current_generation = self
            .inner
            .control_plane
            .credential_generation_digest(record);
        enum_row_matches_provenance(
            row,
            overlay_revision,
            &plan.source_digest,
            record.revisions.connection,
            record.revisions.credential,
            current_generation.as_deref(),
            allow_local_volatile,
        )
    }

    fn row_matches_registration_fences(
        &self,
        row: &StoredEnumSourceValue,
        overlay_revision: u64,
        plan: &EnumSourcePlan,
    ) -> bool {
        if row.overlay_revision != overlay_revision || row.source_digest != plan.source_digest {
            return false;
        }
        let snapshot = self.inner.control_plane.runtime_snapshot();
        snapshot
            .managed()
            .get(&row.connection_id)
            .is_some_and(|record| {
                row.connection_revision == record.revisions.connection
                    && row.credential_revision == record.revisions.credential
            })
    }

    fn adopt_durable_rows(&self, rows: Vec<StoredEnumSourceValue>) {
        let registrations = read_lock(&self.inner.registrations).clone();
        let mut observed = Vec::new();
        let mut adoptable = Vec::new();
        for row in rows {
            let key = SourceKey {
                connection_id: row.connection_id.clone(),
                source_id: row.source_id.clone(),
            };
            let Some(registration) = registrations.get(&key) else {
                continue;
            };
            if row_matches_source_generation(
                &row,
                registration.overlay_revision,
                &registration.plan,
            ) {
                observed.push((key.clone(), row.values_revision));
            } else {
                continue;
            }
            if !self.row_matches_registration(
                &row,
                registration.overlay_revision,
                &registration.plan,
                false,
            ) {
                continue;
            }
            adoptable.push((key, row));
        }
        {
            let mut authority_revisions = write_lock(&self.inner.authority_revisions);
            for (key, values_revision) in observed {
                authority_revisions
                    .entry(key)
                    .and_modify(|revision| *revision = (*revision).max(values_revision))
                    .or_insert(values_revision);
            }
        }
        let mut cache = write_lock(&self.inner.cache);
        for (key, row) in adoptable {
            if cache
                .get(&key)
                .is_none_or(|current| current.row.values_revision < row.values_revision)
            {
                cache.insert(
                    key,
                    CachedSource {
                        row,
                        locally_resolved_volatile: false,
                    },
                );
            }
        }
    }

    fn observe_authority_revisions(
        &self,
        revisions: Vec<StoredEnumSourceRevision>,
    ) -> Vec<SourceKey> {
        let registrations = read_lock(&self.inner.registrations).clone();
        let cached_revisions = read_lock(&self.inner.cache)
            .iter()
            .map(|(key, cached)| (key.clone(), cached.row.values_revision))
            .collect::<BTreeMap<_, _>>();
        let mut observed = Vec::new();
        let mut changed = Vec::new();
        let mut invalidated = Vec::new();
        for revision in revisions {
            let key = SourceKey {
                connection_id: revision.connection_id.clone(),
                source_id: revision.source_id.clone(),
            };
            let Some(registration) = registrations.get(&key) else {
                continue;
            };
            if !revision_matches_source_generation(
                &revision,
                registration.overlay_revision,
                &registration.plan,
            ) {
                continue;
            }
            observed.push((key.clone(), revision.values_revision));
            let snapshot = self.inner.control_plane.runtime_snapshot();
            let current_record = snapshot.managed().get(&revision.connection_id);
            let current_generation = current_record.and_then(|record| {
                self.inner
                    .control_plane
                    .credential_generation_digest(record)
            });
            let adoptable_generation = revision
                .credential_generation_digest
                .as_deref()
                .zip(current_generation.as_deref())
                .is_some_and(|(stored, current)| stored == current);
            let adoptable_revisions = current_record.is_some_and(|record| {
                revision.connection_revision == record.revisions.connection
                    && revision.credential_revision == record.revisions.credential
            });
            if cached_revisions
                .get(&key)
                .is_none_or(|cached_revision| *cached_revision < revision.values_revision)
            {
                if adoptable_revisions && adoptable_generation {
                    changed.push(key);
                } else {
                    // A newer authority revision supersedes the prior LKG even
                    // when this replica cannot adopt its provenance. In
                    // particular, a foreign volatile (`NULL` generation) row
                    // must not leave an older stable value serving as Fresh.
                    invalidated.push((key, revision.values_revision));
                }
            }
        }
        let mut authority_revisions = write_lock(&self.inner.authority_revisions);
        for (key, values_revision) in observed {
            authority_revisions
                .entry(key)
                .and_modify(|current| *current = (*current).max(values_revision))
                .or_insert(values_revision);
        }
        drop(authority_revisions);
        if !invalidated.is_empty() {
            let mut cache = write_lock(&self.inner.cache);
            for (key, values_revision) in invalidated {
                if cache
                    .get(&key)
                    .is_some_and(|cached| cached.row.values_revision < values_revision)
                {
                    cache.remove(&key);
                }
            }
        }
        changed
    }

    fn record_authority_rows(&self, rows: &[StoredEnumSourceValue]) {
        let registrations = read_lock(&self.inner.registrations).clone();
        let mut authority_revisions = write_lock(&self.inner.authority_revisions);
        for row in rows {
            let key = SourceKey {
                connection_id: row.connection_id.clone(),
                source_id: row.source_id.clone(),
            };
            let Some(registration) = registrations.get(&key) else {
                continue;
            };
            if row_matches_source_generation(row, registration.overlay_revision, &registration.plan)
            {
                authority_revisions
                    .entry(key)
                    .and_modify(|revision| *revision = (*revision).max(row.values_revision))
                    .or_insert(row.values_revision);
            }
        }
    }

    fn record_authority_revision(&self, key: &SourceKey, values_revision: u64) {
        write_lock(&self.inner.authority_revisions)
            .entry(key.clone())
            .and_modify(|revision| *revision = (*revision).max(values_revision))
            .or_insert(values_revision);
    }

    fn flight(&self, connection_id: &ConnectionId, source_id: &str) -> Arc<AsyncMutex<()>> {
        let key = SourceKey {
            connection_id: connection_id.clone(),
            source_id: source_id.to_owned(),
        };
        let mut flights = mutex_lock(&self.inner.flights);
        flights.retain(|_, flight| flight.strong_count() > 0);
        if let Some(flight) = flights.get(&key).and_then(Weak::upgrade) {
            return flight;
        }
        let flight = Arc::new(AsyncMutex::new(()));
        flights.insert(key, Arc::downgrade(&flight));
        flight
    }

    fn emit_refresh(
        &self,
        connection_id: &ConnectionId,
        source_id: &str,
        outcome: Result<usize, &EnumSourceFailureReason>,
        elapsed: Duration,
    ) {
        let (event_type, result, item_count, reason) = match outcome {
            Ok(count) => (REFRESHED_EVENT, "success", count, None),
            Err(reason) => (
                REFRESH_FAILED_EVENT,
                "failure",
                0,
                Some(reason.safe_reason()),
            ),
        };
        let mut payload = json!({
            "connection_id": connection_id,
            "source_id": source_id,
            "outcome": result,
            "item_count": item_count,
            "latency_ms": elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        });
        if let (Some(reason), Some(payload)) = (reason, payload.as_object_mut()) {
            payload.insert("reason".to_owned(), Value::String(reason));
        }
        self.inner.audit.emit(AuditEvent::new(
            event_type,
            "enum-source-refresh",
            "internal",
            Some(Actor {
                user_id: "system".to_owned(),
                issuer: None,
                email: None,
                roles: None,
                auth_mode: "system".to_owned(),
            }),
            payload,
        ));
    }
}

fn select_enum_values(
    body: &Value,
    plan: &EnumSourcePlan,
) -> Result<(Vec<Value>, Option<Vec<String>>), EnumSourceFailureReason> {
    let selected = plan.select.items.select(body);
    if selected.is_empty() && plan.limits.min_items > 0 {
        return Err(EnumSourceFailureReason::SelectorNoItems);
    }
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    let mut labels = plan.select.label.as_ref().map(|_| Vec::new());
    for item in selected {
        let value = item
            .pointer(&plan.select.value)
            .cloned()
            .ok_or(EnumSourceFailureReason::ValueRejected)?;
        validate_value(&value, plan.limits.max_value_bytes)?;
        if value.as_str().is_some_and(suspicious_source_text) {
            return Err(EnumSourceFailureReason::SuspiciousValue);
        }
        let canonical =
            serde_json::to_string(&value).map_err(|_| EnumSourceFailureReason::ValueRejected)?;
        if !seen.insert(canonical) {
            continue;
        }
        if values.len() >= plan.limits.max_items {
            return Err(EnumSourceFailureReason::TooManyItems);
        }
        if let (Some(pointer), Some(labels)) = (&plan.select.label, labels.as_mut()) {
            let label = item
                .pointer(pointer)
                .and_then(Value::as_str)
                .ok_or(EnumSourceFailureReason::LabelRejected)?;
            validate_text(label, plan.limits.max_label_bytes)
                .map_err(|_| EnumSourceFailureReason::LabelRejected)?;
            if suspicious_source_text(label) {
                return Err(EnumSourceFailureReason::SuspiciousValue);
            }
            labels.push(label.to_owned());
        }
        values.push(value);
    }
    if values.len() < plan.limits.min_items {
        return Err(EnumSourceFailureReason::SelectorNoItems);
    }
    if validate_enum_source_values_payload(&values, labels.as_deref()).is_err() {
        return Err(EnumSourceFailureReason::ResponseTooLarge);
    }
    Ok((values, labels))
}

fn source_report(
    id: &str,
    kind: StoredOpenApiSourceKind,
    state: &str,
    item_count: usize,
    resolved_at: Option<&str>,
) -> StoredOpenApiSourceReport {
    StoredOpenApiSourceReport {
        id: id.to_owned(),
        kind,
        state: state.to_owned(),
        item_count: u64::try_from(item_count).unwrap_or(u64::MAX),
        resolved_at: resolved_at.map(str::to_owned),
    }
}

fn enum_authority_unavailable() -> OverlayError {
    OverlayError {
        problems: vec![OverlayProblem {
            path: "/enum_sources".to_owned(),
            message: "enum source authority is unavailable".to_owned(),
        }],
    }
}

fn enum_row_matches_write(row: &StoredEnumSourceValue, write: &StoredEnumSourceValueWrite) -> bool {
    row.connection_id == write.connection_id
        && row.source_id == write.source_id
        && row.overlay_revision == write.overlay_revision
        && row.source_digest == write.source_digest
        && row.connection_revision == write.connection_revision
        && row.credential_revision == write.credential_revision
        && row.credential_generation_digest == write.credential_generation_digest
        && row.values == write.values
        && row.labels == write.labels
        && row.resolved_at == write.resolved_at
}

fn enum_row_from_write(
    write: &StoredEnumSourceValueWrite,
    values_revision: u64,
) -> StoredEnumSourceValue {
    StoredEnumSourceValue {
        connection_id: write.connection_id.clone(),
        source_id: write.source_id.clone(),
        overlay_revision: write.overlay_revision,
        source_digest: write.source_digest.clone(),
        values_revision,
        connection_revision: write.connection_revision,
        credential_revision: write.credential_revision,
        credential_generation_digest: write.credential_generation_digest.clone(),
        values: write.values.clone(),
        labels: write.labels.clone(),
        resolved_at: write.resolved_at.clone(),
    }
}

fn row_matches_source_generation(
    row: &StoredEnumSourceValue,
    overlay_revision: u64,
    plan: &EnumSourcePlan,
) -> bool {
    row.overlay_revision == overlay_revision && row.source_digest == plan.source_digest
}

fn revision_matches_source_generation(
    revision: &StoredEnumSourceRevision,
    overlay_revision: u64,
    plan: &EnumSourcePlan,
) -> bool {
    revision.overlay_revision == overlay_revision && revision.source_digest == plan.source_digest
}

fn enum_row_matches_provenance(
    row: &StoredEnumSourceValue,
    overlay_revision: u64,
    source_digest: &str,
    connection_revision: u64,
    credential_revision: u64,
    credential_generation_digest: Option<&str>,
    allow_local_volatile: bool,
) -> bool {
    if row.overlay_revision != overlay_revision
        || row.source_digest != source_digest
        || row.connection_revision != connection_revision
        || row.credential_revision != credential_revision
    {
        return false;
    }
    match (
        row.credential_generation_digest.as_deref(),
        credential_generation_digest,
    ) {
        (Some(stored), Some(current)) => stored == current,
        (None, None) => allow_local_volatile,
        _ => false,
    }
}

fn validate_value(value: &Value, maximum_bytes: usize) -> Result<(), EnumSourceFailureReason> {
    match value {
        Value::String(value) => {
            validate_text(value, maximum_bytes).map_err(|_| EnumSourceFailureReason::ValueRejected)
        }
        Value::Bool(_) => Ok(()),
        _ => Err(EnumSourceFailureReason::ValueRejected),
    }
}

fn validate_text(value: &str, maximum_bytes: usize) -> Result<(), ()> {
    if value.is_empty() || value.len() > maximum_bytes || !enum_source_text_is_printable(value) {
        Err(())
    } else {
        Ok(())
    }
}

/// Same token shapes used by the MCP error redactor. Source values matching
/// them are rejected rather than copied into schemas or audit-adjacent state.
fn suspicious_source_text(value: &str) -> bool {
    let mut token = String::new();
    for character in value.chars() {
        if source_token_character(character) {
            token.push(character);
        } else {
            if suspicious_source_token(&token) {
                return true;
            }
            token.clear();
        }
    }
    suspicious_source_token(&token)
}

fn source_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '.' | '-' | '_' | ':' | '/' | '?' | '&' | '=' | '%' | '+' | '@'
        )
}

fn suspicious_source_token(token: &str) -> bool {
    let token = token
        .trim_matches(|character: char| {
            matches!(character, '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']')
        })
        .to_ascii_lowercase();
    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("sk_")
        || token.starts_with("pk_")
        || token.starts_with("ghp_")
        || token.starts_with("github_pat_")
        || token.starts_with("xoxb-")
        || token.starts_with("xoxp-")
        || token.contains("secret=")
        || token.contains("token=")
        || token.contains("password=")
        || token.contains("api_key=")
        || token.contains("apikey=")
        || token.contains(".internal")
        || token.contains("internal.")
        || token.ends_with(".local")
}

fn connection_failure(error: ConnectionHttpError) -> EnumSourceFailureReason {
    if error.is_secret_resolution_failure()
        || matches!(
            error,
            ConnectionHttpError::OAuthTokenUnavailable
                | ConnectionHttpError::OAuthTokenRejected
                | ConnectionHttpError::OAuthTokenInvalidResponse
        )
    {
        EnumSourceFailureReason::CredentialUnavailable
    } else {
        EnumSourceFailureReason::EgressDenied
    }
}

fn egress_failure(error: EgressError) -> EnumSourceFailureReason {
    if error.is_timeout() {
        EnumSourceFailureReason::Timeout
    } else if matches!(error, EgressError::ResponseTooLarge { .. }) {
        EnumSourceFailureReason::ResponseTooLarge
    } else {
        EnumSourceFailureReason::EgressDenied
    }
}

fn record_adoption_failure(reason: &'static str) {
    ::metrics::counter!(
        "connection_enum_source_adoption_failure_total",
        "reason" => reason
    )
    .increment(1);
    tracing::warn!(
        reason,
        "enum source authority adoption failed and will retry on the next fixed tick"
    );
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("the current UTC timestamp formats as RFC 3339")
}

fn timestamp_age(value: &str) -> Duration {
    let Ok(resolved_at) = OffsetDateTime::parse(value, &Rfc3339) else {
        return Duration::MAX;
    };
    let seconds = (OffsetDateTime::now_utc() - resolved_at).whole_seconds();
    Duration::from_secs(u64::try_from(seconds).unwrap_or_default())
}

fn mutex_lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        config::Config,
        connections::store::{StoredOverlayWrite, OPENAPI_OVERLAY_SCHEMA_VERSION},
        egress::{EgressClient, EgressConfig},
        tools::{
            overlay::{EnumSourceSelectionPlan, SourceCache},
            selector::Selector,
        },
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct CountingAuthorizer {
        calls: AtomicUsize,
    }

    impl SourceAuthorizer for CountingAuthorizer {
        fn authorize(
            &self,
            _connection_id: &ConnectionId,
            _source_id: &str,
            _tool: Option<&str>,
            _rendered_path_and_query: &str,
            _audit_path_template: &str,
        ) -> Result<(), EnumSourceFailureReason> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct DenyingAuthorizer {
        calls: AtomicUsize,
    }

    impl SourceAuthorizer for DenyingAuthorizer {
        fn authorize(
            &self,
            _connection_id: &ConnectionId,
            _source_id: &str,
            _tool: Option<&str>,
            _rendered_path_and_query: &str,
            _audit_path_template: &str,
        ) -> Result<(), EnumSourceFailureReason> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(EnumSourceFailureReason::HttpRuleDenied)
        }
    }

    struct TemporaryEnumStore {
        root: PathBuf,
        database: PathBuf,
    }

    impl TemporaryEnumStore {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("greengateway-enum-source-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).expect("temporary enum-source root should create");
            let database = root.join("connections.sqlite");
            Self { root, database }
        }
    }

    impl Drop for TemporaryEnumStore {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-enum-source-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn enum_plan(min_items: usize) -> EnumSourcePlan {
        EnumSourcePlan {
            id: "statuses".to_owned(),
            source_digest: "a".repeat(64),
            request: SourceRequestPlan {
                tool: None,
                path_and_query: "/metadata/statuses".to_owned(),
                path_template: "/metadata/statuses".to_owned(),
                query: BTreeMap::new(),
                query_params: Vec::new(),
            },
            select: EnumSourceSelectionPlan {
                items: Selector::parse("/items/*").expect("fixture selector should parse"),
                value: "/value".to_owned(),
                label: Some("/label".to_owned()),
            },
            cache: SourceCache::default(),
            limits: SourceLimits {
                min_items,
                ..SourceLimits::default()
            },
        }
    }

    #[test]
    fn source_values_accept_only_exact_bounded_strings_and_booleans() {
        assert_eq!(validate_value(&json!("north"), 5), Ok(()));
        assert_eq!(validate_value(&json!(true), 1), Ok(()));
        assert_eq!(
            validate_value(&json!(1), 32),
            Err(EnumSourceFailureReason::ValueRejected)
        );
        assert_eq!(
            validate_value(&Value::Null, 32),
            Err(EnumSourceFailureReason::ValueRejected)
        );
        assert_eq!(
            validate_value(&json!("north"), 4),
            Err(EnumSourceFailureReason::ValueRejected)
        );
        assert_eq!(
            validate_value(&json!("north\namerica"), 32),
            Err(EnumSourceFailureReason::ValueRejected)
        );
        for spoofed in [
            "north\u{2028}america",
            "north\u{2029}america",
            "north\u{202e}america",
        ] {
            assert_eq!(
                validate_value(&json!(spoofed), 64),
                Err(EnumSourceFailureReason::ValueRejected)
            );
        }
    }

    #[test]
    fn suspicious_source_values_use_fixed_redaction_shapes() {
        for value in [
            "https://private.example.test",
            "ghp_canary",
            "region ghp_canary",
            "choose https://private.example.test now",
            "region?token=canary",
            "database.internal",
            "service.local",
        ] {
            assert!(suspicious_source_text(value), "{value} must be rejected");
        }
        assert!(!suspicious_source_text("north-america"));
    }

    #[test]
    fn selector_matching_nothing_fails_refresh_with_min_items() {
        let required = enum_plan(1);
        assert_eq!(
            select_enum_values(&json!({"items": []}), &required),
            Err(EnumSourceFailureReason::SelectorNoItems)
        );

        let optional = enum_plan(0);
        assert_eq!(
            select_enum_values(&json!({"items": []}), &optional),
            Ok((Vec::new(), Some(Vec::new())))
        );
    }

    #[test]
    fn suspicious_values_fail_the_refresh_selection() {
        let plan = enum_plan(1);
        assert_eq!(
            select_enum_values(
                &json!({
                    "items": [{
                        "value": "region ghp_canary",
                        "label": "North America"
                    }]
                }),
                &plan,
            ),
            Err(EnumSourceFailureReason::SuspiciousValue)
        );
        assert_eq!(
            select_enum_values(
                &json!({
                    "items": [{
                        "value": "north-america",
                        "label": "choose https://private.example.test now"
                    }]
                }),
                &plan,
            ),
            Err(EnumSourceFailureReason::SuspiciousValue)
        );
    }

    #[test]
    fn selected_values_must_fit_the_canonical_durable_lkg_document() {
        let mut plan = enum_plan(1);
        plan.limits.max_items = 1_024;
        plan.limits.max_value_bytes = 1_024;
        let items = (0..300)
            .map(|index| {
                json!({
                    "value": format!("{index:04}-{}", "x".repeat(1_010)),
                    "label": "ok"
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            select_enum_values(&json!({"items": items}), &plan),
            Err(EnumSourceFailureReason::ResponseTooLarge)
        );
    }

    #[test]
    fn selectors_reject_line_separators_and_direction_controls() {
        let plan = enum_plan(1);
        for spoofed in [
            "north\u{2028}america",
            "north\u{2029}america",
            "north\u{202e}america",
        ] {
            assert_eq!(
                select_enum_values(
                    &json!({"items": [{"value": spoofed, "label": "safe"}]}),
                    &plan,
                ),
                Err(EnumSourceFailureReason::ValueRejected)
            );
            assert_eq!(
                select_enum_values(
                    &json!({"items": [{"value": "safe", "label": spoofed}]}),
                    &plan,
                ),
                Err(EnumSourceFailureReason::LabelRejected)
            );
        }
    }

    #[test]
    fn volatile_post_commit_install_requires_the_exact_local_write() {
        let connection_id = ConnectionId::parse("00000000-0000-4000-8000-000000000001")
            .expect("fixture connection ID");
        let write = StoredEnumSourceValueWrite {
            connection_id: connection_id.clone(),
            source_id: "regions".to_owned(),
            overlay_revision: 2,
            source_digest: "a".repeat(64),
            expected_values_revision: 0,
            connection_revision: 3,
            credential_revision: 4,
            credential_generation_digest: None,
            values: vec![json!("na")],
            labels: Some(vec!["North America".to_owned()]),
            resolved_at: "2026-09-03T00:00:00Z".to_owned(),
        };
        let mut row = StoredEnumSourceValue {
            connection_id,
            source_id: write.source_id.clone(),
            overlay_revision: write.overlay_revision,
            source_digest: write.source_digest.clone(),
            values_revision: 9,
            connection_revision: write.connection_revision,
            credential_revision: write.credential_revision,
            credential_generation_digest: None,
            values: write.values.clone(),
            labels: write.labels.clone(),
            resolved_at: write.resolved_at.clone(),
        };
        assert!(enum_row_matches_write(&row, &write));
        row.values = vec![json!("eu")];
        assert!(!enum_row_matches_write(&row, &write));
    }

    #[test]
    fn lkg_enum_values_are_bound_to_every_provenance_generation() {
        let connection_id = ConnectionId::parse("00000000-0000-4000-8000-000000000001")
            .expect("fixture connection ID");
        let digest = "a".repeat(64);
        let generation = "b".repeat(64);
        let row = StoredEnumSourceValue {
            connection_id,
            source_id: "regions".to_owned(),
            overlay_revision: 2,
            source_digest: digest.clone(),
            values_revision: 9,
            connection_revision: 3,
            credential_revision: 4,
            credential_generation_digest: Some(generation.clone()),
            values: vec![json!("na")],
            labels: None,
            resolved_at: "2026-09-03T00:00:00Z".to_owned(),
        };
        assert!(enum_row_matches_provenance(
            &row,
            2,
            &digest,
            3,
            4,
            Some(&generation),
            false,
        ));
        assert!(!enum_row_matches_provenance(
            &row,
            1,
            &digest,
            3,
            4,
            Some(&generation),
            false,
        ));
        assert!(!enum_row_matches_provenance(
            &row,
            2,
            &"c".repeat(64),
            3,
            4,
            Some(&generation),
            false,
        ));
        assert!(!enum_row_matches_provenance(
            &row,
            2,
            &digest,
            4,
            4,
            Some(&generation),
            false,
        ));
        assert!(!enum_row_matches_provenance(
            &row,
            2,
            &digest,
            3,
            5,
            Some(&generation),
            false,
        ));
        assert!(!enum_row_matches_provenance(
            &row,
            2,
            &digest,
            3,
            4,
            Some(&"d".repeat(64)),
            false,
        ));

        let mut volatile = row;
        volatile.credential_generation_digest = None;
        assert!(!enum_row_matches_provenance(
            &volatile, 2, &digest, 3, 4, None, false,
        ));
        assert!(enum_row_matches_provenance(
            &volatile, 2, &digest, 3, 4, None, true,
        ));
    }

    #[tokio::test]
    async fn two_replicas_converge_on_newer_durable_values_in_one_adoption_tick() {
        let temporary = TemporaryEnumStore::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(temporary.database.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let initial = control_plane.runtime_snapshot();
        let created = control_plane
            .create_managed(
                initial.collection_etag(),
                serde_json::from_value(json!({
                    "display_name": "Metadata API",
                    "enabled": true,
                    "kind": "http_api",
                    "endpoint": {
                        "base_url": "https://metadata.example.test",
                        "base_path": "/v1"
                    },
                    "authentication": {"type": "none"},
                    "discovery": {
                        "type": "managed_openapi",
                        "path": "/openapi.json",
                        "use_connection_authentication": true
                    }
                }))
                .expect("fixture Connection should deserialize"),
                "test-admin",
            )
            .await
            .expect("fixture Connection should create");
        let egress_config = EgressConfig::default();
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress client should build"));
        let http = ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client);
        let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
        let replica_a = EnumSourceRuntime::new(
            control_plane.clone(),
            http.clone(),
            audit.clone(),
            Vec::new(),
        );
        let replica_b = EnumSourceRuntime::new(control_plane.clone(), http, audit, Vec::new());
        let source = enum_plan(1);
        let plan = OverlaySourcePlan {
            enum_sources: [(source.id.clone(), source.clone())].into_iter().collect(),
            label_sources: BTreeMap::new(),
        };
        let spec = r#"{"openapi":"3.1.0","info":{"title":"Enums","version":"1"}}"#;
        let spec_digest = hex::encode(Sha256::digest(spec.as_bytes()));
        let overlay = StoredOverlayWrite::Put {
            schema_version: OPENAPI_OVERLAY_SCHEMA_VERSION.to_owned(),
            overlay_json: r#"{"schema_version":"0.1.0","tools":{}}"#.to_owned(),
            source_reports_json: r#"{"schema_version":"0.1.0","sources":[]}"#.to_owned(),
            expected_overlay_revision: 0,
        };
        let store = control_plane
            .managed_store()
            .expect("managed store should exist");
        store
            .replace_openapi_catalog_with_overlay_and_enum_values(
                &created.id,
                &created.etag(),
                0,
                0,
                spec,
                &spec_digest,
                &[],
                Some(&overlay),
                1,
                "test-admin",
                &[],
                &[],
            )
            .await
            .expect("fixture overlay should publish atomically");
        replica_a.install_plan(&created.id, 1, &plan);
        replica_b.install_plan(&created.id, 1, &plan);
        assert_eq!(
            replica_b
                .snapshot(&created.id, &source.id, &source.source_digest)
                .state,
            EnumSourceState::Missing
        );

        let generation = control_plane
            .credential_generation_digest(&created)
            .expect("credential-free Connections have a stable generation");
        let write = StoredEnumSourceValueWrite {
            connection_id: created.id.clone(),
            source_id: source.id.clone(),
            overlay_revision: 1,
            source_digest: source.source_digest.clone(),
            expected_values_revision: 0,
            connection_revision: created.revisions.connection,
            credential_revision: created.revisions.credential,
            credential_generation_digest: Some(generation),
            values: vec![json!("na")],
            labels: Some(vec!["North America".to_owned()]),
            resolved_at: now_rfc3339(),
        };
        let first = store
            .replace_enum_source_value(&write, 0)
            .await
            .expect("authority should publish revision one");
        assert_eq!(first.values_revision, 1);

        let authorizer = CountingAuthorizer::default();
        replica_b.refresh_tick(&authorizer).await;
        assert_eq!(
            authorizer.calls.load(Ordering::SeqCst),
            0,
            "authority adoption must precede refresh and avoid an upstream authorization/fetch"
        );
        let adopted = replica_b.snapshot(&created.id, &source.id, &source.source_digest);
        assert_eq!(adopted.state, EnumSourceState::Fresh);
        assert_eq!(adopted.values_revision, 1);
        assert_eq!(adopted.values, vec![json!("na")]);

        let mut newer = write;
        newer.expected_values_revision = 1;
        newer.values = vec![json!("eu")];
        newer.labels = Some(vec!["Europe".to_owned()]);
        let second = store
            .replace_enum_source_value(&newer, 1)
            .await
            .expect("authority should publish revision two");
        assert_eq!(second.values_revision, 2);
        replica_b.refresh_tick(&authorizer).await;
        assert_eq!(authorizer.calls.load(Ordering::SeqCst), 0);
        let adopted = replica_b.snapshot(&created.id, &source.id, &source.source_digest);
        assert_eq!(adopted.values_revision, 2);
        assert_eq!(adopted.values, vec![json!("eu")]);

        assert_eq!(
            replica_a
                .snapshot(&created.id, &source.id, &source.source_digest)
                .state,
            EnumSourceState::Missing,
            "each replica adopts independently on its own timer"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                replica_a.adopt_from_authority(),
                replica_a.adopt_from_authority()
            );
        })
        .await
        .expect("overlapping adoption passes must not deadlock");
        assert_eq!(
            replica_a
                .snapshot(&created.id, &source.id, &source.source_digest)
                .state,
            EnumSourceState::Fresh
        );

        let mut volatile = newer;
        volatile.expected_values_revision = 2;
        volatile.credential_generation_digest = None;
        volatile.values = vec![json!("private")];
        volatile.labels = Some(vec!["Private".to_owned()]);
        let volatile_row = store
            .replace_enum_source_value(&volatile, 2)
            .await
            .expect("volatile authority fixture should publish");
        replica_a.adopt_from_authority().await;
        let key = SourceKey {
            connection_id: created.id.clone(),
            source_id: source.id.clone(),
        };
        assert_eq!(
            read_lock(&replica_a.inner.authority_revisions)
                .get(&key)
                .copied(),
            Some(3),
            "a non-adoptable volatile row must still advance the CAS watermark"
        );
        assert_eq!(
            replica_a
                .snapshot(&created.id, &source.id, &source.source_digest)
                .state,
            EnumSourceState::Missing,
            "a NULL provider generation written by another replica must not be adopted"
        );

        let denied = DenyingAuthorizer::default();
        replica_a.refresh_tick(&denied).await;
        replica_a.refresh_tick(&denied).await;
        assert_eq!(
            denied.calls.load(Ordering::SeqCst),
            1,
            "a failed source is retried on its TTL, not on every 15-second scheduler pass"
        );

        for index in 0..512 {
            drop(replica_a.flight(&created.id, &format!("preview-{index}")));
        }
        assert!(
            mutex_lock(&replica_a.inner.flights).len() <= 1,
            "completed preview flights must not accumulate"
        );

        let mut replacement = created.write.clone();
        replacement.endpoint.base_path = "/v2".to_owned();
        let updated = control_plane
            .replace_managed(&created.id, &created.etag(), replacement, "test-admin")
            .await
            .expect("endpoint replacement should advance the connection fence");
        let cold = EnumSourceRuntime::new(
            control_plane.clone(),
            replica_a.inner.http.clone(),
            replica_a.inner.audit.clone(),
            vec![volatile_row],
        );
        cold.install_plan(&created.id, 1, &plan);
        assert_eq!(
            cold.snapshot(&created.id, &source.id, &source.source_digest)
                .state,
            EnumSourceState::Missing,
            "a cold runtime must not serve a row from the prior connection revision"
        );
        let key = SourceKey {
            connection_id: created.id.clone(),
            source_id: source.id.clone(),
        };
        assert_eq!(
            read_lock(&cold.inner.authority_revisions)
                .get(&key)
                .copied(),
            Some(3),
            "a stale-fence boot row must still seed the exact CAS watermark"
        );
        let registration = read_lock(&cold.inner.registrations)
            .get(&key)
            .cloned()
            .expect("cold source should register");
        let generation = control_plane
            .credential_generation_digest(&updated)
            .expect("credential-free Connection generation is stable");
        let fetched = FetchedEnum {
            resolved: ResolvedEnumSource {
                values: vec![json!("current")],
                labels: Some(vec!["Current".to_owned()]),
                resolved_at: now_rfc3339(),
            },
            write: StoredEnumSourceValueWrite {
                connection_id: updated.id.clone(),
                source_id: source.id.clone(),
                overlay_revision: 1,
                source_digest: source.source_digest.clone(),
                expected_values_revision: 3,
                connection_revision: updated.revisions.connection,
                credential_revision: updated.revisions.credential,
                credential_generation_digest: Some(generation),
                values: vec![json!("current")],
                labels: Some(vec!["Current".to_owned()]),
                resolved_at: now_rfc3339(),
            },
        };
        assert_eq!(
            cold.publish_refresh(&key, &registration, fetched).await,
            Ok(1),
            "the first successful post-boot refresh must replace revision three"
        );
        let current = cold.snapshot(&updated.id, &source.id, &source.source_digest);
        assert_eq!(current.state, EnumSourceState::Fresh);
        assert_eq!(current.values_revision, 4);
        assert_eq!(current.values, vec![json!("current")]);
    }
}
