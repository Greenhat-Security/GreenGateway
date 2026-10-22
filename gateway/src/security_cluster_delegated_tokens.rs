//! Cluster mode's half of the delegated-token purge (issue #441).
//!
//! Every replica caches the delegated issuer tokens it exchanged in its own
//! memory, so a purge one replica applies leaves the other replicas'
//! tokens in place. Cluster mode carries a purge to every replica through
//! the mechanism every other shared security change uses -- the shared
//! security revision -- rather than a channel of its own:
//!
//! - [`ClusterDelegatedTokenPurgeLedger`] records a purge. It asks the
//!   #426 operation gate first ([`DELEGATED_TOKEN_PURGES`]): a replica
//!   built before this record would not apply it, so while one is live
//!   nothing is recorded and the caller is told why. Then it commits the
//!   record as one shared security revision with its `security_outbox`
//!   row (see `storage::postgres_delegated_token_purges`).
//! - [`DelegatedTokenPurgesResource`] is the record as a reconciled
//!   resource of the strict per-request gate. A replica whose compiled
//!   revision is behind the counter reconciles every resource before it
//!   serves another protected request, and this one applies each purge
//!   recorded since it last looked to the replica's own cache. A replica
//!   that cannot read the record fails the gate and serves no protected
//!   request -- and so no delegated token -- until it can.
//!
//! Neither holds a principal: the record names a digest of one under the
//! deployment ID, and a replica matches it against the tokens it holds.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use async_trait::async_trait;

use crate::{
    audit::AuditLog,
    cluster_membership::{ClusterMembership, GatedWriteRequest},
    connections::{
        http::ConnectionHttpRuntime,
        token_exchange::{
            DelegatedTokenPurgeLedger, DelegatedTokenPurgeTrigger, PurgeNotRecorded, RecordedPurge,
        },
    },
    middleware::rbac::SecurityRevisionCheckError,
    storage::{
        compatibility::{OperationRefusal, DELEGATED_TOKEN_PURGES},
        PostgresDelegatedTokenPurgeStore,
    },
};

use super::ReconciledResource;

/// Most recorded purges one read applies. A replica far behind reads in
/// pages, keeping its place after each, so a pass cut short by its
/// deadline resumes where it stopped.
const PURGE_READ_PAGE: usize = 256;

/// Records a purge for every replica: the operation gate, then one shared
/// security revision.
pub(crate) struct ClusterDelegatedTokenPurgeLedger {
    store: Arc<PostgresDelegatedTokenPurgeStore>,
    /// The roster the operation gate reads. `None` refuses every record:
    /// with no roster, no live replica can be shown to apply it.
    membership: Option<Arc<ClusterMembership>>,
    audit: AuditLog,
}

impl ClusterDelegatedTokenPurgeLedger {
    pub(crate) fn new(
        store: Arc<PostgresDelegatedTokenPurgeStore>,
        membership: Option<Arc<ClusterMembership>>,
        audit: AuditLog,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            membership,
            audit,
        })
    }
}

#[async_trait]
impl DelegatedTokenPurgeLedger for ClusterDelegatedTokenPurgeLedger {
    async fn record(
        &self,
        purge_key: &str,
        origin: &DelegatedTokenPurgeTrigger,
    ) -> Result<i64, PurgeNotRecorded> {
        let requirement = &DELEGATED_TOKEN_PURGES;
        let Some(membership) = self.membership.as_ref() else {
            tracing::error!(
                operation = requirement.operation,
                "a delegated-token purge has no roster to ask; it is not recorded for the other \
                 replicas"
            );
            return Err(refused(&OperationRefusal::RosterUnavailable));
        };
        let (request_id, source_ip, actor) = origin.audit_origin();
        let request = GatedWriteRequest {
            request_id: request_id.to_owned(),
            source_ip: source_ip.to_owned(),
            actor: actor.cloned(),
        };
        // The gate logs and audits its own refusals (`cluster.operation_refused`).
        membership
            .admit_operation(requirement, &self.audit, &request)
            .await
            .map_err(|refusal| refused(&refusal))?;
        self.store.record(purge_key).await.map_err(|error| {
            tracing::error!(
                error = %error,
                "a delegated-token purge could not be recorded at the authority; the other \
                 replicas were not told"
            );
            PurgeNotRecorded::Unavailable
        })
    }
}

fn refused(refusal: &OperationRefusal) -> PurgeNotRecorded {
    PurgeNotRecorded::Refused {
        reason: refusal.reason(),
        detail: refusal.to_string(),
        members_lack_capability: matches!(refusal, OperationRefusal::MembersLackRequirement { .. }),
    }
}

/// The recorded purges as a reconciled resource of the security gate.
///
/// Its activation revision is the latest purge recorded above what this
/// replica has applied, or, when there is none, the latest it applied.
/// Reconciling to an activation applies every purge recorded up to it.
pub(crate) struct DelegatedTokenPurgesResource {
    store: Arc<PostgresDelegatedTokenPurgeStore>,
    connections: ConnectionHttpRuntime,
    /// Every purge recorded at or below this revision has been applied on
    /// this replica, or was recorded before its cache could hold anything.
    /// Starts at the revision read before the replica served, and only
    /// moves forward.
    applied_through: AtomicI64,
    /// The latest recorded purge this replica applied; `0` before the
    /// first.
    latest_applied: AtomicI64,
}

impl DelegatedTokenPurgesResource {
    /// `boot_revision` is the shared security revision read before this
    /// replica could cache a token: no purge recorded at or below it can
    /// name anything the replica holds.
    pub(crate) fn new(
        store: Arc<PostgresDelegatedTokenPurgeStore>,
        connections: ConnectionHttpRuntime,
        boot_revision: i64,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            connections,
            applied_through: AtomicI64::new(boot_revision),
            latest_applied: AtomicI64::new(0),
        })
    }
}

#[async_trait]
impl ReconciledResource for DelegatedTokenPurgesResource {
    fn name(&self) -> &'static str {
        "delegated_token_purges"
    }

    async fn activation_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        let applied = self.applied_through.load(Ordering::Acquire);
        let frontier = self.store.frontier(applied).await.map_err(|error| {
            tracing::error!(
                error = %error,
                "the recorded delegated-token purges could not be read"
            );
            SecurityRevisionCheckError::Unavailable
        })?;
        match frontier.latest_purge {
            Some(latest) => Ok(latest),
            None => {
                // Nothing is recorded above `applied` up to the counter the
                // same statement read, so every purge at or below it is
                // applied: the next read starts there instead of rescanning
                // every other resource's commits.
                self.applied_through
                    .fetch_max(frontier.authority_revision, Ordering::AcqRel);
                Ok(self.latest_applied.load(Ordering::Acquire))
            }
        }
    }

    async fn reconcile(&self, observed_activation: i64) -> Result<(), SecurityRevisionCheckError> {
        loop {
            let applied = self.applied_through.load(Ordering::Acquire);
            if applied >= observed_activation {
                return Ok(());
            }
            let page = self
                .store
                .recorded_between(applied, observed_activation, PURGE_READ_PAGE)
                .await
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        "delegated-token purge reconciliation could not read the recorded purges"
                    );
                    SecurityRevisionCheckError::Unavailable
                })?;
            let Some(last) = page.last().map(|purge| purge.security_revision) else {
                self.applied_through
                    .fetch_max(observed_activation, Ordering::AcqRel);
                return Ok(());
            };
            let purges: Vec<RecordedPurge<'_>> = page
                .iter()
                .map(|purge| RecordedPurge {
                    security_revision: purge.security_revision,
                    purge_key: purge.purge_key.as_deref(),
                })
                .collect();
            let purged = self
                .connections
                .apply_recorded_delegated_token_purges(&purges);
            tracing::debug!(
                records = purges.len(),
                purged_entries = purged,
                through = last,
                "applied recorded delegated-token purges"
            );
            self.latest_applied.fetch_max(last, Ordering::AcqRel);
            // A short page is the whole range; a full one may be followed
            // by more, read from where this one ended.
            let through = if page.len() < PURGE_READ_PAGE {
                observed_activation
            } else {
                last
            };
            self.applied_through.fetch_max(through, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
#[path = "security_cluster_delegated_tokens_tests.rs"]
mod tests;
