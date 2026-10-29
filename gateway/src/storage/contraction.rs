//! Contracting migrations: the migrator's side of the durable contract
//! fence (issue #426, requirement 4 of `docs/architecture/ha-state-model.md`).
//!
//! An additive migration leaves every object an older build uses in place.
//! A contracting one removes some, and a build that still uses them must
//! never serve the schema it leaves behind. The roster cannot keep such a
//! build out: liveness is judged against `CLUSTER_MEMBER_STALE_MS`, so a
//! member that was stopped, swept or paused past the window can come back,
//! and a stale row disappearing is not proof that its build retired. The
//! durable contract fence (migration 20) can, because every build that
//! serves the database checks it at startup, on every heartbeat and before
//! every gated write, and it only moves forward.
//!
//! So a migration that removes anything declares a [`Contraction`], and the
//! migrator runs it as one transaction (`migrations::apply_one`) that, under
//! the migration's own statement and lock timeouts, before its SQL removes
//! anything ([`raise_fence_before_contracting`]):
//!
//! 1. locks the fence row `FOR UPDATE`. Every heartbeat, ready stamp and
//!    draining stamp takes `FOR SHARE` on that row inside its own statement,
//!    so a member's boot or rejoin either committed before the lock was
//!    granted, and is in the roster read below, or waits for this
//!    transaction and is then judged against the raised fence;
//! 2. reads the named backfill, which must be recorded `verified`;
//! 3. reads the roster, liveness on the database clock against the
//!    deployment's stale window, across every deployment ID in the table
//!    (a database holds one deployment, so a live row of any other is
//!    ambiguous membership and is judged like the rest);
//! 4. decides ([`decide`]): the raised fence demands a serving range
//!    reaching the migration's own version -- a build whose range ends below
//!    it cannot serve the contracted schema -- and the union of the fenced
//!    capabilities and the contraction's. Every live member, draining ones
//!    included because they still answer what was routed to them, must
//!    already meet it; otherwise the migration is refused;
//! 5. raises the fence when that moves it, recording the migration as
//!    `raised_by`.
//!
//! The migration's SQL and its ledger row follow in the same transaction.
//! A refusal, a failed statement and a lost connection all roll the whole
//! transaction back: nothing is removed, the fence is not raised, and the
//! ledger stays at the migration before. Once it commits, the raise is
//! logged and audited as `cluster.contract_fence_raised`
//! ([`record_contraction_fence`]).
//!
//! The migrator holds its session advisory lock for the whole run, so an
//! operation's own raise (`PostgresMembershipStore::raise_contract_fence`)
//! answers `migration_in_progress` instead of interleaving, and a second
//! migrator waits. The fence row stays locked until the contraction
//! commits, so every heartbeat in the deployment waits for it: a
//! contraction must be brief metadata DDL, and it runs under the migration
//! timeouts like any other.
//!
//! No shipped migration contracts. The fixture in `contraction_tests.rs`
//! exercises the protocol end to end against PostgreSQL with migrations
//! that exist only in the test.

use std::{collections::BTreeSet, fmt, time::Duration};

use uuid::Uuid;

use super::{
    compatibility::{
        advertisement, BackfillState, Capability, ContractFence, RecognizedCapabilities,
    },
    migrations::{MigrateError, Migration},
    AuditEventStore,
};

/// What a contracting migration removes, and so which builds the durable
/// contract fence must exclude before it runs. The raised fence always
/// demands a serving range reaching the migration's own version; this names
/// what else it demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Constructed only by the contraction fixture: no shipped migration contracts.
pub(crate) struct Contraction {
    /// Capabilities every build that remains must implement: what the
    /// builds that no longer need the removed objects advertise. Empty when
    /// the schema version alone separates them.
    pub(crate) capabilities: &'static [Capability],
    /// A backfill the backfill ledger (`schema_backfills`, migration 20) must
    /// record `verified` before anything is removed: what moved the data
    /// the removed objects held.
    pub(crate) backfill: Option<&'static str>,
}

/// One live roster row, as far as the contraction decision is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveMember {
    pub(crate) instance_id: Uuid,
    /// The highest schema the member's build serves.
    pub(crate) schema_version_max: i32,
    /// The member's advertisement, as this build recognizes it.
    pub(crate) capabilities: RecognizedCapabilities,
}

/// Where the fence must stand before a contraction removes anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractionDecision {
    /// The lowest schema a member's serving range must reach.
    pub(crate) minimum_schema: i32,
    /// The capabilities a member must implement.
    pub(crate) capabilities: BTreeSet<Capability>,
    /// Whether the fence must move to demand that; `false` when it already
    /// does, so nothing is written.
    pub(crate) raises: bool,
    /// The live members the decision was made over, every one of which
    /// already meets it.
    pub(crate) live_members: usize,
}

/// Why a contracting migration was refused. Nothing was removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContractionRefusal {
    /// The fence names capabilities this build does not recognize: a newer
    /// build raised it. This build cannot raise it without dropping them,
    /// which the fence's own trigger would refuse anyway.
    FenceNotRecognized { unrecognized: usize },
    /// The contraction's backfill is not recorded verified. `state` is
    /// `None` when its row holds a state the ledger does not define.
    BackfillUnverified {
        backfill: &'static str,
        state: Option<BackfillState>,
    },
    /// Live members run a build the raised fence would exclude: removing
    /// the objects under them, or fencing them out mid-flight, is exactly
    /// what the protocol exists to prevent.
    LiveMembersExcluded {
        excluded: Vec<Uuid>,
        live: usize,
        minimum_schema: i32,
        capabilities: usize,
    },
}

impl ContractionRefusal {
    /// A stable, closed reason code for logs.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::FenceNotRecognized { .. } => "contract_fence_unrecognized",
            Self::BackfillUnverified { .. } => "backfill_unverified",
            Self::LiveMembersExcluded { .. } => "live_members_excluded",
        }
    }
}

impl fmt::Display for ContractionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FenceNotRecognized { unrecognized } => write!(
                formatter,
                "the deployment's contract fence names {unrecognized} capability name(s) this \
                 build does not recognize, so this build cannot raise it; a newer build raised \
                 it, and only a build that recognizes them may contract this schema"
            ),
            Self::BackfillUnverified { backfill, state } => write!(
                formatter,
                "the '{backfill}' backfill must be recorded verified before anything is \
                 removed, and the backfill ledger {}; finish and verify the backfill, then run \
                 `gateway migrate up` again",
                match state {
                    None => "records a state it does not define",
                    Some(BackfillState::Missing) => "has no record of it",
                    Some(BackfillState::Running) => "records it as still running or interrupted",
                    Some(BackfillState::Failed) => "records it as failed",
                    Some(BackfillState::Verified) => "records it as verified",
                }
            ),
            Self::LiveMembersExcluded {
                excluded,
                live,
                minimum_schema,
                capabilities,
            } => write!(
                formatter,
                "{} of {live} live cluster member(s), draining ones included, run a build the \
                 raised fence would exclude (it requires a serving range reaching schema \
                 {minimum_schema} and {capabilities} fenced capability name(s)); replace them \
                 with an eligible build, or wait until their rows are stale on the database \
                 clock (CLUSTER_MEMBER_STALE_MS), then run `gateway migrate up` again",
                excluded.len()
            ),
        }
    }
}

/// Decide where the fence must stand before a migration whose version is
/// `minimum_schema` removes what `contraction` describes, over the fence and
/// the backfill state read under the fence's row lock and the live roster.
///
/// The raised fence is the higher of the two minimum schemas and the union
/// of the fenced and the contraction's capabilities, so it never lowers
/// anything. A live member meets it exactly when the heartbeat would admit
/// it (`postgres_membership`'s `FENCE_ADMITS_ROW`): its serving maximum
/// reaches the minimum and it advertises every fenced capability. Pure, so
/// every refusal is unit-tested without a database.
pub(crate) fn decide(
    fence: &ContractFence,
    minimum_schema: i32,
    contraction: &Contraction,
    backfill: Option<BackfillState>,
    live: &[LiveMember],
) -> Result<ContractionDecision, ContractionRefusal> {
    let fenced = RecognizedCapabilities::parse(&fence.capabilities);
    if fenced.unrecognized() > 0 {
        return Err(ContractionRefusal::FenceNotRecognized {
            unrecognized: fenced.unrecognized(),
        });
    }
    if let Some(name) = contraction.backfill {
        if backfill != Some(BackfillState::Verified) {
            return Err(ContractionRefusal::BackfillUnverified {
                backfill: name,
                state: backfill,
            });
        }
    }
    let mut capabilities: BTreeSet<Capability> = Capability::KNOWN
        .into_iter()
        .filter(|capability| fenced.contains(*capability))
        .collect();
    let already_fenced = capabilities.len();
    capabilities.extend(contraction.capabilities.iter().copied());
    let minimum_schema = fence.minimum_schema.max(minimum_schema);
    let excluded: Vec<Uuid> = live
        .iter()
        .filter(|member| {
            member.schema_version_max < minimum_schema
                || capabilities
                    .iter()
                    .any(|capability| !member.capabilities.contains(*capability))
        })
        .map(|member| member.instance_id)
        .collect();
    if !excluded.is_empty() {
        return Err(ContractionRefusal::LiveMembersExcluded {
            excluded,
            live: live.len(),
            minimum_schema,
            capabilities: capabilities.len(),
        });
    }
    let raises = minimum_schema != fence.minimum_schema || capabilities.len() != already_fenced;
    Ok(ContractionDecision {
        minimum_schema,
        capabilities,
        raises,
        live_members: live.len(),
    })
}

/// Where a contracting migration's transaction left the fence, for the
/// record made once the migration commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractionFence {
    pub(crate) before: ContractFence,
    /// The raised fence, or `None` when the fence already demanded
    /// everything and nothing was written.
    pub(crate) after: Option<ContractFence>,
    pub(crate) live_members: usize,
}

/// Steps 1 to 5 of the protocol (module docs), inside the contracting
/// migration's open transaction on the migrator's session, before its SQL.
/// A refusal is logged here, with the excluded members' instance IDs, and
/// returned as [`MigrateError::ContractionRefused`]; the caller rolls back.
pub(super) async fn raise_fence_before_contracting(
    client: &deadpool_postgres::ClientWrapper,
    version: i64,
    contraction: &Contraction,
    member_stale_window: Duration,
) -> Result<ContractionFence, MigrateError> {
    let minimum_schema = i32::try_from(version).map_err(|_| {
        tracing::error!(
            version,
            "contraction: the migration version is not a schema version"
        );
        MigrateError::ApplyFailed
    })?;
    let row = client
        .query_opt(
            "SELECT generation, minimum_schema, capabilities
             FROM greengateway.contract_fence
             WHERE singleton
             FOR UPDATE",
            &[],
        )
        .await
        .map_err(|error| apply_failed(&error, "contraction: locking the contract fence failed"))?
        .ok_or_else(|| {
            tracing::error!("contraction: the contract fence row is missing");
            MigrateError::ApplyFailed
        })?;
    let before = fence_from_row(&row)?;
    let backfill = match contraction.backfill {
        Some(name) => {
            let state: Option<String> = client
                .query_opt(
                    "SELECT state FROM greengateway.schema_backfills WHERE name = $1",
                    &[&name],
                )
                .await
                .map_err(|error| apply_failed(&error, "contraction: reading the backfill failed"))?
                .map(|row| row.try_get::<_, String>("state"))
                .transpose()
                .map_err(|error| {
                    apply_failed(&error, "contraction: reading the backfill failed")
                })?;
            BackfillState::from_column(state.as_deref())
        }
        None => None,
    };
    let window_secs = member_stale_window.as_secs_f64();
    let live = client
        .query(
            "SELECT instance_id::text AS instance_id, schema_version_max, capabilities
             FROM greengateway.cluster_members
             WHERE last_heartbeat_at > now() - make_interval(secs => $1::double precision)
             ORDER BY started_at ASC, instance_id ASC",
            &[&window_secs],
        )
        .await
        .map_err(|error| apply_failed(&error, "contraction: reading the roster failed"))?
        .iter()
        .map(live_member_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    let decision = match decide(&before, minimum_schema, contraction, backfill, &live) {
        Ok(decision) => decision,
        Err(refusal) => {
            if let ContractionRefusal::LiveMembersExcluded { excluded, .. } = &refusal {
                for member in excluded {
                    tracing::warn!(
                        member_instance_id = %member,
                        version,
                        "contraction: a live cluster member runs a build the raised contract \
                         fence would exclude"
                    );
                }
            }
            tracing::warn!(
                version,
                reason = refusal.reason(),
                error = %refusal,
                "contraction: refused a contracting migration; nothing was removed"
            );
            return Err(MigrateError::ContractionRefused { version, refusal });
        }
    };
    if !decision.raises {
        return Ok(ContractionFence {
            before,
            after: None,
            live_members: decision.live_members,
        });
    }
    let set: Vec<Capability> = decision.capabilities.iter().copied().collect();
    let capabilities = advertisement(&set).ok_or_else(|| {
        tracing::error!("contraction: the raised capability set exceeds the fence's bounds");
        MigrateError::ApplyFailed
    })?;
    let raised_by = format!("migration.{version}");
    let after = client
        .query_one(
            "UPDATE greengateway.contract_fence
             SET generation = generation + 1,
                 minimum_schema = $1,
                 capabilities = $2,
                 raised_at = now(),
                 raised_by = $3
             WHERE singleton
             RETURNING generation, minimum_schema, capabilities",
            &[&decision.minimum_schema, &capabilities, &raised_by],
        )
        .await
        .map_err(|error| apply_failed(&error, "contraction: raising the contract fence failed"))?;
    Ok(ContractionFence {
        before,
        after: Some(fence_from_row(&after)?),
        live_members: decision.live_members,
    })
}

/// Make a committed contraction's fence observable: one warning naming both
/// fences, and one `cluster.contract_fence_raised` audit event with the
/// migration that raised it, the numbers before and after, and the live
/// member count -- the same event an operation's raise records. The
/// migration has committed, so a failed audit write is logged and does not
/// fail the command; the fence row's `raised_at` and `raised_by` record the
/// raise either way.
pub(super) async fn record_contraction_fence(
    pool: &deadpool_postgres::Pool,
    migration: &Migration,
    fence: &ContractionFence,
) {
    let Some(after) = &fence.after else {
        tracing::info!(
            version = migration.version,
            name = migration.name,
            fence_generation = fence.before.generation,
            "contraction: the contract fence already excluded every build that cannot serve \
             this schema; nothing was raised"
        );
        return;
    };
    tracing::warn!(
        version = migration.version,
        name = migration.name,
        previous_generation = fence.before.generation,
        fence_generation = after.generation,
        minimum_schema = after.minimum_schema,
        live_members = fence.live_members,
        "contraction: raised the durable contract fence before contracting the schema; a \
         gateway build the fence excludes can no longer start or rejoin this deployment"
    );
    let fenced = RecognizedCapabilities::parse(&after.capabilities);
    let event = crate::audit::AuditEvent::new(
        crate::audit::event::CLUSTER_CONTRACT_FENCE_RAISED,
        "migration",
        "internal",
        None,
        serde_json::json!({
            "operation": format!("migration.{}", migration.version),
            "migration": migration.name,
            "outcome": "raised",
            "previous_generation": fence.before.generation,
            "fence_generation": after.generation,
            "previous_minimum_schema": fence.before.minimum_schema,
            "minimum_schema": after.minimum_schema,
            "capabilities": fenced.names(),
            "live_members": fence.live_members,
        }),
    );
    let store = super::postgres_audit::PostgresAuditEventStore::new(pool.clone(), None);
    if let Err(error) = store.insert_events(&[event]).await {
        tracing::error!(
            error = %error,
            version = migration.version,
            fence_generation = after.generation,
            "contraction: the contracting migration committed, but its \
             cluster.contract_fence_raised audit event could not be recorded"
        );
    }
}

fn apply_failed(error: &dyn fmt::Display, message: &'static str) -> MigrateError {
    tracing::error!(error = %error, "{message}");
    MigrateError::ApplyFailed
}

fn fence_from_row(row: &tokio_postgres::Row) -> Result<ContractFence, MigrateError> {
    let read = |error: tokio_postgres::Error| {
        apply_failed(
            &error,
            "contraction: the contract fence row is not readable",
        )
    };
    Ok(ContractFence {
        generation: row.try_get("generation").map_err(read)?,
        minimum_schema: row.try_get("minimum_schema").map_err(read)?,
        capabilities: row.try_get("capabilities").map_err(read)?,
    })
}

fn live_member_from_row(row: &tokio_postgres::Row) -> Result<LiveMember, MigrateError> {
    let read = |error: tokio_postgres::Error| {
        apply_failed(&error, "contraction: a roster row is not readable")
    };
    let instance_id: String = row.try_get("instance_id").map_err(read)?;
    let capabilities: String = row.try_get("capabilities").map_err(read)?;
    Ok(LiveMember {
        instance_id: Uuid::parse_str(&instance_id)
            .map_err(|error| apply_failed(&error, "contraction: a roster row is not readable"))?,
        schema_version_max: row.try_get("schema_version_max").map_err(read)?,
        capabilities: RecognizedCapabilities::parse(&capabilities),
    })
}

#[cfg(test)]
#[path = "contraction_tests.rs"]
mod tests;
