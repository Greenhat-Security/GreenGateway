//! Cluster mode's rule-suggestion engine (issue #241, PR 12): the same
//! explicit, admin-triggered generation standalone mode runs from SQLite,
//! fed from PostgreSQL.
//!
//! Generation has two inputs and one output, and each has a cluster home:
//!
//! - **Observed endpoints and open signals** come from the PR 11
//!   [`DiscoveryReadStore`] over the projector's tables, the store every
//!   replica already serves the admin surfaces from.
//! - **The role/endpoint matrix** comes from the durable PostgreSQL audit
//!   store (`PostgresAuditEventStore::observed_role_endpoint_matrix`), the
//!   same scan the SQLite audit store runs, folded by the same accumulator.
//! - **Suggestions** are persisted by the PostgreSQL lifecycle store with
//!   `ON CONFLICT ... DO NOTHING` on the suggestion identity, so re-running
//!   generation -- on this replica or another -- changes nothing.
//!
//! The planning between the inputs and the output is
//! [`crate::discovery::suggestions::SuggestionPlanner`], shared with the
//! standalone engine: this module contains no planning logic of its own,
//! which is what keeps the two backends' suggestion sets identical for the
//! same fixture (pinned by the generation parity test). Generation stays
//! explicit: no scheduler runs it (that is PR 13's singleton list).

use std::sync::Arc;

use crate::{
    discovery::{
        lifecycle::{TransitionOutcome, TransitionPrecondition},
        query::{utc_timestamp_rfc3339, DiscoveryReadStore},
        signals::{Signal, SignalLifecycleState, SignalListFilters},
        suggestions::{
            direct_rule_safety_for_target, lookback_cutoff, ConfiguredProxyRoute,
            DirectRuleSuggestionSafety, RuleSuggestion, RuleSuggestionConfig, RuleSuggestionError,
            RuleSuggestionLifecycleState, RuleSuggestionListFilters, RuleSuggestionListPage,
            RuleSuggestionRun, SuggestionPlanner, AUDIT_POSTGRES_EVIDENCE_SOURCE,
        },
    },
    rbac::Policy,
    storage::{
        postgres_audit::PostgresAuditEventStore,
        postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore,
    },
};

/// The cluster suggestion engine. Cheap to clone the parts of; holds no
/// per-instance state.
pub struct ClusterRuleSuggestionEngine {
    read_store: Arc<dyn DiscoveryReadStore>,
    audit_store: Arc<PostgresAuditEventStore>,
    suggestion_store: PostgresDiscoveryLifecycleStore,
    config: RuleSuggestionConfig,
    configured_proxy_routes: Vec<ConfiguredProxyRoute>,
}

impl ClusterRuleSuggestionEngine {
    pub fn new(
        read_store: Arc<dyn DiscoveryReadStore>,
        audit_store: Arc<PostgresAuditEventStore>,
        suggestion_store: PostgresDiscoveryLifecycleStore,
        config: RuleSuggestionConfig,
    ) -> Self {
        Self {
            read_store,
            audit_store,
            suggestion_store,
            config,
            configured_proxy_routes: Vec::new(),
        }
    }

    pub(crate) fn with_configured_proxy_routes(
        mut self,
        configured_proxy_routes: Vec<ConfiguredProxyRoute>,
    ) -> Self {
        self.configured_proxy_routes = configured_proxy_routes;
        self
    }

    /// The lifecycle store this engine persists through: the cluster-mode
    /// accept handler runs its atomic acceptance on it.
    pub fn suggestion_store(&self) -> &PostgresDiscoveryLifecycleStore {
        &self.suggestion_store
    }

    /// One explicit generation run against PostgreSQL; the standalone
    /// engine's `generate`, input for input. The baseline is always
    /// available: cluster mode's audit store is the durable one.
    pub async fn generate(
        &self,
        policy: &Policy,
    ) -> Result<RuleSuggestionRun, RuleSuggestionError> {
        let created_at = utc_timestamp_rfc3339();
        let mut run = RuleSuggestionRun::default();
        let observed_endpoints = self.read_store.observed_endpoints().await?;
        let planner = SuggestionPlanner::new(
            policy,
            self.config,
            &self.configured_proxy_routes,
            &observed_endpoints,
        );

        let mut suggestions = if observed_endpoints.is_empty() {
            Vec::new()
        } else {
            let from = lookback_cutoff(self.config.baseline_window_hours);
            let matrix = self
                .audit_store
                .observed_role_endpoint_matrix(&planner.matrix_filters(&from, &created_at))
                .await?;
            planner.baseline_suggestions(
                matrix,
                &from,
                &created_at,
                AUDIT_POSTGRES_EVIDENCE_SOURCE,
                &mut run.baseline,
            )?
        };
        suggestions.extend(planner.anomaly_suggestions(
            self.open_signals().await?,
            &created_at,
            &mut run.anomaly,
        )?);

        let inserted = self
            .suggestion_store
            .insert_suggestions(&suggestions)
            .await?;
        run.inserted_count = inserted.len();
        Ok(run)
    }

    pub async fn list_suggestions(&self) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store.list_suggestions().await
    }

    pub async fn list_suggestion_page(
        &self,
        filters: &RuleSuggestionListFilters,
    ) -> Result<RuleSuggestionListPage, RuleSuggestionError> {
        self.suggestion_store.list_suggestion_page(filters).await
    }

    pub async fn get_suggestion(
        &self,
        suggestion_id: &str,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store.get_suggestion(suggestion_id).await
    }

    /// Move a suggestion to `state` if it is still in `expected.from_state`
    /// (and at `expected.revision`, when given); see
    /// [`crate::discovery::lifecycle`].
    pub async fn transition_suggestion(
        &self,
        suggestion_id: &str,
        state: RuleSuggestionLifecycleState,
        transitioned_by: Option<&str>,
        expected: TransitionPrecondition<RuleSuggestionLifecycleState>,
    ) -> Result<TransitionOutcome<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store
            .transition_suggestion(suggestion_id, state, transitioned_by, expected)
            .await
    }

    /// Re-validate a stored suggestion's routing context against the
    /// inventory as it is NOW; the standalone engine's check over the
    /// cluster read store.
    pub async fn direct_rule_suggestion_safety(
        &self,
        suggestion: &RuleSuggestion,
    ) -> Result<DirectRuleSuggestionSafety, RuleSuggestionError> {
        let observed_endpoints = self.read_store.observed_endpoints().await?;
        Ok(direct_rule_safety_for_target(
            &observed_endpoints,
            &self.configured_proxy_routes,
            &suggestion.method,
            &suggestion.path_pattern,
            &suggestion.created_at,
        ))
    }

    async fn open_signals(&self) -> Result<Vec<Signal>, RuleSuggestionError> {
        let mut cursor = None;
        let mut signals = Vec::new();
        loop {
            let page = self
                .read_store
                .list_signals(&SignalListFilters {
                    state: Some(SignalLifecycleState::Open),
                    signal_type: None,
                    target_kind: None,
                    target_key: None,
                    limit: 500,
                    cursor,
                })
                .await?;
            signals.extend(page.signals);
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            cursor = Some(next_cursor);
        }
        Ok(signals)
    }
}
