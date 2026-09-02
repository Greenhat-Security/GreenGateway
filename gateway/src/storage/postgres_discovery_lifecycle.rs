//! PostgreSQL rule-suggestion lifecycle store (issue #241, PR 12): the
//! cluster side of the suggestion transitions the standalone
//! `RuleSuggestionStore` owns, over migration 9's
//! `discovery_rule_suggestions` and migration 10's revision column.
//!
//! What is written and why it matches the SQLite store:
//!
//! - **The same row, the same decoding.** The row is read through the same
//!   `RawRuleSuggestion` the SQLite store uses, in the same column order, so
//!   a suggestion decodes identically whichever backend stored it.
//! - **Generation is idempotent by the same identity.** `insert_suggestions`
//!   is `INSERT ... ON CONFLICT (suggestion_type, method, path_pattern,
//!   principal_key) DO NOTHING`, the SQLite store's `INSERT OR IGNORE` over
//!   the same unique index: re-running generation inserts nothing new, and
//!   two replicas generating at once cannot double-insert a target. The
//!   batch is sorted by that identity before it is sent, so concurrent
//!   batches take their uniqueness waits in one order and cannot deadlock.
//! - **Listing orders and pages as SQLite does.** The page order is the
//!   SQLite store's (`created_at` as an instant, then `id` bytewise) and
//!   the cursor format is shared, so a page cursor means the same thing on
//!   both backends.
//! - **One conditional statement per transition.** `UPDATE ... SET state,
//!   revision = revision + 1 WHERE id = $1 AND state = $from AND ($rev IS
//!   NULL OR revision = $rev) RETURNING *`: zero rows means another admin --
//!   on this replica or any other -- moved the row first, and the caller
//!   gets the row as it is now (`TransitionRefused`) to answer 409 with,
//!   never overwriting. The accept path re-checks the identity-bound rule
//!   the SQLite store enforces before writing.
//! - **Acceptance is one transaction** (the HA state model's rule 7: "no
//!   partial success exists"). [`PostgresDiscoveryLifecycleStore::accept_suggestion`]
//!   locks the suggestion row `FOR UPDATE`, verifies it is still Open at
//!   the expected revision, runs the policy commit's steps
//!   (`postgres_policy::commit_policy_in`: the ETag precondition, the
//!   immutable version that is also the history row, the security
//!   revision, the active pointer, the `security_outbox` row), transitions
//!   the suggestion to Accepted, and commits once. A stale policy ETag, a
//!   suggestion another replica moved first, or a failure anywhere rolls
//!   the whole thing back: the rule is never installed without the
//!   suggestion moving, and the suggestion never moves without the rule.
//!   The audit events (`policy.changed`, `suggestion.lifecycle_changed`)
//!   are the caller's to emit AFTER this returns, that is after COMMIT:
//!   audit is at-least-once by design, so an event for a rolled-back
//!   acceptance must be impossible while an acceptance whose events were
//!   lost to a crash is tolerable. The one outcome that is neither a
//!   commit nor a rollback from the caller's side is a `COMMIT` whose
//!   acknowledgement is lost: the acceptance may in fact be durable, with
//!   no events emitted for it. The transaction still moved both halves or
//!   neither, so the outbox row -- not the event -- is the durable record
//!   ([`AcceptRefused`] says the same about its `Store` variant).
//!
//! Errors classify into the repository vocabulary and carry an operation
//! label only: no SQL text, no values.

use std::fmt;

#[cfg(test)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio_postgres::{types::FromSql, Row};

use crate::discovery::{
    lifecycle::{TransitionOutcome, TransitionPrecondition, TransitionRefused},
    query::{decode_cursor, encode_cursor, query_limit, utc_timestamp_rfc3339},
    suggestions::{
        NewRuleSuggestion, RawRuleSuggestion, RuleSuggestion, RuleSuggestionCursor,
        RuleSuggestionError, RuleSuggestionLifecycleState, RuleSuggestionListFilters,
        RuleSuggestionListPage, RULE_SUGGESTION_COLUMNS,
    },
};

use super::{
    log_classified,
    policy_history::{ActivePolicy, PolicyCommitError, PolicyCommitRequest},
    postgres::classify_pool_error,
    postgres_discovery_read::{caller_timestamp, SqlParams},
    postgres_documents, postgres_policy, RepositoryError, RepositoryErrorKind,
};

const OPERATION_INSERT_SUGGESTIONS: &str = "discovery_insert_suggestions";
const OPERATION_LIST_SUGGESTIONS: &str = "discovery_list_suggestions";
const OPERATION_GET_SUGGESTION: &str = "discovery_get_suggestion";
const OPERATION_TRANSITION_SUGGESTION: &str = "discovery_transition_suggestion";
const OPERATION_ACCEPT_SUGGESTION: &str = "discovery_accept_suggestion";

const INSERT_SUGGESTIONS_SQL: &str = r#"
INSERT INTO greengateway.discovery_rule_suggestions (
    id, suggestion_type, method, path_pattern, principal_key, proposed_rule_json,
    rationale, evidence_json, state, created_at, updated_at, transitioned_at,
    transitioned_by, source_signal_id
)
SELECT id, suggestion_type, method, path_pattern, principal_key, proposed_rule_json,
       rationale, evidence_json, state, created_at, created_at, NULL, NULL, source_signal_id
FROM UNNEST(
    $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
    $7::text[], $8::text[], $9::text[], $10::text[], $11::text[]
) AS batch(id, suggestion_type, method, path_pattern, principal_key, proposed_rule_json,
           rationale, evidence_json, state, created_at, source_signal_id)
ON CONFLICT (suggestion_type, method, path_pattern, principal_key) DO NOTHING
RETURNING id
"#;

/// Everything one atomic acceptance needs: which suggestion, what the
/// caller read its revision as, who is accepting, and the fully validated
/// policy commit (candidate, expected ETag, actor, diff summary) that
/// installs the proposed rule.
pub struct AcceptSuggestionRequest<'a> {
    pub suggestion_id: &'a str,
    /// The suggestion revision the caller read (`If-Match`-style); `None`
    /// accepts whichever revision is current, provided the row is Open.
    pub expected_revision: Option<i64>,
    /// Recorded as the suggestion's `transitioned_by`.
    pub actor: &'a str,
    pub policy_commit: PolicyCommitRequest<'a>,
}

/// A committed acceptance: the suggestion after its transition and the
/// policy the same transaction activated.
#[derive(Clone, Debug)]
pub struct SuggestionAccepted {
    pub suggestion: RuleSuggestion,
    pub policy: ActivePolicy,
}

/// Why an acceptance did not commit. Every variant except one means
/// nothing was written: not the rule, not the history row, not the outbox
/// row, not the transition -- the transaction refused before or during its
/// work and rolled back, so the two halves stay together.
///
/// The exception is a [`AcceptRefused::Store`] (or
/// [`PolicyCommitError::Store`]) raised by the `COMMIT` itself: a commit
/// whose acknowledgement is lost to a connection reset, a terminated
/// backend, or a timeout is *indeterminate*, not negative. The server may
/// have committed everything. What still holds is that the halves never
/// separate -- either all of the rule, the history row, the outbox row and
/// the transition are durable, or none of them are -- so a caller that
/// reads the suggestion back learns which happened. The audit events are
/// not emitted in that case, which is why the outbox row committed inside
/// the transaction, not the event, is the durable record (HA state model
/// rule 2).
#[derive(Debug)]
pub enum AcceptRefused {
    /// The suggestion is not Open, or is not at the expected revision;
    /// `current` is the row as it is now (another admin's transition).
    /// Boxed: the row is by far the largest payload of this enum.
    Suggestion(Box<TransitionRefused<RuleSuggestion>>),
    /// No suggestion has that id.
    NotFound,
    /// A baseline suggestion without issuer and authentication-method
    /// constraints; accepting it would install an over-broad rule.
    UnsafeBaselineSuggestion { id: String },
    /// The policy commit refused: a stale policy ETag
    /// (`PreconditionFailed`), a reserved tool name, or a store failure.
    Policy(PolicyCommitError),
    /// The suggestion side failed for a store-level reason.
    Store(RuleSuggestionError),
}

impl fmt::Display for AcceptRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suggestion(refused) => write!(
                formatter,
                "suggestion {} is {} at revision {}; nothing was written",
                refused.current.id,
                refused.current.state.as_str(),
                refused.current.revision
            ),
            Self::NotFound => formatter.write_str("suggestion was not found; nothing was written"),
            Self::UnsafeBaselineSuggestion { id } => write!(
                formatter,
                "baseline suggestion {id} is missing issuer or authentication-method constraints; nothing was written"
            ),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "suggestion acceptance failed: {error}"),
        }
    }
}

impl std::error::Error for AcceptRefused {}

impl From<RuleSuggestionError> for AcceptRefused {
    fn from(error: RuleSuggestionError) -> Self {
        Self::Store(error)
    }
}

/// How the transaction body ended, before COMMIT/ROLLBACK is decided.
enum AcceptStep {
    Refused(AcceptRefused),
    /// The test-only crash hook fired between the policy write and the
    /// transition: the caller drops the connection without COMMIT or
    /// ROLLBACK, as a dead process would.
    #[cfg(test)]
    Crashed,
}

impl From<RuleSuggestionError> for AcceptStep {
    fn from(error: RuleSuggestionError) -> Self {
        Self::Refused(AcceptRefused::Store(error))
    }
}

/// The suggestion lifecycle store over one PostgreSQL pool. Cheap to
/// construct; holds no per-instance state beyond the test-only crash hook.
#[derive(Clone)]
pub struct PostgresDiscoveryLifecycleStore {
    pool: deadpool_postgres::Pool,
    /// When set, the next acceptance "crashes" after the policy write and
    /// before the suggestion transition: the connection is dropped with
    /// the transaction open, so the server discards it. Proves the two
    /// writes share one transaction; compiled out of production.
    #[cfg(test)]
    crash_before_transition: Arc<AtomicBool>,
}

impl PostgresDiscoveryLifecycleStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            pool,
            #[cfg(test)]
            crash_before_transition: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Arm the crash hook: the next `accept_suggestion` on this store
    /// (or any clone of it) dies between the policy write and the
    /// suggestion transition.
    #[cfg(test)]
    pub(crate) fn crash_before_transition_for_tests(&self) {
        self.crash_before_transition.store(true, Ordering::SeqCst);
    }

    fn crash_before_transition_armed(&self) -> bool {
        #[cfg(test)]
        {
            self.crash_before_transition.swap(false, Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Persist a generation run's suggestions, skipping every target that
    /// already has a row (open, accepted, or dismissed); returns the ones
    /// actually inserted, as they now read back. One statement for the
    /// whole batch, sorted by identity (see the module documentation).
    pub async fn insert_suggestions(
        &self,
        suggestions: &[NewRuleSuggestion],
    ) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        let operation = OPERATION_INSERT_SUGGESTIONS;
        if suggestions.is_empty() {
            return Ok(Vec::new());
        }
        let mut ordered = suggestions.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            (
                &left.suggestion_type,
                &left.method,
                &left.path_pattern,
                &left.principal_key,
            )
                .cmp(&(
                    &right.suggestion_type,
                    &right.method,
                    &right.path_pattern,
                    &right.principal_key,
                ))
        });

        let mut ids = Vec::with_capacity(ordered.len());
        let mut suggestion_types = Vec::with_capacity(ordered.len());
        let mut methods = Vec::with_capacity(ordered.len());
        let mut path_patterns = Vec::with_capacity(ordered.len());
        let mut principal_keys = Vec::with_capacity(ordered.len());
        let mut proposed_rules = Vec::with_capacity(ordered.len());
        let mut rationales = Vec::with_capacity(ordered.len());
        let mut evidences = Vec::with_capacity(ordered.len());
        let mut states = Vec::with_capacity(ordered.len());
        let mut created_ats = Vec::with_capacity(ordered.len());
        let mut source_signal_ids: Vec<Option<&str>> = Vec::with_capacity(ordered.len());
        for suggestion in &ordered {
            ids.push(suggestion.id.as_str());
            suggestion_types.push(suggestion.suggestion_type.as_str());
            methods.push(suggestion.method.as_str());
            path_patterns.push(suggestion.path_pattern.as_str());
            principal_keys.push(suggestion.principal_key.as_str());
            proposed_rules.push(serde_json::to_string(&suggestion.proposed_rule).map_err(
                |source| RuleSuggestionError::Json {
                    context: "proposed rule",
                    source,
                },
            )?);
            rationales.push(suggestion.rationale.as_str());
            evidences.push(
                serde_json::to_string(&suggestion.evidence).map_err(|source| {
                    RuleSuggestionError::Json {
                        context: "evidence",
                        source,
                    }
                })?,
            );
            states.push(suggestion.state.as_str());
            created_ats.push(suggestion.created_at.as_str());
            source_signal_ids.push(suggestion.source_signal_id.as_deref());
        }

        let client = self.client().await?;
        let rows = client
            .query(
                INSERT_SUGGESTIONS_SQL,
                &[
                    &ids,
                    &suggestion_types,
                    &methods,
                    &path_patterns,
                    &principal_keys,
                    &proposed_rules,
                    &rationales,
                    &evidences,
                    &states,
                    &created_ats,
                    &source_signal_ids,
                ],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        let mut inserted_ids = std::collections::HashSet::with_capacity(rows.len());
        for row in &rows {
            inserted_ids.insert(column::<String>(row, 0, operation)?);
        }
        Ok(ordered
            .into_iter()
            .filter(|suggestion| inserted_ids.contains(&suggestion.id))
            .map(NewRuleSuggestion::as_suggestion)
            .collect())
    }

    /// Every suggestion, newest first: the unpaged list.
    pub async fn list_suggestions(&self) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        Ok(self
            .list_suggestion_page(&RuleSuggestionListFilters {
                state: None,
                suggestion_type: None,
                limit: usize::MAX,
                cursor: None,
            })
            .await?
            .suggestions)
    }

    /// One page of suggestions, newest first, with the SQLite store's
    /// order and cursor.
    pub async fn list_suggestion_page(
        &self,
        filters: &RuleSuggestionListFilters,
    ) -> Result<RuleSuggestionListPage, RuleSuggestionError> {
        let operation = OPERATION_LIST_SUGGESTIONS;
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<RuleSuggestionCursor>("cursor", value))
            .transpose()
            .map_err(|_| RuleSuggestionError::InvalidCursor {
                parameter: "cursor",
            })?;
        let (sql, params) = build_suggestion_list_query(filters, cursor.as_ref());
        let client = self.client().await?;
        let mut rows = client
            .query(sql.as_str(), &params.refs())
            .await
            .map_err(|error| classify_query(error, operation))?
            .iter()
            .map(|row| raw_suggestion(row, operation))
            .collect::<Result<Vec<_>, _>>()?;

        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_cursor(&RuleSuggestionCursor {
                        created_at: row.created_at.clone(),
                        id: row.id.clone(),
                    })
                })
                .transpose()
                .map_err(|_| RuleSuggestionError::InvalidCursor {
                    parameter: "cursor",
                })?
        } else {
            None
        };

        let suggestions = rows
            .into_iter()
            .map(RawRuleSuggestion::into_suggestion)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RuleSuggestionListPage {
            suggestions,
            next_cursor,
        })
    }

    /// Accept a suggestion and install the rule it proposes in ONE
    /// transaction; see the module documentation. Returns after COMMIT,
    /// so the caller can emit the audit events for both changes knowing
    /// they happened. `Err` means nothing was written.
    ///
    pub async fn accept_suggestion(
        &self,
        request: AcceptSuggestionRequest<'_>,
    ) -> Result<SuggestionAccepted, AcceptRefused> {
        let operation = OPERATION_ACCEPT_SUGGESTION;
        let client = self.client().await?;
        postgres_documents::begin(&client, operation)
            .await
            .map_err(store_error)?;
        let crash_before_transition = self.crash_before_transition_armed();
        let outcome = accept_suggestion_in(&client, request, crash_before_transition).await;
        let outcome = match outcome {
            Ok(accepted) => Ok(accepted),
            Err(AcceptStep::Refused(refused)) => Err(refused),
            #[cfg(test)]
            Err(AcceptStep::Crashed) => {
                // A dead process sends neither COMMIT nor ROLLBACK; its
                // connection closes and the server discards the open
                // transaction. Taking the object out of the pool and
                // dropping it is exactly that.
                drop(deadpool_postgres::Object::take(client));
                return Err(store_error(RepositoryError::new(
                    RepositoryErrorKind::Internal,
                    operation,
                )));
            }
        };
        postgres_documents::end_transaction(&client, operation, outcome, store_error).await
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, RuleSuggestionError> {
        self.pool
            .get()
            .await
            .map_err(|error| RuleSuggestionError::Repository(classify_pool_error(error)))
    }

    /// One suggestion, or `None` when no row has that id.
    pub async fn get_suggestion(
        &self,
        suggestion_id: &str,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        let operation = OPERATION_GET_SUGGESTION;
        let client = self.client().await?;
        load_suggestion(&client, suggestion_id, operation).await
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
        let client = self.client().await?;
        transition_suggestion_with(&client, suggestion_id, state, transitioned_by, expected).await
    }
}

/// The conditional transition over a client the caller owns, so the
/// acceptance transaction can run it between the policy commit's steps.
pub(crate) async fn transition_suggestion_with(
    client: &deadpool_postgres::Object,
    suggestion_id: &str,
    state: RuleSuggestionLifecycleState,
    transitioned_by: Option<&str>,
    expected: TransitionPrecondition<RuleSuggestionLifecycleState>,
) -> Result<TransitionOutcome<RuleSuggestion>, RuleSuggestionError> {
    let operation = OPERATION_TRANSITION_SUGGESTION;
    if state == RuleSuggestionLifecycleState::Accepted {
        let Some(suggestion) = load_suggestion(client, suggestion_id, operation).await? else {
            return Ok(TransitionOutcome::NotFound);
        };
        if !suggestion.is_identity_bound_for_acceptance() {
            return Err(RuleSuggestionError::UnsafeBaselineSuggestion { id: suggestion.id });
        }
    }
    let transitioned_at = utc_timestamp_rfc3339();
    let (from_state, also_from_state) = expected.bound_states();
    let row = client
        .query_opt(
            &format!(
                "UPDATE greengateway.discovery_rule_suggestions
                 SET state = $2,
                     updated_at = $3,
                     transitioned_at = $3,
                     transitioned_by = $4,
                     revision = revision + 1
                 WHERE id = $1
                   AND (state = $5 OR state = $7)
                   AND ($6::bigint IS NULL OR revision = $6::bigint)
                 RETURNING {RULE_SUGGESTION_COLUMNS}"
            ),
            &[
                &suggestion_id,
                &state.as_str(),
                &transitioned_at,
                &transitioned_by,
                &from_state.as_str(),
                &expected.revision,
                &also_from_state.as_str(),
            ],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    if let Some(row) = row {
        return Ok(TransitionOutcome::Applied(
            raw_suggestion(&row, operation)?.into_suggestion()?,
        ));
    }
    Ok(
        match load_suggestion(client, suggestion_id, operation).await? {
            Some(current) => TransitionOutcome::Refused(TransitionRefused { current }),
            None => TransitionOutcome::NotFound,
        },
    )
}

/// The acceptance transaction's body, over a client whose transaction the
/// caller opened and will close (or abandon).
///
/// 1. Lock the suggestion row `FOR UPDATE`: a concurrent acceptance or
///    dismissal on any replica waits here, then sees the committed state.
/// 2. Verify it is Open at the expected revision and identity-bound;
///    otherwise refuse with the row as it is, having written nothing.
/// 3. The policy commit's steps: precondition (the policy ETag), the
///    immutable version/history row, the security revision, the active
///    pointer, the outbox row. A stale ETag refuses before any write.
/// 4. Transition the suggestion to Accepted at the revision locked in
///    step 1 (the conditional statement, which cannot be refused under the
///    lock; if it ever were, the transaction fails closed).
async fn accept_suggestion_in(
    client: &deadpool_postgres::Object,
    request: AcceptSuggestionRequest<'_>,
    crash_before_transition: bool,
) -> Result<SuggestionAccepted, AcceptStep> {
    let operation = OPERATION_ACCEPT_SUGGESTION;
    let refused = |refused: AcceptRefused| AcceptStep::Refused(refused);

    // 1. Lock the row for the rest of the transaction.
    let row = client
        .query_opt(
            &format!(
                "SELECT {RULE_SUGGESTION_COLUMNS}
                 FROM greengateway.discovery_rule_suggestions
                 WHERE id = $1
                 FOR UPDATE"
            ),
            &[&request.suggestion_id],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    let Some(row) = row else {
        return Err(refused(AcceptRefused::NotFound));
    };
    let current = raw_suggestion(&row, operation)?.into_suggestion()?;

    // 2. The precondition: still Open, at the revision the caller read.
    let revision_matches = request
        .expected_revision
        .is_none_or(|expected| expected == current.revision);
    if current.state != RuleSuggestionLifecycleState::Open || !revision_matches {
        return Err(refused(AcceptRefused::Suggestion(Box::new(
            TransitionRefused { current },
        ))));
    }
    if !current.is_identity_bound_for_acceptance() {
        return Err(refused(AcceptRefused::UnsafeBaselineSuggestion {
            id: current.id,
        }));
    }

    // 3. The policy commit, inside this transaction.
    let policy = postgres_policy::commit_policy_in(client, request.policy_commit)
        .await
        .map_err(|error| refused(AcceptRefused::Policy(error)))?;

    #[cfg(test)]
    if crash_before_transition {
        return Err(AcceptStep::Crashed);
    }
    #[cfg(not(test))]
    let _ = crash_before_transition;

    // 4. The transition, at the revision locked above.
    let expected = TransitionPrecondition::from_state(RuleSuggestionLifecycleState::Open)
        .with_revision(Some(current.revision));
    match transition_suggestion_with(
        client,
        request.suggestion_id,
        RuleSuggestionLifecycleState::Accepted,
        Some(request.actor),
        expected,
    )
    .await?
    {
        TransitionOutcome::Applied(suggestion) => Ok(SuggestionAccepted { suggestion, policy }),
        TransitionOutcome::Refused(_) | TransitionOutcome::NotFound => {
            // The row is locked by this transaction and was verified Open
            // at this revision; the statement cannot see anything else.
            // Fail closed rather than commit a rule without its
            // suggestion.
            tracing::error!(
                operation,
                "a locked, verified suggestion refused its own acceptance transition; \
                 rolling the acceptance back"
            );
            Err(refused(store_error(RepositoryError::new(
                RepositoryErrorKind::Internal,
                operation,
            ))))
        }
    }
}

fn store_error(error: RepositoryError) -> AcceptRefused {
    AcceptRefused::Store(RuleSuggestionError::Repository(error))
}

/// The SQLite store's list query, ported: `julianday(created_at)` becomes
/// the `timestamptz` cast, the id tiebreak and cursor comparison are
/// bytewise (`COLLATE "C"`), and a cursor timestamp that does not parse
/// excludes rows instead of failing the query.
fn build_suggestion_list_query(
    filters: &RuleSuggestionListFilters,
    cursor: Option<&RuleSuggestionCursor>,
) -> (String, SqlParams) {
    let mut sql =
        format!("SELECT {RULE_SUGGESTION_COLUMNS} FROM greengateway.discovery_rule_suggestions");
    let mut clauses = Vec::new();
    let mut params = SqlParams::default();

    if let Some(state) = filters.state {
        let placeholder = params.bind(state.as_str().to_owned());
        clauses.push(format!("state = {placeholder}"));
    }
    if let Some(suggestion_type) = &filters.suggestion_type {
        let placeholder = params.bind(suggestion_type.clone());
        clauses.push(format!("suggestion_type = {placeholder}"));
    }
    if let Some(cursor) = cursor {
        let created_at = caller_timestamp(&params.bind(cursor.created_at.clone()));
        let id = params.bind(cursor.id.clone());
        clauses.push(format!(
            "(created_at::timestamptz < {created_at} OR (created_at::timestamptz = {created_at} \
             AND id COLLATE \"C\" > {id}))"
        ));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    let limit = params.bind(query_limit(filters.limit));
    sql.push_str(&format!(
        " ORDER BY created_at::timestamptz DESC, id COLLATE \"C\" ASC LIMIT {limit}::bigint"
    ));

    (sql, params)
}

async fn load_suggestion(
    client: &deadpool_postgres::Object,
    suggestion_id: &str,
    operation: &'static str,
) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
    client
        .query_opt(
            &format!(
                "SELECT {RULE_SUGGESTION_COLUMNS}
                 FROM greengateway.discovery_rule_suggestions
                 WHERE id = $1"
            ),
            &[&suggestion_id],
        )
        .await
        .map_err(|error| classify_query(error, operation))?
        .map(|row| raw_suggestion(&row, operation)?.into_suggestion())
        .transpose()
}

fn raw_suggestion(
    row: &Row,
    operation: &'static str,
) -> Result<RawRuleSuggestion, RuleSuggestionError> {
    Ok(RawRuleSuggestion {
        id: column(row, 0, operation)?,
        suggestion_type: column(row, 1, operation)?,
        method: column(row, 2, operation)?,
        path_pattern: column(row, 3, operation)?,
        principal_key: column(row, 4, operation)?,
        proposed_rule_json: column(row, 5, operation)?,
        rationale: column(row, 6, operation)?,
        evidence_json: column(row, 7, operation)?,
        state: column(row, 8, operation)?,
        created_at: column(row, 9, operation)?,
        updated_at: column(row, 10, operation)?,
        transitioned_at: column(row, 11, operation)?,
        transitioned_by: column(row, 12, operation)?,
        source_signal_id: column(row, 13, operation)?,
        revision: column(row, 14, operation)?,
    })
}

/// Read one column; a row that does not decode is data this binary cannot
/// use (`InvalidData`), never a panic on the request path.
fn column<'a, T: FromSql<'a>>(
    row: &'a Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RuleSuggestionError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "suggestion row failed to decode");
        RuleSuggestionError::Repository(RepositoryError::new(
            RepositoryErrorKind::InvalidData,
            operation,
        ))
    })
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RuleSuggestionError {
    let kind = super::postgres::classify_postgres_error(&error);
    RuleSuggestionError::Repository(log_classified(
        operation,
        &error,
        RepositoryError::new(kind, operation),
    ))
}
