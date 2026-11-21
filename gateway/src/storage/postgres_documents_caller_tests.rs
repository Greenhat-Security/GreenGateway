//! Caller operation IDs on the shared document core (issue #425, plan P9).
//!
//! The store-level rows of the family test matrix for the policy, tools and
//! policy test suite documents, run against every keyed action: the six
//! policy mutations through [`PolicyControlPlane::commit_with_operation`],
//! the rule suggestion acceptance through
//! `PostgresDiscoveryLifecycleStore::accept_suggestion_with_operation`, the
//! tools document through [`ToolControlPlane::commit_tools_with_operation`]
//! and the stored policy test suite through
//! `PolicyTestSuiteStore::commit_with_operation`. They all commit through
//! [`commit_in`], so one mistake there would reach every endpoint; each test
//! runs every action. Every test ends by asserting I3 against its own
//! database ([`assert_reservations_match_evidence`]).
//!
//! The family is PostgreSQL only (the standalone rows stay refused, #242),
//! so these tests are gated on the test harness locator like the rest of the
//! module: CI's PostgreSQL jobs run them.
//!
//! There is no keyed no-op test: no document in this family has a no-op
//! path. Every accepted commit writes a new immutable version, so an
//! identical keyed request is a change like any other.

use std::collections::BTreeSet;

use super::*;
use crate::authority_events::caller_operation::{
    test_caller_key, CallerKeyState, CallerOperation, CallerOperationBinding, CallerOutcome,
    OperationReceipt,
};
use crate::storage::policy_tests::{PolicyTestSuiteCommitError, PolicyTestSuitePrecondition};
use crate::storage::postgres_discovery_lifecycle::{
    AcceptRefused, AcceptSuggestionRequest, PostgresDiscoveryLifecycleStore,
};
use crate::storage::postgres_policy_tests::PostgresPolicyTestSuiteStore;
use crate::storage::PolicyTestSuiteStore;

/// One keyed member of the family, by the store that commits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Policy(DocumentAction),
    SuggestionAccept,
    Tools,
    PolicyTests,
}

const FAMILIES: [Family; 9] = [
    Family::Policy(DocumentAction::PolicyPublish),
    Family::Policy(DocumentAction::PolicyRollback),
    Family::Policy(DocumentAction::PolicyRuleCreate),
    Family::Policy(DocumentAction::PolicyRuleUpdate),
    Family::Policy(DocumentAction::PolicyRuleDelete),
    Family::Policy(DocumentAction::PolicyRuleReorder),
    Family::SuggestionAccept,
    Family::Tools,
    Family::PolicyTests,
];

impl Family {
    fn action(self) -> DocumentAction {
        match self {
            Self::Policy(action) => action,
            Self::SuggestionAccept => DocumentAction::PolicySuggestionAccept,
            Self::Tools => DocumentAction::ToolsPublish,
            Self::PolicyTests => DocumentAction::PolicyTestsPublish,
        }
    }

    fn resource_type(self) -> &'static str {
        match self {
            Self::Policy(_) | Self::SuggestionAccept => "policy",
            Self::Tools => "tools",
            Self::PolicyTests => "policy_tests",
        }
    }
}

const ISSUER: &str = "https://idp.example.test";

fn operator() -> ChangeActor {
    ChangeActor::for_test_with_issuer("operator", ISSUER)
}

/// The principal the suite store is given: `subject` under the issuer.
fn principal(subject: &str) -> crate::auth::Principal {
    crate::auth::Principal {
        user_id: subject.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        org_id: None,
        roles: vec!["admin".to_owned()],
        session_id: "session".to_owned(),
        auth_method: AuthMethod::Bearer,
        scopes: None,
        verified_claims: Vec::new(),
    }
}

/// A suite document the store accepts, distinguished by `description`.
fn suite_document(description: &str) -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "description": description,
        "cases": [{
            "id": "health-is-public",
            "kind": "http",
            "request": { "method": "GET", "path": "/health" },
            "principal": "anonymous",
            "expect": { "logical": "allow" }
        }]
    })
}

/// What one keyed request binds: the target (a suggestion's ID for an
/// acceptance, empty for a whole document), the `If-Match` value and the
/// canonical request (here the variant's name).
#[derive(Clone)]
struct Request {
    family: Family,
    target: String,
    etag: String,
    variant: String,
}

impl Request {
    fn key(&self, seed: u8, actor: &ChangeActor) -> CallerOperation {
        CallerOperation::bind(
            test_caller_key(seed),
            &CallerOperationBinding {
                action: self.family.action().code(),
                actor,
                target: &self.target,
                precondition: &self.etag,
                request: self.variant.as_bytes(),
            },
        )
        .expect("the key binds")
    }
}

/// A committed version, or the receipt of an exact retry.
type Outcome = Result<CallerOutcome<i64>, PolicyCommitError>;

struct Fixture {
    pool: deadpool_postgres::Pool,
    policies: PostgresPolicyStore,
    tools: PostgresToolStore,
    suites: PostgresPolicyTestSuiteStore,
    lifecycle: PostgresDiscoveryLifecycleStore,
}

impl Fixture {
    /// Every document of the family active, and the contract fence raised
    /// for `caller_operation_keys` as the operation gate's first admission
    /// raises it.
    async fn new(database: &TestDatabase) -> Self {
        let pool = migrated_pool(database).await;
        let policies = PostgresPolicyStore::new(pool.clone());
        let fixture = Self {
            pool: pool.clone(),
            tools: PostgresToolStore::new(pool.clone()),
            suites: policies.test_suite_store(),
            lifecycle: PostgresDiscoveryLifecycleStore::new(pool.clone()),
            policies,
        };
        PolicyControlPlane::commit(
            &fixture.policies,
            request(
                PolicyCommitPrecondition::Initialize,
                &policy("caller-initial", "reader"),
                DocumentChange::test_policy("installer"),
            ),
        )
        .await
        .expect("the initial policy commits");
        fixture
            .tools
            .seed_empty_document()
            .await
            .expect("the tools document seeds");
        fixture
            .suites
            .commit(
                PolicyTestSuitePrecondition::Absent,
                &suite_document("initial"),
                &principal("operator"),
            )
            .await
            .expect("the first suite is stored");
        fixture.raise_fence().await;
        fixture
    }

    async fn raise_fence(&self) {
        let requirement = &crate::storage::compatibility::CALLER_OPERATION_KEYS;
        let raised = self
            .pool
            .get()
            .await
            .expect("fence checkout")
            .execute(
                "UPDATE greengateway.contract_fence
                 SET generation = generation + 1,
                     minimum_schema = GREATEST(minimum_schema, $1),
                     capabilities = $2,
                     raised_at = now(),
                     raised_by = 'fixture.caller_operation_keys'
                 WHERE singleton",
                &[
                    &requirement.minimum_schema,
                    &requirement.capability.as_str(),
                ],
            )
            .await
            .expect("the fence raises");
        assert_eq!(raised, 1);
    }

    async fn etag(&self, family: Family) -> String {
        match family {
            Family::Policy(_) | Family::SuggestionAccept => {
                PolicyControlPlane::active(&self.policies)
                    .await
                    .expect("the policy reads")
                    .expect("a policy is active")
                    .etag
            }
            Family::Tools => {
                self.tools
                    .active_tools()
                    .await
                    .expect("the tools read")
                    .expect("tools are active")
                    .etag
            }
            Family::PolicyTests => {
                self.suites
                    .active()
                    .await
                    .expect("the suite reads")
                    .expect("a suite is active")
                    .etag
            }
        }
    }

    /// A request for `family` against its current ETag.
    async fn request(&self, family: Family, variant: &str) -> Request {
        Request {
            family,
            target: match family {
                Family::SuggestionAccept => format!("suggestion-{variant}"),
                _ => String::new(),
            },
            etag: self.etag(family).await,
            variant: variant.to_owned(),
        }
    }

    /// Commit `request` by `actor` under `caller`, through the store its
    /// family commits through.
    async fn commit(
        &self,
        request: &Request,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Outcome {
        let expected = PolicyCommitPrecondition::Expected {
            etag: request.etag.clone(),
        };
        let change = DocumentChange {
            action: request.family.action(),
            actor: actor.clone(),
        };
        let candidate = policy(&request.variant, "reader");
        match request.family {
            Family::Policy(_) => PolicyControlPlane::commit_with_operation(
                &self.policies,
                PolicyCommitRequest {
                    precondition: expected,
                    candidate: &candidate,
                    change,
                    diff_summary: &DIFF,
                },
                caller,
            )
            .await
            .map(|outcome| version_of(outcome, |active| active.version)),
            Family::SuggestionAccept => {
                self.seed_open_suggestion(&request.target).await;
                self.lifecycle
                    .accept_suggestion_with_operation(
                        AcceptSuggestionRequest {
                            suggestion_id: &request.target,
                            expected_revision: None,
                            actor: actor.subject(),
                            policy_commit: PolicyCommitRequest {
                                precondition: expected,
                                candidate: &candidate,
                                change,
                                diff_summary: &DIFF,
                            },
                        },
                        caller,
                    )
                    .await
                    .map(|outcome| version_of(outcome, |accepted| accepted.policy.version))
                    .map_err(|refused| match refused {
                        AcceptRefused::Policy(error) => error,
                        other => panic!("the acceptance was refused outside the commit: {other:?}"),
                    })
            }
            Family::Tools => {
                let name = format!("fixture_{}", request.variant.replace('-', "_"));
                ToolControlPlane::commit_tools_with_operation(
                    &self.tools,
                    expected,
                    &tools_document(&[&name]),
                    change,
                    &DIFF,
                    caller,
                )
                .await
                .map(|outcome| version_of(outcome, |active| active.version))
            }
            Family::PolicyTests => self
                .suites
                .commit_with_operation(
                    PolicyTestSuitePrecondition::Expected {
                        etag: request.etag.clone(),
                    },
                    &suite_document(&request.variant),
                    &principal(actor.subject()),
                    caller,
                )
                .await
                .map(|outcome| version_of(outcome, |record| record.version))
                .map_err(|error| match error {
                    PolicyTestSuiteCommitError::PreconditionFailed => {
                        PolicyCommitError::PreconditionFailed
                    }
                    PolicyTestSuiteCommitError::Store(error) => PolicyCommitError::Store(error),
                    PolicyTestSuiteCommitError::CallerOperationConflict => {
                        PolicyCommitError::CallerOperationConflict
                    }
                }),
        }
    }

    /// The handler's unlocked pre-check, through the store `family` uses.
    async fn state(&self, family: Family, caller: &CallerOperation) -> CallerKeyState {
        match family {
            Family::Policy(_) | Family::SuggestionAccept => {
                PolicyControlPlane::caller_operation_state(&self.policies, caller).await
            }
            Family::Tools => ToolControlPlane::caller_operation_state(&self.tools, caller).await,
            Family::PolicyTests => self.suites.caller_operation_state(caller).await,
        }
        .expect("the pre-check reads")
    }

    async fn receipt(&self, family: Family, caller: &CallerOperation) -> Option<OperationReceipt> {
        match family {
            Family::Policy(_) | Family::SuggestionAccept => {
                PolicyControlPlane::caller_operation_receipt(&self.policies, caller).await
            }
            Family::Tools => ToolControlPlane::caller_operation_receipt(&self.tools, caller).await,
            Family::PolicyTests => self.suites.caller_operation_receipt(caller).await,
        }
        .expect("the receipt reads")
    }

    async fn seed_open_suggestion(&self, id: &str) {
        use crate::rbac::{PrincipalMatcher, Rule, RuleAction, RuleDispatchMatcher};
        let rule = Rule {
            id: None,
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: format!("/keyed/{id}"),
            tool_name: None,
            dispatch: Some(RuleDispatchMatcher::contextless()),
            principal: PrincipalMatcher {
                roles: vec!["reader".to_owned()],
                issuers: vec!["provider:test".to_owned()],
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: Vec::new(),
            },
            action: RuleAction::Allow,
            conditions: None,
        };
        self.pool
            .get()
            .await
            .expect("suggestion checkout")
            .execute(
                "INSERT INTO greengateway.discovery_rule_suggestions
                     (id, suggestion_type, method, path_pattern, principal_key,
                      proposed_rule_json, rationale, evidence_json, state, created_at,
                      updated_at)
                 VALUES ($1, 'baseline_allow', 'GET', $2, $3, $4, 'seeded', '{}', 'open',
                         '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z')
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &id,
                    &rule.path,
                    &format!("seed:{id}"),
                    &serde_json::to_string(&rule).expect("the rule serializes"),
                ],
            )
            .await
            .expect("the open suggestion seeds");
    }

    async fn suggestion_state(&self, id: &str) -> String {
        self.pool
            .get()
            .await
            .expect("suggestion checkout")
            .query_one(
                "SELECT state FROM greengateway.discovery_rule_suggestions WHERE id = $1",
                &[&id],
            )
            .await
            .expect("the suggestion reads")
            .get(0)
    }

    /// Everything a refused or replayed request must leave as it was.
    async fn footprint(&self) -> Footprint {
        Footprint {
            policy_versions: count(&self.pool, "policy_documents").await,
            tool_versions: count(&self.pool, "tool_documents").await,
            suite_versions: count(&self.pool, "policy_test_suite_versions").await,
            outbox: count(&self.pool, "security_outbox").await,
            evidence: count(&self.pool, "document_change_evidence").await,
            journal: count(&self.pool, "authority_event_journal").await,
            reservations: reservations(&self.pool).await,
            accepted_suggestions: self
                .pool
                .get()
                .await
                .expect("suggestion checkout")
                .query_one(
                    "SELECT count(*) FROM greengateway.discovery_rule_suggestions \
                     WHERE state = 'accepted'",
                    &[],
                )
                .await
                .expect("suggestions count")
                .get(0),
        }
    }
}

fn version_of<T>(outcome: CallerOutcome<T>, version: impl FnOnce(T) -> i64) -> CallerOutcome<i64> {
    match outcome {
        CallerOutcome::Committed(value) => CallerOutcome::Committed(version(value)),
        CallerOutcome::Replayed(receipt) => CallerOutcome::Replayed(receipt),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    policy_versions: i64,
    tool_versions: i64,
    suite_versions: i64,
    outbox: i64,
    evidence: i64,
    journal: i64,
    reservations: Vec<(String, String, Option<String>)>,
    accepted_suggestions: i64,
}

/// Every reservation as `(operation_id, action, binding_digest)`.
async fn reservations(pool: &deadpool_postgres::Pool) -> Vec<(String, String, Option<String>)> {
    pool.get()
        .await
        .expect("reservation checkout")
        .query(
            "SELECT operation_id::text, action, binding_digest \
             FROM greengateway.authority_caller_operation_ids ORDER BY operation_id",
            &[],
        )
        .await
        .expect("reservations read")
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

/// The evidence rows `key` committed, as `(action, resource_type, new_version)`.
async fn rows_for(
    pool: &deadpool_postgres::Pool,
    key: &CallerOperation,
) -> Vec<(String, String, i64)> {
    evidence(pool)
        .await
        .into_iter()
        .filter(|row| row.operation_id == key.id().to_string())
        .map(|row| (row.action, row.resource_type, row.new_version))
        .collect()
}

/// I3: a document action's reservation exists exactly when an evidence row
/// with that operation ID and action exists, for every caller key (keys are
/// UUIDv7; an unkeyed commit mints a UUIDv4 and reserves nothing).
async fn assert_reservations_match_evidence(pool: &deadpool_postgres::Pool) {
    let document_action = |action: &str| {
        action.starts_with("policy.")
            || action.starts_with("policy_tests.")
            || action.starts_with("tools.")
    };
    let reserved: BTreeSet<(String, String)> = reservations(pool)
        .await
        .into_iter()
        .filter(|(_, action, _)| document_action(action))
        .map(|(key, action, _)| (key, action))
        .collect();
    let evidenced: BTreeSet<(String, String)> = evidence(pool)
        .await
        .into_iter()
        .filter(|row| {
            uuid::Uuid::parse_str(&row.operation_id).map(|id| id.get_version_num()) == Ok(7)
        })
        .map(|row| (row.operation_id, row.action))
        .collect();
    assert_eq!(
        reserved, evidenced,
        "every keyed document change is reserved exactly when it is evidenced"
    );
}

fn expect_conflict(outcome: Outcome, what: &str) {
    assert!(
        matches!(outcome, Err(PolicyCommitError::CallerOperationConflict)),
        "{what} should conflict: {outcome:?}"
    );
}

fn committed(outcome: Outcome, what: &str) -> i64 {
    match outcome {
        Ok(CallerOutcome::Committed(version)) => version,
        other => panic!("{what} should commit: {other:?}"),
    }
}

fn replayed(outcome: Outcome, what: &str) -> OperationReceipt {
    match outcome {
        Ok(CallerOutcome::Replayed(receipt)) => receipt,
        other => panic!("{what} should be answered from its receipt: {other:?}"),
    }
}

macro_rules! database_or_skip {
    () => {{
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        admin_dsn
    }};
}

/// An exact retry of every keyed action returns the receipt read from its
/// committed evidence -- also after another writer has moved the ETag the
/// retry carries -- and makes no second change, evidence row, journal entry
/// or reservation. The committed change's evidence row carries the caller's
/// key as its operation ID, and the key is reserved with its binding digest.
/// An unkeyed commit still mints its own operation ID and reserves nothing.
#[tokio::test]
async fn policy_tools_and_policy_tests_caller_operation_contract() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let seed = 10 + index as u8;
        let request = fixture.request(family, &format!("contract-{index}")).await;
        let key = request.key(seed, &actor);
        assert_eq!(fixture.state(family, &key).await, CallerKeyState::Unused);
        assert_eq!(fixture.receipt(family, &key).await, None);

        let version = committed(
            fixture.commit(&request, &actor, Some(&key)).await,
            &format!("the keyed {family:?}"),
        );
        assert_eq!(
            rows_for(&fixture.pool, &key).await,
            [(
                family.action().code().to_owned(),
                family.resource_type().to_owned(),
                version
            )],
            "{family:?}: one evidence row under the caller's key"
        );
        assert!(
            reservations(&fixture.pool).await.contains(&(
                key.id().to_string(),
                family.action().code().to_owned(),
                Some(key.binding_digest().to_owned())
            )),
            "{family:?}: the key is reserved with its binding digest"
        );
        if family == Family::SuggestionAccept {
            assert_eq!(fixture.suggestion_state(&request.target).await, "accepted");
        }

        let receipt = fixture
            .receipt(family, &key)
            .await
            .expect("the committed key has a receipt");
        assert_eq!(receipt.operation_id, key.id().to_string());
        assert_eq!(receipt.operation, family.action().code());
        assert_eq!(receipt.resource_id, family.resource_type());
        assert_eq!(receipt.revision, Some(version));
        assert_eq!(
            fixture.state(family, &key).await,
            CallerKeyState::SameBinding
        );

        let before = fixture.footprint().await;
        let retried = replayed(
            fixture.commit(&request, &actor, Some(&key)).await,
            &format!("the exact retry of {family:?}"),
        );
        assert_eq!(retried, receipt, "{family:?}: the retry is the receipt");
        assert_eq!(fixture.footprint().await, before, "{family:?}: no change");

        // Another writer moves the ETag; the retry still carries the old
        // `If-Match` and is still answered from its receipt, not `412`.
        let moved = fixture.request(family, &format!("moved-{index}")).await;
        committed(
            fixture.commit(&moved, &actor, None).await,
            "the unkeyed writer",
        );
        let before = fixture.footprint().await;
        let retried = replayed(
            fixture.commit(&request, &actor, Some(&key)).await,
            &format!("the retry of {family:?} after the ETag moved"),
        );
        assert_eq!(retried, receipt);
        assert_eq!(fixture.footprint().await, before);
    }

    // The unkeyed writers minted their own operation IDs (UUIDv4) and
    // reserved nothing: only the nine keys are reserved.
    assert_eq!(reservations(&fixture.pool).await.len(), FAMILIES.len());
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// A key reused with a different actor, target, request or `If-Match` is a
/// conflict and changes nothing, for every action; the pre-check reads it as
/// bound to another request.
#[tokio::test]
async fn a_reused_key_with_a_different_binding_conflicts_and_changes_nothing() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let seed = 30 + index as u8;
        let request = fixture.request(family, &format!("bound-{index}")).await;
        let key = request.key(seed, &actor);
        committed(
            fixture.commit(&request, &actor, Some(&key)).await,
            "the first use",
        );
        let current = fixture.etag(family).await;
        let other_actor = ChangeActor::for_test_with_issuer("other-operator", ISSUER);
        let variations = [
            ("another actor", request.clone(), other_actor.clone()),
            (
                "another target",
                Request {
                    target: format!("{}-other", request.target),
                    etag: current.clone(),
                    ..request.clone()
                },
                actor.clone(),
            ),
            (
                "another request",
                Request {
                    variant: format!("bound-{index}-other"),
                    etag: current.clone(),
                    ..request.clone()
                },
                actor.clone(),
            ),
            (
                "another If-Match",
                Request {
                    etag: current.clone(),
                    ..request.clone()
                },
                actor.clone(),
            ),
        ];
        for (what, varied, varied_actor) in variations {
            let reused = varied.key(seed, &varied_actor);
            assert_eq!(
                fixture.state(family, &reused).await,
                CallerKeyState::OtherBinding,
                "{family:?}: {what}"
            );
            let before = fixture.footprint().await;
            expect_conflict(
                fixture.commit(&varied, &varied_actor, Some(&reused)).await,
                &format!("{family:?} with {what}"),
            );
            assert_eq!(fixture.footprint().await, before, "{family:?}: {what}");
        }
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// A key reserved by another action -- another document action, a keyed
/// Connection create, or a keyed service-token revoke (no binding digest) --
/// cannot take effect here; and a key bound to another action than the
/// commit's is refused before anything is written.
#[tokio::test]
async fn a_key_reserved_by_another_action_cannot_take_effect_here() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    // A key first used by a keyed revoke, and one by a keyed Connection
    // create: reserved without, and with, a binding digest.
    let revoke_key = test_caller_key(60);
    let client = fixture.pool.get().await.expect("reservation checkout");
    assert!(
        crate::storage::postgres_authority_events::reserve_caller_operation(
            &client,
            revoke_key,
            "service_token.revoke",
        )
        .await
        .expect("the revoke reserves")
    );
    let connection_key = CallerOperation::bind(
        test_caller_key(61),
        &CallerOperationBinding {
            action: "connection.create",
            actor: &actor,
            target: "",
            precondition: "",
            request: b"{}",
        },
    )
    .expect("the key binds");
    assert_eq!(
        crate::storage::postgres_authority_events::reserve_bound_operation(
            &client,
            &connection_key,
        )
        .await
        .expect("the connection key reserves"),
        crate::authority_events::caller_operation::CallerKeyReservation::Reserved
    );
    drop(client);

    // A key committed by the policy publication.
    let published = fixture
        .request(Family::Policy(DocumentAction::PolicyPublish), "cross-first")
        .await;
    let published_key = published.key(62, &actor);
    committed(
        fixture
            .commit(&published, &actor, Some(&published_key))
            .await,
        "the publication",
    );

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let request = fixture.request(family, &format!("cross-{index}")).await;
        for (what, seed) in [
            ("a keyed revoke's key", 60),
            ("a keyed Connection create's key", 61),
            ("a policy publication's key", 62),
        ] {
            if seed == 62 && family == Family::Policy(DocumentAction::PolicyPublish) {
                continue;
            }
            let reused = request.key(seed, &actor);
            let before = fixture.footprint().await;
            expect_conflict(
                fixture.commit(&request, &actor, Some(&reused)).await,
                &format!("{family:?} under {what}"),
            );
            assert_eq!(fixture.footprint().await, before);
        }

        // A key bound to another action than the commit names.
        let other = if family == Family::Tools {
            Family::PolicyTests
        } else {
            Family::Tools
        };
        let mislabeled = Request {
            family: other,
            ..request.clone()
        }
        .key(70 + index as u8, &actor);
        // That is the gateway's defect, not a reused key: an internal store
        // failure, never `caller_operation_conflict`.
        let before = fixture.footprint().await;
        let outcome = fixture.commit(&request, &actor, Some(&mislabeled)).await;
        assert!(
            matches!(
                &outcome,
                Err(PolicyCommitError::Store(error))
                    if error.kind() == RepositoryErrorKind::Internal
            ),
            "{family:?} under a key bound to {other:?} is an internal failure: {outcome:?}"
        );
        assert_eq!(fixture.footprint().await, before);
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// I1, I2: a keyed commit whose evidence row cannot be written does not
/// happen, and neither does its reservation; the failure is a store failure
/// (`503`), counted with the evidence failures. Once the fault clears the
/// same key commits, which proves nothing was reserved.
#[tokio::test]
async fn a_failed_evidence_insert_rolls_back_the_keyed_document_commit_and_its_reservation() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let evidence_failures =
        || recorder.count(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL, &[]);
    let client = fixture.pool.get().await.expect("trigger checkout");

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let request = fixture.request(family, &format!("faulted-{index}")).await;
        let key = request.key(80 + index as u8, &actor);
        client
            .batch_execute(
                r#"
                CREATE FUNCTION greengateway.fail_document_change_evidence()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'injected evidence failure';
                END;
                $$;
                CREATE TRIGGER fail_document_change_evidence
                BEFORE INSERT ON greengateway.document_change_evidence
                FOR EACH ROW EXECUTE FUNCTION greengateway.fail_document_change_evidence();
                "#,
            )
            .await
            .expect("the failure trigger installs");
        let before = fixture.footprint().await;
        let failures_before = evidence_failures();
        let outcome = fixture.commit(&request, &actor, Some(&key)).await;
        assert!(
            matches!(outcome, Err(PolicyCommitError::Store(_))),
            "{family:?}: a store failure, never a stale ETag or a conflict: {outcome:?}"
        );
        assert_eq!(fixture.footprint().await, before, "{family:?}: nothing");
        assert_eq!(evidence_failures(), failures_before + 1);
        if family == Family::SuggestionAccept {
            assert_eq!(fixture.suggestion_state(&request.target).await, "open");
        }
        client
            .batch_execute(
                "DROP TRIGGER fail_document_change_evidence \
                     ON greengateway.document_change_evidence; \
                 DROP FUNCTION greengateway.fail_document_change_evidence();",
            )
            .await
            .expect("the failure trigger drops");
        committed(
            fixture.commit(&request, &actor, Some(&key)).await,
            &format!("{family:?} once the fault clears"),
        );
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// I2, I4: a full journal refuses every keyed commit as unavailable, and
/// nothing -- not the change, its evidence or its reservation -- is written.
#[tokio::test]
async fn a_full_journal_refuses_the_keyed_document_commit_and_reserves_nothing() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();
    let client = fixture.pool.get().await.expect("journal checkout");
    client
        .batch_execute(
            "UPDATE greengateway.authority_event_state SET capacity = retained_events \
             WHERE singleton",
        )
        .await
        .expect("the journal fills");

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let request = fixture.request(family, &format!("full-{index}")).await;
        let key = request.key(100 + index as u8, &actor);
        let before = fixture.footprint().await;
        let outcome = fixture.commit(&request, &actor, Some(&key)).await;
        assert!(
            matches!(
                &outcome,
                Err(PolicyCommitError::Store(error))
                    if error.kind() == RepositoryErrorKind::Unavailable
            ),
            "{family:?}: unavailable: {outcome:?}"
        );
        assert_eq!(fixture.footprint().await, before, "{family:?}: nothing");
        assert_eq!(fixture.state(family, &key).await, CallerKeyState::Unused);
    }
    client
        .batch_execute(
            "UPDATE greengateway.authority_event_state SET capacity = 1000 WHERE singleton",
        )
        .await
        .expect("the journal empties");
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// An unused key with a stale `If-Match` is `412`: no change, no evidence,
/// no journal entry and no reservation, for every action. Without a
/// reservation, the key stays free for the caller's next attempt.
#[tokio::test]
async fn a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let stale = Request {
            etag: format!("\"stale-{index}\""),
            ..fixture.request(family, &format!("stale-{index}")).await
        };
        let key = stale.key(120 + index as u8, &actor);
        let before = fixture.footprint().await;
        let outcome = fixture.commit(&stale, &actor, Some(&key)).await;
        assert!(
            matches!(outcome, Err(PolicyCommitError::PreconditionFailed)),
            "{family:?}: a stale ETag: {outcome:?}"
        );
        assert_eq!(fixture.footprint().await, before, "{family:?}: nothing");
        assert_eq!(fixture.state(family, &key).await, CallerKeyState::Unused);
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// Two writers racing one key and one binding commit one change; the other
/// is answered from the winner's receipt.
#[tokio::test]
async fn two_writers_racing_one_key_commit_one_change() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let request = fixture.request(family, &format!("raced-{index}")).await;
        let key = request.key(140 + index as u8, &actor);
        if family == Family::SuggestionAccept {
            fixture.seed_open_suggestion(&request.target).await;
        }
        let (left, right) = tokio::join!(
            fixture.commit(&request, &actor, Some(&key)),
            fixture.commit(&request, &actor, Some(&key))
        );
        let (version, receipt) = match (left, right) {
            (Ok(CallerOutcome::Committed(version)), Ok(CallerOutcome::Replayed(receipt)))
            | (Ok(CallerOutcome::Replayed(receipt)), Ok(CallerOutcome::Committed(version))) => {
                (version, receipt)
            }
            other => panic!("{family:?}: one commit and one receipt: {other:?}"),
        };
        assert_eq!(receipt.revision, Some(version));
        assert_eq!(rows_for(&fixture.pool, &key).await.len(), 1, "{family:?}");
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// Two keys racing one revision leave only the winner's rows: the loser is
/// `412` and reserves nothing.
#[tokio::test]
async fn two_keys_racing_one_revision_leave_only_the_winners_rows() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let left = fixture.request(family, &format!("left-{index}")).await;
        let right = Request {
            variant: format!("right-{index}"),
            // Two acceptances accept two suggestions, so they contend only
            // for the policy ETag.
            target: if family == Family::SuggestionAccept {
                format!("{}-right", left.target)
            } else {
                String::new()
            },
            ..left.clone()
        };
        let left_key = left.key(160 + index as u8, &actor);
        let right_key = right.key(180 + index as u8, &actor);
        let before = reservations(&fixture.pool).await.len();
        let (left_outcome, right_outcome) = tokio::join!(
            fixture.commit(&left, &actor, Some(&left_key)),
            fixture.commit(&right, &actor, Some(&right_key))
        );
        let (winner, loser, lost) = match (left_outcome, right_outcome) {
            (Ok(CallerOutcome::Committed(_)), lost) => (&left_key, &right_key, lost),
            (lost, Ok(CallerOutcome::Committed(_))) => (&right_key, &left_key, lost),
            other => panic!("{family:?}: one must win: {other:?}"),
        };
        assert!(
            matches!(lost, Err(PolicyCommitError::PreconditionFailed)),
            "{family:?}: the other loses on its ETag: {lost:?}"
        );
        assert_eq!(rows_for(&fixture.pool, winner).await.len(), 1);
        assert!(rows_for(&fixture.pool, loser).await.is_empty());
        let reserved = reservations(&fixture.pool).await;
        assert_eq!(reserved.len(), before + 1);
        assert!(reserved
            .iter()
            .any(|(key, _, _)| *key == winner.id().to_string()));
        assert!(!reserved
            .iter()
            .any(|(key, _, _)| *key == loser.id().to_string()));
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// The store-level part of I5: markers in every request field a key binds
/// (the target and the canonical request) reach only the binding digest.
/// The reservation row, the receipt, the evidence row and the journal entry
/// carry none of them, and the stored digest is the opaque hex digest.
#[tokio::test]
async fn a_keyed_document_commit_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record()
{
    const TARGET_MARKER: &str = "MARKER-TARGET-7f3a";
    const REQUEST_MARKER: &str = "MARKER-REQUEST-9c1e";
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();

    for (index, family) in FAMILIES.into_iter().enumerate() {
        let request = fixture.request(family, &format!("marked-{index}")).await;
        // The bound fields carry the markers; the committed document is the
        // fixture's own.
        let bound = Request {
            target: format!("{}{TARGET_MARKER}", request.target),
            variant: format!("{}{REQUEST_MARKER}", request.variant),
            ..request.clone()
        };
        let key = bound.key(200 + index as u8, &actor);
        committed(
            fixture.commit(&request, &actor, Some(&key)).await,
            &format!("the marked {family:?}"),
        );
        let receipt = replayed(
            fixture.commit(&request, &actor, Some(&key)).await,
            "the marked retry",
        );
        let digest = key.binding_digest();
        assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

        let client = fixture.pool.get().await.expect("marker checkout");
        let mut surfaces = vec![serde_json::to_string(&receipt).expect("receipt")];
        for sql in [
            "SELECT row_to_json(r)::text FROM greengateway.authority_caller_operation_ids r",
            "SELECT row_to_json(e)::text FROM greengateway.document_change_evidence e",
            "SELECT row_to_json(j)::text FROM greengateway.authority_event_journal j",
        ] {
            surfaces.extend(
                client
                    .query(sql, &[])
                    .await
                    .expect("surface reads")
                    .iter()
                    .map(|row| row.get::<_, String>(0)),
            );
        }
        for surface in surfaces {
            for marker in [TARGET_MARKER, REQUEST_MARKER] {
                assert!(
                    !surface.contains(marker),
                    "{family:?}: {marker} leaked into {surface}"
                );
            }
        }
    }
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// The acceptance's reservation is written inside the acceptance
/// transaction: a process that dies after the policy commit's steps and
/// before the suggestion's transition leaves no reservation, no evidence,
/// no rule and an open suggestion, so the same key commits afterwards. An
/// exact retry of the committed acceptance -- whose suggestion is no longer
/// open -- is answered from its receipt, not refused for the suggestion's
/// state.
#[tokio::test]
async fn a_keyed_suggestion_acceptance_reserves_inside_the_acceptance_transaction() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let fixture = Fixture::new(&database).await;
    let actor = operator();
    let request = fixture
        .request(Family::SuggestionAccept, "transactional")
        .await;
    let key = request.key(220, &actor);
    fixture.seed_open_suggestion(&request.target).await;

    let before = fixture.footprint().await;
    fixture.lifecycle.crash_before_transition_for_tests();
    let crashed = fixture
        .lifecycle
        .accept_suggestion_with_operation(
            AcceptSuggestionRequest {
                suggestion_id: &request.target,
                expected_revision: None,
                actor: actor.subject(),
                policy_commit: PolicyCommitRequest {
                    precondition: PolicyCommitPrecondition::Expected {
                        etag: request.etag.clone(),
                    },
                    candidate: &policy(&request.variant, "reader"),
                    change: DocumentChange {
                        action: DocumentAction::PolicySuggestionAccept,
                        actor: actor.clone(),
                    },
                    diff_summary: &DIFF,
                },
            },
            Some(&key),
        )
        .await;
    assert!(
        matches!(crashed, Err(AcceptRefused::Store(_))),
        "the crash is a failure: {crashed:?}"
    );
    assert_eq!(
        fixture.footprint().await,
        before,
        "the transaction died whole"
    );
    assert_eq!(fixture.suggestion_state(&request.target).await, "open");
    assert_eq!(
        fixture.state(Family::SuggestionAccept, &key).await,
        CallerKeyState::Unused
    );

    let version = committed(
        fixture.commit(&request, &actor, Some(&key)).await,
        "the acceptance",
    );
    assert_eq!(fixture.suggestion_state(&request.target).await, "accepted");
    let receipt = replayed(
        fixture.commit(&request, &actor, Some(&key)).await,
        "the retry of an accepted suggestion",
    );
    assert_eq!(receipt.revision, Some(version));
    assert_eq!(receipt.operation, "policy.suggestion.accept");

    // An unused key for the accepted suggestion is still refused for its
    // state, and reserves nothing.
    let fresh = Request {
        etag: fixture.etag(Family::SuggestionAccept).await,
        ..request.clone()
    };
    let fresh_key = fresh.key(221, &actor);
    let refused = fixture
        .lifecycle
        .accept_suggestion_with_operation(
            AcceptSuggestionRequest {
                suggestion_id: &fresh.target,
                expected_revision: None,
                actor: actor.subject(),
                policy_commit: PolicyCommitRequest {
                    precondition: PolicyCommitPrecondition::Expected {
                        etag: fresh.etag.clone(),
                    },
                    candidate: &policy("fresh", "reader"),
                    change: DocumentChange {
                        action: DocumentAction::PolicySuggestionAccept,
                        actor: actor.clone(),
                    },
                    diff_summary: &DIFF,
                },
            },
            Some(&fresh_key),
        )
        .await;
    assert!(
        matches!(refused, Err(AcceptRefused::Suggestion(_))),
        "{refused:?}"
    );
    assert_eq!(
        fixture.state(Family::SuggestionAccept, &fresh_key).await,
        CallerKeyState::Unused
    );
    assert_reservations_match_evidence(&fixture.pool).await;
}

/// The first-boot tools seed stays the gateway's own unkeyed write: its
/// evidence row names the system actor `bootstrap` under a minted UUIDv4
/// operation ID, it reserves nothing, and a later boot's seed is a no-op.
#[tokio::test]
async fn the_first_boot_seed_stays_a_system_record_and_reserves_nothing() {
    let admin_dsn = database_or_skip!();
    let _guard = DATABASE.lock().await;
    let database = create_test_database(&admin_dsn).await;
    let pool = migrated_pool(&database).await;
    let tools = PostgresToolStore::new(pool.clone());
    tools.seed_empty_document().await.expect("the seed commits");
    let seeded = evidence(&pool).await;
    assert_eq!(seeded.len(), 1);
    let row = &seeded[0];
    assert_eq!(
        (
            row.actor_kind.as_str(),
            row.actor_user_id.as_str(),
            row.actor_issuer.as_deref(),
            row.actor_auth_mode.as_str(),
            row.action.as_str(),
            row.resource_type.as_str(),
        ),
        (
            "system",
            "bootstrap",
            None,
            "system",
            "tools.publish",
            "tools"
        )
    );
    assert!(is_uuid_v4(&row.operation_id));
    assert!(reservations(&pool).await.is_empty());

    tools.seed_empty_document().await.expect("a later seed");
    assert_eq!(evidence(&pool).await, seeded, "a later boot writes nothing");
    assert!(reservations(&pool).await.is_empty());
    assert_reservations_match_evidence(&pool).await;
}
