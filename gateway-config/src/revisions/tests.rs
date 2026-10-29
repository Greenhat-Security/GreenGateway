use std::{
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use super::*;
use crate::bundle::{BundleReport, Code};
use crate::ledger::AuthMode;

/// A role name that must never reach an error, a plan or a record.
const CANARY: &str = "zqcanary";

// --- fixtures -------------------------------------------------------------------

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-revisions-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("temporary directory should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("permissions should set");
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

const DEPLOYMENT: &str = concat!(
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayDeployment\n",
    "spec:\n",
    "  profile: production\n",
);
const TOOLS: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

fn name(text: &str) -> FileName {
    FileName::parse(text).expect("a portable file name")
}

/// A deny-by-default policy granting each of `roles` one permission.
fn policy(roles: &[&str]) -> String {
    let roles: Vec<String> = roles
        .iter()
        .map(|role| format!("\"{role}\": {{\"permissions\": [\"admin:policy:read\"]}}"))
        .collect();
    format!(
        "{{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\",\n  \"roles\": {{{}}}\n}}\n",
        roles.join(", ")
    )
}

/// A complete bundle named `bundle_name` whose policy grants `roles`, with
/// Connections declared server-managed when `connections`.
fn files_with(bundle_name: &str, roles: &[&str], connections: bool) -> BTreeMap<FileName, Vec<u8>> {
    let policy = policy(roles);
    let mut manifest = format!(
        concat!(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayBundle\n",
            "metadata:\n",
            "  name: {name}\n",
            "spec:\n",
            "  deployment:\n",
            "    path: deployment.yaml\n",
            "    sha256: \"{deployment}\"\n",
            "  resources:\n",
            "    policy:\n",
            "      source: bundle\n",
            "      path: policy.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{policy}\"\n",
            "    tools:\n",
            "      source: bundle\n",
            "      path: tools.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{tools}\"\n",
        ),
        name = bundle_name,
        deployment = sha256_pin(DEPLOYMENT.as_bytes()),
        policy = sha256_pin(policy.as_bytes()),
        tools = sha256_pin(TOOLS.as_bytes()),
    );
    if connections {
        manifest.push_str("    connections:\n      source: server\n");
    }
    BTreeMap::from([
        (name("bundle.yaml"), manifest.into_bytes()),
        (name("deployment.yaml"), DEPLOYMENT.as_bytes().to_vec()),
        (name("policy.json"), policy.into_bytes()),
        (name("tools.json"), TOOLS.as_bytes().to_vec()),
    ])
}

fn files(roles: &[&str]) -> BTreeMap<FileName, Vec<u8>> {
    files_with("payments-production", roles, true)
}

fn read(files: BTreeMap<FileName, Vec<u8>>) -> Bundle<Value, Value> {
    let report: BundleReport<Value, Value> =
        read_bundle_files(files, ReadOptions { strict: true }, &PublishedSchemasOnly);
    report
        .bundle
        .unwrap_or_else(|| panic!("fixture bundle should read: {:?}", report.diagnostics))
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
}

fn operator() -> LedgerActor {
    LedgerActor::system("ggctl-ledger-seed").expect("the label is recordable")
}

fn admin() -> LedgerActor {
    LedgerActor::principal("alice", Some("provider:corp"), AuthMode::SessionCookie)
        .expect("the principal is recordable")
}

fn other_admin() -> LedgerActor {
    LedgerActor::principal("bob", Some("provider:corp"), AuthMode::BearerToken)
        .expect("the principal is recordable")
}

fn plan_id(byte: u8) -> PlanId {
    PlanId::from_random([byte; 16])
}

fn everything(_: &str) -> bool {
    true
}

/// A ledger seeded with a policy granting `roles`, activated as a running
/// gateway would, and a service over it.
fn seeded(
    label: &str,
    roles: &[&str],
) -> (
    TempDir,
    RevisionService<PublishedSchemasCompiler>,
    RevisionSummary,
) {
    let state = TempDir::new(label);
    let (mut ledger, seed) =
        RevisionLedger::seed(state.path(), &read(files(roles)), operator(), at(0)).expect("seed");
    ledger.activate(&seed.revision).expect("activate the seed");
    (
        state,
        RevisionService::new(ledger, PublishedSchemasCompiler),
        seed,
    )
}

fn apply_request(plan: &Plan, key: &str, subject: PlanSubject) -> ApplyRequest {
    ApplyRequest {
        plan: plan.id.clone(),
        actor: admin(),
        if_match: Some(plan.base_etag.clone()),
        idempotency_key: Some(key.to_owned()),
        subject,
        stage_only: false,
    }
}

fn code<T: fmt::Debug>(result: Result<T, RevisionError>) -> &'static str {
    match result {
        Ok(value) => panic!("expected an error, found {value:?}"),
        Err(error) => error.code(),
    }
}

fn revisions(service: &mut RevisionService<PublishedSchemasCompiler>) -> u64 {
    service.state().expect("state").revisions
}

// --- plan and apply -----------------------------------------------------------------

#[test]
fn a_plan_reports_the_change_and_its_apply_records_a_live_revision() {
    let (state, mut service, seed) = seeded("live", &["auditor", "operator"]);
    let candidate = files(&["auditor"]);
    let plan = service
        .create_plan(
            plan_id(1),
            admin(),
            PlanSubject::Bundle(candidate.clone()),
            at(10),
        )
        .expect("plan");

    assert_eq!(plan.operation, Operation::Apply);
    assert_eq!(plan.base, seed.revision);
    assert_eq!(plan.base_etag, revision_etag(&seed));
    assert_eq!(plan.source_digest, read(candidate.clone()).source_digest);
    assert!(plan.semantic_digest.starts_with("sha256:"));
    assert_eq!(plan.activation, Some(ActivationClass::Live));
    // Removing a role tightens the policy: no risk, nothing to acknowledge.
    assert!(plan.risk_codes.is_empty(), "{:?}", plan.risk_codes);
    assert!(!plan.needs_acknowledgement());
    assert_eq!(plan.changed_sections, ["policy"]);
    assert_eq!(
        plan.required_permissions,
        [ADMIN_CONFIG_WRITE, ADMIN_POLICY_WRITE]
    );
    assert_eq!(plan.expires_at, at(10) + PLAN_LIFETIME);
    assert!(service.plan(&plan.id, &admin(), at(11)).is_some());

    let applied = service
        .apply(
            apply_request(&plan, "apply-1", PlanSubject::Bundle(candidate)),
            everything,
            at(20),
        )
        .expect("apply");
    assert!(!applied.replayed);
    assert!(applied.desired && applied.active && !applied.restart_pending);
    let revision = &applied.revision;
    assert_eq!(revision.sequence, 2);
    assert_eq!(revision.operation, Operation::Apply);
    assert_eq!(revision.actor, admin());
    assert_eq!(revision.activation, ActivationClass::Live);
    assert_eq!(revision.recorded_at_ms, 1_800_000_020_000);
    assert_eq!(revision.codes.changed_sections(), ["policy"]);
    assert!(revision.codes.risk_codes().is_empty());
    assert_eq!(
        revision.codes.required_permissions(),
        [ADMIN_CONFIG_WRITE, ADMIN_POLICY_WRITE]
    );
    let request = revision.request.as_ref().expect("an online revision");
    assert_eq!(request.plan(), &plan.id);
    assert!(request.has_idempotency_key("apply-1"));
    assert!(!request.has_idempotency_key("apply-2"));
    assert!(request.acknowledged_risks().is_empty());
    assert!(!request.stage_only());

    // The plan is consumed.
    assert!(service.plan(&plan.id, &admin(), at(21)).is_none());
    assert_eq!(
        code(service.apply(
            apply_request(&plan, "apply-2", PlanSubject::Bundle(files(&["auditor"]))),
            everything,
            at(21),
        )),
        "plan.unknown"
    );

    // And the revision survives a reopen with its request.
    drop(service);
    let mut reopened = RevisionLedger::open(state.path()).expect("reopen");
    let verified = reopened.verify().expect("verify");
    assert_eq!(verified.desired, applied.revision);
    assert_eq!(verified.active, Some(applied.revision.revision.clone()));
}

#[test]
fn an_apply_needs_both_preconditions_and_the_current_etag() {
    let (_state, mut service, seed) = seeded("preconditions", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let base = apply_request(&plan, "apply-1", candidate);

    for (request, expected) in [
        (
            ApplyRequest {
                if_match: None,
                ..base.clone()
            },
            "apply.if_match_required",
        ),
        (
            ApplyRequest {
                idempotency_key: None,
                ..base.clone()
            },
            "apply.idempotency_key_required",
        ),
        (
            ApplyRequest {
                idempotency_key: Some("has space".to_owned()),
                ..base.clone()
            },
            "apply.idempotency_key_invalid",
        ),
        (
            ApplyRequest {
                idempotency_key: Some("k".repeat(129)),
                ..base.clone()
            },
            "apply.idempotency_key_invalid",
        ),
        (
            ApplyRequest {
                if_match: Some("*".to_owned()),
                ..base.clone()
            },
            "apply.precondition_failed",
        ),
        (
            ApplyRequest {
                if_match: Some(format!("W/{}", plan.base_etag)),
                ..base.clone()
            },
            "apply.precondition_failed",
        ),
        (
            ApplyRequest {
                if_match: Some(seed.record_hash.clone()),
                ..base.clone()
            },
            "apply.precondition_failed",
        ),
    ] {
        assert_eq!(code(service.apply(request, everything, at(20))), expected);
    }
    match service.apply(
        ApplyRequest {
            if_match: Some("\"stale\"".to_owned()),
            ..base.clone()
        },
        everything,
        at(20),
    ) {
        Err(RevisionError::PreconditionFailed { current }) => {
            assert_eq!(current, revision_etag(&seed));
        }
        other => panic!("expected a failed precondition, found {other:?}"),
    }
    assert_eq!(revisions(&mut service), 1);
    // Nothing consumed the plan.
    service.apply(base, everything, at(20)).expect("apply");
    assert_eq!(revisions(&mut service), 2);
}

#[test]
fn two_applies_on_one_head_have_exactly_one_winner() {
    let (state, mut service, seed) = seeded("winner", &["auditor", "operator"]);
    let first = PlanSubject::Bundle(files(&["auditor"]));
    let second = PlanSubject::Bundle(files(&["operator"]));
    let first_plan = service
        .create_plan(plan_id(1), admin(), first.clone(), at(10))
        .expect("plan");
    let second_plan = service
        .create_plan(plan_id(2), admin(), second.clone(), at(10))
        .expect("plan");
    assert_eq!(first_plan.base_etag, second_plan.base_etag);

    let won = service
        .apply(
            apply_request(&first_plan, "first", first),
            everything,
            at(20),
        )
        .expect("the first apply wins");
    match service.apply(
        apply_request(&second_plan, "second", second.clone()),
        everything,
        at(21),
    ) {
        Err(RevisionError::PreconditionFailed { current }) => {
            assert_eq!(current, revision_etag(&won.revision));
        }
        other => panic!("expected a failed precondition, found {other:?}"),
    }
    // Sending the new ETag does not make the old plan apply over the winner.
    assert_eq!(
        code(service.apply(
            ApplyRequest {
                if_match: Some(revision_etag(&won.revision)),
                ..apply_request(&second_plan, "second", second)
            },
            everything,
            at(21),
        )),
        "plan.stale"
    );
    assert_eq!(revisions(&mut service), 2);

    // Two services on one ledger, as two processes would hold it: both plan
    // against the same head and only the first apply is recorded.
    let mut other = RevisionService::new(
        RevisionLedger::open(state.path()).expect("second handle"),
        PublishedSchemasCompiler,
    );
    let here = PlanSubject::Bundle(files(&["auditor", "reviewer"]));
    let there = PlanSubject::Bundle(files(&["auditor", "deployer"]));
    let here_plan = service
        .create_plan(plan_id(3), admin(), here.clone(), at(30))
        .expect("plan");
    let there_plan = other
        .create_plan(plan_id(3), admin(), there.clone(), at(30))
        .expect("plan");
    service
        .acknowledge(&here_plan.id, &admin(), &here_plan.risk_codes, at(31))
        .expect("acknowledge");
    other
        .acknowledge(&there_plan.id, &admin(), &there_plan.risk_codes, at(31))
        .expect("acknowledge");
    service
        .apply(apply_request(&here_plan, "here", here), everything, at(32))
        .expect("the first process wins");
    assert_eq!(
        code(other.apply(
            apply_request(&there_plan, "there", there),
            everything,
            at(33)
        )),
        "apply.precondition_failed"
    );
    assert_eq!(revisions(&mut other), 3);
    assert_ne!(won.revision.revision, seed.revision);
}

#[test]
fn a_retried_request_replays_its_revision_and_a_reused_key_conflicts() {
    let (_state, mut service, _seed) = seeded("idempotency", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let request = apply_request(&plan, "apply-1", candidate.clone());
    let applied = service
        .apply(request.clone(), everything, at(20))
        .expect("apply");

    // The same request again, after the plan is consumed and with the head
    // already moved by it: the prior answer, and nothing written.
    let replayed = service
        .apply(request.clone(), everything, at(25))
        .expect("replay");
    assert!(replayed.replayed);
    assert_eq!(replayed.revision, applied.revision);
    assert!(replayed.desired && replayed.active);
    assert_eq!(revisions(&mut service), 2);

    // What an ambiguous outcome is resolved with: a read by key.
    let status = service
        .operation("apply-1")
        .expect("operation read")
        .expect("the key made a revision");
    assert_eq!(status.revision, applied.revision);
    assert!(status.desired && status.active && !status.restart_pending);
    assert!(service.operation("never-sent").expect("read").is_none());
    assert!(service.operation("not a key").expect("read").is_none());

    // The same identity retrying through another authentication path is the
    // same request.
    let by_bearer = LedgerActor::principal("alice", Some("provider:corp"), AuthMode::BearerToken)
        .expect("principal");
    let replayed = service
        .apply(
            ApplyRequest {
                actor: by_bearer,
                ..request.clone()
            },
            everything,
            at(26),
        )
        .expect("replay");
    assert!(replayed.replayed);
    assert_eq!(replayed.revision, applied.revision);

    // The same key on any other request conflicts.
    for different in [
        ApplyRequest {
            stage_only: true,
            ..request.clone()
        },
        ApplyRequest {
            plan: plan_id(9),
            ..request.clone()
        },
        ApplyRequest {
            subject: PlanSubject::Bundle(files(&["operator"])),
            ..request.clone()
        },
        ApplyRequest {
            actor: other_admin(),
            ..request.clone()
        },
        ApplyRequest {
            if_match: Some("\"other\"".to_owned()),
            ..request
        },
    ] {
        assert_eq!(
            code(service.apply(different, everything, at(30))),
            "apply.idempotency_conflict"
        );
    }
    assert_eq!(revisions(&mut service), 2);
}

#[test]
fn the_server_recompiles_and_refuses_a_plan_that_no_longer_matches() {
    let (_state, mut service, _seed) = seeded("recompile", &["auditor", "operator"]);
    let planned = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), planned.clone(), at(10))
        .expect("plan");

    // Other bytes than the plan's, or another kind of subject.
    for subject in [
        PlanSubject::Bundle(files(&["operator"])),
        PlanSubject::Bundle(files_with("payments-staging", &["auditor"], true)),
        PlanSubject::Rollback(plan.base.clone()),
    ] {
        assert_eq!(
            code(service.apply(apply_request(&plan, "apply-x", subject), everything, at(20))),
            "plan.stale"
        );
    }
    assert_eq!(revisions(&mut service), 1);
    // The plan itself still applies.
    service
        .apply(apply_request(&plan, "apply-1", planned), everything, at(20))
        .expect("apply");
}

#[test]
fn risky_changes_need_an_acknowledgement_of_exactly_their_risk_codes() {
    let (_state, mut service, _seed) = seeded("risk", &["auditor"]);
    let candidate = PlanSubject::Bundle(files(&["auditor", "operator"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(0))
        .expect("plan");
    assert_eq!(plan.risk_codes, ["risk.policy_broadened"]);
    assert!(plan.needs_acknowledgement() && plan.acknowledgeable_online());
    assert_eq!(
        plan.diff.risks(),
        BTreeSet::from([RiskCode::PolicyBroadened])
    );

    let request = apply_request(&plan, "apply-1", candidate);
    assert_eq!(
        code(service.apply(request.clone(), everything, at(10))),
        "apply.acknowledgement_required"
    );
    let none: &[&str] = &[];
    for wrong in [
        none,
        &["risk.unknown_impact"],
        &["risk.policy_broadened", "risk.unknown_impact"],
    ] {
        assert_eq!(
            code(service.acknowledge(&plan.id, &admin(), wrong, at(10))),
            "plan.acknowledgement_mismatch"
        );
    }
    // Only the plan's owner can acknowledge it.
    assert_eq!(
        code(service.acknowledge(&plan.id, &other_admin(), &plan.risk_codes, at(10))),
        "plan.unknown"
    );

    let acknowledged = service
        .acknowledge(&plan.id, &admin(), &["risk.policy_broadened"], at(60))
        .expect("acknowledge");
    let acknowledgement = acknowledged.acknowledgement.expect("acknowledged");
    assert_eq!(acknowledgement.risk_codes, ["risk.policy_broadened"]);
    assert_eq!(
        acknowledgement.expires_at,
        at(60) + ACKNOWLEDGEMENT_LIFETIME
    );

    // An expired acknowledgement acknowledges nothing; a new one never
    // outlives its plan.
    assert_eq!(
        code(service.apply(request.clone(), everything, at(60 + 10 * 60))),
        "apply.acknowledgement_required"
    );
    let renewed = service
        .acknowledge(&plan.id, &admin(), &plan.risk_codes, at(12 * 60))
        .expect("acknowledge again");
    assert_eq!(
        renewed.acknowledgement.expect("acknowledged").expires_at,
        plan.expires_at
    );
    let applied = service
        .apply(request, everything, at(13 * 60))
        .expect("apply");
    assert_eq!(
        applied.revision.codes.risk_codes(),
        ["risk.policy_broadened"]
    );
    let request = applied.revision.request.expect("an online revision");
    assert_eq!(request.acknowledged_risks(), ["risk.policy_broadened"]);

    // A plan without risk has nothing to acknowledge.
    let quiet = service
        .create_plan(
            plan_id(2),
            admin(),
            PlanSubject::Bundle(files(&["auditor"])),
            at(14 * 60),
        )
        .expect("plan");
    assert_eq!(
        code(service.acknowledge(&quiet.id, &admin(), none, at(14 * 60))),
        "plan.nothing_to_acknowledge"
    );
}

#[test]
fn an_apply_needs_the_union_of_its_permissions() {
    let (_state, mut service, _seed) = seeded("permissions", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let request = apply_request(&plan, "apply-1", candidate);
    match service.apply(
        request.clone(),
        |permission| permission == ADMIN_CONFIG_WRITE,
        at(20),
    ) {
        Err(RevisionError::Forbidden(missing)) => assert_eq!(missing, [ADMIN_POLICY_WRITE]),
        other => panic!("expected a refusal, found {other:?}"),
    }
    match service.apply(
        request.clone(),
        |permission| permission == ADMIN_POLICY_WRITE,
        at(20),
    ) {
        Err(RevisionError::Forbidden(missing)) => assert_eq!(missing, [ADMIN_CONFIG_WRITE]),
        other => panic!("expected a refusal, found {other:?}"),
    }
    assert_eq!(revisions(&mut service), 1);
    service
        .apply(request, everything, at(20))
        .expect("with every permission");
}

#[test]
fn restart_changes_are_staged_only_and_a_pending_restart_stages_everything() {
    let (_state, mut service, seed) = seeded("restart", &["auditor", "operator"]);
    let renamed = PlanSubject::Bundle(files_with(
        "payments-renamed",
        &["auditor", "operator"],
        true,
    ));
    let plan = service
        .create_plan(plan_id(1), admin(), renamed.clone(), at(10))
        .expect("plan");
    assert_eq!(plan.activation, Some(ActivationClass::Restart));
    assert_eq!(plan.required_permissions, [ADMIN_CONFIG_WRITE]);
    let request = apply_request(&plan, "rename", renamed);
    assert_eq!(
        code(service.apply(request.clone(), everything, at(20))),
        "apply.restart_required"
    );
    let staged = service
        .apply(
            ApplyRequest {
                stage_only: true,
                ..request
            },
            everything,
            at(20),
        )
        .expect("staged");
    assert!(staged.desired && !staged.active && staged.restart_pending);
    assert!(staged
        .revision
        .request
        .as_ref()
        .expect("request")
        .stage_only());
    let state = service.state().expect("state");
    assert_eq!(state.desired.revision, staged.revision.revision);
    assert_eq!(state.active, Some(seed.revision.clone()));

    // While the restart is pending, even a live change is staged only.
    let live = PlanSubject::Bundle(files_with("payments-renamed", &["auditor"], true));
    let plan = service
        .create_plan(plan_id(2), admin(), live.clone(), at(30))
        .expect("plan");
    assert_eq!(plan.activation, Some(ActivationClass::Live));
    let request = apply_request(&plan, "live", live);
    assert_eq!(
        code(service.apply(request.clone(), everything, at(31))),
        "apply.restart_pending"
    );
    let staged = service
        .apply(
            ApplyRequest {
                stage_only: true,
                ..request
            },
            everything,
            at(31),
        )
        .expect("staged");
    assert!(staged.desired && !staged.active && staged.restart_pending);
    assert_eq!(service.state().expect("state").active, Some(seed.revision));
}

#[test]
fn a_live_change_staged_only_leaves_the_active_revision() {
    let (_state, mut service, seed) = seeded("stage-live", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let staged = service
        .apply(
            ApplyRequest {
                stage_only: true,
                ..apply_request(&plan, "stage", candidate)
            },
            everything,
            at(20),
        )
        .expect("staged");
    assert_eq!(staged.revision.activation, ActivationClass::Live);
    assert!(staged.desired && !staged.active && staged.restart_pending);
    assert_eq!(service.state().expect("state").active, Some(seed.revision));
}

#[test]
fn a_ledger_not_yet_activated_takes_staged_revisions_only() {
    let state = TempDir::new("unactivated");
    let (ledger, _seed) = RevisionLedger::seed(
        state.path(),
        &read(files(&["auditor", "operator"])),
        operator(),
        at(0),
    )
    .expect("seed");
    let mut service = RevisionService::new(ledger, PublishedSchemasCompiler);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    assert_eq!(
        code(service.apply(
            apply_request(&plan, "apply-1", candidate),
            everything,
            at(20)
        )),
        "apply.restart_pending"
    );
}

// --- rollback and history -------------------------------------------------------------

#[test]
fn a_rollback_is_a_new_forward_revision_from_prior_content() {
    let (_state, mut service, seed) = seeded("rollback", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let second = service
        .apply(
            apply_request(&plan, "apply-1", candidate),
            everything,
            at(20),
        )
        .expect("apply")
        .revision;

    // Rolling back restores a role, which broadens the policy again.
    let target = PlanSubject::Rollback(seed.revision.clone());
    let plan = service
        .create_plan(plan_id(2), admin(), target.clone(), at(30))
        .expect("rollback plan");
    assert_eq!(
        plan.operation,
        Operation::Rollback {
            target: seed.revision.clone()
        }
    );
    assert_eq!(plan.base, second.revision);
    assert_eq!(plan.source_digest, seed.bundle.source_digest);
    assert_eq!(plan.risk_codes, ["risk.policy_broadened"]);
    // A rollback plan applies only as its own target.
    assert_eq!(
        code(service.apply(
            apply_request(
                &plan,
                "rollback-x",
                PlanSubject::Rollback(second.revision.clone())
            ),
            everything,
            at(31),
        )),
        "plan.stale"
    );
    assert_eq!(
        code(service.apply(
            apply_request(
                &plan,
                "rollback-y",
                PlanSubject::Bundle(files(&["auditor", "operator"]))
            ),
            everything,
            at(31),
        )),
        "plan.stale"
    );
    service
        .acknowledge(&plan.id, &admin(), &plan.risk_codes, at(31))
        .expect("acknowledge");
    let third = service
        .apply(
            apply_request(&plan, "rollback-1", target),
            everything,
            at(32),
        )
        .expect("roll back")
        .revision;
    assert_eq!(third.sequence, 3);
    assert_eq!(
        third.operation,
        Operation::Rollback {
            target: seed.revision.clone()
        }
    );
    assert_eq!(third.bundle.source_digest, seed.bundle.source_digest);
    assert_eq!(
        third.parent.as_ref().map(|parent| &parent.revision),
        Some(&second.revision)
    );

    // History is append-only and newest first.
    let history: Vec<_> = service
        .history(None, 10)
        .expect("history")
        .into_iter()
        .map(|revision| revision.revision)
        .collect();
    assert_eq!(
        history,
        [
            third.revision.clone(),
            second.revision.clone(),
            seed.revision.clone()
        ]
    );
    let page: Vec<_> = service
        .history(Some(3), 1)
        .expect("page")
        .into_iter()
        .map(|revision| revision.revision)
        .collect();
    assert_eq!(page, std::slice::from_ref(&second.revision));

    // The seed's content again changes nothing; the head and unknown
    // revisions are refused.
    let unchanged = service
        .create_plan(
            plan_id(3),
            admin(),
            PlanSubject::Rollback(seed.revision.clone()),
            at(40),
        )
        .expect("plan");
    assert_eq!(unchanged.activation, None);
    assert!(unchanged.diff.is_empty());
    assert_eq!(
        code(service.apply(
            apply_request(
                &unchanged,
                "rollback-2",
                PlanSubject::Rollback(seed.revision)
            ),
            everything,
            at(41),
        )),
        "apply.no_change"
    );
    assert_eq!(
        code(service.create_plan(
            plan_id(4),
            admin(),
            PlanSubject::Rollback(third.revision),
            at(42)
        )),
        "plan.rollback_target_is_head"
    );
    let unknown = RevisionId::parse(&format!("rev-{}", "0".repeat(32))).expect("an ID");
    assert_eq!(
        code(service.create_plan(plan_id(5), admin(), PlanSubject::Rollback(unknown), at(42))),
        "plan.rollback_target_unknown"
    );
    assert_eq!(revisions(&mut service), 3);
}

/// Validators that have grown stricter since a revision was recorded: they
/// refuse any policy granting a role named `legacy`.
struct RefusesLegacy;

impl ResourceValidators for RefusesLegacy {
    type Policy = Value;
    type Tools = Value;

    fn policy(&self, document: Value) -> Option<Value> {
        document
            .pointer("/roles/legacy")
            .is_none()
            .then_some(document)
    }

    fn tools(&self, document: Value) -> Option<Value> {
        Some(document)
    }
}

struct StricterCompiler;

impl PlanCompiler for StricterCompiler {
    type Validators = RefusesLegacy;

    fn validators(&self) -> &RefusesLegacy {
        &RefusesLegacy
    }

    fn policy_value(&self, policy: &Value) -> Option<Value> {
        Some(policy.clone())
    }

    fn tools_value(&self, _: &'static str, tools: &Value) -> Option<Value> {
        Some(tools.clone())
    }
}

#[test]
fn stored_content_is_held_to_the_current_validators() {
    let (state, mut service, seed) = seeded("validators", &["legacy"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(1), admin(), candidate.clone(), at(10))
        .expect("plan");
    let risks = plan.risk_codes.clone();
    if !risks.is_empty() {
        service
            .acknowledge(&plan.id, &admin(), &risks, at(10))
            .expect("acknowledge");
    }
    service
        .apply(
            apply_request(&plan, "apply-1", candidate),
            everything,
            at(20),
        )
        .expect("apply");
    drop(service);

    // A rollback to content the current validators refuse is refused, with
    // the reader's own diagnostics.
    let mut stricter = RevisionService::new(
        RevisionLedger::open(state.path()).expect("reopen"),
        StricterCompiler,
    );
    match stricter.create_plan(
        plan_id(2),
        admin(),
        PlanSubject::Rollback(seed.revision.clone()),
        at(30),
    ) {
        Err(RevisionError::Invalid(diagnostics)) => {
            assert!(diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == Code::ResourceInvalid));
        }
        other => panic!("expected an invalid rollback target, found {other:?}"),
    }

    // A head the current validators refuse cannot be planned against.
    let state = TempDir::new("stricter-head");
    let (ledger, _seed) =
        RevisionLedger::seed(state.path(), &read(files(&["legacy"])), operator(), at(0))
            .expect("seed");
    let mut stricter = RevisionService::new(ledger, StricterCompiler);
    assert_eq!(
        code(stricter.create_plan(
            plan_id(3),
            admin(),
            PlanSubject::Bundle(files(&["auditor"])),
            at(10)
        )),
        "plan.base_invalid"
    );
}

// --- refusals at plan time ---------------------------------------------------------------

#[test]
fn a_plan_refuses_invalid_candidates_and_changes_no_revision_carries() {
    let (_state, mut service, _seed) = seeded("refusals", &["auditor"]);

    // Connections are a #240 authority: no bundle revision changes them.
    match service.create_plan(
        plan_id(1),
        admin(),
        PlanSubject::Bundle(files_with("payments-production", &["auditor"], false)),
        at(10),
    ) {
        Err(RevisionError::NotApplicable(classes)) => {
            assert_eq!(classes, ["connection_or_secret"]);
        }
        other => panic!("expected an inapplicable change, found {other:?}"),
    }

    // The reader's diagnostics, value-free, for a broken candidate; an
    // unreferenced extra file is refused too.
    let mut broken = files(&["auditor"]);
    broken.insert(name("policy.json"), policy(&[CANARY]).into_bytes());
    match service.create_plan(plan_id(2), admin(), PlanSubject::Bundle(broken), at(10)) {
        Err(RevisionError::Invalid(diagnostics)) => {
            assert!(diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == Code::DigestMismatch));
            assert!(!format!("{diagnostics:?}").contains(CANARY));
        }
        other => panic!("expected an invalid candidate, found {other:?}"),
    }
    let mut extra = files(&["auditor"]);
    extra.insert(name("notes.txt"), b"notes\n".to_vec());
    assert_eq!(
        code(service.create_plan(plan_id(3), admin(), PlanSubject::Bundle(extra), at(10))),
        "plan.candidate_invalid"
    );

    // The same content is a plan with nothing to apply.
    let unchanged = PlanSubject::Bundle(files(&["auditor"]));
    let plan = service
        .create_plan(plan_id(4), admin(), unchanged.clone(), at(10))
        .expect("plan");
    assert_eq!(plan.activation, None);
    assert!(plan.risk_codes.is_empty() && plan.changed_sections.is_empty());
    assert_eq!(
        code(service.apply(
            apply_request(&plan, "apply-1", unchanged),
            everything,
            at(20)
        )),
        "apply.no_change"
    );
    assert_eq!(revisions(&mut service), 1);
}

#[test]
fn plans_are_owner_scoped_bounded_and_expire() {
    let (_state, mut service, _seed) = seeded("plans", &["auditor", "operator"]);
    let candidate = PlanSubject::Bundle(files(&["auditor"]));
    for index in 0..MAX_PLANS_PER_ACTOR {
        let id = u8::try_from(index).expect("small");
        service
            .create_plan(plan_id(id), admin(), candidate.clone(), at(10))
            .expect("within the actor's bound");
    }
    assert_eq!(
        code(service.create_plan(plan_id(200), admin(), candidate.clone(), at(10))),
        "plan.quota_exceeded"
    );
    // The same principal authenticated another way is the same owner.
    let by_bearer = LedgerActor::principal("alice", Some("provider:corp"), AuthMode::BearerToken)
        .expect("principal");
    assert!(service.plan(&plan_id(0), &by_bearer, at(11)).is_some());
    assert_eq!(
        code(service.create_plan(plan_id(200), by_bearer, candidate.clone(), at(10))),
        "plan.quota_exceeded"
    );

    // Another actor can plan, but cannot read, acknowledge or apply someone
    // else's plan, and cannot reuse a live plan's ID.
    let theirs = service
        .create_plan(plan_id(100), other_admin(), candidate.clone(), at(10))
        .expect("another actor's plan");
    assert!(service.plan(&theirs.id, &admin(), at(11)).is_none());
    assert!(service.plan(&theirs.id, &other_admin(), at(11)).is_some());
    assert_eq!(
        code(service.create_plan(plan_id(100), admin(), candidate.clone(), at(10))),
        "plan.id_in_use"
    );
    assert_eq!(
        code(service.apply(
            apply_request(&theirs, "apply-1", candidate.clone()),
            everything,
            at(20)
        )),
        "plan.unknown"
    );

    // Plans expire after their lifetime, and their quota frees up.
    let expired = at(10) + PLAN_LIFETIME;
    assert!(service.plan(&plan_id(0), &admin(), expired).is_none());
    assert_eq!(
        code(service.apply(
            ApplyRequest {
                actor: other_admin(),
                ..apply_request(&theirs, "apply-2", candidate.clone())
            },
            everything,
            expired,
        )),
        "plan.unknown"
    );
    service
        .create_plan(plan_id(0), admin(), candidate.clone(), expired)
        .expect("the quota is free again");

    // And the deployment's bound holds across actors.
    let mut made = 1;
    for index in 0..MAX_PLANS {
        let actor = LedgerActor::principal(
            &format!("user{}", index / MAX_PLANS_PER_ACTOR),
            Some("provider:corp"),
            AuthMode::BearerToken,
        )
        .expect("principal");
        let mut bytes = [0_u8; 16];
        bytes[0] = 7;
        bytes[1] = u8::try_from(index).expect("small");
        let created = service.create_plan(
            PlanId::from_random(bytes),
            actor,
            candidate.clone(),
            expired,
        );
        if made < MAX_PLANS {
            created.expect("within the deployment's bound");
            made += 1;
        } else {
            assert_eq!(code(created), "plan.quota_exceeded");
        }
    }
}

// --- unit rules -----------------------------------------------------------------------------

#[test]
fn an_admin_access_path_removal_is_not_acknowledgeable_online() {
    assert_eq!(
        unacknowledgeable(&[
            "risk.admin_access_path_removed".to_owned(),
            "risk.policy_broadened".to_owned()
        ]),
        ["risk.admin_access_path_removed"]
    );
    assert!(unacknowledgeable(&["risk.policy_broadened".to_owned()]).is_empty());
}

#[test]
fn required_permissions_follow_every_touched_resource() {
    let base = read(files(&["auditor"]));
    let tools = concat!(
        "{\"schema_version\": \"0.1.0\", \"tools\": [{\"name\": \"lookup\", ",
        "\"description\": \"Look up\", \"input_json_schema\": {\"type\": \"object\", ",
        "\"properties\": {}, \"additionalProperties\": false}, \"upstream\": ",
        "{\"method\": \"POST\", \"path_template\": \"/v1/echo\", ",
        "\"body\": {\"mode\": \"whole_args_json\"}}}]}\n"
    );
    let mut candidate_files = files(&["auditor"]);
    let manifest = String::from_utf8(candidate_files[&name("bundle.yaml")].clone())
        .expect("UTF-8")
        .replace(&sha256_pin(TOOLS.as_bytes()), &sha256_pin(tools.as_bytes()));
    candidate_files.insert(name("bundle.yaml"), manifest.into_bytes());
    candidate_files.insert(name("tools.json"), tools.as_bytes().to_vec());
    let report: BundleReport<Value, Value> = read_bundle_files(
        candidate_files,
        ReadOptions { strict: true },
        &PublishedSchemasOnly,
    );
    let Some(candidate) = report.bundle else {
        // The published tools schema decides what a tool needs; a fixture
        // it refuses says nothing about permissions.
        panic!("tools fixture should read: {:?}", report.diagnostics);
    };
    let compiled = |bundle: Bundle<Value, Value>| {
        let policy = match &bundle.policy {
            Some(BundledResource::Bundle { document, .. }) => Some(document.clone()),
            _ => None,
        };
        let tools = match &bundle.tools {
            Some(BundledResource::Bundle { document, .. }) => Some(document.clone()),
            _ => None,
        };
        let semantic_digest =
            semantic_digest(&bundle, policy.as_ref(), tools.as_ref()).expect("digest");
        Compiled {
            bundle,
            policy,
            tools,
            semantic_digest,
        }
    };
    let (base, candidate) = (compiled(base), compiled(candidate));
    assert_ne!(base.semantic_digest, candidate.semantic_digest);
    let diff = diff(&base, &candidate);
    assert_eq!(
        required_permissions(&diff),
        [ADMIN_CONFIG_WRITE, ADMIN_TOOLS_WRITE]
    );
}

#[test]
fn a_semantic_digest_ignores_formatting_but_not_meaning() {
    let digest = |policy_text: &str| {
        let mut files = files(&["auditor"]);
        let manifest = String::from_utf8(files[&name("bundle.yaml")].clone())
            .expect("UTF-8")
            .replace(
                &sha256_pin(policy(&["auditor"]).as_bytes()),
                &sha256_pin(policy_text.as_bytes()),
            );
        files.insert(name("bundle.yaml"), manifest.into_bytes());
        files.insert(name("policy.json"), policy_text.as_bytes().to_vec());
        compile(&PublishedSchemasCompiler, files)
            .unwrap_or_else(|_| panic!("fixture should compile"))
            .semantic_digest
    };
    let written = policy(&["auditor"]);
    let reformatted = "{\"roles\":{\"auditor\":{\"permissions\":[\"admin:policy:read\"]}},\"default_action\":\"deny\",\"schema_version\":\"0.1.0\"}\n";
    assert_eq!(digest(&written), digest(reformatted));
    assert_ne!(digest(&written), digest(&policy(&["operator"])));
}

#[test]
fn errors_are_stable_and_value_free() {
    let errors = [
        RevisionError::PreconditionRequired(Precondition::IfMatch),
        RevisionError::PreconditionRequired(Precondition::IdempotencyKey),
        RevisionError::IdempotencyKeyInvalid,
        RevisionError::PreconditionFailed {
            current: "\"sha256:00\"".to_owned(),
        },
        RevisionError::RollbackTargetUnknown,
        RevisionError::RollbackTargetIsHead,
        RevisionError::Invalid(Vec::new()),
        RevisionError::BaseInvalid,
        RevisionError::NotNormalizable,
        RevisionError::NotApplicable(vec!["connection_or_secret"]),
        RevisionError::Unclassified,
        RevisionError::QuotaExceeded,
        RevisionError::PlanIdInUse,
        RevisionError::PlanUnknown,
        RevisionError::PlanStale,
        RevisionError::NoChange,
        RevisionError::AcknowledgementRequired,
        RevisionError::AcknowledgementMismatch,
        RevisionError::NothingToAcknowledge,
        RevisionError::NotAcknowledgeable(vec!["risk.admin_access_path_removed"]),
        RevisionError::IdempotencyConflict,
        RevisionError::Forbidden(vec![ADMIN_POLICY_WRITE]),
        RevisionError::RestartRequired,
        RevisionError::RestartPending,
        RevisionError::Ledger(LedgerError::Full),
    ];
    let mut codes = BTreeSet::new();
    for error in &errors {
        let code = error.code();
        let (family, reason) = code.split_once('.').expect("family.reason");
        assert!(["apply", "plan", "ledger"].contains(&family), "{code}");
        assert!(reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        assert!(codes.insert(code), "{code} is used twice");
        let text = error.to_string();
        assert!(!text.is_empty() && !text.contains(CANARY));
    }
}
