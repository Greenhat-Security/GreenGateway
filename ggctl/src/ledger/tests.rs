use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::SystemTime,
};

use gateway_config::{
    bundle::{read_bundle, PublishedSchemasOnly, ReadOptions},
    ledger::{
        ActivationClass, ActorKind, AuthMode, Corruption, LedgerActor, LedgerError, Proposal,
        RevisionCodes, RevisionId, RevisionLedger, LEDGER_FILE_NAME,
    },
    state_dir::{StateDirError, StateDirectory},
};
use serde_json::{json, Value};

use super::*;
use crate::validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY};

/// A standalone state directory under the system temporary directory,
/// removed on drop.
struct State(PathBuf);

impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl State {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the state directory should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("permissions should set");
        }
        Self(root)
    }

    fn path(&self) -> &str {
        self.0
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }

    fn ledger(&self) -> PathBuf {
        self.0.join(LEDGER_FILE_NAME)
    }

    /// The ledger's pointer, read through the library under the lock.
    fn state(&self) -> gateway_config::ledger::LedgerState {
        let held = StateDirectory::acquire(&self.0).expect("the state directory locks");
        RevisionLedger::inspect(&held).expect("the ledger verifies")
    }
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

fn roles_bundle(roles: &[&str]) -> Fixture {
    Fixture::with("production", &policy(roles))
}

fn seeded_ledger(fixture: &Fixture, state: &State) -> Value {
    let (exit, captured) = run(&[
        "ledger",
        "seed",
        fixture.path(),
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stdout());
    report(&captured)
}

fn assert_paths_not_echoed(captured: &crate::report::tests::Captured, paths: &[&str]) {
    let all = format!("{}{}", captured.stdout(), captured.stderr());
    for path in paths {
        assert!(!all.contains(path), "a path reached the output: {all}");
    }
}

/// Appends a revision as a gateway applying `fixture` online would, by an
/// authenticated principal whose subject is the canary.
fn apply_online(state: &State, fixture: &Fixture) -> RevisionId {
    let held = StateDirectory::acquire(&state.0).expect("the state directory locks");
    let mut ledger = RevisionLedger::open(&held).expect("the ledger opens");
    let read = read_bundle(
        &fixture.root,
        ReadOptions { strict: true },
        &PublishedSchemasOnly,
    );
    let candidate = read.bundle.expect("the fixture bundle reads");
    let head = ledger.state().expect("state").desired.revision;
    let actor = LedgerActor::principal(CANARY, Some("provider:corp"), AuthMode::SessionCookie)
        .expect("recordable");
    ledger
        .append(
            &head,
            Proposal {
                bundle: &candidate,
                actor,
                operation: Operation::Apply,
                activation: ActivationClass::Live,
                codes: RevisionCodes::none(),
                request: None,
                recorded_at: SystemTime::now(),
            },
        )
        .expect("the revision appends")
        .revision
}

#[test]
fn seeding_creates_a_ledger_that_verifies_and_is_never_seeded_over() {
    let fixture = roles_bundle(&["auditor", CANARY]);
    let state = State::new();
    let (exit, captured) = run(&[
        "ledger",
        "seed",
        fixture.path(),
        "--state-dir",
        state.path(),
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    let stdout = captured.stdout();
    assert!(
        stdout.starts_with(
            "bundle payments-production (greengateway.dev/v1alpha1): seeded a new configuration ledger\n"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("\n  desired        rev-"), "{stdout}");
    assert!(
        stdout.contains(" (sequence 1, seed, bundle payments-production)\n  active         none\n")
    );
    assert!(!captured
        .stderr()
        .contains("validate.production_validators_not_run"));
    assert!(captured
        .stderr()
        .contains("ggctl: info: ledger.gateway_recompiles_at_start: "));
    assert_no_canary(&captured);
    assert_paths_not_echoed(&captured, &[fixture.path(), state.path()]);

    let (exit, captured) = run(&[
        "ledger",
        "verify",
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["command"], "ledger verify");
    assert_eq!(codes(&found), ["ledger.gateway_recompiles_at_start"]);
    let ledger = &found["result"]["ledger"];
    assert_eq!(found["result"]["verified"], true);
    assert_eq!(ledger["revisions"], 1);
    assert_eq!(ledger["active"], Value::Null);
    assert_eq!(ledger["restartPending"], true);
    let desired = &ledger["desired"];
    assert_eq!(desired["sequence"], 1);
    assert_eq!(desired["operation"], "seed");
    assert_eq!(desired["actorKind"], "system");
    assert_eq!(desired["activation"], "restart");
    assert_eq!(desired["appliedOnline"], false);
    assert_eq!(desired["bundle"]["name"], "payments-production");
    let recorded = state.state();
    assert_eq!(recorded.desired.actor.subject(), ACTOR_LABEL);
    assert_eq!(recorded.desired.actor.kind(), ActorKind::System);
    assert_eq!(desired["revision"], recorded.desired.revision.as_str());

    // A second seed is refused and changes nothing.
    let before = fs::read(state.ledger()).expect("the ledger");
    let (exit, captured) = run(&[
        "ledger",
        "seed",
        fixture.path(),
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Conflict);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(found["result"]["seeded"], false);
    assert!(codes(&found).contains(&"ledger.exists".to_owned()));
    assert_eq!(fs::read(state.ledger()).expect("the ledger"), before);
    assert_eq!(state.state().revisions, 1);

    // So is a seed beside a previous ledger's journal file, which a new
    // ledger could replay.
    for suffix in ["-wal", "-shm", "-journal"] {
        let state = State::new();
        fs::write(
            state.0.join(format!("{LEDGER_FILE_NAME}{suffix}")),
            b"journal",
        )
        .expect("the leftover should write");
        let (exit, captured) = run(&[
            "ledger",
            "seed",
            fixture.path(),
            "--state-dir",
            state.path(),
        ]);
        assert_eq!(exit, Exit::Conflict, "{suffix}");
        assert!(captured.stderr().contains("ggctl: error: ledger.exists: "));
        assert!(!state.ledger().exists(), "{suffix}");
    }
}

#[test]
fn an_invalid_bundle_or_state_directory_seeds_nothing() {
    let fixture = roles_bundle(&["auditor"]);
    // Strict: an entry the manifest does not reference is an error.
    fixture.write("notes.txt", "unreferenced");
    let state = State::new();
    let (exit, captured) = run(&[
        "ledger",
        "seed",
        fixture.path(),
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], false);
    assert_eq!(found["result"]["seeded"], false);
    assert!(codes(&found).contains(&"bundle.unreferenced_entry".to_owned()));
    // The state directory was not even locked.
    assert_eq!(fs::read_dir(&state.0).expect("state directory").count(), 0);

    let fixture = roles_bundle(&["auditor"]);
    let missing = state.0.join("missing");
    let missing = missing.to_str().expect("UTF-8");
    for words in [
        &["ledger", "seed", fixture.path(), "--state-dir", missing][..],
        &["ledger", "verify", "--state-dir", missing],
        &[
            "ledger",
            "rollback",
            &format!("rev-{}", "0".repeat(32)),
            "--state-dir",
            missing,
        ],
    ] {
        let (exit, captured) = run(words);
        assert_eq!(exit, Exit::Invalid, "{words:?}");
        let position = words
            .iter()
            .position(|word| *word == "--state-dir")
            .expect("option")
            + 1;
        assert!(
            captured.stderr().contains(&format!(
                "ggctl: error: state_dir.missing: {} (argument {position})",
                Code::StateDirMissing.message()
            )),
            "{words:?}: {}",
            captured.stderr()
        );
        assert_paths_not_echoed(&captured, &[missing]);
    }

    // A state directory without a ledger has nothing to verify.
    let (exit, captured) = run(&["ledger", "verify", "--state-dir", state.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: ledger.missing: "));
    assert_eq!(captured.stdout(), "configuration ledger not verified\n");
}

#[test]
fn a_locked_state_directory_exits_5_before_anything_is_read() {
    let fixture = roles_bundle(&["auditor"]);
    let state = State::new();
    seeded_ledger(&fixture, &state);
    let held = StateDirectory::acquire(&state.0).expect("the test holds the lock");
    let before = fs::read(state.ledger()).expect("the ledger");
    let target = format!("rev-{}", "0".repeat(32));
    for words in [
        &[
            "ledger",
            "seed",
            fixture.path(),
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ][..],
        &[
            "ledger",
            "verify",
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        &[
            "ledger",
            "rollback",
            &target,
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
    ] {
        let (exit, captured) = run(words);
        assert_eq!(exit, Exit::Conflict, "{words:?}");
        let found = report(&captured);
        let locked: Vec<_> = found["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .filter(|diagnostic| diagnostic["code"] == "state_dir.locked")
            .collect();
        assert_eq!(locked.len(), 1, "{words:?}");
        let position = words
            .iter()
            .position(|word| *word == "--state-dir")
            .expect("option")
            + 1;
        assert_eq!(locked[0]["location"], json!({"argument": position}));
    }
    assert_eq!(fs::read(state.ledger()).expect("the ledger"), before);
    drop(held);
    let (exit, _) = run(&["ledger", "verify", "--state-dir", state.path()]);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn verify_reports_the_class_of_an_edit_outside_the_gateway() {
    let fixture = roles_bundle(&["auditor", CANARY]);
    let state = State::new();
    seeded_ledger(&fixture, &state);
    // Every handle closed, so the log is checkpointed into the file: change
    // one byte of the stored policy, which no longer matches its pin.
    let mut bytes = fs::read(state.ledger()).expect("the ledger");
    let at: Vec<usize> = bytes
        .windows(CANARY.len())
        .enumerate()
        .filter(|(_, window)| *window == CANARY.as_bytes())
        .map(|(index, _)| index)
        .collect();
    assert_eq!(at.len(), 1, "the canary is stored once, in the policy");
    bytes[at[0]] = b'Z';
    fs::write(state.ledger(), &bytes).expect("the edit should write");

    let (exit, captured) = run(&[
        "ledger",
        "verify",
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(codes(&found), ["ledger.corrupt"]);
    assert_eq!(
        found["result"],
        json!({"verified": false, "corruption": "document"})
    );
    let (exit, captured) = run(&["ledger", "verify", "--state-dir", state.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        captured.stdout(),
        "configuration ledger corrupt (document)\n"
    );
    // A rollback refuses the corrupt ledger the same way, and writes nothing.
    let target = format!("rev-{}", "0".repeat(32));
    let (exit, captured) = run(&[
        "ledger",
        "rollback",
        &target,
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(
        found["result"],
        json!({"rolledBack": false, "corruption": "document"})
    );
    assert_eq!(fs::read(state.ledger()).expect("the ledger"), bytes);
}

#[test]
fn a_rollback_needs_every_risk_code_named_and_appends_a_forward_revision() {
    let wide = roles_bundle(&["auditor", "operator"]);
    let state = State::new();
    let seeded = seeded_ledger(&wide, &state);
    let seed_id = seeded["result"]["ledger"]["desired"]["revision"]
        .as_str()
        .expect("the seed's ID")
        .to_owned();
    let narrow = roles_bundle(&["auditor"]);
    let second = apply_online(&state, &narrow);

    // Rolling back restores a role, which broadens the policy: nothing is
    // written until the risk code is named.
    let words = [
        "ledger",
        "rollback",
        seed_id.as_str(),
        "--state-dir",
        state.path(),
        "--format",
        "json",
    ];
    let (exit, captured) = run(&words);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(codes(&found), ["ledger.acknowledgement_required"]);
    let plan = &found["result"]["plan"];
    assert_eq!(plan["base"], second.as_str());
    assert_eq!(plan["target"], seed_id.as_str());
    assert_eq!(plan["riskCodes"], json!(["risk.policy_broadened"]));
    assert_eq!(plan["unacknowledged"], json!(["risk.policy_broadened"]));
    assert_eq!(plan["changedSections"], json!(["policy"]));
    assert_eq!(
        plan["requiredPermissions"],
        json!(["admin:config:write", "admin:policy:write"])
    );
    assert_eq!(plan["activation"], "live");
    assert_eq!(plan["diff"]["riskCodes"], json!(["risk.policy_broadened"]));
    assert_eq!(found["result"]["rolledBack"], false);
    assert_eq!(state.state().revisions, 2);
    let (_, captured) = run(&words[..5]);
    assert!(captured.stdout().ends_with(
        "not rolled back: acknowledge each risk code with --acknowledge: risk.policy_broadened\n"
    ));

    // A code the rollback does not carry is refused too: exactly its codes.
    let (exit, captured) = run(&[
        "ledger",
        "rollback",
        &seed_id,
        "--state-dir",
        state.path(),
        "--acknowledge",
        "risk.policy_broadened",
        "--acknowledge",
        "risk.unknown_impact",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .contains("ggctl: error: ledger.acknowledgement_mismatch: "));
    assert_eq!(state.state().revisions, 2);

    let (exit, captured) = run(&[
        "ledger",
        "rollback",
        &seed_id,
        "--state-dir",
        state.path(),
        "--acknowledge",
        "risk.policy_broadened",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(codes(&found), ["ledger.gateway_recompiles_at_start"]);
    let result = &found["result"];
    assert_eq!(result["rolledBack"], true);
    assert_eq!(result["plan"]["unacknowledged"], json!([]));
    let revision = &result["revision"];
    assert_eq!(revision["sequence"], 3);
    assert_eq!(revision["operation"], "rollback");
    assert_eq!(revision["rollbackOf"], seed_id.as_str());
    assert_eq!(revision["actorKind"], "system");
    assert_eq!(revision["activation"], "restart");
    assert_eq!(revision["appliedOnline"], false);
    assert_eq!(revision["riskCodes"], json!(["risk.policy_broadened"]));
    assert_eq!(
        revision["bundle"]["sourceDigest"],
        seeded["result"]["ledger"]["desired"]["bundle"]["sourceDigest"]
    );
    assert_eq!(result["ledger"]["revisions"], 3);
    assert_eq!(
        result["ledger"]["desired"]["revision"],
        revision["revision"]
    );

    // Appended, never rewritten: the seed and the online revision are still
    // there, in order, and the new one records no request.
    let held = StateDirectory::acquire(&state.0).expect("the state directory locks");
    let mut ledger = RevisionLedger::open(&held).expect("the ledger opens");
    let history: Vec<_> = ledger
        .revisions(None, 10)
        .expect("history")
        .into_iter()
        .map(|summary| {
            (
                summary.revision.as_str().to_owned(),
                summary.request.is_none(),
            )
        })
        .collect();
    assert_eq!(history.len(), 3);
    assert_eq!(history[1].0, second.as_str());
    assert_eq!(history[2].0, seed_id);
    assert!(history[0].1);
    let desired = ledger.state().expect("state").desired;
    assert_eq!(desired.actor.subject(), ACTOR_LABEL);
    assert_eq!(desired.actor.auth_mode(), AuthMode::System);
    drop(ledger);
    drop(held);

    // The seed's content again changes nothing; the head and an unknown
    // revision are refused, located by REVISION's position.
    let head = revision["revision"].as_str().expect("the head").to_owned();
    let unknown = format!("rev-{}", "0".repeat(32));
    for (target, code) in [
        (seed_id.as_str(), "ledger.no_change"),
        (head.as_str(), "ledger.rollback_target_is_head"),
        (unknown.as_str(), "ledger.rollback_target_unknown"),
    ] {
        let (exit, captured) = run(&[
            "ledger",
            "rollback",
            target,
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Invalid, "{code}");
        let found = report(&captured);
        assert!(
            codes(&found).contains(&code.to_owned()),
            "{code}: {found:#}"
        );
        if code != "ledger.no_change" {
            assert_eq!(found["diagnostics"][0]["location"], json!({"argument": 3}));
        }
        assert!(!captured.stdout().contains(&unknown), "{code}");
    }
    assert_eq!(state.state().revisions, 3);
    // The online revision's actor and the policy's role names never reach
    // the output, nor does a path.
    let (_, captured) = run(&[
        "ledger",
        "rollback",
        second.as_str(),
        "--state-dir",
        state.path(),
    ]);
    assert!(captured
        .stdout()
        .starts_with(&format!("rollback of {head} to the content of {second}:\n")));
    assert_no_canary(&captured);
    assert_paths_not_echoed(&captured, &[state.path()]);
}

#[test]
fn refusals_map_to_ledger_codes_and_a_rollback_without_risk_needs_no_acknowledgement() {
    let fixture = roles_bundle(&["auditor"]);
    let state = State::new();
    let seeded = seeded_ledger(&fixture, &state);
    let seed_id = seeded["result"]["ledger"]["desired"]["revision"]
        .as_str()
        .expect("the seed's ID")
        .to_owned();
    apply_online(&state, &roles_bundle(&["auditor", "operator"]));
    // Stored content the current reader refuses is located by REVISION's
    // position, followed by the reader's own diagnostics.
    let mut result = RollbackResult {
        rolled_back: false,
        corruption: None,
        plan: None,
        revision: None,
        ledger: None,
    };
    let diagnostics = revision_diagnostics(&RevisionError::Invalid(Vec::new()), 3, &mut result);
    assert_eq!(
        diagnostics
            .iter()
            .map(ReportDiagnostic::code)
            .collect::<Vec<_>>(),
        ["ledger.rollback_target_invalid"]
    );
    assert_eq!(
        diagnostics[0].location(),
        Some(crate::report::LocationRecord::Argument { argument: 3 })
    );
    let diagnostics = revision_diagnostics(
        &RevisionError::Ledger(LedgerError::Corrupt(Corruption::Chain)),
        3,
        &mut result,
    );
    assert_eq!(diagnostics[0].code(), "ledger.corrupt");
    assert_eq!(result.corruption, Some("chain"));
    for (error, code) in [
        (RevisionError::BaseInvalid, "ledger.head_invalid"),
        (RevisionError::NotNormalizable, "ledger.not_normalizable"),
        (
            RevisionError::NotApplicable(vec!["bootstrap"]),
            "ledger.change_not_applicable",
        ),
        (RevisionError::Unclassified, "ledger.change_unclassified"),
        (
            RevisionError::NothingToAcknowledge,
            "ledger.nothing_to_acknowledge",
        ),
        (
            RevisionError::PreconditionFailed {
                current: String::new(),
            },
            "ledger.stale",
        ),
        (RevisionError::PlanStale, "ledger.unexpected_refusal"),
        (
            RevisionError::OfflineActorRequired,
            "ledger.unexpected_refusal",
        ),
    ] {
        assert_eq!(
            revision_diagnostics(&error, 3, &mut result)[0].code(),
            code,
            "{error}"
        );
    }
    // Rolling back to the seed removes a role again, which carries no risk
    // code, so nothing needs to be acknowledged; acknowledging anything is
    // refused.
    let (exit, captured) = run(&[
        "ledger",
        "rollback",
        &seed_id,
        "--state-dir",
        state.path(),
        "--acknowledge",
        "risk.policy_broadened",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .contains("ggctl: error: ledger.nothing_to_acknowledge: "));
    let (exit, captured) = run(&["ledger", "rollback", &seed_id, "--state-dir", state.path()]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    assert!(captured
        .stdout()
        .contains("\nrolled back: a new forward revision restores that content\n"));
    assert_eq!(state.state().revisions, 3);
}

#[test]
fn every_state_directory_and_ledger_code_is_the_librarys() {
    for error in [
        StateDirError::Missing,
        StateDirError::NotDirectory,
        StateDirError::Link,
        StateDirError::UnsafePermissions,
        StateDirError::UnsafeLockFile,
        StateDirError::Locked,
        StateDirError::LockUnsupported,
        StateDirError::Unavailable { operation: "test" },
    ] {
        assert_eq!(state_dir_code(&error).as_str(), error.code());
    }
    assert_eq!(
        state_dir_code(&StateDirError::Locked).exit(),
        Exit::Conflict
    );
    let head = RevisionId::parse(&format!("rev-{}", "1".repeat(32))).expect("an ID");
    for error in [
        LedgerError::UnsafeLocation,
        LedgerError::Missing,
        LedgerError::Exists,
        LedgerError::Unsupported,
        LedgerError::Corrupt(Corruption::Pointer),
        LedgerError::Stale { head: head.clone() },
        LedgerError::Refused(gateway_config::ledger::Refusal::RecordTooLarge),
        LedgerError::Full,
        LedgerError::Unavailable { operation: "test" },
    ] {
        assert_eq!(ledger_code(&error).as_str(), error.code());
    }
    assert_eq!(
        ledger_code(&LedgerError::IdempotencyKeyUsed { revision: head }).as_str(),
        "ledger.unexpected_refusal"
    );
    assert_eq!(ledger_code(&LedgerError::Exists).exit(), Exit::Conflict);
    assert_eq!(
        ledger_code(&LedgerError::Corrupt(Corruption::Chain)).exit(),
        Exit::Invalid
    );
    assert_eq!(Code::GatewayRecompilesAtStart.exit(), Exit::Success);
}

#[test]
fn a_revision_argument_outside_the_grammar_is_a_usage_error_and_never_echoed() {
    let state = State::new();
    for revision in ["rev-xyz", CANARY, "REV-00000000000000000000000000000000"] {
        let (exit, captured) = run(&[
            "ledger",
            "rollback",
            revision,
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Usage);
        assert!(captured.stdout().is_empty());
        assert!(captured
            .stderr()
            .starts_with("ggctl: error: usage.invalid_value: "));
        assert!(captured.stderr().contains("(argument 3)"));
        assert!(!captured.stderr().contains(revision));
    }
    assert_eq!(fs::read_dir(&state.0).expect("state directory").count(), 0);
}
