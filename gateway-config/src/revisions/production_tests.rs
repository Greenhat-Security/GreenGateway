//! Ledger plans compiled with the production validators (issue #242): the
//! parity of a plan's diff with the production bundle diff, what only the
//! production validators refuse, and an apply under the union of
//! permissions. These moved here from the gateway's `config::revisions`
//! with [`ProductionCompiler`].

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::{
    bundle::{Code, ProductionBundle},
    ledger::{AuthMode, LedgerActor, PlanId, RevisionLedger},
    semantic_diff::compare_production_bundles,
    state_dir::StateDirectory,
};

const CANARY: &str = "zqcanary";

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-gateway-revisions-{}",
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

    /// The directory, held under its lock. A ledger opened through it
    /// keeps the lock held for as long as the ledger is open.
    fn held(&self) -> StateDirectory {
        StateDirectory::acquire(&self.0).expect("the state directory locks")
    }
}

fn repository_text(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path))
        .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
        .replace("\r\n", "\n")
}

fn name(text: &str) -> FileName {
    FileName::parse(text).expect("a portable file name")
}

/// A production bundle pinning `policy` and the starter tools.
fn files(policy: &str) -> BTreeMap<FileName, Vec<u8>> {
    let deployment = "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n";
    let tools = repository_text("docs/examples/tools.starter.json");
    let manifest = format!(
        concat!(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayBundle\n",
            "metadata:\n",
            "  name: payments-production\n",
            "spec:\n",
            "  deployment:\n",
            "    path: deployment.yaml\n",
            "    sha256: \"{}\"\n",
            "  resources:\n",
            "    policy:\n",
            "      source: bundle\n",
            "      path: policy.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{}\"\n",
            "    tools:\n",
            "      source: bundle\n",
            "      path: tools.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{}\"\n",
            "    connections:\n",
            "      source: server\n",
        ),
        sha256_pin(deployment.as_bytes()),
        sha256_pin(policy.as_bytes()),
        sha256_pin(tools.as_bytes()),
    );
    BTreeMap::from([
        (name("bundle.yaml"), manifest.into_bytes()),
        (name("deployment.yaml"), deployment.as_bytes().to_vec()),
        (name("policy.json"), policy.as_bytes().to_vec()),
        (name("tools.json"), tools.into_bytes()),
    ])
}

fn production_bundle(files: BTreeMap<FileName, Vec<u8>>) -> ProductionBundle {
    let report = read_bundle_files(files, ReadOptions { strict: true }, &ProductionValidators);
    report
        .bundle
        .unwrap_or_else(|| panic!("fixture bundle should read: {:?}", report.diagnostics))
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
}

fn admin() -> LedgerActor {
    LedgerActor::principal("alice", Some("provider:corp"), AuthMode::BearerToken)
        .expect("the principal is recordable")
}

const DENY: &str = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n";

/// A ledger seeded with the deny-by-default policy and activated, and a
/// production service over it.
fn production_service(state: &TempDir) -> RevisionService<ProductionCompiler> {
    let (mut ledger, seed) = RevisionLedger::seed(
        &state.held(),
        &production_bundle(files(DENY)),
        LedgerActor::system("ggctl-ledger-seed").expect("system"),
        at(0),
    )
    .expect("seed");
    ledger.activate(&seed.revision).expect("activate");
    RevisionService::new(ledger, ProductionCompiler)
}

#[test]
fn ledger_plans_run_the_production_validators() {
    // Case-colliding route hosts pass the published schema; only the
    // production validator refuses them.
    let policy = format!(
        "{{\"schema_version\": \"0.1.0\", \"routes\": [{{\"path_prefix\": \"/a\", \"permission\": \"p\", \"hosts\": [\"{CANARY}.example\", \"{}.example\"]}}]}}\n",
        CANARY.to_ascii_uppercase()
    );
    let state = TempDir::new();
    let mut service = production_service(&state);
    match service.create_plan(
        PlanId::from_random([1; 16]),
        admin(),
        PlanSubject::Bundle(files(&policy)),
        at(10),
    ) {
        Err(RevisionError::Invalid(diagnostics)) => {
            let found: Vec<_> = diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code, diagnostic.file.clone()))
                .collect();
            assert_eq!(found, [(Code::ResourceInvalid, Some(name("policy.json")))]);
            assert!(!format!("{diagnostics:?}").contains(CANARY));
        }
        other => panic!("expected the production validator to refuse, found {other:?}"),
    }

    // The schema-only compiler, which runs no production validator,
    // accepts it.
    let schema_state = TempDir::new();
    let (ledger, _seed) = RevisionLedger::seed(
        &schema_state.held(),
        &production_bundle(files(DENY)),
        LedgerActor::system("ggctl-ledger-seed").expect("system"),
        at(0),
    )
    .expect("seed");
    let mut schema_only = RevisionService::new(ledger, PublishedSchemasCompiler);
    schema_only
        .create_plan(
            PlanId::from_random([1; 16]),
            admin(),
            PlanSubject::Bundle(files(&policy)),
            at(10),
        )
        .expect("the published schema accepts it");
}

#[test]
fn a_ledger_plan_diffs_as_the_gateway_diffs_the_same_bundles() {
    let state = TempDir::new();
    let mut service = production_service(&state);
    let base = production_bundle(files(DENY));
    for candidate in [
        // Spelling out the validator's defaults moves only the pin.
        "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"enforcement_mode\": \"enforce\", \"roles\": {}}\n".to_owned(),
        repository_text("dev/policy.json"),
        format!(
            "{{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"roles\": {{\"{CANARY}\": {{\"permissions\": [\"admin:policy:read\"]}}}}}}\n"
        ),
    ] {
        let candidate_files = files(&candidate);
        let report = read_bundle_files(
            candidate_files.clone(),
            ReadOptions { strict: true },
            &ProductionValidators,
        );
        let Some(expected_bundle) = report.bundle else {
            // A repository policy this profile refuses says nothing
            // about parity.
            continue;
        };
        let expected = compare_production_bundles(&base, &expected_bundle);
        let plan = service
            .create_plan(
                PlanId::from_random([2; 16]),
                admin(),
                PlanSubject::Bundle(candidate_files),
                at(10),
            )
            .expect("plan");
        assert_eq!(
            serde_json::to_value(&plan.diff).expect("diff"),
            serde_json::to_value(&expected).expect("diff")
        );
        let report = serde_json::to_string(&plan.diff).expect("diff");
        assert!(!report.contains(CANARY), "{report}");
        // Plans are made one at a time here; drop this one.
        assert!(service
            .plan(&plan.id, &admin(), at(10) + Duration::from_secs(16 * 60))
            .is_none());
    }
}

#[test]
fn a_production_apply_records_the_policy_revision_under_the_union_of_permissions() {
    let state = TempDir::new();
    let mut service = production_service(&state);
    let candidate = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"roles\": {\"auditor\": {\"permissions\": [\"admin:policy:read\"]}}}\n";
    let subject = PlanSubject::Bundle(files(candidate));
    let plan = service
        .create_plan(
            PlanId::from_random([3; 16]),
            admin(),
            subject.clone(),
            at(10),
        )
        .expect("plan");
    assert_eq!(plan.risk_codes, ["risk.policy_broadened"]);
    assert_eq!(
        plan.required_permissions,
        [ADMIN_CONFIG_WRITE, ADMIN_POLICY_WRITE]
    );
    service
        .acknowledge(&plan.id, &admin(), &plan.risk_codes, at(11))
        .expect("acknowledge");
    let request = ApplyRequest {
        plan: plan.id.clone(),
        actor: admin(),
        if_match: Some(plan.base_etag.clone()),
        idempotency_key: Some("deploy-42".to_owned()),
        subject,
        stage_only: false,
    };
    assert_eq!(
        service
            .apply(
                request.clone(),
                |permission| permission == ADMIN_CONFIG_WRITE,
                at(12)
            )
            .map(|applied| applied.revision.sequence)
            .map_err(|error| error.code()),
        Err("apply.permission_denied")
    );
    let applied = service
        .apply(
            request,
            |permission| [ADMIN_CONFIG_WRITE, ADMIN_POLICY_WRITE].contains(&permission),
            at(12),
        )
        .expect("apply");
    assert!(applied.active);
    assert_eq!(
        applied.revision.codes.risk_codes(),
        ["risk.policy_broadened"]
    );
}
