//! The production policy and tools validators at the bundle boundary
//! (issue #242): what only they refuse, what `ggctl init` writes, and the
//! limits the reader shares with the policy and tools loaders. These moved
//! here from the gateway's `config::bundle` with the validators.

use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::*;
use crate::{
    rbac::{policy::KNOWN_TOP_LEVEL_KEYS, DefaultAction},
    semantic_diff::compare_production_bundles,
    tools::definitions::ToolDefinition,
};

/// Reads the bundle in `root` with the production validators, as the
/// gateway and `ggctl` do.
fn read_production_bundle(
    root: &Path,
    options: ReadOptions,
) -> BundleReport<Policy, Vec<ToolDefinition>> {
    read_bundle(root, options, &ProductionValidators)
}

const CANARY: &str = "zqcanary";

struct TempBundle(PathBuf);

impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A bundle of `profile` pinning `policy` and `tools` as its policy and
/// tools files.
fn write_bundle(profile: &str, policy: &str, tools: &str) -> TempBundle {
    let root = std::env::temp_dir().join(format!(
        "greengateway-gateway-bundle-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("temporary bundle directory should create");
    let deployment = format!(
        "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: {profile}\n"
    );
    let deployment = deployment.as_str();
    let digest = |bytes: &str| hex::encode(Sha256::digest(bytes.as_bytes()));
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
        digest(deployment),
        digest(policy),
        digest(tools),
    );
    for (name, contents) in [
        ("deployment.yaml", deployment),
        ("policy.json", policy),
        ("tools.json", tools),
        ("bundle.yaml", manifest.as_str()),
    ] {
        fs::write(root.join(name), contents).expect("bundle file should write");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .expect("permissions should set");
        };
        mode(&root, 0o755);
        for name in [
            "deployment.yaml",
            "policy.json",
            "tools.json",
            "bundle.yaml",
        ] {
            mode(&root.join(name), 0o644);
        }
    }
    TempBundle(root)
}

fn repository_text(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path))
        .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
        .replace("\r\n", "\n")
}

#[test]
fn bundles_are_diffed_by_their_production_documents() {
    let read = |bundle: &TempBundle| {
        read_production_bundle(&bundle.0, ReadOptions::default())
            .bundle
            .expect("the bundle should be read")
    };
    let tools = repository_text("docs/examples/tools.starter.json");
    let deny = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n";
    let base = read(&write_bundle("production", deny, &tools));
    assert!(compare_production_bundles(&base, &base).is_empty());

    // The validator fills in every default, so spelling one out is no
    // change; only the pin moves.
    let spelled = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"enforcement_mode\": \"enforce\", \"roles\": {}}\n";
    let diff =
        compare_production_bundles(&base, &read(&write_bundle("production", spelled, &tools)));
    let fields: Vec<_> = diff.changes().iter().map(|change| change.field()).collect();
    assert_eq!(fields, ["resources.policy.sha256"]);

    // The starter policy allows by default, which only a development
    // bundle may do: moving to it is a profile and a policy weakening.
    let starter = read(&write_bundle(
        "development",
        &repository_text("docs/examples/policy.starter.json"),
        &tools,
    ));
    let diff = compare_production_bundles(&base, &starter);
    let codes: Vec<_> = diff.risks().into_iter().map(|code| code.as_str()).collect();
    assert!(codes.contains(&"risk.policy_default_allow"), "{codes:?}");
    assert!(codes.contains(&"risk.profile_changed"), "{codes:?}");
    assert!(!serde_json::to_string(&diff)
        .expect("a diff serializes")
        .contains(CANARY));
}

#[test]
fn a_bundle_is_read_into_the_production_policy_and_tools() {
    // The starter policy allows by default, which only a development
    // bundle may do.
    let bundle = write_bundle(
        "development",
        &repository_text("docs/examples/policy.starter.json"),
        &repository_text("docs/examples/tools.starter.json"),
    );
    let report = read_production_bundle(&bundle.0, ReadOptions::default());
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    let read = report.bundle.expect("the bundle should be read");
    let Some(BundledResource::Bundle {
        document: policy, ..
    }) = &read.policy
    else {
        panic!("the policy should come from the bundle");
    };
    assert_eq!(policy.id.as_deref(), Some("starter"));
    assert_eq!(policy.default_action, DefaultAction::Allow);
    let Some(BundledResource::Bundle {
        document: tools, ..
    }) = &read.tools
    else {
        panic!("the tools should come from the bundle");
    };
    assert_eq!(tools.len(), 1);
}

#[test]
fn a_document_only_the_production_validator_refuses_is_refused_by_code_alone() {
    // Each passes its published schema, whose uniqueness checks are
    // exact: only the production validators compare route hosts without
    // case, and tool names across the document.
    let deny = "{\"schema_version\": \"0.1.0\"}";
    let tools = repository_text("docs/examples/tools.starter.json");
    let policy = format!(
        "{{\"schema_version\": \"0.1.0\", \"routes\": [{{\"path_prefix\": \"/a\", \"permission\": \"p\", \"hosts\": [\"{CANARY}.example\", \"{}.example\"]}}]}}",
        CANARY.to_ascii_uppercase()
    );
    let mut twice: serde_json::Value =
        serde_json::from_str(&tools).expect("the starter tools are JSON");
    let echo = twice["tools"][0].clone();
    if let Some(list) = twice["tools"].as_array_mut() {
        list.push(echo);
    }
    let twice = twice.to_string().replace("echo", CANARY);
    for (policy, tools, refused) in [
        (policy.as_str(), tools.as_str(), "policy.json"),
        (deny, twice.as_str(), "tools.json"),
    ] {
        let bundle = write_bundle("production", policy, tools);
        let schema_only = read_bundle(&bundle.0, ReadOptions::default(), &PublishedSchemasOnly);
        assert!(
            schema_only.diagnostics.is_empty(),
            "{refused}: {:?}",
            schema_only.diagnostics
        );
        let report = read_production_bundle(&bundle.0, ReadOptions::default());
        assert!(report.bundle.is_none());
        let found: Vec<_> = report
            .diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code,
                    diagnostic
                        .file
                        .as_ref()
                        .map(|file| file.as_str().to_owned()),
                )
            })
            .collect();
        assert_eq!(
            found,
            [(Code::ResourceInvalid, Some(refused.to_owned()))],
            "{refused}"
        );
        for diagnostic in &report.diagnostics {
            let rendered = format!("{diagnostic} {diagnostic:?}");
            assert!(!rendered.contains(CANARY), "{rendered}");
        }
    }
}

/// What `ggctl init` writes (issue #242 PR 6) for every profile and
/// each kind of answer, read with the production validators, which `ggctl
/// init` also reads its output back with.
#[test]
fn every_bundle_ggctl_init_writes_passes_the_production_validators() {
    use crate::bundle::init::{read_answers, scaffold, Answers, AnswersSyntax, GITATTRIBUTES};
    let answers = |spec: &str| {
        read_answers(
            format!(
                "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\nspec:\n{spec}"
            )
            .as_bytes(),
            AnswersSyntax::Yaml,
        )
        .expect("the answers should be read")
    };
    let answer_sets = [
        Answers::default(),
        answers(
            "  name: payments\n  operator:\n    issuer: \"https://idp.example.test/\"\n    auth_methods: [bearer_token, session_cookie]\n",
        ),
        answers("  topology: cluster\n"),
    ];
    for profile in Profile::ALL.iter().copied() {
        for answers in &answer_sets {
            let root = std::env::temp_dir().join(format!(
                "greengateway-gateway-init-{}",
                uuid::Uuid::new_v4()
            ));
            let bundle = TempBundle(root);
            fs::create_dir_all(&bundle.0).expect("temporary bundle directory should create");
            let files = scaffold(profile, answers);
            for file in &files {
                fs::write(bundle.0.join(file.name.as_str()), &file.bytes)
                    .expect("bundle file should write");
            }
            fs::write(bundle.0.join(".gitattributes"), GITATTRIBUTES)
                .expect("attributes should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in fs::read_dir(&bundle.0).expect("the bundle lists") {
                    let path = entry.expect("an entry").path();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                        .expect("permissions should set");
                }
                fs::set_permissions(&bundle.0, fs::Permissions::from_mode(0o700))
                    .expect("permissions should set");
            }

            let report = read_production_bundle(&bundle.0, ReadOptions { strict: true });
            assert!(
                report.diagnostics.is_empty(),
                "{profile:?} {answers:?}: {:?}",
                report.diagnostics
            );
            let read = report.bundle.expect("the bundle should be read");
            assert_eq!(read.source_files(), files);
            match (&read.policy, answers.operator()) {
                (Some(BundledResource::Bundle { document, .. }), operator) => {
                    assert_eq!(document.default_action, DefaultAction::Deny);
                    assert_eq!(
                        document.enforcement_mode,
                        crate::rbac::EnforcementMode::Enforce
                    );
                    assert_eq!(document.roles.len(), usize::from(operator.is_some()));
                    for role in document.roles.values() {
                        assert_eq!(role.issuers, ["https://idp.example.test"]);
                        assert!(!role.auth_methods.is_empty());
                        assert!(!role.permissions.iter().any(|permission| permission == "*"));
                    }
                    let Some(BundledResource::Bundle {
                        document: tools, ..
                    }) = &read.tools
                    else {
                        panic!("a standalone bundle supplies its tools");
                    };
                    assert!(tools.is_empty());
                }
                (Some(BundledResource::Server), None) => {
                    assert!(matches!(read.tools, Some(BundledResource::Server)));
                }
                (policy, operator) => panic!("unexpected {policy:?} with {operator:?}"),
            }
        }
    }
}

#[test]
fn the_shared_reader_holds_the_gateway_limits_and_member_lists() {
    assert_eq!(POLICY_TOP_LEVEL_MEMBERS, KNOWN_TOP_LEVEL_KEYS);
    assert_eq!(
        crate::opaque_id::MAX_SECRET_ALIAS_ID_BYTES,
        crate::connections::MAX_SECRET_ID_BYTES
    );
    assert_eq!(
        MAX_RESOURCE_BYTES as u64,
        crate::rbac::policy::MAX_POLICY_FILE_BYTES
    );
}
