//! The gateway's side of the shared configuration bundle reader
//! (`gateway_config::bundle`, issue #242): its production policy and tools
//! validators.
//!
//! The reader, which `ggctl validate` and `ggctl doctor` run as well, applies
//! the bundle's own checks and each referenced document's published schema,
//! then hands the document to the caller's [`ResourceValidators`]. The
//! gateway's are the production validators that environment mode loads the
//! same documents with, so a bundle the gateway accepts is one its policy and
//! tools loaders accept. `ggctl` cannot link them and its reports say so.
//!
//! Nothing selects a bundle for startup yet (bundle mode is a later #242
//! slice), so only the tests call this.
#![cfg_attr(not(test), expect(dead_code))]

use std::path::Path;

use gateway_config::bundle::{self, BundleReport, ReadOptions, ResourceValidators};
use serde_json::Value;

use crate::{
    rbac::policy::Policy,
    tools::definitions::{definitions_from_json_value, ToolDefinition},
};

/// The production policy and tools validators.
///
/// A validator's error can quote document values, so it is dropped here and
/// the reader reports `resource.invalid` by code alone.
pub(crate) struct ProductionValidators;

impl ResourceValidators for ProductionValidators {
    type Policy = Policy;
    type Tools = Vec<ToolDefinition>;

    fn policy(&self, document: Value) -> Option<Policy> {
        Policy::validate_json_value(document).ok()
    }

    fn tools(&self, document: Value) -> Option<Vec<ToolDefinition>> {
        definitions_from_json_value(document, None).ok()
    }
}

/// Reads the bundle in `root` with the production validators.
pub(crate) fn read_bundle(
    root: &Path,
    options: ReadOptions,
) -> BundleReport<Policy, Vec<ToolDefinition>> {
    bundle::read_bundle(root, options, &ProductionValidators)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use gateway_config::bundle::{BundledResource, Code, POLICY_TOP_LEVEL_MEMBERS};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::rbac::{policy::KNOWN_TOP_LEVEL_KEYS, DefaultAction};

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
            read_bundle(&bundle.0, ReadOptions::default())
                .bundle
                .expect("the bundle should be read")
        };
        let tools = repository_text("docs/examples/tools.starter.json");
        let deny = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n";
        let base = read(&write_bundle("production", deny, &tools));
        assert!(crate::config::semantic_diff::bundles(&base, &base).is_empty());

        // The validator fills in every default, so spelling one out is no
        // change; only the pin moves.
        let spelled = "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"enforcement_mode\": \"enforce\", \"roles\": {}}\n";
        let diff = crate::config::semantic_diff::bundles(
            &base,
            &read(&write_bundle("production", spelled, &tools)),
        );
        let fields: Vec<_> = diff.changes().iter().map(|change| change.field()).collect();
        assert_eq!(fields, ["resources.policy.sha256"]);

        // The starter policy allows by default, which only a development
        // bundle may do: moving to it is a profile and a policy weakening.
        let starter = read(&write_bundle(
            "development",
            &repository_text("docs/examples/policy.starter.json"),
            &tools,
        ));
        let diff = crate::config::semantic_diff::bundles(&base, &starter);
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
        let report = read_bundle(&bundle.0, ReadOptions::default());
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
            let schema_only = bundle::read_bundle(
                &bundle.0,
                ReadOptions::default(),
                &bundle::PublishedSchemasOnly,
            );
            assert!(
                schema_only.diagnostics.is_empty(),
                "{refused}: {:?}",
                schema_only.diagnostics
            );
            let report = read_bundle(&bundle.0, ReadOptions::default());
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

    #[test]
    fn the_shared_reader_holds_the_gateway_limits_and_member_lists() {
        assert_eq!(POLICY_TOP_LEVEL_MEMBERS, KNOWN_TOP_LEVEL_KEYS);
        assert_eq!(
            gateway_config::opaque_id::MAX_SECRET_ALIAS_ID_BYTES,
            crate::connections::model::MAX_SECRET_ID_BYTES
        );
        assert_eq!(
            bundle::MAX_RESOURCE_BYTES as u64,
            crate::rbac::policy::MAX_POLICY_FILE_BYTES
        );
    }
}
