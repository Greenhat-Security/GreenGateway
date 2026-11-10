use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use gateway_config::{bundle::sha256_pin, documents::published_schema};
use serde_json::{json, Value};

use crate::{
    cli::{self, Parsed},
    diagnostic::{Code, Exit},
    report::tests::Captured,
};

pub(crate) const CANARY: &str = "zqcanaryggctl";

pub(crate) const DENY_POLICY: &str =
    "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\"\n}\n";
pub(crate) const TOOLS: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

/// A bundle directory under the system temporary directory, removed on drop.
pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    pub(crate) fn empty() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the bundle directory should create");
        #[cfg(unix)]
        set_mode(&root, 0o755);
        Self { root }
    }

    /// A bundle of `profile` that supplies `policy` and the empty tools
    /// document, and leaves Connections to the server.
    pub(crate) fn with(profile: &str, policy: &str) -> Self {
        let fixture = Self::empty();
        fixture.write(
            "deployment.yaml",
            &format!(
                "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: {profile}\n"
            ),
        );
        fixture.write("policy.json", policy);
        fixture.write("tools.json", TOOLS);
        fixture.pin_policy_version("0.1.0");
        fixture
    }

    fn pin_policy_version(&self, version: &str) {
        self.pin(&format!(
            "      source: bundle\n      path: policy.json\n      schema_version: \"{version}\"\n      sha256: \"POLICY\"\n"
        ));
    }

    pub(crate) fn valid() -> Self {
        Self::with("production", DENY_POLICY)
    }

    pub(crate) fn write(&self, name: &str, contents: &str) {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("the bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    }

    fn pin_of(&self, name: &str) -> String {
        sha256_pin(&fs::read(self.root.join(name)).expect("the bundle file should read"))
    }

    /// Writes the manifest, pinning the files as they are now; `policy` is
    /// the body of its policy declaration, where `POLICY` stands for the
    /// policy file's pin.
    pub(crate) fn pin(&self, policy: &str) {
        let policy = if policy.contains("POLICY") {
            policy.replace("POLICY", &self.pin_of("policy.json"))
        } else {
            policy.to_owned()
        };
        self.write(
            "bundle.yaml",
            &format!(
                concat!(
                    "apiVersion: greengateway.dev/v1alpha1\n",
                    "kind: GatewayBundle\n",
                    "metadata:\n",
                    "  name: payments-production\n",
                    "spec:\n",
                    "  deployment:\n",
                    "    path: deployment.yaml\n",
                    "    sha256: \"{deployment}\"\n",
                    "  resources:\n",
                    "    policy:\n",
                    "{policy}",
                    "    tools:\n",
                    "      source: bundle\n",
                    "      path: tools.json\n",
                    "      schema_version: \"0.1.0\"\n",
                    "      sha256: \"{tools}\"\n",
                    "    connections:\n",
                    "      source: server\n",
                ),
                deployment = self.pin_of("deployment.yaml"),
                policy = policy,
                tools = self.pin_of("tools.json"),
            ),
        );
    }

    pub(crate) fn path(&self) -> &str {
        self.root
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

/// Parses and runs one command line, which must parse.
pub(crate) fn run(words: &[&str]) -> (Exit, Captured) {
    let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
    let mut captured = Captured::default();
    let exit = captured.run(b"", false, |io| match cli::parse(&arguments) {
        Ok(Parsed::Run(invocation)) => (invocation.command.run)(&invocation, io),
        other => panic!("{words:?} should run, got {other:?}"),
    });
    (exit, captured)
}

/// Parses a `--format json` report and holds it to the published schema.
pub(crate) fn report(captured: &Captured) -> Value {
    let report: Value = serde_json::from_str(captured.stdout()).expect("one JSON document");
    let schema = published_schema("greengateway.dev/v1alpha1", "GgctlReport").expect("published");
    let schema: Value = serde_json::from_str(schema.json).expect("JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<_> = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{report:#}");
    assert!(captured.stderr().is_empty(), "{}", captured.stderr());
    report
}

pub(crate) fn codes(found: &Value) -> Vec<String> {
    found["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().expect("code").to_owned())
        .collect()
}

pub(crate) fn assert_no_canary(captured: &Captured) {
    let all = format!("{}{}", captured.stdout(), captured.stderr());
    assert!(
        !all.contains(CANARY),
        "a document value reached the output: {all}"
    );
}

#[test]
fn a_valid_bundle_exits_0_and_says_the_production_validators_passed() {
    let fixture = Fixture::valid();
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    let stdout = captured.stdout();
    let digest = format!(
        "  source digest  sha256:{}",
        &stdout.split("sha256:").nth(1).expect("a source digest")[..64]
    );
    assert_eq!(
        stdout,
        format!(
            "bundle payments-production (greengateway.dev/v1alpha1): valid\n\
             {digest}\n  \
             deployment     deployment.yaml (profile production)\n  \
             compiler       compiled\n  \
             policy         policy.json (schema_version 0.1.0)\n  \
             tools          tools.json (schema_version 0.1.0)\n  \
             connections    server\n"
        )
    );
    assert_eq!(captured.stderr(), "");

    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["command"], "validate");
    assert_eq!(found["outcome"], "success");
    assert!(codes(&found).is_empty());
    let result = &found["result"];
    assert_eq!(result["valid"], true);
    let bundle = &result["bundle"];
    assert_eq!(bundle["apiVersion"], "greengateway.dev/v1alpha1");
    assert_eq!(bundle["name"], "payments-production");
    assert!(bundle["sourceDigest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71));
    assert_eq!(
        bundle["deployment"],
        json!({
            "file": "deployment.yaml",
            "sha256": fixture.pin_of("deployment.yaml"),
            "profile": "production",
            "offlineCompiler": "compiled",
        })
    );
    assert_eq!(
        bundle["policy"],
        json!({
            "source": "bundle",
            "file": "policy.json",
            "schemaVersion": "0.1.0",
            "sha256": fixture.pin_of("policy.json"),
            "productionValidator": "passed",
        })
    );
    assert_eq!(bundle["tools"]["productionValidator"], "passed");
    assert_eq!(bundle["connections"], "server");
}

#[test]
fn a_document_only_the_production_validator_refuses_is_refused_by_code_alone() {
    // Two route hosts that differ only in case pass the published schema,
    // whose uniqueness check is exact. The policy loader compares hosts
    // without case and refuses them, and so does `ggctl validate`, by code
    // alone: the hosts are never echoed.
    let policy = format!(
        "{{\"schema_version\": \"0.1.0\", \"routes\": [{{\"path_prefix\": \"/a\", \"permission\": \"p\", \"hosts\": [\"{CANARY}.example\", \"{}.example\"]}}]}}\n",
        CANARY.to_ascii_uppercase()
    );
    let fixture = Fixture::with("production", &policy);
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(found["result"]["valid"], false);
    assert_eq!(codes(&found), ["resource.invalid"]);
    assert_eq!(found["diagnostics"][0]["location"]["file"], "policy.json");
    assert!(found["result"]["bundle"]["policy"]
        .get("productionValidator")
        .is_none());
    assert_no_canary(&captured);

    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: resource.invalid: "));
    assert_no_canary(&captured);
}

#[test]
fn validate_and_diff_pinned_v1_policies() {
    let mapping = json!({"id": "operators", "issuer": "https://issuer.example", "subjects": [CANARY, "operator"], "grant_roles": ["reader"]});
    let mut policy =
        json!({"schema_version": "1.0.0", "roles": {"reader": {"permissions": ["read"]}}});
    let claimed = Fixture::with("production", &policy.to_string());
    claimed.pin_policy_version("1.0.0");
    let mapped = Fixture::valid();
    for mappings in [json!([]), json!([mapping])] {
        policy["identity_mappings"] = mappings;
        mapped.write("policy.json", &policy.to_string());
        mapped.pin_policy_version("1.0.0");
        let (exit, captured) = run(&["validate", mapped.path()]);
        assert_eq!(exit, Exit::Success, "{}", captured.stderr());
        assert_no_canary(&captured);
        let (exit, captured) = run(&[
            "diff",
            mapped.path(),
            "--against",
            claimed.path(),
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Success);
        assert_no_canary(&captured);
        let found = report(&captured);
        assert_eq!(
            found["result"]["diff"]["riskCodes"],
            json!(["risk.unknown_impact"])
        );
        assert!(captured.stdout().contains("policy.identity_mappings"));
    }

    let mut other = mapping.clone();
    other["id"] = json!("others");
    let mut reordered = mapping.clone();
    reordered["subjects"] = json!(["operator", CANARY]);
    for (fixture, mappings) in [
        (&claimed, json!([mapping, other])),
        (&mapped, json!([other, reordered])),
    ] {
        policy["identity_mappings"] = mappings;
        fixture.write("policy.json", &policy.to_string());
        fixture.pin_policy_version("1.0.0");
    }
    let (exit, captured) = run(&[
        "diff",
        mapped.path(),
        "--against",
        claimed.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    assert_no_canary(&captured);
    assert_eq!(report(&captured)["result"]["diff"]["riskCodes"], json!([]));
    assert!(!captured.stdout().contains("policy.identity_mappings"));

    // Unique element IDs are enforced by the gateway beyond the published
    // schema. Both mappings have a valid shape.
    policy["identity_mappings"] = json!([mapping, mapping]);
    mapped.write("policy.json", &policy.to_string());
    mapped.pin_policy_version("1.0.0");
    let (exit, captured) = run(&["validate", mapped.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_no_canary(&captured);
    assert_eq!(codes(&report(&captured)), ["resource.invalid"]);

    mapped.pin_policy_version("0.1.0");
    let (exit, captured) = run(&["validate", mapped.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        codes(&report(&captured)),
        ["resource.schema_version_mismatch"]
    );
}

#[test]
fn validate_and_doctor_run_the_egress_compiler_on_a_bundle() {
    let fixture = Fixture::valid();
    let set_egress = |hosts: &str, prefixes: &str| {
        let deployment = format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n  egress:\n    allowed_hosts: [{hosts}]\n    nat64_prefixes: [{prefixes}]\n"
        );
        fixture.write("deployment.yaml", &deployment);
        fixture.pin("      source: bundle\n      path: policy.json\n      schema_version: \"0.1.0\"\n      sha256: \"POLICY\"\n");
    };
    set_egress("\"API.example.test\"", "\"2001:db8:1::/96\"");
    for command in ["validate", "doctor"] {
        assert_eq!(run(&[command, fixture.path()]).0, Exit::Success);
    }

    // A port is invalid even on an otherwise well-formed hostname. The
    // prefixes are each valid on their own, and overlap one another.
    set_egress(
        &format!("\"{CANARY}.example.test:443\""),
        "\"2001:db8::/32\", \"2001:db8:1::/96\"",
    );
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_no_canary(&captured);
        let result = report(&captured);
        let locations: Vec<_> = result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|diagnostic| diagnostic["code"] == "bundle.invalid_egress_setting")
            .map(|diagnostic| diagnostic["location"].clone())
            .collect();
        assert_eq!(locations.len(), 2);
        for (location, (path, line)) in locations.iter().zip([
            ("/spec/egress/allowed_hosts", 6),
            ("/spec/egress/nat64_prefixes", 7),
        ]) {
            assert_eq!(location["file"], "deployment.yaml");
            assert_eq!(location["pointer"], path);
            assert_eq!(location["line"], line);
        }
        if command == "doctor" {
            let check = result["result"]["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["id"] == "bundle.structure")
                .unwrap();
            assert_eq!(check["status"], "fail");
            assert_eq!(check["reason"], "bundle.invalid_egress_setting");
        }
    }
}

#[test]
fn validate_and_doctor_enforce_each_deployment_profile_control() {
    let fixture = Fixture::valid();
    let controls = [
        ("auth_disabled", "/spec/authentication/enabled"),
        ("auth_observe_only", "/spec/authentication/mode"),
        (
            "private_egress_allowed",
            "/spec/egress/deny_private_addresses",
        ),
        ("csrf_disabled", "/spec/csrf/enabled"),
        ("audit_best_effort", "/spec/audit/durability"),
        (
            "auth_exemptions_broadened",
            "/spec/authentication/exempt_paths",
        ),
        (
            "rbac_exemptions_broadened",
            "/spec/authorization/exempt_paths",
        ),
        ("csrf_exemptions_broadened", "/spec/csrf/exempt_paths"),
    ];
    let all: Vec<_> = controls.iter().map(|(code, _)| *code).collect();
    for (profile, acknowledged) in [
        ("production", &[][..]),
        ("migration", &[][..]),
        ("migration", &all[..1]),
        ("migration", &["auth_exemptions_broadened"][..]),
        ("migration", all.as_slice()),
        ("development", &[][..]),
    ] {
        let mut spec = json!({
            "profile": profile,
            "authentication": {"enabled": false, "mode": "observe", "exempt_paths": [format!("/{CANARY}")]},
            "authorization": {"exempt_paths": [format!("/health/{CANARY}")]},
            "egress": {"deny_private_addresses": false},
            "csrf": {"enabled": false, "exempt_paths": [format!("/readyz/{CANARY}")]},
            "upstream": {"url": {"secret": CANARY}},
            "audit": {"durability": "best_effort"}
        });
        if !acknowledged.is_empty() {
            spec["compatibility"] = json!({"acknowledged": acknowledged});
        }
        fixture.write(
            "deployment.yaml",
            &json!({
                "apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayDeployment", "spec":spec
            })
            .to_string(),
        );
        fixture.pin_policy_version("0.1.0");
        for command in ["validate", "doctor"] {
            let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
            assert_no_canary(&captured);
            let expected_exit = if profile == "development" || acknowledged.len() == all.len() {
                Exit::Success
            } else {
                Exit::Invalid
            };
            assert_eq!(
                exit,
                expected_exit,
                "{command} {profile}: {}",
                captured.stdout()
            );
            let result = report(&captured);
            if exit == Exit::Success {
                assert_eq!(
                    result["result"]["bundle"]["deployment"]["offlineCompiler"],
                    "not_checked"
                );
            }
            let diagnostics = result["diagnostics"].as_array().expect("diagnostics");
            for (name, path) in controls {
                let code = format!("profile.{name}");
                let found = diagnostics.iter().find(|item| item["code"] == code);
                if profile == "development" {
                    assert!(found.is_none(), "{code}");
                } else {
                    let finding = found.unwrap_or_else(|| panic!("missing {code}: {result}"));
                    assert_eq!(finding["location"]["pointer"], path, "{finding}");
                    assert_eq!(
                        finding["severity"],
                        if acknowledged.contains(&name) {
                            "warning"
                        } else {
                            "error"
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn validate_and_doctor_check_listener_bindings_and_tls_intent_offline() {
    let fixture = Fixture::valid();
    let write = |profile: &str, listeners: Value| {
        fixture.write("deployment.yaml", &format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: {profile}\n  listeners: {listeners}\n"
        ));
        fixture.pin_policy_version("0.1.0");
    };
    write(
        "development",
        json!({
            "public":{"tls":"required","client_certificates":"required","client_certificate_crl":"required"},
            "tls":{"client_certificate_identity":"spiffe"},
            "grpc":{"address":"[::1]:8090"},
            "admin":{"address":"127.0.0.2:8090","tls":"required"}
        }),
    );
    for command in ["validate", "doctor"] {
        assert_eq!(run(&[command, fixture.path()]).0, Exit::Success);
    }
    for (profile, listeners, code, pointer) in [
        (
            "development",
            json!({"admin":{"address":"127.0.0.1:8080"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/admin/address",
        ),
        (
            "development",
            json!({"grpc":{"address":"[::]:8443"}}),
            "profile.listener_not_loopback",
            "/spec/listeners/grpc/address",
        ),
        (
            "development",
            json!({"public":{"address":"0.0.0.0:8080"}}),
            "profile.listener_not_loopback",
            "/spec/listeners/public/address",
        ),
        (
            "production",
            json!({"public":{"address":CANARY}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/public/address",
        ),
        (
            "production",
            json!({"admin":{"tls":"required"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/admin/tls",
        ),
        (
            "production",
            json!({"public":{"client_certificate_crl":"required"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/public/client_certificate_crl",
        ),
        (
            "production",
            json!({"public":{"tls":"required","client_certificates":"optional"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/public/client_certificates",
        ),
        (
            "production",
            json!({"public":{"client_certificates":"required"},"tls":{"client_certificate_identity":"dns"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/public/client_certificates",
        ),
        (
            "production",
            json!({"tls":{"client_certificate_identity":"uri"}}),
            "bundle.invalid_listener_setting",
            "/spec/listeners/tls/client_certificate_identity",
        ),
    ] {
        write(profile, listeners);
        for command in ["validate", "doctor"] {
            let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
            assert_eq!(exit, Exit::Invalid, "{}", captured.stdout());
            assert_no_canary(&captured);
            let result = report(&captured);
            let diagnostics = result["diagnostics"].as_array().unwrap();
            let finding = diagnostics
                .iter()
                .find(|item| item["code"] == code)
                .unwrap();
            assert_eq!(finding["location"]["pointer"], pointer);
            assert!(codes(&result).iter().all(|found| {
                *found == code || (command == "doctor" && *found == "doctor.required_check_failed")
            }));
        }
    }
}

#[test]
fn a_self_contained_bundle_builds_the_shared_plan_with_document_provenance() {
    use gateway_config::compiler::stage::Source;
    let fixture = Fixture::valid();
    let write = |spec: &str| {
        fixture.write(
            "deployment.yaml",
            &format!(
                "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n{spec}"
            ),
        );
        fixture.pin_policy_version("0.1.0");
    };
    write("  profile: development\n  trusted_proxies:\n    trust_headers: true\n    cidrs: [\"192.0.2.0/24\"]\n");
    let bundle = super::read_path(std::ffi::OsStr::new(fixture.path()), false)
        .bundle
        .unwrap();
    let plan = bundle.deployment.offline_plan().unwrap();
    assert!(plan.proxy.trust_proxy_headers);
    assert!(plan.listeners.listen_addr.ip().is_loopback());
    assert_eq!(
        plan.listeners.listen_addr.to_string(),
        gateway_config::compiler::listeners::DEVELOPMENT_LISTEN_ADDR
    );
    let sources = plan.provenance();
    for (setting, expected) in [
        ("LISTEN_ADDR", Source::Profile),
        ("TRUSTED_PROXY_CIDRS", Source::Bundle),
        ("AUTH_ENABLED", Source::Default),
    ] {
        assert_eq!(
            sources
                .iter()
                .find(|field| field.setting == setting)
                .unwrap()
                .source,
            expected
        );
    }
    assert!(!sources
        .iter()
        .any(|field| field.source == Source::Environment));

    // Trusting proxy headers without a trusted network is a cross-field
    // rule. Both CLI paths must refuse it and point to the missing setting.
    write("  profile: production\n  trusted_proxies:\n    trust_headers: true\n");
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        let result = report(&captured);
        assert_eq!(
            result["diagnostics"][0]["code"],
            "bundle.invalid_deployment_setting"
        );
        assert_eq!(
            result["diagnostics"][0]["location"]["pointer"],
            "/spec/trusted_proxies/cidrs"
        );
    }

    write(&format!(
        "  profile: production\n  trusted_proxies:\n    trust_headers: true\n    cidrs: [\"{CANARY}\"]\n"
    ));
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_no_canary(&captured);
        assert_eq!(
            report(&captured)["diagnostics"][0]["location"]["pointer"],
            "/spec/trusted_proxies/cidrs"
        );
    }

    write(&format!(
        "  profile: production\n  upstream:\n    url: {{\"secret\":\"{CANARY}\"}}\n"
    ));
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Success);
        assert_no_canary(&captured);
        assert_eq!(
            report(&captured)["result"]["bundle"]["deployment"]["offlineCompiler"],
            "not_checked"
        );
    }
}

#[test]
fn validate_and_doctor_refuse_wildcard_credentialed_cors_in_a_bundle() {
    let fixture = Fixture::valid();
    let write = |origins: Value| {
        fixture.write("deployment.yaml", &format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n  cors:\n    allowed_origins: {origins}\n"
        ));
        fixture.pin_policy_version("0.1.0");
    };
    let origin = format!("https://{CANARY}.example");
    write(json!([origin]));
    for command in ["validate", "doctor"] {
        assert_eq!(run(&[command, fixture.path()]).0, Exit::Success);
    }
    write(json!([origin, "*"]));
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_no_canary(&captured);
        let result = report(&captured);
        if command == "doctor" {
            assert_eq!(
                codes(&result),
                [
                    "bundle.invalid_runtime_setting",
                    "doctor.required_check_failed"
                ]
            );
            let checks = result["result"]["checks"].as_array().unwrap();
            assert!(checks.iter().any(|check| check["id"] == "bundle.structure"
                && check["status"] == "fail"
                && check["reason"] == "bundle.invalid_runtime_setting"));
        } else {
            assert_eq!(codes(&result), ["bundle.invalid_runtime_setting"]);
        }
        let location = &result["diagnostics"][0]["location"];
        assert_eq!(location["file"], "deployment.yaml");
        assert_eq!(location["line"], 6);
        assert_eq!(location["pointer"], "/spec/cors/allowed_origins");
    }
}

#[test]
fn credential_bearing_provider_endpoints_are_validated_offline_with_safe_locations() {
    let fixture = Fixture::valid();
    let write = |profile, spec: Value| {
        let mut spec = spec;
        spec["profile"] = json!(profile);
        fixture.write(
            "deployment.yaml",
            &json!({
                "apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayDeployment","spec":spec
            })
            .to_string(),
        );
        fixture.pin_policy_version("0.1.0");
    };
    for (profile, endpoint, valid) in [
        (
            "production",
            "https://service.example.test/introspect",
            true,
        ),
        ("production", "http://127.0.0.1/introspect", false),
        ("migration", "http://service.example.test/introspect", false),
        ("development", "http://[::1]/introspect", true),
        (
            "development",
            "http://localhost.example.test/introspect",
            false,
        ),
        (
            "production",
            "https://name@service.example.test/introspect",
            false,
        ),
    ] {
        write(
            profile,
            json!({"authentication":{"providers":[{
                "name":CANARY,"type":"cookie_session","introspection_url":endpoint,"user_id_claim":"sub"
            }]}}),
        );
        for command in ["validate", "doctor"] {
            let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
            assert_eq!(
                exit,
                if valid { Exit::Success } else { Exit::Invalid },
                "{}",
                captured.stdout()
            );
            assert_no_canary(&captured);
            assert!(!captured.stdout().contains(endpoint));
            if !valid {
                let result = report(&captured);
                assert!(result["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["code"] == "profile.provider_transport"
                        && d["location"]["pointer"]
                            == "/spec/authentication/providers/0/introspection_url"));
            }
        }
    }
    let mut spec = json!({"authentication":{"providers":[
        {"name":CANARY,"type":"jwt","issuer":"http://issuer.example.test","jwks_url":"http://keys.example.test/keys"}
    ]}});
    write("production", spec.clone());
    assert_eq!(run(&["validate", fixture.path()]).0, Exit::Success);
    spec["admin_login"] = json!({"provider":CANARY,"client_id":CANARY,"client_secret":{"secret":CANARY},"redirect_uri":"https://admin.example.test/callback"});
    write("production", spec);
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_no_canary(&captured);
    let result = report(&captured);
    let pointers: BTreeSet<_> = result["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "profile.provider_transport")
        .map(|d| d["location"]["pointer"].as_str().unwrap())
        .collect();
    assert_eq!(
        pointers,
        BTreeSet::from([
            "/spec/authentication/providers/0/issuer",
            "/spec/authentication/providers/0/jwks_url"
        ])
    );
}

#[test]
fn validate_and_doctor_check_bundle_providers_and_admin_login_offline() {
    let fixture = Fixture::valid();
    let issuer = format!("https://{CANARY}.example");
    let provider = json!({"name": CANARY, "type": "jwt", "issuer": issuer});
    let mut client = json!({
        "provider": CANARY,
        "client_id": CANARY,
        "redirect_uri": "https://admin.example/callback",
        "client_secret": {"secret": CANARY}
    });
    let write = |providers: Value, login: &Value| {
        fixture.write("deployment.yaml", &format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n  authentication:\n    providers: {providers}\n  admin_login: {login}\n"
        ));
        fixture.pin_policy_version("0.1.0");
    };
    write(json!([provider]), &client);
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Success, "{}", captured.stdout());
        assert_no_canary(&captured);
    }

    // An alias on its own cannot select a login provider. A JWT provider
    // with a JWKS URL alone can verify tokens, but login needs an issuer.
    for (providers, login) in [
        (
            json!([provider]),
            json!({"client_secret": {"secret": CANARY}}),
        ),
        (
            json!([{"name": CANARY, "type": "jwt", "jwks_url": issuer}]),
            client.clone(),
        ),
    ] {
        write(providers, &login);
        let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_no_canary(&captured);
        let result = report(&captured);
        assert_eq!(codes(&result), ["bundle.invalid_admin_login"]);
        assert_eq!(
            result["diagnostics"][0]["location"]["pointer"],
            "/spec/admin_login/provider"
        );
    }

    client.as_object_mut().unwrap().remove("client_secret");
    let mut duplicate_issuer = provider.clone();
    duplicate_issuer["name"] = json!("secondary");
    write(json!([provider, duplicate_issuer]), &client);
    for command in ["validate", "doctor"] {
        let (exit, captured) = run(&[command, fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_no_canary(&captured);
        let result = report(&captured);
        let diagnostics = result["diagnostics"].as_array().unwrap();
        for (code, pointer) in [
            (
                "bundle.invalid_auth_provider",
                "/spec/authentication/providers",
            ),
            (
                "bundle.invalid_admin_login",
                "/spec/admin_login/client_secret",
            ),
        ] {
            assert!(diagnostics.iter().any(|item| item["code"] == code
                && item["location"]["pointer"] == pointer
                && item["location"]["file"] == "deployment.yaml"));
        }
        if command == "doctor" {
            let checks = result["result"]["checks"].as_array().unwrap();
            assert!(checks
                .iter()
                .any(|check| check["id"] == "bundle.structure" && check["status"] == "fail"));
        }
    }
    for providers in [
        json!([{"name":CANARY,"type":"cookie_session"}]),
        json!([provider, provider]),
    ] {
        write(providers, &json!({}));
        let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid);
        assert_eq!(codes(&report(&captured)), ["bundle.invalid_auth_provider"]);
        assert_no_canary(&captured);
    }
}

#[test]
fn an_invalid_bundle_exits_3_with_located_value_free_diagnostics() {
    let fixture = Fixture::valid();
    // The policy changes after it was pinned, and its unknown member names a
    // value that must never be echoed.
    fixture.write(
        "policy.json",
        &format!("{{\"schema_version\": \"0.1.0\", \"{CANARY}\": \"{CANARY}\"}}\n"),
    );
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        captured.stdout(),
        "bundle payments-production (greengateway.dev/v1alpha1): invalid, 1 error\n  \
         deployment     deployment.yaml\n  \
         policy         policy.json (schema_version 0.1.0)\n  \
         tools          tools.json (schema_version 0.1.0)\n  \
         connections    server\n"
    );
    assert!(captured.stderr().starts_with(
        "ggctl: error: bundle.digest_mismatch: a file's SHA-256 digest differs from the digest the manifest pins\n  at: policy.json\n  see: docs/configuration-bundles.md#diagnostics\n"
    ));
    assert_no_canary(&captured);

    // Pinned again, the unknown member itself is reported by position.
    fixture.pin("      source: bundle\n      path: policy.json\n      schema_version: \"0.1.0\"\n      sha256: \"POLICY\"\n");
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(found["result"]["valid"], false);
    assert!(found["result"]["bundle"].get("sourceDigest").is_none());
    assert_eq!(
        found["diagnostics"][0],
        json!({
            "code": "resource.unknown_member",
            "severity": "error",
            "message": "the policy schema does not define this top-level member",
            "remediation": "docs/configuration-bundles.md#diagnostics",
            "location": {"file": "policy.json", "pointer": "", "line": 1, "column": 29},
        })
    );
    assert_no_canary(&captured);
}

#[test]
fn a_production_policy_is_held_to_the_profile_invariants() {
    let policy = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"allow\",\n  \"enforcement_mode\": \"shadow\",\n  \"roles\": {\"ops\": {\"permissions\": [\"read\", \"*\"]}},\n  \"routes\": [{\"path_prefix\": \"/a\", \"permission\": \"read\", \"enforcement_mode\": \"shadow\"}]\n}\n";
    for profile in ["production", "migration"] {
        let fixture = Fixture::with(profile, policy);
        let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid, "{profile}");
        let found = report(&captured);
        let located: Vec<_> = found["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic["code"].as_str().expect("code").to_owned(),
                    diagnostic["location"]["pointer"]
                        .as_str()
                        .expect("pointer")
                        .to_owned(),
                    diagnostic["location"]["line"].as_u64().expect("line"),
                )
            })
            .collect();
        assert_eq!(
            located,
            [
                (
                    "profile.policy_default_allow".to_owned(),
                    "/default_action".to_owned(),
                    3
                ),
                (
                    "profile.policy_shadow_mode".to_owned(),
                    "/enforcement_mode".to_owned(),
                    4
                ),
                ("profile.wildcard_role".to_owned(), "/roles".to_owned(), 5),
                (
                    "profile.policy_shadow_mode".to_owned(),
                    "/routes/0/enforcement_mode".to_owned(),
                    6
                ),
            ],
            "{profile}"
        );
    }

    // The development profile adds no policy invariant, and every report
    // labels it non-production.
    let fixture = Fixture::with("development", policy);
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stdout()
        .contains("  deployment     deployment.yaml (profile development, non-production)\n"));
}

#[test]
fn warnings_pass_unless_strict_or_warnings_as_errors() {
    let fixture = Fixture::valid();
    fixture.write("notes.txt", "an entry the manifest does not reference\n");

    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(codes(&found), ["bundle.unreferenced_entry"]);
    assert_eq!(found["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        found["diagnostics"][0]["location"],
        json!({"file": "notes.txt", "pointer": ""})
    );

    let (exit, captured) = run(&[
        "validate",
        fixture.path(),
        "--warnings-as-errors",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        found["diagnostics"][1],
        json!({
            "code": "validate.warnings_as_errors",
            "severity": "error",
            "message": "--warnings-as-errors was given and a warning was reported",
            "remediation": "docs/ggctl.md#validate-diagnostics",
            "location": {"argument": 3},
        })
    );

    let (exit, captured) = run(&["validate", "--strict", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(
        captured.stdout().ends_with("invalid, 1 error\n")
            || captured.stdout().contains(": invalid, 1 error\n")
    );
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: bundle.unreferenced_entry: "));

    // Without warnings the flag changes nothing.
    let clean = Fixture::valid();
    let (exit, _) = run(&["validate", clean.path(), "--warnings-as-errors"]);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn a_bundle_that_cannot_be_read_exits_1() {
    let fixture = Fixture::empty();
    let missing = fixture.root.join("missing");
    let missing = missing.to_str().expect("UTF-8");
    let (exit, captured) = run(&["validate", missing, "--format", "json"]);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    assert_eq!(found["outcome"], "failure");
    assert_eq!(found["result"], json!({"valid": false}));
    assert_eq!(codes(&found), ["bundle.root_unavailable"]);
    assert!(found["diagnostics"][0].get("location").is_none());
    // The path is an argument and is never echoed.
    assert!(!captured.stdout().contains(missing));

    let (exit, captured) = run(&["validate", missing]);
    assert_eq!(exit, Exit::Failure);
    assert_eq!(captured.stdout(), "bundle: invalid, 1 error\n");

    // An empty directory is a bundle without a manifest: invalid, not I/O.
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: bundle.manifest_missing: "));
}

#[test]
fn sarif_carries_the_diagnostics_alone_and_keeps_the_exit_code() {
    let fixture = Fixture::valid();
    fixture.write("notes.txt", "unreferenced\n");
    fixture.write(
        "tools.json",
        "{\"schema_version\": \"0.1.0\", \"tools\": []}\n",
    );
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "sarif"]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().is_empty());
    let log: Value = serde_json::from_str(captured.stdout()).expect("one SARIF log");
    assert_eq!(log["version"], "2.1.0");
    let results = log["runs"][0]["results"].as_array().expect("results");
    let summary: Vec<_> = results
        .iter()
        .map(|result| {
            (
                result["ruleId"].as_str().expect("rule"),
                result["level"].as_str().expect("level"),
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("bundle.digest_mismatch", "error", Some("tools.json")),
            ("bundle.unreferenced_entry", "warning", Some("notes.txt")),
        ]
    );
    assert!(!captured.stdout().contains(fixture.path()));
}

#[test]
fn only_validate_and_diff_offer_sarif() {
    for words in [
        &["doctor", "x", "--format", "sarif"][..],
        &["schema", "--format", "sarif"],
    ] {
        let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        match cli::parse(&arguments) {
            Err(diagnostic) => assert_eq!(diagnostic.code, Code::InvalidValue, "{words:?}"),
            Ok(parsed) => panic!("{words:?} should be refused, got {parsed:?}"),
        }
    }
}

#[test]
fn ggctl_and_bundle_reader_codes_never_share_a_spelling() {
    // A report carries both catalogs, so a code must name one meaning.
    let mut seen = BTreeSet::new();
    for code in Code::ALL {
        assert!(seen.insert(code.as_str()), "{}", code.as_str());
    }
    for code in gateway_config::bundle::Code::ALL {
        assert!(
            seen.insert(code.as_str()),
            "{} is also a ggctl code",
            code.as_str()
        );
    }
    for reason in crate::doctor::Reason::ALL {
        assert!(seen.insert(reason.as_str()), "{}", reason.as_str());
    }
}
