use std::{fs, path::PathBuf};

use serde_json::{json, Value as JsonValue};

use super::*;
use crate::{
    bundle::{
        read_bundle, BundleReport, BundledResource, PublishedSchemasOnly, ReadOptions,
        MANIFEST_FILE_NAME,
    },
    documents::published_schema,
};

const CANARY: &str = "zqcanaryinit";

/// A directory the scaffold is written into, removed on drop.
struct Written {
    root: PathBuf,
}

impl Drop for Written {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Written {
    fn new(files: &[BundleFile]) -> Self {
        let root =
            std::env::temp_dir().join(format!("greengateway-bundle-init-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("temporary bundle directory should create");
        #[cfg(unix)]
        set_mode(&root, 0o700);
        for file in files {
            let path = root.join(file.name.as_str());
            fs::write(&path, &file.bytes).expect("bundle file should write");
            #[cfg(unix)]
            set_mode(&path, 0o600);
        }
        fs::write(root.join(".gitattributes"), GITATTRIBUTES).expect("attributes should write");
        Self { root }
    }

    fn read(&self) -> BundleReport<JsonValue, JsonValue> {
        read_bundle(
            &self.root,
            ReadOptions { strict: true },
            &PublishedSchemasOnly,
        )
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

fn answers(text: &str) -> Answers {
    read_answers(text.as_bytes(), AnswersSyntax::Yaml)
        .unwrap_or_else(|diagnostics| panic!("{text:?} should be read: {diagnostics:?}"))
}

/// The codes and pointers `text` is refused with.
fn refused(text: &str, syntax: AnswersSyntax) -> Vec<(&'static str, String)> {
    match read_answers(text.as_bytes(), syntax) {
        Ok(answers) => panic!("{text:?} should be refused, read {answers:?}"),
        Err(diagnostics) => {
            for diagnostic in &diagnostics {
                assert!(diagnostic.file.is_none(), "{diagnostic:?}");
                let rendered = format!("{diagnostic} {diagnostic:?}");
                assert!(!rendered.contains(CANARY), "{rendered}");
            }
            diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.pointer.to_string()))
                .collect()
        }
    }
}

fn spec(body: &str) -> String {
    format!("apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\nspec:\n{body}")
}

const EMPTY: &str = "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\nspec: {}\n";

const OPERATOR: &str =
    "  operator:\n    issuer: \"provider:corporate\"\n    auth_methods: [bearer_token]\n";

fn every_answer_set() -> Vec<Answers> {
    vec![
        Answers::default(),
        answers(&spec(&format!("  name: payments\n{OPERATOR}"))),
        answers(&spec(
            "  name: edge-01\n  operator:\n    issuer: \"https://idp.example.test/realms/ops/\"\n    auth_methods: [session_cookie, bearer_token]\n",
        )),
        answers(&spec("  name: fleet\n  topology: cluster\n")),
    ]
}

#[test]
fn every_profile_and_answer_set_scaffolds_a_bundle_the_reader_accepts_strictly() {
    for profile in Profile::ALL.iter().copied() {
        for answers in every_answer_set() {
            let files = scaffold(profile, &answers);
            assert_eq!(files, scaffold(profile, &answers), "deterministic");
            let written = Written::new(&files);
            let report = written.read();
            assert!(
                report.diagnostics.is_empty(),
                "{profile:?} {answers:?}: {:?}",
                report.diagnostics
            );
            let bundle = report.bundle.expect("the scaffold should read as a bundle");
            assert_eq!(bundle.name, answers.name());
            assert_eq!(bundle.deployment.profile, profile);
            assert!(bundle.connections_from_server);
            // The reader saw exactly the files the scaffold wrote, in order.
            assert_eq!(bundle.files, files);
            match answers.topology() {
                Topology::Standalone => {
                    let Some(BundledResource::Bundle { document, .. }) = &bundle.policy else {
                        panic!("a standalone bundle supplies its policy");
                    };
                    assert_eq!(document["default_action"], "deny");
                    assert_eq!(document["enforcement_mode"], "enforce");
                    assert_eq!(document["id"], answers.name());
                    let Some(BundledResource::Bundle { document, .. }) = &bundle.tools else {
                        panic!("a standalone bundle supplies its tools");
                    };
                    assert_eq!(document["tools"], json!([]));
                    assert_eq!(files.len(), 4);
                }
                Topology::Cluster => {
                    assert!(matches!(bundle.policy, Some(BundledResource::Server)));
                    assert!(matches!(bundle.tools, Some(BundledResource::Server)));
                    assert_eq!(files.len(), 2);
                }
            }
        }
    }
}

#[test]
fn the_scaffold_names_its_files_in_the_portable_grammar() {
    for name in [MANIFEST_FILE_NAME, DEPLOYMENT_FILE, POLICY_FILE, TOOLS_FILE] {
        assert_eq!(
            FileName::parse(name).as_ref().map(FileName::as_str),
            Some(name)
        );
    }
    for file in scaffold(Profile::Production, &Answers::default()) {
        assert!(!file.bytes.contains(&b'\r'));
        assert!(file.bytes.ends_with(b"\n"));
    }
}

#[test]
fn the_default_policy_has_no_role_and_the_operator_role_is_bound_and_least_privilege() {
    let policy = |answers: &Answers| -> JsonValue {
        let files = scaffold(Profile::Production, answers);
        let file = files
            .iter()
            .find(|file| file.name.as_str() == POLICY_FILE)
            .expect("a standalone bundle has a policy");
        serde_json::from_slice(&file.bytes).expect("the policy is JSON")
    };
    assert_eq!(
        policy(&Answers::default()),
        json!({
            "schema_version": "0.1.0",
            "id": "greengateway",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {},
            "routes": []
        })
    );
    assert_eq!(
        policy(&answers(&spec(&format!("  name: payments\n{OPERATOR}")))),
        json!({
            "schema_version": "0.1.0",
            "id": "payments",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "operator": {
                    "description": "Reads the gateway's status and configuration capabilities. Generated by ggctl init.",
                    "permissions": ["admin:config:read", "admin:status:read"],
                    "issuers": ["provider:corporate"],
                    "auth_methods": ["bearer_token"]
                }
            },
            "routes": [
                {"methods": ["GET"], "path_prefix": "/v1/admin/config", "permission": "admin:config:read"},
                {"methods": ["GET"], "path_prefix": "/v1/admin/status", "permission": "admin:status:read"}
            ]
        })
    );
    // An exact issuer is written in the form the gateway compares.
    let exact = policy(&answers(&spec(
        "  operator:\n    issuer: \"https://idp.example.test/realms/ops//\"\n    auth_methods: [client_certificate, service_token]\n",
    )));
    assert_eq!(
        exact["roles"]["operator"]["issuers"],
        json!(["https://idp.example.test/realms/ops"])
    );
    assert_eq!(
        exact["roles"]["operator"]["auth_methods"],
        json!(["client_certificate", "service_token"])
    );
}

#[test]
fn the_manifest_and_deployment_document_are_the_documented_text() {
    let files = scaffold(Profile::Development, &answers(&spec("  name: lab\n")));
    let text = |name: &str| {
        let file = files
            .iter()
            .find(|file| file.name.as_str() == name)
            .expect("the file is scaffolded");
        String::from_utf8(file.bytes.clone()).expect("UTF-8")
    };
    assert_eq!(
        text(DEPLOYMENT_FILE),
        concat!(
            "# Generated by ggctl init.\n",
            "# The development profile is for local evaluation, not for production.\n",
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayDeployment\n",
            "spec:\n",
            "  profile: development\n",
        )
    );
    let pin = |name: &str| crate::bundle::sha256_pin(text(name).as_bytes());
    assert_eq!(
        text(MANIFEST_FILE_NAME),
        format!(
            concat!(
                "# Generated by ggctl init. Each sha256 pins the exact bytes of its file:\n",
                "# change a file and its pin together, then run ggctl validate.\n",
                "apiVersion: greengateway.dev/v1alpha1\n",
                "kind: GatewayBundle\n",
                "metadata:\n",
                "  name: \"lab\"\n",
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
            pin(DEPLOYMENT_FILE),
            pin(POLICY_FILE),
            pin(TOOLS_FILE),
        )
    );
    let cluster = scaffold(
        Profile::Production,
        &answers(&spec("  topology: cluster\n")),
    );
    let manifest = String::from_utf8(cluster[0].bytes.clone()).expect("UTF-8");
    assert!(manifest.ends_with(concat!(
        "  resources:\n",
        "    policy:\n",
        "      source: server\n",
        "    tools:\n",
        "      source: server\n",
        "    connections:\n",
        "      source: server\n",
    )));
    assert!(!String::from_utf8(cluster[1].bytes.clone())
        .expect("UTF-8")
        .contains("# The"));
}

#[test]
fn answers_default_every_member_and_read_the_same_from_yaml_and_json() {
    assert_eq!(answers(EMPTY), Answers::default());
    let yaml = answers(&spec(&format!(
        "  name: payments\n  topology: standalone\n{OPERATOR}"
    )));
    let json = read_answers(
        br#"{"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayInitAnswers",
            "spec": {"name": "payments", "topology": "standalone",
                     "operator": {"issuer": "provider:corporate", "auth_methods": ["bearer_token"]}}}"#,
        AnswersSyntax::Json,
    )
    .expect("the JSON answers should be read");
    assert_eq!(yaml, json);
    assert_eq!(yaml.name(), "payments");
    assert_eq!(yaml.topology(), Topology::Standalone);
    let operator = yaml.operator().expect("an operator");
    assert_eq!(operator.issuer(), "provider:corporate");
    assert_eq!(operator.auth_methods(), [AuthMethod::BearerToken]);
}

#[test]
fn answers_are_closed_exact_and_refused_with_value_free_pointers() {
    use AnswersSyntax::{Json, Yaml};
    let cases: Vec<(String, Vec<(&str, &str)>)> = vec![
        (
            "apiVersion: greengateway.dev/v1alpha2\nkind: GatewayInitAnswers\nspec: {}\n".to_owned(),
            vec![("compat.unsupported_api_version", "/apiVersion")],
        ),
        (
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayBundle\nspec: {}\n".to_owned(),
            vec![("compat.unsupported_kind", "/kind")],
        ),
        (
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\n".to_owned(),
            vec![("schema.missing_member", "/spec")],
        ),
        (
            spec(&format!("  profile: production\n  client_secret: {CANARY}\n")),
            vec![
                ("schema.unknown_member", "/spec"),
                ("schema.unknown_member", "/spec"),
            ],
        ),
        (
            spec(&format!("  name: \"{CANARY}_X\"\n")),
            vec![("schema.invalid_name", "/spec/name")],
        ),
        (
            spec("  topology: ha\n"),
            vec![("schema.invalid_value", "/spec/topology")],
        ),
        (
            spec(&format!("  topology: cluster\n{OPERATOR}")),
            vec![("schema.not_applicable", "/spec/operator")],
        ),
        (
            spec("  operator:\n    issuer: \"provider:corporate\"\n"),
            vec![("schema.missing_member", "/spec/operator/auth_methods")],
        ),
        (
            spec("  operator:\n    issuer: \"provider:corporate\"\n    auth_methods: []\n"),
            vec![("schema.invalid_value", "/spec/operator/auth_methods")],
        ),
        (
            spec("  operator:\n    issuer: \"provider:corporate\"\n    auth_methods: bearer_token\n"),
            vec![("schema.wrong_type", "/spec/operator/auth_methods")],
        ),
        (
            spec(&format!(
                "  operator:\n    issuer: \"provider:corporate\"\n    auth_methods: [bearer_token, bearer_token, {CANARY}]\n"
            )),
            vec![
                ("schema.invalid_value", "/spec/operator/auth_methods/1"),
                ("schema.invalid_value", "/spec/operator/auth_methods/2"),
            ],
        ),
        (
            "{\"apiVersion\": \"greengateway.dev/v1alpha1\", \"kind\": \"GatewayInitAnswers\", \"spec\": {\"name\": \"a\", \"name\": \"b\"}}".to_owned(),
            vec![("json.duplicate_key", "")],
        ),
    ];
    for (text, expected) in cases {
        let syntax = if text.starts_with('{') { Json } else { Yaml };
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(code, pointer)| (code, pointer.to_owned()))
            .collect();
        assert_eq!(refused(&text, syntax), expected, "{text}");
    }
    assert_eq!(
        refused(&format!("{EMPTY}\r\n"), Yaml),
        [("bundle.carriage_return", String::new())]
    );
    let large = format!(
        "{}# {}\n",
        spec("  name: a\n"),
        "x".repeat(MAX_ANSWERS_BYTES)
    );
    assert_eq!(
        refused(&large, Yaml),
        [("bundle.file_too_large", String::new())]
    );
}

#[test]
fn an_issuer_is_an_exact_https_issuer_or_an_encoded_provider_boundary() {
    for (issuer, canonical) in [
        ("https://idp.example.test", "https://idp.example.test"),
        ("https://idp.example.test/", "https://idp.example.test"),
        (
            "https://idp.example.test:8443/realms/a",
            "https://idp.example.test:8443/realms/a",
        ),
        ("provider:corporate", "provider:corporate"),
        ("provider:Corp.idp_1~-", "provider:Corp.idp_1~-"),
        ("provider:corporate%20sso", "provider:corporate%20sso"),
    ] {
        assert_eq!(
            canonical_issuer(issuer).as_deref(),
            Some(canonical),
            "{issuer}"
        );
    }
    for issuer in [
        "",
        "http://idp.example.test",
        "HTTPS://idp.example.test",
        "https://",
        "https:///",
        "https:///path",
        "https://user:pass@idp.example.test",
        "https://idp.example.test?tenant=a",
        "https://idp.example.test#a",
        "https://idp.example.test/a b",
        "https://idp.example.test/a\"b",
        "https://idp.example.test/a\\b",
        "provider:",
        "provider:corporate sso",
        "provider:a%2",
        "provider:a%2g",
        "provider:a%2f",
        "provider:a/b",
        "corporate",
    ] {
        assert_eq!(canonical_issuer(issuer), None, "{issuer:?}");
    }
    assert!(canonical_issuer(&format!("provider:{}", "a".repeat(128))).is_some());
    assert!(canonical_issuer(&format!("provider:{}", "a".repeat(129))).is_none());
    assert!(canonical_issuer(&format!("https://{}", "a".repeat(MAX_ISSUER_BYTES))).is_none());
}

#[test]
fn the_published_answers_schema_agrees_with_the_reader() {
    let schema = published_schema(API_VERSION_V1ALPHA1, INIT_ANSWERS_KIND)
        .expect("the answers schema is published");
    let schema: JsonValue = serde_json::from_str(schema.json).expect("JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let document = |spec: JsonValue| json!({"apiVersion": API_VERSION_V1ALPHA1, "kind": INIT_ANSWERS_KIND, "spec": spec});
    let accepted = [
        json!({}),
        json!({"name": "payments", "topology": "standalone"}),
        json!({"topology": "cluster"}),
        json!({"operator": {"issuer": "provider:corporate", "auth_methods": ["bearer_token"]}}),
        json!({"operator": {"issuer": "https://idp.example.test/", "auth_methods": ["session_cookie", "client_certificate"]}}),
    ];
    for spec in accepted {
        let value = document(spec);
        assert!(validator.is_valid(&value), "{value}");
        read_answers(value.to_string().as_bytes(), AnswersSyntax::Json)
            .unwrap_or_else(|diagnostics| panic!("{value}: {diagnostics:?}"));
    }
    // Every refusal the schema can express, it expresses too; the reader
    // alone refuses an operator in a cluster.
    let refused = [
        json!({"profile": "production"}),
        json!({"name": "Payments"}),
        json!({"topology": "ha"}),
        json!({"operator": {"issuer": "provider:corporate"}}),
        json!({"operator": {"issuer": "provider:corporate", "auth_methods": []}}),
        json!({"operator": {"issuer": "provider:corporate", "auth_methods": ["bearer_token", "bearer_token"]}}),
        json!({"operator": {"issuer": "http://idp.example.test", "auth_methods": ["bearer_token"]}}),
        json!({"operator": {"issuer": "https://a@idp.example.test", "auth_methods": ["bearer_token"]}}),
        json!({"operator": {"issuer": "provider:a b", "auth_methods": ["bearer_token"]}}),
    ];
    for spec in refused {
        let value = document(spec);
        assert!(!validator.is_valid(&value), "{value}");
        assert!(read_answers(value.to_string().as_bytes(), AnswersSyntax::Json).is_err());
    }
    let cluster_operator = document(
        json!({"topology": "cluster", "operator": {"issuer": "provider:corporate", "auth_methods": ["bearer_token"]}}),
    );
    assert!(validator.is_valid(&cluster_operator));
    assert!(read_answers(cluster_operator.to_string().as_bytes(), AnswersSyntax::Json).is_err());
}
