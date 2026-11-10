//! Race one approved request on two separately running gateways, then restart its winner.

use super::{
    admin_token, capability_execution_precondition, etag, harness, mutation_tls::MutationUpstream,
    oidc, send_settled, skipped, start_secure_cluster, Cluster, ClusterOptions, ADMIN_ROLE,
    CONNECTIONS_ROUTE, CONNECTION_COLLECTION_ETAG_HEADER, TOOLS_ROUTE,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://ha-gateway.example.test";
const AUDIENCE: &str = "https://widgets.example.test";
const SIGNER: &str = "ha-widget-signer";
const CA: &str = "ha-widget-ca";
const TOOL: &str = "createWidget";
const SPEC: &str = r#"
openapi: 3.0.3
info: {title: Widgets, version: '1'}
paths:
  /widgets:
    post:
      operationId: createWidget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties: {name: {type: string}}
      responses: {'200': {description: Created}}
"#;

async fn register(cluster: &Cluster, upstream: &MutationUpstream, operator: &str) {
    let signer = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    cluster.provision_connection_secret(SIGNER, signer.serialize_pem().as_bytes());
    cluster.provision_connection_secret(CA, upstream.ca_pem().as_bytes());
    let (status, headers, list) =
        send_settled(|| cluster.get("a", CONNECTIONS_ROUTE).bearer(operator)).await;
    assert_eq!(status, 200, "{list}");
    let collection = headers[CONNECTION_COLLECTION_ETAG_HEADER].to_str().unwrap();
    let connection = json!({
        "display_name":"HA widgets", "enabled":true, "kind":"http_api",
        "endpoint":{"base_url":upstream.base_url(),"base_path":"/v1"},
        "authentication":{"type":"none"}, "tls":{"ca_bundle_alias":CA},
        "discovery":{"type":"managed_openapi","use_connection_authentication":false},
        "caller_assertion":{
            "signing_key_id":SIGNER, "kid":"ha-widgets", "algorithm":"es256",
            "issuer":ISSUER, "audience":AUDIENCE, "token_type":"at+jwt",
            "header_name":"X-HA-Mutation-Assertion", "lifetime_seconds":60,
            "bind_request":true, "bind_approval":true, "approval_mode":"managed_http_mutation_v1"
        }
    });
    let (status, headers, created) = send_settled(|| {
        cluster
            .post("a", CONNECTIONS_ROUTE)
            .bearer(operator)
            .if_match(collection)
            .json(&connection)
    })
    .await;
    assert_eq!(status, 201, "{created}");
    let connection_etag = etag(&headers, "Connection creation");
    let connection_id = created["id"].as_str().unwrap();
    let catalog = format!("{CONNECTIONS_ROUTE}/{connection_id}/openapi");
    let (status, _, preview) = send_settled(|| {
        cluster
            .post("a", &format!("{catalog}/preview"))
            .bearer(operator)
            .json(&json!({"spec":SPEC}))
    })
    .await;
    assert_eq!(status, 200, "{preview}");
    let registration = json!({
        "spec":SPEC, "spec_digest":preview["spec_digest"],
        "expected_spec_revision":preview["spec_revision"],
        "expected_catalog_revision":preview["catalog_revision"],
        "security_confirmations":preview["security_confirmations"],
        "selected_tool_names":[TOOL]
    });
    let (status, _, result) = send_settled(|| {
        cluster
            .post("a", &format!("{catalog}/register"))
            .bearer(operator)
            .if_match(&connection_etag)
            .json(&registration)
    })
    .await;
    assert_eq!(status, 201, "{result}");
    assert_eq!(result["registered_tool_names"], json!([TOOL]));
}

fn role_token(cluster: &Cluster, subject: &str, role: &str) -> String {
    cluster.oidc.mint_role_token(
        oidc::PRIMARY_KID,
        subject,
        &uuid::Uuid::new_v4().to_string(),
        &[role],
        3600,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_spend_one_approved_mutation_and_reject_replay_after_restart() {
    let aliases: Vec<Value> = [SIGNER, CA]
        .into_iter()
        .map(|id| json!({"id":id, "label":id, "source":{"type":"file","key":id}}))
        .collect();
    let policy = json!({
        "schema_version":"0.1.0", "default_action":"allow", "enforcement_mode":"enforce",
        "routes":[], "rules":[],
        "roles":{
            ADMIN_ROLE:{"permissions":["*"]},
            "requester":{"permissions":["admin:tools:read","admin:tools:execute"]},
            "reviewer":{"permissions":["admin:tools:approvals:review"]}
        },
        "tools":{TOOL:{"enabled":true,"allowed_roles":["requester"],"timeout_ms":5000,"max_concurrent":2}}
    });
    let options = ClusterOptions {
        seed_policy: Some(policy.to_string()),
        shared_env: vec![(
            "CONNECTION_SECRET_ALIASES".into(),
            json!(aliases).to_string(),
        )],
        ..ClusterOptions::default()
    };
    let Some(mut cluster) = start_secure_cluster(options).await else {
        return skipped();
    };
    let upstream = MutationUpstream::start().await;
    let operator = admin_token(&cluster.oidc, "operator");
    let requester = role_token(&cluster, "alice", "requester");
    let reviewer = role_token(&cluster, "bob", "reviewer");
    register(&cluster, &upstream, &operator).await;
    let (a, b) = tokio::join!(
        capability_execution_precondition(&cluster, "a", &requester, TOOL),
        capability_execution_precondition(&cluster, "b", &requester, TOOL)
    );
    assert_eq!(
        a, b,
        "both replicas must observe the same executable capability"
    );
    let (capability, precondition) = a;
    let approvals = format!("{TOOLS_ROUTE}/{capability}/mutation-approvals");
    let args = json!({"arguments":{"name":"approved change"}});
    let (status, pending) = cluster
        .post("a", &approvals)
        .bearer(&requester)
        .if_match(&precondition)
        .json(&args)
        .send()
        .await;
    assert_eq!(status, 201, "{pending}");
    assert_eq!(pending["status"], "pending");
    let id = pending["id"].as_str().unwrap();
    let record = format!("/v1/admin/mutation-approvals/{id}");
    let (status, reviewed) = cluster
        .post("b", &format!("{record}/review"))
        .bearer(&reviewer)
        .json(&json!({"decision":"approve"}))
        .send()
        .await;
    assert_eq!(status, 200, "{reviewed}");
    assert_eq!(reviewed["status"], "approved");
    assert_eq!(upstream.accepted_connections(), 0);

    let route = format!("{approvals}/{id}/execute");
    let execute = |cluster: &Cluster, replica: &str| -> harness::PinnedRequest {
        cluster
            .post(replica, &route)
            .bearer(&requester)
            .if_match(&precondition)
            .json(&args)
    };
    let (left, right) = tokio::join!(execute(&cluster, "a").send(), execute(&cluster, "b").send());
    let (winner, loser) = match (left.0, right.0) {
        (200, 409) => ("a", right.1),
        (409, 200) => ("b", left.1),
        _ => panic!("expected one success and one refusal: A {left:?}, B {right:?}"),
    };
    assert_eq!(loser["reason"], "mutation_approval_state_conflict");
    for replica in ["a", "b"] {
        let (status, jwks) = cluster
            .get(replica, "/.well-known/caller-assertion-jwks.json")
            .send()
            .await;
        assert_eq!(status, 200, "{jwks}");
        upstream.assert_one_verified_request(
            &jwks,
            id,
            ISSUER,
            AUDIENCE,
            &cluster.oidc.issuer,
            "alice",
        );
    }
    cluster.restart(winner).await;
    cluster.wait_until_all_ready().await;
    for replica in ["a", "b"] {
        let (status, _, consumed) =
            send_settled(|| cluster.get(replica, &record).bearer(&requester)).await;
        assert_eq!(status, 200, "{consumed}");
        assert_eq!(consumed["status"], "consumed");
        let (status, replay) = execute(&cluster, replica).send().await;
        assert_eq!(status, 409, "{replay}");
        assert_eq!(replay["reason"], "mutation_approval_state_conflict");
    }
    assert_eq!(upstream.accepted_connections(), 1);
}
