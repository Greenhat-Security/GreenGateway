use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const SCHEMA_VERSION: &str = "0.2.0";
pub const POLICY_CHANGED: &str = "policy.changed";
pub const POLICY_SHADOW_TRANSITION_REFUSED: &str = "policy.shadow_transition_refused";
/// A server-side policy draft was created, changed or deleted (issue #243,
/// slice 9). Drafts are inactive, so this records workspace activity, not an
/// authorization change.
pub const POLICY_DRAFT_CHANGED: &str = "policy.draft_changed";
/// A draft was published: its candidate became the live policy. Emitted in
/// addition to the `policy.changed` event of the commit itself.
pub const POLICY_DRAFT_PUBLISHED: &str = "policy.draft_published";
/// A publication of a draft its owner holds was refused without writing.
pub const POLICY_DRAFT_PUBLISH_REFUSED: &str = "policy.draft_publish_refused";
pub const SIGNAL_OPENED: &str = "signal.opened";
pub const SIGNAL_LIFECYCLE_CHANGED: &str = "signal.lifecycle_changed";
pub const SUGGESTION_LIFECYCLE_CHANGED: &str = "suggestion.lifecycle_changed";
/// A policy test suite was run (issue #243, slice 11). Records the policy
/// ETag, suite digest and counts of a completed run, never its cases.
pub const POLICY_TESTS_RUN: &str = "policy.tests_run";
/// A policy simulation completed (issue #243, slice 10). Records the base
/// and candidate ETags, the request digest and counts, never its cases.
pub const POLICY_SIMULATION_RUN: &str = "policy.simulation_run";
/// A historical replay job was admitted (issue #243, slice 13). Records the
/// job id, the base and candidate ETags, the request digest, the window, its
/// cutoff and counts; never a record, a principal or policy content. A job
/// whose start is not recorded is never queued.
pub const POLICY_REPLAY_STARTED: &str = "policy.replay_started";
/// A replay job finished reading its window, completely or not: its state,
/// limitation codes, result digest and counts.
pub const POLICY_REPLAY_COMPLETED: &str = "policy.replay_completed";
/// A replay job was cancelled before it produced a result.
pub const POLICY_REPLAY_CANCELLED: &str = "policy.replay_cancelled";
/// A replay job failed with a stable reason and produced no result.
pub const POLICY_REPLAY_FAILED: &str = "policy.replay_failed";
/// A structural policy analysis completed (issue #243, slice 15). Records
/// the base and candidate ETags, the request digest, completeness and
/// finding counts, never a finding's element or policy content.
pub const POLICY_ANALYSIS_RUN: &str = "policy.analysis_run";
pub const SERVICE_TOKEN_CHANGED: &str = "service_token.changed";
pub const SERVICE_TOKEN_DELEGATION_REJECTED: &str = "service_token.delegation_rejected";
/// A policy write the cross-resource checks refused before any authority saw
/// it (issue #243, slice 8): an administrator lockout, or a write bound to a
/// resource snapshot that is no longer current.
/// Codes, the replaced policy's ETag and the resource snapshot digest only.
pub const POLICY_PUBLICATION_REFUSED: &str = "policy.publication_refused";
/// A write of an operation gated on member capabilities was refused because
/// not every live cluster member advertises what it requires (issue #426).
/// Cluster mode only: standalone mode has no roster to gate on.
#[cfg(feature = "postgres")]
pub const CLUSTER_OPERATION_REFUSED: &str = "cluster.operation_refused";
/// Admitting an operation that declares a durable activation fence raised
/// the deployment's contract fence (issue #426): from then on a gateway
/// build without the operation's capability cannot start or rejoin.
#[cfg(feature = "postgres")]
pub const CLUSTER_CONTRACT_FENCE_RAISED: &str = "cluster.contract_fence_raised";
/// A running replica's heartbeat found the durable contract fence excluding
/// its build (issue #426): it writes nothing more to the roster and refuses
/// readiness for good.
#[cfg(feature = "postgres")]
pub const CLUSTER_CONTRACT_FENCED: &str = "cluster.contract_fenced";
/// A cluster replica resolved the authority pseudonym keyring its delivered
/// authority events are referenced under (issue #425): the authority ID, the
/// current and previous key IDs and the sink kind, never key material.
#[cfg(feature = "postgres")]
pub const AUTHORITY_EVENT_KEYRING_LOADED: &str = "authority_event.keyring_loaded";
/// `AUTHORITY_EVIDENCE_DURABILITY=required` refused an authority change this
/// deployment mode records no evidence of (issue #425, PR 4): the operation
/// code, the mode, what asked for it and the reason, never its content.
pub const AUTHORITY_EVIDENCE_OPERATION_REFUSED: &str = "authority_evidence.operation_refused";
pub const CONNECTION_CHANGED: &str = "connection.changed";
pub const CONNECTION_CREDENTIAL_CHANGED: &str = "connection.credential_changed";
pub const CONNECTION_SECRET_CHANGED: &str = "connection.secret_changed";
pub const CONNECTION_REFRESHED: &str = "connection.refreshed";
pub const CONNECTION_TESTED: &str = "connection.tested";
pub const CONNECTION_OAUTH_TOKEN_REFRESH: &str = "connection.oauth_token_refresh";
/// One RFC 8693 exchange a `delegated_issuer_token` Connection made for a
/// caller (issue #441): the actor it was made for, the outcome and the
/// issuer's decision, never any token.
pub const CONNECTION_DELEGATED_TOKEN_EXCHANGE: &str = "connection.delegated_token_exchange";
/// One mint of a caller's own Google token by a `google_domain_wide_delegation`
/// Connection (issue #442): the actor it was minted for, the service account
/// and scopes, how far it got and Google's status and registered error code,
/// never the assertion or any token.
pub const CONNECTION_GOOGLE_DELEGATION_TOKEN: &str = "connection.google_delegation_token";
/// One decision about the signed caller assertion of a request a
/// connection-bound proxy route forwards (issue #463): the `kid` and `jti` of
/// the assertion it carried, or the reason it was refused. The caller is the
/// actor; the token and the key are never recorded. Tool calls record theirs
/// on `tool.upstream_request` instead.
pub const CONNECTION_CALLER_ASSERTION: &str = "connection.caller_assertion";
/// A purge of one principal's cached delegated tokens (issue #441): what started it, whose tokens
/// they were, and how many entries left the cache.
pub const CONNECTION_DELEGATED_TOKEN_PURGE: &str = "connection.delegated_token_purge";
/// One RFC 7009 revocation of a purged delegated token at its issuer (issue #441): the outcome and
/// the issuer's answer, never the token.
pub const CONNECTION_DELEGATED_TOKEN_REVOCATION: &str = "connection.delegated_token_revocation";
pub const CONNECTION_SECRET_RESOLUTION_FAILED: &str = "connection.secret_resolution_failed";
pub const CONNECTION_UNSAFE_METHOD_REJECTED: &str = "connection.unsafe_method_rejected";
pub const GATEWAY_READY: &str = "gateway.ready";
pub const GATEWAY_SHUTDOWN_STARTED: &str = "gateway.shutdown_started";
pub const GATEWAY_SHUTDOWN_COMPLETED: &str = "gateway.shutdown_completed";
pub const GATEWAY_SHUTDOWN_FORCED: &str = "gateway.shutdown_forced";
pub const INBOUND_TLS_RELOADED: &str = "inbound_tls.reloaded";
pub const INBOUND_TLS_RELOAD_FAILED: &str = "inbound_tls.reload_failed";
pub const TRAFFIC_ENDPOINT_REVIEW_CHANGED: &str = "traffic.endpoint_review_changed";
pub const TOOL_INVOKE_START: &str = "tool.invoke_start";
pub const TOOL_INVOKE_SUCCESS: &str = "tool.invoke_success";
pub const TOOL_INVOKE_FAILURE: &str = "tool.invoke_failure";
pub const TOOL_INVOKE_REJECTED: &str = "tool.invoke_rejected";
pub const TOOL_PLAYGROUND_OUTPUT_REJECTED: &str = "tool.playground_output_rejected";
pub const TOOL_TRANSFORM_WARNING: &str = "tool.transform_warning";
pub const TOOL_UPSTREAM_REQUEST: &str = "tool.upstream_request";
pub const TOOL_COMPOSITE_COMPLETED: &str = "tool.composite_completed";
pub const TOOL_REGISTRY_CHANGED: &str = "tool_registry.changed";
pub const TOOL_REGISTRY_LOADED: &str = "tool_registry.loaded";
pub const TOOL_REGISTRY_RELOAD_FAILED: &str = "tool_registry.reload_failed";
pub const UPSTREAM_RETRY_EXHAUSTED: &str = "upstream.retry_exhausted";
pub const UPSTREAM_CIRCUIT_STATE_CHANGED: &str = "upstream.circuit_state_changed";
pub const UPSTREAM_STREAM_TERMINATED: &str = "upstream.stream_terminated";
pub const UPSTREAM_WEBSOCKET_HANDSHAKE: &str = "upstream.websocket_handshake";
pub const UPSTREAM_WEBSOCKET_CLOSED: &str = "upstream.websocket_closed";
pub const UPSTREAM_GRPC_CALL: &str = "upstream.grpc_call";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: String,
    pub schema_version: String,
    pub request_id: String,
    pub source_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub actor: Option<Actor>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    pub auth_mode: String,
}

impl AuditEvent {
    pub fn new(
        event_type: impl Into<String>,
        request_id: impl Into<String>,
        source_ip: impl Into<String>,
        actor: Option<Actor>,
        payload: Value,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.into(),
            timestamp: utc_timestamp_rfc3339(),
            schema_version: SCHEMA_VERSION.to_owned(),
            request_id: request_id.into(),
            source_ip: source_ip.into(),
            user_agent: None,
            actor,
            payload,
        }
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }
}

fn utc_timestamp_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    use jsonschema::Validator;
    use serde_json::json;

    #[test]
    fn new_event_populates_envelope_fields() {
        let actor = Actor {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: Some("user@example.com".to_owned()),
            roles: Some(vec!["admin".to_owned(), "reader".to_owned()]),
            auth_mode: "session".to_owned(),
        };
        let event = AuditEvent::new(
            "auth.login",
            "request-123",
            "203.0.113.10",
            Some(actor),
            json!({ "outcome": "allow" }),
        )
        .with_user_agent("test-agent/1.0");

        assert!(uuid::Uuid::parse_str(&event.event_id).is_ok());
        assert_eq!(event.event_type, "auth.login");
        assert_eq!(event.schema_version, SCHEMA_VERSION);
        assert_eq!(event.request_id, "request-123");
        assert_eq!(event.source_ip, "203.0.113.10");
        assert_eq!(event.user_agent.as_deref(), Some("test-agent/1.0"));
        assert_eq!(event.payload, json!({ "outcome": "allow" }));
        assert!(event.timestamp.contains('T'));
        assert!(event.timestamp.ends_with('Z'));
    }

    #[test]
    fn serialized_events_validate_against_published_schema() {
        let validator = audit_event_schema_validator();
        let event_without_actor = serde_json::to_value(AuditEvent::new(
            "policy.deny",
            "request-456",
            "2001:db8::1",
            None,
            json!({ "resource": "/admin" }),
        ))
        .expect("audit event should serialize");
        let event_with_actor = serde_json::to_value(
            AuditEvent::new(
                "auth.login",
                "request-789",
                "203.0.113.10",
                Some(Actor {
                    user_id: "user-123".to_owned(),
                    issuer: Some("https://idp.example/".to_owned()),
                    email: Some("user@example.com".to_owned()),
                    roles: Some(vec!["admin".to_owned(), "reader".to_owned()]),
                    auth_mode: "session".to_owned(),
                }),
                json!({ "outcome": "allow" }),
            )
            .with_user_agent("test-agent/1.0"),
        )
        .expect("audit event should serialize");

        assert!(event_without_actor["actor"].is_null());
        assert!(event_without_actor.get("user_agent").is_none());
        assert_eq!(
            event_with_actor["actor"]["roles"],
            json!(["admin", "reader"])
        );
        assert_eq!(
            event_with_actor["actor"]["email"],
            json!("user@example.com")
        );
        assert_eq!(
            event_with_actor["actor"]["issuer"],
            json!("https://idp.example/")
        );
        assert_eq!(event_with_actor["user_agent"], json!("test-agent/1.0"));

        assert_schema_accepts(&validator, &event_without_actor);
        assert_schema_accepts(&validator, &event_with_actor);

        let mut wrong_schema_version = event_without_actor.clone();
        wrong_schema_version
            .as_object_mut()
            .expect("audit event should serialize as an object")
            .insert("schema_version".to_owned(), json!("999.0.0"));
        assert!(
            !validator.is_valid(&wrong_schema_version),
            "published schema should reject a wrong schema_version"
        );

        let mut invalid_event_type = event_with_actor;
        invalid_event_type
            .as_object_mut()
            .expect("audit event should serialize as an object")
            .insert("event_type".to_owned(), json!("PolicyDeny"));
        assert!(
            !validator.is_valid(&invalid_event_type),
            "published schema should reject an event_type that violates the pattern"
        );
    }

    #[test]
    fn serialized_actor_omits_missing_roles() {
        let actor = Actor {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: None,
            roles: None,
            auth_mode: "api_key".to_owned(),
        };

        let serialized = serde_json::to_value(actor).expect("actor should serialize");

        assert_eq!(serialized["user_id"], json!("user-123"));
        assert_eq!(serialized["auth_mode"], json!("api_key"));
        assert!(serialized.get("email").is_none());
        assert!(serialized.get("roles").is_none());
    }

    fn audit_event_schema_validator() -> Validator {
        let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = gateway_root
            .parent()
            .expect("gateway crate should live directly under the repo root");
        let schema_path = repo_root.join("docs/schemas/audit_event.v0.schema.json");
        let schema = fs::read_to_string(&schema_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", schema_path.display()));
        let schema = serde_json::from_str(&schema)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

        jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", schema_path.display()))
    }

    fn assert_schema_accepts(validator: &Validator, event: &Value) {
        if let Err(error) = validator.validate(event) {
            panic!("published schema should accept serialized audit event: {error}");
        }
    }
}
