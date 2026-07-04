use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const SCHEMA_VERSION: &str = "0.1.0";
pub const POLICY_CHANGED: &str = "policy.changed";
pub const SIGNAL_LIFECYCLE_CHANGED: &str = "signal.lifecycle_changed";
pub const TRAFFIC_ENDPOINT_REVIEW_CHANGED: &str = "traffic.endpoint_review_changed";

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
            roles: None,
            auth_mode: "api_key".to_owned(),
        };

        let serialized = serde_json::to_value(actor).expect("actor should serialize");

        assert_eq!(serialized["user_id"], json!("user-123"));
        assert_eq!(serialized["auth_mode"], json!("api_key"));
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
