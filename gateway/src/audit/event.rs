use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const SCHEMA_VERSION: &str = "0.1.0";

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
    fn serialized_event_has_schema_required_fields() {
        let event = AuditEvent::new(
            "policy.deny",
            "request-456",
            "2001:db8::1",
            None,
            json!({ "resource": "/admin" }),
        );
        let serialized = serde_json::to_value(event).expect("audit event should serialize");
        let object = serialized
            .as_object()
            .expect("audit event should serialize as an object");

        for field in [
            "event_id",
            "event_type",
            "timestamp",
            "schema_version",
            "request_id",
            "source_ip",
            "actor",
            "payload",
        ] {
            assert!(object.contains_key(field), "missing field {field}");
        }

        assert!(object["event_id"].is_string());
        assert!(object["event_type"].is_string());
        assert!(object["timestamp"].is_string());
        assert_eq!(object["schema_version"], json!(SCHEMA_VERSION));
        assert!(object["request_id"].is_string());
        assert!(object["source_ip"].is_string());
        assert!(object["actor"].is_null());
        assert!(object["payload"].is_object());
        assert!(!object.contains_key("user_agent"));
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
}
