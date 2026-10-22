//! The `GatewayCapabilities` document: the version handshake between a
//! running gateway and `ggctl` (ADR-0008, "Remote client").
//!
//! A gateway serves this document at `GET /v1{ADMIN_PREFIX}/config/capabilities`.
//! `ggctl` reads it before any configuration operation and refuses an
//! operation the server does not list, or a document version it does not
//! accept; `ggctl version --server` reports what it found either way.
//!
//! Compatibility is exact, in both directions:
//!
//! - the document is closed: a member this version does not define, a
//!   duplicate member, or a value outside its grammar makes the whole document
//!   unreadable, never partially read;
//! - a reader accepts only the `(apiVersion, kind)` it implements, so a server
//!   that moves to a new capability document version is reported as
//!   incompatible rather than misread;
//! - the `documents` and `operations` lists are open sets: a name a reader
//!   does not know is not an error, because a reader only ever asks whether
//!   the one operation and document version it is about to use are listed.
//!   Anything not listed is refused.
//!
//! The gateway reports environment mode, accepts no configuration documents
//! and enables no configuration operations today; the #242 slices that add
//! them extend these lists.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::documents::{API_VERSION_V1ALPHA1, CAPABILITIES_KIND};

/// The largest capability document a reader accepts.
pub const MAX_CAPABILITIES_BYTES: usize = 64 * 1024;
/// The most document versions a server may list.
pub const MAX_DOCUMENTS: usize = 32;
/// The most operations a server may list.
pub const MAX_OPERATIONS: usize = 64;
/// The longest gateway version string a reader accepts.
const MAX_VERSION_BYTES: usize = 64;
/// The longest operation or kind name a reader accepts.
const MAX_NAME_BYTES: usize = 64;

/// Where a gateway's deployment configuration comes from.
///
/// Only environment mode exists; bundle and ledger modes (ADR-0008) are
/// later #242 slices, and a reader that does not know a mode cannot reason
/// about it, so a new mode is a new variant every reader must learn.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    /// The process environment, exactly as today.
    Environment,
}

impl SourceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
        }
    }
}

/// One `(apiVersion, kind)` document version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DocumentVersion {
    pub api_version: String,
    pub kind: String,
}

/// The capability document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GatewayCapabilities {
    pub api_version: String,
    pub kind: String,
    /// The gateway binary's release version.
    pub gateway_version: String,
    pub source_mode: SourceMode,
    /// The configuration document versions the server accepts in
    /// configuration requests.
    pub documents: Vec<DocumentVersion>,
    /// The configuration operations the server has enabled.
    pub operations: Vec<String>,
}

impl GatewayCapabilities {
    /// What a gateway in environment mode reports today: no configuration
    /// document is accepted and no configuration operation is enabled over
    /// the admin API.
    pub fn environment(gateway_version: &str) -> Self {
        Self {
            api_version: API_VERSION_V1ALPHA1.to_owned(),
            kind: CAPABILITIES_KIND.to_owned(),
            gateway_version: gateway_version.to_owned(),
            source_mode: SourceMode::Environment,
            documents: Vec::new(),
            operations: Vec::new(),
        }
    }

    /// Whether the server lists `operation`.
    pub fn supports_operation(&self, operation: &str) -> bool {
        self.operations.iter().any(|listed| listed == operation)
    }

    /// Whether the server accepts exactly this document version.
    pub fn accepts_document(&self, api_version: &str, kind: &str) -> bool {
        self.documents
            .iter()
            .any(|listed| listed.api_version == api_version && listed.kind == kind)
    }
}

/// Why a capability document could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadError {
    /// Larger than [`MAX_CAPABILITIES_BYTES`]; nothing was parsed.
    TooLarge,
    /// Not a JSON object with readable `apiVersion` and `kind` members.
    NotADocument,
    /// A capability document version this reader does not implement. The
    /// gateway version is kept when the document states a well-formed one,
    /// so a read-only caller can still report it.
    UnsupportedVersion { gateway_version: Option<String> },
    /// The supported version, but not a valid document of it.
    Invalid { gateway_version: Option<String> },
}

/// The members every capability document version keeps, read without
/// interpreting anything else.
#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "apiVersion")]
    api_version: Option<Value>,
    kind: Option<Value>,
    #[serde(rename = "gatewayVersion")]
    gateway_version: Option<Value>,
}

/// Reads a capability document strictly.
pub fn read(bytes: &[u8]) -> Result<GatewayCapabilities, ReadError> {
    if bytes.len() > MAX_CAPABILITIES_BYTES {
        return Err(ReadError::TooLarge);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| ReadError::NotADocument)?;
    let gateway_version = envelope
        .gateway_version
        .as_ref()
        .and_then(Value::as_str)
        .filter(|version| is_release_version(version))
        .map(str::to_owned);
    let (Some(Value::String(api_version)), Some(Value::String(kind))) =
        (&envelope.api_version, &envelope.kind)
    else {
        return Err(ReadError::NotADocument);
    };
    if api_version != API_VERSION_V1ALPHA1 || kind != CAPABILITIES_KIND {
        return Err(ReadError::UnsupportedVersion { gateway_version });
    }
    let invalid = || ReadError::Invalid {
        gateway_version: gateway_version.clone(),
    };
    let document: GatewayCapabilities = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if is_valid(&document) {
        Ok(document)
    } else {
        Err(invalid())
    }
}

fn is_valid(document: &GatewayCapabilities) -> bool {
    is_release_version(&document.gateway_version)
        && document.documents.len() <= MAX_DOCUMENTS
        && document.operations.len() <= MAX_OPERATIONS
        && document
            .documents
            .iter()
            .all(|listed| is_api_version(&listed.api_version) && is_kind(&listed.kind))
        && document.operations.iter().all(|name| is_operation(name))
        && all_distinct(document.documents.iter())
        && all_distinct(document.operations.iter())
}

fn all_distinct<T: PartialEq>(items: impl Iterator<Item = T> + Clone) -> bool {
    items
        .clone()
        .enumerate()
        .all(|(index, item)| items.clone().take(index).all(|earlier| earlier != item))
}

/// `MAJOR.MINOR.PATCH` with an optional SemVer pre-release and build suffix,
/// bounded, so a server cannot put arbitrary text into an operator's
/// terminal through its version.
pub fn is_release_version(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_VERSION_BYTES {
        return false;
    }
    let (core, suffix) = match text.find(['-', '+']) {
        Some(index) => (&text[..index], &text[index + 1..]),
        None => (text, ""),
    };
    let mut numbers = core.split('.');
    let numeric = numbers
        .by_ref()
        .take(3)
        .filter(|number| {
            !number.is_empty()
                && number.len() <= 9
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        .count();
    numeric == 3
        && numbers.next().is_none()
        && (text.len() == core.len()
            || (!suffix.is_empty()
                && suffix.split(['.', '+', '-']).all(|identifier| {
                    !identifier.is_empty()
                        && identifier.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })))
}

/// `group/version`, lowercase, as `apiVersion` is spelled.
fn is_api_version(text: &str) -> bool {
    let Some((group, version)) = text.split_once('/') else {
        return false;
    };
    !group.is_empty()
        && group.len() <= 63
        && group.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && !version.is_empty()
        && version.len() <= 63
        && version
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// An upper camel case kind name.
fn is_kind(text: &str) -> bool {
    text.len() <= MAX_NAME_BYTES
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// A lowercase snake case operation name.
fn is_operation(text: &str) -> bool {
    text.len() <= MAX_NAME_BYTES
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::documents::{published_schema, BUNDLE_KIND, DEPLOYMENT_KIND};

    fn document() -> Value {
        json!({
            "apiVersion": "greengateway.dev/v1alpha1",
            "kind": "GatewayCapabilities",
            "gatewayVersion": "1.0.1",
            "sourceMode": "environment",
            "documents": [
                {"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayBundle"}
            ],
            "operations": ["validate", "plan"]
        })
    }

    fn read_value(value: &Value) -> Result<GatewayCapabilities, ReadError> {
        read(value.to_string().as_bytes())
    }

    fn schema_validator() -> jsonschema::Validator {
        let schema = published_schema(API_VERSION_V1ALPHA1, CAPABILITIES_KIND)
            .expect("the capabilities schema should be published");
        let schema: Value = serde_json::from_str(schema.json).expect("schema should be JSON");
        jsonschema::validator_for(&schema).expect("schema should compile")
    }

    #[test]
    fn the_environment_document_round_trips_and_matches_the_published_schema() {
        let capabilities = GatewayCapabilities::environment("1.0.1");
        let serialized = serde_json::to_value(&capabilities).expect("serializes");
        assert_eq!(
            serialized,
            json!({
                "apiVersion": "greengateway.dev/v1alpha1",
                "kind": "GatewayCapabilities",
                "gatewayVersion": "1.0.1",
                "sourceMode": "environment",
                "documents": [],
                "operations": []
            })
        );
        assert!(schema_validator().is_valid(&serialized));
        assert_eq!(read_value(&serialized), Ok(capabilities.clone()));
        assert!(!capabilities.supports_operation("validate"));
        assert!(!capabilities.accepts_document(API_VERSION_V1ALPHA1, BUNDLE_KIND));
    }

    #[test]
    fn a_listed_operation_or_document_is_supported_and_nothing_else_is() {
        let capabilities = read_value(&document()).expect("valid document");
        assert!(capabilities.supports_operation("validate"));
        assert!(capabilities.supports_operation("plan"));
        assert!(!capabilities.supports_operation("stage"));
        assert!(!capabilities.supports_operation("Validate"));
        assert!(capabilities.accepts_document(API_VERSION_V1ALPHA1, BUNDLE_KIND));
        assert!(!capabilities.accepts_document(API_VERSION_V1ALPHA1, DEPLOYMENT_KIND));
        assert!(!capabilities.accepts_document("greengateway.dev/v1alpha2", BUNDLE_KIND));
        assert!(schema_validator().is_valid(&document()));
    }

    #[test]
    fn unknown_names_in_the_open_lists_are_not_errors() {
        let mut value = document();
        value["operations"] = json!(["validate", "some_future_operation"]);
        value["documents"] = json!([
            {"apiVersion": "greengateway.dev/v1beta1", "kind": "GatewayBundle"}
        ]);
        let capabilities = read_value(&value).expect("open lists accept new names");
        assert!(capabilities.supports_operation("validate"));
        assert!(!capabilities.accepts_document(API_VERSION_V1ALPHA1, BUNDLE_KIND));
    }

    #[test]
    fn another_document_version_is_unsupported_and_keeps_a_well_formed_gateway_version() {
        for (api_version, kind) in [
            ("greengateway.dev/v1alpha2", "GatewayCapabilities"),
            ("greengateway.dev/v1", "GatewayCapabilities"),
            ("greengateway.dev/v1alpha1", "GatewayCapabilitiesV2"),
            ("greengateway.dev/v1alpha1", "GatewayBundle"),
        ] {
            let mut value = document();
            value["apiVersion"] = json!(api_version);
            value["kind"] = json!(kind);
            value["newMember"] = json!(true);
            assert_eq!(
                read_value(&value),
                Err(ReadError::UnsupportedVersion {
                    gateway_version: Some("1.0.1".to_owned())
                }),
                "{api_version} {kind}"
            );
            value["gatewayVersion"] = json!("1.0.1\u{1b}[31m");
            assert_eq!(
                read_value(&value),
                Err(ReadError::UnsupportedVersion {
                    gateway_version: None
                })
            );
        }
    }

    #[test]
    fn anything_but_an_exact_valid_document_is_refused_whole() {
        let mut cases = Vec::new();
        let mut unknown = document();
        unknown["limits"] = json!({});
        cases.push(unknown);
        for member in ["gatewayVersion", "sourceMode", "documents", "operations"] {
            let mut missing = document();
            missing.as_object_mut().expect("object").remove(member);
            cases.push(missing);
        }
        for (member, value) in [
            ("sourceMode", json!("bundle")),
            ("sourceMode", json!("Environment")),
            ("gatewayVersion", json!("1.0")),
            ("gatewayVersion", json!("v1.0.1")),
            ("gatewayVersion", json!("1.0.1-")),
            ("gatewayVersion", json!("1.0.1-rc\n")),
            ("gatewayVersion", json!(1)),
            ("operations", json!(["Validate"])),
            ("operations", json!(["validate", "validate"])),
            ("operations", json!(["plan;rm"])),
            ("operations", json!([""])),
            ("operations", json!("validate")),
            (
                "documents",
                json!([{"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayBundle", "extra": 1}]),
            ),
            (
                "documents",
                json!([{"apiVersion": "GreenGateway.dev/v1alpha1", "kind": "GatewayBundle"}]),
            ),
            (
                "documents",
                json!([{"apiVersion": "greengateway.dev/v1alpha1", "kind": "gatewayBundle"}]),
            ),
            (
                "documents",
                json!([
                    {"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayBundle"},
                    {"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayBundle"}
                ]),
            ),
        ] {
            let mut changed = document();
            changed[member] = value;
            cases.push(changed);
        }
        let mut many = document();
        many["operations"] = Value::Array(
            (0..=MAX_OPERATIONS)
                .map(|index| json!(format!("operation_{index}")))
                .collect(),
        );
        cases.push(many);
        let validator = schema_validator();
        for case in cases {
            assert_eq!(
                read_value(&case),
                Err(ReadError::Invalid {
                    gateway_version: case["gatewayVersion"]
                        .as_str()
                        .filter(|version| is_release_version(version))
                        .map(str::to_owned)
                }),
                "{case}"
            );
            assert!(
                !validator.is_valid(&case),
                "the schema should refuse {case}"
            );
        }
    }

    #[test]
    fn a_duplicate_member_is_refused_rather_than_last_one_wins() {
        let text = r#"{"apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayCapabilities","gatewayVersion":"1.0.1","sourceMode":"environment","documents":[],"operations":[],"operations":["validate"]}"#;
        assert!(read(text.as_bytes()).is_err());
    }

    #[test]
    fn oversized_or_non_document_input_is_refused_before_interpretation() {
        let mut large = document();
        large["padding"] = json!("x".repeat(MAX_CAPABILITIES_BYTES));
        assert_eq!(read_value(&large), Err(ReadError::TooLarge));
        for text in ["", "null", "[]", "{", "{\"kind\":1}", "{}", "\"text\""] {
            assert_eq!(
                read(text.as_bytes()),
                Err(ReadError::NotADocument),
                "{text}"
            );
        }
    }

    #[test]
    fn release_versions_follow_a_bounded_semver_grammar() {
        for valid in [
            "0.0.0",
            "1.0.1",
            "10.20.30",
            "1.0.0-rc.1",
            "1.0.0+build.5",
            "1.2.3-alpha-1+x",
        ] {
            assert!(is_release_version(valid), "{valid}");
        }
        for invalid in [
            "",
            "1",
            "1.0",
            "1.0.0.0",
            "01.0.0x",
            "1.0.0-",
            "1.0.0+",
            "1.0.0-a..b",
            "1.0.0 ",
            "1.0.0-é",
            "1234567890.0.0",
            &format!("1.0.0-{}", "a".repeat(MAX_VERSION_BYTES)),
        ] {
            assert!(!is_release_version(invalid), "{invalid}");
        }
    }
}
