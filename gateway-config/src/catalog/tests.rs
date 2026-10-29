//! The catalog's own rules, and the committed rendering of it.
//!
//! What the catalog says about the compiler is proved by the gateway's
//! `config::catalog_tests`, which can run the compiler. These tests hold what
//! needs no compiler: that each entry is internally consistent and follows the
//! rules ADR-0008 states for whole groups of fields, and that
//! `docs/configuration-catalog.json` is exactly what [`render_json`] produces.

use std::collections::BTreeSet;

use serde_json::Value;

use super::*;

fn repository_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn repository_text(relative: &str) -> String {
    let path = repository_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

fn rendered() -> String {
    render_json().expect("the catalog renders")
}

/// ADR-0008's grammar for a decimal setting:
/// `^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$`.
fn is_bundle_decimal(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    let whole_ok = whole == "0"
        || (!whole.is_empty()
            && whole.len() <= 16
            && !whole.starts_with('0')
            && whole.bytes().all(|byte| byte.is_ascii_digit()));
    let fraction_ok = fraction.is_none_or(|fraction| {
        (1..=6).contains(&fraction.len()) && fraction.bytes().all(|byte| byte.is_ascii_digit())
    });
    whole_ok && fraction_ok
}

fn decimal(value: &str) -> f64 {
    value
        .parse()
        .unwrap_or_else(|error| panic!("{value} is a decimal: {error}"))
}

#[test]
fn identifiers_and_variables_are_unique_and_follow_one_spelling_rule() {
    let mut ids = BTreeSet::new();
    let mut variables = BTreeSet::new();
    for field in FIELDS {
        assert!(ids.insert(field.id), "{} is listed twice", field.id);
        assert!(
            variables.insert(field.environment),
            "{} is listed twice",
            field.environment
        );
        assert!(
            !field.environment.is_empty()
                && field
                    .environment
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
            "{} is an environment variable name",
            field.environment
        );
        assert_eq!(
            field.id,
            field.environment.to_ascii_lowercase(),
            "a field's identifier is its variable in lower case"
        );
        assert_eq!(
            field.documentation(),
            format!("docs/configuration.md#{}", field.id)
        );
        assert_eq!(super::field(field.environment), Some(field));
    }
    assert_eq!(super::field("listen_addr"), None);
    assert_eq!(super::field("HOSTNAME"), None);
}

#[test]
fn every_type_agrees_with_its_default_and_its_name() {
    for field in FIELDS {
        let name = field.environment;
        let literal = match field.default {
            DefaultValue::Literal(value) => Some(value),
            DefaultValue::Unset | DefaultValue::Derived(_) => None,
        };
        match field.field_type {
            FieldType::Integer(range) => {
                assert!(range.minimum <= range.maximum, "{name}");
                if let Some(value) = literal {
                    let value: u64 = value
                        .parse()
                        .unwrap_or_else(|error| panic!("{name}'s default is an integer: {error}"));
                    assert!(
                        (range.minimum..=range.maximum).contains(&value),
                        "{name}'s default is within its range"
                    );
                }
                let unit = if name.ends_with("_MS") {
                    Unit::Milliseconds
                } else if name.ends_with("_SECS") {
                    Unit::Seconds
                } else if name.ends_with("_HOURS") {
                    Unit::Hours
                } else if name.ends_with("_DAYS") {
                    Unit::Days
                } else if name.ends_with("_BYTES") || name == "MAX_BODY_SIZE" {
                    Unit::Bytes
                } else {
                    Unit::Count
                };
                assert_eq!(range.unit, unit, "{name}'s unit follows its name");
            }
            FieldType::Decimal(range) => {
                let bounds = std::iter::once(range.minimum).chain(range.maximum);
                for bound in bounds {
                    assert!(is_bundle_decimal(bound.value), "{name}: {}", bound.value);
                }
                let value = literal.unwrap_or_else(|| panic!("{name} has a literal default"));
                assert!(
                    is_bundle_decimal(value),
                    "{name}'s default {value} can be written in a bundle"
                );
                let value = decimal(value);
                let minimum = decimal(range.minimum.value);
                assert!(
                    value > minimum || (range.minimum.inclusive && value == minimum),
                    "{name}'s default is above its minimum"
                );
                if let Some(maximum) = range.maximum {
                    let bound = decimal(maximum.value);
                    assert!(
                        value < bound || (maximum.inclusive && value == bound),
                        "{name}'s default is below its maximum"
                    );
                }
            }
            FieldType::Choice(words) => {
                let unique: BTreeSet<_> = words.iter().collect();
                assert_eq!(unique.len(), words.len(), "{name} lists a word twice");
                if let Some(value) = literal {
                    assert!(
                        words.contains(&value),
                        "{name}'s default is one of its words"
                    );
                }
            }
            FieldType::Boolean => {
                let value = literal.unwrap_or_else(|| panic!("{name} has a literal default"));
                assert!(value == "true" || value == "false", "{name}: {value}");
            }
            FieldType::Path | FieldType::PathList => {
                assert_ne!(
                    field.sensitivity,
                    Sensitivity::Public,
                    "{name} is a host path, which reports never show"
                );
            }
            FieldType::SocketAddress
            | FieldType::Url
            | FieldType::Text
            | FieldType::List
            | FieldType::Json => {}
        }
        if field.blank == Blank::ClearsDefault {
            assert_eq!(field.field_type, FieldType::List, "{name}");
            assert_ne!(
                field.default,
                DefaultValue::Unset,
                "{name} has a default to clear"
            );
        }
        if let DefaultValue::Derived(from) = field.default {
            assert!(!from.is_empty(), "{name}");
            for other in from {
                assert_ne!(*other, name, "{name} is derived from itself");
                assert!(
                    super::field(other).is_some(),
                    "{name} is derived from {other}, which is not a field"
                );
            }
        }
    }
}

/// ADR-0008 decides some fields' bundle mapping by rule rather than one by
/// one; the catalog follows the rules exactly.
#[test]
fn bundle_mappings_follow_the_rules_adr_0008_states() {
    for field in FIELDS {
        let name = field.environment;
        let resource =
            name == "POLICY_FILE" || name == "TOOLS_FILE" || name.ends_with("_SQLITE_PATH");
        assert_eq!(
            field.bundle == BundleMapping::Resource,
            resource,
            "{name}: POLICY_FILE, TOOLS_FILE and every *_SQLITE_PATH are replaced by bundle resources"
        );
        let legacy_provider = name.starts_with("JWT_") || name == "ROLES_CLAIM";
        assert_eq!(
            field.bundle == BundleMapping::NotRepresentable,
            legacy_provider,
            "{name}: the single-provider JWT fallback is what a bundle cannot represent"
        );
        if let BundleMapping::Bootstrap(category) = field.bundle {
            assert_eq!(field.reload(), ReloadClass::Bootstrap, "{name}");
            if category == BootstrapCategory::SecretProviderWiring {
                assert_eq!(field.sensitivity, Sensitivity::SecretLocator, "{name}");
            }
        } else {
            assert_eq!(field.reload(), ReloadClass::Restart, "{name}");
        }
        if field.bundle == BundleMapping::Unplaced {
            assert!(
                matches!(field.field_type, FieldType::Path),
                "{name}: only a host path is left unplaced"
            );
        }
        if let BundleMapping::Deployment { path } = field.bundle {
            assert!(
                field.sensitivity != Sensitivity::HostPath,
                "{name}: host paths never enter a bundle"
            );
            assert_eq!(
                path, None,
                "{name}: the deployment schema defines no setting yet"
            );
        }
    }
}

#[test]
fn every_cluster_field_is_excluded_from_cloudflare_for_cluster_mode() {
    for field in FIELDS {
        let name = field.environment;
        let cluster_exclusion =
            field.cloudflare == Cloudflare::Excluded(CloudflareExclusion::ClusterMode);
        if field.state_backends == StateBackends::Cluster {
            assert!(cluster_exclusion, "{name} is read only in cluster mode");
        }
        if cluster_exclusion {
            assert!(
                field.state_backends == StateBackends::Cluster || name == "STATE_BACKEND",
                "{name} is excluded for cluster mode, so it is cluster mode's or selects it"
            );
        }
    }
}

#[test]
fn the_committed_catalog_is_the_rendered_catalog() {
    let committed = repository_text(CATALOG_DOCUMENT);
    assert!(
        committed == rendered(),
        "{CATALOG_DOCUMENT} is not the rendered catalog; regenerate it with \
         `cargo test -p gateway-config --lib catalog::tests::regenerate_the_committed_catalog -- --ignored` \
         and review the difference"
    );
}

#[test]
fn the_rendered_catalog_matches_its_published_schema() {
    let schema_text = repository_text("docs/schemas/configuration-catalog.v1.schema.json");
    let schema: Value = serde_json::from_str(&schema_text).expect("the schema is JSON");
    assert_eq!(
        schema["$id"],
        "https://greengateway.dev/schemas/configuration-catalog.v1.schema.json"
    );
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        CATALOG_SCHEMA_VERSION
    );
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let document: Value = serde_json::from_str(&rendered()).expect("the catalog is JSON");
    let errors: Vec<String> = validator
        .iter_errors(&document)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");

    let fields = document["fields"].as_array().expect("fields is an array");
    assert_eq!(fields.len(), FIELDS.len());
    for (record, field) in fields.iter().zip(FIELDS) {
        assert_eq!(record["environment"], field.environment);
    }

    // The schema refuses what the catalog cannot say.
    let mut wrong = document.clone();
    wrong["fields"][0]["blank"] = Value::from("sometimes");
    assert!(!validator.is_valid(&wrong));
    let mut wrong = document;
    wrong["fields"][0]["comment"] = Value::from("unknown members are refused");
    assert!(!validator.is_valid(&wrong));
}

/// Writes the rendered catalog over the committed one. Run it deliberately,
/// after changing the catalog, and review the difference it makes.
#[test]
#[ignore = "rewrites docs/configuration-catalog.json; run with --ignored after changing the catalog"]
fn regenerate_the_committed_catalog() {
    std::fs::write(repository_path(CATALOG_DOCUMENT), rendered())
        .expect("the committed catalog is writable");
}
