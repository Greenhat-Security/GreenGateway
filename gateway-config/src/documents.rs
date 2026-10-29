//! The versioned documents GreenGateway publishes schemas for.
//!
//! Every document carries an exact `apiVersion` and `kind`. A reader accepts
//! only the pairs it implements: there is no prefix match, no "any alpha",
//! and no downgrade. The schemas are published under `docs/schemas` and
//! compiled in here, so `ggctl schema` prints exactly the files the
//! repository reviews.

/// The one document version that exists today.
pub const API_VERSION_V1ALPHA1: &str = "greengateway.dev/v1alpha1";

/// The configuration bundle manifest (`bundle.yaml`).
pub const BUNDLE_KIND: &str = "GatewayBundle";
/// The deployment document a bundle pins.
pub const DEPLOYMENT_KIND: &str = "GatewayDeployment";
/// The answers `ggctl init` builds a bundle from: ordinary values only.
pub const INIT_ANSWERS_KIND: &str = "GatewayInitAnswers";
/// What a running gateway tells `ggctl` before any configuration operation.
pub const CAPABILITIES_KIND: &str = "GatewayCapabilities";
/// The machine-readable report `ggctl --format json` writes.
pub const REPORT_KIND: &str = "GgctlReport";

/// One published JSON Schema (Draft 2020-12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedSchema {
    pub api_version: &'static str,
    pub kind: &'static str,
    /// The file name under `docs/schemas`, which is also the last segment of
    /// the schema's `$id`.
    pub file_name: &'static str,
    /// The schema file's contents, compiled in from `docs/schemas`.
    pub json: &'static str,
}

/// Every published schema for a versioned document, in a fixed order.
pub const PUBLISHED_SCHEMAS: &[PublishedSchema] = &[
    PublishedSchema {
        api_version: API_VERSION_V1ALPHA1,
        kind: BUNDLE_KIND,
        file_name: "gateway-bundle.v1alpha1.schema.json",
        json: include_str!("../../docs/schemas/gateway-bundle.v1alpha1.schema.json"),
    },
    PublishedSchema {
        api_version: API_VERSION_V1ALPHA1,
        kind: DEPLOYMENT_KIND,
        file_name: "gateway-deployment.v1alpha1.schema.json",
        json: include_str!("../../docs/schemas/gateway-deployment.v1alpha1.schema.json"),
    },
    PublishedSchema {
        api_version: API_VERSION_V1ALPHA1,
        kind: INIT_ANSWERS_KIND,
        file_name: "gateway-init-answers.v1alpha1.schema.json",
        json: include_str!("../../docs/schemas/gateway-init-answers.v1alpha1.schema.json"),
    },
    PublishedSchema {
        api_version: API_VERSION_V1ALPHA1,
        kind: CAPABILITIES_KIND,
        file_name: "gateway-capabilities.v1alpha1.schema.json",
        json: include_str!("../../docs/schemas/gateway-capabilities.v1alpha1.schema.json"),
    },
    PublishedSchema {
        api_version: API_VERSION_V1ALPHA1,
        kind: REPORT_KIND,
        file_name: "ggctl-report.v1alpha1.schema.json",
        json: include_str!("../../docs/schemas/ggctl-report.v1alpha1.schema.json"),
    },
];

/// The schema for exactly this `(apiVersion, kind)` pair.
pub fn published_schema(api_version: &str, kind: &str) -> Option<&'static PublishedSchema> {
    PUBLISHED_SCHEMAS
        .iter()
        .find(|schema| schema.api_version == api_version && schema.kind == kind)
}

/// The document versions a kind is published in, oldest first.
pub fn api_versions_of(kind: &str) -> impl Iterator<Item = &'static str> + '_ {
    PUBLISHED_SCHEMAS
        .iter()
        .filter(move |schema| schema.kind == kind)
        .map(|schema| schema.api_version)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;

    fn parsed(schema: &PublishedSchema) -> Value {
        serde_json::from_str(schema.json)
            .unwrap_or_else(|error| panic!("{} should be JSON: {error}", schema.file_name))
    }

    #[test]
    fn every_published_schema_is_a_draft_2020_12_schema_for_its_exact_pair() {
        for schema in PUBLISHED_SCHEMAS {
            let value = parsed(schema);
            assert_eq!(
                value["$schema"], "https://json-schema.org/draft/2020-12/schema",
                "{}",
                schema.file_name
            );
            assert_eq!(
                value["$id"],
                format!("https://greengateway.dev/schemas/{}", schema.file_name),
                "{}",
                schema.file_name
            );
            assert_eq!(
                value["properties"]["apiVersion"]["const"], schema.api_version,
                "{}",
                schema.file_name
            );
            assert_eq!(
                value["properties"]["kind"]["const"], schema.kind,
                "{}",
                schema.file_name
            );
            assert_eq!(
                value["additionalProperties"],
                Value::Bool(false),
                "{} must be closed",
                schema.file_name
            );
            jsonschema::validator_for(&value)
                .unwrap_or_else(|error| panic!("{} should compile: {error}", schema.file_name));
        }
    }

    #[test]
    fn pairs_and_file_names_are_unique() {
        let pairs: BTreeSet<_> = PUBLISHED_SCHEMAS
            .iter()
            .map(|schema| (schema.api_version, schema.kind))
            .collect();
        let files: BTreeSet<_> = PUBLISHED_SCHEMAS
            .iter()
            .map(|schema| schema.file_name)
            .collect();
        assert_eq!(pairs.len(), PUBLISHED_SCHEMAS.len());
        assert_eq!(files.len(), PUBLISHED_SCHEMAS.len());
    }

    #[test]
    fn lookups_are_exact() {
        assert_eq!(
            published_schema(API_VERSION_V1ALPHA1, BUNDLE_KIND).map(|schema| schema.file_name),
            Some("gateway-bundle.v1alpha1.schema.json")
        );
        for (api_version, kind) in [
            ("greengateway.dev/v1alpha", BUNDLE_KIND),
            ("greengateway.dev/v1alpha1 ", BUNDLE_KIND),
            ("GreenGateway.dev/v1alpha1", BUNDLE_KIND),
            ("greengateway.dev/v1", BUNDLE_KIND),
            (API_VERSION_V1ALPHA1, "gatewaybundle"),
            (API_VERSION_V1ALPHA1, "Gateway"),
        ] {
            assert!(
                published_schema(api_version, kind).is_none(),
                "{api_version} {kind}"
            );
        }
        assert_eq!(
            api_versions_of(REPORT_KIND).collect::<Vec<_>>(),
            [API_VERSION_V1ALPHA1]
        );
        assert_eq!(api_versions_of("Unknown").count(), 0);
    }

    #[test]
    fn every_schema_file_in_the_repository_with_an_api_version_is_published() {
        // A versioned document schema committed under docs/schemas but missing
        // here would be invisible to `ggctl schema`.
        let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/schemas");
        let mut versioned = BTreeSet::new();
        for entry in std::fs::read_dir(directory).expect("docs/schemas should be readable") {
            let entry = entry.expect("docs/schemas entry should be readable");
            let name = entry.file_name().into_string().expect("UTF-8 file name");
            let text = std::fs::read_to_string(entry.path()).expect("schema should be readable");
            let value: Value = serde_json::from_str(&text).expect("schema should be JSON");
            if value["properties"]["apiVersion"]["const"].is_string() {
                versioned.insert(name);
            }
        }
        let published: BTreeSet<_> = PUBLISHED_SCHEMAS
            .iter()
            .map(|schema| schema.file_name.to_owned())
            .collect();
        assert_eq!(versioned, published);
        for schema in PUBLISHED_SCHEMAS {
            let committed = std::fs::read_to_string(format!("{directory}/{}", schema.file_name))
                .expect("published schema should be committed");
            assert_eq!(committed, schema.json, "{}", schema.file_name);
        }
    }
}
