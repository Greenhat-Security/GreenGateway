//! The configuration field catalog, held to the compiler and to the documents
//! that describe it (issue #242, PR 3).
//!
//! `gateway_config::catalog` describes every input the compiler reads. These
//! tests prove each description against the compiler itself rather than
//! against a second copy of its rules: they compile with each literal default
//! set explicitly, at each integer bound and just past it, at each end of a
//! decimal range, with each accepted word and one that is not, and with each
//! state backend's local or cluster-only material, and read what the compiler
//! refused and why. A value is judged on its own by the diagnostics: it is
//! accepted when no diagnostic refuses that input under `ConfigRule::Value`,
//! whatever rules relating it to other settings say.
//!
//! The second half holds the configuration reference, `.env.example`,
//! ADR-0008's bootstrap inputs, the compiler contract's sensitivity table and
//! the deployment schema to the catalog, so none of them can drift from it.
//! The blank-value rules are proved in `parity_tests` and the compiler
//! domains in `stage_tests`, both from the catalog.

use std::{collections::BTreeSet, env::VarError, fs, path::Path};

use gateway_config::catalog::{
    self, Blank, BootstrapCategory, BundleMapping, DecimalBound, DefaultValue, Field, FieldType,
    Sensitivity, StateBackends, FIELDS,
};
use serde_json::Value;

use super::{diagnostic::ConfigRule, inventory, Config, ConfigError};

fn fixture_value(fixture: &[(&str, &str)], name: &str) -> Result<String, VarError> {
    fixture
        .iter()
        .rev()
        .find(|(variable, _)| *variable == name)
        .map(|(_, value)| (*value).to_owned())
        .ok_or(VarError::NotPresent)
}

/// Compiles a fixture environment. A variable listed twice takes its last
/// value, so a context can be extended with the field under test.
fn compile(fixture: &[(&str, &str)]) -> Result<Config, ConfigError> {
    Config::from_env_vars(|name| fixture_value(fixture, name))
}

/// A complete cluster-mode configuration.
const CLUSTER: &[(&str, &str)] = &[
    ("STATE_BACKEND", "postgres"),
    ("DEPLOYMENT_ID", "deploy-catalog"),
    (
        "DATABASE_URL_FILE",
        "/run/secrets/greengateway/database-url",
    ),
    ("CONNECTION_SECRETS_ROOT", "/run/secrets/greengateway"),
    (
        "RATE_LIMIT_KEYRING",
        r#"[{"id":"rl-primary","file":"rate-limit-key","role":"primary"}]"#,
    ),
];

/// A standalone configuration with an admin session store, under which the
/// session's own settings are parsed.
const ADMIN_SESSIONS: &[(&str, &str)] = &[
    (
        "AUTH_PROVIDERS",
        r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"generated-fixture-placeholder","redirect_uri":"https://management.example.test/v1/operations/auth/callback"}]"#,
    ),
    ("ADMIN_LOGIN_PROVIDER", "primary"),
    ("ADMIN_PREFIX", "/operations"),
    ("ADMIN_SESSION_MODE", "standalone_memory"),
];

/// Where a field's value is read and can be judged: cluster mode for the
/// settings only it reads, an admin session store for the session's own
/// settings, and an empty environment for the rest.
fn context(field: &Field) -> Vec<(&'static str, &'static str)> {
    if field.state_backends == StateBackends::Cluster {
        CLUSTER.to_vec()
    } else if field.environment.starts_with("ADMIN_SESSION_")
        && field.environment != "ADMIN_SESSION_MODE"
    {
        ADMIN_SESSIONS.to_vec()
    } else {
        Vec::new()
    }
}

fn with(field: &Field, value: &str) -> Result<Config, ConfigError> {
    let mut fixture: Vec<(&str, &str)> = context(field);
    fixture.push((field.environment, value));
    compile(&fixture)
}

/// The rules that refused `field` under `fixture`.
fn rules_refusing(fixture: &[(&str, &str)], field: &Field) -> Vec<ConfigRule> {
    match compile(fixture) {
        Ok(_) => Vec::new(),
        Err(error) => error
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.variable == Some(field.environment))
            .map(|diagnostic| diagnostic.rule)
            .collect(),
    }
}

/// Whether the compiler accepts `value` for `field` on its own.
fn accepts_on_its_own(field: &Field, value: &str) -> bool {
    let mut fixture = context(field);
    fixture.push((field.environment, value));
    !rules_refusing(&fixture, field).contains(&ConfigRule::Value)
}

fn accepted(fixture: &[(&str, &str)]) -> Config {
    compile(fixture).unwrap_or_else(|error| panic!("{fixture:?} should be accepted:\n{error}"))
}

#[test]
fn the_catalog_lists_exactly_the_compilers_inventory_in_its_order() {
    let catalog: Vec<&str> = FIELDS.iter().map(|field| field.environment).collect();
    assert_eq!(
        catalog,
        inventory::CONFIG_INPUTS,
        "gateway-config's catalog lists every input the compiler reads, once, in the order it \
         reads them; add or move the entry where its block reads it"
    );
}

/// A literal default is the value that, set explicitly, compiles to what
/// leaving the field unset compiles to.
#[test]
fn every_literal_default_compiles_to_what_leaving_the_field_unset_does() {
    for field in FIELDS {
        let DefaultValue::Literal(default) = field.default else {
            continue;
        };
        let unset = accepted(&context(field));
        let set = with(field, default).unwrap_or_else(|error| {
            panic!(
                "{}={default:?} should be accepted:\n{error}",
                field.environment
            )
        });
        assert!(
            set == unset,
            "{}={default:?} is not the default the compiler applies",
            field.environment
        );
    }
}

#[test]
fn every_integer_range_is_the_range_the_compiler_accepts() {
    for field in FIELDS {
        let FieldType::Integer(range) = field.field_type else {
            continue;
        };
        let name = field.environment;
        for value in [range.minimum, range.maximum] {
            assert!(
                accepts_on_its_own(field, &value.to_string()),
                "{name} accepts {value}"
            );
        }
        if let Some(below) = range.minimum.checked_sub(1) {
            assert!(
                !accepts_on_its_own(field, &below.to_string()),
                "{name} refuses {below}, below its minimum"
            );
        }
        let above = match range.maximum.checked_add(1) {
            Some(above) => above.to_string(),
            None => "18446744073709551616".to_owned(),
        };
        assert!(
            !accepts_on_its_own(field, &above),
            "{name} refuses {above}, above its maximum"
        );
        for value in ["-1", "1.5", "ten"] {
            assert!(
                !accepts_on_its_own(field, value),
                "{name} refuses {value:?}"
            );
        }
    }
}

/// `bound` moved by the smallest step ADR-0008's decimal grammar can write.
fn stepped(bound: DecimalBound, up: bool) -> String {
    let value: f64 = bound.value.parse().expect("catalog bounds are decimals");
    let step = if up { 0.000_001 } else { -0.000_001 };
    format!("{:.6}", value + step)
}

#[test]
fn every_decimal_range_is_the_range_the_compiler_accepts() {
    for field in FIELDS {
        let FieldType::Decimal(range) = field.field_type else {
            continue;
        };
        let name = field.environment;
        let minimum = range.minimum;
        assert_eq!(
            accepts_on_its_own(field, minimum.value),
            minimum.inclusive,
            "{name} at its minimum {}",
            minimum.value
        );
        assert!(
            !accepts_on_its_own(field, &stepped(minimum, false)),
            "{name} refuses a value below {}",
            minimum.value
        );
        assert!(
            accepts_on_its_own(field, &stepped(minimum, true)),
            "{name} accepts a value just above {}",
            minimum.value
        );
        match range.maximum {
            Some(maximum) => {
                assert_eq!(
                    accepts_on_its_own(field, maximum.value),
                    maximum.inclusive,
                    "{name} at its maximum {}",
                    maximum.value
                );
                assert!(
                    !accepts_on_its_own(field, &stepped(maximum, true)),
                    "{name} refuses a value above {}",
                    maximum.value
                );
                assert!(
                    accepts_on_its_own(field, &stepped(maximum, false)),
                    "{name} accepts a value just below {}",
                    maximum.value
                );
            }
            None => assert!(
                accepts_on_its_own(field, "1000000"),
                "{name} has no maximum"
            ),
        }
        for value in ["inf", "NaN", "ten"] {
            assert!(
                !accepts_on_its_own(field, value),
                "{name} refuses {value:?}"
            );
        }
    }
}

#[test]
fn every_choice_and_boolean_accepts_exactly_its_words() {
    for field in FIELDS {
        let words: &[&str] = match field.field_type {
            FieldType::Choice(words) => words,
            FieldType::Boolean => &["true", "false"],
            _ => continue,
        };
        let name = field.environment;
        for word in words {
            assert!(accepts_on_its_own(field, word), "{name} accepts {word}");
        }
        for word in ["catalog-probe", "yes", "1"] {
            assert!(!accepts_on_its_own(field, word), "{name} refuses {word}");
        }
    }
}

/// A value, set rather than blank, that the backend checks below try for a
/// field. A field whose probe the compiler refuses on its own is not checked,
/// and a standalone field must have a probe it accepts.
fn probe(field: &Field) -> Option<String> {
    let keyring = r#"[{"id":"probe","file":"probe-key","role":"primary"}]"#;
    Some(match field.field_type {
        FieldType::Boolean => "true".to_owned(),
        FieldType::Integer(range) => range.minimum.max(1).to_string(),
        FieldType::Decimal(_) | FieldType::Choice(_) => match field.default {
            DefaultValue::Literal(value) => value.to_owned(),
            DefaultValue::Unset | DefaultValue::Derived(_) => return None,
        },
        FieldType::Path | FieldType::PathList => "/var/lib/greengateway/catalog-probe".to_owned(),
        FieldType::SocketAddress => "127.0.0.1:9099".to_owned(),
        FieldType::Url => "https://catalog-probe.example.test".to_owned(),
        FieldType::Text | FieldType::List => "catalog-probe".to_owned(),
        FieldType::Json if field.environment.ends_with("_KEYRING") => keyring.to_owned(),
        FieldType::Json => return None,
    })
}

/// Which backend refuses a field is the compiler's to say: standalone mode
/// refuses cluster material, and cluster mode refuses local authority.
#[test]
fn each_state_backend_refuses_only_the_other_backends_fields() {
    for field in FIELDS {
        let name = field.environment;
        let Some(value) = probe(field) else {
            assert_ne!(
                field.state_backends,
                StateBackends::Standalone,
                "{name} needs a probe value"
            );
            continue;
        };
        if !accepts_on_its_own(field, &value) {
            assert_ne!(
                field.state_backends,
                StateBackends::Standalone,
                "{name}'s probe {value:?} should be accepted on its own"
            );
            continue;
        }
        let standalone = rules_refusing(&[(name, value.as_str())], field);
        let mut cluster = CLUSTER.to_vec();
        cluster.push((name, value.as_str()));
        let cluster = rules_refusing(&cluster, field);

        if standalone.contains(&ConfigRule::ClusterSettingInStandaloneMode) {
            assert_eq!(
                field.state_backends,
                StateBackends::Cluster,
                "standalone mode refuses {name}, so only cluster mode reads it"
            );
        }
        assert_eq!(
            cluster.contains(&ConfigRule::LocalAuthorityInClusterMode),
            field.state_backends == StateBackends::Standalone,
            "{name}: cluster mode refuses exactly the standalone fields"
        );
    }
}

fn repository_text(path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// The backticked words in `text`.
fn backticked(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}

/// The `### NAME` sections of the configuration reference, in order, each
/// with its text up to the next heading.
fn reference_sections(reference: &str) -> Vec<(&str, &str)> {
    let mut sections = Vec::new();
    let mut rest = reference;
    while let Some(start) = rest.find("\n### ") {
        let body = &rest[start + 5..];
        let (heading, body) = body.split_once('\n').unwrap_or((body, ""));
        let end = body
            .find("\n## ")
            .into_iter()
            .chain(body.find("\n### "))
            .min();
        sections.push((heading.trim(), &body[..end.unwrap_or(body.len())]));
        rest = body;
    }
    sections
}

/// The reference has one entry per field, and each entry's `Default:` line
/// states the catalog's default: the literal value, that it is empty, or the
/// fields it follows.
#[test]
fn the_configuration_reference_states_every_fields_default() {
    let reference = repository_text("docs/configuration.md");
    let sections = reference_sections(&reference);
    let documented: BTreeSet<&str> = sections
        .iter()
        .map(|(heading, _)| *heading)
        .filter(|heading| inventory::config_input(heading).is_some())
        .collect();
    let catalog: BTreeSet<&str> = FIELDS.iter().map(|field| field.environment).collect();
    assert_eq!(
        documented, catalog,
        "docs/configuration.md has one entry per field"
    );

    for field in FIELDS {
        let name = field.environment;
        let (_, body) = sections
            .iter()
            .find(|(heading, _)| *heading == name)
            .expect("every field has an entry");
        let line = body
            .lines()
            .find(|line| line.starts_with("Default:"))
            .unwrap_or_else(|| panic!("docs/configuration.md#{} has no `Default:` line", field.id));
        match field.default {
            DefaultValue::Literal(value) => assert!(
                backticked(line).contains(&value),
                "docs/configuration.md#{} states the default `{value}`: {line}",
                field.id
            ),
            DefaultValue::Unset => assert!(
                line.to_ascii_lowercase().contains("empty"),
                "docs/configuration.md#{} says the default is empty: {line}",
                field.id
            ),
            DefaultValue::Derived(from) => {
                for other in from {
                    assert!(
                        backticked(line).contains(other),
                        "docs/configuration.md#{} names {other}, which its default follows: {line}",
                        field.id
                    );
                }
            }
        }
        if let FieldType::Integer(range) = field.field_type {
            // Where the entry states a range, it is the catalog's.
            if let Some(stated) = body.split("Range: ").nth(1) {
                let stated = stated.split(['.', '\n']).next().unwrap_or_default();
                assert_eq!(
                    stated,
                    format!("{} to {}", range.minimum, range.maximum),
                    "docs/configuration.md#{} states its range",
                    field.id
                );
            }
        }
    }
}

/// The active `NAME=value` assignments of `.env.example`, in order.
fn env_example_assignments(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.trim(), value))
        .collect()
}

/// `.env.example` sets every field once, and copied as it is it configures
/// nothing: each value it gives is the field's literal default, and a blank
/// one is a field whose blank value means unset. The exemption lists, whose
/// defaults follow `ADMIN_PREFIX`, stay unassigned.
#[test]
fn the_env_example_assigns_every_field_its_default() {
    let text = repository_text(".env.example");
    let assignments = env_example_assignments(&text);
    for field in FIELDS {
        let name = field.environment;
        let values: Vec<&str> = assignments
            .iter()
            .filter(|(assigned, _)| *assigned == name)
            .map(|(_, value)| *value)
            .collect();
        if matches!(field.default, DefaultValue::Derived(_)) && field.blank == Blank::ClearsDefault
        {
            assert!(
                values.is_empty(),
                "{name} stays unset so its derived default applies"
            );
            continue;
        }
        let [value] = values.as_slice() else {
            panic!(".env.example assigns {name} exactly once, not {values:?}");
        };
        if value.is_empty() {
            assert_eq!(
                field.blank,
                Blank::Unset,
                ".env.example leaves {name} blank, which only means unset for a blank-is-unset field"
            );
        } else {
            assert!(
                matches!(field.default, DefaultValue::Literal(default) if default == *value),
                ".env.example sets {name} to {value:?}, which is not its default"
            );
        }
    }
    let unknown: Vec<&str> = assignments
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| catalog::field(name).is_none())
        .collect();
    assert!(
        unknown.is_empty(),
        ".env.example assigns {unknown:?}, which are not fields"
    );

    assert!(
        accepted(&assignments) == accepted(&[]),
        "copying .env.example as it is configures exactly the defaults"
    );
}

/// The backticked names in the second column of the Markdown table row that
/// starts with `row`.
fn table_row_names<'a>(document: &'a str, row: &str) -> Vec<&'a str> {
    let line = document
        .lines()
        .find(|line| line.starts_with(row))
        .unwrap_or_else(|| panic!("no table row starts with {row:?}"));
    let cell = line.split('|').nth(2).unwrap_or_default();
    // The secret-provider row also says, in words, "every variable an
    // `environment` alias names", which is not a field.
    backticked(cell)
        .into_iter()
        .filter(|name| {
            name.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        })
        .collect()
}

/// ADR-0008 lists the bootstrap inputs that may stay in the environment
/// beside a bundle; the catalog classifies exactly those fields as
/// bootstrap, in the same categories.
#[test]
fn the_bootstrap_fields_are_adr_0008s_bootstrap_inputs() {
    let adr = repository_text("docs/adr/0008-setup-cli-and-configuration-bundles.md");
    for (row, category) in [
        (
            "| Host locators for mounted material |",
            BootstrapCategory::HostLocator,
        ),
        (
            "| Secret-provider wiring |",
            BootstrapCategory::SecretProviderWiring,
        ),
    ] {
        let listed: BTreeSet<&str> = table_row_names(&adr, row).into_iter().collect();
        let catalog: BTreeSet<&str> = FIELDS
            .iter()
            .filter(|field| field.bundle == BundleMapping::Bootstrap(category))
            .map(|field| field.environment)
            .collect();
        assert_eq!(listed, catalog, "ADR-0008 {row}");
    }
}

/// The compiler contract's sensitivity table names the inputs that carry
/// secret material or say where it is; the catalog marks exactly those as
/// secret locators or as values that may carry a secret.
#[test]
fn the_secret_fields_are_the_compiler_contracts_sensitive_inputs() {
    let contract = repository_text("docs/architecture/configuration-compiler.md");
    let table: Vec<&str> = contract
        .lines()
        .skip_while(|line| !line.starts_with("| Material | Inputs |"))
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .collect();
    assert!(
        !table.is_empty(),
        "the compiler contract has its sensitivity table"
    );
    let mut documented = BTreeSet::new();
    for row in table {
        let cell = row.split('|').nth(2).unwrap_or_default();
        for name in backticked(cell) {
            // `AUTH_PROVIDERS[].client_secret` is a member of a field.
            let name = name.split('[').next().unwrap_or(name);
            match name.split_once('*') {
                Some((prefix, suffix)) => documented.extend(
                    FIELDS
                        .iter()
                        .map(|field| field.environment)
                        .filter(|field| field.starts_with(prefix) && field.ends_with(suffix)),
                ),
                None => {
                    documented.insert(name);
                }
            }
        }
    }
    let catalog: BTreeSet<&str> = FIELDS
        .iter()
        .filter(|field| {
            matches!(
                field.sensitivity,
                Sensitivity::SecretLocator | Sensitivity::MayCarrySecret
            )
        })
        .map(|field| field.environment)
        .collect();
    assert_eq!(documented, catalog);
}

/// A field reaches a bundle only through the deployment schema: each setting
/// the schema defines under `spec` (beside the profile, which is the bundle's
/// own) is a catalog field's document path and the reverse. The schema also
/// defines the typed forms the catalog's deployment fields will use.
#[test]
fn the_deployment_schema_defines_exactly_the_catalogs_document_paths() {
    let schema: Value = serde_json::from_str(&repository_text(
        "docs/schemas/gateway-deployment.v1alpha1.schema.json",
    ))
    .expect("the deployment schema is JSON");
    let defined: BTreeSet<String> = schema["properties"]["spec"]["properties"]
        .as_object()
        .expect("the deployment schema defines spec members")
        .keys()
        .filter(|member| member.as_str() != "profile")
        .map(|member| format!("/spec/{member}"))
        .collect();
    let catalog: BTreeSet<String> = FIELDS
        .iter()
        .filter_map(|field| match field.bundle {
            BundleMapping::Deployment { path } => path.map(str::to_owned),
            _ => None,
        })
        .collect();
    assert_eq!(defined, catalog);

    let deployment = |predicate: fn(&Field) -> bool| {
        FIELDS.iter().any(|field| {
            matches!(field.bundle, BundleMapping::Deployment { .. }) && predicate(field)
        })
    };
    if deployment(|field| matches!(field.field_type, FieldType::Decimal(_))) {
        assert_eq!(
            schema["$defs"]["decimal"]["pattern"], r"^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$",
            "decimal deployment fields are written in ADR-0008's grammar"
        );
    }
    if deployment(|field| field.sensitivity != Sensitivity::Public) {
        assert!(
            schema["$defs"]["secretReference"].is_object(),
            "a deployment field that can carry a secret takes a secret reference"
        );
    }
}
