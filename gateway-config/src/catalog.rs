//! The configuration field catalog (issue #242 PR 3, ADR-0008).
//!
//! [`FIELDS`] describes every setting the gateway's configuration compiler
//! reads, in the order the compiler's inventory (`CONFIG_INPUTS` in
//! `gateway/src/config/inventory.rs`) requests them: its stable identifier and
//! environment variable, the compiler domain that parses it, its type and
//! bounds, its default, what a blank value means, how sensitive it is, which
//! state backend reads it, what becomes of it in a configuration bundle, its
//! reload class, and whether the Cloudflare wrapper forwards it, with the
//! reason when it does not.
//!
//! The catalog describes the compiler; it is not a second one. The gateway's
//! compiler stays the one parser and semantic validator, and nothing here is
//! consulted at startup. What keeps the description true is a set of parity
//! checks that fail the build on drift:
//!
//! - the gateway's `config::catalog_tests` hold every entry to the compiler
//!   itself: the inventory and its order, each literal default, each integer
//!   bound, decimal range and accepted word, and which settings each state
//!   backend refuses; `config::parity_tests` read the blank-value rules from
//!   here and prove them, and `config::stage_tests` the compiler domains;
//! - the same tests hold `docs/configuration.md` (one entry per field, with
//!   the catalog's default), `.env.example` (every field, and copying it
//!   changes nothing), ADR-0008's bootstrap inputs, the compiler contract's
//!   sensitivity table and the deployment schema to the catalog, and
//!   `gateway/tests/env_example.rs` holds the Cloudflare forwarding list to
//!   the fields marked [`Cloudflare::Forwarded`];
//! - this module's tests hold the catalog to its own rules and to the
//!   committed `docs/configuration-catalog.json`, which [`render_json`]
//!   produces and `docs/schemas/configuration-catalog.v1.schema.json`
//!   describes.
//!
//! Some of ADR-0008's catalog columns are not here yet, because nothing
//! decides or checks them today: deployment-document paths (the deployment
//! schema defines no setting yet, so every [`BundleMapping::Deployment`]
//! path is `None`), exportability and template placeholders, membership of
//! the static-configuration fingerprint, and doctor checks.

mod fields;
#[cfg(test)]
mod tests;

pub use fields::FIELDS;

/// The `schema_version` of the rendered catalog document.
pub const CATALOG_SCHEMA_VERSION: &str = "configuration-catalog.v1";

/// Where the rendered catalog is committed, relative to the repository root.
pub const CATALOG_DOCUMENT: &str = "docs/configuration-catalog.json";

/// One setting the configuration compiler reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    /// The stable field identifier: the environment variable in lower case.
    /// Reports and provenance name a field by it; a bundle document may spell
    /// the field differently, under [`BundleMapping::Deployment`].
    pub id: &'static str,
    /// The environment variable that sets it.
    pub environment: &'static str,
    /// The compiler domain whose plan holds it.
    pub domain: Domain,
    pub field_type: FieldType,
    pub default: DefaultValue,
    pub blank: Blank,
    pub sensitivity: Sensitivity,
    pub state_backends: StateBackends,
    pub bundle: BundleMapping,
    pub cloudflare: Cloudflare,
}

impl Field {
    /// When a new value takes effect.
    pub fn reload(&self) -> ReloadClass {
        match self.bundle {
            BundleMapping::Bootstrap(_) => ReloadClass::Bootstrap,
            BundleMapping::Deployment { .. }
            | BundleMapping::Resource
            | BundleMapping::NotRepresentable
            | BundleMapping::Unplaced => ReloadClass::Restart,
        }
    }

    /// The field's entry in the configuration reference, relative to the
    /// repository root.
    pub fn documentation(&self) -> String {
        format!("docs/configuration.md#{}", self.id)
    }
}

/// The compiler plan a field belongs to (`docs/architecture/configuration-compiler.md#stages`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain {
    Listeners,
    Identity,
    Proxy,
    Storage,
    Connections,
    Egress,
    /// The `runtime` plan: request bounds and rate limits, shutdown, discovery
    /// signals and the tool runtime. Not named `Runtime`, which the transport
    /// guard reviews as the PostgreSQL pool's runtime type wherever it appears.
    RuntimeSettings,
}

impl Domain {
    pub fn code(self) -> &'static str {
        match self {
            Self::Listeners => "listeners",
            Self::Identity => "identity",
            Self::Proxy => "proxy",
            Self::Storage => "storage",
            Self::Connections => "connections",
            Self::Egress => "egress",
            Self::RuntimeSettings => "runtime",
        }
    }
}

/// What a field's value is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// Exactly `true` or `false`.
    Boolean,
    /// An unsigned decimal integer.
    Integer(IntegerRange),
    /// A decimal number. A bundle writes it as a string in ADR-0008's
    /// decimal grammar, never as a JSON number.
    Decimal(DecimalRange),
    /// Exactly one of these words.
    Choice(&'static [&'static str]),
    /// A socket address such as `127.0.0.1:8080` or `[::1]:8080`.
    SocketAddress,
    /// An absolute URL.
    Url,
    /// A path on the gateway's host.
    Path,
    /// A comma-separated list of paths on the gateway's host.
    PathList,
    /// One string, held to the field's own shape rules.
    Text,
    /// A comma-separated list of strings, each held to the field's own
    /// shape rules.
    List,
    /// A JSON document with its own published shape.
    Json,
}

impl FieldType {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer(_) => "integer",
            Self::Decimal(_) => "decimal",
            Self::Choice(_) => "choice",
            Self::SocketAddress => "socket_address",
            Self::Url => "url",
            Self::Path => "path",
            Self::PathList => "path_list",
            Self::Text => "text",
            Self::List => "list",
            Self::Json => "json",
        }
    }
}

/// The values an integer field accepts on its own, both ends inclusive.
///
/// A maximum of `u64::MAX` means the field has no bound of its own beyond
/// the integer it is parsed as (64-bit builds). Rules that relate fields,
/// such as an idle timeout that may not exceed its session's lifetime, are
/// the compiler's and are not repeated here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegerRange {
    pub minimum: u64,
    pub maximum: u64,
    pub unit: Unit,
}

/// What an integer counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unit {
    Count,
    Bytes,
    Milliseconds,
    Seconds,
    Hours,
    Days,
}

impl Unit {
    pub fn code(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::Milliseconds => "milliseconds",
            Self::Seconds => "seconds",
            Self::Hours => "hours",
            Self::Days => "days",
        }
    }
}

/// The values a decimal field accepts on its own. A missing maximum means
/// any finite value above the minimum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecimalRange {
    pub minimum: DecimalBound,
    pub maximum: Option<DecimalBound>,
}

/// One end of a decimal range, written in ADR-0008's decimal grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecimalBound {
    pub value: &'static str,
    pub inclusive: bool,
}

/// What applies when a field is not set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultValue {
    /// The value that, set explicitly, compiles to exactly what leaving the
    /// field unset compiles to.
    Literal(&'static str),
    /// Nothing: the field's feature is off or nothing is configured.
    Unset,
    /// A value computed from these other fields, as the exemption lists
    /// follow `ADMIN_PREFIX`.
    Derived(&'static [&'static str]),
}

/// What an empty or whitespace-only value means
/// (`docs/architecture/configuration-compiler.md#blank-values`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Blank {
    /// The default applies, exactly as if the variable were absent.
    Unset,
    /// The value is parsed as it stands and refused.
    Refused,
    /// The value is an empty list that replaces a non-empty default.
    ClearsDefault,
}

impl Blank {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Refused => "refused",
            Self::ClearsDefault => "clears_default",
        }
    }
}

/// How much a field's value reveals, and so what a report, status view or
/// diff may show of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sensitivity {
    /// The value may be shown.
    Public,
    /// A path on the gateway's host. It locates no secret material, but host
    /// paths stay out of reports, exports and bundles (ADR-0008), so only
    /// whether it is set may be shown.
    HostPath,
    /// Says where secret material is kept: a key file, the database URL
    /// file, the secrets root, an alias, a keyring or a provider document.
    /// Only whether it is set may be shown.
    SecretLocator,
    /// The value itself can carry secret material inline: an OIDC client
    /// secret, a static request header, a client identity locator, or a URL
    /// query. Only whether it is set may be shown.
    MayCarrySecret,
}

impl Sensitivity {
    pub fn code(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::HostPath => "host_path",
            Self::SecretLocator => "secret_locator",
            Self::MayCarrySecret => "may_carry_secret",
        }
    }

    /// What may be shown: the value, or only whether it is set.
    pub fn disclosure(self) -> Disclosure {
        match self {
            Self::Public => Disclosure::Value,
            Self::HostPath | Self::SecretLocator | Self::MayCarrySecret => Disclosure::Presence,
        }
    }
}

/// What a report, status view or diff may show of a field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disclosure {
    Value,
    Presence,
}

impl Disclosure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Presence => "presence",
        }
    }
}

/// Which `STATE_BACKEND` a field is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateBackends {
    /// Both backends accept it.
    Both,
    /// A local store or file: standalone mode reads it and cluster mode
    /// refuses it, because PostgreSQL is the single authority there.
    Standalone,
    /// Only cluster mode reads it. Standalone mode refuses most of these and
    /// ignores the rest.
    Cluster,
}

impl StateBackends {
    pub fn code(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Standalone => "standalone",
            Self::Cluster => "cluster",
        }
    }
}

/// What a field becomes in bundle and ledger modes (ADR-0008, "Source
/// modes"). No release can start from a bundle yet; this records the
/// decision the bundle front end implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleMapping {
    /// A `GatewayDeployment` field. `path` is its JSON Pointer once the
    /// deployment schema defines it; until then a bundle cannot set it.
    Deployment { path: Option<&'static str> },
    /// One of ADR-0008's bootstrap inputs: it stays in the environment beside
    /// a bundle and may not be set inside one.
    Bootstrap(BootstrapCategory),
    /// Replaced by a bundle resource or by a fixed file beneath
    /// `GATEWAY_STATE_DIR`: `POLICY_FILE`, `TOOLS_FILE` and every
    /// `*_SQLITE_PATH`.
    Resource,
    /// Part of the legacy single JWT provider, which a bundle cannot express:
    /// it names its authentication providers explicitly.
    NotRepresentable,
    /// A host path ADR-0008 does not place yet: it is neither a bootstrap
    /// input nor a bundle resource, so bundle mode refuses it until the ADR
    /// decides.
    Unplaced,
}

impl BundleMapping {
    pub fn code(self) -> &'static str {
        match self {
            Self::Deployment { .. } => "deployment",
            Self::Bootstrap(_) => "bootstrap",
            Self::Resource => "resource",
            Self::NotRepresentable => "not_representable",
            Self::Unplaced => "unplaced",
        }
    }
}

/// ADR-0008's bootstrap categories that hold inventoried fields. Its other
/// two, source selection and platform variables, hold variables the
/// compiler does not read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapCategory {
    /// A host locator for mounted material: mount paths differ between
    /// platforms and never enter a bundle.
    HostLocator,
    /// Secret-provider wiring: it maps opaque alias IDs to locators, which is
    /// trusted startup configuration, never bundle input.
    SecretProviderWiring,
}

impl BootstrapCategory {
    pub fn code(self) -> &'static str {
        match self {
            Self::HostLocator => "host_locator",
            Self::SecretProviderWiring => "secret_provider_wiring",
        }
    }
}

/// When a new value takes effect.
///
/// ADR-0008 also defines `live`, a change a running gateway applies, which
/// only ledger mode's online apply can offer; no field has it today.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadClass {
    /// At the next process start.
    Restart,
    /// At the next process start, and only through the environment: no
    /// bundle or ledger revision can change it.
    Bootstrap,
}

impl ReloadClass {
    pub fn code(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Bootstrap => "bootstrap",
        }
    }
}

/// Whether the Cloudflare Worker wrapper (`cloudflare/src/config.ts`)
/// forwards a field to the container.
///
/// A native deployment, Compose and Kubernetes set the gateway's environment
/// directly, so every field is available there and none needs a reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cloudflare {
    Forwarded,
    Excluded(CloudflareExclusion),
}

/// Why the Cloudflare wrapper does not forward a field. A forwarding entry
/// that cannot work is worse than an absent one: it invites the
/// configuration it silently breaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudflareExclusion {
    /// The wrapper sets `LISTEN_ADDR` itself: Cloudflare reaches the
    /// container on one fixed port.
    ContainerListener,
    /// The Worker exposes a single container port, so the admin surface
    /// stays on `ADMIN_PREFIX` of the data listener.
    SingleContainerPort,
    /// Cloudflare terminates TLS at its edge and reaches the container over
    /// plain HTTP/1.1, which a listener demanding a TLS ClientHello would
    /// refuse; there is also nowhere to mount a certificate and key.
    EdgeTerminatesTls,
    /// No HTTP/2 connection preface can reach the container, so a gRPC
    /// listener would sit on a port nothing speaks HTTP/2 to.
    NoGrpc,
    /// The edge terminates the client's TLS connection, so no client
    /// certificate reaches the container, and requiring one would refuse
    /// every request.
    NoClientCertificates,
    /// Cluster mode takes its connection string only from a
    /// permission-checked file, and the deployment has no volume to mount
    /// one on; without cluster mode these settings are refused or unused.
    ClusterMode,
    /// The wrapper serves no cluster status endpoint for the setting to
    /// affect.
    NoClusterStatus,
}

impl CloudflareExclusion {
    pub fn code(self) -> &'static str {
        match self {
            Self::ContainerListener => "container_listener",
            Self::SingleContainerPort => "single_container_port",
            Self::EdgeTerminatesTls => "edge_terminates_tls",
            Self::NoGrpc => "no_grpc",
            Self::NoClientCertificates => "no_client_certificates",
            Self::ClusterMode => "cluster_mode",
            Self::NoClusterStatus => "no_cluster_status",
        }
    }
}

/// The field set by `environment`, if the compiler reads one.
pub fn field(environment: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|field| field.environment == environment)
}

/// The catalog document committed as [`CATALOG_DOCUMENT`]: one field per
/// line, in catalog order, with `\n` line endings.
pub fn render_json() -> Result<String, serde_json::Error> {
    let records = FIELDS
        .iter()
        .map(|field| serde_json::to_string(&render::FieldRecord::from(field)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "{{\n  \"schema_version\": \"{CATALOG_SCHEMA_VERSION}\",\n  \"fields\": [\n    {}\n  ]\n}}\n",
        records.join(",\n    ")
    ))
}

/// The rendered form of one field. Structs rather than maps, so the member
/// order is the declaration order whatever `serde_json` features the build
/// unifies.
mod render {
    use serde::Serialize;

    use super::{Cloudflare, DefaultValue, Field, FieldType};

    #[derive(Serialize)]
    pub(super) struct FieldRecord {
        id: &'static str,
        environment: &'static str,
        domain: &'static str,
        #[serde(rename = "type")]
        field_type: TypeRecord,
        default: DefaultRecord,
        blank: &'static str,
        sensitivity: &'static str,
        disclosure: &'static str,
        state_backends: &'static str,
        reload: &'static str,
        bundle: BundleRecord,
        platforms: PlatformsRecord,
        documentation: String,
    }

    #[derive(Serialize)]
    struct TypeRecord {
        name: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        decimal_minimum: Option<BoundRecord>,
        #[serde(skip_serializing_if = "Option::is_none")]
        decimal_maximum: Option<BoundRecord>,
        #[serde(skip_serializing_if = "Option::is_none")]
        values: Option<&'static [&'static str]>,
    }

    #[derive(Serialize)]
    struct BoundRecord {
        value: &'static str,
        inclusive: bool,
    }

    #[derive(Serialize)]
    struct DefaultRecord {
        kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<&'static [&'static str]>,
    }

    #[derive(Serialize)]
    struct BundleRecord {
        kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<&'static str>,
        /// Present, and `null` until the deployment schema defines it, for a
        /// deployment field only.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<Option<&'static str>>,
    }

    #[derive(Serialize)]
    struct PlatformsRecord {
        native: &'static str,
        compose: &'static str,
        kubernetes: &'static str,
        cloudflare: CloudflareRecord,
    }

    #[derive(Serialize)]
    struct CloudflareRecord {
        support: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'static str>,
    }

    impl From<&Field> for FieldRecord {
        fn from(field: &Field) -> Self {
            Self {
                id: field.id,
                environment: field.environment,
                domain: field.domain.code(),
                field_type: TypeRecord::from(&field.field_type),
                default: DefaultRecord::from(field.default),
                blank: field.blank.code(),
                sensitivity: field.sensitivity.code(),
                disclosure: field.sensitivity.disclosure().code(),
                state_backends: field.state_backends.code(),
                reload: field.reload().code(),
                bundle: BundleRecord::from(field.bundle),
                platforms: PlatformsRecord {
                    native: "supported",
                    compose: "supported",
                    kubernetes: "supported",
                    cloudflare: CloudflareRecord::from(field.cloudflare),
                },
                documentation: field.documentation(),
            }
        }
    }

    impl From<&FieldType> for TypeRecord {
        fn from(field_type: &FieldType) -> Self {
            let mut record = Self {
                name: field_type.code(),
                minimum: None,
                maximum: None,
                unit: None,
                decimal_minimum: None,
                decimal_maximum: None,
                values: None,
            };
            match field_type {
                FieldType::Integer(range) => {
                    record.minimum = Some(range.minimum);
                    record.maximum = Some(range.maximum);
                    record.unit = Some(range.unit.code());
                }
                FieldType::Decimal(range) => {
                    record.decimal_minimum = Some(BoundRecord {
                        value: range.minimum.value,
                        inclusive: range.minimum.inclusive,
                    });
                    record.decimal_maximum = range.maximum.map(|bound| BoundRecord {
                        value: bound.value,
                        inclusive: bound.inclusive,
                    });
                }
                FieldType::Choice(values) => record.values = Some(values),
                FieldType::Boolean
                | FieldType::SocketAddress
                | FieldType::Url
                | FieldType::Path
                | FieldType::PathList
                | FieldType::Text
                | FieldType::List
                | FieldType::Json => {}
            }
            record
        }
    }

    impl From<DefaultValue> for DefaultRecord {
        fn from(default: DefaultValue) -> Self {
            match default {
                DefaultValue::Literal(value) => Self {
                    kind: "literal",
                    value: Some(value),
                    from: None,
                },
                DefaultValue::Unset => Self {
                    kind: "unset",
                    value: None,
                    from: None,
                },
                DefaultValue::Derived(from) => Self {
                    kind: "derived",
                    value: None,
                    from: Some(from),
                },
            }
        }
    }

    impl From<super::BundleMapping> for BundleRecord {
        fn from(bundle: super::BundleMapping) -> Self {
            let (category, path) = match bundle {
                super::BundleMapping::Deployment { path } => (None, Some(path)),
                super::BundleMapping::Bootstrap(category) => (Some(category.code()), None),
                super::BundleMapping::Resource
                | super::BundleMapping::NotRepresentable
                | super::BundleMapping::Unplaced => (None, None),
            };
            Self {
                kind: bundle.code(),
                category,
                path,
            }
        }
    }

    impl From<Cloudflare> for CloudflareRecord {
        fn from(cloudflare: Cloudflare) -> Self {
            match cloudflare {
                Cloudflare::Forwarded => Self {
                    support: "forwarded",
                    reason: None,
                },
                Cloudflare::Excluded(exclusion) => Self {
                    support: "excluded",
                    reason: Some(exclusion.code()),
                },
            }
        }
    }
}
