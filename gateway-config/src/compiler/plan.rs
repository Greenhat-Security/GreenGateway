//! The validated configuration plan, and the compiler that builds it from
//! the environment (issue #433, PR 2).
//!
//! [`compile`] requests every block of inputs in the inventory's order, runs
//! each block's pure stage on the values it read, and collects every problem
//! in one [`Report`], in the order the legacy parser has always reported
//! them. It returns a [`ConfigPlan`] only when no stage found anything. The
//! plan holds every domain's validated settings and the provenance of every
//! input, and carries secret material as locators wherever the input format
//! allows: TLS private keys and the database URL file as `SecretLocator`s,
//! and the Connections aliases, keyrings and providers in types that print
//! them redacted. The one secret value is the OIDC client secret the legacy
//! `AUTH_PROVIDERS` document holds inline, which its `Debug` redacts. Nothing
//! here or in the stages opens a file, resolves a name or reaches a store, a
//! provider or the network; preflight and activation stay with startup, which
//! runs them as stages of their own after this compiler has returned
//! (`bootstrap::start_serving`, #433 PR 3).
//!
//! The gateway's `Config::from_env_vars` is this compiler followed by the
//! gateway's conversion of the plan into its `Config`, which is why its
//! behaviour has not changed. The contract this module keeps is documented
//! in `docs/architecture/configuration-compiler.md`.

use std::env::VarError;

use super::{
    authority_events::AuthorityEventInputs,
    connections::{self, ConnectionInputs, ConnectionsPlan},
    diagnostic::{Lookups, Report},
    egress::{self, EgressInputs, EgressPlan},
    identity::{
        self, AdminSurfaceInputs, AuthenticationInputs, IdentityPlan, ProviderAndCsrfInputs,
        RbacExemptionInputs,
    },
    inventory,
    listeners::{self, ListenerInputs, ListenerPlan},
    proxy::{self, ProxyPlan, RoutingInputs, TrustedProxyInputs},
    runtime::{
        self, ContentTypeInputs, RequestBoundInputs, RuntimeBlocks, RuntimePlan, ShutdownInputs,
        SignalInputs, ToolRuntimeInputs, ToolTimeoutInputs,
    },
    stage::Provenance,
    storage::{
        self, AuditStoreInputs, ClusterInputs, DiscoveryStoreInputs, DocumentInputs,
        StateBackendInputs, StorageBlocks, StoragePlan,
    },
    ConfigError,
};

/// Every domain's validated settings.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigPlan {
    pub listeners: ListenerPlan,
    pub identity: IdentityPlan,
    pub proxy: ProxyPlan,
    pub storage: StoragePlan,
    pub connections: ConnectionsPlan,
    pub egress: EgressPlan,
    pub runtime: RuntimePlan,
}

/// Compiles the configuration a reader describes into a validated plan, or
/// into every problem it has, each with its value-free diagnostic.
pub fn compile(
    get_var: impl FnMut(&str) -> Result<String, VarError>,
) -> Result<ConfigPlan, ConfigError> {
    compile_source(get_var, false)
}

/// A validated bundle can supply policy bytes from its pinned resource.
/// The host-routing rule needs this fact, independently of a legacy path.
pub(crate) fn compile_source(
    mut get_var: impl FnMut(&str) -> Result<String, VarError>,
    bundle_policy: bool,
) -> Result<ConfigPlan, ConfigError> {
    // How each lookup came back -- unset, empty, not Unicode, or set, never
    // the value -- is remembered so a refusal can also be reported as
    // value-free diagnostics. Every lookup still reaches the caller's reader
    // exactly as before, in the same order.
    let mut lookups = Lookups::default();
    let (plan, report) = compile_blocks(
        |name: &str| {
            let value = get_var(name);
            lookups.record(name, &value);
            value
        },
        bundle_policy,
    );
    if report.is_empty() {
        Ok(plan)
    } else {
        let (problems, diagnostics) = report.into_problems_and_diagnostics(&lookups);
        Err(ConfigError {
            problems,
            diagnostics,
        })
    }
}

/// Reads and compiles every block, where the legacy parser read it.
///
/// The plan is always built, with defaults where an input was refused, so
/// that every later block still checks its own inputs and one pass reports
/// every problem. It is a validated plan only when the report is empty.
pub(super) fn compile_blocks(
    mut get_var: impl FnMut(&str) -> Result<String, VarError>,
    bundle_policy: bool,
) -> (ConfigPlan, Report) {
    let mut report = Report::default();

    let listeners = listeners::compile(ListenerInputs::read(&mut get_var)).report(&mut report);
    let admin_surface =
        identity::compile_admin_surface(AdminSurfaceInputs::read(&mut get_var)).report(&mut report);
    let audit =
        storage::compile_audit_stores(AuditStoreInputs::read(&mut get_var)).report(&mut report);
    let shutdown =
        runtime::compile_shutdown(ShutdownInputs::read(&mut get_var)).report(&mut report);
    let discovery = storage::compile_discovery_stores(DiscoveryStoreInputs::read(&mut get_var))
        .report(&mut report);
    let connections =
        connections::compile(ConnectionInputs::read(&mut get_var)).report(&mut report);
    let signals = runtime::compile_signals(SignalInputs::read(&mut get_var)).report(&mut report);
    let documents =
        storage::compile_documents(DocumentInputs::read(&mut get_var)).report(&mut report);
    let request_bounds =
        runtime::compile_request_bounds(RequestBoundInputs::read(&mut get_var)).report(&mut report);
    let trusted_proxy =
        proxy::compile_trusted_proxy(TrustedProxyInputs::read(&mut get_var)).report(&mut report);
    let rbac_exemptions =
        identity::compile_rbac_exemptions(RbacExemptionInputs::read(&mut get_var), &admin_surface)
            .report(&mut report);
    let content_types =
        runtime::compile_content_types(ContentTypeInputs::read(&mut get_var)).report(&mut report);
    let authentication =
        identity::compile_authentication(AuthenticationInputs::read(&mut get_var), &admin_surface)
            .report(&mut report);
    let tool_runtime =
        runtime::compile_tool_runtime(ToolRuntimeInputs::read(&mut get_var)).report(&mut report);
    let cluster = storage::compile_cluster(ClusterInputs::read(&mut get_var)).report(&mut report);
    let runtime = runtime::compile(
        ToolTimeoutInputs::read(&mut get_var),
        RuntimeBlocks {
            shutdown,
            signals,
            request_bounds,
            content_types,
            tool_runtime,
        },
    )
    .report(&mut report);
    let identity = identity::compile(
        ProviderAndCsrfInputs::read(&mut get_var),
        admin_surface,
        rbac_exemptions,
        authentication,
    )
    .report(&mut report);
    let proxy = proxy::compile(
        RoutingInputs::read(&mut get_var),
        trusted_proxy,
        &identity,
        documents.policy_file_configured() || bundle_policy,
    )
    .report(&mut report);
    let egress = egress::compile(EgressInputs::read(&mut get_var)).report(&mut report);
    let storage = storage::compile(
        StateBackendInputs::read(&mut get_var),
        AuthorityEventInputs::read(&mut get_var),
        StorageBlocks {
            audit,
            discovery,
            documents,
            cluster,
        },
        &identity,
        &connections,
        &runtime,
    )
    .report(&mut report);

    (
        ConfigPlan {
            listeners,
            identity,
            proxy,
            storage,
            connections,
            egress,
            runtime,
        },
        report,
    )
}

impl ConfigPlan {
    fn provenance_blocks_mut(&mut self) -> [&mut Vec<Provenance>; 7] {
        [
            &mut self.listeners.provenance,
            &mut self.identity.provenance,
            &mut self.proxy.provenance,
            &mut self.storage.provenance,
            &mut self.connections.provenance,
            &mut self.egress.provenance,
            &mut self.runtime.provenance,
        ]
    }

    /// This plan was built from document values and defaults. The shared
    /// stages already distinguish supplied values from computed defaults.
    pub(crate) fn mark_bundle_sources(
        &mut self,
        development_listen_default: bool,
        bootstrap: &std::collections::BTreeSet<&'static str>,
    ) {
        for fields in self.provenance_blocks_mut() {
            for field in fields {
                if field.source == super::stage::Source::Environment {
                    field.source = if bootstrap.contains(field.setting) {
                        super::stage::Source::Bootstrap
                    } else if development_listen_default && field.setting == super::LISTEN_ADDR {
                        super::stage::Source::Profile
                    } else {
                        super::stage::Source::Bundle
                    };
                }
            }
        }
    }

    /// Where every input came from, in the order the inputs are read: its
    /// setting and its source, never its value.
    pub fn provenance(&self) -> Vec<Provenance> {
        let mut provenance = [
            self.listeners.provenance.as_slice(),
            &self.identity.provenance,
            &self.proxy.provenance,
            &self.storage.provenance,
            &self.connections.provenance,
            &self.egress.provenance,
            &self.runtime.provenance,
        ]
        .concat();
        provenance.sort_by_key(|provenance| inventory::position(provenance.setting));
        provenance
    }

    /// The same plan with no provenance, so two plans can be compared by
    /// their values alone, as two `Config`s are.
    #[cfg(test)]
    pub(super) fn without_provenance(mut self) -> Self {
        for provenance in self.provenance_blocks_mut() {
            provenance.clear();
        }
        self
    }
}
