//! Policy resource snapshots and cross-resource validation (issue #243,
//! checklist item 8).
//!
//! A policy document can be well formed and still be wrong for the gateway it
//! is published to. It can name a tool the gateway does not have, lean on a
//! role it never defines, or leave nobody able to change it again. Nothing in
//! the document shows any of that, so [`validate_resources`] asks the other
//! resources, and [`PolicyResourceSnapshot`] names exactly which versions of
//! them it asked.
//!
//! ## What a snapshot binds
//!
//! The snapshot records the identity of every resource the checks read, never
//! its content: the gateway build, the evaluator semantics and context
//! versions of each lane, the static configuration fingerprint the cluster
//! roster already compares (routing, authentication providers, exempt paths
//! and the environment's egress restrictions among it), the digest of the
//! effective static egress controls, a digest of the tool registry, the
//! Connection collection's ETag and, in cluster mode, the security revision of
//! the installed snapshot. Its own digest is the ADR-0004 `semantic` frame over
//! the RFC 8785 form of those components, so two validations that read the
//! same resources share one digest, and a validation that read anything else
//! does not. A resource that could not be read is named in `unavailable`, the
//! snapshot is not `complete`, and the checks that needed it did not run; the
//! result never guesses what it would have said. A policy write that names the
//! snapshot digest it was reviewed against is refused as stale when the
//! current snapshot differs, rather than re-judged silently.
//!
//! ## What is checked
//!
//! Errors block publication, and only publication: the policy can still be
//! simulated and tested.
//!
//! - `policy_write_unreachable`: the live policy grants `admin:policy:write`
//!   to some role and the candidate to none, so after publication no
//!   principal could change the policy through the policy API. A live policy
//!   that already grants it to nobody is managed some other way -- nobody
//!   can publish through the API at all -- and its successor is not refused
//!   for staying that way.
//! - `publisher_policy_write_lost`: the principal publishing can replace the
//!   live policy and could not replace the candidate. Both answers come from
//!   the shared evaluator: the admin permission check, then the HTTP lane for
//!   that principal's own `PUT` of the policy route, from the host it used,
//!   unless the RBAC stage exempts that route. The pointer names what refuses
//!   it -- the deciding rule or route, the default, or the roles.
//! - `egress_change_requires_restart`: the egress section differs from the
//!   live one, which the policy API has always refused with `409`.
//!
//! Warnings block nothing; each is a reference another resource contradicts:
//! a role that no `roles` entry defines, a route permission no role grants, a
//! tool rule the tool lane can never reach, a tool name the registry does not
//! hold, a Connection endpoint the egress controls refuse, and two role or two
//! tool names that differ only in case. Risks block nothing either; they name
//! an exposure the publisher should know about -- a permissive default, global
//! shadow enforcement, a wildcard grant -- and a publication records them.
//!
//! ## What is not checked
//!
//! Issuer and provider names, admin permission spellings and secret
//! references are not checked. Each needs a registry this gateway does not yet
//! keep in one place, and a check against a partial one would warn about
//! valid values. Startup and `POLICY_FILE` reloads are not checked either:
//! editing the file is how an operator recovers from a lockout.
//!
//! Every check is pure. It reads the views it is handed and the candidate, and
//! performs no DNS, HTTP, store or provider work: a Connection endpoint is
//! judged by the static egress lane without resolution facts.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use http::Method;
use serde::Serialize;
use url::Url;

use crate::{
    auth::Principal,
    canonical_json,
    connections::control_plane::ConnectionControlPlane,
    policy_eval::{
        egress::{
            CompiledEgressPolicy, EgressDestination, EgressEvaluationContext, EgressOutcome,
            ResolutionFact, EGRESS_CONTEXT_VERSION, EGRESS_SEMANTICS_VERSION,
        },
        framed_digest,
        tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
        CompiledPolicy, HostFact, HttpTarget, LogicalDecision, PolicyEffect,
        PolicyEvaluationContext, PrincipalFact, PrincipalIdentity, RuleReference, CONTEXT_VERSION,
        HTTP_SEMANTICS_VERSION,
    },
    rbac::{
        engine::grants_permission,
        policy_document::{
            is_valid_element_id, pointer_token, DiagnosticSeverity, IssueCode, PolicyDiagnostic,
        },
        DefaultAction, EnforcementMode, Policy,
    },
    tools::definitions::ToolRegistry,
};

/// The exact schema version of a [`PolicyResourceSnapshot`].
pub(crate) const RESOURCE_SNAPSHOT_SCHEMA_VERSION: &str = "1.0.0";
/// The media type a snapshot digest frames.
const RESOURCE_SNAPSHOT_MEDIA_TYPE: &str =
    "application/vnd.greengateway.policy-resource-snapshot+json";
/// Frame kind for the tool registry digest. Outside ADR-0004's reserved
/// `source`/`semantic` namespace: the registry serialization is this
/// gateway's own, with no published normalization contract.
const TOOL_REGISTRY_DIGEST_KIND: &str = "gg.policy-resource.tools.v1";

/// The live resources a policy is validated against, attached to the RBAC
/// state once at startup.
///
/// Every handle is the instance the gateway serves from, not a copy taken at
/// boot. The tool registry and the Connection control plane change while the
/// gateway runs, and a check made against a copy would answer for a gateway
/// that no longer exists.
#[derive(Clone)]
pub(crate) struct PolicyResourceSources {
    pub(crate) tools: ToolRegistry,
    pub(crate) connections: ConnectionControlPlane,
    /// The static egress lane the egress client decides every destination by.
    pub(crate) egress: Arc<CompiledEgressPolicy>,
    /// The static configuration fingerprint of the configuration this
    /// process started with, as `sha256:<hex>`.
    pub(crate) configuration_fingerprint: String,
    /// `/v1{ADMIN_PREFIX}/policy`, where a `PUT` replaces the whole policy.
    pub(crate) policy_route: String,
}

impl PolicyResourceSources {
    /// What the resources say now, read once.
    ///
    /// `policy_route_exempt` and `security_revision` are the RBAC state's to
    /// answer, so the caller supplies them.
    pub(crate) fn read(
        &self,
        policy_route_exempt: bool,
        security_revision: Option<i64>,
    ) -> PolicyResourceView {
        PolicyResourceView {
            configuration: Some(self.configuration_fingerprint.clone()),
            egress: Some(Arc::clone(&self.egress)),
            tools: tool_inventory(&self.tools),
            connections: Some(connection_inventory(&self.connections)),
            admin: Some(AdminSurface {
                policy_route: self.policy_route.clone(),
                policy_route_exempt,
            }),
            security_revision,
        }
    }
}

/// What the resources said when they were read, for one validation. `None`
/// is a resource that could not be read, which is never the same as an empty
/// one.
#[derive(Clone, Debug, Default)]
pub(crate) struct PolicyResourceView {
    pub(crate) configuration: Option<String>,
    pub(crate) egress: Option<Arc<CompiledEgressPolicy>>,
    pub(crate) tools: Option<ToolInventory>,
    pub(crate) connections: Option<ConnectionInventory>,
    pub(crate) admin: Option<AdminSurface>,
    /// Cluster mode only; standalone snapshots are not revisioned.
    pub(crate) security_revision: Option<i64>,
}

/// The registered tools: their names, and a digest over their definitions.
#[derive(Clone, Debug)]
pub(crate) struct ToolInventory {
    pub(crate) names: BTreeSet<String>,
    pub(crate) digest: String,
}

/// The Connections: the collection ETag, and the endpoint of every enabled
/// one -- a managed Connection's base URL, a legacy projection's origin.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionInventory {
    pub(crate) etag: String,
    pub(crate) endpoints: Vec<String>,
}

/// Where the policy is replaced, and whether the RBAC stage evaluates policy
/// there at all.
#[derive(Clone, Debug)]
pub(crate) struct AdminSurface {
    pub(crate) policy_route: String,
    pub(crate) policy_route_exempt: bool,
}

fn tool_inventory(registry: &ToolRegistry) -> Option<ToolInventory> {
    let definitions = registry.list();
    let by_name: BTreeMap<&str, _> = definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition.as_ref()))
        .collect();
    // `serde_json` writes struct members in declaration order and maps in key
    // order, so one registry state always serializes to the same bytes. A
    // registry that will not serialize has no identity, and is unavailable
    // rather than given a made-up one.
    let bytes = serde_json::to_vec(&by_name).ok()?;
    Some(ToolInventory {
        names: by_name.keys().map(|name| (*name).to_owned()).collect(),
        digest: digest_text(framed_digest(
            TOOL_REGISTRY_DIGEST_KIND,
            "application/json",
            RESOURCE_SNAPSHOT_SCHEMA_VERSION,
            &bytes,
        )),
    })
}

fn connection_inventory(control_plane: &ConnectionControlPlane) -> ConnectionInventory {
    let snapshot = control_plane.runtime_snapshot();
    let mut endpoints: Vec<String> = snapshot
        .managed()
        .values()
        .filter(|record| record.write.enabled)
        .map(|record| record.write.endpoint.base_url.clone())
        .collect();
    endpoints.extend(
        snapshot
            .legacy()
            .iter()
            .filter_map(|projection| projection.sanitized_origin().map(str::to_owned)),
    );
    ConnectionInventory {
        etag: snapshot.collection_etag().to_owned(),
        endpoints,
    }
}

fn digest_text(digest: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// The versions and digests one validation read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyResourceSnapshot {
    schema_version: &'static str,
    /// `sha256:` over the ADR-0004 `semantic` frame of the RFC 8785 form of
    /// `{schema_version, components}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    complete: bool,
    components: SnapshotComponents,
    /// The components that apply here and could not be read. `admin_routes`
    /// is the policy route and whether the RBAC stage exempts it, which the
    /// publisher check needs and the configuration fingerprint identifies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unavailable: Vec<&'static str>,
}

/// Every value is a string or a small integer, so the canonical form always
/// exists. The security revision is written in decimal for that reason: a
/// watermark past 2^53 has no I-JSON number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SnapshotComponents {
    gateway_build: &'static str,
    evaluator: EvaluatorVersions,
    configuration: Option<String>,
    egress: Option<String>,
    tools: Option<String>,
    connections: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_revision: Option<String>,
}

#[derive(Serialize)]
struct SnapshotDocument<'a> {
    schema_version: &'static str,
    components: &'a SnapshotComponents,
}

/// The semantics and context version of every evaluator lane a policy decides
/// through. A change to any of them is a change to what the policy means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct EvaluatorVersions {
    http: &'static str,
    http_context: u16,
    tools: &'static str,
    tool_context: u16,
    egress: &'static str,
    egress_context: u16,
}

impl PolicyResourceSnapshot {
    fn of(view: &PolicyResourceView) -> Self {
        let components = SnapshotComponents {
            gateway_build: env!("CARGO_PKG_VERSION"),
            evaluator: EvaluatorVersions {
                http: HTTP_SEMANTICS_VERSION,
                http_context: CONTEXT_VERSION,
                tools: TOOL_SEMANTICS_VERSION,
                tool_context: TOOL_CONTEXT_VERSION,
                egress: EGRESS_SEMANTICS_VERSION,
                egress_context: EGRESS_CONTEXT_VERSION,
            },
            configuration: view.configuration.clone(),
            egress: view
                .egress
                .as_ref()
                .map(|egress| digest_text(egress.snapshot().controls_digest())),
            tools: view.tools.as_ref().map(|tools| tools.digest.clone()),
            connections: view
                .connections
                .as_ref()
                .map(|connections| connections.etag.clone()),
            security_revision: view.security_revision.map(|revision| revision.to_string()),
        };
        let mut unavailable = Vec::new();
        for (name, present) in [
            ("configuration", components.configuration.is_some()),
            ("egress", components.egress.is_some()),
            ("tools", components.tools.is_some()),
            ("connections", components.connections.is_some()),
            ("admin_routes", view.admin.is_some()),
        ] {
            if !present {
                unavailable.push(name);
            }
        }
        // Unreachable for these components; a snapshot without its digest
        // is reported incomplete rather than given a made-up one.
        let digest = snapshot_digest(&components);
        Self {
            schema_version: RESOURCE_SNAPSHOT_SCHEMA_VERSION,
            complete: unavailable.is_empty() && digest.is_some(),
            digest,
            components,
            unavailable,
        }
    }

    pub(crate) fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
}

fn snapshot_digest(components: &SnapshotComponents) -> Option<String> {
    let value = serde_json::to_value(SnapshotDocument {
        schema_version: RESOURCE_SNAPSHOT_SCHEMA_VERSION,
        components,
    })
    .ok()?;
    canonical_json::semantic_digest(
        RESOURCE_SNAPSHOT_MEDIA_TYPE,
        RESOURCE_SNAPSHOT_SCHEMA_VERSION,
        &value,
    )
    .ok()
}

/// One finding: its diagnostic, and for an error the free-text detail the
/// caller who sent the document is told. The detail may name values from the
/// document; the diagnostic never does.
#[derive(Clone, Debug)]
pub(crate) struct ResourceFinding {
    pub(crate) diagnostic: PolicyDiagnostic,
    pub(crate) detail: Option<String>,
}

/// Everything the cross-resource checks found, and the snapshot they read.
#[derive(Clone, Debug)]
pub(crate) struct ResourceValidation {
    findings: Vec<ResourceFinding>,
    snapshot: PolicyResourceSnapshot,
}

impl ResourceValidation {
    pub(crate) fn findings(&self) -> &[ResourceFinding] {
        &self.findings
    }

    pub(crate) fn snapshot(&self) -> &PolicyResourceSnapshot {
        &self.snapshot
    }

    pub(crate) fn into_parts(self) -> (Vec<ResourceFinding>, PolicyResourceSnapshot) {
        (self.findings, self.snapshot)
    }

    /// Whether any finding stands in the way of publication.
    pub(crate) fn blocks_publication(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.diagnostic.blocks.publication)
    }

    /// The codes of the findings that block publication, sorted and unique.
    pub(crate) fn blocking_codes(&self) -> Vec<&'static str> {
        self.codes(|diagnostic| diagnostic.blocks.publication)
    }

    /// The codes of the risks found, sorted and unique.
    pub(crate) fn risk_codes(&self) -> Vec<&'static str> {
        self.codes(|diagnostic| diagnostic.severity == DiagnosticSeverity::Risk)
    }

    fn codes(&self, keep: impl Fn(&PolicyDiagnostic) -> bool) -> Vec<&'static str> {
        let codes: BTreeSet<&'static str> = self
            .findings
            .iter()
            .map(|finding| &finding.diagnostic)
            .filter(|diagnostic| keep(diagnostic))
            .map(|diagnostic| diagnostic.code)
            .collect();
        codes.into_iter().collect()
    }
}

/// The principal a validation is made for: the one who would publish.
pub(crate) struct Publisher<'a> {
    pub(crate) principal: &'a Principal,
    /// The request host without its port, as the RBAC stage compares it.
    pub(crate) request_host: Option<String>,
}

/// Validates `candidate` against the resources in `view`, as a replacement
/// for `live`, for `publisher` when one is known.
pub(crate) fn validate_resources(
    candidate: &Policy,
    live: &Policy,
    view: &PolicyResourceView,
    publisher: Option<&Publisher<'_>>,
) -> ResourceValidation {
    let mut findings = Findings::default();

    check_policy_write_reachable(candidate, live, &mut findings);
    if let Some(publisher) = publisher {
        check_publisher_keeps_policy_write(
            candidate,
            live,
            view.admin.as_ref(),
            publisher,
            &mut findings,
        );
    }
    if candidate.egress != live.egress {
        findings.error(
            IssueCode::EgressChangeRequiresRestart,
            "/egress".to_owned(),
            None,
            "egress allowlist changes cannot be applied via the policy API; edit POLICY_FILE \
             and restart the gateway to change egress rules"
                .to_owned(),
        );
    }

    check_role_references(candidate, &mut findings);
    check_route_permissions(candidate, &mut findings);
    check_tool_rules(candidate, &mut findings);
    if let Some(tools) = view.tools.as_ref() {
        check_tool_registration(candidate, tools, &mut findings);
    }
    if let (Some(egress), Some(connections)) = (view.egress.as_ref(), view.connections.as_ref()) {
        check_connection_endpoints(egress, connections, &mut findings);
    }
    check_name_collisions(candidate, &mut findings);

    let snapshot = PolicyResourceSnapshot::of(view);
    if !snapshot.is_complete() {
        findings.note(IssueCode::ResourceUnavailable, String::new(), None);
    }

    check_risks(candidate, &mut findings);

    ResourceValidation {
        findings: findings.0,
        snapshot,
    }
}

#[derive(Default)]
struct Findings(Vec<ResourceFinding>);

impl Findings {
    fn error(
        &mut self,
        code: IssueCode,
        pointer: String,
        element_id: Option<String>,
        detail: String,
    ) {
        self.0.push(ResourceFinding {
            diagnostic: PolicyDiagnostic::finding(code, pointer, element_id),
            detail: Some(detail),
        });
    }

    /// A warning or a risk: the code says which.
    fn note(&mut self, code: IssueCode, pointer: String, element_id: Option<String>) {
        self.0.push(ResourceFinding {
            diagnostic: PolicyDiagnostic::finding(code, pointer, element_id),
            detail: None,
        });
    }
}

/// The stable id of an element, when it has a valid one.
fn element_id(id: Option<&str>) -> Option<String> {
    id.filter(|id| is_valid_element_id(id)).map(str::to_owned)
}

fn sorted_keys<V>(map: &HashMap<String, V>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    keys
}

fn grants_policy_write(policy: &Policy) -> bool {
    policy
        .roles
        .values()
        .any(|role| grants_permission(&role.permissions, crate::ADMIN_POLICY_WRITE_PERMISSION))
}

/// The loss of every policy-write principal: a change that takes the
/// permission from the last role holding it.
fn check_policy_write_reachable(candidate: &Policy, live: &Policy, findings: &mut Findings) {
    if grants_policy_write(live) && !grants_policy_write(candidate) {
        findings.error(
            IssueCode::PolicyWriteUnreachable,
            "/roles".to_owned(),
            None,
            format!(
                "no role grants {} or \"*\", so after this change no principal could change the \
                 policy through the policy API",
                crate::ADMIN_POLICY_WRITE_PERMISSION
            ),
        );
    }
}

/// Whether the publisher could replace a policy, and if not, what refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteReach {
    Reachable,
    /// No role the publisher holds grants the permission, for its issuer and
    /// authentication method.
    NoPermission,
    /// The HTTP lane refuses the publisher's `PUT` of the policy route.
    Refused(Option<RuleReference>),
    /// The HTTP lane could not answer, which the RBAC stage refuses too.
    Unanswered,
}

fn policy_write_reach(
    policy: &CompiledPolicy,
    admin: Option<&AdminSurface>,
    publisher: &Publisher<'_>,
) -> WriteReach {
    if !policy.principal_has_permission(publisher.principal, crate::ADMIN_POLICY_WRITE_PERMISSION) {
        return WriteReach::NoPermission;
    }
    // Without the admin surface only the permission can be judged; the
    // snapshot names it unavailable.
    let Some(admin) = admin else {
        return WriteReach::Reachable;
    };
    if admin.policy_route_exempt {
        return WriteReach::Reachable;
    }
    // The request the RBAC stage would judge: gateway-owned, so never a
    // classified proxy dispatch, from the publisher's own host.
    let context = PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: policy.snapshot(),
        method: Some(Method::PUT),
        path: Some(admin.policy_route.clone()),
        principal: PrincipalFact::Authenticated(PrincipalIdentity::from_principal(
            publisher.principal,
        )),
        target: HttpTarget::Contextless,
        request_host: publisher
            .request_host
            .clone()
            .map_or(HostFact::Absent, HostFact::Present),
        dispatch: None,
    };
    match policy.evaluate(&context) {
        Ok(evaluation)
            if evaluation.is_complete()
                && evaluation.logical() != LogicalDecision::Indeterminate =>
        {
            if evaluation.effect() == PolicyEffect::Block {
                WriteReach::Refused(evaluation.matched())
            } else {
                WriteReach::Reachable
            }
        }
        _ => WriteReach::Unanswered,
    }
}

fn check_publisher_keeps_policy_write(
    candidate: &Policy,
    live: &Policy,
    admin: Option<&AdminSurface>,
    publisher: &Publisher<'_>,
    findings: &mut Findings,
) {
    // Only a publisher who can replace the live policy has anything to lose.
    if policy_write_reach(
        &CompiledPolicy::for_analysis(live.clone()),
        admin,
        publisher,
    ) != WriteReach::Reachable
    {
        return;
    }
    let reach = policy_write_reach(
        &CompiledPolicy::for_analysis(candidate.clone()),
        admin,
        publisher,
    );
    let route = admin.map_or("the policy route", |admin| admin.policy_route.as_str());
    let (pointer, element, reason) = match reach {
        WriteReach::Reachable => return,
        WriteReach::NoPermission => (
            "/roles".to_owned(),
            None,
            format!(
                "no role it holds would grant {} for its issuer and authentication method",
                crate::ADMIN_POLICY_WRITE_PERMISSION
            ),
        ),
        WriteReach::Refused(Some(RuleReference::Direct(index))) => (
            format!("/rules/{index}"),
            candidate
                .rules
                .get(index)
                .and_then(|rule| element_id(rule.id.as_deref())),
            format!("rules[{index}] would refuse its PUT {route}"),
        ),
        WriteReach::Refused(Some(RuleReference::Route(index))) => (
            format!("/routes/{index}"),
            candidate
                .routes
                .get(index)
                .and_then(|route| element_id(route.id.as_deref())),
            format!("routes[{index}] would refuse its PUT {route}"),
        ),
        WriteReach::Refused(None) => (
            "/default_action".to_owned(),
            None,
            format!("the default action would refuse its PUT {route}"),
        ),
        WriteReach::Unanswered => (
            String::new(),
            None,
            format!("its PUT {route} could not be evaluated under the candidate"),
        ),
    };
    findings.error(
        IssueCode::PublisherPolicyWriteLost,
        pointer,
        element,
        format!("the principal making this change could not replace the policy after it: {reason}"),
    );
}

fn check_role_references(candidate: &Policy, findings: &mut Findings) {
    let defined = |role: &String| candidate.roles.contains_key(role);
    for name in sorted_keys(&candidate.tools) {
        let entry = &candidate.tools[name];
        for (index, role) in entry.allowed_roles.iter().enumerate() {
            if !defined(role) {
                findings.note(
                    IssueCode::RoleNotDefined,
                    format!("/tools/{}/allowed_roles/{index}", pointer_token(name)),
                    None,
                );
            }
        }
    }
    for (rule_index, rule) in candidate.rules.iter().enumerate() {
        for (index, role) in rule.principal.roles.iter().enumerate() {
            if !defined(role) {
                findings.note(
                    IssueCode::RoleNotDefined,
                    format!("/rules/{rule_index}/principal/roles/{index}"),
                    element_id(rule.id.as_deref()),
                );
            }
        }
    }
    for (limit_index, limit) in candidate.rate_limits.iter().enumerate() {
        for (index, role) in limit.principal.roles.iter().enumerate() {
            if !defined(role) {
                findings.note(
                    IssueCode::RoleNotDefined,
                    format!("/rate_limits/{limit_index}/principal/roles/{index}"),
                    element_id(limit.id.as_deref()),
                );
            }
        }
    }
}

fn check_route_permissions(candidate: &Policy, findings: &mut Findings) {
    for (index, route) in candidate.routes.iter().enumerate() {
        let granted = candidate
            .roles
            .values()
            .any(|role| grants_permission(&role.permissions, &route.permission));
        if !granted {
            findings.note(
                IssueCode::RoutePermissionUngranted,
                format!("/routes/{index}/permission"),
                element_id(route.id.as_deref()),
            );
        }
    }
}

/// A tool-name rule decides only an invocation the tool lane has admitted,
/// and the lane admits nothing for a tool without an enabled entry.
fn check_tool_rules(candidate: &Policy, findings: &mut Findings) {
    for (index, rule) in candidate.rules.iter().enumerate() {
        let Some(tool_name) = rule.tool_name.as_deref() else {
            continue;
        };
        if !rule.enabled {
            continue;
        }
        let admitted = candidate
            .tools
            .get(tool_name)
            .is_some_and(|entry| entry.enabled);
        if !admitted {
            findings.note(
                IssueCode::ToolRuleNeverDecides,
                format!("/rules/{index}/tool_name"),
                element_id(rule.id.as_deref()),
            );
        }
    }
}

fn check_tool_registration(candidate: &Policy, tools: &ToolInventory, findings: &mut Findings) {
    for name in sorted_keys(&candidate.tools) {
        if !tools.names.contains(name.as_str()) {
            findings.note(
                IssueCode::ToolNotRegistered,
                format!("/tools/{}", pointer_token(name)),
                None,
            );
        }
    }
    for (index, rule) in candidate.rules.iter().enumerate() {
        let Some(tool_name) = rule.tool_name.as_deref() else {
            continue;
        };
        if !tools.names.contains(tool_name) {
            findings.note(
                IssueCode::ToolNotRegistered,
                format!("/rules/{index}/tool_name"),
                element_id(rule.id.as_deref()),
            );
        }
    }
}

/// One warning, however many endpoints are refused, and without naming
/// them: Connection identities belong to the Connections API and its
/// permissions, not to a policy reader.
fn check_connection_endpoints(
    egress: &CompiledEgressPolicy,
    connections: &ConnectionInventory,
    findings: &mut Findings,
) {
    let refused = connections.endpoints.iter().any(|endpoint| {
        // A base URL that does not parse is the Connections API's to refuse.
        let Ok(url) = Url::parse(endpoint) else {
            return false;
        };
        let destination = EgressDestination::from_url(&url);
        let context = EgressEvaluationContext {
            version: EGRESS_CONTEXT_VERSION,
            snapshot: egress.snapshot(),
            destination: &destination,
            resolution: ResolutionFact::Missing,
        };
        matches!(
            egress
                .evaluate(&context)
                .map(|evaluation| evaluation.outcome()),
            Ok(EgressOutcome::Deny(_))
        )
    });
    if refused {
        findings.note(
            IssueCode::ConnectionEndpointEgressDenied,
            "/egress".to_owned(),
            None,
        );
    }
}

/// Role and tool names compare exactly. Two that differ only in case are two
/// names, and almost never meant to be.
fn check_name_collisions(candidate: &Policy, findings: &mut Findings) {
    for (section, names) in [
        ("roles", sorted_keys(&candidate.roles)),
        ("tools", sorted_keys(&candidate.tools)),
    ] {
        let mut seen = BTreeSet::new();
        for name in names {
            if !seen.insert(name.to_ascii_lowercase()) {
                findings.note(
                    IssueCode::NameCaseCollision,
                    format!("/{section}/{}", pointer_token(name)),
                    None,
                );
            }
        }
    }
}

fn check_risks(candidate: &Policy, findings: &mut Findings) {
    if candidate.default_action == DefaultAction::Allow {
        findings.note(
            IssueCode::DefaultActionAllow,
            "/default_action".to_owned(),
            None,
        );
    }
    if candidate.enforcement_mode == EnforcementMode::Shadow {
        findings.note(
            IssueCode::EnforcementModeShadow,
            "/enforcement_mode".to_owned(),
            None,
        );
    }
    for name in sorted_keys(&candidate.roles) {
        for (index, permission) in candidate.roles[name].permissions.iter().enumerate() {
            if permission == "*" {
                findings.note(
                    IssueCode::WildcardPermission,
                    format!("/roles/{}/permissions/{index}", pointer_token(name)),
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "policy_resources_tests.rs"]
mod tests;
