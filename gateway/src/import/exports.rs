//! The canonical exports the import digests (issue #241, PR 15, steps 2-8).
//!
//! Every section's checksum is a SHA-256 over one of these values, and the
//! validation step computes the SAME value from the TARGET so the two can
//! be compared. That is the whole reason they live here rather than inside
//! the sections: a checksum a rehearsal computes one way and a
//! verification computes another way is not evidence of anything, so there
//! is exactly one function per section and both sides call it.
//!
//! Rules every export follows:
//!
//! - **Content, not encoding.** [`super::canonical_digest`] sorts object
//!   keys before hashing, and every array here is built in a defined order
//!   (the source's own key order, or an explicit sort), so a digest depends
//!   on what is stored and not on the order a map iterated.
//! - **Stored values, not derived ones.** A projection that ages with the
//!   clock (a Connection status's `catalog_age_secs`) or that a reader
//!   recomputes is exported as PERSISTED, so a rehearsal at 09:00 and the
//!   apply at 09:40 digest to the same number.
//! - **Nothing secret.** These values feed a digest and are never printed.
//!   Even so, the only credential-shaped things in them are a secret ID (a
//!   locator into the operator's secret store) and a service token's HASH
//!   -- the verifier, never the token. No plaintext exists on either side
//!   of this import.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{
    auth::tokens::ExportedServiceToken,
    connections::{
        pg_store::ImportedConnection,
        store::{expected_bindings, reason_as_str, state_as_str, PersistedConnectionStatus},
    },
    discovery::{
        aggregator::{EndpointAggregate, EndpointKey, PendingFlush},
        query::{ExportedEndpointReview, RawSignal},
        suggestions::RuleSuggestion,
    },
    rbac::{policy_history::PolicyVersion, Policy},
};

use super::ImportError;

pub(super) const POLICY_SECTION: &str = "policy";
pub(super) const TOOLS_SECTION: &str = "tools";
pub(super) const CONNECTIONS_SECTION: &str = "connections";
pub(super) const AUDIT_SECTION: &str = "audit";
pub(super) const DISCOVERY_SECTION: &str = "observations_and_discovery";
pub(super) const PRINCIPALS_SECTION: &str = "principals_and_service_tokens";

/// The policy section: the immutable history the import carries, plus the
/// document it activates.
///
/// The activation version itself is NOT in the export. The import mints it
/// (the standalone POLICY FILE becomes the next version), so it exists on
/// the target and not in the source; what both sides can state is the same
/// history and the same active document.
pub(super) fn policy_export(
    history: &[PolicyVersion],
    active: &Policy,
) -> Result<Value, ImportError> {
    let mut versions = Vec::with_capacity(history.len());
    for entry in history {
        // `include_policy` is set on every read, so a missing snapshot is
        // a store that answered outside its contract.
        let Some(snapshot) = entry.policy.as_ref() else {
            return Err(ImportError::SourceDocumentUnparseable {
                kind: "policy history",
                detail: format!("version {} carries no policy snapshot", entry.version),
            });
        };
        versions.push(json!({
            "version": entry.version,
            "actor": entry.actor_user_id,
            // An INSTANT, not the text it was spelled with: the source's
            // column is RFC 3339 text (nanoseconds when the clock had
            // them) and the target's is `timestamptz` rendered with fixed
            // microseconds, so comparing the spellings would report a
            // difference that is not one. Sub-microsecond precision is
            // genuinely lost in the column, and normalizing both sides is
            // what states that honestly instead of failing on it.
            "created_at": normalized_instant(Some(&entry.created_at)),
            // Recomputed from the document by THIS binary on both sides,
            // never carried across: the ETag the cluster stores must be
            // the one the authority derives, or its self-verification
            // would fail closed on a document it can otherwise serve.
            "etag": policy_etag(snapshot)?,
            "diff_summary": entry.diff_summary,
            "document": document_of(snapshot)?,
        }));
    }
    Ok(json!({
        "section": POLICY_SECTION,
        "active_etag": policy_etag(active)?,
        "active_document": document_of(active)?,
        "history": versions,
    }))
}

fn policy_etag(policy: &Policy) -> Result<String, ImportError> {
    crate::policy_etag(policy).map_err(|error| ImportError::SourceDocumentUnparseable {
        kind: "policy",
        detail: error.to_string(),
    })
}

fn document_of(policy: &Policy) -> Result<Value, ImportError> {
    serde_json::to_value(policy).map_err(|error| ImportError::SourceDocumentUnparseable {
        kind: "policy",
        detail: error.to_string(),
    })
}

/// The tools section: the active document, its ETag, and the tool names
/// reserved for the local lane.
pub(super) fn tools_export(document: &Value, etag: &str, names: &[String]) -> Value {
    json!({
        "section": TOOLS_SECTION,
        "etag": etag,
        "document": document,
        "tool_names": names,
    })
}

/// The names a tools document reserves in the local lane, in the shape the
/// store reserves them: `tools[].name`, deduplicated and ordered.
pub(super) fn tool_names(document: &Value) -> Vec<String> {
    let mut names: Vec<String> = document["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// The Connections section: every record with its identity, its per-axis
/// revisions, its credential bindings AS REFERENCES, its dependencies,
/// both status tables and the managed catalogs.
pub(super) fn connections_export(connections: &[ImportedConnection]) -> Result<Value, ImportError> {
    let mut export: Vec<Value> = Vec::with_capacity(connections.len());
    for connection in connections {
        let record = &connection.record;
        let specification = serde_json::to_value(&record.write).map_err(|error| {
            ImportError::SourceDocumentUnparseable {
                kind: "Connection",
                detail: error.to_string(),
            }
        })?;
        let bindings: Vec<Value> = expected_bindings(&record.write, &record.revisions)
            .into_iter()
            .map(|binding| {
                let mut value = json!({
                    "purpose": binding.purpose,
                    // A secret ID is a LOCATOR, not a secret: it names an
                    // entry in the operator's secret store. The value it
                    // locates is never read here.
                    "secret_id": binding.secret_id,
                    "binding_version": binding.version.max(1),
                });
                // Only an additional header carries a header name; the
                // primary bindings keep the shape they always had.
                if !binding.header_name.is_empty() {
                    value["header_name"] = Value::String(binding.header_name.to_owned());
                }
                value
            })
            .collect();
        let mut dependencies: Vec<Value> = connection
            .dependencies
            .iter()
            .map(|dependency| {
                json!({
                    "kind": dependency.kind,
                    "consumer_id": dependency.consumer_id,
                    // Every imported dependency claims no source document;
                    // see `import_connections_in`.
                    "source_revision": 0,
                })
            })
            .collect();
        dependencies.sort_by_key(|value| value.to_string());
        let mut history: Vec<Value> = connection
            .status_history
            .iter()
            .map(status_export)
            .collect();
        history.sort_by_key(|value| value.to_string());

        export.push(json!({
            "id": record.id.to_string(),
            "etag": record.etag().as_str(),
            "revisions": {
                "connection": record.revisions.connection,
                "credential": record.revisions.credential,
                "tls": record.revisions.tls,
                "discovery": record.revisions.discovery,
                "status": record.revisions.status,
            },
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "last_test_at": connection.activity.last_test_at,
            "last_refresh_at": connection.activity.last_refresh_at,
            "specification": specification,
            "credential_bindings": bindings,
            "dependencies": dependencies,
            "current_status": connection.current_status.as_ref().map(status_export),
            "status_history": history,
            "mcp_catalog": connection.mcp_catalog.as_ref().map(|catalog| json!({
                "catalog_revision": catalog.catalog_revision,
                "observed_etag": catalog.observed_etag.as_str(),
                "refreshed_at": catalog.refreshed_at,
                "entries": catalog
                    .entries
                    .iter()
                    .map(|entry| json!({
                        "remote_tool_name": entry.remote_tool_name,
                        "description": entry.description,
                        "input_schema": entry.input_schema,
                    }))
                    .collect::<Vec<_>>(),
                "resources": catalog.resources,
                "resource_templates": catalog.resource_templates,
            })),
            "openapi_catalog": connection.openapi_catalog.as_ref().map(|catalog| json!({
                "spec_revision": catalog.spec_revision,
                "catalog_revision": catalog.catalog_revision,
                "overlay_revision": catalog.overlay_revision,
                "observed_etag": catalog.observed_etag.as_str(),
                // The digest stands for the specification body: it is a
                // SHA-256 over exactly the bytes stored, re-verified on
                // every read, so including it pins the spec without
                // hashing megabytes of it twice.
                "spec_digest": catalog.spec_digest,
                "refreshed_at": catalog.refreshed_at,
                "entries": catalog
                    .entries
                    .iter()
                    .map(|entry| json!({
                        "tool_name": entry.tool_name,
                        "operation_id": entry.operation_id,
                        "selected_scheme_names": entry.selected_scheme_names,
                        "definition": entry.definition,
                    }))
                    .collect::<Vec<_>>(),
            })),
            "openapi_overlay": connection.openapi_overlay.as_ref().map(|overlay| json!({
                "schema_version": overlay.schema_version,
                "overlay_revision": overlay.overlay_revision,
                "overlay": serde_json::from_str::<Value>(&overlay.overlay_json)
                    .unwrap_or(Value::Null),
                "source_reports": overlay.source_reports_json.as_deref()
                    .map(|reports| serde_json::from_str::<Value>(reports).unwrap_or(Value::Null)),
                "updated_at": overlay.updated_at,
            })),
        }));
    }
    // Record order is the caller's read order, which differs between the
    // two stores. The identity is the id, so sort on it.
    export.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_owned());
    Ok(json!({
        "section": CONNECTIONS_SECTION,
        "connections": export,
    }))
}

/// One persisted status observation. The persisted `catalog_age_secs` is
/// exported, not the safe projection's aged value, so a rehearsal and the
/// apply that follows it an hour later produce the same checksum.
fn status_export(status: &PersistedConnectionStatus) -> Value {
    json!({
        "connection_id": status.connection_id.to_string(),
        "status_revision": status.status_revision,
        "observed_connection_revision": status.observed_connection_revision,
        "observed_credential_revision": status.observed_credential_revision,
        "observed_tls_revision": status.observed_tls_revision,
        "observed_discovery_revision": status.observed_discovery_revision,
        "state": state_as_str(status.state),
        "reason": reason_as_str(status.reason),
        "observed_at": status.observed_at,
        "latency_ms": status.latency_ms,
        "catalog_age_secs": status.catalog_age_secs,
        "catalog_entry_count": status.catalog_entry_count,
    })
}

/// One audit event as the audit section's streaming digest folds it: the
/// durable columns, and nothing the ingesting replica adds.
pub(super) fn event_export(event: &crate::audit::AuditEvent) -> Value {
    json!({
        "event_id": event.event_id,
        "event_type": event.event_type,
        // An INSTANT: `audit_events.occurred_at` is `timestamptz` and the
        // stream renders it with fixed microseconds, where the source
        // keeps the event's own RFC 3339 text.
        "timestamp": normalized_instant(Some(&event.timestamp)),
        "schema_version": event.schema_version,
        "request_id": event.request_id,
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "actor": event.actor,
        "payload": event.payload,
    })
}

/// The discovery section: the endpoint inventory as the aggregator model
/// holds it, the detector windows and learner groups derived from it, and
/// the three lifecycle tables with their revisions.
///
/// Both sides build this from an [`crate::discovery::aggregator::AggregatorState`]
/// rebuilt by `from_rows`, so the comparison is between two runs of the
/// same model over the same data rather than between two readings of two
/// schemas.
pub(super) fn discovery_export(
    batch: &PendingFlush,
    detector_states: &[(EndpointKey, String)],
    template_groups_json: Option<&str>,
    signals: &[RawSignal],
    suggestions: &[RuleSuggestion],
    reviews: &[ExportedEndpointReview],
) -> Result<Value, ImportError> {
    let mut endpoints: Vec<Value> = batch
        .dirty_aggregates
        .iter()
        .map(aggregate_export)
        .collect();
    endpoints.sort_by_key(|value| value["key"].to_string());

    let mut detectors: Vec<Value> = detector_states
        .iter()
        .map(|(key, state_json)| {
            json!({
                "method": key.method,
                "endpoint_template": key.endpoint_template,
                // Parsed rather than embedded as text: the two sides
                // serialize the same state, but a digest over text would
                // depend on the serializer's key order.
                "state": serde_json::from_str::<Value>(state_json).unwrap_or(Value::Null),
            })
        })
        .collect();
    detectors.sort_by_key(|value| {
        (
            value["method"].to_string(),
            value["endpoint_template"].to_string(),
        )
    });

    let mut signal_export: Vec<Value> = signals.iter().map(signal_export).collect();
    signal_export.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_owned());
    let mut suggestion_export: Vec<Value> = suggestions
        .iter()
        .map(suggestion_export)
        .collect::<Result<Vec<_>, _>>()?;
    suggestion_export.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_owned());
    let mut review_export: Vec<Value> = reviews
        .iter()
        .map(|review| {
            json!({
                "method": review.method,
                "endpoint_template": review.endpoint_template,
                "reviewed_at": review.reviewed_at,
                "reviewed_by": review.reviewed_by,
                "revision": review.revision,
            })
        })
        .collect();
    review_export.sort_by_key(|value| {
        (
            value["method"].to_string(),
            value["endpoint_template"].to_string(),
        )
    });

    Ok(json!({
        "section": DISCOVERY_SECTION,
        "endpoints": endpoints,
        "detector_states": detectors,
        "template_groups": template_groups_json
            .map(|groups| serde_json::from_str::<Value>(groups).unwrap_or(Value::Null)),
        "signals": signal_export,
        "rule_suggestions": suggestion_export,
        "endpoint_reviews": review_export,
    }))
}

fn aggregate_export(aggregate: &EndpointAggregate) -> Value {
    let mut principals: Vec<Value> = aggregate
        .principals
        .iter()
        .map(|(identity, seen)| {
            json!({
                "user_id": identity.user_id,
                "issuer": identity.issuer,
                "auth_method": identity.auth_method,
                "first_seen": seen.first_seen,
                "last_seen": seen.last_seen,
            })
        })
        .collect();
    principals.sort_by_key(|value| value.to_string());

    let mut routing_contexts: Vec<Value> = aggregate
        .routing_contexts
        .values()
        .map(|context| {
            let mut context_principals: Vec<Value> = context
                .principals
                .iter()
                .map(|identity| {
                    json!({
                        "user_id": identity.user_id,
                        "issuer": identity.issuer,
                        "auth_method": identity.auth_method,
                    })
                })
                .collect();
            context_principals.sort_by_key(|value| value.to_string());
            json!({
                "route_host": context.key.route_host,
                "route_path_prefix": context.key.route_path_prefix,
                "upstream_origin": context.key.upstream_origin,
                "first_seen": context.first_seen,
                "last_seen": context.last_seen,
                "call_count": context.call_count,
                "principals": context_principals,
            })
        })
        .collect();
    routing_contexts.sort_by_key(|value| value.to_string());

    let mut classified_principals: Vec<Value> = aggregate
        .classified_signal_state
        .principals
        .iter()
        .map(|identity| {
            json!({
                "user_id": identity.user_id,
                "issuer": identity.issuer,
                "auth_method": identity.auth_method,
            })
        })
        .collect();
    classified_principals.sort_by_key(|value| value.to_string());

    json!({
        "key": {
            "method": aggregate.key.method,
            "endpoint_template": aggregate.key.endpoint_template,
        },
        "first_seen": aggregate.first_seen,
        "last_seen": aggregate.last_seen,
        "call_count": aggregate.call_count,
        "schema_mismatch_count": aggregate.schema_mismatch_count,
        "status_counts": aggregate
            .status_counts
            .iter()
            .map(|(status, count)| json!({ "status": status, "count": count }))
            .collect::<Vec<_>>(),
        "latency_count": aggregate.latency_count,
        "latency_samples": aggregate.latency_samples,
        "payload_shape_observation_count": aggregate.payload_shape_observation_count,
        "payload_shape_samples": aggregate
            .payload_shape_samples
            .iter()
            .map(|sample| json!({
                "observed_at": sample.observed_at,
                "shape_hash": sample.shape_hash,
                "shape": sample.shape,
            }))
            .collect::<Vec<_>>(),
        "principals": principals,
        "routing_contexts": routing_contexts,
        "routing_context_known_since": aggregate.routing_context_known_since,
        "classified_signal_state": {
            "call_count": aggregate.classified_signal_state.call_count,
            "schema_mismatch_count": aggregate.classified_signal_state.schema_mismatch_count,
            "error_count": aggregate.classified_signal_state.error_count,
            "principals": classified_principals,
        },
    })
}

fn signal_export(signal: &RawSignal) -> Value {
    json!({
        "id": signal.id,
        "signal_type": signal.signal_type,
        "target_kind": signal.target_kind,
        "target_key": signal.target_key,
        "target_identity": serde_json::from_str::<Value>(&signal.target_identity_json)
            .unwrap_or(Value::Null),
        "explanation": signal.explanation,
        "evidence": serde_json::from_str::<Value>(&signal.evidence_json).unwrap_or(Value::Null),
        "state": signal.state,
        "created_at": signal.created_at,
        "updated_at": signal.updated_at,
        "transitioned_at": signal.transitioned_at,
        "transitioned_by": signal.transitioned_by,
        // Set explicitly by the import rather than left to migration 11's
        // default, so this number is a carried decision on both sides.
        "revision": signal.revision,
    })
}

fn suggestion_export(suggestion: &RuleSuggestion) -> Result<Value, ImportError> {
    let proposed_rule = serde_json::to_value(&suggestion.proposed_rule).map_err(|error| {
        ImportError::SourceDocumentUnparseable {
            kind: "rule suggestion",
            detail: error.to_string(),
        }
    })?;
    Ok(json!({
        "id": suggestion.id,
        "suggestion_type": suggestion.suggestion_type,
        "method": suggestion.method,
        "path_pattern": suggestion.path_pattern,
        "principal_key": suggestion.principal_key,
        "proposed_rule": proposed_rule,
        "rationale": suggestion.rationale,
        "evidence": suggestion.evidence,
        "state": suggestion.state.as_str(),
        "created_at": suggestion.created_at,
        "updated_at": suggestion.updated_at,
        "transitioned_at": suggestion.transitioned_at,
        "transitioned_by": suggestion.transitioned_by,
        "source_signal_id": suggestion.source_signal_id,
        "revision": suggestion.revision,
    }))
}

/// The principals-and-service-tokens section.
///
/// The token HASH is in the digest deliberately: "token hashes equal" is
/// the property that decides whether an already-issued token still
/// authenticates after the cutover, and a checksum that omitted it could
/// not tell a faithful import from one that silently invalidated every
/// token. A SHA-256 over it is one-way and the digest is what is printed;
/// the hash itself never leaves this function.
///
/// The principal directory is not here, because cluster mode has no
/// principal directory to compare against. The section's report says so in
/// counts rather than leaving the omission to be discovered.
pub(super) fn service_tokens_export(tokens: &[ExportedServiceToken]) -> Value {
    let mut export: Vec<Value> = tokens
        .iter()
        .map(|token| {
            json!({
                "id": token.id,
                "token_hash": token.token_hash,
                "token_prefix": token.token_prefix,
                "scopes": serde_json::from_str::<Value>(&token.scopes_json)
                    .unwrap_or(Value::Null),
                "created_by": token.created_by,
                // Timestamps are compared as INSTANTS: the target renders
                // `timestamptz` with fixed microseconds where the source
                // keeps the text it was written with, so the export
                // normalizes both to the same rendering.
                "created_at": normalized_instant(Some(&token.created_at)),
                "expires_at": normalized_instant(token.expires_at.as_deref()),
                "last_used_at": normalized_instant(token.last_used_at.as_deref()),
                "revoked_at": normalized_instant(token.revoked_at.as_deref()),
                // The standalone table has no revision column; every
                // imported token is at revision 1, which is a decision the
                // writer makes explicitly (see `import_service_tokens_in`).
                "revision": 1,
            })
        })
        .collect();
    export.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_owned());
    json!({
        "section": PRINCIPALS_SECTION,
        "service_tokens": export,
        // Stated in the digest so a report claiming this section is
        // verified cannot also be hiding an imported principal directory.
        "principal_directory_rows": 0,
    })
}

/// One RFC 3339 timestamp as a comparable instant: UTC, microsecond
/// precision, `Z`. Text that does not parse is carried through unchanged
/// rather than dropped, so a malformed value is still visible as a
/// difference between the two sides.
///
/// Microseconds because that is what a `timestamptz` column holds. The
/// import does not merely digest this form -- it WRITES it (the policy
/// history's `created_at`, every audit event's timestamp), so the value
/// stored is the one the source stated truncated to the column's
/// precision, rather than the one PostgreSQL would have produced by
/// rounding the cast. The difference is sub-microsecond; the point is
/// that it is stated rather than silent, and that both sides of the
/// validation therefore digest the same text.
pub(super) fn normalized_instant(value: Option<&str>) -> Option<String> {
    let value = value?;
    let Ok(parsed) =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
    else {
        return Some(value.to_owned());
    };
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    );
    Some(
        parsed
            .to_offset(time::UtcOffset::UTC)
            .format(format)
            .unwrap_or_else(|_| value.to_owned()),
    )
}

/// Counts as the section reports carry them: a sorted, named map so the
/// JSON report is stable between runs.
pub(super) fn counts<const N: usize>(entries: [(&str, i64); N]) -> BTreeMap<String, i64> {
    entries
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}
