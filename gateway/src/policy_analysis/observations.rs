//! The aggregate evidence attached to an Optimize analysis. Only counts from
//! the replay evaluator's base/candidate comparison enter the observations.
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::AnalysisError;
use crate::{canonical_json, policy_replay::job};

fn project(view: &Value, complete: bool) -> Option<Value> {
    let result = view.get("result")?;
    let digest =
        canonical_json::semantic_digest(job::RESULT_MEDIA_TYPE, job::RESULT_SCHEMA_VERSION, result)
            .ok()?;
    let source = result.get("source")?;
    let window = view.get("window")?;
    let from = OffsetDateTime::parse(window["from"].as_str()?, &Rfc3339).ok()?;
    let to = OffsetDateTime::parse(window["to"].as_str()?, &Rfc3339).ok()?;
    let cutoff = view.get("cutoff")?;
    let high_water = cutoff["high_water"].as_u64()?;
    let selected = cutoff["selected_records"].as_u64()?;
    let max_records = view["limits"]["max_records"].as_u64()?;
    let records = result.get("records")?;
    let scanned = records["scanned"].as_u64()?;
    let replayable = records["replayable"].as_u64()?;
    let limitations = result["limitations"].as_array()?;
    if result["schema_version"] != job::RESULT_SCHEMA_VERSION
        || result["mode"] != "historical_replay"
        || result["not_replayed"] != json!(job::NOT_REPLAYED)
        || result["complete"].as_bool()? != complete
        || digest != view["result_digest"].as_str()?
        || from >= to
        || source["window"] != *window
        || source["high_water"].as_u64()? != high_water
        || source["max_records"].as_u64()? != max_records
        || records["selected"].as_u64()? != selected
        || max_records == 0
        || max_records > job::MAX_REPLAY_RECORDS as u64
        || scanned > max_records
        || replayable > scanned
        || (complete && selected != scanned)
        || complete != limitations.is_empty()
        || limitations.iter().any(|code| {
            !matches!(
                code.as_str(),
                Some(
                    "scan_truncated"
                        | "source_changed"
                        | "source_pruned"
                        | "deadline_exceeded"
                        | "no_data"
                )
            )
        })
    {
        return None;
    }
    let requested = view["projections"].as_array()?;
    let projections = result["impact"]["projections"].as_object()?;
    if projections.is_empty() || requested.len() != projections.len() {
        return None;
    }
    let mut coverage = Vec::new();
    let mut observations = Vec::new();
    for (projection, tally) in projections {
        if !matches!(projection.as_str(), "as_authored" | "enforce_all_shadow")
            || !requested
                .iter()
                .any(|item| item.as_str() == Some(projection))
        {
            return None;
        }
        let mut projection_records = 0_u64;
        for lane in ["http", "tool"] {
            let tally = tally.get(lane)?;
            let total = tally["records"].as_u64()?;
            projection_records = projection_records.checked_add(total)?;
            let compared = tally["compared"].as_u64()?;
            let transitions = tally.get("transitions")?;
            let indeterminate = transitions["indeterminate"].as_u64()?;
            let unsupported = transitions["unsupported_context"].as_u64()?;
            if total > scanned
                || compared
                    .checked_add(indeterminate)?
                    .checked_add(unsupported)?
                    != total
            {
                return None;
            }
            coverage.push(json!({"projection": projection, "lane": lane, "records": total, "compared": compared,
                "indeterminate": indeterminate, "unsupported_context": unsupported}));
            for (code, count) in [
                ("newly_allowed", transitions["newly_allowed"].as_u64()?),
                (
                    "newly_forwarded",
                    tally["forwarding"]["newly_forwarded"].as_u64()?,
                ),
            ] {
                if count > compared {
                    return None;
                }
                if count > 0 {
                    observations.push(json!({"projection": projection, "lane": lane, "code": code, "count": count}));
                }
            }
        }
        if projection_records != replayable {
            return None;
        }
    }
    Some(json!({
        "proof_basis": "bounded_replay",
        "result_digest": digest, "complete": complete,
        "window": { "from": window["from"], "to": window["to"] },
        "cutoff": { "high_water": high_water, "selected_records": selected },
        "max_records": max_records, "scanned": scanned, "replayable": replayable,
        "limitations": limitations, "not_replayed": job::NOT_REPLAYED,
        "coverage": coverage, "findings": observations,
    }))
}

pub(crate) fn from_evidence(view: &Value, complete: bool) -> Result<Value, AnalysisError> {
    project(view, complete).ok_or(AnalysisError::Internal("invalid_replay_evidence"))
}
