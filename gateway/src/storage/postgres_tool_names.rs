//! Durable tool-name reservations (issue #241, PR 8 review).
//!
//! Every replica's tool registry validates that the merged lanes -- the
//! local tools document, the managed OpenAPI catalogs, the managed MCP
//! catalogs -- carry no duplicate tool name. That check is process-local:
//! it runs against the registry the replica has, before a commit the
//! authority accepts on a different resource's compare-and-swap. Two
//! writers on two lanes can therefore both pass it against the old
//! registry and both commit, and the authority then holds a conflict no
//! replica can install, which the security gate fails closed on.
//!
//! This table makes the authority itself hold the invariant. A lane's
//! commit replaces its own reservations inside its transaction and the
//! primary key refuses a name another lane holds; two lanes racing to
//! publish one name produce exactly one winner, and the loser learns who
//! holds it.

use std::collections::BTreeSet;

use tokio_postgres::error::SqlState;

pub(crate) const LANE_LOCAL: &str = "local";
pub(crate) const LANE_OPENAPI: &str = "openapi";
pub(crate) const LANE_MCP: &str = "mcp";
/// The local lane has one document, so one owner.
pub(crate) const LOCAL_OWNER: &str = "tools";

#[derive(Debug)]
pub(crate) enum ToolNameReservationError {
    /// Another publisher holds the name. `lane`/`owner_id` are empty when
    /// the holder committed between the look-up and the insert: the
    /// transaction is then already aborted and cannot name it.
    Taken {
        tool_name: String,
        lane: String,
        owner_id: String,
    },
    Postgres(tokio_postgres::Error),
}

/// Replace `owner_id`'s reservations in `lane` with `names`, inside the
/// caller's transaction. The caller's rollback discards the change.
pub(crate) async fn reserve_tool_names(
    client: &tokio_postgres::Client,
    lane: &str,
    owner_id: &str,
    names: impl IntoIterator<Item = String>,
) -> Result<(), ToolNameReservationError> {
    let names: Vec<String> = names
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    client
        .execute(
            "DELETE FROM greengateway.tool_name_reservations WHERE lane = $1 AND owner_id = $2",
            &[&lane, &owner_id],
        )
        .await
        .map_err(ToolNameReservationError::Postgres)?;
    if names.is_empty() {
        return Ok(());
    }
    // Name the holder when one is already committed; the primary key is
    // the guard against the one that is not yet.
    if let Some(row) = client
        .query_opt(
            r#"
            SELECT tool_name, lane, owner_id FROM greengateway.tool_name_reservations
            WHERE tool_name = ANY($1) ORDER BY tool_name LIMIT 1
            "#,
            &[&names],
        )
        .await
        .map_err(ToolNameReservationError::Postgres)?
    {
        return Err(ToolNameReservationError::Taken {
            tool_name: row.get(0),
            lane: row.get(1),
            owner_id: row.get(2),
        });
    }
    match client
        .execute(
            r#"
            INSERT INTO greengateway.tool_name_reservations (tool_name, lane, owner_id)
            SELECT unnest($1::text[]), $2, $3
            "#,
            &[&names, &lane, &owner_id],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_db_error()
                .is_some_and(|db| *db.code() == SqlState::UNIQUE_VIOLATION) =>
        {
            Err(ToolNameReservationError::Taken {
                tool_name: error
                    .as_db_error()
                    .and_then(|db| db.detail())
                    .and_then(taken_name_from_detail)
                    .unwrap_or_default(),
                lane: String::new(),
                owner_id: String::new(),
            })
        }
        Err(error) => Err(ToolNameReservationError::Postgres(error)),
    }
}

/// Drop every reservation `owner_id` holds, inside the caller's
/// transaction (a deleted Connection).
pub(crate) async fn release_tool_names(
    client: &tokio_postgres::Client,
    owner_id: &str,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "DELETE FROM greengateway.tool_name_reservations WHERE owner_id = $1",
            &[&owner_id],
        )
        .await
}

/// `Key (tool_name)=(name) already exists.` -> `name`.
fn taken_name_from_detail(detail: &str) -> Option<String> {
    let start = detail.find(")=(")? + 3;
    let end = detail[start..].find(')')? + start;
    Some(detail[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::taken_name_from_detail;

    #[test]
    fn the_taken_name_is_read_from_the_unique_violation_detail() {
        assert_eq!(
            taken_name_from_detail("Key (tool_name)=(billing.list) already exists.").as_deref(),
            Some("billing.list")
        );
        assert_eq!(taken_name_from_detail("no key here"), None);
    }
}
