use serde_json::{Map, Value};

pub(crate) fn resolve_claim<'a>(extra: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(value) = extra.get(path) {
        return Some(value);
    }

    if !path.contains('.') {
        return None;
    }

    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut value = extra.get(first)?;

    for segment in segments {
        let object = value.as_object()?;
        value = object.get(segment)?;
    }

    Some(value)
}

pub(crate) fn extract_roles(
    extra: &Map<String, Value>,
    claim_name: &str,
    delimiter: Option<&str>,
) -> Vec<String> {
    match resolve_claim(extra, claim_name) {
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) => delimiter
            .filter(|delimiter| !delimiter.is_empty())
            .map(|delimiter| {
                value
                    .split(delimiter)
                    .map(str::trim)
                    .filter(|role| !role.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub(crate) fn extract_string_claim(
    extra: &Map<String, Value>,
    claim_name: Option<&str>,
) -> Option<String> {
    resolve_claim(extra, claim_name?)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn resolve_claim_prefers_literal_key_before_dotted_path_segments() {
        let claims = json!({
            "https://myapp.example.com/roles": ["literal-admin"],
            "https://myapp": {
                "example": {
                    "com/roles": ["wrong-split-role"]
                }
            }
        });
        let extra = claims.as_object().expect("claims should be an object");

        let value = resolve_claim(extra, "https://myapp.example.com/roles")
            .expect("literal dotted claim should resolve");

        assert_eq!(value, &json!(["literal-admin"]));
    }

    #[test]
    fn extract_roles_reads_string_arrays() {
        let claims = json!({"roles": ["admin", "member"]});
        let extra = claims.as_object().expect("claims should be an object");

        assert_eq!(extract_roles(extra, "roles", None), vec!["admin", "member"]);
    }

    #[test]
    fn extract_roles_splits_delimited_strings() {
        let claims = json!({"scope": "read write  admin"});
        let extra = claims.as_object().expect("claims should be an object");

        assert_eq!(
            extract_roles(extra, "scope", Some(" ")),
            vec!["read", "write", "admin"]
        );
    }

    #[test]
    fn extract_roles_walks_nested_paths_after_literal_key_miss() {
        let claims = json!({"realm_access": {"roles": ["admin", "member"]}});
        let extra = claims.as_object().expect("claims should be an object");

        assert_eq!(
            extract_roles(extra, "realm_access.roles", None),
            vec!["admin", "member"]
        );
    }

    #[test]
    fn extract_string_claim_reads_nested_string_claims() {
        let claims = json!({"tenant": {"id": "acme-corp"}});
        let extra = claims.as_object().expect("claims should be an object");

        assert_eq!(
            extract_string_claim(extra, Some("tenant.id")),
            Some("acme-corp".to_owned())
        );
    }
}
