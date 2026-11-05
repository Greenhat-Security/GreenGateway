use serde_json::{Map, Value};

use super::principal::{
    VerifiedClaim, MAX_PRINCIPAL_SCOPES, MAX_PRINCIPAL_SCOPE_BYTES, MAX_VERIFIED_CLAIMS,
    MAX_VERIFIED_CLAIM_NAME_BYTES, MAX_VERIFIED_CLAIM_VALUES, MAX_VERIFIED_CLAIM_VALUE_BYTES,
};

/// Claim names no `verified_claims` allowlist may list, compared exactly.
/// Each is already read some other way, or bounds the token rather than
/// describing the caller: the issuer, subject and audience are the
/// principal's identity and its binding; the validity instants and the token,
/// session and nonce identifiers and hashes are credential metadata; `cnf`
/// binds a proof-of-possession key; `scope` and `scp` are the scope fact; and
/// `email` is display metadata, never a policy input.
const RESERVED_CLAIM_NAMES: &[&str] = &[
    "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "sid", "nonce", "at_hash", "c_hash", "s_hash",
    "cnf", "scope", "scp", "email",
];

/// Fragments, compared ASCII case-insensitively, that mark a claim name as
/// one that can carry a credential.
const CREDENTIAL_CLAIM_FRAGMENTS: &[&str] = &["token", "secret", "passw", "credential"];

/// Why `name` cannot be a verified claim -- an allowlist entry, or the claim
/// a `claim` condition reads -- or `None` when it can be.
pub(crate) fn verified_claim_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() || name.len() > MAX_VERIFIED_CLAIM_NAME_BYTES {
        return Some("must be 1 to 256 bytes");
    }
    if name.chars().any(char::is_control) || name.trim() != name {
        return Some("must not contain control characters or leading or trailing whitespace");
    }
    let lowercase = name.to_ascii_lowercase();
    if RESERVED_CLAIM_NAMES.contains(&name)
        || CREDENTIAL_CLAIM_FRAGMENTS
            .iter()
            .any(|fragment| lowercase.contains(fragment))
    {
        return Some(
            "names a claim that carries the principal's identity, scopes, email or credential \
             metadata, which policy reads some other way or never",
        );
    }
    None
}

/// An RFC 6749 `scope-token` of at most [`MAX_PRINCIPAL_SCOPE_BYTES`]:
/// printable ASCII without space, `"` or `\`.
pub(crate) fn is_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PRINCIPAL_SCOPE_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

/// The OAuth scopes a token's top-level `scope` and `scp` claims grant,
/// sorted and de-duplicated: the union of both, each either a
/// space-delimited string (RFC 8693, RFC 9068) or an array of scope tokens.
///
/// `None` -- no scope fact -- when either claim has another type, holds
/// something that is not a scope token, or the union exceeds
/// [`MAX_PRINCIPAL_SCOPES`]. Nothing is truncated or skipped: a scope the
/// gateway dropped could turn a `not` into a match.
pub(crate) fn extract_scopes(extra: &Map<String, Value>) -> Option<Vec<String>> {
    let mut scopes = Vec::new();
    for claim in ["scope", "scp"] {
        match extra.get(claim) {
            None => {}
            Some(Value::String(value)) => {
                for scope in value.split(' ').filter(|scope| !scope.is_empty()) {
                    if !is_scope_token(scope) {
                        return None;
                    }
                    scopes.push(scope.to_owned());
                }
            }
            Some(Value::Array(items)) => {
                for item in items {
                    let scope = item.as_str().filter(|scope| is_scope_token(scope))?;
                    scopes.push(scope.to_owned());
                }
            }
            Some(_) => return None,
        }
    }
    scopes.sort_unstable();
    scopes.dedup();
    (scopes.len() <= MAX_PRINCIPAL_SCOPES).then_some(scopes)
}

/// The claims `allowlist` names, read from a verified token's claims with the
/// exact-key-first, dotted-path-second resolution every claim mapping uses.
///
/// A claim the token does not carry is verified absent: an entry with no
/// values. One whose value is not a string, boolean or number, or a list of
/// at most [`MAX_VERIFIED_CLAIM_VALUES`] strings, or that holds a string past
/// [`MAX_VERIFIED_CLAIM_VALUE_BYTES`] or with a control character, gets no
/// entry at all, so a matcher that reads it is undetermined rather than
/// misread. `allowlist` is already validated, sorted and unique.
pub(crate) fn extract_verified_claims(
    extra: &Map<String, Value>,
    allowlist: &[String],
) -> Vec<VerifiedClaim> {
    allowlist
        .iter()
        .take(MAX_VERIFIED_CLAIMS)
        .filter_map(|name| {
            let values = match resolve_claim(extra, name) {
                None => Vec::new(),
                Some(value) => verified_claim_values(value)?,
            };
            Some(VerifiedClaim {
                name: name.clone(),
                values,
            })
        })
        .collect()
}

fn verified_claim_values(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::String(text) => is_verified_claim_text(text).then(|| vec![value.clone()]),
        Value::Bool(_) | Value::Number(_) => Some(vec![value.clone()]),
        Value::Array(items) => (items.len() <= MAX_VERIFIED_CLAIM_VALUES
            && items
                .iter()
                .all(|item| item.as_str().is_some_and(is_verified_claim_text)))
        .then(|| items.clone()),
        Value::Null | Value::Object(_) => None,
    }
}

/// A verified claim string: at most [`MAX_VERIFIED_CLAIM_VALUE_BYTES`], with
/// no control character.
pub(crate) fn is_verified_claim_text(text: &str) -> bool {
    text.len() <= MAX_VERIFIED_CLAIM_VALUE_BYTES && !text.chars().any(char::is_control)
}

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

    fn object(value: serde_json::Value) -> Map<String, Value> {
        value
            .as_object()
            .cloned()
            .expect("claims should be an object")
    }

    #[test]
    fn scopes_are_the_sorted_union_of_scope_and_scp_in_either_shape() {
        for (claims, expected) in [
            (json!({}), Some(vec![])),
            (json!({"scope": ""}), Some(vec![])),
            (
                json!({"scope": "  write read  read "}),
                Some(vec!["read", "write"]),
            ),
            (
                json!({"scp": ["orders.read", "orders.write"]}),
                Some(vec!["orders.read", "orders.write"]),
            ),
            (
                json!({"scp": "user_impersonation"}),
                Some(vec!["user_impersonation"]),
            ),
            (
                json!({"scope": "read", "scp": ["read", "admin"]}),
                Some(vec!["admin", "read"]),
            ),
        ] {
            assert_eq!(
                extract_scopes(&object(claims.clone())),
                expected.map(|scopes| scopes.into_iter().map(str::to_owned).collect()),
                "{claims}"
            );
        }
    }

    /// A scope claim the gateway cannot read whole is no scope fact at all,
    /// never a shorter list: dropping one scope could turn a `not` into a
    /// match.
    #[test]
    fn a_malformed_or_oversized_scope_claim_is_no_scope_fact() {
        let at_bound = (0..MAX_PRINCIPAL_SCOPES)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            extract_scopes(&object(json!({"scp": at_bound}))).map(|scopes| scopes.len()),
            Some(MAX_PRINCIPAL_SCOPES)
        );
        let past_bound = (0..=MAX_PRINCIPAL_SCOPES)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        for claims in [
            json!({"scope": past_bound}),
            json!({"scope": "s".repeat(MAX_PRINCIPAL_SCOPE_BYTES + 1)}),
            json!({"scope": "read\twrite"}),
            json!({"scope": "read \"admin\""}),
            json!({"scope": 7}),
            json!({"scope": null}),
            json!({"scp": ["read", 1]}),
            json!({"scp": ["read write"]}),
            json!({"scp": [""]}),
            json!({"scope": "read", "scp": {"admin": true}}),
        ] {
            assert_eq!(extract_scopes(&object(claims.clone())), None, "{claims}");
        }
        assert!(is_scope_token(&"s".repeat(MAX_PRINCIPAL_SCOPE_BYTES)));
    }

    #[test]
    fn only_allowlisted_claims_are_captured_and_absence_is_its_own_answer() {
        let claims = object(json!({
            "department": "engineering",
            "groups": ["eng", "oncall"],
            "email_verified": true,
            "level": 3,
            "tenant": {"tier": "gold"},
            "unlisted": "secret-plan",
        }));
        let allowlist = [
            "department",
            "email_verified",
            "groups",
            "level",
            "missing",
            "tenant.tier",
        ]
        .map(str::to_owned);

        let captured = extract_verified_claims(&claims, &allowlist);

        assert_eq!(
            captured,
            vec![
                VerifiedClaim {
                    name: "department".to_owned(),
                    values: vec![json!("engineering")]
                },
                VerifiedClaim {
                    name: "email_verified".to_owned(),
                    values: vec![json!(true)]
                },
                VerifiedClaim {
                    name: "groups".to_owned(),
                    values: vec![json!("eng"), json!("oncall")]
                },
                VerifiedClaim {
                    name: "level".to_owned(),
                    values: vec![json!(3)]
                },
                VerifiedClaim {
                    name: "missing".to_owned(),
                    values: Vec::new()
                },
                VerifiedClaim {
                    name: "tenant.tier".to_owned(),
                    values: vec![json!("gold")]
                },
            ]
        );
        assert!(captured.iter().all(|claim| claim.name != "unlisted"));
    }

    /// A claim whose value is not a bounded scalar or short string list gets
    /// no entry, so a matcher reading it is undetermined, never false.
    #[test]
    fn an_unreadable_allowlisted_claim_is_left_uncaptured() {
        let list_at_bound = vec![json!("v"); MAX_VERIFIED_CLAIM_VALUES];
        let list_past_bound = vec![json!("v"); MAX_VERIFIED_CLAIM_VALUES + 1];
        let claims = object(json!({
            "at_bound": list_at_bound,
            "long": "x".repeat(MAX_VERIFIED_CLAIM_VALUE_BYTES + 1),
            "control": "line\nbreak",
            "too_many": list_past_bound,
            "mixed": ["a", 1],
            "nested": [["a"]],
            "object": {"a": "b"},
            "null": null,
        }));
        let allowlist = [
            "at_bound", "control", "long", "mixed", "nested", "null", "object", "too_many",
        ]
        .map(str::to_owned);

        let captured = extract_verified_claims(&claims, &allowlist);

        assert_eq!(
            captured
                .iter()
                .map(|claim| claim.name.as_str())
                .collect::<Vec<_>>(),
            vec!["at_bound"]
        );
        assert!(is_verified_claim_text(
            &"x".repeat(MAX_VERIFIED_CLAIM_VALUE_BYTES)
        ));
    }

    #[test]
    fn identity_scope_email_and_credential_claims_cannot_be_allowlisted() {
        for name in [
            "iss",
            "sub",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sid",
            "nonce",
            "at_hash",
            "c_hash",
            "s_hash",
            "cnf",
            "scope",
            "scp",
            "email",
            "refresh_token",
            "client_secret",
            "Password",
            "x_credentials",
            "",
            " department",
            "dept\u{7}",
        ] {
            assert!(verified_claim_name_problem(name).is_some(), "{name:?}");
        }
        assert!(
            verified_claim_name_problem(&"d".repeat(MAX_VERIFIED_CLAIM_NAME_BYTES + 1)).is_some()
        );
        for name in [
            "department",
            "groups",
            "acr",
            "amr",
            "realm_access.roles",
            "https://example.com/tier",
            "Email_Verified",
        ] {
            assert_eq!(verified_claim_name_problem(name), None, "{name}");
        }
    }
}
