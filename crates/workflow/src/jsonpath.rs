//! Minimal JSONPath resolver for the subset used by the workflow contract:
//! `$.a.b[0].c`, `$` (whole document), and bare `a.b[0]`. Bracket indices
//! apply to arrays; keys apply to objects.

use serde_json::Value;

/// Resolves a JSONPath within `value`. Returns `None` when any segment is
/// missing or the path is malformed.
pub fn resolve<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("$") {
        trimmed = rest.trim_start_matches('.').trim();
    }
    if trimmed.is_empty() {
        return Some(value);
    }
    // Split on '.' at top level (bracket segments never contain dots).
    let mut current = value;
    for token in trimmed.split('.') {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        current = apply_token(current, token)?;
    }
    Some(current)
}

/// Applies a single dotted segment that may carry array indices, e.g. `b[0][2]`.
fn apply_token<'a>(value: &'a Value, token: &str) -> Option<&'a Value> {
    let (name, indices) = split_indices(token)?;
    let mut current = value;
    if !name.is_empty() {
        current = current.get(name)?;
    }
    for index in indices {
        current = current.get(index)?;
    }
    Some(current)
}

/// Splits `name[0][1]` into (`name`, [0, 1]). Returns `None` when a bracket
/// segment is not a valid non-negative index.
fn split_indices(token: &str) -> Option<(&str, Vec<usize>)> {
    match token.find('[') {
        Some(pos) => {
            let name = &token[..pos];
            let mut indices = Vec::new();
            let mut rest = &token[pos..];
            while let Some(open) = rest.find('[') {
                let remainder = &rest[open + 1..];
                let close = remainder.find(']')?;
                let index = remainder[..close].trim().parse::<usize>().ok()?;
                indices.push(index);
                rest = &remainder[close + 1..];
            }
            Some((name, indices))
        }
        None => Some((token, Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve;
    use serde_json::{Value, json};

    #[test]
    fn whole_document() {
        let value = json!({"a": 1});
        assert_eq!(resolve(&value, "$"), Some(&value));
        assert_eq!(resolve(&value, ""), Some(&value));
    }

    #[test]
    fn nested_keys_and_array_indices() {
        let value: Value =
            serde_json::from_str(r#"{"access_token":"tok","data":{"items":[{"id":1},{"id":2}]}}"#)
                .unwrap();
        assert_eq!(resolve(&value, "$.access_token"), Some(&json!("tok")));
        assert_eq!(resolve(&value, "$.data.items[0].id"), Some(&json!(1)));
        assert_eq!(resolve(&value, "data.items[1].id"), Some(&json!(2)));
        assert_eq!(resolve(&value, "$.data.items[5].id"), None);
        assert_eq!(resolve(&value, "$.missing"), None);
    }

    #[test]
    fn bare_path_without_dollar() {
        let value = json!({"a": {"b": [10, 20]}});
        assert_eq!(resolve(&value, "a.b[1]"), Some(&json!(20)));
    }

    #[test]
    fn malformed_path_returns_none() {
        let value = json!({"a": 1});
        assert_eq!(resolve(&value, "$.a..b"), None);
        assert_eq!(resolve(&value, "a[b]"), None);
    }
}
