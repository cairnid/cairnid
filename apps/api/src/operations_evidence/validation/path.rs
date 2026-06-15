use serde_json::Value;

pub(in crate::operations_evidence) fn value_at_path<'a>(
    value: &'a Value,
    path: &[&str],
) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

pub(in crate::operations_evidence) fn non_empty_string_at_path(
    value: &Value,
    path: &[&str],
) -> bool {
    value_at_path(value, path)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{non_empty_string_at_path, value_at_path};
    use serde_json::json;

    #[test]
    fn value_path_helpers_resolve_nested_non_empty_strings() {
        let value = json!({
            "outer": {
                "inner": "value",
                "empty": ""
            }
        });

        assert_eq!(
            value_at_path(&value, &["outer", "inner"]).and_then(|value| value.as_str()),
            Some("value")
        );
        assert!(non_empty_string_at_path(&value, &["outer", "inner"]));
        assert!(!non_empty_string_at_path(&value, &["outer", "empty"]));
        assert!(!non_empty_string_at_path(&value, &["outer", "missing"]));
    }
}
