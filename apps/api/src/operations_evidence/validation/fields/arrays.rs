use serde_json::Value;

use super::super::path::value_at_path;

pub(in crate::operations_evidence) fn require_empty_array(
    value: &Value,
    field: &'static str,
    failures: &mut Vec<String>,
) {
    match value.get(field).and_then(Value::as_array) {
        Some(values) if values.is_empty() => {}
        Some(_) => failures.push(format!("{field} must be empty")),
        None => failures.push(format!("{field} must be an empty array")),
    }
}

pub(in crate::operations_evidence) fn require_string_array_contains_all(
    value: &Value,
    path: &[&'static str],
    required: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    let Some(values) = value_at_path(value, path).and_then(Value::as_array) else {
        failures.push(format!("{field} must be an array"));
        return;
    };
    for required_value in required {
        if !values
            .iter()
            .any(|value| value.as_str() == Some(*required_value))
        {
            failures.push(format!("{field} must include {required_value}"));
        }
    }
}

pub(in crate::operations_evidence) fn require_object_array_contains_strings(
    value: &Value,
    path: &[&'static str],
    field_name: &'static str,
    required: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    let Some(values) = value_at_path(value, path).and_then(Value::as_array) else {
        failures.push(format!("{field} must be an array"));
        return;
    };
    for required_value in required {
        if !values.iter().any(|value| {
            value
                .get(field_name)
                .and_then(Value::as_str)
                .is_some_and(|value| value == *required_value)
        }) {
            failures.push(format!(
                "{field} must include object with {field_name}={required_value}"
            ));
        }
    }
}

pub(in crate::operations_evidence) fn require_string_array_contains_substrings(
    value: &Value,
    path: &[&'static str],
    required: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    let Some(values) = value_at_path(value, path).and_then(Value::as_array) else {
        failures.push(format!("{field} must be an array"));
        return;
    };
    for required_value in required {
        if !values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value.contains(required_value))
        {
            failures.push(format!("{field} must include {required_value}"));
        }
    }
}

pub(in crate::operations_evidence) fn require_string_array_contains_all_from_value(
    value: &Value,
    prefix: &str,
    field: &'static str,
    required: &[&'static str],
    failures: &mut Vec<String>,
) {
    let Some(values) = value.get(field).and_then(Value::as_array) else {
        failures.push(format!("{prefix}.{field} must be an array"));
        return;
    };
    for required_value in required {
        if !values
            .iter()
            .any(|value| value.as_str() == Some(*required_value))
        {
            failures.push(format!("{prefix}.{field} must include {required_value}"));
        }
    }
}

pub(in crate::operations_evidence) fn require_non_empty_array_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    match value_at_path(value, path).and_then(Value::as_array) {
        Some(values) if !values.is_empty() => {}
        Some(_) => failures.push(format!("{field} must not be empty")),
        None => failures.push(format!("{field} must be a non-empty array")),
    }
}
