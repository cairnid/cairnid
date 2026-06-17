use serde_json::Value;

use super::super::path::value_at_path;

pub(in crate::operations_evidence) fn require_string(
    value: &Value,
    field: &'static str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    match value.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{field} must be {expected}, got {actual}")),
        None => failures.push(format!("{field} must be {expected}")),
    }
}

pub(in crate::operations_evidence) fn require_string_at_path(
    value: &Value,
    path: &[&'static str],
    expected: &str,
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!(
            "{} must be {expected}, got {actual}",
            path.join(".")
        )),
        None => failures.push(format!("{} must be {expected}", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn require_string_at_path_dynamic(
    value: &Value,
    prefix: &str,
    path: &[&'static str],
    expected: &str,
    failures: &mut Vec<String>,
) {
    let field = format!("{prefix}.{}", path.join("."));
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{field} must be {expected}, got {actual}")),
        None => failures.push(format!("{field} must be {expected}")),
    }
}

pub(in crate::operations_evidence) fn validate_user_status_field(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_str) {
        Some("active" | "suspended" | "locked") => {}
        Some(status) => failures.push(format!(
            "{} must be active, suspended, or locked, got {status}",
            path.join(".")
        )),
        None => failures.push(format!(
            "{} must be active, suspended, or locked",
            path.join(".")
        )),
    }
}

pub(in crate::operations_evidence) fn require_bool(
    value: &Value,
    path: &[&'static str],
    expected: bool,
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_bool) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!(
            "{} must be {expected}, got {actual}",
            path.join(".")
        )),
        None => failures.push(format!("{} must be {expected}", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn require_i64_at_least(
    value: &Value,
    path: &[&'static str],
    minimum: i64,
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_i64) {
        Some(actual) if actual >= minimum => {}
        Some(actual) => failures.push(format!(
            "{} must be at least {minimum}, got {actual}",
            path.join(".")
        )),
        None => failures.push(format!("{} must be at least {minimum}", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn require_i64_exact(
    value: &Value,
    path: &[&'static str],
    expected: i64,
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_i64) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!(
            "{} must be {expected}, got {actual}",
            path.join(".")
        )),
        None => failures.push(format!("{} must be {expected}", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn require_non_empty_string_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => {}
        Some(_) => failures.push(format!("{} must not be empty", path.join("."))),
        None => failures.push(format!("{} must be a non-empty string", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn require_non_empty_string_at_path_dynamic(
    value: &Value,
    prefix: &str,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => {}
        Some(_) => failures.push(format!("{prefix}.{} must not be empty", path.join("."))),
        None => failures.push(format!(
            "{prefix}.{} must be a non-empty string",
            path.join(".")
        )),
    }
}

pub(in crate::operations_evidence) fn require_bool_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) -> Option<bool> {
    match value_at_path(value, path).and_then(Value::as_bool) {
        Some(value) => Some(value),
        None => {
            failures.push(format!("{} must be a boolean", path.join(".")));
            None
        }
    }
}

pub(in crate::operations_evidence) fn require_u64_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) -> Option<u64> {
    match value_at_path(value, path).and_then(Value::as_u64) {
        Some(value) => Some(value),
        None => {
            failures.push(format!("{} must be a non-negative integer", path.join(".")));
            None
        }
    }
}
