use serde_json::Value;

use super::super::path::value_at_path;

pub(in crate::operations_evidence) fn validate_optional_membership_role(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path) {
        Some(Value::Null) | None => {}
        Some(Value::String(role)) if matches!(role.as_str(), "member" | "owner") => {}
        Some(Value::String(role)) => failures.push(format!(
            "{} must be member, owner, or null, got {role}",
            path.join(".")
        )),
        Some(_) => failures.push(format!("{} must be member, owner, or null", path.join("."))),
    }
}

pub(in crate::operations_evidence) fn validate_optional_filter_string(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path) {
        Some(Value::Null) | None => {}
        Some(Value::String(_)) => {}
        Some(_) => failures.push(format!("{} must be a string or null", path.join("."))),
    }
}
