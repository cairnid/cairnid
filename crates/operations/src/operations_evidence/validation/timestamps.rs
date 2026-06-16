use super::super::timestamp::parse_release_evidence_timestamp;
use super::path::value_at_path;
use serde_json::Value;
use time::OffsetDateTime;

pub(in crate::operations_evidence) fn require_rfc3339_timestamp(
    value: &Value,
    field: &'static str,
    evidence_kind: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let Some(timestamp) = value.get(field).and_then(Value::as_str) else {
        failures.push(format!(
            "{field} must be present for {evidence_kind} evidence"
        ));
        return;
    };
    if OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).is_err() {
        failures.push(format!("{field} must be an RFC3339 timestamp"));
    } else {
        checks.push(format!("{evidence_kind} completion timestamp is valid"));
    }
}

pub(in crate::operations_evidence) fn require_rfc3339_timestamp_at_path(
    value: &Value,
    path: &[&'static str],
    label: &'static str,
    failures: &mut Vec<String>,
) {
    let Some(timestamp) = value_at_path(value, path).and_then(Value::as_str) else {
        failures.push(format!("{label} must be an RFC3339 timestamp"));
        return;
    };
    if OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).is_err() {
        failures.push(format!("{label} must be an RFC3339 timestamp"));
    }
}

pub(in crate::operations_evidence) fn require_openid_export_timestamp_at_path(
    value: &Value,
    path: &[&'static str],
    label: &str,
    failures: &mut Vec<String>,
) -> bool {
    let Some(timestamp) = value_at_path(value, path).and_then(Value::as_str) else {
        failures.push(format!("{label} must be an OpenID suite export timestamp"));
        return false;
    };
    if parse_release_evidence_timestamp(timestamp).is_some() {
        true
    } else {
        failures.push(format!("{label} must be an OpenID suite export timestamp"));
        false
    }
}

pub(in crate::operations_evidence) fn validate_optional_filter_timestamp(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path) {
        Some(Value::Null) | None => {}
        Some(Value::String(timestamp)) => {
            if OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
                .is_err()
            {
                failures.push(format!(
                    "{} must be an RFC3339 timestamp or null",
                    path.join(".")
                ));
            }
        }
        Some(_) => failures.push(format!(
            "{} must be an RFC3339 timestamp or null",
            path.join(".")
        )),
    }
}
