use crate::operations_evidence::validation::{
    reject_non_empty_array, require_rfc3339_timestamp, require_string,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_email_provider_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "sent", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "email provider smoke",
        checks,
        failures,
    );
    match value.get("provider").and_then(Value::as_str) {
        Some("command") => checks.push("email provider is command".to_owned()),
        Some(provider) => failures.push(format!("provider must be command, got {provider}")),
        None => failures.push("provider must be command".to_owned()),
    }
    match value.get("recipient_email").and_then(Value::as_str) {
        Some(recipient_email) if recipient_email.contains('@') => {}
        Some(_) => failures.push("recipient_email must contain @".to_owned()),
        None => failures.push("recipient_email must be present".to_owned()),
    }
    match value.get("provider_message_id") {
        Some(Value::String(provider_message_id)) if !provider_message_id.is_empty() => {}
        Some(Value::String(_)) => {
            failures.push("provider_message_id must not be empty when present".to_owned());
        }
        Some(Value::Null) | None => {}
        Some(_) => failures.push("provider_message_id must be a string when present".to_owned()),
    }
    if failures.is_empty() {
        checks.push("email provider smoke receipt is complete".to_owned());
    }
}
