use super::constants::REQUIRED_LIFECYCLE_EMAIL_KINDS;
use crate::operations_evidence::validation::{
    reject_non_empty_array, require_rfc3339_timestamp, require_string,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(in crate::operations_evidence) fn validate_lifecycle_email_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "completed", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "lifecycle email smoke",
        checks,
        failures,
    );
    match value.get("provider").and_then(Value::as_str) {
        Some("command") => checks.push("lifecycle email smoke used command provider".to_owned()),
        Some(provider) => failures.push(format!("provider must be command, got {provider}")),
        None => failures.push("provider must be command".to_owned()),
    }

    let Some(messages) = value.get("messages").and_then(Value::as_array) else {
        failures.push("messages must be a non-empty array".to_owned());
        return;
    };
    if messages.is_empty() {
        failures.push("messages must be a non-empty array".to_owned());
        return;
    }

    let mut seen = BTreeSet::new();
    for (index, message) in messages.iter().enumerate() {
        let Some(kind) = message.get("kind").and_then(Value::as_str) else {
            failures.push(format!("messages[{index}].kind must be present"));
            continue;
        };
        if REQUIRED_LIFECYCLE_EMAIL_KINDS.contains(&kind) {
            seen.insert(kind);
        } else {
            failures.push(format!(
                "messages[{index}].kind must be one of {}, got {kind}",
                REQUIRED_LIFECYCLE_EMAIL_KINDS.join(", ")
            ));
            continue;
        }

        validate_lifecycle_message(index, message, kind, failures);
    }

    for &required_kind in REQUIRED_LIFECYCLE_EMAIL_KINDS {
        if !seen.contains(required_kind) {
            failures.push(format!(
                "messages must include lifecycle email kind {required_kind}"
            ));
        }
    }
    if REQUIRED_LIFECYCLE_EMAIL_KINDS
        .iter()
        .all(|&required_kind| seen.contains(required_kind))
    {
        checks.push("all required lifecycle email templates were provider accepted".to_owned());
    }
}

fn validate_lifecycle_message(
    index: usize,
    message: &Value,
    kind: &str,
    failures: &mut Vec<String>,
) {
    match message.get("template").and_then(Value::as_str) {
        Some(template) if template == kind => {}
        Some(template) => failures.push(format!(
            "messages[{index}].template must match kind {kind}, got {template}"
        )),
        None => failures.push(format!("messages[{index}].template must match kind {kind}")),
    }
    match message.get("status").and_then(Value::as_str) {
        Some("sent") => {}
        Some(status) => failures.push(format!(
            "messages[{index}].status must be sent, got {status}"
        )),
        None => failures.push(format!("messages[{index}].status must be sent")),
    }

    let expected_action_url = lifecycle_email_kind_requires_action_url(kind);
    match message.get("action_url_present").and_then(Value::as_bool) {
        Some(actual) if actual == expected_action_url => {}
        Some(actual) => failures.push(format!(
            "messages[{index}].action_url_present must be {expected_action_url}, got {actual}"
        )),
        None => failures.push(format!(
            "messages[{index}].action_url_present must be {expected_action_url}"
        )),
    }

    match message.get("provider_message_id") {
        Some(Value::String(provider_message_id)) if !provider_message_id.is_empty() => {}
        Some(Value::String(_)) => failures.push(format!(
            "messages[{index}].provider_message_id must not be empty when present"
        )),
        Some(Value::Null) | None => {}
        Some(_) => failures.push(format!(
            "messages[{index}].provider_message_id must be a string when present"
        )),
    }
}

pub(super) fn lifecycle_email_kind_requires_action_url(kind: &str) -> bool {
    matches!(
        kind,
        "invitation" | "email_verification" | "password_recovery"
    )
}
