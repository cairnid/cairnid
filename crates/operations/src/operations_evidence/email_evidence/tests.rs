use super::{
    constants::REQUIRED_LIFECYCLE_EMAIL_KINDS,
    lifecycle::{lifecycle_email_kind_requires_action_url, validate_lifecycle_email_smoke},
    provider::validate_email_provider_smoke,
};
use serde_json::{Value, json};

#[test]
fn email_provider_smoke_accepts_command_provider_receipt() {
    let value = json!({
        "status": "sent",
        "provider": "command",
        "recipient_email": "ops@example.com",
        "provider_message_id": "message-123",
        "completed_at": "2026-06-07T12:00:00Z",
        "failures": [],
        "errors": []
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_email_provider_smoke(&value, &mut checks, &mut failures);

    assert!(failures.is_empty(), "{failures:?}");
    assert!(checks.contains(&"email provider is command".to_owned()));
    assert!(checks.contains(&"email provider smoke receipt is complete".to_owned()));
}

#[test]
fn email_provider_smoke_rejects_wrong_provider_and_bad_recipient() {
    let value = json!({
        "status": "queued",
        "provider": "stdout",
        "recipient_email": "not-an-email",
        "provider_message_id": "",
        "completed_at": "not-a-timestamp"
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_email_provider_smoke(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| failure == "status must be sent, got queued")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "provider must be command, got stdout")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "recipient_email must contain @")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "provider_message_id must not be empty when present")
    );
}

#[test]
fn lifecycle_email_smoke_accepts_all_required_kinds() {
    let value = json!({
        "status": "completed",
        "provider": "command",
        "completed_at": "2026-06-07T12:00:00Z",
        "failures": [],
        "errors": [],
        "messages": REQUIRED_LIFECYCLE_EMAIL_KINDS
            .iter()
            .map(|kind| lifecycle_message(kind, lifecycle_email_kind_requires_action_url(kind)))
            .collect::<Vec<_>>()
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_lifecycle_email_smoke(&value, &mut checks, &mut failures);

    assert!(failures.is_empty(), "{failures:?}");
    assert!(checks.contains(&"lifecycle email smoke used command provider".to_owned()));
    assert!(
        checks
            .contains(&"all required lifecycle email templates were provider accepted".to_owned())
    );
}

#[test]
fn lifecycle_email_smoke_rejects_wrong_template_without_echoing_value() {
    let wrong_template = "unexpected_provider_template";
    let value = json!({
        "status": "completed",
        "provider": "command",
        "completed_at": "2026-06-07T12:00:00Z",
        "failures": [],
        "errors": [],
        "messages": [
            {
                "kind": "invitation",
                "template": wrong_template,
                "status": "sent",
                "action_url_present": true,
                "provider_message_id": "provider-invitation"
            }
        ]
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_lifecycle_email_smoke(&value, &mut checks, &mut failures);

    assert!(failures.iter().any(|failure| {
        failure == "messages[0].template must be one of account_invitation for lifecycle kind invitation"
    }));
    assert!(
        failures
            .iter()
            .all(|failure| !failure.contains(wrong_template))
    );
}

#[test]
fn lifecycle_email_smoke_rejects_missing_kind_and_action_url_mismatch() {
    let value = json!({
        "status": "completed",
        "provider": "command",
        "completed_at": "2026-06-07T12:00:00Z",
        "messages": [
            lifecycle_message("invitation", false),
            lifecycle_message("email_verification", true),
            lifecycle_message("password_recovery", true),
            lifecycle_message("password_recovered_notification", false),
            lifecycle_message("password_changed_notification", false),
            {
                "kind": "unknown",
                "template": "unknown",
                "status": "sent",
                "action_url_present": false
            }
        ]
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_lifecycle_email_smoke(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| failure == "messages[0].action_url_present must be true, got false")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("messages[5].kind must be one of"))
    );
    assert!(failures.iter().any(|failure| {
        failure == "messages must include lifecycle email kind new_login_notification"
    }));
}

fn lifecycle_message(kind: &str, action_url_present: bool) -> Value {
    json!({
        "kind": kind,
        "template": lifecycle_template(kind),
        "status": "sent",
        "action_url_present": action_url_present,
        "provider_message_id": format!("{kind}-message")
    })
}

fn lifecycle_template(kind: &str) -> &str {
    match kind {
        "invitation" => "account_invitation",
        _ => kind,
    }
}
