use super::{
    provider::email_provider_name, report::lifecycle_email_smoke_evidence_report_from_messages,
};
use crate::config::EmailProviderConfig;
use crate::operations_evidence::REQUIRED_LIFECYCLE_EMAIL_KINDS;
use cairn_database::LifecycleEmailEvidenceMessage;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[test]
fn lifecycle_email_smoke_report_completes_when_command_provider_sent_all_kinds() {
    let organization_id = Uuid::new_v4();
    let completed_at = OffsetDateTime::UNIX_EPOCH + Duration::days(5);
    let report = lifecycle_email_smoke_evidence_report_from_messages(
        organization_id,
        completed_at,
        "command",
        required_kinds(),
        REQUIRED_LIFECYCLE_EMAIL_KINDS
            .iter()
            .map(|kind| test_message(kind, lifecycle_template(kind)))
            .collect(),
    );

    let value = serde_json::to_value(report).expect("lifecycle smoke report json");

    assert_eq!(value["status"], "completed");
    assert_eq!(value["provider"], "command");
    assert_eq!(value["organization_id"], organization_id.to_string());
    assert_eq!(value["completed_at"], "1970-01-06T00:00:00Z");
    assert!(
        value["missing_kinds"]
            .as_array()
            .expect("missing")
            .is_empty()
    );
    assert!(value["failures"].as_array().expect("failures").is_empty());
    let messages = value["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), REQUIRED_LIFECYCLE_EMAIL_KINDS.len());
    assert!(messages.iter().any(|message| {
        message["kind"] == "invitation" && message["template"] == "account_invitation"
    }));
}

#[test]
fn lifecycle_email_smoke_report_fails_for_wrong_provider_and_missing_kind() {
    let report = lifecycle_email_smoke_evidence_report_from_messages(
        Uuid::new_v4(),
        OffsetDateTime::UNIX_EPOCH,
        "stdout",
        vec!["invitation".to_owned(), "password_recovery".to_owned()],
        vec![test_message("invitation", "account_invitation")],
    );

    let value = serde_json::to_value(report).expect("lifecycle smoke report json");

    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["missing_kinds"][0], "password_recovery");
    assert!(
        value["failures"]
            .as_array()
            .expect("failures")
            .iter()
            .any(|failure| failure.as_str() == Some("provider must be command, got stdout"))
    );
    assert!(
        value["failures"]
            .as_array()
            .expect("failures")
            .iter()
            .any(|failure| failure
                .as_str()
                .is_some_and(|value| value.contains("password_recovery")))
    );
}

#[test]
fn lifecycle_email_smoke_report_fails_for_unknown_template_without_echoing_value() {
    let wrong_template = "unexpected_provider_template";
    let report = lifecycle_email_smoke_evidence_report_from_messages(
        Uuid::new_v4(),
        OffsetDateTime::UNIX_EPOCH,
        "command",
        vec!["invitation".to_owned()],
        vec![test_message("invitation", wrong_template)],
    );

    let value = serde_json::to_value(report).expect("lifecycle smoke report json");

    assert_eq!(value["status"], "incomplete");
    let failures = value["failures"].as_array().expect("failures");
    assert!(failures.iter().any(|failure| failure.as_str().is_some_and(
        |failure| failure
            == "messages[0].template must be one of account_invitation for lifecycle kind invitation"
    )));
    assert!(failures.iter().all(|failure| {
        failure
            .as_str()
            .is_some_and(|failure| !failure.contains(wrong_template))
    }));
    assert_eq!(value["messages"][0]["template"], "invalid_template");
}

#[test]
fn email_provider_name_matches_configured_provider() {
    assert_eq!(
        email_provider_name(&EmailProviderConfig::Disabled),
        "disabled"
    );
    assert_eq!(email_provider_name(&EmailProviderConfig::Stdout), "stdout");
    assert_eq!(
        email_provider_name(&EmailProviderConfig::Command {
            path: "/app/send-mail".to_owned()
        }),
        "command"
    );
}

fn required_kinds() -> Vec<String> {
    REQUIRED_LIFECYCLE_EMAIL_KINDS
        .iter()
        .map(|kind| (*kind).to_owned())
        .collect()
}

fn lifecycle_template(kind: &str) -> &str {
    match kind {
        "invitation" => "account_invitation",
        _ => kind,
    }
}

fn test_message(kind: &str, template: &str) -> LifecycleEmailEvidenceMessage {
    LifecycleEmailEvidenceMessage {
        kind: kind.to_owned(),
        template: template.to_owned(),
        action_url_present: true,
        provider_message_id: Some(format!("{kind}-provider-id")),
        sent_at: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
    }
}
