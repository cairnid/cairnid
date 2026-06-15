use cairn_database::LifecycleEmailEvidenceMessage;
use cairn_domain::OrganizationId;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub(super) struct LifecycleEmailSmokeEvidenceReport {
    status: &'static str,
    provider: &'static str,
    organization_id: OrganizationId,
    #[serde(with = "time::serde::rfc3339")]
    completed_at: OffsetDateTime,
    required_kinds: Vec<String>,
    missing_kinds: Vec<String>,
    messages: Vec<LifecycleEmailSmokeEvidenceMessageReport>,
    failures: Vec<String>,
}

impl LifecycleEmailSmokeEvidenceReport {
    pub(super) fn new(
        organization_id: OrganizationId,
        completed_at: OffsetDateTime,
        provider: &'static str,
        required_kinds: Vec<String>,
        missing_kinds: Vec<String>,
        evidence_messages: Vec<LifecycleEmailEvidenceMessage>,
        failures: Vec<String>,
    ) -> Self {
        let messages = evidence_messages
            .into_iter()
            .map(|message| LifecycleEmailSmokeEvidenceMessageReport {
                kind: message.kind,
                template: message.template,
                status: "sent",
                action_url_present: message.action_url_present,
                provider_message_id: message.provider_message_id,
                sent_at: message.sent_at,
            })
            .collect::<Vec<_>>();

        Self {
            status: if failures.is_empty() {
                "completed"
            } else {
                "incomplete"
            },
            provider,
            organization_id,
            completed_at,
            required_kinds,
            missing_kinds,
            messages,
            failures,
        }
    }

    pub(super) fn is_ready(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Debug, Serialize)]
struct LifecycleEmailSmokeEvidenceMessageReport {
    kind: String,
    template: String,
    status: &'static str,
    action_url_present: bool,
    provider_message_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    sent_at: OffsetDateTime,
}
