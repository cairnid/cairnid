use super::{provider::email_provider_name, types::LifecycleEmailSmokeEvidenceReport};
use crate::{config::ApiConfig, operations_evidence::REQUIRED_LIFECYCLE_EMAIL_KINDS};
use cairn_database::{Database, LifecycleEmailEvidenceMessage};
use cairn_domain::OrganizationId;
use std::collections::BTreeSet;
use time::OffsetDateTime;

pub(super) async fn lifecycle_email_smoke_evidence_report(
    database: &Database,
    config: &ApiConfig,
    organization_id: OrganizationId,
    completed_at: OffsetDateTime,
) -> Result<LifecycleEmailSmokeEvidenceReport, Box<dyn std::error::Error>> {
    let required_kinds = REQUIRED_LIFECYCLE_EMAIL_KINDS
        .iter()
        .map(|kind| (*kind).to_owned())
        .collect::<Vec<_>>();
    let evidence_messages = database
        .list_lifecycle_email_evidence_messages(organization_id, &required_kinds)
        .await?;

    Ok(lifecycle_email_smoke_evidence_report_from_messages(
        organization_id,
        completed_at,
        email_provider_name(&config.email_delivery.provider),
        required_kinds,
        evidence_messages,
    ))
}

pub(super) fn lifecycle_email_smoke_evidence_report_from_messages(
    organization_id: OrganizationId,
    completed_at: OffsetDateTime,
    provider: &'static str,
    required_kinds: Vec<String>,
    evidence_messages: Vec<LifecycleEmailEvidenceMessage>,
) -> LifecycleEmailSmokeEvidenceReport {
    let seen_kinds = evidence_messages
        .iter()
        .map(|message| message.kind.clone())
        .collect::<BTreeSet<_>>();
    let missing_kinds = required_kinds
        .iter()
        .filter(|kind| !seen_kinds.contains(*kind))
        .cloned()
        .collect::<Vec<_>>();
    let mut failures = Vec::new();

    if provider != "command" {
        failures.push(format!("provider must be command, got {provider}"));
    }
    for missing_kind in &missing_kinds {
        failures.push(format!(
            "missing sent lifecycle email evidence for {missing_kind}"
        ));
    }

    LifecycleEmailSmokeEvidenceReport::new(
        organization_id,
        completed_at,
        provider,
        required_kinds,
        missing_kinds,
        evidence_messages,
        failures,
    )
}
