use time::OffsetDateTime;

use super::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS,
    kind::ScimConnectorProfileKind,
    types::{
        ScimConnectorProfileError, ScimConnectorSmokeTemplateCheck,
        ScimConnectorSmokeTemplateReport,
    },
    validation::normalized_https_origin,
};

pub fn scim_connector_smoke_template(
    profile: &str,
    issuer: &str,
) -> Result<ScimConnectorSmokeTemplateReport, ScimConnectorProfileError> {
    let kind = ScimConnectorProfileKind::parse(profile)?;
    if matches!(kind, ScimConnectorProfileKind::Generic) {
        return Err(ScimConnectorProfileError::UnsupportedSmokeTemplateProfile);
    }
    let issuer = normalized_https_origin(issuer)?;

    Ok(ScimConnectorSmokeTemplateReport {
        generated_at: OffsetDateTime::now_utc(),
        status: "template",
        source: "external-scim-connector",
        provider: kind.key(),
        display_name: kind.display_name(),
        scim_base_url: format!("{issuer}/scim/v2"),
        completed_at: "<RFC3339 completion timestamp after the connector smoke run>",
        connector_application_id: "<provider application id or slug>",
        provisioning_job_id: "<provider provisioning job/run id>",
        secondary_token_checked: false,
        rejected_token_checked: false,
        created_user_ids: vec!["<created user UUID 1>", "<created user UUID 2>"],
        deactivated_user_id: "<one created user UUID deactivated by the connector>",
        deleted_group_id: "<group UUID deleted by the connector>",
        checks: REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS
            .iter()
            .map(|name| ScimConnectorSmokeTemplateCheck {
                name,
                status: "pending",
                detail: "replace with token-free provider run evidence",
            })
            .collect(),
        operator_notes: vec![
            "Replace every placeholder before saving as release evidence.",
            "Set status to ok only after the external connector run proves every required check.",
            "Do not include raw bearer tokens, authorization headers, provider credentials, screenshots, passwords, or client secrets.",
            "The release validator rejects this template until timestamps, UUIDs, booleans, and checks are replaced with passing evidence.",
        ],
        forbidden_fields: vec![
            "authorization",
            "authorization_header",
            "bearer_token",
            "client_secret",
            "password",
            "provider_credentials",
            "raw_token",
            "secret_token",
        ],
    })
}
