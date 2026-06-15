use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum ScimConnectorProfileError {
    #[error("unknown SCIM connector profile '{0}'; expected generic, okta, or entra")]
    UnknownProfile(String),
    #[error("SCIM connector smoke templates are only supported for okta or entra")]
    UnsupportedSmokeTemplateProfile,
    #[error("invalid CAIRN_ISSUER: {0}")]
    InvalidIssuer(String),
    #[error(
        "SCIM connector profiles require CAIRN_ISSUER to be an externally reachable HTTPS origin"
    )]
    NonHttpsIssuer,
    #[error(
        "SCIM connector profiles require CAIRN_ISSUER to be an HTTPS origin without credentials, path, query, or fragment"
    )]
    NonOriginIssuer,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScimConnectorProfileReport {
    #[serde(with = "time::serde::rfc3339")]
    pub(super) generated_at: OffsetDateTime,
    pub(super) status: &'static str,
    pub(super) profile: &'static str,
    pub(super) display_name: &'static str,
    pub(super) issuer: String,
    pub(super) scim_base_url: String,
    pub(super) service_provider_config_url: String,
    pub(super) authentication: ScimConnectorAuthentication,
    pub(super) connector_settings: Vec<ScimConnectorSetting>,
    pub(super) recommended_mappings: Vec<ScimConnectorMapping>,
    pub(super) supported_operations: Vec<&'static str>,
    pub(super) validation_checks: Vec<String>,
    pub(super) unsupported_v1_features: Vec<&'static str>,
    pub(super) smoke_commands: Vec<String>,
    pub(super) operator_notes: Vec<&'static str>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScimConnectorSmokeTemplateReport {
    #[serde(with = "time::serde::rfc3339")]
    pub(super) generated_at: OffsetDateTime,
    pub(super) status: &'static str,
    pub(super) source: &'static str,
    pub(super) provider: &'static str,
    pub(super) display_name: &'static str,
    pub(super) scim_base_url: String,
    pub(super) completed_at: &'static str,
    pub(super) connector_application_id: &'static str,
    pub(super) provisioning_job_id: &'static str,
    pub(super) secondary_token_checked: bool,
    pub(super) rejected_token_checked: bool,
    pub(super) created_user_ids: Vec<&'static str>,
    pub(super) deactivated_user_id: &'static str,
    pub(super) deleted_group_id: &'static str,
    pub(super) checks: Vec<ScimConnectorSmokeTemplateCheck>,
    pub(super) operator_notes: Vec<&'static str>,
    pub(super) forbidden_fields: Vec<&'static str>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ScimConnectorSmokeTemplateCheck {
    pub(super) name: &'static str,
    pub(super) status: &'static str,
    pub(super) detail: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ScimConnectorAuthentication {
    pub(super) scheme: &'static str,
    pub(super) connector_header: &'static str,
    pub(super) server_env: &'static str,
    pub(super) rotation_env: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ScimConnectorSetting {
    pub(super) name: &'static str,
    pub(super) value: String,
    pub(super) note: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ScimConnectorMapping {
    pub(super) resource: &'static str,
    pub(super) connector_attribute: &'static str,
    pub(super) scim_attribute: &'static str,
    pub(super) note: &'static str,
}
