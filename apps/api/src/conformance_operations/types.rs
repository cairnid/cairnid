use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct OpenIdConformanceOperationsPreflightReport {
    pub issuer: String,
    pub issuer_https_origin_ready: bool,
    pub static_client_environment_ready: bool,
    pub missing_environment: Vec<&'static str>,
    pub certification_profiles: Vec<&'static str>,
    pub static_registration_command: &'static str,
    pub static_config_command: &'static str,
    pub external_suite_required: bool,
}

pub(super) struct OpenIdConformanceInputs<'a> {
    pub(super) issuer: &'a str,
    pub(super) alias: &'a str,
    pub(super) description: String,
    pub(super) client_id: &'a str,
    pub(super) client_secret: &'a str,
    pub(super) client2_id: &'a str,
    pub(super) client2_secret: &'a str,
}

pub(super) struct OpenIdConformanceRegistrationInputs<'a> {
    pub(super) issuer: &'a str,
    pub(super) alias: &'a str,
    pub(super) suite_base_url: &'a str,
    pub(super) client_id: &'a str,
    pub(super) client2_id: &'a str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceSuiteConfig {
    #[serde(with = "time::serde::rfc3339")]
    pub(super) generated_at: OffsetDateTime,
    pub(super) alias: String,
    pub(super) description: String,
    pub(super) server: OpenIdConformanceServerConfig,
    pub(super) client: OpenIdConformanceClientConfig,
    pub(super) client2: OpenIdConformanceClientConfig,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceServerConfig {
    #[serde(rename = "discoveryUrl")]
    pub(super) discovery_url: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceClientConfig {
    pub(super) client_id: String,
    pub(super) client_secret: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceRegistrationReport {
    #[serde(with = "time::serde::rfc3339")]
    pub(super) generated_at: OffsetDateTime,
    pub(super) status: &'static str,
    pub(super) issuer: String,
    pub(super) suite_alias: String,
    pub(super) certification_profiles: Vec<String>,
    pub(super) run_plan_commands: Vec<String>,
    pub(super) static_clients: Vec<OpenIdConformanceClientRegistration>,
    pub(super) unsupported_v1_profiles: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceClientRegistration {
    pub(super) role: &'static str,
    pub(super) client_id: String,
    pub(super) redirect_uris: Vec<String>,
    pub(super) post_logout_redirect_uris: Vec<String>,
    pub(super) response_types: Vec<String>,
    pub(super) grant_types: Vec<String>,
    pub(super) token_endpoint_auth_methods: Vec<String>,
    pub(super) allowed_scopes: Vec<String>,
    pub(super) pkce_methods: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct OpenIdConformanceResultTemplateReport {
    #[serde(with = "time::serde::rfc3339")]
    pub(super) generated_at: OffsetDateTime,
    pub(super) source: &'static str,
    pub(super) status: &'static str,
    pub(super) result: &'static str,
    pub(super) certification_profile: &'static str,
    pub(super) plan_name: &'static str,
    pub(super) completed_at: &'static str,
    pub(super) published_result_url: &'static str,
    pub(super) accepted_results: Vec<&'static str>,
    pub(super) required_updates: Vec<&'static str>,
    pub(super) forbidden_fields: Vec<&'static str>,
    pub(super) operator_notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OpenIdConformanceResultProfile {
    pub(super) certification_profile: &'static str,
    pub(super) plan_name: &'static str,
}
