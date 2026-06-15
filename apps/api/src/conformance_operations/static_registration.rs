use super::{
    types::{
        OpenIdConformanceClientRegistration, OpenIdConformanceRegistrationInputs,
        OpenIdConformanceRegistrationReport,
    },
    validation::{
        conformance_suite_base_url, required_env, validate_conformance_alias,
        validate_conformance_issuer, validate_conformance_value,
    },
};
use time::OffsetDateTime;

pub(super) fn openid_conformance_static_registration_from_env()
-> Result<OpenIdConformanceRegistrationReport, Box<dyn std::error::Error>> {
    let issuer = required_env("CAIRN_ISSUER")?;
    let suite_base_url = required_env("CAIRN_CONFORMANCE_SUITE_BASE_URL")?;
    openid_conformance_static_registration(OpenIdConformanceRegistrationInputs {
        issuer: &issuer,
        alias: &required_env("CAIRN_CONFORMANCE_ALIAS")?,
        suite_base_url: &suite_base_url,
        client_id: &required_env("CAIRN_CONFORMANCE_CLIENT_ID")?,
        client2_id: &required_env("CAIRN_CONFORMANCE_CLIENT2_ID")?,
    })
}

pub(super) fn openid_conformance_static_registration(
    inputs: OpenIdConformanceRegistrationInputs<'_>,
) -> Result<OpenIdConformanceRegistrationReport, Box<dyn std::error::Error>> {
    validate_conformance_issuer(inputs.issuer)?;
    validate_conformance_alias(inputs.alias)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT_ID", inputs.client_id)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT2_ID", inputs.client2_id)?;
    let suite_base_url = conformance_suite_base_url(inputs.suite_base_url)?;
    let redirect_uri = format!("{suite_base_url}test/a/{}/callback", inputs.alias);

    Ok(OpenIdConformanceRegistrationReport {
        generated_at: OffsetDateTime::now_utc(),
        status: "ready",
        issuer: inputs.issuer.trim_end_matches('/').to_owned(),
        suite_alias: inputs.alias.to_owned(),
        certification_profiles: vec!["Config OP".to_owned(), "Basic OP".to_owned()],
        run_plan_commands: vec![
            "scripts/run-test-plan.py oidcc-config-certification-test-plan cairn-oidcc-static.json"
                .to_owned(),
            "scripts/run-test-plan.py oidcc-basic-certification-test-plan cairn-oidcc-static.json"
                .to_owned(),
        ],
        static_clients: vec![
            OpenIdConformanceClientRegistration {
                role: "primary",
                client_id: inputs.client_id.to_owned(),
                redirect_uris: vec![redirect_uri.clone()],
                post_logout_redirect_uris: vec![format!(
                    "{suite_base_url}test/a/{}/post_logout_redirect",
                    inputs.alias
                )],
                response_types: vec!["code".to_owned()],
                grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
                token_endpoint_auth_methods: vec![
                    "client_secret_basic".to_owned(),
                    "client_secret_post".to_owned(),
                ],
                allowed_scopes: oidf_static_client_scopes(),
                pkce_methods: vec!["S256".to_owned()],
            },
            OpenIdConformanceClientRegistration {
                role: "secondary",
                client_id: inputs.client2_id.to_owned(),
                redirect_uris: vec![redirect_uri],
                post_logout_redirect_uris: vec![format!(
                    "{suite_base_url}test/a/{}/post_logout_redirect",
                    inputs.alias
                )],
                response_types: vec!["code".to_owned()],
                grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
                token_endpoint_auth_methods: vec![
                    "client_secret_basic".to_owned(),
                    "client_secret_post".to_owned(),
                ],
                allowed_scopes: oidf_static_client_scopes(),
                pkce_methods: vec!["S256".to_owned()],
            },
        ],
        unsupported_v1_profiles: vec![
            "Implicit OP".to_owned(),
            "Hybrid OP".to_owned(),
            "Dynamic OP".to_owned(),
            "Form Post OP".to_owned(),
        ],
    })
}

fn oidf_static_client_scopes() -> Vec<String> {
    ["openid", "profile", "email", "groups", "offline_access"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
