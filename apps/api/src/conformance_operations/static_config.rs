use std::env;
use time::OffsetDateTime;

use super::{
    types::{
        OpenIdConformanceClientConfig, OpenIdConformanceInputs, OpenIdConformanceServerConfig,
        OpenIdConformanceSuiteConfig,
    },
    validation::{
        bounded_conformance_description, required_env, validate_conformance_alias,
        validate_conformance_issuer, validate_conformance_value,
    },
};

pub(super) fn openid_conformance_static_config_from_env()
-> Result<OpenIdConformanceSuiteConfig, Box<dyn std::error::Error>> {
    let issuer = required_env("CAIRN_ISSUER")?;
    openid_conformance_static_config(OpenIdConformanceInputs {
        issuer: &issuer,
        alias: &required_env("CAIRN_CONFORMANCE_ALIAS")?,
        description: env::var("CAIRN_CONFORMANCE_DESCRIPTION")
            .unwrap_or_else(|_| "Cairn Identity OIDC static client certification".to_owned()),
        client_id: &required_env("CAIRN_CONFORMANCE_CLIENT_ID")?,
        client_secret: &required_env("CAIRN_CONFORMANCE_CLIENT_SECRET")?,
        client2_id: &required_env("CAIRN_CONFORMANCE_CLIENT2_ID")?,
        client2_secret: &required_env("CAIRN_CONFORMANCE_CLIENT2_SECRET")?,
    })
}

pub(super) fn openid_conformance_static_config(
    inputs: OpenIdConformanceInputs<'_>,
) -> Result<OpenIdConformanceSuiteConfig, Box<dyn std::error::Error>> {
    validate_conformance_issuer(inputs.issuer)?;
    validate_conformance_alias(inputs.alias)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT_ID", inputs.client_id)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT_SECRET", inputs.client_secret)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT2_ID", inputs.client2_id)?;
    validate_conformance_value("CAIRN_CONFORMANCE_CLIENT2_SECRET", inputs.client2_secret)?;

    Ok(OpenIdConformanceSuiteConfig {
        generated_at: OffsetDateTime::now_utc(),
        alias: inputs.alias.to_owned(),
        description: bounded_conformance_description(&inputs.description),
        server: OpenIdConformanceServerConfig {
            discovery_url: format!(
                "{}/.well-known/openid-configuration",
                inputs.issuer.trim_end_matches('/')
            ),
        },
        client: OpenIdConformanceClientConfig {
            client_id: inputs.client_id.to_owned(),
            client_secret: inputs.client_secret.to_owned(),
        },
        client2: OpenIdConformanceClientConfig {
            client_id: inputs.client2_id.to_owned(),
            client_secret: inputs.client2_secret.to_owned(),
        },
    })
}
