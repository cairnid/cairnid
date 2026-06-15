mod discovery;
mod jwks;
mod resources;
#[cfg(test)]
mod tests;
mod types;
mod validation;

pub use self::types::{OidcMetadataSmokeError, OidcMetadataSmokeInputs, OidcMetadataSmokeReport};
use self::{
    discovery::validate_discovery_metadata,
    jwks::validate_jwks_metadata,
    resources::{oidc_metadata_resource_url, oidc_metadata_smoke_issuer},
    types::OidcMetadataSmokeCheck,
};
use reqwest::{Client, StatusCode, Url, header};
use serde_json::Value;
use std::{env, time::Duration as StdDuration};
use time::OffsetDateTime;

const OIDC_METADATA_SMOKE_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const JWKS_PATH: &str = "/.well-known/jwks.json";

pub async fn run_oidc_metadata_smoke_from_env()
-> Result<OidcMetadataSmokeReport, OidcMetadataSmokeError> {
    let issuer = env::var("CAIRN_OIDC_METADATA_SMOKE_ISSUER")
        .or_else(|_| env::var("CAIRN_ISSUER"))
        .map_err(|_| {
            OidcMetadataSmokeError::MissingEnv("CAIRN_OIDC_METADATA_SMOKE_ISSUER or CAIRN_ISSUER")
        })?;

    run_oidc_metadata_smoke(OidcMetadataSmokeInputs { issuer }).await
}

pub async fn run_oidc_metadata_smoke(
    inputs: OidcMetadataSmokeInputs,
) -> Result<OidcMetadataSmokeReport, OidcMetadataSmokeError> {
    let issuer = oidc_metadata_smoke_issuer("CAIRN_OIDC_METADATA_SMOKE_ISSUER", &inputs.issuer)?;
    let issuer_origin = issuer.origin().ascii_serialization();
    let client = Client::builder()
        .timeout(OIDC_METADATA_SMOKE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let discovery_url = oidc_metadata_resource_url(&issuer, DISCOVERY_PATH)?;
    let discovery = get_json(&client, discovery_url, DISCOVERY_PATH).await?;

    let mut checks = vec![OidcMetadataSmokeCheck {
        name: "issuer_https_origin",
        status: "passed",
        detail: "issuer is an HTTPS origin without credentials, path, query, or fragment"
            .to_owned(),
    }];
    checks.push(OidcMetadataSmokeCheck {
        name: "discovery_http_status",
        status: "passed",
        detail: "OpenID discovery endpoint returned HTTP 200 JSON".to_owned(),
    });
    checks.extend(validate_discovery_metadata(&issuer_origin, &discovery)?);

    let jwks_url = oidc_metadata_resource_url(&issuer, JWKS_PATH)?;
    let jwks = get_json(&client, jwks_url, JWKS_PATH).await?;
    checks.push(OidcMetadataSmokeCheck {
        name: "jwks_http_status",
        status: "passed",
        detail: "JWKS endpoint returned HTTP 200 JSON".to_owned(),
    });
    checks.extend(validate_jwks_metadata(&jwks)?);

    Ok(OidcMetadataSmokeReport {
        status: "ok",
        issuer: issuer_origin,
        completed_at: OffsetDateTime::now_utc(),
        checks,
    })
}

async fn get_json(
    client: &Client,
    url: Url,
    path: &'static str,
) -> Result<Value, OidcMetadataSmokeError> {
    let response = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(OidcMetadataSmokeError::UnexpectedStatus {
            path,
            expected: StatusCode::OK.as_u16(),
            actual: status.as_u16(),
        });
    }

    Ok(response.json::<Value>().await?)
}
