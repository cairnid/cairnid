mod assertions;
mod resources;
mod targets;
#[cfg(test)]
mod tests;
mod types;

pub use self::types::{
    SecurityHeaderSmokeError, SecurityHeaderSmokeInputs, SecurityHeaderSmokeReport,
};
use self::{
    assertions::check_security_headers, resources::security_header_smoke_origin,
    targets::security_header_targets,
};
use reqwest::{Client, Url};
use std::{env, time::Duration as StdDuration};
use time::OffsetDateTime;

const SECURITY_HEADER_SMOKE_TIMEOUT: StdDuration = StdDuration::from_secs(10);

pub async fn run_security_header_smoke_from_env()
-> Result<SecurityHeaderSmokeReport, SecurityHeaderSmokeError> {
    let api_base_url = env::var("CAIRN_SECURITY_HEADERS_API_BASE_URL")
        .or_else(|_| env::var("CAIRN_ISSUER"))
        .map_err(|_| {
            SecurityHeaderSmokeError::MissingEnv(
                "CAIRN_SECURITY_HEADERS_API_BASE_URL or CAIRN_ISSUER",
            )
        })?;
    let web_base_url = env::var("CAIRN_SECURITY_HEADERS_WEB_BASE_URL")
        .or_else(|_| env::var("CAIRN_PUBLIC_WEB_ORIGIN"))
        .map_err(|_| {
            SecurityHeaderSmokeError::MissingEnv(
                "CAIRN_SECURITY_HEADERS_WEB_BASE_URL or CAIRN_PUBLIC_WEB_ORIGIN",
            )
        })?;

    run_security_header_smoke(SecurityHeaderSmokeInputs {
        api_base_url,
        web_base_url,
    })
    .await
}

pub async fn run_security_header_smoke(
    inputs: SecurityHeaderSmokeInputs,
) -> Result<SecurityHeaderSmokeReport, SecurityHeaderSmokeError> {
    let api_base_url =
        security_header_smoke_origin("CAIRN_SECURITY_HEADERS_API_BASE_URL", &inputs.api_base_url)?;
    let web_base_url =
        security_header_smoke_origin("CAIRN_SECURITY_HEADERS_WEB_BASE_URL", &inputs.web_base_url)?;
    let client = Client::builder()
        .timeout(SECURITY_HEADER_SMOKE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut checks = Vec::with_capacity(security_header_targets().len());
    for target in security_header_targets() {
        let base_url = security_header_base_url(&api_base_url, &web_base_url, target.service)?;
        checks.push(check_security_headers(&client, base_url, target).await?);
    }

    Ok(SecurityHeaderSmokeReport {
        status: "ok",
        api_base_url: api_base_url.origin().ascii_serialization(),
        web_base_url: web_base_url.origin().ascii_serialization(),
        completed_at: OffsetDateTime::now_utc(),
        checks,
    })
}

fn security_header_base_url<'a>(
    api_base_url: &'a Url,
    web_base_url: &'a Url,
    service: &'static str,
) -> Result<&'a Url, SecurityHeaderSmokeError> {
    match service {
        "api" => Ok(api_base_url),
        "web" => Ok(web_base_url),
        _ => Err(SecurityHeaderSmokeError::InvalidInput(
            "unsupported security-header smoke service".to_owned(),
        )),
    }
}
