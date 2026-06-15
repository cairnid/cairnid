mod resources;
mod response;
mod routes;
#[cfg(test)]
mod tests;
mod types;

pub use self::types::{
    BrowserOriginSmokeError, BrowserOriginSmokeInputs, BrowserOriginSmokeReport,
};
use self::{
    resources::{browser_origin_smoke_base_url, browser_origin_smoke_origin},
    response::assert_rejected,
    routes::browser_origin_mutation_routes,
    types::BrowserOriginSmokeCheck,
};
use reqwest::Client;
use std::{env, time::Duration as StdDuration};
use time::OffsetDateTime;

const BROWSER_ORIGIN_SMOKE_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const DEFAULT_HOSTILE_ORIGIN: &str = "https://browser-origin-smoke.invalid";

pub async fn run_browser_origin_smoke_from_env()
-> Result<BrowserOriginSmokeReport, BrowserOriginSmokeError> {
    let base_url = env::var("CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL")
        .or_else(|_| env::var("CAIRN_ISSUER"))
        .map_err(|_| {
            BrowserOriginSmokeError::MissingEnv(
                "CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL or CAIRN_ISSUER",
            )
        })?;
    let hostile_origin = env::var("CAIRN_BROWSER_ORIGIN_SMOKE_HOSTILE_ORIGIN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    run_browser_origin_smoke(BrowserOriginSmokeInputs {
        base_url,
        hostile_origin,
    })
    .await
}

pub async fn run_browser_origin_smoke(
    inputs: BrowserOriginSmokeInputs,
) -> Result<BrowserOriginSmokeReport, BrowserOriginSmokeError> {
    let base_url = browser_origin_smoke_base_url(&inputs.base_url)?;
    let hostile_origin = browser_origin_smoke_origin(
        "CAIRN_BROWSER_ORIGIN_SMOKE_HOSTILE_ORIGIN",
        inputs
            .hostile_origin
            .as_deref()
            .unwrap_or(DEFAULT_HOSTILE_ORIGIN),
    )?;
    let base_origin = base_url.origin().ascii_serialization();
    if hostile_origin == base_origin {
        return Err(BrowserOriginSmokeError::InvalidInput(
            "hostile origin must differ from the API base origin".to_owned(),
        ));
    }

    let client = Client::builder()
        .timeout(BROWSER_ORIGIN_SMOKE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut checks = Vec::with_capacity(browser_origin_mutation_routes().len());

    for route in browser_origin_mutation_routes() {
        let origin_status = assert_rejected(&client, &base_url, route, "Origin", &hostile_origin)
            .await?
            .as_u16();
        let referer_value = format!("{hostile_origin}/admin");
        let referer_status = assert_rejected(&client, &base_url, route, "Referer", &referer_value)
            .await?
            .as_u16();
        checks.push(BrowserOriginSmokeCheck {
            name: route.name,
            method: route.method,
            path: format!("/{}", route.path),
            status: "passed",
            origin_status,
            referer_status,
            no_store: true,
            pragma_no_cache: true,
            content_type_options_nosniff: true,
            detail: "hostile Origin and Referer were rejected before handler logic".to_owned(),
        });
    }

    Ok(BrowserOriginSmokeReport {
        status: "ok",
        base_url: base_origin,
        hostile_origin,
        completed_at: OffsetDateTime::now_utc(),
        routes_checked: checks.len(),
        checks,
    })
}
