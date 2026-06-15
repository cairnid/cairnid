use crate::{
    browser_origin_smoke::run_browser_origin_smoke_from_env,
    oidc_metadata_smoke::run_oidc_metadata_smoke_from_env,
    security_header_smoke::run_security_header_smoke_from_env,
};

pub(super) async fn run_browser_origin_smoke_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = run_browser_origin_smoke_from_env().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub(super) async fn run_oidc_metadata_smoke_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = run_oidc_metadata_smoke_from_env().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub(super) async fn run_security_headers_smoke_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = run_security_header_smoke_from_env().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
