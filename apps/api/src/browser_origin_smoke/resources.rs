use reqwest::Url;

use super::types::BrowserOriginSmokeError;

pub(super) fn browser_origin_smoke_base_url(value: &str) -> Result<Url, BrowserOriginSmokeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BrowserOriginSmokeError::InvalidInput(
            "browser-origin smoke base URL cannot be empty".to_owned(),
        ));
    }
    let mut url = Url::parse(trimmed).map_err(|error| {
        BrowserOriginSmokeError::InvalidInput(format!("invalid browser-origin smoke URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(BrowserOriginSmokeError::InvalidInput(
            "browser-origin smoke base URL must use http or https".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BrowserOriginSmokeError::InvalidInput(
            "browser-origin smoke base URL must not include credentials".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(BrowserOriginSmokeError::InvalidInput(
            "browser-origin smoke base URL must not include query or fragment".to_owned(),
        ));
    }
    let normalized_path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&normalized_path);
    Ok(url)
}

pub(super) fn browser_origin_smoke_origin(
    name: &'static str,
    value: &str,
) -> Result<String, BrowserOriginSmokeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BrowserOriginSmokeError::InvalidInput(format!(
            "{name} cannot be empty"
        )));
    }
    let url = Url::parse(trimmed).map_err(|error| {
        BrowserOriginSmokeError::InvalidInput(format!("invalid {name}: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(BrowserOriginSmokeError::InvalidInput(format!(
            "{name} must use http or https"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(BrowserOriginSmokeError::InvalidInput(format!(
            "{name} must be an origin without credentials, path, query, or fragment"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

pub(super) fn browser_origin_resource_url(
    base_url: &Url,
    path: &str,
) -> Result<Url, BrowserOriginSmokeError> {
    base_url.join(path).map_err(|error| {
        BrowserOriginSmokeError::InvalidInput(format!(
            "invalid browser-origin smoke path {path}: {error}"
        ))
    })
}
