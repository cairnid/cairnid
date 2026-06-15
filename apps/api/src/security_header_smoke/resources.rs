use reqwest::Url;

use super::types::SecurityHeaderSmokeError;

pub(super) fn security_header_smoke_origin(
    name: &'static str,
    value: &str,
) -> Result<Url, SecurityHeaderSmokeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SecurityHeaderSmokeError::InvalidInput(format!(
            "{name} cannot be empty"
        )));
    }
    let url = Url::parse(trimmed).map_err(|error| {
        SecurityHeaderSmokeError::InvalidInput(format!("invalid {name}: {error}"))
    })?;
    if url.scheme() != "https" {
        return Err(SecurityHeaderSmokeError::InvalidInput(format!(
            "{name} must use https"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SecurityHeaderSmokeError::InvalidInput(format!(
            "{name} must be an HTTPS origin without credentials, path, query, or fragment"
        )));
    }
    Ok(url)
}

pub(super) fn security_header_resource_url(
    base_url: &Url,
    path: &str,
) -> Result<Url, SecurityHeaderSmokeError> {
    base_url
        .join(path.trim_start_matches('/'))
        .map_err(|error| {
            SecurityHeaderSmokeError::InvalidInput(format!(
                "invalid security-header smoke path {path}: {error}"
            ))
        })
}
