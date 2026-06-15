use reqwest::Url;

use super::types::OidcMetadataSmokeError;

pub(super) fn oidc_metadata_smoke_issuer(
    name: &'static str,
    value: &str,
) -> Result<Url, OidcMetadataSmokeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(OidcMetadataSmokeError::InvalidInput(format!(
            "{name} cannot be empty"
        )));
    }
    let url = Url::parse(trimmed).map_err(|error| {
        OidcMetadataSmokeError::InvalidInput(format!("invalid {name}: {error}"))
    })?;
    if url.scheme() != "https" {
        return Err(OidcMetadataSmokeError::InvalidInput(format!(
            "{name} must use https"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OidcMetadataSmokeError::InvalidInput(format!(
            "{name} must be an HTTPS origin without credentials, path, query, or fragment"
        )));
    }
    Ok(url)
}

pub(super) fn oidc_metadata_resource_url(
    issuer: &Url,
    path: &'static str,
) -> Result<Url, OidcMetadataSmokeError> {
    issuer.join(path.trim_start_matches('/')).map_err(|error| {
        OidcMetadataSmokeError::InvalidInput(format!(
            "invalid OIDC metadata smoke path {path}: {error}"
        ))
    })
}
