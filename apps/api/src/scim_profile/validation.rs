use url::Url;

use super::types::ScimConnectorProfileError;

pub(super) fn normalized_https_origin(value: &str) -> Result<String, ScimConnectorProfileError> {
    let url = Url::parse(value.trim())
        .map_err(|error| ScimConnectorProfileError::InvalidIssuer(error.to_string()))?;
    if url.scheme() != "https" {
        return Err(ScimConnectorProfileError::NonHttpsIssuer);
    }
    let origin_only = url.username().is_empty()
        && url.password().is_none()
        && matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none();
    if !origin_only {
        return Err(ScimConnectorProfileError::NonOriginIssuer);
    }
    Ok(url.origin().ascii_serialization())
}
