use cairn_domain::{OidcClientStatus, OidcGrantType};
use cairn_oidc::scope_token_is_valid;

use super::super::super::ApiError;

pub(super) fn admin_oidc_client_type_filter(value: &str) -> Result<bool, ApiError> {
    match value {
        "public" => Ok(true),
        "confidential" => Ok(false),
        _ => Err(ApiError::bad_request(
            "invalid admin OIDC client type filter",
        )),
    }
}

pub(super) fn admin_oidc_client_status_filter(value: &str) -> Result<OidcClientStatus, ApiError> {
    match value {
        "active" => Ok(OidcClientStatus::Active),
        "disabled" => Ok(OidcClientStatus::Disabled),
        _ => Err(ApiError::bad_request(
            "invalid admin OIDC client status filter",
        )),
    }
}

pub(super) fn admin_oidc_client_grant_type_filter(value: &str) -> Result<OidcGrantType, ApiError> {
    match value {
        "authorization_code" => Ok(OidcGrantType::AuthorizationCode),
        "refresh_token" => Ok(OidcGrantType::RefreshToken),
        "client_credentials" => Ok(OidcGrantType::ClientCredentials),
        _ => Err(ApiError::bad_request(
            "invalid admin OIDC client grant_type filter",
        )),
    }
}

pub(super) fn admin_oidc_client_scope_filter(value: &str) -> Result<Option<String>, ApiError> {
    let trimmed = value.trim();
    if trimmed.len() > 128 {
        return Err(ApiError::bad_request(
            "admin OIDC client scope filter too large",
        ));
    }
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !scope_token_is_valid(trimmed) {
        return Err(ApiError::bad_request(
            "invalid admin OIDC client scope filter",
        ));
    }
    Ok(Some(trimmed.to_owned()))
}
