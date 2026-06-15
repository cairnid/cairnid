use axum::http::StatusCode;
use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType};
use cairn_oidc::OAuthErrorBody;

use super::super::ApiError;

pub(in crate::http) fn oidc_client_is_active(client: &OidcClient) -> bool {
    client.status == OidcClientStatus::Active
}

pub(in crate::http) fn require_oauth_client_active(client: &OidcClient) -> Result<(), ApiError> {
    if oidc_client_is_active(client) {
        Ok(())
    } else {
        Err(ApiError::oauth(
            StatusCode::UNAUTHORIZED,
            OAuthErrorBody::invalid_client(),
        ))
    }
}

pub(in crate::http) fn require_token_endpoint_grant(
    client: &OidcClient,
    grant_type: OidcGrantType,
) -> Result<(), ApiError> {
    if client.allows_grant(grant_type) {
        return Ok(());
    }

    Err(ApiError::oauth(
        StatusCode::BAD_REQUEST,
        OAuthErrorBody::unauthorized_client(format!(
            "client is not authorized to use {}",
            grant_type.as_protocol_value()
        )),
    ))
}

pub(in crate::http) fn require_confidential_client_credentials_client(
    client: &OidcClient,
) -> Result<(), ApiError> {
    if client.public_client || client.client_secret_hash.is_none() {
        return Err(ApiError::oauth(
            StatusCode::UNAUTHORIZED,
            OAuthErrorBody::invalid_client(),
        ));
    }

    Ok(())
}
