use axum::http::StatusCode;
use cairn_authn::verify_token_hash;
use cairn_domain::OidcClient;
use cairn_oidc::OAuthErrorBody;

use super::super::{ApiError, AppState, oauth_http::OAuthClientAuth};
use super::{require_oauth_client_active, require_oauth_client_organization};

pub(in crate::http) async fn authenticated_client_from_request(
    state: &AppState,
    client_auth: &OAuthClientAuth,
) -> Result<OidcClient, ApiError> {
    let client_id = client_auth.client_id.as_deref().ok_or_else(|| {
        ApiError::oauth(StatusCode::UNAUTHORIZED, OAuthErrorBody::invalid_client())
    })?;
    let client = state
        .database
        .get_oidc_client_by_public_id(client_id)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(StatusCode::UNAUTHORIZED, OAuthErrorBody::invalid_client())
        })?;
    require_oauth_client_organization(&client, state.organization_id)?;
    require_oauth_client_active(&client)?;
    authenticate_oauth_client(&client, client_auth)?;
    Ok(client)
}

pub(in crate::http) fn authenticate_oauth_client(
    client: &OidcClient,
    client_auth: &OAuthClientAuth,
) -> Result<(), ApiError> {
    if client_auth.client_id.as_deref() != Some(client.client_id.as_str()) {
        return Err(invalid_client());
    }

    if client.public_client {
        if client_auth.client_secret.is_some() {
            return Err(invalid_client());
        }
        return Ok(());
    }

    let Some(expected_hash) = client.client_secret_hash.as_deref() else {
        return Err(invalid_client());
    };
    let Some(secret) = client_auth.client_secret.as_deref() else {
        return Err(invalid_client());
    };
    if verify_token_hash(secret, expected_hash) {
        Ok(())
    } else {
        Err(invalid_client())
    }
}

fn invalid_client() -> ApiError {
    ApiError::oauth(StatusCode::UNAUTHORIZED, OAuthErrorBody::invalid_client())
}
