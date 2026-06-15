use axum::{Json, http::StatusCode, response::Response};
use cairn_authn::generate_hashed_secret;
use cairn_database::AccessTokenRecord;
use cairn_domain::OidcGrantType;
use cairn_oidc::{OAuthErrorBody, TokenRequest, TokenResponse};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};

use super::super::super::{
    AppState,
    api_response::ApiError,
    oauth_client::{
        authenticated_client_from_request, require_confidential_client_credentials_client,
        require_token_endpoint_grant,
    },
    oauth_http::{OAuthClientAuth, oauth_json_response},
    oauth_token::{token_request_scopes, token_response_scope},
};

pub(super) async fn client_credentials_token(
    state: AppState,
    request: TokenRequest,
    client_auth: OAuthClientAuth,
) -> Result<Response, ApiError> {
    let client = authenticated_client_from_request(&state, &client_auth).await?;
    require_confidential_client_credentials_client(&client)?;
    require_token_endpoint_grant(&client, OidcGrantType::ClientCredentials)?;

    let requested_scopes = token_request_scopes(request.scope.as_deref())?.unwrap_or_default();
    if requested_scopes
        .iter()
        .any(|scope| !client.allowed_scopes.iter().any(|allowed| allowed == scope))
    {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_scope("invalid scope"),
        ));
    }

    let now = OffsetDateTime::now_utc();
    let access = generate_hashed_secret(32);
    state
        .database
        .insert_access_token(&AccessTokenRecord {
            token_hash: access.hash,
            organization_id: client.organization_id,
            user_id: None,
            client_id: client.id,
            scopes: requested_scopes.clone(),
            refresh_family_id: None,
            created_at: now,
            expires_at: now + Duration::minutes(15),
            revoked_at: None,
        })
        .await?;

    Ok(oauth_json_response(
        StatusCode::OK,
        Json(TokenResponse {
            access_token: access.value.expose_secret().to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            refresh_token: None,
            id_token: None,
            scope: token_response_scope(&requested_scopes),
        }),
    ))
}
