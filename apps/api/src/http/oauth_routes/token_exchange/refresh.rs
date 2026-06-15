use axum::{Json, http::StatusCode, response::Response};
use cairn_authn::{generate_hashed_secret, hash_token};
use cairn_database::AccessTokenRecord;
use cairn_domain::{OidcGrantType, RefreshToken};
use cairn_oidc::{OAuthErrorBody, TokenRequest, TokenResponse};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};

use super::super::super::{
    AppState,
    api_response::ApiError,
    oauth_client::{
        authenticate_oauth_client, require_oauth_client_active, require_stored_token_organization,
        require_token_endpoint_grant,
    },
    oauth_http::{OAuthClientAuth, oauth_json_response},
    oauth_token::{
        refresh_token_granted_scopes, required_refresh_token, should_issue_refresh_token,
        token_response_scope,
    },
};
use super::super::token_status::token_subject_is_active;

pub(super) async fn refresh_token(
    state: AppState,
    request: TokenRequest,
    client_auth: OAuthClientAuth,
) -> Result<Response, ApiError> {
    let raw_refresh = required_refresh_token(request.refresh_token.as_deref())?;
    let refresh_hash = hash_token(raw_refresh);
    let stored = state
        .database
        .get_refresh_token(&refresh_hash)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_grant("unknown refresh token"),
            )
        })?;
    let now = OffsetDateTime::now_utc();
    require_stored_token_organization(stored.organization_id, state.organization_id)?;

    if stored.rotated_at.is_some() {
        state
            .database
            .revoke_refresh_token_family_and_access_tokens(stored.family_id, now)
            .await?;
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("refresh token reuse detected"),
        ));
    }

    if stored.revoked_at.is_some() || stored.expires_at <= now {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("refresh token expired or revoked"),
        ));
    }
    if !token_subject_is_active(&state, stored.organization_id, stored.user_id).await? {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("refresh token expired or revoked"),
        ));
    }
    let client = state
        .database
        .get_oidc_client(stored.client_id)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_grant("client missing"),
            )
        })?;
    require_oauth_client_active(&client)?;
    authenticate_oauth_client(&client, &client_auth)?;
    require_token_endpoint_grant(&client, OidcGrantType::RefreshToken)?;
    let granted_scopes = refresh_token_granted_scopes(request.scope.as_deref(), &stored.scopes)?;

    let access = generate_hashed_secret(32);
    let refresh = should_issue_refresh_token(&granted_scopes, &client).then(|| {
        let refresh = generate_hashed_secret(32);
        let record = RefreshToken {
            id: refresh.id,
            token_hash: refresh.hash.clone(),
            family_id: stored.family_id,
            organization_id: stored.organization_id,
            user_id: stored.user_id,
            client_id: stored.client_id,
            scopes: granted_scopes.clone(),
            created_at: now,
            expires_at: now + Duration::days(30),
            rotated_at: None,
            revoked_at: None,
        };
        (refresh, record)
    });
    let access_record = AccessTokenRecord {
        token_hash: access.hash,
        organization_id: stored.organization_id,
        user_id: stored.user_id,
        client_id: stored.client_id,
        scopes: granted_scopes.clone(),
        refresh_family_id: Some(stored.family_id),
        created_at: now,
        expires_at: now + Duration::minutes(15),
        revoked_at: None,
    };
    let refresh_record = refresh.as_ref().map(|(_, record)| record);
    let rotated = state
        .database
        .rotate_refresh_token_and_insert_tokens(&refresh_hash, &access_record, refresh_record, now)
        .await?;
    if !rotated {
        state
            .database
            .revoke_refresh_token_family_and_access_tokens(stored.family_id, now)
            .await?;
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("refresh token reuse detected"),
        ));
    }

    Ok(oauth_json_response(
        StatusCode::OK,
        Json(TokenResponse {
            access_token: access.value.expose_secret().to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            refresh_token: refresh
                .as_ref()
                .map(|(refresh, _)| refresh.value.expose_secret().to_owned()),
            id_token: None,
            scope: token_response_scope(&granted_scopes),
        }),
    ))
}
