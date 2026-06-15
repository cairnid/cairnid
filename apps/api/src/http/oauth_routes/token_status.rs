use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use cairn_authn::hash_token;
use cairn_domain::{OidcClient, OrganizationId, UserId};
use serde_json::Value;
use time::OffsetDateTime;

use super::super::{
    AppState,
    api_response::ApiError,
    oauth_client::authenticated_client_from_request,
    oauth_http::{
        introspection_request_from_oauth_form, oauth_client_auth_from_request,
        oauth_empty_response, oauth_json_response, revocation_request_from_oauth_form,
    },
    oauth_token::{
        TokenTypeHint, access_token_active_for_client, active_introspection_response,
        inactive_introspection_response, refresh_token_active_for_client,
        token_type_hint_lookup_order,
    },
    session_auth::user_allows_runtime_access,
};
use super::oauth_form_body_from_request;

pub(in crate::http) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let body = oauth_form_body_from_request(&headers, request).await?;
    let payload = introspection_request_from_oauth_form(&headers, &body)?;
    let client_auth = oauth_client_auth_from_request(
        &headers,
        payload.client_id.as_deref(),
        payload.client_secret.as_deref(),
    )?;
    let client = authenticated_client_from_request(&state, &client_auth).await?;
    let token_hash = hash_token(&payload.token);
    let response = introspection_response_for_token(
        &state,
        &client,
        &token_hash,
        payload.token_type_hint.as_deref(),
        OffsetDateTime::now_utc(),
    )
    .await?;

    Ok(oauth_json_response(StatusCode::OK, Json(response)))
}

pub(in crate::http) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let body = oauth_form_body_from_request(&headers, request).await?;
    let payload = revocation_request_from_oauth_form(&headers, &body)?;
    let client_auth = oauth_client_auth_from_request(
        &headers,
        payload.client_id.as_deref(),
        payload.client_secret.as_deref(),
    )?;
    let client = authenticated_client_from_request(&state, &client_auth).await?;
    let token_hash = hash_token(&payload.token);
    let now = OffsetDateTime::now_utc();
    revoke_token_for_client(
        &state,
        &client,
        &token_hash,
        payload.token_type_hint.as_deref(),
        now,
    )
    .await?;

    Ok(oauth_empty_response(StatusCode::OK))
}

async fn introspection_response_for_token(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    token_type_hint: Option<&str>,
    now: OffsetDateTime,
) -> Result<Value, ApiError> {
    for hint in token_type_hint_lookup_order(token_type_hint) {
        let response = match hint {
            TokenTypeHint::AccessToken => {
                introspect_access_token(state, client, token_hash, now).await?
            }
            TokenTypeHint::RefreshToken => {
                introspect_refresh_token(state, client, token_hash, now).await?
            }
        };
        if let Some(response) = response {
            return Ok(response);
        }
    }

    Ok(inactive_introspection_response())
}

async fn introspect_access_token(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<Option<Value>, ApiError> {
    let Some(token) = state.database.get_access_token(token_hash).await? else {
        return Ok(None);
    };
    if !access_token_active_for_client(&token, client, now) {
        return Ok(Some(inactive_introspection_response()));
    }
    if !token_subject_is_active(state, token.organization_id, token.user_id).await? {
        return Ok(Some(inactive_introspection_response()));
    }

    Ok(Some(active_introspection_response(
        &state.config.issuer,
        client,
        &token.scopes,
        token.user_id,
        Some("Bearer"),
        token.created_at,
        token.expires_at,
    )))
}

async fn introspect_refresh_token(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<Option<Value>, ApiError> {
    let Some(token) = state.database.get_refresh_token(token_hash).await? else {
        return Ok(None);
    };
    if !refresh_token_active_for_client(&token, client, now) {
        return Ok(Some(inactive_introspection_response()));
    }
    if !token_subject_is_active(state, token.organization_id, token.user_id).await? {
        return Ok(Some(inactive_introspection_response()));
    }

    Ok(Some(active_introspection_response(
        &state.config.issuer,
        client,
        &token.scopes,
        token.user_id,
        None,
        token.created_at,
        token.expires_at,
    )))
}

pub(in crate::http::oauth_routes) async fn token_subject_is_active(
    state: &AppState,
    organization_id: OrganizationId,
    user_id: Option<UserId>,
) -> Result<bool, ApiError> {
    let Some(user_id) = user_id else {
        return Ok(true);
    };
    let Some(user) = state.database.get_user(user_id).await? else {
        return Ok(false);
    };
    Ok(user_allows_runtime_access(&user, organization_id))
}

async fn revoke_token_for_client(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    token_type_hint: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    for hint in token_type_hint_lookup_order(token_type_hint) {
        let revoked = match hint {
            TokenTypeHint::AccessToken => {
                revoke_access_token_for_client(state, client, token_hash, now).await?
            }
            TokenTypeHint::RefreshToken => {
                revoke_refresh_token_for_client(state, client, token_hash, now).await?
            }
        };
        if revoked {
            return Ok(());
        }
    }

    Ok(())
}

async fn revoke_access_token_for_client(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<bool, ApiError> {
    if let Some(access) = state.database.get_access_token(token_hash).await?
        && access.organization_id == client.organization_id
        && access.client_id == client.id
    {
        state.database.revoke_access_token(token_hash, now).await?;
        return Ok(true);
    }
    Ok(false)
}

async fn revoke_refresh_token_for_client(
    state: &AppState,
    client: &OidcClient,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<bool, ApiError> {
    if let Some(refresh) = state.database.get_refresh_token(token_hash).await?
        && refresh.organization_id == client.organization_id
        && refresh.client_id == client.id
    {
        state
            .database
            .revoke_refresh_token_family_and_access_tokens(refresh.family_id, now)
            .await?;
        return Ok(true);
    }
    Ok(false)
}
