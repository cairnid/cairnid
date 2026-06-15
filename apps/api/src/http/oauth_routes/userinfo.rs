use axum::{
    Json,
    extract::{RawQuery, Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{MethodRouter, get},
};
use cairn_authn::hash_token;
use cairn_oidc::userinfo;
use time::OffsetDateTime;

use super::super::{
    AppState, OAUTH_FORM_BODY_MAX_BYTES,
    api_response::ApiError,
    content_type::request_has_urlencoded_content_type,
    oauth_client::{bearer_token_matches_organization, oidc_client_is_active},
    oauth_http::{
        BearerTokenError, bearer_challenge_response, bearer_token_error_response,
        bearer_token_from_sources, oauth_json_response, userinfo_request_from_form_body,
    },
    request_body::bounded_request_body,
    session_auth::{groups_claim_for_user, user_allows_runtime_access},
};

pub(in crate::http) fn userinfo_route() -> MethodRouter<AppState> {
    get(userinfo_endpoint).post(userinfo_endpoint_post)
}

async fn userinfo_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    userinfo_response_for_bearer_token(state, &headers, None, raw_query.as_deref()).await
}

async fn userinfo_endpoint_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    request: Request,
) -> Result<Response, ApiError> {
    let form_access_token = match userinfo_form_access_token(&headers, request).await {
        Ok(form_access_token) => form_access_token,
        Err(error) => return Ok(bearer_token_error_response(error)),
    };
    userinfo_response_for_bearer_token(state, &headers, form_access_token, raw_query.as_deref())
        .await
}

async fn userinfo_response_for_bearer_token(
    state: AppState,
    headers: &HeaderMap,
    form_access_token: Option<String>,
    raw_query: Option<&str>,
) -> Result<Response, ApiError> {
    let token = match bearer_token_from_sources(headers, form_access_token, raw_query) {
        Ok(token) => token,
        Err(error) => return Ok(bearer_token_error_response(error)),
    };
    let token_hash = hash_token(token.as_ref());
    let Some(access) = state.database.get_access_token(&token_hash).await? else {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("invalid bearer token"),
            None,
        ));
    };
    if !bearer_token_matches_organization(access.organization_id, state.organization_id) {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("invalid bearer token"),
            None,
        ));
    }
    if access.revoked_at.is_some() || access.expires_at <= OffsetDateTime::now_utc() {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("expired or revoked bearer token"),
            None,
        ));
    }
    let Some(client) = state.database.get_oidc_client(access.client_id).await? else {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("invalid bearer token"),
            None,
        ));
    };
    if client.organization_id != access.organization_id || !oidc_client_is_active(&client) {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("invalid bearer token"),
            None,
        ));
    }
    let Some(user_id) = access.user_id else {
        return Ok(bearer_challenge_response(
            StatusCode::FORBIDDEN,
            Some("insufficient_scope"),
            Some("userinfo requires a user access token"),
            Some("openid"),
        ));
    };
    if !access.scopes.iter().any(|scope| scope == "openid") {
        return Ok(bearer_challenge_response(
            StatusCode::FORBIDDEN,
            Some("insufficient_scope"),
            Some("userinfo requires openid scope"),
            Some("openid"),
        ));
    }
    let user = state.database.get_user(user_id).await?.ok_or_else(|| {
        ApiError::status(
            StatusCode::INTERNAL_SERVER_ERROR,
            "user token is inconsistent",
        )
    })?;
    if !user_allows_runtime_access(&user, access.organization_id) {
        return Ok(bearer_challenge_response(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            Some("invalid bearer token"),
            None,
        ));
    }
    let groups =
        groups_claim_for_user(&state, access.organization_id, user.id, &access.scopes).await?;

    Ok(oauth_json_response(
        StatusCode::OK,
        Json(userinfo(&user, &access.scopes, groups)),
    ))
}

async fn userinfo_form_access_token(
    headers: &HeaderMap,
    request: Request,
) -> Result<Option<String>, BearerTokenError> {
    if !request_has_urlencoded_content_type(headers) {
        return Ok(None);
    }
    let body = bounded_request_body(request, OAUTH_FORM_BODY_MAX_BYTES)
        .await
        .map_err(|_| BearerTokenError::InvalidRequest)?;
    let form = userinfo_request_from_form_body(&body)?;
    Ok(form.access_token)
}
