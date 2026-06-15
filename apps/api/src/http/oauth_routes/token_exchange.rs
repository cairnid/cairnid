mod authorization_code;
mod client_credentials;
mod refresh;

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use cairn_oidc::OAuthErrorBody;

use super::super::{
    AppState,
    api_response::ApiError,
    oauth_http::{
        oauth_client_auth_from_request, oauth_json_response, token_request_from_oauth_form,
    },
    oauth_token::grant_type_is_valid,
};
use super::oauth_form_body_from_request;
use authorization_code::authorization_code_token;
use client_credentials::client_credentials_token;
use refresh::refresh_token;

pub(in crate::http) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let body = oauth_form_body_from_request(&headers, request).await?;
    let request = token_request_from_oauth_form(&headers, &body)?;
    let client_auth = oauth_client_auth_from_request(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;
    let grant_type = request.grant_type.clone();
    if grant_type.trim().is_empty() {
        return Ok(oauth_json_response(
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorBody::invalid_request("missing grant_type")),
        ));
    }
    if !grant_type_is_valid(&grant_type) {
        return Ok(oauth_json_response(
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorBody::invalid_request("invalid grant_type")),
        ));
    }
    match grant_type.as_str() {
        "authorization_code" => authorization_code_token(state, request, client_auth).await,
        "client_credentials" => client_credentials_token(state, request, client_auth).await,
        "refresh_token" => refresh_token(state, request, client_auth).await,
        _ => Ok(oauth_json_response(
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorBody::unsupported_grant_type()),
        )),
    }
}
