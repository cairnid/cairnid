use axum::{
    Json,
    extract::{RawQuery, Request, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use cairn_oidc::EndSessionRequest;
use serde_json::json;

use super::super::{
    AppState,
    api_response::ApiError,
    client_policy::post_logout_redirect_target,
    cookies::clear_browser_session_cookies,
    end_session::{end_session_request_from_form, end_session_request_from_query},
    oauth_http::{add_oauth_cache_headers, oauth_redirect_response},
    session_auth::session_from_cookie,
    session_routes::revoke_session_for_logout,
};

pub(in crate::http) async fn end_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    let request = match end_session_request_from_query(raw_query.as_deref()) {
        Ok(request) => request,
        Err(error) => return Ok(logout_error_response(error)),
    };
    end_session_response(state, headers, request).await
}

pub(in crate::http) async fn end_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ApiError> {
    let request = match end_session_request_from_form(&headers, request).await {
        Ok(request) => request,
        Err(error) => return Ok(logout_error_response(error)),
    };
    end_session_response(state, headers, request).await
}

async fn end_session_response(
    state: AppState,
    headers: HeaderMap,
    request: EndSessionRequest,
) -> Result<Response, ApiError> {
    let redirect_target = post_logout_redirect_target(&state, &request).await?;

    if let Some(session) = session_from_cookie(&state, &headers).await? {
        revoke_session_for_logout(&state, &headers, &session, "rp_initiated").await?;
    }

    let mut response = if let Some(target) = redirect_target {
        oauth_redirect_response(&target)
    } else {
        Json(json!({ "status": "ok" })).into_response()
    };
    add_oauth_cache_headers(response.headers_mut());
    clear_browser_session_cookies(response.headers_mut(), &state.config)?;
    Ok(response)
}

fn logout_error_response(error: ApiError) -> Response {
    let mut response = error.into_response();
    add_oauth_cache_headers(response.headers_mut());
    response
}
