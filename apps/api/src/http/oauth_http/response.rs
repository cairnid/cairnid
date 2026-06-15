use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use cairn_oidc::OAuthErrorBody;
use serde::Serialize;

pub(in crate::http) fn oauth_json_response<T: Serialize>(
    status: StatusCode,
    body: Json<T>,
) -> Response {
    let mut response = (status, body).into_response();
    add_oauth_cache_headers(response.headers_mut());
    response
}

pub(in crate::http) fn oauth_error_response(status: StatusCode, body: OAuthErrorBody) -> Response {
    let include_client_auth_challenge =
        status == StatusCode::UNAUTHORIZED && body.error == "invalid_client";
    let mut response = oauth_json_response(status, Json(body));
    if include_client_auth_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"cairn\""),
        );
    }
    response
}

pub(in crate::http) fn oauth_empty_response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    add_oauth_cache_headers(response.headers_mut());
    response
}

pub(in crate::http) fn oauth_redirect_response(target: &str) -> Response {
    let mut response = Redirect::temporary(target).into_response();
    add_oauth_cache_headers(response.headers_mut());
    response
}

pub(in crate::http) fn add_oauth_cache_headers(headers: &mut HeaderMap) {
    add_no_store_cache_headers(headers);
}

pub(in crate::http) fn add_no_store_cache_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

#[cfg(test)]
mod tests {
    use super::oauth_json_response;
    use axum::{
        Json,
        http::{StatusCode, header},
    };
    use serde_json::json;

    #[test]
    fn oauth_responses_are_no_store() {
        let response = oauth_json_response(StatusCode::OK, Json(json!({ "active": true })));

        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    }
}
