use crate::config::ApiConfig;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

use super::{ApiError, oauth_http::add_no_store_cache_headers};

pub(super) fn http_trace_span(request: &Request) -> tracing::Span {
    let labels = http_trace_labels(request);

    tracing::info_span!(
        "http.request",
        method = %labels.method,
        path = %labels.path,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HttpTraceLabels<'a> {
    pub(super) method: &'a Method,
    pub(super) path: &'a str,
}

pub(super) fn http_trace_labels(request: &Request) -> HttpTraceLabels<'_> {
    HttpTraceLabels {
        method: request.method(),
        path: http_trace_path(request),
    }
}

pub(super) fn http_trace_path(request: &Request) -> &str {
    request.uri().path()
}

pub(super) async fn add_security_headers(
    State(config): State<ApiConfig>,
    request: Request,
    next: Next,
) -> Response {
    let requires_no_store = api_response_requires_no_store(request.uri().path());
    if let Err(error) = validate_api_browser_origin(
        &config,
        request.method(),
        request.uri().path(),
        request.headers(),
    ) {
        let mut response = error.into_response();
        if requires_no_store {
            add_no_store_cache_headers(response.headers_mut());
        }
        insert_security_headers(response.headers_mut(), &config);
        return response;
    }

    let mut response = next.run(request).await;
    if requires_no_store {
        add_no_store_cache_headers(response.headers_mut());
    }
    insert_security_headers(response.headers_mut(), &config);
    response
}

pub(super) fn api_response_requires_no_store(path: &str) -> bool {
    path.starts_with("/api/v1/") || path.starts_with("/scim/v2/")
}

pub(super) fn validate_api_browser_origin(
    config: &ApiConfig,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if !unsafe_api_request_path(method, path) {
        return Ok(());
    }

    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin
            .to_str()
            .map_err(|_| ApiError::status(StatusCode::FORBIDDEN, "invalid request origin"))?;
        if origin != config.public_web_origin {
            return Err(ApiError::status(
                StatusCode::FORBIDDEN,
                "invalid request origin",
            ));
        }
        return Ok(());
    }

    if let Some(referer) = headers.get(header::REFERER) {
        let referer = referer
            .to_str()
            .map_err(|_| ApiError::status(StatusCode::FORBIDDEN, "invalid request origin"))?;
        let referer_origin = Url::parse(referer)
            .ok()
            .map(|url| url.origin().ascii_serialization());
        if referer_origin.as_deref() != Some(config.public_web_origin.as_str()) {
            return Err(ApiError::status(
                StatusCode::FORBIDDEN,
                "invalid request origin",
            ));
        }
    }

    Ok(())
}

pub(super) fn unsafe_api_request_path(method: &Method, path: &str) -> bool {
    path.starts_with("/api/v1/")
        && matches!(
            *method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        )
}

fn insert_security_headers(headers: &mut HeaderMap, config: &ApiConfig) {
    for (name, value) in security_response_header_pairs(config) {
        headers.insert(name, value);
    }
}

pub(super) fn security_response_header_pairs(config: &ApiConfig) -> Vec<(HeaderName, HeaderValue)> {
    let mut headers = vec![
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        ),
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
    ];

    if config.secure_cookies() {
        headers.push((
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ));
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::{http_trace_labels, unsafe_api_request_path};
    use axum::http::{Method, Request};

    #[test]
    fn trace_labels_exclude_query_parameters() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/oauth2/authorize?client_secret=secret")
            .body(axum::body::Body::empty())
            .expect("request");

        let labels = http_trace_labels(&request);
        assert_eq!(labels.method, &Method::GET);
        assert_eq!(labels.path, "/oauth2/authorize");
    }

    #[test]
    fn unsafe_api_request_path_only_matches_mutating_api_routes() {
        assert!(unsafe_api_request_path(&Method::POST, "/api/v1/users"));
        assert!(unsafe_api_request_path(&Method::DELETE, "/api/v1/users/1"));
        assert!(!unsafe_api_request_path(&Method::GET, "/api/v1/users"));
        assert!(!unsafe_api_request_path(&Method::POST, "/oauth2/token"));
    }
}
