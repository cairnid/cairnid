use axum::{
    Json,
    extract::{FromRequest, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use cairn_oidc::OAuthErrorBody;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::{
    API_JSON_BODY_MAX_BYTES, content_type::request_has_json_content_type,
    oauth_http::oauth_error_response, request_body::bounded_request_body,
};

#[derive(Debug)]
pub(super) struct ApiJson<T>(pub(super) T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !request_has_json_content_type(request.headers()) {
            return Err(ApiError::bad_request(
                "content type must be application/json",
            ));
        }
        let body = bounded_request_body(request, API_JSON_BODY_MAX_BYTES)
            .await
            .map_err(|_| ApiError::bad_request("JSON body too large"))?;
        let Json(payload) =
            Json::<T>::from_bytes(&body).map_err(|_| ApiError::bad_request("invalid JSON body"))?;
        Ok(Self(payload))
    }
}

#[derive(Debug)]
pub(super) enum ApiError {
    Status {
        status: StatusCode,
        message: String,
        headers: HeaderMap,
    },
    OAuth {
        status: StatusCode,
        body: OAuthErrorBody,
    },
}

impl ApiError {
    pub(super) fn status(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Status {
            status,
            message: message.into(),
            headers: HeaderMap::new(),
        }
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self::status(StatusCode::BAD_REQUEST, message)
    }

    pub(super) fn status_with_header(
        status: StatusCode,
        message: impl Into<String>,
        header_name: HeaderName,
        header_value: HeaderValue,
    ) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(header_name, header_value);
        Self::Status {
            status,
            message: message.into(),
            headers,
        }
    }

    pub(super) fn rate_limited(retry_after_seconds: i64) -> Self {
        let retry_after = HeaderValue::from_str(&retry_after_seconds.max(1).to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("1"));
        Self::status_with_header(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts; try again later",
            header::RETRY_AFTER,
            retry_after,
        )
    }

    pub(super) fn oauth(status: StatusCode, body: OAuthErrorBody) -> Self {
        Self::OAuth { status, body }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Status {
                status,
                message,
                headers,
            } => {
                let mut response = (status, Json(json!({ "error": message }))).into_response();
                for (name, value) in headers.iter() {
                    response.headers_mut().insert(name.clone(), value.clone());
                }
                response
            }
            Self::OAuth { status, body } => oauth_error_response(status, body),
        }
    }
}

impl From<cairn_database::DatabaseError> for ApiError {
    fn from(error: cairn_database::DatabaseError) -> Self {
        tracing::error!(%error, "database error");
        Self::status(StatusCode::INTERNAL_SERVER_ERROR, "database error")
    }
}

impl From<cairn_domain::DomainError> for ApiError {
    fn from(error: cairn_domain::DomainError) -> Self {
        Self::bad_request(error.to_string())
    }
}

impl From<cairn_authn::AuthnError> for ApiError {
    fn from(error: cairn_authn::AuthnError) -> Self {
        tracing::warn!(%error, "authentication error");
        Self::status(StatusCode::BAD_REQUEST, "authentication error")
    }
}

impl From<cairn_oidc::OidcError> for ApiError {
    fn from(error: cairn_oidc::OidcError) -> Self {
        tracing::error!(%error, "OIDC operation failed");
        Self::status(StatusCode::INTERNAL_SERVER_ERROR, "OIDC operation failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Payload {
        value: String,
    }

    #[tokio::test]
    async fn api_json_extractor_accepts_json_and_rejects_invalid_requests() {
        let valid = Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"value":"ok"}"#))
            .expect("valid request");
        let ApiJson(payload) = ApiJson::<Payload>::from_request(valid, &())
            .await
            .expect("valid JSON payload");
        assert_eq!(
            payload,
            Payload {
                value: "ok".to_owned()
            }
        );

        for (content_type, body, expected_message) in [
            (
                None,
                "{}".to_owned(),
                "content type must be application/json",
            ),
            (
                Some("application/json"),
                "{".to_owned(),
                "invalid JSON body",
            ),
            (
                Some("application/json"),
                "a".repeat(API_JSON_BODY_MAX_BYTES + 1),
                "JSON body too large",
            ),
        ] {
            let mut request = Request::builder().method("POST");
            if let Some(content_type) = content_type {
                request = request.header(header::CONTENT_TYPE, content_type);
            }
            let error = ApiJson::<Payload>::from_request(
                request.body(Body::from(body)).expect("valid request"),
                &(),
            )
            .await
            .expect_err("invalid request should fail");

            assert!(matches!(
                error,
                ApiError::Status {
                    status: StatusCode::BAD_REQUEST,
                    ref message,
                    ..
                } if message == expected_message
            ));
        }
    }

    #[test]
    fn rate_limited_errors_include_retry_after_header() {
        let response = ApiError::rate_limited(42).into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "42");
    }

    #[test]
    fn invalid_client_oauth_errors_include_basic_challenge() {
        let response = ApiError::oauth(StatusCode::UNAUTHORIZED, OAuthErrorBody::invalid_client())
            .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"cairn\""
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    }
}
