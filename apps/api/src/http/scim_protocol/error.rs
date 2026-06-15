use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{constants::SCIM_ERROR_SCHEMA, response::scim_json_response};

#[derive(Debug)]
pub(in crate::http) struct ScimError {
    pub(in crate::http) status: StatusCode,
    pub(in crate::http) detail: String,
    pub(in crate::http) scim_type: Option<&'static str>,
    www_authenticate: Option<HeaderValue>,
}

impl ScimError {
    fn new(status: StatusCode, detail: impl Into<String>, scim_type: Option<&'static str>) -> Self {
        Self {
            status,
            detail: detail.into(),
            scim_type,
            www_authenticate: None,
        }
    }

    pub(in crate::http) fn invalid_value(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail, Some("invalidValue"))
    }

    pub(in crate::http) fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail, Some("invalidFilter"))
    }

    pub(in crate::http) fn invalid_path(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail, Some("invalidPath"))
    }

    pub(in crate::http) fn no_target(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail, Some("noTarget"))
    }

    pub(in crate::http) fn uniqueness(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, detail, Some("uniqueness"))
    }

    pub(in crate::http) fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, detail, None)
    }

    pub(in crate::http) fn mutability(status: StatusCode, detail: impl Into<String>) -> Self {
        Self::new(status, detail, Some("mutability"))
    }

    pub(in crate::http) fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, detail, None)
    }

    pub(in crate::http) fn unauthorized(detail: impl Into<String>) -> Self {
        let mut error = Self::new(StatusCode::UNAUTHORIZED, detail, None);
        error.www_authenticate = Some(HeaderValue::from_static(r#"Bearer realm="SCIM""#));
        error
    }

    pub(in crate::http) fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, detail, None)
    }

    pub(in crate::http) fn server_error(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, detail, None)
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut response = scim_json_response(self.status, scim_error_body(&self));
        if let Some(value) = self.www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

pub(in crate::http) fn scim_error_body(error: &ScimError) -> Value {
    let mut body = json!({
        "schemas": [SCIM_ERROR_SCHEMA],
        "detail": error.detail.as_str(),
        "status": error.status.as_u16().to_string()
    });
    if let Some(scim_type) = error.scim_type {
        body["scimType"] = json!(scim_type);
    }
    body
}

impl From<cairn_database::DatabaseError> for ScimError {
    fn from(error: cairn_database::DatabaseError) -> Self {
        tracing::error!(%error, "database error");
        Self::server_error("database error")
    }
}

impl From<cairn_domain::DomainError> for ScimError {
    fn from(error: cairn_domain::DomainError) -> Self {
        Self::invalid_value(error.to_string())
    }
}
