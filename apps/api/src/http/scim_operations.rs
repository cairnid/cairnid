use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use super::scim_protocol::{ScimError, scim_json_response};

mod groups;
mod users;

pub(super) use self::groups::{
    scim_create_group_operation, scim_delete_group_operation, scim_get_tenant_group,
    scim_patch_group_operation, scim_replace_group_operation,
};
pub(super) use self::users::{
    scim_create_user_operation, scim_delete_user_operation, scim_get_tenant_user,
    scim_patch_user_operation, scim_replace_user_operation,
};

#[derive(Debug)]
pub(super) struct ScimOperationResult {
    pub(super) status: StatusCode,
    pub(super) location: Option<String>,
    pub(super) body: Option<Value>,
}

impl ScimOperationResult {
    pub(super) fn json(status: StatusCode, body: Value, location: Option<String>) -> Self {
        Self {
            status,
            location,
            body: Some(body),
        }
    }

    fn no_content(location: Option<String>) -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            location,
            body: None,
        }
    }

    pub(super) fn into_http_response(self) -> Result<Response, ScimError> {
        let mut response = if let Some(body) = self.body {
            scim_json_response(self.status, body)
        } else {
            self.status.into_response()
        };
        if self.status == StatusCode::CREATED
            && let Some(location) = self.location
        {
            let location = HeaderValue::from_str(&location)
                .map_err(|_| ScimError::server_error("invalid SCIM resource location"))?;
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn scim_operation_created_response_sets_location_header() {
        let response = ScimOperationResult::json(
            StatusCode::CREATED,
            json!({ "id": "resource-id" }),
            Some("https://issuer.example/scim/v2/Users/resource-id".to_owned()),
        )
        .into_http_response()
        .expect("operation response");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://issuer.example/scim/v2/Users/resource-id"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json body"),
            json!({ "id": "resource-id" })
        );
    }

    #[tokio::test]
    async fn scim_operation_no_content_response_has_empty_body() {
        let response = ScimOperationResult::no_content(Some(
            "https://issuer.example/scim/v2/Groups/group-id".to_owned(),
        ))
        .into_http_response()
        .expect("operation response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get(header::LOCATION).is_none());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(body.is_empty());
    }
}
