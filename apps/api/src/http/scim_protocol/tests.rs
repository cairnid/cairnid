use axum::{
    body::to_bytes,
    http::{StatusCode, header},
    response::IntoResponse,
};
use serde_json::{Value, json};

use super::constants::SCIM_LIST_RESPONSE_SCHEMA;
use super::{SCIM_ERROR_SCHEMA, ScimError, scim_error_body, scim_list_response};
use crate::http::content_type::SCIM_CONTENT_TYPE;

#[test]
fn error_body_uses_scim_error_schema_and_status_string() {
    let error = ScimError::invalid_path("unsupported SCIM Bulk path");

    assert_eq!(
        scim_error_body(&error),
        json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "detail": "unsupported SCIM Bulk path",
            "status": "400",
            "scimType": "invalidPath"
        })
    );
}

#[test]
fn unauthorized_errors_include_bearer_challenge() {
    let response = ScimError::unauthorized("missing bearer token").into_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer realm="SCIM""#
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        SCIM_CONTENT_TYPE
    );
}

#[tokio::test]
async fn list_response_uses_scim_list_shape() {
    let response = scim_list_response(vec![json!({ "id": "user-id" })], 3, 2);

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        SCIM_CONTENT_TYPE
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("SCIM list body");
    let payload: Value = serde_json::from_slice(&body).expect("SCIM list JSON");
    assert_eq!(payload["schemas"], json!([SCIM_LIST_RESPONSE_SCHEMA]));
    assert_eq!(payload["totalResults"], json!(3));
    assert_eq!(payload["startIndex"], json!(2));
    assert_eq!(payload["itemsPerPage"], json!(1));
    assert_eq!(payload["Resources"][0]["id"], json!("user-id"));
}
