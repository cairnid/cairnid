use axum::{http::StatusCode, response::Response};
use serde_json::{Value, json};

use crate::http::{
    scim_operations::ScimOperationResult,
    scim_protocol::{
        SCIM_BULK_MAX_OPERATIONS, SCIM_ERROR_SCHEMA, ScimError, scim_error_body, scim_json_response,
    },
};

pub(in crate::http::scim_bulk) fn scim_bulk_success_response(
    method: &str,
    bulk_id: Option<String>,
    result: ScimOperationResult,
) -> Value {
    let mut response = json!({
        "method": method,
        "status": result.status.as_u16().to_string()
    });
    if let Some(bulk_id) = bulk_id {
        response["bulkId"] = json!(bulk_id);
    }
    if let Some(location) = result.location {
        response["location"] = json!(location);
    }
    if let Some(body) = result.body {
        response["response"] = body;
    }
    response
}

pub(in crate::http::scim_bulk) fn scim_bulk_error_response(
    method: &str,
    bulk_id: Option<String>,
    error: &ScimError,
) -> Value {
    let mut response = json!({
        "method": method,
        "status": error.status.as_u16().to_string(),
        "response": scim_error_body(error)
    });
    if let Some(bulk_id) = bulk_id {
        response["bulkId"] = json!(bulk_id);
    }
    response
}

pub(in crate::http::scim_bulk) fn scim_bulk_limit_response() -> Response {
    scim_json_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "detail": "SCIM Bulk operation limit exceeded",
            "status": StatusCode::PAYLOAD_TOO_LARGE.as_u16().to_string(),
            "maxOperations": SCIM_BULK_MAX_OPERATIONS
        }),
    )
}
