use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::constants::SCIM_LIST_RESPONSE_SCHEMA;
use crate::http::{AppState, content_type::SCIM_CONTENT_TYPE};

pub(in crate::http) fn scim_json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    response
}

pub(in crate::http) fn scim_list_response(
    resources: Vec<Value>,
    total_results: i64,
    start_index: i64,
) -> Response {
    scim_json_response(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
            "totalResults": total_results,
            "startIndex": start_index,
            "itemsPerPage": resources.len(),
            "Resources": resources
        }),
    )
}

pub(in crate::http) fn scim_location(state: &AppState, suffix: &str) -> String {
    format!(
        "{}/scim/v2/{}",
        state.config.issuer.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}
