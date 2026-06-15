use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;

use super::{
    AppState,
    scim_auth::require_scim_bearer,
    scim_protocol::{
        SCIM_BULK_MAX_OPERATIONS, SCIM_BULK_REQUEST_SCHEMA, SCIM_BULK_RESPONSE_SCHEMA, ScimError,
        ScimJson, scim_json_response,
    },
};

mod contract;
mod job;
mod operations;
mod references;
#[cfg(test)]
mod tests;

use self::contract::{
    ScimBulkRequest, scim_bulk_fail_on_errors, scim_bulk_job_operations, scim_bulk_limit_response,
    validate_scim_bulk_ids,
};
use self::job::execute_scim_bulk_job;

pub(super) async fn scim_bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    ScimJson(payload): ScimJson<ScimBulkRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    if !payload
        .schemas
        .iter()
        .any(|schema| schema == SCIM_BULK_REQUEST_SCHEMA)
    {
        return Err(ScimError::invalid_value(
            "SCIM Bulk request must include BulkRequest schema",
        ));
    }
    if payload.operations.is_empty() {
        return Err(ScimError::invalid_value(
            "SCIM Bulk request must include at least one operation",
        ));
    }
    if payload.operations.len() > SCIM_BULK_MAX_OPERATIONS {
        return Ok(scim_bulk_limit_response());
    }
    let fail_on_errors = scim_bulk_fail_on_errors(payload.fail_on_errors)?;
    validate_scim_bulk_ids(&payload.operations)?;

    let operations = scim_bulk_job_operations(payload.operations)?;
    let responses = execute_scim_bulk_job(&state, &headers, operations, fail_on_errors).await?;

    Ok(scim_json_response(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
            "Operations": responses
        }),
    ))
}
