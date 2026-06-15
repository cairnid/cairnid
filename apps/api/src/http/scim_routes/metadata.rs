use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;

use super::super::{
    AppState,
    scim_auth::require_scim_bearer,
    scim_metadata::{
        scim_group_resource_type, scim_group_schema_resource, scim_user_resource_type,
        scim_user_schema_resource,
    },
    scim_protocol::{
        SCIM_BULK_MAX_OPERATIONS, SCIM_GROUP_SCHEMA, SCIM_JSON_BODY_MAX_BYTES, SCIM_MAX_COUNT,
        SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA, SCIM_USER_SCHEMA, ScimError, scim_json_response,
        scim_list_response, scim_location,
    },
};

pub(in crate::http) async fn scim_service_provider_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    Ok(scim_json_response(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
            "documentationUri": format!("{}/docs/scim", state.config.issuer.trim_end_matches('/')),
            "patch": { "supported": true },
            "bulk": {
                "supported": true,
                "maxOperations": SCIM_BULK_MAX_OPERATIONS,
                "maxPayloadSize": SCIM_JSON_BODY_MAX_BYTES
            },
            "filter": { "supported": true, "maxResults": SCIM_MAX_COUNT },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "cursorPagination": { "supported": false },
            "securityEvents": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "SCIM requests use an operator-provisioned bearer token hash.",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": true
            }],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": scim_location(&state, "ServiceProviderConfig")
            }
        }),
    ))
}

pub(in crate::http) async fn scim_schemas(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    Ok(scim_list_response(
        vec![
            scim_user_schema_resource(&state),
            scim_group_schema_resource(&state),
        ],
        2,
        1,
    ))
}

pub(in crate::http) async fn scim_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(schema_id): Path<String>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let resource = if schema_id == SCIM_USER_SCHEMA {
        scim_user_schema_resource(&state)
    } else if schema_id == SCIM_GROUP_SCHEMA {
        scim_group_schema_resource(&state)
    } else {
        return Err(ScimError::not_found("SCIM schema not found"));
    };
    Ok(scim_json_response(StatusCode::OK, resource))
}

pub(in crate::http) async fn scim_resource_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    Ok(scim_list_response(
        vec![
            scim_user_resource_type(&state),
            scim_group_resource_type(&state),
        ],
        2,
        1,
    ))
}

pub(in crate::http) async fn scim_resource_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_type): Path<String>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let resource = if resource_type.eq_ignore_ascii_case("User") {
        scim_user_resource_type(&state)
    } else if resource_type.eq_ignore_ascii_case("Group") {
        scim_group_resource_type(&state)
    } else {
        return Err(ScimError::not_found("SCIM resource type not found"));
    };
    Ok(scim_json_response(StatusCode::OK, resource))
}
