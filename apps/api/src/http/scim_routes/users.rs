use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use super::super::{
    AppState,
    scim_auth::require_scim_bearer,
    scim_input::{ScimPatchRequest, ScimUserRequest},
    scim_operations::{
        scim_create_user_operation, scim_delete_user_operation, scim_get_tenant_user,
        scim_patch_user_operation, scim_replace_user_operation,
    },
    scim_projection::{ScimResourceKind, scim_apply_projection, scim_resource_projection_query},
    scim_protocol::{ScimError, ScimJson, scim_json_response, scim_list_response},
    scim_query::{
        ScimSearchRequest, ScimUserListQuery, reject_scim_search_query, scim_user_list_query,
        scim_user_search_query,
    },
    scim_resource::scim_user_resource,
};

pub(in crate::http) async fn scim_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let query = scim_user_list_query(raw_query.as_deref())?;
    scim_user_list_response_for_query(&state, &query).await
}

pub(in crate::http) async fn scim_search_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    ScimJson(payload): ScimJson<ScimSearchRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    reject_scim_search_query(raw_query.as_deref())?;
    let query = scim_user_search_query(payload)?;
    scim_user_list_response_for_query(&state, &query).await
}

async fn scim_user_list_response_for_query(
    state: &AppState,
    query: &ScimUserListQuery,
) -> Result<Response, ScimError> {
    let (total_results, users) = state
        .database
        .list_scim_users_page_filtered(
            state.organization_id,
            &query.filter,
            query.start_index,
            query.count,
        )
        .await?;
    let resources = users
        .iter()
        .map(|user| scim_apply_projection(scim_user_resource(state, user), &query.projection))
        .collect::<Vec<_>>();
    Ok(scim_list_response(
        resources,
        total_results,
        query.start_index,
    ))
}

pub(in crate::http) async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    ScimJson(payload): ScimJson<ScimUserRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_create_user_operation(&state, &headers, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let projection = scim_resource_projection_query(
        raw_query.as_deref(),
        ScimResourceKind::User,
        "SCIM user query",
    )?;
    let user = scim_get_tenant_user(&state, user_id).await?;
    Ok(scim_json_response(
        StatusCode::OK,
        scim_apply_projection(scim_user_resource(&state, &user), &projection),
    ))
}

pub(in crate::http) async fn scim_replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    ScimJson(payload): ScimJson<ScimUserRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_replace_user_operation(&state, &headers, user_id, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    ScimJson(payload): ScimJson<ScimPatchRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_patch_user_operation(&state, &headers, user_id, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_delete_user_operation(&state, &headers, user_id)
        .await?
        .into_http_response()
}
