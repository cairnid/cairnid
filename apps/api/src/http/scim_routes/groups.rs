use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use super::super::{
    AppState,
    scim_auth::require_scim_bearer,
    scim_input::{ScimGroupRequest, ScimPatchRequest},
    scim_operations::{
        scim_create_group_operation, scim_delete_group_operation, scim_get_tenant_group,
        scim_patch_group_operation, scim_replace_group_operation,
    },
    scim_projection::{ScimResourceKind, scim_apply_projection, scim_resource_projection_query},
    scim_protocol::{ScimError, ScimJson, scim_json_response, scim_list_response},
    scim_query::{
        ScimGroupListQuery, ScimSearchRequest, reject_scim_search_query, scim_group_list_query,
        scim_group_search_query,
    },
    scim_resource::{scim_group_members_by_group, scim_group_resource},
};

pub(in crate::http) async fn scim_list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let query = scim_group_list_query(raw_query.as_deref())?;
    scim_group_list_response_for_query(&state, &query).await
}

pub(in crate::http) async fn scim_search_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    ScimJson(payload): ScimJson<ScimSearchRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    reject_scim_search_query(raw_query.as_deref())?;
    let query = scim_group_search_query(payload)?;
    scim_group_list_response_for_query(&state, &query).await
}

async fn scim_group_list_response_for_query(
    state: &AppState,
    query: &ScimGroupListQuery,
) -> Result<Response, ScimError> {
    let (total_results, groups) = state
        .database
        .list_scim_groups_page_filtered(
            state.organization_id,
            &query.filter,
            query.start_index,
            query.count,
        )
        .await?;
    let group_ids = groups.iter().map(|group| group.id).collect::<Vec<_>>();
    let members = state
        .database
        .list_scim_group_members_for_groups(state.organization_id, &group_ids)
        .await?;
    let members_by_group = scim_group_members_by_group(members);
    let resources = groups
        .iter()
        .map(|group| {
            let members = members_by_group
                .get(&group.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            scim_apply_projection(
                scim_group_resource(state, group, members),
                &query.projection,
            )
        })
        .collect::<Vec<_>>();

    Ok(scim_list_response(
        resources,
        total_results,
        query.start_index,
    ))
}

pub(in crate::http) async fn scim_create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    ScimJson(payload): ScimJson<ScimGroupRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_create_group_operation(&state, &headers, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    let projection = scim_resource_projection_query(
        raw_query.as_deref(),
        ScimResourceKind::Group,
        "SCIM group query",
    )?;
    let group = scim_get_tenant_group(&state, group_id).await?;
    let members = state
        .database
        .list_scim_group_members_for_groups(state.organization_id, &[group.id])
        .await?;
    Ok(scim_json_response(
        StatusCode::OK,
        scim_apply_projection(scim_group_resource(&state, &group, &members), &projection),
    ))
}

pub(in crate::http) async fn scim_replace_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    ScimJson(payload): ScimJson<ScimGroupRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_replace_group_operation(&state, &headers, group_id, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    ScimJson(payload): ScimJson<ScimPatchRequest>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_patch_group_operation(&state, &headers, group_id, payload)
        .await?
        .into_http_response()
}

pub(in crate::http) async fn scim_delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<Response, ScimError> {
    require_scim_bearer(&state, &headers)?;
    scim_delete_group_operation(&state, &headers, group_id)
        .await?
        .into_http_response()
}
