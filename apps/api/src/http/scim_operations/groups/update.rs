use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_database::{ScimGroupMutationOutcome, ScimGroupReplaceInput};
use cairn_domain::Group;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::super::{
    ADMINISTRATORS_GROUP_SLUG, AppState,
    request_context::audit_request_context,
    scim_input::{
        ScimGroupInput, ScimGroupRequest, ScimPatchRequest, scim_group_input,
        scim_patch_group_input,
    },
    scim_protocol::{ScimError, scim_location},
    scim_resource::scim_group_resource,
};
use super::super::ScimOperationResult;
use super::lookup::scim_get_tenant_group;

pub(in crate::http) async fn scim_replace_group_operation(
    state: &AppState,
    headers: &HeaderMap,
    group_id: Uuid,
    payload: ScimGroupRequest,
) -> Result<ScimOperationResult, ScimError> {
    let input = scim_group_input(payload)?;
    let member_count = input.member_user_ids.len();
    let group = scim_apply_group_replace(state, group_id, &input).await?;

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.group_replaced",
                group.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "display_name": group.display_name,
                "external_id": group.scim_external_id,
                "member_count": member_count
            }))
            .build(),
        )
        .await?;

    group_resource_result(state, StatusCode::OK, &group).await
}

pub(in crate::http) async fn scim_patch_group_operation(
    state: &AppState,
    headers: &HeaderMap,
    group_id: Uuid,
    payload: ScimPatchRequest,
) -> Result<ScimOperationResult, ScimError> {
    let current_group = scim_get_tenant_group(state, group_id).await?;
    let current_members = state
        .database
        .list_scim_group_members_for_groups(state.organization_id, &[current_group.id])
        .await?;
    let operation_count = payload.operation_count();
    let input = scim_patch_group_input(&current_group, &current_members, payload)?;
    let member_count = input.member_user_ids.len();
    let group = scim_apply_group_replace(state, group_id, &input).await?;

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.group_patched",
                group.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "display_name": group.display_name,
                "external_id": group.scim_external_id,
                "member_count": member_count,
                "operation_count": operation_count
            }))
            .build(),
        )
        .await?;

    group_resource_result(state, StatusCode::OK, &group).await
}

async fn scim_apply_group_replace(
    state: &AppState,
    group_id: Uuid,
    input: &ScimGroupInput,
) -> Result<Group, ScimError> {
    match state
        .database
        .replace_scim_group(ScimGroupReplaceInput {
            organization_id: state.organization_id,
            group_id,
            display_name: &input.display_name,
            scim_external_id: input.external_id.as_deref(),
            member_user_ids: &input.member_user_ids,
            protected_group_slug: ADMINISTRATORS_GROUP_SLUG,
            at: OffsetDateTime::now_utc(),
        })
        .await?
    {
        ScimGroupMutationOutcome::Applied(group) => Ok(group),
        ScimGroupMutationOutcome::NotFound => Err(ScimError::not_found("SCIM group not found")),
        ScimGroupMutationOutcome::ExternalIdAlreadyExists => {
            Err(ScimError::uniqueness("externalId already exists"))
        }
        ScimGroupMutationOutcome::MemberNotFound => Err(ScimError::invalid_value(
            "members.value must reference existing users",
        )),
        ScimGroupMutationOutcome::WouldModifyProtectedGroup => Err(ScimError::mutability(
            StatusCode::CONFLICT,
            "administrators group cannot be modified through SCIM",
        )),
        ScimGroupMutationOutcome::SlugAlreadyExists => Err(ScimError::server_error(
            "unexpected SCIM group replace result",
        )),
    }
}

async fn group_resource_result(
    state: &AppState,
    status: StatusCode,
    group: &Group,
) -> Result<ScimOperationResult, ScimError> {
    let members = state
        .database
        .list_scim_group_members_for_groups(state.organization_id, &[group.id])
        .await?;
    Ok(ScimOperationResult::json(
        status,
        scim_group_resource(state, group, &members),
        Some(scim_location(state, &format!("Groups/{}", group.id))),
    ))
}
