use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_database::ScimGroupMutationOutcome;
use cairn_domain::Group;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::super::{
    AppState,
    request_context::audit_request_context,
    scim_input::{ScimGroupRequest, scim_group_input, scim_group_slug},
    scim_protocol::{ScimError, scim_location},
    scim_resource::scim_group_resource,
};
use super::super::ScimOperationResult;

pub(in crate::http) async fn scim_create_group_operation(
    state: &AppState,
    headers: &HeaderMap,
    payload: ScimGroupRequest,
) -> Result<ScimOperationResult, ScimError> {
    let input = scim_group_input(payload)?;
    let now = OffsetDateTime::now_utc();
    let group_id = Uuid::new_v4();
    let group = Group {
        id: group_id,
        organization_id: state.organization_id,
        slug: scim_group_slug(group_id, input.external_id.as_deref(), &input.display_name)?,
        scim_external_id: input.external_id,
        display_name: input.display_name,
        created_at: now,
    };

    let group = match state
        .database
        .create_scim_group(&group, &input.member_user_ids)
        .await?
    {
        ScimGroupMutationOutcome::Applied(group) => group,
        ScimGroupMutationOutcome::SlugAlreadyExists => {
            return Err(ScimError::uniqueness(
                "displayName or externalId maps to an existing group slug",
            ));
        }
        ScimGroupMutationOutcome::ExternalIdAlreadyExists => {
            return Err(ScimError::uniqueness("externalId already exists"));
        }
        ScimGroupMutationOutcome::MemberNotFound => {
            return Err(ScimError::invalid_value(
                "members.value must reference existing users",
            ));
        }
        ScimGroupMutationOutcome::NotFound
        | ScimGroupMutationOutcome::WouldModifyProtectedGroup => {
            return Err(ScimError::server_error(
                "unexpected SCIM group create result",
            ));
        }
    };

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.group_created",
                group.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "display_name": group.display_name,
                "external_id": group.scim_external_id,
                "member_count": input.member_user_ids.len()
            }))
            .build(),
        )
        .await?;

    let members = state
        .database
        .list_scim_group_members_for_groups(state.organization_id, &[group.id])
        .await?;
    Ok(ScimOperationResult::json(
        StatusCode::CREATED,
        scim_group_resource(state, &group, &members),
        Some(scim_location(state, &format!("Groups/{}", group.id))),
    ))
}
