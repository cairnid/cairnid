use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_database::ScimGroupMutationOutcome;
use serde_json::json;
use uuid::Uuid;

use super::super::super::{
    ADMINISTRATORS_GROUP_SLUG, AppState,
    request_context::audit_request_context,
    scim_protocol::{ScimError, scim_location},
};
use super::super::ScimOperationResult;

pub(in crate::http) async fn scim_delete_group_operation(
    state: &AppState,
    headers: &HeaderMap,
    group_id: Uuid,
) -> Result<ScimOperationResult, ScimError> {
    let group = match state
        .database
        .delete_scim_group(state.organization_id, group_id, ADMINISTRATORS_GROUP_SLUG)
        .await?
    {
        ScimGroupMutationOutcome::Applied(group) => group,
        ScimGroupMutationOutcome::NotFound => {
            return Err(ScimError::not_found("SCIM group not found"));
        }
        ScimGroupMutationOutcome::WouldModifyProtectedGroup => {
            return Err(ScimError::mutability(
                StatusCode::CONFLICT,
                "administrators group cannot be modified through SCIM",
            ));
        }
        ScimGroupMutationOutcome::SlugAlreadyExists
        | ScimGroupMutationOutcome::ExternalIdAlreadyExists
        | ScimGroupMutationOutcome::MemberNotFound => {
            return Err(ScimError::server_error(
                "unexpected SCIM group delete result",
            ));
        }
    };

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.group_deleted",
                group.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "display_name": group.display_name,
                "external_id": group.scim_external_id
            }))
            .build(),
        )
        .await?;

    Ok(ScimOperationResult::no_content(Some(scim_location(
        state,
        &format!("Groups/{}", group.id),
    ))))
}
