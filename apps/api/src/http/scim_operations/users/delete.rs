use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_database::UserStatusMutationOutcome;
use cairn_domain::UserStatus;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::super::{
    ADMINISTRATORS_GROUP_SLUG, AppState,
    request_context::audit_request_context,
    scim_protocol::{ScimError, scim_location},
};
use super::super::ScimOperationResult;

pub(in crate::http) async fn scim_delete_user_operation(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
) -> Result<ScimOperationResult, ScimError> {
    let now = OffsetDateTime::now_utc();
    let user = match state
        .database
        .update_user_status(
            state.organization_id,
            user_id,
            UserStatus::Suspended,
            ADMINISTRATORS_GROUP_SLUG,
            now,
        )
        .await?
    {
        UserStatusMutationOutcome::Applied(user) => user,
        UserStatusMutationOutcome::NotFound => {
            return Err(ScimError::not_found("SCIM user not found"));
        }
        UserStatusMutationOutcome::WouldDeactivateLastOwner => {
            return Err(ScimError::mutability(
                StatusCode::CONFLICT,
                "administrators group must keep at least one active owner",
            ));
        }
    };

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.user_deprovisioned",
                user.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "user_name": user.email,
                "external_id": user.scim_external_id,
                "active": false
            }))
            .build(),
        )
        .await?;

    Ok(ScimOperationResult::no_content(Some(scim_location(
        state,
        &format!("Users/{}", user.id),
    ))))
}
