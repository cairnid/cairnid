use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_domain::{User, UserStatus};
use serde_json::json;

use super::super::super::{
    AppState,
    request_context::audit_request_context,
    scim_input::{ScimUserRequest, scim_user_input},
    scim_protocol::{ScimError, scim_location},
    scim_resource::scim_user_resource,
};
use super::super::ScimOperationResult;

pub(in crate::http) async fn scim_create_user_operation(
    state: &AppState,
    headers: &HeaderMap,
    payload: ScimUserRequest,
) -> Result<ScimOperationResult, ScimError> {
    let input = scim_user_input(payload)?;

    if state
        .database
        .find_user_by_email(state.organization_id, &input.email)
        .await?
        .is_some()
    {
        return Err(ScimError::uniqueness("userName already exists"));
    }
    if let Some(external_id) = input.external_id.as_deref()
        && state
            .database
            .find_user_by_scim_external_id(state.organization_id, external_id)
            .await?
            .is_some()
    {
        return Err(ScimError::uniqueness("externalId already exists"));
    }

    let mut user = User::new(state.organization_id, input.email, input.display_name)?;
    user.scim_external_id = input.external_id;
    user.email_verified = input.email_verified;
    user.status = input.status;
    state.database.create_user(&user, None).await?;

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.user_created",
                user.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "user_name": user.email,
                "external_id": user.scim_external_id,
                "active": user.status == UserStatus::Active
            }))
            .build(),
        )
        .await?;

    let location = scim_location(state, &format!("Users/{}", user.id));
    Ok(ScimOperationResult::json(
        StatusCode::CREATED,
        scim_user_resource(state, &user),
        Some(location),
    ))
}
