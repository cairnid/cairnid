use axum::http::{HeaderMap, StatusCode};
use cairn_audit::AuditEventBuilder;
use cairn_database::{ScimUserUpdateInput, ScimUserUpdateOutcome};
use cairn_domain::{User, UserStatus};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::super::{
    ADMINISTRATORS_GROUP_SLUG, AppState,
    request_context::audit_request_context,
    scim_input::{
        ScimPatchRequest, ScimUserInput, ScimUserRequest, scim_patch_user_input, scim_user_input,
    },
    scim_protocol::{ScimError, scim_location},
    scim_resource::scim_user_resource,
};
use super::super::ScimOperationResult;
use super::lookup::scim_get_tenant_user;

pub(in crate::http) async fn scim_replace_user_operation(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
    payload: ScimUserRequest,
) -> Result<ScimOperationResult, ScimError> {
    let input = scim_user_input(payload)?;
    let user = scim_apply_user_update(state, user_id, &input).await?;

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.user_replaced",
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

    user_resource_result(state, StatusCode::OK, &user)
}

pub(in crate::http) async fn scim_patch_user_operation(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
    payload: ScimPatchRequest,
) -> Result<ScimOperationResult, ScimError> {
    let current_user = scim_get_tenant_user(state, user_id).await?;
    let operation_count = payload.operation_count();
    let input = scim_patch_user_input(&current_user, payload)?;
    let user = scim_apply_user_update(state, user_id, &input).await?;

    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "scim.user_patched",
                user.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "user_name": user.email,
                "external_id": user.scim_external_id,
                "active": user.status == UserStatus::Active,
                "operation_count": operation_count
            }))
            .build(),
        )
        .await?;

    user_resource_result(state, StatusCode::OK, &user)
}

async fn scim_apply_user_update(
    state: &AppState,
    user_id: Uuid,
    input: &ScimUserInput,
) -> Result<User, ScimError> {
    match state
        .database
        .update_user_from_scim(ScimUserUpdateInput {
            organization_id: state.organization_id,
            user_id,
            email: &input.email,
            scim_external_id: input.external_id.as_deref(),
            email_verified: input.email_verified,
            display_name: &input.display_name,
            status: input.status,
            protected_owner_group_slug: ADMINISTRATORS_GROUP_SLUG,
            at: OffsetDateTime::now_utc(),
        })
        .await?
    {
        ScimUserUpdateOutcome::Applied(user) => Ok(user),
        ScimUserUpdateOutcome::NotFound => Err(ScimError::not_found("SCIM user not found")),
        ScimUserUpdateOutcome::WouldDeactivateLastOwner => Err(ScimError::mutability(
            StatusCode::CONFLICT,
            "administrators group must keep at least one active owner",
        )),
        ScimUserUpdateOutcome::EmailAlreadyExists => {
            Err(ScimError::uniqueness("userName already exists"))
        }
        ScimUserUpdateOutcome::ExternalIdAlreadyExists => {
            Err(ScimError::uniqueness("externalId already exists"))
        }
    }
}

fn user_resource_result(
    state: &AppState,
    status: StatusCode,
    user: &User,
) -> Result<ScimOperationResult, ScimError> {
    Ok(ScimOperationResult::json(
        status,
        scim_user_resource(state, user),
        Some(scim_location(state, &format!("Users/{}", user.id))),
    ))
}
