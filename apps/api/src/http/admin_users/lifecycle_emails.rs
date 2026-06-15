use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_domain::{AccountTokenKind, UserStatus};
use serde_json::json;
use time::Duration;
use uuid::Uuid;

use super::super::{
    AppState,
    account_lifecycle::{AccountLifecycleEmail, queue_account_lifecycle_email},
    api_response::ApiError,
    cookies::require_csrf,
    request_context::audit_request_context,
    session_auth::require_recent_admin_session,
};

pub(in crate::http) async fn request_admin_user_email_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let user = state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "user not found"))?
        .user;

    if user.email_verified {
        return Ok(Json(json!({ "status": "already_verified" })).into_response());
    }

    if user.status != UserStatus::Active {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "user must be active",
        ));
    }

    let delivery = queue_account_lifecycle_email(
        &state,
        AccountLifecycleEmail {
            kind: AccountTokenKind::EmailVerification,
            user_id: Some(user.id),
            email: user.email.clone(),
            created_by_user_id: Some(actor.user_id),
            ttl: Duration::hours(24),
            template: "email_verification",
            subject: "Verify your Cairn Identity email",
            action_path: "/verify-email",
            body_intro: "Verify this email address for Cairn Identity.",
            metadata: json!({
                "created_by_user_id": actor.user_id,
                "initiator": "admin"
            }),
        },
    )
    .await?;

    let (ip_address, user_agent) = audit_request_context(&headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.email_verification_requested",
                user.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({ "email": user.email }))
            .build(),
        )
        .await?;

    Ok(Json(delivery).into_response())
}

pub(in crate::http) async fn request_admin_user_password_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let user_with_password = state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "user not found"))?;

    if user_with_password.user.status != UserStatus::Active {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "user must be active",
        ));
    }

    if user_with_password.password_hash.is_none() {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "user does not have password credentials",
        ));
    }

    let delivery = queue_account_lifecycle_email(
        &state,
        AccountLifecycleEmail {
            kind: AccountTokenKind::PasswordRecovery,
            user_id: Some(user_with_password.user.id),
            email: user_with_password.user.email.clone(),
            created_by_user_id: Some(actor.user_id),
            ttl: Duration::hours(1),
            template: "password_recovery",
            subject: "Reset your Cairn Identity password",
            action_path: "/reset-password",
            body_intro: "Reset your Cairn Identity password.",
            metadata: json!({
                "created_by_user_id": actor.user_id,
                "initiator": "admin"
            }),
        },
    )
    .await?;

    let (ip_address, user_agent) = audit_request_context(&headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.password_recovery_requested",
                user_with_password.user.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({ "email": user_with_password.user.email }))
            .build(),
        )
        .await?;

    Ok(Json(delivery).into_response())
}
