use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::hash_token;
use cairn_domain::AccountTokenKind;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::super::{
    AppState,
    account_lifecycle::{
        AccountLifecycleEmail, queue_account_lifecycle_email, valid_account_token,
    },
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::require_session,
};

pub(in crate::http) async fn request_email_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let user = state
        .database
        .get_user(session.user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "user missing"))?;

    if user.email_verified {
        return Ok(Json(json!({ "status": "already_verified" })).into_response());
    }

    let delivery = queue_account_lifecycle_email(
        &state,
        AccountLifecycleEmail {
            kind: AccountTokenKind::EmailVerification,
            user_id: Some(user.id),
            email: user.email.clone(),
            created_by_user_id: Some(user.id),
            ttl: Duration::hours(24),
            template: "email_verification",
            subject: "Verify your Cairn Identity email",
            action_path: "/verify-email",
            body_intro: "Verify this email address for Cairn Identity.",
            metadata: json!({}),
        },
    )
    .await?;

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                user.id,
                "account.email_verification_requested",
                user.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok(Json(delivery).into_response())
}

pub(in crate::http) async fn confirm_email_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<AccountTokenRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let token_hash = hash_token(&payload.token);
    let token =
        valid_account_token(&state, &token_hash, AccountTokenKind::EmailVerification).await?;
    let user_id = token
        .user_id
        .ok_or_else(|| ApiError::bad_request("invalid verification token"))?;
    let consumed = state
        .database
        .consume_account_token_and_set_user_email_verified(
            token.id,
            user_id,
            OffsetDateTime::now_utc(),
        )
        .await?;

    if !consumed {
        return Err(ApiError::status(
            StatusCode::BAD_REQUEST,
            "verification token expired or already used",
        ));
    }

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "account.email_verified",
                user_id.to_string(),
            )
            .metadata(json!({ "email": token.email }))
            .build(),
        )
        .await?;

    Ok(Json(json!({ "status": "ok" })).into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct AccountTokenRequest {
    token: String,
}
