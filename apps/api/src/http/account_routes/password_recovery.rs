use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::{hash_password, hash_token};
use cairn_database::{PasswordRecoveryInput, PasswordRecoveryOutcome};
use cairn_domain::{AccountTokenKind, UserStatus};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::super::{
    ACCOUNT_RECOVERY_RATE_LIMIT_BLOCK, ACCOUNT_RECOVERY_RATE_LIMIT_MAX_ATTEMPTS,
    ACCOUNT_RECOVERY_RATE_LIMIT_WINDOW, AppState,
    account_lifecycle::{
        AccountLifecycleEmail, password_recovery_completed_notification_email,
        password_recovery_response, queue_account_lifecycle_email, valid_account_token,
        valid_new_password,
    },
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    request_context::{
        RequestIdentity, account_recovery_rate_limit_keys, audit_request_context_for_identity,
        enforce_rate_limit, record_rate_limit_failure,
    },
};

pub(in crate::http) async fn request_password_recovery(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<PasswordRecoveryRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let email = cairn_domain::normalize_email(payload.email)?;
    let rate_limit_keys =
        account_recovery_rate_limit_keys(state.organization_id, &request_identity);
    enforce_rate_limit(&state, &rate_limit_keys).await?;
    record_rate_limit_failure(
        &state,
        &rate_limit_keys,
        ACCOUNT_RECOVERY_RATE_LIMIT_WINDOW,
        ACCOUNT_RECOVERY_RATE_LIMIT_MAX_ATTEMPTS,
        ACCOUNT_RECOVERY_RATE_LIMIT_BLOCK,
    )
    .await?;

    let mut queued_delivery = None;
    if let Some(user_with_password) = state
        .database
        .find_user_by_email(state.organization_id, &email)
        .await?
        && user_with_password.password_hash.is_some()
        && user_with_password.user.status == UserStatus::Active
    {
        queued_delivery = Some(
            queue_account_lifecycle_email(
                &state,
                AccountLifecycleEmail {
                    kind: AccountTokenKind::PasswordRecovery,
                    user_id: Some(user_with_password.user.id),
                    email: user_with_password.user.email.clone(),
                    created_by_user_id: None,
                    ttl: Duration::hours(1),
                    template: "password_recovery",
                    subject: "Reset your Cairn Identity password",
                    action_path: "/reset-password",
                    body_intro: "Reset your Cairn Identity password.",
                    metadata: json!({}),
                },
            )
            .await?,
        );
        state
            .database
            .insert_audit_event(
                &AuditEventBuilder::system(
                    state.organization_id,
                    "account.password_recovery_requested",
                    user_with_password.user.id.to_string(),
                )
                .build(),
            )
            .await?;
    }

    Ok(Json(password_recovery_response(
        state.config.environment,
        queued_delivery,
    ))
    .into_response())
}

pub(in crate::http) async fn complete_password_recovery(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CompletePasswordRecoveryRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let token_hash = hash_token(&payload.token);
    let token =
        valid_account_token(&state, &token_hash, AccountTokenKind::PasswordRecovery).await?;
    let user_id = token
        .user_id
        .ok_or_else(|| ApiError::bad_request("invalid recovery token"))?;
    let password_hash = hash_password(&SecretString::from(valid_new_password(payload.password)?))?;
    let now = OffsetDateTime::now_utc();
    let (ip_address, user_agent) = audit_request_context_for_identity(&request_identity, &headers);
    let notification = password_recovery_completed_notification_email(
        &state,
        &token,
        user_id,
        ip_address.as_deref(),
        user_agent.as_deref(),
        now,
    );
    let mutation = match state
        .database
        .consume_password_recovery_token_and_reset_user_password(PasswordRecoveryInput {
            organization_id: token.organization_id,
            user_id,
            token_id: token.id,
            password_hash: &password_hash,
            notification: Some(&notification),
            at: now,
        })
        .await?
    {
        PasswordRecoveryOutcome::Applied(mutation) => *mutation,
        PasswordRecoveryOutcome::NotFound => {
            return Err(ApiError::status(
                StatusCode::BAD_REQUEST,
                "recovery token expired or already used",
            ));
        }
    };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "account.password_recovered",
                user_id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "email": token.email,
                "sessions_revoked": mutation.sessions_revoked,
                "access_tokens_revoked": mutation.access_tokens_revoked,
                "refresh_tokens_revoked": mutation.refresh_tokens_revoked,
                "account_tokens_consumed": mutation.account_tokens_consumed,
                "notification_email_outbox_id": mutation.notification_email_outbox_id
            }))
            .build(),
        )
        .await?;

    Ok(Json(json!({
        "status": "ok",
        "sessions_revoked": mutation.sessions_revoked,
        "access_tokens_revoked": mutation.access_tokens_revoked,
        "refresh_tokens_revoked": mutation.refresh_tokens_revoked,
        "account_tokens_consumed": mutation.account_tokens_consumed
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct PasswordRecoveryRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CompletePasswordRecoveryRequest {
    token: String,
    password: String,
}
