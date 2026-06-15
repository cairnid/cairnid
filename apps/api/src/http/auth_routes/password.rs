use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::{hash_password, verify_password};
use cairn_database::{PasswordChangeInput, PasswordChangeOutcome, SessionRequestContext};
use cairn_domain::UserStatus;
use secrecy::SecretString;
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;

use super::super::{
    AppState, REAUTHENTICATION_RATE_LIMIT_BLOCK, REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS,
    REAUTHENTICATION_RATE_LIMIT_WINDOW,
    account_lifecycle::{password_change_notification_email, valid_new_password},
    api_response::{ApiError, ApiJson},
    cookies::{require_csrf, set_session_cookie},
    mfa::{
        active_second_factor_count, authenticated_session, require_recent_mfa_proof,
        rotated_session_preserving_auth_context,
    },
    request_context::{
        RequestIdentity, audit_request_context_for_identity, enforce_rate_limit,
        reauthentication_rate_limit_keys_for_identity, record_rate_limit_failure,
    },
    session_auth::require_session,
};
use super::requests::ChangePasswordRequest;

pub(in crate::http) async fn change_password(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ChangePasswordRequest>,
) -> Result<Response, ApiError> {
    let current_session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let rate_limit_keys = reauthentication_rate_limit_keys_for_identity(
        current_session.organization_id,
        current_session.user_id,
        &request_identity,
    );
    enforce_rate_limit(&state, &rate_limit_keys).await?;

    let user_with_password = state
        .database
        .get_user_with_password(current_session.organization_id, current_session.user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "user missing"))?;
    let Some(current_password_hash) = user_with_password.password_hash.as_deref() else {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "password authentication unavailable",
        ));
    };
    if user_with_password.user.status != UserStatus::Active {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "user is not active",
        ));
    }
    if verify_password(
        &SecretString::from(payload.current_password),
        current_password_hash,
    )
    .is_err()
    {
        record_rate_limit_failure(
            &state,
            &rate_limit_keys,
            REAUTHENTICATION_RATE_LIMIT_WINDOW,
            REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS,
            REAUTHENTICATION_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let has_active_second_factor = active_second_factor_count(
        &state,
        current_session.organization_id,
        current_session.user_id,
    )
    .await?
        > 0;
    if has_active_second_factor {
        require_recent_mfa_proof(&current_session, now)?;
    }

    let new_password = valid_new_password(payload.new_password)?;
    if verify_password(
        &SecretString::from(new_password.clone()),
        current_password_hash,
    )
    .is_ok()
    {
        return Err(ApiError::bad_request(
            "new password must differ from current password",
        ));
    }
    let new_password_hash = hash_password(&SecretString::from(new_password))?;
    let new_session = if has_active_second_factor {
        rotated_session_preserving_auth_context(&current_session, now)
    } else {
        authenticated_session(
            current_session.organization_id,
            current_session.user_id,
            None,
            now,
        )
    };
    let (ip_address, user_agent) = audit_request_context_for_identity(&request_identity, &headers);
    let notification = password_change_notification_email(
        &state,
        &user_with_password.user,
        &new_session,
        ip_address.as_deref(),
        user_agent.as_deref(),
        now,
    );
    let mutation = match state
        .database
        .change_user_password_and_rotate_session(PasswordChangeInput {
            organization_id: current_session.organization_id,
            user_id: current_session.user_id,
            password_hash: &new_password_hash,
            new_session: &new_session,
            request_context: SessionRequestContext::new(
                ip_address.as_deref(),
                user_agent.as_deref(),
            ),
            notification: Some(&notification),
            at: now,
        })
        .await?
    {
        PasswordChangeOutcome::Applied(mutation) => *mutation,
        PasswordChangeOutcome::NotFound => {
            return Err(ApiError::status(StatusCode::UNAUTHORIZED, "user missing"));
        }
    };

    state
        .database
        .clear_rate_limit_bucket(rate_limit_keys[0].bucket_key())
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                mutation.session.organization_id,
                mutation.session.user_id,
                "account.password_changed",
                mutation.session.user_id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "previous_session_id": current_session.id,
                "new_session_id": mutation.session.id,
                "sessions_revoked": mutation.sessions_revoked,
                "access_tokens_revoked": mutation.access_tokens_revoked,
                "refresh_tokens_revoked": mutation.refresh_tokens_revoked,
                "account_tokens_consumed": mutation.account_tokens_consumed,
                "notification_email_outbox_id": mutation.notification_email_outbox_id
            }))
            .build(),
        )
        .await?;

    let mut response = Json(ChangePasswordResponse {
        status: "changed",
        sessions_revoked: mutation.sessions_revoked,
        access_tokens_revoked: mutation.access_tokens_revoked,
        refresh_tokens_revoked: mutation.refresh_tokens_revoked,
        account_tokens_consumed: mutation.account_tokens_consumed,
        acr: mutation.session.acr.clone(),
        amr: mutation.session.amr.clone(),
    })
    .into_response();
    set_session_cookie(response.headers_mut(), &state.config, mutation.session.id)?;
    Ok(response)
}

#[derive(Debug, Serialize)]
struct ChangePasswordResponse {
    status: &'static str,
    sessions_revoked: u64,
    access_tokens_revoked: u64,
    refresh_tokens_revoked: u64,
    account_tokens_consumed: u64,
    acr: String,
    amr: Vec<String>,
}
