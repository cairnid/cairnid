use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::{hash_password, hash_token};
use cairn_domain::{AccountTokenKind, User};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::super::{
    AppState,
    account_lifecycle::{
        AccountLifecycleEmail, queue_account_lifecycle_email, valid_account_token,
        valid_new_password,
    },
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::require_recent_admin_session,
};

pub(in crate::http) async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateInvitationRequest>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let email = cairn_domain::normalize_email(payload.email)?;

    let user = match state
        .database
        .find_user_by_email(state.organization_id, &email)
        .await?
    {
        Some(existing) if existing.password_hash.is_some() => {
            return Err(ApiError::status(
                StatusCode::CONFLICT,
                "user already has credentials",
            ));
        }
        Some(existing) => existing.user,
        None => {
            let user = User::new(state.organization_id, email.clone(), payload.display_name)?;
            state.database.create_user(&user, None).await?;
            user
        }
    };

    let delivery = queue_account_lifecycle_email(
        &state,
        AccountLifecycleEmail {
            kind: AccountTokenKind::Invitation,
            user_id: Some(user.id),
            email: user.email.clone(),
            created_by_user_id: Some(actor.user_id),
            ttl: Duration::days(7),
            template: "account_invitation",
            subject: "Accept your Cairn Identity invitation",
            action_path: "/accept-invitation",
            body_intro: "You have been invited to Cairn Identity.",
            metadata: json!({ "created_by_user_id": actor.user_id }),
        },
    )
    .await?;

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.invitation_created",
                user.id.to_string(),
            )
            .metadata(json!({ "email": user.email }))
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(delivery)).into_response())
}

pub(in crate::http) async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<AcceptInvitationRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let token_hash = hash_token(&payload.token);
    let token = valid_account_token(&state, &token_hash, AccountTokenKind::Invitation).await?;
    let user_id = token
        .user_id
        .ok_or_else(|| ApiError::bad_request("invalid invitation token"))?;
    let password_hash = hash_password(&SecretString::from(valid_new_password(payload.password)?))?;
    let consumed = state
        .database
        .consume_account_token_and_set_user_password(
            token.id,
            user_id,
            &password_hash,
            true,
            false,
            OffsetDateTime::now_utc(),
        )
        .await?;

    if !consumed {
        return Err(ApiError::status(
            StatusCode::BAD_REQUEST,
            "invitation token expired or already used",
        ));
    }

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "account.invitation_accepted",
                user_id.to_string(),
            )
            .metadata(json!({ "email": token.email }))
            .build(),
        )
        .await?;

    Ok(Json(json!({ "status": "ok" })).into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateInvitationRequest {
    email: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct AcceptInvitationRequest {
    token: String,
    password: String,
}
