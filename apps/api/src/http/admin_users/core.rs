use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::hash_password;
use cairn_database::{ListCursor, UserStatusMutationOutcome};
use cairn_domain::{User, UserStatus};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, ADMINISTRATORS_GROUP_SLUG, AppState,
    account_lifecycle::valid_new_password,
    admin_query::{ListPage, admin_user_list_query, list_page},
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::{require_admin_session, require_recent_admin_session},
};

pub(in crate::http) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<User>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_user_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let users = state
        .database
        .list_users_page_filtered(
            state.organization_id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?;
    Ok(Json(list_page(users, query.page.limit, |user| {
        ListCursor::new(user.created_at, user.id)
    })))
}

pub(in crate::http) async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateUserRequest>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let user = User::new(state.organization_id, payload.email, payload.display_name)?;
    let password_hash = match payload.password {
        Some(password) if !password.is_empty() => {
            let password = valid_new_password(password)?;
            Some(hash_password(&SecretString::from(password))?)
        }
        _ => None,
    };
    state
        .database
        .create_user(&user, password_hash.as_deref())
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.user_created",
                user.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(user)).into_response())
}

pub(in crate::http) async fn update_user_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    ApiJson(payload): ApiJson<UpdateUserStatusRequest>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    let user = match state
        .database
        .update_user_status(
            state.organization_id,
            user_id,
            payload.status,
            ADMINISTRATORS_GROUP_SLUG,
            now,
        )
        .await?
    {
        UserStatusMutationOutcome::Applied(user) => user,
        UserStatusMutationOutcome::NotFound => {
            return Err(ApiError::status(StatusCode::NOT_FOUND, "user not found"));
        }
        UserStatusMutationOutcome::WouldDeactivateLastOwner => {
            return Err(ApiError::status(
                StatusCode::CONFLICT,
                "administrators group must keep at least one active owner",
            ));
        }
    };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.user_status_updated",
                user.id.to_string(),
            )
            .metadata(json!({ "status": user.status }))
            .build(),
        )
        .await?;

    Ok(Json(user).into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateUserRequest {
    email: String,
    display_name: String,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct UpdateUserStatusRequest {
    status: UserStatus,
}
