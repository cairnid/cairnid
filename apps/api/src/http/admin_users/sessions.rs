use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use cairn_audit::AuditEventBuilder;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    AppState, SESSION_LIST_LIMIT,
    api_response::ApiError,
    browser_sessions::{
        BrowserSessionListResponse, BrowserSessionResponse, BrowserSessionRevocationResponse,
    },
    cookies::require_csrf,
    request_context::audit_request_context,
    session_auth::{require_admin_session, require_recent_admin_session},
};

pub(in crate::http) async fn list_admin_user_browser_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Json<BrowserSessionListResponse>, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "user not found"))?;

    let sessions = state
        .database
        .list_active_browser_sessions_for_user(
            state.organization_id,
            user_id,
            OffsetDateTime::now_utc(),
            SESSION_LIST_LIMIT,
        )
        .await?
        .into_iter()
        .map(|summary| BrowserSessionResponse::from_summary(summary, actor.id))
        .collect();

    Ok(Json(BrowserSessionListResponse { sessions }))
}

pub(in crate::http) async fn revoke_admin_user_browser_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<BrowserSessionRevocationResponse>, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "user not found"))?;

    if session_id == actor.id {
        return Err(ApiError::bad_request(
            "use logout to revoke current session",
        ));
    }

    let Some(revoked) = state
        .database
        .revoke_user_browser_session(
            state.organization_id,
            user_id,
            session_id,
            OffsetDateTime::now_utc(),
        )
        .await?
    else {
        return Err(ApiError::status(
            StatusCode::NOT_FOUND,
            "browser session not found",
        ));
    };

    let (ip_address, user_agent) = audit_request_context(&headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.user_session_revoked",
                revoked.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "subject_user_id": user_id,
                "admin_session_id": actor.id,
                "revoked_session_acr": revoked.acr,
                "revoked_session_amr": revoked.amr
            }))
            .build(),
        )
        .await?;

    Ok(Json(BrowserSessionRevocationResponse {
        status: "revoked",
        session_id: revoked.id,
    }))
}
