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
    session_auth::require_session,
};

pub(in crate::http) async fn list_browser_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BrowserSessionListResponse>, ApiError> {
    let session = require_session(&state, &headers).await?;
    let sessions = state
        .database
        .list_active_browser_sessions_for_user(
            session.organization_id,
            session.user_id,
            OffsetDateTime::now_utc(),
            SESSION_LIST_LIMIT,
        )
        .await?
        .into_iter()
        .map(|summary| BrowserSessionResponse::from_summary(summary, session.id))
        .collect();

    Ok(Json(BrowserSessionListResponse { sessions }))
}

pub(in crate::http) async fn revoke_browser_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<BrowserSessionRevocationResponse>, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    if session_id == session.id {
        return Err(ApiError::bad_request(
            "use logout to revoke current session",
        ));
    }

    let Some(revoked) = state
        .database
        .revoke_user_browser_session(
            session.organization_id,
            session.user_id,
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
                session.organization_id,
                session.user_id,
                "session.revoked_by_user",
                revoked.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "current_session_id": session.id,
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
