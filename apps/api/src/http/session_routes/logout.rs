use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_domain::AuthSession;
use serde_json::json;
use time::OffsetDateTime;

use super::super::{
    AppState,
    api_response::ApiError,
    cookies::{clear_browser_session_cookies, require_csrf},
    request_context::audit_request_context,
    session_auth::session_from_cookie,
};

pub(in crate::http) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    if let Some(session) = session_from_cookie(&state, &headers).await? {
        revoke_session_for_logout(&state, &headers, &session, "browser").await?;
    }
    let mut response = Json(json!({ "status": "ok" })).into_response();
    clear_browser_session_cookies(response.headers_mut(), &state.config)?;
    Ok(response)
}

pub(in crate::http) async fn revoke_session_for_logout(
    state: &AppState,
    headers: &HeaderMap,
    session: &AuthSession,
    initiator: &'static str,
) -> Result<(), ApiError> {
    state
        .database
        .revoke_auth_session(session.id, OffsetDateTime::now_utc())
        .await?;
    let (ip_address, user_agent) = audit_request_context(headers);
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "session.logged_out",
                session.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "initiator": initiator,
                "acr": session.acr.clone(),
                "amr": session.amr.clone()
            }))
            .build(),
        )
        .await?;

    Ok(())
}
