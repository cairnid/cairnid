use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
};
use cairn_database::ListCursor;
use cairn_domain::AuditEvent;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_list_query, list_page},
    api_response::ApiError,
    session_auth::require_admin_session,
};

pub(in crate::http) async fn list_admin_user_security_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<AuditEvent>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "user not found"))?;
    let query = admin_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let events = state
        .database
        .list_user_security_events_page(
            state.organization_id,
            user_id,
            query.cursor,
            query.fetch_limit(),
        )
        .await?;

    Ok(Json(list_page(events, query.limit, |event| {
        ListCursor::new(event.created_at, event.id)
    })))
}
