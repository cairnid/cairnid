use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use cairn_domain::User;

use super::super::{AppState, api_response::ApiError, session_auth::require_session};

pub(in crate::http) async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<User>, ApiError> {
    let session = require_session(&state, &headers).await?;
    let user = state
        .database
        .get_user(session.user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "user missing"))?;
    Ok(Json(user))
}
