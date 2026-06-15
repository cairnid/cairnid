use axum::{
    Json,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_database::ListCursor;
use cairn_domain::Group;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_list_query, list_page},
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::{require_admin_session, require_recent_admin_session},
};

pub(in crate::http) async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<Group>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let groups = state
        .database
        .list_groups_page(state.organization_id, query.cursor, query.fetch_limit())
        .await?;
    Ok(Json(list_page(groups, query.limit, |group| {
        ListCursor::new(group.created_at, group.id)
    })))
}

pub(in crate::http) async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateGroupRequest>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let group = Group {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        slug: cairn_domain::checked_string("slug", payload.slug, 80)?,
        scim_external_id: None,
        display_name: cairn_domain::checked_string("display_name", payload.display_name, 160)?,
        created_at: OffsetDateTime::now_utc(),
    };
    state.database.create_group(&group).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.group_created",
                group.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(group)).into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateGroupRequest {
    slug: String,
    display_name: String,
}
