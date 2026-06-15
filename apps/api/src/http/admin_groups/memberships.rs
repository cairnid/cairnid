use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_database::ListCursor;
use cairn_domain::{Membership, MembershipRole};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_GROUP_MEMBERSHIP_LIST_MAX_LIMIT, ADMINISTRATORS_GROUP_SLUG, AppState,
    admin_query::{ListPage, admin_list_query, list_page},
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::{
        require_admin_session, require_group_in_organization, require_recent_admin_session,
    },
};
use super::errors::{group_membership_deletion_error, group_membership_mutation_error};

pub(in crate::http) async fn list_group_memberships(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<Membership>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_list_query(
        raw_query.as_deref(),
        ADMIN_GROUP_MEMBERSHIP_LIST_MAX_LIMIT,
        ADMIN_GROUP_MEMBERSHIP_LIST_MAX_LIMIT,
    )?;
    require_group_in_organization(&state, group_id).await?;
    let memberships = state
        .database
        .list_group_memberships_page(
            state.organization_id,
            group_id,
            query.cursor,
            query.fetch_limit(),
        )
        .await?;
    Ok(Json(list_page(memberships, query.limit, |membership| {
        ListCursor::new(membership.created_at, membership.user_id)
    })))
}

pub(in crate::http) async fn upsert_group_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
    ApiJson(payload): ApiJson<UpsertGroupMembershipRequest>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let membership = Membership {
        organization_id: state.organization_id,
        user_id,
        group_id,
        role: payload.role,
        created_at: OffsetDateTime::now_utc(),
    };
    if let Some(error) = group_membership_mutation_error(
        state
            .database
            .upsert_group_membership(&membership, ADMINISTRATORS_GROUP_SLUG)
            .await?,
    ) {
        return Err(error);
    }

    let stored = state
        .database
        .get_group_membership(state.organization_id, group_id, user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "membership missing"))?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.group_membership_upserted",
                group_id.to_string(),
            )
            .metadata(json!({ "user_id": user_id, "role": stored.role }))
            .build(),
        )
        .await?;

    Ok(Json(stored).into_response())
}

pub(in crate::http) async fn delete_group_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    if let Some(error) = group_membership_deletion_error(
        state
            .database
            .delete_group_membership(
                state.organization_id,
                group_id,
                user_id,
                ADMINISTRATORS_GROUP_SLUG,
            )
            .await?,
    ) {
        return Err(error);
    }

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.group_membership_deleted",
                group_id.to_string(),
            )
            .metadata(json!({ "user_id": user_id }))
            .build(),
        )
        .await?;

    Ok(Json(json!({ "status": "deleted" })).into_response())
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct UpsertGroupMembershipRequest {
    role: MembershipRole,
}
