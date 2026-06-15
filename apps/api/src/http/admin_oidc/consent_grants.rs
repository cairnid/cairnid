use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
};
use cairn_audit::AuditEventBuilder;
use cairn_database::ListCursor;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_consent_grant_list_query, list_page},
    api_response::ApiError,
    client_policy::organization_client_by_id,
    cookies::require_csrf,
    session_auth::{require_admin_session, require_recent_admin_session},
};
use super::types::{AdminConsentGrantRevocationResponse, AdminConsentGrantSummary};

pub(in crate::http) async fn list_client_consent_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<AdminConsentGrantSummary>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let client = organization_client_by_id(&state, client_id).await?;
    let query = admin_consent_grant_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let grants = state
        .database
        .list_consent_grants_for_client_page_filtered(
            state.organization_id,
            client.id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?
        .into_iter()
        .map(AdminConsentGrantSummary::from)
        .collect::<Vec<_>>();

    Ok(Json(list_page(grants, query.page.limit, |grant| {
        ListCursor::new(grant.created_at, grant.id)
    })))
}

pub(in crate::http) async fn revoke_client_consent_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, grant_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<AdminConsentGrantRevocationResponse>, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let client = organization_client_by_id(&state, client_id).await?;
    let Some(revocation) = state
        .database
        .revoke_user_client_consent_and_tokens(
            state.organization_id,
            client.id,
            grant_id,
            OffsetDateTime::now_utc(),
        )
        .await?
    else {
        return Err(ApiError::status(
            StatusCode::NOT_FOUND,
            "consent grant not found",
        ));
    };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.consent_revoked",
                grant_id.to_string(),
            )
            .metadata(json!({
                "client_id": client.id,
                "client_public_id": client.client_id,
                "user_id": revocation.grant.user_id,
                "user_email": revocation.grant.user_email.clone(),
                "scopes": revocation.grant.scopes.clone(),
                "consent_grants_revoked": revocation.consent_grants_revoked,
                "authorization_codes_invalidated": revocation.authorization_codes_invalidated,
                "access_tokens_revoked": revocation.access_tokens_revoked,
                "refresh_tokens_revoked": revocation.refresh_tokens_revoked
            }))
            .build(),
        )
        .await?;

    Ok(Json(AdminConsentGrantRevocationResponse::from(revocation)))
}
