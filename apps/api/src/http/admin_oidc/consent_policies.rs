use axum::{
    Json,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
};
use cairn_audit::AuditEventBuilder;
use cairn_database::ListCursor;
use cairn_domain::ConsentPolicyTemplate;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_list_query, list_page},
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    session_auth::{require_admin_session, require_recent_admin_session},
};
use super::types::CreateConsentPolicyTemplateRequest;

pub(in crate::http) async fn list_consent_policy_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<ConsentPolicyTemplate>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let templates = state
        .database
        .list_consent_policy_templates(state.organization_id, query.cursor, query.fetch_limit())
        .await?;

    Ok(Json(list_page(templates, query.limit, |template| {
        ListCursor::new(template.created_at, template.id)
    })))
}

pub(in crate::http) async fn create_consent_policy_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateConsentPolicyTemplateRequest>,
) -> Result<(StatusCode, Json<ConsentPolicyTemplate>), ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        slug: cairn_domain::checked_string("slug", payload.slug, 80)?,
        name: cairn_domain::checked_string("name", payload.name, 160)?,
        grant_mode: payload.grant_mode,
        created_at: OffsetDateTime::now_utc(),
    };
    state
        .database
        .create_consent_policy_template(&template)
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.consent_policy_template_created",
                template.id.to_string(),
            )
            .metadata(json!({
                "slug": template.slug,
                "grant_mode": template.grant_mode
            }))
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(template)))
}
