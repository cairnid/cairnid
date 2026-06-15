use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_database::{ListCursor, UserConsentGrantSummary};
use cairn_domain::{ConsentAuthorization, ConsentGrant};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState, CONSENT_AUTHORIZATION_TTL,
    admin_oidc::AdminConsentGrantRevocationResponse,
    admin_query::{ListPage, list_page, session_consent_grant_list_query},
    api_response::{ApiError, ApiJson},
    authorization::validate_consent_return_to,
    client_policy::consent_scopes_allowed,
    cookies::require_csrf,
    oauth_client::oidc_client_is_active,
    session_auth::{require_client_in_session_organization, require_session},
};

pub(in crate::http) async fn create_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateConsentRequest>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let client = state
        .database
        .get_oidc_client_by_public_id(&payload.client_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("unknown client"))?;
    require_client_in_session_organization(&client, &session)?;
    if !oidc_client_is_active(&client) {
        return Err(ApiError::bad_request("client disabled"));
    }
    if !consent_scopes_allowed(&payload.scopes, &client) {
        return Err(ApiError::bad_request("invalid consent scope"));
    }
    let authorization_request_hash = validate_consent_return_to(
        &state.config.issuer,
        &payload.return_to,
        &client,
        &payload.scopes,
    )?;

    let now = OffsetDateTime::now_utc();
    let grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: session.organization_id,
        user_id: session.user_id,
        client_id: client.id,
        scopes: payload.scopes,
        created_at: now,
        revoked_at: None,
    };
    state.database.create_consent_grant(&grant).await?;
    state
        .database
        .create_consent_authorization(&ConsentAuthorization {
            id: Uuid::new_v4(),
            organization_id: session.organization_id,
            user_id: session.user_id,
            session_id: session.id,
            client_id: client.id,
            authorization_request_hash,
            scopes: grant.scopes.clone(),
            created_at: now,
            expires_at: now + CONSENT_AUTHORIZATION_TTL,
            consumed_at: None,
        })
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                session.user_id,
                "oauth.consent_granted",
                client.id.to_string(),
            )
            .metadata(json!({ "client_id": client.client_id, "scopes": grant.scopes.clone() }))
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(grant)).into_response())
}

pub(in crate::http) async fn list_session_consent_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<SessionConsentGrantSummary>>, ApiError> {
    let session = require_session(&state, &headers).await?;
    let query = session_consent_grant_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let grants = state
        .database
        .list_consent_grants_for_user_page_filtered(
            session.organization_id,
            session.user_id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?
        .into_iter()
        .map(SessionConsentGrantSummary::from)
        .collect::<Vec<_>>();

    Ok(Json(list_page(grants, query.page.limit, |grant| {
        ListCursor::new(grant.created_at, grant.id)
    })))
}

pub(in crate::http) async fn revoke_session_consent_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<Uuid>,
) -> Result<Json<AdminConsentGrantRevocationResponse>, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let Some(revocation) = state
        .database
        .revoke_current_user_consent_and_tokens(
            session.organization_id,
            session.user_id,
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
                session.organization_id,
                session.user_id,
                "user.consent_revoked",
                grant_id.to_string(),
            )
            .metadata(json!({
                "client_id": revocation.grant.client_id,
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

#[derive(Debug, Serialize)]
pub(in crate::http) struct SessionConsentGrantSummary {
    id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    client_public_id: String,
    client_name: String,
    scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    revoked_at: Option<OffsetDateTime>,
}

impl From<UserConsentGrantSummary> for SessionConsentGrantSummary {
    fn from(grant: UserConsentGrantSummary) -> Self {
        Self {
            id: grant.id,
            organization_id: grant.organization_id,
            user_id: grant.user_id,
            client_id: grant.client_id,
            client_public_id: grant.client_public_id,
            client_name: grant.client_name,
            scopes: grant.scopes,
            created_at: grant.created_at,
            revoked_at: grant.revoked_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateConsentRequest {
    client_id: String,
    return_to: String,
    scopes: Vec<String>,
}
