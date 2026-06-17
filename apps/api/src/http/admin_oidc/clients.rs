use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::generate_hashed_secret;
use cairn_database::{
    ListCursor, OidcClientDetailsMutationOutcome, OidcClientDetailsUpdate,
    OidcClientStatusMutationOutcome,
};
use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType, RedirectUri};
use secrecy::ExposeSecret;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_oidc_client_list_query, list_page},
    api_response::{ApiError, ApiJson},
    client_policy::{organization_client_by_id, validate_consent_policy_template_assignment},
    cookies::require_csrf,
    session_auth::{require_admin_session, require_recent_admin_session},
};
use super::types::{
    AdminOidcClient, CreateClientRequest, CreateOidcClientResponse, RotateClientSecretResponse,
    UpdateClientRequest, UpdateClientStatusRequest, UpdateOidcClientResponse,
    UpdateOidcClientStatusResponse, validate_allowed_client_scopes,
};

pub(in crate::http) async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<AdminOidcClient>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_oidc_client_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let clients = state
        .database
        .list_oidc_clients_page_filtered(
            state.organization_id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?;
    let page = list_page(clients, query.page.limit, |client| {
        ListCursor::new(client.created_at, client.id)
    });

    Ok(Json(ListPage {
        items: page.items.into_iter().map(AdminOidcClient::from).collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(in crate::http) async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
) -> Result<Json<AdminOidcClient>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let client = organization_client_by_id(&state, client_id).await?;

    Ok(Json(AdminOidcClient::from(client)))
}

pub(in crate::http) async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateClientRequest>,
) -> Result<(StatusCode, Json<CreateOidcClientResponse>), ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let allowed_scopes = validate_allowed_client_scopes(payload.allowed_scopes)?;
    let consent_policy_template_id =
        validate_consent_policy_template_assignment(&state, payload.consent_policy_template_id)
            .await?;
    let secret = if payload.public_client {
        None
    } else {
        Some(generate_hashed_secret(32))
    };

    let grant_types = if payload.public_client {
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
        ]
    } else {
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ]
    };

    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        client_id: payload.client_id,
        client_secret_hash: secret.as_ref().map(|secret| secret.hash.clone()),
        consent_policy_template_id,
        name: payload.name,
        redirect_uris: payload
            .redirect_uris
            .into_iter()
            .map(RedirectUri::parse)
            .collect::<Result<Vec<_>, _>>()?,
        post_logout_redirect_uris: payload
            .post_logout_redirect_uris
            .into_iter()
            .map(RedirectUri::parse)
            .collect::<Result<Vec<_>, _>>()?,
        allowed_scopes,
        grant_types,
        public_client: payload.public_client,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    };

    state.database.create_oidc_client(&client).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.client_created",
                client.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateOidcClientResponse {
            client: AdminOidcClient::from(client),
            client_secret: secret
                .as_ref()
                .map(|secret| secret.value.expose_secret().to_owned()),
        }),
    ))
}

pub(in crate::http) async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
    ApiJson(payload): ApiJson<UpdateClientRequest>,
) -> Result<Json<UpdateOidcClientResponse>, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let allowed_scopes = validate_allowed_client_scopes(payload.allowed_scopes)?;
    let consent_policy_template_id =
        validate_consent_policy_template_assignment(&state, payload.consent_policy_template_id)
            .await?;
    let update = OidcClientDetailsUpdate {
        name: payload.name,
        redirect_uris: payload
            .redirect_uris
            .into_iter()
            .map(RedirectUri::parse)
            .collect::<Result<Vec<_>, _>>()?,
        post_logout_redirect_uris: payload
            .post_logout_redirect_uris
            .into_iter()
            .map(RedirectUri::parse)
            .collect::<Result<Vec<_>, _>>()?,
        allowed_scopes,
        consent_policy_template_id,
    };
    let now = OffsetDateTime::now_utc();
    let mutation = match state
        .database
        .update_oidc_client_details(state.organization_id, client_id, update, now)
        .await?
    {
        OidcClientDetailsMutationOutcome::Applied(mutation) => *mutation,
        OidcClientDetailsMutationOutcome::NotFound => {
            return Err(ApiError::status(StatusCode::NOT_FOUND, "client not found"));
        }
    };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.client_updated",
                mutation.client.id.to_string(),
            )
            .metadata(json!({
                "client_id": mutation.client.client_id.clone(),
                "changed_fields": mutation.changed_fields,
                "authorization_codes_invalidated": mutation.authorization_codes_invalidated,
                "access_tokens_revoked": mutation.access_tokens_revoked,
                "refresh_tokens_revoked": mutation.refresh_tokens_revoked
            }))
            .build(),
        )
        .await?;

    Ok(Json(UpdateOidcClientResponse {
        client: AdminOidcClient::from(mutation.client),
        authorization_codes_invalidated: mutation.authorization_codes_invalidated,
        access_tokens_revoked: mutation.access_tokens_revoked,
        refresh_tokens_revoked: mutation.refresh_tokens_revoked,
    }))
}

pub(in crate::http) async fn rotate_client_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
) -> Result<Json<RotateClientSecretResponse>, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let mut client = organization_client_by_id(&state, client_id).await?;
    if client.public_client {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "public clients do not have secrets",
        ));
    }

    let secret = generate_hashed_secret(32);
    let rotated = state
        .database
        .rotate_oidc_client_secret(state.organization_id, client.id, &secret.hash)
        .await?;
    if !rotated {
        return Err(ApiError::status(StatusCode::NOT_FOUND, "client not found"));
    }
    client.client_secret_hash = Some(secret.hash);

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.client_secret_rotated",
                client.id.to_string(),
            )
            .metadata(json!({ "client_id": client.client_id.clone() }))
            .build(),
        )
        .await?;

    Ok(Json(RotateClientSecretResponse {
        client: AdminOidcClient::from(client),
        client_secret: secret.value.expose_secret().to_owned(),
    }))
}

pub(in crate::http) async fn update_client_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
    ApiJson(payload): ApiJson<UpdateClientStatusRequest>,
) -> Result<Json<UpdateOidcClientStatusResponse>, ApiError> {
    let actor = require_recent_admin_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    let mutation = match state
        .database
        .update_oidc_client_status(state.organization_id, client_id, payload.status, now)
        .await?
    {
        OidcClientStatusMutationOutcome::Applied(mutation) => *mutation,
        OidcClientStatusMutationOutcome::NotFound => {
            return Err(ApiError::status(StatusCode::NOT_FOUND, "client not found"));
        }
    };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                state.organization_id,
                actor.user_id,
                "admin.client_status_updated",
                mutation.client.id.to_string(),
            )
            .metadata(json!({
                "client_id": mutation.client.client_id.clone(),
                "status": mutation.client.status,
                "authorization_codes_invalidated": mutation.authorization_codes_invalidated,
                "access_tokens_revoked": mutation.access_tokens_revoked,
                "refresh_tokens_revoked": mutation.refresh_tokens_revoked
            }))
            .build(),
        )
        .await?;

    Ok(Json(UpdateOidcClientStatusResponse {
        client: AdminOidcClient::from(mutation.client),
        authorization_codes_invalidated: mutation.authorization_codes_invalidated,
        access_tokens_revoked: mutation.access_tokens_revoked,
        refresh_tokens_revoked: mutation.refresh_tokens_revoked,
    }))
}
