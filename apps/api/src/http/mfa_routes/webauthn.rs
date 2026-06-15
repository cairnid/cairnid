use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::PasskeyRegistration;
use cairn_domain::{MfaCredential, MfaKind, WebAuthnChallenge, WebAuthnChallengeKind};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    AppState, WEBAUTHN_CHALLENGE_TTL,
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    mfa::{
        active_webauthn_credentials_for_user, default_passkey_label, internal_error,
        passkeys_from_credentials, require_recent_enrollment_authentication, webauthn,
        webauthn_passkey_metadata_json,
    },
    session_auth::require_session,
};
use super::types::{FinishWebAuthnMfaRequest, StartWebAuthnMfaRequest};

pub(in crate::http) async fn start_webauthn_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<StartWebAuthnMfaRequest>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    require_recent_enrollment_authentication(&state, &session, now).await?;
    let user = state
        .database
        .get_user(session.user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "user missing"))?;
    let active_credentials =
        active_webauthn_credentials_for_user(&state, session.organization_id, session.user_id)
            .await?;
    let exclude_credentials = passkeys_from_credentials(&active_credentials)?
        .into_iter()
        .map(|passkey| passkey.cred_id().clone())
        .collect();
    let webauthn = webauthn(&state)?;
    let (options, registration_state) = webauthn
        .start_passkey_registration(
            session.user_id,
            &user.email,
            &user.display_name,
            Some(exclude_credentials),
        )
        .map_err(|error| {
            tracing::warn!(%error, "WebAuthn registration start failed");
            ApiError::bad_request("passkey registration could not start")
        })?;
    let challenge = WebAuthnChallenge {
        id: Uuid::new_v4(),
        organization_id: session.organization_id,
        user_id: session.user_id,
        kind: WebAuthnChallengeKind::Registration,
        state: serde_json::to_value(&registration_state)
            .map_err(|_| internal_error("passkey state serialization failed"))?,
        created_at: now,
        expires_at: now + WEBAUTHN_CHALLENGE_TTL,
        consumed_at: None,
    };
    state.database.insert_webauthn_challenge(&challenge).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "mfa.webauthn_enrollment_started",
                challenge.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "challenge_id": challenge.id,
            "options": options,
            "label": payload.label.unwrap_or_else(default_passkey_label)
        })),
    )
        .into_response())
}

pub(in crate::http) async fn finish_webauthn_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<FinishWebAuthnMfaRequest>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    require_recent_enrollment_authentication(&state, &session, now).await?;
    let challenge = state
        .database
        .consume_webauthn_challenge(
            payload.challenge_id,
            session.organization_id,
            session.user_id,
            WebAuthnChallengeKind::Registration,
            now,
        )
        .await?
        .ok_or_else(|| ApiError::bad_request("invalid or expired passkey challenge"))?;
    let registration_state: PasskeyRegistration = serde_json::from_value(challenge.state)
        .map_err(|_| internal_error("passkey registration state is invalid"))?;
    let passkey = webauthn(&state)?
        .finish_passkey_registration(&payload.credential, &registration_state)
        .map_err(|error| {
            tracing::warn!(%error, "WebAuthn registration finish failed");
            ApiError::status(StatusCode::UNAUTHORIZED, "invalid passkey registration")
        })?;
    let credential_id = cairn_authn::passkey_credential_id(&passkey);
    if state
        .database
        .find_active_webauthn_credential_by_credential_id(session.organization_id, &credential_id)
        .await?
        .is_some()
    {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "passkey is already registered",
        ));
    }

    let label = payload
        .label
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_passkey_label);
    let credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: session.organization_id,
        user_id: session.user_id,
        kind: MfaKind::WebAuthn,
        label,
        secret_metadata: webauthn_passkey_metadata_json("active", &credential_id, &passkey)?,
        created_at: now,
        last_used_at: None,
    };
    state.database.create_mfa_credential(&credential).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "mfa.webauthn_enabled",
                credential.id.to_string(),
            )
            .metadata(json!({ "credential_id": credential_id }))
            .build(),
        )
        .await?;

    Ok(Json(json!({
        "status": "enabled",
        "credential_id": credential.id,
        "label": credential.label
    }))
    .into_response())
}
