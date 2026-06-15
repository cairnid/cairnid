use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::{TotpProfile, generate_secret};
use cairn_domain::{MfaCredential, MfaKind};
use cairn_oidc::encrypt_secret;
use secrecy::ExposeSecret;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    AppState, TOTP_ENROLLMENT_TTL,
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    mfa::{
        encrypted_secret_from_totp_metadata, mfa_metadata_status,
        replace_recovery_codes_for_session, require_key_encryption_key,
        require_recent_enrollment_authentication, totp_credential_aad, totp_metadata_json,
        verify_totp_code,
    },
    session_auth::require_session,
};
use super::types::{ConfirmTotpMfaRequest, StartTotpMfaRequest};

pub(in crate::http) async fn start_totp_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<StartTotpMfaRequest>,
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
    let key_encryption_key = require_key_encryption_key(&state)?;
    let secret = generate_secret(20);
    let profile = TotpProfile::new("Cairn Identity", user.email.clone(), secret.clone());
    let totp = profile.build()?;
    let encrypted_secret = encrypt_secret(
        secret.expose_secret(),
        key_encryption_key,
        &totp_credential_aad(session.organization_id, session.user_id),
    )?;
    let label = payload
        .label
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Authenticator app".to_owned());
    let credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: session.organization_id,
        user_id: session.user_id,
        kind: MfaKind::Totp,
        label,
        secret_metadata: totp_metadata_json("pending", &encrypted_secret),
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
                "mfa.totp_enrollment_started",
                credential.id.to_string(),
            )
            .build(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "credential_id": credential.id,
            "otpauth_url": totp.get_url(),
            "secret_base32": totp.get_secret_base32()
        })),
    )
        .into_response())
}

pub(in crate::http) async fn confirm_totp_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ConfirmTotpMfaRequest>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    require_recent_enrollment_authentication(&state, &session, now).await?;
    let credentials = state
        .database
        .list_mfa_credentials(session.organization_id, session.user_id, MfaKind::Totp)
        .await?;
    let credential = credentials
        .into_iter()
        .find(|credential| {
            credential.id == payload.credential_id && mfa_metadata_status(credential) == "pending"
        })
        .ok_or_else(|| ApiError::bad_request("unknown pending TOTP enrollment"))?;
    if credential.created_at + TOTP_ENROLLMENT_TTL < now {
        return Err(ApiError::bad_request("expired pending TOTP enrollment"));
    }

    if !verify_totp_code(&state, &credential, &payload.code)? {
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid TOTP code",
        ));
    }

    let active_metadata =
        totp_metadata_json("active", &encrypted_secret_from_totp_metadata(&credential)?);
    state
        .database
        .update_mfa_credential_metadata(credential.id, &active_metadata, Some(now))
        .await?;
    let (recovery_codes, recovery_codes_revoked) =
        replace_recovery_codes_for_session(&state, &session, now).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "mfa.totp_enabled",
                credential.id.to_string(),
            )
            .metadata(json!({ "recovery_codes_revoked": recovery_codes_revoked }))
            .build(),
        )
        .await?;

    Ok(Json(json!({
        "status": "enabled",
        "recovery_codes": recovery_codes
    }))
    .into_response())
}
