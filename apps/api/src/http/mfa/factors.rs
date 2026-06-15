use axum::Json;
use cairn_domain::{MfaCredential, MfaKind};
use serde_json::{Value, json};
use std::cmp::Reverse;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{AppState, api_response::ApiError};
use super::mfa_metadata_status;
use super::recovery_codes::consume_recovery_code;
use super::session::MfaVerificationMethod;
use super::totp::{active_totp_credentials_for_user, verify_totp_code};
use super::webauthn::start_webauthn_authentication_challenge;

pub(in crate::http) async fn active_recovery_code_credentials_for_user(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<MfaCredential>, ApiError> {
    Ok(state
        .database
        .list_mfa_credentials(organization_id, user_id, MfaKind::RecoveryCode)
        .await?
        .into_iter()
        .filter(|credential| mfa_metadata_status(credential) == "active")
        .collect())
}

pub(in crate::http) async fn active_webauthn_credentials_for_user(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<MfaCredential>, ApiError> {
    Ok(state
        .database
        .list_mfa_credentials(organization_id, user_id, MfaKind::WebAuthn)
        .await?
        .into_iter()
        .filter(|credential| mfa_metadata_status(credential) == "active")
        .collect())
}

pub(in crate::http) struct ActiveMfaCredentials {
    pub(in crate::http) totp: Vec<MfaCredential>,
    pub(in crate::http) recovery_codes: Vec<MfaCredential>,
    pub(in crate::http) webauthn: Vec<MfaCredential>,
}

impl ActiveMfaCredentials {
    pub(in crate::http) fn requires_mfa(&self) -> bool {
        !self.totp.is_empty() || !self.webauthn.is_empty()
    }
}

pub(in crate::http) async fn active_mfa_credentials_for_user(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<ActiveMfaCredentials, ApiError> {
    Ok(ActiveMfaCredentials {
        totp: active_totp_credentials_for_user(state, organization_id, user_id).await?,
        recovery_codes: active_recovery_code_credentials_for_user(state, organization_id, user_id)
            .await?,
        webauthn: active_webauthn_credentials_for_user(state, organization_id, user_id).await?,
    })
}

pub(in crate::http) async fn visible_mfa_credentials_for_user(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<MfaCredential>, ApiError> {
    let mut credentials = state
        .database
        .list_mfa_credentials(organization_id, user_id, MfaKind::Totp)
        .await?;
    credentials.extend(
        state
            .database
            .list_mfa_credentials(organization_id, user_id, MfaKind::WebAuthn)
            .await?,
    );
    credentials.retain(|credential| mfa_metadata_status(credential) != "revoked");
    credentials.sort_by_key(|credential| Reverse(credential.created_at));
    Ok(credentials)
}

pub(in crate::http) async fn active_second_factor_count(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<usize, ApiError> {
    Ok(
        active_totp_credentials_for_user(state, organization_id, user_id)
            .await?
            .len()
            + active_webauthn_credentials_for_user(state, organization_id, user_id)
                .await?
                .len(),
    )
}

pub(in crate::http) async fn mfa_required_response_for_active(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
    active_mfa: &ActiveMfaCredentials,
) -> Result<Json<Value>, ApiError> {
    mfa_required_response(
        state,
        organization_id,
        user_id,
        !active_mfa.totp.is_empty(),
        !active_mfa.recovery_codes.is_empty(),
        &active_mfa.webauthn,
    )
    .await
}

async fn mfa_required_response(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
    has_totp: bool,
    has_recovery_codes: bool,
    active_webauthn_credentials: &[MfaCredential],
) -> Result<Json<Value>, ApiError> {
    let mut methods = Vec::new();
    if !active_webauthn_credentials.is_empty() {
        methods.push("webauthn");
    }
    if has_totp {
        methods.push("totp");
    }
    if has_recovery_codes {
        methods.push("recovery_code");
    }

    let webauthn = if active_webauthn_credentials.is_empty() {
        None
    } else {
        Some(
            start_webauthn_authentication_challenge(
                state,
                organization_id,
                user_id,
                active_webauthn_credentials,
            )
            .await?,
        )
    };

    Ok(Json(json!({
        "status": "mfa_required",
        "methods": methods,
        "webauthn": webauthn
    })))
}

pub(in crate::http) async fn verify_mfa_code_against_credentials(
    state: &AppState,
    totp_credentials: &[MfaCredential],
    recovery_code_credentials: &[MfaCredential],
    code: &str,
) -> Result<Option<MfaVerificationMethod>, ApiError> {
    for credential in totp_credentials {
        if verify_totp_code(state, credential, code)? {
            state
                .database
                .mark_mfa_credential_used(credential.id, OffsetDateTime::now_utc())
                .await?;
            return Ok(Some(MfaVerificationMethod::Totp));
        }
    }

    if consume_recovery_code(state, recovery_code_credentials, code).await? {
        return Ok(Some(MfaVerificationMethod::RecoveryCode));
    }

    Ok(None)
}
