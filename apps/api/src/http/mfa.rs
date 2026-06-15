use axum::http::StatusCode;
use cairn_domain::{AuthSession, MfaCredential};
use serde_json::Value;
use time::OffsetDateTime;

mod factors;
mod recovery_codes;
mod session;
mod totp;
mod webauthn;

pub(super) use self::factors::{
    active_mfa_credentials_for_user, active_recovery_code_credentials_for_user,
    active_second_factor_count, active_webauthn_credentials_for_user,
    mfa_required_response_for_active, verify_mfa_code_against_credentials,
    visible_mfa_credentials_for_user,
};
pub(super) use self::recovery_codes::replace_recovery_codes_for_session;
pub(super) use self::session::{
    MfaVerificationMethod, authenticated_session, require_recent_authentication,
    require_recent_mfa_proof, rotated_session_preserving_auth_context,
};
pub(super) use self::totp::{
    encrypted_secret_from_totp_metadata, totp_credential_aad, totp_metadata_json, verify_totp_code,
};
pub(super) use self::webauthn::{
    default_passkey_label, passkeys_from_credentials, verify_webauthn_assertion, webauthn,
    webauthn_passkey_metadata_json,
};

use super::{AppState, api_response::ApiError};

pub(super) fn require_key_encryption_key(
    state: &AppState,
) -> Result<&cairn_oidc::KeyEncryptionKey, ApiError> {
    state.config.key_encryption_key.as_ref().ok_or_else(|| {
        ApiError::status(
            StatusCode::PRECONDITION_REQUIRED,
            "CAIRN_KEY_ENCRYPTION_KEY is required for MFA",
        )
    })
}

pub(super) async fn require_recent_enrollment_authentication(
    state: &AppState,
    session: &AuthSession,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let has_active_second_factor =
        active_second_factor_count(state, session.organization_id, session.user_id).await? > 0;
    if has_active_second_factor {
        require_recent_mfa_proof(session, now)
    } else {
        require_recent_authentication(session, now)
    }
}

pub(super) fn mfa_metadata_status(credential: &MfaCredential) -> &str {
    credential
        .secret_metadata
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn invalid_mfa_metadata() -> ApiError {
    ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "invalid MFA metadata")
}

pub(super) fn internal_error(message: &'static str) -> ApiError {
    ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, message)
}
