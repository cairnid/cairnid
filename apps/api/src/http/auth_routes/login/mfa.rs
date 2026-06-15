use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cairn_authn::PublicKeyCredential;
use time::Duration;
use uuid::Uuid;

use super::super::super::{
    AppState,
    api_response::ApiError,
    mfa::{
        MfaVerificationMethod, active_mfa_credentials_for_user, mfa_required_response_for_active,
        verify_mfa_code_against_credentials, verify_webauthn_assertion,
    },
    request_context::{RateLimitKey, record_rate_limit_failure},
};

pub(super) struct SubmittedMfa<'a> {
    pub(super) code: Option<&'a str>,
    pub(super) webauthn_challenge_id: Option<Uuid>,
    pub(super) webauthn_credential: Option<&'a PublicKeyCredential>,
}

pub(super) struct MfaFailurePolicy<'a> {
    pub(super) rate_limit_keys: &'a [RateLimitKey],
    pub(super) window: Duration,
    pub(super) max_attempts: i64,
    pub(super) block_for: Duration,
}

pub(super) enum MfaVerification {
    Verified(Option<MfaVerificationMethod>),
    Required(Response),
}

pub(super) async fn verify_submitted_mfa(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
    submitted: SubmittedMfa<'_>,
    failure_policy: MfaFailurePolicy<'_>,
) -> Result<MfaVerification, ApiError> {
    let active_mfa = active_mfa_credentials_for_user(state, organization_id, user_id).await?;
    if !active_mfa.requires_mfa() {
        return Ok(MfaVerification::Verified(None));
    }

    let mfa_method = if let (Some(challenge_id), Some(assertion)) = (
        submitted.webauthn_challenge_id,
        submitted.webauthn_credential,
    ) {
        match verify_webauthn_assertion(
            state,
            organization_id,
            user_id,
            &active_mfa.webauthn,
            challenge_id,
            assertion,
        )
        .await
        {
            Ok(method) => Some(method),
            Err(error) => {
                record_mfa_rate_limit_failure(state, &failure_policy).await?;
                return Err(error);
            }
        }
    } else {
        let Some(code) = submitted.code else {
            return Ok(MfaVerification::Required(
                mfa_required_response_for_active(state, organization_id, user_id, &active_mfa)
                    .await?
                    .into_response(),
            ));
        };
        verify_mfa_code_against_credentials(
            state,
            &active_mfa.totp,
            &active_mfa.recovery_codes,
            code,
        )
        .await?
    };

    if mfa_method.is_none() {
        record_mfa_rate_limit_failure(state, &failure_policy).await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid MFA credential",
        ));
    }

    Ok(MfaVerification::Verified(mfa_method))
}

async fn record_mfa_rate_limit_failure(
    state: &AppState,
    policy: &MfaFailurePolicy<'_>,
) -> Result<(), ApiError> {
    record_rate_limit_failure(
        state,
        policy.rate_limit_keys,
        policy.window,
        policy.max_attempts,
        policy.block_for,
    )
    .await
}
