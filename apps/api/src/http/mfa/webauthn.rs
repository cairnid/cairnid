use axum::http::StatusCode;
use cairn_authn::{
    Passkey, PasskeyAuthentication, PublicKeyCredential, WebAuthnConfig, Webauthn,
    passkey_credential_id,
};
use cairn_domain::{MfaCredential, WebAuthnChallenge, WebAuthnChallengeKind};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{AppState, WEBAUTHN_CHALLENGE_TTL, api_response::ApiError};
use super::{MfaVerificationMethod, internal_error, invalid_mfa_metadata};

pub(super) async fn start_webauthn_authentication_challenge(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
    active_webauthn_credentials: &[MfaCredential],
) -> Result<Value, ApiError> {
    let passkeys = passkeys_from_credentials(active_webauthn_credentials)?;
    let (options, authentication_state) = webauthn(state)?
        .start_passkey_authentication(&passkeys)
        .map_err(|error| {
            tracing::warn!(%error, "WebAuthn authentication start failed");
            ApiError::bad_request("passkey authentication could not start")
        })?;
    let now = OffsetDateTime::now_utc();
    let challenge = WebAuthnChallenge {
        id: Uuid::new_v4(),
        organization_id,
        user_id,
        kind: WebAuthnChallengeKind::Authentication,
        state: serde_json::to_value(&authentication_state)
            .map_err(|_| internal_error("passkey state serialization failed"))?,
        created_at: now,
        expires_at: now + WEBAUTHN_CHALLENGE_TTL,
        consumed_at: None,
    };
    state.database.insert_webauthn_challenge(&challenge).await?;

    Ok(json!({
        "challenge_id": challenge.id,
        "options": options
    }))
}

pub(in crate::http) async fn verify_webauthn_assertion(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
    active_webauthn_credentials: &[MfaCredential],
    challenge_id: Uuid,
    assertion: &PublicKeyCredential,
) -> Result<MfaVerificationMethod, ApiError> {
    if active_webauthn_credentials.is_empty() {
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "passkey is not enabled",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let challenge = state
        .database
        .consume_webauthn_challenge(
            challenge_id,
            organization_id,
            user_id,
            WebAuthnChallengeKind::Authentication,
            now,
        )
        .await?
        .ok_or_else(|| ApiError::bad_request("invalid or expired passkey challenge"))?;
    let authentication_state: PasskeyAuthentication = serde_json::from_value(challenge.state)
        .map_err(|_| internal_error("passkey authentication state is invalid"))?;
    let authentication_result = webauthn(state)?
        .finish_passkey_authentication(assertion, &authentication_state)
        .map_err(|error| {
            tracing::warn!(%error, "WebAuthn authentication finish failed");
            ApiError::status(StatusCode::UNAUTHORIZED, "invalid passkey assertion")
        })?;

    for credential in active_webauthn_credentials {
        let mut passkey = passkey_from_credential(credential)?;
        let Some(changed) = passkey.update_credential(&authentication_result) else {
            continue;
        };

        if changed {
            let credential_id = passkey_credential_id(&passkey);
            let metadata = webauthn_passkey_metadata_json("active", &credential_id, &passkey)?;
            state
                .database
                .update_mfa_credential_metadata(credential.id, &metadata, Some(now))
                .await?;
        } else {
            state
                .database
                .mark_mfa_credential_used(credential.id, now)
                .await?;
        }

        return Ok(MfaVerificationMethod::WebAuthn);
    }

    Err(ApiError::status(
        StatusCode::UNAUTHORIZED,
        "unknown passkey credential",
    ))
}

pub(in crate::http) fn webauthn(state: &AppState) -> Result<Webauthn, ApiError> {
    WebAuthnConfig::from_origin(state.config.public_web_origin.clone())?
        .build()
        .map_err(ApiError::from)
}

pub(in crate::http) fn passkeys_from_credentials(
    credentials: &[MfaCredential],
) -> Result<Vec<Passkey>, ApiError> {
    credentials.iter().map(passkey_from_credential).collect()
}

fn passkey_from_credential(credential: &MfaCredential) -> Result<Passkey, ApiError> {
    serde_json::from_value(
        credential
            .secret_metadata
            .get("passkey")
            .cloned()
            .ok_or_else(invalid_mfa_metadata)?,
    )
    .map_err(|_| invalid_mfa_metadata())
}

pub(in crate::http) fn webauthn_passkey_metadata_json(
    status: &str,
    credential_id: &str,
    passkey: &Passkey,
) -> Result<Value, ApiError> {
    Ok(json!({
        "status": status,
        "credential_id": credential_id,
        "passkey": serde_json::to_value(passkey)
            .map_err(|_| internal_error("passkey serialization failed"))?
    }))
}

pub(in crate::http) fn default_passkey_label() -> String {
    "Passkey".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_domain::MfaKind;

    #[test]
    fn default_passkey_label_is_stable() {
        assert_eq!(default_passkey_label(), "Passkey");
    }

    #[test]
    fn passkey_metadata_requires_serialized_passkey() {
        let credential = MfaCredential {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: MfaKind::WebAuthn,
            label: "Passkey".to_owned(),
            secret_metadata: json!({
                "status": "active",
                "credential_id": "missing-passkey"
            }),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
        };

        let error = passkeys_from_credentials(&[credential]).expect_err("missing passkey");
        match error {
            ApiError::Status {
                status, message, ..
            } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(message, "invalid MFA metadata");
            }
            other => panic!("expected invalid metadata error, got {other:?}"),
        }
    }
}
