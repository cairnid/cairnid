use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_authn::TotpProfile;
use cairn_domain::{MfaCredential, MfaKind};
use cairn_oidc::{EncryptedSecret, decrypt_secret};
use secrecy::SecretString;
use serde_json::{Value, json};
use uuid::Uuid;

use super::super::{AppState, api_response::ApiError};
use super::{invalid_mfa_metadata, mfa_metadata_status, require_key_encryption_key};

pub(super) async fn active_totp_credentials_for_user(
    state: &AppState,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<MfaCredential>, ApiError> {
    Ok(state
        .database
        .list_mfa_credentials(organization_id, user_id, MfaKind::Totp)
        .await?
        .into_iter()
        .filter(|credential| mfa_metadata_status(credential) == "active")
        .collect())
}

pub(in crate::http) fn verify_totp_code(
    state: &AppState,
    credential: &MfaCredential,
    code: &str,
) -> Result<bool, ApiError> {
    let encrypted_secret = encrypted_secret_from_totp_metadata(credential)?;
    let decrypted_secret = decrypt_secret(
        &encrypted_secret,
        require_key_encryption_key(state)?,
        &totp_credential_aad(credential.organization_id, credential.user_id),
    )
    .map_err(|_| ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "MFA decryption failed"))?;
    let profile = TotpProfile::new(
        "Cairn Identity",
        credential.user_id.to_string(),
        SecretString::from(decrypted_secret),
    );

    profile.verify_current(code).map_err(ApiError::from)
}

pub(in crate::http) fn totp_metadata_json(
    status: &str,
    encrypted_secret: &EncryptedSecret,
) -> Value {
    json!({
        "status": status,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "secret_ciphertext": URL_SAFE_NO_PAD.encode(&encrypted_secret.ciphertext),
        "secret_nonce": URL_SAFE_NO_PAD.encode(&encrypted_secret.nonce)
    })
}

pub(in crate::http) fn encrypted_secret_from_totp_metadata(
    credential: &MfaCredential,
) -> Result<EncryptedSecret, ApiError> {
    let ciphertext = credential
        .secret_metadata
        .get("secret_ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(invalid_mfa_metadata)?;
    let nonce = credential
        .secret_metadata
        .get("secret_nonce")
        .and_then(Value::as_str)
        .ok_or_else(invalid_mfa_metadata)?;

    Ok(EncryptedSecret {
        ciphertext: URL_SAFE_NO_PAD
            .decode(ciphertext)
            .map_err(|_| invalid_mfa_metadata())?,
        nonce: URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| invalid_mfa_metadata())?,
    })
}

pub(in crate::http) fn totp_credential_aad(organization_id: Uuid, user_id: Uuid) -> String {
    format!("cairnid:mfa:totp:{organization_id}:{user_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn totp_metadata_round_trips_encrypted_secret_references() {
        let encrypted_secret = EncryptedSecret {
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let credential = MfaCredential {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: MfaKind::Totp,
            label: "Authenticator".to_owned(),
            secret_metadata: totp_metadata_json("pending", &encrypted_secret),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
        };

        assert_eq!(mfa_metadata_status(&credential), "pending");
        assert_eq!(
            encrypted_secret_from_totp_metadata(&credential).unwrap(),
            encrypted_secret
        );
        assert!(
            !credential
                .secret_metadata
                .to_string()
                .contains("raw-secret")
        );
    }

    #[test]
    fn totp_aad_binds_to_user_and_organization() {
        let organization_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        assert_eq!(
            totp_credential_aad(organization_id, user_id),
            format!("cairnid:mfa:totp:{organization_id}:{user_id}")
        );
        assert_ne!(
            totp_credential_aad(organization_id, user_id),
            totp_credential_aad(Uuid::new_v4(), user_id)
        );
    }
}
