use cairn_authn::{generate_secret, hash_token};
use cairn_domain::{AuthSession, MfaCredential, MfaKind};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{AppState, RECOVERY_CODE_BYTES, RECOVERY_CODE_COUNT, api_response::ApiError};
use super::invalid_mfa_metadata;

pub(super) async fn consume_recovery_code(
    state: &AppState,
    credentials: &[MfaCredential],
    code: &str,
) -> Result<bool, ApiError> {
    let code_hash = hash_token(code);
    for credential in credentials {
        if recovery_code_hash(credential)? == code_hash {
            let now = OffsetDateTime::now_utc();
            return Ok(state
                .database
                .consume_active_recovery_code(
                    credential.organization_id,
                    credential.user_id,
                    &code_hash,
                    now,
                )
                .await?);
        }
    }

    Ok(false)
}

fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            generate_secret(RECOVERY_CODE_BYTES)
                .expose_secret()
                .to_owned()
        })
        .collect()
}

pub(in crate::http) async fn replace_recovery_codes_for_session(
    state: &AppState,
    session: &AuthSession,
    at: OffsetDateTime,
) -> Result<(Vec<String>, u64), ApiError> {
    let recovery_codes = generate_recovery_codes();
    let recovery_codes_revoked = state
        .database
        .revoke_active_mfa_credentials_by_kind(
            session.organization_id,
            session.user_id,
            MfaKind::RecoveryCode,
            at,
        )
        .await?;
    store_recovery_codes(state, session, &recovery_codes, at).await?;
    Ok((recovery_codes, recovery_codes_revoked))
}

async fn store_recovery_codes(
    state: &AppState,
    session: &AuthSession,
    recovery_codes: &[String],
    at: OffsetDateTime,
) -> Result<(), ApiError> {
    for code in recovery_codes {
        let credential = MfaCredential {
            id: Uuid::new_v4(),
            organization_id: session.organization_id,
            user_id: session.user_id,
            kind: MfaKind::RecoveryCode,
            label: "Recovery code".to_owned(),
            secret_metadata: recovery_code_metadata_json("active", &hash_token(code)),
            created_at: at,
            last_used_at: None,
        };
        state.database.create_mfa_credential(&credential).await?;
    }

    Ok(())
}

fn recovery_code_metadata_json(status: &str, code_hash: &str) -> Value {
    json!({
        "status": status,
        "code_hash": code_hash
    })
}

fn recovery_code_hash(credential: &MfaCredential) -> Result<String, ApiError> {
    credential
        .secret_metadata
        .get("code_hash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(invalid_mfa_metadata)
}

#[cfg(test)]
mod tests {
    use super::super::mfa_metadata_status;
    use super::*;

    #[test]
    fn recovery_code_metadata_stores_hash_only() {
        let code = "one-use-code";
        let code_hash = hash_token(code);
        let credential = MfaCredential {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind: MfaKind::RecoveryCode,
            label: "Recovery code".to_owned(),
            secret_metadata: recovery_code_metadata_json("active", &code_hash),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
        };

        assert_eq!(mfa_metadata_status(&credential), "active");
        assert_eq!(recovery_code_hash(&credential).unwrap(), code_hash);
        assert!(!credential.secret_metadata.to_string().contains(code));
    }

    #[test]
    fn recovery_code_generation_returns_one_time_codes() {
        let codes = generate_recovery_codes();

        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert!(codes.iter().all(|code| code.len() >= 16));
    }
}
