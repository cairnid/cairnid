use crate::config::ApiConfig;
use cairn_database::{Database, ReencryptedEmailOutboxDeliveryToken};
use cairn_oidc::{
    EncryptedSecret, KeyEncryptionKey, decrypt_secret, encrypt_secret,
    reencrypt_signing_key_material,
};
use serde::Serialize;
use std::{env, io};
use time::OffsetDateTime;

pub(crate) async fn run_key_encryption_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("rotate") => {
            let config = ApiConfig::from_env()?;
            let old_key = key_encryption_key_from_env("CAIRN_OLD_KEY_ENCRYPTION_KEY")?;
            let new_key = key_encryption_key_from_env("CAIRN_NEW_KEY_ENCRYPTION_KEY")?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;

            let signing_keys = database.list_encrypted_signing_key_materials().await?;
            let mut reencrypted_signing_keys = Vec::with_capacity(signing_keys.len());
            for key in &signing_keys {
                reencrypted_signing_keys
                    .push(reencrypt_signing_key_material(key, &old_key, &new_key)?);
            }

            let email_delivery_tokens = database.list_email_outbox_delivery_tokens().await?;
            let mut reencrypted_email_delivery_tokens =
                Vec::with_capacity(email_delivery_tokens.len());
            for token in &email_delivery_tokens {
                let kind = metadata_str(&token.metadata, "kind", token.id)?;
                let account_token_id = metadata_str(&token.metadata, "account_token_id", token.id)?;
                let aad = account_token_delivery_aad(kind, account_token_id);
                let value = decrypt_secret(
                    &EncryptedSecret {
                        ciphertext: token.delivery_token_ciphertext.clone(),
                        nonce: token.delivery_token_nonce.clone(),
                    },
                    &old_key,
                    &aad,
                )?;
                let encrypted = encrypt_secret(&value, &new_key, &aad)?;
                reencrypted_email_delivery_tokens.push(ReencryptedEmailOutboxDeliveryToken {
                    id: token.id,
                    delivery_token_ciphertext: encrypted.ciphertext,
                    delivery_token_nonce: encrypted.nonce,
                });
            }

            database
                .apply_key_encryption_rotation(
                    &reencrypted_signing_keys,
                    &reencrypted_email_delivery_tokens,
                )
                .await?;
            let report = KeyEncryptionRotationReport {
                status: "rotated",
                signing_keys: reencrypted_signing_keys.len(),
                email_delivery_tokens: reencrypted_email_delivery_tokens.len(),
                completed_at: OffsetDateTime::now_utc(),
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        _ => Err(config_error("usage: cairn-api key-encryption rotate")),
    }
}

fn key_encryption_key_from_env(
    name: &'static str,
) -> Result<KeyEncryptionKey, Box<dyn std::error::Error>> {
    let value = env::var(name)
        .map_err(|_| config_error_owned(format!("missing required environment variable {name}")))?;
    KeyEncryptionKey::from_base64_url_no_pad(&value)
        .map_err(|error| config_error_owned(format!("invalid {name}: {error}")))
}

fn metadata_str<'a>(
    metadata: &'a serde_json::Value,
    field: &'static str,
    email_outbox_id: uuid::Uuid,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    metadata
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            config_error_owned(format!(
                "email_outbox {email_outbox_id} is missing metadata field {field}"
            ))
        })
}

fn account_token_delivery_aad(kind: &str, account_token_id: &str) -> String {
    format!("cairnid:account-token-delivery:{kind}:{account_token_id}")
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[derive(Debug, Serialize)]
struct KeyEncryptionRotationReport {
    status: &'static str,
    signing_keys: usize,
    email_delivery_tokens: usize,
    #[serde(with = "time::serde::rfc3339")]
    completed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::{KeyEncryptionRotationReport, account_token_delivery_aad, metadata_str};
    use serde_json::json;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    #[test]
    fn key_encryption_rotation_report_serializes_evidence_timestamp_as_rfc3339() {
        let report = KeyEncryptionRotationReport {
            status: "rotated",
            signing_keys: 1,
            email_delivery_tokens: 2,
            completed_at: OffsetDateTime::UNIX_EPOCH + Duration::days(3),
        };

        let value = serde_json::to_value(report).expect("kek rotation report json");

        assert_eq!(value["status"], "rotated");
        assert_eq!(value["signing_keys"], 1);
        assert_eq!(value["email_delivery_tokens"], 2);
        assert_eq!(value["completed_at"], "1970-01-04T00:00:00Z");
    }

    #[test]
    fn metadata_str_requires_present_non_empty_string() {
        let id = Uuid::new_v4();
        let metadata = json!({
            "kind": "password_recovery",
            "empty": "",
            "numeric": 42
        });

        assert_eq!(
            metadata_str(&metadata, "kind", id).expect("metadata kind"),
            "password_recovery"
        );
        assert!(
            metadata_str(&metadata, "empty", id)
                .expect_err("empty field")
                .to_string()
                .contains("missing metadata field empty")
        );
        assert!(
            metadata_str(&metadata, "numeric", id)
                .expect_err("non-string field")
                .to_string()
                .contains("missing metadata field numeric")
        );
    }

    #[test]
    fn account_token_delivery_aad_binds_kind_and_token_id() {
        assert_eq!(
            account_token_delivery_aad("email_verification", "token-123"),
            "cairnid:account-token-delivery:email_verification:token-123"
        );
    }
}
