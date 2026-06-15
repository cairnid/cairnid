use super::EmailDeliveryError;
use crate::config::ApiConfig;
use cairn_domain::EmailOutboxMessage;
use cairn_oidc::{EncryptedSecret, decrypt_secret};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub(super) struct EmailCommandPayload {
    pub(super) id: Uuid,
    pub(super) to: String,
    pub(super) subject: String,
    pub(super) text: String,
    pub(super) template: String,
    pub(super) metadata: Value,
}

#[derive(Debug, Clone)]
pub(super) struct RenderedEmail {
    pub(super) payload: EmailCommandPayload,
}

pub(super) fn render_email(
    message: &EmailOutboxMessage,
    config: &ApiConfig,
) -> Result<RenderedEmail, EmailDeliveryError> {
    let text = if message.body_text.contains("{{action_url}}") {
        let action_url = action_url(message, config)?;
        message.body_text.replace("{{action_url}}", &action_url)
    } else {
        message.body_text.clone()
    };

    Ok(RenderedEmail {
        payload: EmailCommandPayload {
            id: message.id,
            to: message.recipient_email.clone(),
            subject: message.subject.clone(),
            text,
            template: message.template.clone(),
            metadata: message.metadata.clone(),
        },
    })
}

fn action_url(
    message: &EmailOutboxMessage,
    config: &ApiConfig,
) -> Result<String, EmailDeliveryError> {
    let key = config
        .key_encryption_key
        .as_ref()
        .ok_or(EmailDeliveryError::MissingKeyEncryptionKey)?;
    let action_path =
        message
            .action_path
            .as_deref()
            .ok_or(EmailDeliveryError::MissingMessageField {
                id: message.id,
                field: "action_path",
            })?;
    let ciphertext = message.delivery_token_ciphertext.clone().ok_or(
        EmailDeliveryError::MissingMessageField {
            id: message.id,
            field: "delivery_token_ciphertext",
        },
    )?;
    let nonce =
        message
            .delivery_token_nonce
            .clone()
            .ok_or(EmailDeliveryError::MissingMessageField {
                id: message.id,
                field: "delivery_token_nonce",
            })?;
    let account_token_id = metadata_str(message, "account_token_id")?;
    let kind = metadata_str(message, "kind")?;
    let encrypted = EncryptedSecret { ciphertext, nonce };
    let token = decrypt_secret(
        &encrypted,
        key,
        &format!("cairnid:account-token-delivery:{kind}:{account_token_id}"),
    )?;

    Ok(format!(
        "{}{}?token={}",
        config.public_web_origin.trim_end_matches('/'),
        action_path,
        percent_encode_minimal(&token)
    ))
}

fn metadata_str<'a>(
    message: &'a EmailOutboxMessage,
    field: &'static str,
) -> Result<&'a str, EmailDeliveryError> {
    message
        .metadata
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(EmailDeliveryError::InvalidMetadata {
            id: message.id,
            field,
        })
}

fn percent_encode_minimal(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use cairn_domain::Environment;
    use cairn_oidc::{KeyEncryptionKey, encrypt_secret};
    use serde_json::json;
    use time::OffsetDateTime;

    #[test]
    fn render_email_inserts_decrypted_action_url() {
        let encoded_key = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let key = KeyEncryptionKey::from_base64_url_no_pad(&encoded_key).unwrap();
        let message_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let encrypted = encrypt_secret(
            "token with space",
            &key,
            &format!("cairnid:account-token-delivery:password_recovery:{token_id}"),
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        let message = EmailOutboxMessage {
            id: message_id,
            organization_id: Uuid::new_v4(),
            recipient_email: "user@example.com".to_owned(),
            subject: "Reset".to_owned(),
            body_text: "Continue: {{action_url}}".to_owned(),
            template: "password_recovery".to_owned(),
            action_path: Some("/reset-password".to_owned()),
            delivery_token_ciphertext: Some(encrypted.ciphertext),
            delivery_token_nonce: Some(encrypted.nonce),
            status: "sending".to_owned(),
            attempts: 1,
            last_error: None,
            provider_message_id: None,
            metadata: json!({
                "kind": "password_recovery",
                "account_token_id": token_id
            }),
            created_at: now,
            updated_at: now,
            next_attempt_at: None,
            sent_at: None,
        };
        let config = ApiConfig {
            environment: Environment::Development,
            bind: "127.0.0.1:8080".to_owned(),
            issuer: "http://localhost:8080".to_owned(),
            public_web_origin: "http://localhost:5173".to_owned(),
            database_url: "postgres://cairn:cairn@localhost:5432/cairn_identity".to_owned(),
            default_org_slug: "default".to_owned(),
            scim: ScimConfig {
                bearer_token_sha256_hashes: Vec::new(),
            },
            audit: AuditOperationsConfig {
                retention_days: 365,
                purge_batch_size: 1000,
                export_max_rows: 10_000,
            },
            email_delivery: EmailDeliveryConfig {
                provider: EmailProviderConfig::Stdout,
                batch_size: 10,
                max_attempts: 5,
                retry_seconds: 300,
                sending_timeout_seconds: 900,
            },
            request_identity: crate::config::RequestIdentityConfig {
                trusted_proxy_ips: Vec::new(),
            },
            bootstrap_setup_secret_hash: None,
            signing: None,
            key_encryption_key: Some(key),
        };

        let rendered = render_email(&message, &config).unwrap();

        assert_eq!(
            rendered.payload.text,
            "Continue: http://localhost:5173/reset-password?token=token%20with%20space"
        );
    }

    #[test]
    fn render_email_allows_token_free_notifications_without_kek() {
        let now = OffsetDateTime::now_utc();
        let config = test_config(Environment::Development, EmailProviderConfig::Stdout);

        for template in [
            "password_changed_notification",
            "password_recovered_notification",
            "new_login_notification",
        ] {
            let message = EmailOutboxMessage {
                id: Uuid::new_v4(),
                organization_id: Uuid::new_v4(),
                recipient_email: "user@example.com".to_owned(),
                subject: "Security notification".to_owned(),
                body_text: format!("Security notification from {template}."),
                template: template.to_owned(),
                action_path: None,
                delivery_token_ciphertext: None,
                delivery_token_nonce: None,
                status: "sending".to_owned(),
                attempts: 1,
                last_error: None,
                provider_message_id: None,
                metadata: json!({
                    "kind": template
                }),
                created_at: now,
                updated_at: now,
                next_attempt_at: None,
                sent_at: None,
            };

            let rendered = render_email(&message, &config).unwrap();

            assert_eq!(rendered.payload.template, template);
            assert_eq!(
                rendered.payload.text,
                format!("Security notification from {template}.")
            );
        }
    }

    fn test_config(environment: Environment, provider: EmailProviderConfig) -> ApiConfig {
        ApiConfig {
            environment,
            bind: "127.0.0.1:8080".to_owned(),
            issuer: "http://localhost:8080".to_owned(),
            public_web_origin: "http://localhost:5173".to_owned(),
            database_url: "postgres://cairn:cairn@localhost:5432/cairn_identity".to_owned(),
            default_org_slug: "default".to_owned(),
            scim: ScimConfig {
                bearer_token_sha256_hashes: Vec::new(),
            },
            audit: AuditOperationsConfig {
                retention_days: 365,
                purge_batch_size: 1000,
                export_max_rows: 10_000,
            },
            email_delivery: EmailDeliveryConfig {
                provider,
                batch_size: 10,
                max_attempts: 5,
                retry_seconds: 300,
                sending_timeout_seconds: 900,
            },
            request_identity: crate::config::RequestIdentityConfig {
                trusted_proxy_ips: Vec::new(),
            },
            bootstrap_setup_secret_hash: None,
            signing: None,
            key_encryption_key: None,
        }
    }
}
