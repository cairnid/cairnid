use super::{
    EmailDeliveryError,
    rendering::{EmailCommandPayload, RenderedEmail},
    truncate_error,
};
use crate::config::{ApiConfig, EmailProviderConfig};
use cairn_domain::Environment;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmailProviderSmokeReport {
    pub status: &'static str,
    pub provider: &'static str,
    pub recipient_email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub provider_message_id: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CommandReceipt {
    provider_message_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProviderReceipt {
    pub provider_message_id: Option<String>,
}

pub async fn smoke_provider(
    config: &ApiConfig,
    recipient_email: &str,
) -> Result<EmailProviderSmokeReport, EmailDeliveryError> {
    let recipient_email = recipient_email.trim();
    if recipient_email.is_empty() || !recipient_email.contains('@') {
        return Err(EmailDeliveryError::InvalidSmokeRecipient);
    }

    let completed_at = OffsetDateTime::now_utc();
    let rendered = RenderedEmail {
        payload: EmailCommandPayload {
            id: Uuid::new_v4(),
            to: recipient_email.to_owned(),
            subject: "Cairn Identity email provider smoke test".to_owned(),
            text: format!(
                "This is a Cairn Identity lifecycle email provider smoke test.\n\nIssuer: {}\nWeb origin: {}\n\nNo account token or user secret is included.",
                config.issuer, config.public_web_origin
            ),
            template: "provider_smoke".to_owned(),
            metadata: serde_json::json!({
                "kind": "provider_smoke",
                "environment": config.environment,
                "issuer": config.issuer,
                "public_web_origin": config.public_web_origin,
                "generated_at": completed_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_owned())
            }),
        },
    };
    let receipt = send_email(&rendered, config).await?;

    Ok(EmailProviderSmokeReport {
        status: "sent",
        provider: provider_name(&config.email_delivery.provider),
        recipient_email: recipient_email.to_owned(),
        completed_at,
        provider_message_id: receipt.provider_message_id,
    })
}

pub(super) async fn send_email(
    rendered: &RenderedEmail,
    config: &ApiConfig,
) -> Result<ProviderReceipt, EmailDeliveryError> {
    match &config.email_delivery.provider {
        EmailProviderConfig::Disabled => Err(EmailDeliveryError::Disabled),
        EmailProviderConfig::Stdout => {
            if matches!(config.environment, Environment::Production) {
                return Err(EmailDeliveryError::ProviderCommand(
                    "stdout provider is development-only".to_owned(),
                ));
            }
            eprintln!("{}", serde_json::to_string(&rendered.payload)?);
            Ok(ProviderReceipt::default())
        }
        EmailProviderConfig::Command { path } => send_command(path, &rendered.payload).await,
    }
}

fn provider_name(provider: &EmailProviderConfig) -> &'static str {
    match provider {
        EmailProviderConfig::Disabled => "disabled",
        EmailProviderConfig::Stdout => "stdout",
        EmailProviderConfig::Command { .. } => "command",
    }
}

async fn send_command(
    path: &str,
    payload: &EmailCommandPayload,
) -> Result<ProviderReceipt, EmailDeliveryError> {
    let path = path.to_owned();
    let payload = serde_json::to_vec(payload)?;
    tokio::task::spawn_blocking(move || run_command(&path, &payload))
        .await
        .map_err(|_| EmailDeliveryError::ProviderCommandJoin)?
}

fn run_command(path: &str, payload: &[u8]) -> Result<ProviderReceipt, EmailDeliveryError> {
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| EmailDeliveryError::ProviderCommand(error.to_string()))?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        EmailDeliveryError::ProviderCommand("failed to open provider stdin".to_owned())
    })?;
    stdin
        .write_all(payload)
        .map_err(|error| EmailDeliveryError::ProviderCommand(error.to_string()))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| EmailDeliveryError::ProviderCommand(error.to_string()))?;
    if !output.status.success() {
        return Err(EmailDeliveryError::ProviderCommand(format!(
            "exit status {}; stderr: {}",
            output.status,
            truncate_error(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        return Ok(ProviderReceipt::default());
    }

    let receipt = serde_json::from_str::<CommandReceipt>(stdout)?;
    Ok(ProviderReceipt {
        provider_message_id: receipt.provider_message_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };

    #[test]
    fn command_receipt_accepts_provider_message_id() {
        let receipt = serde_json::from_str::<CommandReceipt>(
            r#"{ "provider_message_id": "provider-message-1" }"#,
        )
        .unwrap();

        assert_eq!(
            receipt.provider_message_id.as_deref(),
            Some("provider-message-1")
        );
    }

    #[tokio::test]
    async fn smoke_provider_rejects_blank_or_malformed_recipients() {
        let config = test_config(Environment::Development, EmailProviderConfig::Stdout);

        for recipient in ["", "   ", "ops.example.com"] {
            let error = smoke_provider(&config, recipient)
                .await
                .expect_err("smoke recipient must be a plausible email address");

            assert!(matches!(error, EmailDeliveryError::InvalidSmokeRecipient));
        }
    }

    #[tokio::test]
    async fn smoke_provider_rejects_disabled_delivery() {
        let config = test_config(Environment::Development, EmailProviderConfig::Disabled);

        let error = smoke_provider(&config, "ops@example.com")
            .await
            .expect_err("disabled delivery cannot run a provider smoke");

        assert!(matches!(error, EmailDeliveryError::Disabled));
    }

    #[tokio::test]
    async fn smoke_provider_sends_synthetic_email_without_database() {
        let config = test_config(Environment::Development, EmailProviderConfig::Stdout);

        let before = OffsetDateTime::now_utc();
        let report = smoke_provider(&config, "ops@example.com")
            .await
            .expect("stdout smoke should send in development");
        let after = OffsetDateTime::now_utc();

        assert_eq!(report.status, "sent");
        assert_eq!(report.provider, "stdout");
        assert_eq!(report.recipient_email, "ops@example.com");
        assert!(report.completed_at >= before);
        assert!(report.completed_at <= after);
        assert_eq!(report.provider_message_id, None);
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
