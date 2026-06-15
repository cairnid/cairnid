use super::{EmailDeliveryError, provider::send_email, rendering::render_email, truncate_error};
use crate::config::{ApiConfig, EmailProviderConfig};
use cairn_database::Database;
use cairn_domain::Environment;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmailDeliveryReport {
    pub claimed: usize,
    pub sent: usize,
    pub retried: usize,
    pub failed: usize,
}

pub async fn deliver_once(
    database: &Database,
    config: &ApiConfig,
) -> Result<EmailDeliveryReport, EmailDeliveryError> {
    if matches!(
        config.email_delivery.provider,
        EmailProviderConfig::Disabled
    ) {
        return Err(EmailDeliveryError::Disabled);
    }
    if matches!(config.environment, Environment::Production) && config.key_encryption_key.is_none()
    {
        return Err(EmailDeliveryError::MissingKeyEncryptionKey);
    }

    let now = OffsetDateTime::now_utc();
    let stale_sending_before =
        now - Duration::seconds(config.email_delivery.sending_timeout_seconds);
    let messages = database
        .claim_email_outbox_messages(config.email_delivery.batch_size, now, stale_sending_before)
        .await?;
    let mut report = EmailDeliveryReport {
        claimed: messages.len(),
        sent: 0,
        retried: 0,
        failed: 0,
    };

    for message in messages {
        let delivery_result = async {
            let rendered = render_email(&message, config)?;
            send_email(&rendered, config).await
        }
        .await;

        match delivery_result {
            Ok(receipt) => {
                database
                    .mark_email_outbox_sent(
                        message.id,
                        receipt.provider_message_id.as_deref(),
                        OffsetDateTime::now_utc(),
                    )
                    .await?;
                report.sent += 1;
            }
            Err(error) => {
                let failed_at = OffsetDateTime::now_utc();
                let last_error = truncate_error(&error.to_string());
                if error.is_permanent() || message.attempts >= config.email_delivery.max_attempts {
                    database
                        .mark_email_outbox_failed(message.id, &last_error, failed_at)
                        .await?;
                    report.failed += 1;
                } else {
                    let next_attempt_at =
                        failed_at + Duration::seconds(config.email_delivery.retry_seconds);
                    database
                        .mark_email_outbox_retry(
                            message.id,
                            &last_error,
                            next_attempt_at,
                            failed_at,
                        )
                        .await?;
                    report.retried += 1;
                }
            }
        }
    }

    Ok(report)
}
