use crate::config::{ApiConfig, EmailProviderConfig};
use cairn_database::EmailOutboxQueueSummary;
use cairn_domain::Environment;
use serde::Serialize;
use time::OffsetDateTime;

pub(super) fn email_delivery_operations_preflight_report(
    config: &ApiConfig,
    provider: &'static str,
    queue: EmailOutboxQueueSummary,
) -> EmailDeliveryPreflightReport {
    let command_path_configured = match &config.email_delivery.provider {
        EmailProviderConfig::Command { path } => !path.trim().is_empty(),
        _ => false,
    };
    let command_provider_configured = matches!(
        config.email_delivery.provider,
        EmailProviderConfig::Command { .. }
    );
    let enabled = !matches!(
        config.email_delivery.provider,
        EmailProviderConfig::Disabled
    );
    let key_encryption_key_configured = config.key_encryption_key.is_some();
    let production_ready = !matches!(config.environment, Environment::Production)
        || (command_provider_configured
            && command_path_configured
            && key_encryption_key_configured);

    EmailDeliveryPreflightReport {
        provider,
        production_ready,
        command_provider_configured,
        command_path_configured,
        key_encryption_key_configured,
        batch_size: config.email_delivery.batch_size,
        max_attempts: config.email_delivery.max_attempts,
        retry_seconds: config.email_delivery.retry_seconds,
        sending_timeout_seconds: config.email_delivery.sending_timeout_seconds,
        delivery_command: enabled.then_some("cairn-api email-outbox deliver-once"),
        provider_smoke_command: enabled
            .then_some("cairn-api email-outbox smoke-provider <recipient-email>"),
        provider_smoke_required: matches!(config.environment, Environment::Production),
        queue: EmailOutboxQueuePreflightReport {
            queued: queue.queued,
            retry: queue.retry,
            retry_due: queue.retry_due,
            sending: queue.sending,
            stale_sending: queue.stale_sending,
            failed: queue.failed,
            sent: queue.sent,
            unfinished: queue.unfinished,
            oldest_unfinished_at: queue.oldest_unfinished_at,
            next_retry_at: queue.next_retry_at,
            attention_required: queue.failed > 0,
        },
    }
}

pub(super) fn email_provider_name(provider: &EmailProviderConfig) -> &'static str {
    match provider {
        EmailProviderConfig::Disabled => "disabled",
        EmailProviderConfig::Stdout => "stdout",
        EmailProviderConfig::Command { .. } => "command",
    }
}

#[derive(Debug, Serialize)]
pub(super) struct EmailDeliveryPreflightReport {
    pub(super) provider: &'static str,
    pub(super) production_ready: bool,
    pub(super) command_provider_configured: bool,
    pub(super) command_path_configured: bool,
    pub(super) key_encryption_key_configured: bool,
    pub(super) batch_size: i64,
    pub(super) max_attempts: i32,
    pub(super) retry_seconds: i64,
    pub(super) sending_timeout_seconds: i64,
    pub(super) delivery_command: Option<&'static str>,
    pub(super) provider_smoke_command: Option<&'static str>,
    pub(super) provider_smoke_required: bool,
    pub(super) queue: EmailOutboxQueuePreflightReport,
}

#[derive(Debug, Serialize)]
pub(super) struct EmailOutboxQueuePreflightReport {
    pub(super) queued: i64,
    pub(super) retry: i64,
    pub(super) retry_due: i64,
    pub(super) sending: i64,
    pub(super) stale_sending: i64,
    pub(super) failed: i64,
    pub(super) sent: i64,
    pub(super) unfinished: i64,
    pub(super) oldest_unfinished_at: Option<OffsetDateTime>,
    pub(super) next_retry_at: Option<OffsetDateTime>,
    pub(super) attention_required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, ScimConfig};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn email_delivery_preflight_reports_worker_and_retry_settings() {
        let mut config = test_config(Environment::Production);
        config.email_delivery = EmailDeliveryConfig {
            provider: EmailProviderConfig::Command {
                path: "/app/send-email".to_owned(),
            },
            batch_size: 25,
            max_attempts: 8,
            retry_seconds: 120,
            sending_timeout_seconds: 600,
        };

        let queue_summary = EmailOutboxQueueSummary {
            queued: 3,
            retry: 2,
            retry_due: 1,
            sending: 1,
            stale_sending: 1,
            failed: 0,
            sent: 9,
            unfinished: 6,
            oldest_unfinished_at: Some(OffsetDateTime::UNIX_EPOCH),
            next_retry_at: Some(OffsetDateTime::UNIX_EPOCH + Duration::minutes(5)),
        };
        let report = email_delivery_operations_preflight_report(&config, "command", queue_summary);

        assert_eq!(report.provider, "command");
        assert!(report.command_provider_configured);
        assert!(report.command_path_configured);
        assert!(!report.key_encryption_key_configured);
        assert_eq!(report.batch_size, 25);
        assert_eq!(report.max_attempts, 8);
        assert_eq!(report.retry_seconds, 120);
        assert_eq!(report.sending_timeout_seconds, 600);
        assert_eq!(
            report.delivery_command,
            Some("cairn-api email-outbox deliver-once")
        );
        assert_eq!(
            report.provider_smoke_command,
            Some("cairn-api email-outbox smoke-provider <recipient-email>")
        );
        assert!(report.provider_smoke_required);
        assert!(!report.production_ready);
        assert_eq!(report.queue.queued, 3);
        assert_eq!(report.queue.retry, 2);
        assert_eq!(report.queue.retry_due, 1);
        assert_eq!(report.queue.sending, 1);
        assert_eq!(report.queue.stale_sending, 1);
        assert_eq!(report.queue.failed, 0);
        assert_eq!(report.queue.sent, 9);
        assert_eq!(report.queue.unfinished, 6);
        assert_eq!(
            report.queue.oldest_unfinished_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
        assert_eq!(
            report.queue.next_retry_at,
            Some(OffsetDateTime::UNIX_EPOCH + Duration::minutes(5))
        );
        assert!(!report.queue.attention_required);

        config.environment = Environment::Development;
        config.email_delivery.provider = EmailProviderConfig::Stdout;
        let development = email_delivery_operations_preflight_report(
            &config,
            "stdout",
            EmailOutboxQueueSummary::default(),
        );
        assert!(development.production_ready);
        assert!(!development.command_provider_configured);
        assert!(!development.provider_smoke_required);
    }

    fn test_config(environment: Environment) -> ApiConfig {
        ApiConfig {
            environment,
            bind: "127.0.0.1:8080".to_owned(),
            issuer: "https://id.example.com".to_owned(),
            public_web_origin: "https://app.example.com".to_owned(),
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
                provider: EmailProviderConfig::Disabled,
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
