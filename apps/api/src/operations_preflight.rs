use crate::{
    config::ApiConfig,
    conformance_operations::{
        OpenIdConformanceOperationsPreflightReport, openid_conformance_operations_preflight_report,
    },
};
use cairn_database::{Database, EmailOutboxQueueSummary, SigningKeyLifecycleSummary};
use cairn_domain::Environment;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

mod email_delivery;
mod failure_policy;
mod scim;
mod signing;

use self::email_delivery::{
    EmailDeliveryPreflightReport, email_delivery_operations_preflight_report, email_provider_name,
};
use self::failure_policy::operations_preflight_failures;
use self::scim::{ScimOperationsPreflightReport, scim_operations_preflight_report};
use self::signing::{
    SigningPreflightReport, database_active_signing_key_decryptable,
    signing_operations_preflight_report,
};

pub(crate) async fn operations_preflight_report(
    database: &Database,
    config: &ApiConfig,
) -> Result<OperationsPreflightReport, Box<dyn std::error::Error>> {
    database.health_check().await?;
    let applied_migrations = database.applied_migration_count().await?;
    let (active_jwks_count, active_signing_key) = if applied_migrations > 0 {
        (
            database.active_jwks().await?.len(),
            database.active_signing_key().await?,
        )
    } else {
        (0, None)
    };
    let signing_lifecycle = if applied_migrations > 0 {
        database.signing_key_lifecycle_summary().await?
    } else {
        SigningKeyLifecycleSummary::default()
    };
    let database_active_kid = active_signing_key.as_ref().map(|key| key.kid.clone());
    let database_active_key_decryptable =
        database_active_signing_key_decryptable(config, active_signing_key.as_ref());
    let email_provider = email_provider_name(&config.email_delivery.provider);
    let email_outbox_queue = if applied_migrations > 0 {
        let now = OffsetDateTime::now_utc();
        database
            .email_outbox_queue_summary(
                now,
                now - Duration::seconds(config.email_delivery.sending_timeout_seconds),
            )
            .await?
    } else {
        EmailOutboxQueueSummary::default()
    };
    let email_delivery =
        email_delivery_operations_preflight_report(config, email_provider, email_outbox_queue);
    let openid_conformance = openid_conformance_operations_preflight_report(config);
    let scim = scim_operations_preflight_report(config);

    let mut report = OperationsPreflightReport {
        status: "ok",
        environment: config.environment,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations,
        },
        signing: signing_operations_preflight_report(
            config,
            database_active_kid,
            active_jwks_count,
            database_active_key_decryptable,
            signing_lifecycle,
            OffsetDateTime::now_utc(),
        ),
        audit: AuditOperationsPreflightReport {
            retention_days: config.audit.retention_days,
            purge_batch_size: config.audit.purge_batch_size,
            export_max_rows: config.audit.export_max_rows,
        },
        email_delivery,
        openid_conformance,
        scim,
        failures: Vec::new(),
    };
    report.failures = operations_preflight_failures(&report);
    report.status = if report.failures.is_empty() {
        "ok"
    } else {
        "failed"
    };

    Ok(report)
}

#[derive(Debug, Serialize)]
pub(crate) struct OperationsPreflightReport {
    status: &'static str,
    environment: Environment,
    database: DatabasePreflightReport,
    signing: SigningPreflightReport,
    audit: AuditOperationsPreflightReport,
    email_delivery: EmailDeliveryPreflightReport,
    openid_conformance: OpenIdConformanceOperationsPreflightReport,
    scim: ScimOperationsPreflightReport,
    pub(crate) failures: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DatabasePreflightReport {
    reachable: bool,
    applied_migrations: i64,
}

#[derive(Debug, Serialize)]
struct AuditOperationsPreflightReport {
    retention_days: i64,
    purge_batch_size: i64,
    export_max_rows: i64,
}
