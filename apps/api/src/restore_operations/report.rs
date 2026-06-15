use super::{
    checks::restore_drill_checks_and_failures,
    types::{RestoreDrillDatabaseReport, RestoreDrillReport, RestoreDrillSigningReport},
};
use crate::config::ApiConfig;
use cairn_database::Database;
use cairn_oidc::decrypt_signing_material;
use time::OffsetDateTime;

pub(crate) async fn restore_drill_report(
    database: &Database,
    config: &ApiConfig,
    completed_at: OffsetDateTime,
) -> Result<RestoreDrillReport, Box<dyn std::error::Error>> {
    database.health_check().await?;
    let applied_migrations = database.applied_migration_count().await?;
    let organization = if applied_migrations > 0 {
        database
            .get_organization_by_slug(&config.default_org_slug)
            .await?
    } else {
        None
    };
    let (active_jwks_count, active_signing_key) = if applied_migrations > 0 {
        (
            database.active_jwks().await?.len(),
            database.active_signing_key().await?,
        )
    } else {
        (0, None)
    };
    let active_database_key_decryptable =
        match (&config.key_encryption_key, active_signing_key.as_ref()) {
            (Some(key_encryption_key), Some(signing_key)) => {
                decrypt_signing_material(signing_key, key_encryption_key).is_ok()
            }
            _ => false,
        };

    let signing_source_available = config.signing.is_some() || active_database_key_decryptable;
    let mut report = RestoreDrillReport {
        status: "ok",
        organization_slug: config.default_org_slug.clone(),
        organization_id: organization.as_ref().map(|organization| organization.id),
        completed_at,
        database: RestoreDrillDatabaseReport {
            reachable: true,
            applied_migrations,
            migrations_present: applied_migrations > 0,
        },
        signing: RestoreDrillSigningReport {
            legacy_env_configured: config.signing.is_some(),
            key_encryption_key_configured: config.key_encryption_key.is_some(),
            active_database_kid: active_signing_key.as_ref().map(|key| key.kid.clone()),
            active_jwks_count,
            active_database_key_decryptable,
            signing_source_available,
        },
        checks: Vec::new(),
        failures: Vec::new(),
    };
    let (checks, failures) = restore_drill_checks_and_failures(&report);
    report.checks = checks;
    report.failures = failures;
    report.status = if report.failures.is_empty() {
        "ok"
    } else {
        "failed"
    };

    Ok(report)
}
