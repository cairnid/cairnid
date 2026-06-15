use super::{
    checks::restore_drill_checks_and_failures,
    types::{RestoreDrillDatabaseReport, RestoreDrillReport, RestoreDrillSigningReport},
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[test]
fn restore_drill_checks_require_migrations_org_and_signing_source() {
    let report = RestoreDrillReport {
        status: "ok",
        organization_slug: "default".to_owned(),
        organization_id: None,
        completed_at: OffsetDateTime::UNIX_EPOCH,
        database: RestoreDrillDatabaseReport {
            reachable: true,
            applied_migrations: 0,
            migrations_present: false,
        },
        signing: RestoreDrillSigningReport {
            legacy_env_configured: false,
            key_encryption_key_configured: false,
            active_database_kid: None,
            active_jwks_count: 0,
            active_database_key_decryptable: false,
            signing_source_available: false,
        },
        checks: Vec::new(),
        failures: Vec::new(),
    };

    let (checks, failures) = restore_drill_checks_and_failures(&report);

    assert!(checks.iter().any(|check| check == "database is reachable"));
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("no applied SQLx migrations"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("default organization"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("signing source is unavailable"))
    );

    let ready_report = RestoreDrillReport {
        organization_id: Some(Uuid::new_v4()),
        database: RestoreDrillDatabaseReport {
            reachable: true,
            applied_migrations: 7,
            migrations_present: true,
        },
        signing: RestoreDrillSigningReport {
            legacy_env_configured: false,
            key_encryption_key_configured: true,
            active_database_kid: Some("rs256-active".to_owned()),
            active_jwks_count: 1,
            active_database_key_decryptable: true,
            signing_source_available: true,
        },
        ..report
    };

    let (_checks, failures) = restore_drill_checks_and_failures(&ready_report);
    assert!(failures.is_empty());
}

#[test]
fn restore_drill_report_serializes_manual_evidence_timestamp() {
    let completed_at = OffsetDateTime::UNIX_EPOCH + Duration::days(2);
    let report = RestoreDrillReport {
        status: "ok",
        organization_slug: "default".to_owned(),
        organization_id: Some(Uuid::new_v4()),
        completed_at,
        database: RestoreDrillDatabaseReport {
            reachable: true,
            applied_migrations: 7,
            migrations_present: true,
        },
        signing: RestoreDrillSigningReport {
            legacy_env_configured: true,
            key_encryption_key_configured: false,
            active_database_kid: None,
            active_jwks_count: 0,
            active_database_key_decryptable: false,
            signing_source_available: true,
        },
        checks: vec!["database is reachable".to_owned()],
        failures: Vec::new(),
    };

    let value = serde_json::to_value(report).expect("restore drill report json");

    assert_eq!(value["status"], "ok");
    assert_eq!(value["completed_at"], "1970-01-03T00:00:00Z");
    assert!(value["failures"].as_array().expect("failures").is_empty());
}
