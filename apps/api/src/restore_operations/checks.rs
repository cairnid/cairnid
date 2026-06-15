use super::types::RestoreDrillReport;

pub(super) fn restore_drill_checks_and_failures(
    report: &RestoreDrillReport,
) -> (Vec<String>, Vec<String>) {
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    if report.database.reachable {
        checks.push("database is reachable".to_owned());
    } else {
        failures.push("database is not reachable".to_owned());
    }
    if report.database.migrations_present {
        checks.push("restored database has applied migrations".to_owned());
    } else {
        failures.push("restored database has no applied SQLx migrations".to_owned());
    }
    if report.organization_id.is_some() {
        checks.push("default organization exists in restored database".to_owned());
    } else {
        failures.push(format!(
            "default organization {} does not exist in restored database",
            report.organization_slug
        ));
    }
    if report.signing.signing_source_available {
        checks.push("OIDC signing source is available after restore".to_owned());
    } else {
        failures.push(
            "OIDC signing source is unavailable after restore; configure CAIRN_KEY_ENCRYPTION_KEY for restored database keys or legacy CAIRN_SIGNING_* material".to_owned(),
        );
    }
    if report.signing.active_database_kid.is_some() {
        checks.push("restored database contains an active signing key".to_owned());
        if report.signing.active_database_key_decryptable {
            checks.push(
                "active restored database signing key decrypts with configured KEK".to_owned(),
            );
        } else if !report.signing.legacy_env_configured {
            failures.push(
                "active restored database signing key cannot be decrypted and no legacy signing material is configured".to_owned(),
            );
        }
    } else if report.signing.legacy_env_configured {
        checks.push("legacy signing environment material is configured".to_owned());
    } else {
        failures.push("restored database has no active signing key".to_owned());
    }
    if report.signing.active_jwks_count > 0 {
        checks.push("restored database exposes active JWKS material".to_owned());
    } else if !report.signing.legacy_env_configured {
        failures.push("restored database has no active JWKS material".to_owned());
    }

    (checks, failures)
}
