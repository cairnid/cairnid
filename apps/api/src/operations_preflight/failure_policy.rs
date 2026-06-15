use cairn_domain::Environment;

use super::OperationsPreflightReport;

#[cfg(test)]
mod tests;

pub(super) fn operations_preflight_failures(report: &OperationsPreflightReport) -> Vec<String> {
    let mut failures = Vec::new();

    if report.database.applied_migrations == 0 {
        failures.push("no SQLx migrations have been applied".to_owned());
    }

    let has_any_signing_source =
        report.signing.legacy_env_configured || report.signing.database_active_kid.is_some();
    if !has_any_signing_source {
        failures.push(
            "no active OIDC signing source is configured; run signing-key ensure or configure legacy signing material"
                .to_owned(),
        );
    }

    if report.signing.database_active_kid.is_some()
        && !report.signing.database_active_key_decryptable
    {
        failures.push(
            "active database signing key cannot be decrypted with CAIRN_KEY_ENCRYPTION_KEY"
                .to_owned(),
        );
    }

    if report.signing.database_active_kid.is_some() && report.signing.active_jwks_count == 0 {
        failures.push("active database signing key is missing from JWKS".to_owned());
    }

    if report.signing.lifecycle.active_key_count > 1 {
        failures.push(
            "database signing-key lifecycle invariant is broken: multiple active signing keys"
                .to_owned(),
        );
    }

    if matches!(report.environment, Environment::Production) {
        if !report.signing.key_encryption_key_configured && !report.signing.legacy_env_configured {
            failures.push(
                "production requires CAIRN_KEY_ENCRYPTION_KEY or legacy CAIRN_SIGNING_* material"
                    .to_owned(),
            );
        }

        if !report.email_delivery.command_provider_configured {
            failures.push(
                "production lifecycle email delivery must use CAIRN_EMAIL_PROVIDER=command"
                    .to_owned(),
            );
        }

        if report.email_delivery.command_provider_configured
            && !report.email_delivery.command_path_configured
        {
            failures.push(
                "production lifecycle email delivery must configure non-empty CAIRN_EMAIL_COMMAND_PATH"
                    .to_owned(),
            );
        }

        if !report.email_delivery.key_encryption_key_configured {
            failures.push(
                "production lifecycle email delivery requires CAIRN_KEY_ENCRYPTION_KEY for encrypted outbox action links"
                    .to_owned(),
            );
        }

        if report.email_delivery.queue.failed > 0 {
            failures.push(
                "production email_outbox has failed messages; inspect and resolve failed lifecycle email delivery before readiness"
                    .to_owned(),
            );
        }
    }

    failures
}
