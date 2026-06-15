use super::errors::config_error_owned;
use crate::{
    config::ApiConfig, dependency_policy_operations::dependency_policy_evidence_report,
    operations_preflight::operations_preflight_report, restore_operations::restore_drill_report,
};
use cairn_database::Database;
use time::OffsetDateTime;

pub(super) async fn run_preflight_command() -> Result<(), Box<dyn std::error::Error>> {
    let config = ApiConfig::from_env()?;
    let database = Database::connect(&config.database_url).await?;
    let report = operations_preflight_report(&database, &config).await?;
    let ready = report.failures.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "operations preflight failed: {}",
            report.failures.join("; ")
        )))
    }
}

pub(super) fn run_dependency_policy_evidence_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = dependency_policy_evidence_report(OffsetDateTime::now_utc());
    let ready = report.failures.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "dependency policy evidence failed: {}",
            report.failures.join("; ")
        )))
    }
}

pub(super) async fn run_restore_check_command() -> Result<(), Box<dyn std::error::Error>> {
    let config = ApiConfig::from_env()?;
    let database = Database::connect(&config.database_url).await?;
    let report = restore_drill_report(&database, &config, OffsetDateTime::now_utc()).await?;
    let ready = report.failures.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "restore check failed: {}",
            report.failures.join("; ")
        )))
    }
}
