mod export;
mod retention;

use crate::config::ApiConfig;
use cairn_database::Database;
use cairn_domain::OrganizationId;
use export::{audit_export_options, export_audit_events_ndjson};
use retention::purge_expired_audit_events;
use time::OffsetDateTime;

const AUDIT_COMMAND_USAGE: &str = "usage: cairn-api audit <purge-expired|export-ndjson <output-path> [--limit <rows>] [--action <prefix>] [--target <prefix>] [--actor-kind <user|client|system>] [--actor-id <uuid>] [--from <rfc3339>] [--to <rfc3339>] [--after-created-at <rfc3339> --after-id <uuid>]>";

pub async fn run_audit_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("purge-expired") => {
            let config = ApiConfig::from_env()?;
            let (database, organization_id) = default_organization_database(&config).await?;
            let report = purge_expired_audit_events(
                &database,
                &config,
                organization_id,
                OffsetDateTime::now_utc(),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("export-ndjson") => {
            let config = ApiConfig::from_env()?;
            let options = audit_export_options(&args[1..], config.audit.export_max_rows)?;
            let (database, organization_id) = default_organization_database(&config).await?;
            let report = export_audit_events_ndjson(
                &database,
                organization_id,
                config.audit.export_max_rows,
                options,
                OffsetDateTime::now_utc(),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        _ => Err(config_error(AUDIT_COMMAND_USAGE)),
    }
}

async fn default_organization_database(
    config: &ApiConfig,
) -> Result<(Database, OrganizationId), Box<dyn std::error::Error>> {
    let database = Database::connect(&config.database_url).await?;
    database.migrate().await?;
    let organization_id = database
        .get_organization_by_slug(&config.default_org_slug)
        .await?
        .ok_or_else(|| {
            config_error_owned(format!(
                "organization {} does not exist",
                config.default_org_slug
            ))
        })?
        .id;

    Ok((database, organization_id))
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    message.into()
}

fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    message.into()
}
