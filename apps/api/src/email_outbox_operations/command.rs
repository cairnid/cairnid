use super::{errors::config_error, errors::config_error_owned, report};
use crate::{
    config::ApiConfig,
    email::{deliver_once, smoke_provider},
};
use cairn_database::Database;
use time::OffsetDateTime;

pub(crate) async fn run_email_outbox_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("deliver-once") => {
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let report = deliver_once(&database, &config).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("smoke-provider") => {
            let Some(recipient_email) = args.get(1) else {
                return Err(config_error(
                    "usage: cairn-api email-outbox smoke-provider <recipient-email>",
                ));
            };
            let config = ApiConfig::from_env()?;
            let report = smoke_provider(&config, recipient_email).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("lifecycle-smoke-evidence") => {
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let organization = database
                .get_organization_by_slug(&config.default_org_slug)
                .await?
                .ok_or_else(|| {
                    config_error_owned(format!(
                        "organization {} does not exist",
                        config.default_org_slug
                    ))
                })?;
            let report = report::lifecycle_email_smoke_evidence_report(
                &database,
                &config,
                organization.id,
                OffsetDateTime::now_utc(),
            )
            .await?;
            let ready = report.is_ready();
            println!("{}", serde_json::to_string_pretty(&report)?);
            if ready {
                Ok(())
            } else {
                Err(config_error(
                    "lifecycle email smoke evidence is incomplete; run provider lifecycle smoke and deliver-once first",
                ))
            }
        }
        _ => Err(config_error(
            "usage: cairn-api email-outbox <deliver-once|smoke-provider <recipient-email>|lifecycle-smoke-evidence>",
        )),
    }
}
