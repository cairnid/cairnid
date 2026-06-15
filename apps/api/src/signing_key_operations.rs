use crate::config::ApiConfig;
use cairn_database::Database;
use cairn_domain::Environment;
use cairn_oidc::{
    encrypt_signing_material, generate_encrypted_signing_key, generate_key_encryption_key,
};
use serde::Serialize;
use serde_json::json;
use std::io;
use time::OffsetDateTime;

pub(crate) async fn ensure_startup_signing_key(
    database: &Database,
    config: &ApiConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.key_encryption_key.is_none()
        && config.signing.is_none()
        && matches!(config.environment, Environment::Production)
    {
        return Err(config_error(
            "production requires CAIRN_KEY_ENCRYPTION_KEY or legacy CAIRN_SIGNING_* material",
        ));
    }

    let Some(key_encryption_key) = &config.key_encryption_key else {
        return Ok(());
    };

    if database.active_signing_key().await?.is_some() {
        return Ok(());
    }

    let key = match &config.signing {
        Some(signing) => encrypt_signing_material(signing, key_encryption_key)?,
        None => generate_encrypted_signing_key(key_encryption_key)?,
    };
    let kid = key.kid.clone();
    database.upsert_signing_key_material(&key).await?;
    tracing::info!(%kid, imported_from_env = config.signing.is_some(), "ensured active OIDC signing key");
    Ok(())
}

pub(crate) async fn run_signing_key_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("generate-kek") => {
            println!("{}", generate_key_encryption_key());
            Ok(())
        }
        Some("list") => {
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let keys = database.list_signing_keys().await?;
            println!("{}", serde_json::to_string_pretty(&keys)?);
            Ok(())
        }
        Some("ensure") => {
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            ensure_startup_signing_key(&database, &config).await?;
            let active = database.active_signing_key().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "ok",
                    "active_kid": active.map(|key| key.kid)
                }))?
            );
            Ok(())
        }
        Some("rotate") => {
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let key_encryption_key = config.key_encryption_key.as_ref().ok_or_else(|| {
                config_error("CAIRN_KEY_ENCRYPTION_KEY is required to rotate signing keys")
            })?;
            let key = generate_encrypted_signing_key(key_encryption_key)?;
            let report = SigningKeyRotationReport {
                status: "rotated",
                active_kid: key.kid.clone(),
                active: key.signing_active,
                completed_at: OffsetDateTime::now_utc(),
            };
            database.upsert_signing_key_material(&key).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("retire") => {
            let Some(kid) = args.get(1) else {
                return Err(config_error("usage: cairn-api signing-key retire <kid>"));
            };
            let config = ApiConfig::from_env()?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let retired = database
                .retire_signing_key(kid, OffsetDateTime::now_utc())
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": if retired { "retired" } else { "not_found" },
                    "kid": kid
                }))?
            );
            Ok(())
        }
        _ => Err(config_error(
            "usage: cairn-api signing-key <generate-kek|list|ensure|rotate|retire>",
        )),
    }
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[derive(Debug, Serialize)]
struct SigningKeyRotationReport {
    status: &'static str,
    active_kid: String,
    active: bool,
    #[serde(with = "time::serde::rfc3339")]
    completed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::{SigningKeyRotationReport, ensure_startup_signing_key};
    use crate::config::{
        ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use cairn_database::Database;
    use cairn_domain::Environment;
    use time::{Duration, OffsetDateTime};

    #[tokio::test]
    async fn production_startup_requires_signing_source_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
            .expect("lazy pool");
        let database = Database::from_pool(pool);
        let config = test_config(Environment::Production);

        let error = ensure_startup_signing_key(&database, &config)
            .await
            .expect_err("production startup must reject missing signing source");

        assert!(
            error
                .to_string()
                .contains("production requires CAIRN_KEY_ENCRYPTION_KEY")
        );
    }

    #[test]
    fn signing_key_rotation_report_serializes_evidence_timestamp_as_rfc3339() {
        let report = SigningKeyRotationReport {
            status: "rotated",
            active_kid: "rs256-active".to_owned(),
            active: true,
            completed_at: OffsetDateTime::UNIX_EPOCH + Duration::days(4),
        };

        let value = serde_json::to_value(report).expect("signing key rotation report json");

        assert_eq!(value["status"], "rotated");
        assert_eq!(value["active_kid"], "rs256-active");
        assert_eq!(value["active"], true);
        assert_eq!(value["completed_at"], "1970-01-05T00:00:00Z");
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
