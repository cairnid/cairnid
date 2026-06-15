use crate::config::ApiConfig;
use cairn_database::SigningKeyLifecycleSummary;
use cairn_domain::SigningKeyMaterial;
use cairn_oidc::decrypt_signing_material;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

pub(super) const SIGNING_KEY_ROTATION_RECOMMENDED_AFTER_DAYS: i64 = 90;

pub(super) fn database_active_signing_key_decryptable(
    config: &ApiConfig,
    active_signing_key: Option<&SigningKeyMaterial>,
) -> bool {
    match (&config.key_encryption_key, active_signing_key) {
        (Some(key_encryption_key), Some(signing_key)) => {
            decrypt_signing_material(signing_key, key_encryption_key).is_ok()
        }
        _ => false,
    }
}

pub(super) fn signing_operations_preflight_report(
    config: &ApiConfig,
    database_active_kid: Option<String>,
    active_jwks_count: usize,
    database_active_key_decryptable: bool,
    lifecycle: SigningKeyLifecycleSummary,
    now: OffsetDateTime,
) -> SigningPreflightReport {
    let active_key_age_seconds = lifecycle
        .active_created_at
        .map(|created_at| (now - created_at).whole_seconds().max(0));
    let rotation_recommended_after_seconds =
        Duration::days(SIGNING_KEY_ROTATION_RECOMMENDED_AFTER_DAYS).whole_seconds();

    SigningPreflightReport {
        legacy_env_configured: config.signing.is_some(),
        key_encryption_key_configured: config.key_encryption_key.is_some(),
        database_active_kid,
        active_jwks_count,
        database_active_key_decryptable,
        lifecycle: SigningKeyLifecyclePreflightReport {
            total_key_count: lifecycle.total,
            active_key_count: lifecycle.active,
            active_with_private_material_count: lifecycle.active_with_private_material,
            unretired_key_count: lifecycle.unretired,
            retired_key_count: lifecycle.retired,
            rollover_key_count: lifecycle.rollover,
            encrypted_private_material_count: lifecycle.encrypted_private_material,
            active_key_created_at: lifecycle.active_created_at,
            active_key_age_seconds,
            oldest_unretired_key_created_at: lifecycle.oldest_unretired_created_at,
            newest_retired_key_at: lifecycle.newest_retired_at,
            rotation_recommended_after_days: SIGNING_KEY_ROTATION_RECOMMENDED_AFTER_DAYS,
            rotation_recommended: active_key_age_seconds
                .is_some_and(|age| age >= rotation_recommended_after_seconds),
            ensure_command: "cairn-api signing-key ensure",
            rotate_command: "cairn-api signing-key rotate",
            list_command: "cairn-api signing-key list",
            retire_command: "cairn-api signing-key retire <kid>",
        },
    }
}

#[derive(Debug, Serialize)]
pub(super) struct SigningPreflightReport {
    pub(super) legacy_env_configured: bool,
    pub(super) key_encryption_key_configured: bool,
    pub(super) database_active_kid: Option<String>,
    pub(super) active_jwks_count: usize,
    pub(super) database_active_key_decryptable: bool,
    pub(super) lifecycle: SigningKeyLifecyclePreflightReport,
}

#[derive(Debug, Serialize)]
pub(super) struct SigningKeyLifecyclePreflightReport {
    pub(super) total_key_count: i64,
    pub(super) active_key_count: i64,
    pub(super) active_with_private_material_count: i64,
    pub(super) unretired_key_count: i64,
    pub(super) retired_key_count: i64,
    pub(super) rollover_key_count: i64,
    pub(super) encrypted_private_material_count: i64,
    pub(super) active_key_created_at: Option<OffsetDateTime>,
    pub(super) active_key_age_seconds: Option<i64>,
    pub(super) oldest_unretired_key_created_at: Option<OffsetDateTime>,
    pub(super) newest_retired_key_at: Option<OffsetDateTime>,
    pub(super) rotation_recommended_after_days: i64,
    pub(super) rotation_recommended: bool,
    pub(super) ensure_command: &'static str,
    pub(super) rotate_command: &'static str,
    pub(super) list_command: &'static str,
    pub(super) retire_command: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use cairn_domain::Environment;

    #[test]
    fn signing_preflight_reports_lifecycle_age_and_rotation_recommendation() {
        let mut config = test_config(Environment::Production);
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(120);
        let active_created_at = now - Duration::days(91);

        let report = signing_operations_preflight_report(
            &config,
            Some("rs256-active".to_owned()),
            2,
            true,
            SigningKeyLifecycleSummary {
                total: 3,
                active: 1,
                active_with_private_material: 1,
                unretired: 2,
                retired: 1,
                rollover: 1,
                encrypted_private_material: 3,
                active_created_at: Some(active_created_at),
                oldest_unretired_created_at: Some(active_created_at - Duration::days(1)),
                newest_retired_at: Some(now - Duration::days(7)),
            },
            now,
        );

        assert_eq!(report.database_active_kid.as_deref(), Some("rs256-active"));
        assert_eq!(report.active_jwks_count, 2);
        assert_eq!(report.lifecycle.total_key_count, 3);
        assert_eq!(report.lifecycle.active_key_count, 1);
        assert_eq!(report.lifecycle.rollover_key_count, 1);
        assert_eq!(report.lifecycle.retired_key_count, 1);
        assert_eq!(
            report.lifecycle.active_key_age_seconds,
            Some(91 * 24 * 60 * 60)
        );
        assert_eq!(report.lifecycle.rotation_recommended_after_days, 90);
        assert!(report.lifecycle.rotation_recommended);
        assert_eq!(
            report.lifecycle.rotate_command,
            "cairn-api signing-key rotate"
        );

        config.signing = None;
        let fresh_report = signing_operations_preflight_report(
            &config,
            Some("rs256-fresh".to_owned()),
            1,
            true,
            SigningKeyLifecycleSummary {
                total: 1,
                active: 1,
                active_with_private_material: 1,
                unretired: 1,
                retired: 0,
                rollover: 0,
                encrypted_private_material: 1,
                active_created_at: Some(now - Duration::days(1)),
                oldest_unretired_created_at: Some(now - Duration::days(1)),
                newest_retired_at: None,
            },
            now,
        );
        assert!(!fresh_report.lifecycle.rotation_recommended);
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
