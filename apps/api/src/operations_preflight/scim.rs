use crate::config::{ApiConfig, SCIM_BEARER_TOKEN_HASH_MAX_VALUES};
use serde::Serialize;

pub(super) fn scim_operations_preflight_report(
    config: &ApiConfig,
) -> ScimOperationsPreflightReport {
    let bearer_token_hash_count = config.scim.bearer_token_sha256_hashes.len();
    let enabled = bearer_token_hash_count > 0;
    let issuer = config.issuer.trim_end_matches('/');

    ScimOperationsPreflightReport {
        enabled,
        bearer_token_hash_count,
        rotation_window: bearer_token_hash_count > 1,
        max_bearer_token_hashes: SCIM_BEARER_TOKEN_HASH_MAX_VALUES,
        service_provider_config_url: enabled
            .then(|| format!("{issuer}/scim/v2/ServiceProviderConfig")),
        connector_profile_command: "cairn-api scim connector-profile <generic|okta|entra>",
        smoke_command: enabled.then_some("cairn-api scim smoke"),
        deployment_smoke_required: enabled,
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ScimOperationsPreflightReport {
    pub(super) enabled: bool,
    pub(super) bearer_token_hash_count: usize,
    pub(super) rotation_window: bool,
    pub(super) max_bearer_token_hashes: usize,
    pub(super) service_provider_config_url: Option<String>,
    pub(super) connector_profile_command: &'static str,
    pub(super) smoke_command: Option<&'static str>,
    pub(super) deployment_smoke_required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use cairn_domain::Environment;

    #[test]
    fn scim_operations_preflight_reports_disabled_single_and_rotation_states() {
        let mut config = test_config(Environment::Production);
        config.issuer = "https://id.example.com/".to_owned();

        let disabled = scim_operations_preflight_report(&config);
        assert!(!disabled.enabled);
        assert_eq!(disabled.bearer_token_hash_count, 0);
        assert_eq!(disabled.max_bearer_token_hashes, 4);
        assert_eq!(disabled.service_provider_config_url, None);
        assert_eq!(disabled.smoke_command, None);
        assert!(!disabled.deployment_smoke_required);

        config.scim.bearer_token_sha256_hashes = vec![[1_u8; 32]];
        let enabled = scim_operations_preflight_report(&config);
        assert!(enabled.enabled);
        assert_eq!(enabled.bearer_token_hash_count, 1);
        assert!(!enabled.rotation_window);
        assert_eq!(
            enabled.service_provider_config_url.as_deref(),
            Some("https://id.example.com/scim/v2/ServiceProviderConfig")
        );
        assert_eq!(enabled.smoke_command, Some("cairn-api scim smoke"));
        assert!(enabled.deployment_smoke_required);

        config.scim.bearer_token_sha256_hashes = vec![[1_u8; 32], [2_u8; 32]];
        let rotation = scim_operations_preflight_report(&config);
        assert!(rotation.enabled);
        assert_eq!(rotation.bearer_token_hash_count, 2);
        assert!(rotation.rotation_window);
        assert_eq!(
            rotation.connector_profile_command,
            "cairn-api scim connector-profile <generic|okta|entra>"
        );
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
