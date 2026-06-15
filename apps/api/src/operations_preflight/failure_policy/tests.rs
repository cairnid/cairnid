use crate::conformance_operations::OpenIdConformanceOperationsPreflightReport;
use cairn_domain::Environment;

use super::super::email_delivery::{EmailDeliveryPreflightReport, EmailOutboxQueuePreflightReport};
use super::super::scim::ScimOperationsPreflightReport;
use super::super::signing::{
    SIGNING_KEY_ROTATION_RECOMMENDED_AFTER_DAYS, SigningKeyLifecyclePreflightReport,
    SigningPreflightReport,
};
use super::super::{
    AuditOperationsPreflightReport, DatabasePreflightReport, OperationsPreflightReport,
};
use super::operations_preflight_failures;

#[test]
fn production_preflight_requires_command_email_provider_and_signing_source() {
    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Production,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing: test_signing_preflight_report(false, false, None, 0, false),
        audit: test_audit_preflight_report(),
        email_delivery: test_email_delivery_preflight_report("disabled", false, false, false),
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("signing source"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("CAIRN_EMAIL_PROVIDER=command"))
    );
}

#[test]
fn database_signing_key_requires_successful_decryption() {
    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Development,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing: test_signing_preflight_report(
            false,
            true,
            Some("rs256-test".to_owned()),
            1,
            false,
        ),
        audit: test_audit_preflight_report(),
        email_delivery: test_email_delivery_preflight_report("stdout", true, false, false),
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("cannot be decrypted"))
    );
}

#[test]
fn legacy_signing_material_can_satisfy_signing_source() {
    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Production,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing: test_signing_preflight_report(true, false, None, 0, false),
        audit: test_audit_preflight_report(),
        email_delivery: test_email_delivery_preflight_report("command", true, true, true),
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(failures.is_empty());
}

#[test]
fn production_preflight_rejects_multiple_active_database_signing_keys() {
    let mut signing =
        test_signing_preflight_report(false, true, Some("rs256-active".to_owned()), 2, true);
    signing.lifecycle.active_key_count = 2;

    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Production,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing,
        audit: test_audit_preflight_report(),
        email_delivery: test_email_delivery_preflight_report("command", true, true, true),
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("multiple active signing keys"))
    );
}

#[test]
fn production_preflight_requires_email_command_path_and_kek() {
    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Production,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing: test_signing_preflight_report(true, false, None, 0, false),
        audit: test_audit_preflight_report(),
        email_delivery: test_email_delivery_preflight_report("command", false, false, false),
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("CAIRN_EMAIL_COMMAND_PATH"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("CAIRN_KEY_ENCRYPTION_KEY"))
    );
}

#[test]
fn production_preflight_requires_failed_email_outbox_resolution() {
    let mut email_delivery = test_email_delivery_preflight_report("command", true, true, true);
    email_delivery.queue.failed = 2;
    email_delivery.queue.unfinished = 2;
    email_delivery.queue.attention_required = true;

    let report = OperationsPreflightReport {
        status: "ok",
        environment: Environment::Production,
        database: DatabasePreflightReport {
            reachable: true,
            applied_migrations: 7,
        },
        signing: test_signing_preflight_report(true, true, None, 0, false),
        audit: test_audit_preflight_report(),
        email_delivery,
        openid_conformance: test_openid_conformance_preflight_report(false),
        scim: test_scim_preflight_report(false, 0),
        failures: Vec::new(),
    };

    let failures = operations_preflight_failures(&report);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("email_outbox has failed messages"))
    );
}

fn test_audit_preflight_report() -> AuditOperationsPreflightReport {
    AuditOperationsPreflightReport {
        retention_days: 365,
        purge_batch_size: 1000,
        export_max_rows: 10_000,
    }
}

fn test_signing_preflight_report(
    legacy_env_configured: bool,
    key_encryption_key_configured: bool,
    database_active_kid: Option<String>,
    active_jwks_count: usize,
    database_active_key_decryptable: bool,
) -> SigningPreflightReport {
    let active_database_key_count = database_active_kid.as_ref().map_or(0, |_| 1);

    SigningPreflightReport {
        legacy_env_configured,
        key_encryption_key_configured,
        database_active_kid,
        active_jwks_count,
        database_active_key_decryptable,
        lifecycle: SigningKeyLifecyclePreflightReport {
            total_key_count: active_jwks_count as i64,
            active_key_count: active_database_key_count,
            active_with_private_material_count: active_database_key_count,
            unretired_key_count: active_jwks_count as i64,
            retired_key_count: 0,
            rollover_key_count: active_jwks_count.saturating_sub(1) as i64,
            encrypted_private_material_count: active_database_key_count,
            active_key_created_at: None,
            active_key_age_seconds: None,
            oldest_unretired_key_created_at: None,
            newest_retired_key_at: None,
            rotation_recommended_after_days: SIGNING_KEY_ROTATION_RECOMMENDED_AFTER_DAYS,
            rotation_recommended: false,
            ensure_command: "cairn-api signing-key ensure",
            rotate_command: "cairn-api signing-key rotate",
            list_command: "cairn-api signing-key list",
            retire_command: "cairn-api signing-key retire <kid>",
        },
    }
}

fn test_email_delivery_preflight_report(
    provider: &'static str,
    production_ready: bool,
    command_path_configured: bool,
    key_encryption_key_configured: bool,
) -> EmailDeliveryPreflightReport {
    let command_provider_configured = provider == "command";
    let enabled = provider != "disabled";
    EmailDeliveryPreflightReport {
        provider,
        production_ready,
        command_provider_configured,
        command_path_configured,
        key_encryption_key_configured,
        batch_size: 10,
        max_attempts: 5,
        retry_seconds: 300,
        sending_timeout_seconds: 900,
        delivery_command: enabled.then_some("cairn-api email-outbox deliver-once"),
        provider_smoke_command: enabled
            .then_some("cairn-api email-outbox smoke-provider <recipient-email>"),
        provider_smoke_required: false,
        queue: EmailOutboxQueuePreflightReport {
            queued: 0,
            retry: 0,
            retry_due: 0,
            sending: 0,
            stale_sending: 0,
            failed: 0,
            sent: 0,
            unfinished: 0,
            oldest_unfinished_at: None,
            next_retry_at: None,
            attention_required: false,
        },
    }
}

fn test_scim_preflight_report(
    enabled: bool,
    bearer_token_hash_count: usize,
) -> ScimOperationsPreflightReport {
    ScimOperationsPreflightReport {
        enabled,
        bearer_token_hash_count,
        rotation_window: bearer_token_hash_count > 1,
        max_bearer_token_hashes: 4,
        service_provider_config_url: enabled
            .then_some("https://id.example.com/scim/v2/ServiceProviderConfig".to_owned()),
        connector_profile_command: "cairn-api scim connector-profile <generic|okta|entra>",
        smoke_command: enabled.then_some("cairn-api scim smoke"),
        deployment_smoke_required: enabled,
    }
}

fn test_openid_conformance_preflight_report(
    static_client_environment_ready: bool,
) -> OpenIdConformanceOperationsPreflightReport {
    OpenIdConformanceOperationsPreflightReport {
        issuer: "https://id.example.com".to_owned(),
        issuer_https_origin_ready: true,
        static_client_environment_ready,
        missing_environment: if static_client_environment_ready {
            Vec::new()
        } else {
            vec![
                "CAIRN_CONFORMANCE_ALIAS",
                "CAIRN_CONFORMANCE_CLIENT_ID",
                "CAIRN_CONFORMANCE_CLIENT_SECRET",
                "CAIRN_CONFORMANCE_CLIENT2_ID",
                "CAIRN_CONFORMANCE_CLIENT2_SECRET",
                "CAIRN_CONFORMANCE_SUITE_BASE_URL",
            ]
        },
        certification_profiles: vec!["Config OP", "Basic OP"],
        static_registration_command: "cairn-api conformance oidcc-static-registration",
        static_config_command: "cairn-api conformance oidcc-static-config",
        external_suite_required: true,
    }
}
