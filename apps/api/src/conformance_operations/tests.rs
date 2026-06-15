use super::{
    preflight::{
        OPENID_CONFORMANCE_ENVIRONMENT_VARIABLES,
        openid_conformance_operations_preflight_report_for_env,
    },
    result_template::{openid_conformance_result_profile, openid_conformance_result_template},
    static_config::openid_conformance_static_config,
    static_registration::openid_conformance_static_registration,
    types::{OpenIdConformanceInputs, OpenIdConformanceRegistrationInputs},
};
use crate::config::{
    ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
};
use cairn_domain::Environment;
use time::OffsetDateTime;

#[test]
fn openid_conformance_preflight_reports_missing_environment_and_http_issuer() {
    let mut config = test_config(Environment::Development);
    config.issuer = "http://localhost:8080".to_owned();

    let report = openid_conformance_operations_preflight_report_for_env(&config, |_| false);

    assert_eq!(report.issuer, "http://localhost:8080");
    assert!(!report.issuer_https_origin_ready);
    assert!(!report.static_client_environment_ready);
    assert_eq!(
        report.missing_environment,
        OPENID_CONFORMANCE_ENVIRONMENT_VARIABLES.to_vec()
    );
    assert_eq!(report.certification_profiles, vec!["Config OP", "Basic OP"]);
    assert!(report.external_suite_required);
}

#[test]
fn openid_conformance_preflight_reports_ready_static_environment() {
    let mut config = test_config(Environment::Production);
    config.issuer = "https://id.example.com/".to_owned();

    let report = openid_conformance_operations_preflight_report_for_env(&config, |name| {
        OPENID_CONFORMANCE_ENVIRONMENT_VARIABLES.contains(&name)
    });

    assert_eq!(report.issuer, "https://id.example.com");
    assert!(report.issuer_https_origin_ready);
    assert!(report.static_client_environment_ready);
    assert!(report.missing_environment.is_empty());
    assert_eq!(
        report.static_registration_command,
        "cairn-api conformance oidcc-static-registration"
    );
    assert_eq!(
        report.static_config_command,
        "cairn-api conformance oidcc-static-config"
    );
    assert!(report.external_suite_required);
}

#[test]
fn openid_conformance_static_config_matches_oidf_suite_shape() {
    let config = openid_conformance_static_config(OpenIdConformanceInputs {
        issuer: "https://id.example.com",
        alias: "cairn-basic-op",
        description: " Cairn Identity Basic OP ".to_owned(),
        client_id: "oidf-client",
        client_secret: "primary-secret",
        client2_id: "oidf-client-2",
        client2_secret: "secondary-secret",
    })
    .expect("valid conformance config");

    let json = serde_json::to_value(&config).expect("serializable config");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["alias"], "cairn-basic-op");
    assert_eq!(json["description"], "Cairn Identity Basic OP");
    assert_eq!(
        json["server"]["discoveryUrl"],
        "https://id.example.com/.well-known/openid-configuration"
    );
    assert_eq!(json["client"]["client_id"], "oidf-client");
    assert_eq!(json["client"]["client_secret"], "primary-secret");
    assert_eq!(json["client2"]["client_id"], "oidf-client-2");
    assert_eq!(json["client2"]["client_secret"], "secondary-secret");
}

#[test]
fn openid_conformance_static_config_rejects_non_certification_origins_and_aliases() {
    let non_https = openid_conformance_static_config(OpenIdConformanceInputs {
        issuer: "http://id.example.com",
        alias: "cairn-basic-op",
        description: "Cairn Identity Basic OP".to_owned(),
        client_id: "oidf-client",
        client_secret: "primary-secret",
        client2_id: "oidf-client-2",
        client2_secret: "secondary-secret",
    })
    .expect_err("conformance config requires HTTPS");
    assert!(non_https.to_string().contains("HTTPS origin"));

    let invalid_alias = openid_conformance_static_config(OpenIdConformanceInputs {
        issuer: "https://id.example.com",
        alias: "../cairn",
        description: "Cairn Identity Basic OP".to_owned(),
        client_id: "oidf-client",
        client_secret: "primary-secret",
        client2_id: "oidf-client-2",
        client2_secret: "secondary-secret",
    })
    .expect_err("conformance alias must be a safe URL segment");
    assert!(
        invalid_alias
            .to_string()
            .contains("CAIRN_CONFORMANCE_ALIAS")
    );
}

#[test]
fn openid_conformance_registration_reports_required_static_client_settings() {
    let report = openid_conformance_static_registration(OpenIdConformanceRegistrationInputs {
        issuer: "https://id.example.com/",
        alias: "cairn-basic-op",
        suite_base_url: "https://www.certification.openid.net/",
        client_id: "oidf-client",
        client2_id: "oidf-client-2",
    })
    .expect("valid registration report");

    let json = serde_json::to_value(&report).expect("serializable registration report");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(report.status, "ready");
    assert_eq!(
        report.run_plan_commands,
        vec![
            "scripts/run-test-plan.py oidcc-config-certification-test-plan cairn-oidcc-static.json",
            "scripts/run-test-plan.py oidcc-basic-certification-test-plan cairn-oidcc-static.json",
        ]
    );
    assert_eq!(report.static_clients.len(), 2);
    assert_eq!(report.static_clients[0].role, "primary");
    assert_eq!(report.static_clients[1].role, "secondary");
    assert_eq!(
        report.static_clients[0].redirect_uris,
        vec!["https://www.certification.openid.net/test/a/cairn-basic-op/callback"]
    );
    assert!(
        report.static_clients[0]
            .token_endpoint_auth_methods
            .contains(&"client_secret_basic".to_owned())
    );
    assert!(
        report.static_clients[0]
            .token_endpoint_auth_methods
            .contains(&"client_secret_post".to_owned())
    );
    assert!(
        report.static_clients[0]
            .allowed_scopes
            .contains(&"offline_access".to_owned())
    );
    assert!(
        report
            .unsupported_v1_profiles
            .contains(&"Implicit OP".to_owned())
    );
}

#[test]
fn openid_conformance_result_template_reports_normalized_shape_without_secrets() {
    let report = openid_conformance_result_template("config-op").expect("Config OP template");
    let json = serde_json::to_value(&report).expect("serializable result template");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["source"], "openid-conformance-suite");
    assert_eq!(json["status"], "template");
    assert_eq!(json["result"], "pending");
    assert_eq!(json["certification_profile"], "Config OP");
    assert_eq!(json["plan_name"], "oidcc-config-certification-test-plan");
    assert!(
        json["accepted_results"]
            .as_array()
            .expect("accepted results")
            .iter()
            .any(|result| result == "PASSED")
    );
    assert!(
        json["operator_notes"]
            .as_array()
            .expect("operator notes")
            .iter()
            .any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("status=\"template\"")))
    );

    let rendered = serde_json::to_string(&json).expect("template JSON");
    assert!(!rendered.contains("primary-secret"));
    assert!(!rendered.contains("secondary-secret"));
    assert!(!rendered.contains("Authorization: Bearer"));
}

#[test]
fn openid_conformance_result_template_accepts_aliases_and_rejects_unknown_profiles() {
    let basic = openid_conformance_result_profile("oidcc-basic-certification-test-plan")
        .expect("Basic OP alias");
    assert_eq!(basic.certification_profile, "Basic OP");
    assert_eq!(basic.plan_name, "oidcc-basic-certification-test-plan");

    let config = openid_conformance_result_profile("configuration").expect("Config OP alias");
    assert_eq!(config.certification_profile, "Config OP");

    let error = openid_conformance_result_template("implicit-op")
        .expect_err("unsupported profiles must be rejected");
    assert!(error.to_string().contains("config-op or basic-op"));
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
