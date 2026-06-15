use std::env;

use crate::config::ApiConfig;

use super::{
    types::OpenIdConformanceOperationsPreflightReport, validation::validate_conformance_issuer,
};

pub(super) const OPENID_CONFORMANCE_ENVIRONMENT_VARIABLES: [&str; 6] = [
    "CAIRN_CONFORMANCE_ALIAS",
    "CAIRN_CONFORMANCE_CLIENT_ID",
    "CAIRN_CONFORMANCE_CLIENT_SECRET",
    "CAIRN_CONFORMANCE_CLIENT2_ID",
    "CAIRN_CONFORMANCE_CLIENT2_SECRET",
    "CAIRN_CONFORMANCE_SUITE_BASE_URL",
];

pub fn openid_conformance_operations_preflight_report(
    config: &ApiConfig,
) -> OpenIdConformanceOperationsPreflightReport {
    openid_conformance_operations_preflight_report_for_env(
        config,
        |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
    )
}

pub(super) fn openid_conformance_operations_preflight_report_for_env<F>(
    config: &ApiConfig,
    environment_present: F,
) -> OpenIdConformanceOperationsPreflightReport
where
    F: Fn(&'static str) -> bool,
{
    let missing_environment = OPENID_CONFORMANCE_ENVIRONMENT_VARIABLES
        .iter()
        .copied()
        .filter(|name| !environment_present(name))
        .collect::<Vec<_>>();

    OpenIdConformanceOperationsPreflightReport {
        issuer: config.issuer.trim_end_matches('/').to_owned(),
        issuer_https_origin_ready: validate_conformance_issuer(&config.issuer).is_ok(),
        static_client_environment_ready: missing_environment.is_empty(),
        missing_environment,
        certification_profiles: vec!["Config OP", "Basic OP"],
        static_registration_command: "cairn-api conformance oidcc-static-registration",
        static_config_command: "cairn-api conformance oidcc-static-config",
        external_suite_required: true,
    }
}
