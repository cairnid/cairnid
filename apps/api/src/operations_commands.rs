mod args;
mod checks;
mod errors;
mod evidence;
mod smoke;

use self::{
    checks::{
        run_dependency_policy_evidence_command, run_preflight_command, run_restore_check_command,
    },
    errors::config_error,
    evidence::{
        run_evidence_check_command, run_evidence_init_command, run_evidence_manifest_command,
        run_evidence_plan_command, run_evidence_status_command,
    },
    smoke::{
        run_browser_origin_smoke_command, run_oidc_metadata_smoke_command,
        run_security_headers_smoke_command,
    },
};

pub(crate) async fn run_operations_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("preflight") => run_preflight_command().await,
        Some("evidence-check") => run_evidence_check_command(args),
        Some("evidence-status") => run_evidence_status_command(args),
        Some("evidence-manifest") => run_evidence_manifest_command(),
        Some("evidence-plan") => run_evidence_plan_command(),
        Some("evidence-init") => run_evidence_init_command(args),
        Some("dependency-policy-evidence") => run_dependency_policy_evidence_command(),
        Some("restore-check") => run_restore_check_command().await,
        Some("browser-origin-smoke") => run_browser_origin_smoke_command().await,
        Some("oidc-metadata-smoke") => run_oidc_metadata_smoke_command().await,
        Some("security-headers-smoke") => run_security_headers_smoke_command().await,
        _ => Err(config_error(
            "usage: cairn-api operations <preflight|dependency-policy-evidence|restore-check|oidc-metadata-smoke|browser-origin-smoke|security-headers-smoke|evidence-manifest|evidence-plan|evidence-init <evidence-dir> [--force]|evidence-status <evidence-dir> [--max-age-days <days>]|evidence-check <evidence-dir> [--max-age-days <days>]>",
        )),
    }
}
