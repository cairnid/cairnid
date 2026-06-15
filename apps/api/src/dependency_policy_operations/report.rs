use super::{
    checks::{
        DEPENDENCY_POLICY_CHECKS, dependency_policy_check_report,
        dependency_policy_evidence_failures,
    },
    command::{DependencyPolicyCommandResult, run_dependency_policy_command},
    types::DependencyPolicyEvidenceReport,
    workspace::{
        dependency_policy_tool_binary, dependency_policy_workspace,
        dependency_policy_workspace_report,
    },
};
use std::path::Path;
use time::OffsetDateTime;

pub(crate) fn dependency_policy_evidence_report(
    completed_at: OffsetDateTime,
) -> DependencyPolicyEvidenceReport {
    let workspace = dependency_policy_workspace();
    dependency_policy_evidence_report_with_runner(
        &workspace,
        &dependency_policy_tool_binary("CAIRN_CARGO_BIN", "cargo"),
        &dependency_policy_tool_binary("CAIRN_BUN_BIN", "bun"),
        completed_at,
        run_dependency_policy_command,
    )
}

pub(super) fn dependency_policy_evidence_report_with_runner<F>(
    workspace: &Path,
    cargo_bin: &str,
    bun_bin: &str,
    completed_at: OffsetDateTime,
    mut runner: F,
) -> DependencyPolicyEvidenceReport
where
    F: FnMut(&Path, &str, &[&str]) -> DependencyPolicyCommandResult,
{
    let workspace_report = dependency_policy_workspace_report(workspace);
    let checks = DEPENDENCY_POLICY_CHECKS
        .iter()
        .map(|spec| {
            dependency_policy_check_report(workspace, cargo_bin, bun_bin, spec, &mut runner)
        })
        .collect::<Vec<_>>();
    let failures = dependency_policy_evidence_failures(&workspace_report, &checks);

    DependencyPolicyEvidenceReport {
        status: if failures.is_empty() { "ok" } else { "failed" },
        completed_at,
        workspace: workspace_report,
        checks,
        failures,
    }
}
