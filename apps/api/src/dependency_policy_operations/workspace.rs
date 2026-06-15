use super::types::DependencyPolicyWorkspaceReport;
use std::{env, path::PathBuf};

pub(super) fn dependency_policy_workspace() -> PathBuf {
    env::var("CAIRN_DEPENDENCY_POLICY_WORKSPACE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

pub(super) fn dependency_policy_tool_binary(
    env_name: &'static str,
    default: &'static str,
) -> String {
    env::var(env_name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

pub(super) fn dependency_policy_workspace_report(
    workspace: &std::path::Path,
) -> DependencyPolicyWorkspaceReport {
    DependencyPolicyWorkspaceReport {
        cargo_lock_present: workspace.join("Cargo.lock").is_file(),
        bun_lock_present: workspace.join("bun.lock").is_file(),
        package_json_present: workspace.join("package.json").is_file(),
        deny_toml_present: workspace.join("deny.toml").is_file(),
        cargo_audit_config_present: workspace.join(".cargo").join("audit.toml").is_file(),
        dependency_docs_present: workspace.join("docs").join("dependencies.md").is_file(),
    }
}
