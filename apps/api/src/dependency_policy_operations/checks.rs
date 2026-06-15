use super::{
    command::DependencyPolicyCommandResult,
    types::{DependencyPolicyCheckReport, DependencyPolicyWorkspaceReport},
};
use std::path::Path;

pub(super) struct DependencyPolicyCheckSpec {
    pub(super) name: &'static str,
    pub(super) command: &'static str,
    pub(super) program: ToolProgram,
    pub(super) args: &'static [&'static str],
    pub(super) version_args: &'static [&'static str],
}

#[derive(Clone, Copy)]
pub(super) enum ToolProgram {
    Cargo,
    Bun,
}

pub(super) const DEPENDENCY_POLICY_CHECKS: &[DependencyPolicyCheckSpec] = &[
    DependencyPolicyCheckSpec {
        name: "cargo_deny",
        command: "cargo deny check",
        program: ToolProgram::Cargo,
        args: &["deny", "check"],
        version_args: &["deny", "--version"],
    },
    DependencyPolicyCheckSpec {
        name: "cargo_audit",
        command: "cargo audit",
        program: ToolProgram::Cargo,
        args: &["audit"],
        version_args: &["audit", "--version"],
    },
    DependencyPolicyCheckSpec {
        name: "bun_audit",
        command: "bun run audit",
        program: ToolProgram::Bun,
        args: &["run", "audit"],
        version_args: &["--version"],
    },
];

pub(super) fn dependency_policy_check_report<F>(
    workspace: &Path,
    cargo_bin: &str,
    bun_bin: &str,
    spec: &DependencyPolicyCheckSpec,
    runner: &mut F,
) -> DependencyPolicyCheckReport
where
    F: FnMut(&Path, &str, &[&str]) -> DependencyPolicyCommandResult,
{
    let program = match spec.program {
        ToolProgram::Cargo => cargo_bin,
        ToolProgram::Bun => bun_bin,
    };
    let check = runner(workspace, program, spec.args);
    let version = runner(workspace, program, spec.version_args);
    let tool_version = version
        .passed()
        .then(|| version.stdout_first_line.clone())
        .flatten();
    let failure = dependency_policy_check_failure(spec.command, &check, tool_version.as_deref());

    DependencyPolicyCheckReport {
        name: spec.name,
        command: spec.command,
        status: if failure.is_none() {
            "passed"
        } else {
            "failed"
        },
        exit_code: check.exit_code,
        stdout_bytes: check.stdout_bytes,
        stderr_bytes: check.stderr_bytes,
        tool_version,
        failure,
    }
}

pub(super) fn dependency_policy_evidence_failures(
    workspace: &DependencyPolicyWorkspaceReport,
    checks: &[DependencyPolicyCheckReport],
) -> Vec<String> {
    let mut failures = Vec::new();
    if !workspace.cargo_lock_present {
        failures.push("Cargo.lock is required for Rust dependency policy evidence".to_owned());
    }
    if !workspace.bun_lock_present {
        failures.push("bun.lock is required for frontend dependency policy evidence".to_owned());
    }
    if !workspace.package_json_present {
        failures.push("package.json is required for Bun audit evidence".to_owned());
    }
    if !workspace.deny_toml_present {
        failures.push("deny.toml is required for cargo-deny policy evidence".to_owned());
    }
    if !workspace.cargo_audit_config_present {
        failures.push(".cargo/audit.toml is required for cargo-audit policy evidence".to_owned());
    }
    if !workspace.dependency_docs_present {
        failures.push("docs/dependencies.md is required for dependency policy evidence".to_owned());
    }
    for check in checks {
        if let Some(failure) = check.failure.as_deref() {
            failures.push(failure.to_owned());
        }
    }
    failures
}

fn dependency_policy_check_failure(
    command: &'static str,
    check: &DependencyPolicyCommandResult,
    tool_version: Option<&str>,
) -> Option<String> {
    if let Some(failure) = check.failure.as_deref() {
        return Some(format!("{command} did not start: {failure}"));
    }
    if check.exit_code != Some(0) {
        return Some(match check.exit_code {
            Some(exit_code) => format!("{command} exited with status {exit_code}"),
            None => format!("{command} terminated without an exit code"),
        });
    }
    if tool_version.is_none_or(str::is_empty) {
        return Some(format!("{command} tool version could not be captured"));
    }
    None
}
