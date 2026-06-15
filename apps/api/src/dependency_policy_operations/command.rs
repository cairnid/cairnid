use std::{io, path::Path, process::Command};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DependencyPolicyCommandResult {
    pub(super) exit_code: Option<i32>,
    pub(super) stdout_bytes: usize,
    pub(super) stderr_bytes: usize,
    pub(super) stdout_first_line: Option<String>,
    pub(super) failure: Option<String>,
}

impl DependencyPolicyCommandResult {
    pub(super) fn passed(&self) -> bool {
        self.exit_code == Some(0) && self.failure.is_none()
    }
}

pub(super) fn run_dependency_policy_command(
    workspace: &Path,
    program: &str,
    args: &[&str],
) -> DependencyPolicyCommandResult {
    match Command::new(program)
        .args(args)
        .current_dir(workspace)
        .output()
    {
        Ok(output) => DependencyPolicyCommandResult {
            exit_code: output.status.code(),
            stdout_bytes: output.stdout.len(),
            stderr_bytes: output.stderr.len(),
            stdout_first_line: first_non_empty_output_line(&output.stdout),
            failure: None,
        },
        Err(error) => DependencyPolicyCommandResult {
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_first_line: None,
            failure: Some(dependency_policy_start_error(&error)),
        },
    }
}

fn dependency_policy_start_error(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::NotFound => "process not found".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        _ => "process start failed".to_owned(),
    }
}

fn first_non_empty_output_line(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(sanitize_tool_version)
}

fn sanitize_tool_version(line: &str) -> String {
    line.chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect()
}
