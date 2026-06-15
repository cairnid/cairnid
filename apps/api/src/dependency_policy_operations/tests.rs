use super::{
    command::DependencyPolicyCommandResult, report::dependency_policy_evidence_report_with_runner,
};
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn dependency_policy_evidence_reports_expected_checks_without_command_output() {
    let workspace = dependency_policy_workspace_fixture("ready");
    let mut commands = Vec::new();
    let report = dependency_policy_evidence_report_with_runner(
        &workspace,
        "cargo",
        "bun",
        OffsetDateTime::UNIX_EPOCH,
        |_, program, args| {
            commands.push(format!("{program} {}", args.join(" ")));
            match (program, args) {
                ("cargo", ["deny", "--version"]) => {
                    command_result_with_stdout(Some(0), b"cargo-deny 0.19.8\n".to_vec())
                }
                ("cargo", ["audit", "--version"]) => {
                    command_result_with_stdout(Some(0), b"cargo-audit 0.22.2\n".to_vec())
                }
                ("bun", ["--version"]) => command_result_with_stdout(Some(0), b"1.3.4\n".to_vec()),
                _ => DependencyPolicyCommandResult {
                    exit_code: Some(0),
                    stdout_bytes: 128,
                    stderr_bytes: 0,
                    stdout_first_line: Some("ok".to_owned()),
                    failure: None,
                },
            }
        },
    );

    assert_eq!(report.status, "ok");
    assert!(report.failures.is_empty());
    assert!(report.workspace.cargo_lock_present);
    assert!(report.workspace.bun_lock_present);
    assert!(report.workspace.dependency_docs_present);
    assert_eq!(
        commands,
        vec![
            "cargo deny check",
            "cargo deny --version",
            "cargo audit",
            "cargo audit --version",
            "bun run audit",
            "bun --version"
        ]
    );
    assert_eq!(report.checks.len(), 3);
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.status == "passed" && check.failure.is_none())
    );

    let serialized = serde_json::to_string(&report).expect("serialize report");
    assert!(serialized.contains("stdout_bytes"));
    assert!(!serialized.contains("\"stdout\""));
    assert!(!serialized.contains("\"stderr\""));
}

#[test]
fn dependency_policy_evidence_fails_closed_for_missing_files_and_failed_checks() {
    let workspace = dependency_policy_workspace_fixture("missing-audit-config");
    std::fs::remove_file(workspace.join(".cargo").join("audit.toml")).expect("remove audit config");
    std::fs::remove_file(workspace.join("docs").join("dependencies.md"))
        .expect("remove dependency docs");
    let report = dependency_policy_evidence_report_with_runner(
        &workspace,
        "cargo",
        "bun",
        OffsetDateTime::UNIX_EPOCH,
        |_, program, args| match (program, args) {
            ("cargo", ["audit"]) => DependencyPolicyCommandResult {
                exit_code: Some(1),
                stdout_bytes: 0,
                stderr_bytes: 42,
                stdout_first_line: None,
                failure: None,
            },
            ("bun", ["--version"]) => DependencyPolicyCommandResult {
                exit_code: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_first_line: None,
                failure: Some("process not found".to_owned()),
            },
            (_, [_, "--version"]) => command_result_with_stdout(Some(0), b"tool 1.0.0\n".to_vec()),
            _ => DependencyPolicyCommandResult {
                exit_code: Some(0),
                stdout_bytes: 1,
                stderr_bytes: 0,
                stdout_first_line: Some("ok".to_owned()),
                failure: None,
            },
        },
    );

    assert_eq!(report.status, "failed");
    assert!(!report.workspace.cargo_audit_config_present);
    assert!(!report.workspace.dependency_docs_present);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains(".cargo/audit.toml"))
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("docs/dependencies.md"))
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("cargo audit exited with status 1"))
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("bun run audit tool version"))
    );
}

fn dependency_policy_workspace_fixture(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "cairn-dependency-policy-{label}-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(root.join(".cargo")).expect("create dependency policy fixture");
    std::fs::write(root.join("Cargo.lock"), "").expect("write Cargo.lock");
    std::fs::write(root.join("bun.lock"), "").expect("write bun.lock");
    std::fs::write(root.join("package.json"), "{}").expect("write package.json");
    std::fs::write(root.join("deny.toml"), "[advisories]\n").expect("write deny.toml");
    std::fs::write(root.join(".cargo").join("audit.toml"), "[advisories]\n")
        .expect("write audit.toml");
    std::fs::create_dir_all(root.join("docs")).expect("create docs directory");
    std::fs::write(
        root.join("docs").join("dependencies.md"),
        "# dependencies\n",
    )
    .expect("write dependency docs");
    root
}

fn command_result_with_stdout(
    exit_code: Option<i32>,
    stdout: Vec<u8>,
) -> DependencyPolicyCommandResult {
    DependencyPolicyCommandResult {
        exit_code,
        stdout_bytes: stdout.len(),
        stderr_bytes: 0,
        stdout_first_line: String::from_utf8(stdout)
            .ok()
            .and_then(|stdout| stdout.lines().next().map(str::to_owned)),
        failure: None,
    }
}
