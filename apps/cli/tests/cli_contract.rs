#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const SECRET_SENTINEL: &str = "TEST_SECRET_SENTINEL_DO_NOT_PRINT";

#[test]
fn top_level_help_describes_evidence_commands() {
    let output = run_cairnid(["--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("CairnID operator CLI"));
    assert!(stdout.contains("Usage: cairnid"));
    assert!(stdout.contains("evidence"));
    assert!(stdout.contains("Examples:"));
}

#[test]
fn evidence_help_describes_existing_evidence_commands() {
    let output = run_cairnid(["evidence", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("Plan, initialize, inspect, and check release evidence"));
    assert!(stdout.contains("plan"));
    assert!(stdout.contains("manifest"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("check"));
    assert!(stdout.contains("Examples:"));
}

#[test]
fn evidence_check_help_describes_arguments_and_examples() {
    let output = run_cairnid(["evidence", "check", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("Validate release evidence artifacts"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("evidence check"));
    assert!(stdout.contains("EVIDENCE_DIR"));
    assert!(stdout.contains("--evidence-dir <EVIDENCE_DIR>"));
    assert!(stdout.contains("--max-age-days <DAYS>"));
    assert!(stdout.contains("Examples:"));
}

#[test]
fn completions_help_lists_supported_shells() {
    let output = run_cairnid(["completions", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("Write a shell completion script to stdout"));
    assert!(stdout.contains("bash"));
    assert!(stdout.contains("zsh"));
    assert!(stdout.contains("fish"));
    assert!(stdout.contains("powershell"));
    assert!(stdout.contains("elvish"));
}

#[test]
fn completions_rejects_invalid_shell_at_clap_layer() {
    let output = run_cairnid(["completions", "not-a-shell"]);

    assert_exit_code(&output, 2);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("not-a-shell"));
    assert!(!stderr.contains("cairnid failed"));
}

#[test]
fn completions_emit_representative_shell_scripts() {
    for (shell, expected) in [
        ("bash", "_cairnid"),
        ("zsh", "#compdef cairnid"),
        ("fish", "complete -c cairnid"),
        ("powershell", "Register-ArgumentCompleter"),
        ("elvish", "edit:completion:arg-completer[cairnid]"),
    ] {
        let output = run_cairnid(["completions", shell]);

        assert_success(&output);
        assert!(stderr(&output).is_empty());

        let stdout = stdout(&output);
        assert!(
            stdout.contains(expected),
            "{shell} completion output:\n{stdout}"
        );
        assert!(
            stdout.contains("evidence"),
            "{shell} completion output:\n{stdout}"
        );
        assert!(
            stdout.contains("manpage"),
            "{shell} completion output:\n{stdout}"
        );
        assert!(!stdout.contains(SECRET_SENTINEL));
    }
}

#[test]
fn manpage_emits_roff_for_cli_and_evidence_commands() {
    let output = run_cairnid(["manpage"]);

    assert_success(&output);
    assert!(stderr(&output).is_empty());

    let stdout = stdout(&output);
    assert!(stdout.contains(".TH cairnid"));
    assert!(stdout.contains("CairnID operator CLI"));
    assert!(stdout.contains("evidence"));
    assert!(stdout.contains("plan"));
    assert!(stdout.contains("check"));
    assert!(!stdout.contains(SECRET_SENTINEL));
}

#[test]
fn evidence_plan_emits_expected_json_contract() {
    let output = run_cairnid_with_plan_environment(["evidence", "plan"]);

    assert_success(&output);
    assert!(stderr(&output).is_empty());

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid plan JSON");
    assert_eq!(json["status"], "ready");
    assert_eq!(json["artifact_count"], 23);
    assert_eq!(json["ready_artifact_count"], 19);
    assert_eq!(json["manual_artifact_count"], 4);
    assert_eq!(json["missing_environment_artifact_count"], 0);
    assert_eq!(json["steps"].as_array().expect("steps array").len(), 23);
}

#[test]
fn evidence_plan_missing_environment_exits_gate_failed_and_emits_json() {
    let output = run_cairnid_without_plan_environment(["evidence", "plan"]);

    assert_exit_code(&output, 3);

    let stdout = stdout(&output);
    let json: Value = serde_json::from_str(&stdout).expect("valid plan JSON");
    assert_eq!(json["status"], "missing_environment");
    assert!(
        json["missing_environment_artifact_count"]
            .as_u64()
            .expect("missing environment artifact count")
            > 0
    );

    let stderr = stderr(&output);
    assert!(stderr.contains("cairnid failed: release evidence capture environment is incomplete"));
    assert!(!stderr.contains(SECRET_SENTINEL));
}

#[test]
fn evidence_manifest_emits_expected_json_contract_without_values() {
    let output = run_cairnid(["evidence", "manifest"]);

    assert_success(&output);
    assert!(stderr(&output).is_empty());

    let stdout = stdout(&output);
    assert!(!stdout.contains(SECRET_SENTINEL));
    assert!(!stdout.contains("secret-value"));

    let json: Value = serde_json::from_str(&stdout).expect("valid manifest JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["default_max_age_days"], 30);
    assert_eq!(json["artifact_count"], 23);
    assert_eq!(
        json["artifacts"].as_array().expect("artifacts array").len(),
        23
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact["file_name"] == "operations-preflight.json")
    );
    assert!(
        json["notes"]
            .as_array()
            .expect("notes array")
            .iter()
            .any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("access-controlled")))
    );
}

#[test]
fn evidence_init_creates_scaffold_and_status_reports_incomplete_lifecycle() {
    let evidence_dir = unique_evidence_dir("init-status");
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();

    let init = run_cairnid(["evidence", "init", &evidence_dir_arg]);

    assert_success(&init);
    assert!(stderr(&init).is_empty());

    let init_json: Value = serde_json::from_slice(&init.stdout).expect("valid init JSON");
    assert_eq!(init_json["status"], "initialized");
    assert_eq!(init_json["artifact_count"], 23);
    assert_eq!(init_json["secret_artifact_count"], 1);
    assert_eq!(
        init_json["files_written"],
        json!(["release-evidence-manifest.json", "README.md", ".gitignore"])
    );
    assert!(
        evidence_dir
            .join("release-evidence-manifest.json")
            .is_file()
    );
    assert!(evidence_dir.join("README.md").is_file());
    assert!(evidence_dir.join(".gitignore").is_file());

    let status = run_cairnid(["evidence", "status", "--evidence-dir", &evidence_dir_arg]);

    assert_exit_code(&status, 3);

    let status_stdout = stdout(&status);
    let status_json: Value = serde_json::from_str(&status_stdout).expect("valid status JSON");
    assert_eq!(status_json["status"], "incomplete");
    assert_eq!(status_json["artifact_count"], 23);
    assert_eq!(status_json["passed_artifact_count"], 0);
    assert_eq!(status_json["missing_artifact_count"], 23);
    assert_eq!(status_json["failed_artifact_count"], 0);
    assert_eq!(
        status_json["next_actions"]
            .as_array()
            .expect("next actions array")
            .len(),
        23
    );
    assert!(
        status_json["next_actions"]
            .as_array()
            .expect("next actions array")
            .iter()
            .any(
                |action| action["file_name"] == "dependency-policy-check.json"
                    && action["command"]
                        .as_str()
                        .is_some_and(|command| command.contains("dependency-policy-evidence"))
            )
    );

    let status_stderr = stderr(&status);
    assert!(status_stderr.contains("cairnid failed: release evidence is incomplete"));
    assert!(!status_stderr.contains(SECRET_SENTINEL));
}

#[test]
fn evidence_init_refuses_existing_scaffold_without_leaking_path_fragments() {
    let evidence_dir = unique_evidence_dir_with_secret("init-existing");
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();

    assert_success(&run_cairnid(["evidence", "init", &evidence_dir_arg]));
    let output = run_cairnid(["evidence", "init", &evidence_dir_arg]);

    assert_exit_code(&output, 4);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains(
        "cairnid failed: release evidence scaffold file already exists; pass --force to replace it"
    ));
    assert!(!stderr.contains(SECRET_SENTINEL));
    assert!(!stderr.contains(&evidence_dir_arg));
}

#[test]
fn evidence_status_redacts_secret_like_artifact_failures() {
    let evidence_dir = initialized_evidence_dir("status-redaction");
    write_json(
        &evidence_dir,
        "operations-preflight.json",
        json!({
            "status": format!("Bearer {SECRET_SENTINEL}"),
            "environment": "production"
        }),
    );
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();

    let output = run_cairnid(["evidence", "status", "--evidence-dir", &evidence_dir_arg]);

    assert_exit_code(&output, 3);
    let combined = format!("{}\n{}", stdout(&output), stderr(&output));
    assert!(!combined.contains(SECRET_SENTINEL));
    assert!(combined.contains("Bearer <redacted>"));

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid status JSON");
    assert_eq!(json["status"], "incomplete");
    assert_eq!(json["failed_artifact_count"], 1);
    assert_eq!(json["missing_artifact_count"], 22);
}

#[test]
fn evidence_check_reports_incomplete_scaffold_and_redacts_secret_like_failures() {
    let evidence_dir = initialized_evidence_dir("check-redaction");
    write_json(
        &evidence_dir,
        "operations-preflight.json",
        json!({
            "status": format!("Bearer {SECRET_SENTINEL}"),
            "environment": "production"
        }),
    );
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();

    let output = run_cairnid(["evidence", "check", "--evidence-dir", &evidence_dir_arg]);

    assert_exit_code(&output, 3);
    let combined = format!("{}\n{}", stdout(&output), stderr(&output));
    assert!(!combined.contains(SECRET_SENTINEL));
    assert!(combined.contains("Bearer <redacted>"));

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid check JSON");
    assert_eq!(json["status"], "incomplete");
    assert_eq!(
        json["artifacts"].as_array().expect("artifacts array").len(),
        23
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact["name"] == "operations_preflight"
                && artifact["status"] == "failed")
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact["name"] == "dependency_policy_check"
                && artifact["status"] == "missing")
    );
}

#[test]
fn max_age_days_zero_fails_at_clap_layer() {
    let output = run_cairnid([
        "evidence",
        "check",
        "release-evidence",
        "--max-age-days",
        "0",
    ]);

    assert_exit_code(&output, 2);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("--max-age-days <DAYS>"));
    assert!(stderr.contains("invalid value"));
    assert!(!stderr.contains("cairnid failed"));
    assert!(!stderr.contains("not a directory"));
}

#[test]
fn max_age_days_above_limit_fails_at_clap_layer() {
    let output = run_cairnid([
        "evidence",
        "check",
        "release-evidence",
        "--max-age-days",
        "366",
    ]);

    assert_exit_code(&output, 2);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("--max-age-days <DAYS>"));
    assert!(stderr.contains("invalid value"));
    assert!(!stderr.contains("cairnid failed"));
    assert!(!stderr.contains("not a directory"));
}

#[test]
fn missing_evidence_directory_does_not_leak_secret_like_path() {
    let missing_dir = unique_missing_dir();
    let missing_dir_arg = missing_dir.to_string_lossy().into_owned();

    let output = run_cairnid(["evidence", "check", &missing_dir_arg]);

    assert_exit_code(&output, 4);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("cairnid failed: release evidence path is not a directory"));
    assert!(!stderr.contains(SECRET_SENTINEL));
    assert!(!stderr.contains(&missing_dir_arg));
}

#[test]
fn missing_evidence_dir_argument_fails_at_clap_layer() {
    let output = run_cairnid(["evidence", "check"]);

    assert_exit_code(&output, 2);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("required"));
    assert!(!stderr.contains("cairnid failed"));
    assert!(!stderr.contains("not a directory"));
}

fn run_cairnid<const N: usize>(args: [&str; N]) -> Output {
    command(args).output().expect("run cairnid")
}

fn run_cairnid_with_plan_environment<const N: usize>(args: [&str; N]) -> Output {
    let mut command = command(args);
    for name in PLAN_ENVIRONMENT {
        command.env(name, "present");
    }
    command.output().expect("run cairnid")
}

fn run_cairnid_without_plan_environment<const N: usize>(args: [&str; N]) -> Output {
    let mut command = command(args);
    for name in PLAN_ENVIRONMENT {
        command.env_remove(name);
    }
    command.output().expect("run cairnid")
}

fn command<const N: usize>(args: [&str; N]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cairnid"));
    command.args(args);
    command
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn assert_exit_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "expected exit code {code}\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn unique_missing_dir() -> PathBuf {
    unique_temp_path("missing", true)
}

fn unique_evidence_dir(name: &str) -> PathBuf {
    let path = unique_temp_path(name, false);
    fs::create_dir_all(&path).expect("create evidence dir");
    path
}

fn unique_evidence_dir_with_secret(name: &str) -> PathBuf {
    let path = unique_temp_path(name, true);
    fs::create_dir_all(&path).expect("create evidence dir");
    path
}

fn initialized_evidence_dir(name: &str) -> PathBuf {
    let evidence_dir = unique_evidence_dir(name);
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();
    let init = run_cairnid(["evidence", "init", &evidence_dir_arg]);
    assert_success(&init);
    evidence_dir
}

fn write_json(root: &std::path::Path, file_name: &str, value: Value) {
    fs::write(
        root.join(file_name),
        serde_json::to_string_pretty(&value).expect("serialize evidence"),
    )
    .expect("write evidence");
}

fn unique_temp_path(name: &str, include_secret: bool) -> PathBuf {
    let mut path = env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let secret_suffix = if include_secret {
        format!("-{SECRET_SENTINEL}")
    } else {
        String::new()
    };
    path.push(format!(
        "cairnid-cli-contract-{name}-{}-{now}{secret_suffix}",
        std::process::id()
    ));
    path
}

const PLAN_ENVIRONMENT: &[&str] = &[
    "CAIRN_ENV",
    "DATABASE_URL",
    "CAIRN_ISSUER",
    "CAIRN_PUBLIC_WEB_ORIGIN",
    "CAIRN_KEY_ENCRYPTION_KEY",
    "CAIRN_EMAIL_PROVIDER",
    "CAIRN_EMAIL_COMMAND_PATH",
    "CAIRN_CONFORMANCE_ALIAS",
    "CAIRN_CONFORMANCE_SUITE_BASE_URL",
    "CAIRN_CONFORMANCE_CLIENT_ID",
    "CAIRN_CONFORMANCE_CLIENT2_ID",
    "CAIRN_CONFORMANCE_CLIENT_SECRET",
    "CAIRN_CONFORMANCE_CLIENT2_SECRET",
    "CAIRN_SCIM_BEARER_TOKEN",
    "CAIRN_SCIM_SECONDARY_BEARER_TOKEN",
    "CAIRN_SCIM_REJECTED_BEARER_TOKEN",
    "CAIRN_BREAK_GLASS_CONFIRM",
    "CAIRN_OLD_KEY_ENCRYPTION_KEY",
    "CAIRN_NEW_KEY_ENCRYPTION_KEY",
];
