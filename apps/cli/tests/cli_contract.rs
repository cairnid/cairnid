#![forbid(unsafe_code)]

use serde_json::Value;
use std::{
    env,
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
    assert!(stdout.contains("Usage: cairnid evidence check"));
    assert!(stdout.contains("<EVIDENCE_DIR>"));
    assert!(stdout.contains("--max-age-days <DAYS>"));
    assert!(stdout.contains("Examples:"));
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
fn max_age_days_zero_fails_at_clap_layer() {
    let output = run_cairnid([
        "evidence",
        "check",
        "release-evidence",
        "--max-age-days",
        "0",
    ]);

    assert_failure(&output);
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

    assert_failure(&output);
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

    assert_failure(&output);
    assert!(stdout(&output).is_empty());

    let stderr = stderr(&output);
    assert!(stderr.contains("cairnid failed: release evidence path is not a directory"));
    assert!(!stderr.contains(SECRET_SENTINEL));
    assert!(!stderr.contains(&missing_dir_arg));
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

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn unique_missing_dir() -> PathBuf {
    let mut path = env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    path.push(format!(
        "cairnid-cli-contract-{}-{now}-{SECRET_SENTINEL}",
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
