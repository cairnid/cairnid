#![forbid(unsafe_code)]

use cairn_operations::RELEASE_EVIDENCE_SCHEMA_VERSION;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const SECRET_SENTINEL: &str = "TEST_SECRET_SENTINEL_DO_NOT_PRINT";
const RELEASE_ASSET_TAG: &str = "v0.1.0-rc.1";
const RELEASE_ASSET_SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const RELEASE_ASSET_RELEASE_URL: &str =
    "https://github.com/cairnid/cairnid/releases/tag/v0.1.0-rc.1";
const RELEASE_ASSET_RUN_URL: &str = "https://github.com/cairnid/cairnid/actions/runs/123456789";
const CLI_COMPLETION_FILES: &[(&str, &str, &str)] = &[
    ("completions/cairnid.bash", "shell-completion", "bash"),
    ("completions/_cairnid", "shell-completion", "zsh"),
    ("completions/cairnid.fish", "shell-completion", "fish"),
    ("completions/cairnid.ps1", "shell-completion", "powershell"),
    ("completions/cairnid.elv", "shell-completion", "elvish"),
];
const CLI_MANPAGE_FILES: &[&str] = &[
    "man/man1/cairnid.1",
    "man/man1/cairnid-completions.1",
    "man/man1/cairnid-evidence.1",
    "man/man1/cairnid-evidence-plan.1",
    "man/man1/cairnid-evidence-manifest.1",
    "man/man1/cairnid-evidence-init.1",
    "man/man1/cairnid-evidence-status.1",
    "man/man1/cairnid-evidence-check.1",
    "man/man1/cairnid-release-assets.1",
    "man/man1/cairnid-release-assets-verify.1",
    "man/man1/cairnid-manpage.1",
    "man/man1/cairnid-manpages.1",
];

#[test]
fn top_level_help_describes_evidence_commands() {
    let output = run_cairnid(["--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("CairnID operator CLI"));
    assert!(stdout.contains("Usage: cairnid"));
    assert!(stdout.contains("evidence"));
    assert!(stdout.contains("release-assets"));
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
fn release_assets_verify_help_describes_arguments_and_manual_flags() {
    let output = run_cairnid(["release-assets", "verify", "--help"]);

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("Verify local release asset files"));
    assert!(stdout.contains("RELEASE_DIR"));
    assert!(stdout.contains("--tag <TAG>"));
    assert!(stdout.contains("--source-commit <SHA>"));
    assert!(stdout.contains("--release-url <URL>"));
    assert!(stdout.contains("--run-url <URL>"));
    assert!(stdout.contains("--provenance-attestations-verified"));
    assert!(stdout.contains("--sbom-attestations-verified"));
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
        assert!(
            stdout.contains("manpages"),
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
fn manpages_writes_root_and_nested_roff_files() {
    let output_dir = unique_temp_path("manpages", false);
    let output_dir_arg = output_dir.to_string_lossy().into_owned();

    let output = run_cairnid(["manpages", &output_dir_arg]);

    assert_success(&output);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).is_empty());

    for relative_path in CLI_MANPAGE_FILES {
        let file_name = relative_path
            .strip_prefix("man/man1/")
            .expect("manpage path prefix");
        let path = output_dir.join(file_name);
        assert!(path.is_file(), "missing generated manpage {file_name}");
        let roff = fs::read_to_string(&path).expect("read generated manpage");
        assert!(roff.contains(".TH "), "{file_name}:\n{roff}");
        assert!(!roff.contains(SECRET_SENTINEL));
    }

    let evidence_check =
        fs::read_to_string(output_dir.join("cairnid-evidence-check.1")).expect("read nested page");
    assert!(evidence_check.contains("cairnid evidence check"));
    assert!(evidence_check.contains("Validate release evidence artifacts"));

    let release_assets_verify =
        fs::read_to_string(output_dir.join("cairnid-release-assets-verify.1"))
            .expect("read release-assets nested page");
    assert!(release_assets_verify.contains(".TH cairnid-release-assets-verify"));
    assert!(release_assets_verify.contains("cairnid release\\-assets verify"));
    assert!(release_assets_verify.contains("Verify local release asset files"));
}

#[test]
fn evidence_plan_emits_expected_json_contract() {
    let output = run_cairnid_with_plan_environment(["evidence", "plan"]);

    assert_success(&output);
    assert!(stderr(&output).is_empty());

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid plan JSON");
    assert_schema_version(&json);
    assert_eq!(json["status"], "ready");
    assert_eq!(json["artifact_count"], 24);
    assert_eq!(json["ready_artifact_count"], 19);
    assert_eq!(json["manual_artifact_count"], 5);
    assert_eq!(json["missing_environment_artifact_count"], 0);
    assert_eq!(json["steps"].as_array().expect("steps array").len(), 24);
    assert!(
        json["steps"]
            .as_array()
            .expect("steps array")
            .iter()
            .any(
                |step| step["file_name"] == "release-assets-verification.json"
                    && step["release_gate"] == "CLI/MCP public release assets"
                    && step["status"] == "manual_external"
            )
    );
}

#[test]
fn evidence_plan_missing_environment_exits_gate_failed_and_emits_json() {
    let output = run_cairnid_without_plan_environment(["evidence", "plan"]);

    assert_exit_code(&output, 3);

    let stdout = stdout(&output);
    let json: Value = serde_json::from_str(&stdout).expect("valid plan JSON");
    assert_schema_version(&json);
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
    assert_schema_version(&json);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["default_max_age_days"], 30);
    assert_eq!(json["artifact_count"], 24);
    assert_eq!(
        json["artifacts"].as_array().expect("artifacts array").len(),
        24
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact["file_name"] == "operations-preflight.json")
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(
                |artifact| artifact["file_name"] == "release-assets-verification.json"
                    && artifact["release_gate"] == "CLI/MCP public release assets"
                    && artifact["validator"] == "release_assets_verification"
            )
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
fn release_assets_verify_emits_validator_compatible_receipt_for_local_assets() {
    let release_dir = fake_release_assets_dir("verify-success");
    let release_dir_arg = release_dir.to_string_lossy().into_owned();

    let output = run_cairnid([
        "release-assets",
        "verify",
        &release_dir_arg,
        "--tag",
        RELEASE_ASSET_TAG,
        "--source-commit",
        RELEASE_ASSET_SOURCE_COMMIT,
        "--release-url",
        RELEASE_ASSET_RELEASE_URL,
        "--provenance-attestations-verified",
        "--sbom-attestations-verified",
    ]);

    assert_success(&output);
    assert!(stderr(&output).is_empty());
    let receipt_stdout = stdout(&output);
    assert!(!receipt_stdout.contains(SECRET_SENTINEL));

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("valid receipt JSON");
    assert_eq!(receipt["status"], "ok");
    assert_eq!(receipt["release_tag"], RELEASE_ASSET_TAG);
    assert_eq!(receipt["source_commit"], RELEASE_ASSET_SOURCE_COMMIT);
    assert_eq!(receipt["release_url"], RELEASE_ASSET_RELEASE_URL);
    assert!(receipt.get("run_url").is_none());
    assert_eq!(receipt["failures"], json!([]));
    assert_eq!(
        receipt["archives"]
            .as_array()
            .expect("archives array")
            .len(),
        4
    );
    assert_eq!(receipt["sboms"].as_array().expect("sboms array").len(), 4);

    let evidence_dir = unique_evidence_dir("release-assets-verify-check");
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();
    assert_success(&run_cairnid(["evidence", "init", &evidence_dir_arg]));
    fs::write(
        evidence_dir.join("release-assets-verification.json"),
        &output.stdout,
    )
    .expect("write generated receipt");

    let check = run_cairnid(["evidence", "check", "--evidence-dir", &evidence_dir_arg]);
    assert_exit_code(&check, 3);
    let report: Value = serde_json::from_slice(&check.stdout).expect("valid evidence report JSON");
    let release_assets_artifact = report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .find(|artifact| artifact["name"] == "release_assets_verification")
        .expect("release assets artifact");
    assert_eq!(release_assets_artifact["status"], "passed");
    assert_eq!(release_assets_artifact["failures"], json!([]));
    assert!(!stdout(&check).contains(SECRET_SENTINEL));
    assert!(!stderr(&check).contains(SECRET_SENTINEL));
}

#[test]
fn release_assets_verify_emits_failed_json_for_workflow_run_only_receipt() {
    let release_dir = fake_release_assets_dir("verify-workflow-run-only");

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(&output, "release_url must be present");
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("valid failed receipt JSON");
    assert_eq!(receipt["release_url"], Value::Null);
    assert_eq!(receipt["run_url"], RELEASE_ASSET_RUN_URL);
    assert_eq!(
        receipt["archives"]
            .as_array()
            .expect("archives array")
            .len(),
        4
    );
    assert_eq!(receipt["sboms"].as_array().expect("sboms array").len(), 4);
}

#[test]
fn release_assets_verify_emits_failed_json_for_hash_mismatch() {
    let release_dir = fake_release_assets_dir("verify-hash-mismatch");
    let tampered_archive = format!("cairnid-{RELEASE_ASSET_TAG}-x86_64-unknown-linux-gnu.tar.gz");
    fs::write(
        release_dir.join(&tampered_archive),
        format!("tampered archive {SECRET_SENTINEL}"),
    )
    .expect("tamper archive");

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(
        &output,
        &format!("SHA256SUMS.txt hash mismatch for {tampered_archive}"),
    );
}

#[test]
fn release_assets_verify_emits_failed_json_for_missing_manifest() {
    let release_dir = fake_release_assets_dir("verify-missing-manifest");
    fs::remove_file(release_dir.join("release-manifest.json")).expect("remove release manifest");

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(&output, "release-manifest.json must be present");
}

#[test]
fn release_assets_verify_emits_failed_json_for_malformed_manifest() {
    let release_dir = fake_release_assets_dir("verify-malformed-manifest");
    fs::write(
        release_dir.join("release-manifest.json"),
        format!("{{ not valid JSON {SECRET_SENTINEL}"),
    )
    .expect("write malformed release manifest");

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(&output, "release-manifest.json must contain valid JSON");
}

#[test]
fn release_assets_verify_emits_failed_json_for_missing_nested_manpage_manifest_entry() {
    let release_dir = fake_release_assets_dir("verify-missing-nested-manpage-manifest");
    remove_manifest_auxiliary_file(
        &release_dir,
        &format!("cairnid-{RELEASE_ASSET_TAG}-x86_64-unknown-linux-gnu.tar.gz"),
        &format!(
            "cairnid-{RELEASE_ASSET_TAG}-x86_64-unknown-linux-gnu/man/man1/cairnid-evidence.1"
        ),
    );

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(
        &output,
        "release-manifest.json asset cairnid-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz.auxiliary_files must match the CLI archive member metadata",
    );
}

#[test]
fn release_assets_verify_emits_failed_json_for_missing_nested_manpage_archive_member() {
    let release_dir = fake_release_assets_dir("verify-missing-nested-manpage-archive");
    let stem = format!("cairnid-{RELEASE_ASSET_TAG}-x86_64-unknown-linux-gnu");
    let archive_name = format!("{stem}.tar.gz");
    let missing_member = format!("{stem}/man/man1/cairnid-release-assets-verify.1");
    write_release_archive_without_member(
        &release_dir.join(&archive_name),
        "tar.gz",
        &stem,
        "cairnid",
        "x86_64-unknown-linux-gnu",
        "apps/cli",
        &missing_member,
    );
    rewrite_manifest_archive_metadata(&release_dir, &archive_name);
    rewrite_checksum_for_file(&release_dir, &archive_name);
    rewrite_checksum_for_file(&release_dir, "release-manifest.json");

    let output = run_release_assets_verify(&release_dir);

    assert_failed_release_assets_stdout(&output, "cairnid-release-assets-verify.1");
}

#[test]
fn release_assets_verify_rejects_missing_url_at_parse_layer() {
    let no_url = run_cairnid([
        "release-assets",
        "verify",
        "release-dir",
        "--tag",
        RELEASE_ASSET_TAG,
        "--source-commit",
        RELEASE_ASSET_SOURCE_COMMIT,
        "--provenance-attestations-verified",
        "--sbom-attestations-verified",
    ]);
    assert_exit_code(&no_url, 2);
    assert!(stdout(&no_url).is_empty());
    let no_url_stderr = stderr(&no_url);
    assert!(no_url_stderr.contains("error:"));
    assert!(
        no_url_stderr.contains("--release-url <URL>") || no_url_stderr.contains("--run-url <URL>")
    );
    assert!(!no_url_stderr.contains("cairnid failed"));
}

#[test]
fn release_assets_verify_emits_failed_json_for_missing_attestation_confirmations() {
    let release_dir = fake_release_assets_dir("verify-missing-attestations");
    let release_dir_arg = release_dir.to_string_lossy().into_owned();
    let no_attestations = run_cairnid([
        "release-assets",
        "verify",
        &release_dir_arg,
        "--tag",
        RELEASE_ASSET_TAG,
        "--source-commit",
        RELEASE_ASSET_SOURCE_COMMIT,
        "--run-url",
        RELEASE_ASSET_RUN_URL,
    ]);

    assert_failed_release_assets_stdout(
        &no_attestations,
        "--provenance-attestations-verified must be supplied",
    );
    let receipt: Value =
        serde_json::from_slice(&no_attestations.stdout).expect("valid failed receipt JSON");
    let failures = receipt["failures"]
        .as_array()
        .expect("failed receipt failures array");
    assert!(
        failures.iter().any(|failure| failure.as_str().is_some_and(
            |failure| failure.contains("--sbom-attestations-verified must be supplied")
        )),
        "{failures:?}"
    );
    assert_eq!(
        receipt["archives"]
            .as_array()
            .expect("archives array")
            .len(),
        4
    );
    assert_eq!(receipt["sboms"].as_array().expect("sboms array").len(), 4);
    let stderr = stderr(&no_attestations);
    assert!(stderr.contains("cairnid failed: release assets verification failed"));
    assert!(!stderr.contains("error:"));
}

#[test]
fn evidence_init_creates_scaffold_and_status_reports_incomplete_lifecycle() {
    let evidence_dir = unique_evidence_dir("init-status");
    let evidence_dir_arg = evidence_dir.to_string_lossy().into_owned();

    let init = run_cairnid(["evidence", "init", &evidence_dir_arg]);

    assert_success(&init);
    assert!(stderr(&init).is_empty());

    let init_json: Value = serde_json::from_slice(&init.stdout).expect("valid init JSON");
    assert_schema_version(&init_json);
    assert_eq!(init_json["status"], "initialized");
    assert_eq!(init_json["artifact_count"], 24);
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
    assert_schema_version(&status_json);
    assert_eq!(status_json["status"], "incomplete");
    assert_eq!(status_json["artifact_count"], 24);
    assert_eq!(status_json["passed_artifact_count"], 0);
    assert_eq!(status_json["missing_artifact_count"], 24);
    assert_eq!(status_json["failed_artifact_count"], 0);
    assert_eq!(
        status_json["next_actions"]
            .as_array()
            .expect("next actions array")
            .len(),
        24
    );
    assert!(
        status_json["next_actions"]
            .as_array()
            .expect("next actions array")
            .iter()
            .any(
                |action| action["file_name"] == "dependency-policy-check.json"
                    && action["release_gate"] == "Dependency policy"
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
    assert_schema_version(&json);
    assert_eq!(json["status"], "incomplete");
    assert_eq!(json["failed_artifact_count"], 1);
    assert_eq!(json["missing_artifact_count"], 23);
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
    assert_schema_version(&json);
    assert_eq!(json["status"], "incomplete");
    assert_eq!(
        json["artifacts"].as_array().expect("artifacts array").len(),
        24
    );
    assert!(
        json["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact["name"] == "operations_preflight"
                && artifact["release_gate"] == "Operations preflight"
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

fn run_release_assets_verify(release_dir: &Path) -> Output {
    let release_dir_arg = release_dir.to_string_lossy().into_owned();
    run_cairnid([
        "release-assets",
        "verify",
        &release_dir_arg,
        "--tag",
        RELEASE_ASSET_TAG,
        "--source-commit",
        RELEASE_ASSET_SOURCE_COMMIT,
        "--run-url",
        RELEASE_ASSET_RUN_URL,
        "--provenance-attestations-verified",
        "--sbom-attestations-verified",
    ])
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

fn assert_failed_release_assets_stdout(output: &Output, expected_failure: &str) {
    assert_exit_code(output, 3);
    let stdout = stdout(output);
    assert!(!stdout.contains(SECRET_SENTINEL));
    assert!(!stderr(output).contains(SECRET_SENTINEL));

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid failed report JSON");
    assert_eq!(report["status"], "failed");
    let failures = report["failures"]
        .as_array()
        .expect("failed report failures array");
    assert!(
        !failures.is_empty(),
        "failed report should include failures"
    );
    assert!(
        failures.iter().any(|failure| failure
            .as_str()
            .is_some_and(|failure| failure.contains(expected_failure))),
        "{failures:?}"
    );
}

fn assert_schema_version(json: &Value) {
    assert_eq!(
        json["schema_version"],
        json!(RELEASE_EVIDENCE_SCHEMA_VERSION)
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

fn fake_release_assets_dir(name: &str) -> PathBuf {
    let root = unique_evidence_dir(name);
    let targets = [
        ("x86_64-unknown-linux-gnu", "linux", "tar.gz"),
        ("x86_64-pc-windows-msvc", "windows", "zip"),
    ];
    let binaries = [
        ("cairnid", "apps/cli", "operator CLI"),
        ("cairnid-mcp", "apps/mcp", "stdio MCP server"),
    ];

    let mut manifest_assets = Vec::new();
    let mut checksums = Vec::new();
    for (binary, package, description) in binaries {
        for (target, os, archive_format) in targets {
            let stem = format!("{binary}-{RELEASE_ASSET_TAG}-{target}");
            let archive_name = format!("{stem}.{archive_format}");
            let sbom_name = format!("{stem}.sbom.cdx.json");

            let archive_path = root.join(&archive_name);
            write_release_archive(
                &archive_path,
                archive_format,
                &stem,
                binary,
                target,
                package,
            );
            let archive_hash = sha256_file(&archive_path);
            checksums.push((archive_name.clone(), archive_hash.clone()));

            let sbom_path = root.join(&sbom_name);
            fs::write(
                &sbom_path,
                serde_json::to_string_pretty(&json!({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "name": binary,
                            "version": RELEASE_ASSET_TAG
                        }
                    },
                    "components": []
                }))
                .expect("serialize SBOM"),
            )
            .expect("write SBOM");
            let sbom_hash = sha256_file(&sbom_path);
            checksums.push((sbom_name.clone(), sbom_hash.clone()));

            let mut archive_asset = json!({
                "name": archive_name,
                "kind": "archive",
                "binary": binary,
                "description": description,
                "target": target,
                "os": os,
                "arch": "x86_64",
                "archive_format": archive_format,
                "sha256": archive_hash,
                "size_bytes": archive_path.metadata().expect("archive metadata").len(),
                "sbom": sbom_name
            });
            if package == "apps/cli" {
                archive_asset["auxiliary_files"] = json!(cli_auxiliary_manifest_entries(&stem));
            }
            manifest_assets.push(archive_asset);
            manifest_assets.push(json!({
                "name": sbom_name,
                "kind": "sbom",
                "binary": binary,
                "format": "CycloneDX JSON",
                "target": target,
                "os": os,
                "arch": "x86_64",
                "sha256": sbom_hash,
                "size_bytes": sbom_path.metadata().expect("SBOM metadata").len(),
                "subject": archive_name
            }));
        }
    }

    let manifest = json!({
        "schema_version": 1,
        "project": "cairnid",
        "tag": RELEASE_ASSET_TAG,
        "version": "0.1.0-rc.1",
        "release_type": "release-candidate",
        "draft": true,
        "prerelease": true,
        "generated_at": "2026-06-07T12:00:00Z",
        "source": {
            "repository": "cairnid/cairnid",
            "commit": RELEASE_ASSET_SOURCE_COMMIT,
            "ref": "refs/tags/v0.1.0-rc.1",
            "workflow": "Release",
            "workflow_ref": "cairnid/cairnid/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1",
            "run_id": "123456789",
            "run_attempt": "1",
            "run_url": RELEASE_ASSET_RUN_URL,
            "validated_ci_run_url": "https://github.com/cairnid/cairnid/actions/runs/123456700"
        },
        "distribution": {
            "release_workflow": ".github/workflows/release.yml",
            "crates_io": false,
            "homebrew": false,
            "msi": false,
            "macos": false,
            "containers": false
        },
        "checksums": {
            "algorithm": "SHA-256",
            "file": "SHA256SUMS.txt",
            "note": "GitHub also exposes release asset digest metadata after upload."
        },
        "provenance": {
            "github_artifact_attestations": true,
            "action": "actions/attest@v4",
            "key_material": "GitHub Actions OIDC and Sigstore; no long-lived signing key"
        },
        "sbom": {
            "generator": "cargo-cyclonedx",
            "generator_version": "0.5.8",
            "format": "CycloneDX JSON",
            "spec_version": "1.5"
        },
        "tools": {
            "rustc": "rustc 1.96.0",
            "cargo": "cargo 1.96.0",
            "cargo_cyclonedx": "cargo-cyclonedx 0.5.8"
        },
        "assets": manifest_assets
    });
    let manifest_path = root.join("release-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize release manifest") + "\n",
    )
    .expect("write release manifest");
    checksums.push((
        "release-manifest.json".to_owned(),
        sha256_file(&manifest_path),
    ));

    checksums.sort_by(|left, right| left.0.cmp(&right.0));
    let checksum_text = checksums
        .iter()
        .map(|(file_name, hash)| format!("{hash}  {file_name}\n"))
        .collect::<String>();
    fs::write(root.join("SHA256SUMS.txt"), checksum_text).expect("write checksums");

    root
}

fn write_release_archive(
    path: &Path,
    archive_format: &str,
    stem: &str,
    binary: &str,
    target: &str,
    package: &str,
) {
    let members = release_archive_members(stem, binary, target, package);
    match archive_format {
        "zip" => write_zip_archive(path, &members),
        "tar.gz" => write_tar_gz_archive(path, &members),
        other => panic!("unsupported archive format {other}"),
    }
}

fn release_archive_members(
    stem: &str,
    binary: &str,
    target: &str,
    package: &str,
) -> Vec<(String, Vec<u8>)> {
    let binary_name = if target == "x86_64-pc-windows-msvc" {
        format!("{binary}.exe")
    } else {
        binary.to_owned()
    };
    let mut members = vec![
        (
            format!("{stem}/{binary_name}"),
            format!("fake binary for {binary} {target}\n").into_bytes(),
        ),
        (format!("{stem}/LICENSE"), b"Apache-2.0\n".to_vec()),
        (format!("{stem}/README.md"), b"# CairnID\n".to_vec()),
    ];
    if package == "apps/cli" {
        members.extend(cli_auxiliary_archive_members(stem));
    }
    members
}

fn cli_auxiliary_manifest_entries(stem: &str) -> Vec<Value> {
    CLI_COMPLETION_FILES
        .iter()
        .map(|(path, kind, shell)| {
            json!({"path": format!("{stem}/{path}"), "kind": kind, "shell": shell})
        })
        .chain(CLI_MANPAGE_FILES.iter().map(|path| {
            json!({"path": format!("{stem}/{path}"), "kind": "manpage", "section": "1"})
        }))
        .collect()
}

fn cli_auxiliary_archive_members(stem: &str) -> Vec<(String, Vec<u8>)> {
    CLI_COMPLETION_FILES
        .iter()
        .map(|(path, _kind, shell)| {
            let content = match *shell {
                "bash" => b"complete -F _cairnid cairnid\n".to_vec(),
                "zsh" => b"#compdef cairnid\n".to_vec(),
                "fish" => b"complete -c cairnid\n".to_vec(),
                "powershell" => {
                    b"Register-ArgumentCompleter -Native -CommandName cairnid\n".to_vec()
                }
                "elvish" => b"edit:completion:arg-completer[cairnid] = {|@words| }\n".to_vec(),
                other => panic!("unsupported shell {other}"),
            };
            (format!("{stem}/{path}"), content)
        })
        .chain(CLI_MANPAGE_FILES.iter().map(|path| {
            let page = path
                .strip_prefix("man/man1/")
                .expect("manpage path prefix")
                .trim_end_matches(".1")
                .to_ascii_uppercase();
            (
                format!("{stem}/{path}"),
                format!(".TH {page} 1\n").into_bytes(),
            )
        }))
        .collect()
}

fn write_release_archive_without_member(
    path: &Path,
    archive_format: &str,
    stem: &str,
    binary: &str,
    target: &str,
    package: &str,
    omitted_member: &str,
) {
    let members = release_archive_members(stem, binary, target, package)
        .into_iter()
        .filter(|(name, _content)| name != omitted_member)
        .collect::<Vec<_>>();
    match archive_format {
        "zip" => write_zip_archive(path, &members),
        "tar.gz" => write_tar_gz_archive(path, &members),
        other => panic!("unsupported archive format {other}"),
    }
}

fn remove_manifest_auxiliary_file(root: &Path, archive_name: &str, omitted_path: &str) {
    let manifest_path = root.join("release-manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let assets = manifest["assets"]
        .as_array_mut()
        .expect("manifest assets array");
    let archive = assets
        .iter_mut()
        .find(|asset| asset["name"] == archive_name)
        .expect("archive manifest asset");
    let auxiliary_files = archive["auxiliary_files"]
        .as_array_mut()
        .expect("auxiliary files array");
    let original_len = auxiliary_files.len();
    auxiliary_files.retain(|entry| entry["path"] != omitted_path);
    assert_eq!(auxiliary_files.len(), original_len - 1);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize manifest") + "\n",
    )
    .expect("write manifest");
    rewrite_checksum_for_file(root, "release-manifest.json");
}

fn rewrite_manifest_archive_metadata(root: &Path, archive_name: &str) {
    let archive_path = root.join(archive_name);
    let manifest_path = root.join("release-manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let assets = manifest["assets"]
        .as_array_mut()
        .expect("manifest assets array");
    let archive = assets
        .iter_mut()
        .find(|asset| asset["name"] == archive_name)
        .expect("archive manifest asset");
    archive["sha256"] = json!(sha256_file(&archive_path));
    archive["size_bytes"] = json!(archive_path.metadata().expect("archive metadata").len());
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize manifest") + "\n",
    )
    .expect("write manifest");
}

fn rewrite_checksum_for_file(root: &Path, file_name: &str) {
    let checksum_path = root.join("SHA256SUMS.txt");
    let replacement_hash = sha256_file(&root.join(file_name));
    let checksum_text = fs::read_to_string(&checksum_path).expect("read checksums");
    let mut replaced = false;
    let updated = checksum_text
        .lines()
        .map(|line| {
            let Some((_, name)) = line.split_once("  ") else {
                return line.to_owned();
            };
            if name == file_name {
                replaced = true;
                format!("{replacement_hash}  {file_name}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(replaced, "checksum entry missing for {file_name}");
    fs::write(checksum_path, updated).expect("rewrite checksums");
}

fn write_zip_archive(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = File::create(path).expect("create zip archive");
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, content) in members {
        archive
            .start_file(name, options)
            .expect("start zip archive member");
        archive
            .write_all(content)
            .expect("write zip archive member");
    }
    archive.finish().expect("finish zip archive");
}

fn write_tar_gz_archive(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = File::create(path).expect("create tar.gz archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, content) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, content.as_slice())
            .expect("append tar archive member");
    }
    let encoder = archive.into_inner().expect("finish tar archive");
    encoder.finish().expect("finish gzip archive");
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file for sha256");
    format!("{:x}", Sha256::digest(bytes))
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
