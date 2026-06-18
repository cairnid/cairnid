mod fixtures;

use super::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, RELEASE_EVIDENCE_SCHEMA_VERSION,
    ReleaseAssetsVerificationError, ReleaseAssetsVerificationOptions, ReleaseEvidenceError,
    check_release_evidence, init_release_evidence_directory, release_assets_verification_receipt,
    release_assets_verification_report, release_evidence_capture_plan, release_evidence_manifest,
    release_evidence_status_report,
};
use fixtures::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn release_evidence_passes_complete_directory() {
    let root = temp_evidence_dir("complete");
    init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    write_json(&root, "operations-preflight.json", production_preflight());
    write_json(
        &root,
        "dependency-policy-check.json",
        dependency_policy_check(),
    );
    write_json(
        &root,
        "release-assets-verification.json",
        release_assets_verification(),
    );
    write_json(
        &root,
        "openid-static-registration.json",
        openid_static_registration_report(),
    );
    write_json(&root, "cairn-oidcc-static.json", openid_static_config());
    write_json(&root, "oidc-metadata-smoke.json", oidc_metadata_smoke());
    write_json(
        &root,
        "openid-config-op-result.json",
        openid_conformance_summary(
            "Config OP",
            "oidcc-config-certification-test-plan",
            "https://www.certification.openid.net/plan-detail.html?plan=config-op",
        ),
    );
    write_json(
        &root,
        "openid-basic-op-result.json",
        openid_conformance_plan_export("oidcc-basic-certification-test-plan", "PASSED"),
    );
    write_json(
        &root,
        "scim-generic-connector-profile.json",
        scim_connector_profile("generic"),
    );
    write_json(
        &root,
        "scim-okta-connector-profile.json",
        scim_connector_profile("okta"),
    );
    write_json(
        &root,
        "scim-entra-connector-profile.json",
        scim_connector_profile("entra"),
    );
    write_json(&root, "scim-smoke.json", scim_smoke());
    write_json(
        &root,
        "scim-okta-connector-smoke.json",
        scim_connector_smoke("okta"),
    );
    write_json(
        &root,
        "scim-entra-connector-smoke.json",
        scim_connector_smoke("entra"),
    );
    write_json(&root, "browser-origin-smoke.json", browser_origin_smoke());
    write_json(
        &root,
        "security-headers-smoke.json",
        security_headers_smoke(),
    );
    write_json(
        &root,
        "email-provider-smoke.json",
        json!({
            "status": "sent",
            "provider": "command",
            "recipient_email": "ops@example.com",
            "completed_at": "2026-06-07T12:00:00Z",
            "provider_message_id": "provider-smoke-1"
        }),
    );
    write_json(
        &root,
        "lifecycle-email-smoke.json",
        lifecycle_email_smoke_receipt(),
    );
    write_json(
        &root,
        "signing-key-rotation-drill.json",
        signing_key_rotation_receipt(),
    );
    write_json(
        &root,
        "restore-drill.json",
        json!({
            "status": "ok",
            "organization_slug": "default",
            "organization_id": Uuid::new_v4(),
            "completed_at": "2026-06-07T12:00:00Z",
            "database": {
                "reachable": true,
                "applied_migrations": 12,
                "migrations_present": true
            },
            "signing": {
                "legacy_env_configured": false,
                "key_encryption_key_configured": true,
                "active_database_kid": "rs256-active",
                "active_jwks_count": 1,
                "active_database_key_decryptable": true,
                "signing_source_available": true
            },
            "checks": [
                "database is reachable",
                "restored database exposes active JWKS material"
            ],
            "failures": []
        }),
    );
    write_json(
        &root,
        "audit-export-archive-drill.json",
        audit_export_receipt(),
    );
    write_json(
        &root,
        "kek-rotation-drill.json",
        key_encryption_rotation_receipt(),
    );
    write_json(
        &root,
        "break-glass-admin-recovery-drill.json",
        break_glass_admin_recovery_receipt(),
    );
    write_json(
        &root,
        "audit-retention-purge-drill.json",
        audit_retention_purge_receipt(),
    );

    let report = check_release_evidence(
        &root,
        release_evidence_now(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    assert_eq!(report.status, "ready");
    assert_eq!(report.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert!(report.failures.is_empty());
    assert_eq!(report.artifacts.len(), 24);

    let status = release_evidence_status_report(&root, release_evidence_now(), 30)
        .expect("release evidence status report");
    assert_eq!(status.status, "ready");
    assert_eq!(status.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(status.artifact_count, 24);
    assert_eq!(status.passed_artifact_count, 24);
    assert_eq!(status.missing_artifact_count, 0);
    assert_eq!(status.failed_artifact_count, 0);
    assert!(status.next_actions.is_empty());
}

#[test]
fn release_evidence_rejects_missing_or_tampered_scaffold() {
    let missing_scaffold = temp_evidence_dir("missing-scaffold");
    write_json(
        &missing_scaffold,
        "operations-preflight.json",
        production_preflight(),
    );

    let missing_report = check_release_evidence(&missing_scaffold, release_evidence_now(), 30)
        .expect("release evidence report");

    assert_eq!(missing_report.status, "incomplete");
    assert!(
        missing_report
            .failures
            .iter()
            .any(|failure| failure.contains("release-evidence-manifest.json"))
    );
    assert!(
        missing_report
            .failures
            .iter()
            .any(|failure| failure.contains(".gitignore"))
    );

    let tampered = temp_evidence_dir("tampered-scaffold");
    init_release_evidence_directory(&tampered, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    fs::write(tampered.join(".gitignore"), "*\n").expect("tamper gitignore");
    let mut manifest = release_evidence_manifest(release_evidence_now());
    manifest.artifact_count = 0;
    fs::write(
        tampered.join("release-evidence-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize tampered manifest"),
    )
    .expect("tamper manifest");

    let tampered_report = check_release_evidence(&tampered, release_evidence_now(), 30)
        .expect("release evidence report");

    assert_eq!(tampered_report.status, "incomplete");
    assert!(
        tampered_report
            .failures
            .iter()
            .any(|failure| failure.contains("scaffold manifest must match"))
    );
    assert!(
        tampered_report
            .failures
            .iter()
            .any(|failure| failure.contains("guarded release-evidence template"))
    );
}

#[test]
fn release_evidence_rejects_unexpected_inventory_entries() {
    let root = temp_evidence_dir("unexpected-inventory");
    init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    fs::write(
        root.join("provider-console-screenshot.png"),
        "not release evidence",
    )
    .expect("write unexpected file");
    fs::create_dir(root.join("raw-provider-export")).expect("write unexpected directory");

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    assert_eq!(report.status, "incomplete");
    assert!(report.failures.iter().any(|failure| {
        failure.contains("unexpected release evidence entry: provider-console-screenshot.png")
    }));
    assert!(report.failures.iter().any(|failure| {
        failure.contains("unexpected release evidence entry: raw-provider-export")
    }));
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("got directory: raw-provider-export"))
    );
}

#[test]
fn release_evidence_rejects_secret_fields_in_token_free_artifacts() {
    let root = temp_evidence_dir("token-free-secret-fields");
    init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    let mut preflight = production_preflight();
    preflight["request_headers"] = json!({
        "Authorization": "Bearer must-not-be-archived"
    });
    preflight["private_key"] = json!("must-not-be-archived");
    write_json(&root, "operations-preflight.json", preflight);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "operations_preflight")
        .expect("operations preflight artifact");
    assert_eq!(artifact.status, "failed");
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.request_headers must not be present in token-free release evidence artifact operations_preflight",
            )
        }));
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.request_headers.Authorization must not be present in token-free release evidence artifact operations_preflight",
            )
        }));
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.private_key must not be present in token-free release evidence artifact operations_preflight",
            )
        }));
}

#[test]
fn release_evidence_redacts_secret_like_failure_values() {
    let root = temp_evidence_dir("redacted-failure-values");
    init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    let mut preflight = production_preflight();
    preflight["status"] = json!("Bearer highly-sensitive-release-token");
    write_json(&root, "operations-preflight.json", preflight);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "operations_preflight")
        .expect("operations preflight artifact");
    let joined_failures = artifact.failures.join("\n");
    assert!(!joined_failures.contains("highly-sensitive-release-token"));
    assert!(joined_failures.contains("Bearer <redacted>"));
    assert!(
        !report
            .failures
            .join("\n")
            .contains("highly-sensitive-release-token")
    );
}

#[test]
fn release_evidence_status_reports_next_actions_for_incomplete_directory() {
    let root = temp_evidence_dir("status-incomplete");
    write_json(&root, "operations-preflight.json", production_preflight());

    let status = release_evidence_status_report(&root, release_evidence_now(), 30)
        .expect("release evidence status report");

    assert_eq!(status.status, "incomplete");
    assert_eq!(status.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(status.artifact_count, 24);
    assert_eq!(status.passed_artifact_count, 1);
    assert_eq!(status.missing_artifact_count, 23);
    assert_eq!(status.failed_artifact_count, 0);
    assert_eq!(status.next_actions.len(), 23);
    assert!(
        status
            .next_actions
            .iter()
            .any(|action| action.file_name == "cairn-oidcc-static.json"
                && action.release_gate == "Static OpenID artifacts"
                && action.command.contains("oidcc-static-config")
                && action.status == "missing")
    );
    assert!(
        status
            .failures
            .iter()
            .any(|failure| failure.contains("openid_static_config"))
    );
}

#[test]
fn release_evidence_manifest_tracks_required_artifacts_and_risk_flags() {
    let manifest = release_evidence_manifest(OffsetDateTime::now_utc());

    assert_eq!(manifest.status, "ok");
    assert_eq!(manifest.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(manifest.default_max_age_days, 30);
    assert_eq!(manifest.artifact_count, 24);
    assert_eq!(manifest.artifacts.len(), 24);
    assert!(
        manifest
            .notes
            .iter()
            .any(|note| note.contains("access-controlled"))
    );
    assert!(
        manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                !matches!(
                    artifact.name,
                    "dependency_policy_check" | "release_assets_verification"
                )
            })
            .all(|artifact| artifact.requires_production_like_environment)
    );

    let dependency_policy = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "dependency_policy_check")
        .expect("dependency policy artifact");
    assert_eq!(
        dependency_policy.command,
        "cairn-api operations dependency-policy-evidence > dependency-policy-check.json"
    );
    assert_eq!(dependency_policy.validator, "dependency_policy_check");
    assert!(!dependency_policy.requires_production_like_environment);
    assert!(!dependency_policy.contains_secrets);
    assert!(!dependency_policy.writes_application_state);
    assert!(dependency_policy.touches_external_provider);
    assert_eq!(dependency_policy.release_gate, "Dependency policy");

    let release_assets = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "release_assets_verification")
        .expect("release assets artifact");
    assert_eq!(release_assets.file_name, "release-assets-verification.json");
    assert_eq!(release_assets.release_gate, "CLI/MCP public release assets");
    assert_eq!(release_assets.validator, "release_assets_verification");
    assert!(!release_assets.requires_production_like_environment);
    assert!(!release_assets.contains_secrets);
    assert!(!release_assets.writes_application_state);
    assert!(release_assets.touches_external_provider);

    let static_config = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.file_name == "cairn-oidcc-static.json")
        .expect("static config artifact");
    assert!(static_config.contains_secrets);
    assert!(!static_config.writes_application_state);
    assert_eq!(static_config.validator, "openid_static_config");
    assert_eq!(static_config.release_gate, "Static OpenID artifacts");

    let oidc_metadata_smoke = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "oidc_metadata_smoke")
        .expect("OIDC metadata smoke artifact");
    assert_eq!(oidc_metadata_smoke.validator, "oidc_metadata_smoke");
    assert!(!oidc_metadata_smoke.contains_secrets);
    assert!(!oidc_metadata_smoke.writes_application_state);
    assert!(!oidc_metadata_smoke.touches_external_provider);

    let scim_smoke = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_public_smoke")
        .expect("SCIM smoke artifact");
    assert!(scim_smoke.writes_application_state);
    assert!(!scim_smoke.contains_secrets);

    let scim_okta_smoke = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_okta_connector_smoke")
        .expect("SCIM Okta connector smoke artifact");
    assert_eq!(
        scim_okta_smoke.command,
        "save normalized Okta connector smoke summary as scim-okta-connector-smoke.json"
    );
    assert_eq!(scim_okta_smoke.validator, "scim_connector_smoke_okta");
    assert!(!scim_okta_smoke.contains_secrets);
    assert!(scim_okta_smoke.writes_application_state);
    assert!(scim_okta_smoke.touches_external_provider);

    let scim_okta_profile = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_okta_connector_profile")
        .expect("SCIM Okta connector profile artifact");
    assert_eq!(
        scim_okta_profile.command,
        "cairn-api scim connector-profile okta > scim-okta-connector-profile.json"
    );
    assert_eq!(scim_okta_profile.validator, "scim_connector_profile_okta");
    assert!(!scim_okta_profile.contains_secrets);
    assert!(!scim_okta_profile.writes_application_state);
    assert!(!scim_okta_profile.touches_external_provider);

    let email_smoke = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "email_provider_smoke")
        .expect("email smoke artifact");
    assert!(email_smoke.touches_external_provider);
    assert!(!email_smoke.writes_application_state);

    let lifecycle_email_smoke = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "lifecycle_email_smoke")
        .expect("lifecycle email smoke artifact");
    assert_eq!(
        lifecycle_email_smoke.command,
        "cairn-api email-outbox lifecycle-smoke-evidence > lifecycle-email-smoke.json"
    );
    assert_eq!(lifecycle_email_smoke.validator, "lifecycle_email_smoke");
    assert!(!lifecycle_email_smoke.contains_secrets);
    assert!(lifecycle_email_smoke.writes_application_state);
    assert!(lifecycle_email_smoke.touches_external_provider);
}

#[test]
fn release_evidence_plan_reports_missing_environment_without_values() {
    let report = release_evidence_capture_plan(release_evidence_now(), |_| false);

    assert_eq!(report.status, "missing_environment");
    assert_eq!(report.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(report.artifact_count, 24);
    assert_eq!(report.ready_artifact_count, 1);
    assert_eq!(report.manual_artifact_count, 5);
    assert_eq!(report.missing_environment_artifact_count, 18);
    assert!(
        report
            .missing_environment
            .iter()
            .any(|missing| missing.contains("operations_preflight: set DATABASE_URL"))
    );

    let scim_smoke = report
        .steps
        .iter()
        .find(|step| step.name == "scim_public_smoke")
        .expect("SCIM smoke plan step");
    assert_eq!(scim_smoke.status, "missing_environment");
    assert!(
        scim_smoke
            .missing_environment
            .iter()
            .any(|missing| missing.contains("CAIRN_SCIM_SECONDARY_BEARER_TOKEN"))
    );
    assert!(
        scim_smoke
            .missing_environment
            .iter()
            .any(|missing| missing.contains("CAIRN_SCIM_REJECTED_BEARER_TOKEN"))
    );
    assert!(
        scim_smoke
            .operator_notes
            .iter()
            .any(|note| note.contains("secondary, and rejected token checks"))
    );

    let static_config = report
        .steps
        .iter()
        .find(|step| step.name == "openid_static_config")
        .expect("OpenID static config step");
    assert!(static_config.contains_secrets);
    assert_eq!(static_config.release_gate, "Static OpenID artifacts");
    assert!(
        static_config
            .required_environment
            .iter()
            .any(|requirement| requirement.contains_secret
                && requirement
                    .alternatives
                    .iter()
                    .flatten()
                    .any(|name| *name == "CAIRN_CONFORMANCE_CLIENT_SECRET"))
    );

    let serialized = serde_json::to_string(&report).expect("serialize plan");
    assert!(serialized.contains("CAIRN_CONFORMANCE_CLIENT_SECRET"));
    assert!(!serialized.contains("secret-value"));
}

#[test]
fn release_evidence_plan_reports_ready_when_required_environment_is_present() {
    let report = release_evidence_capture_plan(release_evidence_now(), |_| true);

    assert_eq!(report.status, "ready");
    assert!(report.missing_environment.is_empty());
    assert_eq!(report.artifact_count, 24);
    assert_eq!(report.ready_artifact_count, 19);
    assert_eq!(report.manual_artifact_count, 5);
    assert_eq!(report.missing_environment_artifact_count, 0);

    let config_op = report
        .steps
        .iter()
        .find(|step| step.name == "openid_config_op_conformance")
        .expect("Config OP step");
    assert_eq!(config_op.status, "manual_external");
    assert!(config_op.touches_external_provider);
    assert!(
        config_op
            .operator_notes
            .iter()
            .any(|note| note.contains("OpenID Foundation conformance suite"))
    );

    let okta_smoke = report
        .steps
        .iter()
        .find(|step| step.name == "scim_okta_connector_smoke")
        .expect("Okta connector smoke step");
    assert_eq!(okta_smoke.status, "manual_external");
    assert!(okta_smoke.writes_application_state);
    assert!(okta_smoke.touches_external_provider);
    assert!(
        okta_smoke
            .operator_notes
            .iter()
            .any(|note| note.contains("external provisioning client"))
    );

    let release_assets = report
        .steps
        .iter()
        .find(|step| step.name == "release_assets_verification")
        .expect("release assets step");
    assert_eq!(release_assets.status, "manual_external");
    assert_eq!(release_assets.release_gate, "CLI/MCP public release assets");
    assert!(
        release_assets
            .operator_notes
            .iter()
            .any(|note| note.contains("GitHub Release assets"))
    );

    let lifecycle_email_smoke = report
        .steps
        .iter()
        .find(|step| step.name == "lifecycle_email_smoke")
        .expect("lifecycle email smoke step");
    assert_eq!(lifecycle_email_smoke.status, "ready");
    assert!(lifecycle_email_smoke.writes_application_state);
    assert!(lifecycle_email_smoke.touches_external_provider);
    assert!(
        lifecycle_email_smoke
            .operator_notes
            .iter()
            .any(|note| note.contains("state-changing release smoke"))
    );
}

#[test]
fn release_evidence_init_writes_guarded_scaffold() {
    let root = temp_evidence_dir("init");

    let report =
        init_release_evidence_directory(&root, release_evidence_now(), false).expect("init");

    assert_eq!(report.status, "initialized");
    assert_eq!(report.schema_version, RELEASE_EVIDENCE_SCHEMA_VERSION);
    assert!(!report.force);
    assert_eq!(report.artifact_count, 24);
    assert_eq!(report.secret_artifact_count, 1);
    assert!(report.state_changing_artifact_count > 0);
    assert!(report.external_provider_artifact_count > 0);
    assert_eq!(
        report.files_written,
        vec![
            "release-evidence-manifest.json".to_owned(),
            "README.md".to_owned(),
            ".gitignore".to_owned()
        ]
    );
    assert!(report.next_command.contains("cairnid evidence check"));

    let manifest_json = fs::read_to_string(root.join("release-evidence-manifest.json"))
        .expect("read generated manifest");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("generated manifest is JSON");
    assert_eq!(
        manifest["schema_version"],
        json!(RELEASE_EVIDENCE_SCHEMA_VERSION)
    );
    assert_eq!(manifest["artifact_count"], json!(24));
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts array");
    let static_config = artifacts
        .iter()
        .find(|artifact| artifact["file_name"] == "cairn-oidcc-static.json")
        .expect("static config artifact");
    assert_eq!(static_config["contains_secrets"], true);
    assert_eq!(
        static_config["release_gate"],
        json!("Static OpenID artifacts")
    );

    let readme = fs::read_to_string(root.join("README.md")).expect("read README");
    assert!(readme.contains("Do not commit the evidence artifacts"));
    assert!(readme.contains("dependency-policy-check.json"));
    assert!(readme.contains("CLI/MCP public release assets"));
    assert!(readme.contains("release-assets-verification.json"));
    assert!(readme.contains("cairn-oidcc-static.json"));
    assert!(readme.contains("scim-okta-connector-profile.json"));
    assert!(readme.contains("External Provider"));

    let gitignore = fs::read_to_string(root.join(".gitignore")).expect("read .gitignore");
    assert!(gitignore.contains("release-evidence-manifest.json"));
    assert!(!gitignore.contains("*.gitignore"));
    assert!(gitignore.contains("*"));
}

#[test]
fn release_evidence_init_refuses_overwrite_without_force() {
    let root = temp_evidence_dir("init-overwrite");
    init_release_evidence_directory(&root, release_evidence_now(), false).expect("first init");

    let error = init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect_err("second init must refuse overwrite");

    assert!(matches!(
        error,
        ReleaseEvidenceError::ExistingScaffoldFile(_)
    ));

    let report =
        init_release_evidence_directory(&root, release_evidence_now(), true).expect("force init");
    assert!(report.force);
}

#[test]
fn release_evidence_reports_missing_and_failed_artifacts() {
    let root = temp_evidence_dir("incomplete");
    let mut preflight = production_preflight();
    preflight["status"] = json!("failed");
    preflight["environment"] = json!("development");
    preflight["failures"] = json!(["missing production email provider"]);
    write_json(&root, "operations-preflight.json", preflight);
    write_json(
        &root,
        "openid-config-op-result.json",
        json!({ "status": "failed", "errors": ["suite failed"] }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    assert_eq!(report.status, "incomplete");
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("operations_preflight"))
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("openid_config_op_conformance"))
    );
    assert!(
        report
            .artifacts
            .iter()
            .any(|artifact| artifact.status == "missing")
    );
}

#[test]
fn release_evidence_rejects_invalid_dependency_policy_check() {
    let root = temp_evidence_dir("invalid-dependency-policy");
    let mut receipt = dependency_policy_check();
    receipt["status"] = json!("failed");
    receipt["checks"][1]["status"] = json!("failed");
    receipt["checks"][1]["exit_code"] = json!(1);
    receipt["checks"][1]["stdout"] = json!("full audit output must not be archived");
    write_json(&root, "dependency-policy-check.json", receipt);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "dependency_policy_check")
        .expect("dependency policy artifact");
    assert_eq!(artifact.status, "failed");
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks[cargo_audit].status must be passed"))
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("$.checks[1].stdout must not be present") })
    );
}

#[test]
fn release_evidence_rejects_invalid_release_assets_verification() {
    let root = temp_evidence_dir("invalid-release-assets");
    let mut receipt = release_assets_verification();
    receipt["release_tag"] = json!("v0.1");
    receipt["source_commit"] = json!("not-a-commit");
    receipt["attestations"]["provenance_verified"] = json!(false);
    receipt["archives"]
        .as_array_mut()
        .expect("archives array")
        .pop();
    receipt["request_headers"] = json!({ "Authorization": "Bearer must-not-be-archived" });
    write_json(&root, "release-assets-verification.json", receipt);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "release_assets_verification")
        .expect("release assets artifact");
    assert_eq!(artifact.status, "failed");
    assert_eq!(artifact.release_gate, "CLI/MCP public release assets");
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("release_tag must match vMAJOR.MINOR.PATCH") })
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("source_commit must be a 40-character"))
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("attestations.provenance_verified must be true"))
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("archives must contain exactly 4"))
    );
    assert!(artifact.failures.iter().any(|failure| {
        failure.contains(
            "$.request_headers must not be present in token-free release evidence artifact release_assets_verification",
        )
    }));
}

#[test]
fn release_evidence_rejects_failed_release_assets_verification_report() {
    let release = fake_release_assets_dir("failed-release-assets-saved");
    let tampered_archive = format!("cairnid-{}-x86_64-unknown-linux-gnu.tar.gz", release.tag);
    fs::write(release.root.join(&tampered_archive), "tampered archive").expect("tamper archive");
    let failed_report = release_assets_verification_report(
        &release_assets_options(&release),
        release_evidence_now(),
    )
    .expect("failed release assets report");
    assert_eq!(failed_report.status, "failed");
    assert!(!failed_report.failures.is_empty());

    let root = temp_evidence_dir("failed-release-assets-report");
    write_json(
        &root,
        "release-assets-verification.json",
        serde_json::to_value(&failed_report).expect("failed report JSON"),
    );

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "release_assets_verification")
        .expect("release assets artifact");
    assert_eq!(artifact.status, "failed");
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains("failures must be empty"))
    );
}

#[test]
fn release_assets_receipt_generation_accepts_downloaded_release_assets() {
    let release = fake_release_assets_dir("receipt-happy");
    let receipt = release_assets_verification_receipt(
        &release_assets_options(&release),
        release_evidence_now(),
    )
    .expect("release assets receipt");

    assert_eq!(receipt.status, "ok");
    assert!(receipt.failures.is_empty());
    assert_eq!(receipt.release_tag, RELEASE_ASSET_TAG);
    assert_eq!(receipt.source_commit, RELEASE_ASSET_SOURCE_COMMIT);
    assert_eq!(
        receipt.release_url.as_deref(),
        Some(RELEASE_ASSET_RELEASE_URL)
    );
    assert_eq!(receipt.run_url.as_deref(), Some(RELEASE_ASSET_RUN_URL));
    assert_eq!(receipt.archives.len(), 4);
    assert_eq!(receipt.sboms.len(), 4);
    assert!(
        receipt
            .archives
            .iter()
            .all(|archive| archive.github_attestation_verified
                && archive.sbom_attestation_verified
                && archive.sha256_verified
                && archive.manifest_entry_present)
    );
    assert!(
        receipt
            .sboms
            .iter()
            .all(|sbom| sbom.github_attestation_verified
                && sbom.sha256_verified
                && sbom.manifest_entry_present
                && sbom.format == "CycloneDX JSON")
    );

    let evidence_dir = temp_evidence_dir("generated-release-assets-receipt");
    init_release_evidence_directory(&evidence_dir, release_evidence_now(), false).expect("init");
    write_json(
        &evidence_dir,
        "release-assets-verification.json",
        serde_json::to_value(&receipt).expect("receipt JSON"),
    );
    let report = check_release_evidence(&evidence_dir, release_evidence_now(), 30)
        .expect("release evidence report");
    let release_assets = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "release_assets_verification")
        .expect("release assets artifact");
    assert_eq!(release_assets.status, "passed");
    assert!(release_assets.failures.is_empty());
}

#[test]
fn release_assets_receipt_generation_rejects_hash_mismatch_and_missing_asset() {
    let tampered = fake_release_assets_dir("receipt-hash-mismatch");
    let tampered_archive = format!("cairnid-{}-x86_64-unknown-linux-gnu.tar.gz", tampered.tag);
    fs::write(tampered.root.join(&tampered_archive), "tampered archive").expect("tamper archive");

    let error = release_assets_verification_receipt(
        &release_assets_options(&tampered),
        release_evidence_now(),
    )
    .expect_err("hash mismatch fails");
    let failures = release_assets_failures(&error);
    assert!(
        failures.iter().any(|failure| failure.contains(&format!(
            "SHA256SUMS.txt hash mismatch for {tampered_archive}"
        ))),
        "{failures:?}"
    );

    let missing = fake_release_assets_dir("receipt-missing-asset");
    let missing_sbom = format!(
        "cairnid-mcp-{}-x86_64-pc-windows-msvc.sbom.cdx.json",
        missing.tag
    );
    fs::remove_file(missing.root.join(&missing_sbom)).expect("remove SBOM");

    let error = release_assets_verification_receipt(
        &release_assets_options(&missing),
        release_evidence_now(),
    )
    .expect_err("missing asset fails");
    let failures = release_assets_failures(&error);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains(&format!("missing release asset {missing_sbom}"))),
        "{failures:?}"
    );
}

#[test]
fn release_assets_report_returns_failed_json_for_hash_mismatch_and_missing_asset() {
    let tampered = fake_release_assets_dir("report-hash-mismatch");
    let tampered_archive = format!("cairnid-{}-x86_64-unknown-linux-gnu.tar.gz", tampered.tag);
    fs::write(tampered.root.join(&tampered_archive), "tampered archive").expect("tamper archive");

    let report = release_assets_verification_report(
        &release_assets_options(&tampered),
        release_evidence_now(),
    )
    .expect("hash mismatch report");
    assert_failed_release_assets_report(&report, &format!("hash mismatch for {tampered_archive}"));

    let missing = fake_release_assets_dir("report-missing-asset");
    let missing_sbom = format!(
        "cairnid-mcp-{}-x86_64-pc-windows-msvc.sbom.cdx.json",
        missing.tag
    );
    fs::remove_file(missing.root.join(&missing_sbom)).expect("remove SBOM");

    let report = release_assets_verification_report(
        &release_assets_options(&missing),
        release_evidence_now(),
    )
    .expect("missing asset report");
    assert_failed_release_assets_report(&report, &format!("missing release asset {missing_sbom}"));
}

#[test]
fn release_assets_report_returns_failed_json_for_missing_manifest_and_malformed_assets() {
    let missing_manifest = fake_release_assets_dir("report-missing-manifest");
    fs::remove_file(missing_manifest.root.join("release-manifest.json"))
        .expect("remove release manifest");
    let report = release_assets_verification_report(
        &release_assets_options(&missing_manifest),
        release_evidence_now(),
    )
    .expect("missing manifest report");
    assert_failed_release_assets_report(&report, "release-manifest.json must be present");
    assert!(!report.release_manifest.present);

    let malformed_archive = fake_release_assets_dir("report-malformed-archive");
    let archive_name = format!(
        "cairnid-{}-x86_64-pc-windows-msvc.zip",
        malformed_archive.tag
    );
    fs::write(
        malformed_archive.root.join(&archive_name),
        "not a zip archive",
    )
    .expect("write malformed archive");
    rewrite_checksum_for_file(&malformed_archive.root, &archive_name);
    let report = release_assets_verification_report(
        &release_assets_options(&malformed_archive),
        release_evidence_now(),
    )
    .expect("malformed archive report");
    assert_failed_release_assets_report(&report, "archive structure could not be read");

    let malformed_sbom = fake_release_assets_dir("report-malformed-sbom");
    let sbom_name = format!(
        "cairnid-{}-x86_64-pc-windows-msvc.sbom.cdx.json",
        malformed_sbom.tag
    );
    fs::write(
        malformed_sbom.root.join(&sbom_name),
        "{ not valid CycloneDX JSON",
    )
    .expect("write malformed SBOM");
    rewrite_checksum_for_file(&malformed_sbom.root, &sbom_name);
    let report = release_assets_verification_report(
        &release_assets_options(&malformed_sbom),
        release_evidence_now(),
    )
    .expect("malformed SBOM report");
    assert_failed_release_assets_report(&report, "must contain valid JSON");
}

#[test]
fn release_assets_receipt_generation_requires_attestation_confirmation() {
    let release = fake_release_assets_dir("receipt-attestations");
    let mut options = release_assets_options(&release);
    options.provenance_attestations_verified = false;
    options.sbom_attestations_verified = false;

    let error = release_assets_verification_receipt(&options, release_evidence_now())
        .expect_err("missing attestation confirmations fail");
    let failures = release_assets_failures(&error);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("--provenance-attestations-verified must be supplied")),
        "{failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("--sbom-attestations-verified must be supplied")),
        "{failures:?}"
    );
}

#[test]
fn release_evidence_rejects_stale_or_future_completed_at() {
    let root = temp_evidence_dir("stale-completed-at");
    let mut stale_scim = scim_smoke();
    stale_scim["completed_at"] = json!("2026-05-01T12:00:00Z");
    write_json(&root, "scim-smoke.json", stale_scim);

    let mut future_oidc = oidc_metadata_smoke();
    future_oidc["completed_at"] = json!("2026-06-07T12:10:01Z");
    write_json(&root, "oidc-metadata-smoke.json", future_oidc);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let scim_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_public_smoke")
        .expect("SCIM smoke artifact");
    assert_eq!(scim_artifact.status, "failed");
    assert!(scim_artifact.failures.iter().any(|failure| {
        failure.contains("completed_at is older than 30 days and must be refreshed")
    }));

    let metadata_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "oidc_metadata_smoke")
        .expect("OIDC metadata smoke artifact");
    assert_eq!(metadata_artifact.status, "failed");
    assert!(metadata_artifact.failures.iter().any(|failure| {
        failure.contains("completed_at is more than 300 seconds in the future")
    }));
}

#[test]
fn release_evidence_rejects_stale_or_future_openid_result_timestamps() {
    let root = temp_evidence_dir("stale-openid-conformance");
    let mut stale_plan_export =
        openid_conformance_plan_export("oidcc-config-certification-test-plan", "PASSED");
    stale_plan_export["exportedAt"] = json!("May 1, 2026, 12:00:00 PM");
    write_json(&root, "openid-config-op-result.json", stale_plan_export);

    let mut future_normalized = openid_conformance_summary(
        "Basic OP",
        "oidcc-basic-certification-test-plan",
        "https://www.certification.openid.net/plan-detail.html?plan=basic-op",
    );
    future_normalized["completed_at"] = json!("2026-06-07T12:10:01Z");
    write_json(&root, "openid-basic-op-result.json", future_normalized);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let config_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_config_op_conformance")
        .expect("Config OP artifact");
    assert_eq!(config_artifact.status, "failed");
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("exportedAt is older than 30 days"))
    );

    let basic_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_basic_op_conformance")
        .expect("Basic OP artifact");
    assert_eq!(basic_artifact.status, "failed");
    assert!(basic_artifact.failures.iter().any(|failure| {
        failure.contains("completed_at is more than 300 seconds in the future")
    }));
}

#[test]
fn release_evidence_rejects_stale_or_future_openid_static_generated_at() {
    let root = temp_evidence_dir("stale-openid-static-generated-at");
    let mut stale_registration = openid_static_registration_report();
    stale_registration["generated_at"] = json!("2026-05-01T12:00:00Z");
    write_json(&root, "openid-static-registration.json", stale_registration);

    let mut future_config = openid_static_config();
    future_config["generated_at"] = json!("2026-06-07T12:10:01Z");
    write_json(&root, "cairn-oidcc-static.json", future_config);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let registration_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_static_registration")
        .expect("OpenID static registration artifact");
    assert_eq!(registration_artifact.status, "failed");
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("generated_at is older than 30 days"))
    );

    let config_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_static_config")
        .expect("OpenID static config artifact");
    assert_eq!(config_artifact.status, "failed");
    assert!(config_artifact.failures.iter().any(|failure| {
        failure.contains("generated_at is more than 300 seconds in the future")
    }));
}

#[test]
fn release_evidence_rejects_invalid_scim_connector_profiles() {
    let root = temp_evidence_dir("failed-scim-connector-profiles");

    let mut generic = scim_connector_profile("generic");
    generic["profile"] = json!("okta");
    generic["smoke_commands"] = json!(["cairn-api scim smoke"]);
    write_json(&root, "scim-generic-connector-profile.json", generic);

    let mut okta = scim_connector_profile("okta");
    okta["issuer"] = json!("http://id.example.com");
    okta["recommended_mappings"] = json!([]);
    write_json(&root, "scim-okta-connector-profile.json", okta);

    let mut entra = scim_connector_profile("entra");
    entra["generated_at"] = json!("2026-06-07T12:10:01Z");
    entra["connector_settings"] = json!([]);
    write_json(&root, "scim-entra-connector-profile.json", entra);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let generic_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_generic_connector_profile")
        .expect("generic connector profile artifact");
    assert_eq!(generic_artifact.status, "failed");
    assert!(
        generic_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("profile must be generic, got okta"))
    );
    assert!(generic_artifact.failures.iter().any(|failure| {
        failure.contains("smoke_commands must include CAIRN_SCIM_SECONDARY_BEARER_TOKEN")
    }));

    let okta_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_okta_connector_profile")
        .expect("Okta connector profile artifact");
    assert_eq!(okta_artifact.status, "failed");
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("issuer must be an HTTPS origin"))
    );
    assert!(okta_artifact.failures.iter().any(|failure| {
        failure.contains("recommended_mappings must include User mapping for userName")
    }));

    let entra_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_entra_connector_profile")
        .expect("Entra connector profile artifact");
    assert_eq!(entra_artifact.status, "failed");
    assert!(entra_artifact.failures.iter().any(|failure| {
        failure.contains("generated_at is more than 300 seconds in the future")
    }));
    assert!(entra_artifact.failures.iter().any(|failure| {
        failure.contains("connector_settings must include object with name=Tenant URL")
    }));
}

#[test]
fn release_evidence_rejects_openid_results_from_wrong_suite_origin() {
    let root = temp_evidence_dir("wrong-openid-origin");
    let mut plan_export =
        openid_conformance_plan_export("oidcc-config-certification-test-plan", "PASSED");
    plan_export["exportedFrom"] = json!("https://example.com/");
    plan_export["testLogExports"][0]["export"]["exportedFrom"] = json!("https://example.com/");
    write_json(&root, "openid-config-op-result.json", plan_export);

    let normalized = openid_conformance_summary(
        "Basic OP",
        "oidcc-basic-certification-test-plan",
        "https://example.com/plan-detail.html?plan=basic-op",
    );
    write_json(&root, "openid-basic-op-result.json", normalized);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");

    let config_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_config_op_conformance")
        .expect("Config OP artifact");
    assert_eq!(config_artifact.status, "failed");
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("exportedFrom must be an HTTPS URL on"))
    );
    assert!(config_artifact.failures.iter().any(|failure| {
        failure.contains("testLogExports[0].export.exportedFrom must be an HTTPS URL on")
    }));

    let basic_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_basic_op_conformance")
        .expect("Basic OP artifact");
    assert_eq!(basic_artifact.status, "failed");
    assert!(
        basic_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("published_result_url must be an HTTPS URL on"))
    );
}

#[test]
fn release_evidence_rejects_secret_fields_in_openid_normalized_results() {
    let root = temp_evidence_dir("openid-secret-fields");
    let mut normalized = openid_conformance_summary(
        "Config OP",
        "oidcc-config-certification-test-plan",
        "https://www.certification.openid.net/plan-detail.html?plan=config-op",
    );
    normalized["client_secret"] = json!("must-not-be-archived");
    normalized["evidence"] = json!({
        "request_headers": {
            "Authorization": "Bearer must-not-be-archived"
        }
    });
    write_json(&root, "openid-config-op-result.json", normalized);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");
    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_config_op_conformance")
        .expect("Config OP artifact");

    assert_eq!(artifact.status, "failed");
    assert!(artifact.failures.iter().any(|failure| {
        failure.contains("$.client_secret must not be present in token-free OpenID result evidence")
    }));
    assert!(artifact.failures.iter().any(|failure| {
        failure.contains(
            "$.evidence.request_headers must not be present in token-free OpenID result evidence",
        )
    }));
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.evidence.request_headers.Authorization must not be present in token-free OpenID result evidence",
            )
        }));
}

#[test]
fn release_evidence_rejects_secret_fields_in_openid_plan_exports() {
    let root = temp_evidence_dir("openid-plan-secret-fields");
    let mut plan_export =
        openid_conformance_plan_export("oidcc-config-certification-test-plan", "PASSED");
    plan_export["testLogExports"][0]["export"]["request_headers"] = json!({
        "Authorization": "Bearer must-not-be-archived"
    });
    plan_export["testLogExports"][0]["export"]["clientSecret"] = json!("must-not-be-archived");
    write_json(&root, "openid-config-op-result.json", plan_export);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("release evidence report");
    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_config_op_conformance")
        .expect("Config OP artifact");

    assert_eq!(artifact.status, "failed");
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.testLogExports[0].export.request_headers must not be present in token-free OpenID result evidence",
            )
        }));
    assert!(artifact.failures.iter().any(|failure| {
            failure.contains(
                "$.testLogExports[0].export.clientSecret must not be present in token-free OpenID result evidence",
            )
        }));
}

#[test]
fn release_evidence_rejects_generic_or_failed_openid_result_artifacts() {
    let root = temp_evidence_dir("failed-openid-results");
    write_json(
        &root,
        "openid-config-op-result.json",
        json!({
            "status": "passed"
        }),
    );
    write_json(
        &root,
        "openid-basic-op-result.json",
        openid_conformance_plan_export("oidcc-config-certification-test-plan", "FAILED"),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let config_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_config_op_conformance")
        .expect("config OP artifact");
    let basic_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_basic_op_conformance")
        .expect("basic OP artifact");

    assert_eq!(config_artifact.status, "failed");
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("source must be openid-conformance-suite"))
    );
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("plan name must be oidcc-config"))
    );
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("published_result_url"))
    );

    assert_eq!(basic_artifact.status, "failed");
    assert!(
        basic_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("plan name must be oidcc-basic"))
    );
    assert!(
        basic_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("result must be PASSED or WARNING"))
    );
}

#[test]
fn release_evidence_rejects_invalid_oidc_metadata_smoke() {
    let root = temp_evidence_dir("failed-oidc-metadata-smoke");
    write_json(
        &root,
        "oidc-metadata-smoke.json",
        json!({
            "status": "failed",
            "issuer": "http://id.example.com",
            "completed_at": "not-a-timestamp",
            "checks": [
                {
                    "name": "discovery_pkce_s256",
                    "status": "passed",
                    "detail": "ok"
                },
                {
                    "name": "jwks_rs256_public_key_material",
                    "status": "failed",
                    "detail": ""
                },
                {
                    "name": "unexpected_check",
                    "status": "passed",
                    "detail": "ok"
                }
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let metadata_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "oidc_metadata_smoke")
        .expect("OIDC metadata smoke artifact");

    assert_eq!(metadata_artifact.status, "failed");
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("issuer must be an HTTPS origin"))
    );
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("unexpected_check"))
    );
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks must include issuer_https_origin"))
    );
    assert!(
        metadata_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be passed"))
    );
}

#[test]
fn release_evidence_rejects_invalid_scim_smoke() {
    let root = temp_evidence_dir("failed-scim-smoke");
    write_json(
        &root,
        "scim-smoke.json",
        json!({
            "status": "failed",
            "base_url": "http://id.example.com/scim/v2",
            "completed_at": "not-a-timestamp",
            "secondary_token_checked": false,
            "rejected_token_checked": false,
            "created_user_ids": [
                Uuid::new_v4(),
                "not-a-uuid"
            ],
            "soft_deleted_user_ids": [
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4()
            ],
            "deleted_group_id": "not-a-uuid",
            "checks": [
                {
                    "name": "service_provider_config",
                    "status": "failed",
                    "detail": ""
                },
                {
                    "name": "unexpected_check",
                    "status": "passed",
                    "detail": "ok"
                }
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let scim_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_public_smoke")
        .expect("SCIM smoke artifact");

    assert_eq!(scim_artifact.status, "failed");
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("base_url must be an HTTPS SCIM smoke base URL"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("secondary_token_checked must be true"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("rejected_token_checked must be true"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("created_user_ids"))
    );
    assert!(scim_artifact.failures.iter().any(|failure| {
        failure.contains("soft_deleted_user_ids must match created_user_ids for cleanup evidence")
    }));
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("deleted_group_id must be a UUID"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("unexpected_check"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks must include schemas"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be passed"))
    );
    assert!(
        scim_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks[0].detail must not be empty"))
    );
}

#[test]
fn release_evidence_rejects_invalid_scim_connector_smoke() {
    let root = temp_evidence_dir("failed-scim-connector-smoke");

    let mut okta = scim_connector_smoke("okta");
    okta["status"] = json!("failed");
    okta["scim_base_url"] = json!("http://id.example.com/scim/v2");
    okta["completed_at"] = json!("not-a-timestamp");
    okta["connector_application_id"] = json!("");
    okta["secondary_token_checked"] = json!(false);
    okta["deactivated_user_id"] = json!(Uuid::new_v4());
    okta["checks"] = json!([
        {
            "name": "service_provider_config",
            "status": "failed",
            "detail": ""
        },
        {
            "name": "unexpected_check",
            "status": "passed",
            "detail": "unexpected"
        }
    ]);
    okta["raw_token"] = json!("must-not-be-archived");
    write_json(&root, "scim-okta-connector-smoke.json", okta);

    let mut entra = scim_connector_smoke("entra");
    entra["provider"] = json!("okta");
    entra["display_name"] = json!("Okta SCIM 2.0");
    entra["rejected_token_checked"] = json!(false);
    entra["created_user_ids"] = json!([Uuid::new_v4()]);
    entra["deleted_group_id"] = json!("not-a-uuid");
    write_json(&root, "scim-entra-connector-smoke.json", entra);

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let okta_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_okta_connector_smoke")
        .expect("Okta connector smoke artifact");
    assert_eq!(okta_artifact.status, "failed");
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        okta_artifact.failures.iter().any(|failure| {
            failure.contains("scim_base_url must be an HTTPS SCIM smoke base URL")
        })
    );
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
    assert!(okta_artifact.failures.iter().any(|failure| {
        failure.contains("$.raw_token must not be present in token-free connector smoke evidence")
    }));
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("connector_application_id must not be empty") })
    );
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("secondary_token_checked must be true") })
    );
    assert!(okta_artifact.failures.iter().any(|failure| {
        failure.contains("deactivated_user_id must be one of the created_user_ids")
    }));
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("unexpected_check"))
    );
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks must include connector_enabled"))
    );
    assert!(
        okta_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks[0].detail must not be empty"))
    );

    let entra_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "scim_entra_connector_smoke")
        .expect("Entra connector smoke artifact");
    assert_eq!(entra_artifact.status, "failed");
    assert!(
        entra_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("provider must be entra, got okta") })
    );
    assert!(
        entra_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("display_name must be Microsoft Entra SCIM 2.0") })
    );
    assert!(
        entra_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("rejected_token_checked must be true") })
    );
    assert!(
        entra_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("created_user_ids must contain exactly 2 UUIDs") })
    );
    assert!(
        entra_artifact
            .failures
            .iter()
            .any(|failure| { failure.contains("deleted_group_id must be a UUID") })
    );
}

#[test]
fn release_evidence_rejects_failed_restore_drill_report() {
    let root = temp_evidence_dir("failed-restore");
    write_json(&root, "operations-preflight.json", production_preflight());
    write_json(
        &root,
        "restore-drill.json",
        json!({
            "status": "failed",
            "organization_slug": "default",
            "organization_id": null,
            "completed_at": "2026-06-07T12:00:00Z",
            "database": {
                "reachable": true,
                "applied_migrations": 0,
                "migrations_present": false
            },
            "signing": {
                "legacy_env_configured": false,
                "key_encryption_key_configured": false,
                "active_database_kid": null,
                "active_jwks_count": 0,
                "active_database_key_decryptable": false,
                "signing_source_available": false
            },
            "checks": ["database is reachable"],
            "failures": [
                "restored database has no applied SQLx migrations"
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let restore_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "restore_drill")
        .expect("restore drill artifact");

    assert_eq!(restore_artifact.status, "failed");
    assert!(
        restore_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        restore_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("organization_id must be a UUID"))
    );
    assert!(
        restore_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("signing_source_available"))
    );
}

#[test]
fn release_evidence_rejects_invalid_browser_origin_smoke() {
    let root = temp_evidence_dir("failed-browser-origin");
    write_json(
        &root,
        "browser-origin-smoke.json",
        json!({
            "status": "failed",
            "base_url": "http://id.example.com",
            "hostile_origin": "https://browser-origin-smoke.invalid",
            "completed_at": "2026-06-07T12:00:00Z",
            "routes_checked": 2,
            "checks": [
                {
                    "name": "logout",
                    "method": "POST",
                    "path": "/api/v1/session/logout",
                    "status": "passed",
                    "origin_status": 403,
                    "referer_status": 403,
                    "no_store": true,
                    "pragma_no_cache": true,
                    "content_type_options_nosniff": true
                },
                {
                    "name": "admin user create",
                    "method": "GET",
                    "path": "/api/v1/users",
                    "status": "failed",
                    "origin_status": 401,
                    "referer_status": 403,
                    "no_store": false,
                    "pragma_no_cache": true,
                    "content_type_options_nosniff": true
                }
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let browser_origin_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "browser_origin_smoke")
        .expect("browser-origin smoke artifact");

    assert_eq!(browser_origin_artifact.status, "failed");
    assert!(
        browser_origin_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("base_url must be an HTTPS origin"))
    );
    assert!(
        browser_origin_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("method must be POST"))
    );
    assert!(
        browser_origin_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("origin_status must be 403"))
    );
    assert!(
        browser_origin_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("no_store must be true"))
    );
}

#[test]
fn release_evidence_rejects_invalid_security_headers_smoke() {
    let root = temp_evidence_dir("failed-security-headers");
    write_json(
        &root,
        "security-headers-smoke.json",
        json!({
            "status": "failed",
            "api_base_url": "http://id.example.com",
            "web_base_url": "https://app.example.com",
            "completed_at": "2026-06-07T12:00:00Z",
            "checks": [
                {
                    "service": "api",
                    "path": "/healthz",
                    "status": "failed",
                    "status_code": 200,
                    "content_security_policy": false,
                    "strict_transport_security": false,
                    "x_content_type_options_nosniff": true,
                    "x_frame_options_deny": true,
                    "referrer_policy_no_referrer": true,
                    "permissions_policy_restrictive": true,
                    "cross_origin_opener_policy_same_origin": true,
                    "cache_control_no_store": null
                }
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let security_headers_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "security_headers_smoke")
        .expect("security-headers smoke artifact");

    assert_eq!(security_headers_artifact.status, "failed");
    assert!(
        security_headers_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("api_base_url must be an HTTPS origin"))
    );
    assert!(
        security_headers_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("content_security_policy must be true"))
    );
    assert!(
        security_headers_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("checks must include a web service response"))
    );
}

#[test]
fn release_evidence_rejects_invalid_email_provider_smoke() {
    let root = temp_evidence_dir("failed-email-provider-smoke");
    write_json(
        &root,
        "email-provider-smoke.json",
        json!({
            "status": "ok",
            "provider": "stdout",
            "recipient_email": "ops.example.com",
            "completed_at": "not-a-timestamp",
            "provider_message_id": ""
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let email_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "email_provider_smoke")
        .expect("email provider smoke artifact");

    assert_eq!(email_artifact.status, "failed");
    assert!(
        email_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be sent"))
    );
    assert!(
        email_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("provider must be command"))
    );
    assert!(
        email_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("recipient_email must contain @"))
    );
    assert!(
        email_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
    assert!(
        email_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("provider_message_id"))
    );
}

#[test]
fn release_evidence_rejects_invalid_audit_export_archive_receipt() {
    let root = temp_evidence_dir("failed-audit-export");
    write_json(
        &root,
        "audit-export-archive-drill.json",
        json!({
            "status": "failed",
            "organization_id": "not-a-uuid",
            "output_path": "-",
            "rows_exported": 10,
            "bytes_written": 0,
            "limit": 5,
            "export_max_rows": 3,
            "has_more": true,
            "next_after_created_at": null,
            "next_after_id": null,
            "filters": {
                "action_prefix": "admin.",
                "target_prefix": null,
                "actor_kind": "service",
                "actor_id": "not-a-uuid",
                "created_from": "not-a-timestamp",
                "created_to": null
            },
            "completed_at": "2026-06-07T12:00:00Z"
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let audit_export_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "audit_export_archive_drill")
        .expect("audit export artifact");

    assert_eq!(audit_export_artifact.status, "failed");
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("organization_id must be a UUID"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("rows_exported"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("next_after_created_at"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("next_after_id must be a UUID"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("filters.actor_kind"))
    );
    assert!(
        audit_export_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("filters.actor_id must be a UUID"))
    );
}

#[test]
fn release_evidence_rejects_invalid_audit_retention_purge_receipt() {
    let root = temp_evidence_dir("failed-audit-purge");
    write_json(
        &root,
        "audit-retention-purge-drill.json",
        json!({
            "status": "failed",
            "organization_id": "not-a-uuid",
            "retention_days": 7,
            "cutoff": "not-a-timestamp",
            "batch_size": 0,
            "deleted": 10,
            "completed_at": "not-a-timestamp"
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let purge_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "audit_retention_purge_drill")
        .expect("audit retention purge artifact");

    assert_eq!(purge_artifact.status, "failed");
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ok"))
    );
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("organization_id must be a UUID"))
    );
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("retention_days"))
    );
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("batch_size"))
    );
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("cutoff"))
    );
    assert!(
        purge_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
}

#[test]
fn release_evidence_rejects_invalid_break_glass_admin_recovery_receipt() {
    let root = temp_evidence_dir("failed-break-glass");
    write_json(
        &root,
        "break-glass-admin-recovery-drill.json",
        json!({
            "status": "ok",
            "organization_id": "not-a-uuid",
            "user_id": "not-a-uuid",
            "user_email": "",
            "user_status_before": "deleted",
            "user_status_after": "suspended",
            "admin_group_id": "not-a-uuid",
            "admin_group_created": false,
            "membership_role_before": "viewer",
            "membership_role_after": "member",
            "audit_event_id": null,
            "completed_at": "not-a-timestamp"
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let recovery_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "break_glass_admin_recovery_drill")
        .expect("break-glass recovery artifact");

    assert_eq!(recovery_artifact.status, "failed");
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be granted"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("organization_id must be a UUID"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("user_id must be a UUID"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("admin_group_id must be a UUID"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("user_status_after"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("membership_role_after"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("audit_event_id"))
    );
    assert!(
        recovery_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
}

#[test]
fn release_evidence_rejects_invalid_key_encryption_rotation_receipt() {
    let root = temp_evidence_dir("failed-kek-rotation");
    write_json(
        &root,
        "kek-rotation-drill.json",
        json!({
            "status": "ok",
            "signing_keys": 0,
            "email_delivery_tokens": -1,
            "completed_at": "not-a-timestamp"
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let kek_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "kek_rotation_drill")
        .expect("kek rotation artifact");

    assert_eq!(kek_artifact.status, "failed");
    assert!(
        kek_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be rotated"))
    );
    assert!(
        kek_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("signing_keys"))
    );
    assert!(
        kek_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("email_delivery_tokens"))
    );
    assert!(
        kek_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
}

#[test]
fn release_evidence_rejects_invalid_lifecycle_email_smoke_receipt() {
    let root = temp_evidence_dir("failed-lifecycle-email");
    write_json(
        &root,
        "lifecycle-email-smoke.json",
        json!({
            "status": "ok",
            "provider": "stdout",
            "completed_at": "not-a-timestamp",
            "messages": [
                {
                    "kind": "invitation",
                    "template": "unexpected_provider_template",
                    "status": "failed",
                    "action_url_present": false,
                    "provider_message_id": ""
                },
                {
                    "kind": "unknown",
                    "template": "unknown",
                    "status": "sent",
                    "action_url_present": false
                }
            ]
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let lifecycle_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "lifecycle_email_smoke")
        .expect("lifecycle email artifact");

    assert_eq!(lifecycle_artifact.status, "failed");
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be completed"))
    );
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("provider must be command"))
    );
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
    assert!(lifecycle_artifact.failures.iter().any(|failure| {
        failure.contains("template must be one of account_invitation for lifecycle kind invitation")
    }));
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .all(|failure| !failure.contains("unexpected_provider_template"))
    );
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("action_url_present must be true"))
    );
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("provider_message_id"))
    );
    assert!(
        lifecycle_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("password_recovery"))
    );
}

#[test]
fn release_evidence_rejects_invalid_openid_static_artifacts() {
    let root = temp_evidence_dir("failed-openid-static");
    write_json(
        &root,
        "openid-static-registration.json",
        json!({
            "status": "draft",
            "issuer": "http://id.example.com/path",
            "suite_alias": "",
            "certification_profiles": ["Config OP"],
            "run_plan_commands": ["scripts/run-test-plan.py wrong-plan cairn-oidcc-static.json"],
            "static_clients": [
                {
                    "role": "primary",
                    "client_id": "",
                    "redirect_uris": ["http://suite.example.com/callback"],
                    "post_logout_redirect_uris": [],
                    "response_types": [],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_methods": ["client_secret_basic"],
                    "allowed_scopes": ["openid"],
                    "pkce_methods": []
                }
            ],
            "unsupported_v1_profiles": ["Implicit OP"]
        }),
    );
    write_json(
        &root,
        "cairn-oidcc-static.json",
        json!({
            "alias": "",
            "description": "",
            "server": {
                "discoveryUrl": "http://id.example.com/.well-known/openid-configuration"
            },
            "client": {
                "client_id": "",
                "client_secret": ""
            },
            "client2": {
                "client_id": "",
                "client_secret": ""
            }
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let registration_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_static_registration")
        .expect("openid static registration artifact");
    let config_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "openid_static_config")
        .expect("openid static config artifact");

    assert_eq!(registration_artifact.status, "failed");
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be ready"))
    );
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("generated_at must be present"))
    );
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("issuer must be an HTTPS origin"))
    );
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("certification_profiles must include Basic OP"))
    );
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("static_clients must contain exactly 2"))
    );
    assert!(
        registration_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("allowed_scopes must include offline_access"))
    );

    assert_eq!(config_artifact.status, "failed");
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("generated_at must be present"))
    );
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("server.discoveryUrl"))
    );
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("client.client_secret"))
    );
    assert!(
        config_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("client2.client_id"))
    );
}

#[test]
fn release_evidence_rejects_invalid_signing_key_rotation_receipt() {
    let root = temp_evidence_dir("failed-signing-key-rotation");
    write_json(
        &root,
        "signing-key-rotation-drill.json",
        json!({
            "status": "ok",
            "active_kid": "",
            "active": false,
            "completed_at": "not-a-timestamp"
        }),
    );

    let report = check_release_evidence(
        &root,
        OffsetDateTime::now_utc(),
        DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
    )
    .expect("release evidence report");

    let signing_key_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "signing_key_rotation_drill")
        .expect("signing key rotation artifact");

    assert_eq!(signing_key_artifact.status, "failed");
    assert!(
        signing_key_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("status must be rotated"))
    );
    assert!(
        signing_key_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("active_kid"))
    );
    assert!(
        signing_key_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("active must be true"))
    );
    assert!(
        signing_key_artifact
            .failures
            .iter()
            .any(|failure| failure.contains("completed_at"))
    );
}

fn release_assets_options(release: &FakeReleaseAssets) -> ReleaseAssetsVerificationOptions {
    ReleaseAssetsVerificationOptions {
        release_dir: release.root.clone(),
        release_tag: release.tag.to_owned(),
        source_commit: release.source_commit.to_owned(),
        release_url: Some(release.release_url.to_owned()),
        run_url: Some(release.run_url.to_owned()),
        provenance_attestations_verified: true,
        sbom_attestations_verified: true,
    }
}

fn assert_failed_release_assets_report(
    report: &super::ReleaseAssetsVerificationReceipt,
    expected_failure: &str,
) {
    assert_eq!(report.status, "failed");
    assert!(
        !report.failures.is_empty(),
        "failed report should include failures"
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains(expected_failure)),
        "{:?}",
        report.failures
    );
    let value = serde_json::to_value(report).expect("failed report JSON");
    assert_eq!(value["status"], json!("failed"));
    assert!(
        !value["failures"]
            .as_array()
            .expect("report failures array")
            .is_empty()
    );
}

fn release_assets_failures(error: &ReleaseAssetsVerificationError) -> &[String] {
    error.failures().expect("verification failures")
}

fn rewrite_checksum_for_file(root: &Path, file_name: &str) {
    let checksum_path = root.join("SHA256SUMS.txt");
    let replacement_hash = sha256_test_file(&root.join(file_name));
    let checksum_text = fs::read_to_string(&checksum_path).expect("read checksums");
    let mut replaced = false;
    let updated = checksum_text
        .lines()
        .map(|line| {
            let mut parts = line.split_whitespace();
            let _digest = parts.next();
            let entry_file = parts.next().map(|entry| entry.trim_start_matches('*'));
            if entry_file == Some(file_name) {
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

fn sha256_test_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file for sha256");
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn release_evidence_rejects_unsafe_max_age() {
    let root = temp_evidence_dir("max-age");

    let error = check_release_evidence(&root, OffsetDateTime::now_utc(), 0)
        .expect_err("zero max age is invalid");

    assert!(error.to_string().contains("max age"));
}
