use super::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, scim_connector_profile, scim_connector_smoke_template,
    types::ScimConnectorProfileError,
};
use cairn_operations::{
    ReleaseEvidenceArtifactReport, ReleaseEvidenceReport, check_release_evidence,
    init_release_evidence_directory,
};
use serde_json::{Map, Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn scim_connector_profile_reports_generic_shape() {
    let report = scim_connector_profile("generic", "https://id.example.com/")
        .expect("valid generic profile");
    let json = serde_json::to_value(&report).expect("serializable profile");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["status"], "ready");
    assert_eq!(json["profile"], "generic");
    assert_eq!(json["issuer"], "https://id.example.com");
    assert_eq!(json["scim_base_url"], "https://id.example.com/scim/v2");
    assert_eq!(
        json["service_provider_config_url"],
        "https://id.example.com/scim/v2/ServiceProviderConfig"
    );
    assert_eq!(
        json["authentication"]["connector_header"],
        "Authorization: Bearer <raw-token>"
    );
    assert!(
        json["smoke_commands"]
            .as_array()
            .expect("smoke commands")
            .iter()
            .any(|command| command
                .as_str()
                .is_some_and(|command| command.contains("CAIRN_SCIM_SECONDARY_BEARER_TOKEN")))
    );
    assert!(
        report
            .recommended_mappings
            .iter()
            .any(|mapping| mapping.scim_attribute == "members.value")
    );
}

#[test]
fn scim_connector_profile_reports_provider_specific_settings() {
    let okta =
        scim_connector_profile("okta", "https://id.example.com").expect("valid okta profile");
    assert_eq!(okta.profile, "okta");
    assert!(okta.connector_settings.iter().any(|setting| {
        setting.name == "Unique identifier field for users" && setting.value == "userName"
    }));
    assert!(okta.recommended_mappings.iter().any(|mapping| {
        mapping.resource == "User"
            && mapping.connector_attribute == "user.id"
            && mapping.scim_attribute == "externalId"
    }));

    let entra =
        scim_connector_profile("azure-ad", "https://id.example.com").expect("valid entra alias");
    assert_eq!(entra.profile, "entra");
    assert!(
        entra
            .connector_settings
            .iter()
            .any(|setting| setting.name == "Tenant URL")
    );
    assert!(entra.recommended_mappings.iter().any(|mapping| {
        mapping.resource == "User"
            && mapping.connector_attribute == "objectId"
            && mapping.scim_attribute == "externalId"
    }));
}

#[test]
fn scim_connector_profile_rejects_unsafe_inputs() {
    let unknown = scim_connector_profile("custom", "https://id.example.com")
        .expect_err("unknown profile should fail");
    assert!(matches!(
        unknown,
        ScimConnectorProfileError::UnknownProfile(_)
    ));

    let non_https = scim_connector_profile("generic", "http://id.example.com")
        .expect_err("connector profile requires HTTPS");
    assert!(matches!(
        non_https,
        ScimConnectorProfileError::NonHttpsIssuer
    ));

    let with_path = scim_connector_profile("generic", "https://id.example.com/scim/v2")
        .expect_err("connector profile requires origin");
    assert!(matches!(
        with_path,
        ScimConnectorProfileError::NonOriginIssuer
    ));

    let with_credentials = scim_connector_profile("generic", "https://ops@id.example.com")
        .expect_err("connector profile rejects credentials");
    assert!(matches!(
        with_credentials,
        ScimConnectorProfileError::NonOriginIssuer
    ));
}

#[test]
fn scim_connector_smoke_template_reports_provider_shape_without_secrets() {
    let report = scim_connector_smoke_template("okta", "https://id.example.com")
        .expect("valid okta template");
    let json = serde_json::to_value(&report).expect("serializable template");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["status"], "template");
    assert_eq!(json["source"], "external-scim-connector");
    assert_eq!(json["provider"], "okta");
    assert_eq!(json["display_name"], "Okta SCIM 2.0");
    assert_eq!(json["scim_base_url"], "https://id.example.com/scim/v2");
    assert_eq!(json["secondary_token_checked"], false);
    assert_eq!(json["rejected_token_checked"], false);
    assert_eq!(
        json["checks"].as_array().expect("checks").len(),
        REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS.len()
    );
    assert!(
        json["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .any(|check| check["name"] == "bulk_forward_reference" && check["status"] == "pending")
    );
    assert!(
        json["forbidden_fields"]
            .as_array()
            .expect("forbidden fields")
            .iter()
            .any(|field| field == "raw_token")
    );

    let serialized = serde_json::to_string(&report).expect("serialize template");
    assert!(!serialized.contains("Authorization: Bearer"));
    assert!(!serialized.contains("<raw-token>"));
    assert!(!serialized.contains("secret-value"));
}

#[test]
fn scim_connector_smoke_templates_are_rejected_until_external_fields_are_replaced() {
    for (profile, file_name) in [
        ("okta", "scim-okta-connector-smoke.json"),
        ("entra", "scim-entra-connector-smoke.json"),
    ] {
        let template = scim_connector_smoke_template_value(profile);
        let (_, artifact) = check_scim_connector_smoke_artifact(file_name, template);

        assert_eq!(artifact.status, "failed");
        assert_artifact_failure_contains(&artifact, "status must be ok, got template");
        assert_artifact_failure_contains(&artifact, "completed_at must be an RFC3339 timestamp");
        assert_artifact_failure_contains(
            &artifact,
            "secondary_token_checked must be true, got false",
        );
        assert_artifact_failure_contains(
            &artifact,
            "rejected_token_checked must be true, got false",
        );
        assert_artifact_failure_contains(&artifact, "created_user_ids[0] must be a UUID string");
        assert_artifact_failure_contains(&artifact, "checks[0].status must be passed, got pending");
        assert!(
            artifact
                .failures
                .iter()
                .all(|failure| !failure.contains("must-not-archive")),
            "template rejection should not depend on secret-looking values: {:?}",
            artifact.failures
        );
    }
}

#[test]
fn scim_connector_smoke_templates_can_be_completed_with_local_safe_values_for_validator_parity() {
    for (profile, file_name, artifact_name, other_external_artifact) in [
        (
            "okta",
            "scim-okta-connector-smoke.json",
            "scim_okta_connector_smoke",
            "scim_entra_connector_smoke",
        ),
        (
            "entra",
            "scim-entra-connector-smoke.json",
            "scim_entra_connector_smoke",
            "scim_okta_connector_smoke",
        ),
    ] {
        let evidence = completed_scim_connector_smoke_from_template(profile);
        let (report, artifact) = check_scim_connector_smoke_artifact(file_name, evidence);

        assert_eq!(artifact.name, artifact_name);
        assert_eq!(artifact.status, "passed", "{:?}", artifact.failures);
        assert!(artifact.checks.iter().any(|check| {
            check.contains("connector smoke covered required external provisioning flows")
        }));
        assert_release_report_keeps_external_gates_pending(&report, other_external_artifact);
    }
}

#[test]
fn scim_connector_smoke_template_forbidden_fields_match_release_validator_rejections() {
    let template = scim_connector_smoke_template_value("okta");
    let forbidden_fields = forbidden_fields_from_template(&template);
    for required_field in [
        "authorization",
        "authorization_header",
        "bearer_token",
        "client_secret",
        "password",
        "provider_credential",
        "provider_credentials",
        "raw_token",
        "secret_token",
    ] {
        assert!(
            forbidden_fields.iter().any(|field| field == required_field),
            "template should guide operators away from {required_field}"
        );
    }

    for field in forbidden_fields {
        let mut evidence = completed_scim_connector_smoke_from_template("okta");
        let mut probe = Map::new();
        probe.insert(field.clone(), json!("must-not-archive"));
        evidence["validator_probe"] = Value::Object(probe);

        let (_, artifact) =
            check_scim_connector_smoke_artifact("scim-okta-connector-smoke.json", evidence);

        assert_artifact_failure_contains(
            &artifact,
            &format!("$.validator_probe.{field} must not be present"),
        );
    }
}

#[test]
fn scim_connector_smoke_template_accepts_entra_alias_and_rejects_unsupported_inputs() {
    let entra = scim_connector_smoke_template("azuread", "https://id.example.com")
        .expect("valid entra alias");
    assert_eq!(entra.provider, "entra");
    assert_eq!(entra.display_name, "Microsoft Entra SCIM 2.0");

    let generic = scim_connector_smoke_template("generic", "https://id.example.com")
        .expect_err("generic templates are not supported");
    assert!(matches!(
        generic,
        ScimConnectorProfileError::UnsupportedSmokeTemplateProfile
    ));

    let non_https = scim_connector_smoke_template("okta", "http://id.example.com")
        .expect_err("template requires HTTPS issuer");
    assert!(matches!(
        non_https,
        ScimConnectorProfileError::NonHttpsIssuer
    ));
}

fn completed_scim_connector_smoke_from_template(profile: &str) -> Value {
    let mut value = scim_connector_smoke_template_value(profile);
    let provider = value["provider"]
        .as_str()
        .expect("template provider")
        .to_owned();
    value["status"] = json!("ok");
    value["completed_at"] = json!(release_evidence_timestamp());
    value["connector_application_id"] = json!(format!("local-{provider}-application"));
    value["provisioning_job_id"] = json!(format!("local-{provider}-job"));
    value["secondary_token_checked"] = json!(true);
    value["rejected_token_checked"] = json!(true);
    value["created_user_ids"] = json!([
        "01890d6f-109f-767a-96cb-2927626f45b1",
        "01890d6f-109f-767a-96cb-2927626f45b2"
    ]);
    value["deactivated_user_id"] = json!("01890d6f-109f-767a-96cb-2927626f45b1");
    value["deleted_group_id"] = json!("01890d6f-109f-767a-96cb-2927626f45aa");

    for check in value["checks"]
        .as_array_mut()
        .expect("template checks array")
        .iter_mut()
    {
        let name = check["name"].as_str().expect("check name").to_owned();
        check["status"] = json!("passed");
        check["detail"] = json!(format!("{provider} {name} passed locally"));
    }

    value
}

fn scim_connector_smoke_template_value(profile: &str) -> Value {
    let report = scim_connector_smoke_template(profile, "https://id.cairnid.invalid")
        .expect("SCIM connector smoke template");
    serde_json::to_value(report).expect("serialize SCIM connector smoke template")
}

fn forbidden_fields_from_template(value: &Value) -> Vec<String> {
    value["forbidden_fields"]
        .as_array()
        .expect("forbidden_fields array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("forbidden field is a string")
                .to_owned()
        })
        .collect()
}

fn check_scim_connector_smoke_artifact(
    file_name: &'static str,
    value: Value,
) -> (ReleaseEvidenceReport, ReleaseEvidenceArtifactReport) {
    let root = temp_release_evidence_dir("scim-connector-smoke-template-parity");
    init_release_evidence_directory(&root, release_evidence_now(), false)
        .expect("initialize release evidence scaffold");
    write_json(&root, file_name, &value);

    let report =
        check_release_evidence(&root, release_evidence_now(), 30).expect("check release evidence");
    let artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.file_name == file_name)
        .expect("target SCIM connector smoke artifact")
        .clone();

    fs::remove_dir_all(root).expect("cleanup release evidence temp dir");
    (report, artifact)
}

fn assert_artifact_failure_contains(artifact: &ReleaseEvidenceArtifactReport, fragment: &str) {
    assert!(
        artifact
            .failures
            .iter()
            .any(|failure| failure.contains(fragment)),
        "expected artifact failure containing {fragment:?}, got {:?}",
        artifact.failures
    );
}

fn assert_release_report_keeps_external_gates_pending(
    report: &ReleaseEvidenceReport,
    expected_missing_artifact: &str,
) {
    assert_eq!(report.status, "incomplete");
    assert!(report.artifacts.iter().any(|artifact| {
        artifact.name == expected_missing_artifact && artifact.status == "missing"
    }));
}

fn temp_release_evidence_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cairn-api-{name}-{}", Uuid::new_v4()))
}

fn write_json(root: &Path, file_name: &str, value: &Value) {
    fs::write(
        root.join(file_name),
        serde_json::to_string_pretty(value).expect("serialize evidence"),
    )
    .expect("write evidence");
}

fn release_evidence_now() -> OffsetDateTime {
    OffsetDateTime::parse(
        release_evidence_timestamp(),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("valid release evidence timestamp")
}

fn release_evidence_timestamp() -> &'static str {
    "2026-06-07T12:00:00Z"
}
