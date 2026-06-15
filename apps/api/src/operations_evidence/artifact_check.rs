use super::redaction::{
    reject_forbidden_token_free_release_evidence_fields, sanitize_release_evidence_failure,
};
use super::registry::{EvidenceSpec, EvidenceValidator};
use super::timestamp::validate_artifact_root_timestamp_freshness;
use super::{ReleaseEvidenceArtifactReport, ReleaseEvidenceError};
use serde_json::Value;
use std::{fs, io, path::Path};
use time::{Duration, OffsetDateTime};

pub(super) type ArtifactValidator =
    fn(EvidenceValidator, &Value, &mut Vec<String>, &mut Vec<String>);

pub(super) fn check_artifact(
    evidence_dir: &Path,
    spec: EvidenceSpec,
    now: OffsetDateTime,
    max_age_days: i64,
    validate_artifact: ArtifactValidator,
) -> Result<ReleaseEvidenceArtifactReport, ReleaseEvidenceError> {
    let path = evidence_dir.join(spec.file_name);
    let mut checks = Vec::new();
    let mut failures = Vec::new();
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };

    let Some(metadata) = metadata else {
        return Ok(ReleaseEvidenceArtifactReport {
            name: spec.name,
            file_name: spec.file_name,
            status: "missing",
            command: spec.command,
            modified_at: None,
            checks,
            failures: vec!["required evidence artifact is missing".to_owned()],
        });
    };

    let modified_at = metadata.modified().ok().map(OffsetDateTime::from);
    if let Some(modified_at) = modified_at
        && now - modified_at > Duration::days(max_age_days)
    {
        failures.push(format!(
            "artifact is older than {max_age_days} days and must be refreshed"
        ));
    }
    checks.push("artifact exists".to_owned());

    let value = read_json_artifact(&path, &mut failures);
    if let Some(value) = value.as_ref() {
        if !spec.contains_secrets {
            reject_forbidden_token_free_release_evidence_fields(
                value,
                "$",
                spec.name,
                &mut failures,
            );
        }
        validate_artifact_root_timestamp_freshness(
            value,
            now,
            max_age_days,
            &mut checks,
            &mut failures,
        );
        validate_artifact(spec.validator, value, &mut checks, &mut failures);
    }

    let failures = failures
        .into_iter()
        .map(sanitize_release_evidence_failure)
        .collect::<Vec<_>>();

    Ok(ReleaseEvidenceArtifactReport {
        name: spec.name,
        file_name: spec.file_name,
        status: if failures.is_empty() {
            "passed"
        } else {
            "failed"
        },
        command: spec.command,
        modified_at,
        checks,
        failures,
    })
}

fn read_json_artifact(path: &Path, failures: &mut Vec<String>) -> Option<Value> {
    match fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str::<Value>(&contents) {
            Ok(value) => {
                if value.is_object() {
                    Some(value)
                } else {
                    failures.push("artifact JSON root must be an object".to_owned());
                    None
                }
            }
            Err(error) => {
                failures.push(format!("artifact is not valid JSON: {error}"));
                None
            }
        },
        Err(error) => {
            failures.push(format!("artifact could not be read: {error}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, path::PathBuf};

    fn test_spec(contains_secrets: bool) -> EvidenceSpec {
        EvidenceSpec {
            name: "test_artifact",
            file_name: "artifact.json",
            command: "capture artifact",
            validator: EvidenceValidator::OperationsPreflight,
            contains_secrets,
            requires_production_like_environment: false,
            writes_application_state: false,
            touches_external_provider: false,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let root = env::temp_dir().join(format!(
            "cairn-artifact-check-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }

    fn fixed_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid fixed timestamp")
    }

    fn no_op_validator(
        _validator: EvidenceValidator,
        _value: &Value,
        _checks: &mut Vec<String>,
        _failures: &mut Vec<String>,
    ) {
    }

    fn panic_validator(
        _validator: EvidenceValidator,
        _value: &Value,
        _checks: &mut Vec<String>,
        _failures: &mut Vec<String>,
    ) {
        panic!("validator must not run for missing or unreadable artifacts");
    }

    fn evidence_validator(
        validator: EvidenceValidator,
        _value: &Value,
        checks: &mut Vec<String>,
        failures: &mut Vec<String>,
    ) {
        assert!(matches!(validator, EvidenceValidator::OperationsPreflight));
        checks.push("validator dispatched".to_owned());
        failures
            .push("provider expected redacted evidence, got client_secret=raw-value".to_owned());
    }

    #[test]
    fn missing_artifact_reports_missing_without_dispatching_validator() {
        let root = temp_dir("missing");
        let report = check_artifact(&root, test_spec(false), fixed_now(), 30, panic_validator)
            .expect("check artifact");

        assert_eq!(report.status, "missing");
        assert_eq!(report.modified_at, None);
        assert!(report.checks.is_empty());
        assert_eq!(
            report.failures,
            vec!["required evidence artifact is missing".to_owned()]
        );

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn invalid_json_artifact_reports_parse_failure_without_dispatching_validator() {
        let root = temp_dir("invalid-json");
        fs::write(root.join("artifact.json"), "{").expect("write invalid artifact");

        let report = check_artifact(&root, test_spec(false), fixed_now(), 30, panic_validator)
            .expect("check artifact");

        assert_eq!(report.status, "failed");
        assert!(report.checks.contains(&"artifact exists".to_owned()));
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.starts_with("artifact is not valid JSON:"))
        );

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn non_object_json_artifact_reports_contract_failure() {
        let root = temp_dir("non-object");
        fs::write(root.join("artifact.json"), "[]").expect("write array artifact");

        let report = check_artifact(&root, test_spec(false), fixed_now(), 30, panic_validator)
            .expect("check artifact");

        assert_eq!(report.status, "failed");
        assert!(
            report
                .failures
                .contains(&"artifact JSON root must be an object".to_owned())
        );

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn valid_artifact_runs_validator_and_sanitizes_failures() {
        let root = temp_dir("dispatch");
        fs::write(
            root.join("artifact.json"),
            r#"{"completed_at":"2027-01-15T08:00:00Z","status":"ok"}"#,
        )
        .expect("write artifact");

        let report = check_artifact(&root, test_spec(true), fixed_now(), 30, evidence_validator)
            .expect("check artifact");

        assert_eq!(report.status, "failed");
        assert!(report.checks.contains(&"artifact exists".to_owned()));
        assert!(report.checks.contains(
            &"completion timestamp is within the release evidence freshness window".to_owned()
        ));
        assert!(report.checks.contains(&"validator dispatched".to_owned()));
        assert!(
            report
                .failures
                .contains(&"provider expected redacted evidence, got <redacted>".to_owned())
        );

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn token_free_artifact_rejects_secret_shaped_fields() {
        let root = temp_dir("token-free");
        fs::write(
            root.join("artifact.json"),
            r#"{"completed_at":"2027-01-15T08:00:00Z","rawToken":"unsafe"}"#,
        )
        .expect("write artifact");

        let report = check_artifact(&root, test_spec(false), fixed_now(), 30, no_op_validator)
            .expect("check artifact");

        assert_eq!(report.status, "failed");
        assert!(report.failures.iter().any(|failure| failure
            == "$.rawToken must not be present in token-free release evidence artifact test_artifact"));

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }
}
