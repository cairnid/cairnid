use super::super::registry::EvidenceSpec;
use super::super::timestamp::{
    RELEASE_EVIDENCE_CLOCK_SKEW_SECONDS, parse_release_evidence_timestamp,
};
use super::super::{ReleaseEvidenceError, ReleaseEvidenceFailureCode, release_evidence_manifest};
use super::path_safety::{ReleaseEvidencePathKind, release_evidence_path_kind};
use super::{
    RELEASE_EVIDENCE_GITIGNORE, RELEASE_EVIDENCE_GITIGNORE_FILE, RELEASE_EVIDENCE_MANIFEST_FILE,
    RELEASE_EVIDENCE_README_FILE,
};
use serde_json::Value;
use std::{collections::BTreeSet, fs, io, path::Path};
use time::{Duration, OffsetDateTime};

pub(in crate::operations_evidence) fn validate_release_evidence_scaffold(
    evidence_dir: &Path,
    now: OffsetDateTime,
    max_age_days: i64,
    failures: &mut Vec<String>,
    failure_codes: &mut Vec<ReleaseEvidenceFailureCode>,
) -> Result<(), ReleaseEvidenceError> {
    let manifest_path = evidence_dir.join(RELEASE_EVIDENCE_MANIFEST_FILE);
    let manifest_missing_failure = format!(
        "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest is missing; run cairnid evidence init <evidence-dir>"
    );
    if let Some(contents) = read_scaffold_file(
        &manifest_path,
        RELEASE_EVIDENCE_MANIFEST_FILE,
        manifest_missing_failure,
        failures,
        failure_codes,
    )? {
        match serde_json::from_str::<Value>(&contents) {
            Ok(manifest) => {
                let generated_at = manifest
                    .get("generated_at")
                    .and_then(Value::as_str)
                    .and_then(parse_release_evidence_timestamp);
                let Some(generated_at) = generated_at else {
                    failures.push(format!(
                        "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest must include an RFC3339 generated_at timestamp"
                    ));
                    failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
                    return Ok(());
                };

                if now - generated_at > Duration::days(max_age_days) {
                    failures.push(format!(
                        "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest is older than {max_age_days} days and must be regenerated"
                    ));
                    failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
                }
                if generated_at - now > Duration::seconds(RELEASE_EVIDENCE_CLOCK_SKEW_SECONDS) {
                    failures.push(format!(
                        "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest timestamp is too far in the future"
                    ));
                    failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
                }

                let expected = serde_json::to_value(release_evidence_manifest(generated_at))?;
                if manifest != expected {
                    failures.push(format!(
                        "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest must match the current release-evidence artifact contract; rerun cairnid evidence init <evidence-dir> --force"
                    ));
                    failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
                }
            }
            Err(_) => {
                failures.push(format!(
                    "{RELEASE_EVIDENCE_MANIFEST_FILE}: scaffold manifest must be valid release-evidence JSON"
                ));
                failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
            }
        }
    }

    let readme_path = evidence_dir.join(RELEASE_EVIDENCE_README_FILE);
    let readme_missing_failure = format!(
        "{RELEASE_EVIDENCE_README_FILE}: scaffold README is missing; run cairnid evidence init <evidence-dir>"
    );
    if let Some(contents) = read_scaffold_file(
        &readme_path,
        RELEASE_EVIDENCE_README_FILE,
        readme_missing_failure,
        failures,
        failure_codes,
    )? && (!contents.contains("Do not commit the evidence artifacts")
        || !contents.contains("cairnid evidence check")
        || !contents.contains("Do not add screenshots, raw provider exports"))
    {
        failures.push(format!(
            "{RELEASE_EVIDENCE_README_FILE}: scaffold README is missing required release workflow guidance"
        ));
        failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
    }

    let gitignore_path = evidence_dir.join(RELEASE_EVIDENCE_GITIGNORE_FILE);
    let gitignore_missing_failure = format!(
        "{RELEASE_EVIDENCE_GITIGNORE_FILE}: scaffold gitignore is missing; run cairnid evidence init <evidence-dir>"
    );
    if let Some(contents) = read_scaffold_file(
        &gitignore_path,
        RELEASE_EVIDENCE_GITIGNORE_FILE,
        gitignore_missing_failure,
        failures,
        failure_codes,
    )? && contents.replace("\r\n", "\n") != RELEASE_EVIDENCE_GITIGNORE
    {
        failures.push(format!(
            "{RELEASE_EVIDENCE_GITIGNORE_FILE}: scaffold gitignore must match the guarded release-evidence template"
        ));
        failure_codes.push(ReleaseEvidenceFailureCode::StaleOrInvalidScaffold);
    }

    Ok(())
}

pub(in crate::operations_evidence) fn validate_release_evidence_file_inventory(
    evidence_dir: &Path,
    specs: &[EvidenceSpec],
    failures: &mut Vec<String>,
    failure_codes: &mut Vec<ReleaseEvidenceFailureCode>,
) -> Result<(), ReleaseEvidenceError> {
    let allowed_files = allowed_release_evidence_files(specs);

    for entry in fs::read_dir(evidence_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            failures.push(
                "release evidence directory contains a non-UTF-8 entry name; remove it before release"
                    .to_owned(),
            );
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
            continue;
        };

        if !allowed_files.contains(file_name) {
            failures.push(format!(
                "unexpected release evidence entry: {file_name}; remove files that are not generated scaffold files or required artifacts"
            ));
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
        }

        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            failures.push(format!(
                "release evidence entry must be a regular file, got symlink: {file_name}"
            ));
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
        } else if file_type.is_dir() {
            failures.push(format!(
                "release evidence entry must be a regular file, got directory: {file_name}"
            ));
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
        } else if !file_type.is_file() {
            failures.push(format!(
                "release evidence entry must be a regular file: {file_name}"
            ));
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
        }
    }

    Ok(())
}

fn read_scaffold_file(
    path: &Path,
    file_name: &'static str,
    missing_failure: String,
    failures: &mut Vec<String>,
    failure_codes: &mut Vec<ReleaseEvidenceFailureCode>,
) -> Result<Option<String>, ReleaseEvidenceError> {
    match release_evidence_path_kind(path)? {
        ReleaseEvidencePathKind::Missing => {
            failures.push(missing_failure);
            failure_codes.push(ReleaseEvidenceFailureCode::MissingEvidence);
            Ok(None)
        }
        ReleaseEvidencePathKind::RegularFile => match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(contents)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                failures.push(missing_failure);
                failure_codes.push(ReleaseEvidenceFailureCode::MissingEvidence);
                Ok(None)
            }
            Err(error) => Err(error.into()),
        },
        kind => {
            failures.push(kind.scaffold_failure(file_name));
            failure_codes.push(ReleaseEvidenceFailureCode::ArtifactPathFailure);
            Ok(None)
        }
    }
}

fn allowed_release_evidence_files(specs: &[EvidenceSpec]) -> BTreeSet<&'static str> {
    specs
        .iter()
        .map(|spec| spec.file_name)
        .chain([
            RELEASE_EVIDENCE_MANIFEST_FILE,
            RELEASE_EVIDENCE_README_FILE,
            RELEASE_EVIDENCE_GITIGNORE_FILE,
        ])
        .collect()
}
