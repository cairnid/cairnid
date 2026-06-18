mod artifact_check;
mod dispatch;
mod email_evidence;
mod oidc;
mod operations_drill;
mod operations_readiness;
mod plan;
mod public_surface;
mod redaction;
mod registry;
mod release_assets;
mod scaffold;
mod scim;
mod timestamp;
mod types;
mod validation;

use self::dispatch::validate_artifact;
pub use self::email_evidence::{
    REQUIRED_LIFECYCLE_EMAIL_KINDS, lifecycle_email_template_is_allowed,
    lifecycle_email_template_requirement,
};
use self::redaction::sanitize_release_evidence_failure;
use self::registry::EVIDENCE_SPECS;
pub use self::release_assets::{
    ReleaseAssetsVerificationError, ReleaseAssetsVerificationOptions,
    ReleaseAssetsVerificationReceipt, release_assets_verification_receipt,
};
pub use self::types::{
    RELEASE_EVIDENCE_SCHEMA_VERSION, ReleaseEvidenceArtifactReport,
    ReleaseEvidenceEnvironmentRequirement, ReleaseEvidenceError, ReleaseEvidenceInitReport,
    ReleaseEvidenceManifest, ReleaseEvidenceManifestArtifact, ReleaseEvidenceNextAction,
    ReleaseEvidencePlanReport, ReleaseEvidencePlanStep, ReleaseEvidenceReport,
    ReleaseEvidenceStatusReport,
};
use std::path::Path;
use time::OffsetDateTime;

pub const DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS: i64 = 30;

pub fn check_release_evidence(
    evidence_dir: &Path,
    now: OffsetDateTime,
    max_age_days: i64,
) -> Result<ReleaseEvidenceReport, ReleaseEvidenceError> {
    if !(1..=365).contains(&max_age_days) {
        return Err(ReleaseEvidenceError::InvalidMaxAge);
    }
    if !evidence_dir.is_dir() {
        return Err(ReleaseEvidenceError::NotDirectory(
            evidence_dir.to_string_lossy().into_owned(),
        ));
    }

    let mut failures = Vec::new();
    scaffold::validate_release_evidence_scaffold(evidence_dir, now, max_age_days, &mut failures)?;
    scaffold::validate_release_evidence_file_inventory(
        evidence_dir,
        EVIDENCE_SPECS,
        &mut failures,
    )?;

    let mut artifacts = Vec::with_capacity(EVIDENCE_SPECS.len());
    for spec in EVIDENCE_SPECS {
        let artifact = artifact_check::check_artifact(
            evidence_dir,
            *spec,
            now,
            max_age_days,
            validate_artifact,
        )?;
        for failure in &artifact.failures {
            failures.push(format!("{}: {failure}", artifact.name));
        }
        artifacts.push(artifact);
    }

    let failures = failures
        .into_iter()
        .map(sanitize_release_evidence_failure)
        .collect::<Vec<_>>();

    Ok(ReleaseEvidenceReport {
        schema_version: RELEASE_EVIDENCE_SCHEMA_VERSION,
        status: if failures.is_empty() {
            "ready"
        } else {
            "incomplete"
        },
        evidence_dir: evidence_dir.to_string_lossy().into_owned(),
        generated_at: now,
        max_age_days,
        artifacts,
        failures,
    })
}

pub fn release_evidence_status_report(
    evidence_dir: &Path,
    now: OffsetDateTime,
    max_age_days: i64,
) -> Result<ReleaseEvidenceStatusReport, ReleaseEvidenceError> {
    let report = check_release_evidence(evidence_dir, now, max_age_days)?;
    Ok(summarize_release_evidence(&report))
}

pub fn summarize_release_evidence(report: &ReleaseEvidenceReport) -> ReleaseEvidenceStatusReport {
    let passed_artifact_count = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.status == "passed")
        .count();
    let missing_artifact_count = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.status == "missing")
        .count();
    let failed_artifact_count = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.status == "failed")
        .count();
    let next_actions = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.status != "passed")
        .map(|artifact| ReleaseEvidenceNextAction {
            name: artifact.name,
            file_name: artifact.file_name,
            release_gate: artifact.release_gate,
            status: artifact.status,
            command: artifact.command,
            failures: artifact.failures.clone(),
        })
        .collect::<Vec<_>>();

    ReleaseEvidenceStatusReport {
        schema_version: RELEASE_EVIDENCE_SCHEMA_VERSION,
        status: report.status,
        evidence_dir: report.evidence_dir.clone(),
        generated_at: report.generated_at,
        max_age_days: report.max_age_days,
        artifact_count: report.artifacts.len(),
        passed_artifact_count,
        missing_artifact_count,
        failed_artifact_count,
        secret_artifact_count: EVIDENCE_SPECS
            .iter()
            .filter(|spec| spec.contains_secrets)
            .count(),
        state_changing_artifact_count: EVIDENCE_SPECS
            .iter()
            .filter(|spec| spec.writes_application_state)
            .count(),
        external_provider_artifact_count: EVIDENCE_SPECS
            .iter()
            .filter(|spec| spec.touches_external_provider)
            .count(),
        next_actions,
        failures: report.failures.clone(),
    }
}

pub fn init_release_evidence_directory(
    evidence_dir: &Path,
    generated_at: OffsetDateTime,
    force: bool,
) -> Result<ReleaseEvidenceInitReport, ReleaseEvidenceError> {
    scaffold::init_release_evidence_directory(evidence_dir, generated_at, force)
}

pub fn release_evidence_capture_plan<F>(
    generated_at: OffsetDateTime,
    environment_present: F,
) -> ReleaseEvidencePlanReport
where
    F: Fn(&'static str) -> bool,
{
    plan::release_evidence_capture_plan_from_specs(
        EVIDENCE_SPECS,
        generated_at,
        environment_present,
    )
}

pub fn release_evidence_manifest(generated_at: OffsetDateTime) -> ReleaseEvidenceManifest {
    scaffold::release_evidence_manifest_from_specs(EVIDENCE_SPECS, generated_at)
}

#[cfg(test)]
mod tests;
