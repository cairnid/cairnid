use super::super::registry::{EvidenceSpec, evidence_validator_name};
use super::super::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, RELEASE_EVIDENCE_SCHEMA_VERSION,
    ReleaseEvidenceManifest, ReleaseEvidenceManifestArtifact,
};
use time::OffsetDateTime;

pub(in crate::operations_evidence) fn release_evidence_manifest_from_specs(
    specs: &[EvidenceSpec],
    generated_at: OffsetDateTime,
) -> ReleaseEvidenceManifest {
    let artifacts = specs
        .iter()
        .map(|spec| ReleaseEvidenceManifestArtifact {
            name: spec.name,
            file_name: spec.file_name,
            release_gate: spec.release_gate,
            command: spec.command,
            validator: evidence_validator_name(spec.validator),
            contains_secrets: spec.contains_secrets,
            requires_production_like_environment: spec.requires_production_like_environment,
            writes_application_state: spec.writes_application_state,
            touches_external_provider: spec.touches_external_provider,
        })
        .collect::<Vec<_>>();

    ReleaseEvidenceManifest {
        schema_version: RELEASE_EVIDENCE_SCHEMA_VERSION,
        status: "ok",
        generated_at,
        default_max_age_days: DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
        artifact_count: artifacts.len(),
        artifacts,
        notes: vec![
            "Store release evidence in an access-controlled directory.",
            "Do not commit cairn-oidcc-static.json because it contains OIDC client secrets.",
            "This manifest is an operator checklist only; it does not produce artifacts, prove release approval, or claim production readiness.",
            "Review contains_secrets, requires_production_like_environment, writes_application_state, and touches_external_provider before running any command.",
            "State-changing artifacts such as lifecycle-email-smoke.json and signing-key-rotation-drill.json require explicit approval and an approved production-like or restored drill target.",
            "External-provider artifacts such as release-assets-verification.json and lifecycle-email-smoke.json must be normalized token-free receipts without raw provider exports, logs, screenshots, request headers, cookies, or tokens.",
            "release-assets-verification.json is final release evidence only after a published GitHub Release exists and provenance plus SBOM attestation checks have passed; workflow-run and rehearsal receipts are not final release evidence.",
            "Run cairnid evidence check against the completed directory before the first public RC and each public release.",
        ],
    }
}
