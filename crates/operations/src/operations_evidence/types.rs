use serde::Serialize;
use std::io;
use time::OffsetDateTime;

pub const RELEASE_EVIDENCE_SCHEMA_VERSION: &str = "cairnid.evidence.v1";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEvidenceFailureCode {
    MissingEvidence,
    StaleOrInvalidScaffold,
    InvalidJson,
    InvalidJsonRoot,
    StaleOrInvalidTimestamp,
    TimestampContract,
    ForbiddenField,
    ArtifactPathFailure,
    ContractMismatch,
    ValidationFailed,
}

impl ReleaseEvidenceFailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingEvidence => "missing_evidence",
            Self::StaleOrInvalidScaffold => "stale_or_invalid_scaffold",
            Self::InvalidJson => "invalid_json",
            Self::InvalidJsonRoot => "invalid_json_root",
            Self::StaleOrInvalidTimestamp => "stale_or_invalid_timestamp",
            Self::TimestampContract => "timestamp_contract",
            Self::ForbiddenField => "forbidden_field",
            Self::ArtifactPathFailure => "artifact_path_failure",
            Self::ContractMismatch => "contract_mismatch",
            Self::ValidationFailed => "validation_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub evidence_dir: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub max_age_days: i64,
    pub artifacts: Vec<ReleaseEvidenceArtifactReport>,
    pub failures: Vec<String>,
    #[serde(skip_serializing)]
    pub failure_codes: Vec<ReleaseEvidenceFailureCode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceArtifactReport {
    pub name: &'static str,
    pub file_name: &'static str,
    pub release_gate: &'static str,
    pub status: &'static str,
    pub command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified_at: Option<OffsetDateTime>,
    pub checks: Vec<String>,
    pub failures: Vec<String>,
    #[serde(skip_serializing)]
    pub failure_codes: Vec<ReleaseEvidenceFailureCode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceManifest {
    pub schema_version: &'static str,
    pub status: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub default_max_age_days: i64,
    pub artifact_count: usize,
    pub artifacts: Vec<ReleaseEvidenceManifestArtifact>,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceManifestArtifact {
    pub name: &'static str,
    pub file_name: &'static str,
    pub release_gate: &'static str,
    pub command: &'static str,
    pub validator: &'static str,
    pub contains_secrets: bool,
    pub requires_production_like_environment: bool,
    pub writes_application_state: bool,
    pub touches_external_provider: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceInitReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub evidence_dir: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub force: bool,
    pub artifact_count: usize,
    pub secret_artifact_count: usize,
    pub state_changing_artifact_count: usize,
    pub external_provider_artifact_count: usize,
    pub files_written: Vec<String>,
    pub next_command: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidencePlanReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub local_capture_ready: bool,
    pub manual_evidence_pending: bool,
    pub external_evidence_pending: bool,
    pub artifact_count: usize,
    pub ready_artifact_count: usize,
    pub manual_artifact_count: usize,
    pub manual_pending_count: usize,
    pub missing_environment_artifact_count: usize,
    pub secret_artifact_count: usize,
    pub state_changing_artifact_count: usize,
    pub external_provider_artifact_count: usize,
    pub external_pending_count: usize,
    pub pending_manual_evidence: Vec<ReleaseEvidencePlanPendingArtifact>,
    pub pending_external_evidence: Vec<ReleaseEvidencePlanPendingArtifact>,
    pub steps: Vec<ReleaseEvidencePlanStep>,
    pub missing_environment: Vec<String>,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidencePlanPendingArtifact {
    pub name: &'static str,
    pub file_name: &'static str,
    pub release_gate: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidencePlanStep {
    pub name: &'static str,
    pub file_name: &'static str,
    pub release_gate: &'static str,
    pub command: &'static str,
    pub validator: &'static str,
    pub status: &'static str,
    pub pending_manual_evidence: bool,
    pub pending_external_evidence: bool,
    pub contains_secrets: bool,
    pub requires_production_like_environment: bool,
    pub writes_application_state: bool,
    pub touches_external_provider: bool,
    pub required_environment: Vec<ReleaseEvidenceEnvironmentRequirement>,
    pub missing_environment: Vec<String>,
    pub operator_notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceEnvironmentRequirement {
    pub alternatives: Vec<Vec<&'static str>>,
    pub purpose: &'static str,
    pub contains_secret: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceStatusReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub evidence_dir: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub max_age_days: i64,
    pub artifact_count: usize,
    pub passed_artifact_count: usize,
    pub missing_artifact_count: usize,
    pub failed_artifact_count: usize,
    pub secret_artifact_count: usize,
    pub state_changing_artifact_count: usize,
    pub external_provider_artifact_count: usize,
    pub next_actions: Vec<ReleaseEvidenceNextAction>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidenceNextAction {
    pub name: &'static str,
    pub file_name: &'static str,
    pub release_gate: &'static str,
    pub status: &'static str,
    pub command: &'static str,
    pub failures: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseEvidenceError {
    #[error("release evidence max age must be between 1 and 365 days")]
    InvalidMaxAge,
    #[error("release evidence path is not a directory: {0}")]
    NotDirectory(String),
    #[error("release evidence scaffold file already exists; pass --force to replace it: {0}")]
    ExistingScaffoldFile(String),
    #[error("release evidence JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("release evidence filesystem error: {0}")]
    Io(#[from] io::Error),
}
