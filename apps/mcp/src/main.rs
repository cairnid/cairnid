#![forbid(unsafe_code)]

use cairn_operations::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, ReleaseEvidenceArtifactReport,
    ReleaseEvidenceEnvironmentRequirement, ReleaseEvidenceError, ReleaseEvidenceManifest,
    ReleaseEvidenceManifestArtifact, ReleaseEvidencePlanReport, ReleaseEvidencePlanStep,
    ReleaseEvidenceReport, check_release_evidence, release_evidence_capture_plan,
    release_evidence_manifest,
};
use rmcp::{
    Json, ServerHandler, ServiceExt,
    model::{CallToolResult, Implementation, JsonObject, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fs, io,
    path::{Component, Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing_subscriber::EnvFilter;

const DEFAULT_EVIDENCE_CHILD: &str = "release-evidence";

#[derive(Debug, Clone, Default)]
struct CairnIdMcpServer;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct EvidenceDirectoryRequest {
    #[schemars(
        description = "Optional evidence directory. Defaults to release-evidence when omitted or null. Must be a non-empty relative path under the allowlisted evidence root, or an absolute path that resolves inside that root. Parent traversal (`..`), drive-relative paths, symlinked directories, and symlink entries are rejected.",
        extend("default" = DEFAULT_EVIDENCE_CHILD)
    )]
    evidence_dir: Option<String>,
    #[schemars(
        description = "Optional artifact freshness window in days. Defaults to 30 when omitted or null. Must be an integer from 1 through 365 inclusive.",
        range(min = 1, max = 365),
        extend("default" = DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS)
    )]
    max_age_days: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidencePlan {
    status: String,
    generated_at: String,
    artifact_count: usize,
    ready_artifact_count: usize,
    manual_artifact_count: usize,
    missing_environment_artifact_count: usize,
    secret_artifact_count: usize,
    state_changing_artifact_count: usize,
    external_provider_artifact_count: usize,
    steps: Vec<McpEvidencePlanStep>,
    missing_environment: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidencePlanStep {
    name: String,
    file_name: String,
    command: String,
    validator: String,
    status: String,
    contains_secrets: bool,
    requires_production_like_environment: bool,
    writes_application_state: bool,
    touches_external_provider: bool,
    required_environment: Vec<McpEvidenceEnvironmentRequirement>,
    missing_environment: Vec<String>,
    operator_notes: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceEnvironmentRequirement {
    alternatives: Vec<Vec<String>>,
    purpose: String,
    contains_secret: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceManifest {
    status: String,
    generated_at: String,
    default_max_age_days: i64,
    artifact_count: usize,
    artifacts: Vec<McpEvidenceManifestArtifact>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceManifestArtifact {
    name: String,
    file_name: String,
    command: String,
    validator: String,
    contains_secrets: bool,
    requires_production_like_environment: bool,
    writes_application_state: bool,
    touches_external_provider: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceSummary {
    status: String,
    generated_at: String,
    max_age_days: i64,
    artifact_count: usize,
    passed_artifact_count: usize,
    missing_artifact_count: usize,
    failed_artifact_count: usize,
    failure_count: usize,
    failure_codes: BTreeMap<String, usize>,
    artifacts: Vec<McpEvidenceArtifactSummary>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceArtifactSummary {
    name: String,
    file_name: String,
    command: String,
    status: String,
    check_count: usize,
    failure_count: usize,
    failure_codes: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct McpEvidenceErrorEnvelope {
    error: McpEvidenceErrorBody,
}

#[derive(Debug, Serialize)]
struct McpEvidenceErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct McpEvidenceRequestError {
    code: &'static str,
    message: &'static str,
}

impl McpEvidenceRequestError {
    const ALLOWLIST_ROOT_UNAVAILABLE: Self = Self::new(
        "allowlist_root_unavailable",
        "the evidence allowlist root could not be inspected",
    );
    const DRIVE_RELATIVE_OR_ROOT_STYLE_RELATIVE_PATH: Self = Self::new(
        "drive_relative_or_root_style_relative_path",
        "evidence_dir must be a relative path without a drive prefix or root prefix, or an absolute path inside the allowlisted evidence root",
    );
    const EMPTY_EVIDENCE_DIR: Self = Self::new(
        "empty_evidence_dir",
        "evidence_dir must be a non-empty path",
    );
    const EVIDENCE_CONTRACT_FAILED: Self = Self::new(
        "evidence_contract_failed",
        "release evidence failed the required contract",
    );
    const EVIDENCE_READ_FAILED: Self = Self::new(
        "evidence_read_failed",
        "release evidence files could not be read",
    );
    const INVALID_EVIDENCE_JSON: Self = Self::new(
        "invalid_evidence_json",
        "release evidence JSON could not be processed",
    );
    const INVALID_EVIDENCE_DIR: Self = Self::new(
        "invalid_evidence_dir",
        "evidence_dir must be a string path when provided",
    );
    const INVALID_MAX_AGE_DAYS: Self = Self::new(
        "invalid_max_age_days",
        "max_age_days must be an integer from 1 through 365",
    );
    const MISSING_EVIDENCE_DIR: Self = Self::new(
        "missing_evidence_dir",
        "evidence_dir must be an existing directory",
    );
    const NON_DIRECTORY_EVIDENCE_DIR: Self = Self::new(
        "non_directory_evidence_dir",
        "evidence_dir must be a directory",
    );
    const OUTSIDE_ALLOWLISTED_ROOT: Self = Self::new(
        "outside_allowlisted_root",
        "evidence_dir must resolve inside the allowlisted evidence root",
    );
    const PARENT_TRAVERSAL: Self = Self::new(
        "parent_traversal",
        "evidence_dir must not contain parent traversal",
    );
    const SYMLINK_ENTRY: Self = Self::new(
        "symlink_entry",
        "evidence_dir must not contain symlink entries",
    );
    const SYMLINKED_EVIDENCE_DIR: Self = Self::new(
        "symlinked_evidence_dir",
        "evidence_dir must not be a symlink",
    );
    const UNKNOWN_ARGUMENT: Self = Self::new(
        "unknown_argument",
        "only evidence_dir and max_age_days are accepted",
    );

    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl From<McpEvidenceRequestError> for CallToolResult {
    fn from(error: McpEvidenceRequestError) -> Self {
        let envelope = McpEvidenceErrorEnvelope {
            error: McpEvidenceErrorBody {
                code: error.code,
                message: error.message,
            },
        };
        let value = serde_json::to_value(envelope).expect("MCP evidence error must serialize");

        CallToolResult::structured_error(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceDirectoryKind {
    AllowlistRoot,
    EvidenceDir,
}

fn evidence_directory_input_schema() -> std::sync::Arc<JsonObject> {
    let mut schema = rmcp::handler::server::common::schema_for_type::<EvidenceDirectoryRequest>()
        .as_ref()
        .clone();
    schema.insert(
        "additionalProperties".to_owned(),
        serde_json::Value::Bool(false),
    );

    std::sync::Arc::new(schema)
}

#[tool_router]
impl CairnIdMcpServer {
    #[tool(
        name = "cairnid.evidence_plan",
        description = "Return the release evidence capture plan.",
        annotations(
            title = "Evidence Plan",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_plan(&self) -> Result<Json<McpEvidencePlan>, String> {
        let report = release_evidence_capture_plan(
            OffsetDateTime::now_utc(),
            |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
        );

        Ok(Json(mcp_evidence_plan(report)))
    }

    #[tool(
        name = "cairnid.evidence_manifest",
        description = "Return the release evidence artifact manifest.",
        annotations(
            title = "Evidence Manifest",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_manifest(&self) -> Result<Json<McpEvidenceManifest>, String> {
        Ok(Json(mcp_evidence_manifest(release_evidence_manifest(
            OffsetDateTime::now_utc(),
        ))))
    }

    #[tool(
        name = "cairnid.evidence_status",
        description = "Progress/status view for release evidence validation; returns sanitized status counts without changing files.",
        input_schema = evidence_directory_input_schema(),
        annotations(
            title = "Evidence Status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_status(
        &self,
        arguments: JsonObject,
    ) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
        let request = parse_evidence_directory_request(arguments)?;
        let root = evidence_allowlist_root()?;
        evidence_status_for_root(&root, request)
    }

    #[tool(
        name = "cairnid.evidence_check",
        description = "Strict final-gate alias for release evidence validation; returns the same sanitized summary shape as evidence_status without changing files.",
        input_schema = evidence_directory_input_schema(),
        annotations(
            title = "Evidence Check",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_check(
        &self,
        arguments: JsonObject,
    ) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
        let request = parse_evidence_directory_request(arguments)?;
        let root = evidence_allowlist_root()?;
        evidence_check_for_root(&root, request)
    }
}

#[tool_handler]
impl ServerHandler for CairnIdMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "cairnid-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions("Inspect release evidence without modifying files.")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tracing::debug!("starting cairnid-mcp stdio server");

    let service = CairnIdMcpServer.serve(stdio()).await.inspect_err(|error| {
        tracing::error!(?error, "failed to serve cairnid-mcp");
    })?;

    service.waiting().await?;
    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

fn evidence_status_for_root(
    root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    evidence_summary_for_root(root, request)
}

fn evidence_check_for_root(
    root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    evidence_summary_for_root(root, request)
}

fn evidence_summary_for_root(
    root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    let evidence_dir = resolve_evidence_dir_in_root(root, request.evidence_dir.as_deref())?;
    let max_age_days = request
        .max_age_days
        .unwrap_or(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS);
    let report = check_release_evidence(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)
        .map_err(mcp_release_evidence_error)?;

    Ok(Json(mcp_evidence_summary(&report)))
}

fn evidence_allowlist_root() -> Result<PathBuf, McpEvidenceRequestError> {
    let current_dir =
        env::current_dir().map_err(|_| McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE)?;
    canonical_existing_directory(&current_dir, EvidenceDirectoryKind::AllowlistRoot)
}

fn parse_evidence_directory_request(
    mut arguments: JsonObject,
) -> Result<EvidenceDirectoryRequest, McpEvidenceRequestError> {
    let evidence_dir = optional_string_argument(
        arguments.remove("evidence_dir"),
        McpEvidenceRequestError::INVALID_EVIDENCE_DIR,
    )?;
    let max_age_days = optional_i64_argument(
        arguments.remove("max_age_days"),
        McpEvidenceRequestError::INVALID_MAX_AGE_DAYS,
    )?;
    if !arguments.is_empty() {
        return Err(McpEvidenceRequestError::UNKNOWN_ARGUMENT);
    }

    Ok(EvidenceDirectoryRequest {
        evidence_dir,
        max_age_days,
    })
}

fn optional_string_argument(
    value: Option<serde_json::Value>,
    invalid_error: McpEvidenceRequestError,
) -> Result<Option<String>, McpEvidenceRequestError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid_error),
    }
}

fn optional_i64_argument(
    value: Option<serde_json::Value>,
    invalid_error: McpEvidenceRequestError,
) -> Result<Option<i64>, McpEvidenceRequestError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value.as_i64().map(Some).ok_or(invalid_error),
        Some(_) => Err(invalid_error),
    }
}

fn resolve_evidence_dir_in_root(
    root: &Path,
    value: Option<&str>,
) -> Result<PathBuf, McpEvidenceRequestError> {
    let root = canonical_existing_directory(root, EvidenceDirectoryKind::AllowlistRoot)?;
    let requested = value.unwrap_or(DEFAULT_EVIDENCE_CHILD).trim();
    if requested.is_empty() {
        return Err(McpEvidenceRequestError::EMPTY_EVIDENCE_DIR);
    }

    let requested = Path::new(requested);
    reject_parent_traversal(requested)?;
    reject_drive_relative_or_root_style_relative_path(requested)?;

    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let evidence_dir =
        canonical_existing_directory(&candidate, EvidenceDirectoryKind::EvidenceDir)?;

    if !evidence_dir.starts_with(&root) {
        return Err(McpEvidenceRequestError::OUTSIDE_ALLOWLISTED_ROOT);
    }

    reject_symlink_entries(&evidence_dir)?;
    Ok(evidence_dir)
}

fn canonical_existing_directory(
    path: &Path,
    kind: EvidenceDirectoryKind,
) -> Result<PathBuf, McpEvidenceRequestError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if kind == EvidenceDirectoryKind::EvidenceDir
                && error.kind() == io::ErrorKind::NotFound =>
        {
            return Err(McpEvidenceRequestError::MISSING_EVIDENCE_DIR);
        }
        Err(_) => return Err(directory_inspection_error(kind)),
    };

    if metadata.file_type().is_symlink() {
        return Err(directory_symlink_error(kind));
    }
    if !metadata.is_dir() {
        return Err(directory_not_directory_error(kind));
    }

    path.canonicalize()
        .map_err(|_| directory_inspection_error(kind))
}

fn directory_inspection_error(kind: EvidenceDirectoryKind) -> McpEvidenceRequestError {
    match kind {
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::EVIDENCE_READ_FAILED,
    }
}

fn directory_symlink_error(kind: EvidenceDirectoryKind) -> McpEvidenceRequestError {
    match kind {
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::SYMLINKED_EVIDENCE_DIR,
    }
}

fn directory_not_directory_error(kind: EvidenceDirectoryKind) -> McpEvidenceRequestError {
    match kind {
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::NON_DIRECTORY_EVIDENCE_DIR,
    }
}

fn reject_parent_traversal(path: &Path) -> Result<(), McpEvidenceRequestError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(McpEvidenceRequestError::PARENT_TRAVERSAL);
    }

    Ok(())
}

fn reject_drive_relative_or_root_style_relative_path(
    path: &Path,
) -> Result<(), McpEvidenceRequestError> {
    if path.is_absolute() {
        return Ok(());
    }

    if path
        .components()
        .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
    {
        return Err(McpEvidenceRequestError::DRIVE_RELATIVE_OR_ROOT_STYLE_RELATIVE_PATH);
    }

    Ok(())
}

fn reject_symlink_entries(evidence_dir: &Path) -> Result<(), McpEvidenceRequestError> {
    for entry in
        fs::read_dir(evidence_dir).map_err(|_| McpEvidenceRequestError::EVIDENCE_READ_FAILED)?
    {
        let entry = entry.map_err(|_| McpEvidenceRequestError::EVIDENCE_READ_FAILED)?;
        let file_type = entry
            .file_type()
            .map_err(|_| McpEvidenceRequestError::EVIDENCE_READ_FAILED)?;

        if file_type.is_symlink() {
            return Err(McpEvidenceRequestError::SYMLINK_ENTRY);
        }
    }

    Ok(())
}

fn mcp_release_evidence_error(error: ReleaseEvidenceError) -> McpEvidenceRequestError {
    match error {
        ReleaseEvidenceError::InvalidMaxAge => McpEvidenceRequestError::INVALID_MAX_AGE_DAYS,
        ReleaseEvidenceError::NotDirectory(_) => {
            McpEvidenceRequestError::NON_DIRECTORY_EVIDENCE_DIR
        }
        ReleaseEvidenceError::ExistingScaffoldFile(_) => {
            McpEvidenceRequestError::EVIDENCE_CONTRACT_FAILED
        }
        ReleaseEvidenceError::Json(_) => McpEvidenceRequestError::INVALID_EVIDENCE_JSON,
        ReleaseEvidenceError::Io(_) => McpEvidenceRequestError::EVIDENCE_READ_FAILED,
    }
}

fn mcp_evidence_plan(report: ReleaseEvidencePlanReport) -> McpEvidencePlan {
    McpEvidencePlan {
        status: report.status.to_owned(),
        generated_at: rfc3339(report.generated_at),
        artifact_count: report.artifact_count,
        ready_artifact_count: report.ready_artifact_count,
        manual_artifact_count: report.manual_artifact_count,
        missing_environment_artifact_count: report.missing_environment_artifact_count,
        secret_artifact_count: report.secret_artifact_count,
        state_changing_artifact_count: report.state_changing_artifact_count,
        external_provider_artifact_count: report.external_provider_artifact_count,
        steps: report
            .steps
            .into_iter()
            .map(mcp_evidence_plan_step)
            .collect(),
        missing_environment: report.missing_environment,
        notes: report.notes.into_iter().map(str::to_owned).collect(),
    }
}

fn mcp_evidence_plan_step(step: ReleaseEvidencePlanStep) -> McpEvidencePlanStep {
    McpEvidencePlanStep {
        name: step.name.to_owned(),
        file_name: step.file_name.to_owned(),
        command: step.command.to_owned(),
        validator: step.validator.to_owned(),
        status: step.status.to_owned(),
        contains_secrets: step.contains_secrets,
        requires_production_like_environment: step.requires_production_like_environment,
        writes_application_state: step.writes_application_state,
        touches_external_provider: step.touches_external_provider,
        required_environment: step
            .required_environment
            .into_iter()
            .map(mcp_environment_requirement)
            .collect(),
        missing_environment: step.missing_environment,
        operator_notes: step.operator_notes.into_iter().map(str::to_owned).collect(),
    }
}

fn mcp_environment_requirement(
    requirement: ReleaseEvidenceEnvironmentRequirement,
) -> McpEvidenceEnvironmentRequirement {
    McpEvidenceEnvironmentRequirement {
        alternatives: requirement
            .alternatives
            .into_iter()
            .map(|group| group.into_iter().map(str::to_owned).collect())
            .collect(),
        purpose: requirement.purpose.to_owned(),
        contains_secret: requirement.contains_secret,
    }
}

fn mcp_evidence_manifest(manifest: ReleaseEvidenceManifest) -> McpEvidenceManifest {
    McpEvidenceManifest {
        status: manifest.status.to_owned(),
        generated_at: rfc3339(manifest.generated_at),
        default_max_age_days: manifest.default_max_age_days,
        artifact_count: manifest.artifact_count,
        artifacts: manifest
            .artifacts
            .into_iter()
            .map(mcp_manifest_artifact)
            .collect(),
        notes: manifest.notes.into_iter().map(str::to_owned).collect(),
    }
}

fn mcp_manifest_artifact(artifact: ReleaseEvidenceManifestArtifact) -> McpEvidenceManifestArtifact {
    McpEvidenceManifestArtifact {
        name: artifact.name.to_owned(),
        file_name: artifact.file_name.to_owned(),
        command: artifact.command.to_owned(),
        validator: artifact.validator.to_owned(),
        contains_secrets: artifact.contains_secrets,
        requires_production_like_environment: artifact.requires_production_like_environment,
        writes_application_state: artifact.writes_application_state,
        touches_external_provider: artifact.touches_external_provider,
    }
}

fn mcp_evidence_summary(report: &ReleaseEvidenceReport) -> McpEvidenceSummary {
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
    let artifacts = report
        .artifacts
        .iter()
        .map(mcp_artifact_summary)
        .collect::<Vec<_>>();

    McpEvidenceSummary {
        status: stable_report_status(report.status).to_owned(),
        generated_at: rfc3339(report.generated_at),
        max_age_days: report.max_age_days,
        artifact_count: report.artifacts.len(),
        passed_artifact_count,
        missing_artifact_count,
        failed_artifact_count,
        failure_count: report.failures.len(),
        failure_codes: failure_code_counts(report.failures.iter().map(String::as_str)),
        artifacts,
    }
}

fn mcp_artifact_summary(artifact: &ReleaseEvidenceArtifactReport) -> McpEvidenceArtifactSummary {
    McpEvidenceArtifactSummary {
        name: artifact.name.to_owned(),
        file_name: artifact.file_name.to_owned(),
        command: artifact.command.to_owned(),
        status: stable_artifact_status(artifact.status).to_owned(),
        check_count: artifact.checks.len(),
        failure_count: artifact.failures.len(),
        failure_codes: failure_code_counts(artifact.failures.iter().map(String::as_str)),
    }
}

fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime must format as RFC3339")
}

fn stable_report_status(status: &str) -> &'static str {
    match status {
        "ready" => "ready",
        "incomplete" => "incomplete",
        _ => "unknown",
    }
}

fn stable_artifact_status(status: &str) -> &'static str {
    match status {
        "passed" => "passed",
        "missing" => "missing",
        "failed" => "failed",
        _ => "unknown",
    }
}

fn failure_code_counts<'a>(failures: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();

    for failure in failures {
        let code = failure_code(failure).to_owned();
        *counts.entry(code).or_insert(0) += 1;
    }

    counts
}

fn failure_code(failure: &str) -> &'static str {
    if failure.contains("required evidence artifact is missing") {
        "missing_artifact"
    } else if failure.contains("not valid JSON") {
        "invalid_json"
    } else if failure.contains("JSON root must be an object") {
        "invalid_json_root"
    } else if failure.contains("older than") || failure.contains("freshness window") {
        "stale_or_invalid_timestamp"
    } else if failure.contains("timestamp")
        || failure.contains("completed_at")
        || failure.contains("generated_at")
        || failure.contains("exportedAt")
    {
        "timestamp_contract"
    } else if failure.contains("must not be present") {
        "forbidden_field"
    } else if failure.contains("scaffold")
        || failure.contains("manifest")
        || failure.contains(".gitignore")
        || failure.contains("README.md")
    {
        "scaffold_contract"
    } else if failure.contains("unexpected release evidence entry") {
        "unexpected_entry"
    } else if failure.contains("symlink") {
        "symlink_entry"
    } else if failure.contains("could not be read") {
        "read_error"
    } else if failure.contains("must be")
        || failure.contains("must contain")
        || failure.contains("must match")
        || failure.contains("must start")
        || failure.contains("must include")
    {
        "contract_mismatch"
    } else {
        "validation_failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_operations::init_release_evidence_directory;
    use rmcp::ServerHandler;
    use serde_json::{Value, json};
    use std::{
        io,
        time::{SystemTime, UNIX_EPOCH},
    };

    const SENTINEL: &str = "CAIRNID_MCP_SENTINEL_DO_NOT_EXPOSE";

    #[test]
    fn advertises_only_read_only_release_evidence_tools() {
        let tools = CairnIdMcpServer::tool_router().list_all();
        let mut names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        names.sort_unstable();

        assert_eq!(
            names,
            vec![
                "cairnid.evidence_check",
                "cairnid.evidence_manifest",
                "cairnid.evidence_plan",
                "cairnid.evidence_status",
            ]
        );

        for tool in tools {
            let annotations = tool.annotations.expect("tool annotations");
            assert_eq!(annotations.read_only_hint, Some(true));
            assert_eq!(annotations.destructive_hint, Some(false));
        }
    }

    #[test]
    fn structured_evidence_tools_have_output_schemas() {
        assert_output_schema_object(CairnIdMcpServer::evidence_plan_tool_attr().output_schema);
        assert_output_schema_object(CairnIdMcpServer::evidence_manifest_tool_attr().output_schema);
        assert_output_schema_object(CairnIdMcpServer::evidence_status_tool_attr().output_schema);
        assert_output_schema_object(CairnIdMcpServer::evidence_check_tool_attr().output_schema);
    }

    #[test]
    fn evidence_status_input_schema_exposes_enforced_request_contract() {
        assert_evidence_directory_input_schema(
            CairnIdMcpServer::evidence_status_tool_attr()
                .input_schema
                .as_ref(),
        );
    }

    #[test]
    fn evidence_check_input_schema_exposes_enforced_request_contract() {
        assert_evidence_directory_input_schema(
            CairnIdMcpServer::evidence_check_tool_attr()
                .input_schema
                .as_ref(),
        );
    }

    #[test]
    fn evidence_status_and_check_descriptions_distinguish_tool_roles() {
        let status = CairnIdMcpServer::evidence_status_tool_attr();
        let check = CairnIdMcpServer::evidence_check_tool_attr();
        let status_description = status.description.expect("status description");
        let check_description = check.description.expect("check description");

        assert!(status_description.contains("Progress/status view"));
        assert!(check_description.contains("Strict final-gate alias"));
        assert!(check_description.contains("same sanitized summary shape"));
    }

    #[test]
    fn server_info_uses_binary_name() {
        let info = CairnIdMcpServer.get_info();

        assert_eq!(info.server_info.name, "cairnid-mcp");
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn defaults_to_release_evidence_child() {
        let root = temp_root("default-child");
        let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        assert_eq!(
            resolve_evidence_dir_in_root(&root, None).expect("default child"),
            evidence_dir.canonicalize().expect("canonical evidence dir")
        );

        remove_temp_root(root);
    }

    #[test]
    fn accepts_relative_evidence_directory_child() {
        let root = temp_root("relative-child");
        let evidence_dir = root.join("evidence").join("release");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        assert_eq!(
            resolve_evidence_dir_in_root(&root, Some("evidence/release")).expect("relative child"),
            evidence_dir.canonicalize().expect("canonical evidence dir")
        );

        remove_temp_root(root);
    }

    #[test]
    fn rejects_parent_traversal_paths() {
        let root = temp_root("parent-traversal");

        assert!(resolve_evidence_dir_in_root(&root, Some("../release-evidence")).is_err());
        assert!(resolve_evidence_dir_in_root(&root, Some("release-evidence/../other")).is_err());

        remove_temp_root(root);
    }

    #[test]
    fn rejects_absolute_paths_outside_allowlisted_root() {
        let root = temp_root("absolute-root");
        let outside = temp_root("absolute-outside");

        assert!(resolve_evidence_dir_in_root(&root, Some(&outside.to_string_lossy())).is_err());

        remove_temp_root(root);
        remove_temp_root(outside);
    }

    #[test]
    fn accepts_absolute_paths_inside_allowlisted_root() {
        let root = temp_root("absolute-inside");
        let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        assert_eq!(
            resolve_evidence_dir_in_root(&root, Some(&evidence_dir.to_string_lossy()))
                .expect("absolute inside root"),
            evidence_dir.canonicalize().expect("canonical evidence dir")
        );

        remove_temp_root(root);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_drive_relative_paths() {
        let root = temp_root("drive-relative");

        assert!(resolve_evidence_dir_in_root(&root, Some("C:release-evidence")).is_err());

        remove_temp_root(root);
    }

    #[test]
    fn rejects_symlinked_evidence_directory_when_supported() {
        let root = temp_root("symlink-dir");
        let target = root.join("target");
        let link = root.join(DEFAULT_EVIDENCE_CHILD);
        fs::create_dir_all(&target).expect("create symlink target");

        if let Err(error) = create_dir_symlink(&target, &link) {
            if symlink_unavailable(&error) {
                remove_temp_root(root);
                return;
            }
            panic!("create directory symlink: {error}");
        }

        assert!(resolve_evidence_dir_in_root(&root, None).is_err());

        remove_temp_root(root);
    }

    #[test]
    fn rejects_symlinked_evidence_entries_when_supported() {
        let root = temp_root("symlink-entry");
        let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        let target = root.join("target.json");
        let link = evidence_dir.join("operations-preflight.json");
        fs::write(&target, "{}").expect("write symlink target");

        if let Err(error) = create_file_symlink(&target, &link) {
            if symlink_unavailable(&error) {
                remove_temp_root(root);
                return;
            }
            panic!("create file symlink: {error}");
        }

        assert!(resolve_evidence_dir_in_root(&root, None).is_err());

        remove_temp_root(root);
    }

    #[test]
    fn status_and_check_do_not_expose_echoed_artifact_values() {
        let root = temp_root("sentinel");
        let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
        init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
            .expect("initialize evidence directory");
        write_email_provider_artifact_with_sentinel(&evidence_dir);

        let request = EvidenceDirectoryRequest {
            evidence_dir: None,
            max_age_days: Some(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS),
        };
        let status = evidence_status_for_root(&root, request.clone()).expect("MCP status response");
        let check = evidence_check_for_root(&root, request).expect("MCP check response");
        let status_json = serde_json::to_string(&status.0).expect("serialize status response");
        let check_json = serde_json::to_string(&check.0).expect("serialize check response");

        assert!(!status_json.contains(SENTINEL));
        assert!(!check_json.contains(SENTINEL));
        assert!(status_json.contains("contract_mismatch"));
        assert!(check_json.contains("contract_mismatch"));

        remove_temp_root(root);
    }

    fn assert_output_schema_object(output_schema: Option<std::sync::Arc<rmcp::model::JsonObject>>) {
        let schema = output_schema.expect("output schema");

        assert_eq!(
            schema.get("type"),
            Some(&serde_json::Value::String("object".to_owned()))
        );
    }

    fn assert_evidence_directory_input_schema(input_schema: &rmcp::model::JsonObject) {
        let schema = Value::Object(input_schema.clone());
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("input schema properties");
        let evidence_dir = properties
            .get("evidence_dir")
            .expect("evidence_dir input schema");
        let max_age_days = properties
            .get("max_age_days")
            .expect("max_age_days input schema");

        assert_eq!(
            evidence_dir.get("default"),
            Some(&json!(DEFAULT_EVIDENCE_CHILD))
        );
        assert_description_contains(
            evidence_dir,
            &[
                "Defaults to release-evidence",
                "non-empty relative path",
                "inside that root",
                "Parent traversal (`..`)",
                "drive-relative paths",
                "symlinked directories",
                "symlink entries",
            ],
        );

        assert_eq!(max_age_days.get("minimum"), Some(&json!(1)));
        assert_eq!(max_age_days.get("maximum"), Some(&json!(365)));
        assert_eq!(
            max_age_days.get("default"),
            Some(&json!(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS))
        );
        assert_description_contains(max_age_days, &["Defaults to 30", "1 through 365 inclusive"]);

        assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));

        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|value| value.as_str() == Some("evidence_dir"))
        );
        assert!(
            !required
                .iter()
                .any(|value| value.as_str() == Some("max_age_days"))
        );
    }

    fn assert_description_contains(schema: &Value, expected_fragments: &[&str]) {
        let description = schema
            .get("description")
            .and_then(Value::as_str)
            .expect("schema description");

        for expected in expected_fragments {
            assert!(
                description.contains(expected),
                "description {description:?} should contain {expected:?}"
            );
        }
    }

    fn write_email_provider_artifact_with_sentinel(evidence_dir: &Path) {
        let completed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("format completed_at");
        let artifact = serde_json::json!({
            "status": "sent",
            "failures": [],
            "errors": [],
            "completed_at": completed_at,
            "provider": SENTINEL,
            "recipient_email": "ops@example.com"
        });

        fs::write(
            evidence_dir.join("email-provider-smoke.json"),
            serde_json::to_vec_pretty(&artifact).expect("serialize sentinel artifact"),
        )
        .expect("write sentinel artifact");
    }

    fn temp_root(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "cairnid-mcp-{name}-{}-{timestamp}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temp root");
        root
    }

    fn remove_temp_root(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn symlink_unavailable(_error: &io::Error) -> bool {
        false
    }

    #[cfg(windows)]
    fn symlink_unavailable(error: &io::Error) -> bool {
        error.raw_os_error() == Some(1314)
    }
}
