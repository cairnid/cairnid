#![forbid(unsafe_code)]

use cairn_operations::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, ReleaseEvidenceArtifactReport,
    ReleaseEvidenceEnvironmentRequirement, ReleaseEvidenceError, ReleaseEvidenceFailureCode,
    ReleaseEvidenceManifest, ReleaseEvidenceManifestArtifact, ReleaseEvidencePlanReport,
    ReleaseEvidencePlanStep, ReleaseEvidenceReport, check_release_evidence,
    release_evidence_capture_plan, release_evidence_manifest,
};
use clap::Parser;
use rmcp::{
    Json, ServerHandler, ServiceExt,
    model::{CallToolResult, Implementation, JsonObject, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::{Prefix, PrefixComponent};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fmt, fs, io,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DEFAULT_EVIDENCE_CHILD: &str = "release-evidence";
const MCP_EVIDENCE_RESULT_SCHEMA_VERSION: &str = "cairnid.mcp.evidence.v1";
const MIN_EVIDENCE_MAX_AGE_DAYS: i64 = 1;
const MAX_EVIDENCE_MAX_AGE_DAYS: i64 = 365;
const EXIT_INTERNAL_ERROR: u8 = 1;
const EXIT_OPERATOR_INPUT: u8 = 4;

#[derive(Debug, Parser)]
#[command(
    name = "cairnid-mcp",
    version,
    about = "Local stdio MCP server for read-only CairnID release evidence inspection.",
    long_about = None
)]
#[command(
    after_help = "Examples:\n  cairnid-mcp\n  cairnid-mcp --evidence-root C:\\path\\to\\cairnid"
)]
struct Cli {
    #[arg(
        long,
        value_name = "DIR",
        help = "Evidence allowlist root. Defaults to the process working directory"
    )]
    evidence_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct StartupEvidenceRoot {
    supplied: PathBuf,
    canonical: PathBuf,
}

#[derive(Debug, Clone)]
struct CairnIdMcpServer {
    evidence_root: PathBuf,
    canonical_evidence_root: PathBuf,
}

impl CairnIdMcpServer {
    fn new(evidence_root: StartupEvidenceRoot) -> Self {
        Self {
            evidence_root: evidence_root.supplied,
            canonical_evidence_root: evidence_root.canonical,
        }
    }
}

#[derive(Debug)]
enum StartupError {
    EvidenceRoot(StartupEvidenceRootError),
    Serve(Box<dyn Error + Send + Sync>),
}

impl StartupError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::EvidenceRoot(_) => EXIT_OPERATOR_INPUT,
            Self::Serve(_) => EXIT_INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvidenceRoot(error) => write!(formatter, "{error}"),
            Self::Serve(error) => write!(formatter, "stdio server failed: {error}"),
        }
    }
}

impl Error for StartupError {}

#[derive(Debug)]
struct StartupEvidenceRootError {
    kind: StartupEvidenceRootErrorKind,
}

#[derive(Debug)]
enum StartupEvidenceRootErrorKind {
    InspectFailed,
    NotDirectory,
    Symlink,
}

impl StartupEvidenceRootError {
    fn new(kind: StartupEvidenceRootErrorKind) -> Self {
        Self { kind }
    }

    fn inspect_failed() -> Self {
        Self::new(StartupEvidenceRootErrorKind::InspectFailed)
    }
}

impl fmt::Display for StartupEvidenceRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            StartupEvidenceRootErrorKind::InspectFailed => "could not be inspected",
            StartupEvidenceRootErrorKind::NotDirectory => "is not a directory",
            StartupEvidenceRootErrorKind::Symlink => "must not be a symlink",
        };

        write!(formatter, "evidence root {reason}")
    }
}

impl Error for StartupEvidenceRootError {}

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
    schema_version: &'static str,
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
    release_gate: String,
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
    schema_version: &'static str,
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
    release_gate: String,
    command: String,
    validator: String,
    contains_secrets: bool,
    requires_production_like_environment: bool,
    writes_application_state: bool,
    touches_external_provider: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceSummary {
    schema_version: &'static str,
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
    next_actions: Vec<McpEvidenceNextAction>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceArtifactSummary {
    name: String,
    file_name: String,
    release_gate: String,
    command: String,
    status: String,
    check_count: usize,
    failure_count: usize,
    failure_codes: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceNextAction {
    name: String,
    file_name: String,
    release_gate: String,
    status: String,
    command: String,
    failure_codes: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceErrorEnvelope {
    schema_version: &'static str,
    error: McpEvidenceErrorBody,
}

#[derive(Debug, Serialize, JsonSchema)]
struct McpEvidenceErrorBody {
    code: &'static str,
    failure_code: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    failure_codes: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<McpEvidenceSummary>,
}

#[derive(Debug, Clone, Copy)]
struct McpEvidenceRequestError {
    code: &'static str,
    failure_code: &'static str,
    message: &'static str,
}

impl McpEvidenceRequestError {
    #[cfg(test)]
    const ALLOWLIST_ROOT_UNAVAILABLE: Self = Self::new(
        "allowlist_root_unavailable",
        "internal_error",
        "the evidence allowlist root could not be inspected",
    );
    const DRIVE_RELATIVE_OR_ROOT_STYLE_RELATIVE_PATH: Self = Self::new(
        "drive_relative_or_root_style_relative_path",
        "artifact_path_failure",
        "evidence_dir must be a relative path without a drive prefix or root prefix, or an absolute path inside the allowlisted evidence root",
    );
    const EMPTY_EVIDENCE_DIR: Self = Self::new(
        "empty_evidence_dir",
        "missing_evidence",
        "evidence_dir must be a non-empty path",
    );
    const EVIDENCE_CONTRACT_FAILED: Self = Self::new(
        "evidence_contract_failed",
        "stale_or_invalid_scaffold",
        "release evidence failed the required contract",
    );
    const EVIDENCE_READ_FAILED: Self = Self::new(
        "evidence_read_failed",
        "artifact_path_failure",
        "release evidence files could not be read",
    );
    const INVALID_EVIDENCE_JSON: Self = Self::new(
        "invalid_evidence_json",
        "internal_error",
        "release evidence JSON could not be processed",
    );
    const INVALID_EVIDENCE_DIR: Self = Self::new(
        "invalid_evidence_dir",
        "artifact_path_failure",
        "evidence_dir must be a string path when provided",
    );
    const INVALID_MAX_AGE_DAYS: Self = Self::new(
        "invalid_max_age_days",
        "invalid_request",
        "max_age_days must be an integer from 1 through 365",
    );
    const MISSING_EVIDENCE_DIR: Self = Self::new(
        "missing_evidence_dir",
        "missing_evidence",
        "evidence_dir must be an existing directory",
    );
    const NON_DIRECTORY_EVIDENCE_DIR: Self = Self::new(
        "non_directory_evidence_dir",
        "artifact_path_failure",
        "evidence_dir must be a directory",
    );
    const NO_ARGUMENTS_ACCEPTED: Self = Self::new(
        "unknown_argument",
        "invalid_request",
        "this tool does not accept arguments",
    );
    const OUTSIDE_ALLOWLISTED_ROOT: Self = Self::new(
        "outside_allowlisted_root",
        "artifact_path_failure",
        "evidence_dir must resolve inside the allowlisted evidence root",
    );
    const PARENT_TRAVERSAL: Self = Self::new(
        "parent_traversal",
        "artifact_path_failure",
        "evidence_dir must not contain parent traversal",
    );
    const SYMLINK_ENTRY: Self = Self::new(
        "symlink_entry",
        "artifact_path_failure",
        "evidence_dir must not contain symlink entries",
    );
    const SYMLINKED_EVIDENCE_DIR: Self = Self::new(
        "symlinked_evidence_dir",
        "artifact_path_failure",
        "evidence_dir must not be a symlink",
    );
    const UNKNOWN_ARGUMENT: Self = Self::new(
        "unknown_argument",
        "invalid_request",
        "only evidence_dir and max_age_days are accepted",
    );

    const fn new(code: &'static str, failure_code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            failure_code,
            message,
        }
    }
}

impl From<McpEvidenceRequestError> for CallToolResult {
    fn from(error: McpEvidenceRequestError) -> Self {
        let envelope = McpEvidenceErrorEnvelope {
            schema_version: MCP_EVIDENCE_RESULT_SCHEMA_VERSION,
            error: McpEvidenceErrorBody {
                code: error.code,
                failure_code: error.failure_code,
                message: error.message,
                failure_codes: BTreeMap::from([(error.failure_code.to_owned(), 1)]),
                summary: None,
            },
        };
        let value = serde_json::to_value(envelope).expect("MCP evidence error must serialize");

        CallToolResult::structured_error(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceDirectoryKind {
    #[cfg(test)]
    AllowlistRoot,
    EvidenceDir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceDirPathBoundary {
    InsideRoot,
    InsideRootWithParentTraversal,
    OutsideRoot,
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

fn closed_empty_input_schema() -> std::sync::Arc<JsonObject> {
    let mut schema = JsonObject::new();
    schema.insert(
        "type".to_owned(),
        serde_json::Value::String("object".to_owned()),
    );
    schema.insert(
        "properties".to_owned(),
        serde_json::Value::Object(JsonObject::new()),
    );
    schema.insert(
        "additionalProperties".to_owned(),
        serde_json::Value::Bool(false),
    );

    std::sync::Arc::new(schema)
}

fn evidence_result_output_schema<T: JsonSchema + 'static>() -> std::sync::Arc<JsonObject> {
    let mut success = rmcp::handler::server::common::schema_for_type::<T>()
        .as_ref()
        .clone();
    let mut error = rmcp::handler::server::common::schema_for_type::<McpEvidenceErrorEnvelope>()
        .as_ref()
        .clone();
    pin_schema_version_consts(&mut success);
    pin_schema_version_consts(&mut error);
    let mut definitions = JsonObject::new();
    hoist_schema_definitions(&mut success, &mut definitions);
    hoist_schema_definitions(&mut error, &mut definitions);

    let mut schema = JsonObject::new();
    schema.insert(
        "type".to_owned(),
        serde_json::Value::String("object".to_owned()),
    );
    schema.insert(
        "oneOf".to_owned(),
        serde_json::Value::Array(vec![
            serde_json::Value::Object(success),
            serde_json::Value::Object(error),
        ]),
    );
    if !definitions.is_empty() {
        schema.insert("$defs".to_owned(), serde_json::Value::Object(definitions));
    }

    std::sync::Arc::new(schema)
}

fn pin_schema_version_consts(schema: &mut JsonObject) {
    pin_schema_version_const(schema);
    for value in schema.values_mut() {
        pin_schema_version_consts_in_value(value);
    }
}

fn pin_schema_version_consts_in_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            pin_schema_version_const(object);
            for child in object.values_mut() {
                pin_schema_version_consts_in_value(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                pin_schema_version_consts_in_value(child);
            }
        }
        _ => {}
    }
}

fn pin_schema_version_const(schema: &mut JsonObject) {
    let Some(properties) = schema
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let Some(schema_version) = properties
        .get_mut("schema_version")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };

    schema_version.insert(
        "const".to_owned(),
        serde_json::Value::String(MCP_EVIDENCE_RESULT_SCHEMA_VERSION.to_owned()),
    );
}

fn hoist_schema_definitions(schema: &mut JsonObject, definitions: &mut JsonObject) {
    let Some(serde_json::Value::Object(local_definitions)) = schema.remove("$defs") else {
        return;
    };

    for (name, definition) in local_definitions {
        match definitions.get(&name) {
            Some(existing) if existing == &definition => {}
            Some(_) => {
                panic!("conflicting MCP output schema definition for {name}");
            }
            None => {
                definitions.insert(name, definition);
            }
        }
    }
}

#[tool_router]
impl CairnIdMcpServer {
    #[tool(
        name = "cairnid.evidence_plan",
        description = "Return the release evidence capture plan.",
        input_schema = closed_empty_input_schema(),
        output_schema = evidence_result_output_schema::<McpEvidencePlan>(),
        annotations(
            title = "Evidence Plan",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_plan(
        &self,
        arguments: JsonObject,
    ) -> Result<Json<McpEvidencePlan>, CallToolResult> {
        parse_empty_arguments(arguments)?;
        let report = release_evidence_capture_plan(
            OffsetDateTime::now_utc(),
            |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
        );

        Ok(Json(mcp_evidence_plan(report)))
    }

    #[tool(
        name = "cairnid.evidence_manifest",
        description = "Return the release evidence artifact manifest.",
        input_schema = closed_empty_input_schema(),
        output_schema = evidence_result_output_schema::<McpEvidenceManifest>(),
        annotations(
            title = "Evidence Manifest",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn evidence_manifest(
        &self,
        arguments: JsonObject,
    ) -> Result<Json<McpEvidenceManifest>, CallToolResult> {
        parse_empty_arguments(arguments)?;
        Ok(Json(mcp_evidence_manifest(release_evidence_manifest(
            OffsetDateTime::now_utc(),
        ))))
    }

    #[tool(
        name = "cairnid.evidence_status",
        description = "Progress/status view for release evidence validation; returns sanitized status counts without changing files.",
        input_schema = evidence_directory_input_schema(),
        output_schema = evidence_result_output_schema::<McpEvidenceSummary>(),
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
        evidence_status_for_roots(&self.evidence_root, &self.canonical_evidence_root, request)
    }

    #[tool(
        name = "cairnid.evidence_check",
        description = "Strict final-gate release evidence validation; returns the sanitized summary when ready and a structured failure-code error when incomplete, without changing files.",
        input_schema = evidence_directory_input_schema(),
        output_schema = evidence_result_output_schema::<McpEvidenceSummary>(),
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
        evidence_check_for_roots(&self.evidence_root, &self.canonical_evidence_root, request)
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
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cairnid-mcp failed: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

async fn run(cli: Cli) -> Result<(), StartupError> {
    let evidence_root =
        startup_evidence_root(cli.evidence_root).map_err(StartupError::EvidenceRoot)?;
    init_stdio_tracing();
    tracing::debug!(
        evidence_root = %evidence_root.canonical.display(),
        "starting cairnid-mcp stdio server"
    );

    let service = CairnIdMcpServer::new(evidence_root)
        .serve(stdio())
        .await
        .inspect_err(|error| {
            tracing::error!(?error, "failed to serve cairnid-mcp");
        })
        .map_err(|error| StartupError::Serve(Box::new(error)))?;

    service
        .waiting()
        .await
        .map_err(|error| StartupError::Serve(Box::new(error)))?;
    Ok(())
}

fn init_stdio_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::OFF)
        .with_writer(io::sink)
        .with_ansi(false)
        .init();
}

#[cfg(test)]
fn evidence_status_for_root(
    root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    let canonical_root = canonical_existing_directory(root, EvidenceDirectoryKind::AllowlistRoot)?;
    evidence_status_for_roots(root, &canonical_root, request)
}

fn evidence_status_for_roots(
    root: &Path,
    canonical_root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    evidence_summary_for_roots(root, canonical_root, request)
}

#[cfg(test)]
fn evidence_check_for_root(
    root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    let canonical_root = canonical_existing_directory(root, EvidenceDirectoryKind::AllowlistRoot)?;
    evidence_check_for_roots(root, &canonical_root, request)
}

fn evidence_check_for_roots(
    root: &Path,
    canonical_root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    let report = release_evidence_report_for_roots(root, canonical_root, request)?;
    let summary = mcp_evidence_summary(&report);
    if summary.status == "ready" {
        Ok(Json(summary))
    } else {
        Err(incomplete_evidence_error(summary))
    }
}

fn evidence_summary_for_roots(
    root: &Path,
    canonical_root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<Json<McpEvidenceSummary>, CallToolResult> {
    let report = release_evidence_report_for_roots(root, canonical_root, request)?;

    Ok(Json(mcp_evidence_summary(&report)))
}

fn release_evidence_report_for_roots(
    root: &Path,
    canonical_root: &Path,
    request: EvidenceDirectoryRequest,
) -> Result<ReleaseEvidenceReport, CallToolResult> {
    let evidence_dir =
        resolve_evidence_dir_in_roots(root, canonical_root, request.evidence_dir.as_deref())?;
    let max_age_days = request
        .max_age_days
        .unwrap_or(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS);
    check_release_evidence(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)
        .map_err(mcp_release_evidence_error)
        .map_err(CallToolResult::from)
}

fn incomplete_evidence_error(summary: McpEvidenceSummary) -> CallToolResult {
    let failure_code = dominant_failure_code(&summary.failure_codes);
    let envelope = McpEvidenceErrorEnvelope {
        schema_version: MCP_EVIDENCE_RESULT_SCHEMA_VERSION,
        error: McpEvidenceErrorBody {
            code: "release_evidence_incomplete",
            failure_code,
            message: "release evidence is incomplete; inspect failure_codes and summary for the stable machine-readable failure contract",
            failure_codes: summary.failure_codes.clone(),
            summary: Some(summary),
        },
    };
    let value = serde_json::to_value(envelope).expect("MCP evidence check error must serialize");

    CallToolResult::structured_error(value)
}

fn startup_evidence_root(
    value: Option<PathBuf>,
) -> Result<StartupEvidenceRoot, StartupEvidenceRootError> {
    let supplied = match value {
        Some(root) => root,
        None => env::current_dir().map_err(|_| StartupEvidenceRootError::inspect_failed())?,
    };
    let supplied = absolute_startup_evidence_root(supplied)?;
    let canonical = canonical_startup_evidence_root(&supplied)?;

    Ok(StartupEvidenceRoot {
        supplied,
        canonical,
    })
}

fn absolute_startup_evidence_root(root: PathBuf) -> Result<PathBuf, StartupEvidenceRootError> {
    if root.is_absolute() {
        return Ok(root);
    }

    env::current_dir()
        .map(|current_dir| current_dir.join(root))
        .map_err(|_| StartupEvidenceRootError::inspect_failed())
}

fn canonical_startup_evidence_root(path: &Path) -> Result<PathBuf, StartupEvidenceRootError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| StartupEvidenceRootError::inspect_failed())?;

    if metadata.file_type().is_symlink() {
        return Err(StartupEvidenceRootError::new(
            StartupEvidenceRootErrorKind::Symlink,
        ));
    }
    if !metadata.is_dir() {
        return Err(StartupEvidenceRootError::new(
            StartupEvidenceRootErrorKind::NotDirectory,
        ));
    }

    path.canonicalize()
        .map_err(|_| StartupEvidenceRootError::inspect_failed())
}

fn parse_evidence_directory_request(
    mut arguments: JsonObject,
) -> Result<EvidenceDirectoryRequest, McpEvidenceRequestError> {
    if arguments
        .keys()
        .any(|key| !matches!(key.as_str(), "evidence_dir" | "max_age_days"))
    {
        return Err(McpEvidenceRequestError::UNKNOWN_ARGUMENT);
    }

    let evidence_dir = optional_string_argument(
        arguments.remove("evidence_dir"),
        McpEvidenceRequestError::INVALID_EVIDENCE_DIR,
    )?;
    let max_age_days = optional_i64_argument(
        arguments.remove("max_age_days"),
        McpEvidenceRequestError::INVALID_MAX_AGE_DAYS,
    )?;
    validate_max_age_days(max_age_days)?;

    Ok(EvidenceDirectoryRequest {
        evidence_dir,
        max_age_days,
    })
}

fn parse_empty_arguments(arguments: JsonObject) -> Result<(), McpEvidenceRequestError> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(McpEvidenceRequestError::NO_ARGUMENTS_ACCEPTED)
    }
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

fn validate_max_age_days(value: Option<i64>) -> Result<(), McpEvidenceRequestError> {
    match value {
        None => Ok(()),
        Some(value) if (MIN_EVIDENCE_MAX_AGE_DAYS..=MAX_EVIDENCE_MAX_AGE_DAYS).contains(&value) => {
            Ok(())
        }
        Some(_) => Err(McpEvidenceRequestError::INVALID_MAX_AGE_DAYS),
    }
}

#[cfg(test)]
fn resolve_evidence_dir_in_root(
    root: &Path,
    value: Option<&str>,
) -> Result<PathBuf, McpEvidenceRequestError> {
    let canonical_root = canonical_existing_directory(root, EvidenceDirectoryKind::AllowlistRoot)?;
    resolve_evidence_dir_in_roots(root, &canonical_root, value)
}

fn resolve_evidence_dir_in_roots(
    root: &Path,
    canonical_root: &Path,
    value: Option<&str>,
) -> Result<PathBuf, McpEvidenceRequestError> {
    let requested = value.unwrap_or(DEFAULT_EVIDENCE_CHILD).trim();
    if requested.is_empty() {
        return Err(McpEvidenceRequestError::EMPTY_EVIDENCE_DIR);
    }

    let requested = Path::new(requested);
    reject_drive_relative_or_root_style_relative_path(requested)?;
    reject_boundary_escape_or_parent_traversal(root, canonical_root, requested)?;

    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        canonical_root.to_path_buf().join(requested)
    };
    let evidence_dir =
        canonical_existing_directory(&candidate, EvidenceDirectoryKind::EvidenceDir)?;

    if !evidence_dir.starts_with(canonical_root) {
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
        #[cfg(test)]
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::EVIDENCE_READ_FAILED,
    }
}

fn directory_symlink_error(kind: EvidenceDirectoryKind) -> McpEvidenceRequestError {
    match kind {
        #[cfg(test)]
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::SYMLINKED_EVIDENCE_DIR,
    }
}

fn directory_not_directory_error(kind: EvidenceDirectoryKind) -> McpEvidenceRequestError {
    match kind {
        #[cfg(test)]
        EvidenceDirectoryKind::AllowlistRoot => McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE,
        EvidenceDirectoryKind::EvidenceDir => McpEvidenceRequestError::NON_DIRECTORY_EVIDENCE_DIR,
    }
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

fn reject_boundary_escape_or_parent_traversal(
    root: &Path,
    canonical_root: &Path,
    requested: &Path,
) -> Result<(), McpEvidenceRequestError> {
    match evidence_dir_path_boundary(root, canonical_root, requested) {
        EvidenceDirPathBoundary::InsideRoot => Ok(()),
        EvidenceDirPathBoundary::InsideRootWithParentTraversal => {
            Err(McpEvidenceRequestError::PARENT_TRAVERSAL)
        }
        EvidenceDirPathBoundary::OutsideRoot => {
            Err(McpEvidenceRequestError::OUTSIDE_ALLOWLISTED_ROOT)
        }
    }
}

fn evidence_dir_path_boundary(
    root: &Path,
    canonical_root: &Path,
    requested: &Path,
) -> EvidenceDirPathBoundary {
    if requested.is_absolute() {
        return best_absolute_evidence_dir_path_boundary(root, canonical_root, requested);
    }

    relative_evidence_dir_path_boundary(requested)
}

fn best_absolute_evidence_dir_path_boundary(
    root: &Path,
    canonical_root: &Path,
    requested: &Path,
) -> EvidenceDirPathBoundary {
    let supplied_root_boundary = absolute_evidence_dir_path_boundary(root, requested);
    let canonical_root_boundary = absolute_evidence_dir_path_boundary(canonical_root, requested);

    [supplied_root_boundary, canonical_root_boundary]
        .into_iter()
        .min_by_key(|boundary| match boundary {
            EvidenceDirPathBoundary::InsideRoot => 0,
            EvidenceDirPathBoundary::InsideRootWithParentTraversal => 1,
            EvidenceDirPathBoundary::OutsideRoot => 2,
        })
        .expect("fixed path boundary candidates")
}

fn relative_evidence_dir_path_boundary(requested: &Path) -> EvidenceDirPathBoundary {
    let mut depth = 0usize;
    let mut has_parent_traversal = false;

    for component in requested.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                has_parent_traversal = true;
                if depth == 0 {
                    return EvidenceDirPathBoundary::OutsideRoot;
                }
                depth -= 1;
            }
            Component::Prefix(_) | Component::RootDir => {
                return EvidenceDirPathBoundary::OutsideRoot;
            }
        }
    }

    if has_parent_traversal {
        EvidenceDirPathBoundary::InsideRootWithParentTraversal
    } else {
        EvidenceDirPathBoundary::InsideRoot
    }
}

fn absolute_evidence_dir_path_boundary(root: &Path, requested: &Path) -> EvidenceDirPathBoundary {
    let Some((root_key, _)) = lexical_absolute_path_key(root) else {
        return EvidenceDirPathBoundary::OutsideRoot;
    };
    let Some((requested_key, has_parent_traversal)) = lexical_absolute_path_key(requested) else {
        return EvidenceDirPathBoundary::OutsideRoot;
    };

    if root_key.len() > requested_key.len()
        || !root_key
            .iter()
            .zip(requested_key.iter())
            .all(|(root_component, requested_component)| root_component == requested_component)
    {
        return EvidenceDirPathBoundary::OutsideRoot;
    }

    if has_parent_traversal {
        EvidenceDirPathBoundary::InsideRootWithParentTraversal
    } else {
        EvidenceDirPathBoundary::InsideRoot
    }
}

#[cfg(not(windows))]
type PathBoundaryKey = std::ffi::OsString;

#[cfg(windows)]
type PathBoundaryKey = String;

fn lexical_absolute_path_key(path: &Path) -> Option<(Vec<PathBoundaryKey>, bool)> {
    if !path.is_absolute() {
        return None;
    }

    let mut key = Vec::new();
    let anchor_len = push_absolute_anchor_key(path, &mut key)?;
    let mut has_parent_traversal = false;

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => key.push(path_component_key(component)),
            Component::ParentDir => {
                has_parent_traversal = true;
                if key.len() > anchor_len {
                    key.pop();
                }
            }
        }
    }

    Some((key, has_parent_traversal))
}

#[cfg(not(windows))]
fn push_absolute_anchor_key(path: &Path, _key: &mut Vec<PathBoundaryKey>) -> Option<usize> {
    path.is_absolute().then_some(0)
}

#[cfg(windows)]
fn push_absolute_anchor_key(path: &Path, key: &mut Vec<PathBoundaryKey>) -> Option<usize> {
    let Component::Prefix(prefix) = path.components().next()? else {
        return None;
    };
    key.push(windows_prefix_key(prefix));
    Some(key.len())
}

#[cfg(not(windows))]
fn path_component_key(value: &std::ffi::OsStr) -> PathBoundaryKey {
    value.to_os_string()
}

#[cfg(windows)]
fn path_component_key(value: &std::ffi::OsStr) -> PathBoundaryKey {
    windows_os_str_key(value)
}

#[cfg(windows)]
fn windows_prefix_key(prefix: PrefixComponent<'_>) -> String {
    match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
            format!("disk:{}", char::from(drive).to_ascii_lowercase())
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
            "unc:{}:{}",
            windows_os_str_key(server),
            windows_os_str_key(share)
        ),
        _ => format!("other:{}", windows_os_str_key(prefix.as_os_str())),
    }
}

#[cfg(windows)]
fn windows_os_str_key(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().to_lowercase()
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
        schema_version: MCP_EVIDENCE_RESULT_SCHEMA_VERSION,
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
        release_gate: step.release_gate.to_owned(),
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
        schema_version: MCP_EVIDENCE_RESULT_SCHEMA_VERSION,
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
        release_gate: artifact.release_gate.to_owned(),
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
    let next_actions = report
        .artifacts
        .iter()
        .filter(|artifact| stable_artifact_status(artifact.status) != "passed")
        .map(mcp_next_action)
        .collect::<Vec<_>>();

    McpEvidenceSummary {
        schema_version: MCP_EVIDENCE_RESULT_SCHEMA_VERSION,
        status: stable_report_status(report.status).to_owned(),
        generated_at: rfc3339(report.generated_at),
        max_age_days: report.max_age_days,
        artifact_count: report.artifacts.len(),
        passed_artifact_count,
        missing_artifact_count,
        failed_artifact_count,
        failure_count: report.failures.len(),
        failure_codes: failure_code_counts(report.failure_codes.iter().copied()),
        artifacts,
        next_actions,
    }
}

fn mcp_artifact_summary(artifact: &ReleaseEvidenceArtifactReport) -> McpEvidenceArtifactSummary {
    McpEvidenceArtifactSummary {
        name: artifact.name.to_owned(),
        file_name: artifact.file_name.to_owned(),
        release_gate: artifact.release_gate.to_owned(),
        command: artifact.command.to_owned(),
        status: stable_artifact_status(artifact.status).to_owned(),
        check_count: artifact.checks.len(),
        failure_count: artifact.failures.len(),
        failure_codes: failure_code_counts(artifact.failure_codes.iter().copied()),
    }
}

fn mcp_next_action(artifact: &ReleaseEvidenceArtifactReport) -> McpEvidenceNextAction {
    McpEvidenceNextAction {
        name: artifact.name.to_owned(),
        file_name: artifact.file_name.to_owned(),
        release_gate: artifact.release_gate.to_owned(),
        status: stable_artifact_status(artifact.status).to_owned(),
        command: artifact.command.to_owned(),
        failure_codes: failure_code_counts(artifact.failure_codes.iter().copied()),
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

fn failure_code_counts(
    failure_codes: impl IntoIterator<Item = ReleaseEvidenceFailureCode>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();

    for failure_code in failure_codes {
        let code = failure_code.as_str().to_owned();
        *counts.entry(code).or_insert(0) += 1;
    }

    counts
}

fn dominant_failure_code(failure_codes: &BTreeMap<String, usize>) -> &'static str {
    const PRIORITY: &[&str] = &[
        "missing_evidence",
        "stale_or_invalid_scaffold",
        "artifact_path_failure",
        "invalid_json",
        "invalid_json_root",
        "stale_or_invalid_timestamp",
        "timestamp_contract",
        "forbidden_field",
        "contract_mismatch",
        "validation_failed",
    ];

    PRIORITY
        .iter()
        .copied()
        .find(|code| failure_codes.contains_key(*code))
        .unwrap_or("validation_failed")
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
        assert_output_schema_contract(
            CairnIdMcpServer::evidence_plan_tool_attr().output_schema,
            "cairnid.evidence_plan",
            "steps",
            false,
        );
        assert_output_schema_contract(
            CairnIdMcpServer::evidence_manifest_tool_attr().output_schema,
            "cairnid.evidence_manifest",
            "artifacts",
            false,
        );
        assert_output_schema_contract(
            CairnIdMcpServer::evidence_status_tool_attr().output_schema,
            "cairnid.evidence_status",
            "artifacts",
            false,
        );
        assert_output_schema_contract(
            CairnIdMcpServer::evidence_check_tool_attr().output_schema,
            "cairnid.evidence_check",
            "artifacts",
            true,
        );
    }

    #[test]
    fn evidence_plan_input_schema_is_closed_empty() {
        assert_closed_empty_input_schema(
            CairnIdMcpServer::evidence_plan_tool_attr()
                .input_schema
                .as_ref(),
        );
    }

    #[test]
    fn evidence_manifest_input_schema_is_closed_empty() {
        assert_closed_empty_input_schema(
            CairnIdMcpServer::evidence_manifest_tool_attr()
                .input_schema
                .as_ref(),
        );
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
        assert!(check_description.contains("Strict final-gate"));
        assert!(check_description.contains("structured failure-code error"));
    }

    #[test]
    fn server_info_uses_binary_name() {
        let info = CairnIdMcpServer::new(StartupEvidenceRoot {
            supplied: PathBuf::from("."),
            canonical: PathBuf::from("."),
        })
        .get_info();

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

        let outside_escape = resolve_evidence_dir_in_root(&root, Some("../release-evidence"))
            .expect_err("parent traversal escaping root");
        assert_eq!(outside_escape.code, "outside_allowlisted_root");
        let inside_traversal =
            resolve_evidence_dir_in_root(&root, Some("release-evidence/../other"))
                .expect_err("parent traversal within root");
        assert_eq!(inside_traversal.code, "parent_traversal");

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
        let check = match evidence_check_for_root(&root, request) {
            Ok(_) => panic!("MCP check should fail when evidence is incomplete"),
            Err(error) => error,
        };
        let status_json = serde_json::to_string(&status.0).expect("serialize status response");
        let check_json = serde_json::to_string(&check).expect("serialize check response");

        assert_eq!(status.0.schema_version, MCP_EVIDENCE_RESULT_SCHEMA_VERSION);
        assert!(!status_json.contains(SENTINEL));
        assert!(!check_json.contains(SENTINEL));
        assert!(status_json.contains("contract_mismatch"));
        assert!(check_json.contains("contract_mismatch"));
        assert!(status_json.contains("next_actions"));
        assert!(check_json.contains("next_actions"));
        assert!(!status_json.contains("failures"));
        assert!(!check_json.contains("failures"));

        remove_temp_root(root);
    }

    #[test]
    fn mcp_summary_uses_operation_failure_codes_not_failure_text() {
        let report = ReleaseEvidenceReport {
            schema_version: "test",
            status: "incomplete",
            evidence_dir: "release-evidence".to_owned(),
            generated_at: OffsetDateTime::now_utc(),
            max_age_days: DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
            artifacts: vec![ReleaseEvidenceArtifactReport {
                name: "dependency_policy_check",
                file_name: "dependency-policy-check.json",
                release_gate: "Dependency policy",
                status: "failed",
                command: "capture dependency policy",
                modified_at: None,
                checks: Vec::new(),
                failures: vec![
                    "wording changed; this text no longer includes any classifier phrase"
                        .to_owned(),
                ],
                failure_codes: vec![ReleaseEvidenceFailureCode::ContractMismatch],
            }],
            failures: vec![
                "top-level wording changed; stable code must still come from the operation report"
                    .to_owned(),
            ],
            failure_codes: vec![ReleaseEvidenceFailureCode::MissingEvidence],
        };

        let summary = mcp_evidence_summary(&report);

        assert_eq!(
            summary.failure_codes.get("missing_evidence").copied(),
            Some(1)
        );
        assert_eq!(
            summary.artifacts[0]
                .failure_codes
                .get("contract_mismatch")
                .copied(),
            Some(1)
        );
        assert_eq!(
            summary.next_actions[0]
                .failure_codes
                .get("contract_mismatch")
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn request_errors_expose_stable_failure_code_categories() {
        assert_eq!(
            McpEvidenceRequestError::MISSING_EVIDENCE_DIR.failure_code,
            "missing_evidence"
        );
        assert_eq!(
            McpEvidenceRequestError::SYMLINK_ENTRY.failure_code,
            "artifact_path_failure"
        );
        assert_eq!(
            McpEvidenceRequestError::ALLOWLIST_ROOT_UNAVAILABLE.failure_code,
            "internal_error"
        );
    }

    #[test]
    fn incomplete_check_error_includes_summary_and_failure_codes() {
        let root = temp_root("incomplete-check-error");
        let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
        init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
            .expect("initialize evidence directory");

        let request = EvidenceDirectoryRequest {
            evidence_dir: None,
            max_age_days: Some(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS),
        };
        let result = match evidence_check_for_root(&root, request) {
            Ok(_) => panic!("MCP check should fail when evidence is incomplete"),
            Err(error) => error,
        };
        let structured = result.structured_content.expect("structured error content");
        assert_eq!(
            structured.get("schema_version").and_then(Value::as_str),
            Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
        );
        let error = structured
            .get("error")
            .and_then(Value::as_object)
            .expect("error object");

        assert_eq!(
            error.get("code").and_then(Value::as_str),
            Some("release_evidence_incomplete")
        );
        assert_eq!(
            error.get("failure_code").and_then(Value::as_str),
            Some("missing_evidence")
        );
        assert!(
            error
                .get("failure_codes")
                .and_then(Value::as_object)
                .and_then(|codes| codes.get("missing_evidence"))
                .and_then(Value::as_u64)
                .expect("missing evidence failure count")
                > 0
        );
        assert_eq!(
            error
                .get("summary")
                .and_then(|summary| summary.get("schema_version"))
                .and_then(Value::as_str),
            Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
        );
        assert_eq!(
            error
                .get("summary")
                .and_then(|summary| summary.get("status"))
                .and_then(Value::as_str),
            Some("incomplete")
        );
        let next_actions = error
            .get("summary")
            .and_then(|summary| summary.get("next_actions"))
            .and_then(Value::as_array)
            .expect("incomplete summary next actions");
        assert!(!next_actions.is_empty());
        assert!(
            next_actions.iter().any(|action| {
                action.get("file_name").and_then(Value::as_str) == Some("operations-preflight.json")
                    && action
                        .get("failure_codes")
                        .and_then(Value::as_object)
                        .and_then(|codes| codes.get("missing_evidence"))
                        .and_then(Value::as_u64)
                        .is_some_and(|count| count > 0)
            }),
            "incomplete check should include sanitized next action failure codes"
        );

        remove_temp_root(root);
    }

    fn assert_output_schema_contract(
        output_schema: Option<std::sync::Arc<rmcp::model::JsonObject>>,
        tool_name: &str,
        success_collection: &str,
        expect_error_summary: bool,
    ) {
        let schema = output_schema.expect("output schema");
        let schema = Value::Object(schema.as_ref().clone());

        assert_eq!(
            schema.get("type"),
            Some(&serde_json::Value::String("object".to_owned()))
        );
        let variants = schema
            .get("oneOf")
            .and_then(Value::as_array)
            .expect("output schema oneOf variants");
        assert_eq!(variants.len(), 2);
        let success_schema = success_output_schema(tool_name, variants);
        assert_schema_pins_schema_version_const(
            success_schema,
            &format!("{tool_name} success outputSchema"),
        );
        let error_schema = error_output_schema(tool_name, variants);
        assert_schema_pins_schema_version_const(
            error_schema,
            &format!("{tool_name} error outputSchema"),
        );

        assert_schema_array_items_require_release_gate(
            &schema,
            success_schema,
            success_collection,
            &format!("{tool_name} success {success_collection}"),
        );
        if matches!(
            tool_name,
            "cairnid.evidence_status" | "cairnid.evidence_check"
        ) {
            assert_summary_next_actions_contract(
                &schema,
                success_schema,
                &format!("{tool_name} success summary"),
            );
        }

        if expect_error_summary {
            assert_error_summary_contract(tool_name, &schema, error_schema);
        }
    }

    fn success_output_schema<'a>(tool_name: &str, variants: &'a [Value]) -> &'a Value {
        variants
            .iter()
            .find(|schema| !schema_has_error_property(schema))
            .unwrap_or_else(|| panic!("{tool_name} outputSchema success variant"))
    }

    fn error_output_schema<'a>(tool_name: &str, variants: &'a [Value]) -> &'a Value {
        variants
            .iter()
            .find(|schema| schema_has_error_property(schema))
            .unwrap_or_else(|| panic!("{tool_name} outputSchema error variant"))
    }

    fn assert_error_summary_contract(tool_name: &str, root: &Value, error_schema: &Value) {
        let error_body = schema_property(
            root,
            error_schema,
            "error",
            &format!("{tool_name} error envelope"),
        );
        let summary = schema_property(
            root,
            error_body,
            "summary",
            &format!("{tool_name} incomplete-check error body"),
        );
        let summary = resolve_schema(root, summary);
        assert_schema_pins_schema_version_const(
            summary,
            &format!("{tool_name} incomplete-check error summary"),
        );
        assert_schema_array_items_require_release_gate(
            root,
            summary,
            "artifacts",
            &format!("{tool_name} incomplete-check error summary"),
        );
        assert_summary_next_actions_contract(
            root,
            summary,
            &format!("{tool_name} incomplete-check error summary"),
        );
    }

    fn assert_summary_next_actions_contract(root: &Value, schema: &Value, context: &str) {
        assert_schema_array_items_require_release_gate(
            root,
            schema,
            "next_actions",
            &format!("{context} next_actions"),
        );
        assert_schema_array_items_require_properties(
            root,
            schema,
            "next_actions",
            &[
                "name",
                "file_name",
                "release_gate",
                "status",
                "command",
                "failure_codes",
            ],
            &format!("{context} next_actions"),
        );
    }

    fn assert_schema_array_items_require_properties(
        root: &Value,
        schema: &Value,
        array_property: &str,
        required_properties: &[&str],
        context: &str,
    ) {
        let array_schema = schema_property(root, schema, array_property, context);
        let item_schema = array_schema
            .get("items")
            .unwrap_or_else(|| panic!("{context} should advertise array items"));
        let item_schema = resolve_schema(root, item_schema);
        let properties = item_schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{context} item schema properties"));

        for property in required_properties {
            assert!(
                properties.contains_key(*property),
                "{context} item schema should advertise {property}"
            );
            assert!(
                schema_requires_property(item_schema, property),
                "{context} item schema should require {property}"
            );
        }
    }

    fn assert_schema_array_items_require_release_gate(
        root: &Value,
        schema: &Value,
        array_property: &str,
        context: &str,
    ) {
        let array_schema = schema_property(root, schema, array_property, context);
        let item_schema = array_schema
            .get("items")
            .unwrap_or_else(|| panic!("{context} should advertise array items"));
        let item_schema = resolve_schema(root, item_schema);
        let properties = item_schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{context} item schema properties"));

        assert!(
            properties.contains_key("release_gate"),
            "{context} item schema should advertise release_gate"
        );
        assert!(
            schema_requires_property(item_schema, "release_gate"),
            "{context} item schema should require release_gate"
        );
    }

    fn schema_property<'a>(
        root: &'a Value,
        schema: &'a Value,
        property: &str,
        context: &str,
    ) -> &'a Value {
        let resolved = resolve_schema(root, schema);
        resolved
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(property))
            .unwrap_or_else(|| panic!("{context} should advertise {property}"))
    }

    fn resolve_schema<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
        let mut current = schema;

        loop {
            if let Some(reference) = current.get("$ref").and_then(Value::as_str) {
                let pointer = reference
                    .strip_prefix('#')
                    .unwrap_or_else(|| panic!("schema reference should be local: {reference}"));
                current = root
                    .pointer(pointer)
                    .unwrap_or_else(|| panic!("schema reference target should exist: {reference}"));
                continue;
            }

            if let Some(non_null) =
                current
                    .get("anyOf")
                    .and_then(Value::as_array)
                    .and_then(|variants| {
                        variants.iter().find(|variant| {
                            variant.get("type").and_then(Value::as_str) != Some("null")
                        })
                    })
            {
                current = non_null;
                continue;
            }

            return current;
        }
    }

    fn schema_requires_property(schema: &Value, property: &str) -> bool {
        schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| {
                required
                    .iter()
                    .any(|field| field.as_str() == Some(property))
            })
    }

    fn assert_schema_pins_schema_version_const(schema: &Value, context: &str) {
        assert!(
            schema_requires_property(schema, "schema_version"),
            "{context} should require schema_version"
        );

        let schema_version = schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("schema_version"))
            .unwrap_or_else(|| panic!("{context} should advertise schema_version"));
        assert_eq!(
            schema_version.get("const").and_then(Value::as_str),
            Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION),
            "{context} should pin schema_version const"
        );
    }

    fn schema_has_error_property(schema: &Value) -> bool {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("error"))
    }

    fn assert_closed_empty_input_schema(input_schema: &rmcp::model::JsonObject) {
        let schema = Value::Object(input_schema.clone());
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("input schema properties");

        assert_eq!(schema.get("type"), Some(&json!("object")));
        assert!(properties.is_empty());
        assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));

        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(required.is_empty());
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
