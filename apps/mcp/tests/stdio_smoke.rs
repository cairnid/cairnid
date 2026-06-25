use cairn_operations::init_release_evidence_directory;
use jsonschema::{Draft, Validator};
use rmcp::{
    ServiceExt,
    model::{
        CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
        JsonObject, ProtocolVersion, Tool,
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::OffsetDateTime;

const DEFAULT_EVIDENCE_CHILD: &str = "release-evidence";
const MCP_EVIDENCE_RESULT_SCHEMA_VERSION: &str = "cairnid.mcp.evidence.v1";
const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const SENTINEL: &str = "CAIRNID_MCP_STDIO_SMOKE_DO_NOT_EXPOSE";
const UPDATE_CONTRACT_FIXTURES_ENV: &str = "CAIRNID_UPDATE_MCP_FIXTURES";
const CONTRACT_GENERATED_AT: &str = "<generated_at>";
const EVIDENCE_SUMMARY_KEYS: &[&str] = &[
    "schema_version",
    "status",
    "generated_at",
    "max_age_days",
    "artifact_count",
    "passed_artifact_count",
    "missing_artifact_count",
    "failed_artifact_count",
    "failure_count",
    "failure_codes",
    "artifacts",
    "next_actions",
];
const ARTIFACT_SUMMARY_KEYS: &[&str] = &[
    "name",
    "file_name",
    "release_gate",
    "command",
    "status",
    "check_count",
    "failure_count",
    "failure_codes",
];
const NEXT_ACTION_KEYS: &[&str] = &[
    "name",
    "file_name",
    "release_gate",
    "status",
    "command",
    "failure_codes",
];
const REQUIRED_OIDC_METADATA_SMOKE_CHECKS: &[&str] = &[
    "issuer_https_origin",
    "discovery_http_status",
    "discovery_issuer_matches",
    "discovery_endpoint_urls_match_issuer",
    "discovery_strict_code_flow",
    "discovery_refresh_and_client_credentials",
    "discovery_pkce_s256",
    "discovery_rs256",
    "discovery_request_objects_disabled",
    "discovery_rfc9207_iss_supported",
    "jwks_http_status",
    "jwks_rs256_public_key_material",
    "jwks_no_private_key_material",
];
const REQUIRED_SCIM_SMOKE_CHECKS: &[&str] = &[
    "secondary_token",
    "rejected_token",
    "service_provider_config",
    "schemas",
    "resource_types",
    "user_create",
    "user_filter",
    "user_search_request",
    "user_projection",
    "user_patch",
    "user_replace",
    "group_create",
    "group_filter",
    "group_search_request",
    "group_projection",
    "group_patch",
    "group_replace",
    "group_delete",
    "bulk_mutations",
    "user_delete",
    "user_soft_delete",
];
const REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS: &[&str] = &[
    "connector_enabled",
    "service_provider_config",
    "user_create",
    "user_exact_filter",
    "user_search_request",
    "user_projection",
    "user_patch",
    "user_replace",
    "group_create",
    "group_exact_filter",
    "group_search_request",
    "group_projection",
    "group_patch_members",
    "group_replace",
    "user_deactivation",
    "group_delete",
    "token_rotation_acceptance",
    "retired_token_rejection",
];

#[test]
fn binary_help_exits_before_stdio_jsonrpc() {
    let output = run_cairnid_mcp(["--help"]);

    assert!(output.status.success(), "help failed: {output:?}");
    let stdout = output_stdout(&output);
    assert!(stdout.contains("cairnid-mcp"), "{stdout}");
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("--evidence-root <DIR>"), "{stdout}");
    assert!(stdout.contains("--version"), "{stdout}");
    assert!(!stdout.contains("\"jsonrpc\""), "{stdout}");
    assert_eq!(output_stderr(&output), "");
}

#[test]
fn binary_version_exits_before_stdio_jsonrpc() {
    let output = run_cairnid_mcp(["--version"]);

    assert!(output.status.success(), "version failed: {output:?}");
    assert_eq!(
        output_stdout(&output).trim(),
        format!("cairnid-mcp {}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(output_stderr(&output), "");
}

#[test]
fn binary_invalid_evidence_roots_exit_before_stdio_jsonrpc_without_echoing_paths() {
    let root = temp_root("invalid-startup-root");
    let missing = root.join(format!("missing-{SENTINEL}"));
    let file = root.join(format!("file-{SENTINEL}.txt"));
    fs::write(&file, "not a directory").expect("write invalid evidence root file");

    for (invalid_root, expected_reason) in [
        (&missing, "could not be inspected"),
        (&file, "is not a directory"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
            .arg("--evidence-root")
            .arg(invalid_root)
            .stdin(Stdio::null())
            .output()
            .expect("run cairnid-mcp with invalid evidence root");

        assert!(
            !output.status.success(),
            "invalid root unexpectedly succeeded"
        );
        assert_eq!(output_stdout(&output), "");
        let stderr = output_stderr(&output);
        assert!(
            stderr.contains("cairnid-mcp failed: evidence root"),
            "{stderr}"
        );
        assert!(stderr.contains(expected_reason), "{stderr}");
        assert!(!stderr.contains("\"jsonrpc\""), "{stderr}");
        assert!(
            !stderr.contains(SENTINEL),
            "startup stderr exposed sentinel path component: {stderr}"
        );
        assert!(
            !stderr.contains(&invalid_root.display().to_string()),
            "startup stderr exposed invalid evidence root: {stderr}"
        );
    }

    remove_temp_root(root);
}

#[test]
fn stdio_smoke_lists_tools_and_returns_sanitized_evidence_status() {
    let root = temp_root("stdio-smoke");
    let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize evidence directory");
    write_unsafe_artifact_shape(&evidence_dir);

    let mut server = McpProcess::start(&root);

    let initialize = server.request(
        1,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "cairnid-mcp-stdio-smoke",
                    "version": "0.0.0"
                }
            }
        }),
    );
    assert_eq!(
        initialize["serverInfo"]["name"].as_str(),
        Some("cairnid-mcp")
    );
    assert_eq!(
        initialize["protocolVersion"].as_str(),
        Some(MCP_PROTOCOL_VERSION)
    );
    assert!(initialize["capabilities"]["tools"].is_object());

    server.notify(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    let tools = server.request(
        2,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    let tools_array = tools["tools"].as_array().expect("tools array");
    let output_schema_validators = output_schema_validators_from_json_tools(tools_array);
    let mut tool_names = tools_array
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    tool_names.sort_unstable();
    assert_eq!(
        tool_names,
        vec![
            "cairnid.evidence_check",
            "cairnid.evidence_manifest",
            "cairnid.evidence_plan",
            "cairnid.evidence_status",
        ]
    );
    assert_tools_list_output_schemas(tools_array);

    let status = server.request(
        3,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "cairnid.evidence_status",
                "arguments": {
                    "evidence_dir": DEFAULT_EVIDENCE_CHILD
                }
            }
        }),
    );

    assert_eq!(status["isError"].as_bool(), Some(false));
    let structured_value =
        assert_json_result_structured_content_matches_text(&status, "evidence_status");
    assert_structured_content_conforms_to_output_schema(
        &output_schema_validators,
        "cairnid.evidence_status",
        structured_value,
    );
    let structured = structured_value
        .as_object()
        .expect("structured evidence status");
    assert_allowed_keys(
        "structured evidence status",
        structured,
        EVIDENCE_SUMMARY_KEYS,
    );
    assert_eq!(
        structured.get("schema_version").and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    assert_eq!(
        structured.get("status").and_then(Value::as_str),
        Some("incomplete")
    );
    assert!(
        structured
            .get("failure_count")
            .and_then(Value::as_u64)
            .expect("failure_count")
            > 0
    );
    assert!(
        structured
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("forbidden_field"))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0),
        "status should expose stable forbidden_field evidence code: {structured:?}"
    );
    let artifacts = structured
        .get("artifacts")
        .and_then(Value::as_array)
        .expect("artifact summaries");
    assert!(!artifacts.is_empty(), "expected artifact summaries");
    for artifact in artifacts {
        assert_allowed_keys(
            "artifact summary",
            artifact.as_object().expect("artifact summary object"),
            ARTIFACT_SUMMARY_KEYS,
        );
        assert!(
            artifact
                .get("release_gate")
                .and_then(Value::as_str)
                .is_some_and(|release_gate| !release_gate.is_empty()),
            "artifact summary should expose sanitized release gate metadata: {artifact}"
        );
    }
    assert_release_gate(
        named_item(artifacts, "dependency_policy_check", "status artifact"),
        "Dependency policy",
        "status artifact",
    );
    let next_actions = structured
        .get("next_actions")
        .and_then(Value::as_array)
        .expect("next action summaries");
    assert!(!next_actions.is_empty(), "expected next action summaries");
    for action in next_actions {
        assert_allowed_keys(
            "next action summary",
            action.as_object().expect("next action object"),
            NEXT_ACTION_KEYS,
        );
        assert!(
            action
                .get("failure_codes")
                .and_then(Value::as_object)
                .is_some_and(|codes| !codes.is_empty()),
            "next action should expose sanitized failure codes: {action}"
        );
    }
    let dependency_policy_action = named_item(
        next_actions,
        "dependency_policy_check",
        "status next action",
    );
    assert_release_gate(
        dependency_policy_action,
        "Dependency policy",
        "status next action",
    );
    assert_eq!(
        dependency_policy_action
            .get("status")
            .and_then(Value::as_str),
        Some("failed")
    );
    assert!(
        dependency_policy_action
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("forbidden_field"))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0),
        "dependency policy next action should expose forbidden_field code: {dependency_policy_action}"
    );
    assert!(
        !status.to_string().contains(SENTINEL),
        "MCP response exposed raw artifact content: {status}"
    );
    server.assert_stderr_empty();

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_contract_matches_canonical_fixtures() {
    let root = temp_root("contract-fixtures");
    let incomplete_dir = root.join(DEFAULT_EVIDENCE_CHILD);
    init_release_evidence_directory(&incomplete_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize incomplete evidence directory");
    let ready_dir_name = "ready-evidence";
    let ready_dir = root.join(ready_dir_name);
    init_release_evidence_directory(&ready_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize ready evidence directory");
    write_complete_release_evidence(&ready_dir);

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let tools = server.request(
        2,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_contract_fixture(
        "tools-list-schemas.json",
        tools_list_schema_contract(&tools["tools"]),
    );

    let plan = call_evidence_plan(&mut server, 3, json!({}));
    assert_eq!(plan["isError"].as_bool(), Some(false));
    assert_contract_fixture("evidence-plan-success.json", canonical_mcp_result(plan));

    let manifest = call_evidence_manifest(&mut server, 4, json!({}));
    assert_eq!(manifest["isError"].as_bool(), Some(false));
    assert_contract_fixture(
        "evidence-manifest-success.json",
        canonical_mcp_result(manifest),
    );

    let status = call_evidence_status(
        &mut server,
        5,
        json!({
            "evidence_dir": DEFAULT_EVIDENCE_CHILD
        }),
    );
    assert_eq!(status["isError"].as_bool(), Some(false));
    assert_eq!(
        status["structuredContent"]["status"].as_str(),
        Some("incomplete")
    );
    assert_contract_fixture("evidence-status-success.json", canonical_mcp_result(status));

    let check = call_evidence_check(
        &mut server,
        6,
        json!({
            "evidence_dir": ready_dir_name
        }),
    );
    assert_eq!(
        check["isError"].as_bool(),
        Some(false),
        "ready evidence check should pass: {check}"
    );
    assert_eq!(check["structuredContent"]["status"].as_str(), Some("ready"));
    assert_contract_fixture("evidence-check-success.json", canonical_mcp_result(check));

    let request_error = call_evidence_status(
        &mut server,
        7,
        json!({
            "evidence_dir": ""
        }),
    );
    assert_tool_error_code(&request_error, "empty_evidence_dir");
    assert_contract_fixture(
        "request-error-empty-evidence-dir.json",
        canonical_mcp_result(request_error),
    );

    let incomplete_check = call_evidence_check(
        &mut server,
        8,
        json!({
            "evidence_dir": DEFAULT_EVIDENCE_CHILD
        }),
    );
    assert_tool_error_code(&incomplete_check, "release_evidence_incomplete");
    assert_contract_fixture(
        "incomplete-check-error.json",
        canonical_mcp_result(incomplete_check),
    );

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_ignores_inherited_logging_env_for_initialize_and_tools_list() {
    let root = temp_root("stdio-logging-env");
    let mut server = McpProcess::start_with_envs(
        &root,
        &[
            ("RUST_LOG", "trace,cairnid_mcp=trace,rmcp=trace"),
            ("RUST_LOG_STYLE", "always"),
            ("RUST_BACKTRACE", "full"),
            ("RUST_LIB_BACKTRACE", "full"),
        ],
    );

    let initialize = server.request(
        1,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "cairnid-mcp-stdio-logging-env-smoke",
                    "version": "0.0.0"
                }
            }
        }),
    );
    assert_eq!(
        initialize["serverInfo"]["name"].as_str(),
        Some("cairnid-mcp")
    );
    assert_eq!(
        initialize["protocolVersion"].as_str(),
        Some(MCP_PROTOCOL_VERSION)
    );

    server.notify(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    let tools = server.request(
        2,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert!(tools["tools"].is_array(), "tools/list response: {tools}");
    server.assert_stderr_empty();

    drop(server);
    remove_temp_root(root);
}

#[tokio::test]
async fn rmcp_real_client_stdio_smoke_lists_tools_and_calls_evidence_tools() {
    let root = temp_root("rmcp-client-smoke");
    let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize evidence directory");
    write_unsafe_artifact_shape(&evidence_dir);

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
        .arg("--evidence-root")
        .arg(&root)
        .env("RUST_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cairnid-mcp for rmcp client smoke");
    let stdout = child.stdout.take().expect("child stdout");
    let stdin = child.stdin.take().expect("child stdin");
    let client = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("cairnid-mcp-rmcp-stdio-smoke", "0.0.0"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_11_25)
    .serve((stdout, stdin))
    .await
    .expect("initialize rmcp client");
    let server_info = client.peer_info().expect("server info after initialize");
    assert_eq!(server_info.protocol_version, ProtocolVersion::V_2025_11_25);
    assert_eq!(server_info.server_info.name, "cairnid-mcp");

    let tools = client
        .list_all_tools()
        .await
        .expect("list tools through rmcp client");
    let output_schema_validators = output_schema_validators_from_rmcp_tools(&tools);
    let mut tool_names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>();
    tool_names.sort_unstable();
    assert_eq!(
        tool_names,
        vec![
            "cairnid.evidence_check",
            "cairnid.evidence_manifest",
            "cairnid.evidence_plan",
            "cairnid.evidence_status",
        ]
    );

    let plan = client
        .call_tool(
            CallToolRequestParams::new("cairnid.evidence_plan").with_arguments(JsonObject::new()),
        )
        .await
        .expect("call evidence_plan through rmcp client");
    assert_eq!(plan.is_error, Some(false));
    let plan_structured = assert_structured_content_matches_text(&plan, "evidence_plan");
    assert_structured_content_conforms_to_output_schema(
        &output_schema_validators,
        "cairnid.evidence_plan",
        plan_structured,
    );
    assert_eq!(
        plan_structured
            .get("schema_version")
            .and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    assert!(
        plan_structured
            .get("steps")
            .and_then(Value::as_array)
            .is_some_and(|steps| !steps.is_empty()),
        "evidence_plan should include sanitized plan steps"
    );
    let plan_steps = plan_structured
        .get("steps")
        .and_then(Value::as_array)
        .expect("evidence_plan steps");
    assert_release_gate(
        named_item(plan_steps, "dependency_policy_check", "plan step"),
        "Dependency policy",
        "plan step",
    );
    assert_no_sentinel(&plan, "evidence_plan");

    let manifest = client
        .call_tool(
            CallToolRequestParams::new("cairnid.evidence_manifest")
                .with_arguments(JsonObject::new()),
        )
        .await
        .expect("call evidence_manifest through rmcp client");
    assert_eq!(manifest.is_error, Some(false));
    let manifest_structured =
        assert_structured_content_matches_text(&manifest, "evidence_manifest");
    assert_structured_content_conforms_to_output_schema(
        &output_schema_validators,
        "cairnid.evidence_manifest",
        manifest_structured,
    );
    assert_eq!(
        manifest_structured
            .get("schema_version")
            .and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    let manifest_artifacts = manifest_structured
        .get("artifacts")
        .and_then(Value::as_array)
        .expect("evidence_manifest artifacts");
    assert_release_gate(
        named_item(
            manifest_artifacts,
            "dependency_policy_check",
            "manifest artifact",
        ),
        "Dependency policy",
        "manifest artifact",
    );
    assert_no_sentinel(&manifest, "evidence_manifest");

    let status = client
        .call_tool(
            CallToolRequestParams::new("cairnid.evidence_status")
                .with_arguments(json_object(json!({"evidence_dir": DEFAULT_EVIDENCE_CHILD}))),
        )
        .await
        .expect("call evidence_status through rmcp client");
    assert_eq!(status.is_error, Some(false));
    let status_structured = assert_structured_content_matches_text(&status, "evidence_status");
    assert_structured_content_conforms_to_output_schema(
        &output_schema_validators,
        "cairnid.evidence_status",
        status_structured,
    );
    assert_eq!(
        status_structured
            .get("schema_version")
            .and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    assert_eq!(
        status_structured.get("status").and_then(Value::as_str),
        Some("incomplete")
    );
    let status_artifacts = status_structured
        .get("artifacts")
        .and_then(Value::as_array)
        .expect("evidence_status artifacts");
    assert_release_gate(
        named_item(
            status_artifacts,
            "dependency_policy_check",
            "status artifact",
        ),
        "Dependency policy",
        "status artifact",
    );
    let status_next_actions = status_structured
        .get("next_actions")
        .and_then(Value::as_array)
        .expect("evidence_status next actions");
    assert_release_gate(
        named_item(
            status_next_actions,
            "dependency_policy_check",
            "status next action",
        ),
        "Dependency policy",
        "status next action",
    );
    assert_no_sentinel(&status, "evidence_status");

    let check = client
        .call_tool(
            CallToolRequestParams::new("cairnid.evidence_check")
                .with_arguments(json_object(json!({"evidence_dir": DEFAULT_EVIDENCE_CHILD}))),
        )
        .await
        .expect("call evidence_check through rmcp client");
    assert_eq!(check.is_error, Some(true));
    let check_structured = assert_structured_content_matches_text(&check, "evidence_check");
    assert_structured_content_conforms_to_output_schema(
        &output_schema_validators,
        "cairnid.evidence_check",
        check_structured,
    );
    assert_eq!(
        check_structured
            .get("schema_version")
            .and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    assert_eq!(
        check_structured
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("release_evidence_incomplete")
    );
    let check_artifacts = check_structured
        .get("error")
        .and_then(|error| error.get("summary"))
        .and_then(|summary| summary.get("artifacts"))
        .and_then(Value::as_array)
        .expect("evidence_check summary artifacts");
    assert_release_gate(
        named_item(check_artifacts, "dependency_policy_check", "check artifact"),
        "Dependency policy",
        "check artifact",
    );
    let check_next_actions = check_structured
        .get("error")
        .and_then(|error| error.get("summary"))
        .and_then(|summary| summary.get("next_actions"))
        .and_then(Value::as_array)
        .expect("evidence_check summary next actions");
    assert_release_gate(
        named_item(
            check_next_actions,
            "dependency_policy_check",
            "check next action",
        ),
        "Dependency policy",
        "check next action",
    );
    assert_no_sentinel(&check, "evidence_check");

    client.cancel().await.expect("cancel rmcp client");
    let exit_status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("cairnid-mcp should exit after client cancellation")
        .expect("wait for cairnid-mcp");
    assert!(
        exit_status.success(),
        "cairnid-mcp exited with {exit_status}"
    );
    remove_temp_root(root);
}

#[test]
fn stdio_explicit_evidence_root_is_independent_of_launch_cwd() {
    let evidence_root = temp_root("stdio-explicit-root");
    let launch_cwd = temp_root("stdio-explicit-cwd");
    let evidence_dir = evidence_root.join(DEFAULT_EVIDENCE_CHILD);
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize evidence directory");

    let mut server = McpProcess::start_with_args(
        &launch_cwd,
        vec![
            OsString::from("--evidence-root"),
            evidence_root.clone().into_os_string(),
        ],
    );
    initialize_mcp(&mut server);

    let status = call_evidence_status(&mut server, 2, json!({}));
    assert_eq!(status["isError"].as_bool(), Some(false));
    assert_eq!(
        status["structuredContent"]["status"].as_str(),
        Some("incomplete")
    );

    let outside_dir = launch_cwd.join(DEFAULT_EVIDENCE_CHILD);
    fs::create_dir_all(&outside_dir).expect("create outside evidence dir");
    let outside_status = call_evidence_status(
        &mut server,
        3,
        json!({
            "evidence_dir": outside_dir.to_string_lossy().to_string()
        }),
    );
    assert_tool_error_code(&outside_status, "outside_allowlisted_root");

    drop(server);
    remove_temp_root(launch_cwd);
    remove_temp_root(evidence_root);
}

#[test]
fn stdio_relative_evidence_dir_inside_root_is_accepted() {
    let root = temp_root("stdio-relative-inside-root");
    let evidence_dir = root.join("relative-inside-evidence");
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize relative evidence directory");

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let status = call_evidence_status(
        &mut server,
        2,
        json!({
            "evidence_dir": "relative-inside-evidence"
        }),
    );
    assert_eq!(status["isError"].as_bool(), Some(false));
    assert_eq!(
        status["structuredContent"]["status"].as_str(),
        Some("incomplete")
    );

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_absolute_evidence_dir_inside_root_is_accepted() {
    let root = temp_root("stdio-absolute-inside-root");
    let evidence_dir = root.join("absolute-inside-evidence");
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize absolute evidence directory");

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let status = call_evidence_status(
        &mut server,
        2,
        json!({
            "evidence_dir": evidence_dir.to_string_lossy().to_string()
        }),
    );
    assert_eq!(status["isError"].as_bool(), Some(false));
    assert_eq!(
        status["structuredContent"]["status"].as_str(),
        Some("incomplete")
    );

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_absolute_outside_evidence_dirs_do_not_leak_filesystem_state() {
    let root = temp_root("stdio-absolute-outside-root");
    let outside_root = temp_root("stdio-absolute-outside");
    let outside_missing = outside_root.join(format!("missing-{SENTINEL}"));
    let outside_file = outside_root.join(format!("file-{SENTINEL}.txt"));
    let outside_dir = outside_root.join(format!("dir-{SENTINEL}"));
    fs::write(&outside_file, "outside file").expect("write outside file");
    fs::create_dir_all(&outside_dir).expect("create outside directory");

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    for (request_id, path) in (2..).zip([&outside_missing, &outside_file, &outside_dir]) {
        let result = call_evidence_status(
            &mut server,
            request_id,
            json!({
                "evidence_dir": path.to_string_lossy().to_string()
            }),
        );
        assert_tool_error_code(&result, "outside_allowlisted_root");
        assert!(
            !result.to_string().contains(SENTINEL),
            "outside evidence path state leaked sentinel: {result}"
        );
    }

    drop(server);
    remove_temp_root(outside_root);
    remove_temp_root(root);
}

#[test]
fn stdio_absolute_parent_escape_evidence_dirs_do_not_leak_filesystem_state() {
    let root = temp_root("stdio-absolute-parent-escape-root");
    let outside_root = temp_root("stdio-absolute-parent-escape-outside");
    let outside_missing = outside_root.join(format!("missing-{SENTINEL}"));
    let outside_file = outside_root.join(format!("file-{SENTINEL}.txt"));
    let outside_dir = outside_root.join(format!("dir-{SENTINEL}"));
    fs::write(&outside_file, "outside file").expect("write outside file");
    fs::create_dir_all(&outside_dir).expect("create outside directory");

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    for (request_id, outside_path) in (2..).zip([&outside_missing, &outside_file, &outside_dir]) {
        let escaped_path = absolute_escape_through_root(&root, outside_path);
        let result = call_evidence_status(
            &mut server,
            request_id,
            json!({
                "evidence_dir": escaped_path.to_string_lossy().to_string()
            }),
        );
        assert_tool_error_code(&result, "outside_allowlisted_root");
        assert!(
            !result.to_string().contains(SENTINEL),
            "absolute parent escape leaked outside path state: {result}"
        );
    }

    drop(server);
    remove_temp_root(outside_root);
    remove_temp_root(root);
}

#[test]
fn stdio_relative_parent_escape_does_not_leak_filesystem_state() {
    let root = temp_root("stdio-relative-parent-escape-root");
    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let result = call_evidence_status(
        &mut server,
        2,
        json!({
            "evidence_dir": format!("../{SENTINEL}")
        }),
    );
    assert_tool_error_code(&result, "outside_allowlisted_root");
    assert!(
        !result.to_string().contains(SENTINEL),
        "relative parent escape leaked outside path state: {result}"
    );

    drop(server);
    remove_temp_root(root);
}

#[cfg(windows)]
#[test]
fn stdio_unc_absolute_evidence_dir_outside_root_is_rejected_as_outside_root() {
    let root = temp_root("stdio-unc-outside-root");
    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let result = call_evidence_status(
        &mut server,
        2,
        json!({
            "evidence_dir": format!(r"\\{SENTINEL}\share\release-evidence")
        }),
    );
    assert_tool_error_code(&result, "outside_allowlisted_root");
    assert!(
        !result.to_string().contains(SENTINEL),
        "UNC evidence path leaked sentinel: {result}"
    );

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_evidence_status_returns_stable_tool_error_envelopes() {
    let root = temp_root("stdio-errors");
    let default_evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
    fs::create_dir_all(&default_evidence_dir).expect("create default evidence dir");
    fs::write(root.join("not-directory"), "not a directory").expect("write non-directory");
    let outside = temp_root("stdio-outside");
    let symlink_entry_evidence_dir = root.join("symlink-entry-evidence");
    fs::create_dir_all(&symlink_entry_evidence_dir).expect("create symlink evidence dir");
    let symlink_target = root.join("symlink-target.json");
    let symlink_link = symlink_entry_evidence_dir.join("operations-preflight.json");
    fs::write(&symlink_target, "{}").expect("write symlink target");
    let symlink_entry_supported = match create_file_symlink(&symlink_target, &symlink_link) {
        Ok(()) => true,
        Err(error) if symlink_unavailable(&error) => false,
        Err(error) => panic!("create file symlink: {error}"),
    };

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let mut cases = vec![
        (json!({"evidence_dir": 123}), "invalid_evidence_dir"),
        (json!({"evidence_dir": ""}), "empty_evidence_dir"),
        (
            json!({"evidence_dir": "../release-evidence"}),
            "outside_allowlisted_root",
        ),
        (
            json!({"evidence_dir": outside.to_string_lossy().to_string()}),
            "outside_allowlisted_root",
        ),
        (
            json!({"evidence_dir": "missing-evidence"}),
            "missing_evidence_dir",
        ),
        (
            json!({"evidence_dir": "not-directory"}),
            "non_directory_evidence_dir",
        ),
        (
            json!({"evidence_dir": DEFAULT_EVIDENCE_CHILD, "max_age_days": 0}),
            "invalid_max_age_days",
        ),
        (
            json!({"evidence_dir": DEFAULT_EVIDENCE_CHILD, "max_age_days": "0"}),
            "invalid_max_age_days",
        ),
    ];

    if symlink_entry_supported {
        cases.push((
            json!({"evidence_dir": "symlink-entry-evidence"}),
            "symlink_entry",
        ));
    }

    #[cfg(windows)]
    {
        cases.push((
            json!({"evidence_dir": "C:release-evidence"}),
            "drive_relative_or_root_style_relative_path",
        ));
        cases.push((
            json!({"evidence_dir": "\\release-evidence"}),
            "drive_relative_or_root_style_relative_path",
        ));
    }

    let mut request_id = 2;
    for (arguments, expected_code) in cases {
        let result = call_evidence_status(&mut server, request_id, arguments);
        assert_tool_error_code(&result, expected_code);
        request_id += 1;
    }

    let unknown_status = call_evidence_status(
        &mut server,
        request_id,
        json!({
            "evidence_dir": "../release-evidence",
            "unexpected": SENTINEL
        }),
    );
    assert_tool_error_code(&unknown_status, "unknown_argument");
    assert!(
        !unknown_status.to_string().contains(SENTINEL),
        "unknown argument value was echoed: {unknown_status}"
    );
    request_id += 1;

    let unknown_with_invalid_status = call_evidence_status(
        &mut server,
        request_id,
        json!({
            "evidence_dir": 123,
            "unexpected": SENTINEL
        }),
    );
    assert_tool_error_code(&unknown_with_invalid_status, "unknown_argument");
    assert!(
        !unknown_with_invalid_status.to_string().contains(SENTINEL),
        "unknown argument value was echoed: {unknown_with_invalid_status}"
    );
    request_id += 1;

    let result = call_evidence_check(&mut server, request_id, json!({"evidence_dir": 123}));
    assert_tool_error_code(&result, "invalid_evidence_dir");
    request_id += 1;

    let unknown_check = call_evidence_check(
        &mut server,
        request_id,
        json!({
            "max_age_days": "0",
            "unexpected": SENTINEL
        }),
    );
    assert_tool_error_code(&unknown_check, "unknown_argument");
    assert!(
        !unknown_check.to_string().contains(SENTINEL),
        "unknown argument value was echoed: {unknown_check}"
    );

    drop(server);
    remove_temp_root(outside);
    remove_temp_root(root);
}

#[test]
fn stdio_invalid_max_age_days_wins_before_evidence_dir_resolution() {
    let root = temp_root("stdio-invalid-max-age-first");
    let outside = temp_root("stdio-invalid-max-age-outside");
    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let cases = [
        json!({"max_age_days": 0}),
        json!({"evidence_dir": "missing-evidence", "max_age_days": 366}),
        json!({
            "evidence_dir": outside.to_string_lossy().to_string(),
            "max_age_days": 0
        }),
    ];

    let mut request_id = 2;
    for arguments in cases {
        let status = call_evidence_status(&mut server, request_id, arguments.clone());
        assert_tool_error_code(&status, "invalid_max_age_days");
        request_id += 1;

        let check = call_evidence_check(&mut server, request_id, arguments);
        assert_tool_error_code(&check, "invalid_max_age_days");
        request_id += 1;
    }

    drop(server);
    remove_temp_root(outside);
    remove_temp_root(root);
}

#[test]
fn stdio_valid_max_age_days_preserves_evidence_dir_path_errors() {
    let root = temp_root("stdio-valid-max-age-path-errors");
    let outside = temp_root("stdio-valid-max-age-outside");
    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let cases = [
        (
            json!({"evidence_dir": "missing-evidence", "max_age_days": 1}),
            "missing_evidence_dir",
        ),
        (
            json!({
                "evidence_dir": outside.to_string_lossy().to_string(),
                "max_age_days": 365
            }),
            "outside_allowlisted_root",
        ),
    ];

    for (request_id, (arguments, expected_code)) in (2..).zip(cases) {
        let status = call_evidence_status(&mut server, request_id, arguments);
        assert_tool_error_code(&status, expected_code);
    }

    drop(server);
    remove_temp_root(outside);
    remove_temp_root(root);
}

#[test]
fn stdio_no_argument_evidence_tools_reject_stray_arguments() {
    let root = temp_root("stdio-no-arg-errors");
    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let plan = call_evidence_plan(&mut server, 2, json!({"unexpected": SENTINEL}));
    assert_tool_error_code(&plan, "unknown_argument");
    assert!(
        !plan.to_string().contains(SENTINEL),
        "unknown argument value was echoed: {plan}"
    );

    let manifest = call_evidence_manifest(&mut server, 3, json!({"unexpected": SENTINEL}));
    assert_tool_error_code(&manifest, "unknown_argument");
    assert!(
        !manifest.to_string().contains(SENTINEL),
        "unknown argument value was echoed: {manifest}"
    );

    drop(server);
    remove_temp_root(root);
}

#[test]
fn stdio_invalid_evidence_json_remains_sanitized_validation_summary() {
    let root = temp_root("stdio-invalid-json");
    let evidence_dir = root.join(DEFAULT_EVIDENCE_CHILD);
    init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), false)
        .expect("initialize evidence directory");
    fs::write(
        evidence_dir.join("dependency-policy-check.json"),
        "{not json",
    )
    .expect("write invalid JSON artifact");

    let mut server = McpProcess::start(&root);
    initialize_mcp(&mut server);

    let status = call_evidence_status(
        &mut server,
        2,
        json!({
            "evidence_dir": DEFAULT_EVIDENCE_CHILD
        }),
    );

    assert_eq!(status["isError"].as_bool(), Some(false));
    let structured = status["structuredContent"]
        .as_object()
        .expect("structured evidence status");
    assert_allowed_keys(
        "structured evidence status",
        structured,
        EVIDENCE_SUMMARY_KEYS,
    );
    assert_eq!(
        structured.get("status").and_then(Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        structured
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("invalid_json"))
            .and_then(Value::as_u64),
        Some(1)
    );
    let dependency_policy_action = structured
        .get("next_actions")
        .and_then(Value::as_array)
        .and_then(|actions| {
            actions.iter().find(|action| {
                action.get("name").and_then(Value::as_str) == Some("dependency_policy_check")
            })
        })
        .expect("invalid JSON next action");
    assert_eq!(
        dependency_policy_action
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("invalid_json"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        !status.to_string().contains("{not json"),
        "MCP response exposed raw invalid artifact content: {status}"
    );

    let check = call_evidence_check(
        &mut server,
        3,
        json!({
            "evidence_dir": DEFAULT_EVIDENCE_CHILD
        }),
    );
    let error = assert_tool_error_code(&check, "release_evidence_incomplete");
    assert_eq!(
        error.get("failure_code").and_then(Value::as_str),
        Some("missing_evidence")
    );
    assert_eq!(
        error
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("invalid_json"))
            .and_then(Value::as_u64),
        Some(1)
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
    assert_eq!(
        error
            .get("summary")
            .and_then(|summary| summary.get("next_actions"))
            .and_then(Value::as_array)
            .and_then(|actions| {
                actions.iter().find(|action| {
                    action.get("name").and_then(Value::as_str) == Some("dependency_policy_check")
                })
            })
            .and_then(|action| action.get("failure_codes"))
            .and_then(Value::as_object)
            .and_then(|codes| codes.get("invalid_json"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        !check.to_string().contains("{not json"),
        "MCP check error exposed raw invalid artifact content: {check}"
    );

    drop(server);
    remove_temp_root(root);
}

fn write_unsafe_artifact_shape(evidence_dir: &Path) {
    let artifact = json!({
        "status": "ok",
        "release_gate": SENTINEL,
        "generated_at": OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format generated_at"),
        "workspace": {
            "cargo_lock_present": true,
            "bun_lock_present": true,
            "deny_toml_present": true,
            "cargo_audit_config_present": true,
            "dependency_docs_present": true
        },
        "checks": [
            {
                "name": "cargo_deny",
                "status": "passed",
                "command": "cargo deny check",
                "stdout": SENTINEL,
                "stderr": SENTINEL,
                "raw_token": SENTINEL,
                "client_secret": SENTINEL,
                "logs": SENTINEL
            }
        ]
    });

    fs::write(
        evidence_dir.join("dependency-policy-check.json"),
        serde_json::to_vec_pretty(&artifact).expect("serialize artifact"),
    )
    .expect("write unsafe artifact");
}

fn tools_list_schema_contract(tools: &Value) -> Value {
    let mut tools = tools
        .as_array()
        .expect("tools/list tools array")
        .iter()
        .map(|tool| {
            json!({
                "name": tool.get("name").expect("tool name"),
                "inputSchema": tool.get("inputSchema").expect("tool inputSchema"),
                "outputSchema": tool.get("outputSchema").expect("tool outputSchema"),
            })
        })
        .collect::<Vec<_>>();
    tools.sort_by(|left, right| {
        left["name"]
            .as_str()
            .expect("left tool name")
            .cmp(right["name"].as_str().expect("right tool name"))
    });

    Value::Array(tools)
}

fn canonical_mcp_result(mut result: Value) -> Value {
    let structured = result
        .get_mut("structuredContent")
        .expect("MCP result structuredContent");
    normalize_contract_value(structured);
    let normalized_structured = structured.clone();

    let content = result
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|content| content.first_mut())
        .expect("MCP result content[0]");
    let text = content
        .get_mut("text")
        .and_then(|value| value.as_str())
        .expect("MCP result content[0].text");
    let mut text_json =
        serde_json::from_str::<Value>(text).expect("MCP result content[0].text JSON");
    normalize_contract_value(&mut text_json);
    assert_eq!(
        text_json, normalized_structured,
        "content[0].text should mirror structuredContent after canonical normalization"
    );
    content["text"] = Value::String(canonical_json_compact(&text_json));

    normalize_contract_value(&mut result);
    result
}

fn normalize_contract_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.contains_key("generated_at") {
                object.insert(
                    "generated_at".to_owned(),
                    Value::String(CONTRACT_GENERATED_AT.to_owned()),
                );
            }
            for child in object.values_mut() {
                normalize_contract_value(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_contract_value(child);
            }
        }
        _ => {}
    }
}

fn assert_contract_fixture(name: &str, actual: Value) {
    let path = contract_fixture_path(name);
    let actual = canonical_json_pretty(&actual);

    if std::env::var_os(UPDATE_CONTRACT_FIXTURES_ENV).is_some() {
        let parent = path.parent().expect("fixture parent");
        fs::create_dir_all(parent).expect("create contract fixture directory");
        fs::write(&path, &actual).expect("write contract fixture");
        return;
    }

    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read contract fixture {}: {error}", path.display()));
    assert_eq!(actual, expected, "contract fixture {name} drifted");
}

fn contract_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("contract")
        .join(name)
}

fn canonical_json_pretty(value: &Value) -> String {
    let sorted = sorted_json_value(value);
    serde_json::to_string_pretty(&sorted).expect("serialize canonical JSON") + "\n"
}

fn canonical_json_compact(value: &Value) -> String {
    let sorted = sorted_json_value(value);
    serde_json::to_string(&sorted).expect("serialize compact canonical JSON")
}

fn sorted_json_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), sorted_json_value(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(sorted_json_value).collect()),
        _ => value.clone(),
    }
}

fn write_complete_release_evidence(evidence_dir: &Path) {
    write_json_fixture(
        evidence_dir,
        "operations-preflight.json",
        production_preflight(),
    );
    write_json_fixture(
        evidence_dir,
        "dependency-policy-check.json",
        dependency_policy_check(),
    );
    write_json_fixture(
        evidence_dir,
        "release-assets-verification.json",
        release_assets_verification(),
    );
    write_json_fixture(
        evidence_dir,
        "openid-static-registration.json",
        openid_static_registration_report(),
    );
    write_json_fixture(
        evidence_dir,
        "cairn-oidcc-static.json",
        openid_static_config(),
    );
    write_json_fixture(
        evidence_dir,
        "oidc-metadata-smoke.json",
        oidc_metadata_smoke(),
    );
    write_json_fixture(
        evidence_dir,
        "openid-config-op-result.json",
        openid_conformance_summary_with_provenance(
            "Config OP",
            "oidcc-config-certification-test-plan",
            "https://www.certification.openid.net/plan-detail.html?plan=config-op",
        ),
    );
    write_json_fixture(
        evidence_dir,
        "openid-basic-op-result.json",
        openid_conformance_plan_export("oidcc-basic-certification-test-plan", "PASSED"),
    );
    write_json_fixture(
        evidence_dir,
        "scim-generic-connector-profile.json",
        scim_connector_profile("generic"),
    );
    write_json_fixture(
        evidence_dir,
        "scim-okta-connector-profile.json",
        scim_connector_profile("okta"),
    );
    write_json_fixture(
        evidence_dir,
        "scim-entra-connector-profile.json",
        scim_connector_profile("entra"),
    );
    write_json_fixture(evidence_dir, "scim-smoke.json", scim_smoke());
    write_json_fixture(
        evidence_dir,
        "scim-okta-connector-smoke.json",
        scim_connector_smoke("okta"),
    );
    write_json_fixture(
        evidence_dir,
        "scim-entra-connector-smoke.json",
        scim_connector_smoke("entra"),
    );
    write_json_fixture(
        evidence_dir,
        "browser-origin-smoke.json",
        browser_origin_smoke(),
    );
    write_json_fixture(
        evidence_dir,
        "security-headers-smoke.json",
        security_headers_smoke(),
    );
    write_json_fixture(
        evidence_dir,
        "email-provider-smoke.json",
        json!({
            "status": "sent",
            "provider": "command",
            "recipient_email": "ops@example.com",
            "completed_at": "2026-06-07T12:00:00Z",
            "provider_message_id": "provider-smoke-1"
        }),
    );
    write_json_fixture(
        evidence_dir,
        "lifecycle-email-smoke.json",
        lifecycle_email_smoke_receipt(),
    );
    write_json_fixture(evidence_dir, "restore-drill.json", restore_drill_receipt());
    write_json_fixture(
        evidence_dir,
        "signing-key-rotation-drill.json",
        signing_key_rotation_receipt(),
    );
    write_json_fixture(
        evidence_dir,
        "kek-rotation-drill.json",
        key_encryption_rotation_receipt(),
    );
    write_json_fixture(
        evidence_dir,
        "break-glass-admin-recovery-drill.json",
        break_glass_admin_recovery_receipt(),
    );
    write_json_fixture(
        evidence_dir,
        "audit-export-archive-drill.json",
        audit_export_receipt(),
    );
    write_json_fixture(
        evidence_dir,
        "audit-retention-purge-drill.json",
        audit_retention_purge_receipt(),
    );
}

fn write_json_fixture(root: &Path, file_name: &str, value: Value) {
    fs::write(
        root.join(file_name),
        serde_json::to_string_pretty(&value).expect("serialize evidence fixture"),
    )
    .expect("write evidence fixture");
}

fn production_preflight() -> Value {
    json!({
        "status": "ok",
        "environment": "production",
        "failures": [],
        "database": {
            "reachable": true,
            "applied_migrations": 12
        },
        "signing": {
            "database_active_kid": "rs256-active",
            "active_jwks_count": 2,
            "database_active_key_decryptable": true,
            "lifecycle": {
                "active_key_count": 1
            }
        },
        "email_delivery": {
            "production_ready": true,
            "queue": {
                "failed": 0
            }
        },
        "openid_conformance": {
            "issuer_https_origin_ready": true,
            "static_client_environment_ready": true
        }
    })
}

fn dependency_policy_check() -> Value {
    json!({
        "status": "ok",
        "completed_at": "2026-06-07T12:00:00Z",
        "workspace": {
            "cargo_lock_present": true,
            "bun_lock_present": true,
            "package_json_present": true,
            "deny_toml_present": true,
            "cargo_audit_config_present": true,
            "dependency_docs_present": true
        },
        "checks": [
            {
                "name": "cargo_deny",
                "command": "cargo deny check",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 81,
                "stderr_bytes": 0,
                "tool_version": "cargo-deny 0.19.8"
            },
            {
                "name": "cargo_audit",
                "command": "cargo audit",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 128,
                "stderr_bytes": 0,
                "tool_version": "cargo-audit 0.22.2"
            },
            {
                "name": "bun_audit",
                "command": "bun run audit",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 19,
                "stderr_bytes": 0,
                "tool_version": "1.3.14"
            }
        ],
        "failures": []
    })
}

fn release_assets_verification() -> Value {
    let tag = "v0.1.0-rc.1";
    json!({
        "schema_version": "cairnid.release_assets_verification.v1",
        "status": "ok",
        "completed_at": "2026-06-07T12:00:00Z",
        "release_tag": tag,
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "release_url": "https://github.com/cairnid/cairnid/releases/tag/v0.1.0-rc.1",
        "run_url": "https://github.com/cairnid/cairnid/actions/runs/123456789",
        "github_release_immutability_enabled_before_publish": true,
        "checksums": {
            "file_name": "SHA256SUMS.txt",
            "algorithm": "SHA-256",
            "present": true,
            "verified": true
        },
        "release_manifest": {
            "file_name": "release-manifest.json",
            "present": true,
            "sha256_verified": true
        },
        "attestations": {
            "signer_workflow": "cairnid/cairnid/.github/workflows/release.yml",
            "source_ref": "refs/tags/v0.1.0-rc.1",
            "provenance_verified": true,
            "sbom_attestations_verified": true
        },
        "archives": [
            release_archive("cairnid", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
            release_archive("cairnid", tag, "x86_64-pc-windows-msvc", "zip"),
            release_archive("cairnid-mcp", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
            release_archive("cairnid-mcp", tag, "x86_64-pc-windows-msvc", "zip")
        ],
        "sboms": [
            release_sbom("cairnid", tag, "x86_64-unknown-linux-gnu"),
            release_sbom("cairnid", tag, "x86_64-pc-windows-msvc"),
            release_sbom("cairnid-mcp", tag, "x86_64-unknown-linux-gnu"),
            release_sbom("cairnid-mcp", tag, "x86_64-pc-windows-msvc")
        ],
        "failures": []
    })
}

fn release_archive(binary: &str, tag: &str, target: &str, archive_format: &str) -> Value {
    json!({
        "file_name": format!("{binary}-{tag}-{target}.{archive_format}"),
        "binary": binary,
        "target": target,
        "archive_format": archive_format,
        "present": true,
        "sha256": "a".repeat(64),
        "sha256_verified": true,
        "manifest_entry_present": true,
        "github_attestation_verified": true,
        "sbom_file_name": format!("{binary}-{tag}-{target}.sbom.cdx.json"),
        "sbom_attestation_verified": true
    })
}

fn release_sbom(binary: &str, tag: &str, target: &str) -> Value {
    json!({
        "file_name": format!("{binary}-{tag}-{target}.sbom.cdx.json"),
        "binary": binary,
        "target": target,
        "format": "CycloneDX JSON",
        "present": true,
        "sha256": "b".repeat(64),
        "sha256_verified": true,
        "manifest_entry_present": true,
        "github_attestation_verified": true
    })
}

fn openid_static_registration_report() -> Value {
    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "status": "ready",
        "issuer": "https://id.example.com",
        "suite_alias": "cairn-basic-op",
        "certification_profiles": ["Config OP", "Basic OP"],
        "run_plan_commands": [
            "scripts/run-test-plan.py oidcc-config-certification-test-plan cairn-oidcc-static.json",
            "scripts/run-test-plan.py oidcc-basic-certification-test-plan cairn-oidcc-static.json"
        ],
        "static_clients": [
            openid_static_client_registration("primary", "oidf-client"),
            openid_static_client_registration("secondary", "oidf-client-2")
        ],
        "unsupported_v1_profiles": [
            "Implicit OP",
            "Hybrid OP",
            "Dynamic OP",
            "Form Post OP"
        ]
    })
}

fn openid_static_client_registration(role: &str, client_id: &str) -> Value {
    json!({
        "role": role,
        "client_id": client_id,
        "redirect_uris": [
            "https://www.certification.openid.net/test/a/cairn-basic-op/callback"
        ],
        "post_logout_redirect_uris": [
            "https://www.certification.openid.net/test/a/cairn-basic-op/post_logout_redirect"
        ],
        "response_types": ["code"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods": ["client_secret_basic", "client_secret_post"],
        "allowed_scopes": ["openid", "profile", "email", "groups", "offline_access"],
        "pkce_methods": ["S256"]
    })
}

fn openid_static_config() -> Value {
    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "alias": "cairn-basic-op",
        "description": "Cairn Identity OIDC static client certification",
        "server": {
            "discoveryUrl": "https://id.example.com/.well-known/openid-configuration"
        },
        "client": {
            "client_id": "oidf-client",
            "client_secret": "primary-secret"
        },
        "client2": {
            "client_id": "oidf-client-2",
            "client_secret": "secondary-secret"
        }
    })
}

fn openid_conformance_summary_with_provenance(
    profile: &str,
    plan_name: &str,
    published_result_url: &str,
) -> Value {
    let module_names = if plan_name == "oidcc-basic-certification-test-plan" {
        vec!["oidcc-claims-essential", "oidcc-server"]
    } else {
        vec!["oidcc-server"]
    };
    let selected_instances = module_names
        .iter()
        .map(|module_name| {
            json!({
                "module_name": module_name,
                "test_id": format!("{module_name}-selected-test")
            })
        })
        .collect::<Vec<_>>();

    json!({
        "source": "openid-conformance-suite",
        "certification_profile": profile,
        "plan_name": plan_name,
        "status": "FINISHED",
        "result": "PASSED",
        "completed_at": "2026-06-07T12:00:00Z",
        "published_result_url": published_result_url,
        "oidf_export_provenance": {
            "schema": "cairnid.oidf-export-provenance.v1",
            "normalizer": "cairn-api conformance oidcc-normalize-export",
            "source_format": "zip",
            "exported_from": "https://www.certification.openid.net/",
            "suite_version": "5.1.24",
            "plan_module_count": module_names.len(),
            "test_log_count": module_names.len(),
            "module_names": module_names,
            "selected_instances": selected_instances,
            "plan_modules_sha256": "a".repeat(64),
            "test_logs_sha256": "b".repeat(64)
        }
    })
}

fn openid_conformance_plan_export(plan_name: &str, result: &str) -> Value {
    json!({
        "exportedAt": "2026-06-07T12:00:00Z",
        "exportedFrom": "https://www.certification.openid.net/",
        "exportedVersion": "5.1.24",
        "planInfo": {
            "planName": plan_name,
            "modules": [
                {
                    "testModule": "oidcc-server",
                    "instances": ["test-inst-001"]
                },
                {
                    "testModule": "oidcc-server-rotate-keys",
                    "instances": ["test-inst-002"]
                }
            ]
        },
        "testLogExports": [
            openid_conformance_test_export("test-inst-001", "oidcc-server", result),
            openid_conformance_test_export("test-inst-002", "oidcc-server-rotate-keys", "WARNING")
        ]
    })
}

fn openid_conformance_test_export(test_id: &str, test_module_name: &str, result: &str) -> Value {
    json!({
        "testId": test_id,
        "testModuleName": test_module_name,
        "export": {
            "exportedAt": "2026-06-07T12:00:00Z",
            "exportedFrom": "https://www.certification.openid.net/",
            "exportedVersion": "5.1.24",
            "testInfo": {
                "testId": test_id,
                "testName": test_module_name,
                "status": "FINISHED",
                "result": result
            },
            "results": [
                {
                    "result": "SUCCESS",
                    "msg": "Test completed"
                }
            ]
        }
    })
}

fn scim_connector_profile(profile: &str) -> Value {
    let display_name = expected_scim_connector_display_name(profile);
    let connector_settings = match profile {
        "generic" => json!([
            {"name": "SCIM base URL", "value": "https://id.example.com/scim/v2", "note": "service root"},
            {"name": "Authentication", "value": "Bearer token", "note": "authorization header"},
            {"name": "Unique user key", "value": "userName", "note": "exact lookups"},
            {"name": "Stable user ID", "value": "externalId", "note": "immutable user ID"},
            {"name": "Stable group ID", "value": "externalId", "note": "immutable group ID"}
        ]),
        "okta" => json!([
            {"name": "Base URL", "value": "https://id.example.com/scim/v2", "note": "Okta connector base URL"},
            {"name": "Unique identifier field for users", "value": "userName", "note": "assignment reconciliation"},
            {"name": "Authentication mode", "value": "HTTP Header", "note": "bearer token header"},
            {"name": "Supported provisioning actions", "value": "Create Users, Update User Attributes, Deactivate Users, Push Groups", "note": "lifecycle and group push"}
        ]),
        "entra" => json!([
            {"name": "Tenant URL", "value": "https://id.example.com/scim/v2", "note": "directory application provisioning"},
            {"name": "Secret Token", "value": "<raw-token>", "note": "raw token is configured only in Entra"},
            {"name": "Provisioning mode", "value": "Automatic", "note": "test connection first"},
            {"name": "Target object actions", "value": "Create, Update, Delete", "note": "delete maps to soft deprovisioning"}
        ]),
        _ => panic!("unsupported test SCIM connector profile"),
    };

    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "status": "ready",
        "profile": profile,
        "display_name": display_name,
        "issuer": "https://id.example.com",
        "scim_base_url": "https://id.example.com/scim/v2",
        "service_provider_config_url": "https://id.example.com/scim/v2/ServiceProviderConfig",
        "authentication": {
            "scheme": "bearer",
            "connector_header": "Authorization: Bearer <raw-token>",
            "server_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<sha256(raw-token)>",
            "rotation_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<old-sha256>,<new-sha256>"
        },
        "connector_settings": connector_settings,
        "recommended_mappings": [
            {"resource": "User", "connector_attribute": "primary email", "scim_attribute": "userName", "note": "Required login identifier"},
            {"resource": "User", "connector_attribute": "primary email", "scim_attribute": "emails[type eq \"work\"].value", "note": "Primary work email"},
            {"resource": "User", "connector_attribute": "display name", "scim_attribute": "displayName", "note": "Optional display name"},
            {"resource": "User", "connector_attribute": "directory immutable user ID", "scim_attribute": "externalId", "note": "Recommended immutable key"},
            {"resource": "User", "connector_attribute": "assignment state", "scim_attribute": "active", "note": "false suspends users"},
            {"resource": "Group", "connector_attribute": "group name", "scim_attribute": "displayName", "note": "Group display name"},
            {"resource": "Group", "connector_attribute": "directory immutable group ID", "scim_attribute": "externalId", "note": "Recommended immutable key"},
            {"resource": "Group", "connector_attribute": "assigned User resources", "scim_attribute": "members.value", "note": "Cairn User resource IDs"}
        ],
        "supported_operations": [
            "ServiceProviderConfig, Schemas, and ResourceTypes discovery",
            "User create, list, SearchRequest, get, full replace, bounded PATCH, and soft deprovision",
            "Group create, list, SearchRequest, get, full replace, bounded PATCH, and delete",
            "Built-in smoke covers bounded Bulk mutations with same-request bulkId references",
            "Token rotation with up to four active SHA-256 token hashes"
        ],
        "validation_checks": [
            "https://id.example.com/scim/v2/ServiceProviderConfig returns application/scim+json",
            "connector can create and update a user with userName, emails[type eq \"work\"].value, displayName, externalId, and active",
            "connector can create and update a group with displayName, externalId, and User members",
            "connector deactivation maps to active=false or DELETE /Users/{id} and leaves audit history intact",
            "retired bearer tokens receive 401 Unauthorized after the rotation window closes"
        ],
        "unsupported_v1_features": [
            "password synchronization",
            "nested group membership",
            "SCIM change-password operation",
            "SCIM ETags",
            "SCIM cursor pagination",
            "Shared Signals Framework events"
        ],
        "smoke_commands": [
            "$env:CAIRN_SCIM_SMOKE_BASE_URL=\"https://id.example.com\"",
            "$env:CAIRN_SCIM_BEARER_TOKEN=\"<raw-token>\"",
            "$env:CAIRN_SCIM_SECONDARY_BEARER_TOKEN=\"<old-or-new-token-during-rotation>\"",
            "$env:CAIRN_SCIM_REJECTED_BEARER_TOKEN=\"<old-or-invalid-token>\"",
            "cairn-api scim smoke"
        ],
        "operator_notes": [
            "Do not store the raw connector token in application environment variables; store only its SHA-256 digest.",
            "Use stable directory object IDs for externalId so retries and renames remain idempotent.",
            "Map SCIM Group members to User resources returned by Cairn; nested Group members are rejected."
        ]
    })
}

fn expected_scim_connector_display_name(profile: &str) -> &'static str {
    match profile {
        "generic" => "Generic SCIM 2.0",
        "okta" => "Okta SCIM 2.0",
        "entra" => "Microsoft Entra SCIM 2.0",
        _ => panic!("unsupported test SCIM connector profile"),
    }
}

fn scim_smoke() -> Value {
    let created_user_ids = [
        fixed_uuid(1).to_owned(),
        fixed_uuid(2).to_owned(),
        fixed_uuid(3).to_owned(),
    ];
    json!({
        "status": "ok",
        "base_url": "https://id.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "secondary_token_checked": true,
        "rejected_token_checked": true,
        "created_user_ids": created_user_ids,
        "soft_deleted_user_ids": created_user_ids,
        "deleted_group_id": fixed_uuid(4),
        "checks": REQUIRED_SCIM_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

fn scim_connector_smoke(provider: &str) -> Value {
    json!({
        "status": "ok",
        "source": "external-scim-connector",
        "provider": provider,
        "display_name": expected_scim_connector_display_name(provider),
        "scim_base_url": "https://id.example.com/scim/v2",
        "completed_at": "2026-06-07T12:00:00Z",
        "connector_application_id": format!("{provider}-application-id"),
        "provisioning_job_id": format!("{provider}-provisioning-job-id"),
        "secondary_token_checked": true,
        "rejected_token_checked": true,
        "created_user_ids": [
            fixed_uuid(5),
            fixed_uuid(6)
        ],
        "deactivated_user_id": fixed_uuid(5),
        "deleted_group_id": fixed_uuid(7),
        "checks": REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{provider} {name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

fn oidc_metadata_smoke() -> Value {
    json!({
        "status": "ok",
        "issuer": "https://id.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "checks": REQUIRED_OIDC_METADATA_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

fn browser_origin_smoke() -> Value {
    json!({
        "status": "ok",
        "base_url": "https://id.example.com",
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
                "method": "POST",
                "path": "/api/v1/users",
                "status": "passed",
                "origin_status": 403,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            }
        ]
    })
}

fn security_headers_smoke() -> Value {
    json!({
        "status": "ok",
        "api_base_url": "https://id.example.com",
        "web_base_url": "https://app.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "checks": [
            security_headers_smoke_check("api", "/healthz", Value::Null),
            security_headers_smoke_check("api", "/.well-known/openid-configuration", Value::Null),
            security_headers_smoke_check("web", "/healthz", json!(true)),
            security_headers_smoke_check("web", "/login", Value::Null)
        ]
    })
}

fn security_headers_smoke_check(service: &str, path: &str, cache_control_no_store: Value) -> Value {
    json!({
        "service": service,
        "path": path,
        "status": "passed",
        "status_code": 200,
        "content_security_policy": true,
        "strict_transport_security": true,
        "x_content_type_options_nosniff": true,
        "x_frame_options_deny": true,
        "referrer_policy_no_referrer": true,
        "permissions_policy_restrictive": true,
        "cross_origin_opener_policy_same_origin": true,
        "cache_control_no_store": cache_control_no_store
    })
}

fn lifecycle_email_smoke_receipt() -> Value {
    json!({
        "status": "completed",
        "provider": "command",
        "completed_at": "2026-06-07T12:00:00Z",
        "messages": [
            lifecycle_email_message("invitation", true),
            lifecycle_email_message("email_verification", true),
            lifecycle_email_message("password_recovery", true),
            lifecycle_email_message("password_recovered_notification", false),
            lifecycle_email_message("password_changed_notification", false),
            lifecycle_email_message("new_login_notification", false)
        ]
    })
}

fn lifecycle_email_message(kind: &str, action_url_present: bool) -> Value {
    json!({
        "kind": kind,
        "template": lifecycle_email_template(kind),
        "status": "sent",
        "action_url_present": action_url_present,
        "provider_message_id": format!("provider-{kind}")
    })
}

fn lifecycle_email_template(kind: &str) -> &str {
    match kind {
        "invitation" => "account_invitation",
        _ => kind,
    }
}

fn restore_drill_receipt() -> Value {
    json!({
        "status": "ok",
        "organization_slug": "default",
        "organization_id": fixed_uuid(8),
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
    })
}

fn signing_key_rotation_receipt() -> Value {
    json!({
        "status": "rotated",
        "active_kid": "rs256-active",
        "active": true,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

fn key_encryption_rotation_receipt() -> Value {
    json!({
        "status": "rotated",
        "signing_keys": 1,
        "email_delivery_tokens": 0,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

fn break_glass_admin_recovery_receipt() -> Value {
    json!({
        "status": "granted",
        "organization_id": fixed_uuid(9),
        "user_id": fixed_uuid(10),
        "user_email": "ops@example.com",
        "user_status_before": "suspended",
        "user_status_after": "active",
        "admin_group_id": fixed_uuid(11),
        "admin_group_created": true,
        "membership_role_before": null,
        "membership_role_after": "owner",
        "audit_event_id": fixed_uuid(12),
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

fn audit_export_receipt() -> Value {
    json!({
        "status": "ok",
        "organization_id": fixed_uuid(13),
        "output_path": "evidence/cairn-audit-events.ndjson",
        "rows_exported": 2,
        "bytes_written": 256,
        "limit": 100,
        "export_max_rows": 1000,
        "has_more": true,
        "next_after_created_at": "2026-06-07T12:00:00Z",
        "next_after_id": fixed_uuid(14),
        "filters": {
            "action_prefix": "admin.",
            "target_prefix": null,
            "actor_kind": "system",
            "actor_id": null,
            "created_from": "2026-01-01T00:00:00Z",
            "created_to": null
        },
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

fn audit_retention_purge_receipt() -> Value {
    json!({
        "status": "ok",
        "organization_id": fixed_uuid(15),
        "retention_days": 365,
        "cutoff": "2025-06-07T12:00:00Z",
        "batch_size": 1000,
        "deleted": 0,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

fn fixed_uuid(index: u8) -> &'static str {
    match index {
        1 => "01890d6f-109f-767a-96cb-2927626f4501",
        2 => "01890d6f-109f-767a-96cb-2927626f4502",
        3 => "01890d6f-109f-767a-96cb-2927626f4503",
        4 => "01890d6f-109f-767a-96cb-2927626f4504",
        5 => "01890d6f-109f-767a-96cb-2927626f4505",
        6 => "01890d6f-109f-767a-96cb-2927626f4506",
        7 => "01890d6f-109f-767a-96cb-2927626f4507",
        8 => "01890d6f-109f-767a-96cb-2927626f4508",
        9 => "01890d6f-109f-767a-96cb-2927626f4509",
        10 => "01890d6f-109f-767a-96cb-2927626f4510",
        11 => "01890d6f-109f-767a-96cb-2927626f4511",
        12 => "01890d6f-109f-767a-96cb-2927626f4512",
        13 => "01890d6f-109f-767a-96cb-2927626f4513",
        14 => "01890d6f-109f-767a-96cb-2927626f4514",
        15 => "01890d6f-109f-767a-96cb-2927626f4515",
        _ => panic!("fixed UUID index out of range: {index}"),
    }
}

fn assert_allowed_keys(
    context: &str,
    object: &serde_json::Map<String, Value>,
    allowed_keys: &[&str],
) {
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = allowed_keys.to_vec();
    expected.sort_unstable();

    assert_eq!(actual, expected, "{context} keys changed");
}

fn named_item<'a>(items: &'a [Value], name: &str, context: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("{context} named {name} should be present"))
}

fn assert_release_gate(item: &Value, expected: &str, context: &str) {
    assert_eq!(
        item.get("release_gate").and_then(Value::as_str),
        Some(expected),
        "{context} should expose the sanitized registry release gate"
    );
}

fn assert_structured_content_matches_text<'a>(
    result: &'a CallToolResult,
    context: &str,
) -> &'a Value {
    let structured = result
        .structured_content
        .as_ref()
        .unwrap_or_else(|| panic!("{context} omitted structuredContent"));
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or_else(|| panic!("{context} omitted content[0].text"));
    let text_json = serde_json::from_str::<Value>(text)
        .unwrap_or_else(|error| panic!("{context} content[0].text was not JSON: {error}"));

    assert_eq!(
        &text_json, structured,
        "{context} content[0].text should match structuredContent"
    );
    structured
}

fn assert_no_sentinel(result: &CallToolResult, context: &str) {
    let serialized = serde_json::to_string(result)
        .unwrap_or_else(|error| panic!("serialize {context}: {error}"));
    assert!(
        !serialized.contains(SENTINEL),
        "{context} exposed sentinel data: {serialized}"
    );
}

fn json_object(value: Value) -> JsonObject {
    value
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("expected JSON object: {value}"))
}

fn output_schema_validators_from_json_tools(tools: &[Value]) -> BTreeMap<String, Validator> {
    let mut validators = BTreeMap::new();

    for tool in tools {
        let name = tool.get("name").and_then(Value::as_str).expect("tool name");
        let schema = tool
            .get("outputSchema")
            .unwrap_or_else(|| panic!("tool {name} outputSchema"))
            .clone();
        let replaced = validators.insert(name.to_owned(), compile_output_schema(name, &schema));
        assert!(replaced.is_none(), "duplicate tool {name}");
    }

    validators
}

fn output_schema_validators_from_rmcp_tools(tools: &[Tool]) -> BTreeMap<String, Validator> {
    let mut validators = BTreeMap::new();

    for tool in tools {
        let name = tool.name.as_ref();
        let schema = Value::Object(
            tool.output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("tool {name} outputSchema"))
                .as_ref()
                .clone(),
        );
        let replaced = validators.insert(name.to_owned(), compile_output_schema(name, &schema));
        assert!(replaced.is_none(), "duplicate tool {name}");
    }

    validators
}

fn compile_output_schema(tool_name: &str, schema: &Value) -> Validator {
    assert!(
        schema.is_object(),
        "tool {tool_name} outputSchema should be a JSON object"
    );

    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(schema)
        .unwrap_or_else(|error| {
            panic!(
                "tool {tool_name} outputSchema should compile as draft 2020-12 JSON Schema: {error}"
            )
        })
}

fn assert_structured_content_conforms_to_output_schema(
    validators: &BTreeMap<String, Validator>,
    tool_name: &str,
    structured: &Value,
) {
    assert!(
        structured.is_object(),
        "tool {tool_name} structuredContent should be a JSON object"
    );
    let validator = validators
        .get(tool_name)
        .unwrap_or_else(|| panic!("tool {tool_name} outputSchema validator"));

    if let Err(error) = validator.validate(structured) {
        panic!(
            "tool {tool_name} structuredContent failed advertised outputSchema at {}: {error}",
            error.instance_path()
        );
    }
}

fn assert_json_result_structured_content_matches_text<'a>(
    result: &'a Value,
    context: &str,
) -> &'a Value {
    let structured = result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("{context} omitted structuredContent"));
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|content| content.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{context} omitted content[0].text"));
    let text_json = serde_json::from_str::<Value>(text)
        .unwrap_or_else(|error| panic!("{context} content[0].text was not JSON: {error}"));

    assert_eq!(
        &text_json, structured,
        "{context} content[0].text should match structuredContent"
    );
    structured
}

fn assert_tools_list_output_schemas(tools: &[Value]) {
    for name in [
        "cairnid.evidence_plan",
        "cairnid.evidence_manifest",
        "cairnid.evidence_status",
        "cairnid.evidence_check",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("tool {name} advertised"));
        let schema_value = tool
            .get("outputSchema")
            .unwrap_or_else(|| panic!("tool {name} outputSchema"));
        let schema = schema_value
            .as_object()
            .unwrap_or_else(|| panic!("tool {name} outputSchema object"));

        assert_eq!(schema.get("type"), Some(&json!("object")));
        let variants = schema
            .get("oneOf")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("tool {name} outputSchema oneOf"));
        assert_eq!(variants.len(), 2, "tool {name} outputSchema variants");
        let success_collection = match name {
            "cairnid.evidence_plan" => "steps",
            "cairnid.evidence_manifest" | "cairnid.evidence_status" | "cairnid.evidence_check" => {
                "artifacts"
            }
            _ => unreachable!("unexpected evidence tool {name}"),
        };
        let success_schema = success_output_schema(name, variants);
        assert_schema_pins_schema_version_const(
            success_schema,
            &format!("tool {name} success outputSchema"),
        );
        let error_schema = error_output_schema(name, variants);
        assert_schema_pins_schema_version_const(
            error_schema,
            &format!("tool {name} error outputSchema"),
        );

        assert_schema_array_items_require_release_gate(
            schema_value,
            success_schema,
            success_collection,
            &format!("tool {name} success {success_collection}"),
        );
        if matches!(name, "cairnid.evidence_status" | "cairnid.evidence_check") {
            assert_summary_next_actions_contract(
                schema_value,
                success_schema,
                &format!("tool {name} success summary"),
            );
        }

        if name == "cairnid.evidence_check" {
            assert_error_summary_contract(name, schema_value, error_schema);
        }
    }
}

fn success_output_schema<'a>(tool_name: &str, variants: &'a [Value]) -> &'a Value {
    variants
        .iter()
        .find(|schema| !schema_has_error_property(schema))
        .unwrap_or_else(|| panic!("tool {tool_name} outputSchema success variant"))
}

fn error_output_schema<'a>(tool_name: &str, variants: &'a [Value]) -> &'a Value {
    variants
        .iter()
        .find(|schema| schema_has_error_property(schema))
        .unwrap_or_else(|| panic!("tool {tool_name} outputSchema error variant"))
}

fn assert_error_summary_contract(tool_name: &str, root: &Value, error_schema: &Value) {
    let error_body = schema_property(
        root,
        error_schema,
        "error",
        &format!("tool {tool_name} error envelope"),
    );
    let summary = schema_property(
        root,
        error_body,
        "summary",
        &format!("tool {tool_name} incomplete-check error body"),
    );
    let summary = resolve_schema(root, summary);
    assert_schema_pins_schema_version_const(
        summary,
        &format!("tool {tool_name} incomplete-check error summary"),
    );
    assert_schema_array_items_require_release_gate(
        root,
        summary,
        "artifacts",
        &format!("tool {tool_name} incomplete-check error summary"),
    );
    assert_summary_next_actions_contract(
        root,
        summary,
        &format!("tool {tool_name} incomplete-check error summary"),
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
                    variants
                        .iter()
                        .find(|variant| variant.get("type").and_then(Value::as_str) != Some("null"))
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

fn initialize_mcp(server: &mut McpProcess) {
    let initialize = server.request(
        1,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "cairnid-mcp-stdio-smoke",
                    "version": "0.0.0"
                }
            }
        }),
    );
    assert_eq!(
        initialize["serverInfo"]["name"].as_str(),
        Some("cairnid-mcp")
    );
    assert_eq!(
        initialize["protocolVersion"].as_str(),
        Some(MCP_PROTOCOL_VERSION)
    );

    server.notify(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
}

fn call_evidence_status(server: &mut McpProcess, id: u64, arguments: Value) -> Value {
    call_evidence_tool(server, id, "cairnid.evidence_status", arguments)
}

fn call_evidence_check(server: &mut McpProcess, id: u64, arguments: Value) -> Value {
    call_evidence_tool(server, id, "cairnid.evidence_check", arguments)
}

fn call_evidence_plan(server: &mut McpProcess, id: u64, arguments: Value) -> Value {
    call_evidence_tool(server, id, "cairnid.evidence_plan", arguments)
}

fn call_evidence_manifest(server: &mut McpProcess, id: u64, arguments: Value) -> Value {
    call_evidence_tool(server, id, "cairnid.evidence_manifest", arguments)
}

fn call_evidence_tool(
    server: &mut McpProcess,
    id: u64,
    name: &'static str,
    arguments: Value,
) -> Value {
    server.request(
        id,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }),
    )
}

fn assert_tool_error_code<'a>(
    result: &'a Value,
    expected_code: &str,
) -> &'a serde_json::Map<String, Value> {
    assert_eq!(result["isError"].as_bool(), Some(true));
    let structured = result["structuredContent"]
        .as_object()
        .expect("structured tool error");
    assert_eq!(
        structured.get("schema_version").and_then(Value::as_str),
        Some(MCP_EVIDENCE_RESULT_SCHEMA_VERSION)
    );
    let error = structured
        .get("error")
        .and_then(Value::as_object)
        .expect("structured error body");

    assert_eq!(
        error.get("code").and_then(Value::as_str),
        Some(expected_code)
    );
    let failure_code = error
        .get("failure_code")
        .and_then(Value::as_str)
        .expect("stable failure_code");
    assert!(!failure_code.is_empty());
    assert!(
        error
            .get("failure_codes")
            .and_then(Value::as_object)
            .and_then(|codes| codes.get(failure_code))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0),
        "stable failure_codes should count primary failure_code"
    );
    assert!(
        error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| !message.is_empty()),
        "tool error message should be present: {result}"
    );

    let text = result["content"]
        .as_array()
        .and_then(|content| content.first())
        .and_then(|content| content.get("text"))
        .and_then(Value::as_str)
        .expect("tool error text content");
    let text_json = serde_json::from_str::<Value>(text).expect("tool error text is JSON");
    assert_eq!(text_json, result["structuredContent"]);
    error
}

struct McpProcess {
    child: Child,
    stdin: ChildStdin,
    responses: mpsc::Receiver<Result<Value, String>>,
    stderr: Arc<Mutex<String>>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl McpProcess {
    fn start(current_dir: &Path) -> Self {
        Self::start_with_args(current_dir, std::iter::empty::<OsString>())
    }

    fn start_with_envs(current_dir: &Path, envs: &[(&str, &str)]) -> Self {
        Self::start_with_args_and_envs(current_dir, std::iter::empty::<OsString>(), envs)
    }

    fn start_with_args<I, S>(current_dir: &Path, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        Self::start_with_args_and_envs(current_dir, args, &[])
    }

    fn start_with_args_and_envs<I, S>(current_dir: &Path, args: I, envs: &[(&str, &str)]) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"));
        command.args(args).current_dir(current_dir);
        for (name, value) in envs {
            command.env(name, value);
        }

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cairnid-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let stderr_buffer = Arc::new(Mutex::new(String::new()));

        let (sender, responses) = mpsc::channel();
        let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        let _send_result = sender.send(Err(format!("stdout read failed: {error}")));
                        break;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let parsed = serde_json::from_str::<Value>(&line)
                    .map_err(|error| format!("invalid JSON-RPC line `{line}`: {error}"));
                if sender.send(parsed).is_err() {
                    break;
                }
            }
        });
        let stderr_thread = capture_stderr(stderr, Arc::clone(&stderr_buffer));

        Self {
            child,
            stdin,
            responses,
            stderr: stderr_buffer,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
        }
    }

    fn request(&mut self, id: u64, message: Value) -> Value {
        self.write_message(&message);

        loop {
            let response = self.read_response();
            if response.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            assert!(
                response.get("error").is_none(),
                "JSON-RPC request {id} failed: {response}"
            );
            return response
                .get("result")
                .cloned()
                .unwrap_or_else(|| panic!("JSON-RPC response {id} omitted result: {response}"));
        }
    }

    fn notify(&mut self, message: Value) {
        self.write_message(&message);
    }

    fn close(&mut self) {
        let _kill_result = self.child.kill();
        let _wait_result = self.child.wait();
        if let Some(handle) = self.stdout_thread.take() {
            let _join_result = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _join_result = handle.join();
        }
    }

    fn write_message(&mut self, message: &Value) {
        serde_json::to_writer(&mut self.stdin, message).expect("write JSON-RPC request");
        self.stdin.write_all(b"\n").expect("write JSON-RPC newline");
        self.stdin.flush().expect("flush JSON-RPC request");
    }

    fn read_response(&self) -> Value {
        match self.responses.recv_timeout(RESPONSE_TIMEOUT) {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => panic!("{error}; stderr: {}", self.stderr()),
            Err(error) => panic!(
                "timed out waiting for MCP response: {error}; stderr: {}",
                self.stderr()
            ),
        }
    }

    fn stderr(&self) -> String {
        self.stderr.lock().expect("stderr lock").clone()
    }

    fn assert_stderr_empty(&self) {
        let stderr = self.stderr();
        assert_eq!(stderr, "", "successful stdio should not write stderr");
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        self.close();
    }
}

fn run_cairnid_mcp(args: impl IntoIterator<Item = &'static str>) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run cairnid-mcp")
}

fn output_stdout(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn output_stderr(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn capture_stderr(stderr: ChildStderr, output: Arc<Mutex<String>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let mut output = output.lock().expect("stderr lock");
            output.push_str(&line);
            output.push('\n');
        }
    })
}

fn temp_root(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "cairnid-mcp-{name}-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root
}

fn absolute_escape_through_root(root: &Path, outside_path: &Path) -> PathBuf {
    let root_parent = root.parent().expect("temp root should have parent");
    let outside_suffix = outside_path
        .strip_prefix(root_parent)
        .expect("outside path should share temp parent");
    root.join("..").join(outside_suffix)
}

fn remove_temp_root(root: PathBuf) {
    let _remove_result = fs::remove_dir_all(root);
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
fn symlink_unavailable(_error: &io::Error) -> bool {
    false
}

#[cfg(windows)]
fn symlink_unavailable(error: &io::Error) -> bool {
    error.raw_os_error() == Some(1314)
}
