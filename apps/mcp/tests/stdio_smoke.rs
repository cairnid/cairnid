use cairn_operations::init_release_evidence_directory;
use rmcp::{
    ServiceExt,
    model::{
        CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
        JsonObject, ProtocolVersion,
    },
};
use serde_json::{Value, json};
use std::{
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
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const SENTINEL: &str = "CAIRNID_MCP_STDIO_SMOKE_DO_NOT_EXPOSE";
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
                "protocolVersion": "2025-11-25",
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
    let mut tool_names = tools["tools"]
        .as_array()
        .expect("tools array")
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
    assert_tools_list_output_schemas(tools["tools"].as_array().expect("tools array"));

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
    let structured = status["structuredContent"]
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
    assert!(
        !status.to_string().contains(SENTINEL),
        "MCP response exposed raw artifact content: {status}"
    );

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

    let mut tool_names = client
        .list_all_tools()
        .await
        .expect("list tools through rmcp client")
        .into_iter()
        .map(|tool| tool.name.into_owned())
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
            "parent_traversal",
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

    let result = call_evidence_check(&mut server, request_id, json!({"evidence_dir": 123}));
    assert_tool_error_code(&result, "invalid_evidence_dir");
    request_id += 1;

    let unknown_check = call_evidence_check(
        &mut server,
        request_id,
        json!({
            "max_age_days": 0,
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
        let schema = tool["outputSchema"]
            .as_object()
            .unwrap_or_else(|| panic!("tool {name} outputSchema object"));

        assert_eq!(schema.get("type"), Some(&json!("object")));
        let variants = schema
            .get("oneOf")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("tool {name} outputSchema oneOf"));
        assert_eq!(variants.len(), 2, "tool {name} outputSchema variants");
        assert!(
            variants.iter().all(schema_requires_schema_version),
            "tool {name} outputSchema variants should require schema_version"
        );
        assert!(
            variants.iter().any(schema_has_error_property),
            "tool {name} outputSchema should include error envelope"
        );

        let success_collection = match name {
            "cairnid.evidence_plan" => "steps",
            "cairnid.evidence_manifest" | "cairnid.evidence_status" | "cairnid.evidence_check" => {
                "artifacts"
            }
            _ => unreachable!("unexpected evidence tool {name}"),
        };
        let success_schema = success_output_schema(name, variants);
        assert_schema_array_items_require_release_gate(
            success_schema,
            success_schema,
            success_collection,
            &format!("tool {name} success {success_collection}"),
        );

        if name == "cairnid.evidence_check" {
            assert_error_summary_artifacts_require_release_gate(
                name,
                error_output_schema(name, variants),
            );
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

fn assert_error_summary_artifacts_require_release_gate(tool_name: &str, error_schema: &Value) {
    let error_body = schema_property(
        error_schema,
        error_schema,
        "error",
        &format!("tool {tool_name} error envelope"),
    );
    let summary = schema_property(
        error_schema,
        error_body,
        "summary",
        &format!("tool {tool_name} incomplete-check error body"),
    );
    assert_schema_array_items_require_release_gate(
        error_schema,
        summary,
        "artifacts",
        &format!("tool {tool_name} incomplete-check error summary"),
    );
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

fn schema_requires_schema_version(schema: &Value) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .any(|field| field.as_str() == Some("schema_version"))
        })
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
                "protocolVersion": "2025-11-25",
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

    fn start_with_args<I, S>(current_dir: &Path, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
            .args(args)
            .current_dir(current_dir)
            .env("RUST_LOG", "off")
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
