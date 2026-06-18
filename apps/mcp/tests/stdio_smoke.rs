use cairn_operations::init_release_evidence_directory;
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
fn binary_invalid_evidence_root_exits_before_stdio_jsonrpc() {
    let root = temp_root("invalid-startup-root");
    let missing = root.join("missing-root");
    let output = Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
        .arg("--evidence-root")
        .arg(&missing)
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
    assert!(stderr.contains("could not be inspected"), "{stderr}");
    assert!(stderr.contains(&missing.display().to_string()), "{stderr}");

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
    }
    assert!(
        !status.to_string().contains(SENTINEL),
        "MCP response exposed raw artifact content: {status}"
    );

    drop(server);
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
    }
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
