use cairn_operations::init_release_evidence_directory;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::OffsetDateTime;

const DEFAULT_EVIDENCE_CHILD: &str = "release-evidence";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const SENTINEL: &str = "CAIRNID_MCP_STDIO_SMOKE_DO_NOT_EXPOSE";
const EVIDENCE_SUMMARY_KEYS: &[&str] = &[
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_cairnid-mcp"))
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
