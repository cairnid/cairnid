# MCP

`cairnid-mcp` is a local stdio MCP server for inspecting release evidence below an explicit allowlisted root. It exposes only read-only tools backed by the same `cairn-operations` release-evidence validators used by the operator commands.

Inspect the binary safely without starting stdio JSON-RPC:

```powershell
cairnid-mcp --help
cairnid-mcp --version
```

Start it from the repository root. When `--evidence-root` is omitted, the process working directory remains the allowlisted root:

```powershell
cargo run -p cairnid-mcp --locked
```

During stdio protocol use, stdout is reserved for newline-delimited MCP JSON-RPC messages. The server ignores inherited Rust logging and backtrace environment settings for normal stdio logging, so successful protocol requests do not emit ambient diagnostics to stdout or stderr. Startup failures that happen before JSON-RPC begins, such as an invalid `--evidence-root <DIR>`, still exit non-zero and write the documented startup error to stderr.

MCP clients can launch the server from any working directory by passing an explicit evidence root:

```powershell
cairnid-mcp --evidence-root C:\path\to\cairnid
```

## Client configuration

Set `<repo-or-evidence-root>` to the repository root, or another allowlisted root that contains the `release-evidence` directory clients should inspect by default. If `cairnid-mcp` is not on `PATH`, set `command` to the absolute binary path.

For local stdio clients that use an `mcpServers` map:

```json
{
  "mcpServers": {
    "cairnid": {
      "command": "cairnid-mcp",
      "args": ["--evidence-root", "<repo-or-evidence-root>"]
    }
  }
}
```

For local stdio clients that use a `servers` map with an explicit transport type:

```json
{
  "servers": {
    "cairnid": {
      "type": "stdio",
      "command": "cairnid-mcp",
      "args": ["--evidence-root", "<repo-or-evidence-root>"]
    }
  }
}
```

Cargo-run fallback for clients that support a launch working directory:

```json
{
  "mcpServers": {
    "cairnid": {
      "command": "cargo",
      "args": [
        "run",
        "-p",
        "cairnid-mcp",
        "--locked",
        "--",
        "--evidence-root",
        "<repo-or-evidence-root>"
      ],
      "cwd": "<repo-root>"
    }
  }
}
```

The Cargo fallback must run from the workspace root. Prefer the built `cairnid-mcp` binary for release-candidate smoke testing; the fallback is for clients that cannot find the installed binary yet.

Available tools:

- `cairnid.evidence_plan`: returns the release evidence capture plan and missing environment variable names.
- `cairnid.evidence_manifest`: returns the current artifact manifest without writing files.
- `cairnid.evidence_status`: validates release evidence and returns sanitized status counts.
- `cairnid.evidence_check`: validates release evidence and returns sanitized artifact counts.

`evidence_status` and `evidence_check` accept:

- `evidence_dir`: optional evidence directory. When omitted, the server uses `release-evidence` under the configured evidence root.
- `max_age_days`: optional freshness window in days; defaults to the operations validator default.

Unknown request arguments are rejected with `unknown_argument`; the input schema advertises a closed object contract with no additional properties.

## Security boundary

`cairnid-mcp` is a local stdio server. The configured client controls how the process is launched, but every MCP request is constrained by the server boundary below.

- Tool surface: the server advertises only `cairnid.evidence_plan`, `cairnid.evidence_manifest`, `cairnid.evidence_status`, and `cairnid.evidence_check`.
- Write boundary: every advertised tool is read-only. The server does not expose the scaffold initializer, release-evidence init, or any other write-capable operation.
- Root boundary: `--evidence-root <DIR>` is the allowlisted root. When omitted, the process working directory is the allowlisted root.
- Startup root checks: the allowlisted root must be inspectable, must be a directory, and must not be a symlink. Startup root failures exit non-zero before stdio JSON-RPC starts.
- Request path checks: relative `evidence_dir` values are resolved under the configured root. Absolute `evidence_dir` values are accepted only when their canonical path remains under that root.
- Rejected request paths: empty paths, parent traversal with `..`, Windows drive-relative paths such as `C:release-evidence`, rooted relative paths such as `\release-evidence`, paths outside the allowlisted root, non-directories, symlinked evidence directories, and symlink entries inside an evidence directory.
- Validator detail boundary: `evidence_status` and `evidence_check` return stable status and failure-code summaries, not raw validator failure text.
- Data leakage boundary: tool responses do not return artifact JSON, resource links, logs, standard streams, provider exports, secret values, or secret-bearing static OpenID artifacts. `evidence_plan` can return missing environment variable names and artifact metadata needed to run the documented evidence commands.

If `--evidence-root <DIR>` is supplied and the root cannot be inspected, is not a directory, or is a symlink, the process exits non-zero before starting JSON-RPC and writes a startup error to stderr. Request-level errors after startup still use the MCP tool-error envelopes below.

## Structured result contract

Every tool advertises an MCP `outputSchema` for `structuredContent`. Successful structured results and tool-error envelopes include this root metadata field:

- `schema_version`: required and advertised with `const: "cairnid.mcp.evidence.v1"`.

The version identifies the MCP evidence result contract, not the evidence artifact format. Additive fields may be added within the same version. Removing or renaming fields, changing field meaning, changing failure-code semantics, or exposing previously sanitized validator details requires a new schema version.

The `v1` success contracts keep the existing top-level `status` and count fields. Tool errors keep the existing top-level `error` envelope and add `schema_version` alongside it.

Artifact and step entries advertised by `outputSchema` include sanitized `release_gate` labels: `cairnid.evidence_plan` `steps[]`, `cairnid.evidence_manifest` `artifacts[]`, `cairnid.evidence_status` `artifacts[]`, and `cairnid.evidence_check` success or incomplete-error-summary `artifacts[]`.

## Evidence tool errors

Request-level failures from `cairnid.evidence_status` and `cairnid.evidence_check` are returned as MCP tool results, not JSON-RPC protocol errors. The result has `isError: true`, and `structuredContent` contains this stable envelope:

```json
{
  "schema_version": "cairnid.mcp.evidence.v1",
  "error": {
    "code": "empty_evidence_dir",
    "failure_code": "missing_evidence",
    "failure_codes": {
      "missing_evidence": 1
    },
    "message": "evidence_dir must be a non-empty path"
  }
}
```

The text content mirrors the same JSON envelope for clients that only display content text.

`cairnid.evidence_check` also uses this envelope with `code: "release_evidence_incomplete"` when validation completes but the release evidence is not ready. That response includes `failure_codes` and a sanitized `summary`. `cairnid.evidence_status` returns the same incomplete summary with `isError: false`.

Stable request error codes:

- `unknown_argument`: a request includes an argument other than `evidence_dir` or `max_age_days`.
- `invalid_evidence_dir`: `evidence_dir` is present but is not a string path.
- `invalid_max_age_days`: `max_age_days` is present but is not an integer, or is outside 1 through 365.
- `empty_evidence_dir`: `evidence_dir` is empty or whitespace.
- `parent_traversal`: `evidence_dir` contains `..`.
- `drive_relative_or_root_style_relative_path`: `evidence_dir` is a drive-relative path such as `C:release-evidence`, or a rooted relative path such as `\release-evidence`.
- `outside_allowlisted_root`: the canonical evidence path resolves outside the configured evidence root.
- `symlinked_evidence_dir`: the evidence directory itself is a symlink.
- `symlink_entry`: an entry inside the evidence directory is a symlink.
- `missing_evidence_dir`: the requested evidence directory does not exist.
- `non_directory_evidence_dir`: the requested evidence path exists but is not a directory.
- `evidence_read_failed`: the server could not inspect or read the evidence directory or scaffold files.
- `invalid_evidence_json`: the operations validator returned a hard JSON processing error.
- `evidence_contract_failed`: the operations validator returned a hard contract error.
- `allowlist_root_unavailable`: the process working directory could not be inspected as the allowlisted root.

For `cairnid.evidence_status`, evidence validation failures that can be represented safely are not tool errors. Validation summaries return `isError: false`, `status: "incomplete"`, and stable `failure_codes`: `missing_evidence`, `stale_or_invalid_scaffold`, `invalid_json`, `invalid_json_root`, `stale_or_invalid_timestamp`, `timestamp_contract`, `forbidden_field`, `artifact_path_failure`, `contract_mismatch`, or `validation_failed`. `cairnid.evidence_check` applies the same validation failure-code set inside the `release_evidence_incomplete` tool-error envelope. `symlink_entry` is a request-level path-safety error for pre-check symlink entries; validation text about symlink, read, directory, or unexpected-entry issues is summarized as `artifact_path_failure`.

## Release candidate checklist

- Binary identity: `cairnid-mcp --help` exits before stdio JSON-RPC starts, documents `--evidence-root <DIR>`, and `cairnid-mcp --version` prints the package version.
- Stdio protocol smoke: a local client can send `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`; `tools/list` returns exactly the four read-only evidence tools with `outputSchema`; `tools/call` can invoke `cairnid.evidence_status` against `release-evidence`.
- Evidence root behavior: startup rejects missing, non-directory, and symlink allowlisted roots before JSON-RPC starts; request handling accepts relative evidence directories under the root and absolute evidence directories only when they canonicalize under the root.
- Path-safety behavior: request smoke covers `parent_traversal`, `outside_allowlisted_root`, `missing_evidence_dir`, `non_directory_evidence_dir`, `invalid_max_age_days`, `symlinked_evidence_dir`, and `symlink_entry` where symlink creation is available.
- Windows behavior: request smoke covers drive-relative paths such as `C:release-evidence` and rooted relative paths such as `\release-evidence`; symlink cases may require developer-mode or elevated symlink privileges to exercise locally.
- Sanitized incomplete evidence: `cairnid.evidence_status` returns `status: "incomplete"` without raw artifact content, logs, streams, or validator details; `cairnid.evidence_check` returns `release_evidence_incomplete` with `failure_codes` and sanitized `summary` only.
- Release validation commands: run `cargo +stable-x86_64-pc-windows-gnu test -p cairnid-mcp --locked`, `cargo +stable-x86_64-pc-windows-gnu clippy -p cairnid-mcp --all-targets --locked -- -D warnings`, `bun run check:public-surface`, `bun run docs:site -- --out <temp-dir>`, and `git diff --check`.
