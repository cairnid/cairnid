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

MCP clients can launch the server from any working directory by passing an explicit evidence root:

```powershell
cairnid-mcp --evidence-root C:\path\to\cairnid
```

Available tools:

- `cairnid.evidence_plan`: returns the release evidence capture plan and missing environment variable names.
- `cairnid.evidence_manifest`: returns the current artifact manifest without writing files.
- `cairnid.evidence_status`: validates release evidence and returns sanitized status counts.
- `cairnid.evidence_check`: validates release evidence and returns sanitized artifact counts.

`evidence_status` and `evidence_check` accept:

- `evidence_dir`: optional evidence directory. When omitted, the server uses `release-evidence` under the configured evidence root.
- `max_age_days`: optional freshness window in days; defaults to the operations validator default.

Unknown request arguments are rejected with `unknown_argument`; the input schema advertises a closed object contract with no additional properties.

Relative paths are resolved under the configured evidence root. Absolute paths are accepted only when their canonical path remains under that allowlisted root. Parent traversal with `..`, drive-relative paths, symlinked evidence directories, and symlink entries are rejected before the server calls the evidence checker.

If `--evidence-root <DIR>` is supplied and the root cannot be inspected, is not a directory, or is a symlink, the process exits non-zero before starting JSON-RPC and writes a startup error to stderr. Request-level errors after startup still use the MCP tool-error envelopes below.

`evidence_status` and `evidence_check` do not return validator failure text, artifact JSON, resource links, logs, standard streams, or provider exports. Their MCP responses contain stable statuses, artifact names, file names, commands, check counts, failure counts, and failure-code counts. The server does not expose the scaffold initializer or any other write-capable release-evidence operation.

## Structured result contract

Every tool advertises an MCP `outputSchema` for `structuredContent`. Successful structured results and tool-error envelopes include this root metadata field:

- `schema_version`: currently `cairnid.mcp.evidence.v1`.

The version identifies the MCP evidence result contract, not the evidence artifact format. Additive fields may be added within the same version. Removing or renaming fields, changing field meaning, changing failure-code semantics, or exposing previously sanitized validator details requires a new schema version.

The `v1` success contracts keep the existing top-level `status` and count fields. Tool errors keep the existing top-level `error` envelope and add `schema_version` alongside it.

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

Evidence validation failures that can be represented safely are not tool errors. Validation summaries return `isError: false`, `status: "incomplete"`, and stable `failure_codes`: `missing_evidence`, `stale_or_invalid_scaffold`, `invalid_json`, `invalid_json_root`, `stale_or_invalid_timestamp`, `timestamp_contract`, `forbidden_field`, `artifact_path_failure`, `contract_mismatch`, or `validation_failed`. `symlink_entry` is a request-level path-safety error for pre-check symlink entries; validation text about symlink, read, directory, or unexpected-entry issues is summarized as `artifact_path_failure`.
