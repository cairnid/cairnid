# MCP

`cairnid-mcp` is a local stdio MCP server for inspecting release evidence below the process working directory. It exposes only read-only tools backed by the same `cairn-operations` release-evidence validators used by the operator commands.

Start it from the repository root:

```powershell
cargo run -p cairnid-mcp --locked
```

Available tools:

- `cairnid.evidence_plan`: returns the release evidence capture plan and missing environment variable names.
- `cairnid.evidence_manifest`: returns the current artifact manifest without writing files.
- `cairnid.evidence_status`: validates release evidence and returns sanitized status counts.
- `cairnid.evidence_check`: validates release evidence and returns sanitized artifact counts.

`evidence_status` and `evidence_check` accept:

- `evidence_dir`: optional evidence directory. When omitted, the server uses `release-evidence` under the process working directory.
- `max_age_days`: optional freshness window in days; defaults to the operations validator default.

Relative paths are resolved under the process working directory. Absolute paths are accepted only when their canonical path remains under that allowlisted root. Parent traversal with `..`, drive-relative paths, symlinked evidence directories, and symlink entries are rejected before the server calls the evidence checker.

`evidence_status` and `evidence_check` do not return validator failure text, artifact JSON, resource links, logs, standard streams, or provider exports. Their MCP responses contain stable statuses, artifact names, file names, commands, check counts, failure counts, and failure-code counts. The server does not expose the scaffold initializer or any other write-capable release-evidence operation.
